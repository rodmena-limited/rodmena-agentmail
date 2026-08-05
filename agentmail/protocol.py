"""The wire protocol: message types, headers, and the rules that stop the bus looping.

WHY TYPES EXIST. Two agents that both reply politely to every message will exchange
"thanks, noted" until a quota stops them. Typing each message makes "does this deserve a
reply?" a property of the message rather than a judgement call the agent has to get right
every time:

    report        a defect or observation, WITH a reproduction   -> reply expected
    question      a request for information                      -> reply expected
    fix-notice    "we changed something, please re-verify"       -> reply expected
    verify-result the reporter's re-test: confirmed | still-broken-> reply optional
    ack           "received, working on it"                      -> MUST NOT reply
    close         "this thread is done"                          -> MUST NOT reply

WHY A DEPTH CAP. Even correctly-typed traffic can ping-pong if two agents disagree. The
References chain gives a natural depth counter, and past MAX_THREAD_DEPTH the client refuses
to reply at all. A thread that needs 40 turns needs a human, not more automation.
"""
from __future__ import annotations

import re

# HOW METADATA ACTUALLY TRAVELS.
#
# mail-api ACCEPTS these headers on send (they are on the outbound allow-list) but does NOT
# persist arbitrary headers on RECEIPT: `inbound_messages` has no headers column and the
# parser only extracts Authentication-Results. So an X- header we send is delivered to the
# recipient's MTA and then dropped before the agent could read it.
#
# Two things DO survive, and the protocol rides on those:
#
#   * `recipient_tag` — plus-addressing. `tokengate+thr-9f2a@…` is persisted as the tag, so
#     the THREAD ID travels in the address itself. (split_localpart lowercases it, hence
#     lowercase-safe thread ids.)
#   * `message_id` / `in_reply_to` — real RFC 5322 threading, persisted as columns.
#
# Everything else (type, severity, ref) travels in a small front-matter block at the top of
# the body. That keeps the bus working with zero mail-api changes, and has the side benefit
# that a human reading the thread in an ordinary mail client sees the same metadata the agent
# does. The X- headers are still SENT — harmless, useful to a human's client, and if mail-api
# ever persists headers the parser below will simply prefer them.
H_THREAD = "X-Rodmena-Thread"
H_TYPE = "X-Rodmena-Type"
H_SEVERITY = "X-Rodmena-Severity"
H_REF = "X-Rodmena-Ref"
H_AUTO = "Auto-Submitted"
H_AGENT = "X-Rodmena-Agent"
H_TO_AGENT = "X-Rodmena-To-Agent"

FRONT_MATTER_OPEN = "--- agentmail v1 ---"
FRONT_MATTER_CLOSE = "--- end agentmail ---"

AUTO_SUBMITTED = "auto-generated"  # RFC 3834

TYPES = ("report", "question", "fix-notice", "verify-result", "ack", "close", "note")

# SELF-NOTES, AND WHY AGENT IDENTITY IS *NOT* IN THE PLUS-TAG.
#
# Two coding agents can share one repository, and therefore one bus identity: `whoami`
# resolves from the git remote, so both are `mail-api`. A `note` lets them leave each other
# durable, timestamped messages through the same bus everything else uses.
#
# The obvious design — address the other agent as `mail-api+bob@…` — DOES NOT WORK, and the
# reason is worth stating so nobody re-derives it: **the plus-tag is already occupied by the
# thread id** (`thread_address` below). Measured on the live system, a normal bus message
# arrives with `recipient_tag: "thr-3220db32520b463f90c4"`. Putting an agent name there
# would overwrite the thread id, because `Client._to_message` reads the tag as its most
# trustworthy thread source. Stacking them (`+bob.thr-…`) would break `Client.thread()`,
# which queries the API for an EXACT `recipient_tag` match.
#
# So the addressee rides in the front matter instead, alongside type and severity. That slot
# is free, survives receipt (X- headers do not — see above), and is readable by a human.
#
# The security property is weaker than the bus's, and deliberately so: front matter is body
# text, so an agent could forge `to-agent`. That is acceptable HERE and nowhere else — both
# agents already share one inbox, one API key and one working copy, so there is no boundary
# between them left to cross. `to-agent` is addressing, not authorisation. Never reuse it to
# gate anything.

#: A note addressed to nobody in particular: every agent on the platform sees it.
BROADCAST_AGENT = "*"

#: Replying to one of these is what turns a conversation into a loop.
TERMINAL_TYPES = frozenset({"ack", "close"})

#: Types whose sender is waiting on an answer.
EXPECTS_REPLY = frozenset({"report", "question", "fix-notice"})

SEVERITIES = ("crit", "high", "med", "low")

#: Past this many ancestors the client stops replying. Chosen so a normal
#: report -> ack -> fix-notice -> verify-result -> close exchange (5) has ample room, while a
#: genuine disagreement surfaces to a human instead of running forever.
MAX_THREAD_DEPTH = 20


class ProtocolError(ValueError):
    """The caller asked for something the protocol forbids."""


def validate_type(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in TYPES:
        raise ProtocolError(f"unknown message type {value!r}; expected one of {', '.join(TYPES)}")
    return v


def validate_severity(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v not in SEVERITIES:
        raise ProtocolError(
            f"unknown severity {value!r}; expected one of {', '.join(SEVERITIES)}")
    return v


def reply_subject(subject: str) -> str:
    """Prefix with exactly one 'Re: '.

    Mail clients and humans both read these threads, and 'Re: Re: Re: Re:' is the classic
    tell of an automated exchange nobody is steering. Existing prefixes are collapsed, and
    case/whitespace variants ('RE:', 're :') are treated as the same thing.
    """
    s = (subject or "").strip()
    lowered = s.lower()
    while lowered.startswith("re:") or lowered.startswith("re :"):
        s = s[s.index(":") + 1:].lstrip()
        lowered = s.lower()
    return f"Re: {s}" if s else "Re:"


def may_reply_to(msg_type: str, depth: int) -> tuple[bool, str]:
    """Should the client allow a reply to a message of this type at this depth?

    Returns (allowed, reason). The reason is surfaced to the agent so a refusal is
    self-explanatory rather than a silent no-op.
    """
    t = (msg_type or "").strip().lower()
    if t in TERMINAL_TYPES:
        return False, (
            f"message is typed '{t}', which closes the exchange; replying to it is how a "
            f"two-agent courtesy loop starts")
    if depth >= MAX_THREAD_DEPTH:
        return False, (
            f"thread depth {depth} has reached the cap of {MAX_THREAD_DEPTH}; this thread "
            f"needs a human, not another automated turn")
    return True, ""


def encode_body(body: str, *, msg_type: str, thread_id: str,
                severity: str | None = None, ref: str | None = None,
                agent: str | None = None, to_agent: str | None = None) -> str:
    """Prepend the front-matter block that carries metadata mail-api will not persist.

    Kept deliberately readable: a human opening this thread in a normal mail client should be
    able to see what the agents were saying to each other without decoding anything.

    `agent` / `to_agent` name the sending and receiving agent WITHIN one platform, for
    self-notes between two coding agents sharing a repository. See the note above TYPES for
    why this is front matter and not a plus-tag.
    """
    lines = [FRONT_MATTER_OPEN, f"type: {msg_type}", f"thread: {thread_id}"]
    if severity:
        lines.append(f"severity: {severity}")
    if ref:
        lines.append(f"ref: {ref}")
    if agent:
        lines.append(f"agent: {sanitise_agent(agent)}")
    if to_agent:
        lines.append(f"to-agent: {sanitise_agent(to_agent)}")
    lines.append(FRONT_MATTER_CLOSE)
    return "\n".join(lines) + "\n\n" + (body or "")


#: Agent names are used in a front-matter line and a state FILENAME, so they may not contain
#: a path separator, a newline, or anything that would let one agent's name address another's
#: state file. Narrow by construction rather than by escaping at each use site.
_AGENT_SAFE = re.compile(r"[^a-z0-9._-]+")


def sanitise_agent(name: str) -> str:
    """Normalise an agent name to something safe in front matter and in a filename.

    Returns "" for anything that sanitises to nothing, which callers treat as "unset" — an
    unnamed agent is a broadcast, never a silent match against another agent's name.
    """
    n = _AGENT_SAFE.sub("-", (name or "").strip().lower()).strip("-._")
    return "" if n in ("", ".", "..") else n[:40]


def note_is_for(to_agent: str | None, me: str | None) -> bool:
    """Should the agent called `me` be shown a note addressed to `to_agent`?

    Unaddressed notes and explicit broadcasts go to everyone — including an agent that never
    set a name, because the alternative is mail that is delivered to nobody and looks exactly
    like mail that was never sent.
    """
    # BROADCAST_AGENT ('*') sanitises to "", so the empty check below is what actually
    # implements broadcast; there is deliberately no separate '*' branch, because a branch
    # that can never be reached is indistinguishable from one that works.
    target = sanitise_agent(to_agent or "")
    if not target:
        return True
    return target == sanitise_agent(me or "")


def decode_body(raw: str) -> tuple[dict[str, str], str]:
    """Split a received body into (metadata, human text).

    Unparseable or absent front matter is not an error — it yields empty metadata and the
    whole body, so a message hand-written by a human still reaches the agent. The caller
    supplies defaults (type defaults to 'report', which is the type that expects a reply, so
    a malformed message is surfaced rather than silently dropped).
    """
    text = raw or ""
    stripped = text.lstrip()
    if not stripped.startswith(FRONT_MATTER_OPEN):
        return {}, text

    after_open = stripped[len(FRONT_MATTER_OPEN):].lstrip("\r\n")
    end = after_open.find(FRONT_MATTER_CLOSE)
    if end == -1:
        return {}, text                      # opened but never closed -> treat as prose

    block, rest = after_open[:end], after_open[end + len(FRONT_MATTER_CLOSE):]
    meta: dict[str, str] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        meta[k.strip().lower()] = v.strip()
    return meta, rest.lstrip("\r\n")


#: Characters allowed in a plus-address tag. Deliberately narrower than RFC 5322's atext:
#: the tag is generated by us, so there is no reason to permit anything that could confuse a
#: parser downstream.
_TAG_SAFE = re.compile(r"[^a-z0-9._-]+")


def sanitise_thread_tag(thread_id: str) -> str:
    """Make a thread id safe to place in the local part of an address (#354).

    `thread_address` interpolated the tag verbatim, and `Client._parse` falls back to the raw
    `Message-ID` when a message carries no `recipient_tag` — which is EVERY message not sent to
    a plus-address. A Message-ID is `<ulid@domain>` by construction, so a reply came out as:

        folks+<01kz7txx...@mail.rodmena.co.uk>@mail.rodmena.co.uk

    Two `@` and a pair of angle brackets in an addr-spec; mail-api correctly answered 422
    invalid_recipient and the reply could not be sent. On a bus where `report` and `question`
    REQUIRE an answer, that is a thread nobody can close.

    Sanitising HERE rather than reordering the fallback is deliberate: `message_id` is
    SENDER-CONTROLLED on inbound mail, so any tag reaching an address must be cleaned whatever
    its provenance. Fixing only the fallback would leave the next caller exposed.

    Everything up to the first `@` is kept (an angle-bracketed Message-ID keeps its unique
    ULID), unsafe characters collapse to `-`, and the result is trimmed of separator noise.
    """
    tag = (thread_id or "").strip().lower().lstrip("<").rstrip(">")
    tag = tag.split("@", 1)[0]               # a Message-ID's domain is not part of the tag
    tag = _TAG_SAFE.sub("-", tag).strip("-._")
    return tag[:64]                          # plus-address tags are not a place for essays


def thread_address(platform_address: str, thread_id: str) -> str:
    """Route a reply into its thread via plus-addressing: tokengate+thr-9f2a@…

    The tag is persisted as `recipient_tag`, which makes the thread id readable on the
    receiving side even though custom headers are not stored.
    """
    local, _, domain = platform_address.partition("@")
    local = local.split("+", 1)[0]           # never stack tags
    return f"{local}+{sanitise_thread_tag(thread_id)}@{domain}"


#: A thread-opener below this is almost never self-contained. Deliberately generous — the
#: point is to catch "your API is broken, please fix", not to police prose length.
MIN_OPENER_CHARS = 240


def opener_shortcomings(body: str, msg_type: str) -> list[str]:
    """Advisory checks on a message that OPENS a thread. Never blocks; the caller warns.

    The recipient is a different agent in a different repository whose session has never seen
    yours: they cannot read your terminal, your logs or your tickets, and they may open this a
    week later. A reply can lean on the thread above it — an opener cannot lean on anything,
    and a thin one costs a full round trip between two poll-driven agents just to ask "what
    did you actually run?".

    Returns human-readable shortcomings. Heuristics, so they are surfaced as a warning and
    never as a refusal: a genuinely short report is possible, and being wrong about that must
    not stop someone reporting a live defect.
    """
    if msg_type not in EXPECTS_REPLY:
        return []                       # ack/close/verify-result legitimately stand alone

    text = (body or "").strip()
    out: list[str] = []

    if len(text) < MIN_OPENER_CHARS:
        out.append(
            f"body is {len(text)} characters; a thread-opener usually needs more than "
            f"{MIN_OPENER_CHARS} to carry a reproduction and expected-vs-observed")

    # Something that looks like a command or captured output: an indented block, a fenced
    # block, a shell prompt, or an HTTP status. Its absence is the strongest single signal
    # that the reader cannot reproduce this.
    has_evidence = any(marker in text for marker in ("```", "\n    ", "\n\t", "$ ", "-> ")) \
        or any(code in text for code in ("HTTP", "200", "401", "403", "429", "500", "503"))
    if not has_evidence:
        out.append("no reproduction or captured output found — paste the exact command and "
                   "what it actually printed, not a paraphrase")

    if "\n" not in text:
        out.append("single line; state what you ran, what you got, and what you expected")

    return out
