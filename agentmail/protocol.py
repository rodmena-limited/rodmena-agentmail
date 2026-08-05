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

FRONT_MATTER_OPEN = "--- agentmail v1 ---"
FRONT_MATTER_CLOSE = "--- end agentmail ---"

AUTO_SUBMITTED = "auto-generated"  # RFC 3834

TYPES = ("report", "question", "fix-notice", "verify-result", "ack", "close")

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
                severity: str | None = None, ref: str | None = None) -> str:
    """Prepend the front-matter block that carries metadata mail-api will not persist.

    Kept deliberately readable: a human opening this thread in a normal mail client should be
    able to see what the agents were saying to each other without decoding anything.
    """
    lines = [FRONT_MATTER_OPEN, f"type: {msg_type}", f"thread: {thread_id}"]
    if severity:
        lines.append(f"severity: {severity}")
    if ref:
        lines.append(f"ref: {ref}")
    lines.append(FRONT_MATTER_CLOSE)
    return "\n".join(lines) + "\n\n" + (body or "")


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
