"""The agent-mail client.

Everything security-relevant is enforced HERE rather than described in a prompt, because the
agents on this bus are fully autonomous: there is no human approving each turn. A rule an
agent has to remember is a rule that eventually gets skipped under context pressure, so the
three that matter are structural —

  * an unverified message is never handed to the agent at all (`inbox()` quarantines it);
  * a message is never replied to twice, and never past the depth cap (`reply()` refuses);
  * every outgoing message carries Auto-Submitted, so anything else on the internet that
    honours RFC 3834 will not auto-respond to us.

Usage:

    from agentmail import AgentMail

    am = AgentMail.from_env()                    # reads the platform's own credential
    for msg in am.inbox():                       # verified senders only
        if msg.type == "report":
            am.reply(msg, "Reproduced. Fixing.", type="ack")

    am.send("tokengate", "Subject", "Body", type="report", severity="high")
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote

import httpx

from . import protocol as P
from .registry import address_of, is_registered, platform_for_path, platform_of
from .state import State

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "rodmena" / "agentmail"
DEFAULT_BASE_URL = "https://mailserver.rodmena.co.uk"


class AgentMailError(RuntimeError):
    pass


class NotAuthentic(AgentMailError):
    """A message failed the DKIM or registry check and was quarantined."""


@dataclass
class Message:
    """One inbound message, already proven to come from a registered platform."""
    inbound_id: str
    from_addr: str
    sender: str                      # platform key, e.g. "runflow"
    subject: str
    body: str
    message_id: str | None
    in_reply_to: str | None
    thread_id: str
    type: str
    severity: str | None
    ref: str | None
    received_at: str
    dkim: str
    spf: str | None = None
    dmarc: str | None = None
    #: Self-note addressing WITHIN one platform. `agent` is who wrote it, `to_agent` who it
    #: is for (None = everyone on this platform). Both are None for ordinary bus traffic.
    agent: str | None = None
    to_agent: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def expects_reply(self) -> bool:
        return self.type in P.EXPECTS_REPLY

    @property
    def is_note(self) -> bool:
        """A note between agents co-resident on one platform, rather than bus traffic.

        Keyed on the TYPE alone. Comparing sender to recipient would be a tautology — the
        client only ever reads its own inbox, and `sender` is derived from `from_addr` — so
        it would report True for every message and prove nothing.
        """
        return self.type == "note"


@dataclass
class Quarantined:
    """A message we refused to hand to the agent, and why."""
    inbound_id: str
    from_addr: str | None
    subject: str
    reason: str


@dataclass
class Sent:
    """One outbound message this platform sent — the sent-folder view (#257)."""
    track_id: str
    to: list[str]
    subject: str | None
    from_addr: str | None
    status: str
    created_at: str | None
    email_type: str | None


class AgentMail:
    def __init__(self, platform: str, api_key: str, *,
                 base_url: str = DEFAULT_BASE_URL,
                 state_dir: Path | None = None,
                 agent: str | None = None,
                 timeout: float = 20.0) -> None:
        self.platform = platform
        self.address = address_of(platform)
        # This agent's name WITHIN the platform. Only meaningful when two agents share one
        # repository; None means "the only agent here", which sees everything.
        self.agent = P.sanitise_agent(agent or os.environ.get("AGENTMAIL_AGENT", "")) or None
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._state = State(platform, state_dir, agent=self.agent)
        self._quarantine: list[Quarantined] = []
        self.opener_warnings: list[str] = []

    # -- construction --------------------------------------------------------------------
    @classmethod
    def from_env(cls, platform: str | None = None, **kw: Any) -> "AgentMail":
        """Load this platform's credential from the environment or its 0600 config file.

        Order: explicit argument, then AGENTMAIL_PLATFORM, then the repository we are
        standing in, then — only if exactly one credential file exists — that one.

        The cwd rule is what makes onboarding a one-liner: an agent working in
        ~/develop/TokenGate is the TokenGate agent. Guessing when several credentials are
        present and none of the above resolves would let an agent silently send as the wrong
        platform, which is the one impersonation the bus cannot detect — mail-api faithfully
        stamps the From of whoever's key was used, so it would look perfectly authentic.
        """
        platform = (platform
                    or os.environ.get("AGENTMAIL_PLATFORM")
                    or platform_for_path())
        key = os.environ.get("AGENTMAIL_API_KEY")
        base = os.environ.get("AGENTMAIL_BASE_URL", DEFAULT_BASE_URL)

        if not platform:
            files = sorted(CONFIG_DIR.glob("*.env"))
            if len(files) != 1:
                raise AgentMailError(
                    "cannot infer the platform: set AGENTMAIL_PLATFORM (or pass platform=). "
                    f"Found {len(files)} credential files in {CONFIG_DIR}.")
            platform = files[0].stem

        if not key:
            path = CONFIG_DIR / f"{platform}.env"
            try:
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k == "AGENTMAIL_API_KEY":
                        key = v.strip()
                    elif k == "AGENTMAIL_BASE_URL":
                        base = v.strip()
            except FileNotFoundError:
                raise AgentMailError(
                    f"no credential for {platform!r}: set AGENTMAIL_API_KEY or install "
                    f"{path}. See deploy/install-agent-inbox-keys.sh in rodmena-mail-api."
                ) from None

        if not key:
            raise AgentMailError(f"no AGENTMAIL_API_KEY found for platform {platform!r}")
        return cls(platform, key, base_url=base, **kw)

    # -- HTTP ----------------------------------------------------------------------------
    def _request(self, method: str, path: str, **kw: Any) -> Any:
        with httpx.Client(timeout=self._timeout) as c:
            r = c.request(method, f"{self._base}{path}",
                          headers={"Authorization": f"Bearer {self._key}"}, **kw)
        if r.status_code >= 400:
            raise AgentMailError(f"{method} {path} -> {r.status_code}: {r.text[:200]}")
        return r.json() if r.content else None

    # -- reading -------------------------------------------------------------------------
    def inbox(self, limit: int = 50, mark_seen: bool = False) -> list[Message]:
        """Unconsumed, authentic messages, oldest first.

        A message is returned only if it passes `_reject_reason` — a registered sender with
        no failed verification verdict. Everything else goes to `quarantined()` and is never
        handed to the agent, because an agent that reads attacker-controlled text is an agent
        an attacker can instruct.

        AT-LEAST-ONCE. This used to mark every returned message seen immediately, which
        acknowledged delivery before the work was durable anywhere: an agent whose session
        died, was compacted, or was interrupted between the poll and acting on what it read
        lost that message permanently. Delivery is now consumed only when the caller says so
        — `done()`, or a successful `reply()`, which is proof of handling. A message is
        therefore re-delivered until it is dealt with; the reply-once guard is what stops
        that turning into duplicate answers.
        """
        # unconsumed=true asks the SERVER what is outstanding. The local seen-list is now a
        # cache in front of that, not the record itself: it used to be the only record, so a
        # second machine — or this one after losing the file — was handed the whole retention
        # window as unread (R5-29 / mail-api #218).
        # #358: reconcile before listing. An agent that polls at all repairs its own
        # divergence, so a blip during one session does not leave the server holding a phantom
        # backlog for the rest of the retention window.
        self.retry_pending_acks()

        listing = self._request(
            "GET", f"/api/v1/inbound?limit={int(limit)}&unconsumed=true") or {}
        rows = listing.get("inbound", []) if isinstance(listing, dict) else listing

        out: list[Message] = []
        for row in reversed(rows):                       # API is newest-first; act oldest-first
            inbound_id = row.get("inbound_id")
            if not inbound_id or self._state.is_seen(inbound_id):
                continue

            reason = self._reject_reason(row)
            if reason:
                self._quarantine.append(Quarantined(
                    inbound_id, row.get("from_addr"), row.get("subject") or "", reason))
                self._state.mark_seen(inbound_id)
                continue

            detail = self._request("GET", f"/api/v1/inbound/{inbound_id}") or {}
            msg = self._to_message(row, detail.get("inbound", detail))

            # A note addressed to a DIFFERENT co-resident agent is not ours to read. Skip it
            # WITHOUT marking it seen: our seen-set is per-agent, so leaving it untouched is
            # what lets the agent it was addressed to still receive it. Marking it here is
            # exactly the bug per-agent state exists to prevent.
            if not P.note_is_for(msg.to_agent, self.agent):
                continue

            self._state.extend_chain(msg.thread_id, msg.message_id)
            out.append(msg)
            if mark_seen:
                self._state.mark_seen(inbound_id)

        self._state.save()
        return out

    def thread(self, thread_id: str, limit: int = 200) -> list[Message]:
        """All messages in a thread, oldest first.

        Fetches inbound messages filtered by ``recipient_tag`` (the plus-addressing tag that
        carries the thread id). Each message is verified for authenticity just like ``inbox()``;
        anything that fails is quarantined and skipped.
        """
        listing = self._request(
            "GET", f"/api/v1/inbound?recipient_tag={thread_id}&limit={int(limit)}&unconsumed=false"
        ) or {}
        rows = listing.get("inbound", []) if isinstance(listing, dict) else listing

        out: list[Message] = []
        for row in reversed(rows):                       # API is newest-first; return oldest-first
            inbound_id = row.get("inbound_id")
            if not inbound_id:
                continue

            reason = self._reject_reason(row)
            if reason:
                self._quarantine.append(Quarantined(
                    inbound_id, row.get("from_addr"), row.get("subject") or "", reason))
                continue

            detail = self._request("GET", f"/api/v1/inbound/{inbound_id}") or {}
            msg = self._to_message(row, detail.get("inbound", detail))
            out.append(msg)

        return out

    def sent(self, limit: int = 50, recipient: str | None = None,
             since: str | None = None, message_id: str | None = None) -> list["Sent"]:
        """What this platform has SENT, from its own sent folder (mail-api #257).

        The outbound mirror of inbox(): a durable, server-side record of every send — the
        answer to 'did I send X?'. Metadata only (track_id, recipients, subject, sending
        identity, status, timestamp); the API never returns bodies here, so the folder can
        prove a send without re-reading its content.

        A dispute like the ones that motivated #257 ('I sent it' / 'I never received it')
        is resolvable from the product's own interface: both sides now have a server-side
        record — inbox() on the receiving side, sent() on the sending side.
        """
        query = f"limit={int(limit)}"
        if recipient:
            query += f"&recipient={quote(recipient)}"
        if since:
            query += f"&since={quote(since)}"
        if message_id:
            query += f"&message_id={quote(message_id)}"
        listing = self._request("GET", f"/api/v1/sent?{query}") or {}
        rows = listing.get("sent", []) if isinstance(listing, dict) else listing
        return [Sent(
            track_id=row.get("track_id") or "",
            to=list(row.get("to_addrs") or []),
            subject=row.get("subject"),
            from_addr=row.get("from_addr"),
            status=row.get("status") or "",
            created_at=row.get("created_at"),
            email_type=row.get("email_type"),
        ) for row in rows]

    #: Verification verdicts. An EXPLICIT failure is disqualifying; absence is not.
    _VERDICTS = ("dmarc", "dkim", "spf")

    @classmethod
    def _reject_reason(cls, row: dict[str, Any]) -> str | None:
        """Decide whether a message is genuinely from the platform it claims to be.

        Two conditions, and the reasoning behind the second one matters because it is the
        whole security model of the bus.

        1. The sender must be a REGISTERED platform address. mail-api forces the From header
           to the sending tenant's own client_key (`api/send.py`), so no tenant — free or
           otherwise — can put another platform's address there. A stranger who signs up for
           a freepass key sends as `their-key@…`, never as `tokengate@…`.

        2. No verification verdict may be an explicit FAIL.

        WHY NOT "dkim MUST equal pass" (the obvious rule, and the one this originally used):
        measured on the live system, a message sent from one tenant to another is delivered
        by a LOCAL pipe, and the OpenDKIM/OpenDMARC milters are attached to `smtpd`. Internal
        mail therefore never acquires a verdict at all — spf/dkim/dmarc are all NULL — so
        requiring `dkim == "pass"` quarantines every legitimate message on the bus. Verified
        live 2026-07-26:

            genuine internal :  spf=None dkim=None dmarc=None
            forged external  :  spf=None dkim=None dmarc=FAIL   <- OpenDMARC caught it

        The forgery was a real SMTP conversation to the public listener with
        `From: tokengate@mail.rodmena.co.uk`. External mail must traverse `smtpd`, which is
        where the milters live, so it cannot avoid being evaluated — and our domain publishes
        DMARC, so an unaligned From is always judged.

        RESIDUAL RISK, stated rather than hidden: this accepts NULL verdicts, so if OpenDMARC
        ever stops stamping (milter down, misconfiguration), an external forgery would become
        indistinguishable from internal mail. The structural fix is to reject external mail
        claiming a From in our own domain at the MTA, which is tracked separately — this
        client cannot enforce it from where it sits.
        """
        for name in cls._VERDICTS:
            verdict = (row.get(name) or "").strip().lower()
            if verdict == "fail":
                return f"{name}=fail — the sender could not prove it is {row.get('from_addr')!r}"
        if not is_registered(row.get("from_addr")):
            return f"sender {row.get('from_addr')!r} is not a registered platform"
        return None

    def _to_message(self, row: dict[str, Any], detail: dict[str, Any]) -> Message:
        meta, text = P.decode_body(detail.get("text_body") or detail.get("html_body") or "")

        # Thread id, most trustworthy source first: the plus-tag is set by the mail system
        # from the envelope and cannot be edited by the body, whereas front matter is just
        # text. A message with neither is a new topic, so it anchors on its own message-id.
        thread = (row.get("recipient_tag")
                  or meta.get("thread")
                  or row.get("message_id")
                  or row.get("inbound_id"))

        # Default to 'report' rather than something inert: an unlabelled or malformed message
        # is then surfaced to the agent as needing an answer, instead of being quietly
        # classified as an 'ack' that the loop guard refuses to reply to.
        mtype = (meta.get("type") or "report").strip().lower()

        return Message(
            inbound_id=row["inbound_id"],
            from_addr=row.get("from_addr") or "",
            sender=platform_of(row.get("from_addr")) or "",
            subject=row.get("subject") or "",
            body=text,
            message_id=row.get("message_id"),
            in_reply_to=row.get("in_reply_to"),
            thread_id=str(thread),
            type=mtype if mtype in P.TYPES else "report",
            severity=meta.get("severity"),
            ref=meta.get("ref"),
            received_at=str(row.get("received_at") or ""),
            dkim=(row.get("dkim") or ""),
            spf=row.get("spf"),
            dmarc=row.get("dmarc"),
            agent=(P.sanitise_agent(meta.get("agent", "")) or None),
            to_agent=(P.sanitise_agent(meta.get("to-agent", "")) or None),
            raw={**row, **detail},
        )

    def get(self, inbound_id: str) -> Message | None:
        """Fetch one message by id, applying the same authenticity check as inbox().

        `reply` needs this because inbox() marks messages seen, so a second process (or a
        later CLI invocation) cannot get the object back from the seen-list. Re-fetching and
        re-verifying is the correct answer anyway: the guard must apply on every path that
        can hand a message to the agent, not only the polling one.
        """
        detail = self._request("GET", f"/api/v1/inbound/{inbound_id}") or {}
        row = detail.get("inbound", detail)
        if not row or not row.get("inbound_id"):
            return None
        reason = self._reject_reason(row)
        if reason:
            self._quarantine.append(Quarantined(
                inbound_id, row.get("from_addr"), row.get("subject") or "", reason))
            return None
        return self._to_message(row, row)

    def done(self, msg: "Message | str") -> bool:
        """Mark a message consumed so it stops being re-delivered, on EVERY machine.

        Returns True if the SERVER acked it, False if the ack failed and it was queued for
        retry instead (#363). False is not data loss — the queue drains on the next poll —
        but it is not completion either, and a caller must be able to tell.

        Call this when the work it describes is durable — a ticket opened, a fix committed, a
        reply sent. `reply()` calls it for you, since answering is proof of handling.

        The server ack is the authoritative record; the local file is a cache kept in step so
        an unreachable mail-api degrades to the old single-machine behaviour rather than
        re-delivering everything. A failed ack is logged, not raised: the caller has already
        finished the work, and turning that into an exception would make a network blip look
        like a processing failure.
        """
        inbound_id = msg if isinstance(msg, str) else msg.inbound_id
        acked = True
        try:
            self._request("POST", f"/api/v1/inbound/{inbound_id}/ack")
            self._state.clear_pending_ack(inbound_id)
        except AgentMailError as e:
            acked = False
            # #358. Do NOT stop at a log line. This used to mark the message seen and move on,
            # which turned a transient blip into a permanent, silent divergence: invisible to
            # this agent forever, outstanding on the server forever, and `consumed_at` (added
            # in #231 so an operator can answer "did anyone read this?") reporting never-read
            # for a message that was read and acted on. Measured on the live bus before this
            # fix: the client said 0 unconsumed while the server said 35.
            #
            # Still marked seen — the caller finished the work and must not be handed it twice
            # — but recorded so the next poll retries the ack and the two sides reconcile.
            logger.warning("agentmail_ack_failed id=%s: %s — queued for retry on the next "
                           "poll; `pending_acks()` shows the backlog", inbound_id, e)
            self._state.add_pending_ack(inbound_id)
        self._state.mark_seen(inbound_id)
        self._state.save()
        # #363: tell the caller whether the SERVER consumed it, or whether this was merely
        # queued. Returning None made "deferred" and "done" indistinguishable — the library
        # stopped swallowing the failure in #358, but every caller still reported success.
        return acked

    def backlog(self, limit: int = 200) -> dict[str, Any]:
        """Compare what THIS agent sees against what the server still holds (#361).

        The diagnostic for an ack divergence, and deliberately not `pending_acks()`: that only
        records failures since #358 shipped, so on a historical backlog it returns an empty,
        reassuring list — a check that cannot go red for the population being sought. RunFlow
        reported that back after following exactly that advice and concluding, wrongly, that
        they were unaffected.

        Two INDEPENDENT reads of one fact. Polling the same client twice is repetition, not
        corroboration; a divergence is only visible when the readers can disagree.

        Returns ids, not just counts (FR-BACK-2): two readers can agree on "7" while
        disagreeing about which seven, and only the ids tell an agent what to inspect.

        Purely diagnostic — consumes nothing (FR-BACK-4). `reconcile()` is the separate,
        explicit action.
        """
        listing = self._request(
            "GET", f"/api/v1/inbound?limit={int(limit)}&unconsumed=true") or {}
        # The key is `inbound`, NOT `messages`. Reading the wrong one returns an empty list
        # that looks exactly like a clean result — that mistake produced a confident "never
        # delivered" here for a message that had in fact been delivered.
        rows = listing.get("inbound", []) if isinstance(listing, dict) else listing

        diverged, visible, for_other_agent = [], [], []
        for r in rows:
            iid = r.get("inbound_id")
            if not iid:
                continue
            entry = {"inbound_id": iid, "from": r.get("from_addr"),
                     "subject": r.get("subject") or "", "received_at": r.get("received_at")}
            # Seen locally but still outstanding server-side == handled here, never acked there.
            if self._state.is_seen(iid):
                diverged.append(entry)
                continue
            # #366: a note addressed to a DIFFERENT co-resident agent is outstanding on
            # purpose — inbox() withholds it, deliberately without marking it seen, so it
            # still reaches the agent it was for. Counting it as visible made `backlog` and
            # `inbox` disagree (1 vs 0) with no way for the reader to tell why, which is the
            # confusion this command exists to remove.
            #
            # Only a message from our OWN address can be a note, so the detail fetch that
            # reads the front matter is limited to those rather than every row.
            target = self._note_addressee(r)
            if target is not None and not P.note_is_for(target, self.agent):
                entry["to_agent"] = target
                for_other_agent.append(entry)
            else:
                visible.append(entry)

        return {
            # Equal to what inbox() would hand this agent (FR-BACK-8), so the two commands
            # reconcile by construction rather than by the reader's inference.
            "agent_sees": len(visible),
            "server_unconsumed": len(rows),
            "diverged": diverged,
            "for_other_agent": for_other_agent,
            "pending_acks": self._state.pending_acks(),
        }

    def _note_addressee(self, row: dict[str, Any]) -> str | None:
        """The `to-agent` of a note, or None if this is not an addressed note (#366).

        Returns None cheaply for ordinary bus traffic: only a message from our own platform
        address can be a self-note, so nothing else costs a request. A failed lookup also
        returns None, which classifies the row as visible — the safe direction, since showing
        a message that might not be ours beats hiding one that is.
        """
        if (row.get("from_addr") or "").strip().lower() != self.address.lower():
            return None
        try:
            detail = self._request("GET", f"/api/v1/inbound/{row['inbound_id']}") or {}
        except AgentMailError:
            return None
        body = detail.get("inbound", detail)
        meta, _ = P.decode_body(body.get("text_body") or body.get("html_body") or "")
        return P.sanitise_agent(meta.get("to-agent", "")) or None

    def reconcile(self) -> int:
        """Ack the diverged messages — those this agent has ALREADY seen. Returns the count.

        Never touches a message the agent has not been shown (FR-BACK-5): setting
        `consumed_at` on something unread replaces a visible problem with an invisible one,
        which is strictly worse than the backlog it would tidy away.
        """
        acked = 0
        for entry in self.backlog()["diverged"]:
            try:
                self._request("POST", f"/api/v1/inbound/{entry['inbound_id']}/ack")
                acked += 1
            except AgentMailError as e:
                logger.warning("agentmail_reconcile_failed id=%s: %s", entry["inbound_id"], e)
        return acked

    def pending_acks(self) -> list[str]:
        """Messages consumed locally whose server ack has not yet succeeded (#358).

        Non-empty means this agent and the server disagree about what is outstanding. Exposed
        rather than only logged, because a warning written to a logger nobody greps is not
        observability — that is exactly how the original divergence went unnoticed.
        """
        return self._state.pending_acks()

    def retry_pending_acks(self) -> int:
        """Re-attempt every queued ack. Returns how many are still outstanding afterwards.

        Called at the top of `inbox()`, so an agent that polls at all self-heals. An ack that
        fails again stays queued (FR-ACK-4) rather than being dropped — dropping it would
        recreate the exact silent loss this fix exists to remove.
        """
        for inbound_id in self._state.pending_acks():
            try:
                self._request("POST", f"/api/v1/inbound/{inbound_id}/ack")
                self._state.clear_pending_ack(inbound_id)
            except AgentMailError:
                pass                       # keep it queued; the next poll tries again
        self._state.save()
        return len(self._state.pending_acks())

    def quarantined(self) -> list[Quarantined]:
        """Messages rejected this session. Worth logging: a spike means someone is probing."""
        return list(self._quarantine)

    # -- writing -------------------------------------------------------------------------
    def note(self, subject: str, body: str, *, to_agent: str | None = None,
             ref: str | None = None, thread_id: str | None = None) -> str:
        """Leave a note for another coding agent working in THIS repository.

        Two agents in one checkout share a bus identity, so a note is simply a message this
        platform sends to itself: it goes out through mail-api and arrives in this same
        inbox, where `inbox()` hands it to the addressed agent. Verified end to end on the
        live system — a self-addressed message is delivered and readable, it is not
        short-circuited or suppressed as a loop.

        `to_agent` is the other agent's name (`AGENTMAIL_AGENT` on their side). Omit it to
        leave a note for whoever reads next, which is the useful default for a handover.

        WHAT THIS IS FOR: durable handovers that must outlive a session — what you changed,
        what you were part-way through, what you deliberately did not do. It is NOT a chat
        channel. Delivery goes out over SMTP and back in through the inbound pipe, so it
        takes seconds, not milliseconds, and every note is permanently retained and readable
        by a human. If the two agents can simply share a file in the working copy, do that
        instead; use a note when you want it timestamped, attributable and durable.

        ATTRIBUTION IS A LABEL, NOT A FACT (#387, ledger's misattributed-note report). The
        sending agent name is whatever this process was configured with — like `to_agent`
        it rides in forgeable front matter, and NO client-side check can bind it: two
        co-resident agents share one API key, one unix user and one checkout, so anything
        the client verified, a misconfigured (or lying) session could satisfy identically.
        The CLI therefore echoes the acting identity on every emission so a wrong
        AGENTMAIL_AGENT is visible the moment it speaks; if a record needs attribution that
        can survive dispute — an audit trail — put it in the artifact (a signed commit, a
        ticket entry), never in a message envelope.
        """
        return self.send(self.platform, subject, body, type="note",
                         ref=ref, thread_id=thread_id, to_agent=to_agent)

    def notes(self, limit: int = 50) -> list["Message"]:
        """Unconsumed notes addressed to this agent, oldest first. A view over `inbox()`."""
        return [m for m in self.inbox(limit=limit, mark_seen=False) if m.is_note]

    def send(self, to: str, subject: str, body: str, *, type: str = "report",
             severity: str | None = None, ref: str | None = None,
             thread_id: str | None = None, to_agent: str | None = None) -> str:
        """Start a new topic. Returns the thread id.

        Sets `self.opener_warnings` to any advisory shortcomings in the body (see
        `protocol.opener_shortcomings`). A thread-opener has to stand on its own — the reader
        is a different agent in a different repo who cannot see your terminal — and a thin one
        costs a full round trip between two poll-driven agents. These are heuristics, so they
        NEVER block the send: being wrong about a short report must not stop someone
        reporting a live defect.
        """
        mtype = P.validate_type(type)
        self.opener_warnings = P.opener_shortcomings(body, mtype)
        for w in self.opener_warnings:
            logger.warning("agentmail_thin_opener to=%s: %s", to, w)
        sev = P.validate_severity(severity)
        thread = thread_id or _new_thread_id()

        headers = {
            P.H_AUTO: P.AUTO_SUBMITTED,
            P.H_THREAD: thread,
            P.H_TYPE: mtype,
        }
        if sev:
            headers[P.H_SEVERITY] = sev
        if ref:
            headers[P.H_REF] = ref

        # The thread id rides in the address (persisted as recipient_tag); the rest rides in
        # the body. The X- headers go too, but only a human's mail client will ever see them.
        track_id = self._post(
            P.thread_address(address_of(to), thread), subject,
            P.encode_body(body, msg_type=mtype, thread_id=thread, severity=sev, ref=ref,
                          agent=self.agent, to_agent=to_agent),
            headers)
        self._state.extend_chain(thread, _message_id_for(track_id))
        self._state.save()
        return thread

    def reply(self, msg: Message, body: str, *, type: str = "ack",
              severity: str | None = None, ref: str | None = None) -> str | None:
        """Answer a message, or refuse with a reason.

        Returns the thread id on success, None if the protocol forbade the reply. Refusing is
        not an error — it is the loop guard doing its job — so callers can simply check for
        None rather than catching.
        """
        mtype = P.validate_type(type)
        sev = P.validate_severity(severity)

        if self._state.has_replied(msg.message_id):
            return None
        allowed, why = P.may_reply_to(msg.type, self._state.depth(msg.thread_id))
        if not allowed:
            return None

        chain = self._state.chain(msg.thread_id)
        headers = {
            P.H_AUTO: P.AUTO_SUBMITTED,
            P.H_THREAD: msg.thread_id,
            P.H_TYPE: mtype,
        }
        if msg.message_id:
            headers["In-Reply-To"] = msg.message_id
        if chain:
            # RFC 5322: parent's References plus the parent's Message-ID. mail-api does not
            # persist inbound References, so this chain is reconstructed from local state.
            headers["References"] = " ".join(chain[-10:])
        if sev:
            headers[P.H_SEVERITY] = sev
        if ref:
            headers[P.H_REF] = ref

        track_id = self._post(
            P.thread_address(msg.from_addr, msg.thread_id),
            P.reply_subject(msg.subject),
            P.encode_body(body, msg_type=mtype, thread_id=msg.thread_id,
                          severity=sev, ref=ref, agent=self.agent,
                          # A reply to a note goes back to whoever wrote it, so the thread
                          # stays between those two agents instead of leaking to the platform.
                          to_agent=(msg.agent if msg.is_note else None)),
            headers)
        self._state.mark_replied(msg.message_id)
        self.done(msg)                             # answering IS consuming
        self._state.extend_chain(msg.thread_id, _message_id_for(track_id))
        self._state.save()
        return msg.thread_id

    def why_refused(self, msg: Message) -> str:
        """Explain what `reply()` would refuse, for logging."""
        if self._state.has_replied(msg.message_id):
            return "already replied to this message once"
        allowed, why = P.may_reply_to(msg.type, self._state.depth(msg.thread_id))
        return "" if allowed else why

    def _post(self, to_addr: str, subject: str, body: str,
              headers: dict[str, str]) -> str:
        resp = self._request("POST", "/api/v1/emails", json={
            "to": [to_addr],
            "subject": subject,
            "text": body,
            "headers": headers,
        })
        return (resp or {}).get("track_id", "")


def _new_thread_id() -> str:
    import uuid
    return f"thr-{uuid.uuid4().hex[:20]}"


def _message_id_for(track_id: str) -> str | None:
    """mail-api stamps Message-ID as <track_id@mail.rodmena.co.uk>."""
    return f"<{track_id}@mail.rodmena.co.uk>" if track_id else None
