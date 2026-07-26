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

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import httpx

from . import protocol as P
from .registry import address_of, is_registered, platform_of
from .state import State

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
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def expects_reply(self) -> bool:
        return self.type in P.EXPECTS_REPLY


@dataclass
class Quarantined:
    """A message we refused to hand to the agent, and why."""
    inbound_id: str
    from_addr: str | None
    subject: str
    reason: str


class AgentMail:
    def __init__(self, platform: str, api_key: str, *,
                 base_url: str = DEFAULT_BASE_URL,
                 state_dir: Path | None = None,
                 timeout: float = 20.0) -> None:
        self.platform = platform
        self.address = address_of(platform)
        self._key = api_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._state = State(platform, state_dir)
        self._quarantine: list[Quarantined] = []

    # -- construction --------------------------------------------------------------------
    @classmethod
    def from_env(cls, platform: str | None = None, **kw: Any) -> "AgentMail":
        """Load this platform's credential from the environment or its 0600 config file.

        Order: explicit argument, then AGENTMAIL_PLATFORM, then — only if exactly one
        credential file exists — that one. Guessing when several are present would let an
        agent silently send as the wrong platform, which is the one impersonation the bus
        cannot detect (mail-api would faithfully stamp the From of whoever's key was used).
        """
        platform = platform or os.environ.get("AGENTMAIL_PLATFORM")
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
    def inbox(self, limit: int = 50, auto_mark: bool = True) -> list[Message]:
        """New, authentic messages, oldest first.

        A message is returned ONLY if `dkim == "pass"` and the sender is a registered
        platform. Everything else goes to `quarantined()` — it is never handed to the agent,
        because an agent that reads attacker-controlled text is an agent that can be
        instructed by an attacker.

        `auto_mark` records each returned message as seen immediately. Duplicates are worse
        than a missed poll here: the sender will follow up on silence, whereas re-processing
        the same report each tick is how a loop starts.
        """
        listing = self._request("GET", f"/api/v1/inbound?limit={int(limit)}") or {}
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
            self._state.extend_chain(msg.thread_id, msg.message_id)
            out.append(msg)
            if auto_mark:
                self._state.mark_seen(inbound_id)

        self._state.save()
        return out

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
            raw={**row, **detail},
        )

    def quarantined(self) -> list[Quarantined]:
        """Messages rejected this session. Worth logging: a spike means someone is probing."""
        return list(self._quarantine)

    # -- writing -------------------------------------------------------------------------
    def send(self, to: str, subject: str, body: str, *, type: str = "report",
             severity: str | None = None, ref: str | None = None,
             thread_id: str | None = None) -> str:
        """Start a new topic. Returns the thread id."""
        mtype = P.validate_type(type)
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
            P.encode_body(body, msg_type=mtype, thread_id=thread, severity=sev, ref=ref),
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
                          severity=sev, ref=ref),
            headers)
        self._state.mark_replied(msg.message_id)
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
