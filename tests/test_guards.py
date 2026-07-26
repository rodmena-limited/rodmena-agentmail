"""The guards are the product. These tests drive them to REFUSE.

Scope note, deliberately stated: these exercise the client's decision logic with the HTTP
layer stubbed. They prove the rules block what they must — they do NOT prove the wire format
works, because a stub cannot tell you that mail-api persists `recipient_tag` or drops X-
headers. That half is verified live against the running service; see
`tests/test_live_bus.py` and the end-to-end run recorded on ticket #215.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentmail import protocol as P                    # noqa: E402
from agentmail.client import AgentMail, Message        # noqa: E402


@pytest.fixture()
def am(tmp_path, monkeypatch):
    """A client for tokengate@ whose HTTP calls are recorded instead of sent."""
    client = AgentMail("tokengate", "test-key", state_dir=tmp_path)
    sent: list[dict] = []

    def fake(method, path, **kw):
        if method == "POST":
            sent.append(kw.get("json") or {})
            return {"track_id": f"01TRACK{len(sent):04d}"}
        return {}

    monkeypatch.setattr(client, "_request", fake)
    client.sent = sent          # type: ignore[attr-defined]
    return client


def _msg(**kw) -> Message:
    base = dict(
        inbound_id="ib-1", from_addr="runflow@mail.rodmena.co.uk", sender="runflow",
        subject="Quota check", body="text", message_id="<m1@mail.rodmena.co.uk>",
        in_reply_to=None, thread_id="thr-1", type="report", severity="high",
        ref=None, received_at="", dkim="pass",
    )
    base.update(kw)
    return Message(**base)


# --- authenticity: the agent must never even SEE an unverified message -------------------

@pytest.mark.parametrize("verdicts,from_addr,why", [
    # An explicit failure on ANY verdict is disqualifying. dmarc=fail is the one that
    # actually caught a live forgery: a real SMTP conversation to the public listener with
    # From: tokengate@mail.rodmena.co.uk was recorded as dmarc=fail (2026-07-26).
    ({"dmarc": "fail"}, "tokengate@mail.rodmena.co.uk", "forged external sender"),
    ({"dkim": "fail"},  "runflow@mail.rodmena.co.uk",   "dkim failed"),
    ({"spf": "fail"},   "runflow@mail.rodmena.co.uk",   "spf failed"),
    # Registry membership is the other half: mail-api forces From per tenant, so an
    # unregistered address is by definition not a platform.
    ({}, "attacker@evil.example",                "sender not registered"),
    ({}, "runflow@mail.rodmena.co.uk.evil.tld",  "suffix-lookalike domain"),
    ({}, None,                                   "no sender at all"),
])
def test_unverified_mail_is_quarantined_not_delivered(am, monkeypatch, verdicts, from_addr, why):
    rows = [{"inbound_id": "ib-x", "from_addr": from_addr,
             "subject": "hello", "message_id": "<x@y>", **verdicts}]

    def fake(method, path, **kw):
        return {"inbound": rows} if path.startswith("/api/v1/inbound?") else {"inbound": {}}
    monkeypatch.setattr(am, "_request", fake)

    assert am.inbox() == [], f"{why}: message reached the agent"
    assert len(am.quarantined()) == 1
    assert am.quarantined()[0].inbound_id == "ib-x"


def test_internal_mail_with_no_verdicts_is_delivered(am, monkeypatch):
    """Intra-server mail never touches the milters, so all three verdicts are NULL.

    Requiring dkim==pass (the original rule) quarantined every legitimate message on the bus.
    Measured live: genuine internal mail is spf/dkim/dmarc all None.
    """
    rows = [{"inbound_id": "ib-int", "spf": None, "dkim": None, "dmarc": None,
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "s",
             "message_id": "<i@x>", "recipient_tag": "thr-int"}]

    def fake(method, path, **kw):
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": rows}
        return {"inbound": {**rows[0], "text_body": "body"}}
    monkeypatch.setattr(am, "_request", fake)

    got = am.inbox()
    assert len(got) == 1 and got[0].sender == "runflow"


def test_authentic_mail_is_delivered(am, monkeypatch):
    body = P.encode_body("Burst limit releases correctly.", msg_type="report",
                         thread_id="thr-9", severity="med", ref="runflow#3")
    rows = [{"inbound_id": "ib-ok", "dkim": "pass",
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "Findings",
             "message_id": "<ok@mail.rodmena.co.uk>", "recipient_tag": "thr-9"}]

    def fake(method, path, **kw):
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": rows}
        return {"inbound": {**rows[0], "text_body": body}}
    monkeypatch.setattr(am, "_request", fake)

    got = am.inbox()
    assert len(got) == 1
    m = got[0]
    assert m.sender == "runflow" and m.type == "report" and m.severity == "med"
    assert m.thread_id == "thr-9"
    assert m.body == "Burst limit releases correctly."   # front matter stripped
    assert "agentmail v1" not in m.body


def test_a_seen_message_is_not_delivered_twice(am, monkeypatch):
    rows = [{"inbound_id": "ib-dup", "dkim": "pass",
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "s",
             "message_id": "<d@x>"}]

    def fake(method, path, **kw):
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": rows}
        return {"inbound": {**rows[0], "text_body": "hi"}}
    monkeypatch.setattr(am, "_request", fake)

    assert len(am.inbox()) == 1
    assert am.inbox() == [], "the same message was handed to the agent twice"


# --- loop suppression: every one of these must REFUSE ------------------------------------

@pytest.mark.parametrize("terminal", ["ack", "close"])
def test_replying_to_a_terminal_type_is_refused(am, terminal):
    assert am.reply(_msg(type=terminal), "thanks!") is None
    assert am.sent == [], "a terminal-typed message was answered"
    assert terminal in am.why_refused(_msg(type=terminal))


def test_a_message_is_only_ever_replied_to_once(am):
    assert am.reply(_msg(), "first", type="ack") is not None
    assert am.reply(_msg(), "second", type="ack") is None
    assert len(am.sent) == 1


def test_reply_is_refused_past_the_depth_cap(am):
    msg = _msg(thread_id="thr-deep")
    for i in range(P.MAX_THREAD_DEPTH):
        am._state.extend_chain("thr-deep", f"<m{i}@x>")
    assert am.reply(msg, "still going") is None
    assert "cap" in am.why_refused(msg)


def test_every_outgoing_message_is_marked_auto_submitted(am):
    am.send("runflow", "Subject", "Body", type="report")
    assert am.sent[0]["headers"][P.H_AUTO] == P.AUTO_SUBMITTED


# --- threading ---------------------------------------------------------------------------

def test_reply_carries_in_reply_to_and_thread_routing(am):
    am.reply(_msg(), "on it", type="ack")
    sent = am.sent[0]
    assert sent["headers"]["In-Reply-To"] == "<m1@mail.rodmena.co.uk>"
    assert sent["to"] == ["runflow+thr-1@mail.rodmena.co.uk"]
    assert sent["subject"] == "Re: Quota check"


def test_re_prefix_never_stacks():
    assert P.reply_subject("Re: Re: RE:  Deep thread") == "Re: Deep thread"
    assert P.reply_subject("Fresh") == "Re: Fresh"


def test_thread_tag_never_stacks():
    once = P.thread_address("tokengate@mail.rodmena.co.uk", "thr-a")
    assert P.thread_address(once, "thr-b") == "tokengate+thr-b@mail.rodmena.co.uk"


def test_front_matter_survives_a_round_trip():
    enc = P.encode_body("Body text.", msg_type="fix-notice", thread_id="thr-z",
                        severity="crit", ref="tokengate#14")
    meta, text = P.decode_body(enc)
    assert meta == {"type": "fix-notice", "thread": "thr-z",
                    "severity": "crit", "ref": "tokengate#14"}
    assert text == "Body text."


def test_a_human_written_message_still_reaches_the_agent():
    """No front matter is not an error — a person may just send prose."""
    meta, text = P.decode_body("Hi, your API is returning 500s.")
    assert meta == {} and text == "Hi, your API is returning 500s."


def test_unknown_type_and_severity_are_rejected_loudly():
    with pytest.raises(P.ProtocolError):
        P.validate_type("urgent-please-read")
    with pytest.raises(P.ProtocolError):
        P.validate_severity("apocalyptic")
