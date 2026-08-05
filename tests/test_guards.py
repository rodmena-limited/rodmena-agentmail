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

    acked: list[str] = []

    def fake(method, path, **kw):
        # Distinguish SENDING mail from ACKING it. reply() now does both -- it posts the
        # message and then acks the one it answered -- so counting every POST as "sent" made
        # a single reply look like two messages.
        if method == "POST" and path.endswith("/ack"):
            acked.append(path.split("/")[-2])
            return {"outcome": "consumed"}
        if method == "POST":
            sent.append(kw.get("json") or {})
            return {"track_id": f"01TRACK{len(sent):04d}"}
        return {}

    monkeypatch.setattr(client, "_request", fake)
    client.posted = sent          # type: ignore[attr-defined]
    client.acked = acked        # type: ignore[attr-defined]
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


def _inbox_of(am, monkeypatch, rows):
    def fake(method, path, **kw):
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": rows}
        return {"inbound": {**rows[0], "text_body": "hi"}}
    monkeypatch.setattr(am, "_request", fake)


def test_a_message_is_redelivered_until_it_is_marked_done(am, monkeypatch):
    """AT-LEAST-ONCE. Reading must not acknowledge delivery.

    This previously marked a message seen the moment it was returned, so an agent whose
    session died or was compacted between the poll and acting on it lost that message
    permanently — delivery acknowledged before the work was durable anywhere.
    """
    rows = [{"inbound_id": "ib-dup", "dkim": "pass",
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "s",
             "message_id": "<d@x>"}]
    _inbox_of(am, monkeypatch, rows)

    assert len(am.inbox()) == 1
    assert len(am.inbox()) == 1, "reading consumed the message before the caller was done"
    am.done("ib-dup")
    assert am.inbox() == [], "a message marked done was delivered again"


def test_replying_acks_server_side(am):
    """Consumption must reach the server, or another machine sees the message again."""
    msg = _msg(inbound_id="ib-ack")
    assert am.reply(msg, "on it", type="ack") is not None
    assert am.acked == ["ib-ack"], "reply consumed locally but never told the server"


def test_replying_consumes_the_message(am, monkeypatch):
    """Answering IS proof of handling, so it should not also need an explicit done()."""
    rows = [{"inbound_id": "ib-r", "dkim": "pass",
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "s",
             "message_id": "<r@x>"}]
    _inbox_of(am, monkeypatch, rows)
    msg = am.inbox()[0]

    sent: list[dict] = []
    monkeypatch.setattr(am, "_request", lambda m, p, **kw: (
        sent.append(kw.get("json") or {}) or {"track_id": "01T"}) if m == "POST"
        else ({"inbound": rows} if p.startswith("/api/v1/inbound?")
              else {"inbound": {**rows[0], "text_body": "hi"}}))

    assert am.reply(msg, "on it", type="ack") is not None
    assert am.inbox() == [], "a message that was answered came back"


def test_consume_mode_still_available(am, monkeypatch):
    """`mark_seen=True` keeps the old at-most-once behaviour for callers that want it."""
    rows = [{"inbound_id": "ib-c", "dkim": "pass",
             "from_addr": "runflow@mail.rodmena.co.uk", "subject": "s",
             "message_id": "<c@x>"}]
    _inbox_of(am, monkeypatch, rows)
    assert len(am.inbox(mark_seen=True)) == 1
    assert am.inbox() == []


# --- loop suppression: every one of these must REFUSE ------------------------------------

@pytest.mark.parametrize("terminal", ["ack", "close"])
def test_replying_to_a_terminal_type_is_refused(am, terminal):
    assert am.reply(_msg(type=terminal), "thanks!") is None
    assert am.posted == [], "a terminal-typed message was answered"
    assert terminal in am.why_refused(_msg(type=terminal))


def test_a_message_is_only_ever_replied_to_once(am):
    assert am.reply(_msg(), "first", type="ack") is not None
    assert am.reply(_msg(), "second", type="ack") is None
    assert len(am.posted) == 1


def test_reply_is_refused_past_the_depth_cap(am):
    msg = _msg(thread_id="thr-deep")
    for i in range(P.MAX_THREAD_DEPTH):
        am._state.extend_chain("thr-deep", f"<m{i}@x>")
    assert am.reply(msg, "still going") is None
    assert "cap" in am.why_refused(msg)


def test_every_outgoing_message_is_marked_auto_submitted(am):
    am.send("runflow", "Subject", "Body", type="report")
    assert am.posted[0]["headers"][P.H_AUTO] == P.AUTO_SUBMITTED


# --- threading ---------------------------------------------------------------------------

def test_reply_carries_in_reply_to_and_thread_routing(am):
    am.reply(_msg(), "on it", type="ack")
    sent = am.posted[0]
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


# --- thread-openers must stand on their own -----------------------------------------------

def test_a_thin_opener_is_flagged_but_still_sent(am):
    """Advisory, never blocking: being wrong about a short report must not block a real one."""
    thread = am.send("runflow", "broken", "your API is broken, please fix", type="report")
    assert thread, "a thin opener was refused; the check must warn, not block"
    assert am.posted, "nothing was sent"
    assert any("reproduction" in w for w in am.opener_warnings)


def test_a_self_contained_opener_is_not_flagged(am):
    body = ("RunFlow meters every run under runflow:* subjects.\n\n"
            "Reproduction:\n"
            "    $ curl -s -o /dev/null -w '%{http_code}' -X POST .../v1/consume\n"
            "    429\n\n"
            "Expected 200 per /llms.txt; the burst limit should release after the advertised "
            "6s cooldown. Observed: still 429 after 60s. Started ~2026-07-25 midday.")
    am.send("runflow", "Burst limit never releases", body, type="report")
    assert am.opener_warnings == []


def test_terminal_types_are_exempt_from_opener_checks(am):
    """An ack is meant to be one line; warning about it would train agents to ignore warnings."""
    from agentmail import protocol as P
    assert P.opener_shortcomings("ok", "ack") == []
    assert P.opener_shortcomings("done", "close") == []


# --- thread history -----------------------------------------------------------------------

def test_thread_returns_messages_filtered_by_tag(am, monkeypatch):
    """`am.thread(thr-id)` fetches inbound messages filtered by recipient_tag."""
    thread_id = "thr-test"
    rows = [
        # API returns newest-first; second message is newer than first
        {"inbound_id": "ib-t2", "recipient_tag": thread_id, "from_addr": "runflow@mail.rodmena.co.uk",
         "subject": "Second", "message_id": "<m2@x>", "dkim": "pass"},
        {"inbound_id": "ib-t1", "recipient_tag": thread_id, "from_addr": "runflow@mail.rodmena.co.uk",
         "subject": "First",  "message_id": "<m1@x>", "dkim": "pass"},
        {"inbound_id": "ib-other", "recipient_tag": "thr-other", "from_addr": "runflow@mail.rodmena.co.uk",
         "subject": "Other",  "message_id": "<m3@x>", "dkim": "pass"},
    ]

    calls = []
    def fake(method, path, **kw):
        calls.append(path)
        if "recipient_tag=" in path:
            tag = path.split("recipient_tag=")[1].split("&")[0]
            matching = [r for r in rows if r.get("recipient_tag") == tag]
            return {"inbound": matching}
        return {"inbound": {**rows[0], "text_body": f"body-{path.split('/')[-1]}"}}
    monkeypatch.setattr(am, "_request", fake)

    got = am.thread(thread_id)
    assert len(got) == 2, "only messages matching the thread tag should be returned"
    assert got[0].subject == "First", "messages should be oldest-first"
    assert got[1].subject == "Second"
    assert all(m.thread_id == thread_id for m in got)
    assert all(m.sender == "runflow" for m in got)


def test_thread_with_quarantined_message(am, monkeypatch):
    """A message that fails verification in thread() is quarantined, not returned."""
    rows = [
        {"inbound_id": "ib-q", "recipient_tag": "thr-q", "from_addr": "unregistered@evil.example",
         "subject": "Bad", "message_id": "<b@x>"},
    ]

    def fake(method, path, **kw):
        if "recipient_tag=" in path:
            return {"inbound": rows}
        return {"inbound": {**rows[0], "text_body": "body"}}
    monkeypatch.setattr(am, "_request", fake)

    got = am.thread("thr-q")
    assert got == [], "quarantined messages must not appear in thread output"
    assert len(am.quarantined()) == 1


def test_thread_with_no_messages(am, monkeypatch):
    """An empty thread returns an empty list, not an error."""
    def fake(method, path, **kw):
        return {"inbound": []}
    monkeypatch.setattr(am, "_request", fake)

    assert am.thread("thr-nonexistent") == []


# --- sent folder (#257): the outbound mirror of inbox() ---------------------------------

def test_sent_lists_outbound_sends(am, monkeypatch):
    """sent() must return the server's record of what THIS platform sent, parsed into
    the fields the sent folder promises (track_id, recipients, subject, identity,
    status, timestamp) — the answer to 'did I send X?'."""
    rows = [
        {"track_id": "01S1", "to_addrs": ["runflow@mail.rodmena.co.uk"],
         "subject": "Quota check", "from_addr": "tokengate@mail.rodmena.co.uk",
         "status": "sent", "created_at": "2026-08-02T00:00:00Z", "email_type": "report"},
        {"track_id": "01S2", "to_addrs": ["futex@mail.rodmena.co.uk"],
         "subject": "Usage numbers", "from_addr": "tokengate@mail.rodmena.co.uk",
         "status": "sent", "created_at": "2026-08-02T00:10:00Z", "email_type": "report"},
    ]
    calls: list[str] = []

    def fake(method, path, **kw):
        calls.append(path)
        return {"sent": rows}
    monkeypatch.setattr(am, "_request", fake)

    got = am.sent()
    assert [s.track_id for s in got] == ["01S1", "01S2"]
    assert got[0].to == ["runflow@mail.rodmena.co.uk"]
    assert got[0].subject == "Quota check"
    assert got[0].from_addr == "tokengate@mail.rodmena.co.uk"
    assert got[0].status == "sent"
    assert got[0].created_at == "2026-08-02T00:00:00Z"
    assert calls == ["/api/v1/sent?limit=50"], calls


def test_sent_passes_filters_through(am, monkeypatch):
    """recipient / since / message_id must reach the server as query parameters —
    a filter the client drops is a filter that silently answers the wrong question."""
    calls: list[str] = []

    def fake(method, path, **kw):
        calls.append(path)
        return {"sent": []}
    monkeypatch.setattr(am, "_request", fake)

    am.sent(recipient="runflow@mail.rodmena.co.uk",
            since="2026-08-01T00:00:00Z",
            message_id="01S1")
    assert calls == ["/api/v1/sent?limit=50"
                     "&recipient=runflow%40mail.rodmena.co.uk"
                     "&since=2026-08-01T00%3A00%3A00Z"
                     "&message_id=01S1"], calls


def test_sent_never_exposes_a_body(am, monkeypatch):
    """The sent folder must never hand the agent message content (#257 EARS) — the
    client must not even look for a body field, so an over-broad server response
    cannot silently become a content channel."""
    def fake(method, path, **kw):
        return {"sent": [{
            "track_id": "01S1", "to_addrs": ["r@example.com"], "subject": "s",
            "from_addr": "tokengate@mail.rodmena.co.uk", "status": "sent",
            "created_at": "2026-08-02T00:00:00Z",
            "text_body": "secret", "html_body": "<p>secret</p>",   # must be ignored
        }]}
    monkeypatch.setattr(am, "_request", fake)

    got = am.sent()
    assert got[0].track_id == "01S1"
    assert not hasattr(got[0], "body"), "Sent carries a body field"
    assert "secret" not in str(got), "a body leaked into the sent-folder record"
