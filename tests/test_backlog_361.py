"""Self-diagnosing an ack divergence (#361).

#358 went unnoticed on three platforms at once for a structural reason: an agent can only see
what its own client shows it. mail-api held 34 diverged messages, RunFlow 12, RED9 4, and
every one was found either by a hand-written pair of ad-hoc commands or by mail-api noticing
from the operator side and writing to them. RED9: "I can only see what my client shows me, and
my client showed 2."

The point of `backlog()` is that the two reads can DISAGREE. A test that only proves it
returns numbers would miss the whole feature, so these assert on the disagreement.
"""
from __future__ import annotations

import pytest

from agentmail.client import AgentMail, AgentMailError


class _Client(AgentMail):
    def __init__(self, tmp_path, rows):
        super().__init__("mail-api", "key-not-used", state_dir=tmp_path)
        self.rows = rows
        self.acked: list[str] = []
        self.fail_acks = False

    def _request(self, method, path, **kw):
        if path.endswith("/ack"):
            if self.fail_acks:
                raise AgentMailError("simulated")
            self.acked.append(path.split("/")[-2])
            return {"ok": True}
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": self.rows}
        return {}


def _row(iid, subject="s"):
    return {"inbound_id": iid, "from_addr": "futex@mail.rodmena.co.uk",
            "subject": subject, "received_at": "2026-08-01T22:06:53Z"}


# -- detection: the readers must be able to disagree ---------------------------------------

def test_divergence_is_detected(tmp_path):
    """RED9's real shape: server holds 7, agent sees 2, 5 already seen locally."""
    rows = [_row(f"0{i}") for i in range(7)]
    c = _Client(tmp_path, rows)
    for i in range(5):
        c._state.mark_seen(f"0{i}")

    b = c.backlog()
    assert b["server_unconsumed"] == 7
    assert b["agent_sees"] == 2
    assert len(b["diverged"]) == 5


def test_diverged_entries_carry_ids_not_just_counts(tmp_path):
    """FR-BACK-2: two readers can agree on '7' while disagreeing about which seven."""
    c = _Client(tmp_path, [_row("01ABC", "runflow ack #87")])
    c._state.mark_seen("01ABC")
    d = c.backlog()["diverged"]
    assert d[0]["inbound_id"] == "01ABC"
    assert d[0]["subject"] == "runflow ack #87"
    assert d[0]["received_at"]


def test_agreement_reports_no_divergence(tmp_path):
    """The green direction. A detector proven only to fire is half tested."""
    c = _Client(tmp_path, [_row("01NEW")])
    b = c.backlog()
    assert b["diverged"] == []
    assert b["agent_sees"] == 1 == b["server_unconsumed"]


def test_empty_server_is_clean(tmp_path):
    b = _Client(tmp_path, []).backlog()
    assert b["server_unconsumed"] == 0 and b["diverged"] == []


def test_backlog_does_not_consume_anything(tmp_path):
    """FR-BACK-4: a diagnostic that mutates the state it measures destroys the evidence."""
    c = _Client(tmp_path, [_row("01ABC")])
    c._state.mark_seen("01ABC")
    c.backlog()
    assert c.acked == []


# -- reconcile: targeted, never blanket ----------------------------------------------------

def test_reconcile_acks_only_the_diverged(tmp_path):
    """FR-BACK-5. `01UNSEEN` has never been shown to the agent — acking it would set
    consumed_at on an unread message, turning a visible problem into an invisible one."""
    c = _Client(tmp_path, [_row("01SEEN"), _row("01UNSEEN")])
    c._state.mark_seen("01SEEN")

    assert c.reconcile() == 1
    assert c.acked == ["01SEEN"]
    assert "01UNSEEN" not in c.acked


def test_reconcile_with_nothing_diverged_is_a_no_op(tmp_path):
    c = _Client(tmp_path, [_row("01NEW")])
    assert c.reconcile() == 0
    assert c.acked == []


def test_reconcile_survives_an_ack_failure(tmp_path):
    """A failing server must not crash the diagnostic — it reports 0 acked, not an exception."""
    c = _Client(tmp_path, [_row("01SEEN")])
    c._state.mark_seen("01SEEN")
    c.fail_acks = True
    assert c.reconcile() == 0


def test_wrong_json_key_would_not_silently_pass(tmp_path):
    """The `inbound` vs `messages` trap: a response lacking `inbound` must read as zero rows,
    not as a crash, and must not be mistaken for a clean result by the caller."""
    class _Odd(_Client):
        def _request(self, method, path, **kw):
            if path.startswith("/api/v1/inbound?"):
                return {"messages": [_row("01ABC")]}      # the WRONG key
            return {}
    c = _Odd(tmp_path, [])
    b = c.backlog()
    assert b["server_unconsumed"] == 0, "wrong-key response must not be read as data"
