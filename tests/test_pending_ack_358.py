"""A failed server ack must be retried, not silently swallowed (#358).

Found on the live bus: `agentmail inbox` said 0 unconsumed while
`GET /api/v1/inbound?unconsumed=true` said 35. Thirty-four of those were in the local
seen-cache — read and acted on in earlier sessions — but had `consumed_at = None` on the
server, so they were invisible here forever and outstanding there forever.

The old `done()` caught the ack failure, logged a warning, and marked the message seen
anyway. Not raising was right; marking seen with no retry was the defect.
"""
from __future__ import annotations

import pytest

from agentmail.client import AgentMail, AgentMailError, Message


class _Client(AgentMail):
    """AgentMail with the HTTP layer replaced, so acks can be made to fail on demand."""

    def __init__(self, tmp_path, *, fail_acks=False):
        super().__init__("mail-api", "key-not-used", state_dir=tmp_path)
        self.fail_acks = fail_acks
        self.ack_calls: list[str] = []

    def _request(self, method, path, **kw):
        if path.endswith("/ack"):
            self.ack_calls.append(path)
            if self.fail_acks:
                raise AgentMailError("simulated network blip")
            return {"ok": True}
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": []}
        return {}


@pytest.fixture
def msg():
    return Message(
        inbound_id="01ABC", from_addr="futex@mail.rodmena.co.uk", sender="futex",
        subject="s", body="b", message_id="<m@x>", in_reply_to=None, thread_id="thr-1",
        type="report", severity=None, ref=None, received_at="", dkim="",
    )


# -- the failing direction -----------------------------------------------------------------

def test_failed_ack_is_queued_not_swallowed(tmp_path, msg):
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    assert c.pending_acks() == ["01ABC"], "a failed ack must leave a reconcilable record"
    # Still seen: the caller finished the work and must not be handed it twice.
    assert c._state.is_seen("01ABC")


def test_failed_ack_survives_a_restart(tmp_path, msg):
    """The divergence outlived sessions in the real incident, so the record must too."""
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    assert _Client(tmp_path).pending_acks() == ["01ABC"]


# -- the recovering direction (the half that was missing) ----------------------------------

def test_successful_ack_leaves_no_pending_record(tmp_path, msg):
    c = _Client(tmp_path)
    c.done(msg)
    assert c.pending_acks() == []
    assert c.ack_calls == ["/api/v1/inbound/01ABC/ack"]


def test_next_poll_retries_and_clears_the_backlog(tmp_path, msg):
    """FR-ACK-3: an agent that polls at all self-heals."""
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    assert c.pending_acks() == ["01ABC"]

    c.fail_acks = False
    c.inbox()                                  # the poll is what reconciles
    assert c.pending_acks() == [], "a recovered server must clear the backlog"
    assert "/api/v1/inbound/01ABC/ack" in c.ack_calls


def test_retry_that_fails_again_stays_queued(tmp_path, msg):
    """FR-ACK-4: dropping it would recreate the exact silent loss being fixed."""
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    assert c.retry_pending_acks() == 1
    assert c.pending_acks() == ["01ABC"]


def test_retry_is_idempotent_across_many_polls(tmp_path, msg):
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    for _ in range(5):
        c.retry_pending_acks()
    assert c.pending_acks() == ["01ABC"], "no duplicate entries"


def test_pending_acks_is_bounded(tmp_path):
    """FR-ACK-4: a long outage must not grow the state file without limit."""
    from agentmail.state import _MAX_PENDING_ACK, State
    s = State("mail-api", tmp_path)
    for i in range(_MAX_PENDING_ACK + 50):
        s.add_pending_ack(f"id-{i}")
    s.save()
    assert len(State("mail-api", tmp_path).pending_acks()) == _MAX_PENDING_ACK
