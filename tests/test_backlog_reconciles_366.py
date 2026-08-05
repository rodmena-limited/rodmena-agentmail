"""`backlog` must reconcile with `inbox` (#366).

Observed live, same session, seconds apart: `backlog` reported "agent sees 1" while `inbox`
reported 0. The outstanding row was a note addressed to a co-resident agent — correctly
withheld by inbox(), and deliberately not marked seen so it still reaches its addressee — but
backlog() counted it as visible.

Neither number was wrong alone; together they were unresolvable, and #361 tells every platform
to run both. The diagnostic built to explain discrepancies had become a source of one.

FR-BACK-8 is the real assertion here: agent_sees must EQUAL what inbox() returns. These tests
compare the two directly rather than asserting a hardcoded number, because a constant would
still pass if both drifted together.
"""
from __future__ import annotations

import pytest

from agentmail.client import AgentMail


class _Client(AgentMail):
    """Rows plus their bodies, so front-matter addressing can be exercised."""

    def __init__(self, tmp_path, rows, bodies, *, agent=None):
        super().__init__("mail-api", "key-not-used", state_dir=tmp_path, agent=agent)
        self.rows = rows
        self.bodies = bodies
        self.detail_calls = 0

    def _request(self, method, path, **kw):
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": self.rows}
        if path.startswith("/api/v1/inbound/"):
            self.detail_calls += 1
            iid = path.rsplit("/", 1)[-1]
            return {"inbound": {"text_body": self.bodies.get(iid, "")}}
        return {}


def _note_body(to_agent: str | None, author: str = "bob") -> str:
    fm = ["--- agentmail v1 ---", "type: note", "thread: thr-1", f"agent: {author}"]
    if to_agent:
        fm.append(f"to-agent: {to_agent}")
    fm.append("--- end agentmail ---")
    return "\n".join(fm) + "\n\nhandover text"


def _row(iid, from_addr="mail-api@mail.rodmena.co.uk", subject="s"):
    return {"inbound_id": iid, "from_addr": from_addr, "subject": subject,
            "received_at": "2026-08-05T22:45:00Z"}


# -- the reconciliation itself -------------------------------------------------------------

def test_note_for_another_agent_is_not_counted_as_visible(tmp_path):
    """The exact live shape: bob -> alice, read by an UNNAMED session."""
    c = _Client(tmp_path, [_row("01ABC")], {"01ABC": _note_body("alice")})
    b = c.backlog()
    assert b["server_unconsumed"] == 1
    assert b["agent_sees"] == 0, "the agent will never be shown this message"
    assert len(b["for_other_agent"]) == 1
    assert b["for_other_agent"][0]["to_agent"] == "alice"
    assert b["diverged"] == [], "this is not an ack divergence"


@pytest.mark.parametrize("agent", [None, "carol"])
def test_agent_sees_equals_what_inbox_returns(tmp_path, agent):
    """FR-BACK-8 and NFR-BACK-2, for an unnamed agent and a named one.

    Compares the two code paths against each other rather than a constant — a hardcoded
    number would still pass if both drifted the same way.
    """
    rows = [_row("01FORALICE"), _row("01BROADCAST"),
            _row("01PEER", from_addr="futex@mail.rodmena.co.uk")]
    bodies = {"01FORALICE": _note_body("alice"),
              "01BROADCAST": _note_body(None),
              "01PEER": "plain peer report"}
    c = _Client(tmp_path, rows, bodies, agent=agent)

    b = c.backlog()
    inbox_len = len(c.inbox(mark_seen=False))
    assert b["agent_sees"] == inbox_len, (
        f"backlog says {b['agent_sees']} visible, inbox returns {inbox_len} — "
        f"the two commands must not disagree")


def test_note_addressed_to_me_is_visible(tmp_path):
    """The green direction: alice must still be shown her own note."""
    c = _Client(tmp_path, [_row("01ABC")], {"01ABC": _note_body("alice")}, agent="alice")
    b = c.backlog()
    assert b["agent_sees"] == 1
    assert b["for_other_agent"] == []


def test_unaddressed_note_is_visible_to_everyone(tmp_path):
    c = _Client(tmp_path, [_row("01ABC")], {"01ABC": _note_body(None)}, agent="carol")
    assert c.backlog()["agent_sees"] == 1


def test_divergence_still_detected_alongside_a_foreign_note(tmp_path):
    """FR-BACK-9: a note for someone else must not mask or inflate a real divergence."""
    c = _Client(tmp_path, [_row("01SEEN"), _row("01FORALICE")],
                {"01SEEN": "peer mail", "01FORALICE": _note_body("alice")})
    c._state.mark_seen("01SEEN")
    b = c.backlog()
    assert len(b["diverged"]) == 1 and b["diverged"][0]["inbound_id"] == "01SEEN"
    assert len(b["for_other_agent"]) == 1
    assert b["agent_sees"] == 0


# -- cost --------------------------------------------------------------------------------

def test_ordinary_peer_mail_costs_no_extra_request(tmp_path):
    """Only a message from our OWN address can be a self-note, so nothing else is fetched."""
    c = _Client(tmp_path, [_row("01P1", from_addr="futex@mail.rodmena.co.uk"),
                           _row("01P2", from_addr="runflow@mail.rodmena.co.uk")], {})
    c.backlog()
    assert c.detail_calls == 0


def test_unreadable_detail_classifies_as_visible(tmp_path):
    """Failing safe: showing a message that might not be ours beats hiding one that is."""
    class _Broken(_Client):
        def _request(self, method, path, **kw):
            if path.startswith("/api/v1/inbound/"):
                from agentmail.client import AgentMailError
                raise AgentMailError("detail unavailable")
            return super()._request(method, path, **kw)

    c = _Broken(tmp_path, [_row("01ABC")], {})
    assert c.backlog()["agent_sees"] == 1
