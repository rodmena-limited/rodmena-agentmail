"""Notes between two coding agents sharing one repository (#356).

The bug these guard against is not "notes don't send" — it is the SILENT one: two agents in
one checkout shared a single state file, so whichever polled first marked a message seen and
the other never saw it. An inbox that swallowed your mail looks exactly like an inbox with no
mail, which is why this needs a test rather than a manual check.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentmail import protocol as P
from agentmail.state import State


# -- addressing ---------------------------------------------------------------------------

def test_unaddressed_note_reaches_every_agent():
    # A handover note with no addressee must not vanish just because the reader has a name.
    assert P.note_is_for(None, "alice")
    assert P.note_is_for("", "alice")
    assert P.note_is_for(None, None)


def test_broadcast_star_reaches_everyone():
    # '*' sanitises to "", which is what implements broadcast. Asserted explicitly because
    # the mechanism is indirect enough to be broken by a "tidy-up" of sanitise_agent.
    assert P.sanitise_agent(P.BROADCAST_AGENT) == ""
    assert P.note_is_for(P.BROADCAST_AGENT, "alice")


def test_addressed_note_is_withheld_from_other_agents():
    assert P.note_is_for("bob", "bob")
    assert not P.note_is_for("bob", "alice")
    # An unnamed agent must NOT receive mail addressed to a named one, or running without
    # AGENTMAIL_AGENT would silently drain the other agent's notes.
    assert not P.note_is_for("bob", None)


@pytest.mark.parametrize("raw,expected", [
    ("Bob", "bob"),                 # case-folded, so 'Bob' and 'bob' are one agent
    ("  bob  ", "bob"),
    # Dots are legal in a name, so '..' survives as TEXT — harmless, because the separators
    # are gone and the result is one filename component. Traversal is prevented by removing
    # '/', not by removing '.'; test_agent_name_cannot_escape_the_state_directory is the
    # assertion that the property actually holds.
    ("a/../../etc/passwd", "a-..-..-etc-passwd"),
    ("bob\nto-agent: alice", "bob-to-agent-alice"),  # cannot inject a second front-matter line
    ("", ""),
    ("...", ""),
    ("/", ""),
])
def test_agent_names_are_sanitised(raw, expected):
    assert P.sanitise_agent(raw) == expected


def test_agent_name_length_is_bounded():
    assert len(P.sanitise_agent("x" * 500)) == 40


# -- front matter -------------------------------------------------------------------------

def test_note_metadata_round_trips_through_the_body():
    # Front matter is the ONLY carrier that survives receipt — mail-api drops inbound X-
    # headers — so a break here loses the addressee silently.
    encoded = P.encode_body("handover", msg_type="note", thread_id="thr-1",
                            agent="alice", to_agent="bob")
    meta, text = P.decode_body(encoded)
    assert meta["agent"] == "alice"
    assert meta["to-agent"] == "bob"
    assert meta["type"] == "note"
    assert text == "handover"


def test_absent_agent_fields_are_omitted_not_blank():
    meta, _ = P.decode_body(P.encode_body("x", msg_type="report", thread_id="t"))
    assert "agent" not in meta and "to-agent" not in meta


def test_note_is_a_valid_type_and_is_repliable():
    assert "note" in P.TYPES
    assert P.validate_type("note") == "note"
    allowed, _ = P.may_reply_to("note", 0)
    assert allowed, "an agent must be able to answer a colleague's note"


# -- state isolation ----------------------------------------------------------------------

def test_each_agent_gets_its_own_state_file(tmp_path: Path):
    a = State("mail-api", tmp_path, agent="alice")
    b = State("mail-api", tmp_path, agent="bob")
    assert a.path != b.path

    a.mark_seen("01ABC")
    a.save()
    b_reloaded = State("mail-api", tmp_path, agent="bob")
    assert not b_reloaded.is_seen("01ABC"), (
        "alice consuming a message must not hide it from bob — this is the exact "
        "swallow-the-mail bug per-agent state exists to prevent")
    assert State("mail-api", tmp_path, agent="alice").is_seen("01ABC")


def test_unnamed_agent_keeps_the_original_state_path(tmp_path: Path):
    # Backwards compatibility: every existing platform runs without an agent name and must
    # keep reading the state file it already has, or all of them re-deliver their backlog.
    assert State("mail-api", tmp_path).path == tmp_path / "mail-api.json"
    assert State("mail-api", tmp_path, agent="alice").path == tmp_path / "mail-api@alice.json"


def test_agent_name_cannot_escape_the_state_directory(tmp_path: Path):
    # The name reaches a filename, so a traversal here would let one agent clobber another's
    # state — or anything else the process can write.
    s = State("mail-api", tmp_path, agent=P.sanitise_agent("../../evil"))
    assert s.path.parent == tmp_path
