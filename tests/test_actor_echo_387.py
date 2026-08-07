"""Emission echoes the acting identity (#387 — ledger's misattributed-note report).

A session with the wrong AGENTMAIL_AGENT emitted a note attributed to a co-resident agent
that never wrote it, and nothing surfaced the mistake: the confirmation line named the
RECIPIENT but not the SPEAKER. The name is a client-side label that nothing can validate —
two co-resident agents share one key, one user, one checkout — so the only party who can
catch a wrong name is the operator reading the confirmation, at the moment of emission.

These tests pin: note/send/reply confirmations name the acting agent (or say UNNAMED),
and a note addressed to yourself warns (that shape is almost always a misconfigured
AGENTMAIL_AGENT).
"""
from __future__ import annotations

import pytest

import agentmail.cli as cli


class _StubAM:
    def __init__(self, agent: str | None):
        self.platform = "mail-api"
        self.address = "mail-api@mail.rodmena.co.uk"
        self.agent = agent
        self.opener_warnings: list[str] = []

    def note(self, subject, body, *, to_agent=None, ref=None):
        return "thr-test"

    def send(self, to, subject, body, *, type="report", severity=None, ref=None):
        return "thr-test"

    def get(self, inbound_id):
        class _Msg:
            sender = "ledger"
        return _Msg()

    def reply(self, msg, body, *, type=None, severity=None, ref=None):
        return "thr-test"


def _patched(monkeypatch, agent):
    am = _StubAM(agent)
    monkeypatch.setattr(cli.AgentMail, "from_env", staticmethod(lambda *a, **k: am))
    return am


def test_note_confirmation_names_the_acting_agent(monkeypatch, capsys):
    _patched(monkeypatch, "alice")
    assert cli.main(["note", "-s", "s", "-b", "body", "--to", "bob"]) == 0
    out = capsys.readouterr().out
    assert "note left by agent 'alice' for agent 'bob'" in out


def test_unnamed_agent_is_called_out_not_omitted(monkeypatch, capsys):
    """Silence about the identity is the original defect — UNNAMED must be said aloud."""
    _patched(monkeypatch, None)
    assert cli.main(["note", "-s", "s", "-b", "body"]) == 0
    out = capsys.readouterr().out
    assert "UNNAMED agent" in out and "whoever reads next" in out


def test_self_addressed_note_warns_about_misconfigured_identity(monkeypatch, capsys):
    _patched(monkeypatch, "alice")
    assert cli.main(["note", "-s", "s", "-b", "body", "--to", "alice"]) == 0
    captured = capsys.readouterr()
    assert "YOURSELF" in captured.err and "AGENTMAIL_AGENT" in captured.err
    assert "note left by agent 'alice'" in captured.out, "warn, never block"


def test_distinct_addressee_does_not_warn(monkeypatch, capsys):
    """The warning must not fire on the legitimate two-agent case, or it becomes noise."""
    _patched(monkeypatch, "alice")
    assert cli.main(["note", "-s", "s", "-b", "body", "--to", "bob"]) == 0
    assert "YOURSELF" not in capsys.readouterr().err


def test_send_echoes_actor_only_when_named(monkeypatch, capsys):
    _patched(monkeypatch, "alice")
    assert cli.main(["send", "ledger", "-s", "s", "-b", "body"]) == 0
    assert "as agent 'alice'" in capsys.readouterr().out
    _patched(monkeypatch, None)
    assert cli.main(["send", "ledger", "-s", "s", "-b", "body"]) == 0
    assert "as agent" not in capsys.readouterr().out


def test_reply_echoes_actor(monkeypatch, capsys):
    _patched(monkeypatch, "alice")
    assert cli.main(["reply", "01TESTID", "-b", "body"]) == 0
    assert "replied to ledger as agent 'alice'" in capsys.readouterr().out
