"""`done()` must distinguish consumed from merely queued (#363).

RED9 found this while verifying #361: `agentmail done <id>` printed "marked 1 message(s)
done" and exited 0 with a bogus API key, when the server ack could not possibly have
succeeded. Reproduced against the live bus before accepting the report.

Nothing is lost — #358's retry queue catches it — but the failure mode #358 existed to kill
was an agent believing an ack that had not happened, and the CLI still printed the sentence
that produces that belief.
"""
from __future__ import annotations

import pytest

from agentmail.cli import main as cli_main
from agentmail.client import AgentMail, AgentMailError, Message


class _Client(AgentMail):
    def __init__(self, tmp_path, *, fail_acks=False):
        super().__init__("mail-api", "key-not-used", state_dir=tmp_path)
        self.fail_acks = fail_acks

    def _request(self, method, path, **kw):
        if path.endswith("/ack"):
            if self.fail_acks:
                raise AgentMailError("simulated refusal")
            return {"ok": True}
        if path.startswith("/api/v1/inbound?"):
            return {"inbound": []}
        return {}


@pytest.fixture
def msg():
    return Message(
        inbound_id="01ABC", from_addr="futex@mail.rodmena.co.uk", sender="futex",
        subject="s", body="b", message_id="<m@x>", in_reply_to=None, thread_id="t",
        type="report", severity=None, ref=None, received_at="", dkim="",
    )


def test_done_returns_true_when_the_server_acked(tmp_path, msg):
    assert _Client(tmp_path).done(msg) is True


def test_done_returns_false_when_the_ack_failed(tmp_path, msg):
    """FR-DONE-4. Returning None made 'deferred' and 'done' indistinguishable to every
    caller, which is how the CLI came to print a completed fact for a deferred action."""
    c = _Client(tmp_path, fail_acks=True)
    assert c.done(msg) is False
    assert c.pending_acks() == ["01ABC"], "and it must still be queued for retry"


def test_done_still_marks_seen_on_failure(tmp_path, msg):
    """The caller finished the work; it must not be handed the same message again."""
    c = _Client(tmp_path, fail_acks=True)
    c.done(msg)
    assert c._state.is_seen("01ABC")


# -- the CLI surface, both directions ------------------------------------------------------

def _run_cli(monkeypatch, tmp_path, *, fail_acks, capsys):
    client = _Client(tmp_path, fail_acks=fail_acks)
    monkeypatch.setattr("agentmail.cli.AgentMail.from_env",
                        classmethod(lambda cls, *a, **k: client))
    code = cli_main(["done", "01ABC"])
    return code, capsys.readouterr().out


def test_cli_reports_consumed_and_exits_0(monkeypatch, tmp_path, capsys):
    code, out = _run_cli(monkeypatch, tmp_path, fail_acks=False, capsys=capsys)
    assert code == 0
    assert "consumed 1 message(s) server-side" in out
    assert "QUEUED" not in out


def test_cli_reports_queued_and_exits_1(monkeypatch, tmp_path, capsys):
    """FR-DONE-2 and FR-DONE-3: the exact reproduction RED9 sent, inverted into an
    assertion. Before the fix this printed 'marked 1 message(s) done' and exited 0."""
    code, out = _run_cli(monkeypatch, tmp_path, fail_acks=True, capsys=capsys)
    assert code == 1
    assert "QUEUED FOR RETRY, not yet consumed" in out
    assert "done" not in out.lower().split("queued")[0], \
        "must not claim completion anywhere before the queued notice"


def test_cli_partial_success_exits_0(monkeypatch, tmp_path, capsys):
    """A partial failure is not a failed command: the queued ones are not lost, and exiting
    non-zero there would train an operator to ignore the status."""
    class _Flaky(_Client):
        def __init__(self, tmp_path):
            super().__init__(tmp_path)
            self.seen_ids = []

        def _request(self, method, path, **kw):
            if path.endswith("/ack"):
                iid = path.split("/")[-2]
                self.seen_ids.append(iid)
                if iid == "02BAD":
                    raise AgentMailError("simulated")
                return {"ok": True}
            return {"inbound": []}

    client = _Flaky(tmp_path)
    monkeypatch.setattr("agentmail.cli.AgentMail.from_env",
                        classmethod(lambda cls, *a, **k: client))
    code = cli_main(["done", "01GOOD", "02BAD"])
    out = capsys.readouterr().out
    assert code == 0
    assert "consumed 1 message(s)" in out
    assert "QUEUED FOR RETRY" in out
