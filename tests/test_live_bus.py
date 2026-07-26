"""Live end-to-end proof against the running mail system.

The guard tests stub HTTP, so they cannot tell you whether the WIRE FORMAT works — whether
mail-api really persists `recipient_tag`, whether DKIM really lands as `pass` on a
tenant-to-tenant message, whether the front matter survives MIME. That is what this does,
by sending real mail between two real inboxes and reading it back through the API.

    python tests/test_live_bus.py

Not part of the unit suite: it needs live credentials and takes ~1 minute of delivery time.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentmail import AgentMail                                    # noqa: E402
from agentmail import protocol as P                                # noqa: E402

SUBJECT = f"agent-mail bus liveness {int(time.time())}"
checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def wait_for(am: AgentMail, predicate, timeout: int = 120):
    """Poll an inbox until a matching message arrives. Delivery is not instant."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in am.inbox():
            if predicate(m):
                return m
        time.sleep(5)
    return None


def main() -> int:
    tg = AgentMail.from_env("tokengate")
    rf = AgentMail.from_env("runflow")
    print(f"  {tg.address}  <->  {rf.address}\n")

    # 1. tokengate reports to runflow
    thread = tg.send("runflow", SUBJECT,
                     "Liveness probe for the agent-mail bus. No action needed.",
                     type="report", severity="low", ref="mail-api#215")
    check("send accepted", bool(thread), f"thread {thread}")

    # 2. runflow receives it, authenticated
    got = wait_for(rf, lambda m: m.subject == SUBJECT)
    if got is None:
        check("message delivered to runflow inbox", False, "timed out after 120s")
        return 1
    check("message delivered to runflow inbox", True, f"inbound {got.inbound_id}")
    check("sender resolved to a registered platform", got.sender == "tokengate",
          f"from={got.from_addr} verdicts spf={got.spf} dkim={got.dkim} dmarc={got.dmarc}")
    check("thread id survived via recipient_tag", got.thread_id == thread,
          f"got {got.thread_id!r}, sent {thread!r}")
    check("type/severity survived the body front matter",
          got.type == "report" and got.severity == "low",
          f"type={got.type} severity={got.severity}")
    check("front matter stripped from the readable body",
          "agentmail v1" not in got.body, got.body[:60])

    # 3. runflow acks
    replied = rf.reply(got, "Received, nothing to do.", type="ack")
    check("reply accepted", replied == thread, f"thread {replied}")

    # 4. tokengate receives the ack, threaded
    ack = wait_for(tg, lambda m: m.thread_id == thread)
    if ack is None:
        check("ack delivered back to tokengate", False, "timed out")
        return 1
    check("ack delivered back to tokengate", True, f"subject {ack.subject!r}")
    check("subject carries exactly one Re:", ack.subject == P.reply_subject(SUBJECT),
          ack.subject)
    check("In-Reply-To threaded the ack", bool(ack.in_reply_to), str(ack.in_reply_to))

    # 5. the loop guard holds on real data
    check("replying to the ack is refused (loop guard)",
          tg.reply(ack, "you're welcome") is None, tg.why_refused(ack))

    # 6. a forged external sender must never reach the agent. Sent from outside the
    #    submission path with From: tokengate@…, so OpenDMARC judges it unaligned.
    forged = [q for q in rf.quarantined() if "FORGED" in (q.subject or "")]
    check("forged impersonation was quarantined, not delivered", bool(forged),
          forged[0].reason if forged else "no forged probe seen this run (send one to re-test)")

    # CLEAN UP AFTER OURSELVES. This sends REAL mail to a REAL inbox, and with at-least-once
    # delivery nothing retires on its own — six runs of this script left seven unread messages
    # sitting in runflow@, which read to the operator as "who sent RunFlow seven reports?".
    # A test that pollutes production state is a test that gets switched off.
    for client, label in ((rf, "runflow"), (tg, "tokengate")):
        for m in client.inbox():
            if SUBJECT in m.subject or P.reply_subject(SUBJECT) == m.subject:
                client.done(m)
    print("  cleaned up this run's probe messages")

    bad = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(bad)}/{len(checks)} live checks pass")
    for n in bad:
        print(f"  FAILED: {n}")
    return 1 if bad else 0


# Guarded: pytest collects this file by name, and a module-level sys.exit() aborts the whole
# run with INTERNALERROR before any real test executes.
if __name__ == "__main__":
    sys.exit(main())
