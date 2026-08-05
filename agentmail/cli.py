"""Command-line interface.

Coding agents work in a shell far more naturally than they write throwaway Python, and not
every repo has an importable environment (Highway has no venv of its own; the system
interpreter is PEP 668 externally-managed). A single command on PATH makes the bus usable
from any repository without touching that repository's dependencies.

    agentmail whoami
    agentmail inbox
    agentmail send runflow -s "Burst limit never releases" -b @report.md -t report -S high
    agentmail reply 01KYD... -b "Reproduced, fixing." -t ack
    agentmail quarantine

Identity comes from the working directory (see registry.platform_for_path), so running it
inside ~/develop/TokenGate acts as TokenGate. `--as` overrides.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import protocol as P
from .client import AgentMail, AgentMailError
from .registry import PLATFORMS, platform_for_path


def _body(value: str) -> str:
    """A body given as `@path` is read from that file — reports are usually long.
    `@-` reads from stdin, the standard Unix convention."""
    if value.startswith("@"):
        path = value[1:]
        if path == "-":
            return sys.stdin.read()
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return value


def _print_messages(msgs, as_json: bool) -> None:
    if as_json:
        print(json.dumps([{
            "inbound_id": m.inbound_id, "from": m.from_addr, "sender": m.sender,
            "subject": m.subject, "type": m.type, "severity": m.severity,
            "thread": m.thread_id, "ref": m.ref, "received_at": m.received_at,
            "agent": m.agent, "to_agent": m.to_agent, "is_note": m.is_note,
            "body": m.body,
        } for m in msgs], indent=2))
        return
    if not msgs:
        print("no new messages")
        return
    for m in msgs:
        flag = "  (reply expected)" if m.expects_reply else ""
        # For a note, the interesting sender is the co-resident AGENT, not the platform —
        # the platform is always us, so printing only that would hide who actually wrote it.
        who = f"{m.sender} <{m.from_addr}>"
        if m.is_note:
            who = (f"NOTE from agent '{m.agent or 'unnamed'}'"
                   f" -> {'agent ' + repr(m.to_agent) if m.to_agent else 'anyone here'}")
        print(f"\n{'=' * 72}\nfrom:    {who}\n"
              f"subject: {m.subject}\ntype:    {m.type}"
              f"{'  severity: ' + m.severity if m.severity else ''}{flag}\n"
              f"id:      {m.inbound_id}\nthread:  {m.thread_id}\n{'-' * 72}\n{m.body}")


def _print_sent(rows, as_json: bool) -> None:
    if as_json:
        print(json.dumps([{
            "track_id": s.track_id, "to": s.to, "subject": s.subject,
            "from": s.from_addr, "status": s.status, "created_at": s.created_at,
            "type": s.email_type,
        } for s in rows], indent=2))
        return
    if not rows:
        print("no sent messages found")
        return
    for s in rows:
        print(f"\n{'=' * 72}\ntrack_id: {s.track_id}\nto:       {', '.join(s.to)}\n"
              f"subject:  {s.subject or ''}\nfrom:     {s.from_addr or ''}\n"
              f"status:   {s.status}\ncreated:  {s.created_at or ''}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentmail", description=__doc__.split("\n")[0])
    p.add_argument("--as", dest="as_platform", default=None,
                   help="act as this platform (default: inferred from the working directory)")
    p.add_argument("--agent", default=None,
                   help="this agent's name within the platform, when two coding agents share "
                        "one repo (default: $AGENTMAIL_AGENT). Gives each its own seen-state "
                        "and receives notes addressed to it")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("whoami", help="which platform this directory belongs to")
    sub.add_parser("platforms", help="list every platform on the bus")

    p_in = sub.add_parser("inbox", help="new authenticated messages")
    p_in.add_argument("--json", action="store_true")
    p_in.add_argument("--limit", type=int, default=50)
    p_in.add_argument("--consume", action="store_true",
                      help="mark everything read as done in the same breath (at-most-once)")

    p_note = sub.add_parser(
        "note", help="leave a note for another coding agent working in THIS repo")
    p_note.add_argument("-s", "--subject", required=True)
    p_note.add_argument("-b", "--body", required=True, help="text, or @file")
    p_note.add_argument("--to", dest="to_agent", default=None,
                        help="the other agent's name; omit to leave it for whoever reads next")
    p_note.add_argument("--ref", default=None)

    p_notes = sub.add_parser("notes", help="notes addressed to this agent (does not consume)")
    p_notes.add_argument("--json", action="store_true")
    p_notes.add_argument("--limit", type=int, default=50)

    p_s = sub.add_parser("send", help="start a new thread")
    p_s.add_argument("to", choices=sorted(PLATFORMS))
    p_s.add_argument("-s", "--subject", required=True)
    p_s.add_argument("-b", "--body", required=True, help="text, or @file")
    p_s.add_argument("-t", "--type", default="report")
    p_s.add_argument("-S", "--severity", default=None)
    p_s.add_argument("-r", "--ref", default=None)

    p_r = sub.add_parser("reply", help="answer a message by its inbound id")
    p_r.add_argument("inbound_id")
    p_r.add_argument("-b", "--body", required=True, help="text, or @file")
    p_r.add_argument("-t", "--type", default="ack")
    p_r.add_argument("-S", "--severity", default=None)
    p_r.add_argument("-r", "--ref", default=None)

    p_show = sub.add_parser("show", help="re-read one message by id")
    p_show.add_argument("inbound_id")
    p_show.add_argument("--json", action="store_true")

    p_done = sub.add_parser("done", help="mark a message consumed so it stops re-appearing")
    p_done.add_argument("inbound_id", nargs="+")

    p_thread = sub.add_parser("thread", help="list all messages in a thread, oldest first")
    p_thread.add_argument("thread_id")
    p_thread.add_argument("--json", action="store_true")
    p_thread.add_argument("--limit", type=int, default=200)

    p_sent = sub.add_parser(
        "sent", help="what this platform has sent — the sent folder ('did I send X?')")
    p_sent.add_argument("--json", action="store_true")
    p_sent.add_argument("--limit", type=int, default=50)
    p_sent.add_argument("--recipient", default=None, help="exact recipient address")
    p_sent.add_argument("--since", default=None, help="ISO-8601 lower bound on send time")
    p_sent.add_argument("--message-id", dest="message_id", default=None,
                        help="message id (the track_id embedded in the Message-ID)")

    sub.add_parser("quarantine", help="messages rejected this session, and why")

    args = p.parse_args(argv)

    if args.cmd == "platforms":
        for k, (addr, name, repo, git) in sorted(PLATFORMS.items()):
            print(f"  {k:<11} {addr:<32} {name:<11} {git or repo or '(operator identity)'}")
        return 0

    if args.cmd == "whoami" and not args.as_platform:
        # This path deliberately answers without loading a credential, so it still works in a
        # repo whose key is not installed. It must still report the agent name: "which of us
        # am I" is what decides whose notes and whose seen-state this process uses, and it is
        # the answer an agent checks BEFORE it trusts an empty inbox.
        who = platform_for_path()
        agent = P.sanitise_agent(args.agent or os.environ.get("AGENTMAIL_AGENT", ""))
        print((who or "not inside a registered platform repository")
              + (f"  agent={agent}" if who and agent else ""))
        return 0 if who else 1

    try:
        am = AgentMail.from_env(args.as_platform, agent=args.agent)
    except AgentMailError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "whoami":
        # Print the agent name when there is one: with two agents in a repo, "which of us am
        # I" is the question that decides whose notes and whose seen-state this process uses.
        print(f"{am.platform}  <{am.address}>"
              + (f"  agent={am.agent}" if am.agent else ""))
        return 0

    if args.cmd == "note":
        thread = am.note(args.subject, _body(args.body),
                         to_agent=args.to_agent, ref=args.ref)
        target = f"agent '{args.to_agent}'" if args.to_agent else "whoever reads next"
        print(f"note left for {target} (thread {thread})")
        return 0

    if args.cmd == "notes":
        _print_messages(am.notes(limit=args.limit), args.json)
        return 0

    if args.cmd == "inbox":
        msgs = am.inbox(limit=args.limit, mark_seen=args.consume)
        _print_messages(msgs, args.json)
        if args.consume:
            # FTX-107 / mail-api #257: mark_seen is only the local cache; the server ack
            # lives in done(). Without it, inboxes accumulated unconsumed mail server-side.
            for m in msgs:
                am.done(m)
        q = am.quarantined()
        if q:
            print(f"\n({len(q)} message(s) quarantined — `agentmail quarantine` for detail)",
                  file=sys.stderr)
        return 0

    if args.cmd == "show":
        msg = am.get(args.inbound_id)
        if msg is None:
            print(f"error: {args.inbound_id} is not a readable, authentic message",
                  file=sys.stderr)
            return 3
        _print_messages([msg], args.json)
        return 0

    if args.cmd == "thread":
        msgs = am.thread(args.thread_id, limit=args.limit)
        if not msgs:
            print(f"no messages found for thread {args.thread_id}")
            return 0
        _print_messages(msgs, args.json)
        return 0

    if args.cmd == "sent":
        rows = am.sent(limit=args.limit, recipient=args.recipient, since=args.since,
                       message_id=args.message_id)
        _print_sent(rows, args.json)
        return 0

    if args.cmd == "done":
        for i in args.inbound_id:
            am.done(i)
        print(f"marked {len(args.inbound_id)} message(s) done")
        return 0

    if args.cmd == "quarantine":
        # Populated by a preceding inbox() in the same process, so do one first.
        am.inbox()
        for qq in am.quarantined():
            print(f"  {qq.inbound_id}  from={qq.from_addr}  {qq.subject[:40]!r}\n      {qq.reason}")
        return 0

    if args.cmd == "send":
        thread = am.send(args.to, args.subject, _body(args.body), type=args.type,
                         severity=args.severity, ref=args.ref)
        print(f"sent to {args.to} (thread {thread})")
        # Advisory only, and AFTER the send: the message is already away, so this is feedback
        # for the next one rather than a gate on this one.
        if am.opener_warnings:
            print("\nthis opener may not stand on its own to a reader with no shared context:",
                  file=sys.stderr)
            for w in am.opener_warnings:
                print(f"  - {w}", file=sys.stderr)
            print("  see 'The first message in a thread carries the whole thread' in the "
                  "agent-mail skill", file=sys.stderr)
        return 0

    if args.cmd == "reply":
        msg = am.get(args.inbound_id)
        if msg is None:
            print(f"error: {args.inbound_id} is not a readable, authentic message",
                  file=sys.stderr)
            return 3
        thread = am.reply(msg, _body(args.body), type=args.type,
                          severity=args.severity, ref=args.ref)
        if thread is None:
            print(f"refused: {am.why_refused(msg)}", file=sys.stderr)
            return 4
        print(f"replied to {msg.sender} (thread {thread})")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
