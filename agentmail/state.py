"""Durable per-platform state: what we have seen, what we have answered, and thread chains.

Three things have to survive a restart, and all three are correctness-critical:

  * SEEN inbound ids — mail-api's inbound list is offset-paginated and newest-first, so new
    arrivals shift the window. Deduplicating on inbound_id is what makes polling safe;
    without it an agent re-processes the same report every tick.
  * REPLIED message ids — the one-reply-per-message rule. If this were kept in memory, a
    crash-restart loop would answer the same message repeatedly, which is exactly the
    runaway the depth cap is meant to prevent.
  * THREAD chains — mail-api's inbound_messages table stores `message_id` and `in_reply_to`
    but NOT `references`, so an incoming message does not carry its own ancestry. We keep
    the chain locally, keyed by thread id, so replies can emit a proper RFC 5322 References
    header and so depth is measurable.

Written atomically (temp file + os.replace) because a half-written state file would either
re-deliver everything or silently swallow a thread.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_STATE_DIR = Path.home() / ".config" / "rodmena" / "agentmail" / "state"

#: Keep the seen-set bounded. Well above any realistic backlog, far below unbounded growth.
_MAX_SEEN = 5000
_MAX_REPLIED = 5000
#: FR-ACK-4: bounded, so a server that is down for a long time cannot grow the file without
#: limit. Oldest are dropped first — they are also the least likely to still matter.
_MAX_PENDING_ACK = 1000


class State:
    def __init__(self, platform: str, state_dir: Path | None = None,
                 agent: str | None = None) -> None:
        # PER-AGENT STATE. Two coding agents can share one repository, hence one platform
        # identity, hence — before this — one state file. That is a correctness bug, not a
        # cosmetic one: `seen` is what suppresses re-delivery, so whichever agent polled
        # first marked a message seen and the second agent NEVER saw it. Mail addressed to
        # one was silently swallowed by the other, and the symptom is an empty inbox, which
        # looks identical to having no mail.
        #
        # Namespacing the file by agent gives each its own seen/replied sets. The cost is
        # that shared bus mail is now delivered to BOTH agents, so both could answer a peer
        # report; the server-side reply-once guard and `done()` are what bound that, and it
        # is the safer failure — a duplicate ack is recoverable, a message delivered to
        # nobody is not.
        self.platform = platform
        self.agent = agent or None
        stem = f"{platform}@{agent}" if agent else platform
        self.path = (state_dir or DEFAULT_STATE_DIR) / f"{stem}.json"
        self._data: dict[str, Any] = {"seen": [], "replied": [], "threads": {}}
        self._load()

    def _load(self) -> None:
        try:
            self._data = json.loads(self.path.read_text())
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            # A corrupt state file must not wedge the agent. Starting clean re-delivers
            # recent mail, which the one-reply rule then makes harmless; refusing to start
            # would take the platform off the bus entirely.
            pass
        self._data.setdefault("seen", [])
        self._data.setdefault("replied", [])
        self._data.setdefault("threads", {})
        self._data.setdefault("pending_ack", [])

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data["seen"] = self._data["seen"][-_MAX_SEEN:]
        self._data["replied"] = self._data["replied"][-_MAX_REPLIED:]
        self._data["pending_ack"] = self._data["pending_ack"][-_MAX_PENDING_ACK:]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=1))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- seen ---------------------------------------------------------------------------
    def is_seen(self, inbound_id: str) -> bool:
        return inbound_id in set(self._data["seen"])

    def mark_seen(self, inbound_id: str) -> None:
        if inbound_id not in self._data["seen"]:
            self._data["seen"].append(inbound_id)

    # -- pending acks (#358) --------------------------------------------------------------
    # A server ack that failed. The message is still marked seen locally — the agent finished
    # the work and must not be handed it twice — but WITHOUT this list the failure became a
    # permanent, silent divergence: invisible here forever, outstanding on the server forever,
    # and `consumed_at` reporting never-read for a message that was read and acted on.
    # Measured before the fix: client said 0 unconsumed, server said 35.
    def pending_acks(self) -> list[str]:
        return list(self._data.get("pending_ack", []))

    def add_pending_ack(self, inbound_id: str) -> None:
        p = self._data.setdefault("pending_ack", [])
        if inbound_id not in p:
            p.append(inbound_id)

    def clear_pending_ack(self, inbound_id: str) -> None:
        p = self._data.setdefault("pending_ack", [])
        if inbound_id in p:
            p.remove(inbound_id)

    # -- replied ------------------------------------------------------------------------
    def has_replied(self, message_id: str | None) -> bool:
        return bool(message_id) and message_id in set(self._data["replied"])

    def mark_replied(self, message_id: str | None) -> None:
        if message_id and message_id not in self._data["replied"]:
            self._data["replied"].append(message_id)

    # -- threads ------------------------------------------------------------------------
    def chain(self, thread_id: str) -> list[str]:
        """The message-id ancestry for a thread, oldest first."""
        return list(self._data["threads"].get(thread_id, []))

    def extend_chain(self, thread_id: str, message_id: str | None) -> None:
        if not thread_id or not message_id:
            return
        chain = self._data["threads"].setdefault(thread_id, [])
        if message_id not in chain:
            chain.append(message_id)

    def depth(self, thread_id: str) -> int:
        return len(self._data["threads"].get(thread_id, []))
