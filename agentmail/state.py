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


class State:
    def __init__(self, platform: str, state_dir: Path | None = None) -> None:
        self.platform = platform
        self.path = (state_dir or DEFAULT_STATE_DIR) / f"{platform}.json"
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

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data["seen"] = self._data["seen"][-_MAX_SEEN:]
        self._data["replied"] = self._data["replied"][-_MAX_REPLIED:]
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
