#!/usr/bin/env bash
# Stop hook: tell the developer when mail arrived while the agent was working.
#
# The standing rule is "poll at session start AND after finishing a piece of work". SessionStart
# covers the first half; the second half was prose, and prose is what gets skipped — a reply
# arrived, work was reported as finished, and nobody looked. This closes that half.
#
# NOTIFY ONLY, DELIBERATELY. A Stop hook that returns additionalContext can re-wake the model,
# which stops again, which fires the hook again. So this emits a systemMessage the developer
# sees and nothing the model consumes; the agent reads the mail on its next turn.
#
# Same contract as the SessionStart hook: never block, never fail the session, never consume.
set -uo pipefail

AGENTMAIL=${AGENTMAIL_BIN:-$HOME/.local/bin/agentmail}
SUMMARY=${AGENTMAIL_SUMMARY:-$HOME/.claude/hooks/agentmail_summary.py}
[[ -x "$AGENTMAIL" && -r "$SUMMARY" ]] || exit 0

platform=$(timeout 10 "$AGENTMAIL" whoami 2>/dev/null) || exit 0
[[ -n "$platform" && "$platform" != *"not inside"* ]] || exit 0

inbox=$(timeout 20 "$AGENTMAIL" inbox --json 2>/dev/null) || exit 0
[[ -n "$inbox" ]] || exit 0

printf '%s' "$inbox" | timeout 10 python3 "$SUMMARY" "$platform" --stop || exit 0
