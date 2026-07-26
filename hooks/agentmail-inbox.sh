#!/usr/bin/env bash
# SessionStart hook: put this repo's agent-mail inbox in front of the agent automatically.
#
# WHY THIS IS A HOOK AND NOT A CLAUDE.md LINE. "At the start of a session, run agentmail
# inbox" was written into CLAUDE.md, which is passive context — nothing executes it. Whether
# it happened depended on the model noticing one sentence among a hundred lines of standing
# instructions while answering whatever the user actually asked. It didn't happen, and the
# failure was silent: a skipped check is indistinguishable from an empty inbox. The harness
# runs hooks; that is the only mechanism that makes "every session" true.
#
# CONTRACT: never block, never fail the session, never consume mail.
#   * Not a platform repo -> silent, exit 0. Most sessions are not on the bus.
#   * Mail API down, credential missing, agentmail absent -> silent, exit 0. A broken inbox
#     check must not stop someone working.
#   * Reading does NOT mark messages read: agentmail's delivery is at-least-once, so mail
#     stays in the inbox until the agent explicitly finishes with it.
#
# The JSON is built by agentmail_summary.py, NOT inline. The inline version needed
# backslash-escaped quotes through two levels of shell quoting, parsed as a SyntaxError, and
# — with stderr swallowed — made the hook emit nothing at all while mail was waiting. Failing
# open looks exactly like an empty inbox, which is the failure this hook exists to prevent.
set -uo pipefail

AGENTMAIL=${AGENTMAIL_BIN:-$HOME/.local/bin/agentmail}
SUMMARY=${AGENTMAIL_SUMMARY:-$HOME/.claude/hooks/agentmail_summary.py}
[[ -x "$AGENTMAIL" && -r "$SUMMARY" ]] || exit 0

# `whoami` resolves the platform from the marker file / git remote. Non-zero means this
# directory is not on the bus, which is the common case — say nothing.
platform=$(timeout 10 "$AGENTMAIL" whoami 2>/dev/null) || exit 0
[[ -n "$platform" && "$platform" != *"not inside"* ]] || exit 0

inbox=$(timeout 25 "$AGENTMAIL" inbox --json 2>/dev/null) || exit 0
[[ -n "$inbox" ]] || exit 0

printf '%s' "$inbox" | timeout 10 python3 "$SUMMARY" "$platform" || exit 0
