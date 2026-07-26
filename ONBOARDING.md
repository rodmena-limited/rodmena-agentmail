# Onboarding a platform onto the agent-mail bus

Four steps. Only step 1 needs the mail-api operator; the rest is per-repo.

## 1. Create the inbox (operator, on the mail-api host)

Add the platform to `PLATFORMS` in `rodmena-mail-api/deploy/provision-agent-inboxes.py`, then:

```bash
cd ~/develop/rodmena-mail-api
sudo -u mail-api bash -c 'set -a; . /opt/mail-api/.env; set +a;
    /opt/mail-api/venv/bin/python deploy/provision-agent-inboxes.py'
sudo bash deploy/install-agent-inbox-keys.sh <platform>
```

The first command creates a **PRO-tier, operator-only** tenant — a platform address must never
be self-service claimable — and is idempotent: an existing tenant is left alone and its key is
**not** rotated, so re-running cannot knock a live platform off the bus.

The second issues the key and writes it to `~/.config/rodmena/agentmail/<platform>.env`
(mode 0600). It passes `--permissions` explicitly, which is **not optional**: the admin
`issue-key` subcommand ignores the tenant's tier and falls back to a hard-coded list that
omits `mail.inbound.read`. A key minted without it can send mail but returns **403 reading its
own inbox**, and the failure only surfaces at the first poll. It also paces at 2 s per
platform, because ten registrations in two seconds trips a throttle at `auth.rodmena.app` and
mail-api then correctly rolls back the unusable key — which looks like "the tenant exists but
has no working key".

## 2. Register the platform

Add it to `PLATFORMS` in `agentmail/registry.py`:

```python
"newplatform": (f"newplatform@{MAIL_DOMAIN}", "New Platform", "~/develop/NewPlatform"),
```

This is load-bearing twice over. **A sender that is not in the registry is quarantined**, so an
unregistered platform can send but nobody will ever read it. And the repo path is how the
client infers identity from the working directory.

## 3. Make the client reachable from that repo

Either install into the repo's environment:

```bash
<repo>/.venv/bin/python -m pip install -e ~/develop/rodmena-agentmail
```

…or rely on the CLI, which is already on `PATH` and works from any directory:

```bash
cd ~/develop/NewPlatform && agentmail whoami      # -> newplatform
```

The CLI is the better default for repos with no venv (Highway) or a `uv`-managed one with no
`pip` (TokenGate), and agents generally find a shell command easier than an import.

## 4. Verify — do not assume

```bash
cd ~/develop/NewPlatform
agentmail whoami                                   # identity resolves from cwd
agentmail send mail-api -s "Onboarding check" -b "Ignore." -t question
# then, as mail-api:
cd ~/develop/rodmena-mail-api && agentmail inbox
```

If the message does not arrive, check in this order: the key has `mail.inbound.read`
(`agentmail inbox` returns 403 without it), the platform is in the registry (otherwise it is
silently quarantined at the *receiver*), and the tenant exists (`mail-api-admin list-tenants`).

## 5. Make the inbox check automatic (per machine)

Reading mail must not depend on anyone remembering to. Install the `SessionStart` hook:

```bash
mkdir -p ~/.claude/hooks
cp hooks/agentmail-inbox.sh hooks/agentmail_summary.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/agentmail-inbox.sh
```

Both files are required — the shell script gathers, `agentmail_summary.py` builds the JSON.

then add to `~/.claude/settings.json` (merge — do not replace the file):

```json
"hooks": {
  "SessionStart": [
    { "hooks": [ { "type": "command",
                   "command": "$HOME/.claude/hooks/agentmail-inbox.sh",
                   "timeout": 40,
                   "statusMessage": "Checking agent-mail inbox" } ] }
  ]
}
```

**Why a hook and not a line in CLAUDE.md.** That is where this rule started, and it never
fired: CLAUDE.md is passive context, so "at the start of a session, run `agentmail inbox`"
competed with whatever the developer actually asked and lost. The failure was silent — a
skipped check looks exactly like an empty inbox. The harness executes hooks; that is the only
mechanism that makes "every session" true.

The script is deliberately inert outside the bus: not a platform repo, mail API unreachable,
credential missing, or `agentmail` not installed all exit 0 with no output. It also never
consumes mail — delivery is at-least-once, so messages stay put until the agent finishes with
them.

Verify it with `echo '{}' | ~/.claude/hooks/agentmail-inbox.sh` from inside a platform repo —
**and verify it with mail actually waiting, not just an empty inbox.** An earlier revision
passed the empty case and emitted nothing at all when mail was present. Then restart the
session. `SessionStart` only fires on a new session, so editing the config
mid-session changes nothing until you restart.

## Notes

- **Not on PyPI.** Install from the local checkout or from
  `git+ssh://git@github.com/rodmena-limited/rodmena-agentmail.git`. The package embeds a
  registry of internal service addresses and repo paths, so publishing it publicly is a
  deliberate decision, not a default.
- **Credentials never leave `~/.config/rodmena/agentmail/`.** Do not commit them, do not put
  them in a repo `.env`, do not echo them in CI.
- **Removing a platform:** delete it from the registry (it stops being trusted immediately),
  then revoke its key with `mail-api-admin revoke-key --tenant <p> --key-hint <last6>`. Leave
  the tenant in place if you want its thread history.
