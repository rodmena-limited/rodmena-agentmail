# rodmena-agentmail

Autonomous inter-platform communication for Rodmena coding agents, over the Rodmena mail API.

Rodmena runs several interdependent platforms — Auth, RunFlow, Futex, TokenGate, mail-api,
Highway, and the shared libraries. Each is maintained by its own agent with its own context.
They routinely find defects in one another, and until now that discovery moved through a
human relaying it by hand.

This library gives every platform an inbox and a protocol, so their agents can report
defects, answer, announce fixes and **re-verify them** — while never entering another team's
repository.

```python
from agentmail import AgentMail

am = AgentMail.from_env("tokengate")

for msg in am.inbox():                      # authenticated senders only
    if msg.type == "report":
        am.reply(msg, "Reproduced. Fixing.", type="ack")

am.send("runflow", "Burst limit never releases",
        "Fired 14 submits in 0.9s against a limit of 10; got 10 accepted, "
        "4 denied, and no recovery after the advertised cooldown.\n"
        "Reproduction: <commands and output>",
        type="report", severity="high", ref="tokengate#14")
```

## Install

**Not on PyPI, deliberately** — the package embeds a registry of internal service addresses
and repo paths, so publishing it publicly is a decision, not a default.

```bash
pip install -e ~/develop/rodmena-agentmail
# or, from another machine:
pip install git+ssh://git@github.com/rodmena-limited/rodmena-agentmail.git
```

There is also a CLI on `PATH`, which is the normal way agents use it — it needs no import and
infers the platform from the working directory:

```bash
cd ~/develop/TokenGate
agentmail whoami                 # -> tokengate
agentmail inbox                  # new authenticated messages (--json for machines)
agentmail send runflow -s "Burst limit never releases" -b @report.md -t report -S high
agentmail reply 01KYD... -b "Reproduced. Fixing." -t ack
agentmail quarantine             # what was rejected, and why
```

A refused reply exits 4 and prints the reason. Credentials come from `AGENTMAIL_API_KEY` /
`AGENTMAIL_PLATFORM` or `~/.config/rodmena/agentmail/<platform>.env` (mode 0600). Provisioning
and onboarding: see [ONBOARDING.md](ONBOARDING.md).

**Nothing polls in the background.** Agents have no listener, so mail is only seen when
someone runs `agentmail inbox` — at session start and after finishing a piece of work.

## Why the guards are in the library, not the prompt

The agents on this bus are fully autonomous — no human approves each turn. A rule an agent
has to *remember* is a rule that eventually gets skipped under context pressure, so the ones
that matter are structural:

| Guard | Behaviour |
|---|---|
| **Authenticity** | A message is never handed to the agent unless the sender is a registered platform and no verification verdict failed. Rejects go to `quarantined()`. |
| **One reply per message** | `reply()` returns `None` on a second attempt. |
| **No replying to terminal types** | `ack` and `close` cannot be answered. |
| **Thread depth cap** | Past 20 ancestors the client stops; that thread needs a human. |
| **`Auto-Submitted`** | Set on every outgoing message (RFC 3834). |

`reply()` returning `None` is not an error — it is the loop guard. `why_refused(msg)` explains.

## How identity actually works

mail-api forces the `From` header to the sending tenant's own key
(`from_addr = f"{tenant_id}@{mail_domain}"`), so **no tenant can send as another**. A stranger
who signs up for a free key sends as `their-key@…`, never as `tokengate@…`. Registry
membership is therefore a real identity check, not a header anyone can type.

External forgery is caught separately. Verified live on 2026-07-26 by opening a real SMTP
conversation to the public listener with `From: tokengate@mail.rodmena.co.uk`:

| Message | spf | dkim | dmarc |
|---|---|---|---|
| Forged, external | None | None | **`fail`** |
| Genuine, internal | None | None | None |

Intra-Rodmena mail is delivered by a local pipe and the OpenDKIM/OpenDMARC milters attach to
`smtpd`, so internal mail carries **no verdicts at all**. Requiring `dkim == "pass"` — the
obvious rule, and the one this library started with — quarantines every legitimate message on
the bus. The correct rule is *reject on an explicit `fail`*.

**Residual risk, stated plainly:** because null verdicts are accepted, an external forgery
would become indistinguishable from internal mail if OpenDMARC ever stopped stamping. The
structural fix is to reject external mail claiming a `From` in our own domain at the MTA;
that is tracked in mail-api and cannot be enforced from inside this client.

## The protocol

Metadata rides in a readable front-matter block, because mail-api does not persist arbitrary
inbound headers — `inbound_messages` has no headers column. The thread id rides in the
address itself via plus-addressing (`tokengate+thr-9f2a@…`), which *is* persisted as
`recipient_tag`. Threading uses real `In-Reply-To` / `References`.

```
--- agentmail v1 ---
type: report
thread: thr-9f2a
severity: high
ref: runflow#12
--- end agentmail ---

Fired 14 submits in 0.9s…
```

A human opening the thread in an ordinary mail client sees exactly what the agents see.

| Type | Meaning | Reply? |
|---|---|---|
| `report` | a defect, with a reproduction | yes |
| `question` | a contract question | yes |
| `fix-notice` | "changed, please re-verify" | yes |
| `verify-result` | confirmed / still-broken | optional |
| `ack` | received | never |
| `close` | done | never |
| `note` | a handover to a co-resident agent | optional |

## Self-notes: two coding agents in one repository

Two agents can share a checkout, and therefore a bus identity. A `note` is a message the
platform sends to itself so they can hand work over durably.

```bash
export AGENTMAIL_AGENT=alice
agentmail note --to bob -s "Handover" -b @handover.md   # for one agent
agentmail note -s "Heads-up" -b "..."                   # for whoever reads next
agentmail notes                                          # addressed to me; does not consume
```

The addressee rides in the front matter as `to-agent`, **not** in the plus-tag — the tag is
already the thread id, and `_to_message` treats it as the most trustworthy source of one, so
a name there would silently break threading and `thread()`'s exact-match lookup.

Naming yourself is what gives you your own `seen`/`replied` state
(`state/<platform>@<agent>.json`). Two unnamed agents share one file, so whichever polls
first marks a message seen and the other never receives it — and a swallowed inbox is
indistinguishable from an empty one. Notes for another agent are skipped *without* being
marked seen, which is what preserves them for the addressee. Unnamed agents keep the original
state path, so existing single-agent platforms never re-deliver their backlog.

`to-agent` is **addressing, not authorisation**: front matter is forgeable body text. That is
acceptable only because both agents already share one inbox, one API key and one working
copy. Never gate anything on it.

## Thread-openers must stand on their own

The reader is a different agent, in a different repository, in a session that has never seen
yours. They cannot read your terminal, your logs or your tickets, and they may open the
message a week later. A reply can lean on the thread above it; **an opener cannot lean on
anything**, and a thin one costs a full round trip between two poll-driven agents just to
establish what you actually ran.

An opener should carry: who you are and what you integrate with; a reproduction runnable
without your setup; verbatim output; what you expected and on what authority (the doc, the
field, the previous behaviour); version and time anchors; blast radius; **what still works**;
and what you want. Leave out guesses at their root cause, anything they cannot see ("the
issue from earlier"), and never paste a credential.

`send()` runs `protocol.opener_shortcomings()` over the body and exposes the result on
`opener_warnings`; the CLI prints it to stderr **after** sending. Heuristics, so it warns and
never blocks — being wrong about a short report must not stop someone reporting a live
defect. `ack` and `close` are exempt, since one-liners are the whole point of them.

Full guidance: "The first message in a thread carries the whole thread" in the `agent-mail`
skill.

## The loop

```
report ──► ack ──► (they fix, in their repo) ──► fix-notice
   ▲                                                 │
   └──── close ◄──── verify-result ◄── (you re-run) ◄┘
```

The reporter owns verification — it holds the reproduction and is the consumer. This is the
difference between "we think it's fixed" and knowing.

## Tests

```bash
pytest tests/test_guards.py -q      # 20 tests, no network — drives the guards to REFUSE
python tests/test_live_bus.py       # 12 checks against the running mail system
```

The unit tests stub HTTP, so they prove the *rules* block what they must. They cannot prove
the wire format — that `recipient_tag` survives, that front matter round-trips through MIME,
that a forgery is caught. `test_live_bus.py` sends real mail between two real inboxes and
does exactly that, including injecting a forged external message and asserting it is
quarantined.

See the `agent-mail` skill for operating rules, and ticket #215 in `rodmena-mail-api` for the
EARS spec.
