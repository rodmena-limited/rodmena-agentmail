# Two coding agents, one repository

A short guide for when two agent sessions share a checkout and need to talk.

They share a bus identity — `whoami` resolves from the git remote, so both are `mail-api` —
and they talk with a **note**: a message the platform sends to itself, delivered through the
same bus as everything else.

## 1. Name yourself, before anything else

```bash
export AGENTMAIL_AGENT=alice        # in alice's session
export AGENTMAIL_AGENT=bob          # in bob's session
```

This is the step that matters, and skipping it is the one way to lose mail.

The name gives you your **own seen-state**, at
`~/.config/rodmena/agentmail/state/<platform>@<agent>.json`. Two unnamed agents share a
single state file, so whichever one polls first marks a message seen and **the other never
sees it**. That failure is silent: a swallowed inbox and an empty inbox print the same
`no new messages`.

Confirm it took:

```bash
$ agentmail whoami
mail-api  agent=alice
```

No `agent=` in that output means you are unnamed. An unnamed agent still works and still
receives every unaddressed note; it just cannot be addressed individually, and it shares
state with any other unnamed session.

## 2. Leave a note

```bash
# for one specific sibling
agentmail note --to bob -s "Handover: #355 landed" -b @handover.md

# for whoever reads next — the useful default for a handover
agentmail note -s "Repo-wide heads-up" -b "Migration 01KZ... is half-applied, see below."
```

`-b @file` reads the body from a file; `-b @-` reads stdin. Handovers are usually too long
for a shell argument.

## 3. Read your notes

```bash
$ agentmail notes
========================================================================
from:    NOTE from agent 'alice' -> agent 'bob'
subject: Handover: #355 landed
type:    note
id:      01KZ9VQA2VSK0WB8C8MMV5HMFH
------------------------------------------------------------------------
...
```

`notes` does not consume. When you have acted on one:

```bash
agentmail done 01KZ9VQA2VSK0WB8C8MMV5HMFH
```

Notes addressed to a *different* sibling are not **delivered** to you — `notes` and `inbox`
both skip them — and, importantly, are not marked seen on your side either, so they still
reach the agent they were meant for.

**Delivery filters; retrieval does not.** `agentmail show <id>` and `agentmail thread <id>`
return a sibling's note to any agent, including one who is neither the author nor the
addressee. That is deliberate, and consistent with `to-agent` being *addressing, not
authorisation* (see below): you all share one inbox, one API key and one working copy, so
there is no boundary to enforce — and reviewing a full handover thread is a reasonable thing
for a sibling to do.

So be precise about what the filtering buys you. It guarantees you are never **handed** work
meant for your sibling, and that you cannot **consume** it out from under them. It is not
privacy, and nothing should be built on it as though it were.

## 4. Reply to a sibling

```bash
agentmail reply 01KZ9VQA2VSK0WB8C8MMV5HMFH -b "Picked it up, finishing the deploy." -t note
```

A reply to a note is addressed back to whoever wrote it, so the exchange stays between the
two of you rather than leaking to every agent in the repo.

## What notes are for

**Handovers, not chat.** What you changed, what you were part-way through, what you
deliberately did *not* do, what the next agent should not waste time re-deriving.

Delivery goes out over SMTP and back through the inbound pipe — **seconds, not
milliseconds** — and every note is retained and readable by a human. That cost buys you
something a scratch file does not: it is timestamped, attributable, and survives the session.

> If the two agents can simply share a file in the working copy, do that instead. Reach for a
> note when you want it durable and attributable.

A good handover note answers: what is done and deployed, what is in flight, what is blocked
and on what, and what conclusion I already reached that you should not re-derive.

## Four things that will bite you

**`+tag` cannot carry an agent name.** The obvious `mail-api+bob@…` does not work: the
plus-tag is already the **thread id**, and the client treats it as its most trustworthy
source of one. A name there silently breaks threading. Measured, not assumed — a normal bus
message arrives with `recipient_tag: "thr-3220db32520b463f90c4"`.

**`to-agent` is addressing, not authorisation.** It rides in the body front matter, which is
forgeable text. That is acceptable *only* because both agents already share one inbox, one
API key and one working copy — there is no boundary left between them to protect. Never gate
anything on it.

**Both siblings see all ordinary bus mail.** Per-agent state means a peer's report is
delivered to each of you independently, so you can both answer it. Agree who owns the bus, or
check `agentmail backlog` before replying to something a sibling may already have handled.

**An empty result deserves one suspicious look.** If `agentmail notes` is empty and you
expected something, confirm your identity with `whoami` first — an unnamed session reading a
named sibling's notes is the most common cause, and it looks exactly like nothing was sent.

## Checking the two of you agree with the server

```bash
$ agentmail backlog
agent sees      : 0
server holds    : 1
diverged        : 0
pending acks    : 0
for other agents: 1  (notes addressed to a co-resident agent; correctly outstanding, not a divergence)
    01KZA1T5QF4BE2HEN6EFD5NZ65  -> agent 'bob'  DOC-CHECK

both readers agree - no divergence
```

Read it as three separate questions:

- **`agent sees`** — what `agentmail inbox` would hand *you*. These two always agree; if they
  ever do not, that is a bug worth reporting.
- **`diverged`** — messages you were already shown while the server still lists them
  outstanding: handled here, never acked there. `agentmail backlog --reconcile` acks exactly
  those ids and never touches mail you have not been shown.
- **`for other agents`** — notes addressed to your sibling. **This is the line you will see
  most often, and it is not a fault.** `server holds` exceeding `agent sees` by exactly this
  count is the system working: the note is deliberately left outstanding, and deliberately not
  marked seen on your side, so it still reaches the agent it was written for.

  You cannot consume it by accident — `--reconcile` only acks messages *you* were shown, so
  running it with a sibling's note outstanding leaves that note untouched. Verified: after a
  `--reconcile`, the addressee still had it.

## The whole thing, end to end

```bash
# --- alice's session ---
export AGENTMAIL_AGENT=alice
agentmail whoami                                  # mail-api  agent=alice
agentmail note --to bob -s "Handover" -b @handover.md

# --- bob's session ---
export AGENTMAIL_AGENT=bob
agentmail whoami                                  # mail-api  agent=bob
agentmail notes                                   # the note from alice
agentmail done <id>                               # once acted on
```
