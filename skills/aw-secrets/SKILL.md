---
name: aw-secrets
description: Read, write and list this workspace's shared secrets from an agent. Reading asks a human for approval on Telegram and returns a request_id you collect later, unless that secret's gate has been turned off. Use whenever a task needs an API key, token, SSH key or password that is not already in your environment — and read this BEFORE calling read_secret, because every call interrupts a person.
---

# aw-secrets — the workspace's shared secrets

Five tools, from `aw-app-secrets`, exposed through the gateway as
`aw__secrets__list_secrets`, `aw__secrets__write_secret`,
`aw__secrets__delete_secret`, `aw__secrets__read_secret` and
`aw__secrets__collect_secret`.

Backed by **aw-vault** (Postgres, encrypted) through aw-backend's
`/api/approval/*`. The app itself stores nothing.

## The one thing to understand

**Reading interrupts a human.** `read_secret` sends a Telegram message to the
sysadmin bot with the secret's name and your reason. It does **not** wait: it
returns a `request_id` immediately and you collect the answer later.

```
r = read_secret(name="resend_api_key", reason="deploy the staging release")
# -> {"status": "pending", "request_id": "KVnPh…", "name": …, "reason": …}
...do whatever does not need the secret...
v = collect_secret(request_id=r["request_id"])
# -> {"status": "approved", "value": "...", "name": …, "reason": …}
```

`max_wait_s` makes it block instead, up to that many seconds — use it only when
you genuinely cannot continue. Even then, running out of time is **not** a
failure: the request is still live and still collectable with the same id.
Two things make long waits a bad bet here: an agent runs in a per-turn
container, and the MCP gateway cuts the connection before the five-minute
approval window is up.

**The `request_id` is how you tell your request apart** from any other approval
in flight. Hold on to it. Every answer — pending, approved, denied — restates
the secret name, your reason and the scope, so a later turn or a fresh
container can pick up where you left off without remembering anything.

So:

- **Never call it speculatively.** "Let me grab the key in case I need it" is a
  notification on someone's phone.
- **Never call it in a loop or a retry.** A denial is an answer, not a
  transient error.
- **Never re-request something you already have a `request_id` for.** That
  sends a second prompt for a question already on their screen. Use
  `collect_secret`.
- **Call `list_secrets` first** if you are unsure of the exact name. It is free
  and ungated. Guessing a name triggers a prompt for a secret that may not
  exist.
- **Keep the value in a variable.** Delivery is one-shot: the value is cleared
  server-side the moment it reaches you. Re-reading means another prompt.

## Some secrets no longer ask

A human can turn the gate off for an individual secret, in the app's Settings
(Apps › Secrets). `list_secrets` reports it per entry:

```
{"name": "staging_base_url", "description": "…", "auto_approve": true}
```

For those, `read_secret` returns `status: "approved"` with the value on the
first call — no prompt, no `request_id` to collect, no waiting. Everything else
about the call is unchanged, so you do not need to branch on it: read the
`value` if it is there, collect later if it is not.

Two things follow. **You cannot set this flag** — there is no tool for it, on
purpose: an agent that could switch the gate off in front of a secret could
then read that secret unasked, which would make the gate a formality. And a
secret being open is not an invitation to read it speculatively; it is still
someone's credential, and every read is still written to the audit log.

## Writing is NOT gated

`write_secret` needs no approval, on purpose: you already hold the value, so
asking a human to confirm it tells them nothing they do not already know. The
gate exists to stop a value *leaving* the vault.

Consequence worth knowing: writing an existing name **overwrites it**, with no
prompt and no undo. Call `list_secrets` first if you are not certain the name
is free.

`delete_secret` is ungated for the same reason — a delete releases no value, so
there is nothing for the gate to protect. It is irreversible: the value is gone
from the vault, not archived. It is also the thing to use when you want a
secret *empty*, because `write_secret` refuses an empty value rather than let a
typo blank one silently.

## From a terminal or a shell script — `aw-workspace-cli secrets`

The same five verbs, for when the caller is a person at a prompt or a script,
not an agent with a next turn.

```bash
aw-workspace-cli secrets ls [--json]
aw-workspace-cli secrets get <name> --reason "why" [--scope 60min] [--eval] [--json]
aw-workspace-cli secrets get <name> --no-wait          # print the request_id, exit 2
aw-workspace-cli secrets collect <request_id>
printf '%s' "$VALUE" | aw-workspace-cli secrets set <name> [--description "…"]
aw-workspace-cli secrets rm <name> --yes
```

Four differences from the MCP tools, each deliberate:

- **`get` blocks by default** (`--wait 300`). A person at a terminal has no
  "later" to collect in. Pass `--no-wait` for the MCP-style behaviour: it
  prints the `request_id` on stdout, remembers it, and exits 2.
- **The value goes to stdout and nothing else does.** Progress and errors are
  on stderr, so `aw-workspace-cli secrets get deploy_key > id_ed25519` works.
  `--eval` prints `export NAME=value` lines instead, for
  `eval "$(aw-workspace-cli secrets get deploy_env --eval)"`.
- **Running `get` again resumes** an approval you already asked for instead of
  sending a second prompt — so the "approve it and run the same command again"
  advice is literally true.
- **`set` never takes the value as an argument**, only from stdin (or a
  no-echo prompt on a tty). argv lands in shell history, in `ps`, and in
  `/proc/<pid>/cmdline`.

Exit codes: `0` ok · `1` error or denial · `2` requested but not collected yet
· `130` interrupted. `1` and `2` are separate on purpose — retrying a `2` is
reasonable, retrying a `1` means asking a person who already said no.

There is no `set-policy` verb, for the reason above: the caller a gate exists
to interrupt must not be able to disarm it.

## Your `reason` is the whole decision

It is the only thing the human sees besides the name. They are looking at a
phone, deciding in a few seconds.

- `"deploy the staging release"` → approved
- `"agent request"` / `"need it for a task"` → looks like something went wrong,
  and gets denied

Write the reason as if the person reading it has no idea what you are working
on, because they usually do not.

## Scopes

| scope | behaviour | when |
|---|---|---|
| `one_shot` (default) | value delivered exactly once | almost always |
| `10min` / `60min` | the SAME calling process can re-read without a new prompt | only when you genuinely need repeated reads in one task |

Ask for a window only when you know you will re-read. A wider scope is not a
convenience — it is a longer period in which the secret can be pulled again
without anyone being asked.

## Failure modes, and what each means

They are deliberately distinguishable; do not treat them alike.

| what you get | means | what to do |
|---|---|---|
| `not approved: … denied by the human` | they said no | **stop**. Do not retry. Report that it was refused. |
| `not approved: … expired with no answer` | nobody looked in time | ask the user directly, in chat, whether to try again |
| `status: "pending"` from either tool | the human has not answered yet | wait and `collect_secret` again — do NOT issue a new `read_secret` |
| `not approved: … already delivered (one-shot)` | you polled twice | you already had the value — look for it before requesting again |
| `no secret store reachable` | this workspace never completed the aw-remote-host `/link` handshake | not a missing secret. Say the workspace is unlinked. |
| `bad request: reason is required` | you omitted the reason | write one (see above) |

## What this is NOT

An app's own config secrets — `ctx.secrets`, capability `secrets:own` — are a
**different store**: per-app, unshared, and ungated. That is where
`aw-app-git`'s GitHub token and `remote-screen`'s VNC passwords live. These
tools are the shared, human-gated vault. Do not use one expecting the other.
