---
name: aw-secrets
description: Read, write and list this workspace's shared secrets from an agent. Reading asks a human for approval on Telegram and blocks until they answer. Use whenever a task needs an API key, token, SSH key or password that is not already in your environment — and read this BEFORE calling read_secret, because every call interrupts a person.
---

# aw-secrets — the workspace's shared secrets

Three tools, from `aw-app-secrets`, exposed through the gateway as
`aw__secrets__list_secrets`, `aw__secrets__write_secret`,
`aw__secrets__read_secret`.

Backed by **aw-vault** (Postgres, encrypted) through aw-backend's
`/api/approval/*`. The app itself stores nothing.

## The one thing to understand

**Reading interrupts a human.** `read_secret` sends a Telegram message to the
sysadmin bot with the secret's name and your reason, and blocks — up to five
minutes — until someone taps approve or deny.

So:

- **Never call it speculatively.** "Let me grab the key in case I need it" is a
  notification on someone's phone.
- **Never call it in a loop or a retry.** A denial is an answer, not a
  transient error.
- **Call `list_secrets` first** if you are unsure of the exact name. It is free
  and ungated. Guessing a name triggers a prompt for a secret that may not
  exist.
- **Keep the value in a variable.** Delivery is one-shot: the value is cleared
  server-side the moment it reaches you. Re-reading means another prompt.

## Writing is NOT gated

`write_secret` needs no approval, on purpose: you already hold the value, so
asking a human to confirm it tells them nothing they do not already know. The
gate exists to stop a value *leaving* the vault.

Consequence worth knowing: writing an existing name **overwrites it**, with no
prompt and no undo. Call `list_secrets` first if you are not certain the name
is free.

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
| `not approved: … nobody answered it` (timeout) | prompt delivered, unanswered | same as expired |
| `not approved: … already delivered (one-shot)` | you polled twice | you already had the value — look for it before requesting again |
| `no secret store reachable` | this workspace never completed the aw-remote-host `/link` handshake | not a missing secret. Say the workspace is unlinked. |
| `bad request: reason is required` | you omitted the reason | write one (see above) |

## What this is NOT

An app's own config secrets — `ctx.secrets`, capability `secrets:own` — are a
**different store**: per-app, unshared, and ungated. That is where
`aw-app-git`'s GitHub token and `remote-screen`'s VNC passwords live. These
tools are the shared, human-gated vault. Do not use one expecting the other.
