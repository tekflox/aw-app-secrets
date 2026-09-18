"""``aw-workspace-cli secrets`` — the vault from a terminal, or from a script.

The successor to the monolith's ``./aw secrets``. Same five verbs, same
``--eval`` output, so the muscle memory and the shell snippets that already
exist keep working:

    aw-workspace-cli secrets ls
    aw-workspace-cli secrets get resend_api_key --reason "deploy staging"
    eval "$(aw-workspace-cli secrets get deploy_env --eval)"
    printf '%s' "$TOKEN" | aw-workspace-cli secrets set github_token
    aw-workspace-cli secrets rm stale_key --yes

Four things here are not obvious and each one is load-bearing.

**1. This module must import with no third-party packages present.** It runs
in ``aw-workspace-cli``'s interpreter, not the workspace server's, and that
interpreter is not guaranteed to have ``httpx`` or ``fastapi``. So it talks to
this app over REST via :mod:`.workspace_client` (urllib, stdlib) and never
imports ``.tools`` / ``.backend_client`` / ``.routes``. ``tests/test_cli.py``
pins that down by importing this module with both packages blocked.

**2. ``get`` blocks, unlike the MCP tool.** A person typing this is sitting in
front of the terminal; "collect it later" is advice for an agent with a next
turn, not for a shell pipeline. The default is ``--wait 300``.

**3. The waiting is done HERE, in short polls** — ``max_wait_s: 0`` goes to
the server every time. Not a style choice: a command run from an agent-runner
container reaches the workspace through the tunnel edge, which cuts any
request at ~30s. A server-side wait would die at 30 seconds with "502
workspace offline" — a message describing neither what happened nor what to
do — while the approval it was waiting for was still perfectly alive.

**4. stdout carries the payload and nothing else.** Progress, warnings and
explanations go to stderr, so ``secrets get k > keyfile`` stays usable.

There is deliberately no ``set-policy`` verb. Turning a secret's approval gate
off is a decision for the person the gate protects, made in Settings — a
caller that can disarm its own gate has not been gated. Same reason
``SecretTools.set_policy`` is not exposed over MCP.
"""
from __future__ import annotations

import getpass
import json
import re
import sys
import time

from . import caller
from . import pending
from .workspace_client import WorkspaceUnreachable, request

SECRETS_PREFIX = "/api/apps/secrets"
POLL_INTERVAL_S = 2.0
VALID_SCOPES = ("one_shot", "10min", "60min")
DEFAULT_WAIT_S = 300

#: 0 ok · 1 error or denial · 2 asked but not collected · 130 interrupted.
#: 1 and 2 are separate so a script can tell "denied, stop" from "not yet,
#: come back" — collapsing them makes a retry loop the only safe reaction to
#: either, and retrying a denial is how an app starts spamming somebody's
#: phone.
EXIT_OK, EXIT_ERROR, EXIT_PENDING, EXIT_INTERRUPTED = 0, 1, 2, 130

USAGE = """aw-workspace-cli secrets — the workspace's shared vault.

  aw-workspace-cli secrets ls [--json]             every secret's name; never a value
  aw-workspace-cli secrets get <name> [opts]       read one, asking a human if it is gated
  aw-workspace-cli secrets set <name> [--description D]
                                                   store a value read from stdin
  aw-workspace-cli secrets rm <name> [--yes]       delete one
  aw-workspace-cli secrets collect <request_id>    pick up an approval granted later

Aliases: list=ls, add=write=set, delete=remove=rm.

Options for `get`:
  --reason TEXT     why you need it — the only thing the human sees besides the
                    name when deciding. 'deploy the staging release' gets
                    approved; the default does not always.
  --scope SCOPE     one_shot (default) | 10min | 60min. A window is reusable by
                    THIS terminal or THIS agent session, nobody else.
  --wait SECONDS    how long to wait for the answer (default 300)
  --no-wait         print the request_id and exit 2; collect it later
  --eval            print `export NAME=value` lines instead of the raw value
  --json            machine-readable; the value is the only secret field in it

Exit codes: 0 ok · 1 error or denial · 2 requested but not collected · 130 interrupted.

Reading interrupts a person. `ls` is free and ungated — use it to check a name
before `get` guesses one, or the notification they get is for a secret that
was never going to exist.
"""


class CliError(RuntimeError):
    """Something went wrong and the message says what. Never a traceback."""


class Denied(RuntimeError):
    """The human said no, or the request expired. An answer, not a failure —
    and never something to retry."""


class StillPending(RuntimeError):
    """Asked, not answered yet. The request is alive and collectable."""

    def __init__(self, message: str, request_id: str) -> None:
        super().__init__(message)
        self.request_id = request_id


def _announce(message: str) -> None:
    """Progress that is not output. stderr, so it never lands in a pipe the
    caller is parsing — ``aw-workspace-cli secrets get k > keyfile`` has to
    stay usable."""
    print(message, file=sys.stderr)


# ── entry point ──────────────────────────────────────────────────────────

def main(args: list[str]) -> int:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return EXIT_OK
    verb, rest = args[0], args[1:]
    try:
        if verb in ("ls", "list"):
            return _cmd_ls(rest)
        if verb in ("get", "show", "cat", "fetch"):
            return _cmd_get(rest)
        if verb in ("set", "add", "write", "create", "update"):
            return _cmd_set(rest)
        if verb in ("rm", "remove", "delete", "del"):
            return _cmd_rm(rest)
        if verb == "collect":
            return _cmd_collect(rest)
        print(f"aw-workspace-cli secrets: unknown verb {verb!r}\n", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return EXIT_ERROR
    except Denied as exc:
        print(f"aw-workspace-cli secrets: denied — {exc}", file=sys.stderr)
        return EXIT_ERROR
    except StillPending as exc:
        print(f"aw-workspace-cli secrets: {exc}", file=sys.stderr)
        return EXIT_PENDING
    except (CliError, WorkspaceUnreachable) as exc:
        print(f"aw-workspace-cli secrets: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\naw-workspace-cli secrets: interrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED


# ── flag parsing ─────────────────────────────────────────────────────────

_FLAGS_WITH_VALUE = {"--reason", "--scope", "--wait", "--description"}
_BOOL_FLAGS = {"--json", "--eval", "--export", "--env", "--no-wait", "--yes", "-y"}


def _parse(args: list[str], allowed: set[str]) -> tuple[dict, list[str]]:
    """``(options, positionals)``, refusing anything not in ``allowed``.

    Refusing rather than ignoring: ``secrets get k --scpoe 60min`` that quietly
    read one_shot would look like it worked and re-prompt an hour later for
    reasons nobody could trace back to a typo.
    """
    opts: dict = {}
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        key, inline = (a.split("=", 1) + [None])[:2] if a.startswith("--") and "=" in a else (a, None)
        if key in _BOOL_FLAGS:
            if key not in allowed:
                raise CliError(f"{key} is not an option of this command")
            if inline is not None:
                raise CliError(f"{key} takes no value")
            opts[key.lstrip("-")] = True
        elif key in _FLAGS_WITH_VALUE:
            if key not in allowed:
                raise CliError(f"{key} is not an option of this command")
            if inline is None:
                if i + 1 >= len(args):
                    raise CliError(f"{key} needs a value")
                inline, i = args[i + 1], i + 1
            opts[key.lstrip("-")] = inline
        elif a.startswith("-") and a != "-":
            raise CliError(f"unknown option {a}")
        else:
            positional.append(a)
        i += 1
    return opts, positional


def _one_name(positional: list[str], verb: str) -> str:
    if len(positional) != 1 or not positional[0].strip():
        raise CliError(f"usage: aw-workspace-cli secrets {verb} <name>")
    return positional[0].strip()


# ── verbs ────────────────────────────────────────────────────────────────

def _cmd_ls(args: list[str]) -> int:
    opts, positional = _parse(args, {"--json"})
    if positional:
        raise CliError("usage: aw-workspace-cli secrets ls [--json]")

    # Projected field by field rather than passed through, for the same reason
    # SecretTools.list_secrets does it: an extra field appearing upstream must
    # not be able to print a value from a command that promises names only.
    entries = [{"name": s.get("name", ""),
                "description": s.get("description") or "",
                "auto_approve": bool(s.get("auto_approve")),
                "auto_approve_for": s.get("auto_approve_for") or ""}
               for s in _inventory()]
    entries.sort(key=lambda e: e["name"])

    if opts.get("json"):
        print(json.dumps({"secrets": entries, "count": len(entries)}, indent=2))
        return EXIT_OK
    if not entries:
        print("No secrets in the vault. Add one with:\n"
              "    printf '%s' \"$VALUE\" | aw-workspace-cli secrets set <name>")
        return EXIT_OK
    width = max(len(e["name"]) for e in entries)
    print(f"{len(entries)} secret(s) — names only; `secrets get <name>` reads one:")
    for e in entries:
        gate = "open" if e["auto_approve"] else ("allowlist" if e["auto_approve_for"] else "gated")
        note = f"  # {e['description']}" if e["description"] else ""
        print(f"  {e['name']:<{width}}  [{gate}]{note}")
    return EXIT_OK


def _cmd_get(args: list[str]) -> int:
    opts, positional = _parse(args, {"--reason", "--scope", "--wait", "--no-wait",
                                     "--eval", "--export", "--env", "--json"})
    name = _one_name(positional, "get")
    as_eval = bool(opts.get("eval") or opts.get("export") or opts.get("env"))
    as_json = bool(opts.get("json"))
    if as_eval and as_json:
        raise CliError("--eval and --json are two different output formats; pick one")

    scope = opts.get("scope", "one_shot")
    if scope not in VALID_SCOPES:
        raise CliError(f"--scope must be one of {', '.join(VALID_SCOPES)} (got {scope!r})")
    # Tracked separately from wait==0: `--no-wait` asks for a ticket and gets
    # it on stdout, while `--wait 0` asked for a value and must leave stdout
    # empty when it does not get one. Same duration, different promise.
    no_wait = bool(opts.get("no-wait"))
    wait = DEFAULT_WAIT_S
    if no_wait:
        wait = 0
    elif "wait" in opts:
        if not str(opts["wait"]).isdigit():
            raise CliError("--wait takes a number of seconds")
        wait = int(opts["wait"])
    reason = (opts.get("reason") or "").strip() or f"aw-workspace-cli secrets get {name}"

    # Free and ungated, and it runs BEFORE anything is requested: every read of
    # a name that does not exist is a notification on somebody's phone for a
    # secret that was never going to be there. The monolith's ./aw secrets sent
    # exactly that whenever a name was typed slightly wrong.
    available = [s.get("name", "") for s in _inventory()]
    if name not in available:
        raise CliError(
            f"no secret named {name!r} in the vault — nobody was asked. Present: "
            f"{', '.join(sorted(n for n in available if n)) or '(none)'}"
        )

    value = _fetch(name, reason, scope, wait, no_wait=no_wait, announce=not as_json)
    _emit_value(name, value, as_eval=as_eval, as_json=as_json)
    return EXIT_OK


def _cmd_set(args: list[str]) -> int:
    """Writing is ungated on purpose (see SecretTools.write_secret): the caller
    already holds the value, so a prompt would confirm nothing.

    The value is read from stdin or prompted for, and is NEVER an argument.
    argv lands in shell history, in ``ps``, and in ``/proc/<pid>/cmdline`` —
    and that last one is what an auto-approve allowlist matches on.
    """
    opts, positional = _parse(args, {"--description"})
    name = _one_name(positional, "set")

    if sys.stdin.isatty():
        value = getpass.getpass(f"Value for {name!r} (not echoed): ")
    else:
        value = sys.stdin.read()
    value = value.strip()
    if not value:
        raise CliError(
            f"nothing on stdin — {name!r} was not written. To remove a secret use "
            f"`aw-workspace-cli secrets rm {name}`, so that clearing one is never "
            f"something an empty pipe can do."
        )

    status, body = request("POST", f"{SECRETS_PREFIX}/secrets", {
        "name": name, "value": value,
        "description": (opts.get("description") or "").strip(),
    })
    body = _checked(name, status, body)
    _announce(f"Stored {name!r} ({body.get('action', 'written')}). Reading it back asks "
              f"for approval unless you turn that off in Settings › Secrets.")
    return EXIT_OK


def _cmd_rm(args: list[str]) -> int:
    """Ungated — a delete emits no value, so there is nothing for the approval
    gate to protect. It is irreversible though, so it asks: ``--yes``, or type
    the name back. Not a tty and no ``--yes`` is a refusal rather than a
    guess, because the caller in that case is a script and a script that meant
    it can say so."""
    opts, positional = _parse(args, {"--yes", "-y"})
    name = _one_name(positional, "rm")
    confirmed = bool(opts.get("yes") or opts.get("y"))

    if not confirmed:
        if not sys.stdin.isatty():
            raise CliError(
                f"refusing to delete {name!r} unattended. Re-run with --yes if that "
                f"is what you meant."
            )
        _announce(f"Deleting {name!r} cannot be undone. Type the name to confirm:")
        try:
            typed = input().strip()
        except EOFError:
            typed = ""
        if typed != name:
            raise CliError(f"that is not {name!r} — nothing was deleted.")

    status, body = request("DELETE", f"{SECRETS_PREFIX}/secrets/{name}")
    body = _checked(name, status, body)
    # An outstanding approval for a secret that no longer exists is not worth
    # resuming, and leaving the note behind is actively wrong: recreate the
    # same name inside MAX_AGE_S and the next `get` would resume the DELETED
    # secret's request instead of asking about the new one.
    pending.forget(name)
    _announce(f"Deleted {name!r}.")
    return EXIT_OK


def _cmd_collect(args: list[str]) -> int:
    opts, positional = _parse(args, {"--eval", "--export", "--env", "--json"})
    if len(positional) != 1 or not positional[0].strip():
        raise CliError("usage: aw-workspace-cli secrets collect <request_id>")
    request_id = positional[0].strip()
    as_eval = bool(opts.get("eval") or opts.get("export") or opts.get("env"))
    as_json = bool(opts.get("json"))
    if as_eval and as_json:
        raise CliError("--eval and --json are two different output formats; pick one")

    status, body = request("GET", f"{SECRETS_PREFIX}/requests/{request_id}")
    body = _checked(request_id, status, body)
    name = body.get("name") or "?"
    if body.get("status") == "pending":
        raise StillPending(
            f"{name!r} has not been answered yet. The prompt is still live — "
            f"approve it on Telegram, then run this again with the SAME id.",
            request_id)
    # Delivery is one-shot server-side, so whatever happens next this id is
    # spent for anyone else holding it.
    pending.forget(name)
    value = body.get("value")
    if not value:
        raise Denied(
            f"{name!r} was approved but carried no value — a one-shot grant that "
            f"had already been delivered. Request it again with "
            f"`aw-workspace-cli secrets get {name}`."
        )
    _emit_value(name, value, as_eval=as_eval, as_json=as_json)
    return EXIT_OK


# ── the gated read ───────────────────────────────────────────────────────

def _fetch(name: str, reason: str, scope: str, wait: int, *,
           no_wait: bool = False, announce: bool = True) -> str:
    """Request the value and wait for the human, polling client-side.

    ``max_wait_s: 0`` on every call and the waiting done here in short polls,
    because the tunnel edge cuts any single request at ~30s — see this
    module's docstring.
    """
    request_id, body = _resume(name)
    if body is None:
        if announce:
            _announce(f"# requesting '{name}' — approve on Telegram if asked")
        status, body = request("POST", f"{SECRETS_PREFIX}/secrets/{name}/read",
                               {"reason": reason, "scope": scope, "max_wait_s": 0,
                                # Who a window grant would belong to. Computed
                                # HERE because only this process can see its own
                                # session or shell — see caller.py.
                                "caller_key": caller.caller_key(allow_local=True),
                                # Stable across runs, so a scheduled task can be
                                # named on a secret's allowlist and read it
                                # without waking anybody.
                                "agent": caller.agent_identity()})
        body = _checked(name, status, body)
        request_id = body.get("request_id") or ""
        if request_id:
            # Written down BEFORE the wait, not after: the whole point is to
            # survive this process giving up, or dying.
            pending.remember(name, request_id)
    elif announce:
        _announce(f"# collecting the approval you already gave for '{name}'")

    deadline = time.monotonic() + max(0, wait)
    while True:
        if body.get("status") != "pending":
            pending.forget(name)
            value = body.get("value")
            if not value:
                raise Denied(
                    f"{name!r} was approved but carried no value — a one-shot grant "
                    f"that had already been delivered. Run the command again to "
                    f"request a fresh one."
                )
            return value

        if not request_id:
            raise CliError(
                f"the approval for {name!r} is pending but carried no request id, "
                f"so there is nothing to poll. This is a bug in aw-app-secrets."
            )
        if time.monotonic() >= deadline:
            if no_wait:
                # --no-wait asked for the ticket, not the value, so the ticket
                # IS this command's output and belongs on stdout. The elapsed
                # case below is the opposite: stdout was promised a value and
                # must stay empty rather than receive a request id a redirect
                # would silently capture into a file.
                print(request_id)
                raise StillPending(
                    f"requested {name!r}; nobody has answered yet. Approve it on "
                    f"Telegram, then: aw-workspace-cli secrets collect {request_id}",
                    request_id)
            raise StillPending(
                f"nobody answered the approval for {name!r} within {wait}s. The "
                f"request is still live and has been noted — approve it on Telegram "
                f"whenever you get to it and run the SAME command again; it will "
                f"pick up your answer instead of asking twice (or: "
                f"aw-workspace-cli secrets collect {request_id}).",
                request_id)
        time.sleep(POLL_INTERVAL_S)
        status, body = request("GET", f"{SECRETS_PREFIX}/requests/{request_id}")
        body = _checked(name, status, body)


def _resume(name: str) -> tuple[str, dict | None]:
    """An outstanding request for this secret, if one is still collectable.

    Returns ``(request_id, body)`` with ``body`` None when there is nothing to
    resume and a fresh request has to be made. Without this, "run it again"
    sends a SECOND prompt for a question already on somebody's screen.
    """
    request_id = pending.get(name)
    if not request_id:
        return "", None
    status, body = request("GET", f"{SECRETS_PREFIX}/requests/{request_id}")
    if status >= 400 or not isinstance(body, dict) or body.get("status") in (
            None, "not_found", "expired", "denied", "rejected"):
        pending.forget(name)
        return "", None
    return request_id, body


# ── output ───────────────────────────────────────────────────────────────

def _emit_value(name: str, value: str, *, as_eval: bool, as_json: bool) -> None:
    """The one place a value is printed. stdout, on its own, never logged."""
    if as_json:
        print(json.dumps({"name": name, "status": "approved", "value": value}))
        return
    if as_eval:
        for line in _to_export_lines(name, value):
            print(line)
        return
    # No trailing newline added: `secrets get k > keyfile` must produce the
    # value, not the value plus whatever a print() felt like appending. A
    # private key keeps the newline it was stored with.
    sys.stdout.write(value)
    if not value.endswith("\n") and sys.stdout.isatty():
        sys.stdout.write("\n")


_ENV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _to_export_lines(name: str, value: str) -> list[str]:
    """Convert a secret value to eval-friendly ``export KEY=VALUE`` lines.

    Ported unchanged from the monolith's ``./aw secrets get --eval``, because
    the shell snippets that call it already exist. If the value is a
    newline-separated list of KEY=VALUE pairs, each line gets an ``export``
    prefix — nothing is added or removed. Otherwise the whole value is
    exported under the normalised secret name.
    """
    lines = [line.rstrip() for line in value.splitlines() if line.strip()]
    if lines and all(_ENV_LINE.match(line) for line in lines):
        return [f"export {line}" for line in lines]

    var_name = name.upper().replace("-", "_").replace(".", "_").replace("/", "_")
    escaped = value.replace("'", "'\\''")
    return [f"export {var_name}='{escaped}'"]


# ── HTTP plumbing ────────────────────────────────────────────────────────

def _inventory() -> list[dict]:
    status, body = request("GET", f"{SECRETS_PREFIX}/secrets")
    if status == 503:
        raise CliError(
            "this workspace has no secret store: it never completed the "
            "aw-remote-host /link handshake, so there is nothing to read."
        )
    if status >= 400 or not isinstance(body, dict):
        raise CliError(f"could not list secrets (HTTP {status}): {_detail(body)}")
    return [s for s in body.get("secrets", []) if isinstance(s, dict)]


def _checked(name: str, status: int, body) -> dict:
    """Turn an HTTP answer into either a usable body or the right exception.

    A 403 is the human saying no — an answer, not a failure — so it has its own
    type and must never be retried.
    """
    if status == 403:
        raise Denied(_detail(body) or f"the request for {name!r} was refused")
    if status == 503:
        raise CliError(_detail(body) or "no secret store reachable")
    if status >= 400 or not isinstance(body, dict):
        raise CliError(f"{name!r}: {_detail(body) or 'no detail'} (HTTP {status})")
    return body


def _detail(body) -> str:
    if isinstance(body, dict):
        return str(body.get("detail") or body.get("error") or "")
    return str(body or "")


__all__ = ["main", "USAGE", "CliError", "Denied", "StillPending",
           "EXIT_OK", "EXIT_ERROR", "EXIT_PENDING", "EXIT_INTERRUPTED"]
