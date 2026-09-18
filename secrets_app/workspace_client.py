"""Reaching this app's own REST surface over the workspace's HTTP API.

Used only by ``secrets_app.cli`` — the ``aw-workspace-cli secrets`` command,
which runs in a DIFFERENT process (often a different container) from the
workspace server this app is loaded into. So the CLI talks to the app over
HTTP rather than importing :class:`SecretTools` in-process: the in-process
route needs ``httpx`` and ``fastapi``, neither of which the CLI's interpreter
is guaranteed to have, and going through the REST routes keeps "reading needs
approval" on one code path instead of two.

Deliberately self-contained: it does NOT import ``src.cli.local_client`` from
aw-workspace, even though this code usually runs inside that CLI's process and
the import would work. Two reasons, both learned the hard way in this
codebase — an app that reaches into core's internals breaks on a core refactor
it never saw, and a module that can only be imported with aw-workspace on
``sys.path`` cannot be unit-tested in this repo's own CI.

So the address/auth logic is reproduced here, which is a duplication worth
naming:

* **address** — ``AW_WORKSPACE_API_URL`` from the environment or from
  ``<workspace>/.aw-workspace/.env``, falling back to loopback. The env var
  exists because a command run by an agent executes inside a spawned runner
  container: it shares the workspace filesystem but not the server's network
  namespace, so ``127.0.0.1:9030`` is dead there while the published tunnel URL
  works from both.
* **auth** — the workspace API key as ``X-Api-Key``. The CLI has no way to hold
  the browser's identity JWT; the server mints this key at boot and mirrors it
  into that same ``.env`` (0600) precisely so sibling processes can read it.

Nothing here logs or returns a secret value beyond the one call that exists to
fetch it, and that value never touches this module's log output.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 30.0
API_URL_VAR = "AW_WORKSPACE_API_URL"
API_KEY_VAR = "AW_WORKSPACE_API_KEY"
CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")


class WorkspaceUnreachable(RuntimeError):
    """No usable address or key — say which, never a bare connection error."""


def _env_file() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(CONTAINER_DIR, ".aw-workspace")
    return os.path.join(home, ".env")


def _from_env_file(name: str) -> str | None:
    try:
        with open(_env_file(), "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip() or None
    except OSError:
        return None
    return None


def base_url() -> str:
    return (os.environ.get("AW_LOCAL_API_URL")
            or os.environ.get(API_URL_VAR)
            or _from_env_file(API_URL_VAR)
            or f"http://127.0.0.1:{os.environ.get('AW_PORT', '9030')}")


def api_key() -> str:
    key = os.environ.get(API_KEY_VAR) or _from_env_file(API_KEY_VAR)
    if not key:
        raise WorkspaceUnreachable(
            f"{API_KEY_VAR} not found in the environment or {_env_file()} — "
            "is the workspace server running?"
        )
    return key


def request(method: str, path: str, body: dict | None = None,
            timeout: float = DEFAULT_TIMEOUT) -> tuple[int, object]:
    """``(status, parsed_body)``. HTTP errors come back as a status, not an
    exception — a 403 from the approval gate is an answer, not a crash."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base_url() + path, data=data, method=method,
        headers={"X-Api-Key": api_key(),
                 **({"Content-Type": "application/json"} if data else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(), exc.code
    except urllib.error.URLError as exc:
        raise WorkspaceUnreachable(
            f"could not reach the workspace API at {base_url()}: {exc.reason}"
        ) from exc
    try:
        return status, json.loads(raw.decode() or "null")
    except (ValueError, UnicodeDecodeError):
        return status, raw.decode(errors="replace")


__all__ = ["request", "base_url", "api_key", "WorkspaceUnreachable"]
