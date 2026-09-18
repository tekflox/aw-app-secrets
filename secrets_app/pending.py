"""Remembering an approval that was granted after we stopped waiting.

The sequence this exists for, observed end to end:

  1. the command asks for a secret and waits;
  2. nobody taps within the window, so it gives up and says — correctly — that
     the request is still live and to run it again;
  3. the person taps twenty minutes later. The grant is recorded, valid, and
     addressed to a request id nothing remembers;
  4. running the command again creates a NEW request and puts a SECOND prompt
     on their phone, for a question they already answered.

Step 4 is the bug, and it is the kind that makes people stop tapping. The
answer is small: write the request id down, and look for it before asking
again. Then "run it again" does what the message promised.

Kept on the workspace's shared storage, deliberately: the process that asked
is usually gone by the time the answer arrives — a per-turn agent container, a
terminal that was closed — and the one that picks it up is a different
process, often in a different container. A file in ``/tmp`` would be exactly
the wrong place.

``data/secrets/``, NOT ``data/ssh/``: aw-app-ssh keeps its own file of the
same shape, keyed by secret name. One shared file would make the two apps
collide the moment they both have an outstanding request for the same name.

It holds an id and a timestamp. Never a value.
"""
from __future__ import annotations

import json
import os
import time

CONTAINER_DIR = os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace")

#: Past this, stop offering it. aw-backend's widest scope is 60 minutes, so an
#: id older than that cannot still be collectable and polling it would only
#: delay the new request the caller actually needs.
MAX_AGE_S = 3900


def path() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(CONTAINER_DIR, ".aw-workspace")
    return os.path.join(home, "data", "secrets", "pending.json")


def _load() -> dict:
    try:
        with open(path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def get(secret_name: str) -> str | None:
    """The id of an outstanding request for this secret, if it is worth trying."""
    entry = _load().get(secret_name)
    if not isinstance(entry, dict):
        return None
    if time.time() - float(entry.get("at") or 0) > MAX_AGE_S:
        return None
    return entry.get("request_id") or None


def remember(secret_name: str, request_id: str) -> None:
    data = _load()
    data[secret_name] = {"request_id": request_id, "at": time.time()}
    _write(data)


def forget(secret_name: str) -> None:
    """Called the moment a request stops being collectable — delivered, denied
    or expired. Leaving a spent id behind would make the next run poll a dead
    request before asking, which delays the prompt for no reason."""
    data = _load()
    if data.pop(secret_name, None) is not None:
        _write(data)


def _write(data: dict) -> None:
    target = path()
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, target)
    except OSError:
        # Losing the note is a missed optimisation, not a failure: the next run
        # simply asks again, which is what it did before this file existed.
        pass


__all__ = ["get", "remember", "forget", "path", "MAX_AGE_S"]
