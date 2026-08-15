"""The three secret tools, independent of how they're exposed (MCP or REST).

Shape of the thing, so the split makes sense:

  list_secrets  — names + metadata. Never a value. Cheap, ungated.
  write_secret  — create/replace. Ungated ON PURPOSE: the caller already holds
                  the value, so asking a human to confirm it tells them nothing
                  they don't already know. The gate exists to stop a value
                  LEAVING the vault.
  read_secret   — the gated one. Fires a Telegram approval to the sysadmin bot
                  and, by default, does NOT wait: it returns a request_id the
                  agent collects later.
  collect_secret— pick up a request by id, from any process, any turn.

read_secret used to block for up to five minutes. That was wrong here for two
measured reasons: an agent of this platform runs in a per-turn container, so
holding a process open waiting for a human to look at their phone bets against
the architecture; and the MCP gateway cuts the connection well before the
window is up (seen live — `http upstream 'aw-secrets' error`). ``max_wait_s``
now defaults to 0, and a timeout is not an error: the request stays alive and
collectable.

Every outcome is distinguishable — approved, denied, expired, already
delivered, still pending, no store at all — because "it didn't work" is the
failure mode that has cost the most time in this system.
"""
from __future__ import annotations

import logging
import time

from . import caller as caller_module
from .backend_client import ApprovalDenied, BackendUnavailable, SecretsBackend

log = logging.getLogger("aw_apps.secrets")

VALID_SCOPES = ("one_shot", "10min", "60min")
POLL_INTERVAL_S = 2.0


class SecretTools:
    def __init__(self, backend: SecretsBackend, *, default_scope: str = "one_shot",
                 poll_timeout_s: int = 300) -> None:
        self.backend = backend
        self.default_scope = default_scope if default_scope in VALID_SCOPES else "one_shot"
        self.poll_timeout_s = poll_timeout_s

    def list_secrets(self) -> dict:
        secrets = self.backend.list_secrets()
        return {
            "secrets": [
                {"name": s.get("name"), "description": s.get("description") or "",
                 # Whether reading this one still asks a human. Included because
                 # a list that hides it would describe the vault as uniformly
                 # gated when parts of it are not.
                 "auto_approve": bool(s.get("auto_approve")),
                 # The narrow form of the same thing: callers allowed past the
                 # prompt for this one secret. Empty means nobody.
                 "auto_approve_for": s.get("auto_approve_for") or ""}
                for s in secrets
            ],
            "count": len(secrets),
            # Said out loud so an agent doesn't read the absence of values as a
            # failure and start hunting for a flag to make them appear.
            "note": "names only — use read_secret to obtain a value. Ones marked "
                    "auto_approve return instantly; the rest ask a human first.",
        }

    def set_policy(self, name: str, auto_approve: bool, updated_by: str = "",
                   note: str = "", auto_approve_for: str | None = None) -> dict:
        """Turn the approval gate on or off for one secret.

        Not exposed as an MCP tool, deliberately. An agent that can disable the
        gate in front of a secret can then read that secret unasked, which
        makes the gate a formality — the flag is set by a human in the app's
        Settings, or by an explicit REST call, and never by the party the gate
        exists to interrupt.
        """
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        result = self.backend.set_policy(name, auto_approve, updated_by, note,
                                         auto_approve_for)
        log.warning("secrets: approval gate for %s is now %s (by %s)", name,
                    "OFF (instant release)" if auto_approve else "ON", updated_by or "?")
        return {"ok": True, **result}

    def write_secret(self, name: str, value: str, description: str = "") -> dict:
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        if value is None or value == "":
            raise ValueError(
                "value is required — to remove a secret use delete_secret, so that "
                "clearing one is never something a typo can do"
            )
        result = self.backend.write_secret(name, value, description)
        log.info("secrets: wrote %s (%s)", name, result.get("action", "written"))
        return {"ok": True, "name": name, "action": result.get("action", "written")}

    def read_secret(self, name: str, reason: str, scope: str | None = None,
                    caller: str = "", max_wait_s: int | None = None,
                    session: str | None = None,
                    caller_key: str | None = None,
                    agent: str | None = None) -> dict:
        """Request a human's approval for a secret.

        Returns a ``request_id`` ALWAYS — approved, denied or still pending.
        That id is how an agent tells "the thing I asked for" apart from any
        other approval in flight, and it is what :meth:`collect_secret` takes.

        ``max_wait_s`` decides whether this blocks at all:

        * ``0`` (the default) — return immediately with ``status: pending``.
          The agent carries on and collects later. This is the right mode for
          anything running in a per-turn container: holding a process open
          waiting for a human to look at their phone is betting against the
          architecture, and the MCP gateway cuts the connection long before
          the five-minute approval window is up anyway (seen live).
        * ``> 0`` — wait up to that many seconds, then return whatever is true
          at that moment. A timeout is NOT an error here: the request is still
          alive on the server and still collectable. Only an explicit denial or
          a genuine expiry raises.

        ``reason`` is required because it is the only thing the human sees
        besides the name when deciding.

        ``session`` names the agent session this read belongs to, when the
        caller knows it and this process cannot (the MCP path — the agent runs
        in one container, this code in another). It decides who a ``10min`` or
        ``60min`` grant is reusable by; see ``caller.py``.
        """
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        reason = (reason or "").strip()
        if not reason:
            raise ValueError(
                "reason is required — it is what the human reads when deciding "
                "whether to release this secret"
            )
        scope = scope if scope in VALID_SCOPES else self.default_scope
        # Absent means DO NOT WAIT. poll_timeout_s is the ceiling for an
        # explicit wait, not the default — reading it as the default is exactly
        # the bug this line replaces: the docstring said "0 (the default)" while
        # the code sat in the poll loop for the full 300s, and the first real
        # call blocked for 30s until curl gave up.
        wait = 0 if max_wait_s is None else min(max(0, int(max_wait_s)),
                                                self.poll_timeout_s)

        # Who this grant belongs to, if a window scope is in play.
        #
        # An explicit key wins: a CLI in another container is the only party
        # that can see its own shell, so it computes its own and sends it. What
        # this process may derive on its own is a SESSION and nothing else —
        # deriving a local one here would key on the app server's parent, which
        # is the same for every REST caller in the workspace.
        key = (caller_key or "").strip() or caller_module.caller_key(session)
        # A second, STABLE identity, used only for the per-secret allowlist —
        # a session key changes every run and could never be written down.
        agent_id = caller_module.agent_identity(agent)
        request_id = self.backend.request_read(name, reason, scope, caller, key, agent_id)
        log.info("secrets: read requested for %s (scope=%s, request=%s, max_wait=%ss)",
                 name, scope, request_id, wait)

        deadline = time.monotonic() + wait
        while True:
            status, value = self.backend.poll_read(request_id)
            if status == "approved":
                if value is None:
                    raise ApprovalDenied(
                        f"'{name}' was approved but its value was already delivered "
                        "(one-shot). Request it again."
                    )
                return self._delivered(request_id, name, reason, scope, value)
            if status in ("denied", "rejected"):
                raise ApprovalDenied(f"'{name}' was denied by the human.")
            if status == "expired":
                raise ApprovalDenied(f"the request for '{name}' expired with no answer.")
            if time.monotonic() >= deadline:
                return self._still_pending(request_id, name, reason, scope, wait)
            time.sleep(POLL_INTERVAL_S)

    def collect_secret(self, request_id: str) -> dict:
        """Collect a previously requested secret, or report where it stands.

        Self-describing on purpose: an agent calling this may be a DIFFERENT
        process from the one that asked — a later turn, a fresh container, a
        wake-up. It cannot be assumed to remember what the request was about,
        so every answer restates the secret name, the reason given and the
        scope, not just a status word.
        """
        request_id = (request_id or "").strip()
        if not request_id:
            raise ValueError("request_id is required")

        info = self.backend.describe(request_id)
        status = info.get("status")
        name = info.get("secret_name") or "?"
        reason = info.get("reason") or ""
        scope = info.get("scope") or "one_shot"

        if status == "approved" and info.get("value") is not None:
            return self._delivered(request_id, name, reason, scope, info["value"])
        if status == "approved":
            raise ApprovalDenied(
                f"'{name}' was approved but its value was already delivered "
                "(one-shot). Request it again."
            )
        if status in ("denied", "rejected"):
            raise ApprovalDenied(f"'{name}' was denied by the human.")
        if status == "expired":
            raise ApprovalDenied(f"the request for '{name}' expired with no answer.")
        if status in (None, "not_found"):
            raise ApprovalDenied(f"request {request_id} is unknown or has expired.")
        return self._still_pending(request_id, name, reason, scope, 0)

    # ── response shapes ──────────────────────────────────────────────────
    #
    # Both carry the full context of the request, not just a status. The
    # collector is often not the asker.

    @staticmethod
    def _delivered(request_id, name, reason, scope, value) -> dict:
        return {
            "ok": True, "status": "approved", "request_id": request_id,
            "name": name, "reason": reason, "scope": scope, "value": value,
            "note": "Delivered once. Keep it in a variable — collecting again "
                    "returns no value and re-reading prompts the human afresh.",
        }

    @staticmethod
    def _still_pending(request_id, name, reason, scope, waited) -> dict:
        return {
            "ok": True, "status": "pending", "request_id": request_id,
            "name": name, "reason": reason, "scope": scope,
            "note": (
                f"Not answered yet{f' after {waited}s' if waited else ''}. The prompt IS "
                f"delivered and still live — do NOT request it again, that only sends a "
                f"second prompt. Call collect_secret('{request_id}') later."
            ),
        }

    def delete_secret(self, name: str) -> dict:
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        self.backend.delete_secret(name)
        return {"ok": True, "name": name, "deleted": True}


__all__ = ["SecretTools", "ApprovalDenied", "BackendUnavailable", "VALID_SCOPES"]
