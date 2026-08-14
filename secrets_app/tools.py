"""The three secret tools, independent of how they're exposed (MCP or REST).

Shape of the thing, so the split makes sense:

  list_secrets  — names + metadata. Never a value. Cheap, ungated.
  write_secret  — create/replace. Ungated ON PURPOSE: the caller already holds
                  the value, so asking a human to confirm it tells them nothing
                  they don't already know. The gate exists to stop a value
                  LEAVING the vault.
  read_secret   — the gated one. Fires a Telegram approval to the sysadmin bot,
                  waits, and returns the value once.

read_secret blocks by design. An agent asking for a secret cannot do anything
useful until it has one, and a "check back later" handle would just push the
polling into every caller. The wait is bounded (aw-backend expires a pending
request at 300s) and every outcome is distinguishable — approved, denied,
expired, no-store — because "it didn't work" is the failure mode that cost the
most time in this system's history.
"""
from __future__ import annotations

import logging
import time

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
                {"name": s.get("name"), "description": s.get("description") or ""}
                for s in secrets
            ],
            "count": len(secrets),
            # Said out loud so an agent doesn't read the absence of values as a
            # failure and start hunting for a flag to make them appear.
            "note": "names only — use read_secret to obtain a value (asks a human).",
        }

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
                    caller: str = "") -> dict:
        """Request a human's approval and return the value.

        ``reason`` is not decoration: it is the only thing the human sees
        besides the secret's name when deciding, so it is required rather than
        defaulted to something like "agent request".
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

        request_id = self.backend.request_read(name, reason, scope, caller)
        log.info("secrets: read requested for %s (scope=%s, request=%s)",
                 name, scope, request_id)

        deadline = time.monotonic() + self.poll_timeout_s
        while time.monotonic() < deadline:
            status, value = self.backend.poll_read(request_id)
            if status == "approved":
                if value is None:
                    # Approved but nothing delivered: the one-shot value was
                    # already consumed by another poll. Say exactly that rather
                    # than returning an empty string that reads like a secret
                    # whose value is "".
                    raise ApprovalDenied(
                        f"'{name}' was approved but its value was already delivered "
                        "(one-shot). Request it again."
                    )
                return {"ok": True, "name": name, "value": value,
                        "scope": scope, "request_id": request_id}
            if status in ("denied", "rejected"):
                raise ApprovalDenied(f"'{name}' was denied by the human.")
            if status == "expired":
                raise ApprovalDenied(
                    f"the request for '{name}' expired with no answer."
                )
            time.sleep(POLL_INTERVAL_S)

        raise ApprovalDenied(
            f"timed out after {self.poll_timeout_s}s waiting for approval of '{name}'. "
            "The prompt was delivered; nobody answered it."
        )

    def delete_secret(self, name: str) -> dict:
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        self.backend.delete_secret(name)
        return {"ok": True, "name": name, "deleted": True}


__all__ = ["SecretTools", "ApprovalDenied", "BackendUnavailable", "VALID_SCOPES"]
