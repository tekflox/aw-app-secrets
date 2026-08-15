"""HTTP client to aw-backend's ``/api/approval/*`` — the secret store.

Auth: the workspace's OWN host credential, ``AW_WORKSPACE_HOST_TOKEN`` (an
``awlk_`` token minted by the aw-remote-host ``/link`` handshake and kept in
this process's environment). That is not a new credential invented for this
app — aw-backend's ``require_workspace_actor`` already accepts it and its
docstring names this exact case: "a decoupled app's own CLI/MCP reading
``AW_WORKSPACE_HOST_TOKEN`` from its environment". ``CloudRegistry``
(aw-workspace's ``src/apps/registry_client.py``) has been authenticating the
same way since F3.

Verified live on 2026-08-14 against the running deployment:

    GET  {backend}/api/workspaces/aw/app-installs        -> 200
    GET  {backend}/api/workspaces/naoexiste/app-installs -> 401

i.e. the token is durable, already present, and scoped to this workspace and
no other. No service account, and no long-lived credential carrying a human's
identity, is needed for this app to reach the secret API — a conclusion this
app was very nearly built on the opposite of.

The one thing still missing is on the far side: ``/api/approval/*`` is gated by
``require_identity`` (user JWTs only) rather than ``require_workspace_actor``,
so these calls 401 today. That is a change to aw-backend, not to this client —
which is why this module is written against the credential that *should* work
rather than a workaround that would have to be unpicked later.
"""
from __future__ import annotations

import logging
import os

import httpx

log = logging.getLogger("aw_apps.secrets")

DEFAULT_TIMEOUT = 20.0


class BackendUnavailable(RuntimeError):
    """The workspace has no cloud link, so there is no secret store to talk to."""


class ApprovalDenied(RuntimeError):
    """The human said no, or the request expired without an answer."""


class SecretsBackend:
    def __init__(self, backend_url: str | None = None, workspace: str | None = None,
                 token: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.backend_url = (backend_url or os.environ.get("AW_BACKEND_URL", "")).rstrip("/")
        self.workspace = workspace or os.environ.get("AW_WORKSPACE", "")
        self.token = token or os.environ.get("AW_WORKSPACE_HOST_TOKEN", "")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.backend_url and self.token)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _require(self) -> None:
        if not self.configured:
            raise BackendUnavailable(
                "no cloud link: AW_BACKEND_URL and AW_WORKSPACE_HOST_TOKEN must both be set. "
                "A BYOD workspace that never completed the aw-remote-host /link handshake has "
                "no secret store to reach."
            )

    # ── inventory ────────────────────────────────────────────────────────

    def list_secrets(self) -> list[dict]:
        """Names and metadata only — never values. Listing is not a read."""
        self._require()
        r = httpx.get(f"{self.backend_url}/api/approval/secrets",
                      headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("secrets", [])

    def write_secret(self, name: str, value: str, description: str = "") -> dict:
        """Create or replace a secret. Deliberately NOT gated by approval.

        Writing is not the dangerous direction: the caller already holds the
        value, so a prompt would confirm nothing it does not already know. The
        gate exists to stop a value *leaving* the vault, which is `read`.
        """
        self._require()
        r = httpx.post(f"{self.backend_url}/api/approval/secrets",
                       json={"name": name, "value": value, "description": description},
                       headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def delete_secret(self, name: str) -> dict:
        self._require()
        r = httpx.delete(f"{self.backend_url}/api/approval/secrets/{name}",
                         headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── release policy ───────────────────────────────────────────────────

    def set_policy(self, name: str, auto_approve: bool, updated_by: str = "",
                   note: str = "") -> dict:
        """Turn the human approval gate on or off for one secret.

        Lives in aw-backend, not here, and that is the point: aw-backend is
        what decides whether a read needs a tap. A flag held app-side would be
        a client asking itself for permission — anything else calling
        ``/api/approval/request`` would still be gated, and this app skipping
        its own prompt would just make the two disagree.
        """
        self._require()
        r = httpx.put(f"{self.backend_url}/api/approval/policies/{name}",
                      json={"auto_approve": bool(auto_approve),
                            "updated_by": updated_by, "note": note},
                      headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── the gated read ───────────────────────────────────────────────────

    def request_read(self, name: str, reason: str, scope: str = "one_shot",
                     caller: str = "", caller_key: str | None = None,
                     caller_agent: str | None = None) -> str:
        """Ask a human for this secret's value; returns the request id.

        Does not block. The value is collected by :meth:`poll_read` — the two
        are split so a caller can surface "waiting for approval" instead of
        hanging silently for up to five minutes with nothing on screen.
        """
        self._require()
        r = httpx.post(f"{self.backend_url}/api/approval/request",
                       json={"secret_name": name, "reason": reason, "scope": scope,
                             "caller_process": caller or f"aw-app-secrets/{self.workspace}",
                             # What a 10min/60min window is scoped to. Sent
                             # under the name aw-backend actually reads —
                             # `caller_process` was never one of them, which is
                             # why window scopes silently never worked.
                             "caller_key": caller_key,
                             # Stable across runs, so a per-secret allowlist
                             # can name it. caller_key cannot: it is the
                             # session, and that is new every time.
                             "caller_agent": caller_agent},
                       headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()["request_id"]

    def describe(self, request_id: str) -> dict:
        """Full state of a request: status, and the metadata that says what it
        WAS — secret name, reason, scope.

        Needed because the collector is frequently not the asker: a later turn,
        a fresh container, a wake-up. Status alone would arrive without any way
        to know which of several in-flight approvals it belongs to.
        """
        self._require()
        r = httpx.get(f"{self.backend_url}/api/approval/status/{request_id}",
                      headers=self._headers(), timeout=self.timeout)
        if r.status_code == 404:
            return {"status": "not_found"}
        r.raise_for_status()
        return r.json()

    def poll_read(self, request_id: str) -> tuple[str, str | None]:
        """Return ``(status, value)``. ``value`` is only ever set once.

        Delivery is one-shot server-side: the value is cleared from
        aw-backend's memory the moment it is handed over, so a second poll on
        an approved request returns no value. Callers must not retry a poll
        hoping to re-read it.
        """
        self._require()
        r = httpx.get(f"{self.backend_url}/api/approval/status/{request_id}",
                      headers=self._headers(), timeout=self.timeout)
        if r.status_code == 404:
            raise ApprovalDenied(f"request {request_id} is unknown or has expired")
        r.raise_for_status()
        body = r.json()
        return body.get("status", "pending"), body.get("value")
