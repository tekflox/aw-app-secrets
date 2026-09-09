"""HTTP client to aw-backend's ``/api/workspaces/{slug}/approval/*`` — the
secret store.

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

2026-09-09: the far-side gap this module used to work around is closed. The
approval routes moved from the unscoped ``/api/approval/*`` to
``/api/workspaces/{slug}/approval/*`` and their guard changed to
``require_workspace_actor`` — the same one this client's token already
satisfies — as part of scoping the vault itself per workspace (before this,
ANY linked workspace's host token could read ANY workspace's secrets; see
identity_guard.py's history). ``self.workspace`` below is what supplies the
``{slug}`` — it was already being read from ``AW_WORKSPACE`` for the URL
path's `/app-installs` calls, just not yet threaded into these.
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


class BackendRequestFailed(RuntimeError):
    """aw-backend answered a call with a non-2xx status.

    Carries the real ``status_code`` and JSON ``detail`` aw-backend sent, so
    a caller can surface those instead of httpx's own generic "Client error
    '400 Bad Request' for url '...'" — that generic text was all a user ever
    saw for a downstream failure (e.g. the approval-delivery 500 that becomes
    a 400 here), which is what made bug:ssh-approval-request-400-error-
    swallowed slow to diagnose: the real reason never left aw-backend.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"aw-backend ({status_code}): {detail}")


def _response_detail(r: httpx.Response) -> str:
    """The JSON ``detail`` aw-backend sent with an error response, or the raw
    body when it didn't answer with the JSON shape every FastAPI error does."""
    try:
        detail = r.json().get("detail")
    except Exception:
        detail = None
    return detail if detail else r.text[:300]


class SecretsBackend:
    def __init__(self, backend_url: str | None = None, workspace: str | None = None,
                 token: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.backend_url = (backend_url or os.environ.get("AW_BACKEND_URL", "")).rstrip("/")
        self.workspace = workspace or os.environ.get("AW_WORKSPACE", "")
        self.token = token or os.environ.get("AW_WORKSPACE_HOST_TOKEN", "")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.backend_url and self.token and self.workspace)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _base(self) -> str:
        """This workspace's own approval-route root — every call below hangs
        off this. ``self.workspace`` is what the URL's ``{slug}`` needs; it
        also has to be the workspace the host token actually belongs to, or
        aw-backend's ``require_workspace_actor`` 401s (that mismatch is
        exactly what it exists to catch)."""
        return f"{self.backend_url}/api/workspaces/{self.workspace}/approval"

    def _require(self) -> None:
        if not self.configured:
            raise BackendUnavailable(
                "no cloud link: AW_BACKEND_URL, AW_WORKSPACE and AW_WORKSPACE_HOST_TOKEN must "
                "all be set. A BYOD workspace that never completed the aw-remote-host /link "
                "handshake has no secret store to reach."
            )

    # ── inventory ────────────────────────────────────────────────────────

    def list_secrets(self) -> list[dict]:
        """Names and metadata only — never values. Listing is not a read."""
        self._require()
        r = httpx.get(f"{self._base()}/secrets",
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
        r = httpx.post(f"{self._base()}/secrets",
                       json={"name": name, "value": value, "description": description},
                       headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def delete_secret(self, name: str) -> dict:
        self._require()
        r = httpx.delete(f"{self._base()}/secrets/{name}",
                         headers=self._headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── release policy ───────────────────────────────────────────────────

    def set_policy(self, name: str, auto_approve: bool, updated_by: str = "",
                   note: str = "", auto_approve_for: str | None = None) -> dict:
        """Turn the human approval gate on or off for one secret.

        Lives in aw-backend, not here, and that is the point: aw-backend is
        what decides whether a read needs a tap. A flag held app-side would be
        a client asking itself for permission — anything else calling
        ``.../approval/request`` would still be gated, and this app skipping
        its own prompt would just make the two disagree.
        """
        self._require()
        body = {"auto_approve": bool(auto_approve),
                "updated_by": updated_by, "note": note}
        # Omitted, not sent empty, when the caller did not mention it: absent
        # means "leave the allowlist alone", and sending "" would wipe it.
        if auto_approve_for is not None:
            body["auto_approve_for"] = auto_approve_for
        r = httpx.put(f"{self._base()}/policies/{name}",
                      json=body,
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
        r = httpx.post(f"{self._base()}/request",
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
        if r.is_error:
            raise BackendRequestFailed(r.status_code, _response_detail(r))
        return r.json()["request_id"]

    def describe(self, request_id: str) -> dict:
        """Full state of a request: status, and the metadata that says what it
        WAS — secret name, reason, scope.

        Needed because the collector is frequently not the asker: a later turn,
        a fresh container, a wake-up. Status alone would arrive without any way
        to know which of several in-flight approvals it belongs to.
        """
        self._require()
        r = httpx.get(f"{self._base()}/status/{request_id}",
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
        r = httpx.get(f"{self._base()}/status/{request_id}",
                      headers=self._headers(), timeout=self.timeout)
        if r.status_code == 404:
            raise ApprovalDenied(f"request {request_id} is unknown or has expired")
        r.raise_for_status()
        body = r.json()
        return body.get("status", "pending"), body.get("value")
