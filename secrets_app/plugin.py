"""Entrypoint referenced by aw-app.json's runtime.entrypoint.

This app stores nothing. It is a gate in front of aw-backend's
``/api/approval/*`` (itself backed by aw-vault), so it holds no database, no
files and no cache — only the credential it reads from its own environment.

Two things it deliberately does NOT do:

* re-implement auth. Its routes sit behind the framework's ``IdentityGuard``
  like every other app's.
* duplicate ``ctx.secrets``. That facade (capability ``secrets:own``) is an
  app's PRIVATE config store — per-app, unshared, ungated. This app is the
  shared, human-gated one. Conflating them would give every app a way to read
  the vault without a prompt.
"""
from __future__ import annotations

import logging
import os

from . import routes as routes_mod
from .backend_client import SecretsBackend
from .mcp import self_register as mcp_self_register
from .tools import SecretTools

log = logging.getLogger("aw_apps.secrets")


class SecretsAppPlugin:
    async def activate(self, ctx) -> None:
        self.ctx = ctx
        cfg = getattr(ctx, "config", None) or {}

        backend = SecretsBackend()
        self.tools = SecretTools(
            backend,
            default_scope=cfg.get("default_scope") or "one_shot",
            poll_timeout_s=int(cfg.get("poll_timeout_s") or 300),
        )

        if not backend.configured:
            # Activate anyway: a workspace with no cloud link should still boot
            # with the app present and every call answering 503 with the reason,
            # rather than the app silently missing and its tools absent.
            log.warning(
                "aw-app-secrets: no cloud link (AW_BACKEND_URL / "
                "AW_WORKSPACE_HOST_TOKEN unset) — tools will report 503 until "
                "the aw-remote-host /link handshake has run"
            )

        ctx.routes.register(routes_mod.build_app(self.tools))

        # Best-effort, like every other app's: registration is how OTHER
        # processes find us, never something this app's own routes depend on.
        port = int(os.environ.get("AW_PORT", "9030"))
        mcp_self_register.register_self(getattr(ctx, "package_dir", "") or "", port)

        log.info("aw-app-secrets activated (backend=%s)",
                 "configured" if backend.configured else "unlinked")

    async def deactivate(self) -> None:
        log.info("aw-app-secrets deactivated")
