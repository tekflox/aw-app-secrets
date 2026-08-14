"""Write this app's ``mcp.json`` so aw-mcp-gateway's app-scan finds the
``/mcp`` endpoint without manual wiring — mirrors aw-app-diff-tool's
``diff_app/mcp/self_register.py``.

Tier-1 (in-process): this IS the aw-workspace process, so ``gethostname()``
returns the same value ``ContainerSupervisor`` injects into sibling containers
as ``AW_WORKSPACE_HOST``, and the workspace API key is already in this
process's own environment. Nothing secret leaves here.
"""
from __future__ import annotations

import json
import logging
import os
import socket

log = logging.getLogger("aw_apps.secrets")

MCP_SERVER_NAME = "aw-secrets"


def register_self(package_dir: str, port: int) -> None:
    """Best-effort; a bare dev run with no package_dir simply no-ops."""
    if not package_dir:
        return
    try:
        payload = {
            "mcpServers": {
                MCP_SERVER_NAME: {
                    "type": "http",
                    "url": f"http://{socket.gethostname()}:{port}/api/apps/secrets/mcp",
                    "headers": {"X-Api-Key": os.environ.get("AW_WORKSPACE_API_KEY", "")},
                }
            }
        }
        with open(os.path.join(package_dir, "mcp.json"), "w") as fh:
            json.dump(payload, fh, indent=2)
    except Exception:  # noqa: BLE001 — never block activation on discovery
        log.exception("aw-app-secrets: mcp self-register failed")
