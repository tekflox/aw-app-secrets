"""REST + MCP sub-app, mounted by the runtime at ``/api/apps/secrets``.

The REST half is the human/curl surface; the MCP half is what agents use. Both
call the same :class:`SecretTools`, so there is one implementation of "reading
needs approval" and no second path around it.

Every route here sits behind the framework's ``IdentityGuard`` — this app never
re-implements auth, and deliberately does not ask for ``auth_required: false``.
"""
from __future__ import annotations

import logging

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from .backend_client import ApprovalDenied, BackendUnavailable
from .tools import SecretTools

log = logging.getLogger("aw_apps.secrets")

#: Set by the Agents Platform in each agent's MCP config and forwarded by
#: aw-mcp-gateway. Names the agent SESSION, which is stable across the per-turn
#: containers an agent runs in — unlike X-Aw-Caller-Run-Id, which is not.
SESSION_HEADER = "X-Aw-Caller-Session-Id"

#: The calling agent's id, same shape week to week — what an allowlist names.
AGENT_HEADER = "X-Aw-Caller-Agent"


def build_app(tools: SecretTools) -> FastAPI:
    api = FastAPI()

    def _fail(exc: Exception):
        if isinstance(exc, BackendUnavailable):
            return HTTPException(status_code=503, detail=str(exc))
        if isinstance(exc, ApprovalDenied):
            # 403, not 500: a refusal is the system working, not breaking.
            return HTTPException(status_code=403, detail=str(exc))
        if isinstance(exc, ValueError):
            return HTTPException(status_code=400, detail=str(exc))
        return HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}")

    @api.get("/secrets")
    async def list_secrets():
        try:
            return await run_in_threadpool(tools.list_secrets)
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.post("/secrets")
    async def write_secret(data: dict = Body(...)):
        try:
            return await run_in_threadpool(
                tools.write_secret, data.get("name", ""), data.get("value", ""),
                data.get("description", ""))
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.delete("/secrets/{name}")
    async def delete_secret(name: str):
        try:
            return await run_in_threadpool(tools.delete_secret, name)
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.post("/secrets/{name}/read")
    async def read_secret(name: str, request: Request, data: dict = Body(default={})):
        """Returns a request_id immediately unless max_wait_s says otherwise.

        ``session`` in the body is how a CLI in ANOTHER container names its
        caller: this process cannot see that process's env or parent shell, so
        it has to be told. A header is accepted too, for the same reason and by
        the same rule as the MCP path.
        """
        try:
            return await run_in_threadpool(
                tools.read_secret, name, (data or {}).get("reason", ""),
                (data or {}).get("scope"), "rest", (data or {}).get("max_wait_s"),
                (data or {}).get("session") or request.headers.get(SESSION_HEADER),
                (data or {}).get("caller_key"),
                (data or {}).get("agent") or request.headers.get(AGENT_HEADER))
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.put("/policies/{name}")
    async def set_policy(name: str, data: dict = Body(default={})):
        """Turn the human approval gate on or off for one secret.

        Not mirrored as an MCP tool on purpose — see SecretTools.set_policy.
        """
        try:
            return await run_in_threadpool(
                tools.set_policy, name, bool((data or {}).get("auto_approve")),
                str((data or {}).get("updated_by") or "aw-app-secrets"),
                str((data or {}).get("note") or ""))
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.get("/panel")
    async def panel():
        """The Settings UI. HTML, served from this app, rendered in an iframe.

        Deliberately not under ``/api/apps/secrets/ui/`` — core serves app ESM
        bundles from that prefix and would shadow this route.
        """
        from fastapi.responses import HTMLResponse

        from .panel import PANEL_HTML
        return HTMLResponse(PANEL_HTML)

    @api.get("/requests/{request_id}")
    async def collect_secret(request_id: str):
        try:
            return await run_in_threadpool(tools.collect_secret, request_id)
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    # MCP — Streamable HTTP, auto-discovered by aw-mcp-gateway's app-scan
    # (see mcp/self_register.py + mcp/http_handler.py).
    @api.post("/mcp")
    async def mcp_post(request: Request, data: dict | list = Body(...)):
        from .mcp.http_handler import handle as mcp_handle

        # The calling agent's session, forwarded by aw-mcp-gateway from the
        # header the Agents Platform writes into that agent's MCP config. A
        # header rather than a tool argument: the agent never gets to say who
        # it is, so it cannot claim another session's window grant.
        session = request.headers.get(SESSION_HEADER)
        agent = request.headers.get(AGENT_HEADER)
        msgs = data if isinstance(data, list) else [data]
        out = []
        for m in msgs:
            r = await mcp_handle(m, tools, session, agent)
            if r:
                out.append(r)
        if not out:
            return {}
        return out if isinstance(data, list) else out[0]

    @api.get("/mcp")
    async def mcp_get():
        from fastapi.responses import Response
        return Response(status_code=405)

    return api
