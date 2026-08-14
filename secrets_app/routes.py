"""REST + MCP sub-app, mounted by the runtime at ``/api/apps/secrets``.

The REST half is the human/curl surface; the MCP half is what agents use. Both
call the same :class:`SecretTools`, so there is one implementation of "reading
needs approval" and no second path around it.

Every route here sits behind the framework's ``IdentityGuard`` — this app never
re-implements auth, and deliberately does not ask for ``auth_required: false``.
"""
from __future__ import annotations

import logging

from fastapi import Body, FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool

from .backend_client import ApprovalDenied, BackendUnavailable
from .tools import SecretTools

log = logging.getLogger("aw_apps.secrets")


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
    async def read_secret(name: str, data: dict = Body(default={})):
        """Returns a request_id immediately unless max_wait_s says otherwise."""
        try:
            return await run_in_threadpool(
                tools.read_secret, name, (data or {}).get("reason", ""),
                (data or {}).get("scope"), "rest", (data or {}).get("max_wait_s"))
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    @api.get("/requests/{request_id}")
    async def collect_secret(request_id: str):
        try:
            return await run_in_threadpool(tools.collect_secret, request_id)
        except Exception as exc:  # noqa: BLE001
            raise _fail(exc) from exc

    # MCP — Streamable HTTP, auto-discovered by aw-mcp-gateway's app-scan
    # (see mcp/self_register.py + mcp/http_handler.py).
    @api.post("/mcp")
    async def mcp_post(data: dict | list = Body(...)):
        from .mcp.http_handler import handle as mcp_handle

        msgs = data if isinstance(data, list) else [data]
        out = []
        for m in msgs:
            r = await mcp_handle(m, tools)
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
