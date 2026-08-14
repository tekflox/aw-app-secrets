"""MCP server for the secrets tools, over Streamable HTTP (POST /mcp).

Follows aw-app-diff-tool's ``diff_app/mcp/http_handler.py``: this app is Tier-1
(in-process), so the handler calls :class:`SecretTools` DIRECTLY instead of an
HTTP hop back into its own REST route. No credentials to provision for the
gateway, nothing to hand-edit after a deploy — the stdio shape those apps
abandoned needed exactly that.

Values never touch this module's logs. The one tool that returns a secret
returns it and nothing else; errors are phrased so the caller can tell WHY it
failed without the message ever containing the value.
"""
from __future__ import annotations

import json
import logging

from fastapi.concurrency import run_in_threadpool

from ..backend_client import ApprovalDenied, BackendUnavailable

log = logging.getLogger("aw_apps.secrets.mcp")


def _ok(req_id, text):
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": False}}


def _err(req_id, text):
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True}}


TOOLS_SCHEMA = [
    {
        "name": "list_secrets",
        "description": (
            "List the workspace's secret NAMES and descriptions. Never returns "
            "values — use read_secret for that. Cheap and ungated; call it first "
            "when you are unsure of the exact name rather than guessing and "
            "triggering an approval prompt for a secret that does not exist."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "write_secret",
        "description": (
            "Create or replace a secret. NOT gated by approval, on purpose: you "
            "already hold the value, so asking the human to confirm it tells them "
            "nothing. Writing an existing name overwrites it — call list_secrets "
            "first if you are not certain the name is free."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Secret name, e.g. resend_api_key."},
                "value": {"type": "string", "description": "The secret value."},
                "description": {"type": "string",
                                "description": "What this is for — shown to the human on future approvals."},
            },
            "required": ["name", "value"],
        },
    },
    {
        "name": "read_secret",
        "description": (
            "Read a secret's value. This ASKS A HUMAN: a prompt goes to the "
            "sysadmin Telegram bot showing the secret name and your reason, and "
            "this call blocks until they tap approve or deny (up to ~5 minutes). "
            "Expect it to be slow, and expect it to be refused. Do not call it "
            "speculatively or in a loop — every call interrupts a person. The "
            "value is delivered ONCE; store it in a variable rather than "
            "re-reading it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Secret name (see list_secrets)."},
                "reason": {
                    "type": "string",
                    "description": (
                        "Why you need it, in one line. This is the ONLY thing the "
                        "human sees besides the name when deciding — 'deploy to "
                        "staging' gets approved, 'agent request' does not."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["one_shot", "10min", "60min"],
                    "description": (
                        "one_shot (default) delivers the value once. 10min/60min let "
                        "the same calling process re-read without prompting again — "
                        "ask for those only when you genuinely need repeated reads."
                    ),
                },
            },
            "required": ["name", "reason"],
        },
    },
]


async def handle(body: dict, tools) -> dict:
    """Dispatch one JSON-RPC message. ``tools`` is a :class:`SecretTools`."""
    method = body.get("method")
    req_id = body.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "aw-secrets", "version": "0.1.0"},
        }}
    if method == "notifications/initialized":
        return {}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SCHEMA}}
    if method != "tools/call":
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"unknown method {method!r}"}}

    params = body.get("params") or {}
    name = params.get("name")
    args = params.get("arguments") or {}

    try:
        if name == "list_secrets":
            return _ok(req_id, json.dumps(await run_in_threadpool(tools.list_secrets)))
        if name == "write_secret":
            out = await run_in_threadpool(
                tools.write_secret, args.get("name", ""), args.get("value", ""),
                args.get("description", ""))
            return _ok(req_id, json.dumps(out))
        if name == "read_secret":
            out = await run_in_threadpool(
                tools.read_secret, args.get("name", ""), args.get("reason", ""),
                args.get("scope"), "mcp")
            return _ok(req_id, json.dumps(out))
        return _err(req_id, f"unknown tool {name!r}")
    except ApprovalDenied as exc:
        # A refusal is a normal outcome, not a malfunction. Say so plainly so
        # the caller stops instead of retrying into another prompt.
        return _err(req_id, f"not approved: {exc}")
    except BackendUnavailable as exc:
        return _err(req_id, f"no secret store reachable: {exc}")
    except ValueError as exc:
        return _err(req_id, f"bad request: {exc}")
    except Exception as exc:  # noqa: BLE001
        # Deliberately does not echo args — one of them may be a secret value.
        log.exception("secrets: tool %s failed", name)
        return _err(req_id, f"{name} failed: {type(exc).__name__}: {exc}")
