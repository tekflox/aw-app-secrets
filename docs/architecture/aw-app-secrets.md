---
repo: architecture
path: docs/architecture/aw-app-secrets.md
source: generated
edited: false
checksum: sha256:496eb9cf900c4cef0835dcb686900c8425238ea8260ebd34a55583f240894be9
---
# Secrets

- **repo**: aw-app-secrets
- **layer**: app
- **technologies**: python
- **health** (derived): planned

Read, write and list the workspace's secrets, where reading goes through a human approval on Telegram — unless that secret's gate has been turned off in Settings. Backed by aw-vault via aw-backend's /api/approval/* — this app stores nothing itself. NOT the same as an app's own config secrets (`ctx.secrets`, capability `secrets:own`), which are per-app, unshared and ungated.

## Connections
- `http` → **aw-workspace** — routes mounted at /api/apps/secrets
- `stdio-mcp` → **mcp-gateway** — MCP surface aggregated by the gateway

## MCP tools
- `collect_secret`
- `list_secrets`
- `read_secret`
- `write_secret`

## Requirements
_none documented_
