---
repo: architecture
path: docs/architecture/aw-app-secrets.md
source: generated
edited: false
checksum: sha256:17458a67c6b1090593c6bee4a93cf1358d6dce0e2612dbe989636ab16b70fdae
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
### A listagem devolve nomes, nunca valores
- Given um agente chama list_secrets e o backend por acaso devolve o valor junto do nome
- When a listagem é montada campo a campo em vez de repassar o registro do backend (repos/aw-app-secrets/secrets_app/tools.py::SecretTools.list_secrets:48)
- Then só name, description, auto_approve e auto_approve_for saem, mais a nota explicando que valores vêm por read_secret — sem a projeção explícita um campo extra no backend vaza segredo por um caminho que não passa por aprovação humana nenhuma, e a ausência dele hoje é o que impede o agente de ler o vault inteiro sem acordar ninguém
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-secrets/tests/test_tools.py` (passing)

### Ausência de max_wait_s significa não esperar, e o timeout configurado é só teto
- Given um agente rodando em container por turno pede um segredo sem passar max_wait_s
- When read_secret decide se bloqueia (repos/aw-app-secrets/secrets_app/tools.py::SecretTools.read_secret:101)
- Then volta na hora com status pending e um request_id coletável depois, e uma espera explícita é cortada no poll_timeout_s configurado — ler poll_timeout_s como padrão prende o processo esperando alguém olhar o celular, e o gateway MCP derruba a conexão bem antes da janela de aprovação de cinco minutos fechar, então o agente perde o request_id e o trabalho junto
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-secrets/tests/test_tools.py` (passing)

### O processo servidor nunca deriva identidade do próprio shell pai
- Given uma chamada REST chega ao processo servidor do app sem trazer session, e o "shell pai" desse processo é o supervisor do servidor, idêntico para todo chamador do workspace
- When a chave de aprovação é derivada (repos/aw-app-secrets/secrets_app/caller.py::caller_key:103, com allow_local default False)
- Then o retorno é None e o chamador fica não identificado, o que significa perguntar ao humano de novo — só um processo que É o chamador, um CLI no shell da própria pessoa, passa allow_local=True; se o fallback local valesse aqui, uma única chave compartilhada seria cunhada e a janela de 10min que o primeiro chamador conquistou liberaria o segredo para todos os outros sem prompt
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-secrets/tests/test_tools.py` (passing)

### Placeholder não expandido não é identidade
- Given um cliente MCP não expande a referência de env e manda ${AW_SESSION_ID} ou ${AW_AGENT_SLUG} literalmente no header
- When a identidade é validada antes de virar chave ou de bater no allowlist (repos/aw-app-secrets/secrets_app/caller.py::_is_unexpanded:89, usado por ::caller_key:103 e ::agent_identity:131)
- Then o valor é tratado como identidade nenhuma e cai no caminho de perguntar sempre — o placeholder literal é idêntico para todos os agentes, então aceitá-lo funde numa chave só justamente o que existe para separá-los, e um agente herda a janela de aprovação (ou a entrada de allowlist) de outro sem nunca ter sido aprovado
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: `repos/aw-app-secrets/tests/test_tools.py` (passing)
