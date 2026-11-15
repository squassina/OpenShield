# OpenShield — Roadmap e Tarefas Pendentes (PLAN.md)

Status consolidado do projeto com entregas concluídas e itens pendentes para evolução técnica, segurança e confiabilidade em produção.

---

## 1. Concluído Recentemente (Commit `4cf4056`)

- **Execução Real de Firewall e Rollback**:
  - OpenWrt: manipulação de regras isoladas em tabela `inet openshield` via `ubus file.exec` com rollback verificado por handles e tags de comentário (`openshield_<id>`).
  - OPNsense: gerenciamento de alias `openshield_blocked` via API REST (`/api/firewall/alias_util`) com recarga automática de filtros.
- **Detecção de Tentativas de Acesso ao Roteador**:
  - Coleta contínua de logs de força bruta em SSH (`dropbear`/`sshd`), LuCI/Web, `ubus RPC` e drops de entrada WAN.
  - Ingestão dupla: polling periódico via `ubus logread` e endpoint push `POST /api/v1/ingest/router-logs`.
- **Painel e UX**:
  - Painel dedicado para tentativas de acesso na aba *Gateway e Integrações* com busca, filtros rápidos e botão de bloqueio temporário (TTL).
  - Indicador de tentativas no card de incidentes na *Visão Geral*, com escopo por site ativo.
  - Paginação padronizada (`10`, `20`, `50`, `100`) com reset automático de página ao alterar filtros e busca (Serviços, Sites, Notificações, Visão Geral, Incidentes e Dispositivos).
- **Consistência de Dados e DNS**:
  - Sincronização multi-dispositivo de status (`listStatus`) de domínios DNS.
  - Normalização de endereços IPv4-mapped (`::ffff:a.b.c.d`) em todos os fluxos de eventos e drawer lateral.
  - Batching de gravações SQLite e broadcast único via SSE ao final de ciclos de sincronização em lote.

---

## 2. Tarefas Pendentes e Próximos Passos

### 1. Suíte de Testes Automatizados e CI
- **Problema**: O repositório não possui nenhum teste automatizado configurado no `package.json` ou no módulo Python.
- **O que fazer**:
  - Configurar runner de testes TypeScript (ex.: Vitest) para testar os adaptadores de firewall, DNS e o correlator determinístico.
  - Criar testes unitários para:
    - Normalização e validação de IP em `server/adapters/firewallAdapter.ts`.
    - Agrupamento e deduplicação de logs de roteador em `server/adapters/openwrtAdapter.ts`.
    - Gestão de TTL, expiração e rollback em `server/openshieldStore.ts`.
  - Configurar pipeline no GitHub Actions para rodar `lint` (`tsc --noEmit`), `build` e suíte de testes a cada PR/push.

### 2. Recuperação de Regras de Firewall Após Reboot do Roteador
- **Problema**: Regras `nftables` na tabela `inet openshield` no OpenWrt residem na memória volátil do kernel. Se o roteador reiniciar enquanto um bloqueio TTL estiver ativo, a regra desaparece no gateway, mas o OpenShield a manterá registrada como ativa até expirar.
- **O que fazer**:
  - Implementar verificação de reconciliação periódica (durante o heartbeat/sync do gateway): re-aplicar regras ativas se a tabela/regra não for encontrada no `nft list`.
  - Opcional: oferecer modo persistente via UCI (`/etc/config/firewall`) com prefixo `openshield_` para quem preferir regras duráveis entre reboots.

### 3. Autenticação e Hardening para Produção
- **Problema**: A troca de papéis RBAC (`admin`, `operator`, `auditor`) e perfis de operação na interface web é puramente simulada no estado local; o painel na porta 3000 não exige credenciais nem valida tokens de sessão.
- **O que fazer**:
  - Implementar autenticação real para o painel web (JWT ou sessão com cookie `HttpOnly`, `SameSite=Strict`).
  - Proteger rotas mutativas do BFF (`POST`, `PUT`, `DELETE`, `PATCH`) contra acesso anônimo fora da LAN confiável.

### 4. Paridade de Endpoints no FastAPI Node (`node-fastapi`)
- **Problema**: O endpoint `POST /api/v1/ingest/router-logs` foi implementado no BFF Node.js (`server.ts`), mas não foi replicado no serviço Python FastAPI (`node-fastapi/app.py`). Envio direto de logs na porta `8000` retornará erro `404 Not Found`.
- **O que fazer**:
  - Adicionar a rota `POST /api/v1/ingest/router-logs` em `node-fastapi/app.py` recebendo `text/plain` ou `application/json` e registrando eventos `router.access_attempt`.

### 5. Suporte a Multi-Gateway com Fanout por Site
- **Problema**: `applyFirewallRuleLive` em `server/adapters/firewallAdapter.ts` seleciona apenas o primeiro gateway ativo encontrado (`gateways[0]`).
- **O que fazer**:
  - Permitir que políticas de contenção e bloqueio apliquem regras em todos os gateways ativos do mesmo site (ex.: roteador de borda OpenWrt + firewall OPNsense secundário), ou permitir seleção do gateway alvo pelo operador.

### 6. Parsers Dedicados para Adaptadores Secundários
- **Problema**: Adaptadores como Suricata, Zeek, Wazuh, CrowdSec, WireGuard e Uptime Kuma utilizam atualmente o fallback HTTP genérico ou dependem de push manual em `/api/v1/events/ingest`.
- **O que fazer**:
  - Implementar parsers nativos de payload e polling específico para:
    - CrowdSec: `/v1/decisions/stream`.
    - WireGuard / wg-easy: estatísticas de peers e clientes conectados.
    - Uptime Kuma: `/metrics` Prometheus.
