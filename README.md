# OpenShield

Plataforma local-first e *gateway-first* de visibilidade de rede, privacidade DNS, correlação de incidentes e resposta automatizada reversível para **redes residenciais** e **pequenos escritórios**.

O painel web (React + Vite + Tailwind CSS) se comunica com um BFF local em Node.js/Express + TypeScript com persistência em SQLite (WAL), operando tanto em modo **Simulador Mock** (para avaliação sem infraestrutura) quanto em modo **API Real** conectado aos serviços da sua LAN.

---

## Sumário

1. [Arquitetura e Conceitos Principais](#arquitetura-e-conceitos-principais)
2. [Pré-requisitos e Instalação](#pré-requisitos-e-instalação)
3. [Variáveis de Ambiente e Persistência](#variáveis-de-ambiente-e-persistência)
4. [Plugins e Arquitetura de Adaptadores](#plugins-e-arquitetura-de-adaptadores)
5. [Preciso instalar algo no roteador OpenWrt ou nos hosts?](#preciso-instalar-algo-no-roteador-openwrt-ou-nos-hosts)
6. [Guia por Serviço Suportado (16 templates)](#guia-por-serviço-suportado-16-templates)
7. [Configuração pela Interface Web](#configuração-pela-interface-web)
8. [Endpoints de API, Ingestão LAN e Métricas](#endpoints-de-api-ingestão-lan-e-métricas)

---

## Arquitetura e Conceitos Principais

- **Gateway-First (Desacoplamento Físico)**: O roteador continua encaminhando pacotes na LAN mesmo se o OpenShield estiver offline ou reiniciando. O agente/conector utiliza fila outbox em SQLite local (capacidade de 10.000 eventos) com drenagem idempotente.
- **Perfis de Operação**:
  - **Residencial**: Foco em simplicidade e LAN confiável (sem exigência de login por papel).
  - **Pequeno Escritório**: Simulação de RBAC (`Administrador`, `Operador`, `Auditor` somente leitura) e suporte multi-site configurável.
- **Postura de Segurança L0–L3 e Kill Switch**:
  - Padrão **L0 (Observar)**: apenas observação e simulação (*dry-run*).
  - Níveis **L1/L2**: ações limitadas com **TTL** (expiração automática) e **rollback** verificável.
  - **L3**: exige aprovação humana explícita do perfil Administrador.
  - **Parada de Emergência (Kill Switch)**: reverte imediatamente para `L0` e aborta contenções em andamento.
- **Saúde da Rede**: Card na **Visão Geral** que calcula a latência média agregada (`ms`) dos endpoints de segurança conectados e exibe alerta visual automático caso **mais de um endpoint de segurança** (por exemplo, `Pi-hole + AdGuard`) fique offline ou degradado simultaneamente.

---

## Pré-requisitos e Instalação

### Requisitos do servidor onde o OpenShield vai rodar

- **Node.js `>= 22.0.0`** (utiliza o módulo nativo `node:sqlite` para persistência local, sem precisar instalar banco de dados externo).
- **npm** (ou **bun**) para instalar as dependências.

### Passo a passo

1. Instale as dependências:

   ```bash
   npm install
   ```

2. Crie o arquivo de ambiente `.env` a partir do exemplo (opcional para modo Mock; útil para fallbacks ou Gemini):

   ```bash
   cp .env.example .env
   ```

3. Inicie o servidor em modo de desenvolvimento (porta `3000`):

   ```bash
   npm run dev
   ```

4. Ou compile e execute em modo de produção:

   ```bash
   npm run build
   NODE_ENV=production npm start
   ```

5. Acesse no navegador:

   ```text
   http://localhost:3000
   ```

> Ao iniciar pela primeira vez sem base salva, o sistema começa com o inventário limpo para você adicionar apenas os serviços e dispositivos que possui. Se preferir testar rapidamente antes de configurar seus servidores reais, clique em **Carregar Cenário Demo (Mock)** na aba **Configurações**.

---

## Variáveis de Ambiente e Persistência

A maior parte das URLs, portas, usuários e senhas é configurada **diretamente pela interface web** (aba **Configurações**) e armazenada no cofre *write-only* local. As variáveis em `.env` funcionam como configuração de servidor ou *fallback*:

| Variável | Descrição | Padrão / Observação |
| --- | --- | --- |
| `PORT` | Porta HTTP da UI e do BFF | `3000` |
| `OPENSHIELD_DB_PATH` | Caminho do banco SQLite WAL | `.openshield-data/openshield.sqlite3` |
| `OPENSHIELD_OPENWRT_URL` | Fallback de URL `/ubus` do OpenWrt | Opcional (configurável na UI) |
| `OPENSHIELD_OPENWRT_USERNAME` | Fallback de usuário RPC OpenWrt | Opcional (`openshield` ou `root`) |
| `OPENSHIELD_OPENWRT_PASSWORD` | Fallback de senha RPC OpenWrt | Opcional (cofre na UI tem prioridade) |
| `OPENSHIELD_PIHOLE_URL` | Fallback de URL do Pi-hole | Opcional (múltiplos Pi-holes na UI) |
| `OPENSHIELD_PIHOLE_PASSWORD` | Fallback de App Password Pi-hole | Opcional |
| `OPENSHIELD_ADGUARD_URL` | Fallback de URL do AdGuard Home | Opcional |
| `OPENSHIELD_ADGUARD_USERNAME` | Fallback de usuário AdGuard Home | Opcional |
| `OPENSHIELD_ADGUARD_PASSWORD` | Fallback de senha AdGuard Home | Opcional |
| `OPENSHIELD_OLLAMA_URL` | Endpoint do Ollama local | `http://127.0.0.1:11434` |
| `OPENSHIELD_OLLAMA_MODEL` | Modelo padrão no Ollama | `llama3.1:8b` |
| `GEMINI_API_KEY` | Chave para segunda opinião opcional em nuvem | Usada só com *opt-in* manual e payload sanitizado |

### Segurança de Credenciais e Backup

- Senhas, API Keys e tokens gravados na UI ficam na tabela protegida do SQLite local (**cofre write-only**) e **nunca são devolvidos para o navegador** nem incluídos em exportações.
- O recurso **Exportar Backup JSON** gera um arquivo **sanitizado** (estrutura de sites, dispositivos, integrações, políticas e URLs, **sem credenciais**). Ao restaurar um backup em outro host, basta re-inserir as senhas necessárias nos serviços.

---

## Plugins e Arquitetura de Adaptadores

O OpenShield **não requer instalação de plugins externos via marketplace ou pacotes npm adicionais**. Todos os conectores são **adaptadores nativos integrados ao BFF** seguindo os contratos:

- `openshield.gateway.v1` — descoberta e saúde de roteadores/firewalls/VPN.
- `openshield.adapter.v1` — coleta de eventos, DNS, telemetria e execução de regras.
- `openshield.ai.v1` — runtime de análise local-first (Ollama).
- `openshield.event.v1` — esquema padronizado de eventos na LAN.

Caso utilize um serviço que não esteja entre os 15 templates prontos, use o template **Outro Serviço (`custom-http`)** ou envie eventos diretamente por push HTTP para `/api/v1/ingest/events`.

---

## Preciso instalar algo no roteador OpenWrt ou nos hosts?

### 1. No roteador OpenWrt (`openwrt-rpcd`)

**Em instalações OpenWrt padrão (com interface web LuCI), você NÃO precisa instalar nenhum agente ou plugin proprietário do OpenShield no roteador.**

O OpenShield consulta o roteador de forma remota e somente leitura usando o barramento JSON-RPC nativo do OpenWrt (**`ubus` sobre `uhttpd` / `rpcd`**), normalmente exposto em:

```text
http://<IP-DO-ROTEADOR>/ubus
```

#### O que verificar / instalar no OpenWrt (se usar imagem minimalista sem LuCI)

Se o seu OpenWrt não tiver os pacotes RPC habilitados, instale apenas pacotes oficiais do repositório OpenWrt via SSH:

```sh
opkg update
opkg install rpcd uhttpd uhttpd-mod-ubus rpcd-mod-luci
/etc/init.d/rpcd enable && /etc/init.d/rpcd start
/etc/init.d/uhttpd enable && /etc/init.d/uhttpd start
```

> - `rpcd` + `uhttpd-mod-ubus`: obrigatórios para responder JSON-RPC em `/ubus` (`session.login`, `system.board`, `network.interface.dump`).
> - `rpcd-mod-luci` *(ou `luci-mod-rpc` conforme a versão)*: recomendado para liberar `luci-rpc.getHostHints`, permitindo descoberta automática dos clientes conectados na LAN (IP/MAC/hostname). Sem ele, a sincronização ainda lê placa e interfaces, apenas sem lista automática de hosts.
> - `uhttpd-mod-tls` *(opcional)*: caso queira acessar `/ubus` via HTTPS na LAN.

#### Permissões (ACL) recomendadas no OpenWrt

Você pode usar um usuário administrativo já existente ou criar um usuário dedicado com ACL somente leitura em `/etc/config/rpcd` e `/usr/share/rpcd/acl.d/openshield.json`:

1. Em `/etc/config/rpcd`, adicione um bloco `login` com usuário (ex.: `openshield`), senha gerada via `rpcd -s` ou hash padrão e `list read 'openshield'`.
2. Conceda permissão apenas para:
   - `ubus`: `system -> ["board"]`, `network.interface -> ["dump"]`, `luci-rpc -> ["getHostHints"]`.

> **Alternativa sem expor `/ubus`**: se você já roda um **OpenShield Node (FastAPI)** na LAN, informe a URL base da API dele (ex.: `http://192.168.1.10:8000/api/v1`). O adaptador detecta `/api/v1` na URL e consome `/api/v1/events` e `/api/v1/devices` diretamente do Node.

---

## Guia por Serviço Suportado (16 templates)

Abaixo está o que cada adaptador consome em modo **API Real** e o que precisa estar habilitado no respectivo host:

### DNS e Bloqueio (suporta múltiplas instâncias simultâneas)

| Serviço (`kind`) | Endpoints consultados | O que configurar no host do serviço |
| --- | --- | --- |
| **Pi-hole DNS** (`pihole-v6`) | `/api/auth`, `/api/stats/summary`, `/api/queries`, `/api/domains/{deny\|allow}/exact` | Requer **Pi-hole v6** (API REST nativa). Gere uma **App Password / Token** em *Settings → API* e cole no campo de credencial. Você pode cadastrar vários Pi-holes (ex.: primário + secundário) e as regras DNS serão aplicadas em todos os ativos. |
| **AdGuard Home** (`adguard-home`) | `/control/status`, `/control/querylog`, `/control/filtering/status`, `/control/filtering/set_rules` | Nenhuma instalação extra. Informe URL (ex.: `http://192.168.1.13:3000`), usuário e senha admin do AdGuard Home. |
| **Technitium DNS** (`technitium-dns`) | `/api/dashboard/stats/get`, `/api/blocked/add`, `/api/allowed/add`, `/api/blocked/delete` | Nenhuma instalação extra. Gere um **API Token** no painel do Technitium (porta padrão `5380`). |

### Rede, Firewall, VPN e Proxy

| Serviço (`kind`) | Endpoints / Protocolo | O que configurar no host |
| --- | --- | --- |
| **OpenWrt Gateway** (`openwrt-rpcd`) | `POST /ubus` (`session.login`, `system.board`, `network.interface.dump`, `luci-rpc.getHostHints`) ou Node `/api/v1` | `rpcd` + `uhttpd-mod-ubus` ativos no OpenWrt (nativo com LuCI) e credencial RPC válida. |
| **OPNsense / pfSense** (`opnsense-api`) | API REST (ex.: `/api/core/firmware/status`) | Crie um usuário no OPNsense (*System → Access → Users*) com permissão de leitura e gere **API Key + API Secret** (preencha Key no usuário e Secret na senha). |
| **WireGuard / wg-easy** (`wireguard-vpn`) | HTTP REST (ex.: `/api/wireguard/client` na porta `51821`) | Se usar `wg-easy`, informe a URL da API e a senha administrativa configurada no contêiner. |
| **Nginx Proxy Manager** (`nginx-proxy-manager`) | HTTP REST (ex.: `http://<IP>:81/api/`) | Informe usuário/e-mail ou token de API administrativo do Nginx Proxy Manager. |

### IDS, SIEM e Threat Intel

| Serviço (`kind`) | Como funciona em modo API Real | O que configurar no host |
| --- | --- | --- |
| **Suricata IDS** (`suricata-eve`) | Espera endpoint JSON HTTP (ex.: `/eve`) **ou** envio por push para `POST /api/v1/ingest/events` | O Suricata grava logs localmente em `/var/log/suricata/eve.json`. Para modo `live`, exponha um pequeno leitor HTTP/sidecar dos alertas recentes **ou** configure um script/forwarder (Vector/Fluent Bit/cron) enviando eventos `openshield.event.v1` para o OpenShield. |
| **Zeek Analytics** (`zeek-json`) | Espera endpoint JSON HTTP (ex.: `/zeek`) **ou** push para `POST /api/v1/ingest/events` | Mesmo modelo do Suricata: configure saída em JSON no Zeek e exponha/encaminhe para o BFF. |
| **Wazuh SIEM / HIDS** (`wazuh-api`) | API REST nativa do Wazuh Manager (porta padrão `55000`) | Nenhuma instalação extra; informe usuário e senha da API do Wazuh (ex.: `wazuh-wui`). |
| **CrowdSec Intel** (`crowdsec-lapi`) | Local API (`LAPI`) em `/v1/decisions/stream` (porta padrão `8080`) | No host do CrowdSec, gere uma chave de *bouncer* com `cscli bouncers add openshield` e informe a chave gerada. |

### Residência, Monitoramento e IA Local

| Serviço (`kind`) | Endpoints / Protocolo | O que configurar no host |
| --- | --- | --- |
| **Home Assistant** (`home-assistant`) | `/api/` e `/api/states` (porta `8123`) | Nenhuma instalação extra. No perfil do usuário do Home Assistant, gere um **Long-Lived Access Token** e cole no cofre da UI. |
| **Uptime Kuma** (`uptime-kuma`) | `/metrics` ou endpoint HTTP de status (porta `3001`) | Se o `/metrics` exigir API Key ou Basic Auth nas configurações do Uptime Kuma, informe nos campos de credencial. |
| **Netdata / Prometheus** (`netdata-agent`) | `/api/v1/info` (porta `19999`) | Nenhuma instalação extra; o agente Netdata já expõe a API HTTP na LAN. |
| **Ollama IA Local** (`ollama-http`) | `POST /api/generate` (porta `11434`) | Instale o [Ollama](https://ollama.com), faça o download do modelo (`ollama pull llama3.1:8b`) e, se rodar em outro computador da LAN, inicie com `OLLAMA_HOST=0.0.0.0:11434`. |
| **Outro Serviço** (`custom-http`) | Qualquer endpoint HTTP/HTTPS retornando JSON (`Basic` ou `Bearer` opcional) | Informe URL, domínio, `kind` e credenciais opcionais. |

---

## Configuração pela Interface Web

1. **Adicionar Serviços (`Configurações → Adicionar Serviço`)**:
   - Filtre por categoria (*DNS & Bloqueio*, *Rede, VPN & Proxy*, *IDS, SIEM & Intel*, *Residência, Monitor & IA*) e clique no serviço desejado.
   - Os campos dinâmicos aparecem conforme o serviço escolhido (ex.: modelo para Ollama, usuário/API Key para OPNsense/AdGuard, hardware/interfaces para OpenWrt).
   - Você pode salvar em **Simulador Mock** deixando URL e senha em branco para preencher depois, ou preencher imediatamente e escolher **API Real**.
2. **Editar ou Deletar (`Configurações → Serviços e Endpoints Configurados`)**:
   - Todos os serviços salvos ficam listados para edição de URL, site, modo (`Mock` ↔ `API Real`), rotação/remoção de credenciais ou exclusão.
   - Use **Testar e Ativar API Real** para validar conectividade e medir a latência real (`timeout` de 5s).
3. **Dispositivos (`Dispositivos e Topologia`)**:
   - Cadastre dispositivos manualmente (sem limite fixo) ou descubra automaticamente via sincronização do **OpenWrt**.
4. **Monitoramento (`Visão Geral` e `Gateway e Integrações`)**:
   - Acompanhe o painel **Saúde da Rede** para ver a latência média agregada e alertas quando múltiplos endpoints de segurança caírem.
   - Use **Medir Latência / Sincronizar** para atualizar o status em lote de todos os serviços cadastrados.

---

## Endpoints de API, Ingestão LAN e Métricas

- `GET /api/health` — status de saúde do BFF e encaminhamento do gateway.
- `GET /api/v1/state` — snapshot completo atual do workspace (sem segredos).
- `GET /api/v1/stream` — fluxo Server-Sent Events (SSE) em tempo real para UI, timers TTL e outbox.
- `POST /api/v1/integrations/sync-all` — sincroniza e mede latência de todos os adaptadores cadastrados.
- `POST /api/v1/ingest/events` — endpoint de ingestão na LAN aceitando objeto único `openshield.event.v1` ou `{ "events": [...] }`. Exige que `sourceIntegrationId` esteja previamente cadastrado (verificação estrita de proveniência).
- `GET /api/v1/workspace/backup` / `POST /api/v1/workspace/restore` — exportação/importação de backup JSON sanitizado.
- `GET /metrics` — métricas no formato Prometheus (`openshield_http_requests_total`, `openshield_events_ingested_total`, `openshield_outbox_pending_total`, entre outras).
