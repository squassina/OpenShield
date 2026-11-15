import type {
  ActionExecution,
  GatewayEnforcementDetail,
  IntegrationAdapter,
} from '../../src/types/openshield.ts';
import { boundedFetchJson } from './httpClient.ts';
import { callUbus, normalizeIpAddress, openwrtLogin } from './openwrtAdapter.ts';

export interface FirewallEnforcementResult {
  enforcementMode: 'live' | 'simulated';
  ruleRef?: string;
  gatewayId?: string;
  gatewayResults?: GatewayEnforcementDetail[];
  detail: string;
}

export interface FirewallRuleTarget {
  executionId: string;
  targetIp?: string;
  actionType: 'nftables_temp_drop' | 'isolate_iot_segment';
  persistentUci?: boolean;
  targetGatewayIds?: string[];
}

export interface FirewallReconciliationSummary {
  checkedCount: number;
  reappliedExecutionIds: string[];
  details: string[];
  errors: string[];
}

const IPV4_EXACT = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_EXACT = /^[0-9a-fA-F:]{3,45}$/;
const OPNSENSE_ALIAS_NAME = 'openshield_blocked';

export function assertValidIp(rawIp: string): { ip: string; family: 'ip' | 'ip6' } {
  const clean = normalizeIpAddress(rawIp);
  if (IPV4_EXACT.test(clean)) {
    const octets = clean.split('.').map(Number);
    if (octets.every((o) => Number.isInteger(o) && o >= 0 && o <= 255)) {
      return { ip: clean, family: 'ip' };
    }
  }
  if (IPV6_EXACT.test(clean) && clean.includes(':')) {
    return { ip: clean, family: 'ip6' };
  }
  throw new Error(`Endereço IP inválido para regra de firewall: "${rawIp}".`);
}

function isOpenWrtUbusAdapter(adapter: IntegrationAdapter): boolean {
  const url = (adapter.liveEndpointUrl || '').trim();
  if (!url) return false;
  if (adapter.kind !== 'openwrt-rpcd') return false;
  // Exclude FastAPI Node companion endpoints unless explicitly /ubus
  const isNodeOnly =
    !url.includes('/ubus') &&
    (url.includes('/api/v1') || url.includes(':8000') || url.includes('openshield-node'));
  return !isNodeOnly;
}

function resolveOpenWrtUbusUrl(endpointUrl: string): string {
  const trimmed = endpointUrl.trim();
  return trimmed.includes('/ubus') ? trimmed : `${trimmed.replace(/\/+$/, '')}/ubus`;
}

export function selectLiveGatewayAdapters(
  integrations: IntegrationAdapter[],
  preferredSiteId?: string,
  targetGatewayIds?: string[],
): IntegrationAdapter[] {
  const candidates = integrations.filter(
    (i) =>
      i.mode === 'live' &&
      Boolean(i.liveEndpointUrl?.trim()) &&
      (isOpenWrtUbusAdapter(i) || i.kind === 'opnsense-api'),
  );

  if (targetGatewayIds && targetGatewayIds.length > 0) {
    const wanted = new Set(targetGatewayIds);
    const targeted = candidates.filter((c) => wanted.has(c.id));
    if (targeted.length > 0) return targeted;
  }

  if (preferredSiteId) {
    const siteMatched = candidates.filter((c) => c.siteId === preferredSiteId);
    if (siteMatched.length > 0) {
      return siteMatched;
    }
  }

  return candidates;
}

function formatOpenWrtFirewallDiagnostic(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes('código 6') || /access denied/i.test(msg)) {
    return `OpenWrt rpcd recusou acesso de firewall (${msg}). Instale a ACL /usr/share/rpcd/acl.d/openshield-fw.json permitindo file.exec para nft/uci.`;
  }
  return msg;
}

async function ensureOpenWrtTableAndChains(
  ubusUrl: string,
  token: string,
): Promise<void> {
  // Creates isolated table `inet openshield` with priority -5 (never touches fw4 table)
  await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'nft',
    params: ['add', 'table', 'inet', 'openshield'],
  });
  await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'nft',
    params: [
      'add',
      'chain',
      'inet',
      'openshield',
      'input',
      '{ type filter hook input priority -5; policy accept; }',
    ],
  });
  await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'nft',
    params: [
      'add',
      'chain',
      'inet',
      'openshield',
      'forward',
      '{ type filter hook forward priority -5; policy accept; }',
    ],
  });
}

async function applyOpenWrtUciPersistence(
  ubusUrl: string,
  token: string,
  executionId: string,
  ip: string,
  family: 'ip' | 'ip6',
): Promise<string> {
  const section = `openshield_${executionId.replace(/[^a-zA-Z0-9_]/g, '_')}`;
  const cmds: Array<[string, string[]]> = [
    ['uci', ['set', `firewall.${section}=rule`]],
    ['uci', ['set', `firewall.${section}.name=${section}`]],
    ['uci', ['set', `firewall.${section}.src=*`]],
    ['uci', ['set', `firewall.${section}.src_ip=${ip}`]],
    ['uci', ['set', `firewall.${section}.family=${family === 'ip6' ? 'ipv6' : 'ipv4'}`]],
    ['uci', ['set', `firewall.${section}.proto=all`]],
    ['uci', ['set', `firewall.${section}.target=DROP`]],
    ['uci', ['set', `firewall.${section}.enabled=1`]],
    ['uci', ['commit', 'firewall']],
  ];
  for (const [command, params] of cmds) {
    const res = await callUbus(ubusUrl, token, 'file', 'exec', { command, params });
    if (typeof res.code === 'number' && res.code !== 0) {
      throw new Error(`UCI persistência falhou em ${params.join(' ')} (código ${res.code})`);
    }
  }
  await callUbus(ubusUrl, token, 'file', 'exec', {
    command: '/etc/init.d/firewall',
    params: ['reload'],
  }).catch(() => undefined);
  return section;
}

async function removeOpenWrtUciPersistence(
  ubusUrl: string,
  token: string,
  executionId: string,
): Promise<void> {
  const section = `openshield_${executionId.replace(/[^a-zA-Z0-9_]/g, '_')}`;
  const del = await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'uci',
    params: ['-q', 'delete', `firewall.${section}`],
  });
  if (typeof del.code === 'number' && del.code === 0) {
    await callUbus(ubusUrl, token, 'file', 'exec', {
      command: 'uci',
      params: ['commit', 'firewall'],
    });
    await callUbus(ubusUrl, token, 'file', 'exec', {
      command: '/etc/init.d/firewall',
      params: ['reload'],
    }).catch(() => undefined);
  }
}

async function listOpenWrtRulesetStdout(
  adapter: IntegrationAdapter,
  credentials: { username?: string; secret?: string },
): Promise<string> {
  const ubusUrl = resolveOpenWrtUbusUrl(adapter.liveEndpointUrl);
  const username = credentials.username || process.env.OPENSHIELD_OPENWRT_USERNAME || '';
  const password = credentials.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD || '';
  if (!username || !password) {
    return '';
  }
  const token = await openwrtLogin(ubusUrl, username, password);
  const res = await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'nft',
    params: ['-a', 'list', 'table', 'inet', 'openshield'],
  });
  return typeof res.stdout === 'string' ? res.stdout : '';
}

function parseOpenWrtHandlesFromStdout(
  stdout: string,
  executionId: string,
): { found: boolean; ruleRef?: string; handles: Array<{ chain: string; handle: string }> } {
  const tag = `openshield_${executionId}`;
  const handles: Array<{ chain: string; handle: string }> = [];

  let currentChain = 'forward';
  for (const line of stdout.split(/\r?\n/)) {
    const chainMatch = line.match(/^\s*chain\s+([a-zA-Z0-9_-]+)\s*\{/);
    if (chainMatch?.[1]) {
      currentChain = chainMatch[1];
      continue;
    }
    if (line.includes(tag)) {
      const handleMatch = line.match(/#\s*handle\s+(\d+)/);
      if (handleMatch?.[1]) {
        handles.push({ chain: currentChain, handle: handleMatch[1] });
      }
    }
  }

  if (handles.length === 0 && !stdout.includes(tag)) {
    return { found: false, handles: [] };
  }

  const handleLabel = handles.map((h) => `${h.chain}#${h.handle}`).join(',');
  return {
    found: true,
    ruleRef: handleLabel ? `nft:inet/openshield:${handleLabel}` : `nft:inet/openshield:${tag}`,
    handles,
  };
}

async function verifyOpenWrtRule(
  adapter: IntegrationAdapter,
  executionId: string,
  credentials: { username?: string; secret?: string },
): Promise<{ found: boolean; ruleRef?: string; handles: Array<{ chain: string; handle: string }> }> {
  const stdout = await listOpenWrtRulesetStdout(adapter, credentials);
  return parseOpenWrtHandlesFromStdout(stdout, executionId);
}

async function applyOpenWrtRule(
  adapter: IntegrationAdapter,
  target: FirewallRuleTarget,
  credentials: { username?: string; secret?: string },
): Promise<FirewallEnforcementResult> {
  if (!target.targetIp) {
    return {
      enforcementMode: 'simulated',
      detail: 'Simulado (regra sem IP alvo específico para nftables).',
    };
  }

  const ubusUrl = resolveOpenWrtUbusUrl(adapter.liveEndpointUrl);
  const username = credentials.username || process.env.OPENSHIELD_OPENWRT_USERNAME || '';
  const password = credentials.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD || '';
  if (!username || !password) {
    throw new Error(
      `Credenciais ubus ausentes para ${adapter.name}. Configure usuário e senha em Configurações.`,
    );
  }

  const { ip, family } = assertValidIp(target.targetIp);
  const commentTag = `openshield_${target.executionId}`;

  try {
    const token = await openwrtLogin(ubusUrl, username, password);
    await ensureOpenWrtTableAndChains(ubusUrl, token);

    const chains =
      target.actionType === 'nftables_temp_drop' ? ['input', 'forward'] : ['forward'];

    for (const chain of chains) {
      const execRes = await callUbus(ubusUrl, token, 'file', 'exec', {
        command: 'nft',
        params: [
          'add',
          'rule',
          'inet',
          'openshield',
          chain,
          family,
          'saddr',
          ip,
          'counter',
          'drop',
          'comment',
          `"${commentTag}"`,
        ],
      });
      if (typeof execRes.code === 'number' && execRes.code !== 0) {
        const stderr = typeof execRes.stderr === 'string' ? execRes.stderr.trim() : '';
        throw new Error(`nft retornou código ${execRes.code}${stderr ? `: ${stderr}` : ''}`);
      }
    }

    let uciSuffix = '';
    if (target.persistentUci) {
      const section = await applyOpenWrtUciPersistence(ubusUrl, token, target.executionId, ip, family);
      uciSuffix = ` + UCI firewall.${section}`;
    }

    const verify = await verifyOpenWrtRule(adapter, target.executionId, credentials);
    if (!verify.found) {
      throw new Error(
        `Regra ${commentTag} não apareceu na listagem nftables de verificação (${adapter.name}).`,
      );
    }

    const ruleRef = verify.ruleRef || `nft:inet/openshield:${commentTag}`;
    return {
      enforcementMode: 'live',
      gatewayId: adapter.id,
      ruleRef,
      detail: `Bloqueio real aplicado em ${adapter.name} (${ruleRef}${uciSuffix}) e verificado via nft -a list.`,
    };
  } catch (err) {
    throw new Error(formatOpenWrtFirewallDiagnostic(err));
  }
}

async function rollbackOpenWrtRule(
  adapter: IntegrationAdapter,
  executionId: string,
  credentials: { username?: string; secret?: string },
  persistentUci?: boolean,
): Promise<FirewallEnforcementResult> {
  const ubusUrl = resolveOpenWrtUbusUrl(adapter.liveEndpointUrl);
  const username = credentials.username || process.env.OPENSHIELD_OPENWRT_USERNAME || '';
  const password = credentials.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD || '';
  if (!username || !password) {
    throw new Error(`Credenciais ubus ausentes para rollback em ${adapter.name}.`);
  }

  try {
    const token = await openwrtLogin(ubusUrl, username, password);
    const verify = await verifyOpenWrtRule(adapter, executionId, credentials);

    if (persistentUci) {
      await removeOpenWrtUciPersistence(ubusUrl, token, executionId);
    }

    if (!verify.found || verify.handles.length === 0) {
      return {
        enforcementMode: 'live',
        gatewayId: adapter.id,
        ruleRef: `nft:inet/openshield:openshield_${executionId}`,
        detail: `Rollback concluído em ${adapter.name}: regra já não estava presente em inet openshield.`,
      };
    }

    for (const h of verify.handles) {
      const delRes = await callUbus(ubusUrl, token, 'file', 'exec', {
        command: 'nft',
        params: ['delete', 'rule', 'inet', 'openshield', h.chain, 'handle', h.handle],
      });
      if (typeof delRes.code === 'number' && delRes.code !== 0) {
        throw new Error(`Falha ao remover handle ${h.chain}#${h.handle} (código ${delRes.code}).`);
      }
    }

    return {
      enforcementMode: 'live',
      gatewayId: adapter.id,
      ruleRef: verify.ruleRef,
      detail: `Rollback real executado em ${adapter.name}: ${verify.handles.length} regra(s) nftables removida(s).`,
    };
  } catch (err) {
    throw new Error(formatOpenWrtFirewallDiagnostic(err));
  }
}

function buildOpnsenseAuthHeader(credentials: { username?: string; secret?: string }): Record<string, string> {
  const key = credentials.username || process.env.OPENSHIELD_OPNSENSE_KEY || '';
  const secret = credentials.secret || process.env.OPENSHIELD_OPNSENSE_SECRET || '';
  if (!key || !secret) {
    throw new Error('API Key/Secret do OPNsense não configurados para aplicação de firewall.');
  }
  return {
    Authorization: `Basic ${Buffer.from(`${key}:${secret}`).toString('base64')}`,
  };
}

async function applyOpnsenseRule(
  adapter: IntegrationAdapter,
  target: FirewallRuleTarget,
  credentials: { username?: string; secret?: string },
): Promise<FirewallEnforcementResult> {
  if (!target.targetIp) {
    return {
      enforcementMode: 'simulated',
      detail: 'Simulado (regra sem IP alvo específico para alias OPNsense).',
    };
  }
  const { ip } = assertValidIp(target.targetIp);
  const baseUrl = adapter.liveEndpointUrl.replace(/\/api.*$/, '').replace(/\/+$/, '');
  const headers = buildOpnsenseAuthHeader(credentials);

  const addRes = await boundedFetchJson<{ status?: string }>(
    `${baseUrl}/api/firewall/alias_util/add/${OPNSENSE_ALIAS_NAME}`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({ address: ip }),
      timeoutMs: 5000,
    },
  );
  if (!addRes.ok || (addRes.data.status && addRes.data.status !== 'done')) {
    throw new Error(
      `OPNsense (${adapter.name}) recusou adição ao alias ${OPNSENSE_ALIAS_NAME} (HTTP ${addRes.status}).`,
    );
  }

  await boundedFetchJson(`${baseUrl}/api/firewall/filter/apply`, {
    method: 'POST',
    headers,
    body: JSON.stringify({}),
    timeoutMs: 5000,
  });

  return {
    enforcementMode: 'live',
    gatewayId: adapter.id,
    ruleRef: `opnsense:alias/${OPNSENSE_ALIAS_NAME}:${ip}`,
    detail: `Bloqueio real aplicado em ${adapter.name} (alias ${OPNSENSE_ALIAS_NAME} -> ${ip}) e filtro recarregado.`,
  };
}

async function listOpnsenseAliasIps(
  adapter: IntegrationAdapter,
  credentials: { username?: string; secret?: string },
): Promise<Set<string>> {
  const baseUrl = adapter.liveEndpointUrl.replace(/\/api.*$/, '').replace(/\/+$/, '');
  const headers = buildOpnsenseAuthHeader(credentials);
  const listRes = await boundedFetchJson<{ rows?: Array<{ ip?: string; address?: string }> }>(
    `${baseUrl}/api/firewall/alias_util/list/${OPNSENSE_ALIAS_NAME}`,
    {
      method: 'GET',
      headers,
      timeoutMs: 5000,
    },
  );
  const ips = new Set<string>();
  if (listRes.ok && Array.isArray(listRes.data.rows)) {
    for (const row of listRes.data.rows) {
      const candidate = normalizeIpAddress(String(row.ip ?? row.address ?? ''));
      if (candidate) ips.add(candidate);
    }
  }
  return ips;
}

async function rollbackOpnsenseRule(
  adapter: IntegrationAdapter,
  targetIp: string | undefined,
  credentials: { username?: string; secret?: string },
): Promise<FirewallEnforcementResult> {
  if (!targetIp) {
    return {
      enforcementMode: 'simulated',
      detail: 'Rollback simulado (sem IP alvo registrado).',
    };
  }
  const { ip } = assertValidIp(targetIp);
  const baseUrl = adapter.liveEndpointUrl.replace(/\/api.*$/, '').replace(/\/+$/, '');
  const headers = buildOpnsenseAuthHeader(credentials);

  const delRes = await boundedFetchJson<{ status?: string }>(
    `${baseUrl}/api/firewall/alias_util/delete/${OPNSENSE_ALIAS_NAME}`,
    {
      method: 'POST',
      headers,
      body: JSON.stringify({ address: ip }),
      timeoutMs: 5000,
    },
  );
  if (!delRes.ok) {
    throw new Error(
      `OPNsense (${adapter.name}) falhou ao remover ${ip} do alias ${OPNSENSE_ALIAS_NAME} (HTTP ${delRes.status}).`,
    );
  }

  await boundedFetchJson(`${baseUrl}/api/firewall/filter/apply`, {
    method: 'POST',
    headers,
    body: JSON.stringify({}),
    timeoutMs: 5000,
  });

  return {
    enforcementMode: 'live',
    gatewayId: adapter.id,
    ruleRef: `opnsense:alias/${OPNSENSE_ALIAS_NAME}:${ip}`,
    detail: `Rollback real executado em ${adapter.name}: ${ip} removido de ${OPNSENSE_ALIAS_NAME}.`,
  };
}

export async function applyFirewallRuleLive(
  integrations: IntegrationAdapter[],
  target: FirewallRuleTarget,
  getCredential: (integrationId: string) => { username?: string; secret?: string } | null,
  preferredSiteId?: string,
): Promise<FirewallEnforcementResult> {
  const gateways = selectLiveGatewayAdapters(
    integrations,
    preferredSiteId,
    target.targetGatewayIds,
  );
  if (gateways.length === 0) {
    return {
      enforcementMode: 'simulated',
      detail:
        'Contenção registrada em modo simulado (nenhum gateway OpenWrt ubus ou OPNsense configurado em API Real).',
    };
  }

  if (!target.targetIp) {
    return {
      enforcementMode: 'simulated',
      detail: 'Simulado (regra sem IP alvo específico para firewall).',
    };
  }

  const gatewayResults: GatewayEnforcementDetail[] = [];
  const errors: string[] = [];

  for (const gw of gateways) {
    const creds = getCredential(gw.id) ?? {};
    try {
      const res =
        gw.kind === 'openwrt-rpcd'
          ? await applyOpenWrtRule(gw, target, creds)
          : await applyOpnsenseRule(gw, target, creds);
      gatewayResults.push({
        gatewayId: gw.id,
        gatewayName: gw.name,
        enforcementMode: res.enforcementMode,
        ruleRef: res.ruleRef,
        status: 'applied',
        detail: res.detail,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Falha desconhecida no gateway.';
      errors.push(`${gw.name}: ${msg}`);
      gatewayResults.push({
        gatewayId: gw.id,
        gatewayName: gw.name,
        enforcementMode: 'simulated',
        status: 'failed',
        detail: msg,
      });
    }
  }

  const applied = gatewayResults.filter((r) => r.status === 'applied' && r.enforcementMode === 'live');
  if (applied.length === 0) {
    throw new Error(errors.join(' | ') || 'Falha ao aplicar regra em todos os gateways do site.');
  }

  const ruleRefs = applied.map((r) => r.ruleRef).filter(Boolean).join(' + ');
  const summaryDetail =
    applied.length === gateways.length
      ? applied.map((r) => r.detail).join(' | ')
      : `Aplicado em ${applied.length}/${gateways.length} gateway(s): ${applied.map((r) => r.gatewayName).join(', ')}. Falhas: ${errors.join(' | ')}`;

  return {
    enforcementMode: 'live',
    gatewayId: applied[0].gatewayId,
    ruleRef: ruleRefs || undefined,
    gatewayResults,
    detail: summaryDetail,
  };
}

export async function rollbackFirewallRuleLive(
  integrations: IntegrationAdapter[],
  params: {
    executionId: string;
    targetIp?: string;
    ruleRef?: string;
    enforcementMode?: 'live' | 'simulated';
    persistentUci?: boolean;
    gatewayResults?: GatewayEnforcementDetail[];
  },
  getCredential: (integrationId: string) => { username?: string; secret?: string } | null,
  preferredSiteId?: string,
): Promise<FirewallEnforcementResult> {
  if (params.enforcementMode !== 'live') {
    return {
      enforcementMode: 'simulated',
      ruleRef: params.ruleRef,
      detail: 'Rollback simulado concluído (regra havia sido aplicada em modo simulado).',
    };
  }

  const recordedGwIds = params.gatewayResults
    ?.filter((g) => g.status === 'applied' || g.status === 'reconciled')
    .map((g) => g.gatewayId);

  const gateways = selectLiveGatewayAdapters(integrations, preferredSiteId, recordedGwIds);
  if (gateways.length === 0) {
    return {
      enforcementMode: 'simulated',
      ruleRef: params.ruleRef,
      detail: 'Gateway Live não está mais configurado; regra marcada como revertida no estado local.',
    };
  }

  const gatewayResults: GatewayEnforcementDetail[] = [];
  const errors: string[] = [];

  for (const gw of gateways) {
    const creds = getCredential(gw.id) ?? {};
    try {
      const res =
        gw.kind === 'openwrt-rpcd'
          ? await rollbackOpenWrtRule(gw, params.executionId, creds, params.persistentUci)
          : await rollbackOpnsenseRule(gw, params.targetIp, creds);
      gatewayResults.push({
        gatewayId: gw.id,
        gatewayName: gw.name,
        enforcementMode: res.enforcementMode,
        ruleRef: res.ruleRef,
        status: 'rolled_back',
        detail: res.detail,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Falha no rollback.';
      errors.push(`${gw.name}: ${msg}`);
      gatewayResults.push({
        gatewayId: gw.id,
        gatewayName: gw.name,
        enforcementMode: 'live',
        status: 'failed',
        detail: msg,
      });
    }
  }

  const succeeded = gatewayResults.filter((r) => r.status === 'rolled_back');
  if (succeeded.length === 0) {
    throw new Error(errors.join(' | ') || 'Falha no rollback dos gateways.');
  }

  return {
    enforcementMode: 'live',
    gatewayId: succeeded[0].gatewayId,
    ruleRef: params.ruleRef,
    gatewayResults,
    detail:
      errors.length === 0
        ? succeeded.map((r) => r.detail).join(' | ')
        : `Rollback em ${succeeded.length}/${gateways.length} gateway(s). Pendências: ${errors.join(' | ')}`,
  };
}

export async function reconcileGatewayFirewallRulesLive(
  adapter: IntegrationAdapter,
  activeExecutions: ActionExecution[],
  getCredential: (integrationId: string) => { username?: string; secret?: string } | null,
  persistentUciDefault = false,
): Promise<FirewallReconciliationSummary> {
  const summary: FirewallReconciliationSummary = {
    checkedCount: 0,
    reappliedExecutionIds: [],
    details: [],
    errors: [],
  };

  if (
    adapter.mode !== 'live' ||
    !adapter.liveEndpointUrl?.trim() ||
    (!isOpenWrtUbusAdapter(adapter) && adapter.kind !== 'opnsense-api')
  ) {
    return summary;
  }

  const nowMs = Date.now();
  const candidates = activeExecutions.filter((exec) => {
    if (exec.status !== 'active' && exec.status !== 'verified') return false;
    if (exec.enforcementMode !== 'live') return false;
    if (exec.actionType !== 'nftables_temp_drop' && exec.actionType !== 'isolate_iot_segment') {
      return false;
    }
    if (!exec.targetIp) return false;
    if (exec.expiresAt && Date.parse(exec.expiresAt) <= nowMs) return false;
    // If gatewayResults exists and didn't target this gateway, check site match unless gatewayResults is absent
    if (exec.gatewayResults && exec.gatewayResults.length > 0) {
      const targeted = exec.gatewayResults.some((g) => g.gatewayId === adapter.id);
      if (!targeted) return false;
    }
    return true;
  });

  if (candidates.length === 0) {
    return summary;
  }

  const creds = getCredential(adapter.id) ?? {};
  summary.checkedCount = candidates.length;

  if (adapter.kind === 'openwrt-rpcd') {
    let stdout = '';
    try {
      stdout = await listOpenWrtRulesetStdout(adapter, creds);
    } catch (err) {
      summary.errors.push(
        `${adapter.name}: ${err instanceof Error ? err.message : 'erro ao listar nftables'}`,
      );
      return summary;
    }

    for (const exec of candidates) {
      const present = parseOpenWrtHandlesFromStdout(stdout, exec.id);
      if (present.found) continue;

      try {
        const reapplied = await applyOpenWrtRule(
          adapter,
          {
            executionId: exec.id,
            targetIp: exec.targetIp,
            actionType: exec.actionType as 'nftables_temp_drop' | 'isolate_iot_segment',
            persistentUci: exec.persistentUci ?? persistentUciDefault,
          },
          creds,
        );
        summary.reappliedExecutionIds.push(exec.id);
        summary.details.push(
          `${exec.id} (${exec.targetIp}) reaplicado em ${adapter.name} (${reapplied.ruleRef ?? 'inet openshield'})`,
        );
        exec.reconciledAt = new Date().toISOString();
        if (reapplied.ruleRef) {
          exec.ruleRef = reapplied.ruleRef;
        }
        exec.verificationDetail = `${exec.verificationDetail} · Reconciliado pós-reboot em ${adapter.name} (${reapplied.ruleRef ?? 'ok'}).`;
        if (exec.gatewayResults) {
          const entry = exec.gatewayResults.find((g) => g.gatewayId === adapter.id);
          if (entry) {
            entry.status = 'reconciled';
            entry.ruleRef = reapplied.ruleRef;
            entry.detail = reapplied.detail;
          }
        }
      } catch (err) {
        summary.errors.push(
          `${exec.id} (${adapter.name}): ${err instanceof Error ? err.message : 'falha ao reaplicar'}`,
        );
      }
    }
    return summary;
  }

  if (adapter.kind === 'opnsense-api') {
    let aliasIps: Set<string>;
    try {
      aliasIps = await listOpnsenseAliasIps(adapter, creds);
    } catch (err) {
      summary.errors.push(
        `${adapter.name}: ${err instanceof Error ? err.message : 'erro ao consultar alias OPNsense'}`,
      );
      return summary;
    }

    for (const exec of candidates) {
      const cleanIp = normalizeIpAddress(exec.targetIp ?? '');
      if (aliasIps.has(cleanIp)) continue;

      try {
        const reapplied = await applyOpnsenseRule(
          adapter,
          {
            executionId: exec.id,
            targetIp: exec.targetIp,
            actionType: exec.actionType as 'nftables_temp_drop' | 'isolate_iot_segment',
          },
          creds,
        );
        summary.reappliedExecutionIds.push(exec.id);
        summary.details.push(
          `${exec.id} (${exec.targetIp}) restaurado em ${adapter.name} (${reapplied.ruleRef ?? OPNSENSE_ALIAS_NAME})`,
        );
        exec.reconciledAt = new Date().toISOString();
        exec.verificationDetail = `${exec.verificationDetail} · Reconciliado no alias ${OPNSENSE_ALIAS_NAME} em ${adapter.name}.`;
      } catch (err) {
        summary.errors.push(
          `${exec.id} (${adapter.name}): ${err instanceof Error ? err.message : 'falha ao restaurar alias'}`,
        );
      }
    }
  }

  return summary;
}
