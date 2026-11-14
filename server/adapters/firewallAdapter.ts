import type { IntegrationAdapter } from '../../src/types/openshield.ts';
import { boundedFetchJson } from './httpClient.ts';
import { callUbus, normalizeIpAddress, openwrtLogin } from './openwrtAdapter.ts';

export interface FirewallEnforcementResult {
  enforcementMode: 'live' | 'simulated';
  ruleRef?: string;
  gatewayId?: string;
  detail: string;
}

export interface FirewallRuleTarget {
  executionId: string;
  targetIp?: string;
  actionType: 'nftables_temp_drop' | 'isolate_iot_segment';
}

const IPV4_EXACT = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_EXACT = /^[0-9a-fA-F:]{3,45}$/;
const OPNSENSE_ALIAS_NAME = 'openshield_blocked';

function assertValidIp(rawIp: string): { ip: string; family: 'ip' | 'ip6' } {
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

function selectLiveGatewayAdapters(
  integrations: IntegrationAdapter[],
  preferredSiteId?: string,
): IntegrationAdapter[] {
  const candidates = integrations.filter(
    (i) =>
      i.mode === 'live' &&
      Boolean(i.liveEndpointUrl?.trim()) &&
      ((i.kind === 'openwrt-rpcd' && i.liveEndpointUrl.includes('/ubus')) ||
        i.kind === 'opnsense-api'),
  );
  if (!preferredSiteId) return candidates;
  return [...candidates].sort((a, b) => {
    const aMatch = a.siteId === preferredSiteId ? 0 : 1;
    const bMatch = b.siteId === preferredSiteId ? 0 : 1;
    return aMatch - bMatch;
  });
}

function formatOpenWrtFirewallDiagnostic(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.includes('código 6') || /access denied/i.test(msg)) {
    return `OpenWrt rpcd recusou acesso de firewall (${msg}). Instale a ACL /usr/share/rpcd/acl.d/openshield-fw.json permitindo file.exec para nft.`;
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

  const ubusUrl = adapter.liveEndpointUrl;
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

    const verify = await verifyOpenWrtRule(adapter, target.executionId, credentials);
    if (!verify.found) {
      throw new Error(
        `Regra ${commentTag} não apareceu na listagem nftables de verificação (${adapter.name}).`,
      );
    }

    return {
      enforcementMode: 'live',
      gatewayId: adapter.id,
      ruleRef: verify.ruleRef || `nft:inet/openshield:${commentTag}`,
      detail: `Bloqueio real aplicado em ${adapter.name} (${verify.ruleRef || commentTag}) e verificado via nft -a list.`,
    };
  } catch (err) {
    throw new Error(formatOpenWrtFirewallDiagnostic(err));
  }
}

async function verifyOpenWrtRule(
  adapter: IntegrationAdapter,
  executionId: string,
  credentials: { username?: string; secret?: string },
): Promise<{ found: boolean; ruleRef?: string; handles: Array<{ chain: string; handle: string }> }> {
  const ubusUrl = adapter.liveEndpointUrl;
  const username = credentials.username || process.env.OPENSHIELD_OPENWRT_USERNAME || '';
  const password = credentials.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD || '';
  if (!username || !password) {
    return { found: false, handles: [] };
  }

  const token = await openwrtLogin(ubusUrl, username, password);
  const res = await callUbus(ubusUrl, token, 'file', 'exec', {
    command: 'nft',
    params: ['-a', 'list', 'table', 'inet', 'openshield'],
  });
  const stdout = typeof res.stdout === 'string' ? res.stdout : '';
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

async function rollbackOpenWrtRule(
  adapter: IntegrationAdapter,
  executionId: string,
  credentials: { username?: string; secret?: string },
): Promise<FirewallEnforcementResult> {
  const ubusUrl = adapter.liveEndpointUrl;
  const username = credentials.username || process.env.OPENSHIELD_OPENWRT_USERNAME || '';
  const password = credentials.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD || '';
  if (!username || !password) {
    throw new Error(`Credenciais ubus ausentes para rollback em ${adapter.name}.`);
  }

  try {
    const verify = await verifyOpenWrtRule(adapter, executionId, credentials);
    if (!verify.found || verify.handles.length === 0) {
      return {
        enforcementMode: 'live',
        gatewayId: adapter.id,
        ruleRef: `nft:inet/openshield:openshield_${executionId}`,
        detail: `Rollback concluído em ${adapter.name}: regra já não estava presente em inet openshield.`,
      };
    }

    const token = await openwrtLogin(ubusUrl, username, password);
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
  const baseUrl = adapter.liveEndpointUrl.replace(/\/api.*$/, '');
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
  const baseUrl = adapter.liveEndpointUrl.replace(/\/api.*$/, '');
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
  const gateways = selectLiveGatewayAdapters(integrations, preferredSiteId);
  if (gateways.length === 0) {
    return {
      enforcementMode: 'simulated',
      detail:
        'Contenção registrada em modo simulado (nenhum gateway OpenWrt ubus ou OPNsense configurado em API Real).',
    };
  }

  const gw = gateways[0];
  const creds = getCredential(gw.id) ?? {};
  if (gw.kind === 'openwrt-rpcd') {
    return applyOpenWrtRule(gw, target, creds);
  }
  if (gw.kind === 'opnsense-api') {
    return applyOpnsenseRule(gw, target, creds);
  }

  return {
    enforcementMode: 'simulated',
    detail: 'Contenção registrada em modo simulado.',
  };
}

export async function rollbackFirewallRuleLive(
  integrations: IntegrationAdapter[],
  params: {
    executionId: string;
    targetIp?: string;
    ruleRef?: string;
    enforcementMode?: 'live' | 'simulated';
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

  const gateways = selectLiveGatewayAdapters(integrations, preferredSiteId);
  if (gateways.length === 0) {
    return {
      enforcementMode: 'simulated',
      ruleRef: params.ruleRef,
      detail: 'Gateway Live não está mais configurado; regra marcada como revertida no estado local.',
    };
  }

  const gw = gateways[0];
  const creds = getCredential(gw.id) ?? {};
  if (gw.kind === 'openwrt-rpcd') {
    return rollbackOpenWrtRule(gw, params.executionId, creds);
  }
  if (gw.kind === 'opnsense-api') {
    return rollbackOpnsenseRule(gw, params.targetIp, creds);
  }

  return {
    enforcementMode: 'simulated',
    ruleRef: params.ruleRef,
    detail: 'Rollback concluído.',
  };
}
