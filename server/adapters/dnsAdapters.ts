import crypto from 'node:crypto';
import type { DnsInsight, OpenShieldEventV1 } from '../../src/types/openshield.ts';
import { boundedFetchJson } from './httpClient.ts';

export interface DnsSyncResult {
  events: OpenShieldEventV1[];
  insights: DnsInsight[];
  summaryNote: string;
}

async function resolvePiholeHeaders(baseUrl: string, secret?: string): Promise<Record<string, string>> {
  const password = secret || process.env.OPENSHIELD_PIHOLE_PASSWORD;
  if (!password) return {};

  // Attempt Pi-hole v6 session authentication (/api/auth), fallback to direct SID header
  try {
    const authRes = await boundedFetchJson<{ session?: { sid?: string; valid?: boolean } }>(
      `${baseUrl}/api/auth`,
      {
        method: 'POST',
        body: JSON.stringify({ password }),
        timeoutMs: 4000,
      },
    );
    if (authRes.ok && authRes.data.session?.sid) {
      return { 'X-FTL-SID': authRes.data.session.sid };
    }
  } catch {
    // Fallback to direct SID/token header if /api/auth is not exposed
  }

  return { 'X-FTL-SID': password };
}

export async function syncPiholeLive(
  endpointUrl: string,
  integrationId: string,
  adapterName: string,
  credentials?: { secret?: string },
): Promise<DnsSyncResult> {
  const baseUrl = (endpointUrl || process.env.OPENSHIELD_PIHOLE_URL || '').replace(/\/api.*$/, '');
  if (!baseUrl) {
    throw new Error(`URL do servidor ${adapterName} não configurada.`);
  }

  const headers = await resolvePiholeHeaders(baseUrl, credentials?.secret);

  const statsRes = await boundedFetchJson<Record<string, unknown>>(
    `${baseUrl}/api/stats/summary`,
    { headers, timeoutMs: 5000 },
  );

  if (!statsRes.ok) {
    throw new Error(
      `${adapterName} respondeu HTTP ${statsRes.status}. Verifique a URL ou a senha/token na página Configurações.`,
    );
  }

  const queriesObj = (statsRes.data.queries as Record<string, unknown> | undefined) ?? statsRes.data;
  const total = Number(queriesObj.total ?? queriesObj.dns_queries_today ?? 0);
  const blocked = Number(queriesObj.blocked ?? queriesObj.ads_blocked_today ?? 0);

  const insights: DnsInsight[] = [];
  try {
    const qRes = await boundedFetchJson<{
      queries?: Array<{
        domain?: string;
        client?: { name?: string | null; ip?: string };
        status?: string;
        time?: number;
      }>;
    }>(`${baseUrl}/api/queries?length=15`, { headers, timeoutMs: 4000 });

    if (qRes.ok && Array.isArray(qRes.data.queries)) {
      const seen = new Set<string>();
      for (const entry of qRes.data.queries) {
        const domain = String(entry.domain ?? '').trim().toLowerCase();
        if (!domain || seen.has(domain)) continue;
        seen.add(domain);
        const rawStatus = String(entry.status ?? '').toUpperCase();
        const isBlocked =
          rawStatus.includes('GRAVITY') ||
          rawStatus.includes('DENY') ||
          rawStatus.includes('BLOCKED') ||
          rawStatus.includes('REGEX');
        const clientLabel = String(entry.client?.name || entry.client?.ip || 'cliente-lan');
        insights.push({
          id: `dns-live-${crypto.createHash('sha1').update(domain).digest('hex').slice(0, 8)}`,
          domain,
          category: isBlocked ? 'Telemetria & Rastreador' : 'Serviço Local',
          classification: isBlocked ? 'tracker' : 'benign',
          deviceId: 'lan-client',
          deviceHostname: clientLabel,
          queriesCount: 1,
          blockedCount: isBlocked ? 1 : 0,
          listStatus: isBlocked ? 'blocked' : 'monitored',
          lastQueriedAt:
            typeof entry.time === 'number'
              ? new Date(entry.time * 1000).toISOString()
              : new Date().toISOString(),
        });
      }
    }
  } catch {
    // Graceful fallback if /api/queries is unavailable
  }

  const event: OpenShieldEventV1 = {
    eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
    schemaVersion: 'openshield.event.v1',
    occurredAt: new Date().toISOString(),
    sourceIntegrationId: integrationId,
    eventType: 'dns.query',
    severity: 'info',
    dataSource: 'live',
    summary: `Sincronização real (${adapterName}): ${total} consultas totais e ${blocked} bloqueios registrados (${insights.length} domínios amostrados).`,
    payload: {
      serverId: integrationId,
      serverName: adapterName,
      totalQueries: total,
      blockedQueries: blocked,
      sampledDomains: insights.length,
    },
  };

  return {
    events: [event],
    insights,
    summaryNote: `${adapterName} sincronizado (${total} consultas / ${blocked} bloqueadas).`,
  };
}

export async function syncAdguardLive(
  endpointUrl: string,
  integrationId: string,
  credentials?: { username?: string; secret?: string },
): Promise<DnsSyncResult> {
  const baseUrl = (endpointUrl || process.env.OPENSHIELD_ADGUARD_URL || '').replace(/\/control.*$/, '');
  const user = credentials?.username || process.env.OPENSHIELD_ADGUARD_USERNAME;
  const pass = credentials?.secret || process.env.OPENSHIELD_ADGUARD_PASSWORD;

  const headers: Record<string, string> = {};
  if (user && pass) {
    headers.Authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
  }

  const statusRes = await boundedFetchJson<{ running?: boolean; version?: string }>(
    `${baseUrl}/control/status`,
    { headers, timeoutMs: 5000 },
  );

  if (!statusRes.ok) {
    throw new Error(`AdGuard Home respondeu HTTP ${statusRes.status}.`);
  }

  const qlogRes = await boundedFetchJson<{
    data?: Array<{
      question?: { name?: string };
      client?: string;
      reason?: string;
      time?: string;
    }>;
  }>(`${baseUrl}/control/querylog?limit=15`, { headers, timeoutMs: 5000 });

  const entries = Array.isArray(qlogRes.data.data) ? qlogRes.data.data : [];
  const insights: DnsInsight[] = entries
    .filter((entry) => entry.question?.name)
    .slice(0, 8)
    .map((entry) => {
      const domain = String(entry.question?.name ?? '').toLowerCase();
      const isBlocked = String(entry.reason ?? '').toLowerCase().includes('filtered');
      return {
        id: `dns-live-${crypto.createHash('sha1').update(domain).digest('hex').slice(0, 8)}`,
        domain,
        category: isBlocked ? 'Telemetria & Rastreador' : 'Serviço Local',
        classification: isBlocked ? 'tracker' : 'benign',
        deviceId: 'lan-client',
        deviceHostname: String(entry.client ?? 'cliente-lan'),
        queriesCount: 1,
        blockedCount: isBlocked ? 1 : 0,
        listStatus: isBlocked ? 'blocked' : 'monitored',
        lastQueriedAt: entry.time || new Date().toISOString(),
      };
    });

  const event: OpenShieldEventV1 = {
    eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
    schemaVersion: 'openshield.event.v1',
    occurredAt: new Date().toISOString(),
    sourceIntegrationId: integrationId,
    eventType: 'dns.query',
    severity: 'info',
    dataSource: 'live',
    summary: `Sincronização real AdGuard Home (${statusRes.data.version ?? 'v0'}): ${entries.length} registros lidos do querylog.`,
    payload: {
      running: Boolean(statusRes.data.running),
      sampleCount: entries.length,
    },
  };

  return {
    events: [event],
    insights,
    summaryNote: `AdGuard Home sincronizado (${entries.length} consultas recentes).`,
  };
}

export async function syncTechnitiumLive(
  endpointUrl: string,
  integrationId: string,
  adapterName: string,
  credentials?: { secret?: string },
): Promise<DnsSyncResult> {
  const baseUrl = endpointUrl.replace(/\/api.*$/, '');
  const token = credentials?.secret || '';
  const queryUrl = `${baseUrl}/api/dashboard/stats/get?type=LastDay${token ? `&token=${encodeURIComponent(token)}` : ''}`;

  const res = await boundedFetchJson<{
    status?: string;
    errorMessage?: string;
    response?: {
      stats?: { totalQueries?: number; totalBlocked?: number };
      topBlocked?: Array<{ name?: string; hits?: number }>;
      topDomains?: Array<{ name?: string; hits?: number }>;
    };
  }>(queryUrl, { timeoutMs: 5000 });

  if (!res.ok || res.data.status === 'error') {
    throw new Error(
      `${adapterName} respondeu falha: ${res.data.errorMessage || `HTTP ${res.status}`}.`,
    );
  }

  const stats = res.data.response?.stats ?? {};
  const total = Number(stats.totalQueries ?? 0);
  const blocked = Number(stats.totalBlocked ?? 0);
  const insights: DnsInsight[] = [];

  for (const item of (res.data.response?.topBlocked ?? []).slice(0, 5)) {
    const domain = String(item.name ?? '').trim().toLowerCase();
    if (!domain) continue;
    insights.push({
      id: `dns-live-${crypto.createHash('sha1').update(domain).digest('hex').slice(0, 8)}`,
      domain,
      category: 'Telemetria & Rastreador',
      classification: 'tracker',
      deviceId: 'lan-client',
      deviceHostname: adapterName,
      queriesCount: Number(item.hits ?? 1),
      blockedCount: Number(item.hits ?? 1),
      listStatus: 'blocked',
      lastQueriedAt: new Date().toISOString(),
    });
  }

  for (const item of (res.data.response?.topDomains ?? []).slice(0, 5)) {
    const domain = String(item.name ?? '').trim().toLowerCase();
    if (!domain || insights.some((i) => i.domain === domain)) continue;
    insights.push({
      id: `dns-live-${crypto.createHash('sha1').update(domain).digest('hex').slice(0, 8)}`,
      domain,
      category: 'Serviço Local',
      classification: 'benign',
      deviceId: 'lan-client',
      deviceHostname: adapterName,
      queriesCount: Number(item.hits ?? 1),
      blockedCount: 0,
      listStatus: 'monitored',
      lastQueriedAt: new Date().toISOString(),
    });
  }

  const event: OpenShieldEventV1 = {
    eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
    schemaVersion: 'openshield.event.v1',
    occurredAt: new Date().toISOString(),
    sourceIntegrationId: integrationId,
    eventType: 'dns.query',
    severity: 'info',
    dataSource: 'live',
    summary: `Sincronização real (${adapterName}): ${total} consultas e ${blocked} bloqueios nas últimas 24h.`,
    payload: { totalQueries: total, blockedQueries: blocked },
  };

  return {
    events: [event],
    insights,
    summaryNote: `${adapterName} sincronizado (${total} consultas / ${blocked} bloqueadas).`,
  };
}

export async function pushDnsRuleLive(
  kind: string,
  adapterName: string,
  endpointUrl: string,
  domain: string,
  listStatus: DnsInsight['listStatus'],
  credentials?: { username?: string; secret?: string },
): Promise<string> {
  if (kind === 'pihole-v6') {
    const baseUrl = (endpointUrl || process.env.OPENSHIELD_PIHOLE_URL || '').replace(/\/api.*$/, '');
    const headers = await resolvePiholeHeaders(baseUrl, credentials?.secret);

    if (listStatus === 'blocked' || listStatus === 'allowed') {
      const listType = listStatus === 'blocked' ? 'deny' : 'allow';
      const res = await boundedFetchJson(`${baseUrl}/api/domains/${listType}/exact`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          domain,
          comment: 'Gerenciado pelo OpenShield',
          enabled: true,
        }),
        timeoutMs: 5000,
      });
      if (!res.ok) {
        throw new Error(`${adapterName} recusou regra DNS (HTTP ${res.status}).`);
      }
      return `${adapterName}: domínio adicionado à lista ${listType}`;
    }

    // Reverting to monitored: best-effort remove from deny/allow exact lists
    for (const listType of ['deny', 'allow']) {
      try {
        await boundedFetchJson(
          `${baseUrl}/api/domains/${listType}/exact/${encodeURIComponent(domain)}`,
          { method: 'DELETE', headers, timeoutMs: 4000 },
        );
      } catch {
        // Ignore if domain was not on that list
      }
    }
    return `${adapterName}: regra temporária removida (modo monitorado)`;
  }

  if (kind === 'adguard-home') {
    const baseUrl = (endpointUrl || process.env.OPENSHIELD_ADGUARD_URL || '').replace(/\/control.*$/, '');
    const user = credentials?.username || process.env.OPENSHIELD_ADGUARD_USERNAME;
    const pass = credentials?.secret || process.env.OPENSHIELD_ADGUARD_PASSWORD;
    const headers: Record<string, string> = {};
    if (user && pass) {
      headers.Authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    }

    let currentRules: string[] = [];
    try {
      const fRes = await boundedFetchJson<{ user_rules?: string[] }>(
        `${baseUrl}/control/filtering/status`,
        { headers, timeoutMs: 4000 },
      );
      if (fRes.ok && Array.isArray(fRes.data.user_rules)) {
        currentRules = fRes.data.user_rules;
      }
    } catch {
      // Fallback to empty base rules if status check fails
    }

    const blockRule = `||${domain}^`;
    const allowRule = `@@||${domain}^`;
    const cleanedRules = currentRules.filter((r) => r !== blockRule && r !== allowRule);

    if (listStatus === 'blocked') cleanedRules.push(blockRule);
    else if (listStatus === 'allowed') cleanedRules.push(allowRule);

    const res = await boundedFetchJson(`${baseUrl}/control/filtering/set_rules`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ rules: cleanedRules }),
      timeoutMs: 5000,
    });
    if (!res.ok) {
      throw new Error(`AdGuard Home recusou atualização de regra (HTTP ${res.status}).`);
    }
    return listStatus === 'monitored'
      ? `${adapterName}: regra removida (monitorado)`
      : `${adapterName}: regra aplicada`;
  }

  if (kind === 'technitium-dns') {
    const baseUrl = endpointUrl.replace(/\/api.*$/, '');
    const tokenParam = credentials?.secret ? `token=${encodeURIComponent(credentials.secret)}&` : '';
    if (listStatus === 'blocked') {
      const res = await boundedFetchJson(
        `${baseUrl}/api/blocked/add?${tokenParam}domain=${encodeURIComponent(domain)}`,
        { method: 'POST', timeoutMs: 5000 },
      );
      if (!res.ok) throw new Error(`${adapterName} recusou bloqueio DNS (HTTP ${res.status}).`);
      return `${adapterName}: adicionado em Blocked Zones`;
    }
    if (listStatus === 'allowed') {
      const res = await boundedFetchJson(
        `${baseUrl}/api/allowed/add?${tokenParam}domain=${encodeURIComponent(domain)}`,
        { method: 'POST', timeoutMs: 5000 },
      );
      if (!res.ok) throw new Error(`${adapterName} recusou permissão DNS (HTTP ${res.status}).`);
      return `${adapterName}: adicionado em Allowed Zones`;
    }
    try {
      await boundedFetchJson(
        `${baseUrl}/api/blocked/delete?${tokenParam}domain=${encodeURIComponent(domain)}`,
        { method: 'POST', timeoutMs: 4000 },
      );
    } catch {
      // Ignore if absent
    }
    return `${adapterName}: regra removida (monitorado)`;
  }

  return `${adapterName}: estado registrado`;
}
