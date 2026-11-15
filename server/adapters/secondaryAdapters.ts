import crypto from 'node:crypto';
import type { EventSeverity, OpenShieldEventV1 } from '../../src/types/openshield.ts';
import { boundedFetchJson, boundedFetchText } from './httpClient.ts';
import { normalizeIpAddress, type DiscoveredDeviceHint } from './openwrtAdapter.ts';

export interface SecondarySyncResult {
  events: OpenShieldEventV1[];
  discoveredDevices: DiscoveredDeviceHint[];
  summaryNote: string;
}

function buildAuthHeaders(credentials?: { username?: string; secret?: string }): Record<string, string> {
  const headers: Record<string, string> = {};
  if (credentials?.username && credentials?.secret) {
    headers.Authorization = `Basic ${Buffer.from(`${credentials.username}:${credentials.secret}`).toString('base64')}`;
  } else if (credentials?.secret) {
    headers.Authorization = `Bearer ${credentials.secret}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// 1. CrowdSec LAPI (/v1/decisions/stream or /v1/decisions)
// ---------------------------------------------------------------------------
export interface CrowdSecDecisionRaw {
  id?: number | string;
  origin?: string;
  type?: string;
  scope?: string;
  value?: string;
  duration?: string;
  scenario?: string;
  reason?: string;
}

export function parseCrowdSecDecisionsPayload(
  data: unknown,
  integrationId: string,
  nowIso = new Date().toISOString(),
): { events: OpenShieldEventV1[]; activeCount: number; deletedCount: number } {
  const newDecisions: CrowdSecDecisionRaw[] = [];
  let deletedCount = 0;

  if (Array.isArray(data)) {
    for (const item of data) {
      if (item && typeof item === 'object') newDecisions.push(item as CrowdSecDecisionRaw);
    }
  } else if (data && typeof data === 'object') {
    const obj = data as { new?: unknown; deleted?: unknown; decisions?: unknown };
    if (Array.isArray(obj.new)) {
      for (const item of obj.new) {
        if (item && typeof item === 'object') newDecisions.push(item as CrowdSecDecisionRaw);
      }
    }
    if (Array.isArray(obj.decisions)) {
      for (const item of obj.decisions) {
        if (item && typeof item === 'object') newDecisions.push(item as CrowdSecDecisionRaw);
      }
    }
    if (Array.isArray(obj.deleted)) {
      deletedCount = obj.deleted.length;
    }
  }

  const events: OpenShieldEventV1[] = [];
  for (const dec of newDecisions.slice(0, 40)) {
    const value = normalizeIpAddress(String(dec.value ?? ''));
    if (!value) continue;
    const scenario = String(dec.scenario || dec.reason || dec.type || 'crowdsec/decision');
    const origin = String(dec.origin || 'crowdsec');
    const severity: EventSeverity =
      /brute|bf|exploit|scan|ddos/i.test(scenario) ? 'high' : 'medium';

    events.push({
      eventId: dec.id ? `cs-${dec.id}` : `cs-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'threat.ioc',
      severity,
      dataSource: 'live',
      summary: `CrowdSec ${dec.type ?? 'ban'}: ${value} (${scenario})`,
      payload: {
        srcIp: value,
        scope: dec.scope ?? 'Ip',
        scenario,
        duration: dec.duration ?? '4h',
        origin,
        decisionType: dec.type ?? 'ban',
      },
    });
  }

  return {
    events,
    activeCount: newDecisions.length,
    deletedCount,
  };
}

export async function syncCrowdSecLive(
  endpointUrl: string,
  integrationId: string,
  integrationName: string,
  credentials?: { username?: string; secret?: string },
): Promise<SecondarySyncResult> {
  const cleanUrl = endpointUrl.trim().replace(/\/+$/, '');
  const targetUrl =
    cleanUrl.includes('/decisions') ? cleanUrl : `${cleanUrl}/v1/decisions/stream`;

  const headers: Record<string, string> = {};
  const apiKey = credentials?.secret || process.env.OPENSHIELD_CROWDSEC_API_KEY || '';
  if (apiKey) {
    headers['X-Api-Key'] = apiKey;
  }

  const res = await boundedFetchJson<unknown>(targetUrl, {
    headers,
    timeoutMs: 5000,
  });
  if (!res.ok) {
    throw new Error(`CrowdSec (${integrationName}) retornou HTTP ${res.status}.`);
  }

  const parsed = parseCrowdSecDecisionsPayload(res.data, integrationId);
  const events: OpenShieldEventV1[] =
    parsed.events.length > 0
      ? parsed.events
      : [
          {
            eventId: `cs-health-${crypto.randomUUID().slice(0, 8)}`,
            schemaVersion: 'openshield.event.v1',
            occurredAt: new Date().toISOString(),
            sourceIntegrationId: integrationId,
            eventType: 'threat.ioc',
            severity: 'info',
            dataSource: 'live',
            summary: `CrowdSec LAPI (${integrationName}) sincronizado: 0 novas decisões maliciosas.`,
            payload: { activeCount: parsed.activeCount, deletedCount: parsed.deletedCount },
          },
        ];

  return {
    events,
    discoveredDevices: [],
    summaryNote: `CrowdSec sincronizado: ${parsed.activeCount} decisão(ões) ativa(s), ${parsed.deletedCount} removida(s).`,
  };
}

// ---------------------------------------------------------------------------
// 2. WireGuard / wg-easy (/api/wireguard/client)
// ---------------------------------------------------------------------------
export interface WireGuardPeerRaw {
  id?: string;
  name?: string;
  enabled?: boolean;
  address?: string;
  allowedIPs?: string[];
  publicKey?: string;
  latestHandshakeAt?: string | null;
  transferRx?: number;
  transferTx?: number;
}

export function parseWireGuardPeersPayload(
  data: unknown,
  integrationId: string,
  nowIso = new Date().toISOString(),
): {
  events: OpenShieldEventV1[];
  discoveredDevices: DiscoveredDeviceHint[];
  totalPeers: number;
  onlinePeers: number;
} {
  let rawPeers: WireGuardPeerRaw[] = [];
  if (Array.isArray(data)) {
    rawPeers = data.filter((p): p is WireGuardPeerRaw => Boolean(p && typeof p === 'object'));
  } else if (data && typeof data === 'object') {
    const obj = data as { clients?: unknown; peers?: unknown };
    if (Array.isArray(obj.clients)) {
      rawPeers = obj.clients.filter((p): p is WireGuardPeerRaw => Boolean(p && typeof p === 'object'));
    } else if (Array.isArray(obj.peers)) {
      rawPeers = obj.peers.filter((p): p is WireGuardPeerRaw => Boolean(p && typeof p === 'object'));
    }
  }

  const discoveredDevices: DiscoveredDeviceHint[] = [];
  const nowMs = Date.parse(nowIso) || Date.now();
  let onlinePeers = 0;

  for (const peer of rawPeers.slice(0, 60)) {
    const rawIp =
      peer.address ||
      (Array.isArray(peer.allowedIPs) && peer.allowedIPs[0] ? peer.allowedIPs[0].split('/')[0] : '');
    const ip = normalizeIpAddress(String(rawIp || ''));
    const hostname = String(peer.name || peer.id || ip || 'wg-peer').trim();
    if (!ip) continue;

    const handshakeMs = peer.latestHandshakeAt ? Date.parse(peer.latestHandshakeAt) : NaN;
    const isRecentlyActive =
      Boolean(peer.enabled !== false) &&
      Number.isFinite(handshakeMs) &&
      nowMs - handshakeMs <= 5 * 60_000;
    if (isRecentlyActive) onlinePeers += 1;

    discoveredDevices.push({
      id: peer.id ? `wg-${peer.id}` : undefined,
      hostname,
      ip,
      mac: peer.publicKey ? `WG:${peer.publicKey.slice(0, 12)}` : undefined,
      vendor: `WireGuard Peer (${peer.enabled === false ? 'desabilitado' : isRecentlyActive ? 'ativo' : 'ocioso'})`,
      interfaceName: 'wg0',
      segment: 'Escritório / VPN',
      deviceType: /phone|iphone|android|pixel|galaxy|mobile/i.test(hostname) ? 'mobile' : 'workstation',
    });
  }

  const events: OpenShieldEventV1[] = [
    {
      eventId: `wg-sync-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'gateway.discovery',
      severity: 'info',
      dataSource: 'live',
      summary: `WireGuard sincronizado: ${rawPeers.length} peer(s) configurado(s), ${onlinePeers} com handshake recente.`,
      payload: {
        totalPeers: rawPeers.length,
        onlinePeers,
      },
    },
  ];

  return {
    events,
    discoveredDevices,
    totalPeers: rawPeers.length,
    onlinePeers,
  };
}

export async function syncWireGuardLive(
  endpointUrl: string,
  integrationId: string,
  integrationName: string,
  credentials?: { username?: string; secret?: string },
): Promise<SecondarySyncResult> {
  const cleanUrl = endpointUrl.trim().replace(/\/+$/, '');
  const targetUrl = cleanUrl.includes('/api/') ? cleanUrl : `${cleanUrl}/api/wireguard/client`;
  const res = await boundedFetchJson<unknown>(targetUrl, {
    headers: buildAuthHeaders(credentials),
    timeoutMs: 5000,
  });
  if (!res.ok) {
    throw new Error(`WireGuard (${integrationName}) retornou HTTP ${res.status}.`);
  }
  const parsed = parseWireGuardPeersPayload(res.data, integrationId);
  return {
    events: parsed.events,
    discoveredDevices: parsed.discoveredDevices,
    summaryNote: `WireGuard sincronizado: ${parsed.totalPeers} peer(s) (${parsed.onlinePeers} online).`,
  };
}

// ---------------------------------------------------------------------------
// 3. Uptime Kuma (/metrics Prometheus)
// ---------------------------------------------------------------------------
export interface ParsedMonitorStatus {
  name: string;
  type?: string;
  url?: string;
  up: boolean;
  responseTimeMs?: number;
}

function parsePrometheusLabels(rawLabels: string): Record<string, string> {
  const labels: Record<string, string> = {};
  const labelRegex = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/g;
  let match: RegExpExecArray | null;
  while ((match = labelRegex.exec(rawLabels)) !== null) {
    labels[match[1]] = match[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return labels;
}

export function parseUptimeKumaMetricsText(
  metricsText: string,
  integrationId: string,
  nowIso = new Date().toISOString(),
): {
  events: OpenShieldEventV1[];
  monitors: ParsedMonitorStatus[];
  upCount: number;
  downCount: number;
} {
  const byName = new Map<string, ParsedMonitorStatus>();

  for (const rawLine of metricsText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
    if (!match) continue;

    const metricName = match[1];
    const labels = match[2] ? parsePrometheusLabels(match[2]) : {};
    const value = Number(match[3]);
    const monitorName = labels.monitor_name || labels.name;
    if (!monitorName || !Number.isFinite(value)) continue;

    const existing = byName.get(monitorName) ?? {
      name: monitorName,
      type: labels.monitor_type,
      url: labels.monitor_url,
      up: true,
    };

    if (metricName === 'monitor_status') {
      existing.up = value >= 1;
      if (labels.monitor_type) existing.type = labels.monitor_type;
      if (labels.monitor_url) existing.url = labels.monitor_url;
    } else if (metricName === 'monitor_response_time') {
      existing.responseTimeMs = Math.round(value);
    }

    byName.set(monitorName, existing);
  }

  const monitors = [...byName.values()];
  const upCount = monitors.filter((m) => m.up).length;
  const downMonitors = monitors.filter((m) => !m.up);
  const downCount = downMonitors.length;

  const events: OpenShieldEventV1[] = [];
  if (downCount > 0) {
    events.push({
      eventId: `uk-down-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'gateway.health',
      severity: downCount >= 2 ? 'high' : 'medium',
      dataSource: 'live',
      summary: `Uptime Kuma: ${downCount} monitor(es) offline (${downMonitors.map((m) => m.name).slice(0, 4).join(', ')}).`,
      payload: {
        upCount,
        downCount,
        downMonitors: downMonitors.map((m) => ({ name: m.name, url: m.url, type: m.type })),
      },
    });
  } else {
    events.push({
      eventId: `uk-ok-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'gateway.health',
      severity: 'info',
      dataSource: 'live',
      summary: `Uptime Kuma operacional: ${upCount}/${monitors.length} monitor(es) online.`,
      payload: {
        upCount,
        downCount: 0,
        monitorsCount: monitors.length,
      },
    });
  }

  return {
    events,
    monitors,
    upCount,
    downCount,
  };
}

export async function syncUptimeKumaLive(
  endpointUrl: string,
  integrationId: string,
  integrationName: string,
  credentials?: { username?: string; secret?: string },
): Promise<SecondarySyncResult> {
  const cleanUrl = endpointUrl.trim().replace(/\/+$/, '');
  const targetUrl = cleanUrl.endsWith('/metrics') ? cleanUrl : `${cleanUrl}/metrics`;
  const res = await boundedFetchText(targetUrl, {
    headers: buildAuthHeaders(credentials),
    timeoutMs: 5000,
  });
  if (!res.ok) {
    throw new Error(`Uptime Kuma (${integrationName}) retornou HTTP ${res.status}.`);
  }
  const parsed = parseUptimeKumaMetricsText(res.text, integrationId);
  return {
    events: parsed.events,
    discoveredDevices: [],
    summaryNote: `Uptime Kuma sincronizado: ${parsed.upCount} up, ${parsed.downCount} down.`,
  };
}

// ---------------------------------------------------------------------------
// 4. Suricata EVE & Wazuh structured parsers
// ---------------------------------------------------------------------------
export function parseSuricataEvePayload(
  data: unknown,
  integrationId: string,
  nowIso = new Date().toISOString(),
): OpenShieldEventV1[] {
  const rows: Record<string, unknown>[] = Array.isArray(data)
    ? data.filter((r): r is Record<string, unknown> => Boolean(r && typeof r === 'object'))
    : data && typeof data === 'object' && Array.isArray((data as { events?: unknown }).events)
      ? ((data as { events: unknown[] }).events.filter(
          (r): r is Record<string, unknown> => Boolean(r && typeof r === 'object'),
        ))
      : [];

  const events: OpenShieldEventV1[] = [];
  for (const row of rows.slice(0, 30)) {
    const alert = (row.alert ?? {}) as { severity?: number; signature?: string; category?: string };
    const srcIp = row.src_ip ? normalizeIpAddress(String(row.src_ip)) : undefined;
    const destIp = row.dest_ip ? normalizeIpAddress(String(row.dest_ip)) : undefined;
    const sevNum = Number(alert.severity ?? 3);
    const severity: EventSeverity =
      sevNum <= 1 ? 'critical' : sevNum === 2 ? 'high' : sevNum === 3 ? 'medium' : 'low';
    const signature = String(alert.signature || row.event_type || 'Suricata IDS Alert');

    events.push({
      eventId: `sur-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: typeof row.timestamp === 'string' ? row.timestamp : nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'ids.alert',
      severity,
      dataSource: 'live',
      summary: `Suricata: ${signature}${srcIp ? ` (${srcIp} -> ${destIp ?? '?'})` : ''}`,
      payload: {
        srcIp,
        destIp,
        dstPort: row.dest_port,
        proto: row.proto,
        category: alert.category,
        signature,
      },
    });
  }
  return events;
}

export async function syncSuricataLive(
  endpointUrl: string,
  integrationId: string,
  integrationName: string,
  credentials?: { username?: string; secret?: string },
): Promise<SecondarySyncResult> {
  const res = await boundedFetchJson<unknown>(endpointUrl.trim(), {
    headers: buildAuthHeaders(credentials),
    timeoutMs: 5000,
  });
  if (!res.ok) {
    throw new Error(`Suricata (${integrationName}) retornou HTTP ${res.status}.`);
  }
  const parsedEvents = parseSuricataEvePayload(res.data, integrationId);
  const events: OpenShieldEventV1[] =
    parsedEvents.length > 0
      ? parsedEvents
      : [
          {
            eventId: `sur-ok-${crypto.randomUUID().slice(0, 8)}`,
            schemaVersion: 'openshield.event.v1',
            occurredAt: new Date().toISOString(),
            sourceIntegrationId: integrationId,
            eventType: 'ids.alert',
            severity: 'info',
            dataSource: 'live',
            summary: `Suricata (${integrationName}) operacional: 0 novos alertas EVE.`,
            payload: { status: 'ok' },
          },
        ];
  return {
    events,
    discoveredDevices: [],
    summaryNote: `Suricata sincronizado: ${parsedEvents.length} alerta(s) EVE processado(s).`,
  };
}

export function parseWazuhAlertsPayload(
  data: unknown,
  integrationId: string,
  nowIso = new Date().toISOString(),
): OpenShieldEventV1[] {
  let rows: Record<string, unknown>[] = [];
  if (Array.isArray(data)) {
    rows = data.filter((r): r is Record<string, unknown> => Boolean(r && typeof r === 'object'));
  } else if (data && typeof data === 'object') {
    const inner = (data as { data?: { affected_items?: unknown }; hits?: { hits?: unknown } }).data
      ?.affected_items;
    if (Array.isArray(inner)) {
      rows = inner.filter((r): r is Record<string, unknown> => Boolean(r && typeof r === 'object'));
    }
  }

  return rows.slice(0, 30).map((row) => {
    const rule = (row.rule ?? {}) as { level?: number; description?: string; id?: string };
    const agent = (row.agent ?? {}) as { name?: string; ip?: string };
    const level = Number(rule.level ?? 3);
    const severity: EventSeverity =
      level >= 12 ? 'critical' : level >= 8 ? 'high' : level >= 5 ? 'medium' : 'low';
    const agentIp = agent.ip ? normalizeIpAddress(String(agent.ip)) : undefined;
    return {
      eventId: `waz-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: typeof row.timestamp === 'string' ? row.timestamp : nowIso,
      sourceIntegrationId: integrationId,
      eventType: 'ids.alert',
      severity,
      dataSource: 'live',
      summary: `Wazuh [${agent.name ?? 'agent'}]: ${rule.description ?? row.name ?? 'Alerta HIDS'}`,
      payload: {
        srcIp: agentIp,
        agentName: agent.name,
        ruleId: rule.id,
        ruleLevel: level,
      },
    };
  });
}

export async function syncWazuhLive(
  endpointUrl: string,
  integrationId: string,
  integrationName: string,
  credentials?: { username?: string; secret?: string },
): Promise<SecondarySyncResult> {
  const res = await boundedFetchJson<unknown>(endpointUrl.trim(), {
    headers: buildAuthHeaders(credentials),
    timeoutMs: 5000,
  });
  if (!res.ok) {
    throw new Error(`Wazuh (${integrationName}) retornou HTTP ${res.status}.`);
  }
  const parsedEvents = parseWazuhAlertsPayload(res.data, integrationId);
  const events: OpenShieldEventV1[] =
    parsedEvents.length > 0
      ? parsedEvents
      : [
          {
            eventId: `waz-ok-${crypto.randomUUID().slice(0, 8)}`,
            schemaVersion: 'openshield.event.v1',
            occurredAt: new Date().toISOString(),
            sourceIntegrationId: integrationId,
            eventType: 'ids.alert',
            severity: 'info',
            dataSource: 'live',
            summary: `Wazuh (${integrationName}) conectado (HTTP ${res.status}).`,
            payload: { status: 'ok' },
          },
        ];
  return {
    events,
    discoveredDevices: [],
    summaryNote: `Wazuh sincronizado: ${parsedEvents.length} item(ns) processado(s).`,
  };
}
