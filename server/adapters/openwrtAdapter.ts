import crypto from 'node:crypto';
import type { NetworkDevice, OpenShieldEventV1 } from '../../src/types/openshield.ts';
import { boundedFetchJson } from './httpClient.ts';

interface UbusRpcResponse {
  result?: [number, Record<string, unknown>];
  error?: { code?: number; message?: string };
}

export interface DiscoveredDeviceHint {
  id?: string;
  hostname: string;
  ip: string;
  mac?: string;
  vendor?: string;
  interfaceName?: string;
  segment: NetworkDevice['segment'];
  deviceType: NetworkDevice['deviceType'];
}

export interface OpenWrtSyncResult {
  boardInfo: {
    model: string;
    firmware: string;
    interfaces: string[];
  };
  events: OpenShieldEventV1[];
  discoveredDevices: DiscoveredDeviceHint[];
}

function extractHostIp(endpointUrl: string): string {
  try {
    const parsed = new URL(endpointUrl);
    return parsed.hostname || '192.168.1.1';
  } catch {
    return '192.168.1.1';
  }
}

async function callUbus(
  ubusUrl: string,
  sessionToken: string,
  object: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const payload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'call',
    params: [sessionToken, object, method, params],
  };

  const res = await boundedFetchJson<UbusRpcResponse>(ubusUrl, {
    method: 'POST',
    body: JSON.stringify(payload),
    timeoutMs: 5000,
  });

  if (!res.ok) {
    throw new Error(`OpenWrt rpcd respondeu HTTP ${res.status}.`);
  }
  if (res.data.error) {
    throw new Error(`Erro ubus (${res.data.error.code ?? -1}): ${res.data.error.message ?? 'falha RPC'}`);
  }
  const resultTuple = res.data.result;
  if (!Array.isArray(resultTuple) || resultTuple[0] !== 0) {
    throw new Error(`Chamada ubus ${object}.${method} recusada (código ${resultTuple?.[0] ?? 'desconhecido'}).`);
  }
  return resultTuple[1] ?? {};
}

export async function syncOpenWrtReadOnly(
  endpointUrl: string,
  integrationId: string,
  credentials?: { username?: string; secret?: string },
): Promise<OpenWrtSyncResult> {
  const ubusUrl = endpointUrl || process.env.OPENSHIELD_OPENWRT_URL || '';
  const username = credentials?.username || process.env.OPENSHIELD_OPENWRT_USERNAME;
  const password = credentials?.secret || process.env.OPENSHIELD_OPENWRT_PASSWORD;

  if (!ubusUrl) {
    throw new Error('URL do gateway OpenWrt / Node não configurada.');
  }

  // If URL looks like OpenShield FastAPI Node instead of raw /ubus, query Node API directly
  if (!ubusUrl.includes('/ubus') && ubusUrl.includes('/api/v1')) {
    const baseNode = ubusUrl.replace(/\/api\/v1.*$/, '');
    const eventsRes = await boundedFetchJson<{ events?: OpenShieldEventV1[] }>(
      `${baseNode}/api/v1/events?limit=25`,
      { timeoutMs: 5000 },
    );
    if (!eventsRes.ok) {
      throw new Error(`OpenShield Node respondeu HTTP ${eventsRes.status} ao buscar eventos.`);
    }
    const events = Array.isArray(eventsRes.data.events) ? eventsRes.data.events : [];
    const discoveredDevices: DiscoveredDeviceHint[] = [
      {
        id: `gw-${integrationId}`,
        hostname: `openshield-node (${extractHostIp(ubusUrl)})`,
        ip: extractHostIp(ubusUrl),
        vendor: 'OpenShield Node Gateway',
        interfaceName: 'br-lan',
        segment: 'LAN Confiável',
        deviceType: 'router',
      },
    ];

    try {
      const devRes = await boundedFetchJson<{ devices?: Partial<DiscoveredDeviceHint>[] }>(
        `${baseNode}/api/v1/devices`,
        { timeoutMs: 3000 },
      );
      if (devRes.ok && Array.isArray(devRes.data.devices)) {
        for (const dev of devRes.data.devices.slice(0, 30)) {
          if (dev.hostname && dev.ip) {
            discoveredDevices.push({
              hostname: String(dev.hostname),
              ip: String(dev.ip),
              mac: dev.mac ? String(dev.mac) : undefined,
              vendor: dev.vendor ? String(dev.vendor) : 'Descoberto pelo Node',
              interfaceName: dev.interfaceName ? String(dev.interfaceName) : 'br-lan',
              segment: dev.segment ?? 'LAN Confiável',
              deviceType: dev.deviceType ?? 'workstation',
            });
          }
        }
      }
    } catch {
      // Optional endpoint on remote Node
    }

    return {
      boardInfo: {
        model: 'OpenShield Node (FastAPI Sincronizado)',
        firmware: 'openshield.gateway.v1',
        interfaces: ['lan-trusted'],
      },
      events: events.map((ev) => ({ ...ev, dataSource: 'live' })),
      discoveredDevices,
    };
  }

  if (!username || !password) {
    throw new Error(
      'Credenciais OpenWrt não configuradas. Preencha usuário e senha na página Configurações ou via ambiente do servidor.',
    );
  }

  const loginData = await callUbus(
    ubusUrl,
    '00000000000000000000000000000000',
    'session',
    'login',
    { username, password },
  );
  const token = typeof loginData.ubus_rpc_session === 'string' ? loginData.ubus_rpc_session : '';
  if (!token) {
    throw new Error('Falha ao obter token de sessão rpcd/ubus no OpenWrt.');
  }

  const board = await callUbus(ubusUrl, token, 'system', 'board');
  const netDump = await callUbus(ubusUrl, token, 'network.interface', 'dump');

  const release = (board.release as Record<string, unknown> | undefined) ?? {};
  const model = String(board.model ?? board.board_name ?? 'OpenWrt Router');
  const firmware = String(release.description ?? release.version ?? 'OpenWrt');
  const rawIfaces = Array.isArray(netDump.interface) ? netDump.interface : [];
  const interfaces = rawIfaces
    .map((item) => String((item as Record<string, unknown>).interface ?? ''))
    .filter(Boolean);

  const routerIp = extractHostIp(ubusUrl);
  const discoveredDevices: DiscoveredDeviceHint[] = [
    {
      id: `gw-${integrationId}`,
      hostname: String(board.hostname ?? model.toLowerCase().replace(/[^a-z0-9-]/g, '-')),
      ip: routerIp,
      vendor: model,
      interfaceName: interfaces[0] || 'br-lan',
      segment: 'LAN Confiável',
      deviceType: 'router',
    },
  ];

  // Attempt read-only LAN host discovery via luci-rpc if ACL permits
  try {
    const hints = await callUbus(ubusUrl, token, 'luci-rpc', 'getHostHints');
    for (const [mac, rawInfo] of Object.entries(hints).slice(0, 25)) {
      const info = rawInfo as { ipaddrs?: string[]; name?: string };
      const ip = Array.isArray(info.ipaddrs) && info.ipaddrs[0] ? String(info.ipaddrs[0]) : '';
      if (!ip) continue;
      discoveredDevices.push({
        hostname: info.name ? String(info.name) : `host-${ip.replace(/\./g, '-')}`,
        ip,
        mac: mac.toUpperCase(),
        vendor: 'Descoberto via OpenWrt rpcd',
        interfaceName: 'br-lan',
        segment: 'LAN Confiável',
        deviceType: 'workstation',
      });
    }
  } catch {
    // Graceful fallback if luci-rpc ACL is not granted
  }

  const nowIso = new Date().toISOString();
  const discoveryEvent: OpenShieldEventV1 = {
    eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
    schemaVersion: 'openshield.event.v1',
    occurredAt: nowIso,
    sourceIntegrationId: integrationId,
    eventType: 'gateway.discovery',
    severity: 'info',
    dataSource: 'live',
    summary: `Descoberta real OpenWrt (${model} · ${firmware}) concluída com ${discoveredDevices.length} dispositivo(s) identificados.`,
    payload: {
      model,
      firmware,
      interfaces,
      discoveredCount: discoveredDevices.length,
      readOnly: true,
    },
  };

  return {
    boardInfo: { model, firmware, interfaces },
    events: [discoveryEvent],
    discoveredDevices,
  };
}
