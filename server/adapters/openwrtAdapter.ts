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

export interface Ip4NeighEntry {
  mac: string;
  ip: string;
  dev: string;
}

const MAC_REGEX = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/;
const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

export function inferSegmentFromInterface(
  ifaceName?: string,
  devName?: string,
): NetworkDevice['segment'] {
  const combined = `${ifaceName ?? ''} ${devName ?? ''}`.toLowerCase();
  if (/(iot|guest|convid|dmz|vlan20|vlan30|isolat|smart)/.test(combined)) {
    return 'IoT / Convidados';
  }
  if (/(wg|wireguard|vpn|tun|tap|tailscale|office|escritorio|corp)/.test(combined)) {
    return 'Escritório / VPN';
  }
  return 'LAN Confiável';
}

export function inferDeviceTypeFromHint(
  hostname: string,
  ifaceName?: string,
): NetworkDevice['deviceType'] {
  const host = hostname.toLowerCase();
  const iface = (ifaceName ?? '').toLowerCase();
  if (/^wan\d*$/.test(iface) || /(openwrt|router|gateway|mikrotik|pfsense|opnsense)/.test(host)) {
    return 'router';
  }
  if (/(pihole|adguard|nas|synology|proxmox|truenas|server|srv|node|ubuntu|debian|docker|homelab)/.test(host)) {
    return 'server';
  }
  if (/(iphone|ipad|android|pixel|galaxy|xiaomi|oneplus|phone|mobile|celular|moto|redmi)/.test(host)) {
    return 'mobile';
  }
  if (
    /(cam|camera|esp|tasmota|shelly|smart|tv|roku|chromecast|sonos|alexa|echo|bulb|sensor|plug|printer|iot|zigbee|homekit)/.test(
      host,
    ) ||
    inferSegmentFromInterface(ifaceName) === 'IoT / Convidados'
  ) {
    return 'iot';
  }
  return 'workstation';
}

export function buildInterfaceDeviceMap(netDump: unknown): Map<string, string> {
  const devToIface = new Map<string, string>();
  const rawList =
    netDump && typeof netDump === 'object' && Array.isArray((netDump as { interface?: unknown[] }).interface)
      ? ((netDump as { interface: Record<string, unknown>[] }).interface)
      : [];

  // Pass 1: match l3_device == DEV (mirrors jsonfilter @.interface[@.l3_device='$DEV'].interface | head -n1)
  for (const item of rawList) {
    const iface = typeof item?.interface === 'string' ? item.interface.trim() : '';
    const l3 = typeof item?.l3_device === 'string' ? item.l3_device.trim() : '';
    if (iface && l3 && !devToIface.has(l3)) {
      devToIface.set(l3, iface);
    }
  }

  // Pass 2: fallback to device == DEV (mirrors jsonfilter @.interface[@.device='$DEV'].interface | head -n1)
  for (const item of rawList) {
    const iface = typeof item?.interface === 'string' ? item.interface.trim() : '';
    const dev = typeof item?.device === 'string' ? item.device.trim() : '';
    if (iface && dev && !devToIface.has(dev)) {
      devToIface.set(dev, iface);
    }
  }

  return devToIface;
}

export function lookupHostHintName(hints: unknown, mac: string): string {
  if (!hints || typeof hints !== 'object') return '';
  const record = hints as Record<string, { name?: unknown }>;
  const macUp = mac.toUpperCase();
  const macLow = mac.toLowerCase();
  const entry = record[macUp] ?? record[mac] ?? record[macLow];
  return typeof entry?.name === 'string' ? entry.name.trim() : '';
}

export function parseIp4NeighText(rawText: string): Ip4NeighEntry[] {
  const rows: Ip4NeighEntry[] = [];
  for (const line of rawText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Case 1: `ip -4 neigh show` output -> "<ip> dev <dev> lladdr <mac> <state>"
    const tokens = trimmed.split(/\s+/);
    if (IPV4_REGEX.test(tokens[0])) {
      let dev = '';
      let mac = '';
      for (let i = 1; i < tokens.length; i += 1) {
        if (tokens[i] === 'dev' && tokens[i + 1]) dev = tokens[i + 1];
        if (tokens[i] === 'lladdr' && tokens[i + 1]) mac = tokens[i + 1];
      }
      if (MAC_REGEX.test(mac) && mac !== '00:00:00:00:00:00' && dev) {
        rows.push({ ip: tokens[0], mac: mac.toUpperCase(), dev });
        continue;
      }

      // Case 2: `/proc/net/arp` -> "<ip> <hwtype> <flags> <mac> <mask> <dev>"
      if (tokens.length >= 6 && MAC_REGEX.test(tokens[3]) && tokens[3] !== '00:00:00:00:00:00') {
        rows.push({ ip: tokens[0], mac: tokens[3].toUpperCase(), dev: tokens[5] });
      }
    }
  }
  return rows;
}

export function mapOpenWrtNeighbors(input: {
  netDump?: unknown;
  hostHints?: unknown;
  ipNeighRows: Ip4NeighEntry[];
  defaultVendor?: string;
}): DiscoveredDeviceHint[] {
  const devToIface = buildInterfaceDeviceMap(input.netDump);
  const seen = new Set<string>();
  const devices: DiscoveredDeviceHint[] = [];

  for (const row of input.ipNeighRows) {
    const mac = row.mac.trim().toUpperCase();
    const ip = row.ip.trim();
    const dev = row.dev.trim();
    if (!mac || !ip || !dev) continue;

    const dedupeKey = `${mac}|${ip}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const name = lookupHostHintName(input.hostHints, mac);
    const hostname = name || '(sem-nome)';
    const iface = devToIface.get(dev) || dev;

    devices.push({
      hostname,
      ip,
      mac,
      vendor: input.defaultVendor || 'Descoberto via OpenWrt (ubus/neigh)',
      interfaceName: iface,
      segment: inferSegmentFromInterface(iface, dev),
      deviceType: inferDeviceTypeFromHint(hostname, iface),
    });
  }

  return devices;
}

export function parseOpenWrtCommandOutput(rawOutput: string): DiscoveredDeviceHint[] {
  const devices: DiscoveredDeviceHint[] = [];
  const seen = new Set<string>();

  // First check if user pasted raw `ip -4 neigh show` or `/proc/net/arp`
  const rawNeighRows = parseIp4NeighText(rawOutput);
  if (rawNeighRows.length > 0) {
    return mapOpenWrtNeighbors({
      ipNeighRows: rawNeighRows,
      defaultVendor: 'Mapeado via ip neigh OpenWrt',
    });
  }

  // Standard tabular output from:
  // printf "%-22s %-18s %-16s %s\n" "${NAME:-(sem-nome)}" "$MAC" "$IP" "${IFACE:-$DEV}"
  const linePattern =
    /^(.*?)\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+((?:\d{1,3}\.){3}\d{1,3})\s+(\S+)\s*$/;

  for (const line of rawOutput.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const match = trimmed.match(linePattern);
    if (!match) continue;

    const rawName = match[1].trim();
    const mac = match[2].toUpperCase();
    const ip = match[3].trim();
    const iface = match[4].trim();

    const dedupeKey = `${mac}|${ip}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const hostname = rawName || '(sem-nome)';
    devices.push({
      hostname,
      ip,
      mac,
      vendor: 'Mapeado via OpenWrt (ubus + ip neigh)',
      interfaceName: iface || 'br-lan',
      segment: inferSegmentFromInterface(iface),
      deviceType: inferDeviceTypeFromHint(hostname, iface),
    });
  }

  return devices;
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
        for (const dev of devRes.data.devices.slice(0, 60)) {
          if (dev.hostname && dev.ip) {
            const iface = dev.interfaceName ? String(dev.interfaceName) : 'br-lan';
            discoveredDevices.push({
              id: dev.id ? String(dev.id) : undefined,
              hostname: String(dev.hostname),
              ip: String(dev.ip),
              mac: dev.mac ? String(dev.mac).toUpperCase() : undefined,
              vendor: dev.vendor ? String(dev.vendor) : 'Descoberto pelo Node',
              interfaceName: iface,
              segment: dev.segment ?? inferSegmentFromInterface(iface),
              deviceType: dev.deviceType ?? inferDeviceTypeFromHint(String(dev.hostname), iface),
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

  // Fetch luci-rpc getHostHints (HINTS)
  let hostHints: Record<string, unknown> = {};
  try {
    hostHints = await callUbus(ubusUrl, token, 'luci-rpc', 'getHostHints');
  } catch {
    hostHints = {};
  }

  // Fetch `ip -4 neigh show` equivalent via ubus file.exec -> fallback file.read(/proc/net/arp)
  let ipNeighRows: Ip4NeighEntry[] = [];
  try {
    const execRes = await callUbus(ubusUrl, token, 'file', 'exec', {
      command: 'ip',
      params: ['-4', 'neigh', 'show'],
    });
    if (typeof execRes.stdout === 'string' && execRes.stdout.trim()) {
      ipNeighRows = parseIp4NeighText(execRes.stdout);
    }
  } catch {
    // Try /proc/net/arp if file.exec ACL is unavailable
    try {
      const arpRes = await callUbus(ubusUrl, token, 'file', 'read', {
        path: '/proc/net/arp',
      });
      if (typeof arpRes.data === 'string' && arpRes.data.trim()) {
        ipNeighRows = parseIp4NeighText(arpRes.data);
      }
    } catch {
      // Fallback gracefully to hostHints only
    }
  }

  // Map neighbor rows with exact NET + HINTS correlation
  const mappedNeighbors = mapOpenWrtNeighbors({
    netDump,
    hostHints,
    ipNeighRows,
    defaultVendor: 'Descoberto via OpenWrt (ubus + ip neigh)',
  });

  const knownKeys = new Set(
    mappedNeighbors.map((d) => `${(d.mac ?? '').toUpperCase()}|${d.ip}`),
  );
  discoveredDevices.push(...mappedNeighbors);

  // Merge any remaining IPv4 hosts present in luci-rpc.getHostHints if neighbor table was restricted
  const defaultLanIface = interfaces.includes('lan') ? 'lan' : interfaces[0] || 'br-lan';
  for (const [mac, rawInfo] of Object.entries(hostHints)) {
    const info = rawInfo as { ipaddrs?: string[]; name?: string };
    const ip = Array.isArray(info.ipaddrs) && info.ipaddrs[0] ? String(info.ipaddrs[0]) : '';
    const macUp = mac.toUpperCase();
    if (!ip || knownKeys.has(`${macUp}|${ip}`)) continue;
    knownKeys.add(`${macUp}|${ip}`);

    const hostname = info.name ? String(info.name).trim() : '(sem-nome)';
    discoveredDevices.push({
      hostname,
      ip,
      mac: macUp,
      vendor: 'Descoberto via OpenWrt rpcd',
      interfaceName: defaultLanIface,
      segment: inferSegmentFromInterface(defaultLanIface),
      deviceType: inferDeviceTypeFromHint(hostname, defaultLanIface),
    });
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
