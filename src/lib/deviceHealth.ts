import type {
  IntegrationAdapter,
  NetworkDevice,
  OpenShieldEventV1,
  WorkspaceState,
} from '../types/openshield';

export type DeviceHealthStatus = 'online' | 'offline' | 'high_latency';

export interface DeviceHealthInfo {
  status: DeviceHealthStatus;
  latencyMs: number | null;
  lastSeenMinutesAgo: number | null;
}

export const DEVICE_OFFLINE_STALE_MS = 15 * 60 * 1000;
export const HIGH_LATENCY_THRESHOLD_MS = 150;

function normalizeIp(raw?: unknown): string {
  if (typeof raw !== 'string') return '';
  let val = raw.trim();
  if (!val) return '';
  if (val.startsWith('[') && val.includes(']')) {
    val = val.slice(1, val.indexOf(']'));
  }
  if (val.toLowerCase().startsWith('::ffff:')) {
    val = val.slice(7);
  }
  return val.toLowerCase();
}

function extractNumericLatency(payload?: Record<string, unknown>): number | null {
  if (!payload) return null;
  for (const key of ['latencyMs', 'rttMs', 'avgLatencyMs'] as const) {
    const num = Number(payload[key]);
    if (Number.isFinite(num) && num >= 0) {
      return Math.round(num);
    }
  }
  return null;
}

function isExplicitlyOfflineEvent(ev: OpenShieldEventV1): boolean {
  const payload = ev.payload;
  if (!payload) return false;
  if (payload.online === false || payload.reachable === false) return true;
  const rawState = String(payload.status ?? payload.state ?? '').trim().toLowerCase();
  return rawState === 'offline' || rawState === 'down' || rawState === 'unreachable';
}

function hasLatencySpikeFlag(ev: OpenShieldEventV1): boolean {
  const payload = ev.payload;
  if (!payload) return false;
  if (payload.latencySpike === true) return true;
  const health = String(payload.health ?? payload.status ?? '').trim().toLowerCase();
  return health === 'high_latency' || health === 'degraded';
}

function findMatchedAdapter(
  device: NetworkDevice,
  integrations: IntegrationAdapter[],
): IntegrationAdapter | undefined {
  const normIp = normalizeIp(device.ip);
  const hostLower = device.hostname.trim().toLowerCase();
  const hasNamedHost =
    hostLower.length > 0 && hostLower !== '(sem-nome)' && hostLower !== '(unnamed)';

  const byEndpoint = integrations.find((adapter) => {
    const url = adapter.liveEndpointUrl?.toLowerCase() ?? '';
    if (!url) return false;
    if (normIp && url.includes(normIp)) return true;
    if (hasNamedHost && url.includes(hostLower)) return true;
    return false;
  });
  if (byEndpoint) return byEndpoint;

  if (device.deviceType === 'router') {
    return (
      integrations.find((a) => a.domain === 'gateway' && a.siteId === device.siteId) ??
      integrations.find((a) => a.domain === 'gateway')
    );
  }

  return undefined;
}

export function deriveDeviceHealth(
  device: NetworkDevice,
  state: WorkspaceState,
  nowMs = Date.now(),
): DeviceHealthInfo {
  const normIp = normalizeIp(device.ip);
  const hostLower = device.hostname.trim().toLowerCase();
  const hasNamedHost =
    hostLower.length > 0 && hostLower !== '(sem-nome)' && hostLower !== '(unnamed)';

  const matchingEvents = state.events
    .filter((ev) => {
      if (ev.deviceId === device.id) return true;
      if (normIp && normalizeIp(ev.payload?.srcIp) === normIp) return true;
      if (normIp && normalizeIp(ev.payload?.clientIp) === normIp) return true;
      if (
        hasNamedHost &&
        String(ev.payload?.deviceHostname ?? '').trim().toLowerCase() === hostLower
      ) {
        return true;
      }
      return false;
    })
    .sort((a, b) => (Date.parse(b.occurredAt) || 0) - (Date.parse(a.occurredAt) || 0));

  const matchedAdapter = findMatchedAdapter(device, state.integrations);

  let latencyMs: number | null = null;
  for (const ev of matchingEvents) {
    const val = extractNumericLatency(ev.payload);
    if (val !== null) {
      latencyMs = val;
      break;
    }
  }

  if (
    latencyMs === null &&
    matchedAdapter &&
    typeof matchedAdapter.lastLatencyMs === 'number' &&
    Number.isFinite(matchedAdapter.lastLatencyMs)
  ) {
    latencyMs = Math.round(matchedAdapter.lastLatencyMs);
  }

  const latestHistory =
    state.latencyHistory && state.latencyHistory.length > 0
      ? state.latencyHistory[state.latencyHistory.length - 1]
      : undefined;

  if (
    latencyMs === null &&
    device.deviceType === 'router' &&
    latestHistory &&
    Number.isFinite(latestHistory.avgLatencyMs)
  ) {
    latencyMs = Math.round(latestHistory.avgLatencyMs);
  }

  const lastSeenMs = Date.parse(device.lastSeenAt);
  const hasValidLastSeen = Number.isFinite(lastSeenMs);
  const lastSeenMinutesAgo = hasValidLastSeen
    ? Math.max(0, Math.round((nowMs - lastSeenMs) / 60_000))
    : null;

  const isStaleLastSeen = hasValidLastSeen && nowMs - lastSeenMs > DEVICE_OFFLINE_STALE_MS;
  const newestEvent = matchingEvents[0];
  const eventOffline = newestEvent ? isExplicitlyOfflineEvent(newestEvent) : false;
  const adapterUnavailable = matchedAdapter?.status === 'unavailable';
  const gatewayDisabled =
    device.deviceType === 'router' && !state.context.gatewayForwardingActive;

  if (
    device.status === 'isolated' ||
    isStaleLastSeen ||
    eventOffline ||
    adapterUnavailable ||
    gatewayDisabled
  ) {
    return {
      status: 'offline',
      latencyMs,
      lastSeenMinutesAgo,
    };
  }

  const eventHighLatency = matchingEvents.some(hasLatencySpikeFlag);
  const adapterStale = matchedAdapter?.status === 'stale';
  const routerHistoryHighLatency =
    device.deviceType === 'router' &&
    latestHistory !== undefined &&
    latestHistory.avgLatencyMs >= HIGH_LATENCY_THRESHOLD_MS;

  if (
    (latencyMs !== null && latencyMs >= HIGH_LATENCY_THRESHOLD_MS) ||
    eventHighLatency ||
    adapterStale ||
    routerHistoryHighLatency
  ) {
    return {
      status: 'high_latency',
      latencyMs,
      lastSeenMinutesAgo,
    };
  }

  return {
    status: 'online',
    latencyMs,
    lastSeenMinutesAgo,
  };
}
