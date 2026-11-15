import type {
  ActionExecution,
  DnsInsight,
  NetworkDevice,
  OpenShieldEventV1,
  RouterAccessAttempt,
  WorkspaceState,
} from '../types/openshield';

export type TelemetryWindow = '15m' | '1h' | '24h';

export interface TelemetryBucketPoint {
  bucketStartMs: number;
  timeLabel: string;
  fullTimestamp: string;
  rxKb: number;
  txKb: number;
  totalThroughputKb: number;
  packetsOrQueries: number;
  firewallDrops: number;
  dnsDrops: number;
  totalDrops: number;
  avgLatencyMs: number | null;
}

export interface TelemetrySummary {
  window: TelemetryWindow;
  buckets: TelemetryBucketPoint[];
  hasTelemetry: boolean;
  totalRxKb: number;
  totalTxKb: number;
  peakThroughputKb: number;
  totalFirewallDrops: number;
  totalDnsDrops: number;
  totalDrops: number;
  dropRatePct: number;
  totalPacketsOrQueries: number;
  latestLatencyMs: number | null;
  activeFirewallRulesCount: number;
}

const WINDOW_CONFIG: Record<TelemetryWindow, { bucketCount: number; bucketMs: number }> = {
  '15m': { bucketCount: 15, bucketMs: 60_000 },
  '1h': { bucketCount: 12, bucketMs: 5 * 60_000 },
  '24h': { bucketCount: 24, bucketMs: 60 * 60_000 },
};

function toFiniteNumber(val: unknown): number {
  if (typeof val === 'number' && Number.isFinite(val) && val > 0) return val;
  if (typeof val === 'string' && val.trim() !== '') {
    const parsed = Number(val);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return 0;
}

function firstPositive(payload: Record<string, unknown>, keys: string[]): number {
  for (const key of keys) {
    const n = toFiniteNumber(payload[key]);
    if (n > 0) return n;
  }
  return 0;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export function buildTelemetrySummary(
  state: WorkspaceState,
  window: TelemetryWindow,
  locale: string,
  nowMs = Date.now(),
): TelemetrySummary {
  const { bucketCount, bucketMs } = WINDOW_CONFIG[window];
  const windowSpanMs = bucketCount * bucketMs;
  const alignedEndMs = Math.ceil(nowMs / bucketMs) * bucketMs;
  const windowStartMs = alignedEndMs - windowSpanMs;

  const isBusiness = state.context.profile === 'business';
  const scopedDevices: NetworkDevice[] = isBusiness
    ? state.devices
    : state.devices.filter((d) => d.siteId === state.context.activeSiteId);
  const scopedIntegrations = isBusiness
    ? state.integrations
    : state.integrations.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);

  const scopedDeviceIds = new Set(scopedDevices.map((d) => d.id));
  const scopedDeviceHosts = new Set(scopedDevices.map((d) => d.hostname.toLowerCase()));
  const scopedIntegrationIds = new Set(scopedIntegrations.map((i) => i.id));

  const scopedEvents: OpenShieldEventV1[] = isBusiness
    ? state.events
    : state.events.filter(
        (ev) =>
          (ev.deviceId && scopedDeviceIds.has(ev.deviceId)) ||
          scopedIntegrationIds.has(ev.sourceIntegrationId),
      );

  const scopedDnsInsights: DnsInsight[] = isBusiness
    ? state.dnsInsights
    : state.dnsInsights.filter(
        (ins) =>
          scopedDeviceIds.has(ins.deviceId) ||
          scopedDeviceHosts.has(ins.deviceHostname.toLowerCase()),
      );

  const scopedRouterAttempts: RouterAccessAttempt[] = isBusiness
    ? state.routerAccessAttempts ?? []
    : (state.routerAccessAttempts ?? []).filter(
        (r) => !r.siteId || r.siteId === state.context.activeSiteId,
      );

  const scopedIncidents = isBusiness
    ? state.incidents
    : state.incidents.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);
  const scopedIncidentIds = new Set(scopedIncidents.map((i) => i.id));
  const scopedExecutions: ActionExecution[] = isBusiness
    ? state.executions
    : state.executions.filter((e) => scopedIncidentIds.has(e.incidentId));

  const latencyHistory = state.latencyHistory ?? [];

  const hasTelemetry =
    scopedEvents.length > 0 ||
    scopedDnsInsights.length > 0 ||
    scopedRouterAttempts.length > 0 ||
    scopedExecutions.length > 0 ||
    latencyHistory.length > 0;

  interface MutableBucket {
    bucketStartMs: number;
    rxBytes: number;
    txBytes: number;
    packetsOrQueries: number;
    firewallDrops: number;
    dnsDrops: number;
    latencySum: number;
    latencyCount: number;
  }

  const rawBuckets: MutableBucket[] = Array.from({ length: bucketCount }, (_, idx) => ({
    bucketStartMs: windowStartMs + idx * bucketMs,
    rxBytes: 0,
    txBytes: 0,
    packetsOrQueries: 0,
    firewallDrops: 0,
    dnsDrops: 0,
    latencySum: 0,
    latencyCount: 0,
  }));

  const findBucketIdx = (iso: string): number | null => {
    const ts = Date.parse(iso);
    if (!Number.isFinite(ts)) return null;
    if (ts < windowStartMs || ts > alignedEndMs) return null;
    const rawIdx = Math.floor((ts - windowStartMs) / bucketMs);
    return Math.min(bucketCount - 1, Math.max(0, rawIdx));
  };

  // Deduplicate dns.query events if the same domain is already tracked in dnsInsights
  const dnsInsightDomains = new Set(scopedDnsInsights.map((d) => d.domain.toLowerCase()));

  // 1. Ingested Telemetry Events (bytes, packet counters, explicit drops)
  for (const ev of scopedEvents) {
    const idx = findBucketIdx(ev.occurredAt);
    if (idx === null) continue;
    const bucket = rawBuckets[idx];
    const p = ev.payload ?? {};

    let rx = firstPositive(p, ['bytesRecv', 'rxBytes', 'rx_bytes', 'bytesIn', 'transferRx', 'in_bytes']);
    let tx = firstPositive(p, ['bytesSent', 'txBytes', 'tx_bytes', 'bytesOut', 'transferTx', 'out_bytes']);

    if (rx === 0 && tx === 0) {
      const totalBytes = firstPositive(p, ['bytes', 'totalBytes']);
      if (totalBytes > 0) {
        rx = totalBytes * 0.75;
        tx = totalBytes * 0.25;
      }
    }

    const explicitDrops = firstPositive(p, [
      'packetsDropped',
      'droppedPackets',
      'rxDropped',
      'txDropped',
      'rx_dropped',
      'tx_dropped',
      'drops',
    ]);

    if (ev.eventType === 'dns.query') {
      const domain = typeof p.domain === 'string' ? p.domain.trim().toLowerCase() : '';
      if (domain && dnsInsightDomains.has(domain)) {
        // Covered with full accuracy in step 2 (scopedDnsInsights)
        if (explicitDrops > 0) bucket.firewallDrops += explicitDrops;
        continue;
      }
      const queries = Math.max(1, firstPositive(p, ['queriesInWindow', 'queries']));
      bucket.rxBytes += rx > 0 ? rx : queries * 320;
      bucket.txBytes += tx > 0 ? tx : queries * 110;
      bucket.packetsOrQueries += queries;
      if (p.action === 'blocked' || p.blocked === true) {
        bucket.dnsDrops += queries;
      }
      if (explicitDrops > 0) bucket.firewallDrops += explicitDrops;
      continue;
    }

    if (rx > 0 || tx > 0) {
      bucket.rxBytes += rx;
      bucket.txBytes += tx;
    } else if (ev.eventType !== 'router.access_attempt') {
      const pkt = Math.max(1, firstPositive(p, ['packets', 'itemCount', 'discoveredCount', 'totalPeers']));
      bucket.rxBytes += pkt * 640;
      bucket.txBytes += pkt * 280;
    }

    const packets = Math.max(
      1,
      firstPositive(p, ['packets', 'attemptsCount', 'queriesInWindow', 'totalPeers']),
    );
    bucket.packetsOrQueries += packets;

    if (explicitDrops > 0) {
      bucket.firewallDrops += explicitDrops;
    } else if (
      (ev.eventType === 'ids.alert' || ev.eventType === 'threat.ioc') &&
      (p.action === 'blocked' || p.action === 'dropped' || p.blocked === true)
    ) {
      bucket.firewallDrops += 1;
    }
  }

  // 2. DNS Insights (query volume & blocked DNS packets)
  for (const ins of scopedDnsInsights) {
    const idx = findBucketIdx(ins.lastQueriedAt);
    if (idx === null) continue;
    const bucket = rawBuckets[idx];
    const queries = Math.max(0, ins.queriesCount);
    const blocked = Math.max(0, ins.blockedCount);
    bucket.rxBytes += queries * 320;
    bucket.txBytes += queries * 110;
    bucket.packetsOrQueries += queries;
    bucket.dnsDrops += blocked;
  }

  // 3. Unauthorized Router Access Attempts & WAN Drops
  for (const attempt of scopedRouterAttempts) {
    const idx = findBucketIdx(attempt.lastSeenAt) ?? findBucketIdx(attempt.firstSeenAt);
    if (idx === null) continue;
    const bucket = rawBuckets[idx];
    const count = Math.max(1, attempt.attemptsCount);
    // Ingress probe traffic associated with the attempt
    bucket.rxBytes += count * 180;
    bucket.packetsOrQueries += count;
    if (attempt.service === 'wan_drop' || attempt.status === 'blocked') {
      bucket.firewallDrops += count;
    }
  }

  // 4. Firewall Containment Executions (nftables drop / IoT isolation / DNS blocks)
  let activeFirewallRulesCount = 0;
  for (const exec of scopedExecutions) {
    if (
      (exec.status === 'active' || exec.status === 'verified') &&
      (exec.actionType === 'nftables_temp_drop' || exec.actionType === 'isolate_iot_segment')
    ) {
      activeFirewallRulesCount += 1;
    }
    const idx = findBucketIdx(exec.createdAt);
    if (idx === null) continue;
    if (exec.actionType === 'nftables_temp_drop' || exec.actionType === 'isolate_iot_segment') {
      rawBuckets[idx].firewallDrops += 1;
    } else if (exec.actionType === 'dns_block_domain') {
      rawBuckets[idx].dnsDrops += 1;
    }
  }

  // 5. Aggregated Latency History
  let latestKnownLatency: number | null = null;
  for (const sample of latencyHistory) {
    if (typeof sample.avgLatencyMs === 'number' && Number.isFinite(sample.avgLatencyMs)) {
      latestKnownLatency = sample.avgLatencyMs;
    }
    const idx = findBucketIdx(sample.timestamp);
    if (idx === null) continue;
    rawBuckets[idx].latencySum += sample.avgLatencyMs;
    rawBuckets[idx].latencyCount += 1;
  }

  const buckets: TelemetryBucketPoint[] = rawBuckets.map((b) => {
    const dt = new Date(b.bucketStartMs);
    const timeLabel = dt.toLocaleTimeString(locale, {
      hour: '2-digit',
      minute: '2-digit',
    });
    const fullTimestamp = dt.toLocaleString(locale, {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
    const rxKb = round1(b.rxBytes / 1024);
    const txKb = round1(b.txBytes / 1024);
    const avgLatencyMs =
      b.latencyCount > 0 ? Math.round(b.latencySum / b.latencyCount) : null;

    return {
      bucketStartMs: b.bucketStartMs,
      timeLabel,
      fullTimestamp,
      rxKb,
      txKb,
      totalThroughputKb: round1(rxKb + txKb),
      packetsOrQueries: b.packetsOrQueries,
      firewallDrops: b.firewallDrops,
      dnsDrops: b.dnsDrops,
      totalDrops: b.firewallDrops + b.dnsDrops,
      avgLatencyMs,
    };
  });

  const totalRxKb = round1(buckets.reduce((sum, b) => sum + b.rxKb, 0));
  const totalTxKb = round1(buckets.reduce((sum, b) => sum + b.txKb, 0));
  const peakThroughputKb = round1(
    buckets.reduce((max, b) => Math.max(max, b.totalThroughputKb), 0),
  );
  const totalFirewallDrops = buckets.reduce((sum, b) => sum + b.firewallDrops, 0);
  const totalDnsDrops = buckets.reduce((sum, b) => sum + b.dnsDrops, 0);
  const totalDrops = totalFirewallDrops + totalDnsDrops;
  const totalPacketsOrQueries = buckets.reduce((sum, b) => sum + b.packetsOrQueries, 0);
  const dropRatePct =
    totalPacketsOrQueries > 0
      ? round1(Math.min(100, (totalDrops / totalPacketsOrQueries) * 100))
      : 0;

  return {
    window,
    buckets,
    hasTelemetry,
    totalRxKb,
    totalTxKb,
    peakThroughputKb,
    totalFirewallDrops,
    totalDnsDrops,
    totalDrops,
    dropRatePct,
    totalPacketsOrQueries,
    latestLatencyMs: latestKnownLatency,
    activeFirewallRulesCount,
  };
}
