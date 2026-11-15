import type {
  ActionExecution,
  DnsInsight,
  Incident,
  NetworkDevice,
  OpenShieldEventV1,
  RouterAccessAttempt,
  WorkspaceState,
} from '../types/openshield';

export type TelemetryWindow = '15m' | '1h' | '24h';

export interface TelemetryBucketPoint {
  bucketStartMs: number;
  bucketEndMs: number;
  timeLabel: string;
  intervalEndLabel: string;
  fullTimestamp: string;
  rxBytes: number;
  txBytes: number;
  totalBytes: number;
  rxKb: number;
  txKb: number;
  totalThroughputKb: number;
  packetsOrQueries: number;
  firewallDrops: number;
  dnsDrops: number;
  totalDrops: number;
  dropRatioPct: number;
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
    const bucketEndMs = b.bucketStartMs + bucketMs;
    const dt = new Date(b.bucketStartMs);
    const dtEnd = new Date(bucketEndMs);
    const timeLabel = dt.toLocaleTimeString(locale, {
      hour: '2-digit',
      minute: '2-digit',
    });
    const intervalEndLabel = dtEnd.toLocaleTimeString(locale, {
      hour: '2-digit',
      minute: '2-digit',
    });
    const fullTimestamp = dt.toLocaleString(locale, {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
    const rxBytes = Math.round(b.rxBytes);
    const txBytes = Math.round(b.txBytes);
    const totalBytes = rxBytes + txBytes;
    const rxKb = round1(rxBytes / 1024);
    const txKb = round1(txBytes / 1024);
    const totalDrops = b.firewallDrops + b.dnsDrops;
    const dropRatioPct =
      b.packetsOrQueries > 0
        ? round1(Math.min(100, (totalDrops / b.packetsOrQueries) * 100))
        : 0;
    const avgLatencyMs =
      b.latencyCount > 0 ? Math.round(b.latencySum / b.latencyCount) : null;

    return {
      bucketStartMs: b.bucketStartMs,
      bucketEndMs,
      timeLabel,
      intervalEndLabel,
      fullTimestamp,
      rxBytes,
      txBytes,
      totalBytes,
      rxKb,
      txKb,
      totalThroughputKb: round1(rxKb + txKb),
      packetsOrQueries: b.packetsOrQueries,
      firewallDrops: b.firewallDrops,
      dnsDrops: b.dnsDrops,
      totalDrops,
      dropRatioPct,
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

export type ThreatAxisId =
  | 'malware'
  | 'botnet'
  | 'unauthorizedAccess'
  | 'dnsAnomalies'
  | 'bruteForce';

export interface ThreatLandscapeAxis {
  id: ThreatAxisId;
  score: number;
  mitigatedScore: number;
  signalCount: number;
  activeSignals: number;
  mitigatedSignals: number;
  level: 'nominal' | 'elevated' | 'high' | 'critical';
  topEvidence?: string;
}

export interface ThreatLandscapeSummary {
  axes: ThreatLandscapeAxis[];
  overallScore: number;
  highestAxisId: ThreatAxisId | null;
  hasSignals: boolean;
  totalSignals: number;
}

const SEVERITY_POINTS: Record<OpenShieldEventV1['severity'], number> = {
  critical: 34,
  high: 24,
  medium: 14,
  low: 6,
  info: 2,
};

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function resolveThreatLevel(score: number): ThreatLandscapeAxis['level'] {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'elevated';
  return 'nominal';
}

export function buildThreatLandscape(state: WorkspaceState): ThreatLandscapeSummary {
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

  const scopedIncidents: Incident[] = isBusiness
    ? state.incidents
    : state.incidents.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);

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

  const acc: Record<
    ThreatAxisId,
    {
      activeRaw: number;
      mitigatedRaw: number;
      activeSignals: number;
      mitigatedSignals: number;
      topEvidence?: string;
      topWeight: number;
    }
  > = {
    malware: { activeRaw: 0, mitigatedRaw: 0, activeSignals: 0, mitigatedSignals: 0, topWeight: 0 },
    botnet: { activeRaw: 0, mitigatedRaw: 0, activeSignals: 0, mitigatedSignals: 0, topWeight: 0 },
    unauthorizedAccess: {
      activeRaw: 0,
      mitigatedRaw: 0,
      activeSignals: 0,
      mitigatedSignals: 0,
      topWeight: 0,
    },
    dnsAnomalies: {
      activeRaw: 0,
      mitigatedRaw: 0,
      activeSignals: 0,
      mitigatedSignals: 0,
      topWeight: 0,
    },
    bruteForce: {
      activeRaw: 0,
      mitigatedRaw: 0,
      activeSignals: 0,
      mitigatedSignals: 0,
      topWeight: 0,
    },
  };

  const recordSignal = (
    axis: ThreatAxisId,
    points: number,
    mitigated: boolean,
    evidence?: string,
  ) => {
    if (points <= 0) return;
    const bucket = acc[axis];
    if (mitigated) {
      bucket.mitigatedRaw += points;
      bucket.mitigatedSignals += 1;
    } else {
      bucket.activeRaw += points;
      bucket.activeSignals += 1;
    }
    if (evidence && points >= bucket.topWeight) {
      bucket.topWeight = points;
      bucket.topEvidence = evidence;
    }
  };

  // 1. Correlated Incidents
  for (const inc of scopedIncidents) {
    if (inc.status === 'false_positive') continue;
    const mitigated = inc.status === 'contained' || inc.status === 'resolved';
    const text = `${inc.title} ${inc.summary} ${inc.riskFactors.join(' ')} ${inc.recommendedPolicyId}`.toLowerCase();
    const basePoints = Math.max(20, Math.round(inc.riskScore * 0.72));

    let matchedAny = false;
    if (/(malware|trojan|ransom|virus|exploit|cve|payload|dropper|wazuh|ioc|malicios|malicious)/.test(text)) {
      recordSignal('malware', Math.round(basePoints * 0.75), mitigated, inc.title);
      matchedAny = true;
    }
    if (/(botnet|c2|beacon|outbound|sa[ií]da|2222|quarantine|quarentena|exfil|iot)/.test(text)) {
      recordSignal('botnet', basePoints, mitigated, inc.title);
      matchedAny = true;
    }
    if (/(unauthorized|n[aã]o autorizado|luci|ubus|smb|445|rdp|admin|wan drop|acesso)/.test(text)) {
      recordSignal('unauthorizedAccess', basePoints, mitigated, inc.title);
      matchedAny = true;
    }
    if (/(dns|dga|telemetr|rastreamento|tracker|pihole|adguard|technitium|dom[ií]nio)/.test(text)) {
      recordSignal('dnsAnomalies', basePoints, mitigated, inc.title);
      matchedAny = true;
    }
    if (/(brute|for[cç]a bruta|ssh-bf|dropbear|sshd|bad password|credencia)/.test(text)) {
      recordSignal('bruteForce', basePoints, mitigated, inc.title);
      matchedAny = true;
    }

    if (!matchedAny) {
      recordSignal('malware', Math.round(basePoints * 0.6), mitigated, inc.title);
    }
  }

  // 2. Normalized Events (threat.ioc, ids.alert, zeek.connection, dns.query)
  for (const ev of scopedEvents) {
    if (ev.eventType === 'router.access_attempt') continue; // Covered directly in step 3
    const p = ev.payload ?? {};
    const scenario = String(p.scenario ?? p.signature ?? p.reputation ?? '').toLowerCase();
    const text = `${ev.summary} ${scenario}`.toLowerCase();
    const sevPts = SEVERITY_POINTS[ev.severity] ?? 6;
    const isBlocked = p.action === 'blocked' || p.action === 'dropped' || p.blocked === true;

    if (ev.eventType === 'threat.ioc') {
      const conf = typeof p.confidence === 'number' ? Math.max(0.5, Math.min(1, p.confidence)) : 0.8;
      const pts = Math.round(sevPts * 1.15 * conf);
      recordSignal('malware', pts, isBlocked, ev.summary);
      if (/(ssh-bf|brute|auth)/.test(text)) {
        recordSignal('bruteForce', Math.round(pts * 0.7), isBlocked, ev.summary);
      }
      if (/(bot|c2|scan|tor|beacon)/.test(text)) {
        recordSignal('botnet', Math.round(pts * 0.7), isBlocked, ev.summary);
      }
      continue;
    }

    if (ev.eventType === 'ids.alert') {
      if (/(malware|trojan|ransom|exploit|cve|shellcode)/.test(text)) {
        recordSignal('malware', sevPts, isBlocked, ev.summary);
      }
      if (/(outbound|ssh|2222|c2|bot|beacon|scan|exfil)/.test(text)) {
        recordSignal('botnet', sevPts, isBlocked, ev.summary);
      }
      if (/(smb|445|rdp|admin|login|unauthorized|enumera)/.test(text)) {
        recordSignal('unauthorizedAccess', sevPts, isBlocked, ev.summary);
      }
      if (/(brute|password|credential|ssh-bf)/.test(text)) {
        recordSignal('bruteForce', sevPts, isBlocked, ev.summary);
      }
      if (
        !/(malware|trojan|ransom|exploit|cve|shellcode|outbound|ssh|2222|c2|bot|beacon|scan|exfil|smb|445|rdp|admin|login|unauthorized|enumera|brute|password|credential|ssh-bf)/.test(
          text,
        )
      ) {
        recordSignal('malware', sevPts, isBlocked, ev.summary);
      }
      continue;
    }

    if (ev.eventType === 'dns.query' && (ev.severity !== 'info' || isBlocked)) {
      recordSignal('dnsAnomalies', Math.max(8, Math.round(sevPts * 0.7)), isBlocked, ev.summary);
    }
  }

  // 3. Unauthorized Router Access Attempts (SSH, LuCI, ubus, WAN drops)
  for (const attempt of scopedRouterAttempts) {
    if (attempt.status === 'ignored') continue;
    const mitigated = attempt.status === 'blocked';
    const sevBonus =
      attempt.severity === 'critical'
        ? 22
        : attempt.severity === 'high'
          ? 14
          : attempt.severity === 'medium'
            ? 8
            : 4;
    const freqPts = Math.min(48, 16 + Math.round(Math.log2(Math.max(1, attempt.attemptsCount) + 1) * 9));
    const totalPts = freqPts + sevBonus;
    const evidence = `${attempt.srcIp} (${attempt.service.toUpperCase()} · ${attempt.attemptsCount}x)`;

    if (attempt.service === 'ssh') {
      recordSignal('bruteForce', totalPts, mitigated, evidence);
    } else {
      recordSignal('unauthorizedAccess', totalPts, mitigated, evidence);
    }
  }

  // 4. DNS Insights (DGA, suspicious & tracker domains)
  for (const ins of scopedDnsInsights) {
    const blocked = ins.blockedCount;
    const total = Math.max(1, ins.queriesCount);
    const unblocked = Math.max(0, total - blocked);

    if (ins.classification === 'suspicious') {
      const pts = Math.min(45, 18 + Math.round(Math.log10(total + 1) * 12));
      recordSignal(
        'dnsAnomalies',
        pts,
        ins.listStatus === 'blocked' && unblocked === 0,
        `${ins.domain} (${ins.queriesCount}x)`,
      );
    } else if (ins.classification === 'tracker' && (blocked > 0 || total >= 25)) {
      const blockedShare = blocked / total;
      const pts = Math.min(30, 8 + Math.round(Math.log10(total + 1) * 8));
      recordSignal(
        'dnsAnomalies',
        Math.round(pts * (blockedShare > 0.5 ? 0.65 : 1)),
        blockedShare >= 0.7 || ins.listStatus === 'blocked',
        `${ins.domain} (${blocked}/${total} blk)`,
      );
    }
  }

  // 5. High-risk or isolated IoT devices contribute to Botnet/IoT exposure
  for (const dev of scopedDevices) {
    if (dev.status === 'isolated') {
      recordSignal('botnet', 20, true, `${dev.hostname} (${dev.ip})`);
    } else if (dev.deviceType === 'iot' && dev.riskScore >= 60) {
      recordSignal('botnet', Math.round(dev.riskScore * 0.35), false, `${dev.hostname} · Risk ${dev.riskScore}`);
    }
  }

  const orderedIds: ThreatAxisId[] = [
    'malware',
    'botnet',
    'unauthorizedAccess',
    'dnsAnomalies',
    'bruteForce',
  ];

  const axes: ThreatLandscapeAxis[] = orderedIds.map((id) => {
    const item = acc[id];
    const score = clampScore(item.activeRaw);
    const mitigatedScore = clampScore(item.mitigatedRaw);
    return {
      id,
      score,
      mitigatedScore,
      signalCount: item.activeSignals + item.mitigatedSignals,
      activeSignals: item.activeSignals,
      mitigatedSignals: item.mitigatedSignals,
      level: resolveThreatLevel(score),
      topEvidence: item.topEvidence,
    };
  });

  const totalSignals = axes.reduce((sum, a) => sum + a.signalCount, 0);
  const hasSignals = totalSignals > 0;
  const maxScore = axes.reduce((max, a) => Math.max(max, a.score), 0);
  const avgScore = axes.reduce((sum, a) => sum + a.score, 0) / axes.length;
  // Composite weighted towards highest active threat vector
  const overallScore = hasSignals ? clampScore(maxScore * 0.55 + avgScore * 0.45) : 0;
  const sortedByScore = [...axes].sort((a, b) => b.score - a.score);
  const highestAxisId = sortedByScore[0] && sortedByScore[0].score > 0 ? sortedByScore[0].id : null;

  return {
    axes,
    overallScore,
    highestAxisId,
    hasSignals,
    totalSignals,
  };
}
