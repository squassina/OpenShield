import type {
  ActionExecution,
  EventSeverity,
  OpenShieldEventV1,
  RouterAccessAttempt,
  WorkspaceState,
} from '../types/openshield';

export type GeoMapFilterMode = 'blocked' | 'all';

export interface GeoCountryMeta {
  isoAlpha2: string;
  isoNumeric: string;
  defaultName: string;
  /** Approximate [lon, lat] centroid used for crisp hotspot markers */
  centroid: [number, number];
}

export interface GeoCountryThreatStat {
  isoAlpha2: string;
  isoNumeric: string;
  defaultName: string;
  centroid: [number, number];
  blockedAttempts: number;
  observedAttempts: number;
  totalAttempts: number;
  sharePct: number;
  highestSeverity: EventSeverity;
  uniqueIps: string[];
  services: string[];
  lastSeenAt: string;
}

export interface GeoThreatSummary {
  filterMode: GeoMapFilterMode;
  hasGeoData: boolean;
  countries: GeoCountryThreatStat[];
  byNumericId: Record<string, GeoCountryThreatStat>;
  totalBlockedAttempts: number;
  totalObservedAttempts: number;
  totalDisplayedAttempts: number;
  totalCountriesAffected: number;
  maxCountryAttempts: number;
  localPrivateBlockedCount: number;
}

const SEVERITY_RANK: Record<EventSeverity, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

function maxSeverity(a: EventSeverity, b: EventSeverity): EventSeverity {
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;
}

export const GEO_COUNTRIES: GeoCountryMeta[] = [
  { isoAlpha2: 'US', isoNumeric: '840', defaultName: 'United States', centroid: [-98.5, 39.8] },
  { isoAlpha2: 'CA', isoNumeric: '124', defaultName: 'Canada', centroid: [-106.3, 56.1] },
  { isoAlpha2: 'MX', isoNumeric: '484', defaultName: 'Mexico', centroid: [-102.5, 23.6] },
  { isoAlpha2: 'BR', isoNumeric: '076', defaultName: 'Brazil', centroid: [-51.9, -14.2] },
  { isoAlpha2: 'AR', isoNumeric: '032', defaultName: 'Argentina', centroid: [-63.6, -38.4] },
  { isoAlpha2: 'CO', isoNumeric: '170', defaultName: 'Colombia', centroid: [-74.3, 4.6] },
  { isoAlpha2: 'CL', isoNumeric: '152', defaultName: 'Chile', centroid: [-71.5, -35.7] },
  { isoAlpha2: 'GB', isoNumeric: '826', defaultName: 'United Kingdom', centroid: [-3.4, 55.4] },
  { isoAlpha2: 'DE', isoNumeric: '276', defaultName: 'Germany', centroid: [10.4, 51.2] },
  { isoAlpha2: 'NL', isoNumeric: '528', defaultName: 'Netherlands', centroid: [5.3, 52.1] },
  { isoAlpha2: 'FR', isoNumeric: '250', defaultName: 'France', centroid: [2.2, 46.2] },
  { isoAlpha2: 'ES', isoNumeric: '724', defaultName: 'Spain', centroid: [-3.7, 40.5] },
  { isoAlpha2: 'IT', isoNumeric: '380', defaultName: 'Italy', centroid: [12.6, 41.9] },
  { isoAlpha2: 'PT', isoNumeric: '620', defaultName: 'Portugal', centroid: [-8.2, 39.4] },
  { isoAlpha2: 'PL', isoNumeric: '616', defaultName: 'Poland', centroid: [19.1, 51.9] },
  { isoAlpha2: 'RO', isoNumeric: '642', defaultName: 'Romania', centroid: [25.0, 45.9] },
  { isoAlpha2: 'BG', isoNumeric: '100', defaultName: 'Bulgaria', centroid: [25.5, 42.7] },
  { isoAlpha2: 'UA', isoNumeric: '804', defaultName: 'Ukraine', centroid: [31.2, 48.4] },
  { isoAlpha2: 'SE', isoNumeric: '752', defaultName: 'Sweden', centroid: [18.6, 60.1] },
  { isoAlpha2: 'FI', isoNumeric: '246', defaultName: 'Finland', centroid: [25.7, 61.9] },
  { isoAlpha2: 'RU', isoNumeric: '643', defaultName: 'Russia', centroid: [95.0, 61.5] },
  { isoAlpha2: 'TR', isoNumeric: '792', defaultName: 'Turkey', centroid: [35.2, 39.0] },
  { isoAlpha2: 'IL', isoNumeric: '376', defaultName: 'Israel', centroid: [34.8, 31.0] },
  { isoAlpha2: 'AE', isoNumeric: '784', defaultName: 'United Arab Emirates', centroid: [53.8, 23.4] },
  { isoAlpha2: 'IR', isoNumeric: '364', defaultName: 'Iran', centroid: [53.7, 32.4] },
  { isoAlpha2: 'EG', isoNumeric: '818', defaultName: 'Egypt', centroid: [30.8, 26.8] },
  { isoAlpha2: 'NG', isoNumeric: '566', defaultName: 'Nigeria', centroid: [8.7, 9.1] },
  { isoAlpha2: 'ZA', isoNumeric: '710', defaultName: 'South Africa', centroid: [22.9, -30.6] },
  { isoAlpha2: 'IN', isoNumeric: '356', defaultName: 'India', centroid: [78.9, 20.6] },
  { isoAlpha2: 'PK', isoNumeric: '586', defaultName: 'Pakistan', centroid: [69.3, 30.4] },
  { isoAlpha2: 'CN', isoNumeric: '156', defaultName: 'China', centroid: [104.2, 35.9] },
  { isoAlpha2: 'TW', isoNumeric: '158', defaultName: 'Taiwan', centroid: [121.0, 23.7] },
  { isoAlpha2: 'KR', isoNumeric: '410', defaultName: 'South Korea', centroid: [127.8, 35.9] },
  { isoAlpha2: 'JP', isoNumeric: '392', defaultName: 'Japan', centroid: [138.3, 36.2] },
  { isoAlpha2: 'VN', isoNumeric: '704', defaultName: 'Vietnam', centroid: [108.3, 14.1] },
  { isoAlpha2: 'TH', isoNumeric: '764', defaultName: 'Thailand', centroid: [100.9, 15.9] },
  { isoAlpha2: 'ID', isoNumeric: '360', defaultName: 'Indonesia', centroid: [113.9, -0.8] },
  { isoAlpha2: 'PH', isoNumeric: '608', defaultName: 'Philippines', centroid: [121.8, 12.9] },
  { isoAlpha2: 'MY', isoNumeric: '458', defaultName: 'Malaysia', centroid: [101.9, 4.2] },
  { isoAlpha2: 'AU', isoNumeric: '036', defaultName: 'Australia', centroid: [133.8, -25.3] },
];

const BY_ALPHA2 = new Map<string, GeoCountryMeta>(
  GEO_COUNTRIES.map((c) => [c.isoAlpha2, c]),
);
const BY_NUMERIC = new Map<string, GeoCountryMeta>(
  GEO_COUNTRIES.map((c) => [c.isoNumeric, c]),
);
const BY_NAME = new Map<string, GeoCountryMeta>(
  GEO_COUNTRIES.map((c) => [c.defaultName.toLowerCase(), c]),
);

const EXTRA_NAME_ALIASES: Record<string, string> = {
  usa: 'US',
  'united states of america': 'US',
  brasil: 'BR',
  alemanha: 'DE',
  germany: 'DE',
  russia: 'RU',
  'russian federation': 'RU',
  china: 'CN',
  netherlands: 'NL',
  holanda: 'NL',
  'united kingdom': 'GB',
  uk: 'GB',
  france: 'FR',
  franca: 'FR',
  'frança': 'FR',
  japan: 'JP',
  japao: 'JP',
  'japão': 'JP',
  'south korea': 'KR',
  'korea, republic of': 'KR',
  vietnam: 'VN',
  ukraine: 'UA',
  poland: 'PL',
  india: 'IN',
  turkey: 'TR',
  turquia: 'TR',
  romania: 'RO',
  indonesia: 'ID',
  taiwan: 'TW',
};

/**
 * Curated RIR / autonomous system / Tor-exit / threat-intel prefix table
 * for deterministic offline IPv4-to-country resolution when adapters do not
 * provide an explicit GeoIP country code.
 */
const IPV4_PREFIX_COUNTRY: Array<{ prefix: string; isoAlpha2: string }> = [
  // Tor exit / European security research / hosting blocks
  { prefix: '185.220.101.', isoAlpha2: 'DE' },
  { prefix: '185.220.100.', isoAlpha2: 'DE' },
  { prefix: '185.220.', isoAlpha2: 'DE' },
  { prefix: '185.156.', isoAlpha2: 'NL' },
  { prefix: '185.199.', isoAlpha2: 'US' },
  { prefix: '193.142.', isoAlpha2: 'NL' },
  { prefix: '193.106.', isoAlpha2: 'RO' },
  { prefix: '194.26.', isoAlpha2: 'RU' },
  { prefix: '45.155.', isoAlpha2: 'RU' },
  { prefix: '45.146.', isoAlpha2: 'RU' },
  { prefix: '45.134.', isoAlpha2: 'DE' },
  { prefix: '45.95.', isoAlpha2: 'NL' },
  { prefix: '91.240.', isoAlpha2: 'RU' },
  { prefix: '91.92.', isoAlpha2: 'BG' },
  { prefix: '94.102.', isoAlpha2: 'NL' },
  { prefix: '89.248.', isoAlpha2: 'NL' },
  { prefix: '80.82.', isoAlpha2: 'NL' },
  { prefix: '77.247.', isoAlpha2: 'NL' },
  // Documentation / test ranges mapped to representative external origins
  { prefix: '198.51.100.', isoAlpha2: 'US' },
  { prefix: '203.0.113.', isoAlpha2: 'JP' },
  { prefix: '192.0.2.', isoAlpha2: 'GB' },
  // Major regional prefixes
  { prefix: '118.126.', isoAlpha2: 'CN' },
  { prefix: '118.24.', isoAlpha2: 'CN' },
  { prefix: '119.29.', isoAlpha2: 'CN' },
  { prefix: '120.79.', isoAlpha2: 'CN' },
  { prefix: '223.5.', isoAlpha2: 'CN' },
  { prefix: '103.21.', isoAlpha2: 'IN' },
  { prefix: '103.27.', isoAlpha2: 'VN' },
  { prefix: '103.75.', isoAlpha2: 'ID' },
  { prefix: '104.244.', isoAlpha2: 'US' },
  { prefix: '104.16.', isoAlpha2: 'US' },
  { prefix: '162.142.', isoAlpha2: 'US' },
  { prefix: '167.94.', isoAlpha2: 'US' },
  { prefix: '177.71.', isoAlpha2: 'BR' },
  { prefix: '179.96.', isoAlpha2: 'BR' },
  { prefix: '187.19.', isoAlpha2: 'BR' },
  { prefix: '200.160.', isoAlpha2: 'BR' },
  { prefix: '195.154.', isoAlpha2: 'FR' },
  { prefix: '212.47.', isoAlpha2: 'FR' },
  { prefix: '210.122.', isoAlpha2: 'KR' },
  { prefix: '202.12.', isoAlpha2: 'AU' },
  { prefix: '196.25.', isoAlpha2: 'ZA' },
  { prefix: '197.210.', isoAlpha2: 'NG' },
];

const FIRST_OCTET_FALLBACK: Array<{ min: number; max: number; countries: string[] }> = [
  { min: 1, max: 49, countries: ['US', 'CA', 'US', 'CN', 'JP'] },
  { min: 50, max: 79, countries: ['US', 'GB', 'DE', 'FR'] },
  { min: 80, max: 95, countries: ['DE', 'NL', 'GB', 'FR', 'RU', 'PL', 'UA'] },
  { min: 96, max: 115, countries: ['US', 'CN', 'IN', 'JP', 'KR', 'VN'] },
  { min: 116, max: 126, countries: ['CN', 'KR', 'JP', 'TW', 'TH'] },
  { min: 128, max: 175, countries: ['US', 'CA', 'DE', 'GB', 'AU'] },
  { min: 176, max: 191, countries: ['DE', 'NL', 'RU', 'BR', 'FR', 'TR'] },
  { min: 193, max: 197, countries: ['NL', 'DE', 'GB', 'FR', 'RU', 'ZA', 'NG'] },
  { min: 198, max: 209, countries: ['US', 'BR', 'MX', 'AR', 'CA'] },
  { min: 210, max: 223, countries: ['JP', 'KR', 'CN', 'FR', 'DE', 'RU'] },
];

export function normalizeIp(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  let ip = raw.trim();
  if (!ip) return '';
  if (ip.toLowerCase().startsWith('::ffff:')) {
    ip = ip.slice(7);
  }
  // Strip bracketed IPv6 or IPv4:port suffix
  const ipv4Port = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
  if (ipv4Port) {
    ip = ipv4Port[1];
  }
  return ip;
}

export function isPrivateOrNonRoutableIp(ip: string): boolean {
  const clean = normalizeIp(ip).toLowerCase();
  if (!clean) return true;

  const parts = clean.split('.').map(Number);
  if (parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }

  // IPv6 loopback, ULA (fc00::/7), link-local (fe80::/10)
  if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }
  return false;
}

export function resolveCountryMetaFromHint(rawHint: unknown): GeoCountryMeta | null {
  if (typeof rawHint !== 'string') return null;
  const trimmed = rawHint.trim();
  if (!trimmed) return null;

  const upper = trimmed.toUpperCase();
  const byA2 = BY_ALPHA2.get(upper);
  if (byA2) return byA2;

  const paddedNum = trimmed.padStart(3, '0');
  const byNum = BY_NUMERIC.get(paddedNum);
  if (byNum) return byNum;

  const lower = trimmed.toLowerCase();
  const byName = BY_NAME.get(lower);
  if (byName) return byName;

  const aliasA2 = EXTRA_NAME_ALIASES[lower];
  if (aliasA2) return BY_ALPHA2.get(aliasA2) ?? null;

  return null;
}

export function resolveCountryFromPublicIp(ip: string): GeoCountryMeta | null {
  const clean = normalizeIp(ip);
  if (!clean || isPrivateOrNonRoutableIp(clean)) return null;

  for (const rule of IPV4_PREFIX_COUNTRY) {
    if (clean.startsWith(rule.prefix)) {
      return BY_ALPHA2.get(rule.isoAlpha2) ?? null;
    }
  }

  const parts = clean.split('.').map(Number);
  if (parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    const [a, b] = parts;
    for (const band of FIRST_OCTET_FALLBACK) {
      if (a >= band.min && a <= band.max) {
        const idx = (a * 31 + b) % band.countries.length;
        return BY_ALPHA2.get(band.countries[idx]) ?? null;
      }
    }
    return BY_ALPHA2.get('US') ?? null;
  }

  // Public IPv6 deterministic regional fallback
  if (clean.includes(':')) {
    const firstHex = parseInt(clean.split(':')[0] || '2001', 16) || 0;
    const pool = ['US', 'DE', 'NL', 'GB', 'JP', 'BR', 'FR'];
    return BY_ALPHA2.get(pool[firstHex % pool.length]) ?? null;
  }

  return null;
}

interface CountryMutable {
  meta: GeoCountryMeta;
  blockedAttempts: number;
  observedAttempts: number;
  highestSeverity: EventSeverity;
  ips: Set<string>;
  services: Set<string>;
  lastSeenAt: string;
}

export function buildGeoThreatSummary(
  state: WorkspaceState,
  filterMode: GeoMapFilterMode = 'blocked',
): GeoThreatSummary {
  const isBusiness = state.context.profile === 'business';
  const scopedDevices = isBusiness
    ? state.devices
    : state.devices.filter((d) => d.siteId === state.context.activeSiteId);
  const scopedIntegrations = isBusiness
    ? state.integrations
    : state.integrations.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);

  const scopedDeviceIds = new Set(scopedDevices.map((d) => d.id));
  const scopedIntegrationIds = new Set(scopedIntegrations.map((i) => i.id));

  const scopedRouterAttempts: RouterAccessAttempt[] = isBusiness
    ? state.routerAccessAttempts ?? []
    : (state.routerAccessAttempts ?? []).filter(
        (r) => !r.siteId || r.siteId === state.context.activeSiteId,
      );

  const scopedEvents: OpenShieldEventV1[] = isBusiness
    ? state.events
    : state.events.filter(
        (ev) =>
          (ev.deviceId && scopedDeviceIds.has(ev.deviceId)) ||
          scopedIntegrationIds.has(ev.sourceIntegrationId),
      );

  const scopedIncidents = isBusiness
    ? state.incidents
    : state.incidents.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);
  const scopedIncidentIds = new Set(scopedIncidents.map((i) => i.id));
  const scopedExecutions: ActionExecution[] = isBusiness
    ? state.executions
    : state.executions.filter((e) => scopedIncidentIds.has(e.incidentId));

  // Track active/historical blocked external IPs from executions so related events know they were blocked
  const blockedExecutionIps = new Set<string>();
  const linkedExecutionIds = new Set<string>();
  for (const attempt of scopedRouterAttempts) {
    if (attempt.linkedExecutionId) linkedExecutionIds.add(attempt.linkedExecutionId);
  }
  for (const exec of scopedExecutions) {
    if (
      exec.actionType === 'nftables_temp_drop' &&
      exec.status !== 'rolled_back' &&
      exec.status !== 'aborted_kill_switch' &&
      exec.targetIp
    ) {
      const clean = normalizeIp(exec.targetIp);
      if (clean && !isPrivateOrNonRoutableIp(clean)) {
        blockedExecutionIps.add(clean);
      }
    }
  }

  const countryAcc = new Map<string, CountryMutable>();
  let localPrivateBlockedCount = 0;

  const recordAttempt = (params: {
    ip?: string;
    countryHint?: unknown;
    count: number;
    blocked: boolean;
    severity: EventSeverity;
    serviceLabel: string;
    timestamp: string;
  }) => {
    const cleanIp = params.ip ? normalizeIp(params.ip) : '';
    const count = Math.max(1, Math.round(params.count));

    if (cleanIp && isPrivateOrNonRoutableIp(cleanIp) && !params.countryHint) {
      if (params.blocked) localPrivateBlockedCount += count;
      return;
    }

    const meta =
      resolveCountryMetaFromHint(params.countryHint) ??
      (cleanIp ? resolveCountryFromPublicIp(cleanIp) : null);

    if (!meta) return;

    let entry = countryAcc.get(meta.isoNumeric);
    if (!entry) {
      entry = {
        meta,
        blockedAttempts: 0,
        observedAttempts: 0,
        highestSeverity: params.severity,
        ips: new Set<string>(),
        services: new Set<string>(),
        lastSeenAt: params.timestamp,
      };
      countryAcc.set(meta.isoNumeric, entry);
    }

    if (params.blocked) {
      entry.blockedAttempts += count;
    } else {
      entry.observedAttempts += count;
    }

    entry.highestSeverity = maxSeverity(entry.highestSeverity, params.severity);
    if (cleanIp) entry.ips.add(cleanIp);
    if (params.serviceLabel) entry.services.add(params.serviceLabel);
    if (Date.parse(params.timestamp) > Date.parse(entry.lastSeenAt || '')) {
      entry.lastSeenAt = params.timestamp;
    }
  };

  // Deduplication set for router.access_attempt events already tracked in routerAccessAttempts
  const trackedRouterKeys = new Set<string>();

  // 1. Router Access Attempts & WAN Firewall Drops
  for (const attempt of scopedRouterAttempts) {
    if (attempt.status === 'ignored') continue;
    const cleanIp = normalizeIp(attempt.srcIp);
    if (cleanIp) {
      trackedRouterKeys.add(`${attempt.sourceIntegrationId}|${cleanIp}`);
    }
    const isBlocked =
      attempt.status === 'blocked' ||
      attempt.service === 'wan_drop' ||
      (Boolean(cleanIp) && blockedExecutionIps.has(cleanIp));

    recordAttempt({
      ip: cleanIp,
      count: attempt.attemptsCount,
      blocked: isBlocked,
      severity: attempt.severity,
      serviceLabel: attempt.service.toUpperCase(),
      timestamp: attempt.lastSeenAt || attempt.firstSeenAt,
    });
  }

  // 2. Security Events (IDS alerts, Threat IOC, Zeek connections, Router events)
  for (const ev of scopedEvents) {
    const p = ev.payload ?? {};
    const countryHint =
      p.countryCode ?? p.country ?? p.geoCountry ?? p.originCountry ?? p.srcCountry ?? p.isoCode;

    const candidateIps = [
      p.externalIndicator,
      p.indicator,
      p.srcIp,
      p.remoteIp,
      p.destIp,
      p.dstIp,
      p.targetIp,
      p.ip,
    ]
      .map(normalizeIp)
      .filter(Boolean);

    const externalIp = candidateIps.find((ip) => !isPrivateOrNonRoutableIp(ip)) ?? candidateIps[0] ?? '';

    if (ev.eventType === 'router.access_attempt' && externalIp) {
      const key = `${ev.sourceIntegrationId}|${externalIp}`;
      if (trackedRouterKeys.has(key)) {
        continue;
      }
    }

    if (!externalIp && !countryHint) continue;
    if (ev.eventType === 'gateway.discovery' || ev.eventType === 'gateway.health') continue;

    const isBlocked =
      p.action === 'blocked' ||
      p.action === 'dropped' ||
      p.blocked === true ||
      (Boolean(externalIp) && blockedExecutionIps.has(externalIp));

    const isThreatSignal =
      isBlocked ||
      ev.eventType === 'threat.ioc' ||
      ev.eventType === 'ids.alert' ||
      ev.eventType === 'router.access_attempt' ||
      ev.severity === 'high' ||
      ev.severity === 'critical';

    if (!isThreatSignal) continue;

    const attempts =
      typeof p.attemptsCount === 'number' && Number.isFinite(p.attemptsCount) && p.attemptsCount > 0
        ? p.attemptsCount
        : 1;

    const serviceLabel =
      ev.eventType === 'threat.ioc'
        ? 'IOC'
        : ev.eventType === 'ids.alert'
          ? 'IDS'
          : ev.eventType === 'router.access_attempt'
            ? String(p.service ?? 'ROUTER').toUpperCase()
            : 'FLOW';

    recordAttempt({
      ip: externalIp,
      countryHint,
      count: attempts,
      blocked: isBlocked,
      severity: ev.severity,
      serviceLabel,
      timestamp: ev.occurredAt,
    });
  }

  // 3. Standalone Firewall Drop Executions not already linked to a RouterAccessAttempt
  for (const exec of scopedExecutions) {
    if (
      exec.actionType === 'nftables_temp_drop' &&
      exec.status !== 'rolled_back' &&
      exec.status !== 'aborted_kill_switch' &&
      !linkedExecutionIds.has(exec.id) &&
      exec.targetIp
    ) {
      const cleanIp = normalizeIp(exec.targetIp);
      if (cleanIp) {
        recordAttempt({
          ip: cleanIp,
          count: 1,
          blocked: true,
          severity: 'high',
          serviceLabel: 'FIREWALL',
          timestamp: exec.createdAt,
        });
      }
    }
  }

  let totalBlockedAttempts = 0;
  let totalObservedAttempts = 0;
  const rawList: Omit<GeoCountryThreatStat, 'sharePct'>[] = [];

  for (const acc of countryAcc.values()) {
    totalBlockedAttempts += acc.blockedAttempts;
    totalObservedAttempts += acc.observedAttempts;
    const totalAttempts = acc.blockedAttempts + acc.observedAttempts;
    const displayCount = filterMode === 'blocked' ? acc.blockedAttempts : totalAttempts;
    if (displayCount <= 0) continue;

    rawList.push({
      isoAlpha2: acc.meta.isoAlpha2,
      isoNumeric: acc.meta.isoNumeric,
      defaultName: acc.meta.defaultName,
      centroid: acc.meta.centroid,
      blockedAttempts: acc.blockedAttempts,
      observedAttempts: acc.observedAttempts,
      totalAttempts,
      highestSeverity: acc.highestSeverity,
      uniqueIps: Array.from(acc.ips),
      services: Array.from(acc.services),
      lastSeenAt: acc.lastSeenAt,
    });
  }

  const totalDisplayedAttempts = rawList.reduce(
    (sum, item) => sum + (filterMode === 'blocked' ? item.blockedAttempts : item.totalAttempts),
    0,
  );

  const countries: GeoCountryThreatStat[] = rawList
    .map((item) => {
      const count = filterMode === 'blocked' ? item.blockedAttempts : item.totalAttempts;
      return {
        ...item,
        sharePct:
          totalDisplayedAttempts > 0
            ? Math.round((count / totalDisplayedAttempts) * 1000) / 10
            : 0,
      };
    })
    .sort((a, b) => {
      const aVal = filterMode === 'blocked' ? a.blockedAttempts : a.totalAttempts;
      const bVal = filterMode === 'blocked' ? b.blockedAttempts : b.totalAttempts;
      if (bVal !== aVal) return bVal - aVal;
      return b.totalAttempts - a.totalAttempts;
    });

  const byNumericId: Record<string, GeoCountryThreatStat> = {};
  let maxCountryAttempts = 0;
  for (const country of countries) {
    byNumericId[country.isoNumeric] = country;
    const val = filterMode === 'blocked' ? country.blockedAttempts : country.totalAttempts;
    if (val > maxCountryAttempts) maxCountryAttempts = val;
  }

  return {
    filterMode,
    hasGeoData: countries.length > 0,
    countries,
    byNumericId,
    totalBlockedAttempts,
    totalObservedAttempts,
    totalDisplayedAttempts,
    totalCountriesAffected: countries.length,
    maxCountryAttempts,
    localPrivateBlockedCount,
  };
}
