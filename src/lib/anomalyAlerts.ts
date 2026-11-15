import type {
  EventSeverity,
  Incident,
  NetworkDevice,
  OpenShieldEventV1,
  RouterAccessAttempt,
  WorkspaceState,
} from '../types/openshield';
import { normalizeIp } from './geoThreatAnalytics';

export type AnomalyAlertCategory = 'ids' | 'ioc' | 'dns' | 'router' | 'flow';

export interface NetworkAnomalyAlert {
  id: string;
  timestamp: string;
  severity: EventSeverity;
  category: AnomalyAlertCategory;
  vectorLabel: string;
  deviceLabel: string;
  deviceIp?: string;
  sourceIp: string;
  sourceIntegrationId: string;
  summary: string;
  linkedIncidentId: string | null;
}

const SEVERITY_PRIORITY: Record<EventSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function findMatchingDevice(
  devices: NetworkDevice[],
  deviceId: string | undefined,
  candidateIps: string[],
): NetworkDevice | undefined {
  if (deviceId) {
    const byId = devices.find((d) => d.id === deviceId);
    if (byId) return byId;
  }
  for (const ip of candidateIps) {
    const clean = normalizeIp(ip);
    if (!clean) continue;
    const byIp = devices.find((d) => normalizeIp(d.ip) === clean);
    if (byIp) return byIp;
  }
  return undefined;
}

function findLinkedIncident(
  incidents: Incident[],
  eventId?: string,
  explicitIncidentId?: string,
  deviceId?: string,
  sourceIp?: string,
): Incident | undefined {
  if (explicitIncidentId) {
    const exact = incidents.find((i) => i.id === explicitIncidentId);
    if (exact) return exact;
  }
  if (eventId) {
    const byEvent = incidents.find((i) => i.eventIds.includes(eventId));
    if (byEvent) return byEvent;
  }
  if (deviceId) {
    const byDevice = incidents.find((i) => i.deviceId === deviceId);
    if (byDevice) return byDevice;
  }
  if (sourceIp && sourceIp !== '—') {
    const byIp = incidents.find(
      (i) =>
        i.deviceHostname.includes(sourceIp) ||
        i.title.includes(sourceIp) ||
        i.riskFactors.some((r) => r.includes(sourceIp)),
    );
    if (byIp) return byIp;
  }
  return undefined;
}

export function buildNetworkAnomalyAlerts(state: WorkspaceState): NetworkAnomalyAlert[] {
  const isBusiness = state.context.profile === 'business';
  const scopedDevices = isBusiness
    ? state.devices
    : state.devices.filter((d) => d.siteId === state.context.activeSiteId);
  const scopedIntegrations = isBusiness
    ? state.integrations
    : state.integrations.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);
  const scopedIncidents = isBusiness
    ? state.incidents
    : state.incidents.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);

  const scopedDeviceIds = new Set(scopedDevices.map((d) => d.id));
  const scopedIntegrationIds = new Set(scopedIntegrations.map((i) => i.id));
  const integrationById = new Map(scopedIntegrations.map((i) => [i.id, i]));

  const scopedEvents: OpenShieldEventV1[] = isBusiness
    ? state.events
    : state.events.filter(
        (ev) =>
          (ev.deviceId && scopedDeviceIds.has(ev.deviceId)) ||
          scopedIntegrationIds.has(ev.sourceIntegrationId),
      );

  const scopedRouterAttempts: RouterAccessAttempt[] = isBusiness
    ? state.routerAccessAttempts ?? []
    : (state.routerAccessAttempts ?? []).filter(
        (r) => !r.siteId || r.siteId === state.context.activeSiteId,
      );

  const alerts: NetworkAnomalyAlert[] = [];
  const seenRouterKeys = new Set<string>();

  // 1. Router access attempts & WAN anomalies
  for (const attempt of scopedRouterAttempts) {
    if (attempt.status === 'ignored') continue;
    const cleanSrcIp = normalizeIp(attempt.srcIp) || '—';
    seenRouterKeys.add(`${attempt.sourceIntegrationId}|${cleanSrcIp}`);

    const gatewayIntegration = integrationById.get(attempt.sourceIntegrationId);
    const matchingDevice = findMatchingDevice(scopedDevices, undefined, [cleanSrcIp]);
    const linkedIncident = findLinkedIncident(
      scopedIncidents,
      undefined,
      attempt.linkedIncidentId,
      matchingDevice?.id,
      cleanSrcIp,
    );

    const deviceLabel =
      matchingDevice?.hostname ??
      gatewayIntegration?.name ??
      linkedIncident?.deviceHostname ??
      attempt.sourceIntegrationId;

    alerts.push({
      id: `alert-rtr-${attempt.id}`,
      timestamp: attempt.lastSeenAt || attempt.firstSeenAt,
      severity: attempt.severity,
      category: 'router',
      vectorLabel: attempt.service.toUpperCase(),
      deviceLabel,
      deviceIp: matchingDevice?.ip,
      sourceIp: cleanSrcIp,
      sourceIntegrationId: attempt.sourceIntegrationId,
      summary: attempt.lastMessage,
      linkedIncidentId: linkedIncident?.id ?? null,
    });
  }

  // 2. Normalized security anomaly events
  for (const ev of scopedEvents) {
    if (ev.eventType === 'gateway.discovery' || ev.eventType === 'gateway.health') continue;

    const p = ev.payload ?? {};
    const isAnomalousEvent =
      ev.eventType === 'ids.alert' ||
      ev.eventType === 'threat.ioc' ||
      ev.eventType === 'router.access_attempt' ||
      ev.severity !== 'info' ||
      p.action === 'blocked' ||
      p.blocked === true;

    if (!isAnomalousEvent) continue;

    const candidateIps = [
      p.srcIp,
      p.externalIndicator,
      p.indicator,
      p.remoteIp,
      p.targetIp,
      p.ip,
      p.destIp,
      p.dstIp,
    ]
      .map(normalizeIp)
      .filter(Boolean);

    const matchedDevice = findMatchingDevice(scopedDevices, ev.deviceId, candidateIps);
    const sourceIp = candidateIps[0] ?? normalizeIp(matchedDevice?.ip) ?? '—';

    if (
      ev.eventType === 'router.access_attempt' &&
      seenRouterKeys.has(`${ev.sourceIntegrationId}|${sourceIp}`)
    ) {
      continue;
    }

    const linkedIncident = findLinkedIncident(
      scopedIncidents,
      ev.eventId,
      undefined,
      matchedDevice?.id ?? ev.deviceId,
      sourceIp,
    );
    const integration = integrationById.get(ev.sourceIntegrationId);
    const deviceLabel =
      matchedDevice?.hostname ??
      linkedIncident?.deviceHostname ??
      integration?.name ??
      ev.sourceIntegrationId;

    const category: AnomalyAlertCategory =
      ev.eventType === 'ids.alert'
        ? 'ids'
        : ev.eventType === 'threat.ioc'
          ? 'ioc'
          : ev.eventType === 'dns.query'
            ? 'dns'
            : ev.eventType === 'router.access_attempt'
              ? 'router'
              : 'flow';

    alerts.push({
      id: `alert-ev-${ev.eventId}`,
      timestamp: ev.occurredAt,
      severity: ev.severity,
      category,
      vectorLabel: ev.eventType,
      deviceLabel,
      deviceIp: matchedDevice?.ip,
      sourceIp,
      sourceIntegrationId: ev.sourceIntegrationId,
      summary: ev.summary,
      linkedIncidentId: linkedIncident?.id ?? null,
    });
  }

  return alerts.sort((a, b) => {
    const timeDiff = Date.parse(b.timestamp) - Date.parse(a.timestamp);
    if (Number.isFinite(timeDiff) && timeDiff !== 0) return timeDiff;
    return SEVERITY_PRIORITY[b.severity] - SEVERITY_PRIORITY[a.severity];
  });
}
