import type {
  ActionExecution,
  AuditEntry,
  EventSeverity,
  Incident,
  NetworkDevice,
  OpenShieldEventV1,
  RouterAccessAttempt,
  WorkspaceState,
} from '../types/openshield';
import { normalizeIp } from './geoThreatAnalytics';

export type TimelineStatus = 'blocked' | 'alert' | 'verified' | 'warning' | 'info';
export type TimelineSortOrder = 'desc' | 'asc';

export interface SecurityTimelineItem {
  id: string;
  timestamp: string;
  status: TimelineStatus;
  severity: EventSeverity;
  sourceLabel: string;
  eventTypeLabel: string;
  targetLabel?: string;
  summary: string;
  linkedIncidentId: string | null;
}

const AUDIT_HIGHLIGHT_TYPES = new Set<AuditEntry['eventType']>([
  'kill_switch.triggered',
  'kill_switch.reset',
  'authorization.denied',
  'firewall.reconciled',
  'action.rolled_back',
  'action.expired',
]);

function resolveDeviceName(
  devices: NetworkDevice[],
  deviceId?: string,
  candidateIp?: string,
): string | undefined {
  if (deviceId) {
    const byId = devices.find((d) => d.id === deviceId);
    if (byId) return byId.hostname;
  }
  if (candidateIp) {
    const clean = normalizeIp(candidateIp);
    if (clean) {
      const byIp = devices.find((d) => normalizeIp(d.ip) === clean);
      if (byIp) return byIp.hostname;
    }
  }
  return undefined;
}

function resolveLinkedIncidentId(
  incidents: Incident[],
  eventId?: string,
  explicitId?: string,
  deviceId?: string,
): string | null {
  if (explicitId && incidents.some((i) => i.id === explicitId)) return explicitId;
  if (eventId) {
    const byEv = incidents.find((i) => i.eventIds.includes(eventId));
    if (byEv) return byEv.id;
  }
  if (deviceId) {
    const byDev = incidents.find((i) => i.deviceId === deviceId);
    if (byDev) return byDev.id;
  }
  return null;
}

export function buildSecurityTimeline(
  state: WorkspaceState,
  order: TimelineSortOrder = 'desc',
): SecurityTimelineItem[] {
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
  const scopedIncidentIds = new Set(scopedIncidents.map((i) => i.id));
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

  const scopedExecutions: ActionExecution[] = isBusiness
    ? state.executions
    : state.executions.filter((e) => scopedIncidentIds.has(e.incidentId));

  const items: SecurityTimelineItem[] = [];
  const seenRouterKeys = new Set<string>();

  // 1. Router access attempts & WAN drops
  for (const attempt of scopedRouterAttempts) {
    const cleanIp = normalizeIp(attempt.srcIp);
    if (cleanIp) {
      seenRouterKeys.add(`${attempt.sourceIntegrationId}|${cleanIp}`);
    }
    const integration = integrationById.get(attempt.sourceIntegrationId);
    const status: TimelineStatus =
      attempt.status === 'blocked' || attempt.service === 'wan_drop'
        ? 'blocked'
        : attempt.status === 'ignored'
          ? 'info'
          : attempt.severity === 'critical' || attempt.severity === 'high'
            ? 'alert'
            : 'warning';

    items.push({
      id: `tl-rtr-${attempt.id}`,
      timestamp: attempt.lastSeenAt || attempt.firstSeenAt,
      status,
      severity: attempt.severity,
      sourceLabel: integration?.name ?? attempt.sourceIntegrationId,
      eventTypeLabel: `router.${attempt.service}`,
      targetLabel: cleanIp || undefined,
      summary: attempt.lastMessage,
      linkedIncidentId: resolveLinkedIncidentId(
        scopedIncidents,
        undefined,
        attempt.linkedIncidentId,
      ),
    });
  }

  // 2. Normalized security & telemetry events
  for (const ev of scopedEvents) {
    const p = ev.payload ?? {};
    const candidateIp =
      normalizeIp(p.srcIp) ||
      normalizeIp(p.externalIndicator) ||
      normalizeIp(p.indicator) ||
      normalizeIp(p.ip);

    if (
      ev.eventType === 'router.access_attempt' &&
      candidateIp &&
      seenRouterKeys.has(`${ev.sourceIntegrationId}|${candidateIp}`)
    ) {
      continue;
    }

    const isBlocked =
      p.action === 'blocked' || p.action === 'dropped' || p.blocked === true;

    let status: TimelineStatus = 'info';
    if (isBlocked) {
      status = 'blocked';
    } else if (ev.severity === 'critical' || ev.severity === 'high') {
      status = 'alert';
    } else if (ev.severity === 'medium' || ev.severity === 'low') {
      status = 'warning';
    } else if (ev.eventType === 'gateway.health' || ev.eventType === 'gateway.discovery') {
      status = 'verified';
    }

    const integration = integrationById.get(ev.sourceIntegrationId);
    const deviceName = resolveDeviceName(scopedDevices, ev.deviceId, candidateIp);
    const targetParts = [deviceName, candidateIp].filter(Boolean);

    items.push({
      id: `tl-ev-${ev.eventId}`,
      timestamp: ev.occurredAt,
      status,
      severity: ev.severity,
      sourceLabel: integration?.name ?? ev.sourceIntegrationId,
      eventTypeLabel: ev.eventType,
      targetLabel: targetParts.length > 0 ? targetParts.join(' · ') : undefined,
      summary: ev.summary,
      linkedIncidentId: resolveLinkedIncidentId(
        scopedIncidents,
        ev.eventId,
        undefined,
        ev.deviceId,
      ),
    });
  }

  // 3. Policy & firewall containment executions
  for (const exec of scopedExecutions) {
    const status: TimelineStatus =
      exec.status === 'verified' || exec.status === 'active'
        ? 'verified'
        : exec.status === 'awaiting_approval' || exec.status === 'aborted_kill_switch'
          ? 'warning'
          : exec.status === 'rolled_back' || exec.status === 'expired'
            ? 'info'
            : 'info';

    const severity: EventSeverity =
      exec.status === 'aborted_kill_switch'
        ? 'high'
        : exec.status === 'awaiting_approval'
          ? 'medium'
          : 'info';

    items.push({
      id: `tl-exec-${exec.id}`,
      timestamp: exec.createdAt,
      status,
      severity,
      sourceLabel: exec.executedBy,
      eventTypeLabel: `policy.${exec.actionType}`,
      targetLabel: exec.targetIp
        ? `${exec.targetLabel} · ${normalizeIp(exec.targetIp)}`
        : exec.targetLabel,
      summary: exec.verificationDetail,
      linkedIncidentId: scopedIncidents.some((i) => i.id === exec.incidentId)
        ? exec.incidentId
        : null,
    });
  }

  // 4. High-signal security governance audit events (Kill Switch, RBAC denials, Firewall reconciliation)
  for (const entry of state.auditLog) {
    if (!AUDIT_HIGHLIGHT_TYPES.has(entry.eventType)) continue;
    if (!isBusiness && entry.profile === 'business') continue;

    const status: TimelineStatus =
      entry.outcome === 'denied' || entry.eventType === 'kill_switch.triggered'
        ? 'alert'
        : entry.eventType === 'firewall.reconciled' || entry.eventType === 'kill_switch.reset'
          ? 'verified'
          : 'info';

    const severity: EventSeverity =
      entry.eventType === 'kill_switch.triggered'
        ? 'critical'
        : entry.outcome === 'denied'
          ? 'high'
          : 'info';

    items.push({
      id: `tl-audit-${entry.id}`,
      timestamp: entry.timestamp,
      status,
      severity,
      sourceLabel: entry.actor,
      eventTypeLabel: entry.eventType,
      targetLabel: entry.targetId,
      summary: entry.detail,
      linkedIncidentId: null,
    });
  }

  return items.sort((a, b) => {
    const diff = Date.parse(a.timestamp) - Date.parse(b.timestamp);
    if (!Number.isFinite(diff)) return 0;
    return order === 'asc' ? diff : -diff;
  });
}
