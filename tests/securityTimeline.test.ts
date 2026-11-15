import { describe, expect, it } from 'vitest';
import { buildSecurityTimeline } from '../src/lib/securityTimeline.ts';
import type { WorkspaceState } from '../src/types/openshield.ts';

function createBaseState(): WorkspaceState {
  return {
    context: {
      profile: 'residential',
      simulatedRole: 'admin',
      globalAutonomy: 'L0',
      killSwitchActive: false,
      nodeAvailable: true,
      gatewayForwardingActive: true,
      cloudAiOptIn: false,
      activeSiteId: 'site-home',
      sites: [
        { id: 'site-home', name: 'Casa', profile: 'residential' },
        { id: 'site-office-sp', name: 'Escritório SP', profile: 'business' },
      ],
    },
    integrations: [
      {
        id: 'home-gw',
        name: 'OpenWrt Casa',
        domain: 'gateway',
        kind: 'openwrt-rpcd',
        description: 'Gateway',
        protocolVersion: 'openshield.gateway.v1',
        mode: 'live',
        liveEndpointUrl: 'http://192.168.1.1/ubus',
        timeoutMs: 4000,
        status: 'connected',
        lastHeartbeatAt: '2026-11-15T12:00:00.000Z',
        capabilities: ['discover', 'health_check'],
        outboxQueueCount: 0,
        outboxCapacity: 10000,
        siteId: 'site-home',
      },
      {
        id: 'office-gw',
        name: 'OPNsense SP',
        domain: 'gateway',
        kind: 'opnsense-api',
        description: 'Gateway',
        protocolVersion: 'openshield.gateway.v1',
        mode: 'live',
        liveEndpointUrl: 'https://10.10.0.1/api',
        timeoutMs: 4000,
        status: 'connected',
        lastHeartbeatAt: '2026-11-15T12:00:00.000Z',
        capabilities: ['discover', 'health_check'],
        outboxQueueCount: 0,
        outboxCapacity: 10000,
        siteId: 'site-office-sp',
      },
    ],
    devices: [
      {
        id: 'dev-cam-04',
        hostname: 'cam-garagem-ip04',
        ip: '192.168.10.44',
        mac: 'AA:BB:CC:DD:EE:01',
        vendor: 'CamTech',
        interfaceName: 'iot-vlan',
        segment: 'IoT',
        siteId: 'site-home',
        riskScore: 84,
        status: 'attention',
        lastSeenAt: '2026-11-15T11:55:00.000Z',
        dnsQueries24h: 100,
        blockedQueries24h: 20,
        deviceType: 'iot',
      },
    ],
    events: [],
    dnsInsights: [],
    incidents: [],
    policies: [],
    executions: [],
    auditLog: [],
    metrics: {
      httpRequestsTotal: 10,
      eventsIngestedTotal: 0,
      gatewayConnectionsTotal: 1,
      gatewayHeartbeatsTotal: 1,
      authorizationDeniedTotal: 0,
      outboxPendingTotal: 0,
    },
    routerAccessAttempts: [],
  };
}

describe('buildSecurityTimeline', () => {
  it('orders security events chronologically (desc and asc), maps status icons, and deduplicates router probes', () => {
    const state = createBaseState();

    state.incidents = [
      {
        id: 'inc-1',
        title: 'IoT SSH Anomaly',
        summary: 'Summary',
        severity: 'high',
        status: 'open',
        riskScore: 84,
        riskFactors: [],
        deviceId: 'dev-cam-04',
        deviceHostname: 'cam-garagem-ip04',
        siteId: 'site-home',
        eventIds: ['ev-1'],
        timeline: [],
        recommendedPolicyId: 'pol-1',
        recommendedAction: 'Isolate',
        investigation: {
          provider: 'local-ollama-mock',
          modelVersion: 'v1',
          promptTemplateVersion: 'v1',
          generatedAt: '2026-11-15T12:00:00.000Z',
          confidence: 'alta',
          observedFacts: [],
          inferredHypotheses: [],
          recommendedSteps: [],
          promptInjectionGuardNote: 'ok',
        },
      },
    ];

    state.events = [
      {
        eventId: 'ev-1',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:50:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'ids.alert',
        severity: 'high',
        deviceId: 'dev-cam-04',
        summary: 'Outbound SSH anomaly',
        payload: { srcIp: '192.168.10.44' },
      },
      // Duplicate of rtr-1 below — deduplicated
      {
        eventId: 'ev-rtr-dup',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:55:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'router.access_attempt',
        severity: 'critical',
        summary: 'WAN drop',
        payload: { srcIp: '45.155.205.81' },
      },
      // Office event excluded in residential mode
      {
        eventId: 'ev-office',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:59:00.000Z',
        sourceIntegrationId: 'office-gw',
        eventType: 'gateway.health',
        severity: 'info',
        summary: 'OPNsense healthy',
        payload: {},
      },
    ];

    state.routerAccessAttempts = [
      {
        id: 'rtr-1',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '45.155.205.81',
        service: 'wan_drop',
        attemptsCount: 15,
        firstSeenAt: '2026-11-15T11:54:00.000Z',
        lastSeenAt: '2026-11-15T11:55:00.000Z',
        severity: 'high',
        status: 'blocked',
        lastMessage: 'Blocked WAN probe from 45.155.205.81',
        sampleLines: [],
      },
    ];

    state.executions = [
      {
        id: 'exec-1',
        incidentId: 'inc-1',
        policyId: 'pol-1',
        targetLabel: 'cam-garagem-ip04',
        targetIp: '192.168.10.44',
        actionType: 'isolate_iot_segment',
        autonomyLevel: 'L2',
        status: 'verified',
        ttlSeconds: 900,
        expiresAt: '2026-11-15T12:15:00.000Z',
        executedBy: 'admin',
        verificationDetail: 'IoT segment isolated',
        rollbackAvailable: true,
        createdAt: '2026-11-15T11:58:00.000Z',
      },
    ];

    const desc = buildSecurityTimeline(state, 'desc');
    expect(desc.map((i) => i.id)).toEqual(['tl-exec-exec-1', 'tl-rtr-rtr-1', 'tl-ev-ev-1']);
    expect(desc.map((i) => i.status)).toEqual(['verified', 'blocked', 'alert']);
    expect(desc[2].linkedIncidentId).toBe('inc-1');

    const asc = buildSecurityTimeline(state, 'asc');
    expect(asc.map((i) => i.id)).toEqual(['tl-ev-ev-1', 'tl-rtr-rtr-1', 'tl-exec-exec-1']);

    state.context.profile = 'business';
    const biz = buildSecurityTimeline(state, 'desc');
    expect(biz.map((i) => i.id)).toEqual([
      'tl-ev-ev-office',
      'tl-exec-exec-1',
      'tl-rtr-rtr-1',
      'tl-ev-ev-1',
    ]);
    expect(biz[0].status).toBe('verified');
  });
});
