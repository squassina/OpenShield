import { describe, expect, it } from 'vitest';
import { buildNetworkAnomalyAlerts } from '../src/lib/anomalyAlerts.ts';
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
        description: 'Gateway residencial',
        protocolVersion: 'openshield.gateway.v1',
        mode: 'live',
        liveEndpointUrl: 'http://192.168.1.1/ubus',
        timeoutMs: 4000,
        status: 'connected',
        lastHeartbeatAt: '2026-11-15T12:00:00.000Z',
        capabilities: ['discover', 'health_check', 'execute_action'],
        outboxQueueCount: 0,
        outboxCapacity: 10000,
        siteId: 'site-home',
      },
      {
        id: 'office-gw',
        name: 'OPNsense SP',
        domain: 'gateway',
        kind: 'opnsense-api',
        description: 'Gateway escritório',
        protocolVersion: 'openshield.gateway.v1',
        mode: 'live',
        liveEndpointUrl: 'https://10.10.0.1/api',
        timeoutMs: 4000,
        status: 'connected',
        lastHeartbeatAt: '2026-11-15T12:00:00.000Z',
        capabilities: ['discover', 'health_check', 'execute_action'],
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
        dnsQueries24h: 300,
        blockedQueries24h: 50,
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

describe('buildNetworkAnomalyAlerts', () => {
  it('returns empty array when no anomalous events or access probes exist', () => {
    const state = createBaseState();
    state.events = [
      {
        eventId: 'ev-gw-info',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:50:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'gateway.health',
        severity: 'info',
        summary: 'Healthy',
        payload: {},
      },
    ];
    expect(buildNetworkAnomalyAlerts(state)).toEqual([]);
  });

  it('resolves device, normalized source IP, linked incident, deduplication, and site scoping', () => {
    const state = createBaseState();
    state.incidents = [
      {
        id: 'inc-cam-1',
        title: 'IoT Outbound SSH',
        summary: 'Summary',
        severity: 'high',
        status: 'open',
        riskScore: 84,
        riskFactors: [],
        deviceId: 'dev-cam-04',
        deviceHostname: 'cam-garagem-ip04',
        siteId: 'site-home',
        eventIds: ['ev-ids-1'],
        timeline: [],
        recommendedPolicyId: 'pol-1',
        recommendedAction: 'Quarantine',
        investigation: {
          provider: 'local-ollama-mock',
          modelVersion: 'v1',
          promptTemplateVersion: 'v1',
          generatedAt: '2026-11-15T11:58:00.000Z',
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
        eventId: 'ev-ids-1',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:58:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'ids.alert',
        severity: 'high',
        deviceId: 'dev-cam-04',
        summary: 'Outbound SSH 2222 anomaly',
        payload: { srcIp: '::ffff:192.168.10.44', dstPort: 2222 },
      },
      // Duplicate of rtr-1 below — should not double-appear
      {
        eventId: 'ev-rtr-dup',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:59:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'router.access_attempt',
        severity: 'critical',
        summary: 'SSH brute force',
        payload: { srcIp: '185.220.101.42' },
      },
      // Office site event should only show in business profile
      {
        eventId: 'ev-office-1',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:59:30.000Z',
        sourceIntegrationId: 'office-gw',
        eventType: 'threat.ioc',
        severity: 'high',
        summary: 'Office IOC hit',
        payload: { indicator: '45.155.205.81' },
      },
    ];

    state.routerAccessAttempts = [
      {
        id: 'rtr-1',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '185.220.101.42',
        service: 'ssh',
        attemptsCount: 12,
        firstSeenAt: '2026-11-15T11:50:00.000Z',
        lastSeenAt: '2026-11-15T11:59:00.000Z',
        severity: 'critical',
        status: 'observed',
        lastMessage: 'Dropbear SSH bad password from 185.220.101.42',
        sampleLines: [],
      },
    ];

    const resAlerts = buildNetworkAnomalyAlerts(state);
    expect(resAlerts).toHaveLength(2);
    expect(resAlerts[0].id).toBe('alert-rtr-rtr-1');
    expect(resAlerts[0].deviceLabel).toBe('OpenWrt Casa');
    expect(resAlerts[0].sourceIp).toBe('185.220.101.42');

    expect(resAlerts[1].id).toBe('alert-ev-ev-ids-1');
    expect(resAlerts[1].deviceLabel).toBe('cam-garagem-ip04');
    expect(resAlerts[1].sourceIp).toBe('192.168.10.44');
    expect(resAlerts[1].linkedIncidentId).toBe('inc-cam-1');

    state.context.profile = 'business';
    const bizAlerts = buildNetworkAnomalyAlerts(state);
    expect(bizAlerts).toHaveLength(3);
    expect(bizAlerts[0].id).toBe('alert-ev-ev-office-1');
    expect(bizAlerts[0].sourceIp).toBe('45.155.205.81');
  });
});
