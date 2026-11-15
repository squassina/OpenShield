import { describe, expect, it } from 'vitest';
import { buildTelemetrySummary } from '../src/lib/telemetryAnalytics.ts';
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
        id: 'dev-home-1',
        hostname: 'cam-garagem',
        ip: '192.168.10.44',
        mac: 'AA:BB:CC:DD:EE:01',
        vendor: 'CamTech',
        interfaceName: 'iot-vlan',
        segment: 'IoT',
        siteId: 'site-home',
        riskScore: 80,
        status: 'attention',
        lastSeenAt: '2026-11-15T11:55:00.000Z',
        dnsQueries24h: 300,
        blockedQueries24h: 50,
        deviceType: 'iot',
      },
      {
        id: 'dev-office-1',
        hostname: 'srv-financeiro',
        ip: '10.10.1.20',
        mac: 'AA:BB:CC:DD:EE:02',
        vendor: 'Dell',
        interfaceName: 'eth0',
        segment: 'Corp',
        siteId: 'site-office-sp',
        riskScore: 15,
        status: 'nominal',
        lastSeenAt: '2026-11-15T11:55:00.000Z',
        dnsQueries24h: 1000,
        blockedQueries24h: 10,
        deviceType: 'server',
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
    latencyHistory: [],
    routerAccessAttempts: [],
  };
}

describe('buildTelemetrySummary', () => {
  const nowMs = Date.parse('2026-11-15T12:00:00.000Z');

  it('returns an honest empty state when no telemetry exists', () => {
    const state = createBaseState();
    const summary = buildTelemetrySummary(state, '1h', 'en-US', nowMs);

    expect(summary.hasTelemetry).toBe(false);
    expect(summary.buckets).toHaveLength(12);
    expect(summary.totalRxKb).toBe(0);
    expect(summary.totalTxKb).toBe(0);
    expect(summary.totalDrops).toBe(0);
    expect(summary.dropRatePct).toBe(0);
    expect(summary.latestLatencyMs).toBeNull();
  });

  it('aggregates throughput bytes, packet drops, DNS blocks, and latency across time buckets', () => {
    const state = createBaseState();
    state.events = [
      {
        eventId: 'ev-zeek-home',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:52:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'zeek.connection',
        severity: 'info',
        deviceId: 'dev-home-1',
        summary: 'Conn bytes',
        payload: {
          bytesRecv: 1024 * 200, // 200 KB
          bytesSent: 1024 * 50, // 50 KB
          packets: 120,
          packetsDropped: 3,
        },
      },
      // Same domain as dnsInsight below — must not be double counted
      {
        eventId: 'ev-dns-dup',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:56:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'dns.query',
        severity: 'medium',
        deviceId: 'dev-home-1',
        summary: 'DNS burst',
        payload: {
          domain: 'telemetry.tracker.example',
          queriesInWindow: 100,
          action: 'blocked',
        },
      },
      // Office event should be excluded while in residential mode on site-home
      {
        eventId: 'ev-office-only',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:54:00.000Z',
        sourceIntegrationId: 'office-gw',
        eventType: 'zeek.connection',
        severity: 'info',
        deviceId: 'dev-office-1',
        summary: 'Office flow',
        payload: {
          bytesRecv: 1024 * 900,
          bytesSent: 1024 * 100,
        },
      },
    ];

    state.dnsInsights = [
      {
        id: 'dns-1',
        domain: 'telemetry.tracker.example',
        category: 'Telemetria & Rastreador',
        classification: 'tracker',
        deviceId: 'dev-home-1',
        deviceHostname: 'cam-garagem',
        queriesCount: 100,
        blockedCount: 80,
        listStatus: 'blocked',
        lastQueriedAt: '2026-11-15T11:56:00.000Z',
      },
    ];

    state.routerAccessAttempts = [
      {
        id: 'rtr-wan-1',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '203.0.113.55',
        service: 'wan_drop',
        targetPort: 23,
        protocol: 'tcp',
        attemptsCount: 12,
        firstSeenAt: '2026-11-15T11:50:00.000Z',
        lastSeenAt: '2026-11-15T11:57:00.000Z',
        severity: 'medium',
        status: 'observed',
        lastMessage: 'FW WAN drop',
        sampleLines: ['FW WAN drop'],
      },
      {
        id: 'rtr-ssh-observed',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '198.51.100.10',
        service: 'ssh',
        targetPort: 22,
        protocol: 'tcp',
        attemptsCount: 5,
        firstSeenAt: '2026-11-15T11:48:00.000Z',
        lastSeenAt: '2026-11-15T11:49:00.000Z',
        severity: 'high',
        status: 'observed',
        lastMessage: 'SSH bad password',
        sampleLines: ['SSH bad password'],
      },
    ];

    state.executions = [
      {
        id: 'exec-1',
        incidentId: 'inc-home-1',
        policyId: 'pol-1',
        targetLabel: 'cam-garagem',
        targetIp: '192.168.10.44',
        actionType: 'nftables_temp_drop',
        autonomyLevel: 'L2',
        status: 'verified',
        ttlSeconds: 900,
        expiresAt: '2026-11-15T12:10:00.000Z',
        executedBy: 'admin',
        verificationDetail: 'verified',
        rollbackAvailable: true,
        createdAt: '2026-11-15T11:58:00.000Z',
      },
    ];
    state.incidents = [
      {
        id: 'inc-home-1',
        title: 'Test',
        summary: 'Test',
        severity: 'high',
        status: 'contained',
        riskScore: 80,
        riskFactors: [],
        deviceId: 'dev-home-1',
        deviceHostname: 'cam-garagem',
        siteId: 'site-home',
        eventIds: ['ev-zeek-home'],
        timeline: [],
        recommendedPolicyId: 'pol-1',
        recommendedAction: 'drop',
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
    state.latencyHistory = [
      {
        timestamp: '2026-11-15T11:45:00.000Z',
        avgLatencyMs: 14,
        minLatencyMs: 8,
        maxLatencyMs: 22,
        measuredCount: 2,
      },
      {
        timestamp: '2026-11-15T11:57:00.000Z',
        avgLatencyMs: 18,
        minLatencyMs: 10,
        maxLatencyMs: 26,
        measuredCount: 2,
      },
    ];

    const resSummary = buildTelemetrySummary(state, '1h', 'en-US', nowMs);
    expect(resSummary.hasTelemetry).toBe(true);
    expect(resSummary.buckets).toHaveLength(12);
    // Firewall drops: 3 (zeek packetsDropped) + 12 (wan_drop) + 1 (verified nftables execution) = 16
    expect(resSummary.totalFirewallDrops).toBe(16);
    // DNS drops: 80 (from dnsInsights, NOT double counted with ev-dns-dup)
    expect(resSummary.totalDnsDrops).toBe(80);
    expect(resSummary.totalDrops).toBe(96);
    expect(resSummary.activeFirewallRulesCount).toBe(1);
    expect(resSummary.latestLatencyMs).toBe(18);
    // Office 900 KB RX event should be excluded in residential mode
    expect(resSummary.totalRxKb).toBeLessThan(300);

    // Switching to business profile includes both home + office sites across 24h buckets
    state.context.profile = 'business';
    const bizSummary = buildTelemetrySummary(state, '24h', 'en-US', nowMs);
    expect(bizSummary.buckets).toHaveLength(24);
    expect(bizSummary.totalRxKb).toBeGreaterThan(1000);
  });
});
