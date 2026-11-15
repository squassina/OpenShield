import { describe, expect, it } from 'vitest';
import {
  buildGeoThreatSummary,
  isPrivateOrNonRoutableIp,
  resolveCountryFromPublicIp,
} from '../src/lib/geoThreatAnalytics.ts';
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

describe('geoThreatAnalytics', () => {
  it('identifies private/RFC1918 vs routable public IPs and resolves countries deterministically', () => {
    expect(isPrivateOrNonRoutableIp('192.168.10.44')).toBe(true);
    expect(isPrivateOrNonRoutableIp('::ffff:10.0.0.5')).toBe(true);
    expect(isPrivateOrNonRoutableIp('185.220.101.42')).toBe(false);

    expect(resolveCountryFromPublicIp('192.168.1.1')).toBeNull();
    expect(resolveCountryFromPublicIp('185.220.101.42')?.isoAlpha2).toBe('DE');
    expect(resolveCountryFromPublicIp('45.155.205.81')?.isoAlpha2).toBe('RU');
    expect(resolveCountryFromPublicIp('118.126.88.14')?.isoAlpha2).toBe('CN');
    expect(resolveCountryFromPublicIp('177.71.148.20')?.isoAlpha2).toBe('BR');
  });

  it('returns empty geo summary when no blocked malicious origins exist', () => {
    const state = createBaseState();
    const summary = buildGeoThreatSummary(state, 'blocked');
    expect(summary.hasGeoData).toBe(false);
    expect(summary.countries).toHaveLength(0);
    expect(summary.totalBlockedAttempts).toBe(0);
  });

  it('aggregates blocked malicious attempts by country, excludes LAN IPs from world plot, and respects site & filter modes', () => {
    const state = createBaseState();

    state.routerAccessAttempts = [
      {
        id: 'rtr-ru',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '45.155.205.81',
        service: 'wan_drop',
        attemptsCount: 30,
        firstSeenAt: '2026-11-15T11:40:00.000Z',
        lastSeenAt: '2026-11-15T11:55:00.000Z',
        severity: 'high',
        status: 'blocked',
        lastMessage: 'WAN drop',
        sampleLines: ['WAN drop'],
      },
      {
        id: 'rtr-de-observed',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '185.220.101.42',
        service: 'ssh',
        attemptsCount: 10,
        firstSeenAt: '2026-11-15T11:45:00.000Z',
        lastSeenAt: '2026-11-15T11:58:00.000Z',
        severity: 'critical',
        status: 'observed',
        lastMessage: 'SSH brute force',
        sampleLines: ['SSH brute force'],
      },
      {
        id: 'rtr-lan-blocked',
        sourceIntegrationId: 'home-gw',
        siteId: 'site-home',
        srcIp: '192.168.10.44',
        service: 'luci',
        attemptsCount: 4,
        firstSeenAt: '2026-11-15T11:50:00.000Z',
        lastSeenAt: '2026-11-15T11:56:00.000Z',
        severity: 'high',
        status: 'blocked',
        lastMessage: 'LuCI failed login',
        sampleLines: ['LuCI failed login'],
      },
      {
        id: 'rtr-br-office',
        sourceIntegrationId: 'office-gw',
        siteId: 'site-office-sp',
        srcIp: '177.71.148.20',
        service: 'wan_drop',
        attemptsCount: 12,
        firstSeenAt: '2026-11-15T11:51:00.000Z',
        lastSeenAt: '2026-11-15T11:57:00.000Z',
        severity: 'medium',
        status: 'blocked',
        lastMessage: 'WAN drop',
        sampleLines: ['WAN drop'],
      },
    ];

    state.events = [
      // Duplicate of rtr-ru router.access_attempt — must not be double-counted
      {
        eventId: 'ev-rtr-dup',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:55:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'router.access_attempt',
        severity: 'high',
        summary: 'WAN drop',
        payload: { srcIp: '45.155.205.81', attemptsCount: 30, action: 'blocked' },
      },
      // Explicit countryCode payload on blocked IDS alert
      {
        eventId: 'ev-ids-fr',
        schemaVersion: 'openshield.event.v1',
        occurredAt: '2026-11-15T11:59:00.000Z',
        sourceIntegrationId: 'home-gw',
        eventType: 'ids.alert',
        severity: 'high',
        deviceId: 'dev-home-1',
        summary: 'Blocked inbound scan',
        payload: {
          srcIp: '195.154.10.20',
          countryCode: 'FR',
          action: 'blocked',
          attemptsCount: 6,
        },
      },
    ];

    // Residential mode on site-home, 'blocked' filter: RU (30) + FR (6), excludes observed DE and office BR
    const blockedRes = buildGeoThreatSummary(state, 'blocked');
    expect(blockedRes.hasGeoData).toBe(true);
    expect(blockedRes.totalBlockedAttempts).toBe(36);
    expect(blockedRes.localPrivateBlockedCount).toBe(4);
    expect(blockedRes.countries.map((c) => c.isoAlpha2)).toEqual(['RU', 'FR']);
    expect(blockedRes.byNumericId['643']?.blockedAttempts).toBe(30);
    expect(blockedRes.byNumericId['250']?.blockedAttempts).toBe(6);

    // Switching to 'all' mode includes observed DE (10)
    const allRes = buildGeoThreatSummary(state, 'all');
    expect(allRes.countries.map((c) => c.isoAlpha2)).toEqual(['RU', 'DE', 'FR']);
    expect(allRes.totalObservedAttempts).toBe(10);

    // Switching to business profile includes office BR (12)
    state.context.profile = 'business';
    const blockedBiz = buildGeoThreatSummary(state, 'blocked');
    expect(blockedBiz.countries.map((c) => c.isoAlpha2)).toEqual(['RU', 'BR', 'FR']);
    expect(blockedBiz.totalBlockedAttempts).toBe(48);
  });
});
