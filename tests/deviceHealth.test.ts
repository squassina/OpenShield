import { describe, expect, it } from 'vitest';
import {
  DEVICE_OFFLINE_STALE_MS,
  HIGH_LATENCY_THRESHOLD_MS,
  deriveDeviceHealth,
} from '../src/lib/deviceHealth.ts';
import type {
  NetworkDevice,
  OpenShieldEventV1,
  WorkspaceState,
} from '../src/types/openshield.ts';

const NOW_ISO = '2026-11-18T12:00:00.000Z';
const NOW_MS = Date.parse(NOW_ISO);

function createDevice(overrides: Partial<NetworkDevice> = {}): NetworkDevice {
  return {
    id: 'dev-nas-01',
    hostname: 'nas-sala',
    ip: '192.168.1.50',
    mac: 'AA:BB:CC:DD:EE:50',
    vendor: 'Synology',
    interfaceName: 'lan-br0',
    segment: 'Trusted',
    siteId: 'site-home',
    riskScore: 12,
    status: 'nominal',
    lastSeenAt: '2026-11-18T11:58:00.000Z',
    dnsQueries24h: 120,
    blockedQueries24h: 4,
    deviceType: 'server',
    ...overrides,
  };
}

function createEvent(overrides: Partial<OpenShieldEventV1> = {}): OpenShieldEventV1 {
  return {
    eventId: 'evt-1',
    schemaVersion: 'openshield.event.v1',
    occurredAt: '2026-11-18T11:59:00.000Z',
    sourceIntegrationId: 'home-gw',
    eventType: 'gateway.health',
    severity: 'info',
    summary: 'Telemetry check',
    payload: {},
    ...overrides,
  };
}

function createBaseState(devices: NetworkDevice[]): WorkspaceState {
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
      sites: [{ id: 'site-home', name: 'Casa', profile: 'residential' }],
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
        lastHeartbeatAt: NOW_ISO,
        lastLatencyMs: 18,
        capabilities: ['discover', 'health_check', 'execute_action'],
        outboxQueueCount: 0,
        outboxCapacity: 10000,
        siteId: 'site-home',
      },
    ],
    devices,
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
    latencyHistory: [],
  };
}

describe('deriveDeviceHealth', () => {
  it('marks nominal device with recent lastSeenAt and low latency as online', () => {
    const dev = createDevice();
    const state = createBaseState([dev]);
    state.events.push(
      createEvent({
        eventId: 'evt-1',
        deviceId: dev.id,
        payload: { latencyMs: 24 },
      }),
    );

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health).toEqual({
      status: 'online',
      latencyMs: 24,
      lastSeenMinutesAgo: 2,
    });
  });

  it('keeps an attention-risk device online when connectivity and latency are healthy', () => {
    const dev = createDevice({
      id: 'dev-cam-04',
      status: 'attention',
      riskScore: 84,
      deviceType: 'iot',
    });
    const state = createBaseState([dev]);

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('online');
    expect(health.lastSeenMinutesAgo).toBe(2);
  });

  it('marks isolated device as offline', () => {
    const dev = createDevice({ status: 'isolated' });
    const state = createBaseState([dev]);

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('offline');
  });

  it('marks device with stale lastSeenAt (> 15 min) as offline', () => {
    const staleIso = new Date(NOW_MS - DEVICE_OFFLINE_STALE_MS - 60_000).toISOString();
    const dev = createDevice({ lastSeenAt: staleIso });
    const state = createBaseState([dev]);

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('offline');
    expect(health.lastSeenMinutesAgo).toBe(16);
  });

  it('marks router as offline when gateway forwarding is disabled', () => {
    const router = createDevice({
      id: 'dev-gw-01',
      hostname: 'openwrt-casa',
      ip: '192.168.1.1',
      deviceType: 'router',
    });
    const state = createBaseState([router]);
    state.context.gatewayForwardingActive = false;

    const health = deriveDeviceHealth(router, state, NOW_MS);
    expect(health.status).toBe('offline');
  });

  it('marks device as offline when matched integration adapter is unavailable', () => {
    const dev = createDevice({ ip: '192.168.1.1', hostname: 'openwrt-casa' });
    const state = createBaseState([dev]);
    state.integrations[0].status = 'unavailable';

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('offline');
  });

  it('marks device as offline when newest matching event explicitly reports reachable=false', () => {
    const dev = createDevice();
    const state = createBaseState([dev]);
    state.events.push(
      createEvent({
        eventId: 'evt-old',
        deviceId: dev.id,
        occurredAt: '2026-11-18T11:50:00.000Z',
        payload: { latencyMs: 12, status: 'online' },
      }),
      createEvent({
        eventId: 'evt-new',
        deviceId: dev.id,
        severity: 'high',
        occurredAt: '2026-11-18T11:59:30.000Z',
        payload: { reachable: false },
      }),
    );

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('offline');
  });

  it('marks device as high_latency when event latencyMs or rttMs >= threshold', () => {
    const dev = createDevice();
    const state = createBaseState([dev]);
    state.events.push(
      createEvent({
        eventId: 'evt-lat',
        eventType: 'zeek.connection',
        severity: 'medium',
        payload: { srcIp: '192.168.1.50', rttMs: HIGH_LATENCY_THRESHOLD_MS + 42 },
      }),
    );

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('high_latency');
    expect(health.latencyMs).toBe(192);
  });

  it('marks device as high_latency when event has latencySpike flag or matched adapter is stale', () => {
    const dev1 = createDevice({ id: 'dev-1', ip: '192.168.1.51', hostname: 'host-1' });
    const dev2 = createDevice({ id: 'dev-2', ip: '192.168.1.1', hostname: 'openwrt-casa' });
    const state = createBaseState([dev1, dev2]);
    state.events.push(
      createEvent({
        eventId: 'evt-spike',
        deviceId: 'dev-1',
        severity: 'medium',
        payload: { latencySpike: true },
      }),
    );
    state.integrations[0].status = 'stale';
    state.integrations[0].lastLatencyMs = 210;

    expect(deriveDeviceHealth(dev1, state, NOW_MS).status).toBe('high_latency');
    const health2 = deriveDeviceHealth(dev2, state, NOW_MS);
    expect(health2.status).toBe('high_latency');
    expect(health2.latencyMs).toBe(210);
  });

  it('marks router as high_latency when latest latencyHistory sample exceeds threshold', () => {
    const router = createDevice({
      id: 'dev-gw-01',
      hostname: 'openwrt-casa',
      ip: '10.0.0.1',
      deviceType: 'router',
    });
    const state = createBaseState([router]);
    state.integrations = [];
    state.latencyHistory = [
      {
        timestamp: '2026-11-18T11:55:00.000Z',
        avgLatencyMs: 22,
        minLatencyMs: 14,
        maxLatencyMs: 31,
        measuredCount: 5,
      },
      {
        timestamp: '2026-11-18T11:59:00.000Z',
        avgLatencyMs: 185,
        minLatencyMs: 120,
        maxLatencyMs: 260,
        measuredCount: 5,
      },
    ];

    const health = deriveDeviceHealth(router, state, NOW_MS);
    expect(health.status).toBe('high_latency');
    expect(health.latencyMs).toBe(185);
  });

  it('gives offline precedence over high_latency when both conditions are true', () => {
    const dev = createDevice({ status: 'isolated' });
    const state = createBaseState([dev]);
    state.events.push(
      createEvent({
        eventId: 'evt-both',
        deviceId: dev.id,
        severity: 'high',
        payload: { latencyMs: 420, latencySpike: true },
      }),
    );

    const health = deriveDeviceHealth(dev, state, NOW_MS);
    expect(health.status).toBe('offline');
    expect(health.latencyMs).toBe(420);
  });
});
