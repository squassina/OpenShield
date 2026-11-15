import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthService } from '../server/auth.ts';
import { correlateEventIntoIncidents } from '../server/correlator.ts';
import { OpenShieldStore } from '../server/openshieldStore.ts';
import { SqlitePersistence } from '../server/persistence.ts';
import type { Incident, NetworkDevice, OpenShieldEventV1 } from '../src/types/openshield.ts';

const tempDirs: string[] = [];

function createIsolatedStore(): { store: OpenShieldStore; persistence: SqlitePersistence; auth: AuthService } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openshield-vitest-'));
  tempDirs.push(dir);
  const persistence = new SqlitePersistence(path.join(dir, 'openshield.sqlite3'));
  const store = new OpenShieldStore(persistence);
  const auth = new AuthService(persistence);
  return { store, persistence, auth };
}

afterEach(() => {
  vi.useRealTimers();
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('OpenShieldStore, Correlator & AuthService', () => {
  it('enforces RBAC permissions for auditor vs operator/admin and handles AsyncLocalStorage auth context', async () => {
    const { store } = createIsolatedStore();

    store.updateContext({ profile: 'business', simulatedRole: 'auditor' });
    await expect(store.triggerKillSwitch(true)).rejects.toThrow(/RBAC/i);

    store.updateContext({ simulatedRole: 'operator' });
    // Operator can trigger emergency Kill Switch (operate)
    const activated = await store.triggerKillSwitch(true);
    expect(activated.context.killSwitchActive).toBe(true);

    // Operator cannot release Kill Switch or toggle policies (requires policy_admin / admin)
    await expect(store.triggerKillSwitch(false)).rejects.toThrow(/RBAC/i);
    expect(() => store.togglePolicyEnabled('pol-iot-quarantine', false)).toThrow(/RBAC/i);

    // Admin can release Kill Switch and toggle policy rules
    store.updateContext({ simulatedRole: 'admin' });
    const released = await store.triggerKillSwitch(false);
    expect(released.context.killSwitchActive).toBe(false);
    const toggled = store.togglePolicyEnabled('pol-iot-quarantine', false);
    expect(toggled.policies.find((p) => p.id === 'pol-iot-quarantine')?.enabled).toBe(false);
    store.togglePolicyEnabled('pol-iot-quarantine', true);

    // Even in residential profile, authenticated auditor session is strictly enforced
    store.updateContext({ profile: 'residential' });
    await expect(
      store.runWithAuthUser({ username: 'sec-auditor', role: 'auditor' }, () =>
        store.triggerKillSwitch(true),
      ),
    ).rejects.toThrow(/RBAC/i);

    // Non-admin authenticated user cannot escalate or switch simulatedRole
    expect(() =>
      store.runWithAuthUser({ username: 'sec-op', role: 'operator' }, () =>
        store.updateContext({ simulatedRole: 'admin' }),
      ),
    ).toThrow(/administradores/i);
  });

  it('expires active actions on tickTimers and supports manual rollback', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-15T12:00:00.000Z'));

    const { store } = createIsolatedStore();

    // Load demo scenario to have an open incident and policy available
    store.loadDemoScenario();
    store.updateContext({ profile: 'residential', globalAutonomy: 'L2' });
    const current = store.getState();
    const incident = current.incidents[0];
    expect(incident).toBeDefined();

    const proposed = await store.proposePolicyAction({
      incidentId: incident.id,
      policyId: 'pol-iot-quarantine',
      ttlSeconds: 30,
    });
    expect(proposed.execution.status).toBe('verified');

    // Rollback manually
    const afterRollback = await store.rollbackExecution(proposed.execution.id);
    const rolledItem = afterRollback.executions.find((e) => e.id === proposed.execution.id);
    expect(rolledItem?.status).toBe('rolled_back');

    // Propose another action with 30s TTL and advance clock past expiration
    const second = await store.proposePolicyAction({
      incidentId: incident.id,
      policyId: 'pol-iot-quarantine',
      ttlSeconds: 30,
    });
    vi.advanceTimersByTime(45_000);
    store.tickTimers();
    const afterTick = store.getState().executions.find((e) => e.id === second.execution.id);
    expect(afterTick?.status).toBe('expired');
  });

  it('correlates IPv4-mapped IPv6 addresses to matching LAN devices', () => {
    const devices: NetworkDevice[] = [
      {
        id: 'dev-cam',
        hostname: 'cam-garagem',
        ip: '192.168.1.50',
        mac: 'AA:BB:CC:DD:EE:FF',
        vendor: 'Espressif',
        interfaceName: 'br-lan',
        segment: 'lan',
        siteId: 'site-home',
        riskScore: 10,
        status: 'nominal',
        lastSeenAt: new Date().toISOString(),
        dnsQueries24h: 0,
        blockedQueries24h: 0,
        deviceType: 'iot',
      },
    ];
    const incidents: Incident[] = [];
    const ev: OpenShieldEventV1 = {
      eventId: 'ev-map-1',
      schemaVersion: 'openshield.event.v1',
      occurredAt: new Date().toISOString(),
      sourceIntegrationId: 'suricata-1',
      eventType: 'ids.alert',
      severity: 'high',
      summary: 'Outbound beacon',
      payload: { srcIp: '::ffff:192.168.1.50' },
    };

    const res = correlateEventIntoIncidents(ev, incidents, devices, 'site-home');
    expect(res.created).toBe(true);
    expect(res.updatedIncident?.deviceId).toBe('dev-cam');
    expect(res.updatedIncident?.deviceHostname).toBe('cam-garagem');
  });

  it('supports scrypt auth setup, login, HttpOnly/SameSite=Strict HMAC cookies, and RBAC user CRUD', () => {
    const { auth } = createIsolatedStore();

    expect(auth.isAuthConfigured()).toBe(false);
    expect(() => auth.setupInitialAdmin('admin', 'short')).toThrow(/8 caracteres/);

    const admin = auth.setupInitialAdmin('admin', 'StrongPass!123');
    expect(admin.username).toBe('admin');
    expect(admin.role).toBe('admin');
    expect(auth.isAuthConfigured()).toBe(true);
    expect(auth.isAuthRequired()).toBe(true);

    // Second setup must fail
    expect(() => auth.setupInitialAdmin('admin2', 'StrongPass!123')).toThrow(/Já existe/);

    // Invalid vs valid login
    expect(() => auth.login('admin', 'WrongPass!123')).toThrow(/inválidas/);
    const logged = auth.login('admin', 'StrongPass!123');
    expect(logged).toEqual({ username: 'admin', role: 'admin' });

    // Cookie signing & tamper detection
    const cookieHeader = auth.buildSessionCookieHeader(logged, true);
    expect(cookieHeader).toContain('HttpOnly');
    expect(cookieHeader).toContain('SameSite=Strict');
    expect(cookieHeader).toContain('Secure');

    const verified = auth.authenticateFromCookie(cookieHeader.split(';')[0]);
    expect(verified?.username).toBe('admin');
    expect(verified?.role).toBe('admin');
    expect(auth.authenticateFromCookie('openshield_session=tampered.token')).toBeNull();

    // User management & last admin guard
    const op = auth.upsertUser({ username: 'operador1', role: 'operator', password: 'OperatorPass!99' });
    expect(op.role).toBe('operator');
    expect(auth.listUsers()).toHaveLength(2);

    expect(() => auth.deleteUser('admin', 'admin')).toThrow(/sessão atual/);
    expect(() => auth.deleteUser('admin')).toThrow(/pelo menos um usuário Administrador/);

    auth.deleteUser('operador1', 'admin');
    expect(auth.listUsers()).toHaveLength(1);
  });
});
