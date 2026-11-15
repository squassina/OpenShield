import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ActionExecution, IntegrationAdapter } from '../src/types/openshield.ts';
import {
  applyFirewallRuleLive,
  assertValidIp,
  reconcileGatewayFirewallRulesLive,
  rollbackFirewallRuleLive,
  selectLiveGatewayAdapters,
} from '../server/adapters/firewallAdapter.ts';

function makeOpenWrtAdapter(id = 'gw-owrt-1', siteId = 'site-hq'): IntegrationAdapter {
  return {
    id,
    name: 'OpenWrt Main',
    domain: 'gateway',
    kind: 'openwrt-rpcd',
    description: 'OpenWrt test',
    protocolVersion: 'openshield.gateway.v1',
    mode: 'live',
    liveEndpointUrl: 'http://192.168.1.1/ubus',
    timeoutMs: 5000,
    status: 'connected',
    lastHeartbeatAt: new Date().toISOString(),
    capabilities: ['discover', 'execute_action', 'verify_action'],
    outboxQueueCount: 0,
    outboxCapacity: 10000,
    siteId,
  };
}

function makeOpnsenseAdapter(id = 'gw-opn-1', siteId = 'site-hq'): IntegrationAdapter {
  return {
    id,
    name: 'OPNsense Perimeter',
    domain: 'gateway',
    kind: 'opnsense-api',
    description: 'OPNsense test',
    protocolVersion: 'openshield.gateway.v1',
    mode: 'live',
    liveEndpointUrl: 'https://192.168.1.254/api/core/firmware/status',
    timeoutMs: 5000,
    status: 'connected',
    lastHeartbeatAt: new Date().toISOString(),
    capabilities: ['discover', 'execute_action', 'verify_action'],
    outboxQueueCount: 0,
    outboxCapacity: 10000,
    siteId,
  };
}

describe('firewallAdapter', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('validates IPv4, IPv6, and normalized ::ffff: addresses while rejecting injection', () => {
    expect(assertValidIp('203.0.113.45')).toEqual({ ip: '203.0.113.45', family: 'ip' });
    expect(assertValidIp('::ffff:198.51.100.12')).toEqual({ ip: '198.51.100.12', family: 'ip' });
    expect(assertValidIp('2001:db8::1')).toEqual({ ip: '2001:db8::1', family: 'ip6' });

    expect(() => assertValidIp('192.168.1.1; rm -rf /')).toThrow(/Endereço IP inválido/);
    expect(() => assertValidIp('999.10.10.10')).toThrow(/Endereço IP inválido/);
    expect(() => assertValidIp('example.com')).toThrow(/Endereço IP inválido/);
  });

  it('selects all live gateways in the active site and excludes FastAPI node-only endpoints', () => {
    const nodeAdapter: IntegrationAdapter = {
      ...makeOpenWrtAdapter('gw-node'),
      liveEndpointUrl: 'http://192.168.1.10:8000/api/v1/events',
    };
    const owrt = makeOpenWrtAdapter('gw-owrt', 'site-hq');
    const opn = makeOpnsenseAdapter('gw-opn', 'site-hq');
    const branchGw = makeOpenWrtAdapter('gw-branch', 'site-branch');

    const selected = selectLiveGatewayAdapters([nodeAdapter, owrt, opn, branchGw], 'site-hq');
    expect(selected.map((s) => s.id)).toEqual(['gw-owrt', 'gw-opn']);
  });

  it('fans out apply and rollback across OpenWrt ubus (with UCI) and OPNsense API', async () => {
    const ubusCalls: Array<{ object: string; method: string; command?: string; params?: string[] }> = [];
    const opnsensePaths: string[] = [];

    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/ubus')) {
        const body = JSON.parse(String(init?.body ?? '{}')) as {
          params: [string, string, string, { command?: string; params?: string[] }];
        };
        const [, obj, method, arg] = body.params;
        ubusCalls.push({ object: obj, method, command: arg?.command, params: arg?.params });

        if (obj === 'session' && method === 'login') {
          return new Response(JSON.stringify({ result: [0, { ubus_rpc_session: 'tok-123' }] }), {
            status: 200,
          });
        }
        if (obj === 'file' && method === 'exec' && arg?.command === 'nft' && arg.params?.[0] === '-a') {
          return new Response(
            JSON.stringify({
              result: [
                0,
                {
                  code: 0,
                  stdout:
                    'table inet openshield {\n  chain input {\n    ip saddr 203.0.113.99 counter packets 0 bytes 0 drop comment "openshield_exec-multi" # handle 7\n  }\n}\n',
                },
              ],
            }),
            { status: 200 },
          );
        }
        return new Response(JSON.stringify({ result: [0, { code: 0, stdout: '' }] }), {
          status: 200,
        });
      }

      opnsensePaths.push(new URL(url).pathname);
      return new Response(JSON.stringify({ status: 'done' }), { status: 200 });
    }) as typeof fetch;

    const integrations = [makeOpenWrtAdapter('gw-owrt'), makeOpnsenseAdapter('gw-opn')];
    const getCred = (id: string) =>
      id === 'gw-owrt'
        ? { username: 'openshield', secret: 'ubus-pass' }
        : { username: 'opn-key', secret: 'opn-secret' };

    const applied = await applyFirewallRuleLive(
      integrations,
      {
        executionId: 'exec-multi',
        targetIp: '203.0.113.99',
        actionType: 'nftables_temp_drop',
        persistentUci: true,
      },
      getCred,
      'site-hq',
    );

    expect(applied.enforcementMode).toBe('live');
    expect(applied.gatewayResults).toHaveLength(2);
    expect(applied.gatewayResults?.every((g) => g.status === 'applied')).toBe(true);
    expect(ubusCalls.some((c) => c.command === 'uci' && c.params?.includes('commit'))).toBe(true);
    expect(opnsensePaths).toContain('/api/firewall/alias_util/add/openshield_blocked');
    expect(opnsensePaths).toContain('/api/firewall/filter/apply');

    const rolledBack = await rollbackFirewallRuleLive(
      integrations,
      {
        executionId: 'exec-multi',
        targetIp: '203.0.113.99',
        ruleRef: applied.ruleRef,
        enforcementMode: 'live',
        persistentUci: true,
        gatewayResults: applied.gatewayResults,
      },
      getCred,
      'site-hq',
    );

    expect(rolledBack.enforcementMode).toBe('live');
    expect(rolledBack.gatewayResults?.every((g) => g.status === 'rolled_back')).toBe(true);
    expect(ubusCalls.some((c) => c.command === 'nft' && c.params?.[0] === 'delete')).toBe(true);
    expect(opnsensePaths).toContain('/api/firewall/alias_util/delete/openshield_blocked');
  });

  it('reconciles missing active OpenWrt rules after router reboot during gateway sync', async () => {
    let ruleAdded = false;
    globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        params: [string, string, string, { command?: string; params?: string[] }];
      };
      const [, obj, method, arg] = body.params;
      if (obj === 'session' && method === 'login') {
        return new Response(JSON.stringify({ result: [0, { ubus_rpc_session: 'tok-reconcile' }] }), {
          status: 200,
        });
      }
      if (obj === 'file' && method === 'exec' && arg?.command === 'nft') {
        if (arg.params?.[0] === 'add' && arg.params?.[1] === 'rule') {
          ruleAdded = true;
          return new Response(JSON.stringify({ result: [0, { code: 0 }] }), { status: 200 });
        }
        if (arg.params?.[0] === '-a') {
          const stdout = ruleAdded
            ? 'table inet openshield {\n  chain forward {\n    ip saddr 198.51.100.44 drop comment "openshield_exec-reboot" # handle 19\n  }\n}\n'
            : '';
          return new Response(JSON.stringify({ result: [0, { code: 0, stdout }] }), { status: 200 });
        }
      }
      return new Response(JSON.stringify({ result: [0, { code: 0 }] }), { status: 200 });
    }) as typeof fetch;

    const adapter = makeOpenWrtAdapter('gw-owrt');
    const activeExecution: ActionExecution = {
      id: 'exec-reboot',
      incidentId: 'inc-1',
      policyId: 'pol-iot-quarantine',
      targetLabel: 'attacker (198.51.100.44)',
      targetIp: '198.51.100.44',
      enforcementMode: 'live',
      ruleRef: 'nft:inet/openshield:forward#5',
      gatewayResults: [
        {
          gatewayId: 'gw-owrt',
          gatewayName: 'OpenWrt Main',
          enforcementMode: 'live',
          ruleRef: 'nft:inet/openshield:forward#5',
          status: 'applied',
          detail: 'Inicial',
        },
      ],
      actionType: 'nftables_temp_drop',
      autonomyLevel: 'L2',
      status: 'verified',
      ttlSeconds: 900,
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      executedBy: 'admin',
      verificationDetail: 'Inicial',
      rollbackAvailable: true,
      createdAt: new Date().toISOString(),
    };

    const summary = await reconcileGatewayFirewallRulesLive(
      adapter,
      [activeExecution],
      () => ({ username: 'openshield', secret: 'ubus-pass' }),
    );

    expect(summary.checkedCount).toBe(1);
    expect(summary.reappliedExecutionIds).toEqual(['exec-reboot']);
    expect(activeExecution.reconciledAt).toBeTruthy();
    expect(activeExecution.ruleRef).toContain('#19');
    expect(activeExecution.gatewayResults?.[0].status).toBe('reconciled');
  });
});
