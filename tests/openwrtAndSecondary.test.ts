import { describe, expect, it } from 'vitest';
import { parseRouterAccessLogs } from '../server/adapters/openwrtAdapter.ts';
import {
  parseCrowdSecDecisionsPayload,
  parseSuricataEvePayload,
  parseUptimeKumaMetricsText,
  parseWazuhAlertsPayload,
  parseWireGuardPeersPayload,
} from '../server/adapters/secondaryAdapters.ts';

describe('openwrtAdapter & secondaryAdapters parsers', () => {
  it('parses SSH, LuCI, ubus, and WAN drop router access logs and ignores localhost', () => {
    const rawLog = [
      'Sun Nov 15 01:10:00 2026 authpriv.warn dropbear[1201]: Bad password attempt for root from 203.0.113.10:55122',
      'Sun Nov 15 01:10:02 2026 authpriv.warn dropbear[1202]: Bad password attempt for root from 203.0.113.10:55123',
      'Sun Nov 15 01:10:05 2026 authpriv.warn dropbear[1203]: Bad password attempt for admin from 203.0.113.10:55124',
      'Sun Nov 15 01:11:00 2026 daemon.err uhttpd[884]: luci: failed login on / for root from 198.51.100.77',
      'Sun Nov 15 01:11:30 2026 daemon.err rpcd[501]: ubus login failed from ::ffff:192.0.2.55',
      'Sun Nov 15 01:12:00 2026 kern.warn kernel: [1234.5] fw4 DROP IN=wan OUT= SRC=45.33.32.156 DST=192.168.1.1 PROTO=TCP DPT=22',
      'Sun Nov 15 01:12:05 2026 authpriv.warn dropbear[1204]: Bad password attempt for root from 127.0.0.1:40000',
    ].join('\n');

    const { entries, events } = parseRouterAccessLogs(rawLog, 'openwrt-main', '2026-11-15T01:15:00.000Z');

    expect(entries).toHaveLength(4);
    const ssh = entries.find((e) => e.service === 'ssh');
    expect(ssh).toBeDefined();
    expect(ssh?.srcIp).toBe('203.0.113.10');
    expect(ssh?.attemptsCount).toBe(3);
    expect(ssh?.severity).toBe('high');

    const ubus = entries.find((e) => e.service === 'ubus');
    expect(ubus?.srcIp).toBe('192.0.2.55');

    const wan = entries.find((e) => e.service === 'wan_drop');
    expect(wan?.srcIp).toBe('45.33.32.156');
    expect(wan?.targetPort).toBe(22);

    expect(events.every((e) => e.eventType === 'router.access_attempt')).toBe(true);
  });

  it('parses CrowdSec LAPI decisions stream', () => {
    const parsed = parseCrowdSecDecisionsPayload(
      {
        new: [
          {
            id: 42,
            origin: 'crowdsec',
            type: 'ban',
            scope: 'Ip',
            value: '::ffff:185.220.101.4',
            duration: '4h',
            scenario: 'crowdsecurity/ssh-bf',
          },
        ],
        deleted: [{ id: 10 }],
      },
      'crowdsec-1',
    );

    expect(parsed.activeCount).toBe(1);
    expect(parsed.deletedCount).toBe(1);
    expect(parsed.events[0].eventType).toBe('threat.ioc');
    expect(parsed.events[0].severity).toBe('high');
    expect(parsed.events[0].payload.srcIp).toBe('185.220.101.4');
  });

  it('parses WireGuard / wg-easy peers into discovered devices and handshake summary', () => {
    const nowIso = '2026-11-15T10:00:00.000Z';
    const parsed = parseWireGuardPeersPayload(
      [
        {
          id: 'p1',
          name: 'Pixel-Work',
          enabled: true,
          address: '10.8.0.2',
          publicKey: 'abcdef1234567890',
          latestHandshakeAt: '2026-11-15T09:58:00.000Z',
        },
        {
          id: 'p2',
          name: 'Backup-Laptop',
          enabled: true,
          address: '10.8.0.3',
          latestHandshakeAt: '2026-11-14T00:00:00.000Z',
        },
      ],
      'wg-1',
      nowIso,
    );

    expect(parsed.totalPeers).toBe(2);
    expect(parsed.onlinePeers).toBe(1);
    expect(parsed.discoveredDevices).toHaveLength(2);
    expect(parsed.discoveredDevices[0].deviceType).toBe('mobile');
    expect(parsed.discoveredDevices[1].deviceType).toBe('workstation');
    expect(parsed.discoveredDevices[0].interfaceName).toBe('wg0');
  });

  it('parses Uptime Kuma Prometheus /metrics text and detects offline monitors', () => {
    const metrics = [
      '# HELP monitor_status Monitor Status (1 = UP, 0 = DOWN)',
      'monitor_status{monitor_name="Pi-hole DNS",monitor_type="dns",monitor_url="192.168.1.12"} 1',
      'monitor_response_time{monitor_name="Pi-hole DNS"} 18',
      'monitor_status{monitor_name="OpenWrt Gateway",monitor_type="http",monitor_url="http://192.168.1.1"} 0',
    ].join('\n');

    const parsed = parseUptimeKumaMetricsText(metrics, 'kuma-1');
    expect(parsed.upCount).toBe(1);
    expect(parsed.downCount).toBe(1);
    expect(parsed.monitors.find((m) => m.name === 'Pi-hole DNS')?.responseTimeMs).toBe(18);
    expect(parsed.events[0].eventType).toBe('gateway.health');
    expect(parsed.events[0].severity).toBe('medium');
    expect(parsed.events[0].summary).toContain('OpenWrt Gateway');
  });

  it('parses Suricata EVE and Wazuh API alert payloads', () => {
    const surEvents = parseSuricataEvePayload(
      [
        {
          timestamp: '2026-11-15T10:00:00Z',
          src_ip: '192.168.1.50',
          dest_ip: '198.51.100.2',
          dest_port: 4444,
          proto: 'TCP',
          alert: { severity: 1, signature: 'ET MALWARE Beacon', category: 'Malware' },
        },
      ],
      'suricata-1',
    );
    expect(surEvents).toHaveLength(1);
    expect(surEvents[0].severity).toBe('critical');
    expect(surEvents[0].payload.dstPort).toBe(4444);

    const wazEvents = parseWazuhAlertsPayload(
      {
        data: {
          affected_items: [
            {
              timestamp: '2026-11-15T10:01:00Z',
              agent: { name: 'ubuntu-nas', ip: '192.168.1.20' },
              rule: { id: '5710', level: 10, description: 'Attempt to login using a non-existent user' },
            },
          ],
        },
      },
      'wazuh-1',
    );
    expect(wazEvents).toHaveLength(1);
    expect(wazEvents[0].severity).toBe('high');
    expect(wazEvents[0].payload.srcIp).toBe('192.168.1.20');
  });
});
