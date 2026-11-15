import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { HostMetricsCollector, parseLinuxMeminfo } from '../server/hostMetrics.ts';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('HostMetricsCollector', () => {
  it('parses Linux /proc/meminfo MemTotal and MemAvailable accurately', () => {
    const sample = [
      'MemTotal:       16384000 kB',
      'MemFree:         2048000 kB',
      'MemAvailable:    8192000 kB',
      'Buffers:          512000 kB',
    ].join('\n');

    const parsed = parseLinuxMeminfo(sample);
    expect(parsed).toEqual({
      totalBytes: 16384000 * 1024,
      availableBytes: 8192000 * 1024,
    });
    expect(parseLinuxMeminfo('invalid')).toBeNull();
  });

  it('collects valid bounded CPU, RAM, and storage utilization telemetry', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openshield-host-metrics-'));
    tempDirs.push(dir);
    const dbFile = path.join(dir, 'openshield.sqlite3');
    fs.writeFileSync(dbFile, Buffer.alloc(4096, 1));

    const collector = new HostMetricsCollector(dbFile);
    const first = collector.collect();
    const second = collector.collect();

    for (const m of [first, second]) {
      expect(m.hostname.length).toBeGreaterThan(0);
      expect(m.cpu.cores).toBeGreaterThanOrEqual(1);
      expect(m.cpu.usagePct).toBeGreaterThanOrEqual(0);
      expect(m.cpu.usagePct).toBeLessThanOrEqual(100);

      expect(m.memory.totalBytes).toBeGreaterThan(0);
      expect(m.memory.usedBytes).toBeGreaterThanOrEqual(0);
      expect(m.memory.usagePct).toBeGreaterThanOrEqual(0);
      expect(m.memory.usagePct).toBeLessThanOrEqual(100);
      expect(m.memory.processRssBytes).toBeGreaterThan(0);

      expect(m.storage.totalBytes).toBeGreaterThan(0);
      expect(m.storage.usagePct).toBeGreaterThanOrEqual(0);
      expect(m.storage.usagePct).toBeLessThanOrEqual(100);
      expect(m.storage.dbFileBytes).toBe(4096);
    }
  });
});
