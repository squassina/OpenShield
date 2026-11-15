import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { HostSystemMetrics } from '../src/types/openshield.ts';

interface CpuTotals {
  idle: number;
  total: number;
}

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

function clampPct(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, round1(value)));
}

function readCpuTotals(): CpuTotals {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    const t = cpu.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.irq + t.idle;
  }
  return { idle, total };
}

export function parseLinuxMeminfo(raw: string): { totalBytes: number; availableBytes: number } | null {
  const totalMatch = raw.match(/^MemTotal:\s+(\d+)\s+kB$/m);
  const availMatch = raw.match(/^MemAvailable:\s+(\d+)\s+kB$/m);
  if (!totalMatch || !availMatch) return null;

  const totalKb = Number(totalMatch[1]);
  const availKb = Number(availMatch[1]);
  if (!Number.isFinite(totalKb) || !Number.isFinite(availKb) || totalKb <= 0) return null;

  return {
    totalBytes: totalKb * 1024,
    availableBytes: Math.max(0, availKb * 1024),
  };
}

function readMemoryStats(): HostSystemMetrics['memory'] {
  let totalBytes = os.totalmem();
  let availableBytes = os.freemem();

  if (process.platform === 'linux') {
    try {
      const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
      const parsed = parseLinuxMeminfo(meminfo);
      if (parsed) {
        totalBytes = parsed.totalBytes;
        availableBytes = Math.min(parsed.totalBytes, parsed.availableBytes);
      }
    } catch {
      // Fall back to os.totalmem()/os.freemem()
    }
  }

  const usedBytes = Math.max(0, totalBytes - availableBytes);
  const usagePct = totalBytes > 0 ? clampPct((usedBytes / totalBytes) * 100) : 0;

  return {
    totalBytes,
    usedBytes,
    availableBytes,
    usagePct,
    processRssBytes: process.memoryUsage().rss,
  };
}

function readStorageStats(dbFilePath?: string): HostSystemMetrics['storage'] {
  const candidatePath = dbFilePath ? path.dirname(dbFilePath) : process.cwd();
  const mountPath = fs.existsSync(candidatePath) ? candidatePath : process.cwd();

  let totalBytes = 0;
  let usedBytes = 0;
  let availableBytes = 0;

  try {
    const stat = fs.statfsSync(mountPath);
    const bsize = Number(stat.bsize) || 4096;
    const blocks = Number(stat.blocks) || 0;
    const bfree = Number(stat.bfree) || 0;
    const bavail = Number(stat.bavail) || 0;

    totalBytes = blocks * bsize;
    availableBytes = bavail * bsize;
    usedBytes = Math.max(0, (blocks - bfree) * bsize);
  } catch {
    // Graceful fallback on restricted filesystems
  }

  let dbFileBytes = 0;
  if (dbFilePath) {
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        const st = fs.statSync(`${dbFilePath}${suffix}`);
        dbFileBytes += st.size;
      } catch {
        // Ignore missing sidecar files
      }
    }
  }

  const usagePct = totalBytes > 0 ? clampPct((usedBytes / totalBytes) * 100) : 0;

  return {
    mountPath,
    totalBytes,
    usedBytes,
    availableBytes,
    usagePct,
    dbFileBytes,
  };
}

export class HostMetricsCollector {
  private lastCpu: CpuTotals | null = null;
  private dbFilePath?: string;

  constructor(dbFilePath?: string) {
    this.dbFilePath = dbFilePath;
    this.lastCpu = readCpuTotals();
  }

  collect(): HostSystemMetrics {
    const cpus = os.cpus();
    const cores = Math.max(1, cpus.length);
    const model = cpus[0]?.model?.trim() || os.arch();
    const [load1, load5, load15] = os.loadavg();

    const currentCpu = readCpuTotals();
    let cpuUsagePct: number;

    if (this.lastCpu && currentCpu.total > this.lastCpu.total) {
      const totalDelta = currentCpu.total - this.lastCpu.total;
      const idleDelta = Math.max(0, currentCpu.idle - this.lastCpu.idle);
      cpuUsagePct = clampPct(((totalDelta - idleDelta) / totalDelta) * 100);
    } else {
      cpuUsagePct = clampPct((load1 / cores) * 100);
    }
    this.lastCpu = currentCpu;

    return {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      uptimeSeconds: Math.floor(os.uptime()),
      collectedAt: new Date().toISOString(),
      cpu: {
        usagePct: cpuUsagePct,
        cores,
        model,
        loadAvg1m: round1(load1),
        loadAvg5m: round1(load5),
        loadAvg15m: round1(load15),
      },
      memory: readMemoryStats(),
      storage: readStorageStats(this.dbFilePath),
    };
  }
}
