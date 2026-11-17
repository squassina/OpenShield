import { useCallback, useEffect, useState } from 'react';
import { Cpu, HardDrive, MemoryStick, RefreshCw, Server } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import { api } from '../lib/api';
import type { HostSystemMetrics } from '../types/openshield';

interface OverviewHostMetricsCardProps {
  livePaused?: boolean;
  nodeAvailable?: boolean;
}

function formatBytes(bytes: number, locale: string): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  const decimals = idx <= 1 ? 0 : idx === 2 ? 1 : 2;
  return `${val.toLocaleString(locale, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  })} ${units[idx]}`;
}

function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '0m';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function getUtilizationStatus(pct: number): {
  level: 'nominal' | 'elevated' | 'high';
  textClass: string;
  barClass: string;
} {
  if (pct >= 85) {
    return {
      level: 'high',
      textClass: 'text-red-700 dark:text-red-400',
      barClass: 'bg-red-500',
    };
  }
  if (pct >= 65) {
    return {
      level: 'elevated',
      textClass: 'text-amber-700 dark:text-amber-400',
      barClass: 'bg-amber-500',
    };
  }
  return {
    level: 'nominal',
    textClass: 'text-emerald-700 dark:text-emerald-400',
    barClass: 'bg-emerald-500',
  };
}

export function OverviewHostMetricsCard({
  livePaused = false,
  nodeAvailable = true,
}: OverviewHostMetricsCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const [metrics, setMetrics] = useState<HostSystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const data = await api.getHostMetrics();
      setMetrics(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('hostMetrics.loadError'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [t]);

  useEffect(() => {
    void fetchMetrics(false);
  }, [fetchMetrics]);

  useEffect(() => {
    if (livePaused || !nodeAvailable) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void fetchMetrics(false);
      }
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [livePaused, nodeAvailable, fetchMetrics]);

  const statusLabel = (level: 'nominal' | 'elevated' | 'high') =>
    level === 'high'
      ? t('hostMetrics.statusHigh')
      : level === 'elevated'
        ? t('hostMetrics.statusElevated')
        : t('hostMetrics.statusNominal');

  return (
    <section
      aria-label={t('hostMetrics.ariaLabel')}
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] overflow-hidden shadow-xs dark:shadow-none"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">{t('hostMetrics.title')}</h2>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span>{t('hostMetrics.subtitle')}</span>
            {metrics && (
              <>
                <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                  ·
                </span>
                <span className="font-mono text-slate-700 dark:text-slate-300">{metrics.hostname}</span>
                <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                  ·
                </span>
                <span className="font-mono text-slate-600 dark:text-slate-400">
                  {metrics.platform}/{metrics.arch}
                </span>
                <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                  ·
                </span>
                <span className="tabular-nums text-slate-600 dark:text-slate-400">
                  {t('hostMetrics.uptimeLabel', { uptime: formatUptime(metrics.uptimeSeconds) })}
                </span>
              </>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {metrics && (
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 tabular-nums">
              {metrics.nodeVersion} ·{' '}
              {new Date(metrics.collectedAt).toLocaleTimeString(locale, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>
          )}
          <button
            type="button"
            disabled={refreshing}
            onClick={() => void fetchMetrics(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? t('hostMetrics.refreshing') : t('hostMetrics.refresh')}</span>
          </button>
        </div>
      </div>

      {/* Body */}
      {loading && !metrics ? (
        <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-200 dark:divide-slate-800">
          {[0, 1, 2].map((idx) => (
            <div key={idx} className="p-5 space-y-3 animate-pulse">
              <div className="h-3.5 w-28 rounded bg-slate-200 dark:bg-slate-800" />
              <div className="h-6 w-20 rounded bg-slate-200 dark:bg-slate-800" />
              <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-800" />
              <div className="h-3 w-44 rounded bg-slate-200 dark:bg-slate-800" />
            </div>
          ))}
        </div>
      ) : error && !metrics ? (
        <div className="p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs">
          <span className="text-red-700 dark:text-red-300">{error}</span>
          <button
            type="button"
            onClick={() => void fetchMetrics(true)}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer self-start"
          >
            {t('hostMetrics.retry')}
          </button>
        </div>
      ) : metrics ? (
        <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-200 dark:divide-slate-800">
          {/* CPU */}
          {(() => {
            const cpuStatus = getUtilizationStatus(metrics.cpu.usagePct);
            return (
              <div className="p-5 space-y-2.5">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
                    <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>{t('hostMetrics.cpuTitle')}</span>
                  </span>
                  <span className={`font-medium ${cpuStatus.textClass}`}>
                    {statusLabel(cpuStatus.level)}
                  </span>
                </div>

                <div className="flex items-baseline justify-between gap-2 tabular-nums">
                  <span className="text-xl font-semibold font-mono text-slate-900 dark:text-slate-50">
                    {metrics.cpu.usagePct.toLocaleString(locale, {
                      minimumFractionDigits: 1,
                      maximumFractionDigits: 1,
                    })}
                    %
                  </span>
                  <span className="text-xs text-slate-600 dark:text-slate-400">
                    {t('hostMetrics.cpuCores', { count: metrics.cpu.cores })}
                  </span>
                </div>

                <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${cpuStatus.barClass}`}
                    style={{ width: `${Math.max(2, Math.min(100, metrics.cpu.usagePct))}%` }}
                  />
                </div>

                <div className="flex items-center justify-between gap-2 text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
                  <span className="font-mono">
                    {t('hostMetrics.cpuLoad', {
                      l1: metrics.cpu.loadAvg1m.toFixed(1),
                      l5: metrics.cpu.loadAvg5m.toFixed(1),
                    })}
                  </span>
                  <span className="truncate max-w-[160px]" title={metrics.cpu.model}>
                    {metrics.cpu.model}
                  </span>
                </div>
              </div>
            );
          })()}

          {/* RAM */}
          {(() => {
            const ramStatus = getUtilizationStatus(metrics.memory.usagePct);
            return (
              <div className="p-5 space-y-2.5">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
                    <MemoryStick className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    <span>{t('hostMetrics.ramTitle')}</span>
                  </span>
                  <span className={`font-medium ${ramStatus.textClass}`}>
                    {statusLabel(ramStatus.level)}
                  </span>
                </div>

                <div className="flex items-baseline justify-between gap-2 tabular-nums">
                  <span className="text-xl font-semibold font-mono text-slate-900 dark:text-slate-50">
                    {metrics.memory.usagePct.toLocaleString(locale, {
                      minimumFractionDigits: 1,
                      maximumFractionDigits: 1,
                    })}
                    %
                  </span>
                  <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
                    {formatBytes(metrics.memory.usedBytes, locale)} /{' '}
                    {formatBytes(metrics.memory.totalBytes, locale)}
                  </span>
                </div>

                <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${ramStatus.barClass}`}
                    style={{ width: `${Math.max(2, Math.min(100, metrics.memory.usagePct))}%` }}
                  />
                </div>

                <div className="flex items-center justify-between gap-2 text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
                  <span>
                    {t('hostMetrics.ramAvailable', {
                      free: formatBytes(metrics.memory.availableBytes, locale),
                    })}
                  </span>
                  <span className="font-mono">
                    {t('hostMetrics.processRss', {
                      rss: formatBytes(metrics.memory.processRssBytes, locale),
                    })}
                  </span>
                </div>
              </div>
            );
          })()}

          {/* Storage */}
          {(() => {
            const diskStatus = getUtilizationStatus(metrics.storage.usagePct);
            return (
              <div className="p-5 space-y-2.5">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="inline-flex items-center gap-1.5 text-slate-600 dark:text-slate-400">
                    <HardDrive className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>{t('hostMetrics.storageTitle')}</span>
                  </span>
                  <span className={`font-medium ${diskStatus.textClass}`}>
                    {statusLabel(diskStatus.level)}
                  </span>
                </div>

                <div className="flex items-baseline justify-between gap-2 tabular-nums">
                  <span className="text-xl font-semibold font-mono text-slate-900 dark:text-slate-50">
                    {metrics.storage.usagePct.toLocaleString(locale, {
                      minimumFractionDigits: 1,
                      maximumFractionDigits: 1,
                    })}
                    %
                  </span>
                  <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
                    {formatBytes(metrics.storage.usedBytes, locale)} /{' '}
                    {formatBytes(metrics.storage.totalBytes, locale)}
                  </span>
                </div>

                <div className="w-full h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${diskStatus.barClass}`}
                    style={{ width: `${Math.max(2, Math.min(100, metrics.storage.usagePct))}%` }}
                  />
                </div>

                <div className="flex items-center justify-between gap-2 text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
                  <span>
                    {t('hostMetrics.storageAvailable', {
                      free: formatBytes(metrics.storage.availableBytes, locale),
                    })}
                  </span>
                  <span className="font-mono">
                    {t('hostMetrics.dbSize', {
                      size: formatBytes(metrics.storage.dbFileBytes, locale),
                    })}
                  </span>
                </div>
              </div>
            );
          })()}
        </div>
      ) : null}
    </section>
  );
}
