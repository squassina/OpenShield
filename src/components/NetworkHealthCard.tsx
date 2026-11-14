import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Gauge,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getIntlLocale } from '../i18n';
import type { IntegrationAdapter, LatencySample, WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';

interface LatencyChartPoint extends LatencySample {
  timeLabel: string;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload?: LatencyChartPoint; value?: number }>;
}

function formatExactTimestamp(iso: string, locale: string): string {
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) {
    return iso;
  }
  return dt.toLocaleString(locale, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function LatencyTooltip({ active, payload }: CustomTooltipProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  if (!active || !payload || payload.length === 0) {
    return null;
  }
  const point = payload[0]?.payload;
  if (!point) {
    return null;
  }

  return (
    <div className="rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2 shadow-lg text-xs space-y-1">
      <div className="font-mono text-[11px] text-slate-400 tabular-nums">
        {formatExactTimestamp(point.timestamp, locale)}
      </div>
      <div className="flex items-center justify-between gap-4">
        <span className="text-slate-300">{t('networkHealth.tooltipAvgLatency')}</span>
        <span className="font-mono font-semibold text-sky-400 tabular-nums">
          {point.avgLatencyMs} ms
        </span>
      </div>
      <div className="flex items-center justify-between gap-4 text-[11px] text-slate-400 tabular-nums">
        <span>
          {t('networkHealth.rangeLabel')}{' '}
          <span className="font-mono text-slate-200">
            {point.minLatencyMs}–{point.maxLatencyMs} ms
          </span>
        </span>
        <span>
          {point.measuredCount}{' '}
          {point.measuredCount === 1
            ? t('networkHealth.tooltipEndpointSingular')
            : t('networkHealth.tooltipEndpointPlural')}
        </span>
      </div>
    </div>
  );
}

interface NetworkHealthCardProps {
  state: WorkspaceState;
  onSyncAllHealth: () => Promise<void>;
  onNavigate: (tab: NavTab) => void;
  busyKey: string | null;
}

export function NetworkHealthCard({
  state,
  onSyncAllHealth,
  onNavigate,
  busyKey,
}: NetworkHealthCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const getEndpointStatusMeta = (status: IntegrationAdapter['status']) => {
    if (status === 'connected') {
      return {
        label: t('common.online'),
        textClass: 'text-emerald-400',
        Icon: CheckCircle2,
      };
    }
    if (status === 'stale') {
      return {
        label: t('common.degraded'),
        textClass: 'text-amber-400',
        Icon: AlertTriangle,
      };
    }
    return {
      label: t('common.offline'),
      textClass: 'text-red-400',
      Icon: ShieldAlert,
    };
  };

  const securityEndpoints = state.integrations.filter((i) => i.domain !== 'ai_runtime');
  const offlineEndpoints = securityEndpoints.filter(
    (i) => i.status === 'unavailable' || i.status === 'stale',
  );
  const onlineEndpoints = securityEndpoints.filter((i) => i.status === 'connected');
  const measuredEndpoints = onlineEndpoints.filter(
    (i) => typeof i.lastLatencyMs === 'number' && Number.isFinite(i.lastLatencyMs),
  );

  const latencies = measuredEndpoints.map((i) => i.lastLatencyMs as number);
  const hasMeasurements = latencies.length > 0;
  const avgLatencyMs = hasMeasurements
    ? Math.round(latencies.reduce((sum, val) => sum + val, 0) / latencies.length)
    : null;
  const minLatencyMs = hasMeasurements ? Math.min(...latencies) : null;
  const maxLatencyMs = hasMeasurements ? Math.max(...latencies) : null;

  const isMultipleOffline = offlineEndpoints.length > 1;
  const isSingleOffline = offlineEndpoints.length === 1;
  const isSyncing = busyKey === 'sync-all';

  let latencyBandLabel = t('networkHealth.bandWaiting');
  let latencyBandColor = 'text-slate-400';
  let latencyBarColor = 'bg-slate-600';
  let LatencyIcon = Gauge;

  if (!state.context.nodeAvailable) {
    latencyBandLabel = t('networkHealth.bandNodeOffline');
    latencyBandColor = 'text-amber-400';
    latencyBarColor = 'bg-amber-500';
    LatencyIcon = AlertTriangle;
  } else if (avgLatencyMs !== null) {
    if (avgLatencyMs < 50) {
      latencyBandLabel = t('networkHealth.bandExcellent');
      latencyBandColor = 'text-emerald-400';
      latencyBarColor = 'bg-emerald-500';
      LatencyIcon = CheckCircle2;
    } else if (avgLatencyMs < 150) {
      latencyBandLabel = t('networkHealth.bandNormal');
      latencyBandColor = 'text-amber-400';
      latencyBarColor = 'bg-amber-500';
      LatencyIcon = Activity;
    } else {
      latencyBandLabel = t('networkHealth.bandHigh');
      latencyBandColor = 'text-red-400';
      latencyBarColor = 'bg-red-500';
      LatencyIcon = AlertTriangle;
    }
  }

  const latencyFillPercent =
    avgLatencyMs === null ? 0 : Math.min(100, Math.max(8, Math.round((avgLatencyMs / 250) * 100)));

  const cutoff24h = Date.now() - 24 * 60 * 60 * 1000;
  const rawHistory = (state.latencyHistory ?? []).filter(
    (entry) => Date.parse(entry.timestamp) >= cutoff24h,
  );
  const aggregatedSeriesSource =
    rawHistory.length > 0
      ? rawHistory
      : avgLatencyMs !== null && minLatencyMs !== null && maxLatencyMs !== null
        ? [
            {
              timestamp:
                measuredEndpoints[0]?.lastHeartbeatAt || new Date().toISOString(),
              avgLatencyMs,
              minLatencyMs,
              maxLatencyMs,
              measuredCount: measuredEndpoints.length,
            },
          ]
        : [];

  const latencyChartSeries = aggregatedSeriesSource.map((point) => {
    const dt = new Date(point.timestamp);
    const timeLabel = Number.isNaN(dt.getTime())
      ? '--:--'
      : dt.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
    return {
      ...point,
      timeLabel,
    };
  });

  return (
    <section
      aria-label={t('networkHealth.ariaLabel')}
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <h2 className="text-base font-semibold text-slate-100">{t('networkHealth.title')}</h2>
          <p className="text-xs text-slate-400 mt-0.5 tabular-nums">
            {securityEndpoints.length === 0
              ? t('networkHealth.noEndpointsYet')
              : t('networkHealth.endpointsSummary', {
                  online: onlineEndpoints.length,
                  total: securityEndpoints.length,
                })}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            disabled={state.integrations.length === 0 || isSyncing}
            onClick={onSyncAllHealth}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>
              {isSyncing ? t('networkHealth.measuring') : t('networkHealth.measureLatency')}
            </span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('integrations')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer px-2 py-1.5"
          >
            <span>{t('networkHealth.integrationsLink')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Multi-endpoint or single-endpoint availability alert */}
        {isMultipleOffline && (
          <div
            role="alert"
            className="rounded-lg border border-red-800/70 bg-red-950/25 p-3.5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"
          >
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="text-sm font-semibold text-red-200">
                  {t('networkHealth.multiOfflineTitle', { count: offlineEndpoints.length })}
                </div>
                <p className="text-xs text-red-200/85 leading-relaxed">
                  {t('networkHealth.multiOfflinePrefix')}{' '}
                  <span className="font-medium text-red-100">
                    {offlineEndpoints.map((ep) => ep.name).join(' + ')}
                  </span>{' '}
                  {t('networkHealth.multiOfflineSuffix')}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('integrations')}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-red-700/80 bg-red-900/40 text-red-100 hover:bg-red-900/70 transition-colors whitespace-nowrap shrink-0 cursor-pointer self-start"
            >
              {t('networkHealth.checkEndpoints')}
            </button>
          </div>
        )}

        {isSingleOffline && (
          <div
            role="status"
            className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-3.5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div className="text-xs text-amber-100/90 leading-relaxed">
                <span className="font-semibold text-amber-200">
                  {t('networkHealth.singleOfflineTitle', { name: offlineEndpoints[0].name })}
                </span>
                <span className="mx-1.5 text-amber-500/70">·</span>
                <span>{t('networkHealth.singleOfflineSuffix')}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('integrations')}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-amber-700/60 bg-amber-950/40 text-amber-200 hover:bg-amber-900/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer self-start sm:self-auto"
            >
              {t('networkHealth.diagnose')}
            </button>
          </div>
        )}

        {securityEndpoints.length === 0 ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-slate-300">
              {t('networkHealth.emptyPromptPrefix')}{' '}
              <span className="font-medium text-slate-100">
                {t('networkHealth.emptyPromptSettings')}
              </span>{' '}
              {t('networkHealth.emptyPromptSuffix')}
            </div>
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer self-start sm:self-auto"
            >
              {t('overview.configureServices')}
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Aggregated Latency Card */}
            <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 flex flex-col justify-between space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>{t('networkHealth.avgLatencyTitle')}</span>
                <LatencyIcon className={`w-4 h-4 ${latencyBandColor}`} />
              </div>

              <div>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-semibold font-mono text-slate-50 tabular-nums">
                    {avgLatencyMs !== null ? `${avgLatencyMs} ms` : '-- ms'}
                  </span>
                  <span className={`text-xs font-medium ${latencyBandColor}`}>
                    {latencyBandLabel}
                  </span>
                </div>

                <div className="mt-2.5 h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${latencyBarColor}`}
                    style={{ width: `${latencyFillPercent}%` }}
                  />
                </div>
              </div>

              <div className="text-xs text-slate-400 tabular-nums flex flex-wrap items-center gap-x-2 gap-y-1">
                {hasMeasurements ? (
                  <>
                    <span>
                      {t('networkHealth.rangeLabel')}{' '}
                      <span className="font-mono text-slate-200">
                        {minLatencyMs}–{maxLatencyMs} ms
                      </span>
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>
                      {t('networkHealth.measuredCount', {
                        measured: measuredEndpoints.length,
                        total: securityEndpoints.length,
                      })}
                    </span>
                  </>
                ) : (
                  <span>{t('networkHealth.noRecentMeasurements')}</span>
                )}
              </div>

              {/* Small 24h Aggregated Latency Line Chart (Recharts) */}
              <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-slate-400 tabular-nums">
                  <span>{t('networkHealth.chartTitle24h')}</span>
                  <span className="font-mono text-slate-500">
                    {latencyChartSeries.length > 0
                      ? `${latencyChartSeries.length} ${
                          latencyChartSeries.length === 1
                            ? t('networkHealth.sampleSingular')
                            : t('networkHealth.samplePlural')
                        }`
                      : t('networkHealth.noHistory')}
                  </span>
                </div>

                {latencyChartSeries.length > 0 ? (
                  <div className="w-full min-w-0 h-[108px]">
                    <ResponsiveContainer width="100%" height={108}>
                      <LineChart
                        data={latencyChartSeries}
                        margin={{ top: 6, right: 6, left: -12, bottom: 0 }}
                      >
                        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                        <XAxis
                          dataKey="timeLabel"
                          tick={{ fill: '#64748b', fontSize: 10 }}
                          tickLine={false}
                          axisLine={false}
                          minTickGap={24}
                        />
                        <YAxis
                          tick={{ fill: '#64748b', fontSize: 10 }}
                          tickLine={false}
                          axisLine={false}
                          width={42}
                          tickFormatter={(val) => `${val}ms`}
                        />
                        <Tooltip
                          cursor={{ stroke: '#475569', strokeWidth: 1 }}
                          content={<LatencyTooltip />}
                        />
                        <Line
                          type="monotone"
                          dataKey="avgLatencyMs"
                          name={t('networkHealth.chartSeriesName')}
                          stroke="#38bdf8"
                          strokeWidth={2}
                          dot={latencyChartSeries.length <= 3 ? { r: 3, fill: '#38bdf8' } : false}
                          activeDot={{ r: 4, fill: '#38bdf8' }}
                          isAnimationActive={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="h-[72px] rounded-md border border-dashed border-slate-800 flex items-center justify-center text-[11px] text-slate-500 text-center px-3">
                    {t('networkHealth.chartEmptyHint')}
                  </div>
                )}
              </div>
            </div>

            {/* Per-Endpoint Health & Latency Breakdown */}
            <div className="lg:col-span-2 rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
              <div className="px-4 py-2.5 border-b border-slate-800/80 flex items-center justify-between text-xs">
                <span className="font-medium text-slate-200">
                  {t('networkHealth.monitoredEndpointsTitle')}
                </span>
                <span className="text-slate-400 tabular-nums">
                  {offlineEndpoints.length === 0 ? (
                    <span className="inline-flex items-center gap-1.5 text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{t('networkHealth.allOperational')}</span>
                    </span>
                  ) : (
                    <span className="text-red-300 font-medium">
                      {t('networkHealth.countOffline', { count: offlineEndpoints.length })}
                    </span>
                  )}
                </span>
              </div>

              <div className="divide-y divide-slate-800/70 max-h-[280px] overflow-y-auto">
                {securityEndpoints.map((endpoint) => {
                  const statusMeta = getEndpointStatusMeta(endpoint.status);
                  const StatusIcon = statusMeta.Icon;
                  return (
                    <div
                      key={endpoint.id}
                      className="px-4 py-2.5 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <div className="font-medium text-slate-100 truncate">{endpoint.name}</div>
                        <div className="text-[11px] text-slate-400 truncate mt-0.5">
                          <span>{t(`networkHealth.domains.${endpoint.domain}`)}</span>
                          <span className="mx-1.5 text-slate-600" aria-hidden="true">
                            ·
                          </span>
                          <span className="font-mono uppercase">{endpoint.mode}</span>
                          {endpoint.liveEndpointUrl && (
                            <>
                              <span className="mx-1.5 text-slate-600" aria-hidden="true">
                                ·
                              </span>
                              <span className="font-mono text-slate-500">
                                {endpoint.liveEndpointUrl}
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-4 shrink-0 tabular-nums">
                        <span className="font-mono text-slate-300 w-16 text-right">
                          {endpoint.status === 'connected' &&
                          typeof endpoint.lastLatencyMs === 'number'
                            ? `${endpoint.lastLatencyMs} ms`
                            : '-- ms'}
                        </span>
                        <span
                          className={`inline-flex items-center gap-1.5 font-medium w-24 justify-end ${statusMeta.textClass}`}
                        >
                          <StatusIcon className="w-3.5 h-3.5 shrink-0" />
                          <span>{statusMeta.label}</span>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
