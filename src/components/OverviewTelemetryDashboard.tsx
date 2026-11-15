import { useMemo, useState } from 'react';
import { Activity, ArrowDownUp, ArrowRight, ShieldBan } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  Area,
  AreaChart,
  Bar,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getIntlLocale } from '../i18n';
import {
  buildTelemetrySummary,
  type TelemetryBucketPoint,
  type TelemetryWindow,
} from '../lib/telemetryAnalytics';
import type { WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';

interface OverviewTelemetryDashboardProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  livePaused?: boolean;
  frozenAtMs?: number;
  onToggleLivePaused?: () => void;
}

interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ payload?: TelemetryBucketPoint }>;
}

function formatVolumeKb(kb: number, locale: string): string {
  if (!Number.isFinite(kb) || kb <= 0) return '0 KB';
  if (kb >= 1024) {
    return `${(kb / 1024).toLocaleString(locale, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })} MB`;
  }
  return `${kb.toLocaleString(locale, {
    minimumFractionDigits: kb < 10 ? 1 : 0,
    maximumFractionDigits: 1,
  })} KB`;
}

function formatPreciseThroughput(kb: number, bytes: number, locale: string): string {
  const formattedKb = formatVolumeKb(kb, locale);
  if (bytes <= 0) return formattedKb;
  return `${formattedKb} (${bytes.toLocaleString(locale)} B)`;
}

function ThroughputTooltip({ active, payload }: ChartTooltipProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0]?.payload;
  if (!point) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-[#0B1120]/95 backdrop-blur-sm px-3.5 py-2.5 shadow-xl text-xs space-y-2 min-w-[245px]">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1.5 font-mono text-[11px] text-slate-300 tabular-nums">
        <span>
          {point.fullTimestamp} – {point.intervalEndLabel}
        </span>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-300 font-medium">
            {t('telemetryDashboard.tooltipTotalThroughput')}
          </span>
          <span className="font-mono font-semibold text-slate-100">
            {formatPreciseThroughput(point.totalThroughputKb, point.totalBytes, locale)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-400">{t('telemetryDashboard.rxSeries')}</span>
          <span className="font-mono font-semibold text-sky-400">
            {formatPreciseThroughput(point.rxKb, point.rxBytes, locale)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-400">{t('telemetryDashboard.txSeries')}</span>
          <span className="font-mono font-semibold text-emerald-400">
            {formatPreciseThroughput(point.txKb, point.txBytes, locale)}
          </span>
        </div>
      </div>

      <div className="border-t border-slate-800 pt-1.5 space-y-1 text-[11px] tabular-nums">
        <div className="flex items-center justify-between gap-4">
          <span className="text-slate-400">{t('telemetryDashboard.tooltipTotalDrops')}</span>
          <span className="font-mono font-semibold text-red-400">
            {point.totalDrops.toLocaleString(locale)} ({point.dropRatioPct.toLocaleString(locale, {
              minimumFractionDigits: 1,
              maximumFractionDigits: 1,
            })}
            %)
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 text-slate-400">
          <span>{t('telemetryDashboard.tooltipDropBreakdown')}</span>
          <span className="font-mono text-slate-200">
            {point.firewallDrops.toLocaleString(locale)} FW · {point.dnsDrops.toLocaleString(locale)} DNS
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 text-slate-400">
          <span>{t('telemetryDashboard.tooltipFlows')}</span>
          <span className="font-mono text-slate-200">
            {point.packetsOrQueries.toLocaleString(locale)}
          </span>
        </div>
      </div>
    </div>
  );
}

function PacketDropTooltip({ active, payload }: ChartTooltipProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0]?.payload;
  if (!point) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-[#0B1120]/95 backdrop-blur-sm px-3.5 py-2.5 shadow-xl text-xs space-y-2 min-w-[245px]">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1.5 font-mono text-[11px] text-slate-300 tabular-nums">
        <span>
          {point.fullTimestamp} – {point.intervalEndLabel}
        </span>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-300 font-medium">
            {t('telemetryDashboard.tooltipTotalDrops')}
          </span>
          <span className="font-mono font-semibold text-red-300">
            {point.totalDrops.toLocaleString(locale)} ({point.dropRatioPct.toLocaleString(locale, {
              minimumFractionDigits: 1,
              maximumFractionDigits: 1,
            })}
            %)
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-400">{t('telemetryDashboard.firewallDropSeries')}</span>
          <span className="font-mono font-semibold text-red-400">
            {point.firewallDrops.toLocaleString(locale)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 tabular-nums">
          <span className="text-slate-400">{t('telemetryDashboard.dnsDropSeries')}</span>
          <span className="font-mono font-semibold text-amber-400">
            {point.dnsDrops.toLocaleString(locale)}
          </span>
        </div>
      </div>

      <div className="border-t border-slate-800 pt-1.5 space-y-1 text-[11px] tabular-nums">
        <div className="flex items-center justify-between gap-4">
          <span className="text-slate-400">{t('telemetryDashboard.tooltipTotalThroughput')}</span>
          <span className="font-mono text-sky-300">
            {formatPreciseThroughput(point.totalThroughputKb, point.totalBytes, locale)}
          </span>
        </div>
        <div className="flex items-center justify-between gap-4 text-slate-400">
          <span>{t('telemetryDashboard.tooltipFlows')}</span>
          <span className="font-mono text-slate-200">
            {point.packetsOrQueries.toLocaleString(locale)}
          </span>
        </div>
        {point.avgLatencyMs !== null && (
          <div className="flex items-center justify-between gap-4 text-slate-400">
            <span>{t('telemetryDashboard.latencySeries')}</span>
            <span className="font-mono text-sky-300">{point.avgLatencyMs} ms</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function OverviewTelemetryDashboard({
  state,
  onNavigate,
  livePaused = false,
  frozenAtMs,
  onToggleLivePaused,
}: OverviewTelemetryDashboardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const [windowRange, setWindowRange] = useState<TelemetryWindow>('1h');

  const summary = useMemo(
    () => buildTelemetrySummary(state, windowRange, locale, frozenAtMs),
    [state, windowRange, locale, frozenAtMs],
  );

  const hasLatencyPoints = useMemo(
    () => summary.buckets.some((b) => b.avgLatencyMs !== null),
    [summary.buckets],
  );

  const totalThroughputKb = summary.totalRxKb + summary.totalTxKb;
  const pausedTimeLabel =
    livePaused && typeof frozenAtMs === 'number'
      ? new Date(frozenAtMs).toLocaleTimeString(locale, {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      : null;

  return (
    <section
      aria-label={t('telemetryDashboard.ariaLabel')}
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header + Window Selector */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            {t('telemetryDashboard.title')}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span>{t('telemetryDashboard.subtitle')}</span>
            {livePaused && (
              <>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span className="text-amber-300 font-medium tabular-nums">
                  {pausedTimeLabel
                    ? t('telemetryDashboard.pausedAt', { time: pausedTimeLabel })
                    : t('telemetryDashboard.pausedLabel')}
                </span>
                {onToggleLivePaused && (
                  <button
                    type="button"
                    onClick={onToggleLivePaused}
                    className="text-blue-400 hover:text-blue-300 font-medium underline underline-offset-2 cursor-pointer"
                  >
                    {t('telemetryDashboard.resumeInline')}
                  </button>
                )}
              </>
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div
            role="group"
            aria-label={t('telemetryDashboard.windowGroupAria')}
            className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800"
          >
            {(['15m', '1h', '24h'] as const).map((win) => {
              const active = windowRange === win;
              return (
                <button
                  key={win}
                  type="button"
                  onClick={() => setWindowRange(win)}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap cursor-pointer ${
                    active
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
                  }`}
                >
                  {t(`telemetryDashboard.window_${win}`)}
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => onNavigate('dns')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('telemetryDashboard.inspectDnsLink')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="p-5 space-y-5">
        {!summary.hasTelemetry ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-center space-y-2.5">
            <p className="text-sm font-medium text-slate-200">
              {t('telemetryDashboard.emptyTitle')}
            </p>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              {t('telemetryDashboard.emptyHint')}
            </p>
            <div className="pt-1">
              <button
                type="button"
                onClick={() => onNavigate('settings')}
                className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors cursor-pointer"
              >
                {t('overview.configureServices')}
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* 4 Clean Summary Readouts */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5">
              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3.5 space-y-1">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>{t('telemetryDashboard.kpiThroughputTitle')}</span>
                  <ArrowDownUp className="w-3.5 h-3.5 text-sky-400" />
                </div>
                <div className="text-lg font-semibold font-mono text-slate-50 tabular-nums">
                  {formatVolumeKb(totalThroughputKb, locale)}
                </div>
                <div className="text-[11px] text-slate-400 tabular-nums flex items-center gap-1.5">
                  <span className="text-sky-400">
                    RX {formatVolumeKb(summary.totalRxKb, locale)}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="text-emerald-400">
                    TX {formatVolumeKb(summary.totalTxKb, locale)}
                  </span>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3.5 space-y-1">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>{t('telemetryDashboard.kpiPeakTitle')}</span>
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                </div>
                <div className="text-lg font-semibold font-mono text-slate-50 tabular-nums">
                  {formatVolumeKb(summary.peakThroughputKb, locale)}
                </div>
                <div className="text-[11px] text-slate-400 tabular-nums">
                  {t('telemetryDashboard.kpiPeakSub', {
                    count: summary.totalPacketsOrQueries.toLocaleString(locale),
                  })}
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3.5 space-y-1">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>{t('telemetryDashboard.kpiDropsTitle')}</span>
                  <ShieldBan className="w-3.5 h-3.5 text-red-400" />
                </div>
                <div className="text-lg font-semibold font-mono text-slate-50 tabular-nums">
                  {summary.totalDrops.toLocaleString(locale)}
                </div>
                <div className="text-[11px] text-slate-400 tabular-nums flex items-center gap-1.5">
                  <span className="text-red-400">
                    {t('telemetryDashboard.kpiFirewallShort', {
                      count: summary.totalFirewallDrops,
                    })}
                  </span>
                  <span aria-hidden="true">·</span>
                  <span className="text-amber-400">
                    {t('telemetryDashboard.kpiDnsShort', {
                      count: summary.totalDnsDrops,
                    })}
                  </span>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3.5 space-y-1">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>{t('telemetryDashboard.kpiDropRateTitle')}</span>
                  <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                    {summary.latestLatencyMs !== null ? `${summary.latestLatencyMs} ms` : '-- ms'}
                  </span>
                </div>
                <div className="text-lg font-semibold font-mono text-slate-50 tabular-nums">
                  {summary.dropRatePct.toLocaleString(locale, {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1,
                  })}
                  %
                </div>
                <div className="text-[11px] text-slate-400 tabular-nums">
                  {t('telemetryDashboard.kpiActiveRules', {
                    count: summary.activeFirewallRulesCount,
                  })}
                </div>
              </div>
            </div>

            {/* 2-Column Recharts Visualizations */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {/* Chart 1: Throughput RX/TX AreaChart */}
              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-medium text-slate-100">
                      {t('telemetryDashboard.throughputChartTitle')}
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      {t('telemetryDashboard.throughputChartSub')}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-slate-300">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm bg-sky-400" aria-hidden="true" />
                      <span>{t('telemetryDashboard.rxShort')}</span>
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400" aria-hidden="true" />
                      <span>{t('telemetryDashboard.txShort')}</span>
                    </span>
                  </div>
                </div>

                <div className="w-full min-w-0 h-[230px]">
                  <ResponsiveContainer width="100%" height={230}>
                    <AreaChart
                      syncId="openshield-overview-telemetry"
                      data={summary.buckets}
                      margin={{ top: 8, right: 8, left: -8, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="osThroughputRx" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.38} />
                          <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="osThroughputTx" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.34} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="timeLabel"
                        tick={{ fill: '#64748b', fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                        minTickGap={20}
                      />
                      <YAxis
                        tick={{ fill: '#64748b', fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                        width={54}
                        tickFormatter={(val: number) =>
                          val >= 1024 ? `${(val / 1024).toFixed(1)}M` : `${Math.round(val)}K`
                        }
                      />
                      <Tooltip
                        trigger="hover"
                        cursor={{ stroke: '#64748b', strokeWidth: 1, strokeDasharray: '3 3' }}
                        content={<ThroughputTooltip />}
                      />
                      <Area
                        type="monotone"
                        dataKey="rxKb"
                        name={t('telemetryDashboard.rxSeries')}
                        stroke="#38bdf8"
                        strokeWidth={2}
                        fill="url(#osThroughputRx)"
                        activeDot={{ r: 4, strokeWidth: 1.5, stroke: '#0B1120', fill: '#38bdf8' }}
                        isAnimationActive={false}
                      />
                      <Area
                        type="monotone"
                        dataKey="txKb"
                        name={t('telemetryDashboard.txSeries')}
                        stroke="#10b981"
                        strokeWidth={2}
                        fill="url(#osThroughputTx)"
                        activeDot={{ r: 4, strokeWidth: 1.5, stroke: '#0B1120', fill: '#10b981' }}
                        isAnimationActive={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Chart 2: Packet Drops & Latency Overlay ComposedChart */}
              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-medium text-slate-100">
                      {t('telemetryDashboard.dropsChartTitle')}
                    </h3>
                    <p className="text-[11px] text-slate-400">
                      {t('telemetryDashboard.dropsChartSub')}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-slate-300">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm bg-red-400" aria-hidden="true" />
                      <span>{t('telemetryDashboard.fwShort')}</span>
                    </span>
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm bg-amber-400" aria-hidden="true" />
                      <span>{t('telemetryDashboard.dnsShort')}</span>
                    </span>
                    {hasLatencyPoints && (
                      <span className="inline-flex items-center gap-1.5">
                        <span className="w-3 h-0.5 bg-sky-400" aria-hidden="true" />
                        <span>{t('telemetryDashboard.latencyShort')}</span>
                      </span>
                    )}
                  </div>
                </div>

                <div className="w-full min-w-0 h-[230px]">
                  <ResponsiveContainer width="100%" height={230}>
                    <ComposedChart
                      syncId="openshield-overview-telemetry"
                      data={summary.buckets}
                      margin={{ top: 8, right: hasLatencyPoints ? 4 : 8, left: -12, bottom: 0 }}
                    >
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="timeLabel"
                        tick={{ fill: '#64748b', fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                        minTickGap={20}
                      />
                      <YAxis
                        yAxisId="drops"
                        tick={{ fill: '#64748b', fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                        width={46}
                        allowDecimals={false}
                      />
                      {hasLatencyPoints && (
                        <YAxis
                          yAxisId="latency"
                          orientation="right"
                          tick={{ fill: '#64748b', fontSize: 10 }}
                          tickLine={false}
                          axisLine={false}
                          width={42}
                          tickFormatter={(val: number) => `${Math.round(val)}ms`}
                        />
                      )}
                      <Tooltip
                        trigger="hover"
                        cursor={{ fill: 'rgba(30, 41, 59, 0.45)' }}
                        content={<PacketDropTooltip />}
                      />
                      <Bar
                        yAxisId="drops"
                        dataKey="firewallDrops"
                        stackId="drops"
                        name={t('telemetryDashboard.firewallDropSeries')}
                        fill="#f87171"
                        radius={[0, 0, 0, 0]}
                        maxBarSize={22}
                        isAnimationActive={false}
                      />
                      <Bar
                        yAxisId="drops"
                        dataKey="dnsDrops"
                        stackId="drops"
                        name={t('telemetryDashboard.dnsDropSeries')}
                        fill="#f59e0b"
                        radius={[3, 3, 0, 0]}
                        maxBarSize={22}
                        isAnimationActive={false}
                      />
                      {hasLatencyPoints && (
                        <Line
                          yAxisId="latency"
                          type="monotone"
                          dataKey="avgLatencyMs"
                          name={t('telemetryDashboard.latencySeries')}
                          stroke="#38bdf8"
                          strokeWidth={1.75}
                          strokeDasharray="4 3"
                          dot={{ r: 2.5, fill: '#38bdf8' }}
                          activeDot={{ r: 4, strokeWidth: 1.5, stroke: '#0B1120', fill: '#38bdf8' }}
                          connectNulls
                          isAnimationActive={false}
                        />
                      )}
                    </ComposedChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
