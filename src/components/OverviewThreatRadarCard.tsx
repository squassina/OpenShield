import { useMemo } from 'react';
import { ArrowRight, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { getIntlLocale } from '../i18n';
import {
  buildThreatLandscape,
  type ThreatAxisId,
  type ThreatLandscapeAxis,
} from '../lib/telemetryAnalytics';
import type { WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';

interface OverviewThreatRadarCardProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  livePaused?: boolean;
  frozenAtMs?: number;
  onToggleLivePaused?: () => void;
}

interface RadarPoint extends ThreatLandscapeAxis {
  axisLabel: string;
  levelLabel: string;
}

interface RadarTooltipProps {
  active?: boolean;
  payload?: Array<{ payload?: RadarPoint }>;
}

const AXIS_TARGET_TAB: Record<ThreatAxisId, NavTab> = {
  malware: 'incidents',
  botnet: 'devices',
  unauthorizedAccess: 'integrations',
  dnsAnomalies: 'dns',
  bruteForce: 'integrations',
};

function getLevelColors(level: ThreatLandscapeAxis['level']): {
  textClass: string;
  barClass: string;
} {
  if (level === 'critical') {
    return { textClass: 'text-red-400', barClass: 'bg-red-500' };
  }
  if (level === 'high') {
    return { textClass: 'text-orange-400', barClass: 'bg-orange-500' };
  }
  if (level === 'elevated') {
    return { textClass: 'text-amber-400', barClass: 'bg-amber-500' };
  }
  return { textClass: 'text-emerald-400', barClass: 'bg-emerald-500' };
}

function ThreatRadarTooltip({ active, payload }: RadarTooltipProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0]?.payload;
  if (!point) return null;

  const colors = getLevelColors(point.level);

  return (
    <div className="rounded-lg border border-slate-700 bg-[#0B1120]/95 backdrop-blur-sm px-3.5 py-2.5 shadow-xl text-xs space-y-2 min-w-[235px] max-w-[290px]">
      <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1.5">
        <span className="font-semibold text-slate-100">{point.axisLabel}</span>
        <span className={`font-medium ${colors.textClass}`}>{point.levelLabel}</span>
      </div>

      <div className="space-y-1 tabular-nums">
        <div className="flex items-center justify-between gap-4">
          <span className="text-slate-400">{t('threatRadar.activeRiskSeries')}</span>
          <span className="font-mono font-semibold text-red-400">{point.score} / 100</span>
        </div>
        <div className="flex items-center justify-between gap-4">
          <span className="text-slate-400">{t('threatRadar.mitigatedSeries')}</span>
          <span className="font-mono font-semibold text-emerald-400">
            {point.mitigatedScore} / 100
          </span>
        </div>
      </div>

      <div className="border-t border-slate-800 pt-1.5 space-y-1 text-[11px] tabular-nums">
        <div className="flex items-center justify-between gap-4 text-slate-400">
          <span>{t('threatRadar.tooltipSignals')}</span>
          <span className="font-mono text-slate-200">
            {t('threatRadar.signalsCompact', {
              active: point.activeSignals.toLocaleString(locale),
              mitigated: point.mitigatedSignals.toLocaleString(locale),
            })}
          </span>
        </div>
        {point.topEvidence && (
          <div className="text-slate-400 leading-snug line-clamp-2 pt-0.5">
            {point.topEvidence}
          </div>
        )}
      </div>
    </div>
  );
}

export function OverviewThreatRadarCard({
  state,
  onNavigate,
  livePaused = false,
  frozenAtMs,
  onToggleLivePaused,
}: OverviewThreatRadarCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const landscape = useMemo(() => buildThreatLandscape(state), [state]);

  const radarData: RadarPoint[] = useMemo(
    () =>
      landscape.axes.map((axis) => ({
        ...axis,
        axisLabel: t(`threatRadar.axes.${axis.id}`),
        levelLabel: t(`threatRadar.levels.${axis.level}`),
      })),
    [landscape.axes, t],
  );

  const pausedTimeLabel =
    livePaused && typeof frozenAtMs === 'number'
      ? new Date(frozenAtMs).toLocaleTimeString(locale, {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      : null;

  const highestAxisLabel = landscape.highestAxisId
    ? t(`threatRadar.axes.${landscape.highestAxisId}`)
    : null;

  return (
    <section
      aria-label={t('threatRadar.ariaLabel')}
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <h2 className="text-base font-semibold text-slate-100">{t('threatRadar.title')}</h2>
          <p className="text-xs text-slate-400 mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span>{t('threatRadar.subtitle')}</span>
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

        <div className="flex flex-wrap items-center gap-4 shrink-0">
          <div className="flex items-center gap-2 text-xs tabular-nums">
            {landscape.overallScore >= 50 ? (
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <span className="text-slate-400">{t('threatRadar.compositeIndex')}</span>
            <span className="font-mono font-semibold text-slate-100">
              {landscape.overallScore} / 100
            </span>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('incidents')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('threatRadar.incidentsLink')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="p-5">
        {!landscape.hasSignals ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-center space-y-2.5">
            <p className="text-sm font-medium text-slate-200">{t('threatRadar.emptyTitle')}</p>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              {t('threatRadar.emptyHint')}
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
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
            {/* Left: Recharts Radar Chart */}
            <div className="lg:col-span-5 rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="font-medium text-slate-200">
                  {t('threatRadar.chartHeading')}
                </span>
                {highestAxisLabel && (
                  <span className="text-[11px] text-slate-400 tabular-nums">
                    {t('threatRadar.topVector', { axis: highestAxisLabel })}
                  </span>
                )}
              </div>

              <div className="w-full min-w-0 h-[290px]">
                <ResponsiveContainer width="100%" height={290}>
                  <RadarChart cx="50%" cy="50%" outerRadius="72%" data={radarData}>
                    <PolarGrid stroke="#1e293b" />
                    <PolarAngleAxis
                      dataKey="axisLabel"
                      tick={{ fill: '#cbd5e1', fontSize: 11 }}
                    />
                    <PolarRadiusAxis
                      angle={90}
                      domain={[0, 100]}
                      tickCount={5}
                      tick={{ fill: '#64748b', fontSize: 10 }}
                      axisLine={false}
                    />
                    <Tooltip trigger="hover" content={<ThreatRadarTooltip />} />
                    <Radar
                      name={t('threatRadar.activeRiskSeries')}
                      dataKey="score"
                      stroke="#f87171"
                      strokeWidth={2}
                      fill="#ef4444"
                      fillOpacity={0.28}
                      dot={{ r: 3, fill: '#f87171' }}
                      activeDot={{ r: 5, strokeWidth: 1.5, stroke: '#0B1120', fill: '#f87171' }}
                      isAnimationActive={false}
                    />
                    <Radar
                      name={t('threatRadar.mitigatedSeries')}
                      dataKey="mitigatedScore"
                      stroke="#34d399"
                      strokeWidth={1.75}
                      strokeDasharray="4 3"
                      fill="#10b981"
                      fillOpacity={0.14}
                      activeDot={{ r: 4, strokeWidth: 1.5, stroke: '#0B1120', fill: '#34d399' }}
                      isAnimationActive={false}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-5 pt-1 text-[11px] text-slate-300 border-t border-slate-800/80">
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-red-400" aria-hidden="true" />
                  <span>{t('threatRadar.activeRiskLegend')}</span>
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400" aria-hidden="true" />
                  <span>{t('threatRadar.mitigatedLegend')}</span>
                </span>
              </div>
            </div>

            {/* Right: 5-Vector Breakdown List */}
            <div className="lg:col-span-7 rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800/80 flex items-center justify-between text-xs">
                <span className="font-medium text-slate-200">
                  {t('threatRadar.breakdownTitle')}
                </span>
                <span className="text-slate-400 tabular-nums">
                  {t('threatRadar.totalSignalsCount', {
                    count: landscape.totalSignals.toLocaleString(locale),
                  })}
                </span>
              </div>

              <div className="divide-y divide-slate-800/70">
                {radarData.map((axis) => {
                  const colors = getLevelColors(axis.level);
                  const targetTab = AXIS_TARGET_TAB[axis.id];
                  return (
                    <div
                      key={axis.id}
                      className="px-4 py-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between hover:bg-slate-900/60 transition-colors"
                    >
                      <div className="min-w-0 space-y-1 flex-1">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
                          <span className="font-medium text-slate-100">{axis.axisLabel}</span>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className={`font-medium ${colors.textClass}`}>
                            {axis.levelLabel}
                          </span>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="text-slate-400 tabular-nums">
                            {t('threatRadar.signalsCompact', {
                              active: axis.activeSignals.toLocaleString(locale),
                              mitigated: axis.mitigatedSignals.toLocaleString(locale),
                            })}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 truncate">
                          {axis.topEvidence || t('threatRadar.noActiveVectorEvidence')}
                        </p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${colors.barClass}`}
                            style={{ width: `${Math.max(axis.score > 0 ? 6 : 0, axis.score)}%` }}
                          />
                        </div>
                        <span className="font-mono text-xs font-semibold text-slate-100 tabular-nums w-14 text-right">
                          {axis.score} / 100
                        </span>
                        <button
                          type="button"
                          onClick={() => onNavigate(targetTab)}
                          className="text-[11px] font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap cursor-pointer"
                        >
                          {t('threatRadar.inspectAxis')}
                        </button>
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
