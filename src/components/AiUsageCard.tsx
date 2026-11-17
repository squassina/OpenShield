import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Coins,
  Cpu,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getIntlLocale } from '../i18n';
import { useTheme } from '../lib/theme';
import type { AiUsageRecord } from '../types/openshield';
import { PaginationControls, usePagination } from './PaginationControls';

type UsageFilter = 'all' | 'local' | 'cloud';

interface ProviderChartRow {
  name: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  calls: number;
  avgLatencyMs: number;
  costUsd: number;
}

interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ payload?: ProviderChartRow }>;
}

function formatUsd(amount: number, lang: string): string {
  const isEn = lang === 'en';
  if (amount <= 0) return isEn ? '$0.00' : 'US$ 0,00';
  if (amount < 0.01) return isEn ? `$${amount.toFixed(5)}` : `US$ ${amount.toFixed(5)}`;
  return isEn ? `$${amount.toFixed(3)}` : `US$ ${amount.toFixed(3)}`;
}

function formatNumber(n: number, locale: string): string {
  return n.toLocaleString(locale);
}

function UsageBarTooltip({ active, payload }: ChartTooltipProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  if (!active || !payload || payload.length === 0) return null;
  const row = payload[0]?.payload;
  if (!row) return null;

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#0B1120] px-3 py-2.5 shadow-lg text-xs space-y-1.5 min-w-[190px]">
      <div className="font-semibold text-slate-900 dark:text-slate-100">{row.name}</div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-600 dark:text-slate-400">{t('aiUsage.tooltipCalls')}</span>
        <span className="font-mono text-slate-900 dark:text-slate-200">{row.calls}</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-600 dark:text-slate-400">{t('aiUsage.tooltipPrompt')}</span>
        <span className="font-mono text-teal-700 dark:text-teal-400">
          {formatNumber(row.promptTokens, locale)}
        </span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-600 dark:text-slate-400">{t('aiUsage.tooltipCompletion')}</span>
        <span className="font-mono text-emerald-700 dark:text-emerald-400">
          {formatNumber(row.completionTokens, locale)}
        </span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums border-t border-slate-200 dark:border-slate-800 pt-1">
        <span className="text-slate-600 dark:text-slate-400">{t('aiUsage.tooltipLatency')}</span>
        <span className="font-mono text-slate-900 dark:text-slate-200">{row.avgLatencyMs} ms</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-600 dark:text-slate-400">{t('aiUsage.tooltipCost')}</span>
        <span className="font-mono text-amber-700 dark:text-amber-300">
          {formatUsd(row.costUsd, i18n.language)}
        </span>
      </div>
    </div>
  );
}

interface AiUsageCardProps {
  records: AiUsageRecord[];
}

export function AiUsageCard({ records }: AiUsageCardProps) {
  const { t, i18n } = useTranslation();
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const locale = getIntlLocale(i18n.language);
  const [filter, setFilter] = useState<UsageFilter>('all');

  const gridStroke = isDark ? '#1E293B' : '#E2E8F0';
  const xTickColor = isDark ? '#94A3B8' : '#475569';
  const yTickColor = isDark ? '#64748B' : '#475569';
  const promptFill = isDark ? '#2DD4BF' : '#0D9488';
  const completionFill = isDark ? '#10B981' : '#059669';
  const cursorFill = isDark ? 'rgba(148, 163, 184, 0.08)' : 'rgba(15, 23, 42, 0.05)';

  const stats = useMemo(() => {
    const localRows = records.filter((r) => r.channel === 'local');
    const cloudRows = records.filter((r) => r.channel === 'cloud');

    const sumTokens = (rows: AiUsageRecord[]) => ({
      calls: rows.length,
      successCalls: rows.filter((r) => r.outcome === 'success').length,
      prompt: rows.reduce((acc, r) => acc + r.promptTokens, 0),
      completion: rows.reduce((acc, r) => acc + r.completionTokens, 0),
      total: rows.reduce((acc, r) => acc + r.totalTokens, 0),
      avgLatencyMs:
        rows.length > 0
          ? Math.round(rows.reduce((acc, r) => acc + r.durationMs, 0) / rows.length)
          : 0,
      costUsd: rows.reduce((acc, r) => acc + r.estimatedCostUsd, 0),
    });

    const local = sumTokens(localRows);
    const cloud = sumTokens(cloudRows);
    const totalCalls = local.calls + cloud.calls;
    const totalTokens = local.total + cloud.total;
    const localSharePct =
      totalTokens > 0 ? Math.round((local.total / totalTokens) * 100) : totalCalls > 0 ? 100 : 0;

    const chartData: ProviderChartRow[] = [
      {
        name: t('aiUsage.providerLocal'),
        promptTokens: local.prompt,
        completionTokens: local.completion,
        totalTokens: local.total,
        calls: local.calls,
        avgLatencyMs: local.avgLatencyMs,
        costUsd: 0,
      },
      {
        name: t('aiUsage.providerCloud'),
        promptTokens: cloud.prompt,
        completionTokens: cloud.completion,
        totalTokens: cloud.total,
        calls: cloud.calls,
        avgLatencyMs: cloud.avgLatencyMs,
        costUsd: cloud.costUsd,
      },
    ];

    return { local, cloud, totalCalls, totalTokens, localSharePct, chartData };
  }, [records, t]);

  const filteredRecords = useMemo(() => {
    if (filter === 'all') return records;
    return records.filter((r) => r.channel === filter);
  }, [records, filter]);

  const usagePagination = usePagination(filteredRecords, 10, filter);

  return (
    <section
      aria-label={t('aiUsage.ariaLabel')}
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-5"
    >
      {/* Header + Channel Filter */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-base font-semibold text-slate-900 dark:text-slate-100">
            <Coins className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <h2>{t('aiUsage.title')}</h2>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            {t('aiUsage.subtitle')}
          </p>
        </div>

        <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 shrink-0 self-start lg:self-auto">
          {(
            [
              { id: 'all', label: t('aiUsage.filterAll', { count: stats.totalCalls }) },
              { id: 'local', label: t('aiUsage.filterLocal', { count: stats.local.calls }) },
              { id: 'cloud', label: t('aiUsage.filterCloud', { count: stats.cloud.calls }) },
            ] as const
          ).map((item) => {
            const active = filter === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setFilter(item.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* 4 KPI Summary Tiles */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5">
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
            <span>{t('aiUsage.kpiTotalCalls')}</span>
            <Activity className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
          </div>
          <div className="text-xl font-semibold text-slate-900 dark:text-slate-50 font-mono tabular-nums">
            {formatNumber(stats.totalCalls, locale)}
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
            <span className="text-emerald-700 dark:text-emerald-400">
              {t('aiUsage.kpiLocalCount', { count: stats.local.calls })}
            </span>
            <span className="mx-1.5 text-slate-400 dark:text-slate-600">·</span>
            <span className="text-teal-700 dark:text-teal-400">
              {t('aiUsage.kpiCloudCount', { count: stats.cloud.calls })}
            </span>
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
            <span>{t('aiUsage.kpiOllamaTokens')}</span>
            <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="text-xl font-semibold text-emerald-700 dark:text-emerald-300 font-mono tabular-nums">
            {formatNumber(stats.local.total, locale)}
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
            {stats.local.calls > 0
              ? t('aiUsage.kpiOllamaSub', { ms: stats.local.avgLatencyMs })
              : t('aiUsage.kpiOllamaEmpty')}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
            <span>{t('aiUsage.kpiCloudTokens')}</span>
            <Cloud className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
          </div>
          <div className="text-xl font-semibold text-teal-700 dark:text-teal-300 font-mono tabular-nums">
            {formatNumber(stats.cloud.total, locale)}
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
            {stats.cloud.calls > 0
              ? t('aiUsage.kpiCloudSub', {
                  ms: stats.cloud.avgLatencyMs,
                  cost: formatUsd(stats.cloud.costUsd, i18n.language),
                })
              : t('aiUsage.kpiCloudEmpty')}
          </div>
        </div>

        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
            <span>{t('aiUsage.kpiLocalSavings')}</span>
            <span className="font-mono font-semibold text-emerald-700 dark:text-emerald-400 tabular-nums">
              {stats.localSharePct}%
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden flex">
            <div
              className="bg-emerald-500 h-full transition-all"
              style={{ width: `${stats.totalTokens > 0 ? stats.localSharePct : 0}%` }}
            />
            <div
              className="bg-teal-500 h-full transition-all"
              style={{
                width: `${stats.totalTokens > 0 ? 100 - stats.localSharePct : 0}%`,
              }}
            />
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-600 dark:text-slate-400 tabular-nums">
            <span>
              {t('aiUsage.kpiTotalTokens', { count: formatNumber(stats.totalTokens, locale) })}
            </span>
            <span className="font-mono text-amber-700 dark:text-amber-300">
              {formatUsd(stats.cloud.costUsd, i18n.language)}
            </span>
          </div>
        </div>
      </div>

      {records.length === 0 ? (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 p-6 text-center text-xs text-slate-600 dark:text-slate-400">
          {t('aiUsage.emptyMessagePrefix')}{' '}
          <strong className="text-slate-900 dark:text-slate-200">
            {t('aiUsage.emptyActionLocal')}
          </strong>{' '}
          {t('aiUsage.emptyMiddle')}{' '}
          <strong className="text-slate-900 dark:text-slate-200">
            {t('aiUsage.emptyActionCloud')}
          </strong>{' '}
          {t('aiUsage.emptyMessageSuffix')}
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* Comparative Bar Chart */}
          <div className="xl:col-span-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/50 p-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-900 dark:text-slate-200">
                {t('aiUsage.chartTitle')}
              </span>
              <div className="flex items-center gap-3 text-[11px] text-slate-600 dark:text-slate-400">
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-xs bg-teal-600 dark:bg-teal-400 inline-block" />
                  {t('aiUsage.legendPrompt')}
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-xs bg-emerald-600 dark:bg-emerald-400 inline-block" />
                  {t('aiUsage.legendCompletion')}
                </span>
              </div>
            </div>

            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.chartData}
                  margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
                >
                  <CartesianGrid stroke={gridStroke} strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: xTickColor, fontSize: 11 }}
                    axisLine={{ stroke: gridStroke }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: yTickColor, fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip cursor={{ fill: cursorFill }} content={<UsageBarTooltip />} />
                  <Bar
                    dataKey="promptTokens"
                    stackId="tokens"
                    fill={promptFill}
                    radius={[0, 0, 2, 2]}
                    maxBarSize={44}
                  />
                  <Bar
                    dataKey="completionTokens"
                    stackId="tokens"
                    fill={completionFill}
                    radius={[4, 4, 0, 0]}
                    maxBarSize={44}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              {t('aiUsage.chartDisclaimer')}
            </p>
          </div>

          {/* Call & Token Ledger Table */}
          <div className="xl:col-span-8 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-900 dark:text-slate-200">
                {t('aiUsage.ledgerTitle', { count: filteredRecords.length })}
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                {t('aiUsage.ledgerLegend')}
              </span>
            </div>

            <div className="overflow-x-auto max-h-72 overflow-y-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="sticky top-0 bg-slate-100 dark:bg-slate-950 text-[11px] text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">{t('aiUsage.colTime')}</th>
                    <th className="py-2.5 px-3 font-medium">{t('aiUsage.colProvider')}</th>
                    <th className="py-2.5 px-3 font-medium">{t('aiUsage.colIncident')}</th>
                    <th className="py-2.5 px-3 font-medium text-right">
                      {t('aiUsage.colTokensSplit')}
                    </th>
                    <th className="py-2.5 px-3 font-medium text-right">
                      {t('aiUsage.colTotal')}
                    </th>
                    <th className="py-2.5 px-3 font-medium text-right">
                      {t('aiUsage.colLatency')}
                    </th>
                    <th className="py-2.5 px-3 font-medium text-right">
                      {t('aiUsage.colEstCost')}
                    </th>
                    <th className="py-2.5 px-3 font-medium">{t('aiUsage.colStatus')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800/70">
                  {usagePagination.pagedItems.map((row) => (
                    <tr
                      key={row.id}
                      className="hover:bg-slate-100/80 dark:hover:bg-slate-900/50 transition-colors"
                    >
                      <td className="py-2.5 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap tabular-nums">
                        {new Date(row.timestamp).toLocaleString(locale, {
                          day: '2-digit',
                          month: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5 font-medium text-slate-900 dark:text-slate-200 whitespace-nowrap">
                          {row.channel === 'cloud' ? (
                            <Cloud className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400 shrink-0" />
                          ) : (
                            <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                          )}
                          <span>
                            {row.channel === 'cloud'
                              ? t('aiUsage.providerCloud')
                              : t('aiUsage.providerLocal')}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 truncate max-w-[200px]">
                          {row.modelVersion}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div
                          className="text-slate-800 dark:text-slate-200 truncate max-w-[190px]"
                          title={row.incidentTitle}
                        >
                          {row.incidentTitle}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500">
                          {row.incidentId}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-[11px] text-slate-600 dark:text-slate-400 whitespace-nowrap tabular-nums">
                        {formatNumber(row.promptTokens, locale)} /{' '}
                        {formatNumber(row.completionTokens, locale)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono font-semibold text-slate-900 dark:text-slate-100 whitespace-nowrap tabular-nums">
                        {formatNumber(row.totalTokens, locale)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap tabular-nums">
                        {row.durationMs} ms
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono whitespace-nowrap tabular-nums">
                        <span
                          className={
                            row.estimatedCostUsd > 0
                              ? 'text-amber-700 dark:text-amber-300'
                              : 'text-emerald-700 dark:text-emerald-400'
                          }
                        >
                          {formatUsd(row.estimatedCostUsd, i18n.language)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {row.outcome === 'success' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>{t('common.success')}</span>
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1 text-red-700 dark:text-red-400"
                            title={row.detail || t('aiUsage.inferenceErrorFallback')}
                          >
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            <span>{t('common.error')}</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationControls
              page={usagePagination.page}
              pageSize={usagePagination.pageSize}
              totalItems={usagePagination.totalItems}
              totalPages={usagePagination.totalPages}
              onPageChange={usagePagination.setPage}
              onPageSizeChange={usagePagination.setPageSize}
              compact
            />
          </div>
        </div>
      )}
    </section>
  );
}
