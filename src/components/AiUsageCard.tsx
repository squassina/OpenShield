import { useMemo, useState } from 'react';
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
import type { AiUsageRecord } from '../types/openshield';

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

function formatUsd(amount: number): string {
  if (amount <= 0) return 'US$ 0,00';
  if (amount < 0.01) return `US$ ${amount.toFixed(5)}`;
  return `US$ ${amount.toFixed(3)}`;
}

function formatNumber(n: number): string {
  return n.toLocaleString('pt-BR');
}

function UsageBarTooltip({ active, payload }: ChartTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const row = payload[0]?.payload;
  if (!row) return null;

  return (
    <div className="rounded-lg border border-slate-700 bg-[#0B1120] px-3 py-2.5 shadow-lg text-xs space-y-1.5 min-w-[190px]">
      <div className="font-semibold text-slate-100">{row.name}</div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-400">Chamadas:</span>
        <span className="font-mono text-slate-200">{row.calls}</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-400">Tokens Prompt:</span>
        <span className="font-mono text-sky-400">{formatNumber(row.promptTokens)}</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-400">Tokens Resposta:</span>
        <span className="font-mono text-emerald-400">{formatNumber(row.completionTokens)}</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums border-t border-slate-800 pt-1">
        <span className="text-slate-400">Latência média:</span>
        <span className="font-mono text-slate-200">{row.avgLatencyMs} ms</span>
      </div>
      <div className="flex items-center justify-between gap-4 tabular-nums">
        <span className="text-slate-400">Custo estimado:</span>
        <span className="font-mono text-amber-300">{formatUsd(row.costUsd)}</span>
      </div>
    </div>
  );
}

interface AiUsageCardProps {
  records: AiUsageRecord[];
}

export function AiUsageCard({ records }: AiUsageCardProps) {
  const [filter, setFilter] = useState<UsageFilter>('all');

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
        name: 'Ollama Local',
        promptTokens: local.prompt,
        completionTokens: local.completion,
        totalTokens: local.total,
        calls: local.calls,
        avgLatencyMs: local.avgLatencyMs,
        costUsd: 0,
      },
      {
        name: 'Cloud Gemini',
        promptTokens: cloud.prompt,
        completionTokens: cloud.completion,
        totalTokens: cloud.total,
        calls: cloud.calls,
        avgLatencyMs: cloud.avgLatencyMs,
        costUsd: cloud.costUsd,
      },
    ];

    return { local, cloud, totalCalls, totalTokens, localSharePct, chartData };
  }, [records]);

  const filteredRecords = useMemo(() => {
    if (filter === 'all') return records;
    return records.filter((r) => r.channel === filter);
  }, [records, filter]);

  return (
    <section
      aria-label="Consumo de IA e Chamadas à API"
      className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5"
    >
      {/* Header + Channel Filter */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-base font-semibold text-slate-100">
            <Coins className="w-4 h-4 text-sky-400 shrink-0" />
            <h2>Consumo de Tokens e Chamadas à API (Ollama Local vs. Cloud Gemini)</h2>
          </div>
          <p className="text-xs text-slate-400">
            Monitore volume de tokens, latência de inferência e custo estimado entre execução local-first e segunda opinião sanitizada na nuvem.
          </p>
        </div>

        <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800 shrink-0 self-start lg:self-auto">
          {(
            [
              { id: 'all', label: `Todos (${stats.totalCalls})` },
              { id: 'local', label: `Ollama Local (${stats.local.calls})` },
              { id: 'cloud', label: `Cloud Gemini (${stats.cloud.calls})` },
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
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
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
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total de Chamadas</span>
            <Activity className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-xl font-semibold text-slate-50 font-mono tabular-nums">
            {formatNumber(stats.totalCalls)}
          </div>
          <div className="text-[11px] text-slate-400 tabular-nums">
            <span className="text-emerald-400">{stats.local.calls} local</span>
            <span className="mx-1.5 text-slate-600">·</span>
            <span className="text-sky-400">{stats.cloud.calls} nuvem</span>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Ollama Local (Tokens)</span>
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-semibold text-emerald-300 font-mono tabular-nums">
            {formatNumber(stats.local.total)}
          </div>
          <div className="text-[11px] text-slate-400 tabular-nums">
            {stats.local.calls > 0
              ? `Média ${stats.local.avgLatencyMs} ms · US$ 0,00`
              : 'Nenhuma chamada local registrada'}
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Cloud Gemini (Tokens)</span>
            <Cloud className="w-3.5 h-3.5 text-sky-400" />
          </div>
          <div className="text-xl font-semibold text-sky-300 font-mono tabular-nums">
            {formatNumber(stats.cloud.total)}
          </div>
          <div className="text-[11px] text-slate-400 tabular-nums">
            {stats.cloud.calls > 0
              ? `Média ${stats.cloud.avgLatencyMs} ms · ${formatUsd(stats.cloud.costUsd)} est.`
              : 'Nenhuma chamada em nuvem registrada'}
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Economia Local-First</span>
            <span className="font-mono font-semibold text-emerald-400 tabular-nums">
              {stats.localSharePct}%
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden flex">
            <div
              className="bg-emerald-500 h-full transition-all"
              style={{ width: `${stats.totalTokens > 0 ? stats.localSharePct : 0}%` }}
            />
            <div
              className="bg-sky-500 h-full transition-all"
              style={{
                width: `${stats.totalTokens > 0 ? 100 - stats.localSharePct : 0}%`,
              }}
            />
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 tabular-nums">
            <span>Total: {formatNumber(stats.totalTokens)} tokens</span>
            <span className="font-mono text-amber-300">{formatUsd(stats.cloud.costUsd)}</span>
          </div>
        </div>
      </div>

      {records.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-6 text-center text-xs text-slate-400">
          Nenhuma chamada de IA registrada neste workspace ainda. Execute <strong className="text-slate-200">Investigar Local-First</strong> ou <strong className="text-slate-200">Segunda Opinião Nuvem</strong> em um incidente para acompanhar tokens, latência e custo.
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
          {/* Comparative Bar Chart */}
          <div className="xl:col-span-4 rounded-lg border border-slate-800 bg-slate-950/50 p-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">Comparativo de Tokens</span>
              <div className="flex items-center gap-3 text-[11px] text-slate-400">
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-xs bg-sky-400 inline-block" />
                  Prompt
                </span>
                <span className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-xs bg-emerald-400 inline-block" />
                  Resposta
                </span>
              </div>
            </div>

            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={stats.chartData}
                  margin={{ top: 8, right: 8, left: -16, bottom: 0 }}
                >
                  <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#94A3B8', fontSize: 11 }}
                    axisLine={{ stroke: '#1E293B' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: '#64748B', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(148, 163, 184, 0.08)' }}
                    content={<UsageBarTooltip />}
                  />
                  <Bar
                    dataKey="promptTokens"
                    stackId="tokens"
                    fill="#38BDF8"
                    radius={[0, 0, 2, 2]}
                    maxBarSize={44}
                  />
                  <Bar
                    dataKey="completionTokens"
                    stackId="tokens"
                    fill="#10B981"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={44}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Estimativa em USD calculada sobre tokens de entrada/saída na nuvem (tier Flash referencial). Chamadas Ollama executam localmente sem cobrança externa.
            </p>
          </div>

          {/* Call & Token Ledger Table */}
          <div className="xl:col-span-8 rounded-lg border border-slate-800 bg-slate-950/50 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">
                Histórico de Chamadas ({filteredRecords.length})
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                prompt + resposta = total tokens
              </span>
            </div>

            <div className="overflow-x-auto max-h-72 overflow-y-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="sticky top-0 bg-slate-950 text-[11px] text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">Horário</th>
                    <th className="py-2.5 px-3 font-medium">Provedor / Modelo</th>
                    <th className="py-2.5 px-3 font-medium">Incidente</th>
                    <th className="py-2.5 px-3 font-medium text-right">Tokens (E/S)</th>
                    <th className="py-2.5 px-3 font-medium text-right">Total</th>
                    <th className="py-2.5 px-3 font-medium text-right">Latência</th>
                    <th className="py-2.5 px-3 font-medium text-right">Custo Est.</th>
                    <th className="py-2.5 px-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredRecords.map((row) => (
                    <tr key={row.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap tabular-nums">
                        {new Date(row.timestamp).toLocaleString('pt-BR', {
                          day: '2-digit',
                          month: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5 font-medium text-slate-200 whitespace-nowrap">
                          {row.channel === 'cloud' ? (
                            <Cloud className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                          ) : (
                            <Cpu className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          )}
                          <span>{row.channel === 'cloud' ? 'Cloud Gemini' : 'Ollama Local'}</span>
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 truncate max-w-[200px]">
                          {row.modelVersion}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-slate-200 truncate max-w-[190px]" title={row.incidentTitle}>
                          {row.incidentTitle}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500">
                          {row.incidentId}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-[11px] text-slate-400 whitespace-nowrap tabular-nums">
                        {formatNumber(row.promptTokens)} / {formatNumber(row.completionTokens)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono font-semibold text-slate-100 whitespace-nowrap tabular-nums">
                        {formatNumber(row.totalTokens)}
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-slate-300 whitespace-nowrap tabular-nums">
                        {row.durationMs} ms
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono whitespace-nowrap tabular-nums">
                        <span
                          className={
                            row.estimatedCostUsd > 0 ? 'text-amber-300' : 'text-emerald-400'
                          }
                        >
                          {formatUsd(row.estimatedCostUsd)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {row.outcome === 'success' ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>Sucesso</span>
                          </span>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1 text-red-400"
                            title={row.detail || 'Erro na inferência'}
                          >
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            <span>Erro</span>
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
