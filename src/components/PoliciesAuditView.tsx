import { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Clock,
  Download,
  FileText,
  OctagonAlert,
  Play,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../lib/api';
import type { AutonomyLevel, WorkspaceState } from '../types/openshield';

interface PoliciesAuditViewProps {
  state: WorkspaceState;
  onTogglePolicy: (id: string, enabled: boolean) => Promise<void>;
  onProposeAction: (incidentId: string, policyId: string, ttlSeconds?: number) => Promise<void>;
  onApproveExecution: (id: string) => Promise<void>;
  onRollbackExecution: (id: string) => Promise<void>;
  onChangeAutonomy: (level: AutonomyLevel) => Promise<void>;
  busyKey: string | null;
}

const AUTONOMY_INFO: { level: AutonomyLevel; title: string; summary: string }[] = [
  { level: 'L0', title: 'L0 · Observar', summary: 'Coleta, correlaciona e simula sem aplicar mudanças.' },
  { level: 'L1', title: 'L1 · Baixo Impacto', summary: 'Aplica automaticamente bloqueios DNS pré-autorizados.' },
  { level: 'L2', title: 'L2 · Contenção Limitada', summary: 'Contém portas/destinos dentro de escopo e TTL estritos.' },
  { level: 'L3', title: 'L3 · Aprovação Humana', summary: 'Ações amplas ou críticas exigem confirmação explícita.' },
];

export function PoliciesAuditView({
  state,
  onTogglePolicy,
  onProposeAction,
  onApproveExecution,
  onRollbackExecution,
  onChangeAutonomy,
  busyKey,
}: PoliciesAuditViewProps) {
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [auditFilter, setAuditFilter] = useState<'all' | 'success' | 'denied' | 'simulated'>('all');
  const [selectedIncidentId, setSelectedIncidentId] = useState(state.incidents[0]?.id ?? '');
  const [selectedPolicyId, setSelectedPolicyId] = useState(state.policies[0]?.id ?? '');
  const [customTtl, setCustomTtl] = useState(45);
  const [prometheusText, setPrometheusText] = useState<string>('');

  useEffect(() => {
    const timer = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (state.incidents.length === 0) {
      if (selectedIncidentId !== '') setSelectedIncidentId('');
    } else if (!state.incidents.some((inc) => inc.id === selectedIncidentId)) {
      setSelectedIncidentId(state.incidents[0].id);
    }
  }, [state.incidents, selectedIncidentId]);

  useEffect(() => {
    api.getMetricsText().then(setPrometheusText).catch(() => {});
  }, [state.metrics.httpRequestsTotal, state.metrics.eventsIngestedTotal]);

  const filteredAudit = useMemo(() => {
    if (auditFilter === 'all') return state.auditLog;
    return state.auditLog.filter((a) => a.outcome === auditFilter);
  }, [state.auditLog, auditFilter]);

  const handleExportAudit = async (format: 'json' | 'csv') => {
    const { entries } = await api.getAuditLog(500);
    const list =
      auditFilter === 'all' ? entries : entries.filter((item) => item.outcome === auditFilter);

    let content = '';
    let mime = 'application/json';
    if (format === 'json') {
      content = JSON.stringify({ exportedAt: new Date().toISOString(), count: list.length, entries: list }, null, 2);
    } else {
      mime = 'text/csv;charset=utf-8';
      const esc = (v: string) => `"${String(v).replace(/"/g, '""')}"`;
      const header = ['id', 'timestamp', 'eventType', 'actor', 'role', 'targetId', 'outcome', 'profile', 'detail'].join(',');
      const rows = list.map((e) =>
        [e.id, e.timestamp, e.eventType, e.actor, e.role, e.targetId, e.outcome, e.profile, e.detail]
          .map(esc)
          .join(','),
      );
      content = [header, ...rows].join('\n');
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `openshield-audit-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            Políticas Autônomas, Rollback e Auditoria
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            Motor determinístico com níveis L0–L3, expiração automática por TTL, verificação obrigatória e registro transacional de auditoria.
          </p>
        </div>
      </div>

      {/* Autonomy Matrix L0-L3 */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {AUTONOMY_INFO.map((item) => {
          const isCurrent = state.context.globalAutonomy === item.level;
          return (
            <button
              key={item.level}
              type="button"
              disabled={busyKey === 'context' || (state.context.killSwitchActive && item.level !== 'L0')}
              onClick={() => onChangeAutonomy(item.level)}
              className={`text-left rounded-xl border p-4 transition-colors cursor-pointer disabled:opacity-50 ${
                isCurrent
                  ? 'border-blue-500 bg-blue-950/30'
                  : 'border-slate-800 bg-[#131C31] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-semibold">
                <span className={isCurrent ? 'text-blue-400' : 'text-slate-200'}>{item.title}</span>
                {isCurrent && <span className="text-blue-400">Ativo</span>}
              </div>
              <p className="mt-1.5 text-xs text-slate-400 leading-relaxed">{item.summary}</p>
            </button>
          );
        })}
      </section>

      {/* Policy Simulator Bar */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-slate-100">
            Simulador de Execução Governada por Política (TTL & Rollback)
          </h2>
          <p className="text-xs text-slate-400">
            Selecione um incidente e uma política para testar a avaliação determinística no nível de autonomia atual ({state.context.globalAutonomy}).
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <label className="block space-y-1.5 text-xs">
            <span className="text-slate-300 font-medium">Incidente Alvo</span>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs"
            >
              {state.incidents.length === 0 ? (
                <option value="">Nenhum incidente aberto</option>
              ) : (
                state.incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.deviceHostname} · {inc.id}
                  </option>
                ))
              )}
            </select>
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="text-slate-300 font-medium">Política Determinística</span>
            <select
              value={selectedPolicyId}
              onChange={(e) => setSelectedPolicyId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs"
            >
              {state.policies.map((pol) => (
                <option key={pol.id} value={pol.id}>
                  {pol.maxAutonomyLevel} · {pol.name}
                </option>
              ))}
            </select>
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="text-slate-300 font-medium">TTL de Expiração (segundos)</span>
            <input
              type="number"
              min={30}
              max={3600}
              value={customTtl}
              onChange={(e) => setCustomTtl(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs tabular-nums"
            />
          </label>

          <button
            type="button"
            disabled={!selectedIncidentId || !selectedPolicyId || busyKey === `propose-${selectedIncidentId}`}
            onClick={() => onProposeAction(selectedIncidentId, selectedPolicyId, customTtl)}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Avaliar e Executar</span>
          </button>
        </div>
      </section>

      {/* Active Executions & Policies */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Executions with live TTL */}
        <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Execuções, Verificação e Rollback
            </h2>
            <span className="text-xs text-slate-400 tabular-nums">
              {state.executions.length} registros
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {state.executions.map((exec) => {
              const remainingSec = exec.expiresAt
                ? Math.max(0, Math.ceil((Date.parse(exec.expiresAt) - nowMs) / 1000))
                : null;

              return (
                <div key={exec.id} className="p-4 space-y-2.5 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2 tabular-nums">
                    <div className="flex items-center gap-2 font-mono text-slate-400">
                      <span>{exec.id}</span>
                      <span>·</span>
                      <span className="text-slate-200">{exec.autonomyLevel}</span>
                      <span>·</span>
                      <span
                        className={
                          exec.status === 'verified'
                            ? 'text-emerald-400 font-medium'
                            : exec.status === 'awaiting_approval'
                              ? 'text-amber-400 font-medium'
                              : exec.status === 'aborted_kill_switch'
                                ? 'text-red-400 font-medium'
                                : 'text-slate-300 font-medium'
                        }
                      >
                        {exec.status === 'verified'
                          ? 'Verificado'
                          : exec.status === 'awaiting_approval'
                            ? 'Aguardando Aprovação L3'
                            : exec.status === 'dry_run'
                              ? 'Simulação L0'
                              : exec.status === 'expired'
                                ? 'Expirado por TTL'
                                : exec.status === 'rolled_back'
                                  ? 'Revertido (Rollback)'
                                  : 'Abortado (Kill Switch)'}
                      </span>
                    </div>

                    {remainingSec !== null && (exec.status === 'verified' || exec.status === 'active') && (
                      <span className="inline-flex items-center gap-1 font-mono text-amber-300 tabular-nums">
                        <Clock className="w-3.5 h-3.5" />
                        <span>Expira em {remainingSec}s</span>
                      </span>
                    )}
                  </div>

                  <div className="font-medium text-slate-100">{exec.targetLabel}</div>
                  <p className="text-slate-400">{exec.verificationDetail}</p>

                  <div className="flex items-center gap-2 pt-1">
                    {exec.status === 'awaiting_approval' && (
                      <button
                        type="button"
                        disabled={busyKey === `approve-${exec.id}`}
                        onClick={() => onApproveExecution(exec.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 text-white hover:bg-blue-500 font-medium cursor-pointer disabled:opacity-50"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Aprovar Execução L3</span>
                      </button>
                    )}

                    {exec.rollbackAvailable && (
                      <button
                        type="button"
                        disabled={busyKey === `rollback-${exec.id}`}
                        onClick={() => onRollbackExecution(exec.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 font-medium cursor-pointer disabled:opacity-50"
                      >
                        <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
                        <span>Reverter Agora (Rollback)</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Policy Rules */}
        <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Regras de Política Autorizadas
            </h2>
            <span className="text-xs text-slate-400">Governança Determinística</span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {state.policies.map((pol) => (
              <div key={pol.id} className="p-4 flex items-start justify-between gap-4 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 font-mono text-slate-400 tabular-nums">
                    <span className="text-blue-400 font-semibold">{pol.maxAutonomyLevel}</span>
                    <span>·</span>
                    <span>TTL padrão {pol.defaultTtlSeconds}s</span>
                    <span>·</span>
                    <span>{pol.rollbackSupported ? 'Rollback suportado' : 'Sem rollback'}</span>
                  </div>
                  <div className="text-sm font-medium text-slate-100">{pol.name}</div>
                  <p className="text-slate-400">{pol.description}</p>
                  <div className="text-slate-500">Escopo máximo: {pol.maxScope}</div>
                </div>

                <button
                  type="button"
                  disabled={busyKey === `policy-${pol.id}`}
                  onClick={() => onTogglePolicy(pol.id, !pol.enabled)}
                  className={`px-3 py-1.5 rounded-md font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                    pol.enabled
                      ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-700/50'
                      : 'bg-slate-900 text-slate-400 border border-slate-700'
                  }`}
                >
                  {pol.enabled ? 'Habilitada' : 'Desabilitada'}
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Transactional Audit Log & Prometheus Metrics */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-slate-100">
              Trilha de Auditoria Transacional (Audit Log)
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800">
              {[
                { id: 'all', label: 'Todos' },
                { id: 'success', label: 'Sucesso' },
                { id: 'denied', label: 'Negados' },
                { id: 'simulated', label: 'Simulados' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setAuditFilter(tab.id as typeof auditFilter)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    auditFilter === tab.id ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void handleExportAudit('csv')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span>Exportar CSV</span>
            </button>

            <button
              type="button"
              onClick={() => void handleExportAudit('json')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>JSON</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-medium text-slate-400 bg-slate-900/50">
                <th className="py-2.5 px-4">Horário (UTC)</th>
                <th className="py-2.5 px-4">Evento</th>
                <th className="py-2.5 px-4">Ator / Papel</th>
                <th className="py-2.5 px-4">Resultado</th>
                <th className="py-2.5 px-4">Detalhes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-xs">
              {filteredAudit.slice(0, 20).map((entry) => (
                <tr key={entry.id} className="h-[40px] hover:bg-slate-900/40">
                  <td className="px-4 py-2 font-mono text-slate-400 tabular-nums whitespace-nowrap">
                    {new Date(entry.timestamp).toLocaleTimeString('pt-BR')}
                  </td>
                  <td className="px-4 py-2 font-mono text-slate-200 whitespace-nowrap">
                    {entry.eventType}
                  </td>
                  <td className="px-4 py-2 text-slate-300 whitespace-nowrap">
                    {entry.actor} · <span className="text-slate-400">{entry.role}</span>
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap">
                    <span
                      className={
                        entry.outcome === 'denied'
                          ? 'text-red-400 font-medium'
                          : entry.outcome === 'simulated'
                            ? 'text-amber-400 font-medium'
                            : 'text-emerald-400 font-medium'
                      }
                    >
                      {entry.outcome === 'denied'
                        ? 'Negado'
                        : entry.outcome === 'simulated'
                          ? 'Simulado'
                          : 'Sucesso'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-300 max-w-xl">{entry.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Progressive disclosure for Prometheus /metrics */}
        <div className="px-5 py-3.5 border-t border-slate-800 bg-slate-950/40 text-xs">
          <details>
            <summary className="cursor-pointer text-blue-400 hover:text-blue-300 font-medium select-none inline-flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Inspecionar endpoint de métricas Prometheus (/metrics)</span>
            </summary>
            <pre className="mt-3 p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
              {prometheusText || 'Carregando métricas operacionais...'}
            </pre>
          </details>
        </div>
      </section>

      {state.context.killSwitchActive && (
        <div className="rounded-xl border border-red-800/60 bg-red-950/20 p-4 flex items-center gap-3 text-xs text-red-200">
          <OctagonAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span>
            Kill Switch ativo: todas as execuções automatizadas permanecem suspensas em L0. Use o botão no topo para liberar após revisão.
          </span>
        </div>
      )}
    </div>
  );
}
