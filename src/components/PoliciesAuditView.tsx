import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
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
import { getIntlLocale } from '../i18n';
import { api } from '../lib/api';
import type { AutonomyLevel, WorkspaceState } from '../types/openshield';
import { PaginationControls, usePagination } from './PaginationControls';

interface PoliciesAuditViewProps {
  state: WorkspaceState;
  onTogglePolicy: (id: string, enabled: boolean) => Promise<void>;
  onProposeAction: (incidentId: string, policyId: string, ttlSeconds?: number) => Promise<void>;
  onApproveExecution: (id: string) => Promise<void>;
  onRollbackExecution: (id: string) => Promise<void>;
  onChangeAutonomy: (level: AutonomyLevel) => Promise<void>;
  onTogglePersistentUci?: (enabled: boolean) => Promise<void>;
  busyKey: string | null;
}

const AUTONOMY_LEVELS: AutonomyLevel[] = ['L0', 'L1', 'L2', 'L3'];

export function PoliciesAuditView({
  state,
  onTogglePolicy,
  onProposeAction,
  onApproveExecution,
  onRollbackExecution,
  onChangeAutonomy,
  onTogglePersistentUci,
  busyKey,
}: PoliciesAuditViewProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
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

  const execPagination = usePagination(state.executions, 10);
  const auditPagination = usePagination(filteredAudit, 10, auditFilter);

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
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50 text-balance">
            {t('policies.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400 max-w-2xl">
            {t('policies.subtitle')}
          </p>
        </div>

        {onTogglePersistentUci && (
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none px-3.5 py-2.5 flex items-center gap-3 text-xs shrink-0">
            <div className="min-w-0">
              <div className="font-medium text-slate-900 dark:text-slate-100">{t('policies.uciPersistTitle')}</div>
              <div className="text-[11px] text-slate-600 dark:text-slate-400">{t('policies.uciPersistDesc')}</div>
            </div>
            <button
              type="button"
              disabled={busyKey === 'uci-persist'}
              onClick={() => onTogglePersistentUci(!Boolean(state.context.persistentUciFirewall))}
              className={`px-3 py-1.5 rounded-md font-medium whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 border ${
                state.context.persistentUciFirewall
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-600/20 dark:text-emerald-300 dark:border-emerald-700/50'
                  : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100 dark:bg-slate-900 dark:text-slate-300 dark:border-slate-700 dark:hover:bg-slate-800'
              }`}
            >
              {state.context.persistentUciFirewall ? t('common.enabled') : t('common.disabled')}
            </button>
          </div>
        )}
      </div>

      {/* Autonomy Matrix L0-L3 */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {AUTONOMY_LEVELS.map((level) => {
          const isCurrent = state.context.globalAutonomy === level;
          const title = t(`policies.autonomy.${level}Title`);
          const summary = t(`policies.autonomy.${level}Summary`);
          return (
            <button
              key={level}
              type="button"
              disabled={busyKey === 'context' || (state.context.killSwitchActive && level !== 'L0')}
              onClick={() => onChangeAutonomy(level)}
              className={`text-left rounded-xl border p-4 transition-colors cursor-pointer disabled:opacity-50 shadow-xs dark:shadow-none ${
                isCurrent
                  ? 'border-emerald-600 bg-emerald-50 dark:border-emerald-500 dark:bg-emerald-950/30'
                  : 'border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-[#131C31] dark:hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-semibold">
                <span className={isCurrent ? 'text-emerald-700 dark:text-emerald-400' : 'text-slate-900 dark:text-slate-200'}>{title}</span>
                {isCurrent && <span className="text-emerald-700 dark:text-emerald-400">{t('common.active')}</span>}
              </div>
              <p className="mt-1.5 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">{summary}</p>
            </button>
          );
        })}
      </section>

      {/* Policy Simulator Bar */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4">
        <div className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {t('policies.simulatorTitle')}
          </h2>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            {t('policies.simulatorSubtitle', { level: state.context.globalAutonomy })}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <label className="block space-y-1.5 text-xs">
            <span className="text-slate-700 dark:text-slate-300 font-medium">{t('policies.targetIncident')}</span>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
            >
              {state.incidents.length === 0 ? (
                <option value="">{t('policies.noOpenIncidents')}</option>
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
            <span className="text-slate-700 dark:text-slate-300 font-medium">{t('policies.deterministicPolicy')}</span>
            <select
              value={selectedPolicyId}
              onChange={(e) => setSelectedPolicyId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
            >
              {state.policies.map((pol) => (
                <option key={pol.id} value={pol.id}>
                  {pol.maxAutonomyLevel} · {pol.name}
                </option>
              ))}
            </select>
          </label>

          <label className="block space-y-1.5 text-xs">
            <span className="text-slate-700 dark:text-slate-300 font-medium">{t('policies.expirationTtl')}</span>
            <input
              type="number"
              min={30}
              max={3600}
              value={customTtl}
              onChange={(e) => setCustomTtl(Number(e.target.value))}
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs tabular-nums focus:outline-none focus:border-emerald-500"
            />
          </label>

          <button
            type="button"
            disabled={!selectedIncidentId || !selectedPolicyId || busyKey === `propose-${selectedIncidentId}`}
            onClick={() => onProposeAction(selectedIncidentId, selectedPolicyId, customTtl)}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{t('policies.evaluateExecute')}</span>
          </button>
        </div>
      </section>

      {/* Active Executions & Policies */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Executions with live TTL */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('policies.executionsTitle')}
            </h2>
            <span className="text-xs text-slate-600 dark:text-slate-400 tabular-nums">
              {t('policies.recordsCount', { count: state.executions.length })}
            </span>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800/80 max-h-[420px] overflow-y-auto">
            {execPagination.pagedItems.map((exec) => {
              const remainingSec = exec.expiresAt
                ? Math.max(0, Math.ceil((Date.parse(exec.expiresAt) - nowMs) / 1000))
                : null;

              return (
                <div key={exec.id} className="p-4 space-y-2.5 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2 tabular-nums">
                    <div className="flex items-center gap-2 font-mono text-slate-500 dark:text-slate-400">
                      <span>{exec.id}</span>
                      <span>·</span>
                      <span className="text-slate-800 dark:text-slate-200">{exec.autonomyLevel}</span>
                      <span>·</span>
                      <span
                        className={
                          exec.status === 'verified'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : exec.status === 'awaiting_approval'
                              ? 'text-amber-700 dark:text-amber-400 font-medium'
                              : exec.status === 'aborted_kill_switch'
                                ? 'text-red-700 dark:text-red-400 font-medium'
                                : 'text-slate-700 dark:text-slate-300 font-medium'
                        }
                      >
                        {exec.status === 'verified'
                          ? t('policies.execVerified')
                          : exec.status === 'awaiting_approval'
                            ? t('policies.execAwaitingApproval')
                            : exec.status === 'dry_run'
                              ? t('policies.execDryRun')
                              : exec.status === 'expired'
                                ? t('policies.execExpired')
                                : exec.status === 'rolled_back'
                                  ? t('policies.execRolledBack')
                                  : t('policies.execAborted')}
                      </span>
                    </div>

                    {remainingSec !== null && (exec.status === 'verified' || exec.status === 'active') && (
                      <span className="inline-flex items-center gap-1 font-mono text-amber-700 dark:text-amber-300 tabular-nums">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{t('policies.expiresIn', { sec: remainingSec })}</span>
                      </span>
                    )}
                  </div>

                  <div className="font-medium text-slate-900 dark:text-slate-100">{exec.targetLabel}</div>
                  {exec.enforcementMode && (
                    <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-600 dark:text-slate-400 tabular-nums">
                      <span
                        className={
                          exec.enforcementMode === 'live'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : 'text-amber-700 dark:text-amber-300 font-medium'
                        }
                      >
                        {exec.enforcementMode === 'live'
                          ? t('policies.enforcementLive')
                          : t('policies.enforcementSim')}
                      </span>
                      {exec.ruleRef && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-slate-700 dark:text-slate-300">
                            {t('policies.ruleRefLabel')} {exec.ruleRef}
                          </span>
                        </>
                      )}
                      {exec.persistentUci && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-emerald-700 dark:text-emerald-300">UCI</span>
                        </>
                      )}
                      {exec.reconciledAt && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span className="text-emerald-700 dark:text-emerald-300">
                            {t('policies.reconciledAtLabel', {
                              ts: new Date(exec.reconciledAt).toLocaleTimeString(locale),
                            })}
                          </span>
                        </>
                      )}
                    </div>
                  )}
                  {exec.gatewayResults && exec.gatewayResults.length > 0 && (
                    <div className="rounded-lg border border-slate-200 dark:border-slate-800/90 bg-slate-50 dark:bg-slate-950/60 px-3 py-2 space-y-1">
                      <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                        {t('policies.multiGatewayFanout', { count: exec.gatewayResults.length })}
                      </div>
                      {exec.gatewayResults.map((gw) => (
                        <div
                          key={`${exec.id}-${gw.gatewayId}`}
                          className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono"
                        >
                          <span className="text-slate-800 dark:text-slate-200">{gw.gatewayName}</span>
                          <div className="flex items-center gap-2">
                            {gw.ruleRef && (
                              <span className="text-slate-500 dark:text-slate-400 truncate max-w-[200px]">
                                {gw.ruleRef}
                              </span>
                            )}
                            <span
                              className={
                                gw.status === 'failed'
                                  ? 'text-red-700 dark:text-red-400 font-medium'
                                  : gw.status === 'reconciled'
                                    ? 'text-teal-700 dark:text-teal-300 font-medium'
                                    : gw.status === 'rolled_back'
                                      ? 'text-amber-700 dark:text-amber-300 font-medium'
                                      : 'text-emerald-700 dark:text-emerald-400 font-medium'
                              }
                            >
                              {t(`policies.gwStatus.${gw.status}`)}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  <p className="text-slate-600 dark:text-slate-400">{exec.verificationDetail}</p>

                  <div className="flex items-center gap-2 pt-1">
                    {exec.status === 'awaiting_approval' && (
                      <button
                        type="button"
                        disabled={busyKey === `approve-${exec.id}`}
                        onClick={() => onApproveExecution(exec.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-600 text-white hover:bg-emerald-500 font-medium cursor-pointer disabled:opacity-50"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{t('policies.approveL3')}</span>
                      </button>
                    )}

                    {exec.rollbackAvailable && (
                      <button
                        type="button"
                        disabled={busyKey === `rollback-${exec.id}`}
                        onClick={() => onRollbackExecution(exec.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 font-medium cursor-pointer disabled:opacity-50"
                      >
                        <RotateCcw className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                        <span>{t('policies.rollbackNow')}</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          {state.executions.length > 0 && (
            <PaginationControls
              page={execPagination.page}
              pageSize={execPagination.pageSize}
              totalItems={execPagination.totalItems}
              totalPages={execPagination.totalPages}
              onPageChange={execPagination.setPage}
              onPageSizeChange={execPagination.setPageSize}
              compact
            />
          )}
        </section>

        {/* Policy Rules */}
        <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('policies.rulesTitle')}
            </h2>
            <span className="text-xs text-slate-600 dark:text-slate-400">{t('policies.deterministicGov')}</span>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {state.policies.map((pol) => (
              <div key={pol.id} className="p-4 flex items-start justify-between gap-4 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                    <span className="text-emerald-700 dark:text-emerald-400 font-semibold">{pol.maxAutonomyLevel}</span>
                    <span>·</span>
                    <span>{t('policies.defaultTtl', { sec: pol.defaultTtlSeconds })}</span>
                    <span>·</span>
                    <span>
                      {pol.rollbackSupported
                        ? t('policies.rollbackSupported')
                        : t('policies.noRollback')}
                    </span>
                  </div>
                  <div className="text-sm font-medium text-slate-900 dark:text-slate-100">{pol.name}</div>
                  <p className="text-slate-600 dark:text-slate-400">{pol.description}</p>
                  <div className="text-slate-500">
                    {t('policies.maxScope', { scope: pol.maxScope })}
                  </div>
                </div>

                <button
                  type="button"
                  disabled={busyKey === `policy-${pol.id}`}
                  onClick={() => onTogglePolicy(pol.id, !pol.enabled)}
                  className={`px-3 py-1.5 rounded-md font-medium whitespace-nowrap shrink-0 cursor-pointer border ${
                    pol.enabled
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-600/20 dark:text-emerald-300 dark:border-emerald-700/50'
                      : 'bg-white text-slate-600 border-slate-300 hover:bg-slate-100 dark:bg-slate-900 dark:text-slate-400 dark:border-slate-700'
                  }`}
                >
                  {pol.enabled ? t('common.enabled') : t('common.disabled')}
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Transactional Audit Log & Prometheus Metrics */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('policies.auditSectionTitle')}
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              {[
                { id: 'all', label: t('policies.filterAll') },
                { id: 'success', label: t('policies.filterSuccess') },
                { id: 'denied', label: t('policies.filterDenied') },
                { id: 'simulated', label: t('policies.filterSimulated') },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setAuditFilter(tab.id as typeof auditFilter)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    auditFilter === tab.id
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void handleExportAudit('csv')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>{t('policies.exportCsv')}</span>
            </button>

            <button
              type="button"
              onClick={() => void handleExportAudit('json')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
              <span>JSON</span>
            </button>
          </div>
        </div>

        <div className="m-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0B1120]/40 max-h-[440px] overflow-auto">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 z-10 bg-slate-100 dark:bg-[#0B1120] shadow-[0_1px_0_0_rgb(226,232,240)] dark:shadow-[0_1px_0_0_rgb(30,41,59)]">
              <tr className="text-xs font-medium text-slate-600 dark:text-slate-400">
                <th className="py-2.5 px-4">{t('policies.colTimeUtc')}</th>
                <th className="py-2.5 px-4">{t('policies.colEvent')}</th>
                <th className="py-2.5 px-4">{t('policies.colActorRole')}</th>
                <th className="py-2.5 px-4">{t('policies.colOutcome')}</th>
                <th className="py-2.5 px-4">{t('policies.colDetails')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80 text-xs">
              {auditPagination.pagedItems.map((entry) => (
                <tr key={entry.id} className="h-[40px] hover:bg-slate-100/70 dark:hover:bg-slate-900/40">
                  <td className="px-4 py-2 font-mono text-slate-500 dark:text-slate-400 tabular-nums whitespace-nowrap">
                    {new Date(entry.timestamp).toLocaleTimeString(locale)}
                  </td>
                  <td className="px-4 py-2 font-mono text-slate-900 dark:text-slate-200 whitespace-nowrap">
                    {entry.eventType}
                  </td>
                  <td className="px-4 py-2 text-slate-700 dark:text-slate-300 whitespace-nowrap">
                    {entry.actor} · <span className="text-slate-500 dark:text-slate-400">{entry.role}</span>
                  </td>
                  <td className="px-4 py-2 whitespace-nowrap">
                    <span
                      className={
                        entry.outcome === 'denied'
                          ? 'text-red-700 dark:text-red-400 font-medium'
                          : entry.outcome === 'simulated'
                            ? 'text-amber-700 dark:text-amber-400 font-medium'
                            : 'text-emerald-700 dark:text-emerald-400 font-medium'
                      }
                    >
                      {entry.outcome === 'denied'
                        ? t('common.denied')
                        : entry.outcome === 'simulated'
                          ? t('common.simulated')
                          : t('common.success')}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-700 dark:text-slate-300 max-w-xl">{entry.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationControls
          page={auditPagination.page}
          pageSize={auditPagination.pageSize}
          totalItems={auditPagination.totalItems}
          totalPages={auditPagination.totalPages}
          onPageChange={auditPagination.setPage}
          onPageSizeChange={auditPagination.setPageSize}
        />

        {/* Progressive disclosure for Prometheus /metrics */}
        <div className="px-5 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40 text-xs">
          <details>
            <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 font-medium select-none inline-flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{t('policies.inspectPrometheus')}</span>
            </summary>
            <pre className="mt-3 p-3.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
              {prometheusText || t('policies.loadingMetrics')}
            </pre>
          </details>
        </div>
      </section>

      {state.context.killSwitchActive && (
        <div className="rounded-xl border border-red-200 bg-red-50 dark:border-red-800/60 dark:bg-red-950/20 p-4 flex items-center gap-3 text-xs text-red-900 dark:text-red-200">
          <OctagonAlert className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
          <span>{t('policies.killSwitchBanner')}</span>
        </div>
      )}
    </div>
  );
}
