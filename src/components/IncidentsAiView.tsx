import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  CheckCircle2,
  Cloud,
  Cpu,
  Gauge,
  Lock,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';
import type {
  AiSensitivityConfig,
  EventSeverity,
  Incident,
  SensitivityPreset,
  WorkspaceState,
} from '../types/openshield';
import { getIntlLocale } from '../i18n';
import { AiUsageCard } from './AiUsageCard';
import { PaginationControls, usePagination } from './PaginationControls';

const SENSITIVITY_PRESETS: Record<
  Exclude<SensitivityPreset, 'customizado'>,
  AiSensitivityConfig
> = {
  conservador: {
    preset: 'conservador',
    minRiskScoreAlert: 70,
    dnsBurstThresholdPerMin: 250,
    latencySpikeFactor: 3.5,
    flagLowSeverityEvents: false,
  },
  balanceado: {
    preset: 'balanceado',
    minRiskScoreAlert: 50,
    dnsBurstThresholdPerMin: 120,
    latencySpikeFactor: 2.5,
    flagLowSeverityEvents: false,
  },
  agressivo: {
    preset: 'agressivo',
    minRiskScoreAlert: 30,
    dnsBurstThresholdPerMin: 50,
    latencySpikeFactor: 1.8,
    flagLowSeverityEvents: true,
  },
};

const DEFAULT_SENSITIVITY: AiSensitivityConfig = {
  preset: 'balanceado',
  minRiskScoreAlert: 50,
  dnsBurstThresholdPerMin: 120,
  latencySpikeFactor: 2.5,
  flagLowSeverityEvents: false,
};

const SEVERITY_BADGE_STYLES: Record<
  EventSeverity,
  { badgeClass: string; dotClass: string }
> = {
  critical: {
    badgeClass:
      'border-red-200 bg-red-50 text-red-800 dark:border-red-500/45 dark:bg-red-500/15 dark:text-red-300',
    dotClass: 'bg-red-500 dark:bg-red-400',
  },
  high: {
    badgeClass:
      'border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-500/45 dark:bg-orange-500/15 dark:text-orange-300',
    dotClass: 'bg-orange-500 dark:bg-orange-400',
  },
  medium: {
    badgeClass:
      'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-500/45 dark:bg-amber-500/15 dark:text-amber-300',
    dotClass: 'bg-amber-500 dark:bg-amber-400',
  },
  low: {
    badgeClass:
      'border-teal-200 bg-teal-50 text-teal-800 dark:border-teal-500/45 dark:bg-teal-500/15 dark:text-teal-300',
    dotClass: 'bg-teal-500 dark:bg-teal-400',
  },
  info: {
    badgeClass:
      'border-slate-300 bg-slate-100 text-slate-700 dark:border-slate-600/70 dark:bg-slate-800/80 dark:text-slate-300',
    dotClass: 'bg-slate-500 dark:bg-slate-400',
  },
};

function SeverityBadge({
  severity,
  label,
  prefix,
}: {
  severity: EventSeverity;
  label: string;
  prefix: string;
}) {
  const styles = SEVERITY_BADGE_STYLES[severity] ?? SEVERITY_BADGE_STYLES.info;
  return (
    <span
      data-severity={severity}
      aria-label={`${prefix}: ${label}`}
      title={`${prefix}: ${label}`}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold tracking-tight whitespace-nowrap shrink-0 ${styles.badgeClass}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full shrink-0 ${styles.dotClass}`}
        aria-hidden="true"
      />
      <span>{label}</span>
    </span>
  );
}

interface IncidentsAiViewProps {
  state: WorkspaceState;
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onInvestigate: (incidentId: string, mode: 'local' | 'cloud_gemini') => Promise<void>;
  onToggleCloudOptIn: (enabled: boolean) => Promise<void>;
  onUpdateSensitivity: (config: AiSensitivityConfig) => Promise<void>;
  onProposeAction: (incidentId: string, policyId: string) => Promise<void>;
  onUpdateStatus: (incidentId: string, status: Incident['status']) => Promise<void>;
  busyKey: string | null;
}

export function IncidentsAiView({
  state,
  selectedIncidentId,
  onSelectIncident,
  onInvestigate,
  onToggleCloudOptIn,
  onUpdateSensitivity,
  onProposeAction,
  onUpdateStatus,
  busyKey,
}: IncidentsAiViewProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const activeIncident =
    state.incidents.find((i) => i.id === selectedIncidentId) ?? state.incidents[0] ?? null;
  const incidentsPagination = usePagination(state.incidents, 10);
  const timelinePagination = usePagination(
    activeIncident?.timeline ?? [],
    10,
    activeIncident?.id ?? '',
  );

  const currentSensitivity = state.context.aiSensitivity ?? DEFAULT_SENSITIVITY;
  const [sensitivityDraft, setSensitivityDraft] =
    useState<AiSensitivityConfig>(currentSensitivity);
  const [ttlNote, setTtlNote] = useState('900s');

  useEffect(() => {
    setSensitivityDraft(currentSensitivity);
  }, [
    currentSensitivity.preset,
    currentSensitivity.minRiskScoreAlert,
    currentSensitivity.dnsBurstThresholdPerMin,
    currentSensitivity.latencySpikeFactor,
    currentSensitivity.flagLowSeverityEvents,
  ]);

  useEffect(() => {
    if (activeIncident) {
      const pol = state.policies.find((p) => p.id === activeIncident.recommendedPolicyId);
      if (pol) setTtlNote(`${pol.defaultTtlSeconds}s`);
    }
  }, [activeIncident, state.policies]);

  const hasPendingSensitivity =
    sensitivityDraft.preset !== currentSensitivity.preset ||
    sensitivityDraft.minRiskScoreAlert !== currentSensitivity.minRiskScoreAlert ||
    sensitivityDraft.dnsBurstThresholdPerMin !== currentSensitivity.dnsBurstThresholdPerMin ||
    sensitivityDraft.latencySpikeFactor !== currentSensitivity.latencySpikeFactor ||
    sensitivityDraft.flagLowSeverityEvents !== currentSensitivity.flagLowSeverityEvents;

  const isSavingSensitivity = busyKey === 'ai-sensitivity';

  const applyPreset = async (presetKey: Exclude<SensitivityPreset, 'customizado'>) => {
    const presetConfig = SENSITIVITY_PRESETS[presetKey];
    const next: AiSensitivityConfig = {
      preset: presetConfig.preset,
      minRiskScoreAlert: presetConfig.minRiskScoreAlert,
      dnsBurstThresholdPerMin: presetConfig.dnsBurstThresholdPerMin,
      latencySpikeFactor: presetConfig.latencySpikeFactor,
      flagLowSeverityEvents: presetConfig.flagLowSeverityEvents,
    };
    setSensitivityDraft(next);
    await onUpdateSensitivity(next);
  };

  const aggressivityMeta =
    sensitivityDraft.minRiskScoreAlert <= 35 || sensitivityDraft.flagLowSeverityEvents
      ? {
          label: t('incidents.modeAggressive'),
          textClass: 'text-amber-700 dark:text-amber-300',
        }
      : sensitivityDraft.minRiskScoreAlert >= 70
        ? {
            label: t('incidents.modeConservative'),
            textClass: 'text-emerald-700 dark:text-emerald-400',
          }
        : {
            label: t('incidents.modeBalanced'),
            textClass: 'text-teal-700 dark:text-teal-400',
          };

  const presetMeta: Record<
    Exclude<SensitivityPreset, 'customizado'>,
    { label: string; hint: string }
  > = {
    conservador: {
      label: t('incidents.presetConservative'),
      hint: t('incidents.presetConservativeHint'),
    },
    balanceado: {
      label: t('incidents.presetBalanced'),
      hint: t('incidents.presetBalancedHint'),
    },
    agressivo: {
      label: t('incidents.presetAggressive'),
      hint: t('incidents.presetAggressiveHint'),
    },
  };

  const relatedEvents = activeIncident
    ? state.events.filter((e) => activeIncident.eventIds.includes(e.eventId))
    : [];
  const recommendedPolicy = activeIncident
    ? state.policies.find((p) => p.id === activeIncident.recommendedPolicyId)
    : undefined;
  const inv = activeIncident?.investigation;
  const confidenceLabel = inv
    ? inv.confidence === 'alta'
      ? t('incidents.confidenceHigh')
      : inv.confidence === 'média'
        ? t('incidents.confidenceMedium')
        : inv.confidence === 'baixa'
          ? t('incidents.confidenceLow')
          : inv.confidence
    : '';

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50 text-balance">
          {t('incidents.title')}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400 max-w-2xl">
          {t('incidents.subtitle')}
        </p>
      </div>

      {/* AI Anomaly Sensitivity Thresholds Card */}
      <section
        aria-label={t('incidents.sensitivityTitle')}
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4"
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-base font-semibold text-slate-900 dark:text-slate-100">
              <SlidersHorizontal className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <h2>{t('incidents.sensitivityTitle')}</h2>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              {t('incidents.sensitivitySubtitle')}
            </p>
          </div>

          <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 shrink-0">
            {(['conservador', 'balanceado', 'agressivo'] as const).map((presetKey) => {
              const active = sensitivityDraft.preset === presetKey;
              return (
                <button
                  key={presetKey}
                  type="button"
                  disabled={isSavingSensitivity}
                  onClick={() => applyPreset(presetKey)}
                  title={presetMeta[presetKey].hint}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                    active
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900'
                  }`}
                >
                  {presetMeta[presetKey].label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <label className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-2 block">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-slate-800 dark:text-slate-200">{t('incidents.minRiskLabel')}</span>
              <span className="font-mono font-semibold text-emerald-700 dark:text-emerald-400 tabular-nums">
                {sensitivityDraft.minRiskScoreAlert}/100
              </span>
            </div>
            <input
              type="range"
              min={25}
              max={90}
              step={5}
              value={sensitivityDraft.minRiskScoreAlert}
              onChange={(e) =>
                setSensitivityDraft((prev) => ({
                  ...prev,
                  preset: 'customizado',
                  minRiskScoreAlert: Number(e.target.value),
                }))
              }
              className="w-full accent-emerald-600 dark:accent-emerald-500 cursor-pointer"
            />
            <div className="flex justify-between text-[11px] text-slate-500">
              <span>{t('incidents.minRiskLow')}</span>
              <span>{t('incidents.minRiskHigh')}</span>
            </div>
          </label>

          <label className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-2 block">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-slate-800 dark:text-slate-200">{t('incidents.dnsBurstLabel')}</span>
              <span className="font-mono font-semibold text-emerald-700 dark:text-emerald-400 tabular-nums">
                {t('incidents.dnsBurstValue', {
                  count: sensitivityDraft.dnsBurstThresholdPerMin,
                })}
              </span>
            </div>
            <input
              type="range"
              min={20}
              max={400}
              step={10}
              value={sensitivityDraft.dnsBurstThresholdPerMin}
              onChange={(e) =>
                setSensitivityDraft((prev) => ({
                  ...prev,
                  preset: 'customizado',
                  dnsBurstThresholdPerMin: Number(e.target.value),
                }))
              }
              className="w-full accent-emerald-600 dark:accent-emerald-500 cursor-pointer"
            />
            <div className="flex justify-between text-[11px] text-slate-500">
              <span>{t('incidents.dnsBurstLow')}</span>
              <span>{t('incidents.dnsBurstHigh')}</span>
            </div>
          </label>

          <label className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 p-3.5 space-y-2 block">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium text-slate-800 dark:text-slate-200">{t('incidents.latencySpikeLabel')}</span>
              <span className="font-mono font-semibold text-emerald-700 dark:text-emerald-400 tabular-nums">
                {t('incidents.latencySpikeValue', {
                  factor: sensitivityDraft.latencySpikeFactor.toFixed(1),
                })}
              </span>
            </div>
            <input
              type="range"
              min={1.5}
              max={5.0}
              step={0.1}
              value={sensitivityDraft.latencySpikeFactor}
              onChange={(e) =>
                setSensitivityDraft((prev) => ({
                  ...prev,
                  preset: 'customizado',
                  latencySpikeFactor: Number(e.target.value),
                }))
              }
              className="w-full accent-emerald-600 dark:accent-emerald-500 cursor-pointer"
            />
            <div className="flex justify-between text-[11px] text-slate-500">
              <span>{t('incidents.latencySpikeLow')}</span>
              <span>{t('incidents.latencySpikeHigh')}</span>
            </div>
          </label>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between pt-1 text-xs">
          <label className="inline-flex items-center gap-2.5 text-slate-700 dark:text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={sensitivityDraft.flagLowSeverityEvents}
              onChange={(e) =>
                setSensitivityDraft((prev) => ({
                  ...prev,
                  preset: 'customizado',
                  flagLowSeverityEvents: e.target.checked,
                }))
              }
              className="rounded border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-950 text-emerald-600 focus:ring-emerald-500"
            />
            <span>
              {t('incidents.includeLowPrefix')}
              <span className="font-mono text-slate-900 dark:text-slate-200">low</span>
              {t('incidents.includeLowSuffix')}
            </span>
          </label>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <span className={`inline-flex items-center gap-1.5 font-medium ${aggressivityMeta.textClass}`}>
              <Gauge className="w-3.5 h-3.5 shrink-0" />
              <span>{aggressivityMeta.label}</span>
              <span className="text-slate-400 dark:text-slate-500">·</span>
              <span className="font-mono text-slate-600 dark:text-slate-400">{sensitivityDraft.preset}</span>
            </span>

            {hasPendingSensitivity ? (
              <button
                type="button"
                disabled={isSavingSensitivity}
                onClick={() => onUpdateSensitivity(sensitivityDraft)}
                className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
              >
                {isSavingSensitivity ? t('incidents.applying') : t('incidents.applyRealTime')}
              </button>
            ) : (
              <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium whitespace-nowrap">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{t('incidents.activeInEngine')}</span>
              </span>
            )}
          </div>
        </div>
      </section>

      <AiUsageCard records={state.aiUsageHistory ?? []} />

      {!activeIncident || !inv ? (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-10 text-center text-sm text-slate-600 dark:text-slate-400">
          {t('incidents.emptyIncidents')}
        </div>
      ) : (
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Queue (4 cols) */}
        <section className="xl:col-span-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
          <div className="px-4 py-3.5 border-b border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-800 dark:text-slate-300">
            {t('incidents.queueTitle', { count: state.incidents.length })}
          </div>
          <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-[540px] overflow-y-auto">
            {incidentsPagination.pagedItems.map((inc) => {
              const isSelected = inc.id === activeIncident.id;
              return (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => onSelectIncident(inc.id)}
                  className={`w-full text-left p-4 transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-emerald-50 dark:bg-emerald-950/30 border-l-2 border-l-emerald-600 dark:border-l-emerald-400'
                      : 'hover:bg-slate-50 dark:hover:bg-slate-900/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 text-xs tabular-nums">
                    <div className="flex items-center gap-2 min-w-0">
                      <SeverityBadge
                        severity={inc.severity}
                        label={t(`incidents.severity.${inc.severity}`)}
                        prefix={t('incidents.severityLabel')}
                      />
                      <span className="text-slate-700 dark:text-slate-300 font-medium whitespace-nowrap">
                        {inc.riskScore}/100
                      </span>
                    </div>
                    <span className="text-slate-500 dark:text-slate-400 font-mono truncate">{inc.deviceHostname}</span>
                  </div>
                  <div className="mt-1.5 text-sm font-medium text-slate-900 dark:text-slate-100 leading-snug">
                    {inc.title}
                  </div>
                  <div className="mt-1.5 text-xs text-slate-600 dark:text-slate-400">
                    <span>
                      {t('incidents.stateLabel')}{' '}
                      {inc.status === 'contained'
                        ? t('incidents.statusContained')
                        : inc.status === 'false_positive'
                          ? t('incidents.statusFalsePositive')
                          : inc.status === 'resolved'
                            ? t('incidents.statusResolved')
                            : inc.status === 'investigating'
                              ? t('incidents.statusInvestigating')
                              : t('incidents.statusOpen')}
                    </span>
                    <span className="mx-1.5 text-slate-400 dark:text-slate-600">·</span>
                    <span className={inc.dataSource === 'live' ? 'text-emerald-700 dark:text-emerald-400 font-medium' : 'text-slate-500 dark:text-slate-400'}>
                      {inc.dataSource === 'live'
                        ? t('incidents.sourceReal')
                        : t('incidents.sourceSimulated')}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
          <PaginationControls
            page={incidentsPagination.page}
            pageSize={incidentsPagination.pageSize}
            totalItems={incidentsPagination.totalItems}
            totalPages={incidentsPagination.totalPages}
            onPageChange={incidentsPagination.setPage}
            onPageSizeChange={incidentsPagination.setPageSize}
            compact
          />
        </section>

        {/* Right Investigation & Policy Trigger (8 cols) */}
        <section className="xl:col-span-8 space-y-6">
          {/* Incident Header + Evidence Timeline */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 font-mono tabular-nums">
                  <SeverityBadge
                    severity={activeIncident.severity}
                    label={t(`incidents.severity.${activeIncident.severity}`)}
                    prefix={t('incidents.severityLabel')}
                  />
                  <span>{activeIncident.id}</span>
                  <span>·</span>
                  <span>{activeIncident.deviceHostname}</span>
                  <span>·</span>
                  <span>{t('common.score')} {activeIncident.riskScore}/100</span>
                  <span>·</span>
                  <span className={activeIncident.dataSource === 'live' ? 'text-emerald-700 dark:text-emerald-400 font-medium' : ''}>
                    {activeIncident.dataSource === 'live' ? t('common.real') : t('common.simulated')}
                  </span>
                </div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mt-1">
                  {activeIncident.title}
                </h2>
                <p className="text-xs text-slate-700 dark:text-slate-300 mt-1 leading-relaxed">
                  {activeIncident.summary}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onUpdateStatus(activeIncident.id, 'false_positive')}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                >
                  {t('incidents.markFalsePositive')}
                </button>
              </div>
            </div>

            {/* Timeline & Provenance */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('incidents.timelineTitle')}
              </h3>
              <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-slate-50 dark:bg-slate-950/50 overflow-hidden">
                <div className="divide-y divide-slate-200 dark:divide-slate-800/80 max-h-[360px] overflow-y-auto">
                  {timelinePagination.pagedItems.map((step) => {
                    const fullEvent = relatedEvents.find((e) => e.eventId === step.eventId);
                    return (
                      <div key={step.eventId} className="p-3.5 text-xs space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                          <span>
                            {new Date(step.timestamp).toLocaleTimeString(locale)} ·{' '}
                            {t('incidents.sourcePrefix')}{' '}
                            <strong className="text-slate-900 dark:text-slate-200">{step.sourceIntegrationId}</strong>
                          </span>
                          <span>{step.eventId}</span>
                        </div>
                        <p className="text-slate-800 dark:text-slate-200">{step.description}</p>
                        {fullEvent && (
                          <details className="text-slate-600 dark:text-slate-400">
                            <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 select-none">
                              {t('incidents.inspectEnvelope')}
                            </summary>
                            <pre className="mt-2 p-3 rounded bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
                              {JSON.stringify(fullEvent, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    );
                  })}
                </div>
                {activeIncident.timeline.length > 0 && (
                  <PaginationControls
                    page={timelinePagination.page}
                    pageSize={timelinePagination.pageSize}
                    totalItems={timelinePagination.totalItems}
                    totalPages={timelinePagination.totalPages}
                    onPageChange={timelinePagination.setPage}
                    onPageSizeChange={timelinePagination.setPageSize}
                    compact
                  />
                )}
              </div>
            </div>
          </div>

          {/* Hybrid AI Investigation Panel */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400 font-mono">
                  {inv.provider === 'gemini-sanitized' ? (
                    <Cloud className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
                  ) : (
                    <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  )}
                  <span>{inv.modelVersion}</span>
                  <span>·</span>
                  <span>
                    {t('incidents.confidenceLabel')} {confidenceLabel}
                  </span>
                </div>
                <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mt-1">
                  {t('incidents.analysisTitle')}
                </h3>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={busyKey === `inv-local-${activeIncident.id}`}
                  onClick={() => onInvestigate(activeIncident.id, 'local')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap cursor-pointer disabled:opacity-50"
                >
                  <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span>{t('incidents.investigateLocal')}</span>
                </button>

                <button
                  type="button"
                  disabled={busyKey === `inv-cloud-${activeIncident.id}`}
                  onClick={() => onInvestigate(activeIncident.id, 'cloud_gemini')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 whitespace-nowrap cursor-pointer disabled:opacity-50"
                >
                  <Cloud className="w-3.5 h-3.5" />
                  <span>
                    {busyKey === `inv-cloud-${activeIncident.id}`
                      ? t('incidents.investigatingCloud')
                      : t('incidents.investigateCloud')}
                  </span>
                </button>
              </div>
            </div>

            {/* Cloud Opt-in Privacy Gate */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-2.5 px-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60 text-xs">
              <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                <Lock className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400 shrink-0" />
                <span>{t('incidents.privacyGateNote')}</span>
              </div>
              <button
                type="button"
                onClick={() => onToggleCloudOptIn(!state.context.cloudAiOptIn)}
                className={`px-3 py-1.5 rounded-md font-medium whitespace-nowrap shrink-0 cursor-pointer border ${
                  state.context.cloudAiOptIn
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-600/20 dark:text-emerald-300 dark:border-emerald-700/50'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700'
                }`}
              >
                {state.context.cloudAiOptIn
                  ? t('incidents.cloudOptInOn')
                  : t('incidents.cloudOptInOff')}
              </button>
            </div>

            {/* Distinct Facts vs Hypotheses vs Recommendations */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="space-y-2">
                <div className="font-semibold text-slate-900 dark:text-slate-200">{t('incidents.sectionFacts')}</div>
                <ul className="space-y-1.5 text-slate-700 dark:text-slate-300 list-disc pl-4">
                  {inv.observedFacts.map((fact, idx) => (
                    <li key={idx}>{fact}</li>
                  ))}
                </ul>
              </div>
              <div className="space-y-2">
                <div className="font-semibold text-slate-900 dark:text-slate-200">
                  {t('incidents.sectionHypotheses')}
                </div>
                <ul className="space-y-1.5 text-slate-700 dark:text-slate-300 list-disc pl-4">
                  {inv.inferredHypotheses.map((hyp, idx) => (
                    <li key={idx}>{hyp}</li>
                  ))}
                </ul>
              </div>
              <div className="space-y-2">
                <div className="font-semibold text-slate-900 dark:text-slate-200">
                  {t('incidents.sectionRecommendations')}
                </div>
                <ul className="space-y-1.5 text-slate-700 dark:text-slate-300 list-disc pl-4">
                  {inv.recommendedSteps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="text-xs text-slate-600 dark:text-slate-400 pt-1 space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-500 shrink-0" />
                <span>{inv.promptInjectionGuardNote}</span>
              </div>
              {inv.sanitizedPayloadPreview && (
                <details>
                  <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 select-none">
                    {t('incidents.inspectSanitizedPayload')}
                  </summary>
                  <pre className="mt-2 p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
                    {inv.sanitizedPayloadPreview}
                  </pre>
                </details>
              )}
            </div>
          </div>

          {/* Deterministic Policy Action Proposal */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
                <span>
                  {t('incidents.policyEngineMeta', { level: state.context.globalAutonomy })}
                </span>
              </div>
              <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {recommendedPolicy
                  ? recommendedPolicy.name
                  : t('incidents.evaluatePolicyFallback')}
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                {t('incidents.policyEngineHint', {
                  level: state.context.globalAutonomy,
                  ttl: ttlNote,
                })}
              </p>
            </div>

            <button
              type="button"
              disabled={!recommendedPolicy || busyKey === `propose-${activeIncident.id}`}
              onClick={() =>
                recommendedPolicy && onProposeAction(activeIncident.id, recommendedPolicy.id)
              }
              className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {state.context.globalAutonomy === 'L0'
                ? t('incidents.simulateL0')
                : t('incidents.executeViaPolicy', { level: state.context.globalAutonomy })}
            </button>
          </div>
        </section>
      </div>
      )}
    </div>
  );
}
