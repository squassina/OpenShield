import { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  HardDrive,
  Pause,
  Play,
  Router,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import type { WorkspaceState } from '../types/openshield';
import { NetworkHealthCard } from './NetworkHealthCard';
import { OverviewTelemetryDashboard } from './OverviewTelemetryDashboard';
import { OverviewTopologyMap } from './OverviewTopologyMap';
import { PaginationControls, usePagination } from './PaginationControls';

export type NavTab =
  | 'overview'
  | 'integrations'
  | 'devices'
  | 'dns'
  | 'incidents'
  | 'policies'
  | 'audit'
  | 'settings';

interface OverviewViewProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  onToggleNodeOutage: (nodeAvailable: boolean) => void;
  onQuickInvestigate: (incidentId: string) => void;
  onSyncAllHealth: () => Promise<void>;
  busyKey: string | null;
}

export function OverviewView({
  state,
  onNavigate,
  onToggleNodeOutage,
  onQuickInvestigate,
  onSyncAllHealth,
  busyKey,
}: OverviewViewProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const [chartsPaused, setChartsPaused] = useState(false);
  const [frozenSnapshot, setFrozenSnapshot] = useState<{
    state: WorkspaceState;
    capturedAtMs: number;
  } | null>(null);

  const handleToggleChartsPaused = () => {
    if (!chartsPaused) {
      setFrozenSnapshot({ state, capturedAtMs: Date.now() });
      setChartsPaused(true);
    } else {
      setChartsPaused(false);
      setFrozenSnapshot(null);
    }
  };

  const telemetryChartState = chartsPaused && frozenSnapshot ? frozenSnapshot.state : state;
  const telemetryFrozenAtMs =
    chartsPaused && frozenSnapshot ? frozenSnapshot.capturedAtMs : undefined;

  const formatRelativeTime = (iso: string): string => {
    const diffSec = Math.max(0, Math.floor((Date.now() - Date.parse(iso)) / 1000));
    if (diffSec < 60) return t('overview.relSec', { n: diffSec });
    const min = Math.floor(diffSec / 60);
    if (min < 60) return t('overview.relMin', { n: min });
    return t('overview.relHour', { n: Math.floor(min / 60) });
  };

  const isBusiness = state.context.profile === 'business';
  const visibleDevices = isBusiness
    ? state.devices
    : state.devices.filter((d) => d.siteId === state.context.activeSiteId);
  const scopedIntegrations = isBusiness
    ? state.integrations
    : state.integrations.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);
  const scopedIncidents = isBusiness
    ? state.incidents
    : state.incidents.filter((i) => !i.siteId || i.siteId === state.context.activeSiteId);
  const scopedDeviceIds = new Set(visibleDevices.map((d) => d.id));
  const scopedDeviceHosts = new Set(visibleDevices.map((d) => d.hostname.toLowerCase()));
  const scopedDnsInsights = isBusiness
    ? state.dnsInsights
    : state.dnsInsights.filter(
        (ins) =>
          scopedDeviceIds.has(ins.deviceId) ||
          scopedDeviceHosts.has(ins.deviceHostname.toLowerCase()),
      );
  const scopedIncidentIds = new Set(scopedIncidents.map((i) => i.id));
  const scopedExecutions = isBusiness
    ? state.executions
    : state.executions.filter((e) => scopedIncidentIds.has(e.incidentId));
  const scopedIntegrationIds = new Set(scopedIntegrations.map((i) => i.id));
  const scopedEvents = isBusiness
    ? state.events
    : state.events.filter(
        (ev) =>
          (ev.deviceId && scopedDeviceIds.has(ev.deviceId)) ||
          scopedIntegrationIds.has(ev.sourceIntegrationId),
      );
  const scopedRouterAttempts = isBusiness
    ? (state.routerAccessAttempts ?? [])
    : (state.routerAccessAttempts ?? []).filter(
        (r) => !r.siteId || r.siteId === state.context.activeSiteId,
      );
  const observedRouterAttempts = scopedRouterAttempts.filter((r) => r.status === 'observed');

  const openIncidents = scopedIncidents.filter(
    (i) => i.status === 'open' || i.status === 'investigating',
  );
  const activeIntegrations = scopedIntegrations.filter((i) => i.status === 'connected').length;
  const totalBlockedDns = scopedDnsInsights.reduce((acc, item) => acc + item.blockedCount, 0);
  const activeExecutions = scopedExecutions.filter(
    (e) => e.status === 'verified' || e.status === 'awaiting_approval',
  );
  const incidentsPagination = usePagination(
    scopedIncidents,
    10,
    `${state.context.profile}|${state.context.activeSiteId}`,
  );

  return (
    <div className="space-y-6">
      {/* Header summary */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            {isBusiness ? t('overview.titleBusiness') : t('overview.titleResidential')}
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            {isBusiness ? t('overview.subtitleBusiness') : t('overview.subtitleResidential')}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            aria-pressed={chartsPaused}
            onClick={handleToggleChartsPaused}
            className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              chartsPaused
                ? 'border-amber-500/50 bg-amber-500/15 text-amber-300 hover:bg-amber-500/25'
                : 'border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800'
            }`}
          >
            {chartsPaused ? (
              <Play className="w-3.5 h-3.5 shrink-0" />
            ) : (
              <Pause className="w-3.5 h-3.5 shrink-0" />
            )}
            <span>
              {chartsPaused ? t('overview.resumeCharts') : t('overview.pauseCharts')}
            </span>
          </button>
          <button
            type="button"
            disabled={busyKey === 'outage'}
            onClick={() => onToggleNodeOutage(!state.context.nodeAvailable)}
            className="px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            {state.context.nodeAvailable
              ? t('overview.simulateOutage')
              : t('overview.reconnectNode')}
          </button>
          <button
            type="button"
            onClick={() => onNavigate('settings')}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {t('overview.configureServices')}
          </button>
        </div>
      </div>

      {/* 4-column KPI strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('overview.kpiGatewayTitle')}</span>
            <Router className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50">
            {state.context.gatewayForwardingActive
              ? t('overview.kpiGatewayActive')
              : t('overview.kpiGatewayStopped')}
          </div>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            {state.context.nodeAvailable
              ? t('overview.kpiGatewayNodeOnline')
              : t('overview.kpiGatewayNodeOffline', {
                  count: state.metrics.outboxPendingTotal,
                })}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('overview.kpiIncidentsTitle')}</span>
            <ShieldAlert
              className={`w-4 h-4 ${
                openIncidents.length > 0 ? 'text-amber-500' : 'text-emerald-500'
              }`}
            />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {openIncidents.length}
          </div>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            {t('overview.kpiIncidentsSubtitle', { count: visibleDevices.length })}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('overview.kpiDnsTitle')}</span>
            <ShieldCheck className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {totalBlockedDns.toLocaleString(locale)}
          </div>
          <p className="mt-1.5 text-xs text-slate-400 tabular-nums">
            {t('overview.kpiDnsSubtitle', {
              active: activeIntegrations,
              total: scopedIntegrations.length,
            })}
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('overview.kpiAutonomyTitle')}</span>
            <Activity className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {state.context.killSwitchActive
              ? t('overview.kpiAutonomyKillSwitch')
              : t('overview.kpiAutonomyActiveCount', {
                  level: state.context.globalAutonomy,
                  count: activeExecutions.length,
                })}
          </div>
          <p className="mt-1.5 text-xs text-slate-400">
            {state.context.globalAutonomy === 'L0'
              ? t('overview.kpiAutonomyL0Hint')
              : t('overview.kpiAutonomyActiveHint')}
          </p>
        </div>
      </div>

      {/* Unauthorized Router Access Summary Banner */}
      {observedRouterAttempts.length > 0 && (
        <div className="rounded-xl border border-amber-500/35 bg-[#131C31] px-5 py-3.5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3 text-xs">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <div className="font-semibold text-slate-100 tabular-nums">
                {t('overview.routerAccessTitle', { count: observedRouterAttempts.length })}
              </div>
              <p className="text-slate-400 tabular-nums">
                {t('overview.routerAccessSubtitle', {
                  ips: observedRouterAttempts
                    .slice(0, 3)
                    .map((a) => `${a.srcIp} (${a.service.toUpperCase()})`)
                    .join(', '),
                })}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('integrations')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('overview.routerAccessCta')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Real-Time Throughput & Packet Drop Telemetry Dashboard (Recharts) */}
      <OverviewTelemetryDashboard
        state={telemetryChartState}
        onNavigate={onNavigate}
        livePaused={chartsPaused}
        frozenAtMs={telemetryFrozenAtMs}
        onToggleLivePaused={handleToggleChartsPaused}
      />

      {/* Network Health & Multi-Endpoint Availability */}
      <NetworkHealthCard
        state={state}
        onSyncAllHealth={onSyncAllHealth}
        onNavigate={onNavigate}
        busyKey={busyKey}
        frozenLatencyHistory={
          chartsPaused && frozenSnapshot ? frozenSnapshot.state.latencyHistory : undefined
        }
        frozenAtMs={telemetryFrozenAtMs}
      />

      {/* Interactive SVG Topology Map */}
      <OverviewTopologyMap state={state} onNavigate={onNavigate} />

      {/* Main 2-column operational grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left 2 cols: Priority incidents */}
        <section className="xl:col-span-2 rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                {t('overview.incidentsTitle')}
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">{t('overview.incidentsSubtitle')}</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('incidents')}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <span>{t('overview.openFullQueue')}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/80 max-h-[480px] overflow-y-auto">
            {scopedIncidents.length === 0 ? (
              <div className="p-8 text-center space-y-2.5">
                <p className="text-sm text-slate-300 font-medium">
                  {scopedIntegrations.length === 0
                    ? t('overview.noServicesYet')
                    : t('overview.noIncidentsYet')}
                </p>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {scopedIntegrations.length === 0
                    ? t('overview.noServicesHint')
                    : t('overview.noIncidentsHint')}
                </p>
                <div className="pt-1 flex items-center justify-center gap-3">
                  <button
                    type="button"
                    onClick={() => onNavigate('settings')}
                    className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer"
                  >
                    {t('overview.configureServices')}
                  </button>
                  <button
                    type="button"
                    onClick={() => onNavigate('devices')}
                    className="px-3.5 py-1.5 text-xs font-medium rounded-lg border border-slate-700 text-slate-200 hover:bg-slate-800 cursor-pointer"
                  >
                    {t('overview.addDevices')}
                  </button>
                </div>
              </div>
            ) : (
              incidentsPagination.pagedItems.map((incident) => (
                <div key={incident.id} className="p-5 hover:bg-slate-900/40 transition-colors">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2 text-xs text-slate-400 tabular-nums">
                        <span
                          className={
                            incident.severity === 'high' || incident.severity === 'critical'
                              ? 'text-red-400 font-medium'
                              : 'text-amber-400 font-medium'
                          }
                        >
                          {incident.severity === 'high' || incident.severity === 'critical'
                            ? t('overview.riskHigh')
                            : t('overview.riskMedium')}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono">{incident.deviceHostname}</span>
                        <span aria-hidden="true">·</span>
                        <span>
                          {t('common.score')} {incident.riskScore}/100
                        </span>
                        <span aria-hidden="true">·</span>
                        <span>
                          {incident.status === 'contained'
                            ? t('overview.statusContained')
                            : incident.status === 'resolved'
                              ? t('overview.statusResolved')
                              : incident.status === 'investigating'
                                ? t('overview.statusInvestigating')
                                : t('overview.statusOpen')}
                        </span>
                      </div>
                      <h3 className="text-sm font-semibold text-slate-100">{incident.title}</h3>
                      <p className="text-xs text-slate-400 leading-relaxed">{incident.summary}</p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => onQuickInvestigate(incident.id)}
                        className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        {t('overview.inspectAi')}
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
          {scopedIncidents.length > 0 && (
            <PaginationControls
              page={incidentsPagination.page}
              pageSize={incidentsPagination.pageSize}
              totalItems={incidentsPagination.totalItems}
              totalPages={incidentsPagination.totalPages}
              onPageChange={incidentsPagination.setPage}
              onPageSizeChange={incidentsPagination.setPageSize}
              compact
            />
          )}
        </section>

        {/* Right col: Gateway Fail-Safe & Connector Health */}
        <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-slate-800">
            <h2 className="text-base font-semibold text-slate-100">{t('overview.archTitle')}</h2>
            <p className="text-xs text-slate-400 mt-0.5">{t('overview.archSubtitle')}</p>
          </div>

          <div className="p-5 space-y-4 flex-1">
            <div className="space-y-3 text-xs">
              <div className="flex items-start justify-between gap-3 py-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2.5 text-slate-200">
                  <Router className="w-4 h-4 text-emerald-400 shrink-0" />
                  <div>
                    <div className="font-medium">{t('overview.gwTitle')}</div>
                    <div className="text-slate-400">{t('overview.gwSub')}</div>
                  </div>
                </div>
                <span className="text-emerald-400 font-medium whitespace-nowrap">
                  {t('overview.gwStatus')}
                </span>
              </div>

              <div className="flex items-start justify-between gap-3 py-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2.5 text-slate-200">
                  <HardDrive className="w-4 h-4 text-blue-400 shrink-0" />
                  <div>
                    <div className="font-medium">{t('overview.outboxTitle')}</div>
                    <div className="text-slate-400 tabular-nums">{t('overview.outboxCap')}</div>
                  </div>
                </div>
                <span className="font-mono text-slate-200 tabular-nums whitespace-nowrap">
                  {t('overview.outboxPending', { count: state.metrics.outboxPendingTotal })}
                </span>
              </div>

              <div className="flex items-start justify-between gap-3 py-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2.5 text-slate-200">
                  <Cpu className="w-4 h-4 text-slate-300 shrink-0" />
                  <div>
                    <div className="font-medium">{t('overview.nodeTitle')}</div>
                    <div className="text-slate-400">{t('overview.nodeSub')}</div>
                  </div>
                </div>
                <span
                  className={`font-medium whitespace-nowrap ${
                    state.context.nodeAvailable ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  {state.context.nodeAvailable
                    ? t('overview.nodeOnline')
                    : t('overview.nodeOfflineSim')}
                </span>
              </div>
            </div>

            <div className="pt-2">
              <div className="text-xs font-medium text-slate-300 mb-2">
                {t('overview.recentEventsTitle')}
              </div>
              <div className="space-y-2">
                {scopedEvents.length === 0 ? (
                  <div className="text-xs text-slate-500 py-2">{t('overview.noEventsYet')}</div>
                ) : (
                  scopedEvents.slice(0, 3).map((ev) => (
                    <div
                      key={ev.eventId}
                      className="text-xs flex items-center justify-between gap-2 py-1.5 border-b border-slate-800/60 last:border-0"
                    >
                      <div className="truncate text-slate-300">
                        <span className="font-mono text-slate-400">{ev.eventType}</span>
                        <span className="mx-1.5 text-slate-600">·</span>
                        <span>{ev.sourceIntegrationId}</span>
                      </div>
                      <span className="text-slate-500 tabular-nums whitespace-nowrap">
                        {formatRelativeTime(ev.occurredAt)}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="px-5 py-3.5 border-t border-slate-800 bg-slate-900/40 flex items-center justify-between text-xs">
            <span className="text-slate-400 flex items-center gap-1.5">
              {state.context.nodeAvailable ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
              )}
              <span>
                {state.context.nodeAvailable
                  ? t('overview.pipelineSynced')
                  : t('overview.pipelineBuffered')}
              </span>
            </span>
            <button
              type="button"
              onClick={() => onNavigate('policies')}
              className="text-blue-400 hover:text-blue-300 font-medium whitespace-nowrap cursor-pointer"
            >
              {t('overview.auditLink')}
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
