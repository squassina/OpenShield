import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  AlertCircle,
  Ban,
  CheckCircle2,
  Clock,
  EyeOff,
  KeyRound,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Router,
  Search,
  Send,
  ServerOff,
  Settings,
  ShieldAlert,
  ShieldX,
  SlidersHorizontal,
  Terminal,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import { api } from '../lib/api';
import { PaginationControls, usePagination } from './PaginationControls';
import type {
  EnvSecretStatus,
  IntegrationAdapter,
  PeriodicSyncConfig,
  RouterAccessService,
  ServiceProviderMode,
  WorkspaceState,
} from '../types/openshield';

interface IntegrationsViewProps {
  state: WorkspaceState;
  searchQuery?: string;
  onBlockRouterAccessIp: (id: string, ttlSeconds?: number) => Promise<void>;
  onUpdateRouterAccessStatus: (id: string, status: 'observed' | 'ignored') => Promise<void>;
  onSwitchMode: (id: string, mode: ServiceProviderMode, liveUrl: string) => Promise<void>;
  onSyncAdapter: (id: string) => Promise<void>;
  onSyncAll: () => Promise<void>;
  onUpdatePeriodicSync: (config: PeriodicSyncConfig) => Promise<void>;
  onHandshake: (id: string) => Promise<void>;
  onToggleOutage: (nodeAvailable: boolean) => Promise<void>;
  onTestBadProvenance: () => Promise<void>;
  onInjectSampleEvent: () => Promise<void>;
  onSendLiveCorrelatedBatch: () => Promise<void>;
  onRegisterManual: (payload: {
    id: string;
    name: string;
    domain: IntegrationAdapter['domain'];
    kind: string;
    liveEndpointUrl: string;
    configMetadata?: Record<string, string>;
  }) => Promise<void>;
  onOpenSettings: () => void;
  busyKey: string | null;
}

const SYNC_INTERVAL_PRESETS = [
  { seconds: 30, label: '30s' },
  { seconds: 60, label: '1m' },
  { seconds: 300, label: '5m' },
  { seconds: 900, label: '15m' },
  { seconds: 1800, label: '30m' },
] as const;

function formatIntervalLabel(seconds: number): string {
  if (seconds >= 60 && seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }
  return `${seconds}s`;
}

function formatCountdown(msRemaining: number): string {
  const totalSec = Math.max(0, Math.ceil(msRemaining / 1000));
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function IntegrationsView({
  state,
  searchQuery = '',
  onBlockRouterAccessIp,
  onUpdateRouterAccessStatus,
  onSwitchMode,
  onSyncAdapter,
  onSyncAll,
  onUpdatePeriodicSync,
  onHandshake,
  onToggleOutage,
  onTestBadProvenance,
  onInjectSampleEvent,
  onSendLiveCorrelatedBatch,
  onRegisterManual,
  onOpenSettings,
  busyKey,
}: IntegrationsViewProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const [urlDrafts, setUrlDrafts] = useState<Record<string, string>>({});
  const [envStatus, setEnvStatus] = useState<EnvSecretStatus[]>([]);
  const [showManualForm, setShowManualForm] = useState(false);
  const [manualId, setManualId] = useState('unbound-lan');
  const [manualName, setManualName] = useState('Unbound Recursive DNS');
  const [manualDomain, setManualDomain] = useState<IntegrationAdapter['domain']>('dns');
  const [manualKind, setManualKind] = useState('unbound-exporter');
  const [manualUrl, setManualUrl] = useState('http://192.168.1.10:9167/metrics');
  const [extraKey, setExtraKey] = useState('');
  const [extraVal, setExtraVal] = useState('');
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [serviceFilter, setServiceFilter] = useState<'all' | RouterAccessService>('all');
  const [routerSearch, setRouterSearch] = useState('');

  const isBusiness = state.context.profile === 'business';
  const isReadOnlyAuditor = isBusiness && state.context.simulatedRole === 'auditor';

  const scopedRouterAttempts = useMemo(() => {
    const all = state.routerAccessAttempts ?? [];
    const bySite = isBusiness
      ? all
      : all.filter((item) => !item.siteId || item.siteId === state.context.activeSiteId);
    const q = (routerSearch.trim() || searchQuery.trim()).toLowerCase();
    return bySite.filter((item) => {
      if (serviceFilter !== 'all' && item.service !== serviceFilter) return false;
      if (!q) return true;
      return (
        item.srcIp.toLowerCase().includes(q) ||
        item.service.toLowerCase().includes(q) ||
        item.lastMessage.toLowerCase().includes(q) ||
        item.sourceIntegrationId.toLowerCase().includes(q)
      );
    });
  }, [
    state.routerAccessAttempts,
    isBusiness,
    state.context.activeSiteId,
    routerSearch,
    searchQuery,
    serviceFilter,
  ]);

  const routerAccessPagination = usePagination(
    scopedRouterAttempts,
    10,
    `${state.context.profile}|${state.context.activeSiteId}|${serviceFilter}|${routerSearch}|${searchQuery}`,
  );
  const adaptersPagination = usePagination(state.integrations, 10);

  const openwrtLogWarning = useMemo(
    () =>
      state.integrations.find(
        (a) =>
          a.kind === 'openwrt-rpcd' &&
          a.lastLiveCheckMessage &&
          (a.lastLiveCheckMessage.includes('Aviso logs') ||
            a.lastLiveCheckMessage.includes('ubus') ||
            a.lastLiveCheckMessage.includes('ACL')),
      )?.lastLiveCheckMessage ?? null,
    [state.integrations],
  );

  const periodicSync = state.context.periodicSync ?? {
    enabled: false,
    intervalSeconds: 60,
  };

  useEffect(() => {
    if (!periodicSync.enabled) return;
    setNowMs(Date.now());
    const id = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, [periodicSync.enabled, periodicSync.nextRunAt]);

  useEffect(() => {
    api
      .getEnvStatus()
      .then((res) => setEnvStatus(res.variables))
      .catch(() => {});
  }, []);

  const handleManualSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const configMetadata = extraKey.trim() ? { [extraKey.trim()]: extraVal.trim() } : undefined;
    await onRegisterManual({
      id: manualId,
      name: manualName,
      domain: manualDomain,
      kind: manualKind,
      liveEndpointUrl: manualUrl,
      configMetadata,
    });
    setShowManualForm(false);
    setExtraKey('');
    setExtraVal('');
  };

  const sampleCurl = `curl -X POST http://localhost:3000/api/v1/ingest/events \\
  -H "Content-Type: application/json" \\
  -d '{"events":[{"schemaVersion":"openshield.event.v1","sourceIntegrationId":"suricata-lan","eventType":"ids.alert","severity":"high","deviceId":"dev-nas-01","summary":"SMB enumeration attempt detected on LAN","payload":{"dstPort":445,"proto":"TCP"}}]}'`;

  const openwrtGwId =
    state.integrations.find((a) => a.kind === 'openwrt-rpcd')?.id ?? 'openwrt-gw-1';

  const routerPushCmd = `logread -l 120 | curl -sS -X POST "http://<NODE_HOST>:3000/api/v1/ingest/router-logs?sourceIntegrationId=${openwrtGwId}" \\
  -H "Content-Type: text/plain" --data-binary @-`;

  const rpcdAclSnippet = `{
  "openshield": {
    "description": "OpenShield telemetry, logread & isolated nft firewall containment",
    "read": {
      "ubus": {
        "system": ["board", "info"],
        "network.interface": ["dump"],
        "luci-rpc": ["getHostHints", "getNetworkDevices"],
        "log": ["read"]
      },
      "file": {
        "/sbin/ip": ["exec"],
        "/sbin/logread": ["exec"],
        "/usr/sbin/nft": ["exec"]
      }
    },
    "write": {
      "file": {
        "/usr/sbin/nft": ["exec"]
      }
    }
  }
}`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50 text-balance">
            {t('integrations.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400 max-w-2xl">{t('integrations.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={state.integrations.length === 0 || busyKey === 'sync-all'}
            onClick={onSyncAll}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 ${busyKey === 'sync-all' ? 'animate-spin' : ''}`}
            />
            <span>{t('integrations.syncAll', { count: state.integrations.length })}</span>
          </button>

          <button
            type="button"
            onClick={onOpenSettings}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Settings className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <span>{t('integrations.configureEndpoints')}</span>
          </button>

          <button
            type="button"
            onClick={() => setShowManualForm((prev) => !prev)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>
              {showManualForm ? t('integrations.closeManual') : t('integrations.openManual')}
            </span>
          </button>
        </div>
      </div>

      {/* Periodic Auto-Sync Timer */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <Clock
                className={`w-4 h-4 shrink-0 ${
                  periodicSync.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                }`}
              />
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('integrations.autoSyncTitle')}
              </h2>
              <span
                className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium border tabular-nums ${
                  periodicSync.enabled
                    ? state.context.nodeAvailable
                      ? 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300'
                      : 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300'
                    : 'border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400'
                }`}
              >
                {periodicSync.enabled
                  ? state.context.nodeAvailable
                    ? t('integrations.autoSyncActive', {
                        interval: formatIntervalLabel(periodicSync.intervalSeconds),
                      })
                    : t('integrations.autoSyncNodeOffline')
                  : t('integrations.autoSyncPaused')}
              </span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 max-w-2xl">{t('integrations.autoSyncSubtitle')}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div
              className="inline-flex items-center p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800"
              role="group"
              aria-label={t('integrations.autoSyncIntervalLabel')}
            >
              {SYNC_INTERVAL_PRESETS.map((preset) => {
                const isSelected = periodicSync.intervalSeconds === preset.seconds;
                return (
                  <button
                    key={preset.seconds}
                    type="button"
                    disabled={busyKey === 'periodic-sync'}
                    onClick={() =>
                      onUpdatePeriodicSync({
                        enabled: periodicSync.enabled,
                        intervalSeconds: preset.seconds,
                      })
                    }
                    className={`px-2.5 py-1.5 text-xs font-medium font-mono rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                      isSelected
                        ? 'bg-emerald-600 text-white'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                    }`}
                  >
                    {preset.label}
                  </button>
                );
              })}
            </div>

            <button
              type="button"
              disabled={busyKey === 'periodic-sync' || state.integrations.length === 0}
              onClick={() =>
                onUpdatePeriodicSync({
                  enabled: !periodicSync.enabled,
                  intervalSeconds: periodicSync.intervalSeconds,
                })
              }
              className={`inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                periodicSync.enabled
                  ? 'border border-amber-300 bg-amber-50 text-amber-800 hover:bg-amber-100 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-300 dark:hover:bg-amber-500/20'
                  : 'bg-emerald-600 text-white hover:bg-emerald-500'
              }`}
            >
              {periodicSync.enabled ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>{t('integrations.autoSyncPauseBtn')}</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>{t('integrations.autoSyncEnableBtn')}</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-800/80 text-xs text-slate-600 dark:text-slate-400 tabular-nums">
          <div className="flex flex-wrap items-center gap-2">
            {periodicSync.lastRunAt ? (
              <>
                <span>
                  {t('integrations.autoSyncLastRun')}{' '}
                  <strong className="text-slate-900 dark:text-slate-200 font-medium">
                    {new Date(periodicSync.lastRunAt).toLocaleTimeString(locale)}
                  </strong>
                </span>
                {periodicSync.lastRunStatus && (
                  <span
                    className={
                      periodicSync.lastRunStatus === 'success'
                        ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                        : periodicSync.lastRunStatus === 'partial'
                          ? 'text-amber-700 dark:text-amber-400 font-medium'
                          : 'text-red-700 dark:text-red-400 font-medium'
                    }
                  >
                    {periodicSync.lastRunStatus === 'success'
                      ? t('integrations.autoSyncStatusSuccess')
                      : periodicSync.lastRunStatus === 'partial'
                        ? t('integrations.autoSyncStatusPartial')
                        : t('integrations.autoSyncStatusFailed')}
                  </span>
                )}
                {periodicSync.lastRunSummary && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300">{periodicSync.lastRunSummary}</span>
                  </>
                )}
              </>
            ) : (
              <span>{t('integrations.autoSyncNeverRan')}</span>
            )}
          </div>

          {periodicSync.enabled && state.context.nodeAvailable && periodicSync.nextRunAt && (
            <div className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
              <span className="text-slate-500 dark:text-slate-400">{t('integrations.autoSyncNextIn')}</span>
              <span className="font-mono font-semibold text-emerald-700 dark:text-emerald-400">
                {Date.parse(periodicSync.nextRunAt) > nowMs
                  ? formatCountdown(Date.parse(periodicSync.nextRunAt) - nowMs)
                  : t('integrations.autoSyncDueNow')}
              </span>
            </div>
          )}
        </div>
      </section>

      {/* P0 Resilience & Real Ingestion Lab */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{t('integrations.labTitle')}</h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{t('integrations.labSubtitle')}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              disabled={busyKey === 'outage'}
              onClick={() => onToggleOutage(!state.context.nodeAvailable)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <ServerOff className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
              <span>
                {state.context.nodeAvailable
                  ? t('integrations.simulateOutage')
                  : t('integrations.reconnectDrain', {
                      count: state.metrics.outboxPendingTotal,
                    })}
              </span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'ingest'}
              onClick={onInjectSampleEvent}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>{t('integrations.injectEventV1')}</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'ingest-live-batch'}
              onClick={onSendLiveCorrelatedBatch}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5 text-teal-600 dark:text-teal-400" />
              <span>{t('integrations.testIngestCorrelate')}</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'bad-prov'}
              onClick={onTestBadProvenance}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <ShieldX className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />
              <span>{t('integrations.testBadProvenance')}</span>
            </button>
          </div>
        </div>

        {/* Progressive Disclosure: LAN Ingestion Endpoint & Server Env Status */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2 border-t border-slate-200 dark:border-slate-800/80 text-xs">
          <details>
            <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 font-medium select-none inline-flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5" />
              <span>{t('integrations.envSummary')}</span>
            </summary>
            <div className="mt-3 divide-y divide-slate-200 dark:divide-slate-800/80 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/60">
              {envStatus.map((env) => (
                <div key={env.key} className="px-3 py-2 flex items-center justify-between gap-2">
                  <div>
                    <div className="font-mono text-slate-900 dark:text-slate-200">{env.key}</div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400">
                      {env.label} · {env.scope}
                    </div>
                  </div>
                  <span
                    className={
                      env.configured ? 'text-emerald-700 dark:text-emerald-400 font-medium' : 'text-slate-500'
                    }
                  >
                    {env.configured
                      ? t('integrations.envConfigured')
                      : t('integrations.envMissing')}
                  </span>
                </div>
              ))}
            </div>
          </details>

          <details>
            <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 font-medium select-none inline-flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5" />
              <span>{t('integrations.ingestSummary')}</span>
            </summary>
            <pre className="mt-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
              {sampleCurl}
            </pre>
          </details>
        </div>
      </section>

      {/* Manual Fallback Registration Form */}
      {showManualForm && (
        <form
          onSubmit={handleManualSubmit}
          className="rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none p-5 space-y-4"
        >
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('integrations.manualTitle')}
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{t('integrations.manualSubtitle')}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('integrations.manualId')}</span>
              <input
                type="text"
                value={manualId}
                onChange={(e) => setManualId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('integrations.manualName')}</span>
              <input
                type="text"
                value={manualName}
                onChange={(e) => setManualName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('integrations.manualDomain')}</span>
              <select
                value={manualDomain}
                onChange={(e) => setManualDomain(e.target.value as IntegrationAdapter['domain'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
              >
                <option value="gateway">{t('integrations.domainGateway')}</option>
                <option value="dns">{t('integrations.domainDns')}</option>
                <option value="ids">{t('integrations.domainIds')}</option>
                <option value="analytics">{t('integrations.domainAnalytics')}</option>
                <option value="threat_intel">{t('integrations.domainThreatIntel')}</option>
                <option value="ai_runtime">{t('integrations.domainAiRuntime')}</option>
              </select>
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('integrations.manualKind')}</span>
              <input
                type="text"
                value={manualKind}
                onChange={(e) => setManualKind(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs md:col-span-2">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('integrations.manualUrl')}</span>
              <input
                type="url"
                value={manualUrl}
                onChange={(e) => setManualUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-600 dark:text-slate-400">{t('integrations.extraKey')}</span>
              <input
                type="text"
                placeholder={t('integrations.extraKeyPlaceholder')}
                value={extraKey}
                onChange={(e) => setExtraKey(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-600 dark:text-slate-400">{t('integrations.extraVal')}</span>
              <input
                type="text"
                placeholder={t('integrations.extraValPlaceholder')}
                value={extraVal}
                onChange={(e) => setExtraVal(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setShowManualForm(false)}
              className="px-4 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={busyKey === 'manual-reg'}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 cursor-pointer disabled:opacity-50"
            >
              {t('integrations.saveIntegration')}
            </button>
          </div>
        </form>
      )}

      {/* Router Unauthorized Access Attempts */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('integrations.routerAccess.title', { count: scopedRouterAttempts.length })}
              </h2>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 max-w-2xl">
              {t('integrations.routerAccess.subtitle')}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              {(
                [
                  { id: 'all', label: t('integrations.routerAccess.filterAll') },
                  { id: 'ssh', label: 'SSH' },
                  { id: 'luci', label: 'LuCI' },
                  { id: 'ubus', label: 'ubus' },
                  { id: 'wan_drop', label: t('integrations.routerAccess.filterWanDrop') },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setServiceFilter(tab.id)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    serviceFilter === tab.id
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                value={routerSearch}
                onChange={(e) => setRouterSearch(e.target.value)}
                placeholder={t('integrations.routerAccess.searchPlaceholder')}
                className="pl-8 pr-3 py-1.5 w-48 rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        </div>

        {openwrtLogWarning && (
          <div className="mx-5 mt-4 rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-500/30 dark:bg-amber-950/15 px-3.5 py-2.5 flex items-start gap-2.5 text-xs text-amber-900 dark:text-amber-200">
            <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-medium">{t('integrations.routerAccess.aclHintTitle')}</span>{' '}
              <span className="text-amber-800 dark:text-amber-200/90">{openwrtLogWarning}</span>
            </div>
          </div>
        )}

        <div className="divide-y divide-slate-200 dark:divide-slate-800/80 max-h-[460px] overflow-y-auto">
          {scopedRouterAttempts.length === 0 ? (
            <div className="p-8 text-center space-y-1.5 text-xs">
              <div className="text-slate-800 dark:text-slate-300 font-medium">
                {t('integrations.routerAccess.emptyTitle')}
              </div>
              <p className="text-slate-600 dark:text-slate-400 max-w-lg mx-auto">
                {t('integrations.routerAccess.emptySubtitle')}
              </p>
            </div>
          ) : (
            routerAccessPagination.pagedItems.map((attempt) => {
              const isBusyBlock = busyKey === `rtr-block-${attempt.id}`;
              const isBusyStatus = busyKey === `rtr-status-${attempt.id}`;
              const serviceLabel =
                attempt.service === 'ssh'
                  ? 'SSH'
                  : attempt.service === 'luci'
                    ? 'LuCI'
                    : attempt.service === 'ubus'
                      ? 'ubus'
                      : t('integrations.routerAccess.filterWanDrop');

              return (
                <div
                  key={attempt.id}
                  className="px-5 py-4 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between hover:bg-slate-50 dark:hover:bg-slate-900/30 transition-colors"
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 tabular-nums">
                      <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                        {attempt.srcIp}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-slate-700 dark:text-slate-300">
                        {serviceLabel}
                        {attempt.targetPort ? ` · ${attempt.targetPort}` : ''}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span
                        className={
                          attempt.severity === 'critical' || attempt.severity === 'high'
                            ? 'text-red-700 dark:text-red-400 font-medium'
                            : attempt.severity === 'medium'
                              ? 'text-amber-700 dark:text-amber-400 font-medium'
                              : 'text-slate-700 dark:text-slate-300 font-medium'
                        }
                      >
                        {t(`integrations.routerAccess.sev.${attempt.severity}`)}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>
                        {t('integrations.routerAccess.attemptsCount', {
                          count: attempt.attemptsCount,
                        })}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-slate-500 dark:text-slate-400">
                        {new Date(attempt.lastSeenAt).toLocaleTimeString(locale)}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span
                        className={
                          attempt.status === 'blocked'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : attempt.status === 'ignored'
                              ? 'text-slate-500 font-medium'
                              : 'text-amber-700 dark:text-amber-300 font-medium'
                        }
                      >
                        {attempt.status === 'blocked'
                          ? t('integrations.routerAccess.statusBlocked', {
                              until: attempt.blockedUntil
                                ? new Date(attempt.blockedUntil).toLocaleTimeString(locale)
                                : 'TTL',
                            })
                          : attempt.status === 'ignored'
                            ? t('integrations.routerAccess.statusIgnored')
                            : t('integrations.routerAccess.statusObserved')}
                      </span>
                    </div>

                    <p className="text-xs text-slate-800 dark:text-slate-200 leading-relaxed">{attempt.lastMessage}</p>

                    <div className="text-[11px] font-mono text-slate-500">
                      {t('integrations.routerAccess.sourceAdapter', {
                        id: attempt.sourceIntegrationId,
                      })}
                      {attempt.linkedExecutionId && (
                        <>
                          {' '}
                          ·{' '}
                          <span className="text-slate-600 dark:text-slate-400">
                            {t('integrations.routerAccess.linkedExec', {
                              id: attempt.linkedExecutionId,
                            })}
                          </span>
                        </>
                      )}
                    </div>

                    {attempt.sampleLines.length > 0 && (
                      <details className="text-[11px] text-slate-600 dark:text-slate-400">
                        <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 select-none">
                          {t('integrations.routerAccess.viewRawLines', {
                            count: attempt.sampleLines.length,
                          })}
                        </summary>
                        <pre className="mt-1.5 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
                          {attempt.sampleLines.join('\n')}
                        </pre>
                      </details>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      type="button"
                      disabled={
                        isReadOnlyAuditor ||
                        isBusyBlock ||
                        state.context.killSwitchActive ||
                        attempt.status === 'blocked'
                      }
                      onClick={() => onBlockRouterAccessIp(attempt.id, 900)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-200 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800/70 dark:bg-red-950/30 dark:text-red-200 dark:hover:bg-red-900/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
                    >
                      <Ban className="w-3.5 h-3.5" />
                      <span>{t('integrations.routerAccess.blockIpBtn')}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isReadOnlyAuditor || isBusyStatus || attempt.status === 'blocked'}
                      onClick={() =>
                        onUpdateRouterAccessStatus(
                          attempt.id,
                          attempt.status === 'ignored' ? 'observed' : 'ignored',
                        )
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-40"
                    >
                      <EyeOff className="w-3.5 h-3.5" />
                      <span>
                        {attempt.status === 'ignored'
                          ? t('integrations.routerAccess.reopenBtn')
                          : t('integrations.routerAccess.ignoreBtn')}
                      </span>
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {scopedRouterAttempts.length > 0 && (
          <PaginationControls
            page={routerAccessPagination.page}
            pageSize={routerAccessPagination.pageSize}
            totalItems={routerAccessPagination.totalItems}
            totalPages={routerAccessPagination.totalPages}
            onPageChange={routerAccessPagination.setPage}
            onPageSizeChange={routerAccessPagination.setPageSize}
            compact
          />
        )}

        <div className="px-5 py-3.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40 text-xs">
          <details>
            <summary className="cursor-pointer text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 font-medium select-none inline-flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" />
              <span>{t('integrations.routerAccess.setupGuideSummary')}</span>
            </summary>
            <div className="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-slate-700 dark:text-slate-300">
                  {t('integrations.routerAccess.pushCmdTitle')}
                </div>
                <pre className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
                  {routerPushCmd}
                </pre>
              </div>
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-slate-700 dark:text-slate-300">
                  {t('integrations.routerAccess.aclJsonTitle')}
                </div>
                <pre className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 font-mono text-[11px] text-slate-800 dark:text-slate-300 overflow-x-auto">
                  {rpcdAclSnippet}
                </pre>
              </div>
            </div>
          </details>
        </div>
      </section>

      {/* Adapters List */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] shadow-xs dark:shadow-none overflow-hidden">
        <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-[580px] overflow-y-auto">
          {state.integrations.length === 0 ? (
            <div className="p-10 text-center space-y-3">
              <p className="text-sm text-slate-800 dark:text-slate-300 font-medium">{t('integrations.emptyTitle')}</p>
              <p className="text-xs text-slate-600 dark:text-slate-400 max-w-md mx-auto">
                {t('integrations.emptyHintPrefix')}{' '}
                <strong>{t('integrations.emptyHintBold')}</strong>{' '}
                {t('integrations.emptyHintSuffix')}
              </p>
              <button
                type="button"
                onClick={onOpenSettings}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 cursor-pointer"
              >
                <Settings className="w-3.5 h-3.5" />
                <span>{t('integrations.goToSettings')}</span>
              </button>
            </div>
          ) : (
            adaptersPagination.pagedItems.map((adapter) => {
              const currentUrl = urlDrafts[adapter.id] ?? adapter.liveEndpointUrl;
              const isBusy =
                busyKey === `mode-${adapter.id}` ||
                busyKey === `handshake-${adapter.id}` ||
                busyKey === `sync-${adapter.id}`;

            return (
              <div key={adapter.id} className="p-5 space-y-4">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 tabular-nums">
                      <span className="font-mono text-slate-800 dark:text-slate-300">{adapter.id}</span>
                      <span aria-hidden="true">·</span>
                      <span>{adapter.protocolVersion}</span>
                      <span aria-hidden="true">·</span>
                      <span
                        className={
                          adapter.status === 'connected'
                            ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                            : adapter.status === 'stale'
                              ? 'text-amber-700 dark:text-amber-400 font-medium'
                              : 'text-red-700 dark:text-red-400 font-medium'
                        }
                      >
                        {adapter.status === 'connected'
                          ? t('integrations.statusConnected')
                          : adapter.status === 'stale'
                            ? t('integrations.statusStale')
                            : t('integrations.statusUnavailable')}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>
                        {t('integrations.modeLabel')}{' '}
                        <strong className="text-slate-900 dark:text-slate-200 font-medium">
                          {adapter.mode === 'mock'
                            ? t('common.mockSim')
                            : t('integrations.modeRealLive')}
                        </strong>
                      </span>
                      {adapter.lastSyncedAt && (
                        <>
                          <span aria-hidden="true">·</span>
                          <span>
                            {t('integrations.lastSync')}{' '}
                            {new Date(adapter.lastSyncedAt).toLocaleTimeString(locale)}
                          </span>
                        </>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {adapter.domain === 'gateway' ? (
                        <Router className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      ) : (
                        <SlidersHorizontal className="w-4 h-4 text-slate-500 dark:text-slate-400 shrink-0" />
                      )}
                      <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{adapter.name}</h3>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-400 max-w-2xl">{adapter.description}</p>

                    <div className="text-xs text-slate-600 dark:text-slate-400 pt-1">
                      <span className="text-slate-500">
                        {t('integrations.declaredCapabilities')}{' '}
                      </span>
                      <span className="font-mono text-slate-800 dark:text-slate-300">
                        {adapter.capabilities.join(' · ')}
                      </span>
                    </div>

                    {adapter.boardInfo && (
                      <div className="text-xs text-slate-600 dark:text-slate-400 tabular-nums">
                        <span className="text-slate-500">
                          {t('integrations.discoveredHardware')}{' '}
                        </span>
                        <span>
                          {adapter.boardInfo.model} · {adapter.boardInfo.firmware} ·{' '}
                          {t('integrations.interfacesLabel')}{' '}
                          <span className="font-mono text-slate-800 dark:text-slate-300">
                            {adapter.boardInfo.interfaces.join(', ')}
                          </span>
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Per-service Mock <-> Live switch + Real Sync */}
                  <div className="flex flex-col gap-2.5 xl:w-[460px] shrink-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="inline-flex items-center p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => onSwitchMode(adapter.id, 'mock', currentUrl)}
                          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            adapter.mode === 'mock'
                              ? 'bg-emerald-600 text-white'
                              : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                          }`}
                        >
                          {t('common.mockSim')}
                        </button>
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => onSwitchMode(adapter.id, 'live', currentUrl)}
                          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            adapter.mode === 'live'
                              ? 'bg-emerald-600 text-white'
                              : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900'
                          }`}
                        >
                          {t('common.liveApi')}
                        </button>
                      </div>

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onSyncAdapter(adapter.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        <RefreshCw
                          className={`w-3.5 h-3.5 ${busyKey === `sync-${adapter.id}` ? 'animate-spin' : ''}`}
                        />
                        <span>{t('integrations.syncNow')}</span>
                      </button>

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onHandshake(adapter.id)}
                        className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {t('integrations.handshake')}
                      </button>
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        type="url"
                        aria-label={t('integrations.urlAria', { name: adapter.name })}
                        placeholder={t('integrations.urlPlaceholder')}
                        value={currentUrl}
                        onChange={(e) =>
                          setUrlDrafts((prev) => ({ ...prev, [adapter.id]: e.target.value }))
                        }
                        className="flex-1 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-200 font-mono text-xs placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                      />
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onSwitchMode(adapter.id, 'live', currentUrl)}
                        className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {t('integrations.testUrl')}
                      </button>
                    </div>

                    {adapter.lastLiveCheckMessage && (
                      <div className="flex items-start gap-1.5 text-xs text-slate-600 dark:text-slate-400">
                        {adapter.status === 'unavailable' ? (
                          <AlertCircle className="w-3.5 h-3.5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-500 shrink-0 mt-0.5" />
                        )}
                        <span>{adapter.lastLiveCheckMessage}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
        </div>
        {state.integrations.length > 0 && (
          <PaginationControls
            page={adaptersPagination.page}
            pageSize={adaptersPagination.pageSize}
            totalItems={adaptersPagination.totalItems}
            totalPages={adaptersPagination.totalPages}
            onPageChange={adaptersPagination.setPage}
            onPageSizeChange={adaptersPagination.setPageSize}
            compact
          />
        )}
      </section>
    </div>
  );
}
