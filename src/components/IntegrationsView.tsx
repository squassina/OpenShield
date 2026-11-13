import { useEffect, useState, type FormEvent } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  KeyRound,
  Plus,
  RefreshCw,
  Router,
  Send,
  ServerOff,
  Settings,
  ShieldX,
  SlidersHorizontal,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import { api } from '../lib/api';
import type {
  EnvSecretStatus,
  IntegrationAdapter,
  ServiceProviderMode,
  WorkspaceState,
} from '../types/openshield';

interface IntegrationsViewProps {
  state: WorkspaceState;
  onSwitchMode: (id: string, mode: ServiceProviderMode, liveUrl: string) => Promise<void>;
  onSyncAdapter: (id: string) => Promise<void>;
  onSyncAll: () => Promise<void>;
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

export function IntegrationsView({
  state,
  onSwitchMode,
  onSyncAdapter,
  onSyncAll,
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

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            {t('integrations.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">{t('integrations.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={state.integrations.length === 0 || busyKey === 'sync-all'}
            onClick={onSyncAll}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 text-emerald-400 ${busyKey === 'sync-all' ? 'animate-spin' : ''}`}
            />
            <span>{t('integrations.syncAll', { count: state.integrations.length })}</span>
          </button>

          <button
            type="button"
            onClick={onOpenSettings}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Settings className="w-4 h-4 text-blue-400" />
            <span>{t('integrations.configureEndpoints')}</span>
          </button>

          <button
            type="button"
            onClick={() => setShowManualForm((prev) => !prev)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>
              {showManualForm ? t('integrations.closeManual') : t('integrations.openManual')}
            </span>
          </button>
        </div>
      </div>

      {/* P0 Resilience & Real Ingestion Lab */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">{t('integrations.labTitle')}</h2>
            <p className="text-xs text-slate-400 mt-0.5">{t('integrations.labSubtitle')}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              disabled={busyKey === 'outage'}
              onClick={() => onToggleOutage(!state.context.nodeAvailable)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <ServerOff className="w-3.5 h-3.5 text-amber-400" />
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
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
              <span>{t('integrations.injectEventV1')}</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'ingest-live-batch'}
              onClick={onSendLiveCorrelatedBatch}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5 text-emerald-400" />
              <span>{t('integrations.testIngestCorrelate')}</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'bad-prov'}
              onClick={onTestBadProvenance}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <ShieldX className="w-3.5 h-3.5 text-red-400" />
              <span>{t('integrations.testBadProvenance')}</span>
            </button>
          </div>
        </div>

        {/* Progressive Disclosure: LAN Ingestion Endpoint & Server Env Status */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80 text-xs">
          <details>
            <summary className="cursor-pointer text-blue-400 hover:text-blue-300 font-medium select-none inline-flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5" />
              <span>{t('integrations.envSummary')}</span>
            </summary>
            <div className="mt-3 divide-y divide-slate-800/80 rounded-lg border border-slate-800 bg-slate-950/60">
              {envStatus.map((env) => (
                <div key={env.key} className="px-3 py-2 flex items-center justify-between gap-2">
                  <div>
                    <div className="font-mono text-slate-200">{env.key}</div>
                    <div className="text-[11px] text-slate-400">
                      {env.label} · {env.scope}
                    </div>
                  </div>
                  <span
                    className={
                      env.configured ? 'text-emerald-400 font-medium' : 'text-slate-500'
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
            <summary className="cursor-pointer text-blue-400 hover:text-blue-300 font-medium select-none inline-flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5" />
              <span>{t('integrations.ingestSummary')}</span>
            </summary>
            <pre className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
              {sampleCurl}
            </pre>
          </details>
        </div>
      </section>

      {/* Manual Fallback Registration Form */}
      {showManualForm && (
        <form
          onSubmit={handleManualSubmit}
          className="rounded-xl border border-slate-700 bg-[#131C31] p-5 space-y-4"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                {t('integrations.manualTitle')}
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">{t('integrations.manualSubtitle')}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">{t('integrations.manualId')}</span>
              <input
                type="text"
                value={manualId}
                onChange={(e) => setManualId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">{t('integrations.manualName')}</span>
              <input
                type="text"
                value={manualName}
                onChange={(e) => setManualName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">{t('integrations.manualDomain')}</span>
              <select
                value={manualDomain}
                onChange={(e) => setManualDomain(e.target.value as IntegrationAdapter['domain'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
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
              <span className="text-slate-300 font-medium">{t('integrations.manualKind')}</span>
              <input
                type="text"
                value={manualKind}
                onChange={(e) => setManualKind(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs md:col-span-2">
              <span className="text-slate-300 font-medium">{t('integrations.manualUrl')}</span>
              <input
                type="url"
                value={manualUrl}
                onChange={(e) => setManualUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-400">{t('integrations.extraKey')}</span>
              <input
                type="text"
                placeholder={t('integrations.extraKeyPlaceholder')}
                value={extraKey}
                onChange={(e) => setExtraKey(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-400">{t('integrations.extraVal')}</span>
              <input
                type="text"
                placeholder={t('integrations.extraValPlaceholder')}
                value={extraVal}
                onChange={(e) => setExtraVal(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={() => setShowManualForm(false)}
              className="px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={busyKey === 'manual-reg'}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer disabled:opacity-50"
            >
              {t('integrations.saveIntegration')}
            </button>
          </div>
        </form>
      )}

      {/* Adapters List */}
      <div className="rounded-xl border border-slate-800 bg-[#131C31] divide-y divide-slate-800">
        {state.integrations.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm text-slate-300 font-medium">{t('integrations.emptyTitle')}</p>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              {t('integrations.emptyHintPrefix')}{' '}
              <strong>{t('integrations.emptyHintBold')}</strong>{' '}
              {t('integrations.emptyHintSuffix')}
            </p>
            <button
              type="button"
              onClick={onOpenSettings}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer"
            >
              <Settings className="w-3.5 h-3.5" />
              <span>{t('integrations.goToSettings')}</span>
            </button>
          </div>
        ) : (
          state.integrations.map((adapter) => {
            const currentUrl = urlDrafts[adapter.id] ?? adapter.liveEndpointUrl;
            const isBusy =
              busyKey === `mode-${adapter.id}` ||
              busyKey === `handshake-${adapter.id}` ||
              busyKey === `sync-${adapter.id}`;

            return (
              <div key={adapter.id} className="p-5 space-y-4">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 tabular-nums">
                      <span className="font-mono text-slate-300">{adapter.id}</span>
                      <span aria-hidden="true">·</span>
                      <span>{adapter.protocolVersion}</span>
                      <span aria-hidden="true">·</span>
                      <span
                        className={
                          adapter.status === 'connected'
                            ? 'text-emerald-400 font-medium'
                            : adapter.status === 'stale'
                              ? 'text-amber-400 font-medium'
                              : 'text-red-400 font-medium'
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
                        <strong className="text-slate-200 font-medium">
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
                        <Router className="w-4 h-4 text-blue-400 shrink-0" />
                      ) : (
                        <SlidersHorizontal className="w-4 h-4 text-slate-400 shrink-0" />
                      )}
                      <h3 className="text-base font-semibold text-slate-100">{adapter.name}</h3>
                    </div>

                    <p className="text-xs text-slate-400 max-w-2xl">{adapter.description}</p>

                    <div className="text-xs text-slate-400 pt-1">
                      <span className="text-slate-500">
                        {t('integrations.declaredCapabilities')}{' '}
                      </span>
                      <span className="font-mono text-slate-300">
                        {adapter.capabilities.join(' · ')}
                      </span>
                    </div>

                    {adapter.boardInfo && (
                      <div className="text-xs text-slate-400 tabular-nums">
                        <span className="text-slate-500">
                          {t('integrations.discoveredHardware')}{' '}
                        </span>
                        <span>
                          {adapter.boardInfo.model} · {adapter.boardInfo.firmware} ·{' '}
                          {t('integrations.interfacesLabel')}{' '}
                          <span className="font-mono text-slate-300">
                            {adapter.boardInfo.interfaces.join(', ')}
                          </span>
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Per-service Mock <-> Live switch + Real Sync */}
                  <div className="flex flex-col gap-2.5 xl:w-[460px] shrink-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="inline-flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800">
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => onSwitchMode(adapter.id, 'mock', currentUrl)}
                          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            adapter.mode === 'mock'
                              ? 'bg-slate-800 text-slate-100'
                              : 'text-slate-400 hover:text-slate-200'
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
                              ? 'bg-blue-600 text-white'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {t('common.liveApi')}
                        </button>
                      </div>

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onSyncAdapter(adapter.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
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
                        className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
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
                        className="flex-1 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-200 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                      />
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onSwitchMode(adapter.id, 'live', currentUrl)}
                        className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {t('integrations.testUrl')}
                      </button>
                    </div>

                    {adapter.lastLiveCheckMessage && (
                      <div className="flex items-start gap-1.5 text-xs text-slate-400">
                        {adapter.status === 'unavailable' ? (
                          <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
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
    </div>
  );
}
