import { Suspense, lazy, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  AlertTriangle,
  Building2,
  CheckCircle2,
  GlobeLock,
  Home,
  Languages,
  LayoutDashboard,
  Menu,
  Network,
  OctagonAlert,
  PlugZap,
  ScrollText,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react';
import { SUPPORTED_LANGUAGES } from './i18n';
import { OverviewView, type NavTab } from './components/OverviewView';
import { api } from './lib/api';

const AuditLogsView = lazy(() =>
  import('./components/AuditLogsView').then((m) => ({ default: m.AuditLogsView })),
);
const DevicesTopologyView = lazy(() =>
  import('./components/DevicesTopologyView').then((m) => ({ default: m.DevicesTopologyView })),
);
const DnsPrivacyView = lazy(() =>
  import('./components/DnsPrivacyView').then((m) => ({ default: m.DnsPrivacyView })),
);
const IncidentsAiView = lazy(() =>
  import('./components/IncidentsAiView').then((m) => ({ default: m.IncidentsAiView })),
);
const IntegrationsView = lazy(() =>
  import('./components/IntegrationsView').then((m) => ({ default: m.IntegrationsView })),
);
const PoliciesAuditView = lazy(() =>
  import('./components/PoliciesAuditView').then((m) => ({ default: m.PoliciesAuditView })),
);
const SettingsView = lazy(() =>
  import('./components/SettingsView').then((m) => ({ default: m.SettingsView })),
);
import type {
  AiSensitivityConfig,
  AutonomyLevel,
  DnsInsight,
  Incident,
  IntegrationAdapter,
  OperatingProfile,
  PeriodicSyncConfig,
  ServiceProviderMode,
  SimulatedRole,
  WorkspaceState,
} from './types/openshield';

const NAV_ITEMS: { id: NavTab; labelKey: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', labelKey: 'nav.overview', icon: LayoutDashboard },
  { id: 'integrations', labelKey: 'nav.integrations', icon: PlugZap },
  { id: 'devices', labelKey: 'nav.devices', icon: Network },
  { id: 'dns', labelKey: 'nav.dns', icon: GlobeLock },
  { id: 'incidents', labelKey: 'nav.incidents', icon: ShieldAlert },
  { id: 'policies', labelKey: 'nav.policies', icon: Shield },
  { id: 'audit', labelKey: 'nav.audit', icon: ScrollText },
  { id: 'settings', labelKey: 'nav.settings', icon: Settings },
];

export default function App() {
  const { t, i18n } = useTranslation();
  const [state, setState] = useState<WorkspaceState | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ kind: 'info' | 'error'; message: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const showToast = useCallback((kind: 'info' | 'error', message: string) => {
    setToast({ kind, message });
  }, []);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(id);
  }, [toast]);

  // Initial load + live SSE stream subscription
  useEffect(() => {
    let active = true;
    api
      .getState()
      .then((initial) => {
        if (active) {
          setState(initial);
          setLoadError(null);
        }
      })
      .catch((err) => {
        if (active) {
          setLoadError(err instanceof Error ? err.message : t('header.bffLoadErrorFallback'));
        }
      });

    const source = new EventSource('/api/v1/stream');
    source.onmessage = (event) => {
      try {
        const next = JSON.parse(event.data) as WorkspaceState;
        if (active) setState(next);
      } catch {
        // Ignore malformed SSE keepalives
      }
    };

    return () => {
      active = false;
      source.close();
    };
  }, [t]);

  const runAction = async (
    key: string,
    fn: () => Promise<WorkspaceState | void>,
    successMsg?: string,
  ) => {
    setBusyKey(key);
    try {
      const nextState = await fn();
      if (nextState) setState(nextState);
      if (successMsg) showToast('info', successMsg);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : t('toasts.operationError'));
    } finally {
      setBusyKey(null);
    }
  };

  const handleProfileChange = (profile: OperatingProfile) =>
    runAction(
      'context',
      () => api.updateContext({ profile }),
      profile === 'residential' ? t('toasts.profileResidential') : t('toasts.profileBusiness'),
    );

  const handleRoleChange = (simulatedRole: SimulatedRole) =>
    runAction(
      'context',
      () => api.updateContext({ simulatedRole }),
      t('toasts.roleChanged', { role: simulatedRole }),
    );

  const handleAutonomyChange = (globalAutonomy: AutonomyLevel) =>
    runAction(
      'context',
      () => api.updateContext({ globalAutonomy }),
      t('toasts.autonomyChanged', { level: globalAutonomy }),
    );

  const handleSiteChange = (activeSiteId: string) =>
    runAction('context', () => api.updateContext({ activeSiteId }));

  const handleToggleOutage = (nodeAvailable: boolean) =>
    runAction(
      'outage',
      () => api.toggleNodeOutage(nodeAvailable),
      nodeAvailable ? t('toasts.nodeReconnected') : t('toasts.nodeOutageSim'),
    );

  const handleKillSwitch = () => {
    if (!state) return;
    const next = !state.context.killSwitchActive;
    runAction(
      'kill-switch',
      () => api.triggerKillSwitch(next),
      next ? t('toasts.killSwitchOn') : t('toasts.killSwitchOff'),
    );
  };

  const handleSyncAll = () =>
    runAction('sync-all', async () => {
      const res = await api.syncAllIntegrations();
      const okCount = res.results.length;
      const errCount = res.errors.length;
      showToast(
        errCount > 0 && okCount === 0 ? 'error' : 'info',
        t('toasts.syncBatch', { ok: okCount, err: errCount }),
      );
      return res.state;
    });

  const currentTabItem = NAV_ITEMS.find((item) => item.id === activeTab);
  const currentTabTitle = currentTabItem ? t(currentTabItem.labelKey) : t('nav.overview');

  if (loadError) {
    return (
      <div className="min-h-screen bg-[#0B1120] text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl border border-slate-800 bg-[#131C31] p-6 space-y-4">
          <h1 className="text-lg font-semibold text-slate-100">{t('header.bffConnectErrorTitle')}</h1>
          <p className="text-sm text-slate-400">{loadError}</p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer"
          >
            {t('common.retry')}
          </button>
        </div>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="min-h-screen bg-[#0B1120] text-slate-300 flex items-center justify-center p-6">
        <div className="text-sm font-mono">{t('header.initializing')}</div>
      </div>
    );
  }

  const isBusiness = state.context.profile === 'business';

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex">
      {/* Desktop Left Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-[252px] lg:shrink-0 border-r border-slate-800 bg-[#0F172A]">
        <div className="h-16 px-6 flex items-center border-b border-slate-800">
          <a
            href="#overview"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('overview');
            }}
            className="text-lg font-bold tracking-tight text-slate-50 font-display whitespace-nowrap shrink-0"
          >
            OpenShield
          </a>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-slate-800 text-slate-50'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-blue-400' : 'text-slate-400'}`} />
                <span className="truncate">{t(item.labelKey)}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800 text-xs text-slate-400 space-y-1">
          <div className="font-medium text-slate-300">
            {isBusiness ? t('toolbar.sidebarProfileBusiness') : t('toolbar.sidebarProfileResidential')}
          </div>
          <div className="font-mono text-[11px] text-slate-500">
            {state.integrations.filter((i) => i.mode === 'live').length} Live ·{' '}
            {state.integrations.filter((i) => i.mode === 'mock').length} Mock
          </div>
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-50 lg:hidden bg-black/60 flex"
          onClick={() => setMobileMenuOpen(false)}
        >
          <aside
            className="w-[252px] bg-[#0F172A] border-r border-slate-800 h-full flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="h-16 px-5 flex items-center justify-between border-b border-slate-800">
              <span className="text-lg font-bold tracking-tight text-slate-50 font-display">
                OpenShield
              </span>
              <button
                type="button"
                aria-label={t('nav.closeMenu')}
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-100 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <nav className="p-3 space-y-1">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium cursor-pointer ${
                      active ? 'bg-slate-800 text-slate-50' : 'text-slate-400 hover:text-slate-100'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Column */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Strict 3-zone Top Header */}
        <header className="h-16 px-4 lg:px-8 border-b border-slate-800 bg-[#0F172A] flex items-center justify-between gap-8">
          {/* Zone 1: Breadcrumb */}
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label={t('nav.openMenu')}
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 -ml-2 rounded-lg text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="text-xs text-slate-400 whitespace-nowrap truncate">
              <span>OpenShield</span>
              <span className="mx-2 text-slate-600">/</span>
              <span className="text-slate-100 font-medium">{currentTabTitle}</span>
            </div>
          </div>

          {/* Zone 2: Quick Search */}
          <div className="hidden md:flex items-center flex-1 max-w-md">
            <div className="relative w-full">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('header.searchPlaceholder')}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-800 bg-slate-950 text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Zone 3: 1 Primary Action (Emergency Kill Switch) */}
          <div className="shrink-0">
            <button
              type="button"
              disabled={busyKey === 'kill-switch'}
              onClick={handleKillSwitch}
              className={`inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50 ${
                state.context.killSwitchActive
                  ? 'bg-red-600 text-white hover:bg-red-500'
                  : 'border border-red-800/70 bg-red-950/30 text-red-300 hover:bg-red-900/50'
              }`}
            >
              <OctagonAlert className="w-3.5 h-3.5" />
              <span>
                {state.context.killSwitchActive
                  ? t('header.killSwitchActive')
                  : t('header.killSwitchIdle')}
              </span>
            </button>
          </div>
        </header>

        {/* Workspace Context Toolbar (Profile, RBAC, Autonomy, Language, Node status) */}
        <div className="px-4 lg:px-8 py-3 border-b border-slate-800 bg-[#0B1120] flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-3">
            {/* Profile Switcher */}
            <div className="inline-flex items-center p-1 rounded-lg bg-[#131C31] border border-slate-800">
              <button
                type="button"
                disabled={busyKey === 'context'}
                onClick={() => handleProfileChange('residential')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  !isBusiness ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Home className="w-3.5 h-3.5" />
                <span>{t('toolbar.profileResidential')}</span>
              </button>
              <button
                type="button"
                disabled={busyKey === 'context'}
                onClick={() => handleProfileChange('business')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  isBusiness ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Building2 className="w-3.5 h-3.5" />
                <span>{t('toolbar.profileBusiness')}</span>
              </button>
            </div>

            {/* Simulated RBAC & Multi-site (Business mode) */}
            {isBusiness && (
              <>
                <label className="inline-flex items-center gap-2 text-slate-300">
                  <span className="text-slate-400">{t('toolbar.rbacRoleLabel')}</span>
                  <select
                    value={state.context.simulatedRole}
                    onChange={(e) => handleRoleChange(e.target.value as SimulatedRole)}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs"
                  >
                    <option value="admin">{t('toolbar.roleAdmin')}</option>
                    <option value="operator">{t('toolbar.roleOperator')}</option>
                    <option value="auditor">{t('toolbar.roleAuditor')}</option>
                  </select>
                </label>

                <label className="inline-flex items-center gap-2 text-slate-300">
                  <span className="text-slate-400">{t('toolbar.siteLabel')}</span>
                  <select
                    value={state.context.activeSiteId}
                    onChange={(e) => handleSiteChange(e.target.value)}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs"
                  >
                    {state.context.sites
                      .filter((s) => s.profile === 'business')
                      .map((site) => (
                        <option key={site.id} value={site.id}>
                          {site.name}
                        </option>
                      ))}
                  </select>
                </label>
              </>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-slate-300">
              <span className="text-slate-400">{t('toolbar.autonomyLabel')}</span>
              <select
                value={state.context.globalAutonomy}
                disabled={state.context.killSwitchActive}
                onChange={(e) => handleAutonomyChange(e.target.value as AutonomyLevel)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs disabled:opacity-50"
              >
                <option value="L0">{t('toolbar.autonomyL0')}</option>
                <option value="L1">{t('toolbar.autonomyL1')}</option>
                <option value="L2">{t('toolbar.autonomyL2')}</option>
                <option value="L3">{t('toolbar.autonomyL3')}</option>
              </select>
            </label>

            {/* i18n Language Switcher */}
            <label className="inline-flex items-center gap-1.5 text-slate-300">
              <Languages className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="sr-only">{t('toolbar.languageLabel')}</span>
              <select
                aria-label={t('toolbar.languageLabel')}
                value={i18n.language}
                onChange={(e) => void i18n.changeLanguage(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs cursor-pointer"
              >
                {SUPPORTED_LANGUAGES.map((lang) => (
                  <option key={lang.code} value={lang.code}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </label>

            <div className="flex items-center gap-1.5 text-slate-300">
              <Activity
                className={`w-3.5 h-3.5 ${
                  state.context.nodeAvailable ? 'text-emerald-500' : 'text-amber-500'
                }`}
              />
              <span>
                {state.context.nodeAvailable
                  ? t('toolbar.nodeConnected')
                  : t('toolbar.nodeOffline')}
              </span>
            </div>
          </div>
        </div>

        {/* Contextual Security Boundary Banner for Business Profile */}
        {isBusiness && (
          <div className="mx-4 lg:mx-8 mt-5 rounded-lg border border-slate-800 bg-[#131C31] px-4 py-3 flex items-start gap-3 text-xs text-slate-300">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="font-semibold text-slate-100">
                {t('toolbar.businessBannerTitle')}
              </strong>{' '}
              {t('toolbar.businessBannerBody')}
            </div>
          </div>
        )}

        {/* Main Viewport */}
        <main className="flex-1 p-4 lg:p-8 max-w-[1440px] w-full mx-auto">
          <Suspense
            fallback={
              <div className="rounded-xl border border-slate-800 bg-[#131C31] p-8 text-xs font-mono text-slate-400">
                {t('header.initializing')}
              </div>
            }
          >
            {activeTab === 'overview' && (
            <OverviewView
              state={state}
              onNavigate={setActiveTab}
              onToggleNodeOutage={handleToggleOutage}
              onQuickInvestigate={(incId) => {
                setSelectedIncidentId(incId);
                setActiveTab('incidents');
              }}
              onSyncAllHealth={handleSyncAll}
              busyKey={busyKey}
            />
          )}

          {activeTab === 'integrations' && (
            <IntegrationsView
              state={state}
              onSwitchMode={(id: string, mode: ServiceProviderMode, liveUrl: string) =>
                runAction(`mode-${id}`, async () => {
                  const res = await api.switchIntegrationMode(id, mode, liveUrl);
                  showToast('info', res.diagnostic);
                  return res.state;
                })
              }
              onSyncAdapter={(id: string) =>
                runAction(`sync-${id}`, async () => {
                  const res = await api.syncIntegration(id);
                  showToast('info', res.result.message);
                  return res.state;
                })
              }
              onSyncAll={handleSyncAll}
              onUpdatePeriodicSync={(periodicSync: PeriodicSyncConfig) => {
                const sec = periodicSync.intervalSeconds;
                const label = sec >= 60 && sec % 60 === 0 ? `${sec / 60}m` : `${sec}s`;
                return runAction(
                  'periodic-sync',
                  () => api.updateContext({ periodicSync }),
                  periodicSync.enabled
                    ? t('toasts.periodicSyncOn', { interval: label })
                    : t('toasts.periodicSyncOff'),
                );
              }}
              onHandshake={(id) =>
                runAction(
                  `handshake-${id}`,
                  () => api.runHandshake(id),
                  t('toasts.handshakeDone', { id }),
                )
              }
              onToggleOutage={handleToggleOutage}
              onInjectSampleEvent={() =>
                runAction('ingest', async () => {
                  const sourceAdapter =
                    state.integrations.find((i) => i.domain === 'ids') ?? state.integrations[0];
                  if (!sourceAdapter) {
                    throw new Error(t('toasts.needServiceBeforeIngest'));
                  }
                  const res = await api.ingestEvent({
                    sourceIntegrationId: sourceAdapter.id,
                    eventType: sourceAdapter.domain === 'dns' ? 'dns.query' : 'ids.alert',
                    severity: 'medium',
                    deviceId: state.devices[0]?.id,
                    summary: t('toasts.sampleTestSummary'),
                    payload: { simulated: true, port: 8443 },
                  });
                  showToast(
                    'info',
                    res.status === 'buffered'
                      ? t('toasts.eventBuffered')
                      : t('toasts.eventValidated', { id: sourceAdapter.id }),
                  );
                  return res.state;
                })
              }
              onSendLiveCorrelatedBatch={() =>
                runAction('ingest-live-batch', async () => {
                  const sourceAdapter =
                    state.integrations.find((i) => i.domain === 'ids') ?? state.integrations[0];
                  if (!sourceAdapter) {
                    throw new Error(t('toasts.needServiceBeforeCorrelate'));
                  }
                  const res = await api.ingestLanEvents([
                    {
                      schemaVersion: 'openshield.event.v1',
                      sourceIntegrationId: sourceAdapter.id,
                      eventType: 'ids.alert',
                      severity: 'high',
                      deviceId: state.devices[0]?.id,
                      summary: t('toasts.liveBatchSummary'),
                      payload: { dstPort: 445, proto: 'TCP', srcIp: state.devices[0]?.ip || '192.168.1.20' },
                    },
                  ]);
                  const createdId = res.statuses[0]?.correlatedIncidentId;
                  showToast(
                    'info',
                    createdId
                      ? t('toasts.eventCorrelated', { id: createdId })
                      : t('toasts.eventIngestedOk'),
                  );
                  return res.state;
                })
              }
              onTestBadProvenance={() =>
                runAction('bad-prov', async () => {
                  await api.ingestEvent({
                    sourceIntegrationId: 'rogue-sensor-99',
                    eventType: 'ids.alert',
                    severity: 'high',
                    summary: t('toasts.badProvenanceSummary'),
                  });
                })
              }
              onRegisterManual={(payload: {
                id: string;
                name: string;
                domain: IntegrationAdapter['domain'];
                kind: string;
                liveEndpointUrl: string;
                configMetadata?: Record<string, string>;
              }) =>
                runAction(
                  'manual-reg',
                  () => api.registerManualIntegration(payload),
                  t('toasts.serviceRegistered', { name: payload.name }),
                )
              }
              onOpenSettings={() => setActiveTab('settings')}
              busyKey={busyKey}
            />
          )}

          {activeTab === 'devices' && (
            <DevicesTopologyView
              state={state}
              searchQuery={searchQuery}
              onAddDevice={(payload) =>
                runAction(
                  'add-device',
                  () => api.addDevice(payload),
                  t('toasts.deviceAdded', { hostname: payload.hostname }),
                )
              }
              onUpdateDevice={(id, patch) =>
                runAction(
                  `upd-dev-${id}`,
                  () => api.updateDevice(id, patch),
                  t('toasts.deviceUpdated'),
                )
              }
              onRemoveDevice={(id, hostname) =>
                runAction(
                  `rm-dev-${id}`,
                  () => api.removeDevice(id),
                  t('toasts.deviceRemoved', { hostname }),
                )
              }
              onImportOpenWrtMap={(payload) =>
                runAction('import-openwrt-map', async () => {
                  const res = await api.importOpenWrtMap(payload);
                  return res.state;
                }, t('toasts.openwrtMapped'))
              }
              busyKey={busyKey}
            />
          )}

          {activeTab === 'dns' && (
            <DnsPrivacyView
              state={state}
              searchQuery={searchQuery}
              onAddDnsInsight={(payload) =>
                runAction(
                  'dns-add',
                  () => api.addDnsInsight(payload),
                  t('toasts.dnsAdded', { domain: payload.domain }),
                )
              }
              onUpdateDnsList={(id: string, listStatus: DnsInsight['listStatus']) =>
                runAction(
                  `dns-${id}`,
                  () => api.updateDnsList(id, listStatus),
                  t('toasts.dnsListUpdated', { status: listStatus }),
                )
              }
              busyKey={busyKey}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsAiView
              state={state}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              onInvestigate={(incidentId, mode) =>
                runAction(
                  `inv-${mode === 'local' ? 'local' : 'cloud'}-${incidentId}`,
                  () => api.investigateIncident(incidentId, mode),
                  mode === 'local'
                    ? t('toasts.investigatedLocal')
                    : t('toasts.investigatedCloud'),
                )
              }
              onToggleCloudOptIn={(enabled) =>
                runAction(
                  'context',
                  () => api.updateContext({ cloudAiOptIn: enabled }),
                  enabled ? t('toasts.cloudOptInOn') : t('toasts.cloudOptInOff'),
                )
              }
              onUpdateSensitivity={(aiSensitivity: AiSensitivityConfig) =>
                runAction(
                  'ai-sensitivity',
                  () => api.updateContext({ aiSensitivity }),
                  t('toasts.sensitivityUpdated', {
                    preset: aiSensitivity.preset,
                    score: aiSensitivity.minRiskScoreAlert,
                  }),
                )
              }
              onProposeAction={(incidentId, policyId) =>
                runAction(`propose-${incidentId}`, async () => {
                  const res = await api.proposeAction(incidentId, policyId);
                  showToast('info', t('toasts.policyProposed'));
                  return res.state;
                })
              }
              onUpdateStatus={(incidentId: string, status: Incident['status']) =>
                runAction(
                  `inc-status-${incidentId}`,
                  () => api.updateIncidentStatus(incidentId, status),
                  t('toasts.incidentStatusUpdated'),
                )
              }
              busyKey={busyKey}
            />
          )}

          {activeTab === 'policies' && (
            <PoliciesAuditView
              state={state}
              onTogglePolicy={(id, enabled) =>
                runAction(
                  `policy-${id}`,
                  () => api.togglePolicy(id, enabled),
                  t('toasts.policyToggled', {
                    status: enabled
                      ? t('toasts.policyToggledEnabled')
                      : t('toasts.policyToggledDisabled'),
                  }),
                )
              }
              onProposeAction={(incidentId, policyId, ttlSeconds) =>
                runAction(`propose-${incidentId}`, async () => {
                  const res = await api.proposeAction(incidentId, policyId, ttlSeconds);
                  showToast('info', t('toasts.policyEvaluated'));
                  return res.state;
                })
              }
              onApproveExecution={(id) =>
                runAction(
                  `approve-${id}`,
                  () => api.approveExecution(id),
                  t('toasts.l3Approved'),
                )
              }
              onRollbackExecution={(id) =>
                runAction(
                  `rollback-${id}`,
                  () => api.rollbackExecution(id),
                  t('toasts.rollbackDone'),
                )
              }
              onChangeAutonomy={handleAutonomyChange}
              busyKey={busyKey}
            />
          )}

          {activeTab === 'audit' && <AuditLogsView state={state} searchQuery={searchQuery} />}

          {activeTab === 'settings' && (
            <SettingsView
              state={state}
              onAddService={(payload) =>
                runAction(
                  'add-service',
                  () => api.registerManualIntegration(payload),
                  t('toasts.serviceSavedInSettings', { name: payload.name }),
                )
              }
              onSaveConfig={(id, payload) =>
                runAction(
                  `cfg-${id}`,
                  () => api.updateIntegrationConfig(id, payload),
                  payload.clearSecret
                    ? t('toasts.credentialsCleared', { id })
                    : t('toasts.changesSavedFor', { id }),
                )
              }
              onRemoveIntegration={(id, name) =>
                runAction(
                  `rm-${id}`,
                  () => api.removeIntegration(id),
                  t('toasts.serviceDeleted', { name }),
                )
              }
              onTestAndActivateLive={(id, liveUrl) =>
                runAction(`mode-${id}`, async () => {
                  const res = await api.switchIntegrationMode(id, 'live', liveUrl);
                  showToast('info', res.diagnostic);
                  return res.state;
                })
              }
              onAddSite={(payload) =>
                runAction(
                  'site-add',
                  () => api.addSite(payload),
                  t('toasts.siteAdded', { name: payload.name }),
                )
              }
              onRemoveSite={(siteId, siteName) =>
                runAction(
                  `site-rm-${siteId}`,
                  () => api.removeSite(siteId),
                  t('toasts.siteRemoved', { name: siteName }),
                )
              }
              onExportBackup={() =>
                runAction('backup-export', async () => {
                  const data = await api.exportBackup();
                  const blob = new Blob([JSON.stringify(data, null, 2)], {
                    type: 'application/json',
                  });
                  const url = URL.createObjectURL(blob);
                  const anchor = document.createElement('a');
                  anchor.href = url;
                  anchor.download = `openshield-backup-${new Date().toISOString().slice(0, 10)}.json`;
                  document.body.appendChild(anchor);
                  anchor.click();
                  document.body.removeChild(anchor);
                  URL.revokeObjectURL(url);
                  showToast('info', t('toasts.backupExported'));
                })
              }
              onRestoreBackup={(payload) =>
                runAction(
                  'backup-restore',
                  () => api.restoreBackup(payload),
                  t('toasts.backupRestored'),
                )
              }
              onLoadDemo={() =>
                runAction(
                  'workspace-demo',
                  () => api.loadDemoScenario(),
                  t('toasts.demoLoaded'),
                )
              }
              onResetWorkspace={() =>
                runAction(
                  'workspace-reset',
                  () => api.resetWorkspace(),
                  t('toasts.workspaceReset'),
                )
              }
              onNavigateToIntegrations={() => setActiveTab('integrations')}
              onAddNotification={(payload) =>
                runAction(
                  'notif-add',
                  () => api.addNotificationDestination(payload),
                  t('toasts.notifAdded', { name: payload.name }),
                )
              }
              onUpdateNotification={(id, payload) =>
                runAction(
                  `notif-upd-${id}`,
                  () => api.updateNotificationDestination(id, payload),
                  t('toasts.notifUpdated'),
                )
              }
              onRemoveNotification={(id, name) =>
                runAction(
                  `notif-rm-${id}`,
                  () => api.removeNotificationDestination(id),
                  t('toasts.notifRemoved', { name }),
                )
              }
              onTestNotification={(id) =>
                runAction(`notif-test-${id}`, async () => {
                  const res = await api.testNotificationDestination(id);
                  showToast(
                    res.status === 'sent' ? 'info' : 'error',
                    res.message,
                  );
                  return res.state;
                })
              }
              busyKey={busyKey}
            />
          )}
          </Suspense>
        </main>
      </div>

      {/* Non-blocking feedback toast */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 max-w-md rounded-xl border border-slate-700 bg-[#131C31] px-4 py-3 shadow-xl flex items-start gap-3 text-xs">
          {toast.kind === 'error' ? (
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          )}
          <span className="text-slate-100 leading-relaxed">{toast.message}</span>
          <button
            type="button"
            aria-label={t('header.dismissToast')}
            onClick={() => setToast(null)}
            className="text-slate-400 hover:text-slate-200 ml-2 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
