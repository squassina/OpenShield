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
  Lock,
  LogIn,
  LogOut,
  Menu,
  Moon,
  Network,
  OctagonAlert,
  PlugZap,
  ScrollText,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Sun,
  X,
} from 'lucide-react';
import { SUPPORTED_LANGUAGES } from './i18n';
import { OverviewView, type NavTab } from './components/OverviewView';
import { api } from './lib/api';
import { useTheme } from './lib/theme';

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
  AuthStatus,
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
  const { isDark, toggleTheme } = useTheme();
  const [state, setState] = useState<WorkspaceState | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [toast, setToast] = useState<{ kind: 'info' | 'error'; message: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginBusy, setLoginBusy] = useState(false);

  const showToast = useCallback((kind: 'info' | 'error', message: string) => {
    setToast({ kind, message });
  }, []);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(id);
  }, [toast]);

  // Initial auth probe + global 401 listener
  useEffect(() => {
    let active = true;
    api
      .getAuthStatus()
      .then((status) => {
        if (active) setAuthStatus(status);
      })
      .catch((err) => {
        if (active) {
          setLoadError(err instanceof Error ? err.message : t('header.bffLoadErrorFallback'));
        }
      });

    const handleAuthRequired = () => {
      setState(null);
      setAuthStatus((prev) => ({
        authConfigured: prev?.authConfigured ?? true,
        authRequired: true,
        authenticated: false,
        envAdminEnabled: prev?.envAdminEnabled ?? false,
        user: null,
      }));
    };

    window.addEventListener('openshield:auth-required', handleAuthRequired);
    return () => {
      active = false;
      window.removeEventListener('openshield:auth-required', handleAuthRequired);
    };
  }, [t]);

  const canAccessWorkspace =
    authStatus !== null && (!authStatus.authRequired || authStatus.authenticated);

  // Initial state load + live SSE stream subscription (only after auth check passes)
  useEffect(() => {
    if (!canAccessWorkspace) return;
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
  }, [canAccessWorkspace, t]);

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

  const handleTogglePersistentUci = (enabled: boolean) =>
    runAction(
      'uci-persist',
      () => api.updateContext({ persistentUciFirewall: enabled }),
      enabled ? t('toasts.uciPersistOn') : t('toasts.uciPersistOff'),
    );

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginBusy(true);
    setLoginError(null);
    try {
      const res =
        authStatus && !authStatus.authConfigured
          ? await api.setupInitialAdmin({ username: loginUsername.trim() || 'admin', password: loginPassword })
          : await api.login({ username: loginUsername.trim(), password: loginPassword });
      setLoginPassword('');
      setAuthStatus(res.status);
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : t('auth.loginErrorFallback'));
    } finally {
      setLoginBusy(false);
    }
  };

  const handleLogout = async () => {
    setBusyKey('logout');
    try {
      const res = await api.logout();
      setState(null);
      setAuthStatus(res.status);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : t('toasts.operationError'));
    } finally {
      setBusyKey(null);
    }
  };

  const currentTabItem = NAV_ITEMS.find((item) => item.id === activeTab);
  const currentTabTitle = currentTabItem ? t(currentTabItem.labelKey) : t('nav.overview');

  if (loadError) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] p-6 space-y-4 shadow-xs dark:shadow-none">
          <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">{t('header.bffConnectErrorTitle')}</h1>
          <p className="text-sm text-slate-600 dark:text-slate-400">{loadError}</p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 cursor-pointer"
          >
            {t('common.retry')}
          </button>
        </div>
      </div>
    );
  }

  if (authStatus && authStatus.authRequired && !authStatus.authenticated) {
    const needsInitialSetup = !authStatus.authConfigured;
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 flex items-center justify-center p-6">
        <form
          onSubmit={(e) => void handleLoginSubmit(e)}
          className="max-w-md w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] p-6 space-y-5 shadow-xs dark:shadow-none"
        >
          <div className="flex items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
                <Lock className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <h1 className="text-base font-bold text-slate-900 dark:text-slate-50 font-display">OpenShield</h1>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  {needsInitialSetup ? t('auth.setupCardTitle') : t('auth.loginSubtitle')}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={toggleTheme}
                aria-label={isDark ? t('toolbar.themeSwitchToLight') : t('toolbar.themeSwitchToDark')}
                title={isDark ? t('toolbar.themeSwitchToLight') : t('toolbar.themeSwitchToDark')}
                className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              >
                {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-emerald-700" />}
              </button>

              <select
                aria-label={t('toolbar.languageLabel')}
                value={i18n.language}
                onChange={(e) => void i18n.changeLanguage(e.target.value)}
                className="px-2 py-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200 text-xs cursor-pointer"
              >
                {SUPPORTED_LANGUAGES.map((lang) => (
                  <option key={lang.code} value={lang.code}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {needsInitialSetup && (
            <div className="rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/25 px-3.5 py-2.5 text-xs text-emerald-900 dark:text-emerald-200">
              {t('auth.setupCardDesc')}
            </div>
          )}

          {loginError && (
            <div className="rounded-lg border border-red-200 dark:border-red-900/70 bg-red-50 dark:bg-red-950/30 px-3.5 py-2.5 text-xs text-red-800 dark:text-red-200">
              {loginError}
            </div>
          )}

          <div className="space-y-3.5">
            <label className="block space-y-1 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">{t('auth.usernameLabel')}</span>
              <input
                type="text"
                required
                autoFocus
                autoComplete="username"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-700 dark:text-slate-300 font-medium">
                {needsInitialSetup ? t('auth.passwordMinLabel') : t('auth.passwordLabel')}
              </span>
              <input
                type="password"
                required
                minLength={needsInitialSetup ? 8 : 1}
                autoComplete={needsInitialSetup ? 'new-password' : 'current-password'}
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </label>
          </div>

          <button
            type="submit"
            disabled={loginBusy}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors cursor-pointer disabled:opacity-50"
          >
            <LogIn className="w-3.5 h-3.5" />
            <span>{needsInitialSetup ? t('auth.enableAuthButton') : t('auth.loginButton')}</span>
          </button>

          <p className="text-[11px] text-slate-500 text-center">{t('auth.cookieHardeningNote')}</p>
        </form>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-[#0B1120] text-slate-700 dark:text-slate-300 flex items-center justify-center p-6">
        <div className="text-sm font-mono">{t('header.initializing')}</div>
      </div>
    );
  }

  const isBusiness = state.context.profile === 'business';

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0B1120] text-slate-900 dark:text-slate-100 flex">
      {/* Desktop Left Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-[252px] lg:shrink-0 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0F172A]">
        <div className="h-16 px-6 flex items-center gap-2.5 border-b border-slate-200 dark:border-slate-800">
          <div className="w-7 h-7 rounded-lg bg-emerald-600/15 border border-emerald-600/30 flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <a
            href="#overview"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('overview');
            }}
            className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-50 font-display whitespace-nowrap shrink-0"
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
                    ? 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/45 dark:text-slate-50'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900/60'
                }`}
              >
                <Icon
                  className={`w-4 h-4 shrink-0 ${
                    active ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                  }`}
                />
                <span className="truncate">{t(item.labelKey)}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 space-y-1">
          <div className="font-medium text-slate-800 dark:text-slate-300">
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
          className="fixed inset-0 z-50 lg:hidden bg-black/50 dark:bg-black/60 flex"
          onClick={() => setMobileMenuOpen(false)}
        >
          <aside
            className="w-[252px] bg-white dark:bg-[#0F172A] border-r border-slate-200 dark:border-slate-800 h-full flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="h-16 px-5 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-emerald-600/15 border border-emerald-600/30 flex items-center justify-center shrink-0">
                  <Shield className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                </div>
                <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-50 font-display">
                  OpenShield
                </span>
              </div>
              <button
                type="button"
                aria-label={t('nav.closeMenu')}
                onClick={() => setMobileMenuOpen(false)}
                className="p-1.5 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 cursor-pointer"
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
                      active
                        ? 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/45 dark:text-slate-50'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-100'
                    }`}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 ${
                        active ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                      }`}
                    />
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
        <header className="h-16 px-4 lg:px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0F172A] flex items-center justify-between gap-8">
          {/* Zone 1: Breadcrumb */}
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              aria-label={t('nav.openMenu')}
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden p-2 -ml-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap truncate">
              <span>OpenShield</span>
              <span className="mx-2 text-slate-300 dark:text-slate-600">/</span>
              <span className="text-slate-900 dark:text-slate-100 font-medium">{currentTabTitle}</span>
            </div>
          </div>

          {/* Zone 2: Quick Search */}
          <div className="hidden md:flex items-center flex-1 max-w-md">
            <div className="relative w-full">
              <Search className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('header.searchPlaceholder')}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
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
                  : 'border border-red-200 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800/70 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-900/50'
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

        {/* Workspace Context Toolbar (Profile, RBAC, Autonomy, Language, Theme, Node status) */}
        <div className="px-4 lg:px-8 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#0B1120] flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-3">
            {/* Profile Switcher */}
            <div className="inline-flex items-center p-1 rounded-lg bg-white dark:bg-[#131C31] border border-slate-200 dark:border-slate-800">
              <button
                type="button"
                disabled={busyKey === 'context'}
                onClick={() => handleProfileChange('residential')}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  !isBusiness
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
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
                  isBusiness
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                }`}
              >
                <Building2 className="w-3.5 h-3.5" />
                <span>{t('toolbar.profileBusiness')}</span>
              </button>
            </div>

            {/* Simulated RBAC & Multi-site (Business mode) */}
            {isBusiness && (
              <>
                <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <span className="text-slate-500 dark:text-slate-400">{t('toolbar.rbacRoleLabel')}</span>
                  <select
                    value={state.context.simulatedRole}
                    onChange={(e) => handleRoleChange(e.target.value as SimulatedRole)}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
                  >
                    <option value="admin">{t('toolbar.roleAdmin')}</option>
                    <option value="operator">{t('toolbar.roleOperator')}</option>
                    <option value="auditor">{t('toolbar.roleAuditor')}</option>
                  </select>
                </label>

                <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <span className="text-slate-500 dark:text-slate-400">{t('toolbar.siteLabel')}</span>
                  <select
                    value={state.context.activeSiteId}
                    onChange={(e) => handleSiteChange(e.target.value)}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-emerald-500"
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
            <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300">
              <span className="text-slate-500 dark:text-slate-400">{t('toolbar.autonomyLabel')}</span>
              <select
                value={state.context.globalAutonomy}
                disabled={state.context.killSwitchActive}
                onChange={(e) => handleAutonomyChange(e.target.value as AutonomyLevel)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-900 dark:text-slate-100 text-xs disabled:opacity-50 focus:outline-none focus:border-emerald-500"
              >
                <option value="L0">{t('toolbar.autonomyL0')}</option>
                <option value="L1">{t('toolbar.autonomyL1')}</option>
                <option value="L2">{t('toolbar.autonomyL2')}</option>
                <option value="L3">{t('toolbar.autonomyL3')}</option>
              </select>
            </label>

            {/* i18n Language Switcher */}
            <label className="inline-flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
              <Languages className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400 shrink-0" />
              <span className="sr-only">{t('toolbar.languageLabel')}</span>
              <select
                aria-label={t('toolbar.languageLabel')}
                value={i18n.language}
                onChange={(e) => void i18n.changeLanguage(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-900 dark:text-slate-100 text-xs cursor-pointer focus:outline-none focus:border-emerald-500"
              >
                {SUPPORTED_LANGUAGES.map((lang) => (
                  <option key={lang.code} value={lang.code}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </label>

            {/* Light / Dark Theme Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? t('toolbar.themeSwitchToLight') : t('toolbar.themeSwitchToDark')}
              title={isDark ? t('toolbar.themeSwitchToLight') : t('toolbar.themeSwitchToDark')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {isDark ? (
                <Sun className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              ) : (
                <Moon className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
              )}
              <span>{isDark ? t('toolbar.themeDark') : t('toolbar.themeLight')}</span>
            </button>

            <div className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300">
              <Activity
                className={`w-3.5 h-3.5 ${
                  state.context.nodeAvailable
                    ? 'text-emerald-600 dark:text-emerald-500'
                    : 'text-amber-600 dark:text-amber-500'
                }`}
              />
              <span>
                {state.context.nodeAvailable
                  ? t('toolbar.nodeConnected')
                  : t('toolbar.nodeOffline')}
              </span>
            </div>

            {authStatus?.authenticated && authStatus.user && (
              <div className="flex items-center gap-2 pl-2 border-l border-slate-200 dark:border-slate-800">
                <span className="font-mono text-slate-700 dark:text-slate-300">
                  {authStatus.user.username} ·{' '}
                  <span className="text-emerald-700 dark:text-emerald-400">{authStatus.user.role}</span>
                </span>
                <button
                  type="button"
                  disabled={busyKey === 'logout'}
                  onClick={() => void handleLogout()}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#131C31] text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                >
                  <LogOut className="w-3 h-3" />
                  <span>{t('auth.logoutButton')}</span>
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Contextual Security Boundary Banner for Business Profile */}
        {isBusiness && !authStatus?.authConfigured && (
          <div className="mx-4 lg:mx-8 mt-5 rounded-lg border border-amber-200 dark:border-slate-800 bg-amber-50/70 dark:bg-[#131C31] px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-700 dark:text-slate-300">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold text-slate-900 dark:text-slate-100">
                  {t('toolbar.businessBannerTitle')}
                </strong>{' '}
                {t('toolbar.businessBannerBody')}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setActiveTab('settings')}
              className="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 font-medium whitespace-nowrap shrink-0 cursor-pointer"
            >
              {t('auth.configureAuthCta')}
            </button>
          </div>
        )}

        {/* Main Viewport */}
        <main className="flex-1 p-4 lg:p-8 max-w-[1440px] w-full mx-auto">
          <Suspense
            fallback={
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] p-8 text-xs font-mono text-slate-500 dark:text-slate-400">
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
              searchQuery={searchQuery}
              onBlockRouterAccessIp={(id, ttlSeconds) =>
                runAction(`rtr-block-${id}`, async () => {
                  const res = await api.blockRouterAccessIp(id, ttlSeconds);
                  showToast(
                    'info',
                    t('toasts.routerAccessBlocked', {
                      ip: res.execution.targetIp ?? res.execution.targetLabel,
                      mode:
                        res.execution.enforcementMode === 'live'
                          ? t('common.real')
                          : t('common.simulated'),
                    }),
                  );
                  return res.state;
                })
              }
              onUpdateRouterAccessStatus={(id, status) =>
                runAction(
                  `rtr-status-${id}`,
                  () => api.updateRouterAccessStatus(id, status),
                  t('toasts.routerAccessStatusUpdated'),
                )
              }
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
              onTogglePersistentUci={handleTogglePersistentUci}
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
              authStatus={authStatus}
              onAuthStatusChange={setAuthStatus}
              onTogglePersistentUci={handleTogglePersistentUci}
              onNotifyToast={showToast}
              busyKey={busyKey}
            />
          )}
          </Suspense>
        </main>
      </div>

      {/* Non-blocking feedback toast */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 max-w-md rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#131C31] px-4 py-3 shadow-xl flex items-start gap-3 text-xs">
          {toast.kind === 'error' ? (
            <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
          )}
          <span className="text-slate-900 dark:text-slate-100 leading-relaxed">{toast.message}</span>
          <button
            type="button"
            aria-label={t('header.dismissToast')}
            onClick={() => setToast(null)}
            className="text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 ml-2 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
