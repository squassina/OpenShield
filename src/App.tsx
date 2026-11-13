import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Building2,
  CheckCircle2,
  GlobeLock,
  Home,
  LayoutDashboard,
  Menu,
  Network,
  OctagonAlert,
  PlugZap,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react';
import { DevicesTopologyView } from './components/DevicesTopologyView';
import { DnsPrivacyView } from './components/DnsPrivacyView';
import { IncidentsAiView } from './components/IncidentsAiView';
import { IntegrationsView } from './components/IntegrationsView';
import { OverviewView, type NavTab } from './components/OverviewView';
import { PoliciesAuditView } from './components/PoliciesAuditView';
import { SettingsView } from './components/SettingsView';
import { api } from './lib/api';
import type {
  AutonomyLevel,
  DnsInsight,
  Incident,
  IntegrationAdapter,
  OperatingProfile,
  ServiceProviderMode,
  SimulatedRole,
  WorkspaceState,
} from './types/openshield';

const NAV_ITEMS: { id: NavTab; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: 'Visão Geral', icon: LayoutDashboard },
  { id: 'integrations', label: 'Gateway e Integrações', icon: PlugZap },
  { id: 'devices', label: 'Dispositivos e Topologia', icon: Network },
  { id: 'dns', label: 'Privacidade e DNS', icon: GlobeLock },
  { id: 'incidents', label: 'Incidentes e IA', icon: ShieldAlert },
  { id: 'policies', label: 'Políticas e Auditoria', icon: Shield },
  { id: 'settings', label: 'Configurações', icon: Settings },
];

export default function App() {
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
          setLoadError(err instanceof Error ? err.message : 'Falha ao carregar estado inicial.');
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
  }, []);

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
      showToast('error', err instanceof Error ? err.message : 'Erro ao executar operação.');
    } finally {
      setBusyKey(null);
    }
  };

  const handleProfileChange = (profile: OperatingProfile) =>
    runAction(
      'context',
      () => api.updateContext({ profile }),
      profile === 'residential'
        ? 'Perfil alterado para Residencial (LAN confiável).'
        : 'Perfil alterado para Pequeno Escritório (RBAC simulado ativo).',
    );

  const handleRoleChange = (simulatedRole: SimulatedRole) =>
    runAction(
      'context',
      () => api.updateContext({ simulatedRole }),
      `Papel RBAC simulado alterado para ${simulatedRole}.`,
    );

  const handleAutonomyChange = (globalAutonomy: AutonomyLevel) =>
    runAction(
      'context',
      () => api.updateContext({ globalAutonomy }),
      `Teto global de autonomia definido em ${globalAutonomy}.`,
    );

  const handleSiteChange = (activeSiteId: string) =>
    runAction('context', () => api.updateContext({ activeSiteId }));

  const handleToggleOutage = (nodeAvailable: boolean) =>
    runAction(
      'outage',
      () => api.toggleNodeOutage(nodeAvailable),
      nodeAvailable
        ? 'Node reconectado e eventos do outbox drenados com idempotência.'
        : 'Simulação ativada: Node offline, gateway segue roteando e conector bufferiza eventos.',
    );

  const handleKillSwitch = () => {
    if (!state) return;
    const next = !state.context.killSwitchActive;
    runAction(
      'kill-switch',
      () => api.triggerKillSwitch(next),
      next
        ? 'Parada de Emergência (Kill Switch) ativada: automações revertidas para L0.'
        : 'Kill Switch liberado; sistema mantido em L0 Observar por segurança.',
    );
  };

  const handleSyncAll = () =>
    runAction('sync-all', async () => {
      const res = await api.syncAllIntegrations();
      const okCount = res.results.length;
      const errCount = res.errors.length;
      showToast(
        errCount > 0 && okCount === 0 ? 'error' : 'info',
        `Sincronização em lote: ${okCount} sucesso(s), ${errCount} falha(s).`,
      );
      return res.state;
    });

  const currentTabTitle = NAV_ITEMS.find((item) => item.id === activeTab)?.label ?? 'Visão Geral';

  if (loadError) {
    return (
      <div className="min-h-screen bg-[#0B1120] text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl border border-slate-800 bg-[#131C31] p-6 space-y-4">
          <h1 className="text-lg font-semibold text-slate-100">Falha ao conectar ao BFF OpenShield</h1>
          <p className="text-sm text-slate-400">{loadError}</p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer"
          >
            Tentar Novamente
          </button>
        </div>
      </div>
    );
  }

  if (!state) {
    return (
      <div className="min-h-screen bg-[#0B1120] text-slate-300 flex items-center justify-center p-6">
        <div className="text-sm font-mono">Inicializando OpenShield BFF e contratos v1...</div>
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
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800 text-xs text-slate-400 space-y-1">
          <div className="font-medium text-slate-300">
            {isBusiness ? 'Perfil: Pequeno Escritório' : 'Perfil: Residencial'}
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
                aria-label="Fechar menu"
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
                    <span>{item.label}</span>
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
              aria-label="Abrir navegação"
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
                placeholder="Buscar dispositivo, IP ou domínio..."
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
                {state.context.killSwitchActive ? 'Kill Switch Ativo (Liberar)' : 'Parada de Emergência'}
              </span>
            </button>
          </div>
        </header>

        {/* Workspace Context Toolbar (Profile, RBAC, Autonomy, Node status) */}
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
                <span>Residencial</span>
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
                <span>Pequeno Escritório</span>
              </button>
            </div>

            {/* Simulated RBAC & Multi-site (Business mode) */}
            {isBusiness && (
              <>
                <label className="inline-flex items-center gap-2 text-slate-300">
                  <span className="text-slate-400">Papel RBAC:</span>
                  <select
                    value={state.context.simulatedRole}
                    onChange={(e) => handleRoleChange(e.target.value as SimulatedRole)}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs"
                  >
                    <option value="admin">Administrador</option>
                    <option value="operator">Operador</option>
                    <option value="auditor">Auditor (Somente Leitura)</option>
                  </select>
                </label>

                <label className="inline-flex items-center gap-2 text-slate-300">
                  <span className="text-slate-400">Site:</span>
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
              <span className="text-slate-400">Autonomia:</span>
              <select
                value={state.context.globalAutonomy}
                disabled={state.context.killSwitchActive}
                onChange={(e) => handleAutonomyChange(e.target.value as AutonomyLevel)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-700 bg-[#131C31] text-slate-100 text-xs disabled:opacity-50"
              >
                <option value="L0">L0 · Observar</option>
                <option value="L1">L1 · Baixo Impacto</option>
                <option value="L2">L2 · Contenção Limitada</option>
                <option value="L3">L3 · Aprovação Humana</option>
              </select>
            </label>

            <div className="flex items-center gap-1.5 text-slate-300">
              <Activity
                className={`w-3.5 h-3.5 ${
                  state.context.nodeAvailable ? 'text-emerald-500' : 'text-amber-500'
                }`}
              />
              <span>
                {state.context.nodeAvailable ? 'Node Conectado' : 'Node Offline (Gateway Ativo)'}
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
                Simulação de Perfil Pequeno Escritório (RBAC):
              </strong>{' '}
              O modo Residencial opera sem autenticação apenas em LAN confiável. Antes de implantar o perfil Escritório em produção ou multi-site, habilite identidade, credenciais de gateway e RBAC reais no OpenShield Node.
            </div>
          </div>
        )}

        {/* Main Viewport */}
        <main className="flex-1 p-4 lg:p-8 max-w-[1440px] w-full mx-auto">
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
              onHandshake={(id) =>
                runAction(
                  `handshake-${id}`,
                  () => api.runHandshake(id),
                  `Handshake openshield.gateway.v1 concluído para ${id}.`,
                )
              }
              onToggleOutage={handleToggleOutage}
              onInjectSampleEvent={() =>
                runAction('ingest', async () => {
                  const sourceAdapter =
                    state.integrations.find((i) => i.domain === 'ids') ?? state.integrations[0];
                  if (!sourceAdapter) {
                    throw new Error(
                      'Adicione pelo menos um serviço na aba Configurações antes de testar a ingestão de eventos.',
                    );
                  }
                  const res = await api.ingestEvent({
                    sourceIntegrationId: sourceAdapter.id,
                    eventType: sourceAdapter.domain === 'dns' ? 'dns.query' : 'ids.alert',
                    severity: 'medium',
                    deviceId: state.devices[0]?.id,
                    summary: 'Evento de teste normalizado openshield.event.v1 ingerido pelo simulador.',
                    payload: { simulated: true, port: 8443 },
                  });
                  showToast(
                    'info',
                    res.status === 'buffered'
                      ? 'Node offline: evento salvo no spool SQLite local do conector.'
                      : `Evento openshield.event.v1 validado com proveniência "${sourceAdapter.id}".`,
                  );
                  return res.state;
                })
              }
              onSendLiveCorrelatedBatch={() =>
                runAction('ingest-live-batch', async () => {
                  const sourceAdapter =
                    state.integrations.find((i) => i.domain === 'ids') ?? state.integrations[0];
                  if (!sourceAdapter) {
                    throw new Error(
                      'Adicione pelo menos um serviço na aba Configurações antes de testar correlação.',
                    );
                  }
                  const res = await api.ingestLanEvents([
                    {
                      schemaVersion: 'openshield.event.v1',
                      sourceIntegrationId: sourceAdapter.id,
                      eventType: 'ids.alert',
                      severity: 'high',
                      deviceId: state.devices[0]?.id,
                      summary:
                        'Tentativa de enumeração SMB (porta 445) detectada na LAN via endpoint /api/v1/ingest/events.',
                      payload: { dstPort: 445, proto: 'TCP', srcIp: state.devices[0]?.ip || '192.168.1.20' },
                    },
                  ]);
                  const createdId = res.statuses[0]?.correlatedIncidentId;
                  showToast(
                    'info',
                    createdId
                      ? `Evento ingerido e correlacionado automaticamente no incidente ${createdId}.`
                      : 'Evento ingerido via /api/v1/ingest/events.',
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
                    summary: 'Tentativa de injeção sem integração registrada.',
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
                  `Serviço "${payload.name}" registrado.`,
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
                  `Dispositivo "${payload.hostname}" adicionado.`,
                )
              }
              onUpdateDevice={(id, patch) =>
                runAction(
                  `upd-dev-${id}`,
                  () => api.updateDevice(id, patch),
                  'Dispositivo atualizado.',
                )
              }
              onRemoveDevice={(id, hostname) =>
                runAction(
                  `rm-dev-${id}`,
                  () => api.removeDevice(id),
                  `Dispositivo "${hostname}" removido.`,
                )
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
                  `Domínio "${payload.domain}" adicionado à inteligência DNS.`,
                )
              }
              onUpdateDnsList={(id: string, listStatus: DnsInsight['listStatus']) =>
                runAction(
                  `dns-${id}`,
                  () => api.updateDnsList(id, listStatus),
                  `Lista DNS atualizada para "${listStatus}".`,
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
                    ? 'Investigação local-first atualizada com base em evidências.'
                    : 'Segunda opinião via Gemini (payload sanitizado) concluída.',
                )
              }
              onToggleCloudOptIn={(enabled) =>
                runAction(
                  'context',
                  () => api.updateContext({ cloudAiOptIn: enabled }),
                  enabled
                    ? 'Opt-in de segunda opinião em nuvem habilitado.'
                    : 'Modo exclusivamente local-first restaurado.',
                )
              }
              onProposeAction={(incidentId, policyId) =>
                runAction(`propose-${incidentId}`, async () => {
                  const res = await api.proposeAction(incidentId, policyId);
                  showToast(
                    'info',
                    'Política avaliada! Verifique o status, TTL e rollback na aba Políticas e Auditoria.',
                  );
                  return res.state;
                })
              }
              onUpdateStatus={(incidentId: string, status: Incident['status']) =>
                runAction(
                  `inc-status-${incidentId}`,
                  () => api.updateIncidentStatus(incidentId, status),
                  'Status do incidente atualizado.',
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
                  `Política ${enabled ? 'habilitada' : 'desabilitada'}.`,
                )
              }
              onProposeAction={(incidentId, policyId, ttlSeconds) =>
                runAction(`propose-${incidentId}`, async () => {
                  const res = await api.proposeAction(incidentId, policyId, ttlSeconds);
                  showToast('info', 'Avaliação determinística registrada em Execuções.');
                  return res.state;
                })
              }
              onApproveExecution={(id) =>
                runAction(
                  `approve-${id}`,
                  () => api.approveExecution(id),
                  'Ação L3 aprovada e verificada.',
                )
              }
              onRollbackExecution={(id) =>
                runAction(
                  `rollback-${id}`,
                  () => api.rollbackExecution(id),
                  'Rollback executado e verificado no adaptador.',
                )
              }
              onChangeAutonomy={handleAutonomyChange}
              busyKey={busyKey}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              state={state}
              onAddService={(payload) =>
                runAction(
                  'add-service',
                  () => api.registerManualIntegration(payload),
                  `Serviço "${payload.name}" salvo em Serviços e Endpoints Configurados.`,
                )
              }
              onSaveConfig={(id, payload) =>
                runAction(
                  `cfg-${id}`,
                  () => api.updateIntegrationConfig(id, payload),
                  payload.clearSecret
                    ? `Credenciais removidas do cofre do servidor para ${id}.`
                    : `Alterações salvas para ${id}.`,
                )
              }
              onRemoveIntegration={(id, name) =>
                runAction(
                  `rm-${id}`,
                  () => api.removeIntegration(id),
                  `Serviço "${name}" deletado.`,
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
                  `Site "${payload.name}" adicionado.`,
                )
              }
              onRemoveSite={(siteId, siteName) =>
                runAction(
                  `site-rm-${siteId}`,
                  () => api.removeSite(siteId),
                  `Site "${siteName}" removido.`,
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
                  showToast('info', 'Backup JSON sanitizado (sem credenciais) exportado.');
                })
              }
              onRestoreBackup={(payload) =>
                runAction(
                  'backup-restore',
                  () => api.restoreBackup(payload),
                  'Configuração restaurada com segurança a partir do backup JSON.',
                )
              }
              onLoadDemo={() =>
                runAction(
                  'workspace-demo',
                  () => api.loadDemoScenario(),
                  'Cenário de demonstração Mock carregado.',
                )
              }
              onResetWorkspace={() =>
                runAction(
                  'workspace-reset',
                  () => api.resetWorkspace(),
                  'Inventário zerado para configuração manual.',
                )
              }
              onNavigateToIntegrations={() => setActiveTab('integrations')}
              busyKey={busyKey}
            />
          )}
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
            aria-label="Dispensar aviso"
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
