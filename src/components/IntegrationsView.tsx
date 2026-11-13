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
  -d '{"events":[{"schemaVersion":"openshield.event.v1","sourceIntegrationId":"suricata-lan","eventType":"ids.alert","severity":"high","deviceId":"dev-nas-01","summary":"Tentativa de enumeração SMB detectada na LAN","payload":{"dstPort":445,"proto":"TCP"}}]}'`;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            Hub de Gateway e Integrações
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            Alterne e sincronize cada serviço entre Simulador Mock e API Real na LAN confiável sem expor credenciais no navegador.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={state.integrations.length === 0 || busyKey === 'sync-all'}
            onClick={onSyncAll}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${busyKey === 'sync-all' ? 'animate-spin' : ''}`} />
            <span>Sincronizar Todos ({state.integrations.length})</span>
          </button>

          <button
            type="button"
            onClick={onOpenSettings}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Settings className="w-4 h-4 text-blue-400" />
            <span>Configurar Endpoints e DNS</span>
          </button>

          <button
            type="button"
            onClick={() => setShowManualForm((prev) => !prev)}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>{showManualForm ? 'Fechar Cadastro Manual' : 'Configuração Manual (Fallback)'}</span>
          </button>
        </div>
      </div>

      {/* P0 Resilience & Real Ingestion Lab */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Laboratório de Resiliência P0 e Ingestão Real (openshield.event.v1)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Teste queda do Node com spool SQLite, rejeição de proveniência ou envie eventos reais para o correlacionador.
            </p>
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
                  ? 'Simular Queda do Node'
                  : `Reconectar & Drenar (${state.metrics.outboxPendingTotal})`}
              </span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'ingest'}
              onClick={onInjectSampleEvent}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
              <span>Injetar Evento v1</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'ingest-live-batch'}
              onClick={onSendLiveCorrelatedBatch}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5 text-emerald-400" />
              <span>Testar Ingestão & Correlação</span>
            </button>

            <button
              type="button"
              disabled={busyKey === 'bad-prov'}
              onClick={onTestBadProvenance}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <ShieldX className="w-3.5 h-3.5 text-red-400" />
              <span>Testar Proveniência Inválida</span>
            </button>
          </div>
        </div>

        {/* Progressive Disclosure: LAN Ingestion Endpoint & Server Env Status */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2 border-t border-slate-800/80 text-xs">
          <details>
            <summary className="cursor-pointer text-blue-400 hover:text-blue-300 font-medium select-none inline-flex items-center gap-1.5">
              <KeyRound className="w-3.5 h-3.5" />
              <span>Credenciais detectadas no ambiente do servidor (somente status)</span>
            </summary>
            <div className="mt-3 divide-y divide-slate-800/80 rounded-lg border border-slate-800 bg-slate-950/60">
              {envStatus.map((env) => (
                <div key={env.key} className="px-3 py-2 flex items-center justify-between gap-2">
                  <div>
                    <div className="font-mono text-slate-200">{env.key}</div>
                    <div className="text-[11px] text-slate-400">{env.label} · {env.scope}</div>
                  </div>
                  <span
                    className={
                      env.configured ? 'text-emerald-400 font-medium' : 'text-slate-500'
                    }
                  >
                    {env.configured ? 'Configurada' : 'Ausente'}
                  </span>
                </div>
              ))}
            </div>
          </details>

          <details>
            <summary className="cursor-pointer text-blue-400 hover:text-blue-300 font-medium select-none inline-flex items-center gap-1.5">
              <Send className="w-3.5 h-3.5" />
              <span>Endpoint de ingestão LAN para conectores externos (POST /api/v1/ingest/events)</span>
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
                Registrar Integração Manualmente (Fallback de Descoberta)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Campos com nomes de segredos (ex.: password, api_key, token) são rejeitados por segurança e registrados na auditoria.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">ID da Integração</span>
              <input
                type="text"
                value={manualId}
                onChange={(e) => setManualId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">Nome Visível</span>
              <input
                type="text"
                value={manualName}
                onChange={(e) => setManualName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                required
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">Domínio</span>
              <select
                value={manualDomain}
                onChange={(e) => setManualDomain(e.target.value as IntegrationAdapter['domain'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="gateway">Gateway / Firewall</option>
                <option value="dns">Privacidade DNS</option>
                <option value="ids">IDS (Suricata)</option>
                <option value="analytics">Analytics (Zeek)</option>
                <option value="threat_intel">Threat Intel (CrowdSec / MISP)</option>
                <option value="ai_runtime">Runtime IA Local</option>
              </select>
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-300 font-medium">Tipo (Kind)</span>
              <input
                type="text"
                value={manualKind}
                onChange={(e) => setManualKind(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs md:col-span-2">
              <span className="text-slate-300 font-medium">Endpoint Real na LAN</span>
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
              <span className="text-slate-400">Metadado extra (teste enviar &quot;api_key&quot; para validar bloqueio)</span>
              <input
                type="text"
                placeholder="ex.: vlan_id ou api_key"
                value={extraKey}
                onChange={(e) => setExtraKey(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
            <label className="block space-y-1.5 text-xs">
              <span className="text-slate-400">Valor do metadado</span>
              <input
                type="text"
                placeholder="ex.: 10"
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
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyKey === 'manual-reg'}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer disabled:opacity-50"
            >
              Salvar Integração
            </button>
          </div>
        </form>
      )}

      {/* Adapters List */}
      <div className="rounded-xl border border-slate-800 bg-[#131C31] divide-y divide-slate-800">
        {state.integrations.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm text-slate-300 font-medium">
              Nenhum serviço configurado neste ambiente ainda.
            </p>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Acesse <strong>Configurações</strong> para escolher e salvar os serviços da sua rede (OpenWrt, Pi-hole, Suricata, Ollama etc.).
            </p>
            <button
              type="button"
              onClick={onOpenSettings}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer"
            >
              <Settings className="w-3.5 h-3.5" />
              <span>Ir para Configurações</span>
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
                        ? 'Conectado'
                        : adapter.status === 'stale'
                          ? 'Node Offline (Buffer)'
                          : 'Endpoint Indisponível'}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>
                      Modo:{' '}
                      <strong className="text-slate-200 font-medium">
                        {adapter.mode === 'mock' ? 'Simulador Mock' : 'API Real (Live)'}
                      </strong>
                    </span>
                    {adapter.lastSyncedAt && (
                      <>
                        <span aria-hidden="true">·</span>
                        <span>
                          Último sync:{' '}
                          {new Date(adapter.lastSyncedAt).toLocaleTimeString('pt-BR')}
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
                    <span className="text-slate-500">Capacidades declaradas: </span>
                    <span className="font-mono text-slate-300">
                      {adapter.capabilities.join(' · ')}
                    </span>
                  </div>

                  {adapter.boardInfo && (
                    <div className="text-xs text-slate-400 tabular-nums">
                      <span className="text-slate-500">Hardware descoberto: </span>
                      <span>
                        {adapter.boardInfo.model} · {adapter.boardInfo.firmware} · Interfaces{' '}
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
                        Simulador Mock
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
                        API Real
                      </button>
                    </div>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => onSyncAdapter(adapter.id)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${busyKey === `sync-${adapter.id}` ? 'animate-spin' : ''}`} />
                      <span>Sincronizar Agora</span>
                    </button>

                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => onHandshake(adapter.id)}
                      className="px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                    >
                      Handshake
                    </button>
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="url"
                      aria-label={`URL real de ${adapter.name}`}
                      placeholder="Configure a URL aqui ou em Configurações"
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
                      Testar URL
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
