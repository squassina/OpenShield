import { useEffect, useMemo, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import {
  Activity,
  AlertCircle,
  Building2,
  CheckCircle2,
  Cpu,
  Download,
  Edit3,
  GlobeLock,
  KeyRound,
  PlugZap,
  Plus,
  RotateCcw,
  Router,
  Save,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { api } from '../lib/api';
import type {
  EnvSecretStatus,
  IntegrationAdapter,
  OperatingProfile,
  ServiceProviderMode,
  WorkspaceState,
} from '../types/openshield';

export type ServiceCatalogKey =
  | 'openwrt-rpcd'
  | 'opnsense-api'
  | 'wireguard-vpn'
  | 'nginx-proxy-manager'
  | 'pihole-v6'
  | 'adguard-home'
  | 'technitium-dns'
  | 'suricata-eve'
  | 'zeek-json'
  | 'wazuh-api'
  | 'crowdsec-lapi'
  | 'home-assistant'
  | 'uptime-kuma'
  | 'netdata-agent'
  | 'ollama-http'
  | 'custom-http';

type ServiceCategory = 'all' | 'dns' | 'network' | 'security' | 'homelab';

interface ServiceTemplate {
  key: ServiceCatalogKey;
  category: Exclude<ServiceCategory, 'all'>;
  label: string;
  shortDesc: string;
  domain: IntegrationAdapter['domain'];
  kind: string;
  defaultIdPrefix: string;
  defaultNamePrefix: string;
  urlPlaceholder: string;
  showsUsername: boolean;
  usernameLabel?: string;
  usernamePlaceholder?: string;
  showsSecret: boolean;
  secretLabel?: string;
  showsModelName: boolean;
  showsBoardFields: boolean;
  showsCustomDomainKind: boolean;
}

const SERVICE_CATALOG: ServiceTemplate[] = [
  // DNS & Bloqueio
  {
    key: 'pihole-v6',
    category: 'dns',
    label: 'Pi-hole DNS',
    shortDesc: 'Filtragem DNS e bloqueio de rastreadores (múltiplas instâncias)',
    domain: 'dns',
    kind: 'pihole-v6',
    defaultIdPrefix: 'pihole-dns',
    defaultNamePrefix: 'Pi-hole DNS',
    urlPlaceholder: 'http://192.168.1.12',
    showsUsername: false,
    showsSecret: true,
    secretLabel: 'App Password / Token Pi-hole (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'adguard-home',
    category: 'dns',
    label: 'AdGuard Home',
    shortDesc: 'DNS com bloqueio de anúncios, DoH/DoT e reescrita local',
    domain: 'dns',
    kind: 'adguard-home',
    defaultIdPrefix: 'adguard-dns',
    defaultNamePrefix: 'AdGuard Home',
    urlPlaceholder: 'http://192.168.1.13:3000',
    showsUsername: true,
    usernameLabel: 'Usuário Admin AdGuard (opcional)',
    usernamePlaceholder: 'ex: admin',
    showsSecret: true,
    secretLabel: 'Senha Admin AdGuard (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'technitium-dns',
    category: 'dns',
    label: 'Technitium DNS',
    shortDesc: 'Servidor DNS autoritativo/recursivo com DoH e blocklists',
    domain: 'dns',
    kind: 'technitium-dns',
    defaultIdPrefix: 'technitium-dns',
    defaultNamePrefix: 'Technitium DNS',
    urlPlaceholder: 'http://192.168.1.14:5380',
    showsUsername: false,
    showsSecret: true,
    secretLabel: 'Token de API Technitium (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  // Roteadores, Firewall, VPN e Proxy
  {
    key: 'openwrt-rpcd',
    category: 'network',
    label: 'OpenWrt Gateway',
    shortDesc: 'Roteador / Firewall via ubus/rpcd ou Node FastAPI',
    domain: 'gateway',
    kind: 'openwrt-rpcd',
    defaultIdPrefix: 'openwrt-gw',
    defaultNamePrefix: 'Gateway OpenWrt',
    urlPlaceholder: 'http://192.168.1.1/ubus',
    showsUsername: true,
    usernameLabel: 'Usuário ubus / RPC (opcional)',
    usernamePlaceholder: 'ex: openshield ou root',
    showsSecret: true,
    secretLabel: 'Senha / Token ubus (write-only)',
    showsModelName: false,
    showsBoardFields: true,
    showsCustomDomainKind: false,
  },
  {
    key: 'opnsense-api',
    category: 'network',
    label: 'OPNsense / pfSense',
    shortDesc: 'Firewall de perímetro, VLANs e estado via API REST',
    domain: 'gateway',
    kind: 'opnsense-api',
    defaultIdPrefix: 'opnsense-fw',
    defaultNamePrefix: 'Firewall OPNsense',
    urlPlaceholder: 'https://192.168.1.1/api/core/firmware/status',
    showsUsername: true,
    usernameLabel: 'API Key (usuário)',
    usernamePlaceholder: 'Cole a API Key gerada no OPNsense',
    showsSecret: true,
    secretLabel: 'API Secret (write-only)',
    showsModelName: false,
    showsBoardFields: true,
    showsCustomDomainKind: false,
  },
  {
    key: 'wireguard-vpn',
    category: 'network',
    label: 'WireGuard / wg-easy',
    shortDesc: 'VPN leve / acesso remoto seguro para residência e escritório',
    domain: 'gateway',
    kind: 'wireguard-vpn',
    defaultIdPrefix: 'wireguard-vpn',
    defaultNamePrefix: 'WireGuard VPN',
    urlPlaceholder: 'http://192.168.1.10:51821/api/wireguard/client',
    showsUsername: false,
    showsSecret: true,
    secretLabel: 'Senha / Token wg-easy (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'nginx-proxy-manager',
    category: 'network',
    label: 'Nginx Proxy Manager',
    shortDesc: 'Proxy reverso local com SSL/TLS Let’s Encrypt para serviços',
    domain: 'gateway',
    kind: 'nginx-proxy-manager',
    defaultIdPrefix: 'npm-proxy',
    defaultNamePrefix: 'Nginx Proxy Manager',
    urlPlaceholder: 'http://192.168.1.10:81/api/',
    showsUsername: true,
    usernameLabel: 'E-mail / Usuário (opcional)',
    usernamePlaceholder: 'ex: admin@rede.local',
    showsSecret: true,
    secretLabel: 'Token / Senha API (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  // Detecção, SIEM e Threat Intel
  {
    key: 'suricata-eve',
    category: 'security',
    label: 'Suricata IDS',
    shortDesc: 'Alertas de intrusão e assinaturas via EVE JSON na LAN',
    domain: 'ids',
    kind: 'suricata-eve',
    defaultIdPrefix: 'suricata-ids',
    defaultNamePrefix: 'Suricata IDS',
    urlPlaceholder: 'http://192.168.1.10:9090/eve',
    showsUsername: false,
    showsSecret: false,
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'zeek-json',
    category: 'security',
    label: 'Zeek Analytics',
    shortDesc: 'Metadados de fluxos de rede, conexões e sessões TLS',
    domain: 'analytics',
    kind: 'zeek-json',
    defaultIdPrefix: 'zeek-meta',
    defaultNamePrefix: 'Zeek Network Metadata',
    urlPlaceholder: 'http://192.168.1.10:9091/zeek',
    showsUsername: false,
    showsSecret: false,
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'wazuh-api',
    category: 'security',
    label: 'Wazuh SIEM / HIDS',
    shortDesc: 'Monitoramento de integridade, logs e alertas de hosts',
    domain: 'ids',
    kind: 'wazuh-api',
    defaultIdPrefix: 'wazuh-siem',
    defaultNamePrefix: 'Wazuh SIEM',
    urlPlaceholder: 'https://192.168.1.10:55000',
    showsUsername: true,
    usernameLabel: 'Usuário API Wazuh (opcional)',
    usernamePlaceholder: 'ex: wazuh-wui',
    showsSecret: true,
    secretLabel: 'Senha API Wazuh (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'crowdsec-lapi',
    category: 'security',
    label: 'CrowdSec Intel',
    shortDesc: 'Reputação comunitária colaborativa e bloqueio de IPs',
    domain: 'threat_intel',
    kind: 'crowdsec-lapi',
    defaultIdPrefix: 'crowdsec-ti',
    defaultNamePrefix: 'CrowdSec Threat Intel',
    urlPlaceholder: 'http://192.168.1.10:8080/v1/decisions/stream',
    showsUsername: false,
    showsSecret: true,
    secretLabel: 'API Key CrowdSec LAPI (opcional, write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  // Automação Residencial, Observabilidade & IA Local
  {
    key: 'home-assistant',
    category: 'homelab',
    label: 'Home Assistant',
    shortDesc: 'Automação residencial, dispositivos IoT e presença na LAN',
    domain: 'analytics',
    kind: 'home-assistant',
    defaultIdPrefix: 'home-assistant',
    defaultNamePrefix: 'Home Assistant',
    urlPlaceholder: 'http://homeassistant.local:8123/api/',
    showsUsername: false,
    showsSecret: true,
    secretLabel: 'Long-Lived Access Token (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'uptime-kuma',
    category: 'homelab',
    label: 'Uptime Kuma',
    shortDesc: 'Monitoramento leve de disponibilidade HTTP/TCP/DNS',
    domain: 'analytics',
    kind: 'uptime-kuma',
    defaultIdPrefix: 'uptime-kuma',
    defaultNamePrefix: 'Uptime Kuma',
    urlPlaceholder: 'http://192.168.1.10:3001/metrics',
    showsUsername: true,
    usernameLabel: 'Usuário / Key (se protegido)',
    usernamePlaceholder: 'Opcional',
    showsSecret: true,
    secretLabel: 'API Key / Senha /metrics (write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'netdata-agent',
    category: 'homelab',
    label: 'Netdata / Prometheus',
    shortDesc: 'Métricas em tempo real de CPU, tráfego e contêineres',
    domain: 'analytics',
    kind: 'netdata-agent',
    defaultIdPrefix: 'netdata-host',
    defaultNamePrefix: 'Netdata Observability',
    urlPlaceholder: 'http://192.168.1.10:19999/api/v1/info',
    showsUsername: false,
    showsSecret: false,
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'ollama-http',
    category: 'homelab',
    label: 'Ollama IA Local',
    shortDesc: 'Análise local-first de incidentes sem saída de dados',
    domain: 'ai_runtime',
    kind: 'ollama-http',
    defaultIdPrefix: 'ollama-ai',
    defaultNamePrefix: 'Ollama Local AI',
    urlPlaceholder: 'http://127.0.0.1:11434',
    showsUsername: false,
    showsSecret: false,
    showsModelName: true,
    showsBoardFields: false,
    showsCustomDomainKind: false,
  },
  {
    key: 'custom-http',
    category: 'homelab',
    label: 'Outro Serviço',
    shortDesc: 'Adaptador HTTP customizado na rede local',
    domain: 'analytics',
    kind: 'custom-http',
    defaultIdPrefix: 'custom-svc',
    defaultNamePrefix: 'Serviço LAN Customizado',
    urlPlaceholder: 'http://192.168.1.20:8080/api',
    showsUsername: true,
    usernameLabel: 'Usuário / Key (opcional)',
    usernamePlaceholder: 'Opcional',
    showsSecret: true,
    secretLabel: 'Token / Senha (opcional, write-only)',
    showsModelName: false,
    showsBoardFields: false,
    showsCustomDomainKind: true,
  },
];

const CATEGORY_TABS: { id: ServiceCategory; label: string }[] = [
  { id: 'all', label: 'Todos (16)' },
  { id: 'dns', label: 'DNS & Bloqueio' },
  { id: 'network', label: 'Rede, VPN & Proxy' },
  { id: 'security', label: 'IDS, SIEM & Intel' },
  { id: 'homelab', label: 'Residência, Monitor & IA' },
];

function getTemplateForAdapter(adapter: IntegrationAdapter): ServiceTemplate {
  return (
    SERVICE_CATALOG.find((t) => t.kind === adapter.kind) ??
    SERVICE_CATALOG[SERVICE_CATALOG.length - 1]
  );
}

function ServiceIcon({ domain }: { domain: IntegrationAdapter['domain'] }) {
  if (domain === 'gateway') return <Router className="w-4 h-4 text-blue-400 shrink-0" />;
  if (domain === 'dns') return <GlobeLock className="w-4 h-4 text-emerald-400 shrink-0" />;
  if (domain === 'ids') return <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />;
  if (domain === 'ai_runtime') return <Cpu className="w-4 h-4 text-blue-300 shrink-0" />;
  if (domain === 'threat_intel') return <Activity className="w-4 h-4 text-red-400 shrink-0" />;
  return <Server className="w-4 h-4 text-slate-300 shrink-0" />;
}

interface SettingsViewProps {
  state: WorkspaceState;
  onAddService: (payload: {
    id: string;
    name: string;
    domain: IntegrationAdapter['domain'];
    kind: string;
    liveEndpointUrl: string;
    siteId?: string;
    mode?: ServiceProviderMode;
    modelName?: string;
    boardInfo?: IntegrationAdapter['boardInfo'];
    username?: string;
    secret?: string;
  }) => Promise<void>;
  onSaveConfig: (
    id: string,
    payload: {
      name?: string;
      liveEndpointUrl?: string;
      siteId?: string;
      mode?: ServiceProviderMode;
      modelName?: string;
      boardInfo?: IntegrationAdapter['boardInfo'];
      username?: string;
      secret?: string;
      clearSecret?: boolean;
    },
  ) => Promise<void>;
  onRemoveIntegration: (id: string, name: string) => Promise<void>;
  onTestAndActivateLive: (id: string, liveEndpointUrl: string) => Promise<void>;
  onAddSite: (payload: { name: string; profile: OperatingProfile }) => Promise<void>;
  onRemoveSite: (siteId: string, siteName: string) => Promise<void>;
  onExportBackup: () => Promise<void>;
  onRestoreBackup: (payload: Record<string, unknown>) => Promise<void>;
  onLoadDemo: () => Promise<void>;
  onResetWorkspace: () => Promise<void>;
  onNavigateToIntegrations: () => void;
  busyKey: string | null;
}

interface EditDraft {
  name: string;
  liveEndpointUrl: string;
  siteId: string;
  mode: ServiceProviderMode;
  modelName: string;
  boardModel: string;
  boardInterfaces: string;
  username: string;
  secret: string;
}

function domainLabel(domain: IntegrationAdapter['domain']): string {
  switch (domain) {
    case 'gateway':
      return 'Gateway / Firewall / VPN';
    case 'dns':
      return 'Privacidade DNS';
    case 'ids':
      return 'IDS / SIEM';
    case 'analytics':
      return 'Monitoramento & IoT';
    case 'threat_intel':
      return 'Threat Intel';
    case 'ai_runtime':
      return 'Runtime IA Local';
  }
}

export function SettingsView({
  state,
  onAddService,
  onSaveConfig,
  onRemoveIntegration,
  onTestAndActivateLive,
  onAddSite,
  onRemoveSite,
  onExportBackup,
  onRestoreBackup,
  onLoadDemo,
  onResetWorkspace,
  onNavigateToIntegrations,
  busyKey,
}: SettingsViewProps) {
  const [envStatus, setEnvStatus] = useState<EnvSecretStatus[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<ServiceCategory>('all');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteProfile, setNewSiteProfile] = useState<OperatingProfile>(state.context.profile);
  const backupFileInputRef = useRef<HTMLInputElement | null>(null);

  // Step-based Add Service builder state
  const [selectedServiceKey, setSelectedServiceKey] = useState<ServiceCatalogKey>('pihole-v6');
  const activeTemplate = useMemo(
    () => SERVICE_CATALOG.find((t) => t.key === selectedServiceKey) ?? SERVICE_CATALOG[0],
    [selectedServiceKey],
  );

  const visibleCatalog = useMemo(
    () =>
      categoryFilter === 'all'
        ? SERVICE_CATALOG
        : SERVICE_CATALOG.filter((t) => t.category === categoryFilter),
    [categoryFilter],
  );

  const nextSequence = useMemo(() => {
    const countSame = state.integrations.filter(
      (item) => item.kind === activeTemplate.kind,
    ).length;
    return countSame + 1;
  }, [state.integrations, activeTemplate.kind]);

  const [newId, setNewId] = useState('pihole-dns-1');
  const [newName, setNewName] = useState('Pi-hole DNS 1');
  const [newSiteId, setNewSiteId] = useState(state.context.activeSiteId);
  const [newMode, setNewMode] = useState<ServiceProviderMode>('mock');
  const [newUrl, setNewUrl] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newSecret, setNewSecret] = useState('');
  const [newModelName, setNewModelName] = useState('llama3.1:8b');
  const [newBoardModel, setNewBoardModel] = useState('');
  const [newBoardInterfaces, setNewBoardInterfaces] = useState('br-lan, wan');
  const [customDomain, setCustomDomain] = useState<IntegrationAdapter['domain']>('analytics');
  const [customKind, setCustomKind] = useState('custom-http');

  // Inline Edit drawer state inside "Serviços e Endpoints Configurados"
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<EditDraft | null>(null);

  useEffect(() => {
    setNewId(`${activeTemplate.defaultIdPrefix}-${nextSequence}`);
    setNewName(`${activeTemplate.defaultNamePrefix} ${nextSequence}`);
    setNewSiteId(state.context.activeSiteId);
    setNewMode('mock');
    setNewUrl('');
    setNewUsername('');
    setNewSecret('');
    setNewModelName('llama3.1:8b');
    setNewBoardModel('');
    setNewBoardInterfaces('br-lan, wan');
    if (activeTemplate.key === 'custom-http') {
      setCustomDomain('analytics');
      setCustomKind('custom-http');
    }
  }, [activeTemplate, nextSequence, state.context.activeSiteId]);

  useEffect(() => {
    api
      .getEnvStatus()
      .then((res) => setEnvStatus(res.variables))
      .catch(() => {});
  }, []);

  const handleAddSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const effectiveDomain = activeTemplate.showsCustomDomainKind
      ? customDomain
      : activeTemplate.domain;
    const effectiveKind = activeTemplate.showsCustomDomainKind
      ? customKind.trim() || 'custom-http'
      : activeTemplate.kind;

    const boardInfo =
      activeTemplate.showsBoardFields && (newBoardModel.trim() || newBoardInterfaces.trim())
        ? {
            model: newBoardModel.trim() || activeTemplate.label,
            firmware: activeTemplate.kind,
            interfaces: newBoardInterfaces
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean),
          }
        : undefined;

    await onAddService({
      id: newId,
      name: newName,
      domain: effectiveDomain,
      kind: effectiveKind,
      liveEndpointUrl: newUrl,
      siteId: newSiteId,
      mode: newMode,
      modelName: activeTemplate.showsModelName ? newModelName : undefined,
      boardInfo,
      username: activeTemplate.showsUsername ? newUsername || undefined : undefined,
      secret: activeTemplate.showsSecret ? newSecret || undefined : undefined,
    });
  };

  const startEditing = (adapter: IntegrationAdapter) => {
    if (editingId === adapter.id) {
      setEditingId(null);
      setEditDraft(null);
      return;
    }
    setEditingId(adapter.id);
    setEditDraft({
      name: adapter.name,
      liveEndpointUrl: adapter.liveEndpointUrl,
      siteId: adapter.siteId,
      mode: adapter.mode,
      modelName: adapter.modelName ?? '',
      boardModel: adapter.boardInfo?.model ?? '',
      boardInterfaces: adapter.boardInfo?.interfaces.join(', ') ?? '',
      username: adapter.usernameHint ?? '',
      secret: '',
    });
  };

  const handleSaveEdit = async (adapter: IntegrationAdapter) => {
    if (!editDraft) return;
    const tpl = getTemplateForAdapter(adapter);
    const boardInfo =
      tpl.showsBoardFields && (editDraft.boardModel.trim() || editDraft.boardInterfaces.trim())
        ? {
            model: editDraft.boardModel.trim() || tpl.label,
            firmware: adapter.boardInfo?.firmware || tpl.kind,
            interfaces: editDraft.boardInterfaces
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean),
          }
        : undefined;

    await onSaveConfig(adapter.id, {
      name: editDraft.name,
      liveEndpointUrl: editDraft.liveEndpointUrl,
      siteId: editDraft.siteId,
      mode: editDraft.mode,
      modelName: tpl.showsModelName ? editDraft.modelName : undefined,
      boardInfo,
      username: tpl.showsUsername ? editDraft.username : undefined,
      secret: tpl.showsSecret && editDraft.secret ? editDraft.secret : undefined,
    });
    setEditDraft((prev) => (prev ? { ...prev, secret: '' } : null));
    setEditingId(null);
  };

  const handleTestLiveFromEdit = async (adapter: IntegrationAdapter) => {
    if (!editDraft) return;
    const url = editDraft.liveEndpointUrl.trim();
    const tpl = getTemplateForAdapter(adapter);
    await onSaveConfig(adapter.id, {
      name: editDraft.name,
      liveEndpointUrl: url,
      siteId: editDraft.siteId,
      modelName: tpl.showsModelName ? editDraft.modelName : undefined,
      username: tpl.showsUsername ? editDraft.username : undefined,
      secret: tpl.showsSecret && editDraft.secret ? editDraft.secret : undefined,
    });
    setEditDraft((prev) => (prev ? { ...prev, mode: 'live', secret: '' } : null));
    await onTestAndActivateLive(adapter.id, url);
  };

  const handleAddSiteSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!newSiteName.trim()) return;
    await onAddSite({ name: newSiteName.trim(), profile: newSiteProfile });
    setNewSiteName('');
  };

  const handleBackupFileSelected = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const raw = await file.text();
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      await onRestoreBackup(parsed);
    } finally {
      e.target.value = '';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            Configurações de Serviços e Endpoints
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-3xl">
            Escolha e adicione livremente os serviços OSS utilizados na sua residência ou escritório (Pi-hole, AdGuard Home, OPNsense, Home Assistant, WireGuard, Uptime Kuma e outros). Edite ou delete quando precisar.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            disabled={busyKey === 'workspace-demo'}
            onClick={onLoadDemo}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Carregar Cenário Demo (Mock)</span>
          </button>

          {state.integrations.length > 0 && (
            <button
              type="button"
              disabled={busyKey === 'workspace-reset'}
              onClick={onResetWorkspace}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-red-900/60 bg-slate-900 text-red-300 hover:bg-red-950/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Zerar Inventário</span>
            </button>
          )}

          <button
            type="button"
            onClick={onNavigateToIntegrations}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <PlugZap className="w-3.5 h-3.5 text-blue-400" />
            <span>Sincronização e Testes</span>
          </button>
        </div>
      </div>

      {/* Box 1: Adicionar Serviços (Escolha o serviço -> campos dinâmicos -> Salvar) */}
      <form
        onSubmit={handleAddSubmit}
        className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5"
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-3.5">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-blue-400" />
              <span>Adicionar Serviço</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              1. Escolha o serviço · 2. Preencha os campos exibidos (URLs e senhas podem ficar em branco para preencher depois) · 3. Salve o serviço.
            </p>
          </div>

          <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800">
            {CATEGORY_TABS.map((cat) => (
              <button
                key={cat.id}
                type="button"
                onClick={() => setCategoryFilter(cat.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  categoryFilter === cat.id
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>

        {/* Step 1: Choose service type */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-slate-300">Escolha o serviço OSS</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {visibleCatalog.map((tpl) => {
              const selected = tpl.key === selectedServiceKey;
              return (
                <button
                  key={tpl.key}
                  type="button"
                  onClick={() => setSelectedServiceKey(tpl.key)}
                  className={`text-left rounded-lg border p-3 transition-colors cursor-pointer ${
                    selected
                      ? 'border-blue-500 bg-blue-950/35'
                      : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 text-xs font-semibold text-slate-100">
                    <span className="flex items-center gap-2 min-w-0">
                      <ServiceIcon domain={tpl.domain} />
                      <span className="truncate">{tpl.label}</span>
                    </span>
                    <span className="font-mono text-[10px] text-slate-500 shrink-0">
                      {tpl.kind}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400 leading-snug">{tpl.shortDesc}</p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Step 2: Dynamic fields according to chosen service */}
        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
            <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <ServiceIcon domain={activeTemplate.domain} />
              <span>Campos para {activeTemplate.label}</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              protocolo: {activeTemplate.kind}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Nome do Serviço</span>
              <input
                type="text"
                required
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">ID Único</span>
              <input
                type="text"
                required
                value={newId}
                onChange={(e) => setNewId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Rede / Site</span>
              <select
                value={newSiteId}
                onChange={(e) => setNewSiteId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                {state.context.sites.map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Modo de Operação</span>
              <select
                value={newMode}
                onChange={(e) => setNewMode(e.target.value as ServiceProviderMode)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="mock">Simulador Mock (preencher API depois)</option>
                <option value="live">API Real (LAN / Local)</option>
              </select>
            </label>

            {activeTemplate.showsCustomDomainKind && (
              <>
                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">Domínio</span>
                  <select
                    value={customDomain}
                    onChange={(e) =>
                      setCustomDomain(e.target.value as IntegrationAdapter['domain'])
                    }
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                  >
                    <option value="gateway">Gateway / Firewall</option>
                    <option value="dns">Privacidade DNS</option>
                    <option value="ids">IDS / SIEM</option>
                    <option value="analytics">Monitoramento & IoT</option>
                    <option value="threat_intel">Threat Intel</option>
                    <option value="ai_runtime">Runtime IA Local</option>
                  </select>
                </label>

                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">Identificador do Protocolo (Kind)</span>
                  <input
                    type="text"
                    required
                    value={customKind}
                    onChange={(e) => setCustomKind(e.target.value)}
                    placeholder="ex: grafana-loki"
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                  />
                </label>
              </>
            )}

            <label className="block space-y-1 text-xs md:col-span-2">
              <span className="text-slate-300 font-medium">
                Endpoint URL na LAN {newMode === 'mock' ? '(opcional — preencha quando tiver)' : '(obrigatória em API Real)'}
              </span>
              <input
                type="url"
                required={newMode === 'live'}
                placeholder={`Preencher depois, ex: ${activeTemplate.urlPlaceholder}`}
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              />
            </label>

            {activeTemplate.showsUsername && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">
                  {activeTemplate.usernameLabel ?? 'Usuário / API Key'}
                </span>
                <input
                  type="text"
                  placeholder={activeTemplate.usernamePlaceholder ?? 'Opcional'}
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsSecret && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">
                  {activeTemplate.secretLabel ?? 'Senha / Token (write-only)'}
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  placeholder="Opcional — salvo no cofre do servidor"
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsModelName && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">Modelo Local Ollama</span>
                <input
                  type="text"
                  placeholder="ex: llama3.1:8b ou qwen2.5:7b"
                  value={newModelName}
                  onChange={(e) => setNewModelName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsBoardFields && (
              <>
                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">Modelo do Hardware (opcional)</span>
                  <input
                    type="text"
                    placeholder="ex: NanoPi R4S, Protectli, Mini PC"
                    value={newBoardModel}
                    onChange={(e) => setNewBoardModel(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </label>

                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">Interfaces (opcional)</span>
                  <input
                    type="text"
                    placeholder="br-lan, wan, iot-vlan"
                    value={newBoardInterfaces}
                    onChange={(e) => setNewBoardInterfaces(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </label>
              </>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
            <span className="text-xs text-slate-400">
              {activeTemplate.domain === 'dns'
                ? 'Você pode adicionar múltiplos servidores DNS (Pi-hole, AdGuard Home, Technitium); regras DNS sincronizam com todos os ativos.'
                : 'Senhas e tokens são gravados em cofre write-only no servidor e nunca retornam para o navegador.'}
            </span>

            <button
              type="submit"
              disabled={busyKey === 'add-service'}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Salvar Serviço</span>
            </button>
          </div>
        </div>
      </form>

      {/* Box 2: Serviços e Endpoints Configurados (for editing or deletion) */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Serviços e Endpoints Configurados ({state.integrations.length})
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Todos os serviços salvos aparecem aqui para edição de parâmetros/credenciais ou deleção.
            </p>
          </div>
          <span className="text-xs text-slate-400 tabular-nums">
            {state.integrations.filter((i) => i.domain === 'dns').length} servidor(es) DNS ·{' '}
            {state.integrations.filter((i) => i.mode === 'live').length} em API Real
          </span>
        </div>

        {state.integrations.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm text-slate-300 font-medium">
              Nenhum serviço configurado ainda.
            </p>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Escolha um serviço OSS na caixa <strong>Adicionar Serviço</strong> acima para cadastrar Pi-hole, AdGuard Home, OpenWrt, OPNsense, Home Assistant, WireGuard ou outros serviços da sua rede.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {state.integrations.map((adapter) => {
              const tpl = getTemplateForAdapter(adapter);
              const isEditing = editingId === adapter.id && editDraft !== null;
              const isBusy =
                busyKey === `cfg-${adapter.id}` ||
                busyKey === `mode-${adapter.id}` ||
                busyKey === `rm-${adapter.id}`;
              const siteName =
                state.context.sites.find((s) => s.id === adapter.siteId)?.name ?? adapter.siteId;

              return (
                <div key={adapter.id} className="p-5 space-y-4">
                  {/* Summary Row */}
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                        <ServiceIcon domain={adapter.domain} />
                        <span className="text-sm font-semibold text-slate-100">{adapter.name}</span>
                        <span className="font-mono text-slate-400">({adapter.id})</span>
                        <span aria-hidden="true">·</span>
                        <span>{domainLabel(adapter.domain)}</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono text-slate-300">{adapter.kind}</span>
                      </div>

                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
                        <span>
                          Site: <strong className="text-slate-200 font-medium">{siteName}</strong>
                        </span>
                        <span aria-hidden="true">·</span>
                        <span
                          className={
                            adapter.mode === 'live'
                              ? 'text-blue-400 font-medium'
                              : 'text-slate-300 font-medium'
                          }
                        >
                          {adapter.mode === 'live' ? 'API Real' : 'Simulador Mock'}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono text-slate-300 truncate max-w-md">
                          {adapter.liveEndpointUrl || 'URL pendente (Mock ativo)'}
                        </span>
                        {adapter.modelName && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono text-slate-300">modelo: {adapter.modelName}</span>
                          </>
                        )}
                        {adapter.boardInfo && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-slate-300">{adapter.boardInfo.model}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {(tpl.showsSecret || tpl.showsUsername) && (
                        <span className="inline-flex items-center gap-1 text-xs mr-1">
                          {adapter.hasCredential ? (
                            <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Credencial no cofre</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-slate-500">
                              <AlertCircle className="w-3.5 h-3.5" />
                              <span>Sem credencial</span>
                            </span>
                          )}
                        </span>
                      )}

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => startEditing(adapter)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        {isEditing ? <X className="w-3.5 h-3.5" /> : <Edit3 className="w-3.5 h-3.5" />}
                        <span>{isEditing ? 'Fechar Edição' : 'Editar'}</span>
                      </button>

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onRemoveIntegration(adapter.id, adapter.name)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-900/60 text-red-300 hover:bg-red-950/50 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Deletar</span>
                      </button>
                    </div>
                  </div>

                  {/* Inline Edit Form (dynamic fields by service kind) */}
                  {isEditing && editDraft && (
                    <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-4 space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                        <label className="block space-y-1 text-xs">
                          <span className="text-slate-300 font-medium">Nome do Serviço</span>
                          <input
                            type="text"
                            value={editDraft.name}
                            onChange={(e) =>
                              setEditDraft({ ...editDraft, name: e.target.value })
                            }
                            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                          />
                        </label>

                        <label className="block space-y-1 text-xs">
                          <span className="text-slate-300 font-medium">Rede / Site</span>
                          <select
                            value={editDraft.siteId}
                            onChange={(e) =>
                              setEditDraft({ ...editDraft, siteId: e.target.value })
                            }
                            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                          >
                            {state.context.sites.map((site) => (
                              <option key={site.id} value={site.id}>
                                {site.name}
                              </option>
                            ))}
                          </select>
                        </label>

                        <label className="block space-y-1 text-xs">
                          <span className="text-slate-300 font-medium">Modo</span>
                          <select
                            value={editDraft.mode}
                            onChange={(e) =>
                              setEditDraft({
                                ...editDraft,
                                mode: e.target.value as ServiceProviderMode,
                              })
                            }
                            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                          >
                            <option value="mock">Simulador Mock</option>
                            <option value="live">API Real</option>
                          </select>
                        </label>

                        <label className="block space-y-1 text-xs">
                          <span className="text-slate-300 font-medium">Endpoint URL</span>
                          <input
                            type="url"
                            placeholder={tpl.urlPlaceholder}
                            value={editDraft.liveEndpointUrl}
                            onChange={(e) =>
                              setEditDraft({ ...editDraft, liveEndpointUrl: e.target.value })
                            }
                            className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                          />
                        </label>

                        {tpl.showsUsername && (
                          <label className="block space-y-1 text-xs">
                            <span className="text-slate-300 font-medium">
                              {tpl.usernameLabel ?? 'Usuário / API Key'}
                            </span>
                            <input
                              type="text"
                              value={editDraft.username}
                              onChange={(e) =>
                                setEditDraft({ ...editDraft, username: e.target.value })
                              }
                              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                            />
                          </label>
                        )}

                        {tpl.showsSecret && (
                          <label className="block space-y-1 text-xs xl:col-span-2">
                            <span className="text-slate-300 font-medium">
                              {tpl.secretLabel ?? 'Senha / Token (write-only)'}
                            </span>
                            <input
                              type="password"
                              autoComplete="new-password"
                              placeholder={
                                adapter.hasCredential
                                  ? '•••••••• (digite apenas para substituir)'
                                  : 'Preencha quando tiver a senha/token'
                              }
                              value={editDraft.secret}
                              onChange={(e) =>
                                setEditDraft({ ...editDraft, secret: e.target.value })
                              }
                              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                            />
                          </label>
                        )}

                        {tpl.showsModelName && (
                          <label className="block space-y-1 text-xs">
                            <span className="text-slate-300 font-medium">Modelo Local Ollama</span>
                            <input
                              type="text"
                              value={editDraft.modelName}
                              onChange={(e) =>
                                setEditDraft({ ...editDraft, modelName: e.target.value })
                              }
                              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                            />
                          </label>
                        )}

                        {tpl.showsBoardFields && (
                          <>
                            <label className="block space-y-1 text-xs">
                              <span className="text-slate-300 font-medium">Modelo do Hardware</span>
                              <input
                                type="text"
                                value={editDraft.boardModel}
                                onChange={(e) =>
                                  setEditDraft({ ...editDraft, boardModel: e.target.value })
                                }
                                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                              />
                            </label>
                            <label className="block space-y-1 text-xs">
                              <span className="text-slate-300 font-medium">Interfaces</span>
                              <input
                                type="text"
                                value={editDraft.boardInterfaces}
                                onChange={(e) =>
                                  setEditDraft({ ...editDraft, boardInterfaces: e.target.value })
                                }
                                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
                              />
                            </label>
                          </>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-800/80">
                        {adapter.hasCredential && (
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => onSaveConfig(adapter.id, { clearSecret: true })}
                            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                          >
                            Limpar Credencial
                          </button>
                        )}

                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => handleTestLiveFromEdit(adapter)}
                          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                        >
                          Testar e Ativar API Real
                        </button>

                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => handleSaveEdit(adapter)}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                        >
                          <Save className="w-3.5 h-3.5" />
                          <span>Salvar Alterações</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Multi-Site & Sanitized Backup/Restore */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Building2 className="w-4 h-4 text-blue-400 shrink-0" />
                <span>Redes e Sites Gerenciados ({state.context.sites.length})</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Separe dispositivos e serviços por residência, matriz ou filiais.
              </p>
            </div>
          </div>

          <form onSubmit={handleAddSiteSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 items-end">
            <label className="block space-y-1 text-xs sm:col-span-1">
              <span className="text-slate-300 font-medium">Nome do Site</span>
              <input
                type="text"
                required
                placeholder="ex.: Casa de Campo"
                value={newSiteName}
                onChange={(e) => setNewSiteName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Perfil</span>
              <select
                value={newSiteProfile}
                onChange={(e) => setNewSiteProfile(e.target.value as OperatingProfile)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="residential">Residencial</option>
                <option value="business">Pequeno Escritório</option>
              </select>
            </label>

            <button
              type="submit"
              disabled={busyKey === 'site-add'}
              className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Adicionar Site</span>
            </button>
          </form>

          <div className="divide-y divide-slate-800/80 border-t border-slate-800 pt-2">
            {state.context.sites.map((site) => {
              const isActive = state.context.activeSiteId === site.id;
              const sameProfileCount = state.context.sites.filter(
                (s) => s.profile === site.profile,
              ).length;
              return (
                <div key={site.id} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                  <div className="min-w-0">
                    <div className="font-medium text-slate-100 truncate">{site.name}</div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      {site.id} · {site.profile === 'residential' ? 'Residencial' : 'Escritório'}
                      {isActive ? ' · Ativo agora' : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={isActive || sameProfileCount <= 1 || busyKey === `site-rm-${site.id}`}
                    onClick={() => onRemoveSite(site.id, site.name)}
                    className="px-2.5 py-1 text-xs rounded border border-red-900/60 text-red-300 hover:bg-red-950/50 disabled:opacity-35 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Remover
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100">
              Backup e Restauração (JSON sem Credenciais)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Exporte serviços, dispositivos, políticas, domínios DNS e sites para migração ou contingência. Senhas e tokens nunca são incluídos no arquivo.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={busyKey === 'backup-export'}
              onClick={onExportBackup}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span>Exportar Backup JSON</span>
            </button>

            <input
              ref={backupFileInputRef}
              type="file"
              accept=".json,application/json"
              onChange={(e) => void handleBackupFileSelected(e)}
              className="hidden"
            />
            <button
              type="button"
              disabled={busyKey === 'backup-restore'}
              onClick={() => backupFileInputRef.current?.click()}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Restaurar de Arquivo JSON</span>
            </button>
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed">
            No perfil Pequeno Escritório, a restauração completa exige papel Administrador e grava evento <span className="font-mono text-slate-300">workspace.restored</span> na trilha de auditoria.
          </p>
        </section>
      </div>

      {/* Server Environment & Write-only Security Note */}
      <details className="rounded-xl border border-slate-800 bg-[#131C31] p-5 text-xs">
        <summary className="cursor-pointer font-semibold text-slate-200 flex items-center gap-2 select-none">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>Segurança do Cofre Local e Variáveis de Ambiente do Servidor</span>
        </summary>
        <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
          <div className="space-y-2 text-slate-400 leading-relaxed">
            <p>
              Credenciais locais (OpenWrt, OPNsense, Pi-hole, AdGuard, Technitium, Home Assistant, Wazuh, WireGuard) são armazenadas apenas na tabela protegida do SQLite local (<span className="font-mono text-slate-300">.openshield-data</span>) e nunca retornam para o navegador.
            </p>
            <p>
              A chave opcional <span className="font-mono text-slate-300">GEMINI_API_KEY</span> para segunda opinião em nuvem permanece exclusivamente nos Secrets do ambiente do servidor.
            </p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-1.5">
            <div className="flex items-center gap-1.5 font-medium text-slate-200 pb-1">
              <KeyRound className="w-3.5 h-3.5 text-amber-400" />
              <span>Variáveis Detectadas no Servidor</span>
            </div>
            {envStatus.map((item) => (
              <div key={item.key} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="font-mono text-slate-300 truncate">{item.key}</span>
                <span className={item.configured ? 'text-emerald-400 font-medium shrink-0' : 'text-slate-500 shrink-0'}>
                  {item.configured ? 'Configurada' : 'Opcional / Ausente'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}
