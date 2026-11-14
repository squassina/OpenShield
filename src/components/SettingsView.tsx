import { useEffect, useMemo, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
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
import { PaginationControls, usePagination } from './PaginationControls';
import {
  NotificationsCard,
  type NotificationCreatePayload,
  type NotificationUpdatePayload,
} from './NotificationsCard';
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

const CATEGORY_TABS: { id: ServiceCategory; labelKey: string }[] = [
  { id: 'all', labelKey: 'settings.catAll' },
  { id: 'dns', labelKey: 'settings.catDns' },
  { id: 'network', labelKey: 'settings.catNetwork' },
  { id: 'security', labelKey: 'settings.catSecurity' },
  { id: 'homelab', labelKey: 'settings.catHomelab' },
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
  onAddNotification: (payload: NotificationCreatePayload) => Promise<void>;
  onUpdateNotification: (id: string, payload: NotificationUpdatePayload) => Promise<void>;
  onRemoveNotification: (id: string, name: string) => Promise<void>;
  onTestNotification: (id: string) => Promise<void>;
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
  onAddNotification,
  onUpdateNotification,
  onRemoveNotification,
  onTestNotification,
  busyKey,
}: SettingsViewProps) {
  const { t } = useTranslation();
  const domainLabel = (domain: IntegrationAdapter['domain']): string =>
    t(`settings.domains.${domain}`);
  const catalogLabel = (tpl: ServiceTemplate): string =>
    t(`settings.catalog.${tpl.key}.label`, { defaultValue: tpl.label });
  const catalogDesc = (tpl: ServiceTemplate): string =>
    t(`settings.catalog.${tpl.key}.shortDesc`, { defaultValue: tpl.shortDesc });
  const catalogUsernameLabel = (tpl: ServiceTemplate): string =>
    tpl.usernameLabel
      ? t(`settings.catalog.${tpl.key}.usernameLabel`, { defaultValue: tpl.usernameLabel })
      : t('settings.userOrKeyFallback');
  const catalogUsernamePh = (tpl: ServiceTemplate): string =>
    tpl.usernamePlaceholder
      ? t(`settings.catalog.${tpl.key}.usernamePlaceholder`, {
          defaultValue: tpl.usernamePlaceholder,
        })
      : t('notifications.optionalPh');
  const catalogSecretLabel = (tpl: ServiceTemplate): string =>
    tpl.secretLabel
      ? t(`settings.catalog.${tpl.key}.secretLabel`, { defaultValue: tpl.secretLabel })
      : t('settings.secretFallback');

  const [envStatus, setEnvStatus] = useState<EnvSecretStatus[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<ServiceCategory>('all');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteProfile, setNewSiteProfile] = useState<OperatingProfile>(state.context.profile);
  const backupFileInputRef = useRef<HTMLInputElement | null>(null);
  const servicesPagination = usePagination(state.integrations, 10);
  const sitesPagination = usePagination(state.context.sites, 10);

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
    const localizedPrefix = t(`settings.catalog.${activeTemplate.key}.defaultNamePrefix`, {
      defaultValue: activeTemplate.defaultNamePrefix,
    });
    setNewName(`${localizedPrefix} ${nextSequence}`);
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
  }, [activeTemplate, nextSequence, state.context.activeSiteId, t]);

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
            {t('settings.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-3xl">
            {t('settings.subtitle')}
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
            <span>{t('settings.loadDemo')}</span>
          </button>

          {state.integrations.length > 0 && (
            <button
              type="button"
              disabled={busyKey === 'workspace-reset'}
              onClick={onResetWorkspace}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg border border-red-900/60 bg-slate-900 text-red-300 hover:bg-red-950/40 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{t('settings.resetInventory')}</span>
            </button>
          )}

          <button
            type="button"
            onClick={onNavigateToIntegrations}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <PlugZap className="w-3.5 h-3.5 text-blue-400" />
            <span>{t('settings.syncAndTests')}</span>
          </button>
        </div>
      </div>

      {/* Box 1: Add Service */}
      <form
        onSubmit={handleAddSubmit}
        className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5"
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-3.5">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Plus className="w-4 h-4 text-blue-400" />
              <span>{t('settings.addServiceTitle')}</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('settings.addServiceSteps')}
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
                {t(cat.labelKey)}
              </button>
            ))}
          </div>
        </div>

        {/* Step 1: Choose service type */}
        <div className="space-y-2">
          <div className="text-xs font-medium text-slate-300">
            {t('settings.chooseOssService')}
          </div>
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
                      <span className="truncate">{catalogLabel(tpl)}</span>
                    </span>
                    <span className="font-mono text-[10px] text-slate-500 shrink-0">
                      {tpl.kind}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400 leading-snug">
                    {catalogDesc(tpl)}
                  </p>
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
              <span>{t('settings.fieldsFor', { name: catalogLabel(activeTemplate) })}</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {t('settings.protocolLabel', { kind: activeTemplate.kind })}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('settings.serviceName')}</span>
              <input
                type="text"
                required
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('settings.uniqueId')}</span>
              <input
                type="text"
                required
                value={newId}
                onChange={(e) => setNewId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('settings.networkSite')}</span>
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
              <span className="text-slate-300 font-medium">{t('settings.operationMode')}</span>
              <select
                value={newMode}
                onChange={(e) => setNewMode(e.target.value as ServiceProviderMode)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="mock">{t('settings.modeMockLater')}</option>
                <option value="live">{t('settings.modeLiveLan')}</option>
              </select>
            </label>

            {activeTemplate.showsCustomDomainKind && (
              <>
                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">{t('settings.domain')}</span>
                  <select
                    value={customDomain}
                    onChange={(e) =>
                      setCustomDomain(e.target.value as IntegrationAdapter['domain'])
                    }
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
                  >
                    <option value="gateway">{t('settings.domains.gateway')}</option>
                    <option value="dns">{t('settings.domains.dns')}</option>
                    <option value="ids">{t('settings.domains.ids')}</option>
                    <option value="analytics">{t('settings.domains.analytics')}</option>
                    <option value="threat_intel">{t('settings.domains.threat_intel')}</option>
                    <option value="ai_runtime">{t('settings.domains.ai_runtime')}</option>
                  </select>
                </label>

                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">{t('settings.protocolKind')}</span>
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
                {t('settings.endpointUrlLan')}{' '}
                {newMode === 'mock'
                  ? t('settings.urlOptionalHint')
                  : t('settings.urlRequiredHint')}
              </span>
              <input
                type="url"
                required={newMode === 'live'}
                placeholder={t('settings.urlFillLaterPh', { url: activeTemplate.urlPlaceholder })}
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              />
            </label>

            {activeTemplate.showsUsername && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">
                  {catalogUsernameLabel(activeTemplate)}
                </span>
                <input
                  type="text"
                  placeholder={catalogUsernamePh(activeTemplate)}
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsSecret && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">
                  {catalogSecretLabel(activeTemplate)}
                </span>
                <input
                  type="password"
                  autoComplete="new-password"
                  placeholder={t('settings.secretVaultPh')}
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsModelName && (
              <label className="block space-y-1 text-xs">
                <span className="text-slate-300 font-medium">{t('settings.ollamaModel')}</span>
                <input
                  type="text"
                  placeholder="llama3.1:8b / qwen2.5:7b"
                  value={newModelName}
                  onChange={(e) => setNewModelName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                />
              </label>
            )}

            {activeTemplate.showsBoardFields && (
              <>
                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">
                    {t('settings.hardwareModelOptional')}
                  </span>
                  <input
                    type="text"
                    placeholder="NanoPi R4S, Protectli, Mini PC"
                    value={newBoardModel}
                    onChange={(e) => setNewBoardModel(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                  />
                </label>

                <label className="block space-y-1 text-xs">
                  <span className="text-slate-300 font-medium">
                    {t('settings.interfacesOptional')}
                  </span>
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
                ? t('settings.dnsMultiNote')
                : t('settings.writeOnlyNote')}
            </span>

            <button
              type="submit"
              disabled={busyKey === 'add-service'}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{t('settings.saveService')}</span>
            </button>
          </div>
        </div>
      </form>

      {/* Box 2: Configured Services & Endpoints */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              {t('settings.configuredTitle', { count: state.integrations.length })}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('settings.configuredSubtitle')}
            </p>
          </div>
          <span className="text-xs text-slate-400 tabular-nums">
            {t('settings.configuredSummary', {
              dns: state.integrations.filter((i) => i.domain === 'dns').length,
              live: state.integrations.filter((i) => i.mode === 'live').length,
            })}
          </span>
        </div>

        {state.integrations.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <p className="text-sm text-slate-300 font-medium">
              {t('settings.noServicesYet')}
            </p>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              {t('settings.noServicesHintPrefix')}{' '}
              <strong>{t('settings.noServicesHintBold')}</strong>{' '}
              {t('settings.noServicesHintSuffix')}
            </p>
          </div>
        ) : (
          <>
            <div className="divide-y divide-slate-800 max-h-[560px] overflow-y-auto">
              {servicesPagination.pagedItems.map((adapter) => {
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
                          {t('toolbar.siteLabel')}{' '}
                          <strong className="text-slate-200 font-medium">{siteName}</strong>
                        </span>
                        <span aria-hidden="true">·</span>
                        <span
                          className={
                            adapter.mode === 'live'
                              ? 'text-blue-400 font-medium'
                              : 'text-slate-300 font-medium'
                          }
                        >
                          {adapter.mode === 'live' ? t('common.liveApi') : t('common.mockSim')}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="font-mono text-slate-300 truncate max-w-md">
                          {adapter.liveEndpointUrl || t('settings.urlPendingMock')}
                        </span>
                        {adapter.modelName && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono text-slate-300">
                              {t('settings.modelPrefix', { model: adapter.modelName })}
                            </span>
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
                              <span>{t('settings.credInVault')}</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-slate-500">
                              <AlertCircle className="w-3.5 h-3.5" />
                              <span>{t('settings.noCred')}</span>
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
                        <span>{isEditing ? t('settings.closeEdit') : t('common.edit')}</span>
                      </button>

                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onRemoveIntegration(adapter.id, adapter.name)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-900/60 text-red-300 hover:bg-red-950/50 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>{t('common.delete')}</span>
                      </button>
                    </div>
                  </div>

                  {/* Inline Edit Form (dynamic fields by service kind) */}
                  {isEditing && editDraft && (
                    <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-4 space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                        <label className="block space-y-1 text-xs">
                          <span className="text-slate-300 font-medium">
                            {t('settings.serviceName')}
                          </span>
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
                          <span className="text-slate-300 font-medium">
                            {t('settings.networkSite')}
                          </span>
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
                          <span className="text-slate-300 font-medium">
                            {t('settings.modeLabel')}
                          </span>
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
                            <option value="mock">{t('common.mockSim')}</option>
                            <option value="live">{t('common.liveApi')}</option>
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
                              {catalogUsernameLabel(tpl)}
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
                              {catalogSecretLabel(tpl)}
                            </span>
                            <input
                              type="password"
                              autoComplete="new-password"
                              placeholder={
                                adapter.hasCredential
                                  ? t('settings.secretReplacePh')
                                  : t('settings.secretFillLaterPh')
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
                            <span className="text-slate-300 font-medium">
                              {t('settings.ollamaModel')}
                            </span>
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
                              <span className="text-slate-300 font-medium">
                                {t('settings.hardwareModel')}
                              </span>
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
                              <span className="text-slate-300 font-medium">
                                {t('settings.interfaces')}
                              </span>
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
                            {t('settings.clearCred')}
                          </button>
                        )}

                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => handleTestLiveFromEdit(adapter)}
                          className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                        >
                          {t('settings.testActivateLive')}
                        </button>

                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => handleSaveEdit(adapter)}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                        >
                          <Save className="w-3.5 h-3.5" />
                          <span>{t('common.saveChanges')}</span>
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            </div>
            <PaginationControls
              page={servicesPagination.page}
              pageSize={servicesPagination.pageSize}
              totalItems={servicesPagination.totalItems}
              totalPages={servicesPagination.totalPages}
              onPageChange={servicesPagination.setPage}
              onPageSizeChange={servicesPagination.setPageSize}
              compact
            />
          </>
        )}
      </section>

      {/* Box 3: Notificações e Alertas (E-mail SMTP, Webhooks, Telegram) */}
      <NotificationsCard
        state={state}
        onAddNotification={onAddNotification}
        onUpdateNotification={onUpdateNotification}
        onRemoveNotification={onRemoveNotification}
        onTestNotification={onTestNotification}
        busyKey={busyKey}
      />

      {/* Multi-Site & Sanitized Backup/Restore */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Building2 className="w-4 h-4 text-blue-400 shrink-0" />
                <span>{t('settings.sitesTitle', { count: state.context.sites.length })}</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                {t('settings.sitesSubtitle')}
              </p>
            </div>
          </div>

          <form onSubmit={handleAddSiteSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 items-end">
            <label className="block space-y-1 text-xs sm:col-span-1">
              <span className="text-slate-300 font-medium">{t('settings.siteName')}</span>
              <input
                type="text"
                required
                placeholder={t('settings.siteNamePh')}
                value={newSiteName}
                onChange={(e) => setNewSiteName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('settings.profile')}</span>
              <select
                value={newSiteProfile}
                onChange={(e) => setNewSiteProfile(e.target.value as OperatingProfile)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="residential">{t('toolbar.profileResidential')}</option>
                <option value="business">{t('toolbar.profileBusiness')}</option>
              </select>
            </label>

            <button
              type="submit"
              disabled={busyKey === 'site-add'}
              className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{t('settings.addSite')}</span>
            </button>
          </form>

          <div className="divide-y divide-slate-800/80 border-t border-slate-800 pt-2 max-h-[300px] overflow-y-auto">
            {sitesPagination.pagedItems.map((site) => {
              const isActive = state.context.activeSiteId === site.id;
              const sameProfileCount = state.context.sites.filter(
                (s) => s.profile === site.profile,
              ).length;
              return (
                <div key={site.id} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                  <div className="min-w-0">
                    <div className="font-medium text-slate-100 truncate">{site.name}</div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      {site.id} ·{' '}
                      {site.profile === 'residential'
                        ? t('toolbar.profileResidential')
                        : t('toolbar.profileBusiness')}
                      {isActive ? ` · ${t('settings.activeNow')}` : ''}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={isActive || sameProfileCount <= 1 || busyKey === `site-rm-${site.id}`}
                    onClick={() => onRemoveSite(site.id, site.name)}
                    className="px-2.5 py-1 text-xs rounded border border-red-900/60 text-red-300 hover:bg-red-950/50 disabled:opacity-35 whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    {t('common.remove')}
                  </button>
                </div>
              );
            })}
          </div>
          {state.context.sites.length > 0 && (
            <div className="-mx-5 -mb-5 mt-2 overflow-hidden rounded-b-xl">
              <PaginationControls
                page={sitesPagination.page}
                pageSize={sitesPagination.pageSize}
                totalItems={sitesPagination.totalItems}
                totalPages={sitesPagination.totalPages}
                onPageChange={sitesPagination.setPage}
                onPageSizeChange={sitesPagination.setPageSize}
                compact
              />
            </div>
          )}
        </section>

        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100">
              {t('settings.backupTitle')}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('settings.backupSubtitle')}
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
              <span>{t('settings.exportJsonBackup')}</span>
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
              <span>{t('settings.restoreJsonBackup')}</span>
            </button>
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed">
            {t('settings.backupBusinessNotePrefix')}{' '}
            <span className="font-mono text-slate-300">workspace.restored</span>{' '}
            {t('settings.backupBusinessNoteSuffix')}
          </p>
        </section>
      </div>

      {/* Server Environment & Write-only Security Note */}
      <details className="rounded-xl border border-slate-800 bg-[#131C31] p-5 text-xs">
        <summary className="cursor-pointer font-semibold text-slate-200 flex items-center gap-2 select-none">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{t('settings.vaultSummary')}</span>
        </summary>
        <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3 border-t border-slate-800">
          <div className="space-y-2 text-slate-400 leading-relaxed">
            <p>
              {t('settings.vaultP1Prefix')}
              <span className="font-mono text-slate-300">.openshield-data</span>
              {t('settings.vaultP1Suffix')}
            </p>
            <p>
              {t('settings.vaultP2Prefix')}{' '}
              <span className="font-mono text-slate-300">GEMINI_API_KEY</span>{' '}
              {t('settings.vaultP2Suffix')}
            </p>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-1.5">
            <div className="flex items-center gap-1.5 font-medium text-slate-200 pb-1">
              <KeyRound className="w-3.5 h-3.5 text-amber-400" />
              <span>{t('settings.detectedServerVars')}</span>
            </div>
            {envStatus.map((item) => (
              <div key={item.key} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="font-mono text-slate-300 truncate">{item.key}</span>
                <span className={item.configured ? 'text-emerald-400 font-medium shrink-0' : 'text-slate-500 shrink-0'}>
                  {item.configured ? t('settings.varConfigured') : t('settings.varOptionalMissing')}
                </span>
              </div>
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}
