import { useMemo, useState, type FormEvent } from 'react';
import {
  Activity,
  ArrowRight,
  Ban,
  CheckCircle2,
  Eye,
  GitBranch,
  Globe,
  Laptop,
  Network,
  Plus,
  Router,
  Save,
  Server,
  ShieldAlert,
  Smartphone,
  Trash2,
  Video,
  X,
} from 'lucide-react';
import type { DnsInsight, NetworkDevice, WorkspaceState } from '../types/openshield';

interface DevicesTopologyViewProps {
  state: WorkspaceState;
  searchQuery: string;
  onAddDevice: (payload: {
    hostname: string;
    ip: string;
    mac?: string;
    vendor?: string;
    interfaceName?: string;
    segment: NetworkDevice['segment'];
    siteId?: string;
    deviceType: NetworkDevice['deviceType'];
  }) => Promise<void>;
  onUpdateDevice: (
    id: string,
    patch: Partial<
      Pick<
        NetworkDevice,
        'hostname' | 'ip' | 'mac' | 'vendor' | 'interfaceName' | 'segment' | 'siteId' | 'deviceType'
      >
    >,
  ) => Promise<void>;
  onRemoveDevice: (id: string, hostname: string) => Promise<void>;
  busyKey: string | null;
}

const SEGMENTS: NetworkDevice['segment'][] = ['LAN Confiável', 'IoT / Convidados', 'Escritório / VPN'];

function DeviceIcon({ type }: { type: NetworkDevice['deviceType'] }) {
  if (type === 'router') return <Router className="w-4 h-4 text-blue-400 shrink-0" />;
  if (type === 'server') return <Server className="w-4 h-4 text-slate-300 shrink-0" />;
  if (type === 'iot') return <Video className="w-4 h-4 text-amber-400 shrink-0" />;
  if (type === 'mobile') return <Smartphone className="w-4 h-4 text-slate-300 shrink-0" />;
  return <Laptop className="w-4 h-4 text-slate-300 shrink-0" />;
}

interface AggregatedDomainFlow {
  domain: string;
  category: DnsInsight['category'] | 'Evento de Rede';
  classification: DnsInsight['classification'];
  listStatus: DnsInsight['listStatus'];
  queriesCount: number;
  blockedCount: number;
  lastQueriedAt: string;
}

function getTopDomainsForDevice(
  device: NetworkDevice,
  state: WorkspaceState,
  limit = 5,
): AggregatedDomainFlow[] {
  const byDomain = new Map<string, AggregatedDomainFlow>();
  const hostLower = device.hostname.toLowerCase();

  for (const insight of state.dnsInsights) {
    if (
      insight.deviceId === device.id ||
      insight.deviceHostname.toLowerCase() === hostLower
    ) {
      const key = insight.domain.trim().toLowerCase();
      if (!key) continue;
      const existing = byDomain.get(key);
      if (existing) {
        existing.queriesCount += insight.queriesCount;
        existing.blockedCount += insight.blockedCount;
        if (Date.parse(insight.lastQueriedAt) > Date.parse(existing.lastQueriedAt)) {
          existing.lastQueriedAt = insight.lastQueriedAt;
          existing.listStatus = insight.listStatus;
          existing.classification = insight.classification;
          existing.category = insight.category;
        }
      } else {
        byDomain.set(key, {
          domain: key,
          category: insight.category,
          classification: insight.classification,
          listStatus: insight.listStatus,
          queriesCount: insight.queriesCount,
          blockedCount: insight.blockedCount,
          lastQueriedAt: insight.lastQueriedAt,
        });
      }
    }
  }

  for (const ev of state.events) {
    const matchesDevice =
      ev.deviceId === device.id ||
      String(ev.payload?.srcIp ?? '') === device.ip ||
      String(ev.payload?.clientIp ?? '') === device.ip ||
      String(ev.payload?.deviceHostname ?? '').toLowerCase() === hostLower;

    if (!matchesDevice) continue;

    const rawDom =
      ev.payload?.domain ??
      ev.payload?.qname ??
      ev.payload?.targetDomain ??
      ev.payload?.hostname;

    if (typeof rawDom !== 'string') continue;
    const key = rawDom.trim().toLowerCase();
    if (!key || !key.includes('.')) continue;

    const countRaw = Number(ev.payload?.queriesInWindow ?? ev.payload?.count ?? 1);
    const evCount = Number.isFinite(countRaw) && countRaw > 0 ? Math.round(countRaw) : 1;
    const isBlocked = String(ev.payload?.action ?? '').toLowerCase() === 'blocked';

    const existing = byDomain.get(key);
    if (existing) {
      if (evCount > existing.queriesCount) {
        existing.queriesCount = evCount;
      }
      if (isBlocked && existing.blockedCount === 0) {
        existing.blockedCount = evCount;
      }
    } else {
      byDomain.set(key, {
        domain: key,
        category: 'Evento de Rede',
        classification:
          ev.severity === 'critical' || ev.severity === 'high'
            ? 'suspicious'
            : ev.severity === 'medium'
              ? 'tracker'
              : 'benign',
        listStatus: isBlocked ? 'blocked' : 'monitored',
        queriesCount: evCount,
        blockedCount: isBlocked ? evCount : 0,
        lastQueriedAt: ev.occurredAt,
      });
    }
  }

  return Array.from(byDomain.values())
    .sort(
      (a, b) =>
        b.queriesCount - a.queriesCount ||
        b.blockedCount - a.blockedCount ||
        a.domain.localeCompare(b.domain),
    )
    .slice(0, limit);
}

function renderListStatusIndicator(status: DnsInsight['listStatus']) {
  if (status === 'blocked') {
    return (
      <span className="inline-flex items-center gap-1 text-red-400 font-medium whitespace-nowrap">
        <Ban className="w-3 h-3 shrink-0" />
        <span>Bloqueado</span>
      </span>
    );
  }
  if (status === 'allowed') {
    return (
      <span className="inline-flex items-center gap-1 text-emerald-400 font-medium whitespace-nowrap">
        <CheckCircle2 className="w-3 h-3 shrink-0" />
        <span>Permitido</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-amber-300 font-medium whitespace-nowrap">
      <Eye className="w-3 h-3 shrink-0" />
      <span>Monitorado</span>
    </span>
  );
}

export function DevicesTopologyView({
  state,
  searchQuery,
  onAddDevice,
  onUpdateDevice,
  onRemoveDevice,
  busyKey,
}: DevicesTopologyViewProps) {
  const [viewMode, setViewMode] = useState<'topology' | 'flow'>('topology');
  const [segmentFilter, setSegmentFilter] = useState<'all' | NetworkDevice['segment']>('all');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [flowDeviceId, setFlowDeviceId] = useState<string | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);

  // Add device form state
  const [hostname, setHostname] = useState('');
  const [ip, setIp] = useState('');
  const [mac, setMac] = useState('');
  const [vendor, setVendor] = useState('');
  const [interfaceName, setInterfaceName] = useState('br-lan');
  const [segment, setSegment] = useState<NetworkDevice['segment']>('LAN Confiável');
  const [siteId, setSiteId] = useState(state.context.activeSiteId);
  const [deviceType, setDeviceType] = useState<NetworkDevice['deviceType']>('server');

  // Drawer inline edit state
  const [editingDevice, setEditingDevice] = useState<{
    hostname: string;
    ip: string;
    mac: string;
    vendor: string;
    interfaceName: string;
    segment: NetworkDevice['segment'];
    siteId: string;
    deviceType: NetworkDevice['deviceType'];
  } | null>(null);

  const selectedDevice = useMemo(
    () => state.devices.find((d) => d.id === selectedDeviceId) ?? null,
    [state.devices, selectedDeviceId],
  );

  const scopedDevices = useMemo(() => {
    const isBusiness = state.context.profile === 'business';
    const q = searchQuery.trim().toLowerCase();
    return state.devices.filter((d) => {
      if (!isBusiness && d.siteId !== state.context.activeSiteId) return false;
      if (segmentFilter !== 'all' && d.segment !== segmentFilter) return false;
      if (!q) return true;
      return (
        d.hostname.toLowerCase().includes(q) ||
        d.ip.toLowerCase().includes(q) ||
        d.mac.toLowerCase().includes(q) ||
        d.vendor.toLowerCase().includes(q)
      );
    });
  }, [state.devices, state.context.profile, state.context.activeSiteId, segmentFilter, searchQuery]);

  const relatedEvents = useMemo(() => {
    if (!selectedDevice) return [];
    return state.events.filter((e) => e.deviceId === selectedDevice.id);
  }, [selectedDevice, state.events]);

  const activeFlowDevice = useMemo(
    () =>
      scopedDevices.find((d) => d.id === flowDeviceId) ??
      state.devices.find((d) => d.id === flowDeviceId) ??
      null,
    [scopedDevices, state.devices, flowDeviceId],
  );

  const flowTopDomains = useMemo(() => {
    if (!activeFlowDevice) return [];
    return getTopDomainsForDevice(activeFlowDevice, state, 5);
  }, [activeFlowDevice, state]);

  const selectedDrawerTopDomains = useMemo(() => {
    if (!selectedDevice) return [];
    return getTopDomainsForDevice(selectedDevice, state, 5);
  }, [selectedDevice, state]);

  const handleCreateDevice = async (e: FormEvent) => {
    e.preventDefault();
    await onAddDevice({
      hostname,
      ip,
      mac: mac || undefined,
      vendor: vendor || undefined,
      interfaceName,
      segment,
      siteId,
      deviceType,
    });
    setHostname('');
    setIp('');
    setMac('');
    setVendor('');
    setShowAddForm(false);
  };

  const openDrawer = (dev: NetworkDevice) => {
    setSelectedDeviceId(dev.id);
    setEditingDevice({
      hostname: dev.hostname,
      ip: dev.ip,
      mac: dev.mac,
      vendor: dev.vendor,
      interfaceName: dev.interfaceName,
      segment: dev.segment,
      siteId: dev.siteId,
      deviceType: dev.deviceType,
    });
  };

  const handleSaveDeviceEdit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedDevice || !editingDevice) return;
    await onUpdateDevice(selectedDevice.id, editingDevice);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            Dispositivos e Topologia de Rede
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            Inventário dinâmico — adicione, edite ou remova dispositivos conforme sua rede ou sincronize automaticamente via OpenWrt.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* View Mode Switcher: Topology vs Network Flow */}
          <div
            className="inline-flex items-center gap-1 p-1 rounded-lg bg-[#131C31] border border-slate-800"
            role="tablist"
            aria-label="Modo de visualização"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'topology'}
              onClick={() => setViewMode('topology')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'topology'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              <span>Topologia</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'flow'}
              onClick={() => setViewMode('flow')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                viewMode === 'flow'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>Fluxo de Rede</span>
            </button>
          </div>

          <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-[#131C31] border border-slate-800">
            <button
              type="button"
              onClick={() => setSegmentFilter('all')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                segmentFilter === 'all' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Todos
            </button>
            {SEGMENTS.map((seg) => (
              <button
                key={seg}
                type="button"
                onClick={() => setSegmentFilter(seg)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  segmentFilter === seg ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {seg}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => {
              setSiteId(state.context.activeSiteId);
              setShowAddForm((prev) => !prev);
            }}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showAddForm ? 'Fechar Formulário' : 'Adicionar Dispositivo'}</span>
          </button>
        </div>
      </div>

      {/* Add Device Form */}
      {showAddForm && (
        <form
          onSubmit={handleCreateDevice}
          className="rounded-xl border border-slate-700 bg-[#131C31] p-5 space-y-4"
        >
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100">
              Novo Dispositivo na Rede
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Cadastre roteadores, servidores Pi-hole, estações de trabalho ou dispositivos IoT monitorados pelo OpenShield.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Hostname</span>
              <input
                type="text"
                required
                placeholder="ex: pihole-rack-01"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Endereço IP</span>
              <input
                type="text"
                required
                placeholder="ex: 192.168.1.12"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Endereço MAC (opcional)</span>
              <input
                type="text"
                placeholder="ex: DC:A6:32:10:20:30"
                value={mac}
                onChange={(e) => setMac(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Tipo</span>
              <select
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value as NetworkDevice['deviceType'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="router">Roteador / Gateway</option>
                <option value="server">Servidor / Pi-hole / NAS</option>
                <option value="workstation">Estação / Notebook</option>
                <option value="mobile">Celular / Tablet</option>
                <option value="iot">IoT / Câmera / Smart TV</option>
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Segmento</span>
              <select
                value={segment}
                onChange={(e) => setSegment(e.target.value as NetworkDevice['segment'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                {SEGMENTS.map((seg) => (
                  <option key={seg} value={seg}>
                    {seg}
                  </option>
                ))}
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Rede / Site</span>
              <select
                value={siteId}
                onChange={(e) => setSiteId(e.target.value)}
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
              <span className="text-slate-300 font-medium">Interface OpenWrt</span>
              <input
                type="text"
                value={interfaceName}
                onChange={(e) => setInterfaceName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">Fabricante / Descrição (opcional)</span>
              <input
                type="text"
                placeholder="ex: Raspberry Pi, Synology"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              />
            </label>
          </div>

          <div className="flex justify-end gap-2.5 pt-2">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-4 py-2 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={busyKey === 'add-device'}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Salvar Dispositivo</span>
            </button>
          </div>
        </form>
      )}

      {/* Topology OR Network Flow Visualization */}
      {viewMode === 'topology' ? (
        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-100">
              Mapa Lógico de Segmentação (Gateway-First)
            </h2>
            <span className="text-xs text-slate-400 tabular-nums">
              {scopedDevices.length} dispositivo(s) visível(is)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {SEGMENTS.map((seg) => {
              const items = scopedDevices.filter((d) => d.segment === seg);
              return (
                <div
                  key={seg}
                  className="rounded-lg border border-slate-800/90 bg-slate-950/60 p-4 space-y-3"
                >
                  <div className="flex items-center justify-between text-xs border-b border-slate-800 pb-2">
                    <span className="font-semibold text-slate-200">{seg}</span>
                    <span className="text-slate-400 tabular-nums">{items.length} ativos</span>
                  </div>
                  {items.length === 0 ? (
                    <p className="text-xs text-slate-500 py-2">
                      Nenhum dispositivo neste segmento.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {items.map((dev) => (
                        <button
                          key={dev.id}
                          type="button"
                          onClick={() => openDrawer(dev)}
                          className="w-full text-left flex items-center justify-between gap-2 px-2.5 py-2 rounded-md hover:bg-slate-900 transition-colors cursor-pointer"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <DeviceIcon type={dev.deviceType} />
                            <div className="truncate">
                              <div className="text-xs font-medium text-slate-200 truncate">
                                {dev.hostname}
                              </div>
                              <div className="text-[11px] font-mono text-slate-400 tabular-nums">
                                {dev.ip}
                              </div>
                            </div>
                          </div>
                          <span
                            className={`text-xs font-mono tabular-nums whitespace-nowrap ${
                              dev.riskScore >= 70
                                ? 'text-red-400'
                                : dev.riskScore >= 40
                                  ? 'text-amber-400'
                                  : 'text-emerald-400'
                            }`}
                          >
                            Risco {dev.riskScore}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      ) : (
        <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-blue-400 shrink-0" />
                <span>Fluxo de Rede e Destinos DNS por Dispositivo</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Clique em qualquer dispositivo no fluxo abaixo para visualizar o caminho de tráfego e os Top 5 domínios mais acessados conforme os dados agregados.
              </p>
            </div>
            <span className="text-xs text-slate-400 tabular-nums">
              {state.dnsInsights.length} domínio(s) agregados no estado
            </span>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
            {/* Left: Interactive Gateway -> Segment -> Device Flow Map */}
            <div className="xl:col-span-7 space-y-4">
              {/* Gateway Root Node */}
              <div className="rounded-lg border border-blue-900/70 bg-[#0B1120] p-3.5 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <Router className="w-4 h-4 text-blue-400 shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-slate-100">
                      Perímetro Gateway & Resolvedores DNS
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      {state.integrations.filter((i) => i.domain === 'dns').length} DNS ativo(s) ·{' '}
                      {scopedDevices.reduce((sum, d) => sum + d.dnsQueries24h, 0).toLocaleString('pt-BR')} consultas 24h
                    </div>
                  </div>
                </div>
                <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium whitespace-nowrap">
                  <Activity className="w-3.5 h-3.5" />
                  <span>{state.context.gatewayForwardingActive ? 'Encaminhando' : 'Pausado'}</span>
                </span>
              </div>

              {/* Segments & Device Flow Nodes */}
              {scopedDevices.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-800 bg-[#0B1120]/60 p-8 text-center text-xs text-slate-400">
                  Nenhum dispositivo disponível neste filtro para exibir o fluxo de rede.
                </div>
              ) : (
                <div className="space-y-3">
                  {SEGMENTS.map((seg) => {
                    const segDevices = scopedDevices.filter((d) => d.segment === seg);
                    if (segDevices.length === 0) return null;
                    return (
                      <div
                        key={seg}
                        className="rounded-lg border border-slate-800 bg-[#0B1120]/70 p-3.5 space-y-2.5"
                      >
                        <div className="flex items-center justify-between text-xs border-b border-slate-800/80 pb-2">
                          <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                            <ArrowRight className="w-3.5 h-3.5 text-blue-400" />
                            <span>{seg}</span>
                          </span>
                          <span className="text-[11px] text-slate-400 tabular-nums">
                            {segDevices.reduce((s, d) => s + d.dnsQueries24h, 0).toLocaleString('pt-BR')} reqs DNS
                          </span>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                          {segDevices.map((dev) => {
                            const selected = activeFlowDevice?.id === dev.id;
                            const domainCount = getTopDomainsForDevice(dev, state, 50).length;
                            return (
                              <button
                                key={dev.id}
                                type="button"
                                onClick={() => setFlowDeviceId(dev.id)}
                                className={`text-left rounded-lg border p-3 transition-colors cursor-pointer space-y-2 ${
                                  selected
                                    ? 'border-blue-500 bg-blue-950/35'
                                    : 'border-slate-800 bg-[#131C31]/60 hover:border-slate-700'
                                }`}
                              >
                                <div className="flex items-start justify-between gap-2">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <DeviceIcon type={dev.deviceType} />
                                    <div className="min-w-0">
                                      <div className="text-xs font-semibold text-slate-100 truncate">
                                        {dev.hostname}
                                      </div>
                                      <div className="text-[11px] font-mono text-slate-400 tabular-nums">
                                        {dev.ip} · {dev.interfaceName}
                                      </div>
                                    </div>
                                  </div>
                                  <span
                                    className={`text-[11px] font-mono tabular-nums shrink-0 ${
                                      dev.riskScore >= 70
                                        ? 'text-red-400'
                                        : dev.riskScore >= 40
                                          ? 'text-amber-400'
                                          : 'text-emerald-400'
                                    }`}
                                  >
                                    Risco {dev.riskScore}
                                  </span>
                                </div>

                                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/70 tabular-nums">
                                  <span>
                                    {dev.dnsQueries24h.toLocaleString('pt-BR')} consultas ·{' '}
                                    {dev.blockedQueries24h.toLocaleString('pt-BR')} bloq.
                                  </span>
                                  <span className="text-blue-300 font-medium">
                                    {domainCount} domínio(s)
                                  </span>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Right: Top 5 Domains Inspector for Clicked Device */}
            <div className="xl:col-span-5">
              <div className="rounded-lg border border-slate-800 bg-[#0B1120] p-4 space-y-4 h-full">
                {!activeFlowDevice ? (
                  <div className="py-12 text-center space-y-2">
                    <Globe className="w-7 h-7 text-slate-600 mx-auto" />
                    <div className="text-xs font-semibold text-slate-200">
                      Selecione um dispositivo no fluxo
                    </div>
                    <p className="text-[11px] text-slate-400 max-w-xs mx-auto">
                      Clique em qualquer dispositivo à esquerda (ou na tabela abaixo) para inspecionar o fluxo de saída e os Top 5 domínios mais acessados por ele.
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="flex items-start justify-between gap-3 border-b border-slate-800 pb-3">
                      <div className="flex items-start gap-2.5 min-w-0">
                        <DeviceIcon type={activeFlowDevice.deviceType} />
                        <div className="min-w-0">
                          <div className="text-sm font-semibold text-slate-100 truncate">
                            {activeFlowDevice.hostname}
                          </div>
                          <div className="text-[11px] font-mono text-slate-400 tabular-nums">
                            {activeFlowDevice.ip} → {activeFlowDevice.interfaceName} ({activeFlowDevice.segment})
                          </div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => openDrawer(activeFlowDevice)}
                        className="text-xs text-blue-400 hover:text-blue-300 font-medium whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Editar / Eventos
                      </button>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div className="rounded-lg border border-slate-800 bg-[#131C31]/70 p-2.5">
                        <div className="text-[10px] uppercase tracking-wider text-slate-400">
                          Consultas 24h
                        </div>
                        <div className="text-sm font-bold text-slate-100 font-mono tabular-nums mt-0.5">
                          {activeFlowDevice.dnsQueries24h.toLocaleString('pt-BR')}
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-[#131C31]/70 p-2.5">
                        <div className="text-[10px] uppercase tracking-wider text-slate-400">
                          Bloqueios
                        </div>
                        <div className="text-sm font-bold text-amber-300 font-mono tabular-nums mt-0.5">
                          {activeFlowDevice.blockedQueries24h.toLocaleString('pt-BR')}
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-[#131C31]/70 p-2.5">
                        <div className="text-[10px] uppercase tracking-wider text-slate-400">
                          Score Risco
                        </div>
                        <div
                          className={`text-sm font-bold font-mono tabular-nums mt-0.5 ${
                            activeFlowDevice.riskScore >= 70
                              ? 'text-red-400'
                              : activeFlowDevice.riskScore >= 40
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          }`}
                        >
                          {activeFlowDevice.riskScore}/100
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-slate-100 flex items-center gap-1.5">
                          <Globe className="w-3.5 h-3.5 text-blue-400" />
                          <span>Top 5 Domínios Mais Acessados</span>
                        </span>
                        <span className="text-[11px] text-slate-400">
                          Dados agregados no state
                        </span>
                      </div>

                      {flowTopDomains.length === 0 ? (
                        <div className="rounded-lg border border-dashed border-slate-800 p-5 text-center text-xs text-slate-400 space-y-1">
                          <div>Nenhum domínio DNS agregado ainda para este dispositivo.</div>
                          <p className="text-[11px] text-slate-500">
                            Sincronize seu servidor DNS (Pi-hole / AdGuard) ou adicione domínios em Privacidade e DNS para vê-los ranqueados aqui.
                          </p>
                        </div>
                      ) : (
                        <div className="space-y-2.5">
                          {flowTopDomains.map((dom, idx) => {
                            const maxQueries = flowTopDomains[0]?.queriesCount || 1;
                            const pct = Math.max(
                              6,
                              Math.round((dom.queriesCount / maxQueries) * 100),
                            );
                            return (
                              <div
                                key={dom.domain}
                                className="rounded-lg border border-slate-800/90 bg-[#131C31]/60 p-3 space-y-2"
                              >
                                <div className="flex items-start justify-between gap-2 text-xs">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className="font-mono text-[11px] text-slate-500 tabular-nums shrink-0">
                                      #{idx + 1}
                                    </span>
                                    <span className="font-mono font-medium text-slate-100 truncate">
                                      {dom.domain}
                                    </span>
                                  </div>
                                  <span className="font-mono text-xs font-semibold text-slate-200 tabular-nums whitespace-nowrap shrink-0">
                                    {dom.queriesCount.toLocaleString('pt-BR')} reqs
                                  </span>
                                </div>

                                <div className="h-1.5 w-full rounded-full bg-slate-900 overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${
                                      dom.listStatus === 'blocked'
                                        ? 'bg-red-500'
                                        : dom.classification === 'suspicious'
                                          ? 'bg-amber-400'
                                          : 'bg-blue-500'
                                    }`}
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>

                                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                                  <span>{dom.category}</span>
                                  <div className="flex items-center gap-3 tabular-nums">
                                    {dom.blockedCount > 0 && (
                                      <span className="font-mono text-red-300">
                                        {dom.blockedCount.toLocaleString('pt-BR')} bloq.
                                      </span>
                                    )}
                                    {renderListStatusIndicator(dom.listStatus)}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* High-density Device Inventory Table */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-medium text-slate-400 bg-slate-900/50">
                <th className="py-3 px-4">Dispositivo</th>
                <th className="py-3 px-4">IP / Interface</th>
                <th className="py-3 px-4">Segmento</th>
                <th className="py-3 px-4 text-right">Consultas DNS (24h)</th>
                <th className="py-3 px-4 text-right">Bloqueios</th>
                <th className="py-3 px-4 text-right">Risco</th>
                <th className="py-3 px-4 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-xs">
              {scopedDevices.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400 space-y-2">
                    <div>Nenhum dispositivo configurado ou descoberto no momento.</div>
                    <button
                      type="button"
                      onClick={() => setShowAddForm(true)}
                      className="text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
                    >
                      + Adicionar primeiro dispositivo
                    </button>
                  </td>
                </tr>
              ) : (
                scopedDevices.map((dev) => (
                  <tr
                    key={dev.id}
                    className="h-[44px] hover:bg-slate-900/40 transition-colors"
                  >
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2.5">
                        <DeviceIcon type={dev.deviceType} />
                        <div>
                          <div className="font-medium text-slate-100">{dev.hostname}</div>
                          <div className="text-[11px] text-slate-400">{dev.vendor}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-2 font-mono text-slate-300 tabular-nums">
                      {dev.ip} · {dev.interfaceName}
                    </td>
                    <td className="px-4 py-2 text-slate-300">{dev.segment}</td>
                    <td className="px-4 py-2 text-right font-mono text-slate-300 tabular-nums">
                      {dev.dnsQueries24h.toLocaleString('pt-BR')}
                    </td>
                    <td className="px-4 py-2 text-right font-mono text-slate-300 tabular-nums">
                      {dev.blockedQueries24h.toLocaleString('pt-BR')}
                    </td>
                    <td className="px-4 py-2 text-right font-mono tabular-nums">
                      <span
                        className={
                          dev.riskScore >= 70
                            ? 'text-red-400 font-semibold'
                            : dev.riskScore >= 40
                              ? 'text-amber-400 font-semibold'
                              : 'text-emerald-400'
                        }
                      >
                        {dev.riskScore}/100
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <div className="inline-flex items-center gap-3">
                        <button
                          type="button"
                          onClick={() => {
                            setFlowDeviceId(dev.id);
                            setViewMode('flow');
                          }}
                          className="text-slate-300 hover:text-blue-300 font-medium whitespace-nowrap cursor-pointer"
                        >
                          Ver Fluxo
                        </button>
                        <button
                          type="button"
                          onClick={() => openDrawer(dev)}
                          className="text-blue-400 hover:text-blue-300 font-medium whitespace-nowrap cursor-pointer"
                        >
                          Editar / Inspecionar
                        </button>
                        <button
                          type="button"
                          disabled={busyKey === `rm-dev-${dev.id}`}
                          onClick={() => onRemoveDevice(dev.id, dev.hostname)}
                          className="text-red-400 hover:text-red-300 font-medium whitespace-nowrap cursor-pointer disabled:opacity-50"
                        >
                          Remover
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Progressive Disclosure & Edit Drawer */}
      {selectedDevice && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/60"
          onClick={() => setSelectedDeviceId(null)}
        >
          <aside
            className="w-full max-w-lg bg-[#0F172A] border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="text-xs text-slate-400 font-mono">
                  {selectedDevice.id} · {selectedDevice.mac}
                </div>
                <h2 className="text-lg font-semibold text-slate-100 mt-1">
                  {selectedDevice.hostname}
                </h2>
              </div>
              <button
                type="button"
                aria-label="Fechar gaveta do dispositivo"
                onClick={() => setSelectedDeviceId(null)}
                className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {editingDevice && (
              <form onSubmit={handleSaveDeviceEdit} className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-3">
                  <label className="block space-y-1">
                    <span className="text-slate-400">Hostname</span>
                    <input
                      type="text"
                      required
                      value={editingDevice.hostname}
                      onChange={(e) =>
                        setEditingDevice({ ...editingDevice, hostname: e.target.value })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-slate-400">Endereço IP</span>
                    <input
                      type="text"
                      required
                      value={editingDevice.ip}
                      onChange={(e) =>
                        setEditingDevice({ ...editingDevice, ip: e.target.value })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-slate-400">MAC</span>
                    <input
                      type="text"
                      value={editingDevice.mac}
                      onChange={(e) =>
                        setEditingDevice({ ...editingDevice, mac: e.target.value })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-slate-400">Interface</span>
                    <input
                      type="text"
                      value={editingDevice.interfaceName}
                      onChange={(e) =>
                        setEditingDevice({ ...editingDevice, interfaceName: e.target.value })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono"
                    />
                  </label>
                  <label className="block space-y-1">
                    <span className="text-slate-400">Segmento</span>
                    <select
                      value={editingDevice.segment}
                      onChange={(e) =>
                        setEditingDevice({
                          ...editingDevice,
                          segment: e.target.value as NetworkDevice['segment'],
                        })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100"
                    >
                      {SEGMENTS.map((seg) => (
                        <option key={seg} value={seg}>
                          {seg}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="block space-y-1">
                    <span className="text-slate-400">Tipo</span>
                    <select
                      value={editingDevice.deviceType}
                      onChange={(e) =>
                        setEditingDevice({
                          ...editingDevice,
                          deviceType: e.target.value as NetworkDevice['deviceType'],
                        })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100"
                    >
                      <option value="router">Roteador</option>
                      <option value="server">Servidor</option>
                      <option value="workstation">Estação</option>
                      <option value="mobile">Mobile</option>
                      <option value="iot">IoT</option>
                    </select>
                  </label>
                </div>

                <label className="block space-y-1">
                  <span className="text-slate-400">Fabricante / Nota</span>
                  <input
                    type="text"
                    value={editingDevice.vendor}
                    onChange={(e) =>
                      setEditingDevice({ ...editingDevice, vendor: e.target.value })
                    }
                    className="w-full px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-slate-100"
                  />
                </label>

                <div className="flex items-center justify-between pt-2">
                  <button
                    type="button"
                    disabled={busyKey === `rm-dev-${selectedDevice.id}`}
                    onClick={async () => {
                      await onRemoveDevice(selectedDevice.id, selectedDevice.hostname);
                      setSelectedDeviceId(null);
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-900/60 text-red-300 hover:bg-red-950/50 cursor-pointer disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Remover Dispositivo</span>
                  </button>

                  <button
                    type="submit"
                    disabled={busyKey === `upd-dev-${selectedDevice.id}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 cursor-pointer disabled:opacity-50"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>Salvar Alterações</span>
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-3 border-t border-slate-800 pt-4">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <span>Top 5 Domínios Mais Acessados</span>
              </h3>
              {selectedDrawerTopDomains.length === 0 ? (
                <p className="text-xs text-slate-400">
                  Nenhum domínio agregado para este dispositivo em Privacidade DNS ou eventos.
                </p>
              ) : (
                <div className="space-y-2">
                  {selectedDrawerTopDomains.map((dom, idx) => (
                    <div
                      key={dom.domain}
                      className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 flex items-center justify-between gap-2 text-xs"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                          #{idx + 1}
                        </span>
                        <span className="font-mono text-slate-100 truncate">{dom.domain}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0 tabular-nums">
                        <span className="font-mono text-slate-300">
                          {dom.queriesCount.toLocaleString('pt-BR')} reqs
                        </span>
                        {renderListStatusIndicator(dom.listStatus)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-3 border-t border-slate-800 pt-4">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-blue-400" />
                <span>Eventos Correlacionados (openshield.event.v1)</span>
              </h3>
              {relatedEvents.length === 0 ? (
                <p className="text-xs text-slate-400">
                  Nenhum evento recente associado diretamente a este ativo.
                </p>
              ) : (
                <div className="space-y-3">
                  {relatedEvents.map((ev) => (
                    <div
                      key={ev.eventId}
                      className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between text-slate-400 font-mono">
                        <span>{ev.eventType}</span>
                        <span>fonte: {ev.sourceIntegrationId}</span>
                      </div>
                      <p className="text-slate-200">{ev.summary}</p>
                      <pre className="text-[11px] font-mono text-slate-400 bg-slate-950 p-2.5 rounded overflow-x-auto">
                        {JSON.stringify(ev.payload, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}
