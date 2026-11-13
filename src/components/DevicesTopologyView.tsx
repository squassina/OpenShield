import { useMemo, useState, type FormEvent } from 'react';
import {
  Laptop,
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
import type { NetworkDevice, WorkspaceState } from '../types/openshield';

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

export function DevicesTopologyView({
  state,
  searchQuery,
  onAddDevice,
  onUpdateDevice,
  onRemoveDevice,
  busyKey,
}: DevicesTopologyViewProps) {
  const [segmentFilter, setSegmentFilter] = useState<'all' | NetworkDevice['segment']>('all');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
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

      {/* Topology Visual Map */}
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
