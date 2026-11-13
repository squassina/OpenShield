import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Laptop,
  Network,
  Router,
  Server,
  ShieldAlert,
} from 'lucide-react';
import type { IntegrationAdapter, NetworkDevice, WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';

interface OverviewTopologyMapProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
}

type NodeStatusKind = 'online' | 'degraded' | 'offline';

interface SelectedNodeInfo {
  id: string;
  kind: 'client' | 'gateway' | 'node' | 'service';
  title: string;
  subtitle: string;
  status: NodeStatusKind;
  statusLabel: string;
  detail: string;
  targetTab: NavTab;
  targetTabLabel: string;
}

const STATUS_STYLE: Record<
  NodeStatusKind,
  { stroke: string; fill: string; text: string; edge: string; dot: string }
> = {
  online: {
    stroke: '#10b981',
    fill: '#0f172a',
    text: '#34d399',
    edge: '#10b981',
    dot: '#10b981',
  },
  degraded: {
    stroke: '#f59e0b',
    fill: '#0f172a',
    text: '#fbbf24',
    edge: '#f59e0b',
    dot: '#f59e0b',
  },
  offline: {
    stroke: '#ef4444',
    fill: '#0f172a',
    text: '#f87171',
    edge: '#ef4444',
    dot: '#ef4444',
  },
};

function truncateLabel(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen - 1)}…`;
}

function getClientStatus(dev: NetworkDevice): { status: NodeStatusKind; label: string } {
  if (dev.status === 'isolated') return { status: 'offline', label: 'Isolado' };
  if (dev.status === 'attention' || dev.riskScore >= 60) {
    return { status: 'degraded', label: `Atenção · Risco ${dev.riskScore}` };
  }
  return { status: 'online', label: `Nominal · Risco ${dev.riskScore}` };
}

function getAdapterStatus(adapter: IntegrationAdapter): { status: NodeStatusKind; label: string } {
  if (adapter.status === 'connected') {
    return {
      status: 'online',
      label:
        typeof adapter.lastLatencyMs === 'number'
          ? `Online · ${adapter.lastLatencyMs} ms`
          : 'Online',
    };
  }
  if (adapter.status === 'stale') {
    return { status: 'degraded', label: 'Degradado / Stale' };
  }
  return { status: 'offline', label: 'Offline / Indisponível' };
}

function cubicPath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = Math.abs(x2 - x1) * 0.48;
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

export function OverviewTopologyMap({ state, onNavigate }: OverviewTopologyMapProps) {
  const [selectedId, setSelectedId] = useState<string>('openshield-node');

  const isBusiness = state.context.profile === 'business';
  const scopedClients = useMemo(
    () =>
      (isBusiness
        ? state.devices
        : state.devices.filter((d) => d.siteId === state.context.activeSiteId)
      ).slice(0, 6),
    [state.devices, isBusiness, state.context.activeSiteId],
  );
  const totalScopedClientsCount = isBusiness
    ? state.devices.length
    : state.devices.filter((d) => d.siteId === state.context.activeSiteId).length;

  const gatewayAdapter = useMemo(
    () => state.integrations.find((i) => i.domain === 'gateway') ?? null,
    [state.integrations],
  );

  const otherServices = useMemo(
    () =>
      state.integrations
        .filter((i) => !gatewayAdapter || i.id !== gatewayAdapter.id)
        .slice(0, 6),
    [state.integrations, gatewayAdapter],
  );
  const totalOtherServicesCount = state.integrations.filter(
    (i) => !gatewayAdapter || i.id !== gatewayAdapter.id,
  ).length;

  const gatewayStatus: { status: NodeStatusKind; label: string } = useMemo(() => {
    if (!state.context.gatewayForwardingActive) {
      return { status: 'offline', label: 'Encaminhamento Interrompido' };
    }
    if (gatewayAdapter) {
      return getAdapterStatus(gatewayAdapter);
    }
    return { status: 'online', label: 'Plano LAN Ativo' };
  }, [state.context.gatewayForwardingActive, gatewayAdapter]);

  const coreNodeStatus: { status: NodeStatusKind; label: string } = useMemo(() => {
    if (!state.context.nodeAvailable) {
      return {
        status: 'degraded',
        label: `Offline · ${state.metrics.outboxPendingTotal} no spool`,
      };
    }
    if (state.context.killSwitchActive) {
      return { status: 'degraded', label: 'Kill Switch Ativo (L0)' };
    }
    return {
      status: 'online',
      label: `Online · Autonomia ${state.context.globalAutonomy}`,
    };
  }, [
    state.context.nodeAvailable,
    state.context.killSwitchActive,
    state.context.globalAutonomy,
    state.metrics.outboxPendingTotal,
  ]);

  const gwToNodeStatus: NodeStatusKind =
    !state.context.nodeAvailable || gatewayStatus.status === 'degraded'
      ? 'degraded'
      : gatewayStatus.status === 'offline'
        ? 'offline'
        : 'online';

  // Compute balanced SVG vertical canvas
  const maxSideRows = Math.max(scopedClients.length, otherServices.length, 2);
  const rowStep = 58;
  const topPad = 48;
  const bottomPad = 24;
  const svgHeight = Math.max(280, topPad + maxSideRows * rowStep + bottomPad);
  const centerY = Math.round((topPad + (svgHeight - bottomPad)) / 2);

  const clientPositions = useMemo(() => {
    const list = scopedClients;
    const blockH = (list.length - 1) * rowStep;
    const startY = centerY - blockH / 2;
    return list.map((dev, idx) => ({
      dev,
      x: 24,
      y: Math.round(startY + idx * rowStep),
      w: 196,
      h: 44,
    }));
  }, [scopedClients, centerY]);

  const servicePositions = useMemo(() => {
    const list = otherServices;
    const blockH = (list.length - 1) * rowStep;
    const startY = centerY - blockH / 2;
    return list.map((svc, idx) => ({
      svc,
      x: 780,
      y: Math.round(startY + idx * rowStep),
      w: 196,
      h: 44,
    }));
  }, [otherServices, centerY]);

  const gwBox = { x: 292, y: centerY - 38, w: 174, h: 76 };
  const nodeBox = { x: 534, y: centerY - 38, w: 174, h: 76 };

  // Build selected node details map
  const nodeInfoMap = useMemo(() => {
    const map = new Map<string, SelectedNodeInfo>();

    map.set('openshield-node', {
      id: 'openshield-node',
      kind: 'node',
      title: 'OpenShield Node (Core / BFF)',
      subtitle: `Protocolo openshield.event.v1 · Autonomia ${state.context.globalAutonomy}`,
      status: coreNodeStatus.status,
      statusLabel: coreNodeStatus.label,
      detail: state.context.nodeAvailable
        ? `${state.incidents.length} incidente(s) correlacionados · ${state.integrations.length} serviço(s) integrados.`
        : `Node simulado como offline. Conector preservando eventos no outbox SQLite (${state.metrics.outboxPendingTotal} pendentes).`,
      targetTab: 'incidents',
      targetTabLabel: 'Ver Incidentes e IA',
    });

    map.set('openwrt-gateway', {
      id: 'openwrt-gateway',
      kind: 'gateway',
      title: gatewayAdapter?.name ?? 'Gateway OpenWrt (LAN)',
      subtitle: gatewayAdapter
        ? `${gatewayAdapter.mode.toUpperCase()} · ${gatewayAdapter.liveEndpointUrl || 'Simulador local'}`
        : 'Plano de encaminhamento L2/L3 na LAN',
      status: gatewayStatus.status,
      statusLabel: gatewayStatus.label,
      detail: gatewayAdapter?.boardInfo
        ? `${gatewayAdapter.boardInfo.model} · Interfaces: ${gatewayAdapter.boardInfo.interfaces.join(', ')}`
        : 'Atua fora do caminho crítico de pacotes para manter roteamento contínuo mesmo se o Node reiniciar.',
      targetTab: 'integrations',
      targetTabLabel: 'Abrir Gateway e Integrações',
    });

    for (const dev of scopedClients) {
      const st = getClientStatus(dev);
      map.set(dev.id, {
        id: dev.id,
        kind: 'client',
        title: dev.hostname,
        subtitle: `${dev.ip} · ${dev.interfaceName} · ${dev.segment}`,
        status: st.status,
        statusLabel: st.label,
        detail: `${dev.dnsQueries24h.toLocaleString('pt-BR')} consultas DNS (24h) · ${dev.blockedQueries24h.toLocaleString('pt-BR')} bloqueios · Fabricante: ${dev.vendor}`,
        targetTab: 'devices',
        targetTabLabel: 'Ver Topologia e Fluxo',
      });
    }

    for (const svc of otherServices) {
      const st = getAdapterStatus(svc);
      map.set(svc.id, {
        id: svc.id,
        kind: 'service',
        title: svc.name,
        subtitle: `${svc.kind} · Modo ${svc.mode === 'live' ? 'API Real' : 'Simulador Mock'}`,
        status: st.status,
        statusLabel: st.label,
        detail:
          svc.liveEndpointUrl ||
          svc.lastLiveCheckMessage ||
          svc.description,
        targetTab: 'settings',
        targetTabLabel: 'Editar em Configurações',
      });
    }

    return map;
  }, [
    state.context.globalAutonomy,
    state.context.nodeAvailable,
    state.metrics.outboxPendingTotal,
    state.incidents.length,
    state.integrations.length,
    coreNodeStatus,
    gatewayAdapter,
    gatewayStatus,
    scopedClients,
    otherServices,
  ]);

  const selectedInfo =
    nodeInfoMap.get(selectedId) ?? nodeInfoMap.get('openshield-node') ?? null;

  return (
    <section
      aria-label="Mapa de Topologia da Rede"
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Network className="w-4 h-4 text-blue-400 shrink-0" />
            <span>Topologia Visual de Conexões</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Estado em tempo real entre Clientes da Rede, Gateway OpenWrt, OpenShield Node e Serviços Configurados (clique em qualquer nó para inspecionar).
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-300 shrink-0">
          <span className="inline-flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Online / Nominal</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>Degradado / Atenção</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span>Offline / Isolado</span>
          </span>
        </div>
      </div>

      {/* SVG Topology Canvas */}
      <div className="p-4 bg-[#0B1120]/70 overflow-x-auto">
        <svg
          viewBox={`0 0 1000 ${svgHeight}`}
          role="img"
          aria-label="Mapa visual de topologia conectando clientes da rede, gateway OpenWrt, OpenShield Node e serviços configurados"
          className="w-full min-w-[760px] h-auto select-none"
        >
          {/* Tier Column Headers */}
          <text x="122" y="22" textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="600">
            CLIENTES DA REDE ({totalScopedClientsCount})
          </text>
          <text x="379" y="22" textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="600">
            GATEWAY OPENWRT
          </text>
          <text x="621" y="22" textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="600">
            OPENSHIELD NODE
          </text>
          <text x="878" y="22" textAnchor="middle" fill="#94a3b8" fontSize="11" fontWeight="600">
            SERVIÇOS CONFIGURADOS ({totalOtherServicesCount})
          </text>

          {/* Edges: Clients -> Gateway OpenWrt */}
          {clientPositions.map(({ dev, x, y, w, h }) => {
            const cStatus = getClientStatus(dev).status;
            const edgeStatus: NodeStatusKind =
              gatewayStatus.status === 'offline' ? 'offline' : cStatus;
            const stroke = STATUS_STYLE[edgeStatus].edge;
            const isSelected = selectedId === dev.id || selectedId === 'openwrt-gateway';
            return (
              <path
                key={`edge-cli-${dev.id}`}
                d={cubicPath(x + w, y + h / 2, gwBox.x, gwBox.y + gwBox.h / 2)}
                fill="none"
                stroke={stroke}
                strokeWidth={isSelected ? 2.4 : 1.5}
                strokeOpacity={isSelected ? 0.95 : 0.45}
                strokeDasharray={edgeStatus === 'offline' ? '5 4' : undefined}
              />
            );
          })}

          {/* Empty client fallback line */}
          {clientPositions.length === 0 && (
            <path
              d={cubicPath(220, centerY, gwBox.x, gwBox.y + gwBox.h / 2)}
              fill="none"
              stroke="#334155"
              strokeWidth={1.5}
              strokeDasharray="4 4"
            />
          )}

          {/* Edge: Gateway OpenWrt <-> OpenShield Node */}
          <path
            d={cubicPath(
              gwBox.x + gwBox.w,
              gwBox.y + gwBox.h / 2,
              nodeBox.x,
              nodeBox.y + nodeBox.h / 2,
            )}
            fill="none"
            stroke={STATUS_STYLE[gwToNodeStatus].edge}
            strokeWidth={
              selectedId === 'openwrt-gateway' || selectedId === 'openshield-node' ? 3 : 2.2
            }
            strokeOpacity={0.9}
            strokeDasharray={gwToNodeStatus !== 'online' ? '6 4' : undefined}
          />
          <text
            x={(gwBox.x + gwBox.w + nodeBox.x) / 2}
            y={gwBox.y + gwBox.h / 2 - 10}
            textAnchor="middle"
            fill={STATUS_STYLE[gwToNodeStatus].text}
            fontSize="10"
            fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
          >
            {state.context.nodeAvailable ? 'rpcd / v1' : 'spool SQLite'}
          </text>

          {/* Edges: OpenShield Node -> Configured Services */}
          {servicePositions.map(({ svc, x, y, h }) => {
            const sStatus = getAdapterStatus(svc).status;
            const effectiveEdgeStatus: NodeStatusKind =
              !state.context.nodeAvailable && sStatus === 'online' ? 'degraded' : sStatus;
            const stroke = STATUS_STYLE[effectiveEdgeStatus].edge;
            const isSelected = selectedId === svc.id || selectedId === 'openshield-node';
            return (
              <path
                key={`edge-svc-${svc.id}`}
                d={cubicPath(nodeBox.x + nodeBox.w, nodeBox.y + nodeBox.h / 2, x, y + h / 2)}
                fill="none"
                stroke={stroke}
                strokeWidth={isSelected ? 2.4 : 1.5}
                strokeOpacity={isSelected ? 0.95 : 0.45}
                strokeDasharray={effectiveEdgeStatus !== 'online' ? '5 4' : undefined}
              />
            );
          })}

          {servicePositions.length === 0 && (
            <path
              d={cubicPath(nodeBox.x + nodeBox.w, nodeBox.y + nodeBox.h / 2, 780, centerY)}
              fill="none"
              stroke="#334155"
              strokeWidth={1.5}
              strokeDasharray="4 4"
            />
          )}

          {/* Client Nodes (Left Column) */}
          {clientPositions.length === 0 ? (
            <g
              className="cursor-pointer"
              onClick={() => onNavigate('devices')}
            >
              <rect
                x={24}
                y={centerY - 26}
                width={196}
                height={52}
                rx={8}
                fill="#0f172a"
                stroke="#334155"
                strokeDasharray="4 4"
              />
              <text x={122} y={centerY - 4} textAnchor="middle" fill="#cbd5e1" fontSize="11" fontWeight="600">
                Nenhum cliente ainda
              </text>
              <text x={122} y={centerY + 13} textAnchor="middle" fill="#60a5fa" fontSize="10">
                + Adicionar Dispositivos
              </text>
            </g>
          ) : (
            clientPositions.map(({ dev, x, y, w, h }) => {
              const st = getClientStatus(dev);
              const colors = STATUS_STYLE[st.status];
              const isSelected = selectedId === dev.id;
              return (
                <g
                  key={dev.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedId(dev.id)}
                >
                  <rect
                    x={x}
                    y={y}
                    width={w}
                    height={h}
                    rx={8}
                    fill={isSelected ? '#172554' : colors.fill}
                    stroke={isSelected ? '#3b82f6' : colors.stroke}
                    strokeWidth={isSelected ? 2 : 1.2}
                    strokeOpacity={isSelected ? 1 : 0.75}
                  />
                  <circle cx={x + 14} cy={y + 16} r={3.5} fill={colors.dot} />
                  <text
                    x={x + 24}
                    y={y + 19}
                    fill="#f1f5f9"
                    fontSize="11.5"
                    fontWeight="600"
                  >
                    {truncateLabel(dev.hostname, 21)}
                  </text>
                  <text
                    x={x + 24}
                    y={y + 34}
                    fill="#94a3b8"
                    fontSize="10"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    {dev.ip} · {truncateLabel(dev.segment, 12)}
                  </text>
                </g>
              );
            })
          )}

          {totalScopedClientsCount > clientPositions.length && (
            <text
              x={122}
              y={svgHeight - 8}
              textAnchor="middle"
              fill="#60a5fa"
              fontSize="10"
              className="cursor-pointer"
              onClick={() => onNavigate('devices')}
            >
              +{totalScopedClientsCount - clientPositions.length} cliente(s) em Dispositivos →
            </text>
          )}

          {/* Gateway OpenWrt Node */}
          <g
            className="cursor-pointer"
            onClick={() => setSelectedId('openwrt-gateway')}
          >
            <rect
              x={gwBox.x}
              y={gwBox.y}
              width={gwBox.w}
              height={gwBox.h}
              rx={10}
              fill={selectedId === 'openwrt-gateway' ? '#172554' : '#0f172a'}
              stroke={
                selectedId === 'openwrt-gateway'
                  ? '#3b82f6'
                  : STATUS_STYLE[gatewayStatus.status].stroke
              }
              strokeWidth={selectedId === 'openwrt-gateway' ? 2.2 : 1.6}
            />
            <circle
              cx={gwBox.x + 16}
              cy={gwBox.y + 22}
              r={4}
              fill={STATUS_STYLE[gatewayStatus.status].dot}
            />
            <text
              x={gwBox.x + 27}
              y={gwBox.y + 26}
              fill="#f8fafc"
              fontSize="12"
              fontWeight="700"
            >
              {truncateLabel(gatewayAdapter?.name ?? 'Gateway OpenWrt', 17)}
            </text>
            <text
              x={gwBox.x + 14}
              y={gwBox.y + 44}
              fill="#94a3b8"
              fontSize="10"
            >
              {gatewayAdapter?.boardInfo?.model
                ? truncateLabel(gatewayAdapter.boardInfo.model, 24)
                : 'Plano de dados LAN'}
            </text>
            <text
              x={gwBox.x + 14}
              y={gwBox.y + 60}
              fill={STATUS_STYLE[gatewayStatus.status].text}
              fontSize="10"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {truncateLabel(gatewayStatus.label, 24)}
            </text>
          </g>

          {/* OpenShield Core Node */}
          <g
            className="cursor-pointer"
            onClick={() => setSelectedId('openshield-node')}
          >
            <rect
              x={nodeBox.x}
              y={nodeBox.y}
              width={nodeBox.w}
              height={nodeBox.h}
              rx={10}
              fill={selectedId === 'openshield-node' ? '#172554' : '#0f172a'}
              stroke={
                selectedId === 'openshield-node'
                  ? '#3b82f6'
                  : STATUS_STYLE[coreNodeStatus.status].stroke
              }
              strokeWidth={selectedId === 'openshield-node' ? 2.2 : 1.6}
            />
            <circle
              cx={nodeBox.x + 16}
              cy={nodeBox.y + 22}
              r={4}
              fill={STATUS_STYLE[coreNodeStatus.status].dot}
            />
            <text
              x={nodeBox.x + 27}
              y={nodeBox.y + 26}
              fill="#f8fafc"
              fontSize="12"
              fontWeight="700"
            >
              OpenShield Node
            </text>
            <text
              x={nodeBox.x + 14}
              y={nodeBox.y + 44}
              fill="#94a3b8"
              fontSize="10"
            >
              BFF · Correlação & IA
            </text>
            <text
              x={nodeBox.x + 14}
              y={nodeBox.y + 60}
              fill={STATUS_STYLE[coreNodeStatus.status].text}
              fontSize="10"
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
            >
              {truncateLabel(coreNodeStatus.label, 24)}
            </text>
          </g>

          {/* Configured Services Nodes (Right Column) */}
          {servicePositions.length === 0 ? (
            <g
              className="cursor-pointer"
              onClick={() => onNavigate('settings')}
            >
              <rect
                x={780}
                y={centerY - 26}
                width={196}
                height={52}
                rx={8}
                fill="#0f172a"
                stroke="#334155"
                strokeDasharray="4 4"
              />
              <text x={878} y={centerY - 4} textAnchor="middle" fill="#cbd5e1" fontSize="11" fontWeight="600">
                Sem serviços extras
              </text>
              <text x={878} y={centerY + 13} textAnchor="middle" fill="#60a5fa" fontSize="10">
                + Configurar Serviços
              </text>
            </g>
          ) : (
            servicePositions.map(({ svc, x, y, w, h }) => {
              const st = getAdapterStatus(svc);
              const colors = STATUS_STYLE[st.status];
              const isSelected = selectedId === svc.id;
              return (
                <g
                  key={svc.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedId(svc.id)}
                >
                  <rect
                    x={x}
                    y={y}
                    width={w}
                    height={h}
                    rx={8}
                    fill={isSelected ? '#172554' : colors.fill}
                    stroke={isSelected ? '#3b82f6' : colors.stroke}
                    strokeWidth={isSelected ? 2 : 1.2}
                    strokeOpacity={isSelected ? 1 : 0.75}
                  />
                  <circle cx={x + 14} cy={y + 16} r={3.5} fill={colors.dot} />
                  <text
                    x={x + 24}
                    y={y + 19}
                    fill="#f1f5f9"
                    fontSize="11.5"
                    fontWeight="600"
                  >
                    {truncateLabel(svc.name, 21)}
                  </text>
                  <text
                    x={x + 24}
                    y={y + 34}
                    fill={colors.text}
                    fontSize="10"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    {svc.mode.toUpperCase()} · {truncateLabel(st.label, 18)}
                  </text>
                </g>
              );
            })
          )}

          {totalOtherServicesCount > servicePositions.length && (
            <text
              x={878}
              y={svgHeight - 8}
              textAnchor="middle"
              fill="#60a5fa"
              fontSize="10"
              className="cursor-pointer"
              onClick={() => onNavigate('integrations')}
            >
              +{totalOtherServicesCount - servicePositions.length} serviço(s) em Integrações →
            </text>
          )}
        </svg>
      </div>

      {/* Interactive Node Detail Footer Strip */}
      {selectedInfo && (
        <div className="px-5 py-3.5 border-t border-slate-800 bg-slate-900/50 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-xs">
          <div className="flex items-start gap-2.5 min-w-0">
            {selectedInfo.kind === 'gateway' ? (
              <Router className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            ) : selectedInfo.kind === 'node' ? (
              <Cpu className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            ) : selectedInfo.kind === 'client' ? (
              <Laptop className="w-4 h-4 text-slate-300 shrink-0 mt-0.5" />
            ) : (
              <Server className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-semibold text-slate-100">{selectedInfo.title}</span>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span
                  className="font-mono font-medium"
                  style={{ color: STATUS_STYLE[selectedInfo.status].text }}
                >
                  {selectedInfo.statusLabel}
                </span>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span className="font-mono text-slate-400 truncate">{selectedInfo.subtitle}</span>
              </div>
              <p className="text-slate-400 mt-0.5 truncate">{selectedInfo.detail}</p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onNavigate(selectedInfo.targetTab)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer self-start sm:self-auto"
          >
            <span>{selectedInfo.targetTabLabel}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </section>
  );
}
