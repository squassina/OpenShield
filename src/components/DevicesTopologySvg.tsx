import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';
import { Maximize2, Minus, Plus, RotateCcw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import type { NetworkDevice, WorkspaceState } from '../types/openshield';

interface DevicesTopologySvgProps {
  devices: NetworkDevice[];
  segments: NetworkDevice['segment'][];
  segmentFilter: 'all' | NetworkDevice['segment'];
  selectedDeviceId: string | null;
  state: WorkspaceState;
  onSelectDevice: (device: NetworkDevice) => void;
  translateSegment: (seg: NetworkDevice['segment']) => string;
}

type NodeStatusKind = 'nominal' | 'attention' | 'isolated';

const STATUS_STYLE: Record<
  NodeStatusKind,
  { stroke: string; edge: string; text: string; dot: string; badgeBg: string }
> = {
  nominal: {
    stroke: '#10b981',
    edge: '#10b981',
    text: '#34d399',
    dot: '#10b981',
    badgeBg: '#064e3b',
  },
  attention: {
    stroke: '#f59e0b',
    edge: '#f59e0b',
    text: '#fbbf24',
    dot: '#f59e0b',
    badgeBg: '#78350f',
  },
  isolated: {
    stroke: '#ef4444',
    edge: '#ef4444',
    text: '#f87171',
    dot: '#ef4444',
    badgeBg: '#7f1d1d',
  },
};

const MIN_SCALE = 0.25;
const MAX_SCALE = 2.5;
const ZOOM_STEP = 1.2;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function truncateLabel(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen - 1)}…`;
}

function cubicPath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = Math.abs(x2 - x1) * 0.48;
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function bypassCol1Path(
  sx: number,
  sy: number,
  topY: number,
  spineX: number,
  tx: number,
  ty: number,
): string {
  const entryX = sx + 28;
  const r = 8;
  // Route smoothly from Segment Hub -> up to bypass lane above col 0 -> across to spineX -> down -> into target
  if (Math.abs(sy - topY) < 16) {
    return `M ${sx} ${sy} L ${spineX - r} ${sy} Q ${spineX} ${sy} ${spineX} ${sy + r} L ${spineX} ${ty - r} Q ${spineX} ${ty} ${spineX + r} ${ty} L ${tx} ${ty}`;
  }
  return [
    `M ${sx} ${sy}`,
    `L ${entryX - r} ${sy}`,
    `Q ${entryX} ${sy} ${entryX} ${sy - r}`,
    `L ${entryX} ${topY + r}`,
    `Q ${entryX} ${topY} ${entryX + r} ${topY}`,
    `L ${spineX - r} ${topY}`,
    `Q ${spineX} ${topY} ${spineX} ${topY + r}`,
    `L ${spineX} ${ty - r}`,
    `Q ${spineX} ${ty} ${spineX + r} ${ty}`,
    `L ${tx} ${ty}`,
  ].join(' ');
}

function getDeviceStatus(dev: NetworkDevice): NodeStatusKind {
  if (dev.status === 'isolated') return 'isolated';
  if (dev.status === 'attention' || dev.riskScore >= 60) return 'attention';
  return 'nominal';
}

function getDeviceTypeBadge(type: NetworkDevice['deviceType']): string {
  if (type === 'router') return 'GW';
  if (type === 'server') return 'SRV';
  if (type === 'iot') return 'IoT';
  if (type === 'mobile') return 'MOB';
  return 'PC';
}

export function DevicesTopologySvg({
  devices,
  segments,
  segmentFilter,
  selectedDeviceId,
  state,
  onSelectDevice,
  translateSegment,
}: DevicesTopologySvgProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const viewportRef = useRef<HTMLDivElement | null>(null);
  const [viewportSize, setViewportSize] = useState<{ width: number; height: number }>({
    width: 960,
    height: 460,
  });

  const [transform, setTransform] = useState<{ scale: number; x: number; y: number }>({
    scale: 1,
    x: 20,
    y: 20,
  });
  const transformRef = useRef(transform);
  transformRef.current = transform;

  const [isDragging, setIsDragging] = useState(false);
  const [hoveredDeviceId, setHoveredDeviceId] = useState<string | null>(null);

  const dragStateRef = useRef<{
    pointerId: number;
    startClientX: number;
    startClientY: number;
    startPanX: number;
    startPanY: number;
    moved: boolean;
  } | null>(null);
  const suppressNextClickRef = useRef(false);
  const hasAutoFittedRef = useRef(false);

  const activeSegments = useMemo(
    () => (segmentFilter === 'all' ? segments : segments.filter((s) => s === segmentFilter)),
    [segments, segmentFilter],
  );

  const layout = useMemo(() => {
    const GW_X = 28;
    const GW_W = 186;
    const GW_H = 84;

    const SEG_X = 274;
    const SEG_W = 192;
    const SEG_H = 64;

    const DEV_COL0_X = 542;
    const DEV_COL1_X = 796;
    const DEV_W = 216;
    const DEV_H = 56;
    const DEV_ROW_GAP = 14;
    const SEG_BLOCK_GAP = 32;
    const TOP_PAD = 36;
    const BOTTOM_PAD = 28;

    let currentY = TOP_PAD;
    let maxColCount = 1;

    interface PositionedDevice {
      device: NetworkDevice;
      col: 0 | 1;
      x: number;
      y: number;
      w: number;
      h: number;
      status: NodeStatusKind;
    }

    interface PositionedSegment {
      segment: NetworkDevice['segment'];
      x: number;
      y: number;
      w: number;
      h: number;
      cols: 1 | 2;
      bypassTopY: number;
      devices: PositionedDevice[];
      emptyBox?: { x: number; y: number; w: number; h: number };
      status: NodeStatusKind;
    }

    const positionedSegments: PositionedSegment[] = [];

    for (const seg of activeSegments) {
      const segDevices = devices.filter((d) => d.segment === seg);
      const count = segDevices.length;
      const cols: 1 | 2 = count > 4 ? 2 : 1;
      if (cols > maxColCount) maxColCount = cols;

      const rows = count === 0 ? 1 : cols === 2 ? Math.ceil(count / 2) : count;
      const devicesBlockH =
        count === 0 ? SEG_H : rows * DEV_H + Math.max(0, rows - 1) * DEV_ROW_GAP;
      const topBypassPad = cols === 2 ? 20 : 0;
      const blockH = Math.max(SEG_H, topBypassPad + devicesBlockH);
      const segY = currentY + Math.round((blockH - SEG_H) / 2);
      const devicesStartY = currentY + topBypassPad;

      const positionedDevices: PositionedDevice[] = segDevices.map((dev, idx) => {
        const col: 0 | 1 = cols === 2 && idx >= rows ? 1 : 0;
        const row = cols === 2 && idx >= rows ? idx - rows : idx;
        return {
          device: dev,
          col,
          x: col === 0 ? DEV_COL0_X : DEV_COL1_X,
          y: devicesStartY + row * (DEV_H + DEV_ROW_GAP),
          w: DEV_W,
          h: DEV_H,
          status: getDeviceStatus(dev),
        };
      });

      const segStatus: NodeStatusKind = positionedDevices.some((d) => d.status === 'isolated')
        ? 'isolated'
        : positionedDevices.some((d) => d.status === 'attention')
          ? 'attention'
          : 'nominal';

      positionedSegments.push({
        segment: seg,
        x: SEG_X,
        y: segY,
        w: SEG_W,
        h: SEG_H,
        cols,
        bypassTopY: currentY + 6,
        devices: positionedDevices,
        emptyBox:
          count === 0
            ? {
                x: DEV_COL0_X,
                y: segY + Math.round((SEG_H - 42) / 2),
                w: DEV_W,
                h: 42,
              }
            : undefined,
        status: segStatus,
      });

      currentY += blockH + SEG_BLOCK_GAP;
    }

    const contentHeight = Math.max(300, currentY - SEG_BLOCK_GAP + BOTTOM_PAD);
    const contentWidth =
      maxColCount === 2 ? DEV_COL1_X + DEV_W + 36 : DEV_COL0_X + DEV_W + 36;
    const gwY = Math.round(contentHeight / 2 - GW_H / 2);

    return {
      contentWidth,
      contentHeight,
      gateway: { x: GW_X, y: gwY, w: GW_W, h: GW_H },
      segments: positionedSegments,
      devCol1SpineX: DEV_COL1_X - 24,
    };
  }, [activeSegments, devices]);

  const computeFitTransform = useCallback(
    (vw: number, vh: number) => {
      const paddingX = 36;
      const paddingY = 36;
      const usableW = Math.max(120, vw - paddingX * 2);
      const usableH = Math.max(120, vh - paddingY * 2);
      const fitScale = clamp(
        Math.min(usableW / layout.contentWidth, usableH / layout.contentHeight),
        MIN_SCALE,
        1.15,
      );
      const x = Math.round((vw - layout.contentWidth * fitScale) / 2);
      const y = Math.round((vh - layout.contentHeight * fitScale) / 2);
      return { scale: fitScale, x, y };
    },
    [layout.contentWidth, layout.contentHeight],
  );

  const fitToView = useCallback(() => {
    const el = viewportRef.current;
    const vw = el?.clientWidth || viewportSize.width;
    const vh = el?.clientHeight || viewportSize.height;
    setTransform(computeFitTransform(vw, vh));
  }, [computeFitTransform, viewportSize.width, viewportSize.height]);

  const resetZoom100 = useCallback(() => {
    const el = viewportRef.current;
    const vw = el?.clientWidth || viewportSize.width;
    const vh = el?.clientHeight || viewportSize.height;
    setTransform({
      scale: 1,
      x: Math.round((vw - layout.contentWidth) / 2),
      y: Math.max(16, Math.round((vh - layout.contentHeight) / 2)),
    });
  }, [layout.contentWidth, layout.contentHeight, viewportSize.width, viewportSize.height]);

  const zoomAtPoint = useCallback(
    (factor: number, clientX?: number, clientY?: number) => {
      const el = viewportRef.current;
      const rect = el?.getBoundingClientRect();
      const focalX =
        rect && typeof clientX === 'number'
          ? clientX - rect.left
          : (rect?.width ?? viewportSize.width) / 2;
      const focalY =
        rect && typeof clientY === 'number'
          ? clientY - rect.top
          : (rect?.height ?? viewportSize.height) / 2;

      setTransform((prev) => {
        const nextScale = clamp(prev.scale * factor, MIN_SCALE, MAX_SCALE);
        if (Math.abs(nextScale - prev.scale) < 0.0001) return prev;
        const ratio = nextScale / prev.scale;
        return {
          scale: nextScale,
          x: focalX - (focalX - prev.x) * ratio,
          y: focalY - (focalY - prev.y) * ratio,
        };
      });
    },
    [viewportSize.width, viewportSize.height],
  );

  // Measure viewport & auto-fit cleanly on initial render
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;

    const updateSize = () => {
      const width = el.clientWidth;
      const height = el.clientHeight;
      if (width <= 0 || height <= 0) return;
      setViewportSize({ width, height });
      if (!hasAutoFittedRef.current) {
        hasAutoFittedRef.current = true;
        setTransform(computeFitTransform(width, height));
      }
    };

    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(el);
    return () => observer.disconnect();
  }, [computeFitTransform]);

  // Re-fit smoothly when user switches segment filter
  const prevFilterRef = useRef(segmentFilter);
  useEffect(() => {
    if (prevFilterRef.current !== segmentFilter) {
      prevFilterRef.current = segmentFilter;
      fitToView();
    }
  }, [segmentFilter, fitToView]);

  // Non-passive wheel listener for smooth cursor-centered zoom
  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      // Normalize trackpad pinch / wheel delta smoothly
      const intensity = e.ctrlKey ? 0.012 : 0.0018;
      const factor = Math.exp(-e.deltaY * intensity);
      zoomAtPoint(clamp(factor, 0.78, 1.28), e.clientX, e.clientY);
    };

    el.addEventListener('wheel', handleWheel, { passive: false });
    return () => el.removeEventListener('wheel', handleWheel);
  }, [zoomAtPoint]);

  const handlePointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    // Only primary mouse button or touch
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    // Ignore pointer down on toolbar controls
    if ((e.target as HTMLElement).closest('[data-topology-control="true"]')) return;

    dragStateRef.current = {
      pointerId: e.pointerId,
      startClientX: e.clientX,
      startClientY: e.clientY,
      startPanX: transformRef.current.x,
      startPanY: transformRef.current.y,
      moved: false,
    };
    suppressNextClickRef.current = false;
  };

  const handlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragStateRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;

    const dx = e.clientX - drag.startClientX;
    const dy = e.clientY - drag.startClientY;
    if (!drag.moved && Math.hypot(dx, dy) > 5) {
      drag.moved = true;
      suppressNextClickRef.current = true;
      setIsDragging(true);
      try {
        e.currentTarget.setPointerCapture(e.pointerId);
      } catch {
        // Ignore if pointer already ended
      }
    }

    if (drag.moved) {
      setTransform((prev) => ({
        ...prev,
        x: drag.startPanX + dx,
        y: drag.startPanY + dy,
      }));
    }
  };

  const handlePointerUpOrCancel = (e: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragStateRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;

    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
    if (drag.moved) {
      // Allow immediate click event on same tick to see suppress flag, then reset
      window.setTimeout(() => {
        suppressNextClickRef.current = false;
      }, 0);
    }
    dragStateRef.current = null;
    setIsDragging(false);
  };

  const handleViewportKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === '+' || e.key === '=') {
      e.preventDefault();
      zoomAtPoint(ZOOM_STEP);
    } else if (e.key === '-' || e.key === '_') {
      e.preventDefault();
      zoomAtPoint(1 / ZOOM_STEP);
    } else if (e.key === '0') {
      e.preventDefault();
      fitToView();
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      setTransform((prev) => ({ ...prev, x: prev.x + 48 }));
    } else if (e.key === 'ArrowRight') {
      e.preventDefault();
      setTransform((prev) => ({ ...prev, x: prev.x - 48 }));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setTransform((prev) => ({ ...prev, y: prev.y + 48 }));
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setTransform((prev) => ({ ...prev, y: prev.y - 48 }));
    }
  };

  const gatewayStatus: NodeStatusKind = !state.context.gatewayForwardingActive
    ? 'isolated'
    : 'nominal';
  const gatewayStyle = STATUS_STYLE[gatewayStatus];
  const dnsAdaptersCount = state.integrations.filter((i) => i.domain === 'dns').length;
  const activeHighlightId = hoveredDeviceId ?? selectedDeviceId;

  const zoomPercent = Math.round(transform.scale * 100);

  return (
    <div className="space-y-3">
      {/* Header + Status Legend */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            {t('devices.svgTopologyTitle')}
          </h3>
          <span className="text-[11px] text-slate-400">{t('devices.panZoomHint')}</span>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-300">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>{t('devices.legendNominal')}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>{t('devices.legendAttention')}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-red-400" />
            <span>{t('devices.legendIsolated')}</span>
          </span>
        </div>
      </div>

      {/* Interactive Zoom/Pan SVG Viewport */}
      <div
        ref={viewportRef}
        tabIndex={0}
        onKeyDown={handleViewportKeyDown}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUpOrCancel}
        onPointerCancel={handlePointerUpOrCancel}
        style={{ touchAction: 'none' }}
        aria-label={t('devices.svgTopologyAria')}
        className={`relative w-full h-[460px] rounded-xl border border-slate-800 bg-[#0B1120] overflow-hidden select-none focus:outline-none focus:ring-1 focus:ring-blue-500/70 ${
          isDragging ? 'cursor-grabbing' : 'cursor-grab'
        }`}
      >
        {/* Floating Zoom & Pan Toolbar */}
        <div
          data-topology-control="true"
          className="absolute top-3 right-3 z-10 inline-flex items-center gap-1 rounded-lg border border-slate-700/90 bg-[#0F172A]/95 p-1 shadow-lg backdrop-blur-sm"
        >
          <button
            type="button"
            onClick={() => zoomAtPoint(1 / ZOOM_STEP)}
            disabled={transform.scale <= MIN_SCALE + 0.01}
            aria-label={t('devices.zoomOut')}
            title={t('devices.zoomOut')}
            className="p-1.5 rounded-md text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Minus className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={resetZoom100}
            title={t('devices.resetZoom')}
            className="px-2 py-1 min-w-[50px] text-center font-mono text-[11px] font-medium text-slate-200 hover:text-white hover:bg-slate-800 rounded-md tabular-nums transition-colors cursor-pointer"
          >
            {zoomPercent}%
          </button>

          <button
            type="button"
            onClick={() => zoomAtPoint(ZOOM_STEP)}
            disabled={transform.scale >= MAX_SCALE - 0.01}
            aria-label={t('devices.zoomIn')}
            title={t('devices.zoomIn')}
            className="p-1.5 rounded-md text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>

          <div className="w-px h-4 bg-slate-700 mx-0.5" />

          <button
            type="button"
            onClick={fitToView}
            aria-label={t('devices.fitToView')}
            title={t('devices.fitToView')}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium text-slate-300 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Maximize2 className="w-3 h-3" />
            <span>{t('devices.fitShort')}</span>
          </button>

          <button
            type="button"
            onClick={resetZoom100}
            aria-label={t('devices.resetZoom')}
            title={t('devices.resetZoom')}
            className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" />
          </button>
        </div>

        {/* SVG Graph Canvas */}
        <svg
          width="100%"
          height="100%"
          role="img"
          aria-label={t('devices.svgTopologyAria')}
          className="block w-full h-full"
        >
          <defs>
            <pattern
              id="openshield-topo-grid"
              width="24"
              height="24"
              patternUnits="userSpaceOnUse"
            >
              <circle cx="1" cy="1" r="1" fill="#1e293b" />
            </pattern>
          </defs>

          <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}>
            {/* Subtle spatial dot-grid covering generous area around content */}
            <rect
              x={-800}
              y={-800}
              width={layout.contentWidth + 1600}
              height={layout.contentHeight + 1600}
              fill="url(#openshield-topo-grid)"
            />

            {/* Column Headers */}
            <text
              x={layout.gateway.x + layout.gateway.w / 2}
              y={18}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="10"
              fontWeight="600"
              letterSpacing="0.06em"
            >
              {t('topologyMap.colGateway')}
            </text>
            <text
              x={274 + 96}
              y={18}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="10"
              fontWeight="600"
              letterSpacing="0.06em"
            >
              {t('devices.colSegment').toUpperCase()} ({activeSegments.length})
            </text>
            <text
              x={layout.contentWidth > 850 ? 778 : 650}
              y={18}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="10"
              fontWeight="600"
              letterSpacing="0.06em"
            >
              {t('topologyMap.colClients', { count: devices.length })}
            </text>

            {/* Edges: Gateway -> Segments */}
            {layout.segments.map((segNode) => {
              const segStyle = STATUS_STYLE[segNode.status];
              const edgeColor =
                gatewayStatus === 'isolated' ? STATUS_STYLE.isolated.edge : segStyle.edge;
              const isHighlighted = segNode.devices.some(
                (d) => d.device.id === activeHighlightId,
              );
              return (
                <path
                  key={`gw-seg-${segNode.segment}`}
                  d={cubicPath(
                    layout.gateway.x + layout.gateway.w,
                    layout.gateway.y + layout.gateway.h / 2,
                    segNode.x,
                    segNode.y + segNode.h / 2,
                  )}
                  fill="none"
                  stroke={edgeColor}
                  strokeWidth={isHighlighted ? 2.6 : 1.7}
                  strokeOpacity={isHighlighted ? 0.95 : 0.45}
                  strokeDasharray={gatewayStatus === 'isolated' ? '5 4' : undefined}
                />
              );
            })}

            {/* Edges: Segment -> Devices */}
            {layout.segments.map((segNode) => {
              const sx = segNode.x + segNode.w;
              const sy = segNode.y + segNode.h / 2;

              return (
                <g key={`seg-edges-${segNode.segment}`}>
                  {segNode.emptyBox && (
                    <path
                      d={cubicPath(
                        sx,
                        sy,
                        segNode.emptyBox.x,
                        segNode.emptyBox.y + segNode.emptyBox.h / 2,
                      )}
                      fill="none"
                      stroke="#334155"
                      strokeWidth={1.3}
                      strokeDasharray="4 4"
                    />
                  )}

                  {segNode.devices.map((devNode) => {
                    const dStyle = STATUS_STYLE[devNode.status];
                    const isHighlighted = devNode.device.id === activeHighlightId;
                    const tx = devNode.x;
                    const ty = devNode.y + devNode.h / 2;
                    const pathD =
                      devNode.col === 0
                        ? cubicPath(sx, sy, tx, ty)
                        : bypassCol1Path(
                            sx,
                            sy,
                            segNode.bypassTopY,
                            layout.devCol1SpineX,
                            tx,
                            ty,
                          );

                    return (
                      <path
                        key={`edge-dev-${devNode.device.id}`}
                        d={pathD}
                        fill="none"
                        stroke={dStyle.edge}
                        strokeWidth={isHighlighted ? 2.5 : 1.5}
                        strokeOpacity={isHighlighted ? 0.98 : 0.45}
                        strokeDasharray={devNode.status === 'isolated' ? '5 4' : undefined}
                      />
                    );
                  })}
                </g>
              );
            })}

            {/* Gateway Node */}
            <g>
              <rect
                x={layout.gateway.x}
                y={layout.gateway.y}
                width={layout.gateway.w}
                height={layout.gateway.h}
                rx={12}
                fill="#0f172a"
                stroke={gatewayStyle.stroke}
                strokeWidth={2}
              />
              <circle
                cx={layout.gateway.x + 18}
                cy={layout.gateway.y + 22}
                r={5}
                fill={gatewayStyle.dot}
              />
              <text
                x={layout.gateway.x + 30}
                y={layout.gateway.y + 26}
                fill="#f8fafc"
                fontSize="12.5"
                fontWeight="700"
              >
                {t('devices.gatewayNodeTitle')}
              </text>
              <text
                x={layout.gateway.x + 16}
                y={layout.gateway.y + 46}
                fill={gatewayStyle.text}
                fontSize="10.5"
                fontWeight="500"
              >
                {state.context.gatewayForwardingActive
                  ? t('devices.gatewayForwardingOn')
                  : t('devices.gatewayForwardingOff')}
              </text>
              <text
                x={layout.gateway.x + 16}
                y={layout.gateway.y + 66}
                fill="#94a3b8"
                fontSize="10"
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                {dnsAdaptersCount} DNS · {devices.length} hosts
              </text>
            </g>

            {/* Segment Hub Nodes */}
            {layout.segments.map((segNode) => {
              const sStyle = STATUS_STYLE[segNode.status];
              return (
                <g key={`seg-node-${segNode.segment}`}>
                  <rect
                    x={segNode.x}
                    y={segNode.y}
                    width={segNode.w}
                    height={segNode.h}
                    rx={10}
                    fill="#0f172a"
                    stroke={segNode.devices.length > 0 ? sStyle.stroke : '#334155'}
                    strokeWidth={1.6}
                  />
                  <circle
                    cx={segNode.x + 16}
                    cy={segNode.y + 23}
                    r={4.5}
                    fill={segNode.devices.length > 0 ? sStyle.dot : '#475569'}
                  />
                  <text
                    x={segNode.x + 28}
                    y={segNode.y + 27}
                    fill="#f1f5f9"
                    fontSize="12"
                    fontWeight="600"
                  >
                    {truncateLabel(translateSegment(segNode.segment), 20)}
                  </text>
                  <text
                    x={segNode.x + 16}
                    y={segNode.y + 47}
                    fill="#94a3b8"
                    fontSize="10.5"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    {t('devices.segmentDeviceCount', { count: segNode.devices.length })}
                  </text>
                </g>
              );
            })}

            {/* Empty Segment Placeholders */}
            {layout.segments.map(
              (segNode) =>
                segNode.emptyBox && (
                  <g key={`empty-${segNode.segment}`}>
                    <rect
                      x={segNode.emptyBox.x}
                      y={segNode.emptyBox.y}
                      width={segNode.emptyBox.w}
                      height={segNode.emptyBox.h}
                      rx={8}
                      fill="#0f172a"
                      fillOpacity={0.5}
                      stroke="#334155"
                      strokeDasharray="4 4"
                      strokeWidth={1.2}
                    />
                    <text
                      x={segNode.emptyBox.x + segNode.emptyBox.w / 2}
                      y={segNode.emptyBox.y + 25}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="10.5"
                    >
                      {t('devices.noDevicesInSegment')}
                    </text>
                  </g>
                ),
            )}

            {/* Device Nodes */}
            {layout.segments.flatMap((segNode) =>
              segNode.devices.map((devNode) => {
                const { device: dev, x, y, w, h, status } = devNode;
                const dStyle = STATUS_STYLE[status];
                const isSelected = selectedDeviceId === dev.id;
                const isHovered = hoveredDeviceId === dev.id;

                return (
                  <g
                    key={dev.id}
                    role="button"
                    tabIndex={0}
                    aria-label={`${dev.hostname} (${dev.ip})`}
                    style={{ cursor: isDragging ? 'grabbing' : 'pointer' }}
                    onMouseEnter={() => setHoveredDeviceId(dev.id)}
                    onMouseLeave={() =>
                      setHoveredDeviceId((curr) => (curr === dev.id ? null : curr))
                    }
                    onClick={(e) => {
                      e.stopPropagation();
                      if (suppressNextClickRef.current) return;
                      onSelectDevice(dev);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        e.stopPropagation();
                        onSelectDevice(dev);
                      }
                    }}
                  >
                    {(isSelected || isHovered) && (
                      <rect
                        x={x - 3}
                        y={y - 3}
                        width={w + 6}
                        height={h + 6}
                        rx={12}
                        fill="none"
                        stroke={isSelected ? '#60a5fa' : dStyle.stroke}
                        strokeOpacity={0.45}
                        strokeWidth={2}
                      />
                    )}
                    <rect
                      x={x}
                      y={y}
                      width={w}
                      height={h}
                      rx={9}
                      fill={isSelected ? '#172554' : isHovered ? '#1e293b' : '#0f172a'}
                      stroke={isSelected ? '#60a5fa' : dStyle.stroke}
                      strokeWidth={isSelected || isHovered ? 2 : 1.4}
                    />

                    {/* Type Badge */}
                    <rect
                      x={x + 10}
                      y={y + 10}
                      width={30}
                      height={16}
                      rx={4}
                      fill="#1e293b"
                    />
                    <text
                      x={x + 25}
                      y={y + 21}
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize="9"
                      fontWeight="700"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {getDeviceTypeBadge(dev.deviceType)}
                    </text>

                    {/* Hostname */}
                    <text
                      x={x + 46}
                      y={y + 22}
                      fill="#f8fafc"
                      fontSize="11.5"
                      fontWeight="600"
                    >
                      {truncateLabel(dev.hostname, 17)}
                    </text>

                    {/* IP + Interface */}
                    <text
                      x={x + 10}
                      y={y + 42}
                      fill="#94a3b8"
                      fontSize="10"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {truncateLabel(`${dev.ip} · ${dev.interfaceName}`, 23)}
                    </text>

                    {/* Risk Pill */}
                    <circle cx={x + w - 42} cy={y + 39} r={3.5} fill={dStyle.dot} />
                    <text
                      x={x + w - 10}
                      y={y + 42}
                      textAnchor="end"
                      fill={dStyle.text}
                      fontSize="10"
                      fontWeight="700"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {dev.riskScore.toLocaleString(locale)}
                    </text>
                  </g>
                );
              }),
            )}
          </g>
        </svg>

        {devices.length === 0 && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <div className="rounded-lg border border-slate-800 bg-[#0F172A]/90 px-4 py-2.5 text-xs text-slate-400">
              {t('devices.emptyTopology')}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
