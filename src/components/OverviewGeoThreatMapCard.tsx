import { useMemo, useRef, useState } from 'react';
import { geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import { ArrowRight, Globe2, ShieldBan, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { feature } from 'topojson-client';
import countriesAtlas from 'world-atlas/countries-110m.json';
import { getIntlLocale } from '../i18n';
import {
  buildGeoThreatSummary,
  type GeoCountryThreatStat,
  type GeoMapFilterMode,
} from '../lib/geoThreatAnalytics';
import type { EventSeverity, WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';

interface OverviewGeoThreatMapCardProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  livePaused?: boolean;
  frozenAtMs?: number;
  onToggleLivePaused?: () => void;
}

interface CountryGeometryItem {
  id: string;
  name: string;
  pathD: string;
}

interface HoverState {
  numericId: string;
  defaultName: string;
  xPct: number;
  yPct: number;
}

const MAP_WIDTH = 960;
const MAP_HEIGHT = 440;

const HEAT_STOPS = [
  '#7f1d1d', // low
  '#991b1b',
  '#b91c1c',
  '#dc2626',
  '#ef4444', // peak
] as const;

function getHeatFill(value: number, maxValue: number): string {
  if (value <= 0 || maxValue <= 0) return '#182235';
  const ratio = Math.min(1, value / maxValue);
  if (ratio >= 0.8) return HEAT_STOPS[4];
  if (ratio >= 0.55) return HEAT_STOPS[3];
  if (ratio >= 0.35) return HEAT_STOPS[2];
  if (ratio >= 0.15) return HEAT_STOPS[1];
  return HEAT_STOPS[0];
}

function getSeverityTextClass(severity: EventSeverity): string {
  if (severity === 'critical') return 'text-red-400';
  if (severity === 'high') return 'text-orange-400';
  if (severity === 'medium') return 'text-amber-400';
  if (severity === 'low') return 'text-sky-400';
  return 'text-slate-300';
}

export function OverviewGeoThreatMapCard({
  state,
  onNavigate,
  livePaused = false,
  frozenAtMs,
  onToggleLivePaused,
}: OverviewGeoThreatMapCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const mapBoxRef = useRef<HTMLDivElement | null>(null);

  const [filterMode, setFilterMode] = useState<GeoMapFilterMode>('blocked');
  const [selectedNumericId, setSelectedNumericId] = useState<string | null>(null);
  const [hovered, setHovered] = useState<HoverState | null>(null);

  const summary = useMemo(
    () => buildGeoThreatSummary(state, filterMode),
    [state, filterMode],
  );

  const regionNames = useMemo(() => {
    try {
      return new Intl.DisplayNames([locale], { type: 'region' });
    } catch {
      return null;
    }
  }, [locale]);

  const localizeCountryName = (alpha2: string | undefined, fallbackName: string): string => {
    if (alpha2 && regionNames) {
      try {
        const localized = regionNames.of(alpha2);
        if (localized) return localized;
      } catch {
        // fallback below
      }
    }
    return fallbackName;
  };

  // Build D3 projection, graticule, and country SVG paths once
  const mapGeometry = useMemo(() => {
    type TopoInput = Parameters<typeof feature>[0];
    type GeomObject = Parameters<typeof feature>[1];

    const topology = countriesAtlas as unknown as TopoInput & {
      objects: { countries: GeomObject };
    };
    const collection = feature(topology, topology.objects.countries) as unknown as {
      type: 'FeatureCollection';
      features: Array<{
        type: 'Feature';
        id?: string | number;
        properties?: { name?: string };
        geometry: unknown;
      }>;
    };

    // Exclude Antarctica (ISO 010) so populated landmasses fill the dashboard viewport cleanly
    const inhabitedFeatures = collection.features.filter(
      (f) => String(f.id ?? '').padStart(3, '0') !== '010',
    );
    const fittedCollection = {
      type: 'FeatureCollection' as const,
      features: inhabitedFeatures,
    };

    const projection = geoNaturalEarth1().fitExtent(
      [
        [14, 14],
        [MAP_WIDTH - 14, MAP_HEIGHT - 14],
      ],
      fittedCollection as unknown as Parameters<ReturnType<typeof geoNaturalEarth1>['fitExtent']>[1],
    );
    const pathGenerator = geoPath(projection);
    const graticulePath = pathGenerator(geoGraticule10()) ?? '';

    const countries: CountryGeometryItem[] = inhabitedFeatures
      .map((feat) => {
        const id = String(feat.id ?? '').padStart(3, '0');
        const pathD = pathGenerator(feat as unknown as Parameters<typeof pathGenerator>[0]) ?? '';
        return {
          id,
          name: feat.properties?.name ?? id,
          pathD,
        };
      })
      .filter((item) => item.pathD !== '');

    return { projection, graticulePath, countries };
  }, []);

  const pausedTimeLabel =
    livePaused && typeof frozenAtMs === 'number'
      ? new Date(frozenAtMs).toLocaleTimeString(locale, {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      : null;

  const selectedCountry: GeoCountryThreatStat | null =
    selectedNumericId && summary.byNumericId[selectedNumericId]
      ? summary.byNumericId[selectedNumericId]
      : null;

  const hoveredCountry: GeoCountryThreatStat | null =
    hovered && summary.byNumericId[hovered.numericId]
      ? summary.byNumericId[hovered.numericId]
      : null;

  const handleMapMouseMove = (
    e: React.MouseEvent<SVGElement>,
    numericId: string,
    defaultName: string,
  ) => {
    const box = mapBoxRef.current;
    if (!box) return;
    const rect = box.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const rawXPct = ((e.clientX - rect.left) / rect.width) * 100;
    const rawYPct = ((e.clientY - rect.top) / rect.height) * 100;
    setHovered({
      numericId,
      defaultName,
      xPct: Math.max(12, Math.min(82, rawXPct)),
      yPct: Math.max(12, Math.min(78, rawYPct)),
    });
  };

  return (
    <section
      aria-label={t('geoThreatMap.ariaLabel')}
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-red-400 shrink-0" />
            <h2 className="text-base font-semibold text-slate-100">{t('geoThreatMap.title')}</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <span>{t('geoThreatMap.subtitle')}</span>
            {livePaused && (
              <>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span className="text-amber-300 font-medium tabular-nums">
                  {pausedTimeLabel
                    ? t('telemetryDashboard.pausedAt', { time: pausedTimeLabel })
                    : t('telemetryDashboard.pausedLabel')}
                </span>
                {onToggleLivePaused && (
                  <button
                    type="button"
                    onClick={onToggleLivePaused}
                    className="text-blue-400 hover:text-blue-300 font-medium underline underline-offset-2 cursor-pointer"
                  >
                    {t('telemetryDashboard.resumeInline')}
                  </button>
                )}
              </>
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {/* Summary KPI counters (unboxed tabular text) */}
          <div className="flex flex-wrap items-center gap-3 text-xs tabular-nums text-slate-300">
            <span className="inline-flex items-center gap-1.5">
              <ShieldBan className="w-3.5 h-3.5 text-red-400 shrink-0" />
              <span className="text-slate-400">{t('geoThreatMap.blockedTotalLabel')}:</span>
              <span className="font-mono font-semibold text-slate-100">
                {summary.totalBlockedAttempts.toLocaleString(locale)}
              </span>
            </span>
            <span aria-hidden="true" className="text-slate-700">
              ·
            </span>
            <span>
              <span className="text-slate-400">{t('geoThreatMap.countriesLabel')}: </span>
              <span className="font-mono font-semibold text-slate-100">
                {summary.totalCountriesAffected.toLocaleString(locale)}
              </span>
            </span>
          </div>

          {/* Segmented filter control */}
          <div
            role="group"
            aria-label={t('geoThreatMap.title')}
            className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800 shrink-0"
          >
            <button
              type="button"
              onClick={() => setFilterMode('blocked')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                filterMode === 'blocked'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
              }`}
            >
              {t('geoThreatMap.filterBlocked')}
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                filterMode === 'all'
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
              }`}
            >
              {t('geoThreatMap.filterAll')}
            </button>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('integrations')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('geoThreatMap.integrationsLink')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Body */}
      {!summary.hasGeoData ? (
        <div className="p-8 text-center space-y-2.5">
          <p className="text-sm font-medium text-slate-200">{t('geoThreatMap.emptyTitle')}</p>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">{t('geoThreatMap.emptyHint')}</p>
          {summary.localPrivateBlockedCount > 0 && (
            <p className="text-xs text-slate-400 tabular-nums pt-1">
              {t('geoThreatMap.localDropsNote', {
                count: summary.localPrivateBlockedCount.toLocaleString(locale),
              })}
            </p>
          )}
          <div className="pt-1">
            <button
              type="button"
              onClick={() => onNavigate('integrations')}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors cursor-pointer"
            >
              {t('geoThreatMap.integrationsLink')}
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 divide-y xl:divide-y-0 xl:divide-x divide-slate-800">
          {/* Left: D3 Choropleth Map */}
          <div className="xl:col-span-8 p-5 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="font-medium text-slate-200">{t('geoThreatMap.mapTitle')}</span>

              <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400 tabular-nums">
                {summary.localPrivateBlockedCount > 0 && (
                  <>
                    <span>
                      {t('geoThreatMap.localDropsNote', {
                        count: summary.localPrivateBlockedCount.toLocaleString(locale),
                      })}
                    </span>
                    <span aria-hidden="true" className="text-slate-700">
                      ·
                    </span>
                  </>
                )}
                <div className="inline-flex items-center gap-1.5">
                  <span>{t('geoThreatMap.legendLow')}</span>
                  <div className="inline-flex items-center gap-0.5" aria-hidden="true">
                    <span className="w-3.5 h-2 rounded-xs bg-[#182235] border border-slate-700" />
                    {HEAT_STOPS.map((color) => (
                      <span
                        key={color}
                        className="w-3.5 h-2 rounded-xs"
                        style={{ backgroundColor: color }}
                      />
                    ))}
                  </div>
                  <span>
                    {t('geoThreatMap.legendHigh')} ({summary.maxCountryAttempts.toLocaleString(locale)})
                  </span>
                </div>
              </div>
            </div>

            <div
              ref={mapBoxRef}
              className="relative w-full rounded-lg border border-slate-800 bg-[#0B1120] overflow-hidden"
              onMouseLeave={() => setHovered(null)}
            >
              <svg
                viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
                role="img"
                aria-label={t('geoThreatMap.ariaLabel')}
                className="w-full h-auto block select-none"
              >
                {/* Graticule grid */}
                <path
                  d={mapGeometry.graticulePath}
                  fill="none"
                  stroke="#1e293b"
                  strokeOpacity={0.5}
                  strokeWidth={0.6}
                />

                {/* Country choropleth paths */}
                <g>
                  {mapGeometry.countries.map((country) => {
                    const stat = summary.byNumericId[country.id];
                    const metricValue = stat
                      ? filterMode === 'blocked'
                        ? stat.blockedAttempts
                        : stat.totalAttempts
                      : 0;
                    const isSelected = selectedNumericId === country.id;
                    const isHovered = hovered?.numericId === country.id;
                    const fill = stat
                      ? getHeatFill(metricValue, summary.maxCountryAttempts)
                      : '#182235';

                    return (
                      <path
                        key={country.id}
                        d={country.pathD}
                        fill={fill}
                        stroke={
                          isSelected
                            ? '#38bdf8'
                            : isHovered
                              ? '#fca5a5'
                              : stat
                                ? '#ef4444'
                                : '#263449'
                        }
                        strokeWidth={isSelected ? 1.6 : isHovered ? 1.2 : stat ? 0.75 : 0.45}
                        strokeOpacity={isSelected || isHovered ? 1 : stat ? 0.8 : 0.75}
                        className={stat ? 'cursor-pointer transition-opacity' : 'transition-colors'}
                        onMouseMove={(e) => handleMapMouseMove(e, country.id, country.name)}
                        onClick={() => {
                          if (!stat) {
                            setSelectedNumericId(null);
                            return;
                          }
                          setSelectedNumericId((prev) =>
                            prev === country.id ? null : country.id,
                          );
                        }}
                      />
                    );
                  })}
                </g>

                {/* Hotspot centroid rings so compact countries (NL, TW, GB, etc.) remain obvious */}
                <g>
                  {summary.countries.map((stat) => {
                    const projected = mapGeometry.projection(stat.centroid);
                    if (!projected) return null;
                    const [cx, cy] = projected;
                    const val =
                      filterMode === 'blocked' ? stat.blockedAttempts : stat.totalAttempts;
                    const radius = Math.max(
                      3.5,
                      Math.min(11, 3.5 + Math.sqrt(val / Math.max(1, summary.maxCountryAttempts)) * 7.5),
                    );
                    const isSelected = selectedNumericId === stat.isoNumeric;

                    return (
                      <g
                        key={`hotspot-${stat.isoNumeric}`}
                        className="cursor-pointer"
                        onMouseMove={(e) =>
                          handleMapMouseMove(e, stat.isoNumeric, stat.defaultName)
                        }
                        onClick={() =>
                          setSelectedNumericId((prev) =>
                            prev === stat.isoNumeric ? null : stat.isoNumeric,
                          )
                        }
                      >
                        <circle
                          cx={cx}
                          cy={cy}
                          r={radius + 4}
                          fill="#ef4444"
                          fillOpacity={isSelected ? 0.35 : 0.2}
                        />
                        <circle
                          cx={cx}
                          cy={cy}
                          r={radius}
                          fill={isSelected ? '#38bdf8' : '#f87171'}
                          fillOpacity={0.9}
                          stroke="#0B1120"
                          strokeWidth={1.1}
                        />
                      </g>
                    );
                  })}
                </g>
              </svg>

              {/* Floating Hover Tooltip */}
              {hovered && (
                <div
                  style={{
                    left: `${hovered.xPct}%`,
                    top: `${hovered.yPct}%`,
                    transform: 'translate(-50%, -108%)',
                  }}
                  className="pointer-events-none absolute z-20 rounded-lg border border-slate-700 bg-[#0B1120]/95 backdrop-blur-sm px-3.5 py-2.5 shadow-xl text-xs space-y-1.5 min-w-[220px] max-w-[275px]"
                >
                  <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-1.5">
                    <span className="font-semibold text-slate-100 truncate">
                      {hoveredCountry
                        ? localizeCountryName(hoveredCountry.isoAlpha2, hoveredCountry.defaultName)
                        : hovered.defaultName}
                    </span>
                    {hoveredCountry && (
                      <span className="font-mono text-[11px] text-slate-400 shrink-0">
                        {hoveredCountry.isoAlpha2}
                      </span>
                    )}
                  </div>

                  {!hoveredCountry ? (
                    <div className="text-slate-400 text-[11px]">
                      {t('geoThreatMap.noActivityLabel')}
                    </div>
                  ) : (
                    <div className="space-y-1 tabular-nums">
                      <div className="flex items-center justify-between gap-4">
                        <span className="text-slate-400">{t('geoThreatMap.tooltipBlocked')}</span>
                        <span className="font-mono font-semibold text-red-400">
                          {hoveredCountry.blockedAttempts.toLocaleString(locale)}
                        </span>
                      </div>
                      {hoveredCountry.observedAttempts > 0 && (
                        <div className="flex items-center justify-between gap-4">
                          <span className="text-slate-400">{t('geoThreatMap.tooltipObserved')}</span>
                          <span className="font-mono font-semibold text-amber-300">
                            {hoveredCountry.observedAttempts.toLocaleString(locale)}
                          </span>
                        </div>
                      )}
                      <div className="flex items-center justify-between gap-4">
                        <span className="text-slate-400">{t('geoThreatMap.tooltipShare')}</span>
                        <span className="font-mono text-slate-200">
                          {hoveredCountry.sharePct.toLocaleString(locale, {
                            minimumFractionDigits: 1,
                            maximumFractionDigits: 1,
                          })}
                          %
                        </span>
                      </div>
                      <div className="flex items-center justify-between gap-4">
                        <span className="text-slate-400">{t('geoThreatMap.tooltipSeverity')}</span>
                        <span
                          className={`font-medium ${getSeverityTextClass(hoveredCountry.highestSeverity)}`}
                        >
                          {t(`incidents.severity.${hoveredCountry.highestSeverity}`)}
                        </span>
                      </div>
                      <div className="border-t border-slate-800 pt-1 text-[11px] space-y-0.5">
                        <div className="text-slate-400">
                          {t('geoThreatMap.tooltipVectors')}:{' '}
                          <span className="font-mono text-slate-200">
                            {hoveredCountry.services.join(', ')}
                          </span>
                        </div>
                        <div className="text-slate-400 truncate">
                          {t('geoThreatMap.tooltipTopIps')}:{' '}
                          <span className="font-mono text-slate-200">
                            {hoveredCountry.uniqueIps.slice(0, 2).join(', ')}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right: Top Origin Countries Breakdown & Inspector */}
          <div className="xl:col-span-4 p-5 flex flex-col justify-between gap-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold text-slate-200">
                  {t('geoThreatMap.topCountriesTitle')}
                </h3>
                {selectedCountry && (
                  <button
                    type="button"
                    onClick={() => setSelectedNumericId(null)}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 cursor-pointer"
                  >
                    <X className="w-3 h-3" />
                    <span>{t('geoThreatMap.clearSelection')}</span>
                  </button>
                )}
              </div>

              <div className="divide-y divide-slate-800/80 max-h-[260px] overflow-y-auto">
                {summary.countries.slice(0, 8).map((country) => {
                  const count =
                    filterMode === 'blocked' ? country.blockedAttempts : country.totalAttempts;
                  const widthPct = Math.max(
                    6,
                    Math.round((count / Math.max(1, summary.maxCountryAttempts)) * 100),
                  );
                  const isSelected = selectedNumericId === country.isoNumeric;
                  const displayName = localizeCountryName(country.isoAlpha2, country.defaultName);

                  return (
                    <button
                      key={country.isoNumeric}
                      type="button"
                      onClick={() =>
                        setSelectedNumericId((prev) =>
                          prev === country.isoNumeric ? null : country.isoNumeric,
                        )
                      }
                      className={`w-full text-left py-2.5 px-2 transition-colors cursor-pointer space-y-1.5 ${
                        isSelected ? 'bg-slate-800/70 rounded-md' : 'hover:bg-slate-900/50'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 text-xs tabular-nums">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono text-[11px] text-slate-400 w-6 shrink-0">
                            {country.isoAlpha2}
                          </span>
                          <span className="font-medium text-slate-100 truncate">
                            {displayName}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="font-mono font-semibold text-red-400">
                            {count.toLocaleString(locale)}
                          </span>
                          <span className="font-mono text-[11px] text-slate-400 w-11 text-right">
                            {country.sharePct.toLocaleString(locale, {
                              minimumFractionDigits: 1,
                              maximumFractionDigits: 1,
                            })}
                            %
                          </span>
                        </div>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${widthPct}%`,
                            backgroundColor: getHeatFill(count, summary.maxCountryAttempts),
                          }}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Selected Country Inspector (or Top Country summary) */}
            {(() => {
              const target = selectedCountry ?? summary.countries[0];
              if (!target) return null;
              const targetName = localizeCountryName(target.isoAlpha2, target.defaultName);
              return (
                <div className="border-t border-slate-800 pt-3.5 space-y-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-medium text-slate-400">
                      {t('geoThreatMap.selectedDetailTitle')}
                    </span>
                    <span
                      className={`font-medium ${getSeverityTextClass(target.highestSeverity)}`}
                    >
                      {t(`incidents.severity.${target.highestSeverity}`)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-100">
                      {targetName} ({target.isoAlpha2})
                    </span>
                    <span className="font-mono text-slate-300 tabular-nums">
                      {filterMode === 'blocked'
                        ? t('geoThreatMap.attemptsUnit', {
                            count: target.blockedAttempts.toLocaleString(locale),
                          })
                        : t('geoThreatMap.allAttemptsUnit', {
                            count: target.totalAttempts.toLocaleString(locale),
                          })}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 space-y-1">
                    <div className="font-mono text-slate-300 truncate">
                      {t('geoThreatMap.tooltipTopIps')}: {target.uniqueIps.slice(0, 4).join(', ')}
                    </div>
                    <div className="flex items-center justify-between gap-2 tabular-nums">
                      <span className="font-mono text-slate-300">
                        {t('geoThreatMap.tooltipVectors')}: {target.services.join(', ')}
                      </span>
                      <span className="text-slate-500">
                        {new Date(target.lastSeenAt).toLocaleTimeString(locale, {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </section>
  );
}
