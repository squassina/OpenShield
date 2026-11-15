import { useMemo, useState } from 'react';
import { AlertTriangle, ArrowRight, Search } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import { buildNetworkAnomalyAlerts } from '../lib/anomalyAlerts';
import type { EventSeverity, WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';
import { PaginationControls, usePagination } from './PaginationControls';

interface OverviewAnomalyAlertsCardProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  onQuickInvestigate: (incidentId: string) => void;
}

type AnomalyFilter = 'all' | 'critical_high' | 'ids_ioc' | 'router';

const SEVERITY_TEXT_STYLES: Record<EventSeverity, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-sky-400',
  info: 'text-slate-300',
};

export function OverviewAnomalyAlertsCard({
  state,
  onNavigate,
  onQuickInvestigate,
}: OverviewAnomalyAlertsCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const [filter, setFilter] = useState<AnomalyFilter>('all');
  const [search, setSearch] = useState('');

  const allAlerts = useMemo(() => buildNetworkAnomalyAlerts(state), [state]);

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allAlerts.filter((alert) => {
      if (filter === 'critical_high') {
        if (alert.severity !== 'critical' && alert.severity !== 'high') return false;
      } else if (filter === 'ids_ioc') {
        if (alert.category !== 'ids' && alert.category !== 'ioc') return false;
      } else if (filter === 'router') {
        if (alert.category !== 'router') return false;
      }

      if (!q) return true;
      return (
        alert.deviceLabel.toLowerCase().includes(q) ||
        alert.sourceIp.toLowerCase().includes(q) ||
        alert.summary.toLowerCase().includes(q) ||
        alert.vectorLabel.toLowerCase().includes(q)
      );
    });
  }, [allAlerts, filter, search]);

  const pagination = usePagination(
    filteredAlerts,
    10,
    `${state.context.profile}|${state.context.activeSiteId}|${filter}|${search}`,
  );

  const handleViewDetails = (linkedIncidentId: string | null) => {
    if (linkedIncidentId) {
      onQuickInvestigate(linkedIncidentId);
    } else {
      onNavigate('incidents');
    }
  };

  return (
    <section
      aria-label={t('anomalyAlerts.ariaLabel')}
      className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between px-5 py-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <h2 className="text-base font-semibold text-slate-100">
              {t('anomalyAlerts.title')}
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">{t('anomalyAlerts.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <span className="text-xs font-mono text-slate-300 tabular-nums">
            {t('anomalyAlerts.totalCount', {
              count: allAlerts.length,
            })}
          </span>
          <button
            type="button"
            onClick={() => onNavigate('incidents')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('anomalyAlerts.openIncidents')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      {allAlerts.length > 0 && (
        <div className="px-5 py-3 border-b border-slate-800/80 flex flex-col gap-2.5 lg:flex-row lg:items-center lg:justify-between bg-slate-950/30">
          <div
            role="group"
            aria-label={t('anomalyAlerts.title')}
            className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-950 border border-slate-800 self-start"
          >
            {(
              [
                { id: 'all', label: t('anomalyAlerts.filterAll') },
                { id: 'critical_high', label: t('anomalyAlerts.filterCriticalHigh') },
                { id: 'ids_ioc', label: t('anomalyAlerts.filterIdsIoc') },
                { id: 'router', label: t('anomalyAlerts.filterRouter') },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`px-3 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  filter === tab.id
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative w-full lg:w-72">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('anomalyAlerts.searchPlaceholder')}
              aria-label={t('anomalyAlerts.searchPlaceholder')}
              className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-800 bg-slate-950 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>
      )}

      {/* Alerts List */}
      {allAlerts.length === 0 ? (
        <div className="p-8 text-center space-y-2.5">
          <p className="text-sm font-medium text-slate-200">{t('anomalyAlerts.emptyTitle')}</p>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">{t('anomalyAlerts.emptyHint')}</p>
          <div className="pt-1">
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors cursor-pointer"
            >
              {t('overview.configureServices')}
            </button>
          </div>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-400">
          {t('anomalyAlerts.emptyFiltered')}
        </div>
      ) : (
        <>
          <div className="divide-y divide-slate-800/80 max-h-[420px] overflow-y-auto">
            {pagination.pagedItems.map((alert) => {
              const sevColor = SEVERITY_TEXT_STYLES[alert.severity] ?? SEVERITY_TEXT_STYLES.info;
              return (
                <div
                  key={alert.id}
                  className="px-5 py-3.5 flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between hover:bg-slate-900/40 transition-colors"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs tabular-nums">
                      <span className={`font-semibold ${sevColor}`}>
                        {t(`incidents.severity.${alert.severity}`)}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">
                        {t('anomalyAlerts.deviceLabel')}:{' '}
                        <strong className="font-medium text-slate-100">
                          {alert.deviceLabel}
                        </strong>
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">
                        {t('anomalyAlerts.sourceIpLabel')}:{' '}
                        <span className="font-mono text-slate-200">{alert.sourceIp}</span>
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="font-mono text-slate-400">{alert.vectorLabel}</span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="font-mono text-slate-500">
                        {new Date(alert.timestamp).toLocaleTimeString(locale, {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed truncate">
                      {alert.summary}
                    </p>
                  </div>

                  <div className="shrink-0">
                    <button
                      type="button"
                      onClick={() => handleViewDetails(alert.linkedIncidentId)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-blue-400 hover:text-blue-300 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <span>{t('anomalyAlerts.viewDetails')}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          <PaginationControls
            page={pagination.page}
            pageSize={pagination.pageSize}
            totalItems={pagination.totalItems}
            totalPages={pagination.totalPages}
            onPageChange={pagination.setPage}
            onPageSizeChange={pagination.setPageSize}
            compact
          />
        </>
      )}
    </section>
  );
}
