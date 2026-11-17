import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Info,
  ShieldAlert,
  ShieldBan,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import {
  buildSecurityTimeline,
  type TimelineSortOrder,
  type TimelineStatus,
} from '../lib/securityTimeline';
import type { WorkspaceState } from '../types/openshield';
import type { NavTab } from './OverviewView';
import { PaginationControls, usePagination } from './PaginationControls';

interface OverviewSecurityTimelineCardProps {
  state: WorkspaceState;
  onNavigate: (tab: NavTab) => void;
  onQuickInvestigate: (incidentId: string) => void;
}

type TimelineFilter = 'all' | 'alerts' | 'mitigated' | 'info';

function getStatusVisual(status: TimelineStatus) {
  switch (status) {
    case 'blocked':
      return {
        Icon: ShieldBan,
        nodeClass: 'border-emerald-300 dark:border-emerald-500/45 text-emerald-700 dark:text-emerald-400',
        labelClass: 'text-emerald-700 dark:text-emerald-400',
      };
    case 'verified':
      return {
        Icon: CheckCircle2,
        nodeClass: 'border-emerald-300 dark:border-emerald-500/45 text-emerald-700 dark:text-emerald-400',
        labelClass: 'text-emerald-700 dark:text-emerald-400',
      };
    case 'alert':
      return {
        Icon: ShieldAlert,
        nodeClass: 'border-red-300 dark:border-red-500/50 text-red-700 dark:text-red-400',
        labelClass: 'text-red-700 dark:text-red-400',
      };
    case 'warning':
      return {
        Icon: AlertTriangle,
        nodeClass: 'border-amber-300 dark:border-amber-500/50 text-amber-700 dark:text-amber-400',
        labelClass: 'text-amber-700 dark:text-amber-400',
      };
    case 'info':
    default:
      return {
        Icon: Info,
        nodeClass: 'border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400',
        labelClass: 'text-slate-700 dark:text-slate-300',
      };
  }
}

export function OverviewSecurityTimelineCard({
  state,
  onNavigate,
  onQuickInvestigate,
}: OverviewSecurityTimelineCardProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const [sortOrder, setSortOrder] = useState<TimelineSortOrder>('desc');
  const [filter, setFilter] = useState<TimelineFilter>('all');

  const allItems = useMemo(
    () => buildSecurityTimeline(state, sortOrder),
    [state, sortOrder],
  );

  const filteredItems = useMemo(() => {
    return allItems.filter((item) => {
      if (filter === 'alerts') {
        return item.status === 'alert' || item.status === 'warning';
      }
      if (filter === 'mitigated') {
        return item.status === 'blocked' || item.status === 'verified';
      }
      if (filter === 'info') {
        return item.status === 'info';
      }
      return true;
    });
  }, [allItems, filter]);

  const pagination = usePagination(
    filteredItems,
    10,
    `${state.context.profile}|${state.context.activeSiteId}|${sortOrder}|${filter}`,
  );

  const formatRelativeTime = (iso: string): string => {
    const ts = Date.parse(iso);
    if (!Number.isFinite(ts)) return '';
    const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (diffSec < 60) return t('overview.relSec', { n: diffSec });
    const min = Math.floor(diffSec / 60);
    if (min < 60) return t('overview.relMin', { n: min });
    return t('overview.relHour', { n: Math.floor(min / 60) });
  };

  return (
    <section
      aria-label={t('securityTimeline.ariaLabel')}
      className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#131C31] overflow-hidden shadow-xs dark:shadow-none"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              {t('securityTimeline.title')}
            </h2>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{t('securityTimeline.subtitle')}</p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {/* Chronological order toggle */}
          <div
            role="group"
            aria-label={t('securityTimeline.title')}
            className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800"
          >
            <button
              type="button"
              onClick={() => setSortOrder('desc')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                sortOrder === 'desc'
                  ? 'bg-emerald-600 text-white'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              {t('securityTimeline.orderNewest')}
            </button>
            <button
              type="button"
              onClick={() => setSortOrder('asc')}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                sortOrder === 'asc'
                  ? 'bg-emerald-600 text-white'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              {t('securityTimeline.orderOldest')}
            </button>
          </div>

          <button
            type="button"
            onClick={() => onNavigate('audit')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>{t('securityTimeline.auditLink')}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Status Filter Bar */}
      {allItems.length > 0 && (
        <div className="px-5 py-2.5 border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/80 dark:bg-slate-950/30 flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
            {(
              [
                { id: 'all', label: t('securityTimeline.filterAll') },
                { id: 'alerts', label: t('securityTimeline.filterAlerts') },
                { id: 'mitigated', label: t('securityTimeline.filterMitigated') },
                { id: 'info', label: t('securityTimeline.filterInfo') },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  filter === tab.id
                    ? 'bg-emerald-600 text-white'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <span className="text-xs font-mono text-slate-600 dark:text-slate-400 tabular-nums">
            {filteredItems.length.toLocaleString(locale)} / {allItems.length.toLocaleString(locale)}
          </span>
        </div>
      )}

      {/* Vertical Timeline Body */}
      {allItems.length === 0 ? (
        <div className="p-8 text-center space-y-2.5">
          <p className="text-sm font-medium text-slate-800 dark:text-slate-200">{t('securityTimeline.emptyTitle')}</p>
          <p className="text-xs text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
            {t('securityTimeline.emptyHint')}
          </p>
          <div className="pt-1">
            <button
              type="button"
              onClick={() => onNavigate('settings')}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors cursor-pointer"
            >
              {t('overview.configureServices')}
            </button>
          </div>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="p-8 text-center text-xs text-slate-600 dark:text-slate-400">
          {t('securityTimeline.emptyFiltered')}
        </div>
      ) : (
        <>
          <div className="px-5 py-4 max-h-[440px] overflow-y-auto">
            <ol className="relative space-y-5 before:content-[''] before:absolute before:left-[13px] before:top-3 before:bottom-3 before:w-px before:bg-slate-200 dark:before:bg-slate-800">
              {pagination.pagedItems.map((item) => {
                const { Icon, nodeClass, labelClass } = getStatusVisual(item.status);
                const ts = Date.parse(item.timestamp);
                const timeStr = Number.isFinite(ts)
                  ? new Date(ts).toLocaleTimeString(locale, {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })
                  : item.timestamp;
                const relStr = formatRelativeTime(item.timestamp);

                return (
                  <li key={item.id} className="relative pl-10">
                    {/* Status Icon Node */}
                    <span
                      aria-hidden="true"
                      className={`absolute left-0 top-0.5 w-7 h-7 rounded-full border bg-white dark:bg-[#0B1120] flex items-center justify-center ${nodeClass}`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                    </span>

                    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:justify-between">
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs tabular-nums">
                          <span className={`font-semibold ${labelClass}`}>
                            {t(`securityTimeline.statuses.${item.status}`)}
                          </span>
                          <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                            ·
                          </span>
                          <time
                            dateTime={item.timestamp}
                            className="font-mono text-slate-800 dark:text-slate-200"
                            title={Number.isFinite(ts) ? new Date(ts).toLocaleString(locale) : item.timestamp}
                          >
                            {timeStr}
                          </time>
                          {relStr && (
                            <span className="text-slate-500">({relStr})</span>
                          )}
                          <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                            ·
                          </span>
                          <span className="text-slate-700 dark:text-slate-300 font-medium">{item.sourceLabel}</span>
                          <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                            ·
                          </span>
                          <span className="font-mono text-slate-600 dark:text-slate-400">{item.eventTypeLabel}</span>
                          {item.targetLabel && (
                            <>
                              <span aria-hidden="true" className="text-slate-400 dark:text-slate-600">
                                ·
                              </span>
                              <span className="font-mono text-slate-700 dark:text-slate-300">{item.targetLabel}</span>
                            </>
                          )}
                        </div>
                        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">{item.summary}</p>
                      </div>

                      {item.linkedIncidentId && (
                        <button
                          type="button"
                          onClick={() => onQuickInvestigate(item.linkedIncidentId!)}
                          className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 hover:text-emerald-600 dark:text-emerald-400 dark:hover:text-emerald-300 whitespace-nowrap shrink-0 cursor-pointer self-start"
                        >
                          <span>{t('securityTimeline.inspectIncident')}</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
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
