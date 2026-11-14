import { useMemo, useState, type FormEvent } from 'react';
import { Eye, GlobeLock, Plus, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';
import type { DnsInsight, WorkspaceState } from '../types/openshield';
import { PaginationControls, usePagination } from './PaginationControls';

interface DnsPrivacyViewProps {
  state: WorkspaceState;
  searchQuery: string;
  onAddDnsInsight: (payload: {
    domain: string;
    category?: DnsInsight['category'];
    classification?: DnsInsight['classification'];
    deviceHostname?: string;
    listStatus?: DnsInsight['listStatus'];
  }) => Promise<void>;
  onUpdateDnsList: (id: string, listStatus: DnsInsight['listStatus']) => Promise<void>;
  busyKey: string | null;
}

export function DnsPrivacyView({
  state,
  searchQuery,
  onAddDnsInsight,
  onUpdateDnsList,
  busyKey,
}: DnsPrivacyViewProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);
  const [filter, setFilter] = useState<'all' | DnsInsight['classification']>('all');
  const [showAddForm, setShowAddForm] = useState(false);
  const [domainInput, setDomainInput] = useState('');
  const [classification, setClassification] = useState<DnsInsight['classification']>('tracker');
  const [category, setCategory] = useState<DnsInsight['category']>('Telemetria & Rastreador');
  const [listStatus, setListStatus] = useState<DnsInsight['listStatus']>('blocked');
  const [deviceHostname, setDeviceHostname] = useState('');

  const filteredInsights = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return state.dnsInsights.filter((item) => {
      if (filter !== 'all' && item.classification !== filter) return false;
      if (!q) return true;
      return (
        item.domain.toLowerCase().includes(q) ||
        item.deviceHostname.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q)
      );
    });
  }, [state.dnsInsights, filter, searchQuery]);

  const dnsPagination = usePagination(filteredInsights, 10, `${filter}|${searchQuery}`);

  const dnsAdapters = state.integrations.filter((i) => i.domain === 'dns');
  const liveDnsCount = dnsAdapters.filter((i) => i.mode === 'live').length;
  const totalQueries = state.dnsInsights.reduce((s, d) => s + d.queriesCount, 0);
  const totalBlocked = state.dnsInsights.reduce((s, d) => s + d.blockedCount, 0);
  const blockRate = totalQueries > 0 ? Math.round((totalBlocked / totalQueries) * 100) : 0;

  const handleAddSubmit = async (e: FormEvent) => {
    e.preventDefault();
    await onAddDnsInsight({
      domain: domainInput,
      classification,
      category,
      listStatus,
      deviceHostname: deviceHostname.trim() || undefined,
    });
    setDomainInput('');
    setDeviceHostname('');
    setShowAddForm(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
            {t('dns.title')}
          </h1>
          <p className="mt-1 text-sm text-slate-400 max-w-2xl">
            {t('dns.subtitle', { total: dnsAdapters.length, live: liveDnsCount })}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="inline-flex items-center gap-1 p-1 rounded-lg bg-[#131C31] border border-slate-800">
            {[
              { id: 'all', label: t('dns.filterAll') },
              { id: 'tracker', label: t('dns.filterTracker') },
              { id: 'suspicious', label: t('dns.filterSuspicious') },
              { id: 'benign', label: t('dns.filterBenign') },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id as typeof filter)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  filter === tab.id ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setShowAddForm((prev) => !prev)}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showAddForm ? t('dns.closeForm') : t('dns.addDomain')}</span>
          </button>
        </div>
      </div>

      {/* Add Manual Domain Form */}
      {showAddForm && (
        <form
          onSubmit={handleAddSubmit}
          className="rounded-xl border border-slate-700 bg-[#131C31] p-5 space-y-4"
        >
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-100">{t('dns.formTitle')}</h2>
            <p className="text-xs text-slate-400 mt-0.5">{t('dns.formSubtitle')}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5">
            <label className="block space-y-1 text-xs lg:col-span-2">
              <span className="text-slate-300 font-medium">{t('dns.domainLabel')}</span>
              <input
                type="text"
                required
                placeholder={t('dns.domainPlaceholder')}
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              />
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('dns.classificationLabel')}</span>
              <select
                value={classification}
                onChange={(e) => {
                  const next = e.target.value as DnsInsight['classification'];
                  setClassification(next);
                  if (next === 'tracker') setCategory('Telemetria & Rastreador');
                  else if (next === 'suspicious') setCategory('Suspeito / DGA');
                  else setCategory('Serviço Local');
                }}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="tracker">{t('dns.classTracker')}</option>
                <option value="suspicious">{t('dns.classSuspicious')}</option>
                <option value="benign">{t('dns.classBenign')}</option>
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('dns.initialStateLabel')}</span>
              <select
                value={listStatus}
                onChange={(e) => setListStatus(e.target.value as DnsInsight['listStatus'])}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value="blocked">{t('common.blocked')}</option>
                <option value="monitored">{t('common.monitored')}</option>
                <option value="allowed">{t('common.allowed')}</option>
              </select>
            </label>

            <label className="block space-y-1 text-xs">
              <span className="text-slate-300 font-medium">{t('dns.deviceOptionalLabel')}</span>
              <input
                type="text"
                list="openshield-device-hosts"
                placeholder={t('dns.devicePlaceholder')}
                value={deviceHostname}
                onChange={(e) => setDeviceHostname(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-100 font-mono text-xs placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              />
              <datalist id="openshield-device-hosts">
                {state.devices.map((dev) => (
                  <option key={dev.id} value={dev.hostname} />
                ))}
              </datalist>
            </label>
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-1">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={busyKey === 'dns-add'}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {t('dns.saveDomain')}
            </button>
          </div>
        </form>
      )}

      {/* DNS Summary Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('dns.kpiQueriesTitle')}</span>
            <Eye className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {totalQueries.toLocaleString(locale)}
          </div>
          <p className="mt-1 text-xs text-slate-400">{t('dns.kpiQueriesSub')}</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('dns.kpiBlocksTitle')}</span>
            <GlobeLock className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {totalBlocked.toLocaleString(locale)} ({blockRate}%)
          </div>
          <p className="mt-1 text-xs text-slate-400">{t('dns.kpiBlocksSub')}</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t('dns.kpiSuspiciousTitle')}</span>
            <ShieldCheck className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-xl font-semibold text-slate-50 tabular-nums">
            {state.dnsInsights.filter((d) => d.classification === 'suspicious').length}
          </div>
          <p className="mt-1 text-xs text-slate-400">{t('dns.kpiSuspiciousSub')}</p>
        </div>
      </div>

      {/* Domains Table */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="m-4 rounded-lg border border-slate-800 bg-[#0B1120]/40 max-h-[540px] overflow-auto">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 z-10 bg-[#0B1120] shadow-[0_1px_0_0_rgb(30,41,59)]">
              <tr className="text-xs font-medium text-slate-400">
                <th className="py-3 px-4">{t('dns.colDomainCat')}</th>
                <th className="py-3 px-4">{t('dns.colMainDevice')}</th>
                <th className="py-3 px-4 text-right">{t('dns.colQueries')}</th>
                <th className="py-3 px-4 text-right">{t('dns.colBlocked')}</th>
                <th className="py-3 px-4">{t('dns.colListStatus')}</th>
                <th className="py-3 px-4 text-right">{t('dns.colResolverAction')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-xs">
              {filteredInsights.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center space-y-3">
                    <div className="text-slate-300 font-medium">{t('dns.emptyTable')}</div>
                    <p className="text-slate-400 text-xs max-w-md mx-auto">
                      {t('dns.emptyTableHint')}
                    </p>
                    <button
                      type="button"
                      onClick={() => setShowAddForm(true)}
                      className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>{t('dns.addFirstDomain')}</span>
                    </button>
                  </td>
                </tr>
              ) : (
                dnsPagination.pagedItems.map((item) => {
                  const isBusy = busyKey === `dns-${item.id}`;
                  return (
                    <tr
                      key={item.id}
                      className="h-[48px] hover:bg-slate-900/40 transition-colors"
                    >
                      <td className="px-4 py-2.5">
                        <div className="font-mono text-slate-100">{item.domain}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          {t(`dns.categories.${item.category}`, { defaultValue: item.category })}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-300">
                        {item.deviceHostname}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-300 tabular-nums">
                        {item.queriesCount.toLocaleString(locale)}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-300 tabular-nums">
                        {item.blockedCount.toLocaleString(locale)}
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={
                            item.listStatus === 'blocked'
                              ? 'text-red-400 font-medium'
                              : item.listStatus === 'allowed'
                                ? 'text-emerald-400 font-medium'
                                : 'text-amber-400 font-medium'
                          }
                        >
                          {item.listStatus === 'blocked'
                            ? t('common.blocked')
                            : item.listStatus === 'allowed'
                              ? t('common.allowed')
                              : t('common.monitored')}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            disabled={isBusy || item.listStatus === 'blocked'}
                            onClick={() => onUpdateDnsList(item.id, 'blocked')}
                            className="px-2.5 py-1 rounded border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {t('dns.actionBlock')}
                          </button>
                          <button
                            type="button"
                            disabled={isBusy || item.listStatus === 'allowed'}
                            onClick={() => onUpdateDnsList(item.id, 'allowed')}
                            className="px-2.5 py-1 rounded border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {t('dns.actionAllow')}
                          </button>
                          <button
                            type="button"
                            disabled={isBusy || item.listStatus === 'monitored'}
                            onClick={() => onUpdateDnsList(item.id, 'monitored')}
                            className="px-2.5 py-1 rounded border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {t('dns.actionMonitor')}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <PaginationControls
          page={dnsPagination.page}
          pageSize={dnsPagination.pageSize}
          totalItems={dnsPagination.totalItems}
          totalPages={dnsPagination.totalPages}
          onPageChange={dnsPagination.setPage}
          onPageSizeChange={dnsPagination.setPageSize}
        />
      </section>
    </div>
  );
}
