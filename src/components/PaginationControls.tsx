import { useEffect, useMemo, useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { getIntlLocale } from '../i18n';

export type PageSizeOption = 10 | 20 | 50 | 100;

export const PAGE_SIZE_OPTIONS: readonly PageSizeOption[] = [10, 20, 50, 100];

export function usePagination<T>(
  items: readonly T[],
  defaultSize: PageSizeOption = 10,
  resetKey?: string | number,
) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSizeState] = useState<PageSizeOption>(defaultSize);

  useEffect(() => {
    setPage(1);
  }, [resetKey]);

  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);

  const pagedItems = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, safePage, pageSize]);

  const setPageSize = (nextSize: PageSizeOption) => {
    setPageSizeState(nextSize);
    setPage(1);
  };

  return {
    page: safePage,
    pageSize,
    totalPages,
    totalItems,
    pagedItems,
    setPage: (next: number) => setPage(Math.min(Math.max(1, next), totalPages)),
    setPageSize,
  };
}

interface PaginationControlsProps {
  page: number;
  pageSize: PageSizeOption;
  totalItems: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: PageSizeOption) => void;
  compact?: boolean;
}

export function PaginationControls({
  page,
  pageSize,
  totalItems,
  totalPages,
  onPageChange,
  onPageSizeChange,
  compact = false,
}: PaginationControlsProps) {
  const { t, i18n } = useTranslation();
  const locale = getIntlLocale(i18n.language);

  const from = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(totalItems, page * pageSize);

  return (
    <div
      className={`flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80 bg-[#0B1120]/50 text-xs text-slate-400 tabular-nums ${
        compact ? 'px-3.5 py-2.5' : 'px-5 py-3'
      }`}
    >
      <div className="flex flex-wrap items-center gap-3">
        <span>
          {totalItems === 0
            ? t('pagination.empty')
            : t('pagination.showing', {
                from: from.toLocaleString(locale),
                to: to.toLocaleString(locale),
                total: totalItems.toLocaleString(locale),
              })}
        </span>

        <div className="inline-flex items-center gap-1.5">
          <span className="text-[11px] text-slate-500">{t('pagination.rowsPerPage')}</span>
          <div className="inline-flex items-center p-0.5 rounded-md border border-slate-800 bg-slate-950">
            {PAGE_SIZE_OPTIONS.map((opt) => (
              <button
                key={opt}
                type="button"
                onClick={() => onPageSizeChange(opt)}
                className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                  pageSize === opt
                    ? 'bg-blue-600 text-white font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {opt}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <span className="text-[11px] font-mono text-slate-400 whitespace-nowrap">
          {t('pagination.pageOf', {
            page: page.toLocaleString(locale),
            totalPages: totalPages.toLocaleString(locale),
          })}
        </span>
        <div className="inline-flex items-center gap-1">
          <button
            type="button"
            disabled={page <= 1}
            aria-label={t('pagination.prevAria')}
            onClick={() => onPageChange(page - 1)}
            className="p-1.5 rounded-md border border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            disabled={page >= totalPages}
            aria-label={t('pagination.nextAria')}
            onClick={() => onPageChange(page + 1)}
            className="p-1.5 rounded-md border border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
