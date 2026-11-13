import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CalendarClock,
  CheckCircle2,
  Database,
  Download,
  Filter,
  FlaskConical,
  OctagonAlert,
  RefreshCw,
  RotateCcw,
  ScrollText,
  Search,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
} from 'lucide-react';
import { api } from '../lib/api';
import type { AuditEntry, WorkspaceState } from '../types/openshield';

type AuditCategory = 'all' | 'propose_action' | 'kill_switch' | 'config' | 'state_change';
type TimePreset = 'all' | '1h' | '24h' | '7d' | 'custom';
type OutcomeFilter = 'all' | 'success' | 'simulated' | 'denied';

interface AuditLogsViewProps {
  state: WorkspaceState;
  searchQuery?: string;
}

const CATEGORY_OPTIONS: { id: AuditCategory; label: string }[] = [
  { id: 'all', label: 'Todos' },
  { id: 'propose_action', label: 'Propose Action / Políticas' },
  { id: 'kill_switch', label: 'Kill Switch' },
  { id: 'config', label: 'Configurações' },
  { id: 'state_change', label: 'Mudanças de Estado' },
];

const EVENT_TYPE_LABELS: Record<string, string> = {
  'action.proposed': 'Ação Proposta (Propose Action)',
  'action.approved': 'Ação L3 Aprovada',
  'action.executed': 'Ação Executada',
  'action.verified': 'Ação Verificada',
  'action.expired': 'TTL da Ação Expirado',
  'action.rolled_back': 'Rollback de Ação',
  'kill_switch.triggered': 'Kill Switch Acionado',
  'kill_switch.reset': 'Kill Switch Liberado',
  'context.updated': 'Estado / Contexto Atualizado',
  'gateway.connected': 'Gateway Conectado',
  'event.ingested': 'Evento Ingerido',
  'ai.investigated': 'Investigação de IA Executada',
  'authorization.denied': 'Autorização RBAC Negada',
  'integration.registered': 'Integração Registrada',
  'integration.removed': 'Integração Removida',
  'integration.synced': 'Integração Sincronizada',
  'credentials.updated': 'Credenciais Atualizadas',
  'device.added': 'Dispositivo Adicionado',
  'device.updated': 'Dispositivo Atualizado',
  'device.removed': 'Dispositivo Removido',
  'dns.added': 'Domínio DNS Adicionado',
  'dns.list_updated': 'Lista DNS Atualizada',
  'site.added': 'Site Adicionado',
  'site.removed': 'Site Removido',
  'workspace.demo_loaded': 'Cenário Demo Carregado',
  'workspace.reset': 'Workspace Zerado',
  'workspace.restored': 'Backup Restaurado',
};

const KNOWN_EVENT_TYPES = Object.keys(EVENT_TYPE_LABELS);

function formatTimestampPtBr(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Intl.DateTimeFormat('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(ms));
}

function getCategoryIcon(eventType: string) {
  if (eventType.startsWith('kill_switch.')) {
    return <OctagonAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />;
  }
  if (eventType.startsWith('action.')) {
    return <ShieldCheck className="w-3.5 h-3.5 text-blue-400 shrink-0" />;
  }
  if (
    eventType.startsWith('integration.') ||
    eventType.startsWith('credentials.') ||
    eventType.startsWith('device.') ||
    eventType.startsWith('dns.') ||
    eventType.startsWith('site.') ||
    eventType.startsWith('workspace.')
  ) {
    return <SlidersHorizontal className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
  }
  return <Activity className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
}

function renderOutcomeIndicator(outcome: AuditEntry['outcome']) {
  if (outcome === 'success') {
    return (
      <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
        <span>Sucesso</span>
      </span>
    );
  }
  if (outcome === 'simulated') {
    return (
      <span className="inline-flex items-center gap-1.5 text-amber-300 font-medium whitespace-nowrap">
        <FlaskConical className="w-3.5 h-3.5 shrink-0" />
        <span>Simulado</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-red-400 font-medium whitespace-nowrap">
      <ShieldX className="w-3.5 h-3.5 shrink-0" />
      <span>Negado</span>
    </span>
  );
}

function escapeCsvField(value: string): string {
  const safe = value.replace(/"/g, '""');
  return `"${safe}"`;
}

export function AuditLogsView({ state, searchQuery = '' }: AuditLogsViewProps) {
  const [category, setCategory] = useState<AuditCategory>('all');
  const [eventType, setEventType] = useState<string>('all');
  const [timePreset, setTimePreset] = useState<TimePreset>('all');
  const [fromLocal, setFromLocal] = useState<string>('');
  const [toLocal, setToLocal] = useState<string>('');
  const [outcome, setOutcome] = useState<OutcomeFilter>('all');
  const [localSearch, setLocalSearch] = useState<string>('');
  const [limit, setLimit] = useState<number>(250);

  const [entries, setEntries] = useState<AuditEntry[]>(state.auditLog);
  const [totalMatched, setTotalMatched] = useState<number>(state.auditLog.length);
  const [availableEventTypes, setAvailableEventTypes] = useState<string[]>(KNOWN_EVENT_TYPES);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string>(new Date().toISOString());

  const effectiveSearch = useMemo(() => {
    const local = localSearch.trim();
    const global = searchQuery.trim();
    if (local) return local;
    return global;
  }, [localSearch, searchQuery]);

  const resolvedRange = useMemo(() => {
    const now = Date.now();
    if (timePreset === '1h') {
      return { from: new Date(now - 60 * 60 * 1000).toISOString(), to: undefined };
    }
    if (timePreset === '24h') {
      return { from: new Date(now - 24 * 60 * 60 * 1000).toISOString(), to: undefined };
    }
    if (timePreset === '7d') {
      return { from: new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString(), to: undefined };
    }
    if (timePreset === 'custom') {
      const fromMs = fromLocal ? Date.parse(fromLocal) : NaN;
      const toMs = toLocal ? Date.parse(toLocal) : NaN;
      return {
        from: Number.isFinite(fromMs) ? new Date(fromMs).toISOString() : undefined,
        to: Number.isFinite(toMs) ? new Date(toMs).toISOString() : undefined,
      };
    }
    return { from: undefined, to: undefined };
  }, [timePreset, fromLocal, toLocal]);

  const fetchAuditLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getAuditLog({
        limit,
        category,
        eventType,
        from: resolvedRange.from,
        to: resolvedRange.to,
        outcome,
        search: effectiveSearch,
      });
      setEntries(res.entries);
      setTotalMatched(res.totalMatched ?? res.entries.length);
      if (res.eventTypes && res.eventTypes.length > 0) {
        const merged = Array.from(new Set([...KNOWN_EVENT_TYPES, ...res.eventTypes])).sort();
        setAvailableEventTypes(merged);
      }
      setLastUpdatedAt(new Date().toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha ao consultar trilha de auditoria SQLite.');
    } finally {
      setLoading(false);
    }
  }, [limit, category, eventType, resolvedRange.from, resolvedRange.to, outcome, effectiveSearch]);

  const latestAuditId = state.auditLog[0]?.id ?? '';
  const stateAuditLength = state.auditLog.length;

  useEffect(() => {
    const timer = setTimeout(() => {
      void fetchAuditLogs();
    }, 120);
    return () => clearTimeout(timer);
  }, [fetchAuditLogs, latestAuditId, stateAuditLength]);

  const summaryCounts = useMemo(() => {
    let actions = 0;
    let killSwitch = 0;
    let denied = 0;
    for (const item of entries) {
      if (item.eventType.startsWith('action.')) actions += 1;
      if (item.eventType.startsWith('kill_switch.')) killSwitch += 1;
      if (item.outcome === 'denied') denied += 1;
    }
    return { actions, killSwitch, denied };
  }, [entries]);

  const hasActiveFilters =
    category !== 'all' ||
    eventType !== 'all' ||
    timePreset !== 'all' ||
    outcome !== 'all' ||
    localSearch.trim().length > 0;

  const handleResetFilters = () => {
    setCategory('all');
    setEventType('all');
    setTimePreset('all');
    setFromLocal('');
    setToLocal('');
    setOutcome('all');
    setLocalSearch('');
  };

  const handleExportJson = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      filters: {
        category,
        eventType,
        timePreset,
        from: resolvedRange.from ?? null,
        to: resolvedRange.to ?? null,
        outcome,
        search: effectiveSearch || null,
      },
      totalMatched,
      entries,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `openshield-audit-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  };

  const handleExportCsv = () => {
    const header = [
      'id',
      'timestamp',
      'eventType',
      'actor',
      'role',
      'targetId',
      'outcome',
      'profile',
      'detail',
    ].join(',');
    const lines = entries.map((e) =>
      [
        escapeCsvField(e.id),
        escapeCsvField(e.timestamp),
        escapeCsvField(e.eventType),
        escapeCsvField(e.actor),
        escapeCsvField(e.role),
        escapeCsvField(e.targetId),
        escapeCsvField(e.outcome),
        escapeCsvField(e.profile),
        escapeCsvField(e.detail),
      ].join(','),
    );
    const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `openshield-audit-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <ScrollText className="w-5 h-5 text-blue-400 shrink-0" />
            <h1 className="text-xl font-bold text-slate-100 font-display">Logs de Auditoria</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Histórico persistente em SQLite de todas as mudanças de estado, alterações de configuração,
            propostas de ação (<span className="font-mono text-slate-300">Propose Action</span>) e acionamentos
            do <span className="font-mono text-slate-300">Kill Switch</span>.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void fetchAuditLogs()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-[#131C31] text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Atualizar</span>
          </button>

          <button
            type="button"
            onClick={handleExportCsv}
            disabled={entries.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-700 bg-[#131C31] text-slate-200 hover:bg-slate-800 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exportar CSV</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            disabled={entries.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exportar JSON</span>
          </button>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Registros Encontrados</span>
            <Database className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 tabular-nums">
            {totalMatched}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
            Exibindo {entries.length} no filtro SQLite
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Propose Action & Políticas</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 tabular-nums">
            {summaryCounts.actions}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">
            Eventos <span className="font-mono">action.*</span> na amostra
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Eventos Kill Switch</span>
            <OctagonAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 tabular-nums">
            {summaryCounts.killSwitch}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">
            Paradas e liberações de emergência
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#131C31] p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Bloqueios / Negados</span>
            <ShieldX className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 tabular-nums">
            {summaryCounts.denied}
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">
            Recusas RBAC ou política
          </div>
        </div>
      </div>

      {/* Filter Panel */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Filter className="w-4 h-4 text-blue-400" />
            <span>Filtros Persistentes (SQLite)</span>
          </div>

          <div className="flex items-center gap-3 text-[11px] text-slate-400">
            <span className="font-mono tabular-nums">
              Sincronizado: {formatTimestampPtBr(lastUpdatedAt)}
            </span>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 cursor-pointer whitespace-nowrap"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Limpar filtros</span>
              </button>
            )}
          </div>
        </div>

        {/* Category Quick Tabs */}
        <div className="flex flex-wrap items-center gap-2">
          {CATEGORY_OPTIONS.map((opt) => {
            const active = category === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => setCategory(opt.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? 'border-blue-500 bg-blue-600/20 text-blue-200'
                    : 'border-slate-800 bg-[#0B1120] text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                {opt.label}
              </button>
            );
          })}
        </div>

        {/* Detailed Controls Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 text-xs">
          {/* Action Type Exact Select */}
          <label className="space-y-1">
            <span className="block text-[11px] text-slate-400">Tipo de Ação Exata</span>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
            >
              <option value="all">Todos os tipos de evento</option>
              {availableEventTypes.map((evt) => (
                <option key={evt} value={evt}>
                  {EVENT_TYPE_LABELS[evt] ? `${EVENT_TYPE_LABELS[evt]} (${evt})` : evt}
                </option>
              ))}
            </select>
          </label>

          {/* Timestamp Preset */}
          <label className="space-y-1">
            <span className="block text-[11px] text-slate-400">Janela de Timestamp</span>
            <select
              value={timePreset}
              onChange={(e) => setTimePreset(e.target.value as TimePreset)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
            >
              <option value="all">Todo o histórico persistido</option>
              <option value="1h">Última 1 hora</option>
              <option value="24h">Últimas 24 horas</option>
              <option value="7d">Últimos 7 dias</option>
              <option value="custom">Intervalo personalizado (De / Até)</option>
            </select>
          </label>

          {/* Outcome Select */}
          <label className="space-y-1">
            <span className="block text-[11px] text-slate-400">Resultado</span>
            <select
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as OutcomeFilter)}
              className="w-full px-3 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
            >
              <option value="all">Todos os resultados</option>
              <option value="success">Sucesso</option>
              <option value="simulated">Simulado (Dry-Run / Mock)</option>
              <option value="denied">Negado (RBAC / Proveniência)</option>
            </select>
          </label>

          {/* Limit & Search */}
          <div className="grid grid-cols-3 gap-2">
            <label className="col-span-2 space-y-1">
              <span className="block text-[11px] text-slate-400">Busca Textual</span>
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="search"
                  value={localSearch}
                  onChange={(e) => setLocalSearch(e.target.value)}
                  placeholder="Ator, alvo ou detalhe..."
                  className="w-full pl-8 pr-2.5 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 placeholder:text-slate-500 text-xs focus:outline-none focus:border-blue-500"
                />
              </div>
            </label>

            <label className="space-y-1">
              <span className="block text-[11px] text-slate-400">Limite</span>
              <select
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="w-full px-2 py-2 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs focus:outline-none focus:border-blue-500"
              >
                <option value={100}>100</option>
                <option value={250}>250</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
              </select>
            </label>
          </div>
        </div>

        {/* Custom Timestamp Range Inputs */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-end gap-4 text-xs">
          <div className="flex items-center gap-1.5 text-slate-400 pb-2">
            <CalendarClock className="w-3.5 h-3.5 text-blue-400" />
            <span>Filtro por Timestamp:</span>
          </div>

          <label className="space-y-1">
            <span className="block text-[11px] text-slate-400">De (Data/Hora Inicial)</span>
            <input
              type="datetime-local"
              value={fromLocal}
              onChange={(e) => {
                setFromLocal(e.target.value);
                setTimePreset('custom');
              }}
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs font-mono focus:outline-none focus:border-blue-500"
            />
          </label>

          <label className="space-y-1">
            <span className="block text-[11px] text-slate-400">Até (Data/Hora Final)</span>
            <input
              type="datetime-local"
              value={toLocal}
              onChange={(e) => {
                setToLocal(e.target.value);
                setTimePreset('custom');
              }}
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-[#0B1120] text-slate-100 text-xs font-mono focus:outline-none focus:border-blue-500"
            />
          </label>

          {searchQuery.trim() && !localSearch.trim() && (
            <div className="text-[11px] text-blue-300 pb-2">
              Filtro global do topo ativo: <span className="font-mono">"{searchQuery.trim()}"</span>
            </div>
          )}
        </div>
      </section>

      {/* Error State */}
      {error && (
        <div className="rounded-xl border border-red-900/70 bg-red-950/30 px-4 py-3 text-xs text-red-200 flex items-center justify-between gap-4">
          <span>{error}</span>
          <button
            type="button"
            onClick={() => void fetchAuditLogs()}
            className="px-3 py-1 rounded border border-red-700 text-red-100 hover:bg-red-900/50 cursor-pointer whitespace-nowrap"
          >
            Tentar novamente
          </button>
        </div>
      )}

      {/* Persistent Audit Table */}
      <section className="rounded-xl border border-slate-800 bg-[#131C31] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs font-semibold text-slate-200">
            Trilha Cronológica Imutável (SQLite · mais recentes primeiro)
          </div>
          <div className="text-[11px] text-slate-400 tabular-nums">
            {entries.length} de {totalMatched} registro(s) correspondente(s)
          </div>
        </div>

        {entries.length === 0 ? (
          <div className="p-10 text-center space-y-2">
            <ScrollText className="w-7 h-7 text-slate-600 mx-auto" />
            <div className="text-sm font-medium text-slate-300">
              Nenhum registro encontrado para os filtros aplicados
            </div>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Ajuste a janela de timestamp, altere a categoria ou execute ações como Propose Action,
              alterações de configuração ou Kill Switch para gerar novos registros persistentes.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0B1120]/70 text-[11px] uppercase tracking-wider text-slate-400">
                  <th className="py-3 px-4 font-semibold whitespace-nowrap">Timestamp</th>
                  <th className="py-3 px-4 font-semibold whitespace-nowrap">Tipo / Ação</th>
                  <th className="py-3 px-4 font-semibold whitespace-nowrap">Ator & Contexto</th>
                  <th className="py-3 px-4 font-semibold whitespace-nowrap">Alvo</th>
                  <th className="py-3 px-4 font-semibold whitespace-nowrap">Resultado</th>
                  <th className="py-3 px-4 font-semibold">Detalhes da Operação</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {entries.map((entry) => (
                  <tr
                    key={entry.id}
                    className="hover:bg-slate-900/50 transition-colors align-top"
                  >
                    <td className="py-3 px-4 whitespace-nowrap font-mono tabular-nums text-slate-300">
                      <div>{formatTimestampPtBr(entry.timestamp)}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">{entry.id}</div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 font-medium text-slate-100 whitespace-nowrap">
                        {getCategoryIcon(entry.eventType)}
                        <span>{EVENT_TYPE_LABELS[entry.eventType] ?? entry.eventType}</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 mt-0.5 pl-5">
                        {entry.eventType}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="text-slate-200 font-medium">{entry.actor}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">
                        {entry.role} · {entry.profile === 'business' ? 'Escritório' : 'Residencial'}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap font-mono text-slate-300">
                      {entry.targetId}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      {renderOutcomeIndicator(entry.outcome)}
                    </td>

                    <td className="py-3 px-4 text-slate-300 leading-relaxed min-w-[260px]">
                      {entry.detail}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
