import { useEffect, useState } from 'react';
import { Cloud, Cpu, Lock, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { Incident, WorkspaceState } from '../types/openshield';

interface IncidentsAiViewProps {
  state: WorkspaceState;
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onInvestigate: (incidentId: string, mode: 'local' | 'cloud_gemini') => Promise<void>;
  onToggleCloudOptIn: (enabled: boolean) => Promise<void>;
  onProposeAction: (incidentId: string, policyId: string) => Promise<void>;
  onUpdateStatus: (incidentId: string, status: Incident['status']) => Promise<void>;
  busyKey: string | null;
}

export function IncidentsAiView({
  state,
  selectedIncidentId,
  onSelectIncident,
  onInvestigate,
  onToggleCloudOptIn,
  onProposeAction,
  onUpdateStatus,
  busyKey,
}: IncidentsAiViewProps) {
  const activeIncident =
    state.incidents.find((i) => i.id === selectedIncidentId) ?? state.incidents[0] ?? null;

  const [ttlNote, setTtlNote] = useState('900s');

  useEffect(() => {
    if (activeIncident) {
      const pol = state.policies.find((p) => p.id === activeIncident.recommendedPolicyId);
      if (pol) setTtlNote(`${pol.defaultTtlSeconds}s`);
    }
  }, [activeIncident, state.policies]);

  if (!activeIncident) {
    return (
      <div className="rounded-xl border border-slate-800 bg-[#131C31] p-10 text-center text-sm text-slate-400">
        Nenhum incidente correlacionado no momento.
      </div>
    );
  }

  const relatedEvents = state.events.filter((e) => activeIncident.eventIds.includes(e.eventId));
  const recommendedPolicy = state.policies.find((p) => p.id === activeIncident.recommendedPolicyId);
  const inv = activeIncident.investigation;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-50 text-balance">
          Incidentes e Investigação por IA Híbrida
        </h1>
        <p className="mt-1 text-sm text-slate-400 max-w-2xl">
          Correlação baseada em evidências com IA local-first por padrão e segunda opinião opcional em nuvem após sanitização estrita.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left Queue (4 cols) */}
        <section className="xl:col-span-4 rounded-xl border border-slate-800 bg-[#131C31] divide-y divide-slate-800">
          <div className="px-4 py-3.5 text-xs font-semibold text-slate-300">
            Fila de Incidentes ({state.incidents.length})
          </div>
          {state.incidents.map((inc) => {
            const isSelected = inc.id === activeIncident.id;
            return (
              <button
                key={inc.id}
                type="button"
                onClick={() => onSelectIncident(inc.id)}
                className={`w-full text-left p-4 transition-colors cursor-pointer ${
                  isSelected ? 'bg-slate-800/70' : 'hover:bg-slate-900/40'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-xs tabular-nums">
                  <span
                    className={
                      inc.severity === 'high' || inc.severity === 'critical'
                        ? 'text-red-400 font-medium'
                        : 'text-amber-400 font-medium'
                    }
                  >
                    {inc.severity === 'high' ? 'Risco Alto' : 'Risco Médio'} · {inc.riskScore}/100
                  </span>
                  <span className="text-slate-400 font-mono">{inc.deviceHostname}</span>
                </div>
                <div className="mt-1.5 text-sm font-medium text-slate-100 leading-snug">
                  {inc.title}
                </div>
                <div className="mt-1.5 text-xs text-slate-400">
                  <span>
                    Estado:{' '}
                    {inc.status === 'contained'
                      ? 'Contido (TTL)'
                      : inc.status === 'false_positive'
                        ? 'Falso Positivo'
                        : inc.status === 'resolved'
                          ? 'Resolvido'
                          : inc.status === 'investigating'
                            ? 'Em Investigação'
                            : 'Aberto'}
                  </span>
                  <span className="mx-1.5 text-slate-600">·</span>
                  <span className={inc.dataSource === 'live' ? 'text-blue-400' : 'text-slate-400'}>
                    {inc.dataSource === 'live' ? 'Origem: Real' : 'Origem: Simulado'}
                  </span>
                </div>
              </button>
            );
          })}
        </section>

        {/* Right Investigation & Policy Trigger (8 cols) */}
        <section className="xl:col-span-8 space-y-6">
          {/* Incident Header + Evidence Timeline */}
          <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                  <span>{activeIncident.id}</span>
                  <span>·</span>
                  <span>{activeIncident.deviceHostname}</span>
                  <span>·</span>
                  <span>Score {activeIncident.riskScore}/100</span>
                  <span>·</span>
                  <span className={activeIncident.dataSource === 'live' ? 'text-blue-400' : ''}>
                    {activeIncident.dataSource === 'live' ? 'Real' : 'Simulado'}
                  </span>
                </div>
                <h2 className="text-lg font-semibold text-slate-100 mt-1">
                  {activeIncident.title}
                </h2>
                <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                  {activeIncident.summary}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onUpdateStatus(activeIncident.id, 'false_positive')}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 whitespace-nowrap cursor-pointer"
                >
                  Marcar Falso Positivo
                </button>
              </div>
            </div>

            {/* Timeline & Provenance */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-100">
                Linha do Tempo de Evidências (Proveniência Preservada)
              </h3>
              <div className="divide-y divide-slate-800/80 border border-slate-800 rounded-lg bg-slate-950/50">
                {activeIncident.timeline.map((step) => {
                  const fullEvent = relatedEvents.find((e) => e.eventId === step.eventId);
                  return (
                    <div key={step.eventId} className="p-3.5 text-xs space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-slate-400 font-mono tabular-nums">
                        <span>
                          {new Date(step.timestamp).toLocaleTimeString('pt-BR')} · fonte:{' '}
                          <strong className="text-slate-200">{step.sourceIntegrationId}</strong>
                        </span>
                        <span>{step.eventId}</span>
                      </div>
                      <p className="text-slate-200">{step.description}</p>
                      {fullEvent && (
                        <details className="text-slate-400">
                          <summary className="cursor-pointer text-blue-400 hover:text-blue-300 select-none">
                            Inspecionar envelope openshield.event.v1
                          </summary>
                          <pre className="mt-2 p-3 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                            {JSON.stringify(fullEvent, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Hybrid AI Investigation Panel */}
          <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5 space-y-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                  {inv.provider === 'gemini-sanitized' ? (
                    <Cloud className="w-3.5 h-3.5 text-blue-400" />
                  ) : (
                    <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  )}
                  <span>{inv.modelVersion}</span>
                  <span>·</span>
                  <span>Confiança: {inv.confidence}</span>
                </div>
                <h3 className="text-base font-semibold text-slate-100 mt-1">
                  Análise e Explicação Fundamentada
                </h3>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={busyKey === `inv-local-${activeIncident.id}`}
                  onClick={() => onInvestigate(activeIncident.id, 'local')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 whitespace-nowrap cursor-pointer disabled:opacity-50"
                >
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Investigar Local-First</span>
                </button>

                <button
                  type="button"
                  disabled={busyKey === `inv-cloud-${activeIncident.id}`}
                  onClick={() => onInvestigate(activeIncident.id, 'cloud_gemini')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 whitespace-nowrap cursor-pointer disabled:opacity-50"
                >
                  <Cloud className="w-3.5 h-3.5" />
                  <span>
                    {busyKey === `inv-cloud-${activeIncident.id}`
                      ? 'Sanitizando e Consultando...'
                      : 'Segunda Opinião Nuvem'}
                  </span>
                </button>
              </div>
            </div>

            {/* Cloud Opt-in Privacy Gate */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-2.5 px-3.5 rounded-lg border border-slate-800 bg-slate-950/60 text-xs">
              <div className="flex items-center gap-2 text-slate-300">
                <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                <span>
                  Gateway de Privacidade: envio à nuvem fica desabilitado até opt-in explícito e remove IPs internos, MACs e segredos.
                </span>
              </div>
              <button
                type="button"
                onClick={() => onToggleCloudOptIn(!state.context.cloudAiOptIn)}
                className={`px-3 py-1.5 rounded-md font-medium whitespace-nowrap shrink-0 cursor-pointer ${
                  state.context.cloudAiOptIn
                    ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-700/50'
                    : 'bg-slate-800 text-slate-300 border border-slate-700'
                }`}
              >
                {state.context.cloudAiOptIn ? 'Nuvem Opt-In: Ativado' : 'Ativar Nuvem Opt-In'}
              </button>
            </div>

            {/* Distinct Facts vs Hypotheses vs Recommendations */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="space-y-2">
                <div className="font-semibold text-slate-200">1. Fatos Observados</div>
                <ul className="space-y-1.5 text-slate-300 list-disc pl-4">
                  {inv.observedFacts.map((fact, idx) => (
                    <li key={idx}>{fact}</li>
                  ))}
                </ul>
              </div>
              <div className="space-y-2">
                <div className="font-semibold text-slate-200">2. Hipóteses Inferidas</div>
                <ul className="space-y-1.5 text-slate-300 list-disc pl-4">
                  {inv.inferredHypotheses.map((hyp, idx) => (
                    <li key={idx}>{hyp}</li>
                  ))}
                </ul>
              </div>
              <div className="space-y-2">
                <div className="font-semibold text-slate-200">3. Recomendações</div>
                <ul className="space-y-1.5 text-slate-300 list-disc pl-4">
                  {inv.recommendedSteps.map((step, idx) => (
                    <li key={idx}>{step}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="text-xs text-slate-400 pt-1 space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                <span>{inv.promptInjectionGuardNote}</span>
              </div>
              {inv.sanitizedPayloadPreview && (
                <details>
                  <summary className="cursor-pointer text-blue-400 hover:text-blue-300 select-none">
                    Visualizar payload minimizado e sanitizado (auditoria de privacidade)
                  </summary>
                  <pre className="mt-2 p-3 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                    {inv.sanitizedPayloadPreview}
                  </pre>
                </details>
              )}
            </div>
          </div>

          {/* Deterministic Policy Action Proposal */}
          <div className="rounded-xl border border-slate-800 bg-[#131C31] p-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                <span>Motor de Políticas Determinístico · Teto atual: {state.context.globalAutonomy}</span>
              </div>
              <div className="text-sm font-semibold text-slate-100">
                {recommendedPolicy ? recommendedPolicy.name : 'Avaliar política de contenção'}
              </div>
              <p className="text-xs text-slate-400">
                IA apenas recomenda; a execução respeita a política e o teto {state.context.globalAutonomy} com TTL de {ttlNote}.
              </p>
            </div>

            <button
              type="button"
              disabled={!recommendedPolicy || busyKey === `propose-${activeIncident.id}`}
              onClick={() =>
                recommendedPolicy && onProposeAction(activeIncident.id, recommendedPolicy.id)
              }
              className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
            >
              {state.context.globalAutonomy === 'L0'
                ? 'Simular Resposta (Dry-Run L0)'
                : `Executar via Política (${state.context.globalAutonomy})`}
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
