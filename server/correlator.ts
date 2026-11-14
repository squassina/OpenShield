import crypto from 'node:crypto';
import type {
  AiSensitivityConfig,
  Incident,
  NetworkDevice,
  OpenShieldEventV1,
} from '../src/types/openshield.ts';
import { buildSanitizedContext } from './geminiSanitizer.ts';

function normalizeIp(ip: string): string {
  return ip.trim().replace(/^::ffff:/i, '');
}

export function correlateEventIntoIncidents(
  event: OpenShieldEventV1,
  incidents: Incident[],
  devices: NetworkDevice[],
  activeSiteId: string,
  aiSensitivity?: AiSensitivityConfig,
): { updatedIncident: Incident | null; created: boolean } {
  const allowLowSeverity =
    event.eventType === 'threat.ioc' ||
    event.eventType === 'router.access_attempt' ||
    Boolean(aiSensitivity?.flagLowSeverityEvents);

  if (event.severity === 'info' || (event.severity === 'low' && !allowLowSeverity)) {
    return { updatedIncident: null, created: false };
  }

  const baseScore =
    event.severity === 'critical'
      ? 90
      : event.severity === 'high'
        ? 78
        : event.severity === 'medium'
          ? 52
          : 35;

  const minRiskThreshold = aiSensitivity?.minRiskScoreAlert ?? 50;
  if (baseScore < minRiskThreshold && !(event.severity === 'low' && allowLowSeverity)) {
    return { updatedIncident: null, created: false };
  }

  const rawSrcIp =
    typeof event.payload.srcIp === 'string'
      ? normalizeIp(event.payload.srcIp)
      : typeof event.payload.clientIp === 'string'
        ? normalizeIp(event.payload.clientIp)
        : '';

  const matchedDevice =
    devices.find((d) => d.id === event.deviceId) ??
    (rawSrcIp
      ? devices.find((d) => normalizeIp(d.ip) === rawSrcIp)
      : undefined);

  const isRouterAccess = event.eventType === 'router.access_attempt';
  const deviceId =
    matchedDevice?.id ??
    event.deviceId ??
    (isRouterAccess && rawSrcIp ? `src-${rawSrcIp}` : 'dev-lan-unknown');
  const deviceHostname =
    matchedDevice?.hostname ??
    (isRouterAccess && rawSrcIp ? rawSrcIp : 'dispositivo-lan');

  // Look for an existing open/investigating incident on the same device or attacker IP
  const existing = incidents.find(
    (inc) =>
      (inc.status === 'open' || inc.status === 'investigating') &&
      (inc.deviceId === deviceId ||
        (rawSrcIp && (inc.title.includes(rawSrcIp) || inc.riskFactors.some((r) => r.includes(rawSrcIp))))),
  );

  if (existing) {
    if (!existing.eventIds.includes(event.eventId)) {
      existing.eventIds.push(event.eventId);
      existing.timeline.push({
        timestamp: event.occurredAt,
        sourceIntegrationId: event.sourceIntegrationId,
        eventId: event.eventId,
        description: event.summary,
        severity: event.severity,
      });
      const boost = event.severity === 'critical' ? 20 : event.severity === 'high' ? 12 : 6;
      existing.riskScore = Math.min(99, existing.riskScore + boost);
      if (event.dataSource === 'live') {
        existing.dataSource = 'live';
      }
      const factor = `Sinal correlacionado de ${event.sourceIntegrationId}: ${event.eventType}`;
      if (!existing.riskFactors.includes(factor)) {
        existing.riskFactors.push(factor);
      }
    }
    return { updatedIncident: existing, created: false };
  }

  const isDns = event.eventType === 'dns.query';
  const newIncident: Incident = {
    id: `inc-${crypto.randomUUID().slice(0, 8)}`,
    title: isRouterAccess
      ? `Tentativas de acesso não autorizado ao roteador (${rawSrcIp || deviceHostname})`
      : isDns
        ? `Anomalia DNS detectada em ${deviceHostname}`
        : `Alerta de segurança correlacionado em ${deviceHostname}`,
    summary: event.summary,
    severity: event.severity,
    status: 'open',
    riskScore: baseScore,
    riskFactors: [
      `Origem: ${event.sourceIntegrationId} (${event.eventType})`,
      `Severidade normalizada: ${event.severity}`,
      `Sensibilidade IA: ${aiSensitivity?.preset ?? 'balanceado'} (limiar >= ${minRiskThreshold})`,
      ...(rawSrcIp ? [`IP origem: ${rawSrcIp}`] : []),
    ],
    deviceId,
    deviceHostname,
    siteId: matchedDevice?.siteId ?? activeSiteId,
    dataSource: event.dataSource ?? 'mock',
    eventIds: [event.eventId],
    timeline: [
      {
        timestamp: event.occurredAt,
        sourceIntegrationId: event.sourceIntegrationId,
        eventId: event.eventId,
        description: event.summary,
        severity: event.severity,
      },
    ],
    recommendedPolicyId: isDns ? 'pol-dns-tracker' : 'pol-iot-quarantine',
    recommendedAction: isRouterAccess
      ? `Bloquear IP ${rawSrcIp || deviceHostname} temporariamente no firewall do gateway (TTL 15 min)`
      : isDns
        ? 'Avaliar bloqueio do domínio suspeito via adaptador DNS (TTL 30 min)'
        : 'Avaliar contenção temporária do destino externo no gateway (TTL 15 min)',
    investigation: {
      provider: 'local-ollama-mock',
      modelVersion: 'correlator-deterministico-v1',
      promptTemplateVersion: 'openshield.local.v1.4',
      generatedAt: new Date().toISOString(),
      confidence: baseScore >= 75 ? 'alta' : 'média',
      observedFacts: [event.summary],
      inferredHypotheses: [
        'Incidente gerado automaticamente pelo motor determinístico de correlação.',
      ],
      recommendedSteps: [
        'Executar investigação por IA local-first ou inspecionar envelope openshield.event.v1.',
      ],
      sanitizedPayloadPreview: buildSanitizedContext(
        {
          id: 'preview',
          title: event.summary,
          summary: event.summary,
          severity: event.severity,
          status: 'open',
          riskScore: baseScore,
          riskFactors: [],
          deviceId,
          deviceHostname,
          siteId: activeSiteId,
          eventIds: [event.eventId],
          timeline: [],
          recommendedPolicyId: 'pol-iot-quarantine',
          recommendedAction: '',
          investigation: {
            provider: 'local-ollama-mock',
            modelVersion: '',
            promptTemplateVersion: '',
            generatedAt: '',
            confidence: 'média',
            observedFacts: [],
            inferredHypotheses: [],
            recommendedSteps: [],
            promptInjectionGuardNote: '',
          },
        },
        [event],
      ),
      promptInjectionGuardNote:
        'Gerado pelo correlacionador determinístico; strings externas não alteram políticas.',
    },
  };

  incidents.unshift(newIncident);
  return { updatedIncident: newIncident, created: true };
}
