import crypto from 'node:crypto';
import type {
  ActionExecution,
  AiSensitivityConfig,
  AiUsageRecord,
  AuditEntry,
  AutonomyLevel,
  DnsInsight,
  EnvSecretStatus,
  EventSeverity,
  Incident,
  IntegrationAdapter,
  LatencySample,
  NetworkDevice,
  NotificationChannelType,
  NotificationDestination,
  NotificationDispatchRecord,
  NotificationSeverityThreshold,
  NotificationTriggerEvent,
  OpenShieldEventV1,
  OperatingContext,
  OperatingProfile,
  PeriodicSyncConfig,
  PolicyRule,
  ServiceProviderMode,
  SyncAdapterResult,
  WorkspaceState,
} from '../src/types/openshield.ts';
import {
  pushDnsRuleLive,
  syncAdguardLive,
  syncPiholeLive,
  syncTechnitiumLive,
  type ClientQueryStats,
} from './adapters/dnsAdapters.ts';
import { boundedFetchJson } from './adapters/httpClient.ts';
import { runLocalOllamaInvestigation } from './adapters/ollamaAdapter.ts';
import {
  mapOpenWrtNeighbors,
  parseIp4NeighText,
  parseOpenWrtCommandOutput,
  syncOpenWrtReadOnly,
  type DiscoveredDeviceHint,
} from './adapters/openwrtAdapter.ts';
import { correlateEventIntoIncidents } from './correlator.ts';
import { buildSanitizedContext, runSanitizedCloudInvestigation } from './geminiSanitizer.ts';
import { deliverNotification, type AlertDispatchPayload } from './notifier.ts';
import { SqlitePersistence } from './persistence.ts';

const SECRET_FIELD_PATTERN = /(password|passwd|secret|token|api_key|apikey|private_key|credential)/i;
const AUTONOMY_RANK: Record<AutonomyLevel, number> = { L0: 0, L1: 1, L2: 2, L3: 3 };
const DEFAULT_AI_SENSITIVITY: AiSensitivityConfig = {
  preset: 'balanceado',
  minRiskScoreAlert: 50,
  dnsBurstThresholdPerMin: 120,
  latencySpikeFactor: 2.5,
  flagLowSeverityEvents: false,
};

const DEFAULT_PERIODIC_SYNC: PeriodicSyncConfig = {
  enabled: false,
  intervalSeconds: 60,
};

function minutesAgoIso(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

export class OpenShieldStore {
  private persistence: SqlitePersistence;
  private state: WorkspaceState;
  private listeners: Set<() => void> = new Set();
  private periodicSyncInFlight = false;

  constructor(persistence?: SqlitePersistence) {
    this.persistence = persistence ?? new SqlitePersistence();
    const saved = this.persistence.loadSnapshot();
    if (saved) {
      this.state = saved;
      this.state.latencyHistory ??= [];
      this.state.notifications ??= [];
      this.state.notificationHistory ??= [];
      this.state.aiUsageHistory ??= [];
      this.state.context.aiSensitivity ??= { ...DEFAULT_AI_SENSITIVITY };
      this.state.context.periodicSync ??= { ...DEFAULT_PERIODIC_SYNC };
      if (this.state.context.periodicSync.enabled) {
        const intervalMs = Math.max(15, this.state.context.periodicSync.intervalSeconds || 60) * 1000;
        const nextMs = this.state.context.periodicSync.nextRunAt
          ? Date.parse(this.state.context.periodicSync.nextRunAt)
          : NaN;
        if (!Number.isFinite(nextMs) || nextMs <= Date.now()) {
          this.state.context.periodicSync.nextRunAt = new Date(Date.now() + intervalMs).toISOString();
        }
      }
      this.state.metrics.outboxPendingTotal = this.persistence.outboxCount();
      const recentAudit = this.persistence.loadRecentAudit(200);
      if (recentAudit.length > 0) {
        this.state.auditLog = recentAudit;
      }
    } else {
      this.state = this.createInitialState();
      for (const ev of this.state.events) {
        this.persistence.persistEvent(ev);
      }
      for (const entry of [...this.state.auditLog].reverse()) {
        this.persistence.appendAudit(entry);
      }
      this.persistence.saveSnapshot(this.state);
    }
  }

  private recordAggregatedLatencySample(nowIso = new Date().toISOString()): void {
    const measured = this.state.integrations
      .filter(
        (i) =>
          i.domain !== 'ai_runtime' &&
          i.status === 'connected' &&
          typeof i.lastLatencyMs === 'number' &&
          Number.isFinite(i.lastLatencyMs),
      )
      .map((i) => i.lastLatencyMs as number);

    if (measured.length === 0) {
      return;
    }

    const avgLatencyMs = Math.round(
      measured.reduce((sum, v) => sum + v, 0) / measured.length,
    );
    const sample: LatencySample = {
      timestamp: nowIso,
      avgLatencyMs,
      minLatencyMs: Math.min(...measured),
      maxLatencyMs: Math.max(...measured),
      measuredCount: measured.length,
    };

    const cutoffMs = Date.now() - 24 * 60 * 60 * 1000;
    const history = (this.state.latencyHistory ?? []).filter(
      (entry) => Date.parse(entry.timestamp) >= cutoffMs,
    );
    history.push(sample);
    if (history.length > 288) {
      history.splice(0, history.length - 288);
    }
    this.state.latencyHistory = history;
  }

  private recordAiUsage(entry: Omit<AiUsageRecord, 'id' | 'timestamp'>, timestamp?: string): void {
    this.state.aiUsageHistory ??= [];
    this.state.aiUsageHistory.unshift({
      id: `ai-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: timestamp ?? new Date().toISOString(),
      ...entry,
    });
    if (this.state.aiUsageHistory.length > 100) {
      this.state.aiUsageHistory.length = 100;
    }
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    this.persistence.saveSnapshot(this.state);
    for (const listener of this.listeners) {
      listener();
    }
  }

  private hasEnvFallback(adapter: IntegrationAdapter): { hasSecret: boolean; usernameHint?: string } {
    if (adapter.kind === 'openwrt-rpcd') {
      return {
        hasSecret: Boolean(process.env.OPENSHIELD_OPENWRT_PASSWORD),
        usernameHint: process.env.OPENSHIELD_OPENWRT_USERNAME || undefined,
      };
    }
    if (adapter.kind === 'pihole-v6') {
      return { hasSecret: Boolean(process.env.OPENSHIELD_PIHOLE_PASSWORD) };
    }
    if (adapter.kind === 'adguard-home') {
      return {
        hasSecret: Boolean(process.env.OPENSHIELD_ADGUARD_PASSWORD),
        usernameHint: process.env.OPENSHIELD_ADGUARD_USERNAME || undefined,
      };
    }
    return { hasSecret: false };
  }

  getState(): WorkspaceState {
    const cloned = structuredClone(this.state);
    cloned.integrations = cloned.integrations.map((adapter) => {
      const stored = this.persistence.getServiceCredential(adapter.id);
      const envFallback = this.hasEnvFallback(adapter);
      return {
        ...adapter,
        hasCredential: Boolean(stored?.secret) || envFallback.hasSecret,
        usernameHint: stored?.username || envFallback.usernameHint || adapter.usernameHint,
      };
    });
    cloned.notifications = (cloned.notifications ?? []).map((dest) => {
      const stored = this.persistence.getServiceCredential(`notif:${dest.id}`);
      return {
        ...dest,
        hasSecret: Boolean(stored?.secret),
        usernameHint: stored?.username || dest.usernameHint,
      };
    });
    return cloned;
  }

  getEnvStatus(): EnvSecretStatus[] {
    const check = (key: string, label: string, scope: string): EnvSecretStatus => {
      const val = process.env[key];
      const configured = Boolean(val && val.trim() !== '' && val !== 'MY_GEMINI_API_KEY');
      return { key, label, scope, configured };
    };

    return [
      check('OPENSHIELD_OPENWRT_URL', 'URL rpcd/ubus OpenWrt (Fallback)', 'Gateway OpenWrt'),
      check('OPENSHIELD_OPENWRT_USERNAME', 'Usuário RPC OpenWrt (Fallback)', 'Gateway OpenWrt'),
      check('OPENSHIELD_OPENWRT_PASSWORD', 'Senha RPC OpenWrt (Fallback)', 'Gateway OpenWrt'),
      check('OPENSHIELD_PIHOLE_PASSWORD', 'Token Pi-hole Global (Fallback)', 'Pi-hole DNS'),
      check('OPENSHIELD_OLLAMA_URL', 'Endpoint Runtime Ollama (Fallback)', 'IA Local-First'),
      check('GEMINI_API_KEY', 'Chave Gemini (Opcional Nuvem)', 'IA Segunda Opinião'),
    ];
  }

  queryAuditLog(filters: {
    eventType?: string;
    category?: string;
    from?: string;
    to?: string;
    outcome?: string;
    search?: string;
    limit?: number;
  }) {
    return this.persistence.queryAudit(filters);
  }

  recordHttpRequest(): void {
    this.state.metrics.httpRequestsTotal += 1;
  }

  private addAudit(entry: Omit<AuditEntry, 'id' | 'timestamp' | 'profile'>): void {
    const record: AuditEntry = {
      id: `aud-${crypto.randomUUID().slice(0, 8)}`,
      timestamp: new Date().toISOString(),
      profile: this.state.context.profile,
      ...entry,
    };
    this.persistence.appendAudit(record);
    this.state.auditLog.unshift(record);
    if (this.state.auditLog.length > 250) {
      this.state.auditLog.length = 250;
    }
  }

  private currentActor(): { actor: string; role: string } {
    if (this.state.context.profile === 'residential') {
      return { actor: 'lan-residencial-local', role: 'residencial-sem-auth' };
    }
    const roleMap = {
      admin: 'ana.silva@escritorio (Admin)',
      operator: 'carlos.netops@escritorio (Operador)',
      auditor: 'compliance.audit@escritorio (Auditor)',
    };
    return {
      actor: roleMap[this.state.context.simulatedRole],
      role: this.state.context.simulatedRole,
    };
  }

  assertCanMutate(required: 'operator' | 'admin' | 'policy_admin'): void {
    if (this.state.context.profile === 'residential') {
      return;
    }
    const role = this.state.context.simulatedRole;
    if (role === 'auditor') {
      throw new Error('Permissão negada (RBAC): o papel Auditor possui acesso somente leitura.');
    }
    if (required === 'policy_admin' && role !== 'admin') {
      throw new Error(
        'Permissão negada (RBAC): apenas o papel Administrador pode alterar políticas de autonomia ou aprovar ações L3.',
      );
    }
    if (required === 'admin' && role !== 'admin') {
      throw new Error('Permissão negada (RBAC): esta operação exige o papel Administrador.');
    }
  }

  tickTimers(): void {
    const now = Date.now();
    let changed = false;
    const expiredDnsToRevert: { execId: string; domain: string }[] = [];

    for (const exec of this.state.executions) {
      if ((exec.status === 'active' || exec.status === 'verified') && exec.expiresAt) {
        if (now >= Date.parse(exec.expiresAt)) {
          exec.status = 'expired';
          exec.verificationDetail = `TTL de ${exec.ttlSeconds}s expirado automaticamente; regra temporária removida do adaptador.`;
          exec.rollbackAvailable = false;
          if (exec.actionType === 'dns_block_domain' && exec.targetDomain) {
            expiredDnsToRevert.push({ execId: exec.id, domain: exec.targetDomain });
          }
          this.addAudit({
            eventType: 'action.expired',
            actor: 'openshield-policy-timer',
            role: 'system',
            targetId: exec.id,
            outcome: 'success',
            detail: `Contenção "${exec.targetLabel}" expirada por TTL (${exec.ttlSeconds}s) e revertida com segurança.`,
          });
          const inc = this.state.incidents.find((i) => i.id === exec.incidentId);
          if (inc && inc.status === 'contained') {
            inc.status = 'resolved';
          }
          changed = true;
        }
      }
    }

    if (changed) {
      this.notify();
    }

    for (const item of expiredDnsToRevert) {
      void this.revertLiveDnsOnExpiry(item.execId, item.domain);
    }

    const periodic = this.state.context.periodicSync;
    if (
      periodic?.enabled &&
      !this.periodicSyncInFlight &&
      this.state.context.nodeAvailable &&
      this.state.integrations.length > 0
    ) {
      const nextMs = periodic.nextRunAt ? Date.parse(periodic.nextRunAt) : 0;
      if (!Number.isFinite(nextMs) || now >= nextMs) {
        void this.runPeriodicSyncTick();
      }
    }
  }

  private async runPeriodicSyncTick(): Promise<void> {
    if (this.periodicSyncInFlight) return;
    const periodic = this.state.context.periodicSync;
    if (!periodic?.enabled) return;

    this.periodicSyncInFlight = true;
    const intervalSec = Math.max(15, Math.min(3600, Math.round(periodic.intervalSeconds || 60)));
    try {
      const out = await this.syncAllIntegrations({ bypassRbac: true, trigger: 'timer' });
      const nowIso = new Date().toISOString();
      const okCount = out.results.length;
      const errCount = out.errors.length;
      this.state.context.periodicSync = {
        ...this.state.context.periodicSync,
        enabled: Boolean(this.state.context.periodicSync?.enabled),
        intervalSeconds: intervalSec,
        lastRunAt: nowIso,
        nextRunAt: this.state.context.periodicSync?.enabled
          ? new Date(Date.now() + intervalSec * 1000).toISOString()
          : undefined,
        lastRunStatus:
          errCount === 0 ? 'success' : okCount > 0 ? 'partial' : 'failed',
        lastRunSummary: `${okCount} OK · ${errCount} fail`,
      };
      this.notify();
    } catch {
      const nowIso = new Date().toISOString();
      this.state.context.periodicSync = {
        ...this.state.context.periodicSync,
        enabled: Boolean(this.state.context.periodicSync?.enabled),
        intervalSeconds: intervalSec,
        lastRunAt: nowIso,
        nextRunAt: this.state.context.periodicSync?.enabled
          ? new Date(Date.now() + intervalSec * 1000).toISOString()
          : undefined,
        lastRunStatus: 'failed',
        lastRunSummary: '0 OK · 1 fail',
      };
      this.notify();
    } finally {
      this.periodicSyncInFlight = false;
    }
  }

  private async revertLiveDnsOnExpiry(execId: string, domain: string): Promise<void> {
    const { notes } = await this.applyDnsRuleToLiveAdapters(domain, 'monitored');
    if (notes.length > 0) {
      const exec = this.state.executions.find((e) => e.id === execId);
      if (exec) {
        exec.verificationDetail = `${exec.verificationDetail} (${notes.join(' · ')})`;
        this.notify();
      }
    }
  }

  updateContext(patch: Partial<OperatingContext>): WorkspaceState {
    if (patch.simulatedRole && patch.simulatedRole !== this.state.context.simulatedRole) {
      this.state.context.simulatedRole = patch.simulatedRole;
    }

    if (patch.profile && patch.profile !== this.state.context.profile) {
      this.state.context.profile = patch.profile;
      this.state.context.activeSiteId =
        patch.profile === 'residential' ? 'site-home' : 'site-office-sp';
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: this.state.context.activeSiteId,
        outcome: 'success',
        detail:
          patch.profile === 'residential'
            ? 'Perfil alternado para Residencial (acesso LAN confiável sem credenciais de API).'
            : 'Perfil alternado para Pequeno Escritório (RBAC simulado e multi-site ativados).',
      });
    }

    if (patch.activeSiteId) {
      this.state.context.activeSiteId = patch.activeSiteId;
    }

    if (typeof patch.cloudAiOptIn === 'boolean') {
      this.assertCanMutate('operator');
      this.state.context.cloudAiOptIn = patch.cloudAiOptIn;
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'ai-privacy-gateway',
        outcome: 'success',
        detail: patch.cloudAiOptIn
          ? 'Opt-in explícito de segunda opinião via IA em nuvem (sanitizada) habilitado.'
          : 'Segunda opinião via IA em nuvem desabilitada; operando exclusivamente em modo local-first.',
      });
    }

    if (patch.globalAutonomy) {
      this.assertCanMutate('policy_admin');
      if (this.state.context.killSwitchActive && patch.globalAutonomy !== 'L0') {
        throw new Error(
          'Kill Switch ativo: desative a parada de emergência antes de elevar o nível de autonomia.',
        );
      }
      this.state.context.globalAutonomy = patch.globalAutonomy;
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'autonomy-ceiling',
        outcome: 'success',
        detail: `Teto global de autonomia ajustado para ${patch.globalAutonomy}.`,
      });
    }

    if (patch.aiSensitivity) {
      this.assertCanMutate('operator');
      const raw = patch.aiSensitivity;
      const sanitized: AiSensitivityConfig = {
        preset:
          raw.preset === 'conservador' ||
          raw.preset === 'balanceado' ||
          raw.preset === 'agressivo' ||
          raw.preset === 'customizado'
            ? raw.preset
            : 'customizado',
        minRiskScoreAlert: Math.max(20, Math.min(95, Math.round(Number(raw.minRiskScoreAlert) || 50))),
        dnsBurstThresholdPerMin: Math.max(
          10,
          Math.min(1000, Math.round(Number(raw.dnsBurstThresholdPerMin) || 120)),
        ),
        latencySpikeFactor: Math.max(
          1.2,
          Math.min(10, Math.round((Number(raw.latencySpikeFactor) || 2.5) * 10) / 10),
        ),
        flagLowSeverityEvents: Boolean(raw.flagLowSeverityEvents),
      };
      this.state.context.aiSensitivity = sanitized;
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'ai-anomaly-sensitivity',
        outcome: 'success',
        detail: `Sensibilidade IA atualizada (${sanitized.preset}): score>=${sanitized.minRiskScoreAlert}, rajada DNS>=${sanitized.dnsBurstThresholdPerMin}/min, latência>=${sanitized.latencySpikeFactor}x, severidade baixa=${sanitized.flagLowSeverityEvents ? 'ativa' : 'inativa'}.`,
      });
    }

    if (patch.periodicSync) {
      this.assertCanMutate('operator');
      const raw = patch.periodicSync;
      const intervalSeconds = Math.max(
        15,
        Math.min(3600, Math.round(Number(raw.intervalSeconds) || 60)),
      );
      const enabled = Boolean(raw.enabled);
      const prev = this.state.context.periodicSync ?? { ...DEFAULT_PERIODIC_SYNC };
      this.state.context.periodicSync = {
        ...prev,
        enabled,
        intervalSeconds,
        nextRunAt: enabled
          ? new Date(Date.now() + intervalSeconds * 1000).toISOString()
          : undefined,
      };
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'periodic-sync-timer',
        outcome: 'success',
        detail: enabled
          ? `Sincronização periódica ativada a cada ${intervalSeconds}s.`
          : `Sincronização periódica pausada (intervalo configurado: ${intervalSeconds}s).`,
      });
    }

    this.notify();
    return this.getState();
  }

  toggleNodeOutage(nodeAvailable: boolean): WorkspaceState {
    this.assertCanMutate('operator');
    this.state.context.nodeAvailable = nodeAvailable;
    this.state.context.gatewayForwardingActive = true;

    const gateways = this.state.integrations.filter((i) => i.domain === 'gateway');
    const primaryTargetId = gateways[0]?.id ?? 'openshield-gateway';

    if (!nodeAvailable) {
      for (const gw of gateways) {
        gw.status = 'stale';
      }
      for (let idx = 0; idx < 3; idx += 1) {
        const queuedEv: OpenShieldEventV1 = {
          eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
          schemaVersion: 'openshield.event.v1',
          occurredAt: new Date().toISOString(),
          sourceIntegrationId: primaryTargetId,
          eventType: 'gateway.health',
          severity: 'info',
          dataSource: 'mock',
          summary:
            'Heartbeat persistido no spool SQLite local enquanto OpenShield Node está offline.',
          payload: {
            forwardingActive: true,
            bufferedDuringOutage: true,
            sequence: idx + 1,
          },
        };
        this.persistence.enqueueOutbox(queuedEv);
      }
      const pending = this.persistence.outboxCount();
      for (const gw of gateways) gw.outboxQueueCount = pending;
      this.state.metrics.outboxPendingTotal = pending;

      this.addAudit({
        eventType: 'gateway.connected',
        actor: 'gateway-connector-agent',
        role: 'connector',
        targetId: primaryTargetId,
        outcome: 'simulated',
        detail:
          'Simulação de indisponibilidade do Node iniciada. O gateway continua roteando pacotes e o conector grava eventos no spool SQLite.',
      });
    } else {
      const queuedList = this.persistence.listOutbox();
      let drainedCount = 0;
      for (const queued of queuedList) {
        if (this.persistence.persistEvent(queued)) {
          this.state.events.unshift(queued);
          this.state.metrics.eventsIngestedTotal += 1;
          drainedCount += 1;
        }
      }
      this.persistence.clearOutbox();
      if (this.state.events.length > 100) {
        this.state.events.length = 100;
      }
      for (const gw of gateways) {
        gw.status = 'connected';
        gw.lastHeartbeatAt = new Date().toISOString();
        gw.outboxQueueCount = 0;
      }
      this.state.metrics.outboxPendingTotal = 0;
      this.state.metrics.gatewayHeartbeatsTotal += 1;
      this.addAudit({
        eventType: 'gateway.connected',
        actor: 'gateway-connector-agent',
        role: 'connector',
        targetId: primaryTargetId,
        outcome: 'success',
        detail: `Node reconectado: ${drainedCount} evento(s) drenados do spool SQLite com verificação idempotente.`,
      });
    }

    this.notify();
    return this.getState();
  }

  updateIntegrationConfig(
    id: string,
    patch: {
      name?: string;
      liveEndpointUrl?: string;
      siteId?: string;
      mode?: ServiceProviderMode;
      modelName?: string;
      boardInfo?: IntegrationAdapter['boardInfo'];
      username?: string;
      secret?: string;
      clearSecret?: boolean;
    },
  ): WorkspaceState {
    this.assertCanMutate('operator');
    const adapter = this.state.integrations.find((item) => item.id === id);
    if (!adapter) {
      throw new Error(`Serviço "${id}" não encontrado.`);
    }

    if (patch.name !== undefined && patch.name.trim()) {
      adapter.name = patch.name.trim();
    }
    if (patch.liveEndpointUrl !== undefined) {
      adapter.liveEndpointUrl = patch.liveEndpointUrl.trim();
    }
    if (patch.siteId !== undefined && patch.siteId.trim()) {
      adapter.siteId = patch.siteId.trim();
    }
    if (patch.mode !== undefined) {
      if (patch.mode === 'live' && (!adapter.liveEndpointUrl || !/^https?:\/\//i.test(adapter.liveEndpointUrl))) {
        throw new Error('Preencha uma URL HTTP/HTTPS válida antes de salvar o serviço em modo API Real.');
      }
      adapter.mode = patch.mode;
    }
    if (patch.modelName !== undefined) {
      adapter.modelName = patch.modelName.trim() || undefined;
    }
    if (patch.boardInfo !== undefined) {
      adapter.boardInfo = patch.boardInfo;
    }

    if (patch.clearSecret) {
      this.persistence.deleteServiceCredential(adapter.id);
      adapter.usernameHint = undefined;
      this.addAudit({
        eventType: 'credentials.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: 'success',
        detail: `Credenciais removidas do cofre do servidor para "${adapter.name}".`,
      });
    } else if (patch.username !== undefined || (patch.secret !== undefined && patch.secret !== '')) {
      const existing = this.persistence.getServiceCredential(adapter.id);
      const nextUser = patch.username !== undefined ? patch.username.trim() : (existing?.username ?? '');
      const nextSecret = patch.secret !== undefined && patch.secret !== '' ? patch.secret : (existing?.secret ?? '');
      this.persistence.setServiceCredential(adapter.id, nextUser, nextSecret);
      this.addAudit({
        eventType: 'credentials.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: 'success',
        detail: `Configuração e credenciais atualizadas no cofre local do servidor para "${adapter.name}".`,
      });
    } else {
      this.addAudit({
        eventType: 'context.updated',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: 'success',
        detail: `Parâmetros atualizados para "${adapter.name}" (${adapter.liveEndpointUrl || 'sem URL'}).`,
      });
    }

    this.notify();
    return this.getState();
  }

  removeIntegration(id: string): WorkspaceState {
    this.assertCanMutate('operator');
    const idx = this.state.integrations.findIndex((i) => i.id === id);
    if (idx < 0) {
      throw new Error(`Serviço "${id}" não encontrado.`);
    }
    const [removed] = this.state.integrations.splice(idx, 1);
    this.persistence.deleteServiceCredential(id);
    this.addAudit({
      eventType: 'integration.removed',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Serviço "${removed.name}" (${id}) removido e credenciais apagadas.`,
    });
    this.notify();
    return this.getState();
  }

  async testAndSwitchIntegrationMode(
    id: string,
    mode: ServiceProviderMode,
    liveEndpointUrl?: string,
  ): Promise<{ state: WorkspaceState; diagnostic: string }> {
    this.assertCanMutate('operator');
    const adapter = this.state.integrations.find((item) => item.id === id);
    if (!adapter) {
      throw new Error(`Integração "${id}" não encontrada.`);
    }

    if (liveEndpointUrl !== undefined) {
      adapter.liveEndpointUrl = liveEndpointUrl.trim();
    }

    if (mode === 'mock') {
      adapter.mode = 'mock';
      adapter.status = this.state.context.nodeAvailable ? 'connected' : 'stale';
      adapter.lastHeartbeatAt = new Date().toISOString();
      adapter.lastLiveCheckMessage = 'Operando via simulador determinístico de contratos v1.';
      this.addAudit({
        eventType: 'integration.registered',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: 'success',
        detail: `Integração "${adapter.name}" alternada para modo Simulador Mock.`,
      });
      this.notify();
      return { state: this.getState(), diagnostic: adapter.lastLiveCheckMessage };
    }

    const url = adapter.liveEndpointUrl;
    if (!url || !/^https?:\/\//i.test(url)) {
      throw new Error('Configure uma URL HTTP/HTTPS válida na página Configurações antes de ativar API Real.');
    }

    const startedAt = Date.now();
    try {
      const res = await boundedFetchJson(url, { timeoutMs: adapter.timeoutMs || 5000 });
      const latencyMs = Math.max(1, Date.now() - startedAt);
      adapter.mode = 'live';
      adapter.status = res.ok ? 'connected' : 'unavailable';
      adapter.lastHeartbeatAt = new Date().toISOString();
      adapter.lastLatencyMs = res.ok ? latencyMs : undefined;
      adapter.lastLiveCheckMessage = res.ok
        ? `Conexão real verificada (HTTP ${res.status} · ${latencyMs} ms) dentro do timeout de 5s.`
        : `Endpoint respondeu HTTP ${res.status}; verifique rota/credenciais em Configurações.`;

      if (res.ok) {
        this.recordAggregatedLatencySample(adapter.lastHeartbeatAt);
      }

      this.addAudit({
        eventType: 'integration.registered',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: res.ok ? 'success' : 'denied',
        detail: `Integração "${adapter.name}" configurada para API Real (${url}): ${adapter.lastLiveCheckMessage}`,
      });
      this.notify();
      return { state: this.getState(), diagnostic: adapter.lastLiveCheckMessage };
    } catch (err) {
      const reason = err instanceof Error ? err.message : 'Falha de rede ao alcançar endpoint real.';
      adapter.mode = 'live';
      adapter.status = 'unavailable';
      adapter.lastLatencyMs = undefined;
      adapter.lastLiveCheckMessage = `${reason} (Mantido em modo API Real sem interromper o gateway.)`;
      this.addAudit({
        eventType: 'integration.registered',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: adapter.id,
        outcome: 'denied',
        detail: `Teste de conexão real para "${adapter.name}" falhou: ${reason}`,
      });
      this.notify();
      return { state: this.getState(), diagnostic: adapter.lastLiveCheckMessage };
    }
  }

  private upsertDiscoveredDevices(hints: DiscoveredDeviceHint[], siteId: string): number {
    let addedOrUpdated = 0;
    const nowIso = new Date().toISOString();

    for (const hint of hints) {
      const hintMacUp = hint.mac?.trim().toUpperCase();
      const validHintMac =
        hintMacUp && hintMacUp !== 'NÃO INFORMADO' && hintMacUp !== '00:00:00:00:00:00'
          ? hintMacUp
          : undefined;

      const existing = this.state.devices.find(
        (d) =>
          (hint.id && d.id === hint.id) ||
          (validHintMac && d.mac.toUpperCase() === validHintMac) ||
          d.ip === hint.ip,
      );

      if (existing) {
        existing.lastSeenAt = nowIso;
        if (validHintMac && (!existing.mac || existing.mac === 'Não informado')) {
          existing.mac = validHintMac;
        }
        if (hint.ip && validHintMac && existing.mac.toUpperCase() === validHintMac) {
          existing.ip = hint.ip;
        }
        if (
          hint.hostname &&
          hint.hostname !== '(sem-nome)' &&
          (!existing.hostname ||
            existing.hostname === '(sem-nome)' ||
            existing.hostname.startsWith('host-'))
        ) {
          existing.hostname = hint.hostname;
        }
        if (hint.interfaceName) {
          existing.interfaceName = hint.interfaceName;
        }
        if (hint.segment) {
          existing.segment = hint.segment;
        }
        if (
          hint.vendor &&
          (existing.vendor === 'Configurado manualmente' ||
            existing.vendor === 'Descoberto via Rede')
        ) {
          existing.vendor = hint.vendor;
        }
        addedOrUpdated += 1;
      } else {
        const cleanId =
          hint.id?.trim().toLowerCase().replace(/[^a-z0-9-_]/g, '-') ||
          `dev-${hint.hostname.toLowerCase().replace(/[^a-z0-9]/g, '-').slice(0, 18)}-${crypto.randomUUID().slice(0, 4)}`;
        this.state.devices.push({
          id: cleanId,
          hostname: hint.hostname,
          ip: hint.ip,
          mac: validHintMac || 'Não informado',
          vendor: hint.vendor || 'Descoberto via Rede',
          interfaceName: hint.interfaceName || 'br-lan',
          segment: hint.segment,
          siteId,
          riskScore: 8,
          status: 'nominal',
          lastSeenAt: nowIso,
          dnsQueries24h: 0,
          blockedQueries24h: 0,
          deviceType: hint.deviceType,
        });
        addedOrUpdated += 1;
      }
    }
    return addedOrUpdated;
  }

  private findDeviceForTelemetry(ref: {
    deviceId?: string;
    ip?: string;
    hostname?: string;
  }): NetworkDevice | undefined {
    const id = ref.deviceId?.trim();
    if (id && id !== 'lan-client' && id !== 'manual') {
      const byId = this.state.devices.find((d) => d.id === id);
      if (byId) return byId;
    }

    const rawHost = ref.hostname?.trim();
    const ipCandidate =
      ref.ip?.trim() ||
      (rawHost && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(rawHost) ? rawHost : '');
    if (ipCandidate) {
      const byIp = this.state.devices.find((d) => d.ip === ipCandidate);
      if (byIp) return byIp;
    }

    if (
      rawHost &&
      rawHost !== '(sem-nome)' &&
      rawHost !== '(unnamed)' &&
      rawHost !== 'cliente-lan' &&
      rawHost !== 'lan-client'
    ) {
      const hostLower = rawHost.toLowerCase();
      const byExactHost = this.state.devices.find(
        (d) => d.hostname.toLowerCase() === hostLower,
      );
      if (byExactHost) return byExactHost;

      const baseHost = hostLower.split('.')[0];
      if (baseHost && baseHost.length >= 2) {
        const byBaseHost = this.state.devices.find((d) => {
          const dLower = d.hostname.toLowerCase();
          if (dLower === '(sem-nome)' || dLower === '(unnamed)') return false;
          return dLower.split('.')[0] === baseHost;
        });
        if (byBaseHost) return byBaseHost;
      }
    }

    return undefined;
  }

  private refreshDeviceFlowCounters(
    matchedIds: Set<string>,
    clientStats?: ClientQueryStats[],
  ): void {
    const statsByDeviceId = new Map<string, { queries: number; blocked: number }>();
    if (clientStats) {
      for (const stat of clientStats) {
        const dev = this.findDeviceForTelemetry({ ip: stat.ip, hostname: stat.hostname });
        if (!dev) continue;
        const prev = statsByDeviceId.get(dev.id) ?? { queries: 0, blocked: 0 };
        prev.queries += stat.queries;
        prev.blocked += stat.blocked;
        statsByDeviceId.set(dev.id, prev);
        matchedIds.add(dev.id);
      }
    }

    for (const devId of matchedIds) {
      const dev = this.state.devices.find((d) => d.id === devId);
      if (!dev) continue;

      let sumQueries = 0;
      let sumBlocked = 0;
      let suspiciousHits = 0;
      for (const ins of this.state.dnsInsights) {
        if (ins.deviceId === dev.id || (dev.ip && ins.deviceIp === dev.ip)) {
          sumQueries += ins.queriesCount;
          sumBlocked += ins.blockedCount;
          if (ins.classification === 'suspicious') suspiciousHits += 1;
        }
      }

      const statTotals = statsByDeviceId.get(dev.id);
      dev.dnsQueries24h = Math.max(
        dev.dnsQueries24h,
        sumQueries,
        statTotals?.queries ?? 0,
      );
      dev.blockedQueries24h = Math.max(
        dev.blockedQueries24h,
        sumBlocked,
        statTotals?.blocked ?? 0,
      );

      if (dev.blockedQueries24h > 0 || suspiciousHits > 0) {
        const computedRisk = Math.min(
          92,
          12 + Math.min(35, dev.blockedQueries24h * 2) + suspiciousHits * 15,
        );
        if (computedRisk > dev.riskScore) {
          dev.riskScore = computedRisk;
        }
        if (dev.status === 'nominal' && dev.riskScore >= 50) {
          dev.status = 'attention';
        }
      }
    }
  }

  private upsertDnsInsights(insights: DnsInsight[], clientStats?: ClientQueryStats[]): void {
    const matchedDeviceIds = new Set<string>();

    for (const rawInsight of insights) {
      const matched = this.findDeviceForTelemetry({
        deviceId: rawInsight.deviceId,
        ip: rawInsight.deviceIp,
        hostname: rawInsight.deviceHostname,
      });

      const insight: DnsInsight = matched
        ? {
            ...rawInsight,
            deviceId: matched.id,
            deviceHostname: matched.hostname,
            deviceIp: matched.ip,
          }
        : rawInsight;

      if (matched) {
        matchedDeviceIds.add(matched.id);
      }

      const deviceKey =
        insight.deviceId && insight.deviceId !== 'lan-client'
          ? insight.deviceId
          : insight.deviceIp || insight.deviceHostname.toLowerCase();

      const existingIdx = this.state.dnsInsights.findIndex((d) => {
        if (d.domain !== insight.domain) return false;
        const existingKey =
          d.deviceId && d.deviceId !== 'lan-client'
            ? d.deviceId
            : d.deviceIp || d.deviceHostname.toLowerCase();
        return existingKey === deviceKey;
      });

      if (existingIdx >= 0) {
        const cur = this.state.dnsInsights[existingIdx];
        cur.queriesCount = Math.max(cur.queriesCount, insight.queriesCount || 1);
        cur.blockedCount = Math.max(cur.blockedCount, insight.blockedCount || 0);
        cur.lastQueriedAt = insight.lastQueriedAt;
        if (matched) {
          cur.deviceId = matched.id;
          cur.deviceHostname = matched.hostname;
          cur.deviceIp = matched.ip;
        }
      } else {
        this.state.dnsInsights.unshift(insight);
      }
    }

    if (this.state.dnsInsights.length > 250) {
      this.state.dnsInsights.length = 250;
    }

    this.refreshDeviceFlowCounters(matchedDeviceIds, clientStats);
  }

  async syncIntegration(
    id: string,
    options?: { skipLatencySample?: boolean; bypassRbac?: boolean; actor?: string },
  ): Promise<{ result: SyncAdapterResult; state: WorkspaceState }> {
    if (!options?.bypassRbac) {
      this.assertCanMutate('operator');
    }
    const adapter = this.state.integrations.find((i) => i.id === id);
    if (!adapter) {
      throw new Error(`Integração "${id}" não encontrada.`);
    }

    const startedAt = Date.now();
    const nowIso = new Date().toISOString();

    if (adapter.mode === 'mock') {
      const simEvent: OpenShieldEventV1 = {
        eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
        schemaVersion: 'openshield.event.v1',
        occurredAt: nowIso,
        sourceIntegrationId: adapter.id,
        eventType:
          adapter.domain === 'gateway'
            ? 'gateway.health'
            : adapter.domain === 'dns'
              ? 'dns.query'
              : adapter.domain === 'threat_intel'
                ? 'threat.ioc'
                : 'ids.alert',
        severity: adapter.domain === 'ids' ? 'medium' : 'info',
        deviceId: this.state.devices[0]?.id,
        dataSource: 'mock',
        summary: `Ciclo de sincronização simulado para ${adapter.name} concluído.`,
        payload: { syncKind: 'mock', capabilities: adapter.capabilities },
      };

      if (adapter.domain === 'dns' && this.state.devices.length > 0) {
        const mockCatalog: Array<{
          domain: string;
          category: DnsInsight['category'];
          classification: DnsInsight['classification'];
          listStatus: DnsInsight['listStatus'];
          queries: number;
          blocked: number;
        }> = [
          {
            domain: 'api.github.com',
            category: 'Nuvem Corporativa',
            classification: 'benign',
            listStatus: 'monitored',
            queries: 42,
            blocked: 0,
          },
          {
            domain: 'telemetry.sdk.in',
            category: 'Telemetria & Rastreador',
            classification: 'tracker',
            listStatus: 'blocked',
            queries: 28,
            blocked: 28,
          },
          {
            domain: 'metrics.icloud.com',
            category: 'Telemetria & Rastreador',
            classification: 'tracker',
            listStatus: 'blocked',
            queries: 19,
            blocked: 19,
          },
          {
            domain: 'cdn.cloudflare.net',
            category: 'Nuvem Corporativa',
            classification: 'benign',
            listStatus: 'monitored',
            queries: 64,
            blocked: 0,
          },
        ];

        const targets = this.state.devices.slice(0, 6);
        const simInsights: DnsInsight[] = [];
        targets.forEach((dev, idx) => {
          const itemA = mockCatalog[idx % mockCatalog.length];
          const itemB = mockCatalog[(idx + 1) % mockCatalog.length];
          for (const item of [itemA, itemB]) {
            simInsights.push({
              id: `dns-mock-${dev.id}-${item.domain.replace(/[^a-z0-9]/g, '').slice(0, 12)}`,
              domain: item.domain,
              category: item.category,
              classification: item.classification,
              deviceId: dev.id,
              deviceHostname: dev.hostname,
              deviceIp: dev.ip,
              queriesCount: item.queries,
              blockedCount: item.blocked,
              listStatus: item.listStatus,
              lastQueriedAt: nowIso,
            });
          }
        });
        this.upsertDnsInsights(simInsights);
      }

      this.ingestEvent(simEvent);
      adapter.lastSyncedAt = nowIso;
      adapter.lastHeartbeatAt = nowIso;
      adapter.status = this.state.context.nodeAvailable ? 'connected' : 'stale';
      adapter.lastLatencyMs = this.state.context.nodeAvailable
        ? Math.max(1, Date.now() - startedAt)
        : undefined;
      if (!options?.skipLatencySample) {
        this.recordAggregatedLatencySample(nowIso);
      }
      const result: SyncAdapterResult = {
        adapterId: adapter.id,
        mode: 'mock',
        eventsIngested: 1,
        devicesDiscovered: 0,
        message: `Sincronização simulada concluída para ${adapter.name}.`,
        syncedAt: nowIso,
      };
      this.notify();
      return { result, state: this.getState() };
    }

    const cred = this.persistence.getServiceCredential(adapter.id);
    let ingested = 0;
    let discovered = 0;
    let message = '';

    if (adapter.kind === 'openwrt-rpcd') {
      const owrt = await syncOpenWrtReadOnly(adapter.liveEndpointUrl, adapter.id, {
        username: cred?.username,
        secret: cred?.secret,
      });
      adapter.boardInfo = owrt.boardInfo;
      discovered = this.upsertDiscoveredDevices(owrt.discoveredDevices, adapter.siteId);
      for (const ev of owrt.events) {
        const res = this.ingestEvent(ev);
        if (res.status === 'accepted') ingested += 1;
      }
      message = `OpenWrt/Node real sincronizado: ${owrt.boardInfo.model} (${discovered} dispositivo(s), ${ingested} evento(s)).`;
    } else if (adapter.kind === 'pihole-v6') {
      const pihole = await syncPiholeLive(adapter.liveEndpointUrl, adapter.id, adapter.name, {
        secret: cred?.secret,
      });
      for (const ev of pihole.events) {
        const res = this.ingestEvent(ev);
        if (res.status === 'accepted') ingested += 1;
      }
      this.upsertDnsInsights(pihole.insights, pihole.clientStats);
      message = pihole.summaryNote;
    } else if (adapter.kind === 'adguard-home') {
      const adguard = await syncAdguardLive(adapter.liveEndpointUrl, adapter.id, {
        username: cred?.username,
        secret: cred?.secret,
      });
      for (const ev of adguard.events) {
        const res = this.ingestEvent(ev);
        if (res.status === 'accepted') ingested += 1;
      }
      this.upsertDnsInsights(adguard.insights, adguard.clientStats);
      message = adguard.summaryNote;
    } else if (adapter.kind === 'technitium-dns') {
      const tech = await syncTechnitiumLive(adapter.liveEndpointUrl, adapter.id, adapter.name, {
        secret: cred?.secret,
      });
      for (const ev of tech.events) {
        const res = this.ingestEvent(ev);
        if (res.status === 'accepted') ingested += 1;
      }
      this.upsertDnsInsights(tech.insights, tech.clientStats);
      message = tech.summaryNote;
    } else {
      const headers: Record<string, string> = {};
      if (cred?.username && cred?.secret) {
        headers.Authorization = `Basic ${Buffer.from(`${cred.username}:${cred.secret}`).toString('base64')}`;
      } else if (cred?.secret) {
        headers.Authorization = `Bearer ${cred.secret}`;
      }
      const res = await boundedFetchJson<unknown>(adapter.liveEndpointUrl, {
        headers,
        timeoutMs: adapter.timeoutMs || 5000,
      });
      if (!res.ok) {
        throw new Error(`Adaptador ${adapter.name} retornou HTTP ${res.status}.`);
      }

      const isHaStates = adapter.kind === 'home-assistant' && Array.isArray(res.data);
      const summaryText = isHaStates
        ? `Home Assistant sincronizado: ${(res.data as unknown[]).length} entidade(s) IoT lida(s) via /api/states.`
        : `Coleta real bem-sucedida em ${adapter.name} (HTTP ${res.status}).`;

      const ev: OpenShieldEventV1 = {
        eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
        schemaVersion: 'openshield.event.v1',
        occurredAt: nowIso,
        sourceIntegrationId: adapter.id,
        eventType:
          adapter.domain === 'threat_intel'
            ? 'threat.ioc'
            : adapter.domain === 'ids'
              ? 'ids.alert'
              : adapter.domain === 'gateway'
                ? 'gateway.health'
                : adapter.domain === 'dns'
                  ? 'dns.query'
                  : 'zeek.connection',
        severity: 'info',
        dataSource: 'live',
        summary: summaryText,
        payload:
          res.data && typeof res.data === 'object' && !Array.isArray(res.data)
            ? (res.data as Record<string, unknown>)
            : { itemCount: Array.isArray(res.data) ? res.data.length : 1 },
      };
      this.ingestEvent(ev);
      ingested = 1;
      message = summaryText;
    }

    adapter.status = 'connected';
    adapter.lastSyncedAt = nowIso;
    adapter.lastHeartbeatAt = nowIso;
    adapter.lastLatencyMs = Math.max(1, Date.now() - startedAt);
    adapter.lastLiveCheckMessage = message;
    if (!options?.skipLatencySample) {
      this.recordAggregatedLatencySample(nowIso);
    }

    this.addAudit({
      eventType: 'integration.synced',
      actor: options?.actor ?? this.currentActor().actor,
      role: options?.actor ? 'system' : this.currentActor().role,
      targetId: adapter.id,
      outcome: 'success',
      detail: message,
    });

    this.notify();
    return {
      result: {
        adapterId: adapter.id,
        mode: 'live',
        eventsIngested: ingested,
        devicesDiscovered: discovered,
        message,
        syncedAt: nowIso,
      },
      state: this.getState(),
    };
  }

  async syncAllIntegrations(options?: {
    bypassRbac?: boolean;
    trigger?: 'manual' | 'timer';
  }): Promise<{
    results: SyncAdapterResult[];
    errors: { adapterId: string; name: string; error: string }[];
    state: WorkspaceState;
  }> {
    if (!options?.bypassRbac) {
      this.assertCanMutate('operator');
    }
    const results: SyncAdapterResult[] = [];
    const errors: { adapterId: string; name: string; error: string }[] = [];

    for (const adapter of [...this.state.integrations]) {
      try {
        const out = await this.syncIntegration(adapter.id, {
          skipLatencySample: true,
          bypassRbac: options?.bypassRbac,
          actor: options?.trigger === 'timer' ? 'openshield-sync-timer' : undefined,
        });
        results.push(out.result);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Falha desconhecida ao sincronizar.';
        adapter.status = 'unavailable';
        adapter.lastLatencyMs = undefined;
        adapter.lastLiveCheckMessage = msg;
        errors.push({ adapterId: adapter.id, name: adapter.name, error: msg });
      }
    }

    this.recordAggregatedLatencySample();
    const unavailableEndpoints = this.state.integrations.filter(
      (i) => i.domain !== 'ai_runtime' && i.status === 'unavailable',
    );
    if (unavailableEndpoints.length > 0) {
      const isMulti = unavailableEndpoints.length >= 2;
      void this.dispatchAlertToDestinations(
        {
          trigger: 'endpoint_offline',
          severity: isMulti ? 'critical' : 'high',
          title: isMulti
            ? `${unavailableEndpoints.length} endpoints de segurança offline simultaneamente`
            : `Endpoint de segurança indisponível: ${unavailableEndpoints[0].name}`,
          summary: `Endpoints offline detectados durante verificação de saúde: ${unavailableEndpoints.map((e) => e.name).join(', ')}.`,
          source: 'health-monitor',
          occurredAt: new Date().toISOString(),
        },
        ['endpoint_offline'],
      );
    }
    this.notify();
    return { results, errors, state: this.getState() };
  }

  registerManualIntegration(input: {
    id: string;
    name: string;
    domain: IntegrationAdapter['domain'];
    kind: string;
    liveEndpointUrl: string;
    siteId?: string;
    mode?: ServiceProviderMode;
    modelName?: string;
    boardInfo?: IntegrationAdapter['boardInfo'];
    username?: string;
    secret?: string;
    configMetadata?: Record<string, string>;
  }): WorkspaceState {
    this.assertCanMutate('operator');
    const cleanId = input.id.trim().toLowerCase().replace(/[^a-z0-9-_]/g, '-');
    if (!cleanId || !input.name.trim()) {
      throw new Error('ID e nome do serviço são obrigatórios.');
    }
    if (this.state.integrations.some((i) => i.id === cleanId)) {
      throw new Error(`Serviço "${cleanId}" já está cadastrado (use outro ID único).`);
    }

    if (input.configMetadata) {
      for (const key of Object.keys(input.configMetadata)) {
        if (SECRET_FIELD_PATTERN.test(key)) {
          this.state.metrics.authorizationDeniedTotal += 1;
          this.addAudit({
            eventType: 'authorization.denied',
            actor: this.currentActor().actor,
            role: this.currentActor().role,
            targetId: cleanId,
            outcome: 'denied',
            detail: `Registro rejeitado: campo sensível "${key}" não é permitido nos metadados da integração.`,
          });
          this.notify();
          throw new Error(
            `Campo proibido "${key}": credenciais não são aceitas em metadados públicos; utilize o campo de cofre do servidor.`,
          );
        }
      }
    }

    const endpoint = input.liveEndpointUrl.trim();
    const initialMode: ServiceProviderMode = input.mode ?? 'mock';
    if (initialMode === 'live' && (!endpoint || !/^https?:\/\//i.test(endpoint))) {
      throw new Error('Para iniciar em modo API Real, informe uma URL HTTP/HTTPS válida.');
    }

    const capabilities: IntegrationAdapter['capabilities'] =
      input.kind === 'pihole-v6' || input.kind === 'adguard-home' || input.kind === 'technitium-dns'
        ? ['health_check', 'read_events', 'read_configuration', 'write_configuration']
        : input.domain === 'gateway'
          ? ['discover', 'health_check']
          : input.kind === 'ollama-http' || input.domain === 'ai_runtime'
            ? ['health_check']
            : ['health_check', 'read_events'];

    const protocolVersion =
      input.domain === 'gateway'
        ? 'openshield.gateway.v1'
        : input.domain === 'ai_runtime'
          ? 'openshield.ai.v1'
          : 'openshield.adapter.v1';

    const descriptionMap: Record<string, string> = {
      'openwrt-rpcd': 'Conector de gateway OpenWrt fora do caminho de pacotes (rpcd/ubus ou Node FastAPI).',
      'opnsense-api': 'Firewall/roteador OPNsense ou pfSense com monitoramento de perímetro e regras via API.',
      'wireguard-vpn': 'VPN WireGuard (wg-easy / Tailscale) para acompanhamento de túneis e peers remotos.',
      'nginx-proxy-manager': 'Proxy reverso local com gerenciamento de certificados TLS e acesso interno.',
      'pihole-v6': 'Servidor Pi-hole para telemetria DNS, bloqueio de rastreadores e sincronização de listas.',
      'adguard-home': 'AdGuard Home para filtragem DNS de anúncios, rastreadores e controle de consultas.',
      'technitium-dns': 'Servidor DNS autoritativo e recursivo Technitium com DoH/DoT e bloqueio local.',
      'suricata-eve': 'Sensor IDS Suricata via protocolo EVE JSON para detecção de ameaças na LAN.',
      'zeek-json': 'Coletor Zeek para metadados comportamentais de sessões, TLS e fluxos.',
      'wazuh-api': 'Plataforma SIEM/HIDS Wazuh para integridade de arquivos, logs e alertas nos hosts.',
      'crowdsec-lapi': 'Feed CrowdSec LAPI para correlação de reputação e indicadores maliciosos.',
      'home-assistant': 'Hub Home Assistant para inventário IoT residencial, presença e automações.',
      'uptime-kuma': 'Monitor de disponibilidade Uptime Kuma para checagem de serviços e endpoints locais.',
      'netdata-agent': 'Agente Netdata / Prometheus para telemetria em tempo real de hosts e largura de banda.',
      'ollama-http': 'Runtime local-first Ollama para análise de incidentes sem saída de dados.',
    };

    const newAdapter: IntegrationAdapter = {
      id: cleanId,
      name: input.name.trim(),
      domain: input.domain,
      kind: input.kind.trim() || 'custom-http',
      description:
        descriptionMap[input.kind] ||
        'Serviço adicionado pelo usuário com contrato openshield.adapter.v1.',
      protocolVersion,
      mode: initialMode,
      liveEndpointUrl: endpoint,
      timeoutMs: 5000,
      status: 'connected',
      lastHeartbeatAt: new Date().toISOString(),
      capabilities,
      outboxQueueCount: 0,
      outboxCapacity: 10000,
      siteId: input.siteId?.trim() || this.state.context.activeSiteId,
      modelName: input.modelName?.trim() || undefined,
      boardInfo: input.boardInfo,
      lastLiveCheckMessage: endpoint
        ? initialMode === 'live'
          ? 'Configurado em modo API Real (pronto para sincronizar).'
          : 'Salvo em Simulador Mock (URL já preenchida para alternar quando desejar).'
        : 'Salvo em Simulador Mock (URL pendente de preenchimento).',
    };

    if (input.username || input.secret) {
      this.persistence.setServiceCredential(
        cleanId,
        (input.username ?? '').trim(),
        input.secret ?? '',
      );
    }

    this.state.integrations.push(newAdapter);
    this.addAudit({
      eventType: 'integration.registered',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: cleanId,
      outcome: 'success',
      detail: `Serviço "${newAdapter.name}" (${newAdapter.kind}) adicionado no site ${newAdapter.siteId}.`,
    });
    this.notify();
    return this.getState();
  }

  addDevice(input: {
    id?: string;
    hostname: string;
    ip: string;
    mac?: string;
    vendor?: string;
    interfaceName?: string;
    segment: NetworkDevice['segment'];
    siteId?: string;
    deviceType: NetworkDevice['deviceType'];
  }): WorkspaceState {
    this.assertCanMutate('operator');
    const hostname = input.hostname.trim();
    const ip = input.ip.trim();
    if (!hostname || !ip) {
      throw new Error('Hostname e endereço IP do dispositivo são obrigatórios.');
    }

    const cleanId =
      input.id?.trim().toLowerCase().replace(/[^a-z0-9-_]/g, '-') ||
      `dev-${hostname.toLowerCase().replace(/[^a-z0-9]/g, '-').slice(0, 18)}-${crypto.randomUUID().slice(0, 4)}`;

    if (this.state.devices.some((d) => d.id === cleanId)) {
      throw new Error(`Dispositivo "${cleanId}" já existe no inventário.`);
    }

    const newDevice: NetworkDevice = {
      id: cleanId,
      hostname,
      ip,
      mac: input.mac?.trim() || 'Não informado',
      vendor: input.vendor?.trim() || 'Configurado manualmente',
      interfaceName: input.interfaceName?.trim() || 'br-lan',
      segment: input.segment,
      siteId: input.siteId?.trim() || this.state.context.activeSiteId,
      riskScore: 10,
      status: 'nominal',
      lastSeenAt: new Date().toISOString(),
      dnsQueries24h: 0,
      blockedQueries24h: 0,
      deviceType: input.deviceType,
    };

    this.state.devices.push(newDevice);
    this.addAudit({
      eventType: 'device.added',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: newDevice.id,
      outcome: 'success',
      detail: `Dispositivo "${newDevice.hostname}" (${newDevice.ip}) adicionado em ${newDevice.segment}.`,
    });
    this.notify();
    return this.getState();
  }

  importOpenWrtMapping(input: {
    rawOutput?: string;
    netDump?: unknown;
    hostHints?: unknown;
    ipNeighText?: string;
    siteId?: string;
  }): {
    discoveredCount: number;
    devices: DiscoveredDeviceHint[];
    state: WorkspaceState;
  } {
    this.assertCanMutate('operator');
    const siteId = input.siteId?.trim() || this.state.context.activeSiteId;

    let hints: DiscoveredDeviceHint[] = [];
    if (input.ipNeighText || input.netDump || input.hostHints) {
      const ipNeighRows = parseIp4NeighText(input.ipNeighText ?? '');
      hints = mapOpenWrtNeighbors({
        netDump: input.netDump,
        hostHints: input.hostHints,
        ipNeighRows,
        defaultVendor: 'Mapeado via OpenWrt (ubus + ip neigh)',
      });
    } else if (input.rawOutput?.trim()) {
      hints = parseOpenWrtCommandOutput(input.rawOutput);
    }

    if (hints.length === 0) {
      throw new Error(
        'Nenhum dispositivo válido encontrado na saída OpenWrt. Formato esperado: <NOME> <MAC> <IP> <INTERFACE>.',
      );
    }

    const discoveredCount = this.upsertDiscoveredDevices(hints, siteId);
    const interfacesFound = Array.from(
      new Set(hints.map((h) => h.interfaceName).filter(Boolean)),
    );

    const gatewaySourceId =
      this.state.integrations.find((i) => i.domain === 'gateway')?.id ?? 'openwrt-gateway';
    const nowIso = new Date().toISOString();
    const discoveryEvent: OpenShieldEventV1 = {
      eventId: `ev-${crypto.randomUUID().slice(0, 8)}`,
      schemaVersion: 'openshield.event.v1',
      occurredAt: nowIso,
      sourceIntegrationId: gatewaySourceId,
      eventType: 'gateway.discovery',
      severity: 'info',
      dataSource: 'live',
      summary: `Mapeamento OpenWrt (ubus + ip -4 neigh) aplicado: ${discoveredCount} dispositivo(s) em ${interfacesFound.join(', ') || 'br-lan'}.`,
      payload: {
        discoveredCount,
        interfaces: interfacesFound,
        mappingMethod: 'ubus_network_interface_host_hints_ip4_neigh',
      },
    };
    this.persistence.persistEvent(discoveryEvent);
    this.state.events.unshift(discoveryEvent);
    if (this.state.events.length > 150) {
      this.state.events.length = 150;
    }

    this.addAudit({
      eventType: 'device.added',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: siteId,
      outcome: 'success',
      detail: `Mapeamento OpenWrt importado: ${discoveredCount} dispositivo(s) sincronizado(s) na topologia.`,
    });
    this.notify();

    return {
      discoveredCount,
      devices: hints,
      state: this.getState(),
    };
  }

  updateDevice(
    id: string,
    patch: Partial<
      Pick<
        NetworkDevice,
        'hostname' | 'ip' | 'mac' | 'vendor' | 'interfaceName' | 'segment' | 'siteId' | 'deviceType' | 'status'
      >
    >,
  ): WorkspaceState {
    this.assertCanMutate('operator');
    const dev = this.state.devices.find((d) => d.id === id);
    if (!dev) {
      throw new Error(`Dispositivo "${id}" não encontrado.`);
    }

    if (patch.hostname !== undefined && patch.hostname.trim()) dev.hostname = patch.hostname.trim();
    if (patch.ip !== undefined && patch.ip.trim()) dev.ip = patch.ip.trim();
    if (patch.mac !== undefined) dev.mac = patch.mac.trim() || 'Não informado';
    if (patch.vendor !== undefined) dev.vendor = patch.vendor.trim() || 'Configurado manualmente';
    if (patch.interfaceName !== undefined && patch.interfaceName.trim()) dev.interfaceName = patch.interfaceName.trim();
    if (patch.segment !== undefined) dev.segment = patch.segment;
    if (patch.siteId !== undefined && patch.siteId.trim()) dev.siteId = patch.siteId.trim();
    if (patch.deviceType !== undefined) dev.deviceType = patch.deviceType;
    if (patch.status !== undefined) dev.status = patch.status;
    dev.lastSeenAt = new Date().toISOString();

    this.addAudit({
      eventType: 'device.updated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: dev.id,
      outcome: 'success',
      detail: `Dispositivo "${dev.hostname}" (${dev.ip}) atualizado.`,
    });
    this.notify();
    return this.getState();
  }

  removeDevice(id: string): WorkspaceState {
    this.assertCanMutate('operator');
    const idx = this.state.devices.findIndex((d) => d.id === id);
    if (idx < 0) {
      throw new Error(`Dispositivo "${id}" não encontrado.`);
    }
    const [removed] = this.state.devices.splice(idx, 1);
    this.addAudit({
      eventType: 'device.removed',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Dispositivo "${removed.hostname}" (${removed.ip}) removido do inventário.`,
    });
    this.notify();
    return this.getState();
  }

  runGatewayHandshake(integrationId: string): WorkspaceState {
    const adapter = this.state.integrations.find((i) => i.id === integrationId);
    if (!adapter) {
      throw new Error('Gateway ou adaptador não encontrado.');
    }
    if (!this.state.context.nodeAvailable) {
      throw new Error(
        'OpenShield Node está simulado como indisponível. O gateway continua encaminhando pacotes na LAN.',
      );
    }
    adapter.status = 'connected';
    adapter.lastHeartbeatAt = new Date().toISOString();
    this.state.metrics.gatewayConnectionsTotal += 1;
    this.state.metrics.gatewayHeartbeatsTotal += 1;
    this.addAudit({
      eventType: 'gateway.connected',
      actor: adapter.id,
      role: 'gateway-connector',
      targetId: adapter.id,
      outcome: 'success',
      detail: `Handshake ${adapter.protocolVersion} concluído; capacidades anunciadas: ${adapter.capabilities.join(', ')}.`,
    });
    this.notify();
    return this.getState();
  }

  ingestEvent(input: {
    eventId?: string;
    schemaVersion?: string;
    occurredAt?: string;
    sourceIntegrationId: string;
    eventType: OpenShieldEventV1['eventType'];
    severity: OpenShieldEventV1['severity'];
    summary: string;
    deviceId?: string;
    dataSource?: 'mock' | 'live';
    payload?: Record<string, unknown>;
    simulateDuplicateId?: string;
  }): {
    status: 'accepted' | 'duplicate' | 'buffered';
    event: OpenShieldEventV1;
    correlatedIncidentId: string | null;
    state: WorkspaceState;
  } {
    if (input.schemaVersion && input.schemaVersion !== 'openshield.event.v1') {
      throw new Error(
        `Versão de schema não suportada (${input.schemaVersion}). Esperado: openshield.event.v1.`,
      );
    }

    const source = this.state.integrations.find((i) => i.id === input.sourceIntegrationId);
    if (!source) {
      this.state.metrics.authorizationDeniedTotal += 1;
      this.addAudit({
        eventType: 'authorization.denied',
        actor: input.sourceIntegrationId,
        role: 'untrusted-source',
        targetId: input.sourceIntegrationId,
        outcome: 'denied',
        detail: `Proveniência rejeitada: sourceIntegrationId "${input.sourceIntegrationId}" não está registrado no Node.`,
      });
      this.notify();
      throw new Error(
        `Proveniência rejeitada (HTTP 403): fonte "${input.sourceIntegrationId}" não possui integração registrada.`,
      );
    }

    const eventId =
      input.simulateDuplicateId || input.eventId || `ev-${crypto.randomUUID().slice(0, 8)}`;
    const event: OpenShieldEventV1 = {
      eventId,
      schemaVersion: 'openshield.event.v1',
      occurredAt: input.occurredAt || new Date().toISOString(),
      sourceIntegrationId: input.sourceIntegrationId,
      eventType: input.eventType,
      severity: input.severity,
      deviceId: input.deviceId,
      dataSource: input.dataSource ?? (source.mode === 'live' ? 'live' : 'mock'),
      summary: input.summary,
      payload: input.payload ?? {},
    };

    if (!this.state.context.nodeAvailable) {
      const currentOutbox = this.persistence.outboxCount();
      if (currentOutbox >= 10000) {
        throw new Error(
          'Outbox local do conector atingiu o limite seguro de 10.000 eventos pendentes.',
        );
      }
      this.persistence.enqueueOutbox(event);
      const nextOutbox = this.persistence.outboxCount();
      source.outboxQueueCount = nextOutbox;
      this.state.metrics.outboxPendingTotal = nextOutbox;
      this.notify();
      return { status: 'buffered', event, correlatedIncidentId: null, state: this.getState() };
    }

    if (this.persistence.hasEventId(eventId)) {
      return { status: 'duplicate', event, correlatedIncidentId: null, state: this.getState() };
    }

    this.persistence.persistEvent(event);
    this.state.events.unshift(event);
    if (this.state.events.length > 100) {
      this.state.events.length = 100;
    }
    this.state.metrics.eventsIngestedTotal += 1;

    const correlation = correlateEventIntoIncidents(
      event,
      this.state.incidents,
      this.state.devices,
      this.state.context.activeSiteId,
      this.state.context.aiSensitivity,
    );

    // Update per-device Flow telemetry & risk score from ingested events
    const matchedDevice = this.findDeviceForTelemetry({
      deviceId: event.deviceId,
      ip:
        typeof event.payload?.srcIp === 'string'
          ? event.payload.srcIp
          : typeof event.payload?.clientIp === 'string'
            ? event.payload.clientIp
            : undefined,
      hostname:
        typeof event.payload?.deviceHostname === 'string'
          ? event.payload.deviceHostname
          : undefined,
    });

    if (matchedDevice) {
      matchedDevice.lastSeenAt = event.occurredAt;
      const rawDom =
        event.payload?.domain ??
        event.payload?.qname ??
        event.payload?.targetDomain ??
        event.payload?.hostname;
      const domainStr = typeof rawDom === 'string' ? rawDom.trim().toLowerCase() : '';
      const countRaw = Number(event.payload?.queriesInWindow ?? event.payload?.count ?? 1);
      const count = Number.isFinite(countRaw) && countRaw > 0 ? Math.round(countRaw) : 1;
      const isBlocked = String(event.payload?.action ?? '').toLowerCase() === 'blocked';

      if (event.eventType === 'dns.query' || (domainStr && domainStr.includes('.'))) {
        matchedDevice.dnsQueries24h += count;
        if (isBlocked) {
          matchedDevice.blockedQueries24h += count;
        }
        if (domainStr && domainStr.includes('.')) {
          this.upsertDnsInsights([
            {
              id: `dns-ev-${matchedDevice.id}-${crypto.createHash('sha1').update(domainStr).digest('hex').slice(0, 6)}`,
              domain: domainStr,
              category: isBlocked
                ? 'Telemetria & Rastreador'
                : event.severity === 'high' || event.severity === 'critical'
                  ? 'Suspeito / DGA'
                  : 'Nuvem Corporativa',
              classification:
                event.severity === 'high' || event.severity === 'critical'
                  ? 'suspicious'
                  : isBlocked
                    ? 'tracker'
                    : 'benign',
              deviceId: matchedDevice.id,
              deviceHostname: matchedDevice.hostname,
              deviceIp: matchedDevice.ip,
              queriesCount: count,
              blockedCount: isBlocked ? count : 0,
              listStatus: isBlocked ? 'blocked' : 'monitored',
              lastQueriedAt: event.occurredAt,
            },
          ]);
        }
      }

      if (correlation.updatedIncident) {
        matchedDevice.riskScore = Math.max(
          matchedDevice.riskScore,
          correlation.updatedIncident.riskScore,
        );
        if (matchedDevice.status === 'nominal' && matchedDevice.riskScore >= 50) {
          matchedDevice.status = 'attention';
        }
      }
    }

    this.addAudit({
      eventType: 'event.ingested',
      actor: source.id,
      role: 'integration-adapter',
      targetId: eventId,
      outcome: 'success',
      detail: `Evento ${event.eventType} (${event.severity}, ${event.dataSource}) ingerido com proveniência "${source.id}".`,
    });

    if (correlation.updatedIncident) {
      const inc = correlation.updatedIncident;
      const matchTriggers: NotificationTriggerEvent[] = ['critical_incident', 'ai_anomaly'];
      void this.dispatchAlertToDestinations(
        {
          trigger: inc.riskScore >= 75 ? 'critical_incident' : 'ai_anomaly',
          severity: inc.severity,
          title: inc.title,
          summary: `${inc.summary} (Score de risco: ${inc.riskScore}/100)`,
          source: source.name,
          deviceHostname: inc.deviceHostname,
          occurredAt: event.occurredAt,
          siteId: inc.siteId,
        },
        matchTriggers,
      );
    }

    this.notify();
    return {
      status: 'accepted',
      event,
      correlatedIncidentId: correlation.updatedIncident?.id ?? null,
      state: this.getState(),
    };
  }

  private async applyDnsRuleToLiveAdapters(
    domain: string,
    listStatus: DnsInsight['listStatus'],
  ): Promise<{ notes: string[]; errors: string[] }> {
    const liveDnsAdapters = this.state.integrations.filter(
      (a) => a.domain === 'dns' && a.mode === 'live',
    );
    const notes: string[] = [];
    const errors: string[] = [];

    for (const dnsAdapter of liveDnsAdapters) {
      try {
        const cred = this.persistence.getServiceCredential(dnsAdapter.id);
        const note = await pushDnsRuleLive(
          dnsAdapter.kind,
          dnsAdapter.name,
          dnsAdapter.liveEndpointUrl,
          domain,
          listStatus,
          { username: cred?.username, secret: cred?.secret },
        );
        notes.push(note);
      } catch (err) {
        errors.push(
          `${dnsAdapter.name}: ${err instanceof Error ? err.message : 'erro ao aplicar regra'}`,
        );
      }
    }

    const insight = this.state.dnsInsights.find((d) => d.domain === domain);
    if (insight) {
      insight.listStatus = listStatus;
    }

    return { notes, errors };
  }

  async addDnsInsight(input: {
    domain: string;
    category?: DnsInsight['category'];
    classification?: DnsInsight['classification'];
    deviceHostname?: string;
    listStatus?: DnsInsight['listStatus'];
  }): Promise<WorkspaceState> {
    this.assertCanMutate('operator');
    const normalized = input.domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!normalized || !/^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$/i.test(normalized) || !normalized.includes('.')) {
      throw new Error('Informe um domínio válido (ex.: tracker.exemplo.com).');
    }

    const listStatus: DnsInsight['listStatus'] = input.listStatus ?? 'monitored';
    const classification: DnsInsight['classification'] = input.classification ?? 'tracker';
    const category: DnsInsight['category'] =
      input.category ??
      (classification === 'tracker'
        ? 'Telemetria & Rastreador'
        : classification === 'suspicious'
          ? 'Suspeito / DGA'
          : 'Serviço Local');
    const hostname = input.deviceHostname?.trim() || 'manual-lan';

    let syncNotes: string[] = [];
    if (listStatus !== 'monitored') {
      const liveDnsAdapters = this.state.integrations.filter(
        (a) => a.domain === 'dns' && a.mode === 'live',
      );
      for (const dnsAdapter of liveDnsAdapters) {
        const cred = this.persistence.getServiceCredential(dnsAdapter.id);
        const note = await pushDnsRuleLive(
          dnsAdapter.kind,
          dnsAdapter.name,
          dnsAdapter.liveEndpointUrl,
          normalized,
          listStatus,
          { username: cred?.username, secret: cred?.secret },
        );
        syncNotes.push(note);
      }
    }

    const existing = this.state.dnsInsights.find((d) => d.domain === normalized);
    if (existing) {
      existing.category = category;
      existing.classification = classification;
      existing.listStatus = listStatus;
      existing.deviceHostname = hostname;
      existing.lastQueriedAt = new Date().toISOString();
    } else {
      this.state.dnsInsights.unshift({
        id: `dns-${crypto.randomUUID().slice(0, 8)}`,
        domain: normalized,
        category,
        classification,
        deviceId: this.state.devices.find((d) => d.hostname === hostname)?.id ?? 'manual',
        deviceHostname: hostname,
        queriesCount: 1,
        blockedCount: listStatus === 'blocked' ? 1 : 0,
        listStatus,
        lastQueriedAt: new Date().toISOString(),
      });
    }

    const suffix = syncNotes.length > 0 ? ` (${syncNotes.join(' · ')})` : '';
    this.addAudit({
      eventType: 'dns.added',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: normalized,
      outcome: 'success',
      detail: `Domínio "${normalized}" adicionado em Privacidade DNS com status "${listStatus}".${suffix}`,
    });
    this.notify();
    return this.getState();
  }

  async updateDnsListStatus(
    id: string,
    listStatus: DnsInsight['listStatus'],
  ): Promise<WorkspaceState> {
    this.assertCanMutate('operator');
    const item = this.state.dnsInsights.find((d) => d.id === id);
    if (!item) {
      throw new Error('Domínio DNS não encontrado.');
    }

    const liveDnsAdapters = this.state.integrations.filter(
      (a) => a.domain === 'dns' && a.mode === 'live',
    );
    const syncNotes: string[] = [];

    for (const dnsAdapter of liveDnsAdapters) {
      const cred = this.persistence.getServiceCredential(dnsAdapter.id);
      const note = await pushDnsRuleLive(
        dnsAdapter.kind,
        dnsAdapter.name,
        dnsAdapter.liveEndpointUrl,
        item.domain,
        listStatus,
        { username: cred?.username, secret: cred?.secret },
      );
      syncNotes.push(note);
    }

    const suffix = syncNotes.length > 0 ? ` (${syncNotes.join(' · ')})` : '';
    item.listStatus = listStatus;
    this.addAudit({
      eventType: 'dns.list_updated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: item.domain,
      outcome: 'success',
      detail: `Domínio "${item.domain}" movido para status "${listStatus}".${suffix}`,
    });
    this.notify();
    return this.getState();
  }

  async investigateIncident(
    incidentId: string,
    mode: 'local' | 'cloud_gemini',
  ): Promise<WorkspaceState> {
    this.assertCanMutate('operator');
    const incident = this.state.incidents.find((i) => i.id === incidentId);
    if (!incident) {
      throw new Error('Incidente não encontrado.');
    }

    const relatedEvents = this.state.events.filter((e) => incident.eventIds.includes(e.eventId));

    if (mode === 'cloud_gemini') {
      if (!this.state.context.cloudAiOptIn) {
        throw new Error(
          'Segunda opinião em nuvem desabilitada por padrão. Ative o opt-in explícito de IA em Nuvem antes de enviar contexto sanitizado.',
        );
      }
      const startedAt = Date.now();
      try {
        const { investigation, usage } = await runSanitizedCloudInvestigation(
          incident,
          relatedEvents,
        );
        incident.investigation = investigation;
        incident.status = incident.status === 'open' ? 'investigating' : incident.status;
        this.recordAiUsage({
          incidentId: incident.id,
          incidentTitle: incident.title,
          provider: investigation.provider,
          channel: 'cloud',
          modelVersion: investigation.modelVersion,
          promptTokens: usage.promptTokens,
          completionTokens: usage.completionTokens,
          totalTokens: usage.totalTokens,
          durationMs: usage.durationMs,
          estimatedCostUsd: usage.estimatedCostUsd,
          outcome: 'success',
          detail: 'Segunda opinião sanitizada em nuvem concluída.',
        });
        this.addAudit({
          eventType: 'ai.investigated',
          actor: this.currentActor().actor,
          role: this.currentActor().role,
          targetId: incident.id,
          outcome: 'success',
          detail: `Segunda opinião via ${investigation.modelVersion} concluída (${usage.totalTokens} tokens · ~US$ ${usage.estimatedCostUsd.toFixed(6)}) após sanitização.`,
        });
        this.notify();
        return this.getState();
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Falha na chamada à API Gemini';
        this.recordAiUsage({
          incidentId: incident.id,
          incidentTitle: incident.title,
          provider: 'gemini-sanitized',
          channel: 'cloud',
          modelVersion: 'gemini-4-hydrogen (nuvem opt-in)',
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
          durationMs: Math.max(1, Date.now() - startedAt),
          estimatedCostUsd: 0,
          outcome: 'error',
          detail: message,
        });
        this.notify();
        throw err;
      }
    }

    const ollamaAdapter = this.state.integrations.find(
      (a) => a.kind === 'ollama-http' || a.domain === 'ai_runtime',
    );
    if (ollamaAdapter && ollamaAdapter.mode === 'live') {
      const startedAt = Date.now();
      const targetModel = ollamaAdapter.modelName || process.env.OPENSHIELD_OLLAMA_MODEL || 'llama3.1:8b';
      try {
        const { investigation: liveInvestigation, usage } = await runLocalOllamaInvestigation(
          ollamaAdapter.liveEndpointUrl,
          incident,
          relatedEvents,
          ollamaAdapter.modelName,
        );
        incident.investigation = liveInvestigation;
        incident.status = incident.status === 'open' ? 'investigating' : incident.status;
        ollamaAdapter.lastHeartbeatAt = new Date().toISOString();
        ollamaAdapter.status = 'connected';
        ollamaAdapter.lastLatencyMs = usage.durationMs;
        this.recordAiUsage({
          incidentId: incident.id,
          incidentTitle: incident.title,
          provider: liveInvestigation.provider,
          channel: 'local',
          modelVersion: liveInvestigation.modelVersion,
          promptTokens: usage.promptTokens,
          completionTokens: usage.completionTokens,
          totalTokens: usage.totalTokens,
          durationMs: usage.durationMs,
          estimatedCostUsd: 0,
          outcome: 'success',
          detail: 'Inferência executada no runtime Ollama local.',
        });
        this.addAudit({
          eventType: 'ai.investigated',
          actor: this.currentActor().actor,
          role: this.currentActor().role,
          targetId: incident.id,
          outcome: 'success',
          detail: `Investigação local real via ${liveInvestigation.modelVersion} concluída (${usage.totalTokens} tokens · ${usage.durationMs}ms).`,
        });
        this.notify();
        return this.getState();
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Falha na chamada ao Ollama local';
        this.recordAiUsage({
          incidentId: incident.id,
          incidentTitle: incident.title,
          provider: 'local-ollama-live',
          channel: 'local',
          modelVersion: `${targetModel} (Ollama local real)`,
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
          durationMs: Math.max(1, Date.now() - startedAt),
          estimatedCostUsd: 0,
          outcome: 'error',
          detail: message,
        });
        this.notify();
        throw err;
      }
    }

    const sanitizedPreview = buildSanitizedContext(incident, relatedEvents);
    const localInvestigation = {
      provider: 'local-ollama-mock' as const,
      modelVersion: `${ollamaAdapter?.modelName || 'llama3.1:8b-instruct'} (local-first simulado)`,
      promptTemplateVersion: 'openshield.local.v1.4',
      generatedAt: new Date().toISOString(),
      confidence: (incident.riskScore >= 75 ? 'alta' : 'média') as 'alta' | 'média',
      observedFacts: [
        `Correlação de ${incident.eventIds.length} evento(s) normalizados no schema openshield.event.v1.`,
        ...incident.riskFactors,
      ],
      inferredHypotheses: [
        `O comportamento observado no dispositivo ${incident.deviceHostname} indica ${incident.summary.toLowerCase()}`,
        'Nenhum dado bruto ou pacote completo saiu da rede local durante esta análise.',
      ],
      recommendedSteps: [
        incident.recommendedAction,
        'Validar se há alteração legítima agendada antes de elevar autonomia além de L1/L2.',
      ],
      sanitizedPayloadPreview: sanitizedPreview,
      promptInjectionGuardNote:
        'Inferência local executada apenas sobre evidências persistidas; strings externas delimitadas contra prompt injection.',
    };
    incident.investigation = localInvestigation;
    incident.status = incident.status === 'open' ? 'investigating' : incident.status;

    const estPromptTokens = Math.max(140, Math.ceil((sanitizedPreview.length + 180) / 4));
    const estCompletionTokens = Math.max(85, Math.ceil(JSON.stringify(localInvestigation.observedFacts.concat(localInvestigation.inferredHypotheses, localInvestigation.recommendedSteps)).length / 4));
    const simDurationMs = 190 + (sanitizedPreview.length % 130);
    this.recordAiUsage({
      incidentId: incident.id,
      incidentTitle: incident.title,
      provider: localInvestigation.provider,
      channel: 'local',
      modelVersion: localInvestigation.modelVersion,
      promptTokens: estPromptTokens,
      completionTokens: estCompletionTokens,
      totalTokens: estPromptTokens + estCompletionTokens,
      durationMs: simDurationMs,
      estimatedCostUsd: 0,
      outcome: 'success',
      detail: 'Inferência local-first simulada (sem consumo em nuvem).',
    });

    this.addAudit({
      eventType: 'ai.investigated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: incident.id,
      outcome: 'success',
      detail: `Investigação local-first (${incident.investigation.modelVersion}) gerada para o incidente "${incident.id}".`,
    });
    this.notify();
    return this.getState();
  }

  updateIncidentStatus(incidentId: string, status: Incident['status']): WorkspaceState {
    this.assertCanMutate('operator');
    const incident = this.state.incidents.find((i) => i.id === incidentId);
    if (!incident) {
      throw new Error('Incidente não encontrado.');
    }
    incident.status = status;
    this.addAudit({
      eventType: 'context.updated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: incident.id,
      outcome: 'success',
      detail: `Status do incidente "${incident.title}" atualizado para "${status}".`,
    });
    this.notify();
    return this.getState();
  }

  togglePolicyEnabled(policyId: string, enabled: boolean): WorkspaceState {
    this.assertCanMutate('policy_admin');
    const policy = this.state.policies.find((p) => p.id === policyId);
    if (!policy) {
      throw new Error('Política não encontrada.');
    }
    policy.enabled = enabled;
    this.addAudit({
      eventType: 'context.updated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: policy.id,
      outcome: 'success',
      detail: `Política "${policy.name}" ${enabled ? 'habilitada' : 'desabilitada'}.`,
    });
    this.notify();
    return this.getState();
  }

  private resolveIncidentTargetDomain(incident: Incident): string | undefined {
    const related = this.state.events.filter((e) => incident.eventIds.includes(e.eventId));
    for (const ev of related) {
      if (typeof ev.payload.domain === 'string' && ev.payload.domain.trim()) {
        return ev.payload.domain.trim().toLowerCase();
      }
    }
    const dnsMatch = this.state.dnsInsights.find(
      (d) =>
        (d.deviceId === incident.deviceId || d.deviceHostname === incident.deviceHostname) &&
        d.classification !== 'benign',
    );
    return dnsMatch?.domain;
  }

  async proposePolicyAction(input: {
    incidentId: string;
    policyId: string;
    ttlSeconds?: number;
  }): Promise<{ execution: ActionExecution; state: WorkspaceState }> {
    this.assertCanMutate('operator');
    const incident = this.state.incidents.find((i) => i.id === input.incidentId);
    const policy = this.state.policies.find((p) => p.id === input.policyId);
    if (!incident || !policy) {
      throw new Error('Incidente ou política inválida.');
    }
    if (!policy.enabled) {
      throw new Error(`Política "${policy.name}" está desabilitada.`);
    }

    if (this.state.context.killSwitchActive) {
      this.state.metrics.authorizationDeniedTotal += 1;
      this.addAudit({
        eventType: 'authorization.denied',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: incident.id,
        outcome: 'denied',
        detail: 'Execução bloqueada: Kill Switch global está ativo.',
      });
      this.notify();
      throw new Error('Kill Switch ativo: nenhuma ação automatizada pode ser executada.');
    }

    const globalCeiling = this.state.context.globalAutonomy;
    const effectiveLevel =
      AUTONOMY_RANK[policy.maxAutonomyLevel] <= AUTONOMY_RANK[globalCeiling]
        ? policy.maxAutonomyLevel
        : globalCeiling;

    const ttl = Math.max(30, Math.min(input.ttlSeconds ?? policy.defaultTtlSeconds, 3600));
    const actionType: ActionExecution['actionType'] =
      effectiveLevel === 'L0'
        ? 'dry_run_only'
        : policy.id === 'pol-dns-tracker'
          ? 'dns_block_domain'
          : policy.id === 'pol-iot-quarantine'
            ? 'isolate_iot_segment'
            : 'nftables_temp_drop';

    const targetDomain =
      actionType === 'dns_block_domain' || policy.id === 'pol-dns-tracker'
        ? this.resolveIncidentTargetDomain(incident)
        : undefined;

    let status: ActionExecution['status'] = 'dry_run';
    let expiresAt: string | null = null;
    let verificationDetail =
      'Modo L0 (Observar): simulação concluída sem alterar firewall, DNS ou encaminhamento.';

    if (effectiveLevel === 'L3') {
      status = 'awaiting_approval';
      verificationDetail =
        'Aguardando aprovação humana explícita (L3) antes de aplicar contenção no adaptador.';
    } else if (effectiveLevel === 'L1' || effectiveLevel === 'L2') {
      status = 'verified';
      expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
      let liveNote = '';
      if (actionType === 'dns_block_domain' && targetDomain) {
        const res = await this.applyDnsRuleToLiveAdapters(targetDomain, 'blocked');
        if (res.notes.length > 0) {
          liveNote = ` Sincronizado em DNS real: ${res.notes.join(' · ')}.`;
        } else if (res.errors.length > 0) {
          liveNote = ` Aviso DNS real: ${res.errors.join(' · ')}.`;
        }
      }
      verificationDetail = `Ação ${effectiveLevel} aplicada e verificada via verify_action. Expiração automática agendada em ${ttl}s.${liveNote}`;
      incident.status = 'contained';
    }

    const execution: ActionExecution = {
      id: `act-${crypto.randomUUID().slice(0, 8)}`,
      incidentId: incident.id,
      policyId: policy.id,
      targetLabel: targetDomain
        ? `${incident.deviceHostname} · ${targetDomain}`
        : `${incident.deviceHostname} · ${incident.recommendedAction}`,
      targetDomain,
      actionType,
      autonomyLevel: effectiveLevel,
      status,
      ttlSeconds: ttl,
      expiresAt,
      executedBy: this.currentActor().actor,
      verificationDetail,
      rollbackAvailable: status === 'verified' && policy.rollbackSupported,
      createdAt: new Date().toISOString(),
    };

    this.state.executions.unshift(execution);
    this.addAudit({
      eventType: effectiveLevel === 'L0' ? 'action.proposed' : 'action.executed',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: execution.id,
      outcome: effectiveLevel === 'L0' ? 'simulated' : 'success',
      detail: `${execution.verificationDetail} (Política: ${policy.name})`,
    });

    this.notify();
    return { execution, state: this.getState() };
  }

  async approveL3Execution(executionId: string): Promise<WorkspaceState> {
    this.assertCanMutate('policy_admin');
    if (this.state.context.killSwitchActive) {
      throw new Error('Kill Switch ativo: aprovação bloqueada.');
    }
    const exec = this.state.executions.find((e) => e.id === executionId);
    if (!exec || exec.status !== 'awaiting_approval') {
      throw new Error('Execução não está aguardando aprovação L3.');
    }

    let liveNote = '';
    if (exec.actionType === 'dns_block_domain' && exec.targetDomain) {
      const res = await this.applyDnsRuleToLiveAdapters(exec.targetDomain, 'blocked');
      if (res.notes.length > 0) liveNote = ` (${res.notes.join(' · ')})`;
    }

    exec.status = 'verified';
    exec.expiresAt = new Date(Date.now() + exec.ttlSeconds * 1000).toISOString();
    exec.rollbackAvailable = true;
    exec.verificationDetail = `Aprovado por ${this.currentActor().actor}; regra verificada com TTL de ${exec.ttlSeconds}s.${liveNote}`;

    const inc = this.state.incidents.find((i) => i.id === exec.incidentId);
    if (inc) {
      inc.status = 'contained';
    }

    this.addAudit({
      eventType: 'action.approved',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: exec.id,
      outcome: 'success',
      detail: `Ação L3 "${exec.targetLabel}" aprovada e verificada com sucesso.`,
    });
    this.notify();
    return this.getState();
  }

  async rollbackExecution(executionId: string): Promise<WorkspaceState> {
    this.assertCanMutate('operator');
    const exec = this.state.executions.find((e) => e.id === executionId);
    if (!exec || !exec.rollbackAvailable) {
      throw new Error('Esta execução não possui rollback disponível no momento.');
    }

    let liveNote = '';
    if (exec.actionType === 'dns_block_domain' && exec.targetDomain) {
      const res = await this.applyDnsRuleToLiveAdapters(exec.targetDomain, 'monitored');
      if (res.notes.length > 0) {
        liveNote = ` Revertido em DNS real: ${res.notes.join(' · ')}.`;
      } else if (res.errors.length > 0) {
        liveNote = ` Aviso ao reverter DNS: ${res.errors.join(' · ')}.`;
      }
    }

    exec.status = 'rolled_back';
    exec.rollbackAvailable = false;
    exec.expiresAt = null;
    exec.verificationDetail = `Rollback executado por ${this.currentActor().actor} e verificado no adaptador.${liveNote}`;

    const inc = this.state.incidents.find((i) => i.id === exec.incidentId);
    if (inc && inc.status === 'contained') {
      inc.status = 'investigating';
    }

    this.addAudit({
      eventType: 'action.rolled_back',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: exec.id,
      outcome: 'success',
      detail: `Rollback concluído para "${exec.targetLabel}".${liveNote}`,
    });
    this.notify();
    return this.getState();
  }

  async triggerKillSwitch(active: boolean): Promise<WorkspaceState> {
    if (active) {
      this.state.context.killSwitchActive = true;
      this.state.context.globalAutonomy = 'L0';
      let abortedCount = 0;

      for (const exec of this.state.executions) {
        if (
          exec.status === 'active' ||
          exec.status === 'verified' ||
          exec.status === 'awaiting_approval'
        ) {
          if (exec.actionType === 'dns_block_domain' && exec.targetDomain && exec.status !== 'awaiting_approval') {
            await this.applyDnsRuleToLiveAdapters(exec.targetDomain, 'monitored');
          }
          exec.status = 'aborted_kill_switch';
          exec.rollbackAvailable = false;
          exec.expiresAt = null;
          exec.verificationDetail =
            'Interrompido pelo Kill Switch global; contenção temporária revertida e encaminhamento preservado.';
          abortedCount += 1;
        }
      }

      this.addAudit({
        eventType: 'kill_switch.triggered',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'global-kill-switch',
        outcome: 'success',
        detail: `Parada de Emergência acionada: ${abortedCount} ação(ões) revertidas, autonomia travada em L0. Tráfego do gateway preservado.`,
      });

      void this.dispatchAlertToDestinations(
        {
          trigger: 'kill_switch',
          severity: 'critical',
          title: 'Parada de Emergência (Kill Switch) Acionada',
          summary: `Kill Switch ativado por ${this.currentActor().actor}. ${abortedCount} ação(ões) revertidas e autonomia travada em L0.`,
          source: 'kill-switch',
          occurredAt: new Date().toISOString(),
        },
        ['kill_switch'],
      );
    } else {
      this.assertCanMutate('policy_admin');
      this.state.context.killSwitchActive = false;
      this.addAudit({
        eventType: 'kill_switch.reset',
        actor: this.currentActor().actor,
        role: this.currentActor().role,
        targetId: 'global-kill-switch',
        outcome: 'success',
        detail:
          'Kill Switch liberado pelo administrador; sistema permanece em L0 (Observar) até ajuste explícito.',
      });
    }

    this.notify();
    return this.getState();
  }

  private meetsSeverityThreshold(
    actual: EventSeverity,
    min: NotificationSeverityThreshold,
  ): boolean {
    const rank: Record<EventSeverity, number> = {
      info: 0,
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    const thresholdRank: Record<NotificationSeverityThreshold, number> = {
      medium: 2,
      high: 3,
      critical: 4,
    };
    return rank[actual] >= thresholdRank[min];
  }

  private async dispatchAlertToDestinations(
    payload: AlertDispatchPayload,
    matchTriggers: NotificationTriggerEvent[],
  ): Promise<void> {
    const targets = (this.state.notifications ?? []).filter(
      (dest) =>
        dest.enabled &&
        dest.triggers.some((t) => matchTriggers.includes(t)) &&
        this.meetsSeverityThreshold(payload.severity, dest.minSeverity),
    );
    if (targets.length === 0) return;

    this.state.notificationHistory ??= [];
    for (const dest of targets) {
      const cred = this.persistence.getServiceCredential(`notif:${dest.id}`);
      const outcome = await deliverNotification(dest, payload, {
        username: cred?.username || dest.usernameHint,
        secret: cred?.secret,
      });
      const nowIso = new Date().toISOString();
      dest.lastDispatchedAt = nowIso;
      dest.lastDispatchStatus = outcome.status;
      dest.lastDispatchMessage = outcome.message;

      const record: NotificationDispatchRecord = {
        id: `ntf-log-${crypto.randomUUID().slice(0, 8)}`,
        destinationId: dest.id,
        destinationName: dest.name,
        channelType: dest.type,
        trigger: payload.trigger,
        severity: payload.severity,
        title: payload.title,
        status: outcome.status,
        detail: outcome.message,
        dispatchedAt: nowIso,
      };
      this.state.notificationHistory.unshift(record);
      if (this.state.notificationHistory.length > 50) {
        this.state.notificationHistory.length = 50;
      }

      this.addAudit({
        eventType: 'notification.dispatched',
        actor: 'openshield-notifier',
        role: 'system',
        targetId: dest.id,
        outcome: outcome.status === 'sent' ? 'success' : 'denied',
        detail: `Alerta "${payload.title}" -> ${dest.name} (${dest.type}): ${outcome.message}`,
      });
    }
    this.notify();
  }

  addNotificationDestination(input: {
    name: string;
    type: NotificationChannelType;
    target: string;
    enabled?: boolean;
    minSeverity?: NotificationSeverityThreshold;
    triggers?: NotificationTriggerEvent[];
    emailFrom?: string;
    smtpHost?: string;
    smtpPort?: number;
    smtpSecure?: boolean;
    webhookMethod?: 'POST' | 'PUT';
    webhookFormat?: 'openshield_json' | 'slack' | 'discord';
    username?: string;
    secret?: string;
  }): WorkspaceState {
    this.assertCanMutate('operator');
    const name = input.name?.trim();
    const target = input.target?.trim();
    if (!name || !target) {
      throw new Error('Nome do destino e endereço/ID de destino são obrigatórios.');
    }

    if (input.type === 'email') {
      if (!target.includes('@')) {
        throw new Error('Informe um endereço de e-mail destinatário válido.');
      }
      if (!input.smtpHost?.trim()) {
        throw new Error('Informe o servidor SMTP (host) para notificações por e-mail.');
      }
    } else if (input.type === 'webhook') {
      if (!/^https?:\/\//i.test(target)) {
        throw new Error('A URL do Webhook deve começar com http:// ou https://.');
      }
    } else if (input.type === 'telegram') {
      if (!input.secret?.trim()) {
        throw new Error('Informe o Bot Token do Telegram para salvar no cofre do servidor.');
      }
    }

    const triggers: NotificationTriggerEvent[] =
      Array.isArray(input.triggers) && input.triggers.length > 0
        ? Array.from(new Set(input.triggers))
        : ['critical_incident', 'kill_switch', 'endpoint_offline'];

    const id = `notif-${input.type}-${crypto.randomUUID().slice(0, 6)}`;
    const dest: NotificationDestination = {
      id,
      name,
      type: input.type,
      enabled: input.enabled ?? true,
      minSeverity: input.minSeverity ?? 'high',
      triggers,
      target,
      emailFrom: input.emailFrom?.trim() || undefined,
      smtpHost: input.smtpHost?.trim() || undefined,
      smtpPort: input.smtpPort ? Number(input.smtpPort) : undefined,
      smtpSecure: typeof input.smtpSecure === 'boolean' ? input.smtpSecure : undefined,
      webhookMethod: input.webhookMethod === 'PUT' ? 'PUT' : 'POST',
      webhookFormat: input.webhookFormat ?? 'openshield_json',
      createdAt: new Date().toISOString(),
    };

    if (input.username?.trim() || input.secret?.trim()) {
      this.persistence.setServiceCredential(
        `notif:${id}`,
        (input.username ?? '').trim(),
        input.secret ?? '',
      );
    }

    this.state.notifications ??= [];
    this.state.notifications.unshift(dest);

    this.addAudit({
      eventType: 'notification.added',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Destino de alerta "${name}" (${input.type} -> ${target}) configurado para severidade >= ${dest.minSeverity}.`,
    });
    this.notify();
    return this.getState();
  }

  updateNotificationDestination(
    id: string,
    patch: {
      name?: string;
      enabled?: boolean;
      minSeverity?: NotificationSeverityThreshold;
      triggers?: NotificationTriggerEvent[];
      target?: string;
      emailFrom?: string;
      smtpHost?: string;
      smtpPort?: number;
      smtpSecure?: boolean;
      webhookMethod?: 'POST' | 'PUT';
      webhookFormat?: 'openshield_json' | 'slack' | 'discord';
      username?: string;
      secret?: string;
      clearSecret?: boolean;
    },
  ): WorkspaceState {
    this.assertCanMutate('operator');
    this.state.notifications ??= [];
    const dest = this.state.notifications.find((d) => d.id === id);
    if (!dest) {
      throw new Error(`Destino de notificação "${id}" não encontrado.`);
    }

    if (patch.name !== undefined && patch.name.trim()) dest.name = patch.name.trim();
    if (typeof patch.enabled === 'boolean') dest.enabled = patch.enabled;
    if (patch.minSeverity) dest.minSeverity = patch.minSeverity;
    if (Array.isArray(patch.triggers) && patch.triggers.length > 0) {
      dest.triggers = Array.from(new Set(patch.triggers));
    }
    if (patch.target !== undefined && patch.target.trim()) {
      if (dest.type === 'webhook' && !/^https?:\/\//i.test(patch.target.trim())) {
        throw new Error('A URL do Webhook deve começar com http:// ou https://.');
      }
      if (dest.type === 'email' && !patch.target.trim().includes('@')) {
        throw new Error('Informe um endereço de e-mail destinatário válido.');
      }
      dest.target = patch.target.trim();
    }
    if (patch.emailFrom !== undefined) dest.emailFrom = patch.emailFrom.trim() || undefined;
    if (patch.smtpHost !== undefined) dest.smtpHost = patch.smtpHost.trim() || undefined;
    if (patch.smtpPort !== undefined) dest.smtpPort = Number(patch.smtpPort) || undefined;
    if (typeof patch.smtpSecure === 'boolean') dest.smtpSecure = patch.smtpSecure;
    if (patch.webhookMethod) dest.webhookMethod = patch.webhookMethod;
    if (patch.webhookFormat) dest.webhookFormat = patch.webhookFormat;

    if (patch.clearSecret) {
      this.persistence.deleteServiceCredential(`notif:${id}`);
      dest.usernameHint = undefined;
    } else if (patch.username !== undefined || (patch.secret !== undefined && patch.secret !== '')) {
      const existing = this.persistence.getServiceCredential(`notif:${id}`);
      const nextUser = patch.username !== undefined ? patch.username.trim() : (existing?.username ?? '');
      const nextSecret =
        patch.secret !== undefined && patch.secret !== '' ? patch.secret : (existing?.secret ?? '');
      this.persistence.setServiceCredential(`notif:${id}`, nextUser, nextSecret);
    }

    this.addAudit({
      eventType: 'notification.updated',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Destino "${dest.name}" (${dest.type}) atualizado (${dest.enabled ? 'ativo' : 'pausado'}, severidade >= ${dest.minSeverity}).`,
    });
    this.notify();
    return this.getState();
  }

  removeNotificationDestination(id: string): WorkspaceState {
    this.assertCanMutate('operator');
    this.state.notifications ??= [];
    const idx = this.state.notifications.findIndex((d) => d.id === id);
    if (idx < 0) {
      throw new Error(`Destino de notificação "${id}" não encontrado.`);
    }
    const [removed] = this.state.notifications.splice(idx, 1);
    this.persistence.deleteServiceCredential(`notif:${id}`);

    this.addAudit({
      eventType: 'notification.removed',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Destino de notificação "${removed.name}" (${removed.type}) removido e segredo apagado.`,
    });
    this.notify();
    return this.getState();
  }

  async testNotificationDestination(
    id: string,
  ): Promise<{ status: 'sent' | 'failed'; message: string; state: WorkspaceState }> {
    this.assertCanMutate('operator');
    this.state.notifications ??= [];
    const dest = this.state.notifications.find((d) => d.id === id);
    if (!dest) {
      throw new Error(`Destino de notificação "${id}" não encontrado.`);
    }

    const cred = this.persistence.getServiceCredential(`notif:${dest.id}`);
    const nowIso = new Date().toISOString();
    const payload: AlertDispatchPayload = {
      trigger: 'critical_incident',
      severity: 'high',
      title: `Teste de Notificação OpenShield (${dest.name})`,
      summary:
        'Alerta de verificação disparado pelo backend OpenShield. O canal permanecerá ativo mesmo com a dashboard fechada.',
      source: 'openshield-settings-test',
      occurredAt: nowIso,
      siteId: this.state.context.activeSiteId,
    };

    const outcome = await deliverNotification(dest, payload, {
      username: cred?.username || dest.usernameHint,
      secret: cred?.secret,
    });

    dest.lastDispatchedAt = nowIso;
    dest.lastDispatchStatus = outcome.status;
    dest.lastDispatchMessage = outcome.message;

    this.state.notificationHistory ??= [];
    this.state.notificationHistory.unshift({
      id: `ntf-log-${crypto.randomUUID().slice(0, 8)}`,
      destinationId: dest.id,
      destinationName: dest.name,
      channelType: dest.type,
      trigger: 'critical_incident',
      severity: 'high',
      title: payload.title,
      status: outcome.status,
      detail: outcome.message,
      dispatchedAt: nowIso,
    });
    if (this.state.notificationHistory.length > 50) {
      this.state.notificationHistory.length = 50;
    }

    this.addAudit({
      eventType: 'notification.tested',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: dest.id,
      outcome: outcome.status === 'sent' ? 'success' : 'denied',
      detail: `Teste manual de alerta para "${dest.name}" (${dest.type}): ${outcome.message}`,
    });
    this.notify();
    return { ...outcome, state: this.getState() };
  }

  renderPrometheusMetrics(): string {
    const m = this.state.metrics;
    return [
      '# HELP openshield_http_requests_total Total de requisições HTTP processadas pelo BFF/Node.',
      '# TYPE openshield_http_requests_total counter',
      `openshield_http_requests_total ${m.httpRequestsTotal}`,
      '# HELP openshield_events_ingested_total Total de eventos normalizados openshield.event.v1 ingeridos.',
      '# TYPE openshield_events_ingested_total counter',
      `openshield_events_ingested_total ${m.eventsIngestedTotal}`,
      '# HELP openshield_gateway_connections_total Total de handshakes openshield.gateway.v1 aceitos.',
      '# TYPE openshield_gateway_connections_total counter',
      `openshield_gateway_connections_total ${m.gatewayConnectionsTotal}`,
      '# HELP openshield_gateway_heartbeats_total Total de heartbeats de presença recebidos.',
      '# TYPE openshield_gateway_heartbeats_total counter',
      `openshield_gateway_heartbeats_total ${m.gatewayHeartbeatsTotal}`,
      '# HELP openshield_authorization_denied_total Tentativas bloqueadas por proveniência inválida ou política.',
      '# TYPE openshield_authorization_denied_total counter',
      `openshield_authorization_denied_total ${m.authorizationDeniedTotal}`,
      '# HELP openshield_connector_outbox_pending Eventos pendentes no spool SQLite do conector.',
      '# TYPE openshield_connector_outbox_pending gauge',
      `openshield_connector_outbox_pending ${m.outboxPendingTotal}`,
    ].join('\n');
  }

  addSite(input: { name: string; profile: OperatingContext['profile'] }): WorkspaceState {
    this.assertCanMutate('operator');
    const name = input.name.trim();
    if (!name) {
      throw new Error('Nome do site ou rede é obrigatório.');
    }
    const id = `site-${name.toLowerCase().replace(/[^a-z0-9]/g, '-').slice(0, 20)}-${crypto.randomUUID().slice(0, 4)}`;
    this.state.context.sites.push({ id, name, profile: input.profile });
    this.addAudit({
      eventType: 'site.added',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: id,
      outcome: 'success',
      detail: `Site "${name}" (${input.profile === 'residential' ? 'Residencial' : 'Escritório'}) adicionado.`,
    });
    this.notify();
    return this.getState();
  }

  removeSite(siteId: string): WorkspaceState {
    this.assertCanMutate('operator');
    const target = this.state.context.sites.find((s) => s.id === siteId);
    if (!target) {
      throw new Error(`Site "${siteId}" não encontrado.`);
    }
    if (this.state.context.activeSiteId === siteId) {
      throw new Error('Não é possível remover o site atualmente selecionado como ativo.');
    }
    const sameProfileCount = this.state.context.sites.filter(
      (s) => s.profile === target.profile,
    ).length;
    if (sameProfileCount <= 1) {
      throw new Error('Cada perfil precisa manter pelo menos um site configurado.');
    }
    this.state.context.sites = this.state.context.sites.filter((s) => s.id !== siteId);
    this.addAudit({
      eventType: 'site.removed',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: siteId,
      outcome: 'success',
      detail: `Site "${target.name}" removido da configuração multi-site.`,
    });
    this.notify();
    return this.getState();
  }

  exportSanitizedBackup(): {
    version: 'openshield.backup.v1';
    exportedAt: string;
    context: {
      profile: OperatingContext['profile'];
      globalAutonomy: AutonomyLevel;
      cloudAiOptIn: boolean;
      activeSiteId: string;
      sites: OperatingContext['sites'];
    };
    integrations: Array<Omit<IntegrationAdapter, 'hasCredential' | 'usernameHint'>>;
    devices: NetworkDevice[];
    policies: PolicyRule[];
    dnsInsights: DnsInsight[];
  } {
    const cleanIntegrations = this.state.integrations.map(
      ({ hasCredential: _hc, usernameHint: _uh, ...rest }) => rest,
    );
    return {
      version: 'openshield.backup.v1',
      exportedAt: new Date().toISOString(),
      context: {
        profile: this.state.context.profile,
        globalAutonomy: this.state.context.globalAutonomy,
        cloudAiOptIn: this.state.context.cloudAiOptIn,
        activeSiteId: this.state.context.activeSiteId,
        sites: structuredClone(this.state.context.sites),
      },
      integrations: structuredClone(cleanIntegrations),
      devices: structuredClone(this.state.devices),
      policies: structuredClone(this.state.policies),
      dnsInsights: structuredClone(this.state.dnsInsights),
    };
  }

  restoreSanitizedBackup(payload: {
    version?: string;
    context?: {
      profile?: OperatingContext['profile'];
      globalAutonomy?: AutonomyLevel;
      cloudAiOptIn?: boolean;
      activeSiteId?: string;
      sites?: OperatingContext['sites'];
    };
    integrations?: Array<Record<string, unknown>>;
    devices?: NetworkDevice[];
    policies?: PolicyRule[];
    dnsInsights?: DnsInsight[];
  }): WorkspaceState {
    this.assertCanMutate('admin');
    if (payload.version !== 'openshield.backup.v1') {
      throw new Error('Arquivo de backup inválido: versão esperada openshield.backup.v1.');
    }
    if (!Array.isArray(payload.integrations) || !Array.isArray(payload.devices)) {
      throw new Error('Estrutura de backup inválida: listas de integrações e dispositivos ausentes.');
    }

    if (payload.context?.sites && payload.context.sites.length > 0) {
      this.state.context.sites = payload.context.sites.map((s) => ({
        id: String(s.id),
        name: String(s.name),
        profile: s.profile === 'business' ? 'business' : 'residential',
      }));
    }
    if (payload.context?.profile) {
      this.state.context.profile = payload.context.profile === 'business' ? 'business' : 'residential';
    }
    if (payload.context?.activeSiteId && this.state.context.sites.some((s) => s.id === payload.context?.activeSiteId)) {
      this.state.context.activeSiteId = payload.context.activeSiteId;
    } else if (this.state.context.sites[0]) {
      this.state.context.activeSiteId = this.state.context.sites[0].id;
    }
    if (typeof payload.context?.cloudAiOptIn === 'boolean') {
      this.state.context.cloudAiOptIn = payload.context.cloudAiOptIn;
    }

    this.state.integrations = payload.integrations.map((raw) => {
      const sanitized: Record<string, unknown> = { ...raw };
      delete sanitized.secret;
      delete sanitized.password;
      delete sanitized.token;
      delete sanitized.apiKey;
      delete sanitized.hasCredential;
      delete sanitized.usernameHint;
      return sanitized as unknown as IntegrationAdapter;
    });

    this.state.devices = structuredClone(payload.devices);
    if (Array.isArray(payload.policies) && payload.policies.length > 0) {
      this.state.policies = structuredClone(payload.policies);
    }
    if (Array.isArray(payload.dnsInsights)) {
      this.state.dnsInsights = structuredClone(payload.dnsInsights);
    }

    this.addAudit({
      eventType: 'workspace.restored',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: 'workspace-backup',
      outcome: 'success',
      detail: `Backup sanitizado restaurado (${this.state.integrations.length} serviços, ${this.state.devices.length} dispositivos). Credenciais locais devem ser conferidas se necessário.`,
    });
    this.notify();
    return this.getState();
  }

  loadDemoScenario(): WorkspaceState {
    this.assertCanMutate('operator');
    this.persistence.clearAllCredentials();
    this.persistence.clearEventsStore();
    const demo = this.createDemoState();
    demo.context.profile = this.state.context.profile;
    demo.context.simulatedRole = this.state.context.simulatedRole;
    demo.context.activeSiteId = this.state.context.activeSiteId;
    this.state = demo;
    for (const ev of this.state.events) {
      this.persistence.persistEvent(ev);
    }
    this.addAudit({
      eventType: 'workspace.demo_loaded',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: 'demo-scenario',
      outcome: 'simulated',
      detail: 'Cenário de demonstração Mock carregado (editável e removível livremente).',
    });
    this.notify();
    return this.getState();
  }

  resetWorkspace(): WorkspaceState {
    this.assertCanMutate('operator');
    this.persistence.clearAllCredentials();
    this.persistence.clearEventsStore();
    const clean = this.createInitialState();
    clean.context.profile = this.state.context.profile;
    clean.context.simulatedRole = this.state.context.simulatedRole;
    clean.context.activeSiteId = this.state.context.activeSiteId;
    this.state = clean;
    this.addAudit({
      eventType: 'workspace.reset',
      actor: this.currentActor().actor,
      role: this.currentActor().role,
      targetId: 'workspace',
      outcome: 'success',
      detail: 'Inventário de serviços e dispositivos zerado pelo usuário.',
    });
    this.notify();
    return this.getState();
  }

  private createInitialState(): WorkspaceState {
    const policies: PolicyRule[] = [
      {
        id: 'pol-dns-tracker',
        name: 'Bloqueio DNS de Rastreadores Comprovados',
        description:
          'Adiciona domínios classificados como telemetria abusiva às listas de bloqueio dos servidores Pi-hole.',
        eventPattern: 'dns.query · classification=tracker',
        maxAutonomyLevel: 'L1',
        maxScope: 'Apenas domínio específico nos servidores DNS ativos',
        defaultTtlSeconds: 1800,
        rollbackSupported: true,
        enabled: true,
      },
      {
        id: 'pol-iot-quarantine',
        name: 'Contenção Temporária de Saída Anômala IoT',
        description:
          'Bloqueia porta e IP externo específico no firewall nftables mantendo acesso local e encaminhamento geral.',
        eventPattern: 'ids.alert + threat.ioc · segment=IoT',
        maxAutonomyLevel: 'L2',
        maxScope: '1 dispositivo IoT · 1 destino/porta por até 30 min',
        defaultTtlSeconds: 900,
        rollbackSupported: true,
        enabled: true,
      },
      {
        id: 'pol-host-isolate',
        name: 'Isolamento Completo de Estação de Trabalho',
        description:
          'Isola completamente um host corporativo na VLAN de quarentena. Requer aprovação humana.',
        eventPattern: 'severity=critical · segment=Escritório',
        maxAutonomyLevel: 'L3',
        maxScope: '1 estação de trabalho (requer aprovação Administrador)',
        defaultTtlSeconds: 1800,
        rollbackSupported: true,
        enabled: true,
      },
    ];

    return {
      context: {
        profile: 'residential',
        simulatedRole: 'admin',
        globalAutonomy: 'L0',
        killSwitchActive: false,
        nodeAvailable: true,
        gatewayForwardingActive: true,
        cloudAiOptIn: false,
        activeSiteId: 'site-home',
        sites: [
          { id: 'site-home', name: 'Residência Principal', profile: 'residential' },
          { id: 'site-office-sp', name: 'Escritório Centro (Matriz)', profile: 'business' },
          { id: 'site-office-filial', name: 'Escritório Coworking (Filial)', profile: 'business' },
        ],
        aiSensitivity: { ...DEFAULT_AI_SENSITIVITY },
      },
      integrations: [],
      devices: [],
      events: [],
      dnsInsights: [],
      incidents: [],
      policies,
      executions: [],
      auditLog: [
        {
          id: 'aud-init-01',
          timestamp: new Date().toISOString(),
          eventType: 'context.updated',
          actor: 'openshield-core',
          role: 'system',
          targetId: 'workspace',
          outcome: 'success',
          detail: 'OpenShield pronto: adicione seus serviços e dispositivos em Configurações.',
          profile: 'residential',
        },
      ],
      metrics: {
        httpRequestsTotal: 0,
        eventsIngestedTotal: 0,
        gatewayConnectionsTotal: 0,
        gatewayHeartbeatsTotal: 0,
        authorizationDeniedTotal: 0,
        outboxPendingTotal: 0,
      },
      latencyHistory: [],
      notifications: [],
      notificationHistory: [],
      aiUsageHistory: [],
    };
  }

  private createDemoState(): WorkspaceState {
    const events: OpenShieldEventV1[] = [
      {
        eventId: 'ev-8f21a104',
        schemaVersion: 'openshield.event.v1',
        occurredAt: minutesAgoIso(4),
        sourceIntegrationId: 'suricata-lan',
        eventType: 'ids.alert',
        severity: 'high',
        deviceId: 'dev-cam-04',
        dataSource: 'mock',
        summary:
          'Tentativa repetida de conexão de saída para porta SSH/2222 não usual a partir da Câmera Garagem.',
        payload: {
          signature: 'ET POLICY Outbound SSH on non-standard port',
          dstPort: 2222,
          proto: 'TCP',
          srcIp: '192.168.10.44',
          externalIndicator: '185.220.101.42',
        },
      },
      {
        eventId: 'ev-7b40e219',
        schemaVersion: 'openshield.event.v1',
        occurredAt: minutesAgoIso(5),
        sourceIntegrationId: 'crowdsec-ti',
        eventType: 'threat.ioc',
        severity: 'high',
        deviceId: 'dev-cam-04',
        dataSource: 'mock',
        summary:
          'IP externo 185.220.101.42 listado na base comunitária CrowdSec por varredura de credenciais IoT.',
        payload: {
          indicator: '185.220.101.42',
          reputation: 'malicious',
          confidence: 0.91,
          scenario: 'crowdsecurity/ssh-bf',
        },
      },
      {
        eventId: 'ev-5c11d090',
        schemaVersion: 'openshield.event.v1',
        occurredAt: minutesAgoIso(9),
        sourceIntegrationId: 'pihole-dns-1',
        eventType: 'dns.query',
        severity: 'medium',
        deviceId: 'dev-tv-sala',
        dataSource: 'mock',
        summary:
          'Smart TV realizou 184 consultas em 10 minutos para domínio de telemetria e rastreamento.',
        payload: {
          domain: 'metrics-eu.smartview-telemetry.example',
          queryType: 'A',
          action: 'blocked',
          queriesInWindow: 184,
        },
      },
      {
        eventId: 'ev-4a09c871',
        schemaVersion: 'openshield.event.v1',
        occurredAt: minutesAgoIso(12),
        sourceIntegrationId: 'zeek-meta',
        eventType: 'zeek.connection',
        severity: 'low',
        deviceId: 'dev-ws-office',
        dataSource: 'mock',
        summary:
          'Sessão TLS estabelecida para atualização corporativa sem anomalia de certificado.',
        payload: {
          service: 'ssl',
          bytesSent: 14820,
          bytesRecv: 192440,
          srcIp: '192.168.1.52',
        },
      },
      {
        eventId: 'ev-1d02b112',
        schemaVersion: 'openshield.event.v1',
        occurredAt: minutesAgoIso(18),
        sourceIntegrationId: 'home-gateway',
        eventType: 'gateway.discovery',
        severity: 'info',
        dataSource: 'mock',
        summary:
          'Descoberta de placa e interfaces OpenWrt (br-lan, eth0.2, wg0) concluída via rpcd/ubus.',
        payload: {
          board: 'FriendlyElec NanoPi R4S',
          release: 'OpenWrt 23.05.4',
          interfaces: ['br-lan', 'wan', 'iot-vlan'],
        },
      },
    ];

    const devices = [
      {
        id: 'dev-gw-01',
        hostname: 'openwrt-nanopi-r4s',
        ip: '192.168.1.1',
        mac: 'E4:5F:01:88:1A:01',
        vendor: 'FriendlyElec / OpenWrt',
        interfaceName: 'br-lan',
        segment: 'LAN Confiável' as const,
        siteId: 'site-home',
        riskScore: 8,
        status: 'nominal' as const,
        lastSeenAt: minutesAgoIso(1),
        dnsQueries24h: 410,
        blockedQueries24h: 4,
        deviceType: 'router' as const,
      },
      {
        id: 'dev-cam-04',
        hostname: 'cam-garagem-ip04',
        ip: '192.168.10.44',
        mac: 'B8:27:EB:44:91:0C',
        vendor: 'Shenzhen CamTech',
        interfaceName: 'iot-vlan',
        segment: 'IoT / Convidados' as const,
        siteId: 'site-home',
        riskScore: 84,
        status: 'attention' as const,
        lastSeenAt: minutesAgoIso(2),
        dnsQueries24h: 1290,
        blockedQueries24h: 312,
        deviceType: 'iot' as const,
      },
      {
        id: 'dev-tv-sala',
        hostname: 'smart-tv-sala',
        ip: '192.168.10.21',
        mac: 'A4:77:33:12:09:FE',
        vendor: 'LGE Electronics',
        interfaceName: 'iot-vlan',
        segment: 'IoT / Convidados' as const,
        siteId: 'site-home',
        riskScore: 46,
        status: 'attention' as const,
        lastSeenAt: minutesAgoIso(3),
        dnsQueries24h: 4820,
        blockedQueries24h: 2140,
        deviceType: 'iot' as const,
      },
      {
        id: 'dev-ws-office',
        hostname: 'estacao-financas-01',
        ip: '192.168.1.52',
        mac: '3C:22:FB:90:11:7A',
        vendor: 'Apple Inc.',
        interfaceName: 'br-lan',
        segment: 'Escritório / VPN' as const,
        siteId: 'site-office-sp',
        riskScore: 12,
        status: 'nominal' as const,
        lastSeenAt: minutesAgoIso(2),
        dnsQueries24h: 2950,
        blockedQueries24h: 188,
        deviceType: 'workstation' as const,
      },
      {
        id: 'dev-nas-01',
        hostname: 'nas-backups-local',
        ip: '192.168.1.20',
        mac: '00:11:32:AA:55:09',
        vendor: 'Synology Inc.',
        interfaceName: 'br-lan',
        segment: 'LAN Confiável' as const,
        siteId: 'site-home',
        riskScore: 10,
        status: 'nominal' as const,
        lastSeenAt: minutesAgoIso(1),
        dnsQueries24h: 640,
        blockedQueries24h: 12,
        deviceType: 'server' as const,
      },
    ];

    const incidents: Incident[] = [
      {
        id: 'inc-2026-001',
        title: 'Conexão de saída suspeita em dispositivo IoT correlacionada com IOC CrowdSec',
        summary:
          'A câmera IP da garagem tentou conexões SSH repetidas na porta 2222 para um endereço listado por varredura de força bruta.',
        severity: 'high',
        status: 'open',
        riskScore: 84,
        riskFactors: [
          'Alerta IDS Suricata (ET POLICY Outbound SSH) em segmento IoT',
          'Correspondência positiva no feed CrowdSec (confiança 91%)',
          'Dispositivo IoT sem necessidade operacional de conexões SSH de saída',
        ],
        deviceId: 'dev-cam-04',
        deviceHostname: 'cam-garagem-ip04',
        siteId: 'site-home',
        dataSource: 'mock',
        eventIds: ['ev-8f21a104', 'ev-7b40e219'],
        timeline: [
          {
            timestamp: minutesAgoIso(5),
            sourceIntegrationId: 'crowdsec-ti',
            eventId: 'ev-7b40e219',
            description:
              'Indicador 185.220.101.42 marcado com reputação maliciosa no feed comunitário.',
            severity: 'high',
          },
          {
            timestamp: minutesAgoIso(4),
            sourceIntegrationId: 'suricata-lan',
            eventId: 'ev-8f21a104',
            description:
              'Suricata detectou 6 tentativas de conexão TCP/2222 vindas de cam-garagem-ip04.',
            severity: 'high',
          },
        ],
        recommendedPolicyId: 'pol-iot-quarantine',
        recommendedAction:
          'Aplicar bloqueio temporário de saída TCP/2222 para IP externo (TTL 15 min)',
        investigation: {
          provider: 'local-ollama-mock',
          modelVersion: 'llama3.1:8b-instruct (local-first simulado)',
          promptTemplateVersion: 'openshield.local.v1.4',
          generatedAt: minutesAgoIso(3),
          confidence: 'alta',
          observedFacts: [
            '6 pacotes SYN de saída da interface iot-vlan para 185.220.101.42:2222 registrados pelo Suricata.',
            'Feed CrowdSec classifica o destino como originador de varredura ssh-bf.',
          ],
          inferredHypotheses: [
            'Possível firmware desatualizado tentando callback para servidor remoto não autorizado.',
            'Baixa probabilidade de tráfego administrativo legítimo por estar na sub-rede IoT.',
          ],
          recommendedSteps: [
            'Simular ou aplicar bloqueio temporário L2 com TTL de 900s via nftables.',
            'Verificar versão de firmware da câmera e restringir DNS/saída da VLAN IoT.',
          ],
          sanitizedPayloadPreview:
            '{\n  "incidentTitle": "Conexão de saída suspeita em [DISPOSITIVO_INTERNO]",\n  "severity": "high",\n  "riskScore": 84\n}',
          promptInjectionGuardNote:
            'Análise local-first concluída sem envio externo; evidências delimitadas contra prompt injection.',
        },
      },
      {
        id: 'inc-2026-002',
        title: 'Pico de telemetria DNS em Smart TV bloqueado pelo Pi-hole',
        summary:
          'Volume elevado de requisições periódicas para domínio de rastreamento publicitário na sala.',
        severity: 'medium',
        status: 'investigating',
        riskScore: 46,
        riskFactors: [
          '184 consultas em janela de 10 minutos',
          'Domínio categorizado como Telemetria & Rastreador',
        ],
        deviceId: 'dev-tv-sala',
        deviceHostname: 'smart-tv-sala',
        siteId: 'site-home',
        dataSource: 'mock',
        eventIds: ['ev-5c11d090'],
        timeline: [
          {
            timestamp: minutesAgoIso(9),
            sourceIntegrationId: 'pihole-dns-1',
            eventId: 'ev-5c11d090',
            description:
              'Pi-hole Primário interceptou rajada de consultas para metrics-eu.smartview-telemetry.example.',
            severity: 'medium',
          },
        ],
        recommendedPolicyId: 'pol-dns-tracker',
        recommendedAction: 'Manter domínio na lista de bloqueio DNS (baixo impacto L1)',
        investigation: {
          provider: 'local-ollama-mock',
          modelVersion: 'llama3.1:8b-instruct (local-first simulado)',
          promptTemplateVersion: 'openshield.local.v1.4',
          generatedAt: minutesAgoIso(8),
          confidence: 'alta',
          observedFacts: [
            'Pi-hole já bloqueou 100% das 184 tentativas recentes sem quebra de streaming.',
          ],
          inferredHypotheses: [
            'Comportamento padrão de SDK de telemetria tentando retentativas após bloqueio DNS.',
          ],
          recommendedSteps: [
            'Manter bloqueio na lista de privacidade e observar tendência nas próximas 24h.',
          ],
          promptInjectionGuardNote:
            'Análise local-first concluída sem envio externo; evidências delimitadas contra prompt injection.',
        },
      },
    ];

    return {
      context: {
        profile: 'residential',
        simulatedRole: 'admin',
        globalAutonomy: 'L0',
        killSwitchActive: false,
        nodeAvailable: true,
        gatewayForwardingActive: true,
        cloudAiOptIn: false,
        activeSiteId: 'site-home',
        sites: [
          { id: 'site-home', name: 'Residência Principal', profile: 'residential' },
          { id: 'site-office-sp', name: 'Escritório Centro (Matriz)', profile: 'business' },
          { id: 'site-office-filial', name: 'Escritório Coworking (Filial)', profile: 'business' },
        ],
        aiSensitivity: { ...DEFAULT_AI_SENSITIVITY },
      },
      integrations: [
        {
          id: 'home-gateway',
          name: 'OpenWrt Gateway Connector',
          domain: 'gateway',
          kind: 'openwrt-rpcd',
          description:
            'Conector fora do caminho de pacotes (rpcd/ubus somente leitura ou OpenShield Node FastAPI).',
          protocolVersion: 'openshield.gateway.v1',
          mode: 'mock',
          liveEndpointUrl: process.env.OPENSHIELD_OPENWRT_URL || '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(1),
          lastLatencyMs: 6,
          capabilities: ['discover', 'health_check'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-home',
          boardInfo: {
            model: 'FriendlyElec NanoPi R4S',
            firmware: 'OpenWrt 23.05.4',
            interfaces: ['br-lan', 'wan', 'iot-vlan'],
          },
          lastLiveCheckMessage: 'Aguardando preenchimento da URL na página Configurações.',
        },
        {
          id: 'pihole-dns-1',
          name: 'Pi-hole Primário (DNS 1)',
          domain: 'dns',
          kind: 'pihole-v6',
          description:
            'Servidor DNS principal: telemetria de consultas, bloqueio de rastreadores e sincronização de listas.',
          protocolVersion: 'openshield.adapter.v1',
          mode: 'mock',
          liveEndpointUrl: process.env.OPENSHIELD_PIHOLE_URL || '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(1),
          lastLatencyMs: 4,
          capabilities: ['health_check', 'read_events', 'read_configuration', 'write_configuration'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-home',
          lastLiveCheckMessage: 'Aguardando preenchimento da URL na página Configurações.',
        },
        {
          id: 'pihole-dns-2',
          name: 'Pi-hole Secundário (DNS 2)',
          domain: 'dns',
          kind: 'pihole-v6',
          description:
            'Segundo servidor Pi-hole para redundância DNS ou separação entre residência e escritório.',
          protocolVersion: 'openshield.adapter.v1',
          mode: 'mock',
          liveEndpointUrl: '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(2),
          lastLatencyMs: 11,
          capabilities: ['health_check', 'read_events', 'read_configuration', 'write_configuration'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-office-sp',
          lastLiveCheckMessage: 'Aguardando preenchimento da URL na página Configurações.',
        },
        {
          id: 'suricata-lan',
          name: 'Suricata IDS Sensor',
          domain: 'ids',
          kind: 'suricata-eve',
          description:
            'Alertas de protocolo e assinaturas de ameaça via espelhamento/TAP passivo ou ingestão LAN.',
          protocolVersion: 'openshield.adapter.v1',
          mode: 'mock',
          liveEndpointUrl: '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(2),
          lastLatencyMs: 9,
          capabilities: ['health_check', 'read_events'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-home',
        },
        {
          id: 'zeek-meta',
          name: 'Zeek Network Metadata',
          domain: 'analytics',
          kind: 'zeek-json',
          description: 'Metadados comportamentais de conexões, sessões TLS e fluxos.',
          protocolVersion: 'openshield.adapter.v1',
          mode: 'mock',
          liveEndpointUrl: '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(3),
          lastLatencyMs: 14,
          capabilities: ['health_check', 'read_events'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-office-sp',
        },
        {
          id: 'crowdsec-ti',
          name: 'CrowdSec Threat Intel',
          domain: 'threat_intel',
          kind: 'crowdsec-lapi',
          description: 'Reputação comunitária e correlação de IPs maliciosos (IOCs).',
          protocolVersion: 'openshield.adapter.v1',
          mode: 'mock',
          liveEndpointUrl: '',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(2),
          lastLatencyMs: 19,
          capabilities: ['health_check', 'read_events'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-home',
        },
        {
          id: 'ollama-local',
          name: 'Ollama Local AI Runtime',
          domain: 'ai_runtime',
          kind: 'ollama-http',
          description: 'Inferência local-first sem saída de dados da LAN confiável.',
          protocolVersion: 'openshield.ai.v1',
          mode: 'mock',
          liveEndpointUrl: process.env.OPENSHIELD_OLLAMA_URL || '',
          modelName: process.env.OPENSHIELD_OLLAMA_MODEL || 'llama3.1:8b',
          timeoutMs: 5000,
          status: 'connected',
          lastHeartbeatAt: minutesAgoIso(1),
          lastLatencyMs: 28,
          capabilities: ['health_check'],
          outboxQueueCount: 0,
          outboxCapacity: 10000,
          siteId: 'site-home',
        },
      ],
      devices,
      events,
      dnsInsights: [
        {
          id: 'dns-1',
          domain: 'metrics-eu.smartview-telemetry.example',
          category: 'Telemetria & Rastreador',
          classification: 'tracker',
          deviceId: 'dev-tv-sala',
          deviceHostname: 'smart-tv-sala',
          queriesCount: 2140,
          blockedCount: 2140,
          listStatus: 'blocked',
          lastQueriedAt: minutesAgoIso(2),
        },
        {
          id: 'dns-2',
          domain: 'ota-update-check.camtech-iot.example',
          category: 'Suspeito / DGA',
          classification: 'suspicious',
          deviceId: 'dev-cam-04',
          deviceHostname: 'cam-garagem-ip04',
          queriesCount: 388,
          blockedCount: 0,
          listStatus: 'monitored',
          lastQueriedAt: minutesAgoIso(3),
        },
        {
          id: 'dns-3',
          domain: 'analytics.vendor-cloud.example',
          category: 'Telemetria & Rastreador',
          classification: 'tracker',
          deviceId: 'dev-ws-office',
          deviceHostname: 'estacao-financas-01',
          queriesCount: 188,
          blockedCount: 188,
          listStatus: 'blocked',
          lastQueriedAt: minutesAgoIso(7),
        },
        {
          id: 'dns-4',
          domain: 'backup-sync.office-drive.example',
          category: 'Nuvem Corporativa',
          classification: 'benign',
          deviceId: 'dev-ws-office',
          deviceHostname: 'estacao-financas-01',
          queriesCount: 612,
          blockedCount: 0,
          listStatus: 'allowed',
          lastQueriedAt: minutesAgoIso(1),
        },
      ],
      incidents,
      policies: [
        {
          id: 'pol-dns-tracker',
          name: 'Bloqueio DNS de Rastreadores Comprovados',
          description:
            'Adiciona domínios classificados como telemetria abusiva às listas de bloqueio dos servidores Pi-hole.',
          eventPattern: 'dns.query · classification=tracker',
          maxAutonomyLevel: 'L1',
          maxScope: 'Apenas domínio específico nos servidores DNS ativos',
          defaultTtlSeconds: 1800,
          rollbackSupported: true,
          enabled: true,
        },
        {
          id: 'pol-iot-quarantine',
          name: 'Contenção Temporária de Saída Anômala IoT',
          description:
            'Bloqueia porta e IP externo específico no firewall nftables mantendo acesso local e encaminhamento geral.',
          eventPattern: 'ids.alert + threat.ioc · segment=IoT',
          maxAutonomyLevel: 'L2',
          maxScope: '1 dispositivo IoT · 1 destino/porta por até 30 min',
          defaultTtlSeconds: 900,
          rollbackSupported: true,
          enabled: true,
        },
        {
          id: 'pol-host-isolate',
          name: 'Isolamento Completo de Estação de Trabalho',
          description:
            'Isola completamente um host corporativo na VLAN de quarentena. Requer aprovação humana.',
          eventPattern: 'severity=critical · segment=Escritório',
          maxAutonomyLevel: 'L3',
          maxScope: '1 estação de trabalho (requer aprovação Administrador)',
          defaultTtlSeconds: 1800,
          rollbackSupported: true,
          enabled: true,
        },
      ],
      executions: [
        {
          id: 'act-seed-01',
          incidentId: 'inc-2026-002',
          policyId: 'pol-dns-tracker',
          targetLabel: 'smart-tv-sala · Bloqueio DNS metrics-eu.smartview-telemetry.example',
          actionType: 'dns_block_domain',
          autonomyLevel: 'L0',
          status: 'dry_run',
          ttlSeconds: 1800,
          expiresAt: null,
          executedBy: 'openshield-policy-engine',
          verificationDetail:
            'Simulação L0 registrada: bloqueio pronto para autorização ou elevação para L1.',
          rollbackAvailable: false,
          createdAt: minutesAgoIso(7),
        },
      ],
      auditLog: [
        {
          id: 'aud-seed-01',
          timestamp: minutesAgoIso(18),
          eventType: 'gateway.connected',
          actor: 'home-gateway',
          role: 'gateway-connector',
          targetId: 'home-gateway',
          outcome: 'success',
          detail:
            'Handshake openshield.gateway.v1 concluído; capacidades somente leitura registradas.',
          profile: 'residential',
        },
        {
          id: 'aud-seed-02',
          timestamp: minutesAgoIso(4),
          eventType: 'event.ingested',
          actor: 'suricata-lan',
          role: 'integration-adapter',
          targetId: 'ev-8f21a104',
          outcome: 'success',
          detail: 'Evento ids.alert (high) normalizado e persistido com proveniência suricata-lan.',
          profile: 'residential',
        },
      ],
      metrics: {
        httpRequestsTotal: 142,
        eventsIngestedTotal: 5,
        gatewayConnectionsTotal: 1,
        gatewayHeartbeatsTotal: 18,
        authorizationDeniedTotal: 0,
        outboxPendingTotal: 0,
      },
      latencyHistory: [
        10, 11, 9, 10, 12, 13, 11, 10, 14, 16, 15, 13,
        12, 11, 13, 15, 18, 14, 12, 11, 12, 13, 11, 11,
      ].map((avg, idx, arr) => ({
        timestamp: minutesAgoIso((arr.length - 1 - idx) * 60),
        avgLatencyMs: avg,
        minLatencyMs: Math.max(3, avg - 6),
        maxLatencyMs: avg + 8,
        measuredCount: 6,
      })),
      notifications: [],
      notificationHistory: [],
      aiUsageHistory: [
        {
          id: 'ai-seed-05',
          timestamp: minutesAgoIso(3),
          incidentId: 'inc-2026-001',
          incidentTitle: 'Conexão de saída suspeita em dispositivo IoT correlacionada com IOC CrowdSec',
          provider: 'local-ollama-mock',
          channel: 'local',
          modelVersion: 'llama3.1:8b-instruct (local-first simulado)',
          promptTokens: 482,
          completionTokens: 214,
          totalTokens: 696,
          durationMs: 245,
          estimatedCostUsd: 0,
          outcome: 'success',
          detail: 'Correlação inicial automática executada localmente.',
        },
        {
          id: 'ai-seed-04',
          timestamp: minutesAgoIso(19),
          incidentId: 'inc-2026-001',
          incidentTitle: 'Conexão de saída suspeita em dispositivo IoT correlacionada com IOC CrowdSec',
          provider: 'gemini-sanitized',
          channel: 'cloud',
          modelVersion: 'gemini-4-hydrogen (nuvem opt-in)',
          promptTokens: 390,
          completionTokens: 268,
          totalTokens: 658,
          durationMs: 910,
          estimatedCostUsd: 0.00011,
          outcome: 'success',
          detail: 'Segunda opinião sanitizada confirmou anomalia C2 em porta SSH não padrão.',
        },
        {
          id: 'ai-seed-03',
          timestamp: minutesAgoIso(47),
          incidentId: 'inc-2026-002',
          incidentTitle: 'Pico de telemetria DNS em Smart TV bloqueado pelo Pi-hole',
          provider: 'local-ollama-mock',
          channel: 'local',
          modelVersion: 'llama3.1:8b-instruct (local-first simulado)',
          promptTokens: 348,
          completionTokens: 176,
          totalTokens: 524,
          durationMs: 212,
          estimatedCostUsd: 0,
          outcome: 'success',
          detail: 'Triagem local-first identificou domínio de rastreamento recorrente.',
        },
        {
          id: 'ai-seed-02',
          timestamp: minutesAgoIso(115),
          incidentId: 'inc-2026-002',
          incidentTitle: 'Pico de telemetria DNS em Smart TV bloqueado pelo Pi-hole',
          provider: 'local-ollama-mock',
          channel: 'local',
          modelVersion: 'llama3.1:8b-instruct (local-first simulado)',
          promptTokens: 310,
          completionTokens: 158,
          totalTokens: 468,
          durationMs: 198,
          estimatedCostUsd: 0,
          outcome: 'success',
          detail: 'Reavaliação após incremento de consultas DNS.',
        },
        {
          id: 'ai-seed-01',
          timestamp: minutesAgoIso(190),
          incidentId: 'inc-2026-001',
          incidentTitle: 'Conexão de saída suspeita em dispositivo IoT correlacionada com IOC CrowdSec',
          provider: 'gemini-sanitized',
          channel: 'cloud',
          modelVersion: 'gemini-4-hydrogen (nuvem opt-in)',
          promptTokens: 412,
          completionTokens: 242,
          totalTokens: 654,
          durationMs: 1040,
          estimatedCostUsd: 0.000104,
          outcome: 'success',
          detail: 'Auditoria comparativa com payload sanitizado.',
        },
      ],
    };
  }
}
