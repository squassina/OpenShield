import dotenv from 'dotenv';
import express from 'express';
import crypto from 'node:crypto';
import { createServer } from 'node:http';
import path from 'node:path';
import type {
  AiSensitivityConfig,
  AutonomyLevel,
  DnsInsight,
  Incident,
  IntegrationAdapter,
  NetworkDevice,
  NotificationChannelType,
  NotificationSeverityThreshold,
  NotificationTriggerEvent,
  OpenShieldEventV1,
  OperatingProfile,
  PeriodicSyncConfig,
  RouterAccessService,
  ServiceProviderMode,
  SimulatedRole,
} from './src/types/openshield.ts';
import { AuthService } from './server/auth.ts';
import { OpenShieldStore } from './server/openshieldStore.ts';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;
const app = express();
const store = new OpenShieldStore();
const authService = new AuthService(store.getPersistence());

function isSecureRequest(req: express.Request): boolean {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}

function checkIngestToken(req: express.Request): boolean {
  const configuredToken = process.env.OPENSHIELD_INGEST_TOKEN?.trim();
  if (!configuredToken) return true;
  const headerToken =
    (typeof req.headers['x-openshield-ingest-token'] === 'string'
      ? req.headers['x-openshield-ingest-token'].trim()
      : '') ||
    (typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.slice(7).trim()
      : '');
  const a = Buffer.from(headerToken, 'utf8');
  const b = Buffer.from(configuredToken, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.use(express.json({ limit: '1mb' }));

// Track API request telemetry
app.use('/api', (_req, _res, next) => {
  store.recordHttpRequest();
  next();
});

// Auth endpoints (HttpOnly + SameSite=Strict signed session cookie)
app.get('/api/v1/auth/status', (req, res) => {
  res.json(authService.getAuthStatus(req.headers.cookie));
});

app.post('/api/v1/auth/setup', (req, res) => {
  try {
    const { username, password } = (req.body ?? {}) as { username?: string; password?: string };
    const created = authService.setupInitialAdmin(String(username ?? 'admin'), String(password ?? ''));
    res.setHeader(
      'Set-Cookie',
      authService.buildSessionCookieHeader({ username: created.username, role: created.role }, isSecureRequest(req)),
    );
    store.recordAuthEvent({
      eventType: 'auth.user_updated',
      actor: created.username,
      role: created.role,
      targetId: created.username,
      outcome: 'success',
      detail: `Administrador inicial "${created.username}" configurado com senha scrypt e cookie HttpOnly/SameSite=Strict.`,
    });
    res.status(201).json({
      user: created,
      status: {
        authConfigured: true,
        authRequired: true,
        authenticated: true,
        envAdminEnabled: authService.isEnvAdminConfigured(),
        user: { username: created.username, role: created.role },
      },
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao configurar administrador.' });
  }
});

app.post('/api/v1/auth/login', (req, res) => {
  try {
    const { username, password } = (req.body ?? {}) as { username?: string; password?: string };
    const user = authService.login(String(username ?? ''), String(password ?? ''));
    res.setHeader(
      'Set-Cookie',
      authService.buildSessionCookieHeader(user, isSecureRequest(req)),
    );
    store.recordAuthEvent({
      eventType: 'auth.login',
      actor: user.username,
      role: user.role,
      targetId: user.username,
      outcome: 'success',
      detail: `Sessão autenticada iniciada para "${user.username}" (${user.role}).`,
    });
    res.json({
      status: {
        authConfigured: authService.isAuthConfigured(),
        authRequired: authService.isAuthRequired(),
        authenticated: true,
        envAdminEnabled: authService.isEnvAdminConfigured(),
        user,
      },
    });
  } catch (err) {
    const attempted = typeof req.body?.username === 'string' ? req.body.username : 'desconhecido';
    store.recordAuthEvent({
      eventType: 'auth.login',
      actor: attempted,
      role: 'anonymous',
      targetId: attempted,
      outcome: 'denied',
      detail: `Tentativa de login rejeitada para "${attempted}".`,
    });
    res.status(401).json({ error: err instanceof Error ? err.message : 'Credenciais inválidas.' });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  const current = authService.authenticateFromCookie(req.headers.cookie);
  res.setHeader('Set-Cookie', authService.buildClearCookieHeader(isSecureRequest(req)));
  if (current) {
    store.recordAuthEvent({
      eventType: 'auth.logout',
      actor: current.username,
      role: current.role,
      targetId: current.username,
      outcome: 'success',
      detail: `Sessão encerrada para "${current.username}".`,
    });
  }
  res.json({
    status: {
      authConfigured: authService.isAuthConfigured(),
      authRequired: authService.isAuthRequired(),
      authenticated: false,
      envAdminEnabled: authService.isEnvAdminConfigured(),
      user: null,
    },
  });
});

// Enforce session authentication and propagate real RBAC actor into AsyncLocalStorage
app.use('/api/v1', (req, res, next) => {
  if (req.path.startsWith('/auth/') && !req.path.startsWith('/auth/users')) {
    next();
    return;
  }

  if (req.path.startsWith('/ingest/')) {
    if (!checkIngestToken(req)) {
      res.status(401).json({ error: 'Token de ingestão inválido ou ausente.' });
      return;
    }
    next();
    return;
  }

  const session = authService.authenticateFromCookie(req.headers.cookie);
  if (authService.isAuthRequired() && !session) {
    res.status(401).json({
      error: 'Autenticação necessária: faça login no painel OpenShield.',
      code: 'AUTH_REQUIRED',
    });
    return;
  }

  store.runWithAuthUser(session ? { username: session.username, role: session.role } : null, () => {
    next();
  });
});

app.get('/api/v1/auth/users', (_req, res) => {
  try {
    store.assertCanMutate('admin');
    res.json({ users: authService.listUsers() });
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Acesso negado.' });
  }
});

app.post('/api/v1/auth/users', (req, res) => {
  try {
    store.assertCanMutate('admin');
    const { username, role, password } = (req.body ?? {}) as {
      username?: string;
      role?: SimulatedRole;
      password?: string;
    };
    const saved = authService.upsertUser({
      username: String(username ?? ''),
      role: role ?? 'operator',
      password: String(password ?? ''),
    });
    const session = authService.authenticateFromCookie(req.headers.cookie);
    store.recordAuthEvent({
      eventType: 'auth.user_updated',
      actor: session?.username ?? 'system',
      role: session?.role ?? 'admin',
      targetId: saved.username,
      outcome: 'success',
      detail: `Usuário "${saved.username}" salvo com papel RBAC "${saved.role}".`,
    });
    res.status(201).json({ user: saved, users: authService.listUsers() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Falha ao salvar usuário.';
    res.status(msg.includes('RBAC') ? 403 : 400).json({ error: msg });
  }
});

app.delete('/api/v1/auth/users/:username', (req, res) => {
  try {
    store.assertCanMutate('admin');
    const session = authService.authenticateFromCookie(req.headers.cookie);
    authService.deleteUser(req.params.username, session?.username);
    store.recordAuthEvent({
      eventType: 'auth.user_updated',
      actor: session?.username ?? 'system',
      role: session?.role ?? 'admin',
      targetId: req.params.username,
      outcome: 'success',
      detail: `Usuário "${req.params.username}" removido do cofre local.`,
    });
    res.json({ users: authService.listUsers() });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Falha ao remover usuário.';
    res.status(msg.includes('RBAC') ? 403 : 400).json({ error: msg });
  }
});

// Tick TTL expirations every second
setInterval(() => {
  store.tickTimers();
}, 1000);

// Health check
app.get('/api/health', (_req, res) => {
  const state = store.getState();
  res.json({
    status: state.context.nodeAvailable ? 'ready' : 'node_simulated_offline',
    gatewayForwardingActive: state.context.gatewayForwardingActive,
    schemaVersion: 'openshield.event.v1',
  });
});

// Safe environment variable presence check (booleans only, zero secrets exposed)
app.get('/api/v1/system/env-status', (_req, res) => {
  res.json({ variables: store.getEnvStatus() });
});

// Prometheus-compatible text metrics
app.get('/metrics', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(store.renderPrometheusMetrics());
});

// Full workspace snapshot
app.get('/api/v1/state', (_req, res) => {
  res.json(store.getState());
});

// Server-Sent Events stream for real-time TTL, sync & outbox updates
app.get('/api/v1/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendState = () => {
    res.write(`data: ${JSON.stringify(store.getState())}\n\n`);
  };

  sendState();
  const unsubscribe = store.subscribe(sendState);
  const keepAlive = setInterval(() => {
    res.write(': keepalive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(keepAlive);
    unsubscribe();
  });
});

// Operating context & RBAC switching
app.patch('/api/v1/context', (req, res) => {
  try {
    const body = req.body as {
      profile?: OperatingProfile;
      simulatedRole?: SimulatedRole;
      globalAutonomy?: AutonomyLevel;
      cloudAiOptIn?: boolean;
      activeSiteId?: string;
      aiSensitivity?: AiSensitivityConfig;
      periodicSync?: PeriodicSyncConfig;
      persistentUciFirewall?: boolean;
    };
    const state = store.updateContext(body);
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Operação não permitida.' });
  }
});

// P0 Outage simulator
app.post('/api/v1/simulator/node-outage', (req, res) => {
  try {
    const { nodeAvailable } = req.body as { nodeAvailable: boolean };
    const state = store.toggleNodeOutage(Boolean(nodeAvailable));
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Operação não permitida.' });
  }
});

// Real LAN ingestion endpoint (supports single event or batch array)
app.post('/api/v1/ingest/events', (req, res) => {
  try {
    const body = req.body as
      | OpenShieldEventV1
      | { events: OpenShieldEventV1[] };
    const items = 'events' in body && Array.isArray(body.events) ? body.events : [body as OpenShieldEventV1];

    const results = items.map((ev) =>
      store.ingestEvent({
        ...ev,
        dataSource: ev.dataSource ?? 'live',
      }),
    );

    const anyAccepted = results.some((r) => r.status === 'accepted');
    const latestState = results[results.length - 1]?.state ?? store.getState();
    res.status(anyAccepted ? 201 : 202).json({
      count: results.length,
      statuses: results.map((r) => ({
        eventId: r.event.eventId,
        status: r.status,
        correlatedIncidentId: r.correlatedIncidentId,
      })),
      state: latestState,
    });
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha na ingestão de evento.' });
  }
});

// P0 Simulator event ingestion & provenance check
app.post('/api/v1/simulator/ingest-event', (req, res) => {
  try {
    const body = req.body as {
      sourceIntegrationId: string;
      eventType: OpenShieldEventV1['eventType'];
      severity: OpenShieldEventV1['severity'];
      summary: string;
      deviceId?: string;
      payload?: Record<string, unknown>;
      simulateDuplicateId?: string;
    };
    const result = store.ingestEvent(body);
    const httpCode = result.status === 'accepted' ? 201 : 202;
    res.status(httpCode).json(result);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Proveniência rejeitada.' });
  }
});

// Router access attempts log ingestion (syslog / logread push)
app.post('/api/v1/ingest/router-logs', express.text({ type: 'text/plain', limit: '1mb' }), (req, res) => {
  try {
    const querySource =
      typeof req.query.sourceIntegrationId === 'string'
        ? req.query.sourceIntegrationId.trim()
        : '';

    let sourceIntegrationId = querySource;
    let rawLog: string | undefined;
    let entries:
      | Array<{
          srcIp: string;
          service: RouterAccessService;
          targetPort?: number;
          protocol?: string;
          attemptsCount?: number;
          message?: string;
          occurredAt?: string;
        }>
      | undefined;

    if (typeof req.body === 'string') {
      rawLog = req.body;
    } else if (req.body && typeof req.body === 'object') {
      const body = req.body as {
        sourceIntegrationId?: string;
        rawLog?: string;
        entries?: typeof entries;
      };
      if (typeof body.sourceIntegrationId === 'string' && body.sourceIntegrationId.trim()) {
        sourceIntegrationId = body.sourceIntegrationId.trim();
      }
      if (typeof body.rawLog === 'string') {
        rawLog = body.rawLog;
      }
      if (Array.isArray(body.entries)) {
        entries = body.entries;
      }
    }

    if (!sourceIntegrationId) {
      res.status(400).json({ error: 'sourceIntegrationId é obrigatório.' });
      return;
    }

    const result = store.ingestRouterLogs({
      sourceIntegrationId,
      rawLog,
      entries,
    });
    res.status(202).json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Falha na ingestão de logs do roteador.';
    const status = msg.includes('Proveniência rejeitada') || msg.includes('403') ? 403 : 400;
    res.status(status).json({ error: msg });
  }
});

// Integrations: handshake, mode switch (mock <-> live), real sync, manual registration
app.post('/api/v1/integrations/:id/handshake', (req, res) => {
  try {
    const state = store.runGatewayHandshake(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha no handshake.' });
  }
});

app.post('/api/v1/integrations/sync-all', async (_req, res) => {
  try {
    const out = await store.syncAllIntegrations();
    res.json(out);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha na sincronização em lote.' });
  }
});

app.post('/api/v1/integrations/:id/sync', async (req, res) => {
  try {
    const out = await store.syncIntegration(req.params.id);
    res.json(out);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao sincronizar adaptador.' });
  }
});

app.patch('/api/v1/integrations/:id/mode', async (req, res) => {
  try {
    const { mode, liveEndpointUrl } = req.body as {
      mode: ServiceProviderMode;
      liveEndpointUrl?: string;
    };
    const result = await store.testAndSwitchIntegrationMode(req.params.id, mode, liveEndpointUrl);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao alternar modo.' });
  }
});

app.patch('/api/v1/integrations/:id/config', (req, res) => {
  try {
    const body = req.body as {
      name?: string;
      liveEndpointUrl?: string;
      siteId?: string;
      mode?: ServiceProviderMode;
      modelName?: string;
      boardInfo?: IntegrationAdapter['boardInfo'];
      username?: string;
      secret?: string;
      clearSecret?: boolean;
    };
    const state = store.updateIntegrationConfig(req.params.id, body);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao salvar configuração.' });
  }
});

app.delete('/api/v1/integrations/:id', (req, res) => {
  try {
    const state = store.removeIntegration(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao remover serviço.' });
  }
});

app.post('/api/v1/integrations', (req, res) => {
  try {
    const body = req.body as {
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
    };
    const state = store.registerManualIntegration(body);
    res.status(201).json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao registrar serviço.' });
  }
});

// Dynamic Network Devices CRUD
app.post('/api/v1/devices', (req, res) => {
  try {
    const body = req.body as {
      id?: string;
      hostname: string;
      ip: string;
      mac?: string;
      vendor?: string;
      interfaceName?: string;
      segment: NetworkDevice['segment'];
      siteId?: string;
      deviceType: NetworkDevice['deviceType'];
    };
    const state = store.addDevice(body);
    res.status(201).json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao adicionar dispositivo.' });
  }
});

app.post('/api/v1/devices/import-openwrt-map', (req, res) => {
  try {
    const body = req.body as {
      rawOutput?: string;
      netDump?: unknown;
      hostHints?: unknown;
      ipNeighText?: string;
      siteId?: string;
    };
    const result = store.importOpenWrtMapping(body);
    res.status(200).json(result);
  } catch (err) {
    res.status(400).json({
      error: err instanceof Error ? err.message : 'Falha ao importar mapeamento OpenWrt.',
    });
  }
});

app.patch('/api/v1/devices/:id', (req, res) => {
  try {
    const body = req.body as Partial<
      Pick<
        NetworkDevice,
        'hostname' | 'ip' | 'mac' | 'vendor' | 'interfaceName' | 'segment' | 'siteId' | 'deviceType' | 'status'
      >
    >;
    const state = store.updateDevice(req.params.id, body);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao atualizar dispositivo.' });
  }
});

app.delete('/api/v1/devices/:id', (req, res) => {
  try {
    const state = store.removeDevice(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao remover dispositivo.' });
  }
});

// Optional Demo Scenario, Reset & Sanitized Backup/Restore
app.post('/api/v1/workspace/load-demo', (_req, res) => {
  try {
    const state = store.loadDemoScenario();
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao carregar cenário demo.' });
  }
});

app.post('/api/v1/workspace/reset', (_req, res) => {
  try {
    const state = store.resetWorkspace();
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao limpar inventário.' });
  }
});

app.get('/api/v1/workspace/backup', (_req, res) => {
  res.json(store.exportSanitizedBackup());
});

app.post('/api/v1/workspace/restore', (req, res) => {
  try {
    const state = store.restoreSanitizedBackup(req.body);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao restaurar backup.' });
  }
});

// Multi-site management
app.post('/api/v1/sites', (req, res) => {
  try {
    const body = req.body as { name: string; profile: OperatingProfile };
    const state = store.addSite(body);
    res.status(201).json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao adicionar site.' });
  }
});

app.delete('/api/v1/sites/:id', (req, res) => {
  try {
    const state = store.removeSite(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao remover site.' });
  }
});

// P2 DNS privacy list control & manual domain entry
app.post('/api/v1/dns', async (req, res) => {
  try {
    const body = req.body as {
      domain: string;
      category?: DnsInsight['category'];
      classification?: DnsInsight['classification'];
      deviceHostname?: string;
      listStatus?: DnsInsight['listStatus'];
    };
    const state = await store.addDnsInsight(body);
    res.status(201).json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao adicionar domínio DNS.' });
  }
});

app.post('/api/v1/dns/:id/list-status', async (req, res) => {
  try {
    const { listStatus } = req.body as { listStatus: DnsInsight['listStatus'] };
    const state = await store.updateDnsListStatus(req.params.id, listStatus);
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao atualizar lista DNS.' });
  }
});

// P4 Hybrid AI investigation (local-first default + optional Ollama real + optional sanitized Gemini)
app.post('/api/v1/incidents/:id/investigate', async (req, res) => {
  try {
    const { mode } = req.body as { mode: 'local' | 'cloud_gemini' };
    const state = await store.investigateIncident(req.params.id, mode);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha na investigação.' });
  }
});

app.patch('/api/v1/incidents/:id/status', (req, res) => {
  try {
    const { status } = req.body as { status: Incident['status'] };
    const state = store.updateIncidentStatus(req.params.id, status);
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao atualizar incidente.' });
  }
});

// P5 Policies, L0-L3 Execution, Approval, Rollback & Kill Switch
app.patch('/api/v1/policies/:id', (req, res) => {
  try {
    const { enabled } = req.body as { enabled: boolean };
    const state = store.togglePolicyEnabled(req.params.id, Boolean(enabled));
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao atualizar política.' });
  }
});

app.post('/api/v1/actions/propose', async (req, res) => {
  try {
    const body = req.body as { incidentId: string; policyId: string; ttlSeconds?: number };
    const result = await store.proposePolicyAction(body);
    res.status(201).json(result);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Ação bloqueada pela política.' });
  }
});

app.post('/api/v1/actions/:id/approve', async (req, res) => {
  try {
    const state = await store.approveL3Execution(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao aprovar ação L3.' });
  }
});

app.post('/api/v1/actions/:id/rollback', async (req, res) => {
  try {
    const state = await store.rollbackExecution(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao executar rollback.' });
  }
});

app.post('/api/v1/kill-switch', async (req, res) => {
  try {
    const { active } = req.body as { active: boolean };
    const state = await store.triggerKillSwitch(Boolean(active));
    res.json(state);
  } catch (err) {
    res.status(403).json({ error: err instanceof Error ? err.message : 'Falha ao acionar Kill Switch.' });
  }
});

// Router access attempts containment & triage
app.post('/api/v1/router-access/:id/block', async (req, res) => {
  try {
    const body = (req.body ?? {}) as { ttlSeconds?: number };
    const result = await store.blockRouterAccessAttempt(req.params.id, body.ttlSeconds);
    res.status(201).json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Falha ao bloquear IP no roteador.';
    const status =
      msg.includes('Kill Switch') || msg.includes('RBAC') || msg.includes('Permissão')
        ? 403
        : 400;
    res.status(status).json({ error: msg });
  }
});

app.patch('/api/v1/router-access/:id/status', (req, res) => {
  try {
    const { status } = (req.body ?? {}) as { status?: string };
    if (status !== 'observed' && status !== 'ignored') {
      res.status(400).json({ error: 'Status inválido; use "observed" ou "ignored".' });
      return;
    }
    const state = store.updateRouterAccessStatus(req.params.id, status);
    res.json(state);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Falha ao atualizar tentativa de acesso.';
    const status = msg.includes('RBAC') || msg.includes('Permissão') ? 403 : 400;
    res.status(status).json({ error: msg });
  }
});

// Notification & Alert destinations (Email, Webhook, Telegram)
app.post('/api/v1/notifications', (req, res) => {
  try {
    const body = req.body as {
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
    };
    const state = store.addNotificationDestination(body);
    res.status(201).json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao adicionar destino de alerta.' });
  }
});

app.patch('/api/v1/notifications/:id', (req, res) => {
  try {
    const body = req.body as {
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
    };
    const state = store.updateNotificationDestination(req.params.id, body);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao atualizar destino de alerta.' });
  }
});

app.delete('/api/v1/notifications/:id', (req, res) => {
  try {
    const state = store.removeNotificationDestination(req.params.id);
    res.json(state);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao remover destino de alerta.' });
  }
});

app.post('/api/v1/notifications/:id/test', async (req, res) => {
  try {
    const out = await store.testNotificationDestination(req.params.id);
    res.json(out);
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Falha ao testar envio de alerta.' });
  }
});

// Persistent SQLite Audit endpoint (supports timestamp, action type, category, outcome & search filters)
app.get('/api/v1/audit', (req, res) => {
  const rawLimit = Number(req.query.limit ?? 200);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(1000, rawLimit)) : 200;
  const result = store.queryAuditLog({
    eventType: typeof req.query.eventType === 'string' ? req.query.eventType : undefined,
    category: typeof req.query.category === 'string' ? req.query.category : undefined,
    from: typeof req.query.from === 'string' ? req.query.from : undefined,
    to: typeof req.query.to === 'string' ? req.query.to : undefined,
    outcome: typeof req.query.outcome === 'string' ? req.query.outcome : undefined,
    search: typeof req.query.search === 'string' ? req.query.search : undefined,
    limit,
  });
  res.json(result);
});

function startServer() {
  const httpServer = createServer(app);

  if (process.env.NODE_ENV !== 'production') {
    let viteMiddleware: express.RequestHandler | null = null;
    let viteInitError: Error | null = null;

    const viteReady = import('vite')
      .then(({ createServer: createViteServer }) =>
        createViteServer({
          server: {
            middlewareMode: true,
            hmr: process.env.DISABLE_HMR === 'true' ? false : { server: httpServer },
            ws: { server: httpServer },
          },
          appType: 'spa',
        }),
      )
      .then((vite) => {
        viteMiddleware = vite.middlewares;
      })
      .catch((err) => {
        viteInitError = err instanceof Error ? err : new Error(String(err));
        console.error('Vite middleware initialization failed:', viteInitError);
      });

    app.use(async (req, res, next) => {
      await viteReady;
      if (viteInitError) {
        res.status(500).send('Vite initialization failed');
        return;
      }
      if (viteMiddleware) {
        viteMiddleware(req, res, next);
        return;
      }
      next();
    });
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`OpenShield BFF & UI listening on http://localhost:${PORT}`);
  });
}

startServer();
