import dotenv from 'dotenv';
import express from 'express';
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
  ServiceProviderMode,
  SimulatedRole,
} from './src/types/openshield.ts';
import { OpenShieldStore } from './server/openshieldStore.ts';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;
const app = express();
const store = new OpenShieldStore();

app.use(express.json({ limit: '1mb' }));

// Track API request telemetry
app.use('/api', (_req, _res, next) => {
  store.recordHttpRequest();
  next();
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
