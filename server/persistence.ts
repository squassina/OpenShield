import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type {
  AuditEntry,
  OpenShieldEventV1,
  WorkspaceState,
} from '../src/types/openshield.ts';

export interface StoredCredential {
  integrationId: string;
  username: string;
  secret: string;
  updatedAt: string;
}

export class SqlitePersistence {
  private db: DatabaseSync;

  constructor(dbFilePath?: string) {
    const resolvedPath =
      dbFilePath ||
      process.env.OPENSHIELD_DB_PATH ||
      path.join(process.cwd(), '.openshield-data', 'openshield.sqlite3');

    const dir = path.dirname(resolvedPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      fs.chmodSync(dir, 0o700);
    } catch {
      // Best-effort permission hardening on supported filesystems
    }

    this.db = new DatabaseSync(resolvedPath);

    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;

      CREATE TABLE IF NOT EXISTS workspace_snapshot (
        id TEXT PRIMARY KEY,
        payload TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS events_store (
        event_id TEXT PRIMARY KEY,
        occurred_at TEXT NOT NULL,
        source_integration_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        payload TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS outbox_spool (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_trail (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        target_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        detail TEXT NOT NULL,
        profile TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS service_credentials (
        integration_id TEXT PRIMARY KEY,
        username TEXT NOT NULL DEFAULT '',
        secret TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
      );
    `);

    try {
      fs.chmodSync(resolvedPath, 0o600);
    } catch {
      // Ignore on virtual filesystems
    }
  }

  setServiceCredential(integrationId: string, username: string, secret: string): void {
    const existing = this.getServiceCredential(integrationId);
    const nextUser = username !== undefined ? username : (existing?.username ?? '');
    const nextSecret = secret !== '' ? secret : (existing?.secret ?? '');
    const stmt = this.db.prepare(`
      INSERT INTO service_credentials (integration_id, username, secret, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(integration_id) DO UPDATE SET
        username = excluded.username,
        secret = excluded.secret,
        updated_at = excluded.updated_at
    `);
    stmt.run(integrationId, nextUser, nextSecret, new Date().toISOString());
  }

  getServiceCredential(integrationId: string): StoredCredential | null {
    const row = this.db
      .prepare('SELECT integration_id, username, secret, updated_at FROM service_credentials WHERE integration_id = ?')
      .get(integrationId);
    if (!row) return null;
    return {
      integrationId: String(row.integration_id),
      username: String(row.username ?? ''),
      secret: String(row.secret ?? ''),
      updatedAt: String(row.updated_at),
    };
  }

  deleteServiceCredential(integrationId: string): void {
    this.db
      .prepare('DELETE FROM service_credentials WHERE integration_id = ?')
      .run(integrationId);
  }

  clearAllCredentials(): void {
    this.db.exec('DELETE FROM service_credentials');
  }

  clearEventsStore(): void {
    this.db.exec('DELETE FROM events_store');
    this.db.exec('DELETE FROM outbox_spool');
  }

  loadSnapshot(): WorkspaceState | null {
    const row = this.db
      .prepare('SELECT payload FROM workspace_snapshot WHERE id = ?')
      .get('primary');
    if (!row || typeof row.payload !== 'string') {
      return null;
    }
    try {
      return JSON.parse(row.payload) as WorkspaceState;
    } catch {
      return null;
    }
  }

  saveSnapshot(state: WorkspaceState): void {
    const stmt = this.db.prepare(`
      INSERT INTO workspace_snapshot (id, payload, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        payload = excluded.payload,
        updated_at = excluded.updated_at
    `);
    stmt.run('primary', JSON.stringify(state), new Date().toISOString());
  }

  hasEventId(eventId: string): boolean {
    const row = this.db
      .prepare('SELECT 1 AS found FROM events_store WHERE event_id = ?')
      .get(eventId);
    return Boolean(row);
  }

  persistEvent(event: OpenShieldEventV1): boolean {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO events_store (
        event_id, occurred_at, source_integration_id, event_type, severity, payload
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(
      event.eventId,
      event.occurredAt,
      event.sourceIntegrationId,
      event.eventType,
      event.severity,
      JSON.stringify(event),
    );
    return res.changes > 0;
  }

  enqueueOutbox(event: OpenShieldEventV1): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO outbox_spool (event_id, payload, created_at)
      VALUES (?, ?, ?)
    `);
    stmt.run(event.eventId, JSON.stringify(event), new Date().toISOString());
  }

  listOutbox(): OpenShieldEventV1[] {
    const rows = this.db
      .prepare('SELECT payload FROM outbox_spool ORDER BY seq ASC')
      .all();
    return rows
      .map((r) => {
        try {
          return JSON.parse(String(r.payload)) as OpenShieldEventV1;
        } catch {
          return null;
        }
      })
      .filter((x): x is OpenShieldEventV1 => x !== null);
  }

  clearOutbox(): void {
    this.db.exec('DELETE FROM outbox_spool');
  }

  outboxCount(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM outbox_spool').get();
    return Number(row?.cnt ?? 0);
  }

  appendAudit(entry: AuditEntry): void {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO audit_trail (
        id, timestamp, event_type, actor, role, target_id, outcome, detail, profile
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      entry.id,
      entry.timestamp,
      entry.eventType,
      entry.actor,
      entry.role,
      entry.targetId,
      entry.outcome,
      entry.detail,
      entry.profile,
    );
  }

  loadRecentAudit(limit = 200): AuditEntry[] {
    const rows = this.db
      .prepare('SELECT * FROM audit_trail ORDER BY seq DESC LIMIT ?')
      .all(limit);
    return rows.map((r) => ({
      id: String(r.id),
      timestamp: String(r.timestamp),
      eventType: String(r.event_type) as AuditEntry['eventType'],
      actor: String(r.actor),
      role: String(r.role),
      targetId: String(r.target_id),
      outcome: String(r.outcome) as AuditEntry['outcome'],
      detail: String(r.detail),
      profile: String(r.profile) as AuditEntry['profile'],
    }));
  }

  queryAudit(filters: {
    eventType?: string;
    category?: string;
    from?: string;
    to?: string;
    outcome?: string;
    search?: string;
    limit?: number;
  } = {}): { entries: AuditEntry[]; totalMatched: number; eventTypes: string[] } {
    const clauses: string[] = [];
    const params: (string | number)[] = [];

    if (filters.eventType && filters.eventType !== 'all') {
      clauses.push('event_type = ?');
      params.push(filters.eventType);
    }

    if (filters.category && filters.category !== 'all') {
      if (filters.category === 'kill_switch') {
        clauses.push("event_type LIKE 'kill_switch.%'");
      } else if (filters.category === 'propose_action') {
        clauses.push("event_type LIKE 'action.%'");
      } else if (filters.category === 'config') {
        clauses.push(
          "event_type IN ('integration.registered','integration.removed','integration.synced','credentials.updated','device.added','device.updated','device.removed','dns.added','dns.list_updated','site.added','site.removed','workspace.demo_loaded','workspace.reset','workspace.restored')",
        );
      } else if (filters.category === 'state_change') {
        clauses.push(
          "event_type IN ('context.updated','gateway.connected','event.ingested','ai.investigated','authorization.denied')",
        );
      }
    }

    if (filters.from) {
      const fromMs = Date.parse(filters.from);
      if (Number.isFinite(fromMs)) {
        clauses.push('timestamp >= ?');
        params.push(new Date(fromMs).toISOString());
      }
    }

    if (filters.to) {
      const toMs = Date.parse(filters.to);
      if (Number.isFinite(toMs)) {
        clauses.push('timestamp <= ?');
        params.push(new Date(toMs).toISOString());
      }
    }

    if (filters.outcome && filters.outcome !== 'all') {
      clauses.push('outcome = ?');
      params.push(filters.outcome);
    }

    if (filters.search && filters.search.trim()) {
      const q = `%${filters.search.trim().toLowerCase()}%`;
      clauses.push(
        '(LOWER(detail) LIKE ? OR LOWER(actor) LIKE ? OR LOWER(target_id) LIKE ? OR LOWER(event_type) LIKE ?)',
      );
      params.push(q, q, q, q);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = Number.isFinite(filters.limit)
      ? Math.max(1, Math.min(1000, Number(filters.limit)))
      : 200;

    const countRow = this.db
      .prepare(`SELECT COUNT(*) AS total FROM audit_trail ${whereSql}`)
      .get(...params);
    const totalMatched = Number(countRow?.total ?? 0);

    const rows = this.db
      .prepare(`SELECT * FROM audit_trail ${whereSql} ORDER BY seq DESC LIMIT ?`)
      .all(...params, limit);

    const distinctRows = this.db
      .prepare('SELECT DISTINCT event_type FROM audit_trail ORDER BY event_type ASC')
      .all();

    return {
      entries: rows.map((r) => ({
        id: String(r.id),
        timestamp: String(r.timestamp),
        eventType: String(r.event_type) as AuditEntry['eventType'],
        actor: String(r.actor),
        role: String(r.role),
        targetId: String(r.target_id),
        outcome: String(r.outcome) as AuditEntry['outcome'],
        detail: String(r.detail),
        profile: String(r.profile) as AuditEntry['profile'],
      })),
      totalMatched,
      eventTypes: distinctRows.map((r) => String(r.event_type)),
    };
  }
}
