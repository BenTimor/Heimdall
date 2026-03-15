import type Database from "better-sqlite3";

export interface AuditRow {
  id: number;
  timestamp: string;
  machine_id: string;
  method: string;
  target: string;
  action: string;
  injected_secrets: string;
  created_at: string;
}

export interface AuditInfo {
  id: number;
  timestamp: string;
  machineId: string;
  method: string;
  target: string;
  action: string;
  injectedSecrets: string[];
  createdAt: string;
}

export interface AuditQuery {
  page?: number;
  limit?: number;
  machineId?: string;
  action?: string;
}

export interface AuditPage {
  entries: AuditInfo[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export function getAuditEntries(db: Database.Database, query: AuditQuery = {}): AuditPage {
  const page = Math.max(1, query.page ?? 1);
  const limit = Math.min(100, Math.max(1, query.limit ?? 50));
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: any[] = [];

  if (query.machineId) {
    conditions.push("machine_id = ?");
    params.push(query.machineId);
  }
  if (query.action) {
    conditions.push("action = ?");
    params.push(query.action);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  const countRow = db.prepare(`SELECT COUNT(*) as total FROM audit_log ${where}`).get(...params) as { total: number };
  const total = countRow.total;

  const rows = db.prepare(
    `SELECT * FROM audit_log ${where} ORDER BY id DESC LIMIT ? OFFSET ?`
  ).all(...params, limit, offset) as AuditRow[];

  return {
    entries: rows.map(r => ({
      id: r.id,
      timestamp: r.timestamp,
      machineId: r.machine_id,
      method: r.method,
      target: r.target,
      action: r.action,
      injectedSecrets: JSON.parse(r.injected_secrets || "[]"),
      createdAt: r.created_at,
    })),
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  };
}

export interface AuditStats {
  total: number;
  byAction: Record<string, number>;
  uniqueClients: number;
  last24h: number;
  last7d: number;
}

export function getAuditStats(db: Database.Database): AuditStats {
  const total = (db.prepare("SELECT COUNT(*) as c FROM audit_log").get() as { c: number }).c;

  const actionRows = db.prepare("SELECT action, COUNT(*) as c FROM audit_log GROUP BY action").all() as { action: string; c: number }[];
  const byAction: Record<string, number> = {};
  for (const row of actionRows) {
    byAction[row.action] = row.c;
  }

  const uniqueClients = (db.prepare("SELECT COUNT(DISTINCT machine_id) as c FROM audit_log WHERE machine_id != ''").get() as { c: number }).c;

  const last24h = (db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE timestamp >= datetime('now', '-1 day')").get() as { c: number }).c;

  const last7d = (db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE timestamp >= datetime('now', '-7 days')").get() as { c: number }).c;

  return { total, byAction, uniqueClients, last24h, last7d };
}

export function insertAuditEntry(
  db: Database.Database,
  entry: { timestamp: string; machineId: string; method: string; target: string; action: string; injectedSecrets: string[] },
): void {
  db.prepare(
    "INSERT INTO audit_log (timestamp, machine_id, method, target, action, injected_secrets) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(entry.timestamp, entry.machineId, entry.method, entry.target, entry.action, JSON.stringify(entry.injectedSecrets));
}
