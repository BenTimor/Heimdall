import crypto from "node:crypto";
import type Database from "better-sqlite3";

export interface ClientRow {
  id: number;
  machine_id: string;
  token_hash: string;
  description: string;
  enabled: number;
  created_at: string;
  updated_at: string;
}

export interface ClientInfo {
  id: number;
  machineId: string;
  description: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function listClients(db: Database.Database): ClientInfo[] {
  const rows = db.prepare("SELECT id, machine_id, description, enabled, created_at, updated_at FROM clients ORDER BY id").all() as ClientRow[];
  return rows.map(r => ({
    id: r.id,
    machineId: r.machine_id,
    description: r.description,
    enabled: r.enabled === 1,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

export function getClientById(db: Database.Database, id: number): ClientInfo | null {
  const row = db.prepare("SELECT id, machine_id, description, enabled, created_at, updated_at FROM clients WHERE id = ?").get(id) as ClientRow | undefined;
  if (!row) return null;
  return {
    id: row.id,
    machineId: row.machine_id,
    description: row.description,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function findClientByMachineId(db: Database.Database, machineId: string): (ClientRow & { enabled: number }) | null {
  return db.prepare("SELECT * FROM clients WHERE machine_id = ?").get(machineId) as ClientRow | null;
}

export function createClient(db: Database.Database, machineId: string, description: string): { client: ClientInfo; token: string } {
  const token = generateToken();
  const tokenHash = hashToken(token);
  db.prepare("INSERT INTO clients (machine_id, token_hash, description) VALUES (?, ?, ?)").run(machineId, tokenHash, description);
  const client = findClientByMachineId(db, machineId)!;
  return {
    client: {
      id: client.id,
      machineId: client.machine_id,
      description: client.description,
      enabled: client.enabled === 1,
      createdAt: client.created_at,
      updatedAt: client.updated_at,
    },
    token,
  };
}

export function updateClient(db: Database.Database, id: number, updates: { description?: string; enabled?: boolean }): boolean {
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.description !== undefined) {
    fields.push("description = ?");
    values.push(updates.description);
  }
  if (updates.enabled !== undefined) {
    fields.push("enabled = ?");
    values.push(updates.enabled ? 1 : 0);
  }

  if (fields.length === 0) return false;

  fields.push("updated_at = datetime('now')");
  values.push(id);

  const result = db.prepare(`UPDATE clients SET ${fields.join(", ")} WHERE id = ?`).run(...values);
  return result.changes > 0;
}

export function deleteClient(db: Database.Database, id: number): boolean {
  const result = db.prepare("DELETE FROM clients WHERE id = ?").run(id);
  return result.changes > 0;
}

export function regenerateToken(db: Database.Database, id: number): string | null {
  const client = db.prepare("SELECT id FROM clients WHERE id = ?").get(id) as { id: number } | undefined;
  if (!client) return null;

  const token = generateToken();
  const tokenHash = hashToken(token);
  db.prepare("UPDATE clients SET token_hash = ?, updated_at = datetime('now') WHERE id = ?").run(tokenHash, id);
  return token;
}
