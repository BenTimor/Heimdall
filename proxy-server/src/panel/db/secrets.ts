import type Database from "better-sqlite3";
import { encryptSecret, decryptSecret, type EncryptedData } from "./crypto.js";

export interface SecretRow {
  id: number;
  name: string;
  provider: string;
  path: string;
  field: string;
  encrypted_value: Buffer | null;
  iv: Buffer | null;
  auth_tag: Buffer | null;
  allowed_domains: string;
  created_at: string;
  updated_at: string;
}

export interface SecretInfo {
  id: number;
  name: string;
  provider: string;
  path: string;
  field: string;
  hasValue: boolean;
  allowedDomains: string[];
  createdAt: string;
  updatedAt: string;
}

export function listSecrets(db: Database.Database): SecretInfo[] {
  const rows = db.prepare("SELECT * FROM secrets ORDER BY id").all() as SecretRow[];
  return rows.map(toSecretInfo);
}

export function getSecretById(db: Database.Database, id: number): SecretInfo | null {
  const row = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as SecretRow | undefined;
  if (!row) return null;
  return toSecretInfo(row);
}

export function getSecretByName(db: Database.Database, name: string): SecretRow | null {
  return db.prepare("SELECT * FROM secrets WHERE name = ?").get(name) as SecretRow | null;
}

export function createSecret(
  db: Database.Database,
  data: {
    name: string;
    provider: string;
    path?: string;
    field?: string;
    value?: string;
    allowedDomains?: string[];
  },
  encryptionKey: Buffer,
): SecretInfo {
  let encryptedValue: Buffer | null = null;
  let iv: Buffer | null = null;
  let authTag: Buffer | null = null;

  if (data.provider === "stored" && data.value) {
    const encrypted = encryptSecret(data.value, encryptionKey);
    encryptedValue = encrypted.encrypted;
    iv = encrypted.iv;
    authTag = encrypted.authTag;
  }

  const allowedDomains = JSON.stringify(data.allowedDomains ?? []);

  db.prepare(
    "INSERT INTO secrets (name, provider, path, field, encrypted_value, iv, auth_tag, allowed_domains) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(data.name, data.provider, data.path ?? "", data.field ?? "", encryptedValue, iv, authTag, allowedDomains);

  const lastRow = db.prepare("SELECT last_insert_rowid() as id").get() as { id: number };
  return getSecretById(db, lastRow.id)!;
}

export function updateSecret(
  db: Database.Database,
  id: number,
  data: {
    provider?: string;
    path?: string;
    field?: string;
    value?: string;
    allowedDomains?: string[];
  },
  encryptionKey: Buffer,
): boolean {
  const existing = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id) as SecretRow | undefined;
  if (!existing) return false;

  const provider = data.provider ?? existing.provider;
  const secretPath = data.path ?? existing.path;
  const field = data.field ?? existing.field;
  const allowedDomains = data.allowedDomains ? JSON.stringify(data.allowedDomains) : existing.allowed_domains;

  let encryptedValue = existing.encrypted_value;
  let iv = existing.iv;
  let authTag = existing.auth_tag;

  if (data.value !== undefined && provider === "stored") {
    const encrypted = encryptSecret(data.value, encryptionKey);
    encryptedValue = encrypted.encrypted;
    iv = encrypted.iv;
    authTag = encrypted.authTag;
  }

  db.prepare(
    "UPDATE secrets SET provider = ?, path = ?, field = ?, encrypted_value = ?, iv = ?, auth_tag = ?, allowed_domains = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(provider, secretPath, field, encryptedValue, iv, authTag, allowedDomains, id);

  return true;
}

export function deleteSecret(db: Database.Database, id: number): boolean {
  const result = db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
  return result.changes > 0;
}

/** Decrypt a stored secret value — only used internally by the StoredProvider, never exposed via API */
export function decryptStoredSecret(row: SecretRow, encryptionKey: Buffer): string | null {
  if (!row.encrypted_value || !row.iv || !row.auth_tag) return null;
  return decryptSecret(
    { encrypted: row.encrypted_value, iv: row.iv, authTag: row.auth_tag },
    encryptionKey,
  );
}

function toSecretInfo(row: SecretRow): SecretInfo {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    path: row.path,
    field: row.field,
    hasValue: row.encrypted_value !== null,
    allowedDomains: JSON.parse(row.allowed_domains || "[]"),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
