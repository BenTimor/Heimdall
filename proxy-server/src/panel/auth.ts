import crypto from "node:crypto";
import bcrypt from "bcrypt";
import type Database from "better-sqlite3";

const BCRYPT_ROUNDS = 12;

export interface AdminRow {
  id: number;
  username: string;
  password_hash: string;
  must_change_password: number;
}

export interface SessionRow {
  id: string;
  admin_id: number;
  expires_at: string;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function createSession(db: Database.Database, adminId: number, ttlHours: number): string {
  const sessionId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + ttlHours * 60 * 60 * 1000).toISOString();
  db.prepare("INSERT INTO sessions (id, admin_id, expires_at) VALUES (?, ?, ?)").run(sessionId, adminId, expiresAt);
  return sessionId;
}

export function validateSession(db: Database.Database, sessionId: string): AdminRow | null {
  const session = db.prepare(
    "SELECT s.admin_id, s.expires_at FROM sessions s WHERE s.id = ?"
  ).get(sessionId) as { admin_id: number; expires_at: string } | undefined;

  if (!session) return null;

  if (new Date(session.expires_at) < new Date()) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
    return null;
  }

  return db.prepare("SELECT * FROM admins WHERE id = ?").get(session.admin_id) as AdminRow | undefined ?? null;
}

export function deleteSession(db: Database.Database, sessionId: string): void {
  db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
}

export function cleanExpiredSessions(db: Database.Database): number {
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  return result.changes;
}

export async function ensureDefaultAdmin(db: Database.Database, defaultPassword: string): Promise<void> {
  const existing = db.prepare("SELECT id FROM admins LIMIT 1").get();
  if (existing) return;

  const hash = await hashPassword(defaultPassword);
  db.prepare("INSERT INTO admins (username, password_hash, must_change_password) VALUES (?, ?, 1)").run("admin", hash);
}
