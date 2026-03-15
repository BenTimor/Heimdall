import fs from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";

export interface AuditEntry {
  timestamp: string;
  machineId: string;
  method: string;
  target: string;
  injectedSecrets: string[];
  action: "injected" | "passthrough" | "blocked";
}

export class AuditLogger {
  private fd: number | null = null;
  private enabled: boolean;
  private db: Database.Database | null = null;
  private insertStmt: Database.Statement | null = null;

  constructor(config: { enabled: boolean; file?: string }, db?: Database.Database) {
    this.enabled = config.enabled;

    if (this.enabled && config.file) {
      const dir = path.dirname(config.file);
      fs.mkdirSync(dir, { recursive: true });
      this.fd = fs.openSync(config.file, "a");
    }

    if (db) {
      this.db = db;
      this.insertStmt = db.prepare(
        "INSERT INTO audit_log (timestamp, machine_id, method, target, action, injected_secrets) VALUES (?, ?, ?, ?, ?, ?)"
      );
    }
  }

  logRequest(entry: AuditEntry): void {
    if (!this.enabled) return;

    // Write to JSONL file
    if (this.fd !== null) {
      fs.writeSync(this.fd, JSON.stringify(entry) + "\n");
    }

    // Write to SQLite
    if (this.insertStmt) {
      try {
        this.insertStmt.run(
          entry.timestamp,
          entry.machineId,
          entry.method,
          entry.target,
          entry.action,
          JSON.stringify(entry.injectedSecrets),
        );
      } catch {
        // Don't crash the proxy if audit DB write fails
      }
    }
  }
}
