import fs from "node:fs";
import * as fsp from "node:fs/promises";
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

/** Maximum entries in the JSONL write buffer before auto-flush. */
const FILE_BUFFER_LIMIT = 50;
/** Maximum entries in the SQLite batch buffer before auto-flush. */
const DB_BUFFER_LIMIT = 50;
/** Periodic flush interval in milliseconds. */
const FLUSH_INTERVAL_MS = 100;

export class AuditLogger {
  private filePath: string | null = null;
  private enabled: boolean;
  private db: Database.Database | null = null;
  private insertStmt: Database.Statement | null = null;

  /** Buffered JSONL lines waiting to be flushed to disk. */
  private fileBuffer: string[] = [];
  /** Buffered entries waiting to be flushed to SQLite. */
  private dbBuffer: AuditEntry[] = [];
  /** SQLite batch insert transaction (prepared lazily). */
  private batchInsert: ((entries: AuditEntry[]) => void) | null = null;

  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;

  constructor(config: { enabled: boolean; file?: string }, db?: Database.Database) {
    this.enabled = config.enabled;

    if (this.enabled && config.file) {
      const dir = path.dirname(config.file);
      fs.mkdirSync(dir, { recursive: true });
      this.filePath = config.file;
    }

    if (db) {
      this.db = db;
      this.insertStmt = db.prepare(
        "INSERT INTO audit_log (timestamp, machine_id, method, target, action, injected_secrets) VALUES (?, ?, ?, ?, ?, ?)"
      );
      // Wrap batch insert in a transaction for efficiency
      this.batchInsert = db.transaction((entries: AuditEntry[]) => {
        for (const entry of entries) {
          this.insertStmt!.run(
            entry.timestamp,
            entry.machineId,
            entry.method,
            entry.target,
            entry.action,
            JSON.stringify(entry.injectedSecrets),
          );
        }
      });
    }

    if (this.enabled && (this.filePath || this.db)) {
      this.flushTimer = setInterval(() => this.flushSync(), FLUSH_INTERVAL_MS);
      this.flushTimer.unref();
    }
  }

  logRequest(entry: AuditEntry): void {
    if (!this.enabled) return;

    // Push to JSONL buffer
    if (this.filePath !== null) {
      this.fileBuffer.push(JSON.stringify(entry) + "\n");
    }

    // Push to SQLite buffer
    if (this.insertStmt) {
      this.dbBuffer.push(entry);
    }

    // Auto-flush when buffers are full
    if (this.fileBuffer.length >= FILE_BUFFER_LIMIT || this.dbBuffer.length >= DB_BUFFER_LIMIT) {
      this.flushSync();
    }
  }

  /**
   * Flush all buffered entries to disk and SQLite synchronously.
   * Safe to call from the periodic timer or on shutdown.
   */
  private flushSync(): void {
    if (this.flushing) return;
    this.flushing = true;

    try {
      // Flush JSONL file buffer
      if (this.filePath && this.fileBuffer.length > 0) {
        const data = this.fileBuffer.join("");
        this.fileBuffer.length = 0;
        // Use async write — fire and forget (data already captured above)
        fsp.appendFile(this.filePath, data).catch(() => {
          // Don't crash on file write failure
        });
      }

      // Flush SQLite buffer in a single transaction
      if (this.batchInsert && this.dbBuffer.length > 0) {
        const entries = this.dbBuffer.splice(0);
        try {
          this.batchInsert(entries);
        } catch {
          // Don't crash the proxy if audit DB write fails
        }
      }
    } finally {
      this.flushing = false;
    }
  }

  /**
   * Flush all pending entries. Call during graceful shutdown.
   */
  async flush(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    // Flush JSONL synchronously to ensure nothing is lost
    if (this.filePath && this.fileBuffer.length > 0) {
      const data = this.fileBuffer.join("");
      this.fileBuffer.length = 0;
      await fsp.appendFile(this.filePath, data);
    }

    // Flush SQLite
    if (this.batchInsert && this.dbBuffer.length > 0) {
      const entries = this.dbBuffer.splice(0);
      try {
        this.batchInsert(entries);
      } catch {
        // Don't crash
      }
    }
  }
}
