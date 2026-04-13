import type Database from "better-sqlite3";
import type { AuthBackend, ClientLookup } from "./auth-backend.js";

interface ClientRow {
  token_hash: string;
  enabled: number;
  source_cidrs: string;
}

export class DbAuthBackend implements AuthBackend {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  findClient(machineId: string): ClientLookup | null {
    const row = this.db.prepare(
      "SELECT token_hash, enabled, source_cidrs FROM clients WHERE machine_id = ?"
    ).get(machineId) as ClientRow | undefined;

    if (!row) return null;

    let sourceCidrs: string[] = [];
    try {
      sourceCidrs = JSON.parse(row.source_cidrs || "[]");
    } catch {
      sourceCidrs = [];
    }

    return {
      tokenOrHash: row.token_hash,
      isHashed: true,
      enabled: row.enabled === 1,
      sourceCidrs,
    };
  }
}
