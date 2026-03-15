import type Database from "better-sqlite3";
import type { AuthBackend, ClientLookup } from "./auth-backend.js";

interface ClientRow {
  token_hash: string;
  enabled: number;
}

export class DbAuthBackend implements AuthBackend {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  findClient(machineId: string): ClientLookup | null {
    const row = this.db.prepare(
      "SELECT token_hash, enabled FROM clients WHERE machine_id = ?"
    ).get(machineId) as ClientRow | undefined;

    if (!row) return null;

    return {
      tokenOrHash: row.token_hash,
      isHashed: true,
      enabled: row.enabled === 1,
    };
  }
}
