import type Database from "better-sqlite3";
import type { AuthConfig } from "../../config/schema.js";
import { hashToken } from "./clients.js";
import { createLogger } from "../../utils/logger.js";

const logger = createLogger({ name: "config-migration" });

export function migrateConfigClients(db: Database.Database, authConfig: AuthConfig): { migrated: number; skipped: number } {
  let migrated = 0;
  let skipped = 0;

  const insert = db.prepare(
    "INSERT OR IGNORE INTO clients (machine_id, token_hash, description, source_cidrs) VALUES (?, ?, ?, ?)"
  );

  const transaction = db.transaction(() => {
    for (const client of authConfig.clients) {
      const tokenHash = hashToken(client.token);
      const result = insert.run(
        client.machineId,
        tokenHash,
        "Migrated from config",
        JSON.stringify(client.sourceCidrs ?? []),
      );
      if (result.changes > 0) {
        migrated++;
        logger.info({ machineId: client.machineId }, "Migrated config client to database");
      } else {
        skipped++;
      }
    }
  });

  transaction();

  if (migrated > 0) {
    logger.info({ migrated, skipped }, "Config client migration complete");
  }

  return { migrated, skipped };
}
