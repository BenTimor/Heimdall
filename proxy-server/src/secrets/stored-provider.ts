import type { SecretProvider } from "./types.js";
import type Database from "better-sqlite3";
import { decryptSecret } from "../panel/db/crypto.js";

interface SecretRow {
  encrypted_value: Buffer | null;
  iv: Buffer | null;
  auth_tag: Buffer | null;
}

export class StoredProvider implements SecretProvider {
  readonly name = "stored";
  private db: Database.Database;
  private encryptionKey: Buffer;

  constructor(db: Database.Database, encryptionKey: Buffer) {
    this.db = db;
    this.encryptionKey = encryptionKey;
  }

  async getSecret(path: string, _field?: string): Promise<string | null> {
    // For stored provider, "path" is the secret name in the DB
    const row = this.db.prepare(
      "SELECT encrypted_value, iv, auth_tag FROM secrets WHERE name = ? AND provider = 'stored'"
    ).get(path) as SecretRow | undefined;

    if (!row || !row.encrypted_value || !row.iv || !row.auth_tag) {
      return null;
    }

    try {
      return decryptSecret(
        { encrypted: row.encrypted_value, iv: row.iv, authTag: row.auth_tag },
        this.encryptionKey,
      );
    } catch {
      return null;
    }
  }
}
