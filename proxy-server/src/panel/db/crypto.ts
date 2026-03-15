import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createLogger } from "../../utils/logger.js";

const logger = createLogger({ name: "panel-crypto" });

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export function loadOrCreateEncryptionKey(keyFile: string): Buffer {
  const dir = path.dirname(keyFile);
  fs.mkdirSync(dir, { recursive: true });

  if (fs.existsSync(keyFile)) {
    const key = fs.readFileSync(keyFile);
    if (key.length !== 32) {
      throw new Error(`Encryption key file must be exactly 32 bytes, got ${key.length}`);
    }
    logger.info("Loaded existing encryption key");
    return key;
  }

  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  logger.info({ keyFile }, "Generated new encryption key");
  return key;
}

export function encryptSecret(plaintext: string, key: Buffer): EncryptedData {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { encrypted, iv, authTag };
}

export function decryptSecret(data: EncryptedData, key: Buffer): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, data.iv);
  decipher.setAuthTag(data.authTag);
  const decrypted = Buffer.concat([decipher.update(data.encrypted), decipher.final()]);
  return decrypted.toString("utf-8");
}
