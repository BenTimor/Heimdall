import crypto from "node:crypto";
import type { AuthBackend } from "./auth-backend.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger({ name: "authenticator" });

export interface AuthResult {
  authenticated: boolean;
  machineId?: string;
  error?: string;
}

export class Authenticator {
  private enabled: boolean;
  private backend: AuthBackend;

  constructor(config: { enabled: boolean }, backend: AuthBackend) {
    this.enabled = config.enabled;
    this.backend = backend;
    if (!config.enabled) {
      logger.warn("Proxy authentication is DISABLED — all requests will be accepted without credentials");
    }
  }

  authenticate(proxyAuthHeader?: string): AuthResult {
    if (!this.enabled) {
      return { authenticated: true, machineId: "anonymous" };
    }

    if (!proxyAuthHeader) {
      return { authenticated: false, error: "Missing Proxy-Authorization header" };
    }

    const parts = proxyAuthHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Basic") {
      return { authenticated: false, error: "Malformed Proxy-Authorization header" };
    }

    let decoded: string;
    try {
      decoded = Buffer.from(parts[1], "base64").toString("utf-8");
    } catch {
      return { authenticated: false, error: "Invalid base64 in Proxy-Authorization" };
    }

    const colonIdx = decoded.indexOf(":");
    if (colonIdx === -1) {
      return { authenticated: false, error: "Malformed credentials — missing colon separator" };
    }

    const machineId = decoded.slice(0, colonIdx);
    const token = decoded.slice(colonIdx + 1);

    const client = this.backend.findClient(machineId);
    if (!client) {
      return { authenticated: false, error: "Unknown machine ID" };
    }

    if (!client.enabled) {
      return { authenticated: false, error: "Client is disabled" };
    }

    if (client.isHashed) {
      // DB backend: hash the incoming token and compare against stored hash
      const incomingHash = crypto.createHash("sha256").update(token).digest("hex");
      const hashBuf = Buffer.from(incomingHash, "utf-8");
      const expectedBuf = Buffer.from(client.tokenOrHash, "utf-8");

      if (hashBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(hashBuf, expectedBuf)) {
        return { authenticated: false, error: "Invalid token" };
      }
    } else {
      // Config backend: plain-text comparison
      const tokenBuf = Buffer.from(token, "utf-8");
      const expectedBuf = Buffer.from(client.tokenOrHash, "utf-8");

      if (tokenBuf.length !== expectedBuf.length) {
        return { authenticated: false, error: "Invalid token" };
      }

      if (!crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
        return { authenticated: false, error: "Invalid token" };
      }
    }

    return { authenticated: true, machineId };
  }
}
