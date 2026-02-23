import crypto from "node:crypto";
import type { AuthConfig } from "../config/schema.js";

export interface AuthResult {
  authenticated: boolean;
  machineId?: string;
  error?: string;
}

export class Authenticator {
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  authenticate(proxyAuthHeader?: string): AuthResult {
    if (!this.config.enabled) {
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

    const client = this.config.clients.find((c) => c.machineId === machineId);
    if (!client) {
      return { authenticated: false, error: "Unknown machine ID" };
    }

    const tokenBuf = Buffer.from(token, "utf-8");
    const expectedBuf = Buffer.from(client.token, "utf-8");

    if (tokenBuf.length !== expectedBuf.length) {
      return { authenticated: false, error: "Invalid token" };
    }

    if (!crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
      return { authenticated: false, error: "Invalid token" };
    }

    return { authenticated: true, machineId };
  }
}
