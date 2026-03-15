import type { AuthBackend, ClientLookup } from "./auth-backend.js";
import type { AuthConfig } from "../config/schema.js";

export class ConfigAuthBackend implements AuthBackend {
  private clients: Map<string, string>;

  constructor(config: AuthConfig) {
    this.clients = new Map();
    for (const c of config.clients) {
      this.clients.set(c.machineId, c.token);
    }
  }

  findClient(machineId: string): ClientLookup | null {
    const token = this.clients.get(machineId);
    if (!token) return null;
    return { tokenOrHash: token, isHashed: false, enabled: true };
  }
}
