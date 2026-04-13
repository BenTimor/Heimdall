import type { AuthBackend, ClientLookup } from "./auth-backend.js";
import type { AuthConfig } from "../config/schema.js";

export class ConfigAuthBackend implements AuthBackend {
  private clients: Map<string, AuthConfig["clients"][number]>;

  constructor(config: AuthConfig) {
    this.clients = new Map();
    for (const c of config.clients) {
      this.clients.set(c.machineId, c);
    }
  }

  findClient(machineId: string): ClientLookup | null {
    const client = this.clients.get(machineId);
    if (!client) return null;
    return {
      tokenOrHash: client.token,
      isHashed: false,
      enabled: true,
      sourceCidrs: client.sourceCidrs ?? [],
    };
  }
}
