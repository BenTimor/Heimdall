import type { AuthBackend, ClientLookup } from "./auth-backend.js";

export class CompositeAuthBackend implements AuthBackend {
  private backends: AuthBackend[];

  constructor(...backends: AuthBackend[]) {
    this.backends = backends;
  }

  findClient(machineId: string): ClientLookup | null {
    for (const backend of this.backends) {
      const result = backend.findClient(machineId);
      if (result) return result;
    }
    return null;
  }
}
