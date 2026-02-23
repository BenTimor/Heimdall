import type { SecretProvider } from "./types.js";

export class EnvProvider implements SecretProvider {
  readonly name = "env";

  async getSecret(path: string): Promise<string | null> {
    return process.env[path] ?? null;
  }
}
