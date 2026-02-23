import type { SecretProvider } from "./types.js";
import type { SecretCache } from "./cache.js";
import type { SecretConfig } from "../config/schema.js";
import { createLogger, type Logger } from "../utils/logger.js";

const defaultLogger = createLogger({ name: "secret-resolver" });

export class SecretResolver {
  private providers: Map<string, SecretProvider>;
  private cache: SecretCache;
  private logger: Logger;

  constructor(
    providers: Map<string, SecretProvider>,
    cache: SecretCache,
    logger?: Logger
  ) {
    this.providers = providers;
    this.cache = cache;
    this.logger = logger ?? defaultLogger;
  }

  async resolve(
    secretName: string,
    secretConfig: SecretConfig
  ): Promise<string | null> {
    const cacheKey = `${secretConfig.provider}:${secretConfig.path}:${secretConfig.field ?? ""}`;

    const cached = this.cache.get(cacheKey);
    if (cached !== null) {
      return cached;
    }

    const provider = this.providers.get(secretConfig.provider);
    if (!provider) {
      this.logger.warn(
        { secretName, provider: secretConfig.provider },
        "Unknown secret provider"
      );
      return null;
    }

    try {
      const value = await provider.getSecret(
        secretConfig.path,
        secretConfig.field
      );
      if (value !== null) {
        this.cache.set(cacheKey, value);
      }
      return value;
    } catch (err) {
      this.logger.warn(
        { err, secretName, provider: secretConfig.provider },
        "Secret provider error"
      );
      return null;
    }
  }
}
