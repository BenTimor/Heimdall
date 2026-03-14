import type { SecretConfig } from "../config/schema.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { Logger } from "../utils/logger.js";
import { scanHeaders } from "./scanner.js";
import { matchesAnyDomain } from "../utils/domain-matcher.js";
import { createLogger } from "../utils/logger.js";

export interface InjectionResult {
  secretName: string;
  headerName: string;
  status: "injected" | "domain_mismatch" | "not_found" | "no_config";
}

const defaultLogger = createLogger({ name: "injector" });

export async function injectSecrets(
  targetDomain: string,
  headers: Record<string, string>,
  secretsConfig: Record<string, SecretConfig>,
  resolver: SecretResolver,
  logger?: Logger
): Promise<{
  injectedHeaders: Record<string, string>;
  injections: InjectionResult[];
}> {
  const log = logger ?? defaultLogger;
  const scanResult = scanHeaders(headers);
  const injections: InjectionResult[] = [];
  const injectedHeaders = { ...headers };

  for (const { headerName, placeholder, secretName } of scanResult.placeholders) {
    const config = secretsConfig[secretName];
    if (!config) {
      log.warn({ secretName }, "No config found for secret placeholder");
      injections.push({
        secretName,
        headerName,
        status: "no_config",
      });
      continue;
    }

    if (!matchesAnyDomain(targetDomain, config.allowedDomains)) {
      log.warn(
        { secretName, targetDomain, allowedDomains: config.allowedDomains },
        "Domain mismatch — refusing to inject secret (possible exfiltration)"
      );
      // Remove the placeholder to avoid leaking secret names
      injectedHeaders[headerName] = injectedHeaders[headerName].replaceAll(
        placeholder,
        ""
      );
      injections.push({
        secretName,
        headerName,
        status: "domain_mismatch",
      });
      continue;
    }

    const value = await resolver.resolve(secretName, config);
    if (value === null) {
      log.warn({ secretName }, "Secret not found or provider returned null");
      injections.push({
        secretName,
        headerName,
        status: "not_found",
      });
      continue;
    }

    injectedHeaders[headerName] = injectedHeaders[headerName].replaceAll(
      placeholder,
      value
    );
    injections.push({
      secretName,
      headerName,
      status: "injected",
    });
  }

  return { injectedHeaders, injections };
}
