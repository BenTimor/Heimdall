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

  // First pass: categorize placeholders and identify which need resolution
  interface PendingResolution {
    index: number;
    headerName: string;
    placeholder: string;
    secretName: string;
    config: SecretConfig;
  }

  const pending: PendingResolution[] = [];

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

    pending.push({
      index: pending.length,
      headerName,
      placeholder,
      secretName,
      config,
    });
  }

  // Second pass: resolve all eligible secrets concurrently
  const results = await Promise.all(
    pending.map((p) => resolver.resolve(p.secretName, p.config).catch(() => null))
  );

  // Third pass: apply resolved values to headers
  for (let i = 0; i < pending.length; i++) {
    const p = pending[i];
    const value = results[i];

    if (value === null) {
      log.warn({ secretName: p.secretName }, "Secret not found or provider returned null");
      injections.push({
        secretName: p.secretName,
        headerName: p.headerName,
        status: "not_found",
      });
      continue;
    }

    injectedHeaders[p.headerName] = injectedHeaders[p.headerName].replaceAll(
      p.placeholder,
      value
    );
    injections.push({
      secretName: p.secretName,
      headerName: p.headerName,
      status: "injected",
    });
  }

  const failed = injections.filter((i) => i.status !== "injected");
  if (failed.length > 0) {
    log.info(
      { targetDomain, failures: failed.map((f) => ({ secretName: f.secretName, status: f.status })) },
      "Injection failures detected",
    );
  }

  return { injectedHeaders, injections };
}
