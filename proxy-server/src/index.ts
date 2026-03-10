import { loadConfig } from "./config/loader.js";
import { createLogger } from "./utils/logger.js";
import { loadCertManager } from "./proxy/cert-manager.js";
import { SecretCache } from "./secrets/cache.js";
import { EnvProvider } from "./secrets/env-provider.js";
import { AwsProvider } from "./secrets/aws-provider.js";
import { SecretResolver } from "./secrets/resolver.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { ProxyServer } from "./proxy/server.js";
import { Authenticator } from "./auth/authenticator.js";
import { TunnelServer } from "./tunnel/tunnel-server.js";
import type { SecretProvider } from "./secrets/types.js";

async function main() {
  // Determine config file path: CLI arg > env > default
  const configPath =
    process.argv[2] ||
    process.env.GUARDIAN_CONFIG ||
    "config/server-config.yaml";

  let config;
  try {
    config = loadConfig(configPath);
  } catch (err) {
    console.error(`Failed to load config from ${configPath}:`, err);
    process.exit(1);
  }

  const logger = createLogger({
    level: config.logging.level,
    name: "guardian-proxy",
  });

  logger.info({ configPath }, "Configuration loaded");

  // Load CA certificate manager
  let certManager;
  try {
    certManager = loadCertManager(config.ca.certFile, config.ca.keyFile);
    logger.info("CA certificate loaded");
  } catch (err) {
    logger.fatal({ err }, "Failed to load CA certificate — run `pnpm run generate-ca` first");
    process.exit(1);
  }

  // Set up secret providers
  const providers = new Map<string, SecretProvider>();
  providers.set("env", new EnvProvider());

  if (Object.values(config.secrets).some((s) => s.provider === "aws")) {
    providers.set("aws", new AwsProvider(config.aws.region));
    logger.info({ region: config.aws.region }, "AWS Secrets Manager provider enabled");
  }

  // Set up cache and resolver
  const cache = new SecretCache(
    config.cache.enabled ? config.cache.defaultTtlSeconds * 1000 : 0,
  );
  const resolver = new SecretResolver(providers, cache, logger);

  // Set up audit logger
  const auditLogger = new AuditLogger(config.logging.audit);

  // Create and start proxy
  const proxy = new ProxyServer({
    config,
    certManager,
    resolver,
    auditLogger,
    logger,
  });

  await proxy.start();

  // Start tunnel server if configured
  let tunnelServer: TunnelServer | null = null;
  if (config.tunnel?.enabled) {
    const authenticator = new Authenticator(config.auth);
    tunnelServer = new TunnelServer({
      tunnelConfig: config.tunnel,
      authenticator,
      proxyServer: proxy,
      logger,
    });
    await tunnelServer.start();
  }

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info({ signal }, "Shutting down...");
    try {
      if (tunnelServer) {
        await tunnelServer.stop();
      }
      await proxy.stop();
      logger.info("Proxy server stopped gracefully");
    } catch (err) {
      logger.error({ err }, "Error during shutdown");
    }
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
