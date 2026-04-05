import * as fs from "node:fs";
import forge from "node-forge";
import { loadConfig } from "./config/loader.js";
import { createLogger } from "./utils/logger.js";
import { loadCertManager } from "./proxy/cert-manager.js";
import { SecretCache } from "./secrets/cache.js";
import { EnvProvider } from "./secrets/env-provider.js";
import { AwsProvider } from "./secrets/aws-provider.js";
import { StoredProvider } from "./secrets/stored-provider.js";
import { SecretResolver } from "./secrets/resolver.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { ProxyServer } from "./proxy/server.js";
import { ConnectionPool } from "./proxy/connection-pool.js";
import { UpstreamHttp2Pool } from "./proxy/upstream-http2-pool.js";
import { Authenticator } from "./auth/authenticator.js";
import { ConfigAuthBackend } from "./auth/config-backend.js";
import { DbAuthBackend } from "./auth/db-backend.js";
import { CompositeAuthBackend } from "./auth/composite-backend.js";
import { TunnelServer } from "./tunnel/tunnel-server.js";
import { initDatabase } from "./panel/db/database.js";
import { loadOrCreateEncryptionKey } from "./panel/db/crypto.js";
import { migrateConfigClients } from "./panel/db/migrate-config.js";
import { listSecrets } from "./panel/db/secrets.js";
import { startPanelServer } from "./panel/server.js";
import type { SecretProvider } from "./secrets/types.js";
import type { SecretConfig } from "./config/schema.js";
import type Database from "better-sqlite3";

async function main() {
  // Determine config file path: CLI arg > env > default
  const configPath =
    process.argv[2] ||
    process.env.HEIMDALL_CONFIG ||
    "config/server-config.yaml";

  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(configPath);
  } catch (err) {
    console.error(`Failed to load config from ${configPath}:`, err);
    process.exit(1);
  }

  const logger = createLogger({
    level: config.logging.level,
    name: "heimdall-proxy",
  });

  logger.info({ configPath }, "Configuration loaded");

  // Load CA certificate manager with OCSP responder URL (AIA extension)
  const ocspHost = config.proxy.publicHost ?? "127.0.0.1";
  const ocspUrl = `http://${ocspHost}:${config.proxy.port}/ocsp`;
  let certManager;
  try {
    certManager = loadCertManager(config.ca.certFile, config.ca.keyFile, ocspUrl);
    logger.info({ ocspUrl }, "CA certificate loaded with OCSP responder URL");
  } catch (err) {
    logger.fatal({ err }, "Failed to load CA certificate — run `pnpm run generate-ca` first");
    process.exit(1);
  }

  // Parse CA cert/key for the OCSP responder endpoint
  const caCertPem = fs.readFileSync(config.ca.certFile, "utf-8");
  const caKeyPem = fs.readFileSync(config.ca.keyFile, "utf-8");
  const caCert = forge.pki.certificateFromPem(caCertPem);
  const caKey = forge.pki.privateKeyFromPem(caKeyPem);

  // Initialize panel database if panel is enabled
  let db: Database.Database | undefined;
  let encryptionKey: Buffer | undefined;
  const panelConfig = config.panel;

  if (panelConfig?.enabled) {
    db = initDatabase(panelConfig.dbPath);
    encryptionKey = loadOrCreateEncryptionKey(panelConfig.encryptionKeyFile);
    migrateConfigClients(db, config.auth);
  }

  // Set up secret providers
  const providers = new Map<string, SecretProvider>();
  providers.set("env", new EnvProvider());

  // Hoist AWS provider — needed for panel secret writes even if no YAML secrets use AWS
  let awsProvider: AwsProvider | undefined;
  if (Object.values(config.secrets).some((s) => s.provider === "aws") || panelConfig?.enabled) {
    awsProvider = new AwsProvider(config.aws.region);
    providers.set("aws", awsProvider);
    logger.info({ region: config.aws.region }, "AWS Secrets Manager provider enabled");
  }

  if (db && encryptionKey) {
    providers.set("stored", new StoredProvider(db, encryptionKey));
    logger.info("Stored secret provider enabled (panel DB)");
  }

  // Set up cache and resolver
  const cache = new SecretCache(
    config.cache.enabled ? config.cache.defaultTtlSeconds * 1000 : 0,
  );
  const resolver = new SecretResolver(providers, cache, logger);

  // Set up authenticator with appropriate backend
  const configBackend = new ConfigAuthBackend(config.auth);
  let authenticator: Authenticator;

  if (db) {
    const dbBackend = new DbAuthBackend(db);
    const compositeBackend = new CompositeAuthBackend(dbBackend, configBackend);
    authenticator = new Authenticator({ enabled: config.auth.enabled }, compositeBackend);
  } else {
    authenticator = new Authenticator({ enabled: config.auth.enabled }, configBackend);
  }

  // Set up audit logger (dual-write to JSONL + SQLite when panel is enabled)
  const auditLogger = new AuditLogger(config.logging.audit, db);

  // Build merged secrets config (YAML + DB)
  function buildSecretsConfig(): Record<string, SecretConfig> {
    const merged = { ...config.secrets };
    if (db) {
      for (const secret of listSecrets(db)) {
        merged[secret.name] = {
          provider: secret.provider,
          path: secret.provider === "stored" ? secret.name : secret.path,
          field: secret.field || undefined,
          allowedDomains: secret.allowedDomains,
        };
      }
    }
    return merged;
  }

  // Create upstream connection pools for MITM forwarding
  const connectionPool = config.proxy.connectionPool.enabled
    ? new ConnectionPool(logger, {
        idleTtlMs: config.proxy.connectionPool.idleTtlMs,
        maxPerHost: config.proxy.connectionPool.maxPerHost,
        maxTotal: config.proxy.connectionPool.maxTotal,
        cleanupIntervalMs: config.proxy.connectionPool.cleanupIntervalMs,
        tcpNoDelay: config.proxy.tcpNoDelay,
      })
    : null;

  const upstreamHttp2Pool = new UpstreamHttp2Pool(logger, {
    idleTtlMs: config.proxy.connectionPool.idleTtlMs,
    cleanupIntervalMs: config.proxy.connectionPool.cleanupIntervalMs,
    tcpNoDelay: config.proxy.tcpNoDelay,
  });

  // Create and start proxy
  const proxy = new ProxyServer({
    config,
    certManager,
    resolver,
    auditLogger,
    authenticator,
    logger,
    caCert,
    caKey,
    connectionPool: connectionPool ?? undefined,
    upstreamHttp2Pool,
  });

  // Apply initial merged secrets config
  proxy.updateSecretsConfig(buildSecretsConfig());

  await proxy.start();

  // Start tunnel server if configured
  let tunnelServer: TunnelServer | null = null;
  if (config.tunnel?.enabled) {
    tunnelServer = new TunnelServer({
      tunnelConfig: config.tunnel,
      authenticator,
      proxyServer: proxy,
      logger,
      tcpNoDelay: config.proxy.tcpNoDelay,
      latencyLoggingEnabled: config.logging.latency.enabled,
    });
    await tunnelServer.start();
  }

  // Start admin panel if configured
  let panelStop: (() => Promise<void>) | null = null;
  if (panelConfig?.enabled && db && encryptionKey) {
    const panel = await startPanelServer({
      config: panelConfig,
      db,
      encryptionKey,
      logger,
      proxyPort: config.proxy.port,
      tunnelPort: config.tunnel?.port,
      reloadSecrets: () => {
        proxy.updateSecretsConfig(buildSecretsConfig());
        logger.info("Secrets config reloaded from database");
      },
      awsProvider,
    });
    panelStop = panel.stop;
  }

  // Graceful shutdown (guard against repeated signals)
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, "Shutting down...");
    try {
      if (panelStop) {
        await panelStop();
      }
      if (tunnelServer) {
        await tunnelServer.stop();
      }
      await proxy.stop();
      connectionPool?.close();
      upstreamHttp2Pool.close();
      if (db) {
        db.close();
      }
      logger.info("Proxy server stopped gracefully");
    } catch (err) {
      logger.error({ err }, "Error during shutdown");
    }
    process.exit(0);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // Safety nets — prevent the process from crashing on stray socket errors.
  // Every socket SHOULD have its own error handler, but if one is missed
  // (e.g. race during tunnel teardown), log it instead of crashing.
  process.on("uncaughtException", (err) => {
    logger.error({ err }, "Uncaught exception");
  });
  process.on("unhandledRejection", (reason) => {
    logger.error({ err: reason }, "Unhandled rejection");
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
