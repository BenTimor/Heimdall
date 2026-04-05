import { z } from "zod";

export const SecretConfigSchema = z.object({
  provider: z.string(),
  path: z.string(),
  field: z.string().optional(),
  allowedDomains: z.array(z.string()).default([]),
});

export type SecretConfig = z.infer<typeof SecretConfigSchema>;

export const AuthClientSchema = z.object({
  machineId: z.string(),
  token: z.string(),
});

export type AuthClient = z.infer<typeof AuthClientSchema>;

export const AuthConfigSchema = z.object({
  enabled: z.boolean().default(true),
  clients: z.array(AuthClientSchema).default([]),
});

export type AuthConfig = z.infer<typeof AuthConfigSchema>;

export const ConnectionPoolConfigSchema = z.object({
  enabled: z.boolean().default(true),
  idleTtlMs: z.number().int().min(0).default(30_000),
  maxPerHost: z.number().int().positive().default(6),
  maxTotal: z.number().int().positive().default(256),
  cleanupIntervalMs: z.number().int().positive().default(10_000),
});

export const ProxyConfigSchema = z.object({
  port: z.number().int().min(1).max(65535).default(8080),
  host: z.string().default("0.0.0.0"),
  /** Public IP/hostname reachable by clients — used for OCSP responder URL in MITM certs.
   *  If not set, falls back to 127.0.0.1 (only works when proxy runs on the same machine). */
  publicHost: z.string().optional(),
  /** Disable Nagle's algorithm on proxy-side sockets to reduce WAN latency for small frames. */
  tcpNoDelay: z.boolean().default(true),
  connectionPool: ConnectionPoolConfigSchema.default({}),
});

export const CaConfigSchema = z.object({
  certFile: z.string().default("certs/ca.crt"),
  keyFile: z.string().default("certs/ca.key"),
});

export const CacheConfigSchema = z.object({
  enabled: z.boolean().default(true),
  defaultTtlSeconds: z.number().int().min(0).default(300),
});

export const BypassConfigSchema = z.object({
  domains: z.array(z.string()).default([]),
});

export const AwsConfigSchema = z.object({
  region: z.string().default("us-east-1"),
});

export const AuditConfigSchema = z.object({
  enabled: z.boolean().default(true),
  file: z.string().optional(),
});

export const LatencyLoggingConfigSchema = z.object({
  enabled: z.boolean().default(false),
});

export const LoggingConfigSchema = z.object({
  level: z.string().default("info"),
  audit: AuditConfigSchema.default({}),
  latency: LatencyLoggingConfigSchema.default({}),
});

export const TunnelConfigSchema = z.object({
  enabled: z.boolean().default(false),
  port: z.number().int().min(1).max(65535).default(8443),
  host: z.string().default("0.0.0.0"),
  tls: z.object({
    certFile: z.string(),
    keyFile: z.string(),
  }),
  heartbeatIntervalMs: z.number().int().min(1000).default(30000),
  heartbeatTimeoutMs: z.number().int().min(2000).default(90000),
  maxConnectionsPerSession: z.number().positive().default(1000),
});

export type TunnelConfig = z.infer<typeof TunnelConfigSchema>;

export const PanelConfigSchema = z.object({
  enabled: z.boolean().default(false),
  port: z.number().int().min(1).max(65535).default(9090),
  host: z.string().default("127.0.0.1"),
  dbPath: z.string().default("data/heimdall.db"),
  defaultAdminPassword: z.string().default("change-me-immediately"),
  sessionTtlHours: z.number().int().min(1).default(24),
  encryptionKeyFile: z.string().default("data/encryption.key"),
});

export type PanelConfig = z.infer<typeof PanelConfigSchema>;

export const ServerConfigSchema = z.object({
  proxy: ProxyConfigSchema.default({}),
  ca: CaConfigSchema.default({}),
  secrets: z.record(z.string(), SecretConfigSchema).default({}),
  cache: CacheConfigSchema.default({}),
  auth: AuthConfigSchema.default({}),
  bypass: BypassConfigSchema.default({}),
  aws: AwsConfigSchema.default({}),
  logging: LoggingConfigSchema.default({}),
  tunnel: TunnelConfigSchema.optional(),
  panel: PanelConfigSchema.optional(),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;
