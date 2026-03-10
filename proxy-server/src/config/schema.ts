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

export const ProxyConfigSchema = z.object({
  port: z.number().int().min(1).max(65535).default(8080),
  host: z.string().default("0.0.0.0"),
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

export const LoggingConfigSchema = z.object({
  level: z.string().default("info"),
  audit: AuditConfigSchema.default({}),
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
});

export type TunnelConfig = z.infer<typeof TunnelConfigSchema>;

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
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;
