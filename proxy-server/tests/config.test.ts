import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { ServerConfigSchema } from "../src/config/schema.js";
import { loadConfig } from "../src/config/loader.js";

describe("ServerConfigSchema", () => {
  it("parses a full valid config", () => {
    const input = {
      proxy: {
        port: 9090,
        host: "127.0.0.1",
        tcpNoDelay: true,
        connectionPool: {
          enabled: true,
          idleTtlMs: 15_000,
          maxPerHost: 8,
          maxTotal: 512,
          cleanupIntervalMs: 5_000,
        },
      },
      ca: { certFile: "ca.crt", keyFile: "ca.key" },
      secrets: {
        MY_KEY: {
          provider: "env",
          path: "MY_KEY",
          allowedDomains: ["example.com"],
        },
      },
      cache: { enabled: false, defaultTtlSeconds: 60 },
      auth: {
        enabled: true,
        clients: [{ machineId: "m1", token: "t1" }],
      },
      bypass: { domains: ["*.corp"] },
      aws: { region: "eu-west-1" },
      logging: {
        level: "debug",
        audit: { enabled: true, file: "a.jsonl" },
        latency: { enabled: true },
      },
    };
    const result = ServerConfigSchema.parse(input);
    expect(result.proxy.port).toBe(9090);
    expect(result.secrets.MY_KEY.provider).toBe("env");
    expect(result.auth.clients).toHaveLength(1);
    expect(result.proxy.connectionPool.maxPerHost).toBe(8);
    expect(result.logging.latency.enabled).toBe(true);
  });

  it("applies default values for missing optional fields", () => {
    const result = ServerConfigSchema.parse({});
    expect(result.proxy.port).toBe(8080);
    expect(result.proxy.host).toBe("0.0.0.0");
    expect(result.cache.enabled).toBe(true);
    expect(result.cache.defaultTtlSeconds).toBe(300);
    expect(result.auth.enabled).toBe(true);
    expect(result.aws.region).toBe("us-east-1");
    expect(result.proxy.tcpNoDelay).toBe(true);
    expect(result.proxy.connectionPool.enabled).toBe(true);
    expect(result.logging.level).toBe("info");
    expect(result.logging.latency.enabled).toBe(false);
  });

  it("rejects invalid port", () => {
    expect(() =>
      ServerConfigSchema.parse({ proxy: { port: 99999 } })
    ).toThrow();
  });

  it("rejects secret config missing provider", () => {
    expect(() =>
      ServerConfigSchema.parse({
        secrets: { KEY: { path: "x" } },
      })
    ).toThrow();
  });

  it("rejects secret config missing path", () => {
    expect(() =>
      ServerConfigSchema.parse({
        secrets: { KEY: { provider: "env" } },
      })
    ).toThrow();
  });
});

describe("loadConfig", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "heimdall-test-"));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads and parses a valid YAML file", () => {
    const file = path.join(tmpDir, "valid.yaml");
    fs.writeFileSync(
      file,
      `proxy:\n  port: 3000\nsecrets:\n  X:\n    provider: env\n    path: X\n    allowedDomains: ["a.com"]\n`
    );
    const cfg = loadConfig(file);
    expect(cfg.proxy.port).toBe(3000);
    expect(cfg.secrets.X.provider).toBe("env");
  });

  it("throws on missing file", () => {
    expect(() => loadConfig(path.join(tmpDir, "nope.yaml"))).toThrow(
      /Failed to read config file/
    );
  });

  it("throws on invalid YAML", () => {
    const file = path.join(tmpDir, "bad.yaml");
    fs.writeFileSync(file, `proxy:\n  port: :\n`);
    expect(() => loadConfig(file)).toThrow(/Failed to parse YAML/);
  });

  it("throws on Zod validation failure", () => {
    const file = path.join(tmpDir, "invalid.yaml");
    fs.writeFileSync(file, `proxy:\n  port: 99999\n`);
    expect(() => loadConfig(file)).toThrow(/Config validation failed/);
  });
});
