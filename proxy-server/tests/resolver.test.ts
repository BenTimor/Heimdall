import { describe, it, expect, vi, beforeEach } from "vitest";
import { SecretResolver } from "../src/secrets/resolver.js";
import { SecretCache } from "../src/secrets/cache.js";
import type { SecretProvider } from "../src/secrets/types.js";
import type { SecretConfig } from "../src/config/schema.js";

function createMockProvider(
  name: string,
  impl?: (path: string, field?: string) => Promise<string | null>
): SecretProvider {
  return {
    name,
    getSecret: vi.fn(impl ?? (async () => "mock-value")),
  };
}

describe("SecretResolver", () => {
  let cache: SecretCache;
  let envProvider: SecretProvider;
  let providers: Map<string, SecretProvider>;

  beforeEach(() => {
    cache = new SecretCache(60000);
    envProvider = createMockProvider("env");
    providers = new Map([["env", envProvider]]);
  });

  const secretConfig: SecretConfig = {
    provider: "env",
    path: "MY_SECRET",
    allowedDomains: ["api.example.com"],
  };

  it("resolves from provider on cache miss and stores in cache", async () => {
    const resolver = new SecretResolver(providers, cache);
    const result = await resolver.resolve("MY_SECRET", secretConfig);

    expect(result).toBe("mock-value");
    expect(envProvider.getSecret).toHaveBeenCalledWith("MY_SECRET", undefined);
    // Should now be cached
    expect(cache.get("env:MY_SECRET:")).toBe("mock-value");
  });

  it("returns cached value on cache hit without calling provider", async () => {
    cache.set("env:MY_SECRET:", "cached-value");
    const resolver = new SecretResolver(providers, cache);
    const result = await resolver.resolve("MY_SECRET", secretConfig);

    expect(result).toBe("cached-value");
    expect(envProvider.getSecret).not.toHaveBeenCalled();
  });

  it("returns null for unknown provider", async () => {
    const resolver = new SecretResolver(providers, cache);
    const result = await resolver.resolve("X", {
      provider: "vault",
      path: "x",
      allowedDomains: [],
    });
    expect(result).toBeNull();
  });

  it("returns null when provider throws", async () => {
    const failProvider = createMockProvider("fail", async () => {
      throw new Error("connection timeout");
    });
    const failProviders = new Map([["fail", failProvider]]);
    const resolver = new SecretResolver(failProviders, cache);

    const result = await resolver.resolve("X", {
      provider: "fail",
      path: "x",
      allowedDomains: [],
    });
    expect(result).toBeNull();
  });

  it("includes field in cache key", async () => {
    const resolver = new SecretResolver(providers, cache);
    const configWithField: SecretConfig = {
      provider: "env",
      path: "MY_SECRET",
      field: "api_key",
      allowedDomains: [],
    };
    await resolver.resolve("MY_SECRET", configWithField);
    expect(cache.get("env:MY_SECRET:api_key")).toBe("mock-value");
  });
});
