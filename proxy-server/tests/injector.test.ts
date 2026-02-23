import { describe, it, expect, vi } from "vitest";
import { injectSecrets } from "../src/injection/injector.js";
import type { SecretResolver } from "../src/secrets/resolver.js";
import type { SecretConfig } from "../src/config/schema.js";

function createMockResolver(
  impl?: (name: string, config: SecretConfig) => Promise<string | null>
): SecretResolver {
  return {
    resolve: vi.fn(impl ?? (async () => "resolved-secret")),
  } as unknown as SecretResolver;
}

const secretsConfig: Record<string, SecretConfig> = {
  OPENAI_API_KEY: {
    provider: "env",
    path: "OPENAI_API_KEY",
    allowedDomains: ["api.openai.com"],
  },
  ANTHROPIC_API_KEY: {
    provider: "env",
    path: "ANTHROPIC_API_KEY",
    allowedDomains: ["api.anthropic.com"],
  },
};

describe("injectSecrets", () => {
  it("injects a valid placeholder for a matching domain", async () => {
    const resolver = createMockResolver();
    const { injectedHeaders, injections } = await injectSecrets(
      "api.openai.com",
      { Authorization: "Bearer __OPENAI_API_KEY__" },
      secretsConfig,
      resolver
    );

    expect(injectedHeaders.Authorization).toBe("Bearer resolved-secret");
    expect(injections).toHaveLength(1);
    expect(injections[0].status).toBe("injected");
  });

  it("injects multiple placeholders in a single header", async () => {
    const config: Record<string, SecretConfig> = {
      KEY_A: {
        provider: "env",
        path: "KEY_A",
        allowedDomains: ["api.example.com"],
      },
      KEY_B: {
        provider: "env",
        path: "KEY_B",
        allowedDomains: ["api.example.com"],
      },
    };

    let callCount = 0;
    const resolver = createMockResolver(async () => {
      callCount++;
      return `val-${callCount}`;
    });

    const { injectedHeaders } = await injectSecrets(
      "api.example.com",
      { "X-Keys": "__KEY_A__ __KEY_B__" },
      config,
      resolver
    );

    expect(injectedHeaders["X-Keys"]).toBe("val-1 val-2");
  });

  it("injects across multiple headers", async () => {
    const resolver = createMockResolver();
    const { injections } = await injectSecrets(
      "api.openai.com",
      {
        Authorization: "Bearer __OPENAI_API_KEY__",
        "X-Extra": "something",
      },
      secretsConfig,
      resolver
    );

    expect(injections).toHaveLength(1);
    expect(injections[0].headerName).toBe("Authorization");
    expect(injections[0].status).toBe("injected");
  });

  it("refuses injection for wrong domain (exfiltration)", async () => {
    const resolver = createMockResolver();
    const { injectedHeaders, injections } = await injectSecrets(
      "evil.com",
      { Authorization: "Bearer __OPENAI_API_KEY__" },
      secretsConfig,
      resolver
    );

    expect(injectedHeaders.Authorization).toBe("Bearer ");
    expect(injections[0].status).toBe("domain_mismatch");
    expect(resolver.resolve).not.toHaveBeenCalled();
  });

  it("handles unknown secret name", async () => {
    const resolver = createMockResolver();
    const { injections } = await injectSecrets(
      "api.openai.com",
      { Authorization: "Bearer __UNKNOWN_SECRET__" },
      secretsConfig,
      resolver
    );

    expect(injections[0].status).toBe("no_config");
  });

  it("handles provider returning null", async () => {
    const resolver = createMockResolver(async () => null);
    const { injectedHeaders, injections } = await injectSecrets(
      "api.openai.com",
      { Authorization: "Bearer __OPENAI_API_KEY__" },
      secretsConfig,
      resolver
    );

    expect(injectedHeaders.Authorization).toBe("Bearer __OPENAI_API_KEY__");
    expect(injections[0].status).toBe("not_found");
  });
});
