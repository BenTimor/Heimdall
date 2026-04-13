import { describe, it, expect } from "vitest";
import { Authenticator } from "../src/auth/authenticator.js";
import { ConfigAuthBackend } from "../src/auth/config-backend.js";
import type { AuthConfig } from "../src/config/schema.js";

const config: AuthConfig = {
  enabled: true,
  clients: [
    {
      machineId: "dev-laptop-1",
      token: "secret-token-123",
      sourceCidrs: ["203.0.113.10/32"],
    },
    { machineId: "ci-runner-7", token: "another-token-456" },
  ],
};

const backend = new ConfigAuthBackend(config);

function makeBasicHeader(machineId: string, token: string): string {
  return `Basic ${Buffer.from(`${machineId}:${token}`).toString("base64")}`;
}

describe("Authenticator", () => {
  it("authenticates valid credentials", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "secret-token-123"),
      { sourceIp: "203.0.113.10" },
    );
    expect(result.authenticated).toBe(true);
    expect(result.machineId).toBe("dev-laptop-1");
  });

  it("accepts IPv4-mapped source addresses for restricted clients", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "secret-token-123"),
      { sourceIp: "::ffff:203.0.113.10" },
    );
    expect(result.authenticated).toBe(true);
    expect(result.machineId).toBe("dev-laptop-1");
  });

  it("rejects wrong token", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "wrong-token")
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toBe("Invalid token");
  });

  it("rejects missing header", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(undefined);
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Missing");
  });

  it("rejects malformed base64", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    // Valid base64 but no colon in decoded string
    const result = auth.authenticate(
      `Basic ${Buffer.from("no-colon-here").toString("base64")}`
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Malformed credentials");
  });

  it("rejects non-Basic auth scheme", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate("Bearer some-token");
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Malformed");
  });

  it("allows anonymous when auth is disabled", () => {
    const disabledBackend = new ConfigAuthBackend({ enabled: false, clients: [] });
    const disabledAuth = new Authenticator({ enabled: false }, disabledBackend);
    const result = disabledAuth.authenticate(undefined);
    expect(result.authenticated).toBe(true);
    expect(result.machineId).toBe("anonymous");
  });

  it("rejects unknown machine ID", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("unknown-machine", "secret-token-123")
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Unknown machine ID");
  });

  it("rejects source-restricted clients when source IP is missing", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "secret-token-123")
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toBe("Source IP not allowed");
  });

  it("rejects source-restricted clients from non-allowed IPs", () => {
    const auth = new Authenticator({ enabled: true }, backend);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "secret-token-123"),
      { sourceIp: "198.51.100.8" },
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toBe("Source IP not allowed");
  });
});
