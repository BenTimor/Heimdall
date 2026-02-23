import { describe, it, expect } from "vitest";
import { Authenticator } from "../src/auth/authenticator.js";
import type { AuthConfig } from "../src/config/schema.js";

const config: AuthConfig = {
  enabled: true,
  clients: [
    { machineId: "dev-laptop-1", token: "secret-token-123" },
    { machineId: "ci-runner-7", token: "another-token-456" },
  ],
};

function makeBasicHeader(machineId: string, token: string): string {
  return `Basic ${Buffer.from(`${machineId}:${token}`).toString("base64")}`;
}

describe("Authenticator", () => {
  it("authenticates valid credentials", () => {
    const auth = new Authenticator(config);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "secret-token-123")
    );
    expect(result.authenticated).toBe(true);
    expect(result.machineId).toBe("dev-laptop-1");
  });

  it("rejects wrong token", () => {
    const auth = new Authenticator(config);
    const result = auth.authenticate(
      makeBasicHeader("dev-laptop-1", "wrong-token")
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toBe("Invalid token");
  });

  it("rejects missing header", () => {
    const auth = new Authenticator(config);
    const result = auth.authenticate(undefined);
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Missing");
  });

  it("rejects malformed base64", () => {
    const auth = new Authenticator(config);
    // Valid base64 but no colon in decoded string
    const result = auth.authenticate(
      `Basic ${Buffer.from("no-colon-here").toString("base64")}`
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Malformed credentials");
  });

  it("rejects non-Basic auth scheme", () => {
    const auth = new Authenticator(config);
    const result = auth.authenticate("Bearer some-token");
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Malformed");
  });

  it("allows anonymous when auth is disabled", () => {
    const disabledAuth = new Authenticator({ enabled: false, clients: [] });
    const result = disabledAuth.authenticate(undefined);
    expect(result.authenticated).toBe(true);
    expect(result.machineId).toBe("anonymous");
  });

  it("rejects unknown machine ID", () => {
    const auth = new Authenticator(config);
    const result = auth.authenticate(
      makeBasicHeader("unknown-machine", "secret-token-123")
    );
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain("Unknown machine ID");
  });
});
