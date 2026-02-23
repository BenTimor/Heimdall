import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EnvProvider } from "../src/secrets/env-provider.js";

describe("EnvProvider", () => {
  const provider = new EnvProvider();
  const TEST_KEY = "GUARDIAN_TEST_SECRET_XYZ";

  afterEach(() => {
    delete process.env[TEST_KEY];
  });

  it("returns env var value when it exists", async () => {
    process.env[TEST_KEY] = "my-secret-value";
    const result = await provider.getSecret(TEST_KEY);
    expect(result).toBe("my-secret-value");
  });

  it("returns null when env var does not exist", async () => {
    const result = await provider.getSecret(TEST_KEY);
    expect(result).toBeNull();
  });

  it("has name 'env'", () => {
    expect(provider.name).toBe("env");
  });
});
