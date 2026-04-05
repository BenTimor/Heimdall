import { describe, it, expect, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { AuditLogger, type AuditEntry } from "../src/audit/audit-logger.js";

describe("AuditLogger", () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  const sampleEntry: AuditEntry = {
    timestamp: "2025-01-01T00:00:00Z",
    machineId: "dev-laptop-1",
    method: "GET",
    target: "api.openai.com:443",
    injectedSecrets: ["OPENAI_API_KEY"],
    action: "injected",
  };

  it("writes a JSON line to the audit file", async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "heimdall-audit-"));
    const auditFile = path.join(tmpDir, "audit.jsonl");

    const logger = new AuditLogger({ enabled: true, file: auditFile });
    logger.logRequest(sampleEntry);
    await logger.flush();

    const content = fs.readFileSync(auditFile, "utf-8").trim();
    expect(content.length).toBeGreaterThan(0);

    const parsed = JSON.parse(content);
    expect(parsed.machineId).toBe("dev-laptop-1");
    expect(parsed.method).toBe("GET");
    expect(parsed.target).toBe("api.openai.com:443");
    expect(parsed.injectedSecrets).toEqual(["OPENAI_API_KEY"]);
    expect(parsed.action).toBe("injected");
    // Must NOT contain secret values
    expect(content).not.toContain("sk-");
  });

  it("is a no-op when disabled", () => {
    const logger = new AuditLogger({ enabled: false });
    // Should not throw
    logger.logRequest(sampleEntry);
  });

  it("is a no-op when enabled but no file specified", () => {
    const logger = new AuditLogger({ enabled: true });
    // Should not throw
    logger.logRequest(sampleEntry);
  });
});
