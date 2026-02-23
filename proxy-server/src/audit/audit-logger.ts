import fs from "node:fs";
import path from "node:path";

export interface AuditEntry {
  timestamp: string;
  machineId: string;
  method: string;
  target: string;
  injectedSecrets: string[];
  action: "injected" | "passthrough" | "blocked";
}

export class AuditLogger {
  private fd: number | null = null;
  private enabled: boolean;

  constructor(config: { enabled: boolean; file?: string }) {
    this.enabled = config.enabled;

    if (this.enabled && config.file) {
      const dir = path.dirname(config.file);
      fs.mkdirSync(dir, { recursive: true });
      this.fd = fs.openSync(config.file, "a");
    }
  }

  logRequest(entry: AuditEntry): void {
    if (!this.enabled || this.fd === null) return;
    fs.writeSync(this.fd, JSON.stringify(entry) + "\n");
  }
}
