import fs from "node:fs";
import { parse as parseYaml } from "yaml";
import { ServerConfigSchema, type ServerConfig } from "./schema.js";

export function loadConfig(filePath: string): ServerConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    throw new Error(
      `Failed to read config file "${filePath}": ${(err as Error).message}`
    );
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(
      `Failed to parse YAML in "${filePath}": ${(err as Error).message}`
    );
  }

  const result = ServerConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Config validation failed for "${filePath}":\n${issues}`);
  }

  return result.data;
}
