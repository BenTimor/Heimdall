import type { FastifyInstance } from "fastify";
import type { PanelConfig } from "../../config/schema.js";

const startTime = Date.now();

export function registerSystemRoutes(
  app: FastifyInstance,
  config: PanelConfig,
  proxyPort: number,
  tunnelPort?: number,
): void {
  app.get("/panel/api/system/info", async () => {
    return {
      version: "0.1.0",
      uptime: Math.floor((Date.now() - startTime) / 1000),
      isExposed: config.host === "0.0.0.0",
      panelPort: config.port,
      proxyPort,
      tunnelPort: tunnelPort ?? null,
    };
  });
}
