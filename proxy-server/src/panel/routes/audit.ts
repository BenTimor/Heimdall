import type { FastifyInstance } from "fastify";
import type Database from "better-sqlite3";
import { getAuditEntries, getAuditStats } from "../db/audit.js";

export function registerAuditRoutes(app: FastifyInstance, db: Database.Database): void {
  app.get("/panel/api/audit", async (request) => {
    const query = request.query as {
      page?: string;
      limit?: string;
      machineId?: string;
      action?: string;
    };

    return getAuditEntries(db, {
      page: query.page ? parseInt(query.page, 10) : undefined,
      limit: query.limit ? parseInt(query.limit, 10) : undefined,
      machineId: query.machineId,
      action: query.action,
    });
  });

  app.get("/panel/api/audit/stats", async () => {
    return getAuditStats(db);
  });
}
