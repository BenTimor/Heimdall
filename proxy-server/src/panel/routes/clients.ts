import type { FastifyInstance } from "fastify";
import type Database from "better-sqlite3";
import {
  listClients,
  getClientById,
  createClient,
  updateClient,
  deleteClient,
  regenerateToken,
} from "../db/clients.js";

export function registerClientRoutes(
  app: FastifyInstance,
  db: Database.Database,
  reloadSecrets: () => void,
): void {
  app.get("/panel/api/clients", async () => {
    return listClients(db);
  });

  app.post("/panel/api/clients", async (request, reply) => {
    const body = request.body as { machineId?: string; description?: string; sourceCidrs?: string[] } | null;
    if (!body?.machineId) {
      return reply.code(400).send({ error: "machineId is required" });
    }

    try {
      const result = createClient(db, body.machineId, body.description ?? "", body.sourceCidrs ?? []);
      return reply.code(201).send({
        client: result.client,
        token: result.token,
      });
    } catch (err: any) {
      if (err.message?.includes("UNIQUE constraint")) {
        return reply.code(409).send({ error: "Client with this machineId already exists" });
      }
      throw err;
    }
  });

  app.put("/panel/api/clients/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { description?: string; enabled?: boolean; sourceCidrs?: string[] } | null;

    const updated = updateClient(db, parseInt(id, 10), {
      description: body?.description,
      enabled: body?.enabled,
      sourceCidrs: body?.sourceCidrs,
    });

    if (!updated) {
      return reply.code(404).send({ error: "Client not found" });
    }

    return getClientById(db, parseInt(id, 10));
  });

  app.delete("/panel/api/clients/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const deleted = deleteClient(db, parseInt(id, 10));

    if (!deleted) {
      return reply.code(404).send({ error: "Client not found" });
    }

    return { ok: true };
  });

  app.post("/panel/api/clients/:id/regenerate-token", async (request, reply) => {
    const { id } = request.params as { id: string };
    const token = regenerateToken(db, parseInt(id, 10));

    if (!token) {
      return reply.code(404).send({ error: "Client not found" });
    }

    return { token };
  });
}
