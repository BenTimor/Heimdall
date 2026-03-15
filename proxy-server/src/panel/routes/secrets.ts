import type { FastifyInstance } from "fastify";
import type Database from "better-sqlite3";
import {
  listSecrets,
  getSecretById,
  createSecret,
  updateSecret,
  deleteSecret,
} from "../db/secrets.js";

export function registerSecretRoutes(
  app: FastifyInstance,
  db: Database.Database,
  encryptionKey: Buffer,
  reloadSecrets: () => void,
): void {
  app.get("/panel/api/secrets", async () => {
    return listSecrets(db);
  });

  app.post("/panel/api/secrets", async (request, reply) => {
    const body = request.body as {
      name?: string;
      provider?: string;
      path?: string;
      field?: string;
      value?: string;
      allowedDomains?: string[];
    } | null;

    if (!body?.name || !body?.provider) {
      return reply.code(400).send({ error: "name and provider are required" });
    }

    if (!["env", "aws", "stored"].includes(body.provider)) {
      return reply.code(400).send({ error: "provider must be one of: env, aws, stored" });
    }

    if (body.provider === "stored" && !body.value) {
      return reply.code(400).send({ error: "value is required for stored provider" });
    }

    if (body.provider !== "stored" && !body.path) {
      return reply.code(400).send({ error: "path is required for env and aws providers" });
    }

    try {
      const secret = createSecret(db, {
        name: body.name,
        provider: body.provider,
        path: body.path,
        field: body.field,
        value: body.value,
        allowedDomains: body.allowedDomains,
      }, encryptionKey);
      reloadSecrets();
      return reply.code(201).send(secret);
    } catch (err: any) {
      if (err.message?.includes("UNIQUE constraint")) {
        return reply.code(409).send({ error: "Secret with this name already exists" });
      }
      throw err;
    }
  });

  app.put("/panel/api/secrets/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as {
      provider?: string;
      path?: string;
      field?: string;
      value?: string;
      allowedDomains?: string[];
    } | null;

    const updated = updateSecret(db, parseInt(id, 10), body ?? {}, encryptionKey);
    if (!updated) {
      return reply.code(404).send({ error: "Secret not found" });
    }

    reloadSecrets();
    return getSecretById(db, parseInt(id, 10));
  });

  app.delete("/panel/api/secrets/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const deleted = deleteSecret(db, parseInt(id, 10));

    if (!deleted) {
      return reply.code(404).send({ error: "Secret not found" });
    }

    reloadSecrets();
    return { ok: true };
  });
}
