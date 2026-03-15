import type { FastifyInstance } from "fastify";
import type Database from "better-sqlite3";
import type { AwsProvider } from "../../secrets/aws-provider.js";
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
  awsProvider?: AwsProvider,
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

    // Write value to AWS Secrets Manager if provided
    if (body.provider === "aws" && body.value) {
      if (!awsProvider) {
        return reply.code(400).send({ error: "AWS provider is not configured" });
      }
      try {
        await awsProvider.setSecret(body.path!, body.value, body.field);
      } catch (err: any) {
        return reply.code(502).send({ error: `Failed to write AWS secret: ${err.message}` });
      }
      delete body.value; // never store the value locally
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

    // Write value to AWS Secrets Manager if provided
    if (body?.value && (body.provider === "aws" || (!body.provider && getSecretById(db, parseInt(id, 10))?.provider === "aws"))) {
      if (!awsProvider) {
        return reply.code(400).send({ error: "AWS provider is not configured" });
      }
      const existing = getSecretById(db, parseInt(id, 10));
      if (!existing) {
        return reply.code(404).send({ error: "Secret not found" });
      }
      const awsPath = body.path || existing.path;
      const awsField = body.field ?? existing.field;
      if (!awsPath) {
        return reply.code(400).send({ error: "AWS secret path is required" });
      }
      try {
        await awsProvider.setSecret(awsPath, body.value, awsField || undefined);
      } catch (err: any) {
        return reply.code(502).send({ error: `Failed to write AWS secret: ${err.message}` });
      }
      delete body.value; // never store the value locally
    }

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
