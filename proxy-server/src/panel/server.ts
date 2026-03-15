import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type Database from "better-sqlite3";
import type { PanelConfig } from "../config/schema.js";
import type { Logger } from "../utils/logger.js";
import type { AwsProvider } from "../secrets/aws-provider.js";
import { validateSession } from "./auth.js";
import { ensureDefaultAdmin, cleanExpiredSessions } from "./auth.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerClientRoutes } from "./routes/clients.js";
import { registerSecretRoutes } from "./routes/secrets.js";
import { registerAuditRoutes } from "./routes/audit.js";
import { registerSystemRoutes } from "./routes/system.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface PanelServerDeps {
  config: PanelConfig;
  db: Database.Database;
  encryptionKey: Buffer;
  logger: Logger;
  proxyPort: number;
  tunnelPort?: number;
  reloadSecrets: () => void;
  awsProvider?: AwsProvider;
}

export async function startPanelServer(deps: PanelServerDeps): Promise<{ stop: () => Promise<void> }> {
  const { config, db, logger } = deps;

  // Ensure default admin exists
  await ensureDefaultAdmin(db, config.defaultAdminPassword);

  const app = Fastify({ logger: false });

  // Register cookie plugin
  await app.register(fastifyCookie);

  // Serve static SPA files
  await app.register(fastifyStatic, {
    root: path.join(__dirname, "public"),
    prefix: "/panel/",
    decorateReply: false,
  });

  // Rate limiter state for login (in-memory)
  const loginAttempts = new Map<string, { count: number; resetAt: number }>();

  // Auth middleware for API routes
  app.addHook("onRequest", async (request, reply) => {
    const url = request.url;

    // Allow static files and login
    if (!url.startsWith("/panel/api/")) return;
    if (url === "/panel/api/auth/login") return;

    const sessionId = request.cookies.guardian_session;
    if (!sessionId) {
      reply.code(401).send({ error: "Not authenticated" });
      return;
    }

    const admin = validateSession(db, sessionId);
    if (!admin) {
      reply.code(401).send({ error: "Session expired" });
      return;
    }

    // Attach admin to request for routes
    (request as any).admin = admin;
  });

  // CSRF check: require JSON content-type on mutating requests
  app.addHook("onRequest", async (request, reply) => {
    if (!request.url.startsWith("/panel/api/")) return;
    if (request.method === "GET" || request.method === "HEAD" || request.method === "OPTIONS" || request.method === "DELETE") return;

    const contentType = request.headers["content-type"];
    if (!contentType?.includes("application/json")) {
      reply.code(415).send({ error: "Content-Type must be application/json" });
      return;
    }
  });

  // Register API routes
  registerAuthRoutes(app, db, config, loginAttempts);
  registerClientRoutes(app, db, deps.reloadSecrets);
  registerSecretRoutes(app, db, deps.encryptionKey, deps.reloadSecrets, deps.awsProvider);
  registerAuditRoutes(app, db);
  registerSystemRoutes(app, config, deps.proxyPort, deps.tunnelPort);

  // Redirect root to /panel/
  app.get("/", async (_request, reply) => {
    return reply.redirect("/panel/");
  });

  // SPA fallback: serve index.html for non-API panel routes
  app.setNotFoundHandler((request, reply) => {
    if (request.url.startsWith("/panel/") && !request.url.startsWith("/panel/api/")) {
      return reply.sendFile("index.html");
    }
    reply.code(404).send({ error: "Not found" });
  });

  // Periodic session cleanup
  const cleanupInterval = setInterval(() => {
    try {
      const cleaned = cleanExpiredSessions(db);
      if (cleaned > 0) {
        logger.debug({ cleaned }, "Cleaned expired sessions");
      }
    } catch {
      // ignore cleanup errors
    }
  }, 60 * 60 * 1000);

  // Start listening
  await app.listen({ port: config.port, host: config.host });
  logger.info({ port: config.port, host: config.host }, "Admin panel started");

  if (config.host === "0.0.0.0") {
    logger.warn("Admin panel is exposed on all interfaces — use SSH tunnel for production access");
  }

  return {
    stop: async () => {
      clearInterval(cleanupInterval);
      await app.close();
      logger.info("Admin panel stopped");
    },
  };
}
