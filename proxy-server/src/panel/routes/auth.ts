import type { FastifyInstance } from "fastify";
import type Database from "better-sqlite3";
import type { PanelConfig } from "../../config/schema.js";
import { verifyPassword, hashPassword, createSession, deleteSession } from "../auth.js";
import type { AdminRow } from "../auth.js";

export function registerAuthRoutes(
  app: FastifyInstance,
  db: Database.Database,
  config: PanelConfig,
  loginAttempts: Map<string, { count: number; resetAt: number }>,
): void {
  app.post("/panel/api/auth/login", async (request, reply) => {
    const ip = request.ip;

    // Rate limiting
    const now = Date.now();
    const attempt = loginAttempts.get(ip);
    if (attempt) {
      if (now < attempt.resetAt) {
        if (attempt.count >= 5) {
          return reply.code(429).send({ error: "Too many login attempts, try again later" });
        }
      } else {
        loginAttempts.delete(ip);
      }
    }

    const body = request.body as { username?: string; password?: string } | null;
    if (!body?.username || !body?.password) {
      return reply.code(400).send({ error: "Username and password are required" });
    }

    const admin = db.prepare("SELECT * FROM admins WHERE username = ?").get(body.username) as AdminRow | undefined;
    if (!admin) {
      trackAttempt(loginAttempts, ip, now);
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    const valid = await verifyPassword(body.password, admin.password_hash);
    if (!valid) {
      trackAttempt(loginAttempts, ip, now);
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    // Clear rate limit on success
    loginAttempts.delete(ip);

    const sessionId = createSession(db, admin.id, config.sessionTtlHours);

    reply.setCookie("heimdall_session", sessionId, {
      httpOnly: true,
      sameSite: "strict",
      path: "/panel",
      maxAge: config.sessionTtlHours * 60 * 60,
    });

    return {
      username: admin.username,
      mustChangePassword: admin.must_change_password === 1,
    };
  });

  app.post("/panel/api/auth/logout", async (request, reply) => {
    const sessionId = request.cookies.heimdall_session;
    if (sessionId) {
      deleteSession(db, sessionId);
    }

    reply.clearCookie("heimdall_session", { path: "/panel" });
    return { ok: true };
  });

  app.post("/panel/api/auth/change-password", async (request, reply) => {
    const admin = (request as any).admin as AdminRow;
    const body = request.body as { currentPassword?: string; newPassword?: string } | null;

    if (!body?.currentPassword || !body?.newPassword) {
      return reply.code(400).send({ error: "Current and new password are required" });
    }

    if (body.newPassword.length < 8) {
      return reply.code(400).send({ error: "New password must be at least 8 characters" });
    }

    const valid = await verifyPassword(body.currentPassword, admin.password_hash);
    if (!valid) {
      return reply.code(401).send({ error: "Current password is incorrect" });
    }

    const newHash = await hashPassword(body.newPassword);
    db.prepare("UPDATE admins SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?").run(newHash, admin.id);

    return { ok: true };
  });
}

function trackAttempt(map: Map<string, { count: number; resetAt: number }>, ip: string, now: number): void {
  const existing = map.get(ip);
  if (existing && now < existing.resetAt) {
    existing.count++;
  } else {
    map.set(ip, { count: 1, resetAt: now + 60_000 });
  }
}
