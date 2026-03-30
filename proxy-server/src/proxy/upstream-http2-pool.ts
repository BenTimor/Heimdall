import * as http2 from "node:http2";
import * as tls from "node:tls";
import type { Logger } from "../utils/logger.js";

interface PooledSession {
  session: http2.ClientHttp2Session;
  lastUsed: number;
}

export interface AcquiredUpstreamHttp2Session {
  session: http2.ClientHttp2Session;
  reused: boolean;
  connectTimeMs: number;
  tlsSessionReused: boolean | null;
  cachedTlsSessionOffered: boolean;
}

export interface UpstreamHttp2PoolOptions {
  /** Max idle time in ms before an H2 session is evicted (default 30000) */
  idleTtlMs?: number;
  /** Cleanup interval in ms (default 10000) */
  cleanupIntervalMs?: number;
  /** How long to remember that a host did not negotiate h2 (default = idleTtlMs) */
  unsupportedTtlMs?: number;
  /** Disable Nagle's algorithm on outbound upstream sockets (default true) */
  tcpNoDelay?: boolean;
}

const now = (): number => Date.now();

function formatAuthorityHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function isUsableSession(session: http2.ClientHttp2Session): boolean {
  const socket = session.socket as tls.TLSSocket | undefined;
  return !session.closed && !session.destroyed && !!socket && !socket.destroyed;
}

export class UpstreamHttp2Pool {
  private sessions = new Map<string, PooledSession>();
  private tlsSessionCache = new Map<string, Buffer>();
  private unsupportedUntil = new Map<string, number>();
  private idleTtlMs: number;
  private unsupportedTtlMs: number;
  private tcpNoDelay: boolean;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  constructor(private logger?: Logger, opts?: UpstreamHttp2PoolOptions) {
    this.idleTtlMs = opts?.idleTtlMs ?? 30_000;
    this.unsupportedTtlMs = opts?.unsupportedTtlMs ?? this.idleTtlMs;
    this.tcpNoDelay = opts?.tcpNoDelay ?? true;

    const cleanupMs = opts?.cleanupIntervalMs ?? 10_000;
    this.cleanupTimer = setInterval(() => this.evictExpired(), cleanupMs);
    this.cleanupTimer.unref();
  }

  private key(host: string, port: number): string {
    return `${host}:${port}`;
  }

  async acquire(
    host: string,
    port: number,
    extraTlsOptions?: tls.ConnectionOptions,
  ): Promise<AcquiredUpstreamHttp2Session | null> {
    if (this.closed) {
      return null;
    }

    const k = this.key(host, port);
    const unsupportedUntil = this.unsupportedUntil.get(k);
    if (unsupportedUntil && unsupportedUntil > now()) {
      return null;
    }

    const existing = this.sessions.get(k);
    if (existing && isUsableSession(existing.session)) {
      existing.lastUsed = now();
      this.logger?.debug({ host, port }, "Reusing pooled HTTP/2 session");
      return {
        session: existing.session,
        reused: true,
        connectTimeMs: 0,
        tlsSessionReused: null,
        cachedTlsSessionOffered: false,
      };
    }

    if (existing) {
      this.invalidate(host, port, existing.session);
    }

    const startedAt = process.hrtime.bigint();
    const cachedTlsSession = this.tlsSessionCache.get(k);
    const socket = tls.connect({
      host,
      port,
      servername: host,
      ALPNProtocols: ["h2", "http/1.1"],
      session: cachedTlsSession,
      ...extraTlsOptions,
    });

    socket.on("session", (session) => {
      this.tlsSessionCache.set(k, session);
    });

    if (this.tcpNoDelay) {
      socket.setNoDelay(true);
    }

    try {
      await new Promise<void>((resolve, reject) => {
        const onSecureConnect = () => {
          cleanup();
          resolve();
        };
        const onError = (err: Error) => {
          cleanup();
          reject(err);
        };
        const onClose = () => {
          cleanup();
          reject(new Error("socket closed before secureConnect"));
        };
        const cleanup = () => {
          socket.removeListener("secureConnect", onSecureConnect);
          socket.removeListener("error", onError);
          socket.removeListener("close", onClose);
        };

        socket.once("secureConnect", onSecureConnect);
        socket.once("error", onError);
        socket.once("close", onClose);
      });
    } catch (err) {
      if (!socket.destroyed) socket.destroy();
      this.logger?.debug({ err, host, port }, "Failed to establish upstream HTTP/2 candidate socket");
      return null;
    }

    if (socket.alpnProtocol !== "h2") {
      this.unsupportedUntil.set(k, now() + this.unsupportedTtlMs);
      this.logger?.debug(
        { host, port, negotiatedAlpn: socket.alpnProtocol || null },
        "Origin did not negotiate h2; using HTTP/1.1 fallback",
      );
      if (!socket.destroyed) socket.destroy();
      return null;
    }

    const authority = `https://${formatAuthorityHost(host)}:${port}`;
    const session = http2.connect(authority, {
      createConnection: () => socket,
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const onConnect = () => {
          cleanup();
          resolve();
        };
        const onError = (err: Error) => {
          cleanup();
          reject(err);
        };
        const onClose = () => {
          cleanup();
          reject(new Error("HTTP/2 session closed before connect"));
        };
        const cleanup = () => {
          session.removeListener("connect", onConnect);
          session.removeListener("error", onError);
          session.removeListener("close", onClose);
        };

        session.once("connect", onConnect);
        session.once("error", onError);
        session.once("close", onClose);
      });
    } catch (err) {
      this.logger?.debug({ err, host, port }, "Failed to establish upstream HTTP/2 session");
      if (!session.closed && !session.destroyed) {
        session.destroy();
      }
      return null;
    }

    const removeEntry = () => {
      const current = this.sessions.get(k);
      if (current?.session === session) {
        this.sessions.delete(k);
      }
    };

    session.on("close", removeEntry);
    session.on("error", removeEntry);
    session.on("goaway", removeEntry);

    this.sessions.set(k, { session, lastUsed: now() });

    return {
      session,
      reused: false,
      connectTimeMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      tlsSessionReused: typeof socket.isSessionReused === "function" ? socket.isSessionReused() : null,
      cachedTlsSessionOffered: cachedTlsSession !== undefined,
    };
  }

  touch(host: string, port: number): void {
    const entry = this.sessions.get(this.key(host, port));
    if (entry) {
      entry.lastUsed = now();
    }
  }

  invalidate(host: string, port: number, session?: http2.ClientHttp2Session): void {
    const k = this.key(host, port);
    const entry = this.sessions.get(k);
    if (!entry) return;
    if (session && entry.session !== session) return;

    this.sessions.delete(k);
    if (!entry.session.closed && !entry.session.destroyed) {
      entry.session.close();
      entry.session.destroy();
    }
  }

  close(): void {
    this.closed = true;
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    for (const { session } of this.sessions.values()) {
      if (!session.closed && !session.destroyed) {
        session.close();
        session.destroy();
      }
    }

    this.sessions.clear();
    this.tlsSessionCache.clear();
    this.unsupportedUntil.clear();
  }

  private evictExpired(): void {
    const current = now();

    for (const [key, expiresAt] of this.unsupportedUntil.entries()) {
      if (expiresAt <= current) {
        this.unsupportedUntil.delete(key);
      }
    }

    for (const [key, entry] of this.sessions.entries()) {
      if (current - entry.lastUsed <= this.idleTtlMs) {
        continue;
      }

      this.sessions.delete(key);
      if (!entry.session.closed && !entry.session.destroyed) {
        entry.session.close();
        entry.session.destroy();
      }
    }
  }
}
