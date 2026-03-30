import * as tls from "node:tls";
import type { Logger } from "../utils/logger.js";

interface PooledConnection {
  socket: tls.TLSSocket;
  lastUsed: number;
}

export interface ConnectionPoolOptions {
  /** Max idle time in ms before a connection is evicted (default 30000) */
  idleTtlMs?: number;
  /** Max connections per host:port (default 6) */
  maxPerHost?: number;
  /** Max total connections across all hosts (default 256) */
  maxTotal?: number;
  /** Cleanup interval in ms (default 10000) */
  cleanupIntervalMs?: number;
}

/**
 * Pool for upstream TLS connections.
 * Keeps idle connections alive for reuse, keyed by host:port.
 */
export class ConnectionPool {
  private pool = new Map<string, PooledConnection[]>();
  private idleTtlMs: number;
  private maxPerHost: number;
  private maxTotal: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private totalCount = 0;
  private closed = false;

  constructor(private logger?: Logger, opts?: ConnectionPoolOptions) {
    this.idleTtlMs = opts?.idleTtlMs ?? 30_000;
    this.maxPerHost = opts?.maxPerHost ?? 6;
    this.maxTotal = opts?.maxTotal ?? 256;

    const cleanupMs = opts?.cleanupIntervalMs ?? 10_000;
    this.cleanupTimer = setInterval(() => this.evictExpired(), cleanupMs);
    // Don't prevent the process from exiting
    this.cleanupTimer.unref();
  }

  private key(host: string, port: number): string {
    return `${host}:${port}`;
  }

  /**
   * Acquire a TLS connection to host:port.
   * Returns a reused idle connection if available, otherwise creates a new one.
   */
  acquire(
    host: string,
    port: number,
    extraTlsOptions?: tls.ConnectionOptions,
  ): Promise<tls.TLSSocket> {
    if (this.closed) {
      return this.createNew(host, port, extraTlsOptions);
    }

    const k = this.key(host, port);
    const bucket = this.pool.get(k);

    // Try to find a usable idle connection
    while (bucket && bucket.length > 0) {
      const entry = bucket.pop()!;
      this.totalCount--;

      if (bucket.length === 0) {
        this.pool.delete(k);
      }

      // Check that socket is still alive
      if (!entry.socket.destroyed && entry.socket.writable) {
        this.logger?.debug({ host, port }, "Reusing pooled connection");
        return Promise.resolve(entry.socket);
      }
      // Socket was already dead — skip it
      if (!entry.socket.destroyed) entry.socket.destroy();
    }

    return this.createNew(host, port, extraTlsOptions);
  }

  /**
   * Release a connection back to the pool for reuse.
   * If the socket is dead or the pool is full, it gets destroyed instead.
   */
  release(host: string, port: number, socket: tls.TLSSocket): void {
    if (this.closed || socket.destroyed || !socket.writable) {
      if (!socket.destroyed) socket.destroy();
      return;
    }

    // Enforce total limit
    if (this.totalCount >= this.maxTotal) {
      socket.destroy();
      return;
    }

    const k = this.key(host, port);
    let bucket = this.pool.get(k);
    if (!bucket) {
      bucket = [];
      this.pool.set(k, bucket);
    }

    // Enforce per-host limit
    if (bucket.length >= this.maxPerHost) {
      socket.destroy();
      return;
    }

    // Remove all existing listeners so they don't interfere with the next user
    socket.removeAllListeners("data");
    socket.removeAllListeners("end");
    socket.removeAllListeners("close");
    socket.removeAllListeners("error");

    // If the server closes the connection while idle, clean it up
    socket.on("error", () => {
      this.removeFromPool(k, socket);
      if (!socket.destroyed) socket.destroy();
    });
    socket.on("close", () => {
      this.removeFromPool(k, socket);
    });
    // If data arrives while the socket is idle in the pool (shouldn't happen
    // under normal HTTP/1.1 — only if the server pushes or sends a goaway)
    // discard the connection.
    socket.on("data", () => {
      this.removeFromPool(k, socket);
      if (!socket.destroyed) socket.destroy();
    });

    bucket.push({ socket, lastUsed: Date.now() });
    this.totalCount++;
    this.logger?.debug({ host, port, poolSize: this.totalCount }, "Connection released to pool");
  }

  /** Close all pooled connections and stop the cleanup timer. */
  close(): void {
    this.closed = true;
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const bucket of this.pool.values()) {
      for (const entry of bucket) {
        if (!entry.socket.destroyed) entry.socket.destroy();
      }
    }
    this.pool.clear();
    this.totalCount = 0;
  }

  /** Number of idle connections currently in the pool. */
  get size(): number {
    return this.totalCount;
  }

  private createNew(
    host: string,
    port: number,
    extraTlsOptions?: tls.ConnectionOptions,
  ): Promise<tls.TLSSocket> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host,
          port,
          servername: host,
          ...extraTlsOptions,
        },
        () => {
          resolve(socket);
        },
      );
      socket.on("error", (err) => {
        reject(err);
      });
    });
  }

  private removeFromPool(k: string, socket: tls.TLSSocket): void {
    const bucket = this.pool.get(k);
    if (!bucket) return;
    const idx = bucket.findIndex((e) => e.socket === socket);
    if (idx !== -1) {
      bucket.splice(idx, 1);
      this.totalCount--;
      if (bucket.length === 0) {
        this.pool.delete(k);
      }
    }
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [k, bucket] of this.pool.entries()) {
      for (let i = bucket.length - 1; i >= 0; i--) {
        if (now - bucket[i].lastUsed > this.idleTtlMs) {
          const entry = bucket[i];
          bucket.splice(i, 1);
          this.totalCount--;
          if (!entry.socket.destroyed) entry.socket.destroy();
        }
      }
      if (bucket.length === 0) {
        this.pool.delete(k);
      }
    }
  }
}
