import * as tls from "node:tls";
import * as fs from "node:fs";
import type { TunnelConfig } from "../config/schema.js";
import type { Logger } from "../utils/logger.js";
import { Authenticator } from "../auth/authenticator.js";
import { FrameDecoder, FrameType, encodeFrame, type Frame } from "./protocol.js";
import { SessionManager, VirtualSocket, type AgentSession } from "./session-manager.js";
import type { ProxyServer } from "../proxy/server.js";

export interface TunnelServerDeps {
  tunnelConfig: TunnelConfig;
  authenticator: Authenticator;
  proxyServer: ProxyServer;
  logger: Logger;
  /** Disable Nagle's algorithm on accepted tunnel sockets. */
  tcpNoDelay?: boolean;
  /** Emit structured tunnel timing logs for NEW_CONNECTION handling. */
  latencyLoggingEnabled?: boolean;
  /** Override TLS options for testing (e.g. provide cert/key directly). */
  tlsOptions?: tls.TlsOptions;
}

export class TunnelServer {
  private server: tls.Server | null = null;
  private deps: TunnelServerDeps;
  private sessions: SessionManager;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(deps: TunnelServerDeps) {
    this.deps = deps;
    this.sessions = new SessionManager();
  }

  start(): Promise<void> {
    const { tunnelConfig, logger } = this.deps;

    const tlsOpts: tls.TlsOptions = this.deps.tlsOptions ?? {
      cert: fs.readFileSync(tunnelConfig.tls.certFile),
      key: fs.readFileSync(tunnelConfig.tls.keyFile),
    };

    this.server = tls.createServer(tlsOpts, (socket) => {
      this.handleConnection(socket);
    });

    this.server.on("error", (err) => {
      logger.error({ err }, "Tunnel server error");
    });

    // Catch errors on raw TCP sockets before/after TLS wrapping.
    // Without this, ECONNRESET on the underlying socket crashes the process.
    this.server.on("connection", (rawSocket: import("node:net").Socket) => {
      rawSocket.on("error", (err) => {
        logger.debug({ err }, "Raw tunnel socket error");
      });
    });

    // Catch TLS handshake failures (e.g. non-TLS traffic hitting the port)
    this.server.on("tlsClientError", (err) => {
      logger.debug({ err }, "TLS client error");
    });

    // Start heartbeat checker
    this.heartbeatTimer = setInterval(() => {
      this.checkHeartbeats();
    }, tunnelConfig.heartbeatIntervalMs);

    return new Promise((resolve) => {
      this.server!.listen(tunnelConfig.port, tunnelConfig.host, () => {
        logger.info(
          { port: tunnelConfig.port, host: tunnelConfig.host },
          "Tunnel server started",
        );
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    // Destroy all sessions
    for (const session of this.sessions.allSessions()) {
      if (!session.socket.destroyed) {
        session.socket.destroy();
      }
    }

    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          this.deps.logger.info("Tunnel server stopped");
          resolve();
        }
      });
    });
  }

  get address(): { port: number; host: string } | null {
    const addr = this.server?.address();
    if (!addr || typeof addr === "string") return null;
    return { port: addr.port, host: addr.address };
  }

  get sessionCount(): number {
    return this.sessions.size;
  }

  private handleConnection(socket: tls.TLSSocket): void {
    const { logger } = this.deps;

    if (this.deps.tcpNoDelay ?? true) {
      try {
        socket.setNoDelay(true);
      } catch (err) {
        logger.debug({ err }, "Failed to set TCP_NODELAY on tunnel socket");
      }
    }
    const decoder = new FrameDecoder();
    let machineId: string | null = null;
    let authTimeout: ReturnType<typeof setTimeout> | null = null;

    // Require auth within 10 seconds
    authTimeout = setTimeout(() => {
      logger.warn("Tunnel client did not authenticate in time");
      socket.write(encodeFrame(0, FrameType.AUTH_FAIL, Buffer.from("auth timeout")));
      socket.destroy();
    }, 10000);

    socket.on("data", (chunk: Buffer) => {
      let frames: Frame[];
      try {
        frames = decoder.decode(chunk);
      } catch (err) {
        logger.warn({ err }, "Tunnel protocol error");
        socket.destroy();
        return;
      }

      for (const frame of frames) {
        if (!machineId) {
          // Not authenticated yet — only accept AUTH
          if (frame.type !== FrameType.AUTH) {
            logger.warn({ frameType: frame.type }, "Expected AUTH frame");
            socket.destroy();
            return;
          }

          if (authTimeout) {
            clearTimeout(authTimeout);
            authTimeout = null;
          }

          machineId = this.handleAuth(socket, frame);
          if (!machineId) return; // auth failed, socket destroyed
          continue;
        }

        this.handleFrame(machineId, frame);
      }
    });

    socket.on("error", (err) => {
      logger.debug({ err, machineId }, "Tunnel socket error");
    });

    socket.on("close", () => {
      if (authTimeout) {
        clearTimeout(authTimeout);
      }
      if (machineId) {
        logger.info({ machineId }, "Tunnel agent disconnected");
        this.sessions.remove(machineId);
      }
    });
  }

  private handleAuth(socket: tls.TLSSocket, frame: Frame): string | null {
    const { authenticator, logger } = this.deps;

    // Payload format: "machineId:token"
    const payload = frame.payload.toString("utf-8");
    const colonIdx = payload.indexOf(":");
    if (colonIdx === -1) {
      logger.warn("Invalid AUTH payload format");
      socket.write(encodeFrame(0, FrameType.AUTH_FAIL, Buffer.from("invalid payload")));
      socket.destroy();
      return null;
    }

    const machineId = payload.slice(0, colonIdx);
    const token = payload.slice(colonIdx + 1);

    // Build a Basic auth header and use the existing authenticator
    const basicHeader = `Basic ${Buffer.from(`${machineId}:${token}`).toString("base64")}`;
    const result = authenticator.authenticate(basicHeader);

    if (!result.authenticated) {
      logger.warn({ machineId, error: result.error }, "Tunnel auth failed");
      socket.write(encodeFrame(0, FrameType.AUTH_FAIL, Buffer.from(result.error ?? "auth failed")));
      socket.destroy();
      return null;
    }

    logger.info({ machineId }, "Tunnel agent authenticated");
    this.sessions.register(machineId, socket);
    socket.write(encodeFrame(0, FrameType.AUTH_OK));
    return machineId;
  }

  private handleFrame(machineId: string, frame: Frame): void {
    const { logger } = this.deps;
    const session = this.sessions.get(machineId);
    if (!session) return;

    switch (frame.type) {
      case FrameType.NEW_CONNECTION:
        this.handleNewConnection(session, frame);
        break;

      case FrameType.DATA: {
        const vs = session.activeConnections.get(frame.connId);
        if (vs) {
          vs.pushData(frame.payload);
        } else {
          logger.debug({ connId: frame.connId, machineId }, "DATA for unknown connection");
        }
        break;
      }

      case FrameType.CLOSE: {
        const vs = session.activeConnections.get(frame.connId);
        if (vs) {
          vs.pushEnd();
          if (!vs.destroyed) {
            vs.destroy();
          }
          session.activeConnections.delete(frame.connId);
        }
        break;
      }

      case FrameType.HEARTBEAT:
        session.lastHeartbeat = Date.now();
        session.socket.write(encodeFrame(0, FrameType.HEARTBEAT_ACK));
        break;

      case FrameType.DOMAIN_LIST_REQUEST: {
        const domains = this.deps.proxyServer.getSecretDomains();
        const payload = Buffer.from(JSON.stringify(domains));
        session.socket.write(encodeFrame(0, FrameType.DOMAIN_LIST_RESPONSE, payload));
        logger.debug({ machineId, domainCount: domains.length }, "Sent domain list to agent");
        break;
      }

      default:
        logger.debug({ frameType: frame.type, machineId }, "Unexpected frame type");
    }
  }

  private handleNewConnection(session: AgentSession, frame: Frame): void {
    const { logger, proxyServer, tunnelConfig } = this.deps;

    // Enforce per-session connection limit
    const maxConns = tunnelConfig.maxConnectionsPerSession;
    if (session.activeConnections.size >= maxConns) {
      logger.warn(
        { machineId: session.machineId, activeConnections: session.activeConnections.size, maxConnectionsPerSession: maxConns },
        "Connection limit reached for session",
      );
      session.socket.write(encodeFrame(frame.connId, FrameType.CLOSE));
      return;
    }

    // Payload: "host:port"
    const target = frame.payload.toString("utf-8");
    const colonIdx = target.lastIndexOf(":");
    if (colonIdx === -1) {
      logger.warn({ target }, "Invalid NEW_CONNECTION target");
      session.socket.write(encodeFrame(frame.connId, FrameType.CLOSE));
      return;
    }

    const targetHost = target.slice(0, colonIdx);
    const targetPort = parseInt(target.slice(colonIdx + 1), 10);

    if (!targetHost || isNaN(targetPort) || targetPort < 1 || targetPort > 65535) {
      logger.warn({ target }, "Invalid NEW_CONNECTION target");
      session.socket.write(encodeFrame(frame.connId, FrameType.CLOSE));
      return;
    }

    const acceptedAtNs = process.hrtime.bigint();
    const vs = new VirtualSocket(frame.connId, session.socket);
    session.activeConnections.set(frame.connId, vs);

    if (this.deps.latencyLoggingEnabled) {
      logger.info(
        {
          connId: frame.connId,
          target: `${targetHost}:${targetPort}`,
          machineId: session.machineId,
        },
        "Tunnel NEW_CONNECTION received",
      );
    } else {
      logger.debug(
        { connId: frame.connId, target: `${targetHost}:${targetPort}`, machineId: session.machineId },
        "New tunnel connection",
      );
    }

    // Route through the proxy's tunnel handler
    proxyServer.handleTunnelConnection(vs, targetHost, targetPort, session.machineId, {
      connId: frame.connId,
      tunnelAcceptedAtNs: acceptedAtNs,
    });
  }

  private checkHeartbeats(): void {
    const { logger, tunnelConfig } = this.deps;
    const now = Date.now();

    for (const session of this.sessions.allSessions()) {
      if (now - session.lastHeartbeat > tunnelConfig.heartbeatTimeoutMs) {
        logger.warn(
          { machineId: session.machineId },
          "Tunnel agent heartbeat timeout",
        );
        if (!session.socket.destroyed) {
          session.socket.destroy();
        }
        this.sessions.remove(session.machineId);
      }
    }
  }
}

