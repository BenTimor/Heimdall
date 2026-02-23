import * as http from "node:http";
import * as tls from "node:tls";
import type { Socket } from "node:net";
import type { ServerConfig } from "../config/schema.js";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import { Authenticator } from "../auth/authenticator.js";
import { matchesAnyDomain } from "../utils/domain-matcher.js";
import { handlePassthrough } from "./passthrough.js";
import { handleMitm, type MitmDeps } from "./mitm.js";

export interface ProxyServerDeps {
  config: ServerConfig;
  certManager: CertManager;
  resolver: SecretResolver;
  auditLogger: AuditLogger;
  logger: Logger;
  /** Extra TLS options for outbound MITM connections (e.g. for testing) */
  targetTlsOptions?: tls.ConnectionOptions;
}

export class ProxyServer {
  private server: http.Server;
  private config: ServerConfig;
  private authenticator: Authenticator;
  private deps: ProxyServerDeps;

  constructor(deps: ProxyServerDeps) {
    this.deps = deps;
    this.config = deps.config;
    this.authenticator = new Authenticator(this.config.auth);

    this.server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    this.server.on("connect", (req, clientSocket, head) => {
      this.handleConnect(req, clientSocket as Socket, head);
    });

    this.server.on("error", (err) => {
      deps.logger.error({ err }, "Proxy server error");
    });
  }

  /**
   * Handle plain HTTP requests (non-CONNECT).
   * Returns 405 — we only support CONNECT-based proxying.
   */
  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Auth check
    const authResult = this.authenticator.authenticate(
      req.headers["proxy-authorization"] as string | undefined,
    );
    if (!authResult.authenticated) {
      res.writeHead(407, {
        "Proxy-Authenticate": 'Basic realm="Guardian Proxy"',
        "Content-Type": "text/plain",
      });
      res.end("Proxy authentication required");
      return;
    }

    // We only handle CONNECT for HTTPS proxying
    res.writeHead(405, { "Content-Type": "text/plain" });
    res.end("Only CONNECT method is supported for proxying");
  }

  /**
   * Handle CONNECT requests — the core of the proxy.
   */
  private handleConnect(req: http.IncomingMessage, clientSocket: Socket, head: Buffer): void {
    const { logger, config } = this.deps;

    // Parse target host:port from the CONNECT request
    const target = req.url;
    if (!target) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }

    const colonIdx = target.lastIndexOf(":");
    if (colonIdx === -1) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }

    const targetHost = target.slice(0, colonIdx);
    const targetPort = parseInt(target.slice(colonIdx + 1), 10);

    if (!targetHost || isNaN(targetPort) || targetPort < 1 || targetPort > 65535) {
      clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }

    // Auth check
    const authResult = this.authenticator.authenticate(
      req.headers["proxy-authorization"] as string | undefined,
    );
    if (!authResult.authenticated) {
      clientSocket.end(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Guardian Proxy\"\r\n\r\n",
      );
      this.deps.auditLogger.logRequest({
        timestamp: new Date().toISOString(),
        machineId: "unknown",
        method: "CONNECT",
        target: `${targetHost}:${targetPort}`,
        injectedSecrets: [],
        action: "blocked",
      });
      return;
    }

    const machineId = authResult.machineId ?? "unknown";

    logger.info(
      { target: `${targetHost}:${targetPort}`, machineId },
      "CONNECT request",
    );

    // If head buffer has data, push it back onto the socket
    if (head && head.length > 0) {
      clientSocket.unshift(head);
    }

    // Decide: bypass (passthrough) or MITM
    const isBypassed = matchesAnyDomain(targetHost, config.bypass.domains);
    const hasSecretConfig = this.hasSecretsForDomain(targetHost);

    if (isBypassed || !hasSecretConfig) {
      // Passthrough — no MITM needed
      logger.debug({ target: `${targetHost}:${targetPort}` }, "Passthrough mode");
      this.deps.auditLogger.logRequest({
        timestamp: new Date().toISOString(),
        machineId,
        method: "CONNECT",
        target: `${targetHost}:${targetPort}`,
        injectedSecrets: [],
        action: "passthrough",
      });
      handlePassthrough(clientSocket, targetHost, targetPort, logger);
    } else {
      // MITM — intercept, inject secrets, forward
      logger.debug({ target: `${targetHost}:${targetPort}` }, "MITM mode");
      const mitmDeps: MitmDeps = {
        certManager: this.deps.certManager,
        resolver: this.deps.resolver,
        config: this.config,
        auditLogger: this.deps.auditLogger,
        logger,
        targetTlsOptions: this.deps.targetTlsOptions,
      };
      handleMitm(clientSocket, targetHost, targetPort, machineId, mitmDeps).catch((err) => {
        logger.error({ err, target: `${targetHost}:${targetPort}` }, "MITM handler error");
      });
    }
  }

  /**
   * Check if any configured secret is bound to this domain.
   */
  private hasSecretsForDomain(hostname: string): boolean {
    for (const secretConfig of Object.values(this.config.secrets)) {
      if (matchesAnyDomain(hostname, secretConfig.allowedDomains)) {
        return true;
      }
    }
    return false;
  }

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(this.config.proxy.port, this.config.proxy.host, () => {
        this.deps.logger.info(
          { port: this.config.proxy.port, host: this.config.proxy.host },
          "Proxy server started",
        );
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          this.deps.logger.info("Proxy server stopped");
          resolve();
        }
      });
    });
  }

  get address(): { port: number; host: string } | null {
    const addr = this.server.address();
    if (!addr || typeof addr === "string") return null;
    return { port: addr.port, host: addr.address };
  }
}
