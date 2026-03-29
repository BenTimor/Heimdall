import * as http from "node:http";
import * as tls from "node:tls";
import type { Socket } from "node:net";
import forge from "node-forge";
import type { ServerConfig, SecretConfig } from "../config/schema.js";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { AuditLogger } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import type { Authenticator } from "../auth/authenticator.js";
import { matchesAnyDomain } from "../utils/domain-matcher.js";
import { handlePassthrough } from "./passthrough.js";
import { handleMitm, type MitmDeps } from "./mitm.js";
import { handleOcspHttpRequest } from "./ocsp-response.js";

export interface ProxyServerDeps {
  config: ServerConfig;
  certManager: CertManager;
  resolver: SecretResolver;
  auditLogger: AuditLogger;
  authenticator: Authenticator;
  logger: Logger;
  /** Extra TLS options for outbound MITM connections (e.g. for testing) */
  targetTlsOptions?: tls.ConnectionOptions;
  /** CA cert for OCSP responder (optional — enables POST /ocsp endpoint) */
  caCert?: forge.pki.Certificate;
  /** CA private key for signing OCSP responses (required if caCert is set) */
  caKey?: forge.pki.rsa.PrivateKey;
}

export class ProxyServer {
  private server: http.Server;
  private config: ServerConfig;
  private authenticator: Authenticator;
  private secretsConfig: Record<string, SecretConfig>;
  private deps: ProxyServerDeps;

  constructor(deps: ProxyServerDeps) {
    this.deps = deps;
    this.config = deps.config;
    this.authenticator = deps.authenticator;
    this.secretsConfig = { ...deps.config.secrets };

    this.server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    this.server.on("connect", (req, clientSocket, head) => {
      this.handleConnect(req, clientSocket as Socket, head);
    });

    this.server.on("error", (err) => {
      deps.logger.error({ err }, "Proxy server error");
    });

    this.server.on("clientError", (err, socket) => {
      deps.logger.debug({ err }, "Client socket error");
      if (!socket.destroyed) {
        socket.destroy();
      }
    });
  }

  /**
   * Handle plain HTTP requests (non-CONNECT).
   * Serves OCSP responses at GET/POST /ocsp (no auth — called by OS cert validation).
   * Returns 405 for everything else.
   */
  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Handle OCSP requests (no auth required — called by OS certificate validation)
    // POST /ocsp — body is DER-encoded OCSPRequest
    // GET /ocsp/{base64-encoded-DER-OCSPRequest} — RFC 6960 Appendix A
    if (req.url?.startsWith("/ocsp")) {
      if (req.method === "POST" && req.url === "/ocsp") {
        this.handleOcspRequest(req, res);
        return;
      }
      if (req.method === "GET" && req.url.startsWith("/ocsp/")) {
        this.handleOcspGetRequest(req, res);
        return;
      }
    }

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
   * Handle GET /ocsp/{base64} — AIA-based OCSP responder (RFC 6960 Appendix A).
   * Windows schannel sends OCSP requests via GET with the DER-encoded request
   * base64-encoded and URL-encoded in the path.
   */
  private handleOcspGetRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (!this.deps.caCert || !this.deps.caKey) {
      this.deps.logger.warn("OCSP GET request received but CA cert/key not configured");
      res.writeHead(500);
      res.end();
      return;
    }

    try {
      // Extract base64 from path: /ocsp/{base64-encoded-DER}
      const encoded = req.url!.slice("/ocsp/".length);
      const decoded = Buffer.from(decodeURIComponent(encoded), "base64");
      const response = handleOcspHttpRequest(decoded, this.deps.caCert!, this.deps.caKey!);
      res.writeHead(200, {
        "Content-Type": "application/ocsp-response",
        "Content-Length": response.length.toString(),
      });
      res.end(response);
    } catch (err) {
      this.deps.logger.warn({ err }, "OCSP GET request handling failed");
      res.writeHead(500);
      res.end();
    }
  }

  /**
   * Handle POST /ocsp — AIA-based OCSP responder.
   * Parses the DER-encoded OCSPRequest body and returns a signed "good" response.
   */
  private handleOcspRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (!this.deps.caCert || !this.deps.caKey) {
      this.deps.logger.warn("OCSP request received but CA cert/key not configured");
      res.writeHead(500);
      res.end();
      return;
    }

    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const body = Buffer.concat(chunks);
        const response = handleOcspHttpRequest(body, this.deps.caCert!, this.deps.caKey!);
        res.writeHead(200, {
          "Content-Type": "application/ocsp-response",
          "Content-Length": response.length.toString(),
        });
        res.end(response);
      } catch (err) {
        this.deps.logger.warn({ err }, "OCSP request handling failed");
        res.writeHead(500);
        res.end();
      }
    });
  }

  /**
   * Handle CONNECT requests — the core of the proxy.
   */
  private handleConnect(req: http.IncomingMessage, clientSocket: Socket, head: Buffer): void {
    const { logger, config } = this.deps;

    // Register error handler early — after CONNECT upgrade, the HTTP server's
    // clientError handler no longer covers this socket.
    clientSocket.on("error", (err) => {
      logger.debug({ err }, "Client socket error (CONNECT)");
    });

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

    logger.debug(
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
        secretsConfig: this.secretsConfig,
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
  /** Reload secrets config from an external source (e.g. panel DB merge). */
  updateSecretsConfig(newSecrets: Record<string, SecretConfig>): void {
    this.secretsConfig = newSecrets;
  }

  /** Return deduplicated list of domains that have secrets configured. */
  getSecretDomains(): string[] {
    const domains = new Set<string>();
    for (const secretConfig of Object.values(this.secretsConfig)) {
      for (const domain of secretConfig.allowedDomains) {
        domains.add(domain);
      }
    }
    return Array.from(domains);
  }

  private hasSecretsForDomain(hostname: string): boolean {
    for (const secretConfig of Object.values(this.secretsConfig)) {
      if (matchesAnyDomain(hostname, secretConfig.allowedDomains)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Handle a connection arriving from the tunnel server.
   * Skips CONNECT parsing and auth (already done by tunnel server).
   * Goes straight to bypass-check → passthrough or MITM.
   */
  handleTunnelConnection(
    socket: import("node:stream").Duplex,
    targetHost: string,
    targetPort: number,
    machineId: string,
  ): void {
    const { logger, config } = this.deps;

    logger.debug({ target: `${targetHost}:${targetPort}`, machineId }, "Tunnel connection");

    // VirtualSocket extends Duplex, not net.Socket — TLSSocket wrapping a Duplex
    // does NOT auto-forward error events.  Register a handler so errors during
    // session teardown (e.g. tunnel agent disconnect) don't crash the process.
    socket.on("error", (err) => {
      logger.debug({ err, target: `${targetHost}:${targetPort}`, machineId }, "Tunnel virtual socket error");
    });

    const isBypassed = matchesAnyDomain(targetHost, config.bypass.domains);
    const hasSecretConfig = this.hasSecretsForDomain(targetHost);

    if (isBypassed || !hasSecretConfig) {
      logger.debug({ target: `${targetHost}:${targetPort}` }, "Tunnel passthrough mode");
      this.deps.auditLogger.logRequest({
        timestamp: new Date().toISOString(),
        machineId,
        method: "TUNNEL",
        target: `${targetHost}:${targetPort}`,
        injectedSecrets: [],
        action: "passthrough",
      });
      handlePassthrough(socket as import("node:net").Socket, targetHost, targetPort, logger, { tunnelMode: true });
    } else {
      logger.debug({ target: `${targetHost}:${targetPort}` }, "Tunnel MITM mode");
      const mitmDeps: MitmDeps = {
        certManager: this.deps.certManager,
        resolver: this.deps.resolver,
        secretsConfig: this.secretsConfig,
        auditLogger: this.deps.auditLogger,
        logger,
        targetTlsOptions: this.deps.targetTlsOptions,
        tunnelMode: true,
      };
      handleMitm(socket as import("node:net").Socket, targetHost, targetPort, machineId, mitmDeps).catch((err) => {
        logger.error({ err, target: `${targetHost}:${targetPort}` }, "Tunnel MITM handler error");
      });
    }
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
