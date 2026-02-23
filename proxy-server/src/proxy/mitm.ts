import * as tls from "node:tls";
import type { Socket } from "node:net";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { ServerConfig } from "../config/schema.js";
import type { AuditLogger, AuditEntry } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import { injectSecrets } from "../injection/injector.js";
import { parseHttpRequest, serializeHttpRequest, isKeepAlive } from "./http-parser.js";

export interface MitmDeps {
  certManager: CertManager;
  resolver: SecretResolver;
  config: ServerConfig;
  auditLogger: AuditLogger;
  logger: Logger;
  /** Extra TLS options for outbound connections (e.g. rejectUnauthorized for testing) */
  targetTlsOptions?: tls.ConnectionOptions;
}

export async function handleMitm(
  clientSocket: Socket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const { certManager, resolver, config, auditLogger, logger } = deps;

  // Generate certificate for this hostname
  const { cert, key } = certManager.getCertificate(targetHost);

  // Send CONNECT 200 to client before wrapping in TLS
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  // Create TLS server socket wrapping the client connection
  const tlsServer = new tls.TLSSocket(clientSocket, {
    isServer: true,
    cert,
    key,
  });

  tlsServer.on("error", (err) => {
    logger.debug({ err, target: `${targetHost}:${targetPort}` }, "TLS server socket error");
    if (!clientSocket.destroyed) clientSocket.destroy();
  });

  // Process HTTP requests on the decrypted stream
  try {
    let keepAlive = true;
    while (keepAlive) {
      const req = await parseHttpRequest(tlsServer);
      if (!req) break; // Connection closed

      keepAlive = isKeepAlive(req.httpVersion, req.headers);

      // Remove hop-by-hop headers that shouldn't be forwarded
      delete req.headers["proxy-authorization"];
      delete req.headers["proxy-connection"];

      // Inject secrets into headers
      const { injectedHeaders, injections } = await injectSecrets(
        targetHost,
        req.headers,
        config.secrets,
        resolver,
        logger,
      );

      // Audit log
      const injectedNames = injections
        .filter((i) => i.status === "injected")
        .map((i) => i.secretName);

      const auditEntry: AuditEntry = {
        timestamp: new Date().toISOString(),
        machineId,
        method: req.method,
        target: `${targetHost}:${targetPort}`,
        injectedSecrets: injectedNames,
        action: injectedNames.length > 0 ? "injected" : "passthrough",
      };
      auditLogger.logRequest(auditEntry);

      // Forward to real target — force Connection: close so the target
      // closes the socket after responding (simplifies response reading)
      req.headers = injectedHeaders;
      req.headers["connection"] = "close";
      const serialized = serializeHttpRequest(req);

      await forwardToTarget(
        tlsServer, targetHost, targetPort, serialized, logger,
        deps.targetTlsOptions,
      );
    }
  } catch (err) {
    logger.debug({ err, target: `${targetHost}:${targetPort}` }, "MITM session error");
  } finally {
    if (!tlsServer.destroyed) tlsServer.destroy();
  }
}

/**
 * Open a TLS connection to the real target, send the request, and pipe
 * the response back to the client.
 */
function forwardToTarget(
  clientTls: tls.TLSSocket,
  targetHost: string,
  targetPort: number,
  requestData: Buffer,
  logger: Logger,
  extraTlsOptions?: tls.ConnectionOptions,
): Promise<void> {
  return new Promise((resolve) => {
    const targetSocket = tls.connect(
      {
        host: targetHost,
        port: targetPort,
        servername: targetHost,
        ...extraTlsOptions,
      },
      () => {
        targetSocket.write(requestData);
      },
    );

    // Buffer the full response then write to client
    const chunks: Buffer[] = [];

    targetSocket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });

    targetSocket.on("end", () => {
      if (chunks.length > 0) {
        const responseData = Buffer.concat(chunks);
        if (!clientTls.destroyed) {
          clientTls.write(responseData);
        }
      }
      resolve();
    });

    targetSocket.on("error", (err) => {
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      if (!clientTls.destroyed) {
        const errorResponse = `HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway`;
        clientTls.write(errorResponse);
      }
      resolve();
    });

    clientTls.on("error", () => {
      if (!targetSocket.destroyed) targetSocket.destroy();
      resolve();
    });
  });
}
