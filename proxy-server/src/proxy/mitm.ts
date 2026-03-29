import * as tls from "node:tls";
import { EventEmitter } from "node:events";
import type { Socket } from "node:net";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { SecretConfig } from "../config/schema.js";
import type { AuditLogger, AuditEntry } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import { injectSecrets } from "../injection/injector.js";
import {
  parseHttpHeaders,
  pipeBody,
  serializeHttpHeaders,
  isKeepAlive,
} from "./http-parser.js";
import type { SocketReader, BodyInfo } from "./http-parser.js";

export interface MitmDeps {
  certManager: CertManager;
  resolver: SecretResolver;
  secretsConfig: Record<string, SecretConfig>;
  auditLogger: AuditLogger;
  logger: Logger;
  /** Extra TLS options for outbound connections (e.g. rejectUnauthorized for testing) */
  targetTlsOptions?: tls.ConnectionOptions;
  /** When true, skip sending "HTTP/1.1 200 Connection Established" (tunnel mode). */
  tunnelMode?: boolean;
}

export async function handleMitm(
  clientSocket: Socket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const { certManager, resolver, secretsConfig, auditLogger, logger } = deps;

  // Generate certificate for this hostname
  const { cert, key, ocspResponse } = certManager.getCertificate(targetHost);

  // In tunnel mode the client (agent) already started TLS — no CONNECT was sent.
  if (!deps.tunnelMode) {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  // Create a server-like EventEmitter for OCSP stapling support.
  // Node.js TLSSocket wires up onOCSPRequest during _init() only when
  // options.server has OCSPRequest listeners.  Setting _handle.onOCSPRequest
  // after construction is too late — the handshake starts in the constructor.
  const ocspEmitter = new EventEmitter();
  if (ocspResponse) {
    ocspEmitter.on("OCSPRequest", (_certDer: any, _issuerDer: any, cb: Function) => {
      cb(null, ocspResponse);
    });
  }

  // Create TLS server socket wrapping the client connection
  const tlsServer = new tls.TLSSocket(clientSocket, {
    isServer: true,
    cert,
    key,
    server: ocspEmitter,
  } as any);

  tlsServer.on("error", (err) => {
    logger.warn({ err, target: `${targetHost}:${targetPort}` }, "TLS server socket error");
    if (!clientSocket.destroyed) clientSocket.destroy();
  });

  // Process HTTP requests on the decrypted stream
  try {
    let keepAlive = true;
    while (keepAlive) {
      const parsed = await parseHttpHeaders(tlsServer);
      if (!parsed) break; // Connection closed

      keepAlive = isKeepAlive(parsed.httpVersion, parsed.headers);

      // Remove hop-by-hop headers that shouldn't be forwarded
      delete parsed.headers["proxy-authorization"];
      delete parsed.headers["proxy-connection"];

      // Inject secrets into headers
      const { injectedHeaders, injections } = await injectSecrets(
        targetHost,
        parsed.headers,
        secretsConfig,
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
        method: parsed.method,
        target: `${targetHost}:${targetPort}`,
        injectedSecrets: injectedNames,
        action: injectedNames.length > 0 ? "injected" : "passthrough",
      };
      logger.info(
        { target: `${targetHost}:${targetPort}`, method: parsed.method, injectedSecrets: injectedNames, machineId },
        "MITM request processed",
      );
      auditLogger.logRequest(auditEntry);

      // Forward to real target — force Connection: close so the target
      // closes the socket after responding (simplifies response reading)
      parsed.headers = injectedHeaders;
      parsed.headers["connection"] = "close";
      const headerData = serializeHttpHeaders(parsed);

      await forwardToTarget(
        tlsServer, targetHost, targetPort, headerData,
        parsed.bodyInfo, parsed.reader, logger,
        deps.targetTlsOptions,
      );
    }
  } catch (err) {
    logger.warn({ err, target: `${targetHost}:${targetPort}` }, "MITM session error");
  } finally {
    // Use end() instead of destroy() so that any queued response data
    // (from forwardToTarget's clientTls.write) is flushed before the
    // TLS close_notify.  destroy() discards buffered writes immediately,
    // which causes "Remote end closed connection without response" when
    // the client sends Connection: close (keepAlive = false → loop exits
    // right after the write, before the event loop can flush it).
    if (!tlsServer.destroyed) tlsServer.end();
  }
}

/**
 * Open a TLS connection to the real target, send the request headers,
 * stream the request body, then pipe the response back to the client.
 */
function forwardToTarget(
  clientTls: tls.TLSSocket,
  targetHost: string,
  targetPort: number,
  headerData: Buffer,
  bodyInfo: BodyInfo,
  reader: SocketReader,
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
      async () => {
        // Write serialized headers to the target
        targetSocket.write(headerData);

        // Stream the request body to the target
        try {
          await pipeBody(reader, bodyInfo, targetSocket);
        } catch (err) {
          logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error piping request body");
          if (!targetSocket.destroyed) targetSocket.destroy();
          resolve();
          return;
        }

        // Now stream the response back to the client
        targetSocket.pipe(clientTls, { end: false });
      },
    );

    const cleanup = () => {
      targetSocket.removeListener("end", onEnd);
      targetSocket.removeListener("error", onTargetError);
      clientTls.removeListener("error", onClientError);
    };

    const onEnd = () => {
      cleanup();
      resolve();
    };

    const onTargetError = (err: Error) => {
      cleanup();
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      if (!clientTls.destroyed) {
        const errorResponse = `HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway`;
        clientTls.write(errorResponse);
      }
      resolve();
    };

    const onClientError = () => {
      cleanup();
      if (!targetSocket.destroyed) targetSocket.destroy();
      resolve();
    };

    targetSocket.on("end", onEnd);
    targetSocket.on("error", onTargetError);
    clientTls.on("error", onClientError);
  });
}
