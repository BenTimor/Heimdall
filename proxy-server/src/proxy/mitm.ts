import * as tls from "node:tls";
import { EventEmitter } from "node:events";
import type { Socket } from "node:net";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { SecretConfig } from "../config/schema.js";
import type { AuditLogger, AuditEntry } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import type { ConnectionPool } from "./connection-pool.js";
import { injectSecrets } from "../injection/injector.js";
import {
  parseHttpHeaders,
  pipeBody,
  serializeHttpHeaders,
  isKeepAlive,
  SocketReader,
} from "./http-parser.js";
import type { BodyInfo } from "./http-parser.js";

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
  /** Upstream connection pool (optional — falls back to per-request connections) */
  connectionPool?: ConnectionPool;
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
      logger.debug(
        { target: `${targetHost}:${targetPort}`, method: parsed.method, injectedSecrets: injectedNames, machineId },
        "MITM request processed",
      );
      auditLogger.logRequest(auditEntry);

      parsed.headers = injectedHeaders;
      if (deps.connectionPool) {
        // With pooling, tell the upstream to keep the connection alive
        parsed.headers["connection"] = "keep-alive";
      } else {
        // Without pooling, force close so response reading is simple
        parsed.headers["connection"] = "close";
      }
      const headerData = serializeHttpHeaders(parsed);

      await forwardToTarget(
        tlsServer, targetHost, targetPort, headerData,
        parsed.bodyInfo, parsed.reader, logger,
        deps.targetTlsOptions,
        deps.connectionPool,
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
 *
 * When a ConnectionPool is provided, connections are reused across requests.
 * Response reading uses explicit header parsing + body streaming instead of
 * relying on the socket 'end' event, so that keep-alive connections work.
 */
async function forwardToTarget(
  clientTls: tls.TLSSocket,
  targetHost: string,
  targetPort: number,
  headerData: Buffer,
  bodyInfo: BodyInfo,
  reader: SocketReader,
  logger: Logger,
  extraTlsOptions?: tls.ConnectionOptions,
  pool?: ConnectionPool,
): Promise<void> {
  if (!pool) {
    // Legacy path: no pool, use Connection: close and pipe until end
    return forwardToTargetLegacy(
      clientTls, targetHost, targetPort, headerData,
      bodyInfo, reader, logger, extraTlsOptions,
    );
  }

  let targetSocket: tls.TLSSocket;
  let isRetry = false;

  const doForward = async (retrying: boolean): Promise<void> => {
    try {
      targetSocket = await pool.acquire(targetHost, targetPort, extraTlsOptions);
    } catch (err) {
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      if (!clientTls.destroyed) {
        clientTls.write(
          "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway",
        );
      }
      return;
    }

    // Write request headers
    targetSocket.write(headerData);

    // Stream request body
    try {
      await pipeBody(reader, bodyInfo, targetSocket);
    } catch (err) {
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error piping request body");
      if (!targetSocket.destroyed) targetSocket.destroy();
      return;
    }

    // Read the response using explicit parsing (not pipe-until-end)
    try {
      const respReader = new SocketReader(targetSocket);
      const HEADER_END = Buffer.from("\r\n\r\n");
      const respHeaderBuf = await respReader.readUntil(HEADER_END);

      if (!respHeaderBuf) {
        respReader.detach();
        if (!targetSocket.destroyed) targetSocket.destroy();
        // Stale pooled connection — retry once with a fresh one
        if (!retrying) {
          return doForward(true);
        }
        if (!clientTls.destroyed) {
          clientTls.write(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway",
          );
        }
        return;
      }

      // Write response headers to client
      clientTls.write(respHeaderBuf);

      // Parse response headers to determine body framing
      const respHeaderStr = respHeaderBuf.toString("utf-8");
      const respLines = respHeaderStr.split("\r\n");
      const respHeaders: Record<string, string> = {};
      for (let i = 1; i < respLines.length; i++) {
        const line = respLines[i];
        if (!line) break;
        const colonIdx = line.indexOf(":");
        if (colonIdx === -1) continue;
        respHeaders[line.slice(0, colonIdx).trim().toLowerCase()] = line.slice(colonIdx + 1).trim();
      }

      const respConnection = respHeaders["connection"]?.toLowerCase();
      const canReuse = respConnection !== "close";

      const transferEncoding = respHeaders["transfer-encoding"];
      const contentLength = respHeaders["content-length"];

      if (transferEncoding?.toLowerCase().includes("chunked")) {
        // Stream chunked body
        await streamChunkedResponse(respReader, clientTls);
      } else if (contentLength) {
        const len = parseInt(contentLength, 10);
        if (len > 0) {
          await streamFixedResponse(respReader, clientTls, len);
        }
      }
      // else: no body (e.g. 204, 304, HEAD response)

      respReader.detach();

      // Release back to pool if possible
      if (canReuse && !targetSocket.destroyed && targetSocket.writable) {
        pool.release(targetHost, targetPort, targetSocket);
      } else {
        if (!targetSocket.destroyed) targetSocket.destroy();
      }
    } catch (err) {
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error reading target response");
      if (!targetSocket!.destroyed) targetSocket!.destroy();
      // If we haven't written anything useful to the client, send 502
      if (!clientTls.destroyed) {
        // We may have partially written — the client side will see a broken response.
        // Not much we can do at this point.
      }
    }
  };

  await doForward(false);
}

/**
 * Legacy forwardToTarget using Connection: close and pipe-until-end.
 * Used when no connection pool is configured.
 */
function forwardToTargetLegacy(
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
        targetSocket.write(headerData);

        try {
          await pipeBody(reader, bodyInfo, targetSocket);
        } catch (err) {
          logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error piping request body");
          if (!targetSocket.destroyed) targetSocket.destroy();
          resolve();
          return;
        }

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

/**
 * Stream a chunked response body from source reader to dest writable.
 * Forwards the raw chunked framing.
 */
async function streamChunkedResponse(
  reader: SocketReader,
  dest: tls.TLSSocket,
): Promise<void> {
  while (true) {
    const sizeLine = await reader.readLine();
    if (sizeLine === null) break;

    const chunkSize = parseInt(sizeLine.trim(), 16);

    // Forward the chunk size line
    dest.write(`${sizeLine}\r\n`);

    if (isNaN(chunkSize) || chunkSize === 0) {
      // Terminal chunk — read and forward the trailing CRLF
      const trailer = await reader.readLine();
      dest.write("\r\n");
      break;
    }

    // Read and forward chunk data
    const chunkData = await reader.readExact(chunkSize);
    if (chunkData) {
      dest.write(chunkData);
    }
    // Read trailing CRLF after chunk data
    await reader.readLine();
    dest.write("\r\n");
  }
}

/**
 * Stream a fixed-length response body from source reader to dest writable.
 */
async function streamFixedResponse(
  reader: SocketReader,
  dest: tls.TLSSocket,
  length: number,
): Promise<void> {
  // readExact handles the reader's internal buffer correctly — it drains
  // any already-buffered bytes first, then awaits from the socket.
  const data = await reader.readExact(length);
  if (data) {
    dest.write(data);
  }
}
