import * as tls from "node:tls";
import { EventEmitter, once } from "node:events";
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
  /** Emit structured latency logs for MITM sessions/requests. */
  latencyLoggingEnabled?: boolean;
  /** Connection ID from the tunnel protocol (if this originated from the agent). */
  tunnelConnId?: number;
  /** Timestamp captured when the tunnel server received NEW_CONNECTION. */
  tunnelAcceptedAtNs?: bigint;
  /** Disable Nagle's algorithm on outbound upstream sockets. */
  tcpNoDelay?: boolean;
}

interface ForwardMetrics {
  poolReused: boolean | null;
  poolRetryCount: number;
  upstreamConnectMs: number;
  responseHeaderMs: number | null;
  responseStreamMs: number | null;
  totalMs: number;
  errorStage?: "connect" | "request_body" | "response_headers" | "response_body";
}

const FIXED_RESPONSE_CHUNK_SIZE = 16 * 1024;

const nowNs = (): bigint => process.hrtime.bigint();
const nsToMs = (durationNs: bigint): number => Number(durationNs) / 1_000_000;

export async function handleMitm(
  clientSocket: Socket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const { certManager, resolver, secretsConfig, auditLogger, logger } = deps;
  const target = `${targetHost}:${targetPort}`;
  const sessionStartNs = nowNs();
  const certStartNs = sessionStartNs;

  // Generate certificate for this hostname
  const { cert, key, ocspResponse, fromCache, keySource } = certManager.getCertificate(targetHost);
  const certReadyNs = nowNs();

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

  tlsServer.once("secure", () => {
    if (!deps.latencyLoggingEnabled) return;

    const secureAtNs = nowNs();
    logger.info(
      {
        machineId,
        connId: deps.tunnelConnId,
        target,
        tunnelMode: deps.tunnelMode ?? false,
        certMs: nsToMs(certReadyNs - certStartNs),
        certFromCache: fromCache,
        certKeySource: keySource,
        tlsHandshakeMs: nsToMs(secureAtNs - certReadyNs),
        sessionSetupMs: nsToMs(secureAtNs - sessionStartNs),
        tunnelAcceptToTlsReadyMs: deps.tunnelAcceptedAtNs
          ? nsToMs(secureAtNs - deps.tunnelAcceptedAtNs)
          : undefined,
      },
      "MITM connection timing",
    );
  });

  tlsServer.on("error", (err) => {
    logger.warn({ err, target, machineId, connId: deps.tunnelConnId }, "TLS server socket error");
    if (!clientSocket.destroyed) clientSocket.destroy();
  });

  // Process HTTP requests on the decrypted stream
  try {
    let keepAlive = true;
    let requestSeq = 0;

    while (keepAlive) {
      const requestStartNs = nowNs();
      const parsed = await parseHttpHeaders(tlsServer);
      const parseDoneNs = nowNs();
      if (!parsed) break; // Connection closed

      requestSeq++;
      const requestId = deps.tunnelConnId !== undefined
        ? `${machineId}:${deps.tunnelConnId}:${requestSeq}`
        : `${machineId}:${targetHost}:${targetPort}:${requestSeq}`;

      keepAlive = isKeepAlive(parsed.httpVersion, parsed.headers);

      // Remove hop-by-hop headers that shouldn't be forwarded
      delete parsed.headers["proxy-authorization"];
      delete parsed.headers["proxy-connection"];

      // Inject secrets into headers
      const injectionStartNs = nowNs();
      const { injectedHeaders, injections } = await injectSecrets(
        targetHost,
        parsed.headers,
        secretsConfig,
        resolver,
        logger,
      );
      const injectionDoneNs = nowNs();

      // Audit log
      const injectedNames = injections
        .filter((i) => i.status === "injected")
        .map((i) => i.secretName);

      const auditEntry: AuditEntry = {
        timestamp: new Date().toISOString(),
        machineId,
        method: parsed.method,
        target,
        injectedSecrets: injectedNames,
        action: injectedNames.length > 0 ? "injected" : "passthrough",
      };
      const auditStartNs = nowNs();
      auditLogger.logRequest(auditEntry);
      const auditDoneNs = nowNs();

      parsed.headers = injectedHeaders;
      if (deps.connectionPool) {
        // With pooling, tell the upstream to keep the connection alive
        parsed.headers["connection"] = "keep-alive";
      } else {
        // Without pooling, force close so response reading is simple
        parsed.headers["connection"] = "close";
      }
      const headerData = serializeHttpHeaders(parsed);

      const forwardMetrics = await forwardToTarget(
        tlsServer,
        targetHost,
        targetPort,
        headerData,
        parsed.bodyInfo,
        parsed.reader,
        logger,
        deps.targetTlsOptions,
        deps.connectionPool,
        deps.tcpNoDelay,
      );

      const requestDoneNs = nowNs();
      const timingFields = {
        machineId,
        connId: deps.tunnelConnId,
        requestId,
        target,
        tunnelMode: deps.tunnelMode ?? false,
        method: parsed.method,
        path: parsed.path,
        keepAlive,
        injectedSecrets: injectedNames,
        parseMs: nsToMs(parseDoneNs - requestStartNs),
        secretResolveMs: nsToMs(injectionDoneNs - injectionStartNs),
        auditMs: nsToMs(auditDoneNs - auditStartNs),
        upstreamPoolReused: forwardMetrics.poolReused,
        upstreamPoolRetryCount: forwardMetrics.poolRetryCount,
        upstreamConnectMs: forwardMetrics.upstreamConnectMs,
        upstreamResponseHeaderMs: forwardMetrics.responseHeaderMs,
        upstreamResponseStreamMs: forwardMetrics.responseStreamMs,
        upstreamTotalMs: forwardMetrics.totalMs,
        totalMs: nsToMs(requestDoneNs - requestStartNs),
        errorStage: forwardMetrics.errorStage,
      };

      if (deps.latencyLoggingEnabled) {
        logger.info(timingFields, "MITM request timing");
      } else {
        logger.debug(timingFields, "MITM request processed");
      }
    }
  } catch (err) {
    logger.warn({ err, target, machineId, connId: deps.tunnelConnId }, "MITM session error");
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
  tcpNoDelay: boolean = true,
): Promise<ForwardMetrics> {
  if (!pool) {
    // Legacy path: no pool, use Connection: close and pipe until end
    return forwardToTargetLegacy(
      clientTls,
      targetHost,
      targetPort,
      headerData,
      bodyInfo,
      reader,
      logger,
      extraTlsOptions,
      tcpNoDelay,
    );
  }

  const overallStartNs = nowNs();
  const metrics: ForwardMetrics = {
    poolReused: null,
    poolRetryCount: 0,
    upstreamConnectMs: 0,
    responseHeaderMs: null,
    responseStreamMs: null,
    totalMs: 0,
  };

  let targetSocket: tls.TLSSocket | null = null;

  const doForward = async (retrying: boolean): Promise<void> => {
    try {
      const acquired = await pool.acquire(targetHost, targetPort, extraTlsOptions);
      targetSocket = acquired.socket;
      metrics.poolReused = acquired.reused;
      metrics.upstreamConnectMs += acquired.connectTimeMs;
    } catch (err) {
      metrics.errorStage = "connect";
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      await writeBadGateway(clientTls);
      return;
    }

    // Write request headers
    targetSocket.write(headerData);

    // Stream request body
    try {
      await pipeBody(reader, bodyInfo, targetSocket);
    } catch (err) {
      metrics.errorStage = "request_body";
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error piping request body");
      if (!targetSocket.destroyed) targetSocket.destroy();
      return;
    }

    // Read the response using explicit parsing (not pipe-until-end)
    try {
      const respReader = new SocketReader(targetSocket);
      const HEADER_END = Buffer.from("\r\n\r\n");
      const headerStartNs = nowNs();
      const respHeaderBuf = await respReader.readUntil(HEADER_END);
      metrics.responseHeaderMs = nsToMs(nowNs() - headerStartNs);

      if (!respHeaderBuf) {
        respReader.detach();
        if (!targetSocket.destroyed) targetSocket.destroy();
        // Stale pooled connection — retry once with a fresh one
        if (!retrying) {
          metrics.poolRetryCount += 1;
          return doForward(true);
        }
        metrics.errorStage = "response_headers";
        await writeBadGateway(clientTls);
        return;
      }

      // Write response headers to client
      await writeChunk(clientTls, respHeaderBuf);

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

      const streamStartNs = nowNs();
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
      metrics.responseStreamMs = nsToMs(nowNs() - streamStartNs);

      respReader.detach();

      // Release back to pool if possible
      if (canReuse && !targetSocket.destroyed && targetSocket.writable) {
        pool.release(targetHost, targetPort, targetSocket);
      } else if (!targetSocket.destroyed) {
        targetSocket.destroy();
      }
    } catch (err) {
      metrics.errorStage = metrics.responseHeaderMs === null ? "response_headers" : "response_body";
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error reading target response");
      if (targetSocket && !targetSocket.destroyed) {
        targetSocket.destroy();
      }
      // We may have partially written a response to the client already. At this
      // point the best we can do is tear down the upstream socket and let the
      // client observe the truncated/broken response.
    }
  };

  await doForward(false);
  metrics.totalMs = nsToMs(nowNs() - overallStartNs);
  return metrics;
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
  tcpNoDelay: boolean = true,
): Promise<ForwardMetrics> {
  const overallStartNs = nowNs();
  const metrics: ForwardMetrics = {
    poolReused: null,
    poolRetryCount: 0,
    upstreamConnectMs: 0,
    responseHeaderMs: null,
    responseStreamMs: null,
    totalMs: 0,
  };

  return new Promise((resolve) => {
    const connectStartNs = nowNs();
    const targetSocket = tls.connect({
      host: targetHost,
      port: targetPort,
      servername: targetHost,
      ...extraTlsOptions,
    });

    if (tcpNoDelay) {
      targetSocket.setNoDelay(true);
    }

    const onSecureConnect = async () => {
      metrics.upstreamConnectMs = nsToMs(nowNs() - connectStartNs);
      targetSocket.write(headerData);

      try {
        await pipeBody(reader, bodyInfo, targetSocket);
      } catch (err) {
        metrics.errorStage = "request_body";
        cleanup();
        logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error piping request body");
        if (!targetSocket.destroyed) targetSocket.destroy();
        metrics.totalMs = nsToMs(nowNs() - overallStartNs);
        resolve(metrics);
        return;
      }

      const streamStartNs = nowNs();
      targetSocket.pipe(clientTls, { end: false });
      targetSocket.once("end", () => {
        metrics.responseStreamMs = nsToMs(nowNs() - streamStartNs);
      });
    };

    const cleanup = () => {
      targetSocket.removeListener("secureConnect", onSecureConnect);
      targetSocket.removeListener("end", onEnd);
      targetSocket.removeListener("error", onTargetError);
      clientTls.removeListener("error", onClientError);
    };

    const onEnd = () => {
      cleanup();
      metrics.totalMs = nsToMs(nowNs() - overallStartNs);
      resolve(metrics);
    };

    const onTargetError = async (err: Error) => {
      cleanup();
      metrics.errorStage = metrics.upstreamConnectMs === 0 ? "connect" : "response_body";
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      await writeBadGateway(clientTls);
      metrics.totalMs = nsToMs(nowNs() - overallStartNs);
      resolve(metrics);
    };

    const onClientError = () => {
      cleanup();
      if (!targetSocket.destroyed) targetSocket.destroy();
      metrics.totalMs = nsToMs(nowNs() - overallStartNs);
      resolve(metrics);
    };

    targetSocket.once("secureConnect", onSecureConnect);
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
    await writeChunk(dest, `${sizeLine}\r\n`);

    if (isNaN(chunkSize) || chunkSize === 0) {
      // Terminal chunk — read and forward the trailing CRLF
      await reader.readLine();
      await writeChunk(dest, "\r\n");
      break;
    }

    // Read and forward chunk data
    const chunkData = await reader.readExact(chunkSize);
    if (chunkData) {
      await writeChunk(dest, chunkData);
    }
    // Read trailing CRLF after chunk data
    await reader.readLine();
    await writeChunk(dest, "\r\n");
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
  let remaining = length;

  while (remaining > 0) {
    const chunk = await reader.readSome(Math.min(FIXED_RESPONSE_CHUNK_SIZE, remaining));
    if (!chunk) {
      break;
    }

    remaining -= chunk.length;
    await writeChunk(dest, chunk);
  }
}

async function writeBadGateway(dest: tls.TLSSocket): Promise<void> {
  if (dest.destroyed) return;
  await writeChunk(
    dest,
    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway",
  );
}

async function writeChunk(dest: tls.TLSSocket, chunk: string | Buffer): Promise<void> {
  if (dest.destroyed) return;
  if (dest.write(chunk)) return;
  await once(dest, "drain");
}
