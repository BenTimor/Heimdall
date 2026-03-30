import * as http from "node:http";
import * as http2 from "node:http2";
import * as tls from "node:tls";
import { EventEmitter, once } from "node:events";
import type { Socket } from "node:net";
import type { Writable } from "node:stream";
import type { CertManager } from "./cert-manager.js";
import type { SecretResolver } from "../secrets/resolver.js";
import type { SecretConfig } from "../config/schema.js";
import type { AuditLogger, AuditEntry } from "../audit/audit-logger.js";
import type { Logger } from "../utils/logger.js";
import type { ConnectionPool } from "./connection-pool.js";
import type { UpstreamHttp2Pool, AcquiredUpstreamHttp2Session } from "./upstream-http2-pool.js";
import { injectSecrets } from "../injection/injector.js";
import {
  parseHttpHeaders,
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
  /** Upstream HTTP/1.1 connection pool (optional — falls back to per-request connections) */
  connectionPool?: ConnectionPool;
  /** Reusable upstream HTTP/2 session pool (optional — falls back to HTTP/1.1 only) */
  upstreamHttp2Pool?: UpstreamHttp2Pool;
  /** Emit structured latency logs for MITM sessions/requests. */
  latencyLoggingEnabled?: boolean;
  /** Connection ID from the tunnel protocol (if this originated from the agent). */
  tunnelConnId?: number;
  /** Timestamp captured when the tunnel server received NEW_CONNECTION. */
  tunnelAcceptedAtNs?: bigint;
  /** Disable Nagle's algorithm on outbound upstream sockets. */
  tcpNoDelay?: boolean;
}

type ClientProtocol = "http/1.1" | "h2";
type UpstreamProtocol = "http/1.1" | "h2";

type ForwardErrorStage = "connect" | "request_body" | "response_headers" | "response_body";

interface ForwardMetrics {
  upstreamProtocol: UpstreamProtocol;
  poolReused: boolean | null;
  poolRetryCount: number;
  upstreamConnectMs: number;
  upstreamTlsSessionReused: boolean | null;
  upstreamCachedTlsSessionOffered: boolean;
  responseHeaderMs: number | null;
  responseStreamMs: number | null;
  totalMs: number;
  errorStage?: ForwardErrorStage;
}

interface RequestProcessingTimings {
  passiveWaitMs?: number;
  headerParseMs: number;
  parseMs: number;
}

interface NormalizedRequest {
  requestStartNs: bigint;
  requestId: string;
  firstRequestOnConnection: boolean;
  clientProtocol: ClientProtocol;
  keepAlive: boolean;
  method: string;
  path: string;
  headers: Record<string, string>;
  bodySource: BodySource;
  responseWriter: ResponseWriter;
  timings: RequestProcessingTimings;
  clientStreamId?: number;
}

interface BodySource {
  hasBody: boolean;
  knownLength: number | null;
  consume(onChunk: (chunk: Buffer) => Promise<void>): Promise<void>;
}

interface ResponseMeta {
  statusCode: number;
  headers: Record<string, string>;
  contentLength: number | null;
  hasBody: boolean;
  requestMethod: string;
}

interface ResponseWriter {
  protocol: ClientProtocol;
  readonly headersSent: boolean;
  beginResponse(meta: ResponseMeta): Promise<void>;
  writeBodyChunk(chunk: Buffer): Promise<void>;
  endResponse(): Promise<void>;
  writeBadGateway(): Promise<void>;
  abort(): Promise<void>;
}

interface Http1AcquiredConnection {
  socket: tls.TLSSocket;
  reused: boolean;
  connectTimeMs: number;
  tlsSessionReused: boolean | null;
  cachedTlsSessionOffered: boolean;
}

const FIXED_BODY_CHUNK_SIZE = 16 * 1024;
const H1_HEADER_END = Buffer.from("\r\n\r\n");
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "te",
  "trailer",
  "proxy-authenticate",
  "proxy-authorization",
  "expect",
]);

const nowNs = (): bigint => process.hrtime.bigint();
const nsToMs = (durationNs: bigint): number => Number(durationNs) / 1_000_000;

export async function handleMitm(
  clientSocket: Socket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const { certManager, logger } = deps;
  const target = `${targetHost}:${targetPort}`;
  const sessionStartNs = nowNs();
  const certStartNs = sessionStartNs;

  const { cert, key, ocspResponse, fromCache, keySource } = certManager.getCertificate(targetHost);
  const certReadyNs = nowNs();

  if (!deps.tunnelMode) {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  const secureServer = http2.createSecureServer({
    cert,
    key,
    allowHTTP1: true,
    ALPNProtocols: ["h2", "http/1.1"],
  } as any);

  if (ocspResponse) {
    secureServer.on("OCSPRequest", (_certificate: Buffer, _issuer: Buffer, callback: Function) => {
      callback(null, ocspResponse);
    });
  }

  const pending = new Set<Promise<void>>();
  let requestSeq = 0;
  let h1IdleStartedAtNs: bigint | undefined;

  secureServer.on("error", (err) => {
    logger.warn({ err, target, machineId, connId: deps.tunnelConnId }, "MITM secure server error");
    if (!clientSocket.destroyed) clientSocket.destroy();
  });

  secureServer.on("sessionError", (err) => {
    logger.warn({ err, target, machineId, connId: deps.tunnelConnId }, "MITM HTTP/2 session error");
  });

  secureServer.on("secureConnection", (tlsSocket) => {
    const secureAtNs = nowNs();
    const clientProtocol: ClientProtocol = tlsSocket.alpnProtocol === "h2" ? "h2" : "http/1.1";

    if (clientProtocol === "http/1.1") {
      h1IdleStartedAtNs = secureAtNs;
    }

    if (deps.latencyLoggingEnabled) {
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
          clientAlpnProtocol: tlsSocket.alpnProtocol || null,
          clientProtocol,
        },
        "MITM connection timing",
      );
    }
  });

  secureServer.on("request", (req, res) => {
    requestSeq += 1;

    const clientProtocol: ClientProtocol = req.httpVersion.startsWith("2") ? "h2" : "http/1.1";
    const headersReadyAtNs = nowNs();
    const passiveWaitStartNs = clientProtocol === "http/1.1" && h1IdleStartedAtNs
      ? h1IdleStartedAtNs
      : headersReadyAtNs;
    const normalizedHeaders = normalizeNodeRequestHeaders(req.headers, targetHost, targetPort);
    const keepAlive = clientProtocol === "h2"
      ? true
      : isKeepAlive(`HTTP/${req.httpVersion}`, normalizedHeaders);
    const requestId = deps.tunnelConnId !== undefined
      ? clientProtocol === "h2" && (req as any).stream?.id !== undefined
        ? `${machineId}:${deps.tunnelConnId}:s${(req as any).stream.id}`
        : `${machineId}:${deps.tunnelConnId}:${requestSeq}`
      : clientProtocol === "h2" && (req as any).stream?.id !== undefined
        ? `${machineId}:${targetHost}:${targetPort}:s${(req as any).stream.id}`
        : `${machineId}:${targetHost}:${targetPort}:${requestSeq}`;

    const task = processMitmRequest(
      {
        requestStartNs: passiveWaitStartNs,
        requestId,
        firstRequestOnConnection: requestSeq === 1,
        clientProtocol,
        keepAlive,
        method: req.method ?? "GET",
        path: req.url ?? "/",
        headers: stripProxyHeaders(normalizedHeaders),
        bodySource: createNodeRequestBodySource(
          req,
          clientProtocol === "h2"
            ? !((req as any).stream?.endAfterHeaders ?? true)
            : hasHttp1RequestBody(normalizedHeaders),
          normalizedHeaders["content-length"],
        ),
        responseWriter: new CompatibilityResponseWriter(res, clientProtocol),
        timings: {
          passiveWaitMs: clientProtocol === "http/1.1"
            ? nsToMs(headersReadyAtNs - passiveWaitStartNs)
            : undefined,
          headerParseMs: 0,
          parseMs: clientProtocol === "http/1.1"
            ? nsToMs(headersReadyAtNs - passiveWaitStartNs)
            : 0,
        },
        clientStreamId: clientProtocol === "h2" ? (req as any).stream?.id : undefined,
      },
      targetHost,
      targetPort,
      machineId,
      deps,
    ).finally(() => {
      if (clientProtocol === "http/1.1") {
        h1IdleStartedAtNs = nowNs();
      }
      pending.delete(task);
    });

    pending.add(task);
  });

  try {
    secureServer.emit("connection", clientSocket as any);

    await new Promise<void>((resolve) => {
      const done = () => resolve();
      clientSocket.once("close", done);
      clientSocket.once("end", done);
      clientSocket.once("error", done);
    });

    if (pending.size > 0) {
      await Promise.allSettled([...pending]);
    }
  } catch (err) {
    logger.warn({ err, target, machineId, connId: deps.tunnelConnId }, "MITM session error");
  } finally {
    secureServer.close();
    if (!clientSocket.destroyed) {
      clientSocket.end();
    }
  }
}

function normalizeNodeRequestHeaders(
  headers: http.IncomingHttpHeaders | http2.IncomingHttpHeaders,
  targetHost: string,
  targetPort: number,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const stringValue = headerValueToString(value as string | string[] | number | undefined);
    if (stringValue !== null) {
      normalized[name.toLowerCase()] = stringValue;
    }
  }

  if (!normalized.host) {
    normalized.host = defaultAuthority(targetHost, targetPort);
  }

  return normalized;
}

function createNodeRequestBodySource(
  request: AsyncIterable<unknown>,
  hasBody: boolean,
  contentLengthHeader?: string,
): BodySource {
  let consumed = false;
  const knownLength = parseNumericHeader(contentLengthHeader);

  return {
    hasBody,
    knownLength,
    async consume(onChunk: (chunk: Buffer) => Promise<void>): Promise<void> {
      if (consumed) {
        throw new Error("Request body source already consumed");
      }
      consumed = true;

      for await (const chunk of request) {
        const buf = asBuffer(chunk as Buffer | Uint8Array | string);
        if (buf.length > 0) {
          await onChunk(buf);
        }
      }
    },
  };
}

class CompatibilityResponseWriter implements ResponseWriter {
  private ended = false;

  constructor(
    private response: http.ServerResponse | http2.Http2ServerResponse,
    public readonly protocol: ClientProtocol,
  ) {}

  get headersSent(): boolean {
    return this.response.headersSent;
  }

  async beginResponse(meta: ResponseMeta): Promise<void> {
    if (this.response.headersSent || this.ended) return;

    const headers = this.protocol === "h2"
      ? sanitizeHttp2ResponseHeaders(meta.headers)
      : sanitizeHttp1ResponseHeaders(meta.headers);

    if (meta.contentLength !== null) {
      headers["content-length"] = String(meta.contentLength);
    } else {
      delete headers["content-length"];
    }
    delete headers["transfer-encoding"];

    this.response.writeHead(meta.statusCode, headers);
    if (!meta.hasBody) {
      this.ended = true;
      this.response.end();
    }
  }

  async writeBodyChunk(chunk: Buffer): Promise<void> {
    if (this.ended || chunk.length === 0) return;
    await writeChunk(this.response as unknown as Writable & { destroyed?: boolean }, chunk);
  }

  async endResponse(): Promise<void> {
    if (this.ended) return;
    this.ended = true;
    await new Promise<void>((resolve) => {
      this.response.end(() => resolve());
    });
  }

  async writeBadGateway(): Promise<void> {
    if (this.response.headersSent || this.ended) return;
    this.ended = true;
    const body = "502 Bad Gateway";
    this.response.writeHead(502, {
      "content-type": "text/plain",
      "content-length": Buffer.byteLength(body).toString(),
    });
    await new Promise<void>((resolve) => {
      this.response.end(body, () => resolve());
    });
  }

  async abort(): Promise<void> {
    this.ended = true;
    const maybeHttp2Stream = (this.response as http2.Http2ServerResponse).stream;
    if (maybeHttp2Stream && !maybeHttp2Stream.closed && !maybeHttp2Stream.destroyed) {
      maybeHttp2Stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
      return;
    }

    if (typeof (this.response as http.ServerResponse).destroy === "function") {
      (this.response as http.ServerResponse).destroy();
    }
  }
}

async function handleHttp1ClientSession(
  tlsServer: tls.TLSSocket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  let keepAlive = true;
  let requestSeq = 0;

  while (keepAlive) {
    const requestStartNs = nowNs();
    const parsed = await parseHttpHeaders(tlsServer);
    if (!parsed) break;

    requestSeq += 1;
    keepAlive = isKeepAlive(parsed.httpVersion, parsed.headers);

    const requestId = deps.tunnelConnId !== undefined
      ? `${machineId}:${deps.tunnelConnId}:${requestSeq}`
      : `${machineId}:${targetHost}:${targetPort}:${requestSeq}`;

    const bodySource = createHttp1BodySource(parsed.reader, parsed.bodyInfo);
    const responseWriter = new Http1ResponseWriter(tlsServer, keepAlive);

    await processMitmRequest(
      {
        requestStartNs,
        requestId,
        firstRequestOnConnection: requestSeq === 1,
        clientProtocol: "http/1.1",
        keepAlive,
        method: parsed.method,
        path: parsed.path,
        headers: stripProxyHeaders(parsed.headers),
        bodySource,
        responseWriter,
        timings: {
          passiveWaitMs: parsed.timings.waitForHeadersMs,
          headerParseMs: parsed.timings.parseHeadersMs,
          parseMs: parsed.timings.totalMs,
        },
      },
      targetHost,
      targetPort,
      machineId,
      deps,
    );
  }
}

async function handleHttp2ClientSession(
  tlsServer: tls.TLSSocket,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const bufferedData = drainReadableBuffer(tlsServer);
  const session = http2.performServerHandshake(tlsServer);
  const pending = new Set<Promise<void>>();
  let requestSeq = 0;

  deps.logger.debug(
    { target: `${targetHost}:${targetPort}`, machineId, connId: deps.tunnelConnId },
    "HTTP/2 client session started",
  );

  session.on("error", (err) => {
    deps.logger.warn(
      { err, target: `${targetHost}:${targetPort}`, machineId, connId: deps.tunnelConnId },
      "HTTP/2 client session error",
    );
  });

  session.on("stream", (stream, headers) => {
    requestSeq += 1;
    deps.logger.debug(
      {
        target: `${targetHost}:${targetPort}`,
        machineId,
        connId: deps.tunnelConnId,
        clientStreamId: stream.id,
      },
      "HTTP/2 client stream received",
    );
    const requestSeqForStream = requestSeq;

    const task = handleHttp2ClientStream(
      stream,
      headers,
      requestSeqForStream,
      targetHost,
      targetPort,
      machineId,
      deps,
    )
      .catch(async (err) => {
        deps.logger.warn(
          {
            err,
            target: `${targetHost}:${targetPort}`,
            machineId,
            connId: deps.tunnelConnId,
            clientStreamId: stream.id,
          },
          "HTTP/2 client stream error",
        );
        if (!stream.closed && !stream.destroyed) {
          stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
        }
      })
      .finally(() => {
        pending.delete(task);
      });

    pending.add(task);
  });

  if (bufferedData.length > 0) {
    tlsServer.unshift(bufferedData);
  }

  await new Promise<void>((resolve) => {
    session.once("close", resolve);
  });

  if (pending.size > 0) {
    await Promise.allSettled([...pending]);
  }
}

async function handleHttp2ClientStream(
  stream: http2.ServerHttp2Stream,
  headers: http2.IncomingHttpHeaders,
  requestSeq: number,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const requestStartNs = nowNs();
  const normalized = normalizeHttp2Request(headers, targetHost, targetPort);
  const parsedAtNs = nowNs();

  if (!normalized.method || !normalized.path || normalized.method.toUpperCase() === "CONNECT") {
    const writer = new Http2ResponseWriter(stream);
    await writer.writeBadGateway();
    return;
  }

  const requestId = deps.tunnelConnId !== undefined
    ? `${machineId}:${deps.tunnelConnId}:s${stream.id}`
    : `${machineId}:${targetHost}:${targetPort}:s${stream.id}`;

  const bodySource = createHttp2BodySource(stream, normalized.headers["content-length"]);
  const responseWriter = new Http2ResponseWriter(stream);

  await processMitmRequest(
    {
      requestStartNs,
      requestId,
      firstRequestOnConnection: requestSeq === 1,
      clientProtocol: "h2",
      keepAlive: true,
      method: normalized.method,
      path: normalized.path,
      headers: stripProxyHeaders(normalized.headers),
      bodySource,
      responseWriter,
      timings: {
        headerParseMs: nsToMs(parsedAtNs - requestStartNs),
        parseMs: nsToMs(parsedAtNs - requestStartNs),
      },
      clientStreamId: stream.id,
    },
    targetHost,
    targetPort,
    machineId,
    deps,
  );
}

async function processMitmRequest(
  request: NormalizedRequest,
  targetHost: string,
  targetPort: number,
  machineId: string,
  deps: MitmDeps,
): Promise<void> {
  const { resolver, secretsConfig, auditLogger, logger } = deps;
  const target = `${targetHost}:${targetPort}`;
  const headersForInjection = { ...request.headers };

  try {
    const injectionStartNs = nowNs();
    const { injectedHeaders, injections } = await injectSecrets(
      targetHost,
      headersForInjection,
      secretsConfig,
      resolver,
      logger,
    );
    const injectionDoneNs = nowNs();

    const injectedNames = injections
      .filter((injection) => injection.status === "injected")
      .map((injection) => injection.secretName);

    const auditEntry: AuditEntry = {
      timestamp: new Date().toISOString(),
      machineId,
      method: request.method,
      target,
      injectedSecrets: injectedNames,
      action: injectedNames.length > 0 ? "injected" : "passthrough",
    };

    const auditStartNs = nowNs();
    auditLogger.logRequest(auditEntry);
    const auditDoneNs = nowNs();

    const forwardMetrics = await forwardToTarget(
      request,
      targetHost,
      targetPort,
      injectedHeaders,
      logger,
      deps.targetTlsOptions,
      deps.connectionPool,
      deps.upstreamHttp2Pool,
      deps.tcpNoDelay,
    );

    const requestDoneNs = nowNs();
    const totalMs = nsToMs(requestDoneNs - request.requestStartNs);
    const clientPassiveWaitMs = request.timings.passiveWaitMs;
    const activeHandlingMs = clientPassiveWaitMs !== undefined
      ? Math.max(0, totalMs - clientPassiveWaitMs)
      : totalMs;

    const timingFields = {
      machineId,
      connId: deps.tunnelConnId,
      clientStreamId: request.clientStreamId,
      requestId: request.requestId,
      target,
      tunnelMode: deps.tunnelMode ?? false,
      clientProtocol: request.clientProtocol,
      method: request.method,
      path: request.path,
      keepAlive: request.keepAlive,
      firstRequestOnConnection: request.firstRequestOnConnection,
      injectedSecrets: injectedNames,
      waitForRequestMs: request.timings.passiveWaitMs,
      headerParseMs: request.timings.headerParseMs,
      parseMs: request.timings.parseMs,
      clientPassiveWaitMs,
      activeHandlingMs,
      secretResolveMs: nsToMs(injectionDoneNs - injectionStartNs),
      auditMs: nsToMs(auditDoneNs - auditStartNs),
      upstreamProtocol: forwardMetrics.upstreamProtocol,
      upstreamPoolReused: forwardMetrics.poolReused,
      upstreamPoolRetryCount: forwardMetrics.poolRetryCount,
      upstreamConnectMs: forwardMetrics.upstreamConnectMs,
      upstreamTlsSessionReused: forwardMetrics.upstreamTlsSessionReused,
      upstreamCachedTlsSessionOffered: forwardMetrics.upstreamCachedTlsSessionOffered,
      upstreamResponseHeaderMs: forwardMetrics.responseHeaderMs,
      upstreamResponseStreamMs: forwardMetrics.responseStreamMs,
      upstreamTotalMs: forwardMetrics.totalMs,
      totalMs,
      errorStage: forwardMetrics.errorStage,
    };

    if (deps.latencyLoggingEnabled) {
      logger.info(timingFields, "MITM request timing");
    } else {
      logger.debug(timingFields, "MITM request processed");
    }
  } catch (err) {
    logger.warn(
      {
        err,
        target,
        machineId,
        connId: deps.tunnelConnId,
        clientStreamId: request.clientStreamId,
        requestId: request.requestId,
      },
      "MITM request failed",
    );

    if (!request.responseWriter.headersSent) {
      await request.responseWriter.writeBadGateway();
    } else {
      await request.responseWriter.abort();
    }
  }
}

async function forwardToTarget(
  request: NormalizedRequest,
  targetHost: string,
  targetPort: number,
  injectedHeaders: Record<string, string>,
  logger: Logger,
  extraTlsOptions?: tls.ConnectionOptions,
  pool?: ConnectionPool,
  upstreamHttp2Pool?: UpstreamHttp2Pool,
  tcpNoDelay: boolean = true,
): Promise<ForwardMetrics> {
  if (upstreamHttp2Pool) {
    const acquiredHttp2 = await upstreamHttp2Pool.acquire(targetHost, targetPort, extraTlsOptions);
    if (acquiredHttp2) {
      return forwardToTargetHttp2(
        request,
        targetHost,
        targetPort,
        injectedHeaders,
        logger,
        acquiredHttp2,
        upstreamHttp2Pool,
      );
    }
  }

  return forwardToTargetHttp1(
    request,
    targetHost,
    targetPort,
    injectedHeaders,
    logger,
    extraTlsOptions,
    pool,
    tcpNoDelay,
  );
}

async function forwardToTargetHttp2(
  request: NormalizedRequest,
  targetHost: string,
  targetPort: number,
  injectedHeaders: Record<string, string>,
  logger: Logger,
  acquired: AcquiredUpstreamHttp2Session,
  pool: UpstreamHttp2Pool,
): Promise<ForwardMetrics> {
  const overallStartNs = nowNs();
  const metrics: ForwardMetrics = {
    upstreamProtocol: "h2",
    poolReused: acquired.reused,
    poolRetryCount: 0,
    upstreamConnectMs: acquired.connectTimeMs,
    upstreamTlsSessionReused: acquired.tlsSessionReused,
    upstreamCachedTlsSessionOffered: acquired.cachedTlsSessionOffered,
    responseHeaderMs: null,
    responseStreamMs: null,
    totalMs: 0,
  };

  const session = acquired.session;
  const outgoingHeaders = buildHttp2UpstreamHeaders(
    request.method,
    request.path,
    injectedHeaders,
    targetHost,
    targetPort,
    request.bodySource,
  );

  const upstreamStream = session.request(outgoingHeaders, {
    endStream: !request.bodySource.hasBody,
  });

  let responseHeadersAtNs: bigint | null = null;
  const responseHeadersPromise = new Promise<http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader>((resolve, reject) => {
    const onResponse = (headers: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader) => {
      cleanup();
      responseHeadersAtNs = nowNs();
      resolve(headers);
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("upstream HTTP/2 stream closed before response headers"));
    };
    const cleanup = () => {
      upstreamStream.removeListener("response", onResponse);
      upstreamStream.removeListener("error", onError);
      upstreamStream.removeListener("close", onClose);
    };

    upstreamStream.once("response", onResponse);
    upstreamStream.once("error", onError);
    upstreamStream.once("close", onClose);
  });

  try {
    if (request.bodySource.hasBody) {
      try {
        await request.bodySource.consume(async (chunk) => {
          await writeChunk(upstreamStream, chunk);
        });
        upstreamStream.end();
      } catch (err) {
        metrics.errorStage = "request_body";
        if (!upstreamStream.closed && !upstreamStream.destroyed) {
          upstreamStream.close(http2.constants.NGHTTP2_CANCEL);
        }
        metrics.totalMs = nsToMs(nowNs() - overallStartNs);
        return metrics;
      }
    }

    const headerWaitStartedAtNs = nowNs();
    let responseHeaders: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader;
    try {
      responseHeaders = await responseHeadersPromise;
    } catch (err) {
      metrics.errorStage = "response_headers";
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error reading upstream HTTP/2 response headers");
      pool.invalidate(targetHost, targetPort, session);
      if (!request.responseWriter.headersSent) {
        await request.responseWriter.writeBadGateway();
      } else {
        await request.responseWriter.abort();
      }
      metrics.totalMs = nsToMs(nowNs() - overallStartNs);
      return metrics;
    }

    metrics.responseHeaderMs = responseHeadersAtNs
      ? Math.max(0, nsToMs(responseHeadersAtNs - headerWaitStartedAtNs))
      : nsToMs(nowNs() - headerWaitStartedAtNs);

    const responseMeta = buildHttp2ResponseMeta(responseHeaders, request.method);
    await request.responseWriter.beginResponse(responseMeta);

    const responseStreamStartNs = nowNs();
    try {
      for await (const chunk of upstreamStream) {
        await request.responseWriter.writeBodyChunk(asBuffer(chunk));
      }
      await request.responseWriter.endResponse();
      metrics.responseStreamMs = nsToMs(nowNs() - responseStreamStartNs);
      pool.touch(targetHost, targetPort);
    } catch (err) {
      metrics.errorStage = metrics.responseHeaderMs === null ? "response_headers" : "response_body";
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error streaming upstream HTTP/2 response body");
      pool.invalidate(targetHost, targetPort, session);
      await request.responseWriter.abort();
    }
  } finally {
    metrics.totalMs = nsToMs(nowNs() - overallStartNs);
  }

  return metrics;
}

async function forwardToTargetHttp1(
  request: NormalizedRequest,
  targetHost: string,
  targetPort: number,
  injectedHeaders: Record<string, string>,
  logger: Logger,
  extraTlsOptions?: tls.ConnectionOptions,
  pool?: ConnectionPool,
  tcpNoDelay: boolean = true,
): Promise<ForwardMetrics> {
  const overallStartNs = nowNs();
  const metrics: ForwardMetrics = {
    upstreamProtocol: "http/1.1",
    poolReused: null,
    poolRetryCount: 0,
    upstreamConnectMs: 0,
    upstreamTlsSessionReused: null,
    upstreamCachedTlsSessionOffered: false,
    responseHeaderMs: null,
    responseStreamMs: null,
    totalMs: 0,
  };

  const outgoingHeaders = buildHttp1UpstreamHeaders(
    injectedHeaders,
    targetHost,
    targetPort,
    request.bodySource,
    !!pool,
  );
  const headerData = serializeHttpHeaders({
    method: request.method,
    path: request.path,
    httpVersion: "HTTP/1.1",
    headers: outgoingHeaders,
  });

  const doForward = async (retrying: boolean): Promise<void> => {
    let acquired: Http1AcquiredConnection;
    try {
      acquired = await acquireHttp1Connection(targetHost, targetPort, extraTlsOptions, pool, tcpNoDelay);
      metrics.poolReused = acquired.reused;
      metrics.upstreamConnectMs += acquired.connectTimeMs;
      metrics.upstreamTlsSessionReused = acquired.tlsSessionReused;
      metrics.upstreamCachedTlsSessionOffered = acquired.cachedTlsSessionOffered;
    } catch (err) {
      metrics.errorStage = "connect";
      logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (MITM)");
      await request.responseWriter.writeBadGateway();
      return;
    }

    const targetSocket = acquired.socket;

    try {
      await writeChunk(targetSocket, headerData);

      if (request.bodySource.hasBody) {
        try {
          if (request.bodySource.knownLength !== null) {
            await request.bodySource.consume(async (chunk) => {
              await writeChunk(targetSocket, chunk);
            });
          } else {
            await request.bodySource.consume(async (chunk) => {
              await writeChunk(targetSocket, `${chunk.length.toString(16)}\r\n`);
              if (chunk.length > 0) {
                await writeChunk(targetSocket, chunk);
              }
              await writeChunk(targetSocket, "\r\n");
            });
            await writeChunk(targetSocket, "0\r\n\r\n");
          }
        } catch (err) {
          metrics.errorStage = "request_body";
          if (!targetSocket.destroyed) targetSocket.destroy();
          return;
        }
      }

      const respReader = new SocketReader(targetSocket);
      const headerStartNs = nowNs();
      const responseHead = await readHttp1ResponseHead(respReader);
      metrics.responseHeaderMs = nsToMs(nowNs() - headerStartNs);

      if (!responseHead) {
        respReader.detach();
        if (!targetSocket.destroyed) targetSocket.destroy();
        if (!retrying && acquired.reused && !request.bodySource.hasBody) {
          metrics.poolRetryCount += 1;
          return doForward(true);
        }

        metrics.errorStage = "response_headers";
        await request.responseWriter.writeBadGateway();
        return;
      }

      const responseMeta = buildHttp1ResponseMeta(responseHead, request.method);
      await request.responseWriter.beginResponse(responseMeta);

      const responseStreamStartNs = nowNs();
      try {
        if (responseMeta.hasBody) {
          if (responseHead.transferEncodingChunked) {
            await streamHttp1ChunkedBodyRaw(respReader, request.responseWriter);
          } else if (responseMeta.contentLength !== null) {
            await streamHttp1FixedBodyRaw(respReader, request.responseWriter, responseMeta.contentLength);
          } else if (!responseHead.canReuseConnection) {
            await streamHttp1UntilEof(respReader, request.responseWriter);
          }
        }
        await request.responseWriter.endResponse();
        metrics.responseStreamMs = nsToMs(nowNs() - responseStreamStartNs);
      } catch (err) {
        metrics.errorStage = metrics.responseHeaderMs === null ? "response_headers" : "response_body";
        logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error reading target response");
        await request.responseWriter.abort();
      } finally {
        respReader.detach();
      }

      if (pool && responseHead.canReuseConnection && !targetSocket.destroyed && targetSocket.writable) {
        pool.release(targetHost, targetPort, targetSocket);
      } else if (!targetSocket.destroyed) {
        targetSocket.destroy();
      }
    } catch (err) {
      metrics.errorStage = metrics.responseHeaderMs === null ? "response_headers" : "response_body";
      logger.debug({ err, target: `${targetHost}:${targetPort}` }, "Error forwarding to target");
      if (!targetSocket.destroyed) {
        targetSocket.destroy();
      }
      if (!request.responseWriter.headersSent) {
        await request.responseWriter.writeBadGateway();
      } else {
        await request.responseWriter.abort();
      }
    }
  };

  await doForward(false);
  metrics.totalMs = nsToMs(nowNs() - overallStartNs);
  return metrics;
}

class Http1ResponseWriter implements ResponseWriter {
  public readonly protocol: ClientProtocol = "http/1.1";
  private started = false;
  private ended = false;
  private mode: "none" | "raw" | "chunked" = "none";

  constructor(private socket: tls.TLSSocket, private keepAlive: boolean) {}

  get headersSent(): boolean {
    return this.started;
  }

  async beginResponse(meta: ResponseMeta): Promise<void> {
    if (this.started || this.socket.destroyed) return;

    const headers = sanitizeHttp1ResponseHeaders(meta.headers);
    const hasBody = meta.hasBody;

    if (!hasBody) {
      this.mode = "none";
      if (meta.contentLength !== null) {
        headers["content-length"] = String(meta.contentLength);
      }
      delete headers["transfer-encoding"];
    } else if (meta.contentLength !== null) {
      this.mode = "raw";
      headers["content-length"] = String(meta.contentLength);
      delete headers["transfer-encoding"];
    } else {
      this.mode = "chunked";
      headers["transfer-encoding"] = "chunked";
      delete headers["content-length"];
    }

    headers["connection"] = this.keepAlive ? "keep-alive" : "close";

    this.started = true;
    if (this.mode === "none") {
      this.ended = true;
    }

    await writeChunk(this.socket, serializeHttp1ResponseHead(meta.statusCode, headers));
  }

  async writeBodyChunk(chunk: Buffer): Promise<void> {
    if (this.socket.destroyed || this.mode === "none" || chunk.length === 0) return;

    if (this.mode === "chunked") {
      await writeChunk(this.socket, `${chunk.length.toString(16)}\r\n`);
      await writeChunk(this.socket, chunk);
      await writeChunk(this.socket, "\r\n");
      return;
    }

    await writeChunk(this.socket, chunk);
  }

  async endResponse(): Promise<void> {
    if (this.socket.destroyed || this.ended) return;

    if (this.mode === "chunked") {
      await writeChunk(this.socket, "0\r\n\r\n");
    }

    this.ended = true;
  }

  async writeBadGateway(): Promise<void> {
    if (this.started || this.socket.destroyed) return;
    this.started = true;
    this.ended = true;
    await writeChunk(
      this.socket,
      "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 15\r\nConnection: close\r\n\r\n502 Bad Gateway",
    );
  }

  async abort(): Promise<void> {
    if (!this.socket.destroyed) {
      this.socket.destroy();
    }
  }
}

class Http2ResponseWriter implements ResponseWriter {
  public readonly protocol: ClientProtocol = "h2";
  private started = false;
  private ended = false;

  constructor(private stream: http2.ServerHttp2Stream) {}

  get headersSent(): boolean {
    return this.started;
  }

  async beginResponse(meta: ResponseMeta): Promise<void> {
    if (this.started || this.stream.closed || this.stream.destroyed) return;

    const headers = sanitizeHttp2ResponseHeaders(meta.headers);
    const outgoing: http2.OutgoingHttpHeaders = {
      ":status": meta.statusCode,
      ...headers,
    };

    if (meta.contentLength !== null) {
      outgoing["content-length"] = String(meta.contentLength);
    }

    this.started = true;
    this.ended = !meta.hasBody;
    this.stream.respond(outgoing, { endStream: !meta.hasBody });
  }

  async writeBodyChunk(chunk: Buffer): Promise<void> {
    if (this.stream.closed || this.stream.destroyed || this.ended || chunk.length === 0) return;
    await writeChunk(this.stream, chunk);
  }

  async endResponse(): Promise<void> {
    if (this.stream.closed || this.stream.destroyed || this.ended) return;
    this.ended = true;
    this.stream.end();
  }

  async writeBadGateway(): Promise<void> {
    if (this.started || this.stream.closed || this.stream.destroyed) return;

    const body = Buffer.from("502 Bad Gateway");
    this.started = true;
    this.ended = true;
    this.stream.respond({
      ":status": 502,
      "content-type": "text/plain",
      "content-length": body.length.toString(),
    });
    this.stream.end(body);
  }

  async abort(): Promise<void> {
    if (!this.stream.closed && !this.stream.destroyed) {
      this.stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
    }
  }
}

function createHttp1BodySource(reader: SocketReader, bodyInfo: BodyInfo): BodySource {
  let consumed = false;

  return {
    hasBody: bodyInfo.type !== "none" && (bodyInfo.type !== "content-length" || bodyInfo.length > 0),
    knownLength: bodyInfo.type === "content-length" ? bodyInfo.length : null,
    async consume(onChunk: (chunk: Buffer) => Promise<void>): Promise<void> {
      if (consumed) {
        throw new Error("HTTP/1 body source already consumed");
      }
      consumed = true;

      try {
        if (bodyInfo.type === "none") {
          reader.detach();
          return;
        }

        if (bodyInfo.type === "content-length") {
          let remaining = bodyInfo.length;
          const residual = reader.getResidual();
          const initialChunk = residual.subarray(0, Math.min(residual.length, remaining));
          if (initialChunk.length > 0) {
            remaining -= initialChunk.length;
            await onChunk(Buffer.from(initialChunk));
          }

          while (remaining > 0) {
            const chunk = await reader.readSome(Math.min(FIXED_BODY_CHUNK_SIZE, remaining));
            if (!chunk) break;
            remaining -= chunk.length;
            await onChunk(chunk);
          }

          reader.detach();
          return;
        }

        while (true) {
          const sizeLine = await reader.readLine();
          if (sizeLine === null) break;

          const chunkSize = parseInt(sizeLine.trim(), 16);
          if (isNaN(chunkSize) || chunkSize === 0) {
            while (true) {
              const trailerLine = await reader.readLine();
              if (trailerLine === null || trailerLine === "") {
                break;
              }
            }
            break;
          }

          const chunk = await reader.readExact(chunkSize);
          await reader.readLine();
          if (chunk && chunk.length > 0) {
            await onChunk(chunk);
          }
        }
      } finally {
        reader.detach();
      }
    },
  };
}

function createHttp2BodySource(
  stream: http2.ServerHttp2Stream,
  contentLengthHeader?: string,
): BodySource {
  let consumed = false;
  const knownLength = parseNumericHeader(contentLengthHeader);
  const hasBody = !stream.endAfterHeaders && (knownLength === null || knownLength > 0);

  return {
    hasBody,
    knownLength,
    async consume(onChunk: (chunk: Buffer) => Promise<void>): Promise<void> {
      if (consumed) {
        throw new Error("HTTP/2 body source already consumed");
      }
      consumed = true;

      for await (const chunk of stream) {
        const buf = asBuffer(chunk);
        if (buf.length > 0) {
          await onChunk(buf);
        }
      }
    },
  };
}

function normalizeHttp2Request(
  headers: http2.IncomingHttpHeaders,
  targetHost: string,
  targetPort: number,
): { method: string | null; path: string | null; headers: Record<string, string> } {
  const method = headerValueToString(headers[":method"]);
  const path = headerValueToString(headers[":path"]);
  const authority = headerValueToString(headers[":authority"]);

  const normalizedHeaders: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (name.startsWith(":")) continue;
    const stringValue = headerValueToString(value);
    if (stringValue !== null) {
      normalizedHeaders[name.toLowerCase()] = stringValue;
    }
  }

  if (!normalizedHeaders.host) {
    normalizedHeaders.host = authority ?? defaultAuthority(targetHost, targetPort);
  }

  return {
    method: method ?? null,
    path: path ?? "/",
    headers: normalizedHeaders,
  };
}

function buildHttp1UpstreamHeaders(
  headers: Record<string, string>,
  targetHost: string,
  targetPort: number,
  bodySource: BodySource,
  keepAlive: boolean,
): Record<string, string> {
  const outgoing: Record<string, string> = {};

  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (lowerName.startsWith(":")) continue;
    if (HOP_BY_HOP_HEADERS.has(lowerName)) continue;
    outgoing[lowerName] = value;
  }

  if (!outgoing.host) {
    outgoing.host = defaultAuthority(targetHost, targetPort);
  }

  if (bodySource.hasBody) {
    if (bodySource.knownLength !== null) {
      outgoing["content-length"] = String(bodySource.knownLength);
      delete outgoing["transfer-encoding"];
    } else {
      delete outgoing["content-length"];
      outgoing["transfer-encoding"] = "chunked";
    }
  } else {
    delete outgoing["content-length"];
    delete outgoing["transfer-encoding"];
  }

  outgoing.connection = keepAlive ? "keep-alive" : "close";
  return outgoing;
}

function buildHttp2UpstreamHeaders(
  method: string,
  path: string,
  headers: Record<string, string>,
  targetHost: string,
  targetPort: number,
  bodySource: BodySource,
): http2.OutgoingHttpHeaders {
  const outgoing: http2.OutgoingHttpHeaders = {
    ":method": method,
    ":path": path,
    ":scheme": "https",
    ":authority": headers.host ?? defaultAuthority(targetHost, targetPort),
  };

  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (lowerName.startsWith(":")) continue;
    if (lowerName === "host") continue;
    if (HOP_BY_HOP_HEADERS.has(lowerName)) continue;
    outgoing[lowerName] = value;
  }

  if (bodySource.hasBody && bodySource.knownLength !== null) {
    outgoing["content-length"] = String(bodySource.knownLength);
  } else {
    delete outgoing["content-length"];
  }

  return outgoing;
}

async function acquireHttp1Connection(
  host: string,
  port: number,
  extraTlsOptions: tls.ConnectionOptions | undefined,
  pool: ConnectionPool | undefined,
  tcpNoDelay: boolean,
): Promise<Http1AcquiredConnection> {
  if (pool) {
    const acquired = await pool.acquire(host, port, extraTlsOptions);
    return {
      socket: acquired.socket,
      reused: acquired.reused,
      connectTimeMs: acquired.connectTimeMs,
      tlsSessionReused: acquired.tlsSessionReused,
      cachedTlsSessionOffered: acquired.cachedTlsSessionOffered,
    };
  }

  return new Promise((resolve, reject) => {
    const startedAt = nowNs();
    const socket = tls.connect({
      host,
      port,
      servername: host,
      ...extraTlsOptions,
    });

    if (tcpNoDelay) {
      socket.setNoDelay(true);
    }

    const onSecureConnect = () => {
      cleanup();
      resolve({
        socket,
        reused: false,
        connectTimeMs: nsToMs(nowNs() - startedAt),
        tlsSessionReused: typeof socket.isSessionReused === "function" ? socket.isSessionReused() : null,
        cachedTlsSessionOffered: false,
      });
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      socket.removeListener("secureConnect", onSecureConnect);
      socket.removeListener("error", onError);
    };

    socket.once("secureConnect", onSecureConnect);
    socket.once("error", onError);
  });
}

async function waitForSecureHandshake(socket: tls.TLSSocket): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onSecure = () => {
      cleanup();
      resolve();
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("TLS socket closed before secure handshake completed"));
    };
    const cleanup = () => {
      socket.removeListener("secure", onSecure);
      socket.removeListener("error", onError);
      socket.removeListener("close", onClose);
    };

    socket.once("secure", onSecure);
    socket.once("error", onError);
    socket.once("close", onClose);
  });
}

async function readHttp1ResponseHead(reader: SocketReader): Promise<{
  statusCode: number;
  headers: Record<string, string>;
  contentLength: number | null;
  transferEncodingChunked: boolean;
  canReuseConnection: boolean;
} | null> {
  const headerBuf = await reader.readUntil(H1_HEADER_END);
  if (!headerBuf) {
    return null;
  }

  const headerText = headerBuf.toString("utf-8");
  const lines = headerText.split("\r\n");
  const statusLine = lines[0] ?? "";
  const statusCode = parseInt(statusLine.split(" ")[1] ?? "0", 10);
  const headers: Record<string, string> = {};

  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line) break;
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const name = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    headers[name] = value;
  }

  const contentLength = parseNumericHeader(headers["content-length"]);
  const transferEncodingChunked = headers["transfer-encoding"]?.toLowerCase().includes("chunked") ?? false;
  const connectionHeader = headers.connection?.toLowerCase();
  const canReuseConnection = connectionHeader !== "close" && !transferEncodingChunked && contentLength !== null;

  return {
    statusCode,
    headers,
    contentLength,
    transferEncodingChunked,
    canReuseConnection,
  };
}

function buildHttp1ResponseMeta(
  responseHead: {
    statusCode: number;
    headers: Record<string, string>;
    contentLength: number | null;
    transferEncodingChunked: boolean;
    canReuseConnection: boolean;
  },
  requestMethod: string,
): ResponseMeta {
  const responseAllowsBody = canResponseHaveBody(responseHead.statusCode, requestMethod);
  const hasBody = responseAllowsBody && (
    responseHead.transferEncodingChunked
    || (responseHead.contentLength !== null && responseHead.contentLength > 0)
    || (responseHead.contentLength === null && !responseHead.canReuseConnection)
  );

  return {
    statusCode: responseHead.statusCode,
    headers: responseHead.headers,
    contentLength: responseHead.contentLength,
    hasBody,
    requestMethod,
  };
}

function buildHttp2ResponseMeta(
  headers: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader,
  requestMethod: string,
): ResponseMeta {
  const statusCode = typeof headers[":status"] === "number"
    ? headers[":status"]
    : parseInt(String(headers[":status"] ?? "0"), 10);

  const normalizedHeaders: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (name.startsWith(":")) continue;
    const stringValue = headerValueToString(value);
    if (stringValue !== null) {
      normalizedHeaders[name.toLowerCase()] = stringValue;
    }
  }

  const contentLength = parseNumericHeader(normalizedHeaders["content-length"]);
  const hasBody = canResponseHaveBody(statusCode, requestMethod)
    && (contentLength === null || contentLength > 0);

  return {
    statusCode,
    headers: normalizedHeaders,
    contentLength,
    hasBody,
    requestMethod,
  };
}

async function streamHttp1ChunkedBodyRaw(reader: SocketReader, writer: ResponseWriter): Promise<void> {
  while (true) {
    const sizeLine = await reader.readLine();
    if (sizeLine === null) break;

    const chunkSize = parseInt(sizeLine.trim(), 16);
    if (isNaN(chunkSize) || chunkSize === 0) {
      while (true) {
        const trailerLine = await reader.readLine();
        if (trailerLine === null || trailerLine === "") {
          break;
        }
      }
      break;
    }

    const chunk = await reader.readExact(chunkSize);
    await reader.readLine();
    if (chunk && chunk.length > 0) {
      await writer.writeBodyChunk(chunk);
    }
  }
}

async function streamHttp1FixedBodyRaw(
  reader: SocketReader,
  writer: ResponseWriter,
  length: number,
): Promise<void> {
  let remaining = length;
  while (remaining > 0) {
    const chunk = await reader.readSome(Math.min(FIXED_BODY_CHUNK_SIZE, remaining));
    if (!chunk) break;
    remaining -= chunk.length;
    await writer.writeBodyChunk(chunk);
  }
}

async function streamHttp1UntilEof(reader: SocketReader, writer: ResponseWriter): Promise<void> {
  while (true) {
    const chunk = await reader.readSome(FIXED_BODY_CHUNK_SIZE);
    if (!chunk) break;
    await writer.writeBodyChunk(chunk);
  }
}

function sanitizeHttp1ResponseHeaders(headers: Record<string, string>): Record<string, string> {
  const outgoing: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (lowerName.startsWith(":")) continue;
    if (lowerName === "connection") continue;
    if (lowerName === "proxy-connection") continue;
    if (lowerName === "keep-alive") continue;
    if (lowerName === "upgrade") continue;
    outgoing[lowerName] = value;
  }
  return outgoing;
}

function sanitizeHttp2ResponseHeaders(headers: Record<string, string>): Record<string, string> {
  const outgoing: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (lowerName.startsWith(":")) continue;
    if (HOP_BY_HOP_HEADERS.has(lowerName)) continue;
    outgoing[lowerName] = value;
  }
  return outgoing;
}

function stripProxyHeaders(headers: Record<string, string>): Record<string, string> {
  const cleaned = { ...headers };
  delete cleaned["proxy-authorization"];
  delete cleaned["proxy-connection"];
  return cleaned;
}

function hasHttp1RequestBody(headers: Record<string, string>): boolean {
  const contentLength = parseNumericHeader(headers["content-length"]);
  if (contentLength !== null) {
    return contentLength > 0;
  }
  return headers["transfer-encoding"] !== undefined;
}

function defaultAuthority(host: string, port: number): string {
  return port === 443 ? host : `${host}:${port}`;
}

function canResponseHaveBody(statusCode: number, requestMethod: string): boolean {
  if (requestMethod.toUpperCase() === "HEAD") {
    return false;
  }
  if (statusCode >= 100 && statusCode < 200) {
    return false;
  }
  if (statusCode === 204 || statusCode === 304) {
    return false;
  }
  return true;
}

function serializeHttp1ResponseHead(statusCode: number, headers: Record<string, string>): Buffer {
  const statusMessage = http.STATUS_CODES[statusCode] ?? "OK";
  const lines = [`HTTP/1.1 ${statusCode} ${statusMessage}`];

  for (const [name, value] of Object.entries(headers)) {
    lines.push(`${name}: ${value}`);
  }

  lines.push("", "");
  return Buffer.from(lines.join("\r\n"));
}

function parseNumericHeader(value: string | undefined): number | null {
  if (!value) return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function headerValueToString(value: string | string[] | number | undefined): string | null {
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

function asBuffer(chunk: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(chunk)) return chunk;
  if (typeof chunk === "string") return Buffer.from(chunk);
  return Buffer.from(chunk);
}

function drainReadableBuffer(socket: tls.TLSSocket): Buffer {
  const chunks: Buffer[] = [];
  while (true) {
    const chunk = socket.read();
    if (chunk === null) break;
    chunks.push(asBuffer(chunk));
  }
  return Buffer.concat(chunks);
}

async function writeChunk(dest: Writable & { destroyed?: boolean }, chunk: string | Buffer): Promise<void> {
  if ((dest as any).destroyed) return;
  if ((dest as any).write(chunk)) return;
  await once(dest as any, "drain");
}
