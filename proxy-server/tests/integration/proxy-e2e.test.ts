import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import * as https from "node:https";
import * as http from "node:http";
import * as tls from "node:tls";
import * as net from "node:net";
import * as http2 from "node:http2";
import forge from "node-forge";
import { ProxyServer } from "../../src/proxy/server.js";
import { CertManager } from "../../src/proxy/cert-manager.js";
import { SecretResolver } from "../../src/secrets/resolver.js";
import { SecretCache } from "../../src/secrets/cache.js";
import { EnvProvider } from "../../src/secrets/env-provider.js";
import { AuditLogger } from "../../src/audit/audit-logger.js";
import { Authenticator } from "../../src/auth/authenticator.js";
import { ConfigAuthBackend } from "../../src/auth/config-backend.js";
import { UpstreamHttp2Pool } from "../../src/proxy/upstream-http2-pool.js";
import type { ServerConfig } from "../../src/config/schema.js";
import type { Logger } from "../../src/utils/logger.js";

function createTestCA(): { caCertPem: string; caKeyPem: string; caCert: forge.pki.Certificate } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  const attrs = [{ name: "commonName", value: "Test CA" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true },
    { name: "keyUsage", keyCertSign: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    caCertPem: forge.pki.certificateToPem(cert),
    caKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    caCert: cert,
  };
}

function createMockLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    fatal: vi.fn(),
    trace: vi.fn(),
    child: vi.fn().mockReturnThis(),
    level: "silent",
  } as unknown as Logger;
}

/**
 * Create an HTTPS server (mock target API) using the same CA for certs.
 */
function createMockHttpsServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ server: https.Server; port: number; host: string; cert: string; key: string }> {
  // Generate self-signed cert for mock server
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "02";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  cert.setSubject([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setIssuer([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setExtensions([
    { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  return new Promise((resolve) => {
    const server = https.createServer({ cert: certPem, key: keyPem }, handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      resolve({ server, port: addr.port, host: "127.0.0.1", cert: certPem, key: keyPem });
    });
  });
}

function createMockHttp2Server(
  handler: (stream: http2.ServerHttp2Stream, headers: http2.IncomingHttpHeaders) => void,
): Promise<{ server: http2.Http2SecureServer; port: number; host: string; cert: string; key: string }> {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "03";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  cert.setSubject([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setIssuer([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setExtensions([
    { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  return new Promise((resolve) => {
    const server = http2.createSecureServer({ cert: certPem, key: keyPem });
    server.on("stream", handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      resolve({ server, port: addr.port, host: "127.0.0.1", cert: certPem, key: keyPem });
    });
  });
}

function connectThroughProxyTls(
  proxyPort: number,
  targetHost: string,
  targetPort: number,
  proxyAuth?: string,
  tlsOptions: tls.ConnectionOptions = {},
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("CONNECT timeout")), 10000);

    const proxySocket = net.connect(proxyPort, "127.0.0.1", () => {
      let connectLine = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
      if (proxyAuth) {
        connectLine += `Proxy-Authorization: Basic ${Buffer.from(proxyAuth).toString("base64")}\r\n`;
      }
      connectLine += "\r\n";
      proxySocket.write(connectLine);
    });

    let dataBuf = Buffer.alloc(0);
    const onProxyData = (chunk: Buffer) => {
      dataBuf = Buffer.concat([dataBuf, chunk]);
      const headerEnd = dataBuf.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;

      proxySocket.removeListener("data", onProxyData);
      const statusLine = dataBuf.subarray(0, headerEnd).toString().split("\r\n")[0] ?? "";
      const statusCode = parseInt(statusLine.split(" ")[1] ?? "0", 10);
      if (statusCode !== 200) {
        clearTimeout(timeout);
        proxySocket.destroy();
        reject(new Error(`CONNECT failed with ${statusCode}`));
        return;
      }

      const tlsSocket = tls.connect(
        {
          socket: proxySocket,
          servername: targetHost,
          rejectUnauthorized: false,
          ...tlsOptions,
        },
        () => {
          clearTimeout(timeout);
          resolve(tlsSocket);
        },
      );

      tlsSocket.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    };

    proxySocket.on("data", onProxyData);
    proxySocket.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

async function requestThroughProxyHttp2(opts: {
  proxyPort: number;
  targetHost: string;
  targetPort: number;
  path: string;
  headers?: http2.OutgoingHttpHeaders;
  auth?: string;
}): Promise<{ statusCode: number; headers: http2.IncomingHttpHeaders; body: string; clientAlpn: string | false }> {
  const tlsSocket = await connectThroughProxyTls(
    opts.proxyPort,
    opts.targetHost,
    opts.targetPort,
    opts.auth,
    { ALPNProtocols: ["h2", "http/1.1"] },
  );

  const authority = `https://${opts.targetHost}:${opts.targetPort}`;
  const session = http2.connect(authority, {
    createConnection: () => tlsSocket,
  });

  return new Promise((resolve, reject) => {
    const req = session.request({
      ":method": "GET",
      ":path": opts.path,
      ...(opts.headers ?? {}),
    });

    let responseHeaders: http2.IncomingHttpHeaders = {};
    const chunks: Buffer[] = [];

    req.on("response", (headers) => {
      responseHeaders = headers;
    });
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const statusCode = typeof responseHeaders[":status"] === "number"
        ? responseHeaders[":status"]
        : parseInt(String(responseHeaders[":status"] ?? "0"), 10);
      session.close();
      resolve({
        statusCode,
        headers: responseHeaders,
        body: Buffer.concat(chunks).toString("utf-8"),
        clientAlpn: (session.socket as tls.TLSSocket).alpnProtocol,
      });
    });
    req.on("error", (err) => {
      session.destroy();
      reject(err);
    });
    session.on("error", reject);
    req.end();
  });
}

/**
 * Make a request through the proxy using raw sockets.
 * Returns the response body.
 */
function requestThroughProxy(
  proxyPort: number,
  targetHost: string,
  targetPort: number,
  requestLines: string,
  proxyAuth?: string,
  caCertPem?: string,
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Request timeout")), 10000);

    const proxySocket = net.connect(proxyPort, "127.0.0.1", () => {
      // Send CONNECT
      let connectLine = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
      if (proxyAuth) {
        connectLine += `Proxy-Authorization: Basic ${Buffer.from(proxyAuth).toString("base64")}\r\n`;
      }
      connectLine += "\r\n";
      proxySocket.write(connectLine);
    });

    let established = false;
    let dataBuf = Buffer.alloc(0);

    proxySocket.on("data", (chunk) => {
      dataBuf = Buffer.concat([dataBuf, chunk]);

      if (!established) {
        const str = dataBuf.toString();
        if (str.includes("\r\n\r\n")) {
          // Check CONNECT response
          const statusLine = str.split("\r\n")[0];
          const statusCode = parseInt(statusLine.split(" ")[1], 10);

          if (statusCode !== 200) {
            clearTimeout(timeout);
            resolve({ statusCode, headers: {}, body: str });
            proxySocket.destroy();
            return;
          }

          established = true;
          dataBuf = Buffer.alloc(0);

          // Upgrade to TLS
          const tlsSocket = tls.connect(
            {
              socket: proxySocket,
              servername: targetHost,
              // Accept our test CA certs
              rejectUnauthorized: false,
            },
            () => {
              // Send the actual HTTP request over TLS
              tlsSocket.write(requestLines);
            },
          );

          tlsSocket.on("data", (data: Buffer) => {
            dataBuf = Buffer.concat([dataBuf, data]);
          });

          tlsSocket.on("end", () => {
            clearTimeout(timeout);
            const responseStr = dataBuf.toString();
            const parsed = parseRawHttpResponse(responseStr);
            resolve(parsed);
          });

          tlsSocket.on("error", (err) => {
            clearTimeout(timeout);
            reject(err);
          });
        }
      }
    });

    proxySocket.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    proxySocket.on("close", () => {
      clearTimeout(timeout);
      if (!established) {
        const str = dataBuf.toString();
        if (str) {
          const statusLine = str.split("\r\n")[0];
          const statusCode = parseInt(statusLine.split(" ")[1], 10);
          resolve({ statusCode, headers: {}, body: str });
        } else {
          reject(new Error("Connection closed without response"));
        }
      }
    });
  });
}

function parseRawHttpResponse(raw: string): { statusCode: number; headers: Record<string, string>; body: string } {
  const headerEnd = raw.indexOf("\r\n\r\n");
  const headerSection = headerEnd !== -1 ? raw.slice(0, headerEnd) : raw;
  let body = headerEnd !== -1 ? raw.slice(headerEnd + 4) : "";

  const lines = headerSection.split("\r\n");
  const statusLine = lines[0] || "";
  const statusCode = parseInt(statusLine.split(" ")[1] || "0", 10);

  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon !== -1) {
      headers[lines[i].slice(0, colon).trim().toLowerCase()] = lines[i].slice(colon + 1).trim();
    }
  }

  // Decode chunked transfer encoding if present
  if (headers["transfer-encoding"]?.includes("chunked") && body) {
    body = decodeChunkedBody(body);
  }

  return { statusCode, headers, body };
}

function decodeChunkedBody(raw: string): string {
  const parts: string[] = [];
  let remaining = raw;

  while (remaining.length > 0) {
    const lineEnd = remaining.indexOf("\r\n");
    if (lineEnd === -1) break;

    const sizeStr = remaining.slice(0, lineEnd).trim();
    const chunkSize = parseInt(sizeStr, 16);
    if (isNaN(chunkSize) || chunkSize === 0) break;

    const chunkStart = lineEnd + 2;
    parts.push(remaining.slice(chunkStart, chunkStart + chunkSize));
    remaining = remaining.slice(chunkStart + chunkSize + 2); // +2 for trailing \r\n
  }

  return parts.join("");
}

describe("Proxy E2E", () => {
  let proxy: ProxyServer;
  let proxyPort: number;
  let mockTarget: Awaited<ReturnType<typeof createMockHttpsServer>>;
  let ca: ReturnType<typeof createTestCA>;

  beforeAll(async () => {
    // Allow time for cert generation
    // Set up env secrets
    process.env.TEST_API_KEY = "sk-test-secret-123";
    process.env.OTHER_KEY = "other-secret-value";

    ca = createTestCA();

    // Create mock HTTPS target that reports the headers it receives
    mockTarget = await createMockHttpsServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          path: req.url,
          method: req.method,
          headers: req.headers,
        }),
      );
    });

    const certManager = new CertManager(ca.caCertPem, ca.caKeyPem);
    const cache = new SecretCache(300_000);
    const providers = new Map([["env", new EnvProvider()]]);
    const resolver = new SecretResolver(providers, cache);
    const auditLogger = new AuditLogger({ enabled: false });
    const logger = createMockLogger();

    const config: ServerConfig = {
      proxy: {
        port: 0,
        host: "127.0.0.1",
        tcpNoDelay: true,
        connectionPool: {
          enabled: true,
          idleTtlMs: 30_000,
          maxPerHost: 6,
          maxTotal: 256,
          cleanupIntervalMs: 10_000,
        },
      },
      ca: { certFile: "", keyFile: "" },
      secrets: {
        TEST_API_KEY: {
          provider: "env",
          path: "TEST_API_KEY",
          allowedDomains: ["127.0.0.1"],
        },
        OTHER_KEY: {
          provider: "env",
          path: "OTHER_KEY",
          allowedDomains: ["other-domain.com"],
        },
      },
      cache: { enabled: true, defaultTtlSeconds: 300 },
      auth: {
        enabled: true,
        clients: [
          { machineId: "test-machine", token: "test-token-123" },
        ],
      },
      bypass: { domains: [] },
      aws: { region: "us-east-1" },
      logging: { level: "silent", audit: { enabled: false }, latency: { enabled: false } },
    };

    const authenticator = new Authenticator({ enabled: config.auth.enabled }, new ConfigAuthBackend(config.auth));

    proxy = new ProxyServer({
      config,
      certManager,
      resolver,
      auditLogger,
      authenticator,
      logger,
      targetTlsOptions: { rejectUnauthorized: false },
    });

    await proxy.start();
    proxyPort = proxy.address!.port;
  });

  afterAll(async () => {
    await proxy.stop();
    mockTarget.server.close();
    delete process.env.TEST_API_KEY;
    delete process.env.OTHER_KEY;
  });

  it("should inject secrets into matching domain requests", async () => {
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer __TEST_API_KEY__\r\nConnection: close\r\n\r\n`,
      "test-machine:test-token-123",
    );

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.headers.authorization).toBe("Bearer sk-test-secret-123");
  });

  it("should reject injection on domain mismatch (exfiltration prevention)", async () => {
    // OTHER_KEY only allows "other-domain.com", not 127.0.0.1
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer __OTHER_KEY__\r\nConnection: close\r\n\r\n`,
      "test-machine:test-token-123",
    );

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    // Should NOT contain the secret — placeholder should be removed
    expect(body.headers.authorization).not.toContain("other-secret-value");
    expect(body.headers.authorization).not.toContain("__OTHER_KEY__");
  });

  it("should return 407 when no auth credentials provided", async () => {
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
      // No auth
    );

    expect(result.statusCode).toBe(407);
  });

  it("should return 407 when auth credentials are wrong", async () => {
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
      "test-machine:wrong-token",
    );

    expect(result.statusCode).toBe(407);
  });

  it("should handle requests with no placeholders as passthrough", async () => {
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer already-set\r\nConnection: close\r\n\r\n`,
      "test-machine:test-token-123",
    );

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.headers.authorization).toBe("Bearer already-set");
    expect(body.path).toBe("/health");
  });

  it("should handle malformed CONNECT request", async () => {
    const result = await new Promise<{ statusCode: number }>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      const sock = net.connect(proxyPort, "127.0.0.1", () => {
        const auth = Buffer.from("test-machine:test-token-123").toString("base64");
        sock.write(`CONNECT invalid-no-port HTTP/1.1\r\nProxy-Authorization: Basic ${auth}\r\nHost: x\r\n\r\n`);
      });

      let buf = "";
      sock.on("data", (data) => {
        buf += data.toString();
        if (buf.includes("\r\n\r\n")) {
          clearTimeout(timeout);
          const statusCode = parseInt(buf.split(" ")[1], 10);
          resolve({ statusCode });
          sock.destroy();
        }
      });
      sock.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });

    expect(result.statusCode).toBe(400);
  });

  it("should handle POST with body", async () => {
    const body = JSON.stringify({ prompt: "hello world", key: "__TEST_API_KEY__" });
    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      mockTarget.port,
      `POST /v1/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${body.length}\r\nContent-Type: application/json\r\nAuthorization: Bearer __TEST_API_KEY__\r\nConnection: close\r\n\r\n${body}`,
      "test-machine:test-token-123",
    );

    expect(result.statusCode).toBe(200);
    const respBody = JSON.parse(result.body);
    // Header injection should work
    expect(respBody.headers.authorization).toBe("Bearer sk-test-secret-123");
    expect(respBody.method).toBe("POST");
  });
});

describe("Proxy H2 E2E", () => {
  let proxy: ProxyServer;
  let proxyPort: number;
  let h1Target: Awaited<ReturnType<typeof createMockHttpsServer>>;
  let h2Target: Awaited<ReturnType<typeof createMockHttp2Server>>;
  let ca: ReturnType<typeof createTestCA>;
  let logger: Logger;
  let upstreamHttp2Pool: UpstreamHttp2Pool;

  beforeAll(async () => {
    process.env.TEST_API_KEY = "sk-h2-secret-456";

    ca = createTestCA();
    logger = createMockLogger();
    upstreamHttp2Pool = new UpstreamHttp2Pool(logger, {
      idleTtlMs: 30_000,
      cleanupIntervalMs: 10_000,
      tcpNoDelay: true,
    });

    h1Target = await createMockHttpsServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        upstreamProtocol: "http/1.1",
        path: req.url,
        method: req.method,
        headers: req.headers,
      }));
    });

    h2Target = await createMockHttp2Server((stream, headers) => {
      const regularHeaders: Record<string, string> = {};
      for (const [name, value] of Object.entries(headers)) {
        if (name.startsWith(":")) continue;
        regularHeaders[name] = Array.isArray(value) ? value.join(", ") : String(value);
      }

      const body = JSON.stringify({
        upstreamProtocol: "h2",
        path: headers[":path"],
        method: headers[":method"],
        headers: regularHeaders,
      });

      stream.respond({
        ":status": 200,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body).toString(),
      });
      stream.end(body);
    });

    const certManager = new CertManager(ca.caCertPem, ca.caKeyPem);
    const cache = new SecretCache(300_000);
    const providers = new Map([["env", new EnvProvider()]]);
    const resolver = new SecretResolver(providers, cache);
    const auditLogger = new AuditLogger({ enabled: false });

    const config: ServerConfig = {
      proxy: {
        port: 0,
        host: "127.0.0.1",
        tcpNoDelay: true,
        connectionPool: {
          enabled: true,
          idleTtlMs: 30_000,
          maxPerHost: 6,
          maxTotal: 256,
          cleanupIntervalMs: 10_000,
        },
      },
      ca: { certFile: "", keyFile: "" },
      secrets: {
        TEST_API_KEY: {
          provider: "env",
          path: "TEST_API_KEY",
          allowedDomains: ["127.0.0.1"],
        },
      },
      cache: { enabled: true, defaultTtlSeconds: 300 },
      auth: {
        enabled: true,
        clients: [{ machineId: "h2-machine", token: "h2-token-123" }],
      },
      bypass: { domains: [] },
      aws: { region: "us-east-1" },
      logging: { level: "silent", audit: { enabled: false }, latency: { enabled: false } },
    };

    const authenticator = new Authenticator({ enabled: config.auth.enabled }, new ConfigAuthBackend(config.auth));

    proxy = new ProxyServer({
      config,
      certManager,
      resolver,
      auditLogger,
      authenticator,
      logger,
      targetTlsOptions: { rejectUnauthorized: false },
      upstreamHttp2Pool,
    });

    await proxy.start();
    proxyPort = proxy.address!.port;
  });

  afterAll(async () => {
    await proxy.stop();
    upstreamHttp2Pool.close();
    h1Target.server.close();
    h2Target.server.close();
    delete process.env.TEST_API_KEY;
  });

  it("speaks client-facing h2 and uses upstream h2 when the origin supports it", async () => {
    vi.clearAllMocks();

    const result = await requestThroughProxyHttp2({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: h2Target.port,
      path: "/h2-upstream",
      headers: {
        authorization: "Bearer __TEST_API_KEY__",
      },
      auth: "h2-machine:h2-token-123",
    });

    expect(result.clientAlpn).toBe("h2");
    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.upstreamProtocol).toBe("h2");
    expect(body.headers.authorization).toBe("Bearer sk-h2-secret-456");

    const mitmLogs = ((logger.debug as unknown as { mock: { calls: Array<[Record<string, unknown>, string]> } }).mock.calls)
      .filter(([, message]) => message === "MITM request processed")
      .map(([fields]) => fields);
    expect(mitmLogs.some((fields) => fields.clientProtocol === "h2" && fields.upstreamProtocol === "h2")).toBe(true);
  });

  it("falls back to upstream http/1.1 when the origin does not negotiate h2", async () => {
    vi.clearAllMocks();

    const result = await requestThroughProxyHttp2({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: h1Target.port,
      path: "/h1-fallback",
      headers: {
        authorization: "Bearer __TEST_API_KEY__",
      },
      auth: "h2-machine:h2-token-123",
    });

    expect(result.clientAlpn).toBe("h2");
    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.upstreamProtocol).toBe("http/1.1");
    expect(body.headers.authorization).toBe("Bearer sk-h2-secret-456");

    const mitmLogs = ((logger.debug as unknown as { mock: { calls: Array<[Record<string, unknown>, string]> } }).mock.calls)
      .filter(([, message]) => message === "MITM request processed")
      .map(([fields]) => fields);
    expect(mitmLogs.some((fields) => fields.clientProtocol === "h2" && fields.upstreamProtocol === "http/1.1")).toBe(true);
  });

  it("can use upstream h2 even for an http/1.1 client", async () => {
    vi.clearAllMocks();

    const result = await requestThroughProxy(
      proxyPort,
      "127.0.0.1",
      h2Target.port,
      "GET /h1-client-h2-origin HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer __TEST_API_KEY__\r\nConnection: close\r\n\r\n",
      "h2-machine:h2-token-123",
    );

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.upstreamProtocol).toBe("h2");
    expect(body.headers.authorization).toBe("Bearer sk-h2-secret-456");

    const mitmLogs = ((logger.debug as unknown as { mock: { calls: Array<[Record<string, unknown>, string]> } }).mock.calls)
      .filter(([, message]) => message === "MITM request processed")
      .map(([fields]) => fields);
    expect(mitmLogs.some((fields) => fields.clientProtocol === "http/1.1" && fields.upstreamProtocol === "h2")).toBe(true);
  });
});
