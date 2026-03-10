import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import * as https from "node:https";
import * as http from "node:http";
import * as tls from "node:tls";
import * as net from "node:net";
import forge from "node-forge";
import { ProxyServer } from "../../src/proxy/server.js";
import { CertManager } from "../../src/proxy/cert-manager.js";
import { SecretResolver } from "../../src/secrets/resolver.js";
import { SecretCache } from "../../src/secrets/cache.js";
import { EnvProvider } from "../../src/secrets/env-provider.js";
import { AuditLogger } from "../../src/audit/audit-logger.js";
import type { ServerConfig } from "../../src/config/schema.js";
import type { Logger } from "../../src/utils/logger.js";

function createTestCA() {
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
  };
}

function createMockLogger(): Logger {
  return {
    info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(),
    fatal: vi.fn(), trace: vi.fn(), child: vi.fn().mockReturnThis(), level: "silent",
  } as unknown as Logger;
}

function createMockHttpsServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ server: https.Server; port: number }> {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "02";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  cert.setSubject([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setIssuer([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setExtensions([{ name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return new Promise((resolve) => {
    const server = https.createServer(
      { cert: forge.pki.certificateToPem(cert), key: forge.pki.privateKeyToPem(keys.privateKey) },
      handler,
    );
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      resolve({ server, port: addr.port });
    });
  });
}

/** Open a CONNECT tunnel, upgrade to TLS, send request, get response */
function proxyRequest(opts: {
  proxyPort: number;
  targetHost: string;
  targetPort: number;
  request: string;
  auth?: string;
}): Promise<{ connectStatus: number; httpStatus: number; body: string }> {
  const { proxyPort, targetHost, targetPort, request, auth } = opts;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Request timeout")), 8000);

    const sock = net.connect(proxyPort, "127.0.0.1", () => {
      let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
      if (auth) connectReq += `Proxy-Authorization: Basic ${Buffer.from(auth).toString("base64")}\r\n`;
      connectReq += "\r\n";
      sock.write(connectReq);
    });

    let phase = "connect" as "connect" | "tls";
    let connectBuf = "";
    let dataBuf = Buffer.alloc(0);

    sock.on("data", (chunk) => {
      if (phase !== "connect") return;
      connectBuf += chunk.toString();

      if (!connectBuf.includes("\r\n\r\n")) return;
      const connectStatus = parseInt(connectBuf.split(" ")[1], 10);

      if (connectStatus !== 200) {
        clearTimeout(timer);
        resolve({ connectStatus, httpStatus: 0, body: connectBuf });
        sock.destroy();
        return;
      }

      phase = "tls";
      const tlsSock = tls.connect({ socket: sock, servername: targetHost, rejectUnauthorized: false }, () => {
        tlsSock.write(request);
      });

      tlsSock.on("data", (d: Buffer) => { dataBuf = Buffer.concat([dataBuf, d]); });
      tlsSock.on("end", () => {
        clearTimeout(timer);
        const { statusCode, body } = parseHttpResponse(dataBuf.toString());
        resolve({ connectStatus: 200, httpStatus: statusCode, body });
      });
      tlsSock.on("error", (err) => { clearTimeout(timer); reject(err); });
    });

    sock.on("error", (err) => { clearTimeout(timer); reject(err); });
    sock.on("close", () => {
      clearTimeout(timer);
      if (phase === "connect" && connectBuf) {
        const s = parseInt(connectBuf.split(" ")[1], 10);
        resolve({ connectStatus: s, httpStatus: 0, body: connectBuf });
      }
    });
  });
}

function parseHttpResponse(raw: string): { statusCode: number; body: string } {
  const idx = raw.indexOf("\r\n\r\n");
  if (idx === -1) return { statusCode: 0, body: raw };
  const headerSection = raw.slice(0, idx);
  let body = raw.slice(idx + 4);
  const statusCode = parseInt(headerSection.split(" ")[1] || "0", 10);

  // Decode chunked
  if (headerSection.toLowerCase().includes("transfer-encoding: chunked")) {
    body = decodeChunked(body);
  }
  return { statusCode, body };
}

function decodeChunked(raw: string): string {
  const parts: string[] = [];
  let rest = raw;
  while (rest.length > 0) {
    const nl = rest.indexOf("\r\n");
    if (nl === -1) break;
    const size = parseInt(rest.slice(0, nl).trim(), 16);
    if (isNaN(size) || size === 0) break;
    parts.push(rest.slice(nl + 2, nl + 2 + size));
    rest = rest.slice(nl + 2 + size + 2);
  }
  return parts.join("");
}

const AUTH = "test-machine:test-token-123";

describe("Proxy Hardening", () => {
  let proxy: ProxyServer;
  let proxyPort: number;
  let mockTarget: Awaited<ReturnType<typeof createMockHttpsServer>>;

  beforeAll(async () => {
    process.env.TEST_API_KEY = "sk-hardening-test";

    const ca = createTestCA();
    mockTarget = await createMockHttpsServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const reqBody = Buffer.concat(chunks).toString();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          path: req.url,
          method: req.method,
          headers: req.headers,
          bodyLength: reqBody.length,
        }));
      });
    });

    const config: ServerConfig = {
      proxy: { port: 0, host: "127.0.0.1" },
      ca: { certFile: "", keyFile: "" },
      secrets: {
        TEST_API_KEY: { provider: "env", path: "TEST_API_KEY", allowedDomains: ["127.0.0.1"] },
      },
      cache: { enabled: true, defaultTtlSeconds: 300 },
      auth: { enabled: true, clients: [{ machineId: "test-machine", token: "test-token-123" }] },
      bypass: { domains: [] },
      aws: { region: "us-east-1" },
      logging: { level: "silent", audit: { enabled: false } },
    };

    proxy = new ProxyServer({
      config,
      certManager: new CertManager(ca.caCertPem, ca.caKeyPem),
      resolver: new SecretResolver(new Map([["env", new EnvProvider()]]), new SecretCache(300_000)),
      auditLogger: new AuditLogger({ enabled: false }),
      logger: createMockLogger(),
      targetTlsOptions: { rejectUnauthorized: false },
    });

    await proxy.start();
    proxyPort = proxy.address!.port;
  }, 30000);

  afterAll(async () => {
    await proxy.stop();
    mockTarget.server.close();
    delete process.env.TEST_API_KEY;
  });

  it("should handle POST with body streaming", async () => {
    const postBody = JSON.stringify({ message: "hello world", data: "x".repeat(500) });
    const result = await proxyRequest({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: mockTarget.port,
      request: `POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${postBody.length}\r\nContent-Type: application/json\r\nAuthorization: Bearer __TEST_API_KEY__\r\nConnection: close\r\n\r\n${postBody}`,
      auth: AUTH,
    });

    expect(result.httpStatus).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.method).toBe("POST");
    expect(body.bodyLength).toBe(postBody.length);
    expect(body.headers.authorization).toBe("Bearer sk-hardening-test");
  });

  it("should handle large body (10KB)", async () => {
    const largeBody = "X".repeat(10_000);
    const result = await proxyRequest({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: mockTarget.port,
      request: `POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${largeBody.length}\r\nConnection: close\r\n\r\n${largeBody}`,
      auth: AUTH,
    });

    expect(result.httpStatus).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.bodyLength).toBe(10_000);
  });

  it("should handle 5 concurrent requests", async () => {
    const promises = Array.from({ length: 5 }, (_, i) =>
      proxyRequest({
        proxyPort,
        targetHost: "127.0.0.1",
        targetPort: mockTarget.port,
        request: `GET /concurrent/${i} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer __TEST_API_KEY__\r\nConnection: close\r\n\r\n`,
        auth: AUTH,
      }),
    );

    const results = await Promise.all(promises);
    for (let i = 0; i < 5; i++) {
      expect(results[i].httpStatus).toBe(200);
      const body = JSON.parse(results[i].body);
      expect(body.path).toBe(`/concurrent/${i}`);
      expect(body.headers.authorization).toBe("Bearer sk-hardening-test");
    }
  });

  it("should return 407 when no auth credentials", async () => {
    const result = await proxyRequest({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: mockTarget.port,
      request: `GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
      // no auth
    });

    expect(result.connectStatus).toBe(407);
  });

  it("should return 502 when target connection fails", async () => {
    const result = await proxyRequest({
      proxyPort,
      targetHost: "127.0.0.1",
      targetPort: 59999, // nothing listens here
      request: `GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
      auth: AUTH,
    });

    expect(result.httpStatus).toBe(502);
  });

  it("should return 400 for malformed CONNECT", async () => {
    const result = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timeout")), 5000);
      const sock = net.connect(proxyPort, "127.0.0.1", () => {
        const authStr = Buffer.from(AUTH).toString("base64");
        sock.write(`CONNECT no-port HTTP/1.1\r\nProxy-Authorization: Basic ${authStr}\r\nHost: x\r\n\r\n`);
      });
      let buf = "";
      sock.on("data", (d) => {
        buf += d.toString();
        if (buf.includes("\r\n")) {
          clearTimeout(timer);
          resolve(parseInt(buf.split(" ")[1], 10));
          sock.destroy();
        }
      });
      sock.on("error", (err) => { clearTimeout(timer); reject(err); });
    });

    expect(result).toBe(400);
  });
});
