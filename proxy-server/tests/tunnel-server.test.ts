import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import * as tls from "node:tls";
import * as net from "node:net";
import forge from "node-forge";
import { TunnelServer } from "../src/tunnel/tunnel-server.js";
import { encodeFrame, FrameType, FrameDecoder } from "../src/tunnel/protocol.js";
import { Authenticator } from "../src/auth/authenticator.js";
import { ConfigAuthBackend } from "../src/auth/config-backend.js";
import type { ProxyServer } from "../src/proxy/server.js";
import type { TunnelConfig } from "../src/config/schema.js";
import type { Logger } from "../src/utils/logger.js";

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

function createSelfSignedCert(): { cert: string; key: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
  cert.setSubject([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setIssuer([{ name: "commonName", value: "127.0.0.1" }]);
  cert.setExtensions([
    { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

function connectToTunnel(
  port: number,
  ca: string,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: "127.0.0.1", port, rejectUnauthorized: false },
      () => resolve(socket),
    );
    socket.on("error", reject);
  });
}

describe("TunnelServer", () => {
  let tunnelServer: TunnelServer;
  let tunnelPort: number;
  let tlsCert: ReturnType<typeof createSelfSignedCert>;
  let handleTunnelConnectionMock: ReturnType<typeof vi.fn>;
  let logger: Logger;

  beforeAll(async () => {
    tlsCert = createSelfSignedCert();
    logger = createMockLogger();
    handleTunnelConnectionMock = vi.fn();
    const getSecretDomainsMock = vi.fn().mockReturnValue(["api.openai.com", "*.anthropic.com"]);

    const tunnelConfig: TunnelConfig = {
      enabled: true,
      port: 0,
      host: "127.0.0.1",
      tls: { certFile: "", keyFile: "" },
      heartbeatIntervalMs: 60000, // long so it doesn't fire during tests
      heartbeatTimeoutMs: 120000,
    };

    const authConfig = {
      enabled: true,
      clients: [{ machineId: "agent-1", token: "secret-token" }],
    };
    const authenticator = new Authenticator({ enabled: true }, new ConfigAuthBackend(authConfig));

    const mockProxy = {
      handleTunnelConnection: handleTunnelConnectionMock,
      getSecretDomains: getSecretDomainsMock,
    } as unknown as ProxyServer;

    tunnelServer = new TunnelServer({
      tunnelConfig,
      authenticator,
      proxyServer: mockProxy,
      logger,
      tlsOptions: { cert: tlsCert.cert, key: tlsCert.key },
    });

    await tunnelServer.start();
    tunnelPort = tunnelServer.address!.port;
  });

  afterAll(async () => {
    await tunnelServer.stop();
  });

  beforeEach(() => {
    handleTunnelConnectionMock.mockReset();
  });

  it("authenticates a valid agent", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    const responsePromise = new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", (chunk: Buffer) => {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_OK) {
            clearTimeout(timeout);
            resolve();
          } else if (frame.type === FrameType.AUTH_FAIL) {
            clearTimeout(timeout);
            reject(new Error("AUTH_FAIL: " + frame.payload.toString()));
          }
        }
      });
    });

    socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:secret-token")));
    await responsePromise;
    socket.destroy();
  });

  it("rejects invalid credentials", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    const responsePromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", (chunk: Buffer) => {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_FAIL) {
            clearTimeout(timeout);
            resolve(frame.payload.toString());
          }
        }
      });
    });

    socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:wrong-token")));
    const reason = await responsePromise;
    expect(reason).toContain("Invalid token");
  });

  it("rejects non-AUTH frame before authentication", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);

    const closePromise = new Promise<void>((resolve) => {
      socket.on("close", () => resolve());
    });

    // Send DATA before AUTH
    socket.write(encodeFrame(1, FrameType.DATA, Buffer.from("sneaky")));
    await closePromise;
  });

  it("responds to HEARTBEAT with HEARTBEAT_ACK", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    // Auth first
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_OK) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve();
          }
        }
      });
      socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:secret-token")));
    });

    // Send heartbeat
    const ackPromise = new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.HEARTBEAT_ACK) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve();
          }
        }
      });
    });

    socket.write(encodeFrame(0, FrameType.HEARTBEAT));
    await ackPromise;
    socket.destroy();
  });

  it("routes NEW_CONNECTION to ProxyServer.handleTunnelConnection", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    // Auth first
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_OK) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve();
          }
        }
      });
      socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:secret-token")));
    });

    // Send NEW_CONNECTION
    socket.write(encodeFrame(1, FrameType.NEW_CONNECTION, Buffer.from("api.openai.com:443")));

    // Wait for the mock to be called
    await vi.waitFor(() => {
      expect(handleTunnelConnectionMock).toHaveBeenCalledTimes(1);
    }, { timeout: 3000 });

    const [vs, host, port, machineId] = handleTunnelConnectionMock.mock.calls[0];
    expect(host).toBe("api.openai.com");
    expect(port).toBe(443);
    expect(machineId).toBe("agent-1");
    expect(vs.connId).toBe(1);

    socket.destroy();
  });

  it("cleans up session on disconnect", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    // Auth first
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_OK) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve();
          }
        }
      });
      socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:secret-token")));
    });

    // Disconnect
    socket.destroy();

    // Wait for cleanup
    await new Promise((r) => setTimeout(r, 100));
    // The session count should reflect the removal (may be 0 since agent-1 was the only session)
    // Since we can't easily inspect sessionCount from outside, check via the logger
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ machineId: "agent-1" }),
      "Tunnel agent disconnected",
    );
  });

  it("responds to DOMAIN_LIST_REQUEST with domain list", async () => {
    const socket = await connectToTunnel(tunnelPort, tlsCert.cert);
    const decoder = new FrameDecoder();

    // Auth first
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.AUTH_OK) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve();
          }
        }
      });
      socket.write(encodeFrame(0, FrameType.AUTH, Buffer.from("agent-1:secret-token")));
    });

    // Send DOMAIN_LIST_REQUEST
    const domainListPromise = new Promise<string[]>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("timeout")), 5000);
      socket.on("data", function handler(chunk: Buffer) {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.DOMAIN_LIST_RESPONSE) {
            clearTimeout(timeout);
            socket.removeListener("data", handler);
            resolve(JSON.parse(frame.payload.toString()));
          }
        }
      });
    });

    socket.write(encodeFrame(0, FrameType.DOMAIN_LIST_REQUEST));
    const domains = await domainListPromise;
    expect(domains).toEqual(expect.arrayContaining(["api.openai.com", "*.anthropic.com"]));
    expect(domains).toHaveLength(2);
    socket.destroy();
  });
});
