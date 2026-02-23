import { describe, it, expect, vi, afterEach } from "vitest";
import * as net from "node:net";
import { handlePassthrough } from "../src/proxy/passthrough.js";
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
    level: "info",
  } as unknown as Logger;
}

describe("handlePassthrough", () => {
  const servers: net.Server[] = [];

  afterEach(() => {
    for (const s of servers) {
      s.close();
    }
    servers.length = 0;
  });

  it("should pipe data bidirectionally between client and target", async () => {
    const logger = createMockLogger();

    // Create a mock target server that echoes data back
    const targetServer = net.createServer((socket) => {
      socket.on("data", (data) => {
        socket.write(`echo:${data.toString()}`);
      });
    });
    servers.push(targetServer);

    await new Promise<void>((resolve) => {
      targetServer.listen(0, "127.0.0.1", resolve);
    });
    const targetAddr = targetServer.address() as net.AddressInfo;

    // Create a pair of connected sockets to simulate client
    const { clientSocket, proxySocket } = await createSocketPair();

    handlePassthrough(proxySocket, "127.0.0.1", targetAddr.port, logger);

    // Wait for the 200 Connection Established
    const established = await readFromSocket(clientSocket);
    expect(established).toContain("200 Connection Established");

    // Send data through the tunnel
    clientSocket.write("hello");
    const response = await readFromSocket(clientSocket);
    expect(response).toBe("echo:hello");

    clientSocket.destroy();
    proxySocket.destroy();
  });

  it("should send 502 when target is unreachable", async () => {
    const logger = createMockLogger();
    const { clientSocket, proxySocket } = await createSocketPair();

    // Connect to a port that nothing listens on
    handlePassthrough(proxySocket, "127.0.0.1", 1, logger);

    const response = await readFromSocket(clientSocket);
    expect(response).toContain("502 Bad Gateway");

    clientSocket.destroy();
    proxySocket.destroy();
  });
});

function createSocketPair(): Promise<{ clientSocket: net.Socket; proxySocket: net.Socket }> {
  return new Promise((resolve) => {
    let client: net.Socket;
    const server = net.createServer((proxySocket) => {
      server.close();
      resolve({ clientSocket: client, proxySocket });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      client = net.connect(addr.port, "127.0.0.1");
    });
  });
}

function readFromSocket(socket: net.Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("Timeout reading from socket"));
    }, 5000);

    const onData = (data: Buffer) => {
      cleanup();
      resolve(data.toString());
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
    };

    socket.once("data", onData);
    socket.once("error", onError);
  });
}
