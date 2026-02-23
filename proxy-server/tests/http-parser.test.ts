import { describe, it, expect, afterEach } from "vitest";
import * as net from "node:net";
import { parseHttpRequest, serializeHttpRequest, isKeepAlive } from "../src/proxy/http-parser.js";
import type { ParsedHttpRequest } from "../src/proxy/http-parser.js";

const activeSockets: net.Socket[] = [];
const activeServers: net.Server[] = [];

afterEach(() => {
  for (const s of activeSockets) {
    if (!s.destroyed) s.destroy();
  }
  activeSockets.length = 0;
  for (const s of activeServers) {
    s.close();
  }
  activeServers.length = 0;
});

describe("parseHttpRequest", () => {
  it("should parse a simple GET request", async () => {
    const { reader, writer } = await createStreamPair();

    writer.write("GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer __KEY__\r\n\r\n");

    const req = await parseHttpRequest(reader);
    expect(req).not.toBeNull();
    expect(req!.method).toBe("GET");
    expect(req!.path).toBe("/v1/models");
    expect(req!.httpVersion).toBe("HTTP/1.1");
    expect(req!.headers["host"]).toBe("api.openai.com");
    expect(req!.headers["authorization"]).toBe("Bearer __KEY__");
    expect(req!.body.length).toBe(0);
  });

  it("should parse a POST request with Content-Length body", async () => {
    const { reader, writer } = await createStreamPair();
    const body = '{"model":"gpt-4"}';

    writer.write(
      `POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
    );

    const req = await parseHttpRequest(reader);
    expect(req).not.toBeNull();
    expect(req!.method).toBe("POST");
    expect(req!.body.toString()).toBe(body);
  });

  it("should parse chunked transfer-encoding", async () => {
    const { reader, writer } = await createStreamPair();

    writer.write(
      "POST /api HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );

    const req = await parseHttpRequest(reader);
    expect(req).not.toBeNull();
    expect(req!.body.toString()).toBe("hello world");
  });

  it("should return null when socket closes with no data", async () => {
    const { reader, writer } = await createStreamPair();
    writer.end();

    const req = await parseHttpRequest(reader);
    expect(req).toBeNull();
  });

  it("should handle multiple sequential requests (keep-alive)", async () => {
    const { reader, writer } = await createStreamPair();

    // Send first request
    writer.write("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const req1 = await parseHttpRequest(reader);
    expect(req1).not.toBeNull();
    expect(req1!.path).toBe("/first");

    // Send second request on same socket
    writer.write("GET /second HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    const req2 = await parseHttpRequest(reader);
    expect(req2).not.toBeNull();
    expect(req2!.path).toBe("/second");
  });
});

describe("serializeHttpRequest", () => {
  it("should serialize a request back to wire format", () => {
    const req: ParsedHttpRequest = {
      method: "GET",
      path: "/v1/models",
      httpVersion: "HTTP/1.1",
      headers: {
        host: "api.openai.com",
        authorization: "Bearer sk-test",
      },
      body: Buffer.alloc(0),
    };

    const buf = serializeHttpRequest(req);
    const str = buf.toString();
    expect(str).toContain("GET /v1/models HTTP/1.1\r\n");
    expect(str).toContain("host: api.openai.com\r\n");
    expect(str).toContain("authorization: Bearer sk-test\r\n");
    expect(str).toContain("\r\n\r\n");
  });

  it("should include body in serialized output", () => {
    const body = Buffer.from("test body");
    const req: ParsedHttpRequest = {
      method: "POST",
      path: "/api",
      httpVersion: "HTTP/1.1",
      headers: { "content-length": "9" },
      body,
    };

    const buf = serializeHttpRequest(req);
    expect(buf.toString()).toContain("test body");
  });
});

describe("isKeepAlive", () => {
  it("should default to keep-alive for HTTP/1.1", () => {
    expect(isKeepAlive("HTTP/1.1", {})).toBe(true);
  });

  it("should default to close for HTTP/1.0", () => {
    expect(isKeepAlive("HTTP/1.0", {})).toBe(false);
  });

  it("should respect Connection: close header", () => {
    expect(isKeepAlive("HTTP/1.1", { connection: "close" })).toBe(false);
  });

  it("should respect Connection: keep-alive header", () => {
    expect(isKeepAlive("HTTP/1.0", { connection: "keep-alive" })).toBe(true);
  });
});

/**
 * Create a pair of connected sockets for testing.
 * Returns { reader, writer } where writer writes to reader.
 */
function createStreamPair(): Promise<{ reader: net.Socket; writer: net.Socket }> {
  return new Promise((resolve) => {
    let writerSocket: net.Socket;
    const server = net.createServer((readerSocket) => {
      activeServers.push(server);
      activeSockets.push(readerSocket, writerSocket);
      resolve({ reader: readerSocket, writer: writerSocket });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      writerSocket = net.connect(addr.port, "127.0.0.1");
    });
  });
}
