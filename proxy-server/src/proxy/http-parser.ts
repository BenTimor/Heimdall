import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";

export interface ParsedHttpRequest {
  method: string;
  path: string;
  httpVersion: string;
  headers: Record<string, string>;
  body: Buffer;
}

type ReadableSocket = Socket | TLSSocket;

/**
 * Buffered reader over a socket stream. Accumulates data into an internal
 * buffer and provides synchronous-style read helpers that await new data
 * only when the buffer doesn't have enough.
 */
class SocketReader {
  private socket: ReadableSocket;
  private buf = Buffer.alloc(0);
  private ended = false;
  private waiters: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  private error: Error | null = null;

  constructor(socket: ReadableSocket) {
    this.socket = socket;

    socket.on("data", (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      // Wake any waiters
      this.flushWaiters();
    });

    socket.on("end", () => {
      this.ended = true;
      this.flushWaiters();
    });

    socket.on("close", () => {
      this.ended = true;
      this.flushWaiters();
    });

    socket.on("error", (err) => {
      this.error = err;
      this.ended = true;
      this.flushWaiters();
    });
  }

  private flushWaiters() {
    const toNotify = this.waiters.splice(0);
    for (const w of toNotify) {
      if (this.error) {
        w.reject(this.error);
      } else {
        w.resolve();
      }
    }
  }

  /** Wait until the buffer has new data (or the socket ends/errors). */
  private waitForData(): Promise<void> {
    if (this.buf.length > 0 || this.ended || this.error) {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  /** Read until the buffer contains the given delimiter. Returns everything
   *  up to AND including the delimiter. Returns null if the socket ended first. */
  async readUntil(delimiter: Buffer): Promise<Buffer | null> {
    while (true) {
      const idx = this.buf.indexOf(delimiter);
      if (idx !== -1) {
        const end = idx + delimiter.length;
        const result = this.buf.subarray(0, end);
        this.buf = this.buf.subarray(end);
        return Buffer.from(result); // copy out
      }
      if (this.ended) return null;
      await this.waitForData();
    }
  }

  /** Read exactly N bytes. Returns null if the socket closed before we got enough. */
  async readExact(n: number): Promise<Buffer | null> {
    while (this.buf.length < n) {
      if (this.ended) return null;
      await this.waitForData();
    }
    const result = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return Buffer.from(result);
  }

  /** Read a single CRLF-terminated line. Returns the line WITHOUT the CRLF. */
  async readLine(): Promise<string | null> {
    const CRLF = Buffer.from("\r\n");
    const data = await this.readUntil(CRLF);
    if (!data) return null;
    return data.subarray(0, data.length - 2).toString("utf-8");
  }

  get isEnded(): boolean {
    return this.ended && this.buf.length === 0;
  }

  /** Detach from the socket (stop listening). */
  detach() {
    this.socket.removeAllListeners("data");
    this.socket.removeAllListeners("end");
    this.socket.removeAllListeners("close");
    this.socket.removeAllListeners("error");
  }
}

/**
 * Parse an HTTP/1.1 request from a socket stream.
 * Returns the parsed request including the full body.
 */
export async function parseHttpRequest(
  socket: ReadableSocket,
): Promise<ParsedHttpRequest | null> {
  const reader = new SocketReader(socket);

  try {
    // Read headers (until \r\n\r\n)
    const HEADER_END = Buffer.from("\r\n\r\n");
    const headerBuf = await reader.readUntil(HEADER_END);
    if (!headerBuf) return null;

    const headerStr = headerBuf.toString("utf-8");
    const lines = headerStr.split("\r\n");

    // Request line
    const requestLine = lines[0];
    if (!requestLine) return null;

    const spaceIdx1 = requestLine.indexOf(" ");
    const spaceIdx2 = requestLine.indexOf(" ", spaceIdx1 + 1);
    if (spaceIdx1 === -1 || spaceIdx2 === -1) return null;

    const method = requestLine.slice(0, spaceIdx1);
    const path = requestLine.slice(spaceIdx1 + 1, spaceIdx2);
    const httpVersion = requestLine.slice(spaceIdx2 + 1);

    // Parse headers
    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line === "") break;
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const name = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      headers[name] = value;
    }

    // Read body
    let body: Buffer = Buffer.alloc(0);
    const transferEncoding = headers["transfer-encoding"];
    const contentLength = headers["content-length"];

    if (transferEncoding?.toLowerCase().includes("chunked")) {
      body = await readChunkedBody(reader) as Buffer;
    } else if (contentLength) {
      const len = parseInt(contentLength, 10);
      if (len > 0) {
        const data = await reader.readExact(len);
        if (data) body = data as Buffer;
      }
    }

    return { method, path, httpVersion, headers, body };
  } finally {
    reader.detach();
  }
}

async function readChunkedBody(reader: SocketReader): Promise<Buffer> {
  const chunks: Buffer[] = [];

  while (true) {
    const sizeLine = await reader.readLine();
    if (sizeLine === null) break;

    const chunkSize = parseInt(sizeLine.trim(), 16);
    if (isNaN(chunkSize) || chunkSize === 0) {
      // Read trailing CRLF after 0-length chunk
      await reader.readLine();
      break;
    }

    const chunkData = await reader.readExact(chunkSize);
    if (chunkData) chunks.push(chunkData);

    // Read trailing CRLF after chunk data
    await reader.readLine();
  }

  return Buffer.concat(chunks);
}

/**
 * Serialize an HTTP request back into raw bytes for forwarding.
 */
export function serializeHttpRequest(req: ParsedHttpRequest): Buffer {
  const lines: string[] = [];
  lines.push(`${req.method} ${req.path} ${req.httpVersion}`);

  for (const [name, value] of Object.entries(req.headers)) {
    lines.push(`${name}: ${value}`);
  }
  lines.push("");
  lines.push("");

  const header = lines.join("\r\n");
  if (req.body.length > 0) {
    return Buffer.concat([Buffer.from(header), req.body]);
  }
  return Buffer.from(header);
}

/**
 * Check if the connection should be kept alive based on HTTP version and headers.
 */
export function isKeepAlive(httpVersion: string, headers: Record<string, string>): boolean {
  const connection = headers["connection"]?.toLowerCase();
  if (connection === "close") return false;
  if (connection === "keep-alive") return true;
  return httpVersion === "HTTP/1.1";
}
