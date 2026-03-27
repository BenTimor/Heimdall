import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { Writable } from "node:stream";

export interface ParsedHttpRequest {
  method: string;
  path: string;
  httpVersion: string;
  headers: Record<string, string>;
  body: Buffer;
}

export type BodyInfo =
  | { type: "content-length"; length: number }
  | { type: "chunked" }
  | { type: "none" };

export interface ParsedHttpHeaders {
  method: string;
  path: string;
  httpVersion: string;
  headers: Record<string, string>;
  bodyInfo: BodyInfo;
  reader: SocketReader;
}

type ReadableSocket = Socket | TLSSocket;

/**
 * Buffered reader over a socket stream. Accumulates data into an internal
 * buffer and provides synchronous-style read helpers that await new data
 * only when the buffer doesn't have enough.
 */
export class SocketReader {
  private socket: ReadableSocket;
  private buf = Buffer.alloc(0);
  private ended = false;
  private waiters: Array<{ resolve: () => void; reject: (err: Error) => void }> = [];
  private error: Error | null = null;

  // Store bound handler references so detach() removes only OUR listeners
  // (not error handlers registered by handleMitm or forwardToTarget).
  private onData: (chunk: Buffer) => void;
  private onEnd: () => void;
  private onClose: () => void;
  private onError: (err: Error) => void;

  constructor(socket: ReadableSocket) {
    this.socket = socket;

    this.onData = (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.flushWaiters();
    };
    this.onEnd = () => {
      this.ended = true;
      this.flushWaiters();
    };
    this.onClose = () => {
      this.ended = true;
      this.flushWaiters();
    };
    this.onError = (err: Error) => {
      this.error = err;
      this.ended = true;
      this.flushWaiters();
    };

    socket.on("data", this.onData);
    socket.on("end", this.onEnd);
    socket.on("close", this.onClose);
    socket.on("error", this.onError);
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

  /** Returns the buffered data beyond what's been consumed (bytes already
   *  read from the socket but not yet returned by readLine/readExact). */
  getResidual(): Buffer {
    return Buffer.from(this.buf);
  }

  /** Returns the underlying socket. */
  getSocket(): ReadableSocket {
    return this.socket;
  }

  /** Detach from the socket (stop listening).
   *  Only removes the listeners THIS reader attached — preserves error
   *  handlers registered by handleMitm / forwardToTarget. */
  detach() {
    this.socket.removeListener("data", this.onData);
    this.socket.removeListener("end", this.onEnd);
    this.socket.removeListener("close", this.onClose);
    this.socket.removeListener("error", this.onError);
  }
}

/**
 * Parse HTTP request headers from a socket stream, stopping after the header
 * section. Does NOT read the body — caller is responsible for streaming or
 * reading the body via the returned reader + bodyInfo.
 *
 * The caller must call reader.detach() when done with the socket.
 */
export async function parseHttpHeaders(
  socket: ReadableSocket,
): Promise<ParsedHttpHeaders | null> {
  const reader = new SocketReader(socket);

  // Read headers (until \r\n\r\n)
  const HEADER_END = Buffer.from("\r\n\r\n");
  const headerBuf = await reader.readUntil(HEADER_END);
  if (!headerBuf) {
    reader.detach();
    return null;
  }

  const headerStr = headerBuf.toString("utf-8");
  const lines = headerStr.split("\r\n");

  // Request line
  const requestLine = lines[0];
  if (!requestLine) {
    reader.detach();
    return null;
  }

  const spaceIdx1 = requestLine.indexOf(" ");
  const spaceIdx2 = requestLine.indexOf(" ", spaceIdx1 + 1);
  if (spaceIdx1 === -1 || spaceIdx2 === -1) {
    reader.detach();
    return null;
  }

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

  // Determine body info from headers
  const transferEncoding = headers["transfer-encoding"];
  const contentLength = headers["content-length"];

  let bodyInfo: BodyInfo;
  if (transferEncoding?.toLowerCase().includes("chunked")) {
    bodyInfo = { type: "chunked" };
  } else if (contentLength) {
    bodyInfo = { type: "content-length", length: parseInt(contentLength, 10) };
  } else {
    bodyInfo = { type: "none" };
  }

  return { method, path, httpVersion, headers, bodyInfo, reader };
}

/**
 * Stream the request body from a SocketReader to a destination Writable.
 *
 * First writes any residual bytes already buffered in the reader (beyond the
 * headers), then reads the remaining body bytes from the underlying socket.
 * Calls reader.detach() when done.
 */
export async function pipeBody(
  reader: SocketReader,
  bodyInfo: BodyInfo,
  dest: Writable,
): Promise<void> {
  if (bodyInfo.type === "none") {
    reader.detach();
    return;
  }

  if (bodyInfo.type === "content-length") {
    const residual = reader.getResidual();
    const totalLength = bodyInfo.length;

    if (totalLength <= 0) {
      reader.detach();
      return;
    }

    // Write residual bytes first (up to the total body length)
    const residualToWrite = residual.subarray(0, Math.min(residual.length, totalLength));
    if (residualToWrite.length > 0) {
      dest.write(residualToWrite);
    }

    const remaining = totalLength - residualToWrite.length;

    if (remaining > 0) {
      const socket = reader.getSocket();
      reader.detach();

      // Read exactly `remaining` bytes from the socket
      await new Promise<void>((resolve, reject) => {
        let bytesRead = 0;

        const onData = (chunk: Buffer) => {
          const needed = remaining - bytesRead;
          if (chunk.length <= needed) {
            dest.write(chunk);
            bytesRead += chunk.length;
          } else {
            // Write only the needed portion — but since we detached, there
            // shouldn't be a reader to put bytes back into.  This edge case
            // should not happen with well-formed content-length requests.
            dest.write(chunk.subarray(0, needed));
            bytesRead += needed;
          }
          if (bytesRead >= remaining) {
            cleanup();
            resolve();
          }
        };

        const onEnd = () => {
          cleanup();
          resolve();
        };

        const onError = (err: Error) => {
          cleanup();
          reject(err);
        };

        const cleanup = () => {
          socket.removeListener("data", onData);
          socket.removeListener("end", onEnd);
          socket.removeListener("close", onEnd);
          socket.removeListener("error", onError);
        };

        socket.on("data", onData);
        socket.on("end", onEnd);
        socket.on("close", onEnd);
        socket.on("error", onError);
      });
    } else {
      reader.detach();
    }

    return;
  }

  if (bodyInfo.type === "chunked") {
    // For chunked encoding, use the reader to parse chunks and forward them
    // in chunked format to the destination.
    while (true) {
      const sizeLine = await reader.readLine();
      if (sizeLine === null) break;

      const chunkSize = parseInt(sizeLine.trim(), 16);

      if (isNaN(chunkSize) || chunkSize === 0) {
        // Write the final chunk: "0\r\n\r\n"
        dest.write(`0\r\n\r\n`);
        // Consume trailing CRLF from the reader
        await reader.readLine();
        break;
      }

      const chunkData = await reader.readExact(chunkSize);
      // Consume trailing CRLF after chunk data
      await reader.readLine();

      // Write chunk in chunked encoding format
      dest.write(`${chunkSize.toString(16)}\r\n`);
      if (chunkData) {
        dest.write(chunkData);
      }
      dest.write("\r\n");
    }

    reader.detach();
    return;
  }
}

/**
 * Parse an HTTP/1.1 request from a socket stream.
 * Returns the parsed request including the full body.
 *
 * This is a backward-compatible wrapper around parseHttpHeaders that also
 * reads and buffers the full body.
 */
export async function parseHttpRequest(
  socket: ReadableSocket,
): Promise<ParsedHttpRequest | null> {
  const parsed = await parseHttpHeaders(socket);
  if (!parsed) return null;

  const { method, path, httpVersion, headers, bodyInfo, reader } = parsed;

  try {
    // Read body
    let body: Buffer = Buffer.alloc(0);

    if (bodyInfo.type === "chunked") {
      body = await readChunkedBody(reader) as Buffer;
    } else if (bodyInfo.type === "content-length") {
      const len = bodyInfo.length;
      if (len > 0) {
        // The reader may already have residual body bytes buffered.
        // readExact handles this correctly — it reads from the internal
        // buffer first, then awaits more data from the socket as needed.
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
 * Serialize just the request line + headers + trailing empty line (no body).
 */
export function serializeHttpHeaders(req: {
  method: string;
  path: string;
  httpVersion: string;
  headers: Record<string, string>;
}): Buffer {
  const lines: string[] = [];
  lines.push(`${req.method} ${req.path} ${req.httpVersion}`);

  for (const [name, value] of Object.entries(req.headers)) {
    lines.push(`${name}: ${value}`);
  }
  lines.push("");
  lines.push("");

  return Buffer.from(lines.join("\r\n"));
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
