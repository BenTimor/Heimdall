import type { Socket } from "node:net";
import * as net from "node:net";
import type { Logger } from "../utils/logger.js";

export interface PassthroughOptions {
  /** When true, skip sending "HTTP/1.1 200 Connection Established" (tunnel mode). */
  tunnelMode?: boolean;
}

export function handlePassthrough(
  clientSocket: Socket,
  targetHost: string,
  targetPort: number,
  logger: Logger,
  options?: PassthroughOptions,
): void {
  const targetSocket = net.connect(targetPort, targetHost, () => {
    if (!options?.tunnelMode) {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    }
    targetSocket.pipe(clientSocket);
    clientSocket.pipe(targetSocket);
  });

  targetSocket.on("error", (err) => {
    logger.warn({ err, target: `${targetHost}:${targetPort}` }, "Target connection error (passthrough)");
    if (!clientSocket.destroyed) {
      if (options?.tunnelMode) {
        clientSocket.destroy();
      } else {
        clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      }
    }
  });

  clientSocket.on("error", (err) => {
    logger.debug({ err }, "Client socket error (passthrough)");
    if (!targetSocket.destroyed) {
      targetSocket.destroy();
    }
  });

  clientSocket.on("close", () => {
    if (!targetSocket.destroyed) {
      targetSocket.destroy();
    }
  });

  targetSocket.on("close", () => {
    if (!clientSocket.destroyed) {
      clientSocket.destroy();
    }
  });
}
