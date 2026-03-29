import { Duplex } from "node:stream";
import type { Socket } from "node:net";
import { encodeFrame, FrameType } from "./protocol.js";

/**
 * VirtualSocket represents one multiplexed connection over the tunnel.
 * Writes to VirtualSocket become DATA frames sent to the agent.
 * DATA frames from the agent are pushed as readable data.
 * Destroying sends a CLOSE frame.
 */
export class VirtualSocket extends Duplex {
  readonly connId: number;
  private agentSocket: Socket;
  private _ended = false;

  constructor(connId: number, agentSocket: Socket) {
    super();
    this.connId = connId;
    this.agentSocket = agentSocket;
  }

  /** Called when proxy code writes data into this socket (going to the agent). */
  _write(chunk: Buffer, _encoding: string, callback: (error?: Error | null) => void): void {
    if (this._ended) {
      callback(new Error("VirtualSocket has ended"));
      return;
    }
    if (this.agentSocket.destroyed) {
      callback(new Error("Tunnel agent socket destroyed"));
      return;
    }
    const frame = encodeFrame(this.connId, FrameType.DATA, chunk);
    this.agentSocket.write(frame, callback);
  }

  _read(): void {
    // Data is pushed externally via pushData()
  }

  /** Push data received from agent DATA frame into the readable side. */
  pushData(data: Buffer): void {
    if (!this._ended) {
      this.push(data);
    }
  }

  /** Signal end-of-stream on the readable side. */
  pushEnd(): void {
    if (!this._ended) {
      this.push(null);
    }
  }

  _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    if (!this._ended) {
      this._ended = true;
      // Send CLOSE frame to agent (best-effort)
      if (!this.agentSocket.destroyed) {
        this.agentSocket.write(encodeFrame(this.connId, FrameType.CLOSE), () => {
          callback(error);
        });
        return;
      }
    }
    callback(error);
  }
}

export interface AgentSession {
  machineId: string;
  socket: Socket;
  activeConnections: Map<number, VirtualSocket>;
  lastHeartbeat: number;
}

export class SessionManager {
  private sessions = new Map<string, AgentSession>();

  register(machineId: string, socket: Socket): AgentSession {
    // If there's an existing session for this machineId, clean it up
    const existing = this.sessions.get(machineId);
    if (existing) {
      this.destroySession(machineId);
    }

    const session: AgentSession = {
      machineId,
      socket,
      activeConnections: new Map(),
      lastHeartbeat: Date.now(),
    };
    this.sessions.set(machineId, session);
    return session;
  }

  get(machineId: string): AgentSession | undefined {
    return this.sessions.get(machineId);
  }

  remove(machineId: string): void {
    this.destroySession(machineId);
  }

  /** Destroy all VirtualSockets for a session and remove it. */
  private destroySession(machineId: string): void {
    const session = this.sessions.get(machineId);
    if (!session) return;

    for (const vs of session.activeConnections.values()) {
      if (!vs.destroyed) {
        vs.destroy();
      }
    }
    session.activeConnections.clear();
    this.sessions.delete(machineId);
  }

  get size(): number {
    return this.sessions.size;
  }

  allSessions(): IterableIterator<AgentSession> {
    return this.sessions.values();
  }
}
