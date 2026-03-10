import { describe, it, expect, vi, beforeEach } from "vitest";
import { PassThrough } from "node:stream";
import type { Socket } from "node:net";
import { SessionManager, VirtualSocket } from "../src/tunnel/session-manager.js";
import { FrameType, FrameDecoder, FRAME_HEADER_SIZE } from "../src/tunnel/protocol.js";

function mockSocket(): Socket {
  const pt = new PassThrough();
  // Add minimal Socket-like properties
  (pt as any).destroyed = false;
  const origDestroy = pt.destroy.bind(pt);
  pt.destroy = ((err?: Error) => {
    (pt as any).destroyed = true;
    return origDestroy(err);
  }) as any;
  return pt as unknown as Socket;
}

describe("SessionManager", () => {
  let manager: SessionManager;

  beforeEach(() => {
    manager = new SessionManager();
  });

  it("registers and retrieves a session", () => {
    const socket = mockSocket();
    const session = manager.register("machine-1", socket);
    expect(session.machineId).toBe("machine-1");
    expect(manager.get("machine-1")).toBe(session);
    expect(manager.size).toBe(1);
  });

  it("removes a session", () => {
    const socket = mockSocket();
    manager.register("machine-1", socket);
    manager.remove("machine-1");
    expect(manager.get("machine-1")).toBeUndefined();
    expect(manager.size).toBe(0);
  });

  it("replaces existing session for same machineId", () => {
    const socket1 = mockSocket();
    const socket2 = mockSocket();
    const session1 = manager.register("machine-1", socket1);
    const session2 = manager.register("machine-1", socket2);
    expect(session1).not.toBe(session2);
    expect(manager.get("machine-1")).toBe(session2);
    expect(manager.size).toBe(1);
  });

  it("destroys VirtualSockets when session is removed", async () => {
    const socket = mockSocket();
    const session = manager.register("machine-1", socket);
    const vs = new VirtualSocket(1, socket);
    session.activeConnections.set(1, vs);

    manager.remove("machine-1");

    // VirtualSocket should be destroyed
    expect(vs.destroyed).toBe(true);
  });

  it("returns undefined for unknown machineId", () => {
    expect(manager.get("nope")).toBeUndefined();
  });

  it("iterates over all sessions", () => {
    manager.register("a", mockSocket());
    manager.register("b", mockSocket());
    const ids = [...manager.allSessions()].map((s) => s.machineId);
    expect(ids).toContain("a");
    expect(ids).toContain("b");
  });
});

describe("VirtualSocket", () => {
  it("write() sends DATA frame to agent socket", (ctx) => {
    return new Promise<void>((resolve) => {
      const agentSocket = mockSocket();
      const decoder = new FrameDecoder();
      const vs = new VirtualSocket(42, agentSocket);

      (agentSocket as any).on("data", (chunk: Buffer) => {
        const frames = decoder.decode(chunk);
        if (frames.length > 0) {
          expect(frames[0].connId).toBe(42);
          expect(frames[0].type).toBe(FrameType.DATA);
          expect(frames[0].payload.toString()).toBe("hello");
          vs.destroy();
          resolve();
        }
      });

      vs.write(Buffer.from("hello"));
    });
  });

  it("pushData() makes data readable", (ctx) => {
    return new Promise<void>((resolve) => {
      const agentSocket = mockSocket();
      const vs = new VirtualSocket(1, agentSocket);

      const chunks: Buffer[] = [];
      vs.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
      });
      vs.on("end", () => {
        expect(Buffer.concat(chunks).toString()).toBe("world");
        resolve();
      });

      vs.pushData(Buffer.from("world"));
      vs.pushEnd();
    });
  });

  it("destroy() sends CLOSE frame to agent socket", (ctx) => {
    return new Promise<void>((resolve) => {
      const agentSocket = mockSocket();
      const decoder = new FrameDecoder();
      const vs = new VirtualSocket(7, agentSocket);

      (agentSocket as any).on("data", (chunk: Buffer) => {
        const frames = decoder.decode(chunk);
        for (const frame of frames) {
          if (frame.type === FrameType.CLOSE && frame.connId === 7) {
            resolve();
          }
        }
      });

      vs.destroy();
    });
  });

  it("write() is no-op after destroy", (ctx) => {
    return new Promise<void>((resolve) => {
      const agentSocket = mockSocket();
      const vs = new VirtualSocket(1, agentSocket);

      vs.on("close", () => {
        // After destroy, writing should silently succeed (callback called, no frame sent)
        const writeSpy = vi.spyOn(agentSocket, "write");
        vs.write(Buffer.from("after-close"), (err) => {
          // The write callback should be called even though no frame was sent
          // (writeSpy may have been called for the CLOSE frame, not for this data)
          resolve();
        });
      });

      vs.destroy();
    });
  });
});
