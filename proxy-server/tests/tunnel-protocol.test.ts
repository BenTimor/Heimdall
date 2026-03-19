import { describe, it, expect } from "vitest";
import {
  FrameType,
  encodeFrame,
  FrameDecoder,
  FRAME_HEADER_SIZE,
  MAX_PAYLOAD_SIZE,
} from "../src/tunnel/protocol.js";

describe("tunnel protocol", () => {
  describe("encodeFrame", () => {
    it("encodes a frame with payload", () => {
      const buf = encodeFrame(1, FrameType.DATA, Buffer.from("hello"));
      expect(buf.length).toBe(FRAME_HEADER_SIZE + 5);
      expect(buf.readUInt32BE(0)).toBe(1);      // connId
      expect(buf.readUInt8(4)).toBe(0x02);       // DATA
      expect(buf.readUInt32BE(5)).toBe(5);       // payload length
      expect(buf.subarray(9).toString()).toBe("hello");
    });

    it("encodes a frame with empty payload", () => {
      const buf = encodeFrame(0, FrameType.HEARTBEAT);
      expect(buf.length).toBe(FRAME_HEADER_SIZE);
      expect(buf.readUInt32BE(5)).toBe(0);
    });

    it("rejects payload exceeding max size", () => {
      const big = Buffer.alloc(MAX_PAYLOAD_SIZE + 1);
      expect(() => encodeFrame(0, FrameType.DATA, big)).toThrow(RangeError);
    });

    it("accepts payload at exact max size", () => {
      const maxBuf = Buffer.alloc(MAX_PAYLOAD_SIZE);
      const encoded = encodeFrame(0, FrameType.DATA, maxBuf);
      expect(encoded.length).toBe(FRAME_HEADER_SIZE + MAX_PAYLOAD_SIZE);
    });
  });

  describe("FrameDecoder", () => {
    it("decodes a single complete frame", () => {
      const decoder = new FrameDecoder();
      const encoded = encodeFrame(5, FrameType.NEW_CONNECTION, Buffer.from("host:443"));
      const frames = decoder.decode(encoded);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(5);
      expect(frames[0].type).toBe(FrameType.NEW_CONNECTION);
      expect(frames[0].payload.toString()).toBe("host:443");
    });

    it("decodes multiple frames in one chunk", () => {
      const decoder = new FrameDecoder();
      const f1 = encodeFrame(1, FrameType.DATA, Buffer.from("abc"));
      const f2 = encodeFrame(2, FrameType.DATA, Buffer.from("def"));
      const f3 = encodeFrame(0, FrameType.HEARTBEAT);
      const combined = Buffer.concat([f1, f2, f3]);

      const frames = decoder.decode(combined);
      expect(frames).toHaveLength(3);
      expect(frames[0].payload.toString()).toBe("abc");
      expect(frames[1].payload.toString()).toBe("def");
      expect(frames[2].type).toBe(FrameType.HEARTBEAT);
      expect(frames[2].payload.length).toBe(0);
    });

    it("handles partial delivery (byte-by-byte)", () => {
      const decoder = new FrameDecoder();
      const encoded = encodeFrame(10, FrameType.DATA, Buffer.from("XY"));

      const allFrames: ReturnType<typeof decoder.decode> = [];
      for (let i = 0; i < encoded.length; i++) {
        const frames = decoder.decode(encoded.subarray(i, i + 1));
        allFrames.push(...frames);
      }

      expect(allFrames).toHaveLength(1);
      expect(allFrames[0].connId).toBe(10);
      expect(allFrames[0].payload.toString()).toBe("XY");
    });

    it("handles split at header/payload boundary", () => {
      const decoder = new FrameDecoder();
      const encoded = encodeFrame(3, FrameType.DATA, Buffer.from("SPLIT"));

      // Feed header only
      let frames = decoder.decode(encoded.subarray(0, FRAME_HEADER_SIZE));
      expect(frames).toHaveLength(0);
      expect(decoder.bufferedBytes).toBe(FRAME_HEADER_SIZE);

      // Feed payload
      frames = decoder.decode(encoded.subarray(FRAME_HEADER_SIZE));
      expect(frames).toHaveLength(1);
      expect(frames[0].payload.toString()).toBe("SPLIT");
      expect(decoder.bufferedBytes).toBe(0);
    });

    it("handles frame split mid-header", () => {
      const decoder = new FrameDecoder();
      const encoded = encodeFrame(7, FrameType.CLOSE, Buffer.from("bye"));

      // Feed first 4 bytes (just connId)
      let frames = decoder.decode(encoded.subarray(0, 4));
      expect(frames).toHaveLength(0);

      // Feed the rest
      frames = decoder.decode(encoded.subarray(4));
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(7);
      expect(frames[0].type).toBe(FrameType.CLOSE);
      expect(frames[0].payload.toString()).toBe("bye");
    });

    it("buffers trailing bytes across multiple feeds", () => {
      const decoder = new FrameDecoder();
      const f1 = encodeFrame(1, FrameType.DATA, Buffer.from("A"));
      const f2 = encodeFrame(2, FrameType.DATA, Buffer.from("B"));
      const combined = Buffer.concat([f1, f2]);

      // Feed f1 complete + first 3 bytes of f2
      const splitPoint = f1.length + 3;
      let frames = decoder.decode(combined.subarray(0, splitPoint));
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(1);
      expect(decoder.bufferedBytes).toBe(3);

      // Feed rest of f2
      frames = decoder.decode(combined.subarray(splitPoint));
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(2);
      expect(frames[0].payload.toString()).toBe("B");
      expect(decoder.bufferedBytes).toBe(0);
    });

    it("rejects payload exceeding max size during decode", () => {
      const decoder = new FrameDecoder();
      // Manually build a header with payload length = MAX_PAYLOAD_SIZE + 1
      const header = Buffer.alloc(FRAME_HEADER_SIZE);
      header.writeUInt32BE(0, 0);
      header.writeUInt8(FrameType.DATA, 4);
      header.writeUInt32BE(MAX_PAYLOAD_SIZE + 1, 5);

      expect(() => decoder.decode(header)).toThrow(RangeError);
    });

    it("resets internal buffer", () => {
      const decoder = new FrameDecoder();
      // Feed partial frame
      const encoded = encodeFrame(1, FrameType.DATA, Buffer.from("partial"));
      decoder.decode(encoded.subarray(0, 5));
      expect(decoder.bufferedBytes).toBe(5);

      decoder.reset();
      expect(decoder.bufferedBytes).toBe(0);

      // Should decode cleanly after reset
      const frames = decoder.decode(encodeFrame(2, FrameType.HEARTBEAT));
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(2);
    });
  });

  describe("roundtrip encode/decode for every frame type", () => {
    const frameTypes: [FrameType, string, Buffer][] = [
      [FrameType.NEW_CONNECTION, "NEW_CONNECTION", Buffer.from("api.example.com:443")],
      [FrameType.DATA, "DATA", Buffer.from("request body data")],
      [FrameType.CLOSE, "CLOSE", Buffer.alloc(0)],
      [FrameType.AUTH, "AUTH", Buffer.from("machine1:token123")],
      [FrameType.AUTH_OK, "AUTH_OK", Buffer.alloc(0)],
      [FrameType.AUTH_FAIL, "AUTH_FAIL", Buffer.from("bad credentials")],
      [FrameType.HEARTBEAT, "HEARTBEAT", Buffer.alloc(0)],
      [FrameType.HEARTBEAT_ACK, "HEARTBEAT_ACK", Buffer.alloc(0)],
      [FrameType.DOMAIN_LIST_REQUEST, "DOMAIN_LIST_REQUEST", Buffer.alloc(0)],
      [FrameType.DOMAIN_LIST_RESPONSE, "DOMAIN_LIST_RESPONSE", Buffer.from('["api.openai.com","*.example.com"]')],
    ];

    for (const [type, name, payload] of frameTypes) {
      it(`roundtrips ${name} (type=0x${type.toString(16).padStart(2, "0")})`, () => {
        const connId = type === FrameType.HEARTBEAT || type === FrameType.AUTH ? 0 : 42;
        const encoded = encodeFrame(connId, type, payload);
        const decoder = new FrameDecoder();
        const frames = decoder.decode(encoded);

        expect(frames).toHaveLength(1);
        expect(frames[0].connId).toBe(connId);
        expect(frames[0].type).toBe(type);
        expect(Buffer.compare(frames[0].payload, payload)).toBe(0);
      });
    }
  });

  describe("zero-length payloads", () => {
    it("encodes and decodes frame with no payload", () => {
      const encoded = encodeFrame(0, FrameType.HEARTBEAT);
      expect(encoded.length).toBe(FRAME_HEADER_SIZE);

      const decoder = new FrameDecoder();
      const frames = decoder.decode(encoded);
      expect(frames).toHaveLength(1);
      expect(frames[0].payload.length).toBe(0);
    });

    it("handles consecutive zero-payload frames", () => {
      const decoder = new FrameDecoder();
      const combined = Buffer.concat([
        encodeFrame(0, FrameType.HEARTBEAT),
        encodeFrame(0, FrameType.HEARTBEAT_ACK),
        encodeFrame(5, FrameType.CLOSE),
      ]);

      const frames = decoder.decode(combined);
      expect(frames).toHaveLength(3);
      expect(frames[0].type).toBe(FrameType.HEARTBEAT);
      expect(frames[1].type).toBe(FrameType.HEARTBEAT_ACK);
      expect(frames[2].type).toBe(FrameType.CLOSE);
      expect(frames[2].connId).toBe(5);
    });
  });

  describe("cross-language hex fixtures", () => {
    // These exact byte sequences must also be produced by the Rust implementation.

    it("AUTH frame: connId=0, payload='machine1:token123'", () => {
      const encoded = encodeFrame(0, FrameType.AUTH, Buffer.from("machine1:token123"));
      const expected = Buffer.from(
        "00000000" + "04" + "00000011" + "6d616368696e65313a746f6b656e313233",
        "hex"
      );
      expect(Buffer.compare(encoded, expected)).toBe(0);
    });

    it("DATA frame: connId=42, payload='Hello'", () => {
      const encoded = encodeFrame(42, FrameType.DATA, Buffer.from("Hello"));
      const expected = Buffer.from(
        "0000002a" + "02" + "00000005" + "48656c6c6f",
        "hex"
      );
      expect(Buffer.compare(encoded, expected)).toBe(0);
    });

    it("HEARTBEAT frame: connId=0, empty payload", () => {
      const encoded = encodeFrame(0, FrameType.HEARTBEAT);
      const expected = Buffer.from(
        "00000000" + "07" + "00000000",
        "hex"
      );
      expect(Buffer.compare(encoded, expected)).toBe(0);
    });

    it("decodes cross-language AUTH fixture", () => {
      const raw = Buffer.from(
        "00000000" + "04" + "00000011" + "6d616368696e65313a746f6b656e313233",
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(0);
      expect(frames[0].type).toBe(FrameType.AUTH);
      expect(frames[0].payload.toString()).toBe("machine1:token123");
    });

    it("decodes cross-language DATA fixture", () => {
      const raw = Buffer.from(
        "0000002a" + "02" + "00000005" + "48656c6c6f",
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(42);
      expect(frames[0].type).toBe(FrameType.DATA);
      expect(frames[0].payload.toString()).toBe("Hello");
    });

    it("decodes cross-language HEARTBEAT fixture", () => {
      const raw = Buffer.from(
        "00000000" + "07" + "00000000",
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(0);
      expect(frames[0].type).toBe(FrameType.HEARTBEAT);
      expect(frames[0].payload.length).toBe(0);
    });

    it("DOMAIN_LIST_REQUEST frame: connId=0, empty payload", () => {
      const encoded = encodeFrame(0, FrameType.DOMAIN_LIST_REQUEST);
      const expected = Buffer.from(
        "00000000" + "09" + "00000000",
        "hex"
      );
      expect(Buffer.compare(encoded, expected)).toBe(0);
    });

    it("DOMAIN_LIST_RESPONSE frame: connId=0, JSON payload", () => {
      const payload = Buffer.from('["api.openai.com"]');
      const encoded = encodeFrame(0, FrameType.DOMAIN_LIST_RESPONSE, payload);
      const expected = Buffer.from(
        "00000000" + "0a" + "00000012" + Buffer.from('["api.openai.com"]').toString("hex"),
        "hex"
      );
      expect(Buffer.compare(encoded, expected)).toBe(0);
    });

    it("decodes cross-language DOMAIN_LIST_REQUEST fixture", () => {
      const raw = Buffer.from(
        "00000000" + "09" + "00000000",
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(0);
      expect(frames[0].type).toBe(FrameType.DOMAIN_LIST_REQUEST);
      expect(frames[0].payload.length).toBe(0);
    });

    it("decodes cross-language DOMAIN_LIST_RESPONSE fixture", () => {
      const raw = Buffer.from(
        "00000000" + "0a" + "00000012" + Buffer.from('["api.openai.com"]').toString("hex"),
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(1);
      expect(frames[0].connId).toBe(0);
      expect(frames[0].type).toBe(FrameType.DOMAIN_LIST_RESPONSE);
      expect(JSON.parse(frames[0].payload.toString())).toEqual(["api.openai.com"]);
    });

    it("decodes all three cross-language fixtures concatenated", () => {
      const raw = Buffer.from(
        "00000000" + "04" + "00000011" + "6d616368696e65313a746f6b656e313233" +
        "0000002a" + "02" + "00000005" + "48656c6c6f" +
        "00000000" + "07" + "00000000",
        "hex"
      );
      const decoder = new FrameDecoder();
      const frames = decoder.decode(raw);
      expect(frames).toHaveLength(3);

      expect(frames[0].type).toBe(FrameType.AUTH);
      expect(frames[0].payload.toString()).toBe("machine1:token123");

      expect(frames[1].type).toBe(FrameType.DATA);
      expect(frames[1].connId).toBe(42);
      expect(frames[1].payload.toString()).toBe("Hello");

      expect(frames[2].type).toBe(FrameType.HEARTBEAT);
      expect(frames[2].payload.length).toBe(0);
    });
  });

  describe("FrameType enum values", () => {
    it("has correct numeric values", () => {
      expect(FrameType.NEW_CONNECTION).toBe(0x01);
      expect(FrameType.DATA).toBe(0x02);
      expect(FrameType.CLOSE).toBe(0x03);
      expect(FrameType.AUTH).toBe(0x04);
      expect(FrameType.AUTH_OK).toBe(0x05);
      expect(FrameType.AUTH_FAIL).toBe(0x06);
      expect(FrameType.HEARTBEAT).toBe(0x07);
      expect(FrameType.HEARTBEAT_ACK).toBe(0x08);
      expect(FrameType.DOMAIN_LIST_REQUEST).toBe(0x09);
      expect(FrameType.DOMAIN_LIST_RESPONSE).toBe(0x0A);
    });
  });
});
