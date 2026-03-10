// Tunnel protocol: binary frame encoding/decoding for multiplexed connections.
//
// Frame format (Big Endian):
//   [Connection ID: 4B] [Frame Type: 1B] [Payload Length: 4B] [Payload: variable]
//
// Header is always 9 bytes. Max payload: 65536 bytes. Connection ID 0 = control channel.

export const FRAME_HEADER_SIZE = 9;
export const MAX_PAYLOAD_SIZE = 65536;

export enum FrameType {
  NEW_CONNECTION = 0x01,
  DATA = 0x02,
  CLOSE = 0x03,
  AUTH = 0x04,
  AUTH_OK = 0x05,
  AUTH_FAIL = 0x06,
  HEARTBEAT = 0x07,
  HEARTBEAT_ACK = 0x08,
}

export interface Frame {
  connId: number;
  type: FrameType;
  payload: Buffer;
}

export function encodeFrame(connId: number, type: FrameType, payload: Buffer = Buffer.alloc(0)): Buffer {
  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError(`Payload length ${payload.length} exceeds maximum ${MAX_PAYLOAD_SIZE}`);
  }

  const buf = Buffer.alloc(FRAME_HEADER_SIZE + payload.length);
  buf.writeUInt32BE(connId, 0);
  buf.writeUInt8(type, 4);
  buf.writeUInt32BE(payload.length, 5);
  payload.copy(buf, FRAME_HEADER_SIZE);
  return buf;
}

export class FrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  /** Feed raw bytes into the decoder. Returns an array of complete frames. */
  decode(chunk: Buffer): Frame[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);

    const frames: Frame[] = [];
    while (this.buffer.length >= FRAME_HEADER_SIZE) {
      const payloadLen = this.buffer.readUInt32BE(5);

      if (payloadLen > MAX_PAYLOAD_SIZE) {
        throw new RangeError(`Received payload length ${payloadLen} exceeds maximum ${MAX_PAYLOAD_SIZE}`);
      }

      const totalLen = FRAME_HEADER_SIZE + payloadLen;
      if (this.buffer.length < totalLen) {
        break; // wait for more data
      }

      const connId = this.buffer.readUInt32BE(0);
      const type = this.buffer.readUInt8(4) as FrameType;
      const payload = Buffer.from(this.buffer.subarray(FRAME_HEADER_SIZE, totalLen));

      frames.push({ connId, type, payload });
      this.buffer = Buffer.from(this.buffer.subarray(totalLen));
    }

    return frames;
  }

  /** Returns the number of buffered bytes not yet decoded into frames. */
  get bufferedBytes(): number {
    return this.buffer.length;
  }

  /** Reset internal buffer state. */
  reset(): void {
    this.buffer = Buffer.alloc(0);
  }
}
