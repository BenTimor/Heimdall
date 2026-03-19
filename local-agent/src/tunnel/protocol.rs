use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// Maximum allowed payload size (64 KiB).
pub const MAX_PAYLOAD_SIZE: usize = 65536;

/// Frame header size: 4 (conn_id) + 1 (frame_type) + 4 (payload_length).
const HEADER_SIZE: usize = 9;

/// Connection ID reserved for the control channel.
#[allow(dead_code)]
pub const CONTROL_CONNECTION_ID: u32 = 0;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD_SIZE})")]
    PayloadTooLarge(usize),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    NewConnection = 0x01,
    Data = 0x02,
    Close = 0x03,
    Auth = 0x04,
    AuthOk = 0x05,
    AuthFail = 0x06,
    Heartbeat = 0x07,
    HeartbeatAck = 0x08,
    DomainListRequest = 0x09,
    DomainListResponse = 0x0A,
}

impl FrameType {
    pub fn from_u8(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x01 => Ok(FrameType::NewConnection),
            0x02 => Ok(FrameType::Data),
            0x03 => Ok(FrameType::Close),
            0x04 => Ok(FrameType::Auth),
            0x05 => Ok(FrameType::AuthOk),
            0x06 => Ok(FrameType::AuthFail),
            0x07 => Ok(FrameType::Heartbeat),
            0x08 => Ok(FrameType::HeartbeatAck),
            0x09 => Ok(FrameType::DomainListRequest),
            0x0A => Ok(FrameType::DomainListResponse),
            other => Err(ProtocolError::UnknownFrameType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub conn_id: u32,
    pub frame_type: FrameType,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(conn_id: u32, frame_type: FrameType, payload: impl Into<Bytes>) -> Self {
        Self {
            conn_id,
            frame_type,
            payload: payload.into(),
        }
    }
}

/// Encode a frame into a byte buffer.
pub fn encode_frame(frame: &Frame, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    let payload_len = frame.payload.len();
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }

    dst.reserve(HEADER_SIZE + payload_len);
    dst.put_u32(frame.conn_id);
    dst.put_u8(frame.frame_type as u8);
    dst.put_u32(payload_len as u32);
    dst.put_slice(&frame.payload);
    Ok(())
}

/// Tokio codec for framing protocol messages on a transport.
#[derive(Debug, Default)]
pub struct FrameCodec;

impl FrameCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, ProtocolError> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Peek at the payload length without consuming bytes yet.
        let payload_len =
            u32::from_be_bytes([src[5], src[6], src[7], src[8]]) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge(payload_len));
        }

        let total_len = HEADER_SIZE + payload_len;
        if src.len() < total_len {
            // Reserve space so the next read can fill it in.
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        // We have a complete frame — consume it.
        let conn_id = src.get_u32();
        let frame_type = FrameType::from_u8(src.get_u8())?;
        let _payload_len = src.get_u32(); // already validated above
        let payload = src.split_to(payload_len).freeze();

        Ok(Some(Frame {
            conn_id,
            frame_type,
            payload,
        }))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_frame(&frame, dst)
    }
}
