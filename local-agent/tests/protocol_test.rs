use bytes::{BufMut, Bytes, BytesMut};
use guardian_local_agent::tunnel::protocol::*;
use tokio_util::codec::{Decoder, Encoder};

// ---------------------------------------------------------------------------
// Helper: encode a frame to bytes via the codec
// ---------------------------------------------------------------------------
fn encode(frame: Frame) -> BytesMut {
    let mut codec = FrameCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(frame, &mut buf).expect("encode failed");
    buf
}

// ---------------------------------------------------------------------------
// Helper: decode all frames from a buffer
// ---------------------------------------------------------------------------
fn decode_all(mut buf: BytesMut) -> Vec<Frame> {
    let mut codec = FrameCodec::new();
    let mut frames = Vec::new();
    while let Some(frame) = codec.decode(&mut buf).expect("decode failed") {
        frames.push(frame);
    }
    frames
}

// ===========================================================================
// Cross-language hex fixtures (MUST match Node.js side exactly)
// ===========================================================================

#[test]
fn cross_lang_auth_frame() {
    let frame = Frame::new(0, FrameType::Auth, Bytes::from_static(b"machine1:token123"));
    let buf = encode(frame);

    let expected: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, // conn_id = 0
        0x04, // frame_type = Auth
        0x00, 0x00, 0x00, 0x11, // payload_length = 17
        // "machine1:token123"
        0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x31, 0x3a, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x31,
        0x32, 0x33,
    ];
    assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn cross_lang_data_frame() {
    let frame = Frame::new(42, FrameType::Data, Bytes::from_static(b"Hello"));
    let buf = encode(frame);

    let expected: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x2a, // conn_id = 42
        0x02, // frame_type = Data
        0x00, 0x00, 0x00, 0x05, // payload_length = 5
        // "Hello"
        0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ];
    assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn cross_lang_heartbeat_frame() {
    let frame = Frame::new(0, FrameType::Heartbeat, Bytes::new());
    let buf = encode(frame);

    let expected: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, // conn_id = 0
        0x07, // frame_type = Heartbeat
        0x00, 0x00, 0x00, 0x00, // payload_length = 0
    ];
    assert_eq!(&buf[..], &expected[..]);
}

// ===========================================================================
// Cross-language: decode hex fixtures produced by Node.js
// ===========================================================================

#[test]
fn cross_lang_decode_auth_from_hex() {
    let raw: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e,
        0x65, 0x31, 0x3a, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x31, 0x32, 0x33,
    ];
    let frames = decode_all(BytesMut::from(&raw[..]));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].conn_id, 0);
    assert_eq!(frames[0].frame_type, FrameType::Auth);
    assert_eq!(frames[0].payload, &b"machine1:token123"[..]);
}

#[test]
fn cross_lang_decode_data_from_hex() {
    let raw: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
    ];
    let frames = decode_all(BytesMut::from(&raw[..]));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].conn_id, 42);
    assert_eq!(frames[0].frame_type, FrameType::Data);
    assert_eq!(frames[0].payload, &b"Hello"[..]);
}

#[test]
fn cross_lang_decode_heartbeat_from_hex() {
    let raw: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00];
    let frames = decode_all(BytesMut::from(&raw[..]));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].conn_id, 0);
    assert_eq!(frames[0].frame_type, FrameType::Heartbeat);
    assert!(frames[0].payload.is_empty());
}

// ===========================================================================
// Roundtrip encode/decode for every frame type
// ===========================================================================

#[test]
fn roundtrip_new_connection() {
    let frame = Frame::new(
        1,
        FrameType::NewConnection,
        Bytes::from_static(b"api.openai.com:443"),
    );
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_data() {
    let frame = Frame::new(7, FrameType::Data, Bytes::from_static(b"some data payload"));
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_close() {
    let frame = Frame::new(99, FrameType::Close, Bytes::new());
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_auth() {
    let frame = Frame::new(0, FrameType::Auth, Bytes::from_static(b"user:pass"));
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_auth_ok() {
    let frame = Frame::new(0, FrameType::AuthOk, Bytes::from_static(b"welcome"));
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_auth_fail() {
    let frame = Frame::new(0, FrameType::AuthFail, Bytes::from_static(b"bad token"));
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_heartbeat() {
    let frame = Frame::new(0, FrameType::Heartbeat, Bytes::new());
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_heartbeat_ack() {
    let frame = Frame::new(0, FrameType::HeartbeatAck, Bytes::new());
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

// ===========================================================================
// Partial frame delivery
// ===========================================================================

#[test]
fn partial_header_returns_none() {
    let frame = Frame::new(1, FrameType::Data, Bytes::from_static(b"test"));
    let full = encode(frame);

    let mut codec = FrameCodec::new();

    // Feed only first 5 bytes of header (need 9)
    let mut partial = BytesMut::from(&full[..5]);
    assert!(codec.decode(&mut partial).unwrap().is_none());
}

#[test]
fn partial_payload_returns_none() {
    let frame = Frame::new(1, FrameType::Data, Bytes::from_static(b"hello world"));
    let full = encode(frame);

    let mut codec = FrameCodec::new();

    // Feed header + partial payload
    let mut partial = BytesMut::from(&full[..12]);
    assert!(codec.decode(&mut partial).unwrap().is_none());
}

#[test]
fn partial_then_complete() {
    let frame = Frame::new(5, FrameType::Data, Bytes::from_static(b"payload"));
    let full = encode(frame.clone());

    let mut codec = FrameCodec::new();
    let mut buf = BytesMut::new();

    // Feed byte by byte
    for &byte in full.iter() {
        buf.put_u8(byte);
        let result = codec.decode(&mut buf).unwrap();
        if buf.is_empty() {
            // Last byte completed the frame
            assert_eq!(result, Some(frame.clone()));
            return;
        } else if result.is_some() {
            assert_eq!(result, Some(frame.clone()));
            return;
        }
    }
    panic!("frame was never decoded");
}

// ===========================================================================
// Multiple frames in one chunk
// ===========================================================================

#[test]
fn multiple_frames_in_one_buffer() {
    let f1 = Frame::new(1, FrameType::Data, Bytes::from_static(b"first"));
    let f2 = Frame::new(2, FrameType::Data, Bytes::from_static(b"second"));
    let f3 = Frame::new(0, FrameType::Heartbeat, Bytes::new());

    let mut buf = BytesMut::new();
    let mut codec = FrameCodec::new();
    codec.encode(f1.clone(), &mut buf).unwrap();
    codec.encode(f2.clone(), &mut buf).unwrap();
    codec.encode(f3.clone(), &mut buf).unwrap();

    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![f1, f2, f3]);
}

// ===========================================================================
// Zero-length payloads
// ===========================================================================

#[test]
fn zero_length_payload_all_types() {
    let types = [
        FrameType::NewConnection,
        FrameType::Data,
        FrameType::Close,
        FrameType::Auth,
        FrameType::AuthOk,
        FrameType::AuthFail,
        FrameType::Heartbeat,
        FrameType::HeartbeatAck,
        FrameType::DomainListRequest,
        FrameType::DomainListResponse,
    ];

    for ft in types {
        let frame = Frame::new(0, ft, Bytes::new());
        let buf = encode(frame.clone());
        assert_eq!(buf.len(), 9, "empty frame for {:?} should be 9 bytes", ft);
        let decoded = decode_all(buf);
        assert_eq!(decoded, vec![frame]);
    }
}

// ===========================================================================
// Max payload enforcement
// ===========================================================================

#[test]
fn encode_rejects_oversized_payload() {
    let big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
    let frame = Frame::new(1, FrameType::Data, Bytes::from(big));
    let mut buf = BytesMut::new();
    let mut codec = FrameCodec::new();
    let result = codec.encode(frame, &mut buf);
    assert!(result.is_err());
}

#[test]
fn encode_accepts_max_payload() {
    let data = vec![0xABu8; MAX_PAYLOAD_SIZE];
    let frame = Frame::new(1, FrameType::Data, Bytes::from(data.clone()));
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].payload.len(), MAX_PAYLOAD_SIZE);
}

#[test]
fn decode_rejects_oversized_payload_length() {
    // Craft a raw frame with payload_length = MAX_PAYLOAD_SIZE + 1
    let bad_len = (MAX_PAYLOAD_SIZE as u32) + 1;
    let mut raw = BytesMut::new();
    raw.put_u32(1); // conn_id
    raw.put_u8(0x02); // Data
    raw.put_u32(bad_len); // payload_length (too big)
                          // Don't need actual payload bytes — decoder should reject at header check.

    let mut codec = FrameCodec::new();
    let result = codec.decode(&mut raw);
    assert!(result.is_err());
}

// ===========================================================================
// Unknown frame type
// ===========================================================================

#[test]
fn decode_rejects_unknown_frame_type() {
    let mut raw = BytesMut::new();
    raw.put_u32(0); // conn_id
    raw.put_u8(0xFF); // unknown type
    raw.put_u32(0); // payload_length = 0

    let mut codec = FrameCodec::new();
    let result = codec.decode(&mut raw);
    assert!(result.is_err());
}

// ===========================================================================
// FrameType conversion
// ===========================================================================

#[test]
fn frame_type_round_trips() {
    let types = [
        (0x01, FrameType::NewConnection),
        (0x02, FrameType::Data),
        (0x03, FrameType::Close),
        (0x04, FrameType::Auth),
        (0x05, FrameType::AuthOk),
        (0x06, FrameType::AuthFail),
        (0x07, FrameType::Heartbeat),
        (0x08, FrameType::HeartbeatAck),
        (0x09, FrameType::DomainListRequest),
        (0x0A, FrameType::DomainListResponse),
    ];
    for (byte, expected) in types {
        let ft = FrameType::from_u8(byte).unwrap();
        assert_eq!(ft, expected);
        assert_eq!(ft as u8, byte);
    }
}

#[test]
fn frame_type_rejects_invalid() {
    assert!(FrameType::from_u8(0x00).is_err());
    assert!(FrameType::from_u8(0x0B).is_err());
    assert!(FrameType::from_u8(0xFF).is_err());
}

// ===========================================================================
// New frame types: DomainListRequest, DomainListResponse
// ===========================================================================

#[test]
fn roundtrip_domain_list_request() {
    let frame = Frame::new(0, FrameType::DomainListRequest, Bytes::new());
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn roundtrip_domain_list_response() {
    let payload = Bytes::from(r#"["api.openai.com","*.example.com"]"#);
    let frame = Frame::new(0, FrameType::DomainListResponse, payload);
    let buf = encode(frame.clone());
    let decoded = decode_all(buf);
    assert_eq!(decoded, vec![frame]);
}

#[test]
fn cross_lang_domain_list_request_frame() {
    let frame = Frame::new(0, FrameType::DomainListRequest, Bytes::new());
    let buf = encode(frame);

    let expected: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, // conn_id = 0
        0x09, // frame_type = DomainListRequest
        0x00, 0x00, 0x00, 0x00, // payload_length = 0
    ];
    assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn cross_lang_domain_list_response_frame() {
    let payload_str = r#"["api.openai.com"]"#;
    let frame = Frame::new(0, FrameType::DomainListResponse, Bytes::from(payload_str));
    let buf = encode(frame);

    let mut expected = vec![
        0x00, 0x00, 0x00, 0x00, // conn_id = 0
        0x0a, // frame_type = DomainListResponse
        0x00, 0x00, 0x00, 0x12, // payload_length = 18
    ];
    expected.extend_from_slice(payload_str.as_bytes());
    assert_eq!(&buf[..], &expected[..]);
}

#[test]
fn cross_lang_decode_domain_list_request_from_hex() {
    let raw: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00];
    let frames = decode_all(BytesMut::from(&raw[..]));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].conn_id, 0);
    assert_eq!(frames[0].frame_type, FrameType::DomainListRequest);
    assert!(frames[0].payload.is_empty());
}

#[test]
fn cross_lang_decode_domain_list_response_from_hex() {
    let payload_str = r#"["api.openai.com"]"#;
    let mut raw: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x12];
    raw.extend_from_slice(payload_str.as_bytes());
    let frames = decode_all(BytesMut::from(&raw[..]));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].conn_id, 0);
    assert_eq!(frames[0].frame_type, FrameType::DomainListResponse);
    assert_eq!(frames[0].payload, payload_str.as_bytes());
}
