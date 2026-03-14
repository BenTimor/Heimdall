use guardian_local_agent::sni::{extract_sni, SniError};

// ---------------------------------------------------------------------------
// Helpers to build ClientHello byte arrays programmatically
// ---------------------------------------------------------------------------

/// Build a minimal ClientHello with the given SNI hostname as the only extension.
fn build_client_hello(hostname: &str) -> Vec<u8> {
    let sni_ext = build_sni_extension(hostname);
    build_client_hello_with_extensions(&sni_ext)
}

/// Build the raw bytes of a server_name (0x0000) extension for the given hostname.
fn build_sni_extension(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let name_len = name_bytes.len() as u16;

    // server_name extension data:
    // server_name_list_length (2B) + host_name type (1B) + host_name_length (2B) + name
    let sni_ext_data_len = 2 + 1 + 2 + name_len;
    let server_name_list_len = 1 + 2 + name_len;

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type: server_name
    sni_ext.extend_from_slice(&sni_ext_data_len.to_be_bytes()); // extension data length
    sni_ext.extend_from_slice(&server_name_list_len.to_be_bytes()); // server name list length
    sni_ext.push(0x00); // host_name type
    sni_ext.extend_from_slice(&name_len.to_be_bytes()); // host name length
    sni_ext.extend_from_slice(name_bytes); // hostname

    sni_ext
}

/// Build a dummy extension with the given type and an empty payload.
fn build_dummy_extension(ext_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&ext_type.to_be_bytes());
    ext.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ext.extend_from_slice(payload);
    ext
}

/// Build a complete TLS record containing a ClientHello with the given extensions bytes.
fn build_client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
    build_client_hello_full(extensions, 0, &[0x03, 0x01])
}

/// Build a complete TLS record with configurable session ID length and record version.
fn build_client_hello_full(
    extensions: &[u8],
    session_id_len: u8,
    record_version: &[u8; 2],
) -> Vec<u8> {
    let extensions_len = extensions.len() as u16;

    // ClientHello body
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 client version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(session_id_len); // session ID length
    body.extend_from_slice(&vec![0xAA; session_id_len as usize]); // session ID bytes
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length = 2
    body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
    body.push(0x01); // compression methods length = 1
    body.push(0x00); // null compression
    body.extend_from_slice(&extensions_len.to_be_bytes());
    body.extend_from_slice(extensions);

    let body_len = body.len();

    // Handshake header: type (1B) + length (3B)
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let record_len = handshake.len() as u16;

    // TLS record header: content_type (1B) + version (2B) + length (2B)
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(record_version);
    record.extend_from_slice(&record_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Build a ClientHello with no extensions section at all (body ends after compression methods).
fn build_client_hello_no_extensions() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 client version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0x00); // session ID length = 0
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length = 2
    body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
    body.push(0x01); // compression methods length = 1
    body.push(0x00); // null compression
    // NO extensions length or extensions data

    let body_len = body.len();

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let record_len = handshake.len() as u16;

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&record_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_extract_sni_basic() {
    let data = build_client_hello("api.openai.com");
    let hostname = extract_sni(&data).expect("should extract SNI");
    assert_eq!(hostname, "api.openai.com");
}

#[test]
fn test_extract_sni_various_hostnames() {
    for name in &["example.com", "a.b.c.d.example.com", "x"] {
        let data = build_client_hello(name);
        let hostname = extract_sni(&data).expect(&format!("should extract '{}'", name));
        assert_eq!(hostname, *name);
    }
}

#[test]
fn test_multiple_extensions() {
    // Put a dummy extension (type 0x000A — supported_groups) before SNI
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&build_dummy_extension(0x000A, &[0x00, 0x02, 0x00, 0x17]));
    extensions.extend_from_slice(&build_sni_extension("api.openai.com"));

    let data = build_client_hello_with_extensions(&extensions);
    let hostname = extract_sni(&data).expect("should find SNI after other extension");
    assert_eq!(hostname, "api.openai.com");
}

#[test]
fn test_sni_not_first_extension() {
    // SNI after 3 other extensions
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&build_dummy_extension(0x000A, &[0x00, 0x02, 0x00, 0x17])); // supported_groups
    extensions.extend_from_slice(&build_dummy_extension(0x000B, &[0x01, 0x00])); // ec_point_formats
    extensions.extend_from_slice(&build_dummy_extension(0x0023, &[])); // session_ticket (empty)
    extensions.extend_from_slice(&build_sni_extension("deep.nested.example.org"));

    let data = build_client_hello_with_extensions(&extensions);
    let hostname = extract_sni(&data).expect("should find SNI after multiple extensions");
    assert_eq!(hostname, "deep.nested.example.org");
}

#[test]
fn test_no_sni_extension() {
    // Build ClientHello with only non-SNI extensions
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&build_dummy_extension(0x000A, &[0x00, 0x02, 0x00, 0x17]));
    extensions.extend_from_slice(&build_dummy_extension(0x000B, &[0x01, 0x00]));

    let data = build_client_hello_with_extensions(&extensions);
    let err = extract_sni(&data).unwrap_err();
    assert!(
        matches!(err, SniError::NoSniExtension),
        "expected NoSniExtension, got: {:?}",
        err
    );
}

#[test]
fn test_not_tls_handshake() {
    // Plain HTTP request
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let err = extract_sni(data).unwrap_err();
    assert!(
        matches!(err, SniError::NotTlsHandshake),
        "expected NotTlsHandshake, got: {:?}",
        err
    );
}

#[test]
fn test_not_client_hello() {
    // TLS record with handshake type 0x02 (ServerHello) instead of 0x01
    let mut data = build_client_hello("example.com");
    data[5] = 0x02; // Change ClientHello (0x01) to ServerHello (0x02)
    let err = extract_sni(&data).unwrap_err();
    assert!(
        matches!(err, SniError::NotClientHello),
        "expected NotClientHello, got: {:?}",
        err
    );
}

#[test]
fn test_truncated_at_various_points() {
    let full = build_client_hello("api.openai.com");

    // Empty buffer
    let err = extract_sni(&[]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));

    // Just 1 byte (0x16)
    let err = extract_sni(&full[..1]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));

    // Just 4 bytes (partial TLS record header)
    let err = extract_sni(&full[..4]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));

    // Just the TLS record header (5 bytes) — no handshake type
    let err = extract_sni(&full[..5]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));

    // Up to offset 43 — session ID length present but no more
    let err = extract_sni(&full[..44]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));

    // Truncated in the middle of extensions
    let err = extract_sni(&full[..full.len() - 5]).unwrap_err();
    assert!(matches!(err, SniError::BufferTooShort { .. }));
}

#[test]
fn test_no_extensions() {
    let data = build_client_hello_no_extensions();
    let err = extract_sni(&data).unwrap_err();
    assert!(
        matches!(err, SniError::NoSniExtension),
        "expected NoSniExtension for ClientHello without extensions, got: {:?}",
        err
    );
}

#[test]
fn test_tls13_client_hello() {
    // TLS 1.3 uses supported_versions extension (0x002B) with version 0x0304
    // The ClientHello still has TLS 1.2 (0x0303) in the client_version field,
    // with a supported_versions extension indicating actual TLS 1.3 support.
    let mut extensions = Vec::new();

    // supported_versions extension (0x002B): list_len(1B) + 1 version (2B) = 3 bytes payload
    let sv_payload = [0x02, 0x03, 0x04]; // list_len=2, version=0x0304 (TLS 1.3)
    extensions.extend_from_slice(&build_dummy_extension(0x002B, &sv_payload));

    // SNI extension
    extensions.extend_from_slice(&build_sni_extension("tls13.example.com"));

    // Use record version 0x0301 (typical for TLS 1.3 ClientHello records)
    let data = build_client_hello_full(&extensions, 0, &[0x03, 0x01]);
    let hostname = extract_sni(&data).expect("should extract SNI from TLS 1.3 ClientHello");
    assert_eq!(hostname, "tls13.example.com");
}

#[test]
fn test_session_id_present() {
    // ClientHello with a 32-byte session ID
    let extensions = build_sni_extension("session-id.example.com");
    let data = build_client_hello_full(&extensions, 32, &[0x03, 0x01]);
    let hostname = extract_sni(&data).expect("should extract SNI with session ID present");
    assert_eq!(hostname, "session-id.example.com");
}

#[test]
fn test_record_length_exceeds_max() {
    // Build a valid ClientHello, then tamper the TLS record length field
    // (bytes 3-4) to exceed the 16384 byte limit.
    let mut data = build_client_hello("example.com");
    // Set record length to 16385 (0x4001) — one over the max
    data[3] = 0x40;
    data[4] = 0x01;
    let err = extract_sni(&data).unwrap_err();
    assert!(
        matches!(err, SniError::BufferTooShort { .. }),
        "expected BufferTooShort for oversized record length, got: {:?}",
        err
    );
}

#[test]
fn test_hostname_exceeds_253_bytes() {
    // Build a ClientHello with a hostname longer than 253 characters.
    // DNS labels are max 253 chars total — anything longer is invalid.
    let long_hostname: String = "a".repeat(254);
    let data = build_client_hello(&long_hostname);
    let err = extract_sni(&data).unwrap_err();
    assert!(
        matches!(err, SniError::InvalidHostname),
        "expected InvalidHostname for hostname > 253 bytes, got: {:?}",
        err
    );
}
