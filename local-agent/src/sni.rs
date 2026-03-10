use thiserror::Error;

#[derive(Debug, Error)]
pub enum SniError {
    #[error("not a TLS handshake record")]
    NotTlsHandshake,
    #[error("not a ClientHello message")]
    NotClientHello,
    #[error("buffer too short: needed {needed} bytes, only {available} available")]
    BufferTooShort { needed: usize, available: usize },
    #[error("no SNI extension found in ClientHello")]
    NoSniExtension,
    #[error("invalid hostname in SNI extension")]
    InvalidHostname,
}

/// Check that `buf` has at least `needed` bytes starting from `offset`.
fn check_len(buf: &[u8], offset: usize, needed: usize) -> Result<(), SniError> {
    if buf.len() < offset + needed {
        Err(SniError::BufferTooShort {
            needed: offset + needed,
            available: buf.len(),
        })
    } else {
        Ok(())
    }
}

fn read_u16_be(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Extract the SNI hostname from a TLS ClientHello message.
///
/// Parses the TLS record header, handshake header, and ClientHello fields
/// to locate the server_name (SNI) extension and return its hostname value.
pub fn extract_sni(buf: &[u8]) -> Result<String, SniError> {
    // 1. TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    check_len(buf, 0, 5)?;

    if buf[0] != 0x16 {
        return Err(SniError::NotTlsHandshake);
    }
    if buf[1] != 0x03 {
        return Err(SniError::NotTlsHandshake);
    }

    // 2. Handshake type at offset 5
    check_len(buf, 5, 1)?;
    if buf[5] != 0x01 {
        return Err(SniError::NotClientHello);
    }

    // 3. Skip handshake length (3 bytes at offset 6)
    check_len(buf, 6, 3)?;

    // 4. Client version (2 bytes at offset 9)
    check_len(buf, 9, 2)?;

    // 5. Random (32 bytes at offset 11)
    check_len(buf, 11, 32)?;

    let mut pos = 43;

    // 6. Session ID length (1 byte) + session ID
    check_len(buf, pos, 1)?;
    let session_id_len = buf[pos] as usize;
    pos += 1;
    check_len(buf, pos, session_id_len)?;
    pos += session_id_len;

    // 7. Cipher suites length (2 bytes BE) + cipher suites
    check_len(buf, pos, 2)?;
    let cipher_suites_len = read_u16_be(buf, pos) as usize;
    pos += 2;
    check_len(buf, pos, cipher_suites_len)?;
    pos += cipher_suites_len;

    // 8. Compression methods length (1 byte) + compression methods
    check_len(buf, pos, 1)?;
    let comp_methods_len = buf[pos] as usize;
    pos += 1;
    check_len(buf, pos, comp_methods_len)?;
    pos += comp_methods_len;

    // 9. Extensions length (2 bytes BE)
    if pos >= buf.len() {
        return Err(SniError::NoSniExtension);
    }
    check_len(buf, pos, 2)?;
    let extensions_len = read_u16_be(buf, pos) as usize;
    pos += 2;
    check_len(buf, pos, extensions_len)?;

    let extensions_end = pos + extensions_len;

    // 10. Parse extensions
    while pos + 4 <= extensions_end {
        let ext_type = read_u16_be(buf, pos);
        let ext_data_len = read_u16_be(buf, pos + 2) as usize;
        pos += 4;

        check_len(buf, pos, ext_data_len)?;

        if ext_type == 0x0000 {
            // 11-12. Parse server_name extension
            return parse_server_name_extension(&buf[pos..pos + ext_data_len]);
        }

        pos += ext_data_len;
    }

    Err(SniError::NoSniExtension)
}

/// Parse the server_name extension payload to extract the hostname.
fn parse_server_name_extension(data: &[u8]) -> Result<String, SniError> {
    // server_name_list_length (2B)
    if data.len() < 2 {
        return Err(SniError::BufferTooShort {
            needed: 2,
            available: data.len(),
        });
    }
    let _list_len = read_u16_be(data, 0);
    let mut pos = 2;

    // name_type (1B) — must be 0x00 for host_name
    if data.len() < pos + 1 {
        return Err(SniError::BufferTooShort {
            needed: pos + 1,
            available: data.len(),
        });
    }
    let name_type = data[pos];
    pos += 1;

    if name_type != 0x00 {
        return Err(SniError::NoSniExtension);
    }

    // host_name_length (2B)
    if data.len() < pos + 2 {
        return Err(SniError::BufferTooShort {
            needed: pos + 2,
            available: data.len(),
        });
    }
    let name_len = read_u16_be(data, pos) as usize;
    pos += 2;

    // hostname bytes
    if data.len() < pos + name_len {
        return Err(SniError::BufferTooShort {
            needed: pos + name_len,
            available: data.len(),
        });
    }
    let name_bytes = &data[pos..pos + name_len];

    // Validate: must be valid UTF-8 and ASCII
    let hostname = std::str::from_utf8(name_bytes).map_err(|_| SniError::InvalidHostname)?;
    if !hostname.is_ascii() {
        return Err(SniError::InvalidHostname);
    }

    Ok(hostname.to_string())
}
