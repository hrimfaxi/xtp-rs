use crate::sniff::is_valid_sni_hostname;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSniffError {
    PeekEmpty,
    InsufficientPrefix,
    ProtocolNotMatched,
    TlsNoSni,
    ParseError,
    InvalidHostname,
    TooLargeClientHello,
}

pub fn be_u16(b: &[u8]) -> Result<u16, TlsSniffError> {
    if b.len() < 2 {
        return Err(TlsSniffError::ParseError);
    }
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

pub fn be_u24(b: &[u8]) -> Result<usize, TlsSniffError> {
    if b.len() < 3 {
        return Err(TlsSniffError::ParseError);
    }
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
}

pub fn parse_sni_from_client_hello_body(body: &[u8]) -> Result<String, TlsSniffError> {
    if body.len() < 2 + 32 + 1 {
        return Err(TlsSniffError::ParseError);
    }

    let mut off = 0usize;

    let mut saw_ech = false;
    let mut found_sni: Option<String> = None;

    off += 2; // legacy_version
    off += 32; // random

    let session_id_len = *body.get(off).ok_or(TlsSniffError::ParseError)? as usize;
    off += 1;
    if off + session_id_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }
    off += session_id_len;

    let cipher_suites_len =
        be_u16(body.get(off..off + 2).ok_or(TlsSniffError::ParseError)?)? as usize;
    off += 2;
    if cipher_suites_len == 0
        || !cipher_suites_len.is_multiple_of(2)
        || off + cipher_suites_len > body.len()
    {
        return Err(TlsSniffError::ParseError);
    }
    off += cipher_suites_len;

    let compression_methods_len = *body.get(off).ok_or(TlsSniffError::ParseError)? as usize;
    off += 1;
    if compression_methods_len == 0 || off + compression_methods_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }
    off += compression_methods_len;

    if off == body.len() {
        return Err(TlsSniffError::TlsNoSni);
    }

    let extensions_len = be_u16(body.get(off..off + 2).ok_or(TlsSniffError::ParseError)?)? as usize;
    off += 2;
    if off + extensions_len > body.len() {
        return Err(TlsSniffError::ParseError);
    }

    let ext_end = off + extensions_len;
    while off + 4 <= ext_end {
        let ext_type = be_u16(&body[off..off + 2])?;
        let ext_len = be_u16(&body[off + 2..off + 4])? as usize;
        off += 4;

        if off + ext_len > ext_end {
            return Err(TlsSniffError::ParseError);
        }

        match ext_type {
            0xfe0d => {
                saw_ech = true;
            }
            0x0000 => {
                let ext = &body[off..off + ext_len];
                if ext.len() < 2 {
                    return Err(TlsSniffError::ParseError);
                }

                let list_len = be_u16(&ext[0..2])? as usize;
                if list_len + 2 != ext.len() {
                    return Err(TlsSniffError::ParseError);
                }

                let mut p = 2usize;
                while p + 3 <= ext.len() {
                    let name_type = ext[p];
                    let name_len = be_u16(&ext[p + 1..p + 3])? as usize;
                    p += 3;

                    if p + name_len > ext.len() {
                        return Err(TlsSniffError::ParseError);
                    }

                    if name_type == 0 {
                        let host = std::str::from_utf8(&ext[p..p + name_len])
                            .map_err(|_| TlsSniffError::InvalidHostname)?
                            .to_ascii_lowercase();

                        if !is_valid_sni_hostname(&host) {
                            return Err(TlsSniffError::InvalidHostname);
                        }

                        found_sni = Some(host);
                    }

                    p += name_len;
                }

                if p != ext.len() {
                    return Err(TlsSniffError::ParseError);
                }
            }
            _ => {}
        }

        off += ext_len;
    }

    if off != ext_end {
        return Err(TlsSniffError::ParseError);
    }

    // 扫描完所有扩展后统一决定：
    // 如果有 ECH，按无目标处理（无法解密 inner SNI）
    if saw_ech {
        return Err(TlsSniffError::TlsNoSni);
    }

    match found_sni {
        Some(host) => Ok(host),
        None => Err(TlsSniffError::TlsNoSni),
    }
}
