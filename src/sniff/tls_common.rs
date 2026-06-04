use tracing::trace;

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
            0xfe0d | 0xff07 => {
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
        trace!(
            body_len = body.len(),
            "tls sniff: ECH detected, inner SNI encrypted"
        );
        return Err(TlsSniffError::TlsNoSni);
    }

    match found_sni {
        Some(host) => Ok(host),
        None => Err(TlsSniffError::TlsNoSni),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // ----- 辅助函数：构造最小 ClientHello body -----
    pub fn client_hello_body(sni: Option<&str>, ech: bool) -> Vec<u8> {
        let mut body = Vec::new();
        // legacy_version (TLS 1.2)
        body.extend_from_slice(&[0x03, 0x03]);
        // random (32 bytes)
        body.extend_from_slice(&[0u8; 32]);
        // session_id (length 0)
        body.push(0);
        // cipher_suites (length 2, one suite)
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        // compression_methods (length 1, method null)
        body.extend_from_slice(&[0x01, 0x00]);

        // extensions
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let host_bytes = host.as_bytes();
            let name_len = host_bytes.len();
            // server_name_list 内容：1 byte name_type, 2 bytes name_length, name_data
            let sni_list_len = 3 + name_len; // name_type(1) + name_length(2) + name_data
            let ext_data_len = 2 + sni_list_len; // 2 bytes for server_name_list length
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&[0x00, 0x00]); // extension type: server_name
            sni_ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
            sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
            sni_ext.push(0x00); // name_type = host_name
            sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
            sni_ext.extend_from_slice(host_bytes);
            exts.extend_from_slice(&sni_ext);
        }
        if ech {
            // ECH extension: type 0xfe0d, empty payload
            let mut ech_ext = Vec::new();
            ech_ext.extend_from_slice(&[0xfe, 0x0d]);
            ech_ext.extend_from_slice(&[0x00, 0x00]); // zero-length payload
            exts.extend_from_slice(&ech_ext);
        }
        // 写入 extensions 总长度及数据
        if !exts.is_empty() {
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
        }
        body
    }

    #[test]
    fn be_u16_works() {
        assert_eq!(be_u16(&[0x12, 0x34]).unwrap(), 0x1234);
        assert!(be_u16(&[0x12]).is_err());
    }

    #[test]
    fn be_u24_works() {
        assert_eq!(be_u24(&[0x01, 0x02, 0x03]).unwrap(), 0x010203);
        assert!(be_u24(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn parse_sni_valid() {
        let body = client_hello_body(Some("example.com"), false);
        let host = parse_sni_from_client_hello_body(&body).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn sni_lowercase() {
        let body = client_hello_body(Some("EXAMPLE.COM"), false);
        let host = parse_sni_from_client_hello_body(&body).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn no_extensions() {
        // 无 extensions 的 body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session_id
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]); // compressions
        // 没有 extensions length → off == body.len()
        assert_eq!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::TlsNoSni)
        );
    }

    #[test]
    fn ech_returns_no_sni_even_with_outer_sni() {
        let body = client_hello_body(Some("example.com"), true);
        assert_eq!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::TlsNoSni)
        );
    }

    #[test]
    fn invalid_sni_hostname() {
        // 非法 hostname（空字符串）
        let body = client_hello_body(Some(""), false);
        assert!(matches!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::InvalidHostname)
        ));
    }

    #[test]
    fn invalid_utf8_sni() {
        let mut body = client_hello_body(Some("example.com"), false);
        let pos = body
            .windows(b"example.com".len())
            .position(|w| w == b"example.com")
            .unwrap();
        body[pos] = 0xff; // 非法 UTF-8
        assert_eq!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::InvalidHostname)
        );
    }

    #[test]
    fn cipher_suites_odd_length() {
        // 在 cipher_suites_len 后减少一个字节，使长度变为奇数
        // 简便方法：直接在构建时写入奇数长度
        // 这里手动构建一个异常 body
        let mut bad = vec![0x03, 0x03];
        bad.extend_from_slice(&[0u8; 32]);
        bad.push(0); // session_id len=0
        bad.extend_from_slice(&[0x00, 0x03]); // cipher_suites_len=3 (奇数)
        bad.extend_from_slice(&[0x00, 0xff, 0x00]); // 3字节
        bad.extend_from_slice(&[0x01, 0x00]); // compressions
        // 无 extensions
        assert_eq!(
            parse_sni_from_client_hello_body(&bad),
            Err(TlsSniffError::ParseError)
        );
    }

    #[test]
    fn compression_methods_len_zero() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session_id
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x00]); // compressions_len=0，错误
        assert_eq!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::ParseError)
        );
    }

    #[test]
    fn sni_list_length_mismatch() {
        let mut body = client_hello_body(Some("example.com"), false);

        let pos = body
            .windows(b"example.com".len())
            .position(|w| w == b"example.com")
            .unwrap();

        // SNI 扩展里 list_len 在 host 前 5 字节附近：
        // ext_type(2), ext_len(2), list_len(2), name_type(1), name_len(2), host
        // 这里简单从 host 位置往前推到 list_len。
        let list_len_pos = pos - 5;
        body[list_len_pos] = 0x00;
        body[list_len_pos + 1] = 0x01;

        assert_eq!(
            parse_sni_from_client_hello_body(&body),
            Err(TlsSniffError::ParseError)
        );
    }
}
