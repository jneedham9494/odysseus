//! Minimal, bounded parsing of an HTTP/1.x proxy request head.
//!
//! We only extract what the allowlist decision and forwarding need: the method,
//! the target host and port, and whether this is a `CONNECT` tunnel. The head
//! is size-limited to defend against unbounded-read abuse.

use std::io::{self, Read};

/// Hard cap on the request head we will buffer (protects against a client that
/// never sends the terminating blank line).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// A parsed request head plus any bytes already read past it (early body).
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub host: String,
    pub port: u16,
    pub is_connect: bool,
    /// Value of the `Proxy-Authorization` header, if present.
    pub proxy_auth: Option<String>,
    /// Raw head bytes (request line + headers + terminating CRLFCRLF).
    pub raw: Vec<u8>,
    /// Bytes read from the socket that belong after the head.
    pub leftover: Vec<u8>,
}

/// Read from `stream` until the end of the header block (`\r\n\r\n`).
pub fn read_head<R: Read>(stream: &mut R) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before end of request head",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok((buf, Vec::new()));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head exceeded size limit",
            ));
        }
    }
}

/// Parse an already-read head block into a [`RequestHead`].
pub fn parse_head(raw: Vec<u8>, leftover: Vec<u8>) -> Result<RequestHead, String> {
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let target = parts.next().ok_or("missing request target")?.to_string();

    let mut host_header: Option<String> = None;
    let mut proxy_auth: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            match name.as_str() {
                "host" => host_header = Some(value),
                "proxy-authorization" => proxy_auth = Some(value),
                _ => {}
            }
        }
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let (host, port) = if is_connect {
        split_host_port(&target, 443).ok_or("invalid CONNECT target")?
    } else if let Some(authority) = authority_from_absolute(&target) {
        split_host_port(authority, 80).ok_or("invalid absolute-form target")?
    } else if let Some(h) = host_header.as_deref() {
        // Origin-form request from a client using us as a plain gateway.
        split_host_port(h, 80).ok_or("invalid Host header")?
    } else {
        return Err("cannot determine target host".to_string());
    };

    Ok(RequestHead {
        method,
        host,
        port,
        is_connect,
        proxy_auth,
        raw,
        leftover,
    })
}

/// Extract the authority from an absolute-form target like
/// `http://host:port/path`. Returns `None` for origin-form (`/path`).
fn authority_from_absolute(target: &str) -> Option<&str> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    let end = rest.find('/').unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Split `host:port` (default when no port), honouring `[ipv6]:port` bracketing.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let (inside, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        return Some((format!("[{inside}]"), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((authority.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> RequestHead {
        parse_head(raw.as_bytes().to_vec(), Vec::new()).expect("parse")
    }

    #[test]
    fn parses_connect_target() {
        let h = head("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n");
        assert!(h.is_connect);
        assert_eq!(h.host, "api.example.com");
        assert_eq!(h.port, 443);
    }

    #[test]
    fn parses_absolute_form_get() {
        let h = head("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(!h.is_connect);
        assert_eq!(h.host, "example.com");
        assert_eq!(h.port, 80);
    }

    #[test]
    fn parses_absolute_form_with_port() {
        let h = head("GET http://example.com:8443/x HTTP/1.1\r\nHost: example.com:8443\r\n\r\n");
        assert_eq!(h.port, 8443);
    }

    #[test]
    fn extracts_proxy_authorization() {
        let h = head(
            "CONNECT x.io:443 HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\nHost: x.io\r\n\r\n",
        );
        assert_eq!(h.proxy_auth.as_deref(), Some("Bearer abc"));
    }

    #[test]
    fn origin_form_uses_host_header() {
        let h = head("GET /path HTTP/1.1\r\nHost: origin.example.com\r\n\r\n");
        assert_eq!(h.host, "origin.example.com");
    }

    #[test]
    fn ipv6_connect_target() {
        let h = head("CONNECT [2606:4700::1]:443 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(h.host, "[2606:4700::1]");
        assert_eq!(h.port, 443);
    }
}
