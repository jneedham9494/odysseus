//! SSRF-safe DNS resolution and bidirectional byte tunnelling.
//!
//! Even when a *name* is on the allowlist, the address it resolves to might be
//! private/loopback/metadata (a DNS-rebinding attack). [`filter_safe_addrs`]
//! drops every forbidden resolved address; if none remain the connection is
//! refused. This is unit-tested with injected addresses (no live DNS).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::allowlist::is_forbidden_ip;

/// Keep only resolved addresses that are not forbidden, returning the safe set
/// and the count that was dropped (for logging).
pub fn filter_safe_addrs<I: IntoIterator<Item = SocketAddr>>(addrs: I) -> (Vec<SocketAddr>, usize) {
    let mut safe = Vec::new();
    let mut dropped = 0usize;
    for addr in addrs {
        if is_forbidden_ip(addr.ip()) {
            dropped += 1;
        } else {
            safe.push(addr);
        }
    }
    (safe, dropped)
}

/// Resolve `host:port` and return only safe upstream addresses.
///
/// # Errors
/// Returns an error when resolution fails or every resolved address is
/// forbidden (fail-closed — we never fall back to a raw connect).
pub fn safe_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    // Strip IPv6 brackets for the resolver; `to_socket_addrs` wants bare form.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let resolved = (bare, port).to_socket_addrs()?;
    let (safe, dropped) = filter_safe_addrs(resolved);
    if safe.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("all {dropped} resolved address(es) for {host} are forbidden"),
        ));
    }
    Ok(safe)
}

/// Connect to the first reachable safe upstream address.
pub fn connect_upstream(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, "no upstream addresses")
    }))
}

/// Pump bytes both ways between two streams until each side reaches EOF.
pub fn tunnel(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let client_reader = client.try_clone()?;
    let upstream_writer = upstream.try_clone()?;

    let up = thread::spawn(move || copy_and_close(client_reader, upstream_writer));
    // client <- upstream in the current thread.
    let _ = copy_and_close(upstream, client);
    let _ = up.join();
    Ok(())
}

/// Copy `from` -> `to` then half-close `to` so the peer observes EOF.
fn copy_and_close(mut from: TcpStream, mut to: TcpStream) -> io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..n])?;
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 443)
    }

    #[test]
    fn filter_drops_private_and_metadata_keeps_public() {
        let addrs = vec![
            v4(10, 0, 0, 1),         // private
            v4(169, 254, 169, 254),  // metadata
            v4(93, 184, 216, 34),    // public
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443), // loopback
        ];
        let (safe, dropped) = filter_safe_addrs(addrs);
        assert_eq!(dropped, 3);
        assert_eq!(safe, vec![v4(93, 184, 216, 34)]);
    }

    #[test]
    fn filter_all_forbidden_yields_empty() {
        let (safe, dropped) = filter_safe_addrs(vec![v4(127, 0, 0, 1), v4(192, 168, 0, 1)]);
        assert!(safe.is_empty());
        assert_eq!(dropped, 2);
    }
}
