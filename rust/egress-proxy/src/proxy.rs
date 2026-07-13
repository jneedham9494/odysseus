//! The blocking TCP forward-proxy server.
//!
//! One thread per connection (this sits on an internal boundary with modest
//! concurrency, so a thread-per-conn model keeps the code simple and audit-
//! able). Every request runs [`crate::allowlist::decide`] before any upstream
//! socket is opened; refusals return an HTTP error and never connect out.

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use crate::allowlist::{decide, Decision};
use crate::config::{constant_time_eq, Config};
use crate::net::{connect_upstream, safe_resolve, tunnel};
use crate::request::{parse_head, read_head, RequestHead};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of authenticating a request against the optional proxy token.
enum AuthOutcome {
    Ok,
    Required,
}

/// Bind and serve forever. Blocks the calling thread.
pub fn serve(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(config.bind)?;
    let config = std::sync::Arc::new(config);
    eprintln!(
        "egress-proxy listening on {} | allowlist entries: {} | auth: {} | policy: fail-closed",
        config.bind,
        config.allowlist.len(),
        if config.proxy_token.is_some() {
            "token-required"
        } else {
            "none (loopback only)"
        },
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = config.clone();
                thread::spawn(move || {
                    if let Err(e) = handle(stream, &cfg) {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

/// Handle a single client connection end-to-end.
pub fn handle(mut client: TcpStream, config: &Config) -> io::Result<()> {
    let (raw, leftover) = read_head(&mut client)?;
    let head = match parse_head(raw, leftover) {
        Ok(h) => h,
        Err(msg) => return write_status(&mut client, 400, "Bad Request", &msg),
    };

    if let AuthOutcome::Required = authenticate(&head, config) {
        return write_proxy_auth_required(&mut client);
    }

    match decide(&head.host, &config.allowlist) {
        Decision::Allow => forward(client, head),
        Decision::Refuse(reason) => {
            eprintln!("REFUSE {}:{} — {}", head.host, head.port, reason.as_str());
            write_status(&mut client, 403, "Forbidden", reason.as_str())
        }
    }
}

/// Check the optional owner token via `Proxy-Authorization: Bearer <token>`.
fn authenticate(head: &RequestHead, config: &Config) -> AuthOutcome {
    let Some(expected) = config.proxy_token.as_deref() else {
        return AuthOutcome::Ok; // no token configured -> auth disabled
    };
    let presented = head
        .proxy_auth
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        AuthOutcome::Ok
    } else {
        AuthOutcome::Required
    }
}

/// Open the safe upstream connection and splice traffic.
fn forward(mut client: TcpStream, head: RequestHead) -> io::Result<()> {
    let addrs = match safe_resolve(&head.host, head.port) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("REFUSE {}:{} — {e}", head.host, head.port);
            return write_status(&mut client, 403, "Forbidden", "resolution refused");
        }
    };
    let mut upstream = match connect_upstream(&addrs, CONNECT_TIMEOUT) {
        Ok(u) => u,
        Err(e) => return write_status(&mut client, 502, "Bad Gateway", &e.to_string()),
    };

    if head.is_connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        // Absolute-form request: replay the original head (and any early body)
        // to the origin, then splice the rest. Simple and correct for
        // connection-close semantics.
        upstream.write_all(&head.raw)?;
        if !head.leftover.is_empty() {
            upstream.write_all(&head.leftover)?;
        }
    }
    tunnel(client, upstream)
}

fn write_status(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> io::Result<()> {
    let payload = format!("egress-proxy: {body}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{payload}",
        payload.len()
    );
    stream.write_all(response.as_bytes())
}

fn write_proxy_auth_required(stream: &mut TcpStream) -> io::Result<()> {
    let body = "egress-proxy: owner token required\n";
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Bearer realm=\"egress-proxy\"\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}
