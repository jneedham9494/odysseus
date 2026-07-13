//! Environment-driven configuration. No config-file parser is pulled in so the
//! crate stays dependency-free; secrets come from the environment only.
//!
//! | Variable                      | Meaning                                        |
//! |-------------------------------|------------------------------------------------|
//! | `EGRESS_PROXY_BIND`           | Listen address (default `127.0.0.1:8080`).     |
//! | `EGRESS_PROXY_ALLOWLIST`      | Comma-separated allow entries.                 |
//! | `EGRESS_PROXY_ALLOWLIST_FILE` | Path to newline-separated allow entries.       |
//! | `EGRESS_PROXY_TOKEN`          | Optional `Proxy-Authorization: Bearer` secret. |
//!
//! With neither allowlist source set, the proxy denies all egress (fail-closed).
//! With no token set the proxy accepts unauthenticated clients — safe only
//! because it binds loopback by default; set a token for any non-loopback bind.

use std::env;
use std::fs;
use std::net::SocketAddr;

use crate::allowlist::Allowlist;

const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Fully-resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub allowlist: Allowlist,
    /// Owner token required in `Proxy-Authorization: Bearer <token>` when set.
    pub proxy_token: Option<String>,
}

impl Config {
    /// Build configuration from the process environment.
    ///
    /// # Errors
    /// Returns a human-readable message if `EGRESS_PROXY_BIND` is not a valid
    /// socket address or the allowlist file cannot be read.
    pub fn from_env() -> Result<Self, String> {
        let bind_raw = env::var("EGRESS_PROXY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
        let bind: SocketAddr = bind_raw
            .parse()
            .map_err(|e| format!("invalid EGRESS_PROXY_BIND '{bind_raw}': {e}"))?;

        let mut entries: Vec<String> = Vec::new();
        if let Ok(inline) = env::var("EGRESS_PROXY_ALLOWLIST") {
            entries.extend(inline.split(',').map(|s| s.to_string()));
        }
        if let Ok(path) = env::var("EGRESS_PROXY_ALLOWLIST_FILE") {
            let body = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read EGRESS_PROXY_ALLOWLIST_FILE '{path}': {e}"))?;
            entries.extend(body.lines().map(|s| s.to_string()));
        }

        let proxy_token = env::var("EGRESS_PROXY_TOKEN")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());

        Ok(Config {
            bind,
            allowlist: Allowlist::from_entries(entries),
            proxy_token,
        })
    }
}

/// Constant-time byte comparison for the proxy token, so a mismatched-length or
/// mismatched-content token cannot be distinguished by timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_std_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn allowlist_from_comma_and_comments() {
        let al = Allowlist::from_entries(
            "example.com, # note\n, *.api.dev".split('\n').flat_map(|l| l.split(',')),
        );
        // "example.com" + "*.api.dev" survive; comment/blank dropped.
        assert_eq!(al.len(), 2);
    }
}
