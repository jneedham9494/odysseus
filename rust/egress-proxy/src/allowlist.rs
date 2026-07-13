//! The core egress decision: is a target host allowed to leave the boundary?
//!
//! This module is pure (no I/O) so the security-critical logic is exhaustively
//! unit-testable. Policy, in order:
//!
//! 1. Empty/malformed host        -> REFUSE (`InvalidHost`).
//! 2. Host is a raw IP literal     -> REFUSE. If the literal is a private /
//!    loopback / link-local (incl. the 169.254.169.254 cloud metadata
//!    endpoint) / CGNAT / multicast address the reason is `ForbiddenAddress`,
//!    otherwise `IpLiteral`. Named hosts only — literals never pass.
//! 3. Allowlist is empty           -> REFUSE (`EmptyAllowlist`, deny-all).
//! 4. Host matches an allow entry  -> ALLOW.
//! 5. Otherwise                     -> REFUSE (`NotAllowlisted`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Outcome of an egress decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Refuse(RefuseReason),
}

impl Decision {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Why a request was refused. Stable enough to log and assert on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// No allowlist configured — fail-closed deny-all.
    EmptyAllowlist,
    /// Target was a raw (public) IP literal; only named hosts may pass.
    IpLiteral,
    /// Target resolves to a private/loopback/link-local/metadata/CGNAT address.
    ForbiddenAddress,
    /// Named host is not on the allowlist.
    NotAllowlisted,
    /// Host was empty or otherwise unparseable.
    InvalidHost,
}

impl RefuseReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RefuseReason::EmptyAllowlist => "no allowlist configured (deny-all)",
            RefuseReason::IpLiteral => "raw IP literal not permitted",
            RefuseReason::ForbiddenAddress => "private/loopback/metadata address refused",
            RefuseReason::NotAllowlisted => "host not on egress allowlist",
            RefuseReason::InvalidHost => "empty or malformed host",
        }
    }
}

/// A single allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// Matches exactly this host.
    Exact(String),
    /// Matches any subdomain of the stored parent (e.g. `.example.com`).
    /// Built from a `*.example.com` or `.example.com` entry.
    Suffix(String),
}

/// An immutable set of allowed host patterns.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    entries: Vec<HostPattern>,
}

impl Allowlist {
    /// Build an allowlist from raw entries. Blank lines and `#` comments are
    /// ignored; entries are normalised to lowercase. `*.example.com` and
    /// `.example.com` become subdomain-suffix matches.
    pub fn from_entries<I, S>(raw: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut entries = Vec::new();
        for item in raw {
            let line = item.as_ref().trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let host = line.to_ascii_lowercase();
            if let Some(rest) = host.strip_prefix("*.") {
                entries.push(HostPattern::Suffix(format!(".{rest}")));
            } else if host.starts_with('.') {
                entries.push(HostPattern::Suffix(host));
            } else {
                entries.push(HostPattern::Exact(host));
            }
        }
        Allowlist { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn matches(&self, host: &str) -> bool {
        self.entries.iter().any(|p| match p {
            HostPattern::Exact(h) => h == host,
            HostPattern::Suffix(suffix) => host.ends_with(suffix.as_str()),
        })
    }
}

/// Normalise a host: lowercase, strip a trailing dot, strip IPv6 brackets.
fn normalise_host(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.');
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.to_ascii_lowercase()
}

/// Return true if `ip` must never be reachable through the proxy: private,
/// loopback, link-local (includes 169.254.169.254 metadata), CGNAT, multicast,
/// documentation, broadcast or unspecified. IPv4-mapped IPv6 is unwrapped and
/// re-checked so `::ffff:169.254.169.254` cannot slip through.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_v4(mapped);
            }
            if let Some(compat) = v6.to_ipv4() {
                return is_forbidden_v4(compat);
            }
            is_forbidden_v6(v6)
        }
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()          // 10/8, 172.16/12, 192.168/16
        || ip.is_loopback()  // 127/8
        || ip.is_link_local()// 169.254/16 (cloud metadata lives here)
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0              // 0.0.0.0/8 "this host"
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64/10 CGNAT
        || o[0] >= 240 // 240/4 reserved
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// The one true egress decision for a target `host`.
pub fn decide(host: &str, allowlist: &Allowlist) -> Decision {
    let host = normalise_host(host);
    if host.is_empty() {
        return Decision::Refuse(RefuseReason::InvalidHost);
    }

    // IP literals are refused before consulting the allowlist so a raw address
    // can never be smuggled past name-based rules.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_forbidden_ip(ip) {
            Decision::Refuse(RefuseReason::ForbiddenAddress)
        } else {
            Decision::Refuse(RefuseReason::IpLiteral)
        };
    }

    if allowlist.is_empty() {
        return Decision::Refuse(RefuseReason::EmptyAllowlist);
    }
    if allowlist.matches(&host) {
        Decision::Allow
    } else {
        Decision::Refuse(RefuseReason::NotAllowlisted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(hosts: &[&str]) -> Allowlist {
        Allowlist::from_entries(hosts.iter().copied())
    }

    #[test]
    fn allowlisted_host_passes() {
        let al = allow(&["api.openai.com", "example.com"]);
        assert_eq!(decide("api.openai.com", &al), Decision::Allow);
        assert_eq!(decide("EXAMPLE.com.", &al), Decision::Allow); // case + trailing dot
    }

    #[test]
    fn non_allowlisted_host_refused() {
        let al = allow(&["api.openai.com"]);
        assert_eq!(
            decide("evil.example.net", &al),
            Decision::Refuse(RefuseReason::NotAllowlisted)
        );
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let al = allow(&[]);
        assert!(al.is_empty());
        assert_eq!(
            decide("api.openai.com", &al),
            Decision::Refuse(RefuseReason::EmptyAllowlist)
        );
    }

    #[test]
    fn public_ip_literal_refused() {
        let al = allow(&["example.com"]);
        assert_eq!(
            decide("93.184.216.34", &al),
            Decision::Refuse(RefuseReason::IpLiteral)
        );
    }

    #[test]
    fn cloud_metadata_endpoint_refused() {
        let al = allow(&["example.com"]);
        assert_eq!(
            decide("169.254.169.254", &al),
            Decision::Refuse(RefuseReason::ForbiddenAddress)
        );
        // IPv4-mapped form must not bypass it.
        assert_eq!(
            decide("[::ffff:169.254.169.254]", &al),
            Decision::Refuse(RefuseReason::ForbiddenAddress)
        );
    }

    #[test]
    fn rfc1918_addresses_refused() {
        let al = allow(&["example.com"]);
        for ip in ["10.0.0.5", "172.16.9.9", "192.168.1.1"] {
            assert_eq!(
                decide(ip, &al),
                Decision::Refuse(RefuseReason::ForbiddenAddress),
                "{ip} should be forbidden"
            );
        }
    }

    #[test]
    fn wildcard_matches_subdomains_only() {
        let al = allow(&["*.example.com"]);
        assert_eq!(decide("api.example.com", &al), Decision::Allow);
        assert_eq!(decide("a.b.example.com", &al), Decision::Allow);
        assert_eq!(
            decide("example.com", &al),
            Decision::Refuse(RefuseReason::NotAllowlisted)
        );
        // Suffix must be on a dot boundary, not a substring.
        assert_eq!(
            decide("notexample.com", &al),
            Decision::Refuse(RefuseReason::NotAllowlisted)
        );
    }

    #[test]
    fn empty_host_is_invalid() {
        let al = allow(&["example.com"]);
        assert_eq!(
            decide("   ", &al),
            Decision::Refuse(RefuseReason::InvalidHost)
        );
    }
}
