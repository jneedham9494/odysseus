//! End-to-end policy tests exercised through the public crate API (no network).
//! These assert the security-critical invariants a reviewer cares about.

use egress_proxy::allowlist::{decide, is_forbidden_ip};
use egress_proxy::net::filter_safe_addrs;
use egress_proxy::{Allowlist, Decision, RefuseReason};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn al(hosts: &[&str]) -> Allowlist {
    Allowlist::from_entries(hosts.iter().copied())
}

#[test]
fn allowlisted_host_is_the_only_thing_that_passes() {
    let list = al(["api.openai.com", "*.githubusercontent.com"].as_ref());
    assert!(decide("api.openai.com", &list).is_allowed());
    assert!(decide("raw.githubusercontent.com", &list).is_allowed());
    assert!(!decide("attacker.example", &list).is_allowed());
}

#[test]
fn dangerous_targets_are_refused_even_when_allowlist_is_populated() {
    let list = al(["api.openai.com"].as_ref());
    let cases = [
        ("169.254.169.254", RefuseReason::ForbiddenAddress), // cloud metadata
        ("10.1.2.3", RefuseReason::ForbiddenAddress),        // RFC1918
        ("192.168.0.10", RefuseReason::ForbiddenAddress),    // RFC1918
        ("127.0.0.1", RefuseReason::ForbiddenAddress),       // loopback
        ("0.0.0.0", RefuseReason::ForbiddenAddress),         // this-host
        ("100.64.0.1", RefuseReason::ForbiddenAddress),      // CGNAT
        ("[::1]", RefuseReason::ForbiddenAddress),           // ipv6 loopback
        ("[fc00::1]", RefuseReason::ForbiddenAddress),       // ipv6 unique-local
        ("[fe80::1]", RefuseReason::ForbiddenAddress),       // ipv6 link-local
        ("8.8.8.8", RefuseReason::IpLiteral),                // public IP literal
        ("attacker.example", RefuseReason::NotAllowlisted),  // off-list name
    ];
    for (host, want) in cases {
        assert_eq!(
            decide(host, &list),
            Decision::Refuse(want),
            "host {host} expected refusal {want:?}"
        );
    }
}

#[test]
fn allowlist_ignores_comments_and_blanks() {
    let list = al(["# a comment", "", "  ", "example.com"].as_ref());
    assert_eq!(list.len(), 1);
    assert!(decide("example.com", &list).is_allowed());
}

#[test]
fn no_allowlist_is_deny_all_fail_closed() {
    let list = al(&[]);
    assert_eq!(
        decide("api.openai.com", &list),
        Decision::Refuse(RefuseReason::EmptyAllowlist)
    );
}

#[test]
fn resolved_metadata_address_is_dropped_for_allowlisted_name() {
    // Simulates DNS rebinding: an allowlisted name resolving to the metadata IP.
    let metadata = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 443);
    assert!(is_forbidden_ip(metadata.ip()));
    let (safe, dropped) = filter_safe_addrs([metadata]);
    assert!(safe.is_empty());
    assert_eq!(dropped, 1);
}
