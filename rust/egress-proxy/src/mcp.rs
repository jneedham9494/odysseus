//! Placeholder for an rmcp-based MCP server interface. **Disabled by default.**
//!
//! # Why this is only a stub today
//!
//! An MCP server is a new *inbound* entry point. Per the odysseus security
//! model, a new interface is a new attack surface and must ship **off** until
//! it is:
//!
//! 1. Authenticated as owner-only (reuse `EGRESS_PROXY_TOKEN`-style secret; no
//!    token configured == interface disabled), and
//! 2. Routed through the existing approval queue (`src/pending_actions.py`)
//!    with the taint model and Phase-4 autonomy guard — never a side door that
//!    bypasses the boundary.
//!
//! The core deliverable of this crate — the fail-closed egress allowlist proxy
//! — needs none of that and is complete without it.
//!
//! # Next step (documented, intentionally not implemented)
//!
//! Add the `rmcp` crate under the `mcp` cargo feature and expose read-only
//! tools that report policy, e.g.:
//!
//! - `egress_policy` — return the current allowlist + bind + auth mode.
//! - `egress_check { host }` — run [`crate::allowlist::decide`] and return the
//!   `Decision` WITHOUT performing any network I/O (pure, side-effect free).
//!
//! Any *mutating* tool (e.g. adding an allowlist entry) must enqueue a pending
//! action for owner approval rather than taking effect directly.
//!
//! ```ignore
//! // Cargo.toml (under the `mcp` feature):
//! //   rmcp = { version = "0.x", features = ["server", "transport-io"] }
//! //
//! // #[tool(name = "egress_check")]
//! // async fn egress_check(&self, host: String) -> String {
//! //     format!("{:?}", egress_proxy::allowlist::decide(&host, &self.allowlist))
//! // }
//! ```

/// Whether the MCP interface is compiled in. Always `false` unless the `mcp`
/// cargo feature is enabled (and even then it currently only compiles a stub).
pub const MCP_ENABLED: bool = cfg!(feature = "mcp");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn mcp_disabled_by_default() {
        // Guards the "new interfaces ship disabled" invariant for the default
        // build used by the deployment. Intentionally a compile-time constant:
        // the default build must never compile the MCP interface in.
        assert!(!MCP_ENABLED);
    }
}
