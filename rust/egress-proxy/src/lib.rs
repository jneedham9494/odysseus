//! Egress-allowlist HTTP forward-proxy for the odysseus trust boundary.
//!
//! Outbound requests from agent/tool code are meant to be pointed at this
//! proxy (e.g. `HTTP_PROXY`/`HTTPS_PROXY`). Every request is checked against a
//! configured host allowlist and is **REFUSED unless explicitly allowed**
//! (fail-closed). With no allowlist configured the proxy denies everything.
//!
//! Module map:
//! - [`allowlist`]: the pure allow/refuse decision (heavily unit-tested).
//! - [`config`]: environment-driven configuration loading.
//! - [`request`]: minimal, bounded HTTP request-head parsing.
//! - [`net`]: SSRF-safe DNS resolution + byte tunnelling.
//! - [`proxy`]: the blocking TCP forward-proxy server.
//! - [`mcp`]: documented (disabled) placeholder for an rmcp MCP interface.

pub mod allowlist;
pub mod config;
pub mod mcp;
pub mod net;
pub mod proxy;
pub mod request;

pub use allowlist::{Allowlist, Decision, RefuseReason};
pub use config::Config;
