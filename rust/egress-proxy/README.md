# egress-proxy

A small, dependency-free **Rust** HTTP forward-proxy that enforces an egress
**allowlist** on the odysseus trust boundary. It is the first Rust edge in the
codebase.

Outbound requests from agent/tool code are pointed at this proxy
(`HTTP_PROXY` / `HTTPS_PROXY`). Each request is checked against a configured
host allowlist and is **REFUSED unless explicitly allowed** — fail-closed.

## Policy (fail-closed)

A target is **ALLOWED** only if it is a named host on the allowlist. Everything
else is **REFUSED**:

| Target                                  | Result   | Reason              |
|-----------------------------------------|----------|---------------------|
| Host on the allowlist                   | ALLOW    | —                   |
| Host not on the allowlist               | REFUSE   | `NotAllowlisted`    |
| No allowlist configured (deny-all)      | REFUSE   | `EmptyAllowlist`    |
| Raw public IP literal (e.g. `8.8.8.8`)  | REFUSE   | `IpLiteral`         |
| Cloud metadata `169.254.169.254`        | REFUSE   | `ForbiddenAddress`  |
| RFC1918 `10/8` `172.16/12` `192.168/16` | REFUSE   | `ForbiddenAddress`  |
| Loopback / link-local / CGNAT / ULA     | REFUSE   | `ForbiddenAddress`  |
| Empty / malformed host                  | REFUSE   | `InvalidHost`       |

Defense-in-depth: even an allowlisted **name** is refused at connect time if it
resolves to a forbidden address (DNS-rebinding / SSRF protection — see
`net::safe_resolve`).

Both `CONNECT` (HTTPS tunnels) and absolute-form HTTP requests are supported.

## Configuration (environment only)

| Variable                      | Default            | Meaning                                   |
|-------------------------------|--------------------|-------------------------------------------|
| `EGRESS_PROXY_BIND`           | `127.0.0.1:8080`   | Listen address.                           |
| `EGRESS_PROXY_ALLOWLIST`      | (unset)            | Comma-separated allow entries.            |
| `EGRESS_PROXY_ALLOWLIST_FILE` | (unset)            | Path to newline-separated allow entries.  |
| `EGRESS_PROXY_TOKEN`          | (unset)            | Owner token; required via `Proxy-Authorization: Bearer <token>` when set. |

With no allowlist source set, **all** egress is refused. With no token set the
proxy accepts unauthenticated clients — safe only for the default loopback
bind; **set a token for any non-loopback bind.**

## Run

```bash
cd rust/egress-proxy
EGRESS_PROXY_ALLOWLIST_FILE=allowlist.example.txt \
EGRESS_PROXY_TOKEN="$(openssl rand -hex 16)" \
  cargo run --release

# point a client at it:
curl -x http://127.0.0.1:8080 \
     -H 'Proxy-Authorization: Bearer <token>' \
     https://api.openai.com/v1/models     # ALLOW (if allowlisted)
curl -x http://127.0.0.1:8080 http://169.254.169.254/  # 403 REFUSE
```

## Test loop (CARGO, not Python)

```bash
cargo --version   # requires a machine with Rust installed
cargo test        # runs the unit + integration policy tests
```

The tests have **zero external dependencies**, so `cargo test` is hermetic (no
crate registry fetch). Required cases covered: an allowlisted host passes; a
non-allowlisted host / IP-literal / metadata endpoint (`169.254.169.254`) /
RFC1918 address is refused; and no-allowlist is deny-all.

## MCP interface — next step, disabled by default

`src/mcp.rs` documents an optional `rmcp` MCP server interface behind the `mcp`
cargo feature. It ships **off**: a new inbound interface is a new entry point
and must be owner-authenticated and routed through the existing approval queue
(`src/pending_actions.py`) + taint model + Phase-4 autonomy guard before it can
be enabled — never a side door around the boundary. The core deliverable (the
egress allowlist proxy) is complete without it.

## Design notes

- **No external crates.** For a security component on the trust boundary the
  audit surface is deliberately just the Rust std library.
- **Thread-per-connection** blocking I/O — simple and auditable for an internal
  boundary with modest concurrency.
- Every request runs `allowlist::decide` **before** any upstream socket opens;
  a refusal never touches the network.
