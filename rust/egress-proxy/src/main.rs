//! Binary entry point for the egress-allowlist forward-proxy.
//!
//! Configuration is read entirely from the environment (see [`Config`]). On any
//! configuration error we exit non-zero rather than starting with an unsafe or
//! ambiguous policy.

use std::process::ExitCode;

use egress_proxy::{proxy, Config};

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("egress-proxy: configuration error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    if config.allowlist.is_empty() {
        eprintln!(
            "egress-proxy: WARNING — allowlist is empty; ALL egress will be refused \
             (fail-closed). Set EGRESS_PROXY_ALLOWLIST or EGRESS_PROXY_ALLOWLIST_FILE."
        );
    }

    match proxy::serve(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("egress-proxy: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
