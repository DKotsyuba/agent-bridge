//! `bridge-root-mcp <adapter-channel-socket> <root-relay-socket>`: the
//! harness-launched stdio MCP frontend of the root tools.
//!
//! It holds no credential and accepts no identity argument; see
//! [`bridge_interfaces::mcp`]. Exit status is 0 at stdin EOF and 1 on an
//! invocation or output error. Diagnostics go to stderr without proofs or
//! payloads.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use bridge_adapters::RegistryAttestor;

/// Largest age of a joined hook record the frontend accepts, in ms.
const MAX_CALLER_AGE_MS: u64 = 10 * 60_000;

/// Entry point.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [channel, relay] = args.as_slice() else {
        eprintln!("usage: bridge-root-mcp <adapter-channel-socket> <root-relay-socket>");
        return ExitCode::FAILURE;
    };
    if bridge_adapters::desktop::exec_frontend().is_err() {
        eprintln!("Bridge signed application frontend unavailable");
        return ExitCode::FAILURE;
    }
    let _desktop = match bridge_adapters::desktop::start_frontend(&PathBuf::from(channel)) {
        Ok(relay) => relay,
        Err(_) => {
            eprintln!("Bridge application frontend relay unavailable");
            None
        }
    };
    let attestor = RegistryAttestor::new(
        &PathBuf::from(channel),
        Duration::from_secs(5),
        MAX_CALLER_AGE_MS,
    );
    let seal = |meta: &_, now| attestor.attest_sealed(meta, now).map(|(_, proof)| proof);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut output = std::io::stdout().lock();
    match bridge_interfaces::mcp::serve(&mut input, &mut output, &seal, &PathBuf::from(relay)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
