//! `bridge-root-relay <interfaces-config>`: the root relay daemon.
//!
//! Loads `core_socket` and `[root]`, reads the relay's core publisher
//! token from its protected file, builds the caller attestor (the adapter
//! channel when `[root].channel` is set; otherwise the fail-closed
//! `Unattested` provider, logged as a warning) and serves the relay socket
//! until SIGTERM/SIGINT (a second signal exits at once). Logs are JSON
//! lines on stderr without tokens, proofs or payloads. Exit 1 when it
//! cannot start.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bridge_adapters::RegistryAttestor;
use bridge_adapters::registry::{CallerAttestor, Unattested};
use bridge_core::service::log_event;
use bridge_interfaces::config::{InterfacesConfig, read_secret};
use bridge_interfaces::root::{ATTEST_TIMEOUT, RelayServer, RootRelay};
use signal_hook::consts::{SIGINT, SIGTERM};

/// Logs a startup failure.
fn fail(event: &str, detail: &str) -> ExitCode {
    log_event("error", event, &[("detail", detail)]);
    ExitCode::FAILURE
}

/// Entry point.
fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: bridge-root-relay <interfaces-config>");
        return ExitCode::FAILURE;
    };
    let config = match InterfacesConfig::load(&PathBuf::from(path)) {
        Ok(config) => config,
        Err(error) => return fail("config_invalid", &error),
    };
    let Some(root) = config.root else {
        return fail("config_invalid", "no [root] section");
    };
    let token = match read_secret(&root.token_file) {
        Ok(token) => token,
        Err(error) => return fail("secret_refused", &error),
    };
    let attestor: Box<dyn CallerAttestor> = match &root.channel {
        Some(channel) => Box::new(RegistryAttestor::new(
            channel,
            ATTEST_TIMEOUT,
            root.max_caller_age_ms,
        )),
        None => {
            log_event(
                "warn",
                "root_unattested",
                &[("detail", "no adapter channel: every request refuses")],
            );
            Box::new(Unattested)
        }
    };
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        let registered =
            signal_hook::flag::register_conditional_shutdown(signal, 1, Arc::clone(&terminate))
                .and_then(|_| signal_hook::flag::register(signal, Arc::clone(&terminate)));
        if registered.is_err() {
            return fail("signal_registration_failed", "signal handlers unavailable");
        }
    }
    let socket = root.socket.clone();
    let relay = Arc::new(RootRelay::new(config.core_socket, root, token, attestor));
    let server = match RelayServer::start(&socket, relay) {
        Ok(server) => server,
        Err(error) => return fail("relay_start_failed", &error.to_string()),
    };
    log_event("info", "root_relay_started", &[]);
    while !terminate.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    server.stop();
    log_event("info", "root_relay_stopped", &[]);
    ExitCode::SUCCESS
}
