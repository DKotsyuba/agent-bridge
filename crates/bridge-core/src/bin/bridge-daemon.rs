//! Bridge daemon: bind the local socket and serve grants.
//!
//! Usage: `bridge-daemon <config.toml>`. The single argument is the daemon
//! configuration (database, socket, limits, grants); see [`Config`].
//!
//! The daemon exits 0 after a drained stop, requested either by an operator
//! grant over the socket or by SIGTERM / SIGINT (OS shutdown): new work is
//! fenced, in-flight requests finish, and only this instance's socket is
//! removed. A second signal while draining terminates the process
//! immediately with status 1; custody is already durable by then because
//! every acknowledged publish was committed before it was acknowledged.
//! The daemon starts without native carriers: events stay pending and
//! visible until a qualified adapter drives them.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bridge_core::service::{self, Config};
use signal_hook::consts::{SIGINT, SIGTERM};

/// Reads the config path argument, starts the service and blocks until a
/// drained stop.
fn main() -> ExitCode {
    let config_path = match std::env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: bridge-daemon <config.toml>");
            return ExitCode::FAILURE;
        }
    };
    let config_text = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(error) => {
            service::log_event(
                "error",
                "config_read_failed",
                &[("path", &config_path), ("error", &error.to_string())],
            );
            return ExitCode::FAILURE;
        }
    };
    let config: Config = match toml::from_str(&config_text) {
        Ok(config) => config,
        Err(error) => {
            // The TOML error text can quote the offending value, which may be
            // a grant token; only the line number is logged.
            let line = error.span().map_or_else(String::new, |span| {
                let start = span.start.min(config_text.len());
                (config_text.as_bytes()[..start]
                    .iter()
                    .filter(|&&byte| byte == b'\n')
                    .count()
                    + 1)
                .to_string()
            });
            service::log_event(
                "error",
                "config_parse_failed",
                &[
                    ("path", &config_path),
                    ("line", &line),
                    (
                        "detail",
                        "configuration is invalid; the message is withheld",
                    ),
                ],
            );
            return ExitCode::FAILURE;
        }
    };
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        // Registered in this order, so a repeated signal exits at once.
        let registered =
            signal_hook::flag::register_conditional_shutdown(signal, 1, Arc::clone(&terminate))
                .and_then(|_| signal_hook::flag::register(signal, Arc::clone(&terminate)));
        if let Err(error) = registered {
            service::log_event(
                "error",
                "signal_registration_failed",
                &[("error", &error.to_string())],
            );
            return ExitCode::FAILURE;
        }
    }
    let running = match service::start(config) {
        Ok(running) => running,
        Err(error) => {
            service::log_event(
                "error",
                "service_start_failed",
                &[("error", &error.to_string())],
            );
            return ExitCode::FAILURE;
        }
    };
    service::log_event(
        "info",
        "service_started",
        &[("socket", &running.socket_path().display().to_string())],
    );
    while running.is_running() {
        if terminate.load(Ordering::SeqCst) {
            service::log_event("info", "signal_received", &[]);
            running.shutdown();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    running.join();
    ExitCode::SUCCESS
}
