//! Bridge publisher daemon: bind the local socket and serve grants.
//!
//! Usage: `bridge-daemon <config.toml>`. The single argument is the daemon
//! configuration (database, socket, limits, grants); see [`Config`]. The
//! daemon exits 0 after a drained shutdown requested through an admin grant
//! on the socket. OS-signal handling is a documented followup of the
//! lifecycle task; today shutdown is protocol-driven.

use std::process::ExitCode;

use bridge_core::service::{self, Config};

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
            service::log_event(
                "error",
                "config_parse_failed",
                &[("path", &config_path), ("error", &error.to_string())],
            );
            return ExitCode::FAILURE;
        }
    };
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
    running.join();
    ExitCode::SUCCESS
}
