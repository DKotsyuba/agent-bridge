//! Owned fixture process for adapter tests and fault injection.
//!
//! This binary is a test fixture, not a product component: integration
//! tests spawn it to play the parts that must be real *processes* — a Codex
//! queue helper, a Claude later peer, and a root hook transport — under
//! exact, reproducible faults. Every mode records what it did as a status
//! file next to the caller's temp state and exits with a defined code, so
//! logs and exit status persist for evidence.
//!
//! Usage: `bridge-fixture <mode> [args...]`, where args are file paths
//! supplied by the owning test. Modes:
//!
//! - `hook-emit <payload> <status>`: write the full payload to stdout,
//!   flush, record `emitted`, exit 0.
//! - `hook-crash-before-reply <payload> <status>`: record
//!   `crashed-before-reply`, exit 1 without writing stdout.
//! - `hook-partial-stdout <payload> <status>`: write half the payload,
//!   record `partial`, exit 1.
//! - `hook-killed <status>`: record `killed`, then abort (signal death).
//! - `hook-late <payload> <status>`: sleep past a short deadline, then
//!   emit and record `late-return`, exit 0.
//! - `codex-helper <store> <thread> <payload> <status>`: the confined
//!   queue-add helper; validates its own launch shape (argv verb `add`,
//!   absolute store, no `CODEX_*` environment) and records
//!   `queue-accepted` with a client message id, exit 0. Shape violations
//!   record `confinement-violation` and exit 3.
//! - `codex-helper-archived <store> <thread> <payload> <status>`: record
//!   `archived-refused`, exit 0.
//! - `claude-later <payload> <status>`: record `later-accepted` with a
//!   message id, exit 0.
//! - `claude-held <payload> <status> <release> <wait_ms>`: record
//!   `held`; poll for the release file; on appearance record `released`,
//!   on timeout record `still-held`; exit 0 either way.
//!
//! Unknown modes record `unknown-mode` on stderr and exit 2.

use std::io::Write as _;
use std::path::Path;
use std::process::exit;

/// Reads one file to a string, or records the failure and exits 4.
fn read_or_exit(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("fixture read failure {path:?}: {error}");
            exit(4);
        }
    }
}

/// Records one status line to the status file.
fn record(status: &Path, line: &str) {
    if let Err(error) = std::fs::write(status, format!("{line}\n")) {
        eprintln!("fixture status write failure {status:?}: {error}");
        exit(4);
    }
}

/// Copies the payload to stdout completely and flushes.
fn emit(payload: &str) {
    let mut out = std::io::stdout();
    if let Err(error) = out.write_all(payload.as_bytes()) {
        eprintln!("fixture stdout failure: {error}");
        exit(4);
    }
    if let Err(error) = out.flush() {
        eprintln!("fixture stdout flush failure: {error}");
        exit(4);
    }
}

/// A deterministic pseudo id for fixture correlation records.
fn id_from(text: &str) -> String {
    // Not a hash: fixtures need stable ids, not security.
    format!(
        "cu-{:x}",
        text.bytes().map(u32::from).fold(0u32, u32::wrapping_add)
    )
}

/// Main dispatch; see the module documentation for modes.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        "hook-emit" => {
            let payload = read_or_exit(Path::new(&args[2]));
            emit(&payload);
            record(Path::new(&args[3]), "emitted");
            exit(0);
        }
        "hook-crash-before-reply" => {
            let _ = read_or_exit(Path::new(&args[2]));
            record(Path::new(&args[3]), "crashed-before-reply");
            exit(1);
        }
        "hook-partial-stdout" => {
            let payload = read_or_exit(Path::new(&args[2]));
            let half = payload.len() / 2;
            let mut out = std::io::stdout();
            let _ = out.write_all(&payload.as_bytes()[..half]);
            let _ = out.flush();
            record(Path::new(&args[3]), "partial");
            exit(1);
        }
        "hook-killed" => {
            record(Path::new(&args[2]), "killed");
            std::process::abort();
        }
        "hook-late" => {
            let payload = read_or_exit(Path::new(&args[2]));
            std::thread::sleep(std::time::Duration::from_millis(300));
            emit(&payload);
            record(Path::new(&args[3]), "late-return");
            exit(0);
        }
        "codex-helper" | "codex-helper-archived" => {
            let (store, thread, payload_path, status) = (
                Path::new(&args[2]),
                args[3].as_str(),
                Path::new(&args[4]),
                Path::new(&args[5]),
            );
            // Confinement self-checks: no foreign harness environment, an
            // absolute store, and a payload that exists.
            let contaminated: Vec<String> = std::env::vars()
                .map(|(key, _)| key)
                .filter(|key| key.starts_with("CODEX_"))
                .collect();
            if !contaminated.is_empty() || !store.is_absolute() || !payload_path.is_file() {
                record(
                    status,
                    &format!(
                        "confinement-violation env={contaminated:?} store={:?} payload={:?}",
                        store, payload_path
                    ),
                );
                exit(3);
            }
            if mode == "codex-helper-archived" {
                record(status, "archived-refused");
                exit(0);
            }
            let payload = read_or_exit(payload_path);
            record(
                status,
                &format!("queue-accepted {} {}", thread, id_from(&payload)),
            );
            exit(0);
        }
        "claude-later" => {
            let payload = read_or_exit(Path::new(&args[2]));
            record(
                Path::new(&args[3]),
                &format!("later-accepted {}", id_from(&payload)),
            );
            exit(0);
        }
        "claude-held" => {
            let payload = read_or_exit(Path::new(&args[2]));
            let status = Path::new(&args[3]);
            let release = Path::new(&args[4]);
            let wait_ms: u64 = args[5].parse().unwrap_or(200);
            record(status, &format!("held {}", id_from(&payload)));
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
            while std::time::Instant::now() < deadline {
                if release.is_file() {
                    record(status, "released");
                    exit(0);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            record(status, "still-held");
            exit(0);
        }
        other => {
            eprintln!("unknown-mode {other:?}");
            exit(2);
        }
    }
}
