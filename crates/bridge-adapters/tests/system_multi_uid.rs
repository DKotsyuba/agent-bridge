//! Process-level check of the system worker's inherited-socket parent fence.
//!
//! This uses real Linux peer credentials but does not exercise cross-UID routing.

#![cfg(target_os = "linux")]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use bridge_adapters::os;
use serde_json::Value;

/// A worker refuses an unprivileged socket owner before reading configuration.
#[test]
fn worker_refuses_unprivileged_parent() {
    let (parent, worker) = UnixStream::pair().unwrap();
    let peer = os::peer_identity(&worker).unwrap();
    assert_eq!(peer.pid, std::process::id());
    if peer.uid == 0 {
        eprintln!("worker parent check requires a non-root test runner; skipped");
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_bridge-native-daemon"))
        .args([
            "--system-worker",
            "/dev/null/never-read-daemon.toml",
            "/dev/null/never-read-interfaces.toml",
            "1",
        ])
        .stdin(Stdio::from(OwnedFd::from(worker)))
        .output()
        .unwrap();
    drop(parent);

    assert!(!output.status.success());
    let log: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(log["event"], "system_worker_failed");
    assert_eq!(
        log["detail"],
        "worker channel is not owned by its root parent"
    );
}
