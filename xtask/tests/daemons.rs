//! `cargo xtask check-daemons` detects a surviving test daemon and passes
//! once it is gone.

use std::path::Path;
use std::process::{Command, Stdio};

/// Runs `check-daemons` limited to `dir`.
fn check(dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("check-daemons")
        .arg("--dir")
        .arg(dir)
        .output()
        .expect("xtask check-daemons starts")
}

/// A process named like the daemon with its configuration inside the directory
/// fails the check; the same check passes after the process is killed.
#[test]
fn a_surviving_daemon_fails_the_check() {
    let root = std::env::temp_dir().join(format!("xd{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let config = root.join("bridge.toml");
    std::fs::write(&config, "").unwrap();
    // `bash -c 'exec -a NAME ...'` gives the long-running `tail` the daemon's
    // name and the configuration as its argument, like the real command line.
    let mut child = Command::new("bash")
        .args(["-c", "exec -a \"$0\" tail -f /dev/null \"$1\""])
        .arg(root.join("bridge-native-daemon"))
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let alive = poll(&root, false);
    child.kill().unwrap();
    child.wait().unwrap();
    let gone = check(&root);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(
        !alive.status.success(),
        "a live daemon must fail: {}",
        String::from_utf8_lossy(&alive.stdout)
    );
    assert!(String::from_utf8_lossy(&alive.stderr).contains("survived"));
    assert!(
        gone.status.success(),
        "{}",
        String::from_utf8_lossy(&gone.stderr)
    );
}

/// Runs the check until it has the wanted outcome (the child's `exec` may not
/// be visible yet), for at most five seconds, and returns the last result.
fn poll(dir: &Path, want_success: bool) -> std::process::Output {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let output = check(dir);
        if output.status.success() == want_success || std::time::Instant::now() > deadline {
            return output;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
