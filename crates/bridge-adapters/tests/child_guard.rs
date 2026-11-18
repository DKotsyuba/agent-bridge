//! Regression tests for [`common::ChildGuard`], which every test that starts a
//! `bridge-native-daemon` relies on so a failing test cannot leave it running.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::ChildGuard;

/// Environment marker that turns this test binary into the guard's parent.
const PARENT_MODE: &str = "BRIDGE_TEST_GUARD_PARENT";

/// A long-running stand-in for a daemon.
fn sleeper() -> Command {
    let mut command = ChildGuard::command("/bin/sleep");
    command
        .arg("600")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

/// Whether `pid` no longer runs: absent from `/proc`, or an unreaped zombie
/// (a killed orphan stays a zombie until its new parent reaps it).
fn gone(pid: u32) -> bool {
    match std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z')),
    }
}

/// Polls until `pid` is gone, for at most `budget`.
fn gone_within(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if gone(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    gone(pid)
}

/// Dropping the guard kills and reaps a running child.
#[test]
fn dropping_the_guard_kills_the_child() {
    let guard = ChildGuard::spawn(sleeper());
    let pid = guard.id();
    assert!(!gone(pid), "the child runs while guarded");
    drop(guard);
    assert!(gone(pid), "the child is reaped by the drop");
}

/// A failing assertion unwinding past the guard still kills the child: the
/// exact leak of a daemon started by a test that then fails.
#[test]
fn a_panicking_test_does_not_leak_the_child() {
    let pid = std::sync::atomic::AtomicU32::new(0);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = ChildGuard::spawn(sleeper());
        pid.store(guard.id(), std::sync::atomic::Ordering::SeqCst);
        panic!("simulated failed assertion");
    }));
    assert!(outcome.is_err());
    let pid = pid.load(std::sync::atomic::Ordering::SeqCst);
    assert_ne!(pid, 0);
    assert!(gone(pid), "the child did not survive the unwind");
}

/// A guard that cannot run `Drop` (its test process is SIGKILLed) still does
/// not leave the child behind: this binary re-runs itself as the parent, the
/// outer test kills it, and the guarded child must follow.
#[test]
fn a_killed_parent_does_not_leak_the_child() {
    if std::env::var_os(PARENT_MODE).is_some() {
        let guard = ChildGuard::spawn(sleeper());
        println!("CHILD {}", guard.id());
        std::thread::sleep(Duration::from_secs(600));
        return;
    }
    if !Path::new("/usr/bin/setpriv").exists() {
        eprintln!("setpriv is unavailable; parent-death teardown is not provided");
        return;
    }
    let mut parent = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_guard::a_killed_parent_does_not_leak_the_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PARENT_MODE, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let reader = BufReader::new(parent.stdout.take().unwrap());
    let child: u32 = reader
        .lines()
        .map_while(Result::ok)
        // libtest prints its own `test ... ` prefix on the same line.
        .find_map(|line| {
            line.split_once("CHILD ")
                .and_then(|(_, pid)| pid.trim().parse().ok())
        })
        .expect("the parent reports its guarded child");
    assert!(!gone(child));
    parent.kill().unwrap();
    parent.wait().unwrap();
    let ended = gone_within(child, Duration::from_secs(5));
    if !ended {
        let _ = Command::new("/bin/kill")
            .arg("-KILL")
            .arg(child.to_string())
            .status();
    }
    assert!(ended, "the child died with its parent");
}
