//! Gated qualification of the Codex queue-only helper against the real
//! Codex App Server build, in a fresh owned store. Ignored by default.
//!
//! Run only when explicitly provisioned:
//! `BRIDGE_QUALIFY_CODEX_EXE=<absolute codex executable> cargo test -p
//! bridge-adapters --test qualify_codex -- --ignored --nocapture`.
//!
//! Every App Server process here runs under the helper's own confinement
//! policy (no network, no child processes) with `CODEX_HOME` set to a fresh
//! temporary directory, so no user store, credential or model is touched.
//! The owner step creates one thread in that store and exits; the helper
//! then queues to it while no process has it loaded; a separate confined
//! reader lists the queue. This qualifies the queue-only carrier against
//! the loaded build; it does not show model delivery or GUI consumption.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use bridge_adapters::codex::{HELPER_POLICY, Helper};
use bridge_core::dispatch::Outcome;
use serde_json::{Value, json};

/// Runs one confined App Server session: sends `requests` in order (each
/// `(method, params)`; `initialized` is sent as a notification after
/// `initialize`) and returns every response by request order.
fn session(exe: &Path, home: &Path, requests: &[(&str, Value)]) -> Vec<Value> {
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", HELPER_POLICY])
        .arg(exe)
        .args([
            "app-server",
            "--listen",
            "stdio://",
            "--strict-config",
            "-c",
            "analytics.enabled=false",
        ])
        .env_clear()
        .env("CODEX_HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start confined app-server");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut responses = Vec::new();
    for (index, (method, params)) in requests.iter().enumerate() {
        let id = index as u64 + 1;
        writeln!(
            stdin,
            "{}",
            json!({"id": id, "method": method, "params": params})
        )
        .unwrap();
        let response = loop {
            let line = lines
                .recv_timeout(Duration::from_secs(20))
                .expect("app-server response");
            let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            if value["id"] == json!(id) && value.get("method").is_none() {
                break value;
            }
        };
        if *method == "initialize" {
            writeln!(stdin, "{}", json!({"method": "initialized", "params": {}})).unwrap();
        }
        responses.push(response);
    }
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    responses
}

/// Real Codex: the confined helper queues to an unloaded owned thread and a missing thread refuses.
#[test]
#[ignore = "needs a provisioned real Codex build (BRIDGE_QUALIFY_CODEX_EXE)"]
fn real_codex_queue_only_helper_adds_to_an_unloaded_owned_thread() {
    let Some(exe) = std::env::var_os("BRIDGE_QUALIFY_CODEX_EXE").map(PathBuf::from) else {
        eprintln!("BRIDGE_QUALIFY_CODEX_EXE not set; not qualified");
        return;
    };
    let home = std::env::temp_dir().join(format!("m2-codex-qual-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let init = json!({"clientInfo": {"name": "agent_bridge_qual", "version": "0"}, "capabilities": {"experimentalApi": true}});

    // Owner step: create one thread in the owned store, then exit.
    let owner = session(
        &exe,
        &home,
        &[("initialize", init.clone()), ("thread/start", json!({}))],
    );
    let thread = owner[1]["result"]["thread"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("thread/start failed: {}", owner[1]))
        .to_string();

    // Helper: the product's confined queue-only hand-off.
    let helper = Helper {
        sandbox: Path::new("/usr/bin/sandbox-exec"),
        executable: &exe,
        store: &home,
        timeout: Duration::from_secs(20),
    };
    let outcome = helper.queue_add(&thread, "agent-bridge-qual-1", "AGENT_BRIDGE_QUAL_MARKER");
    assert!(
        matches!(outcome, Outcome::NativeAccepted { .. }),
        "{outcome:?}"
    );

    // Reader: the queue holds exactly the helper's item.
    let reader = session(
        &exe,
        &home,
        &[
            ("initialize", init.clone()),
            ("thread/queue/list", json!({"threadId": thread})),
        ],
    );
    let items = reader[1]["result"]["data"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        items
            .iter()
            .any(|item| item["clientUserMessageId"] == "agent-bridge-qual-1"),
        "{}",
        reader[1]
    );

    // A thread that does not exist in the store is refused natively.
    let missing = helper.queue_add(
        "00000000-0000-7000-8000-000000000000",
        "agent-bridge-qual-2",
        "x",
    );
    assert!(
        matches!(missing, Outcome::KnownUnsent { .. }),
        "{missing:?}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
