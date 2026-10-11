//! Gated qualification of the Codex queue-only helper against the real
//! Codex App Server build, in a fresh owned store. Ignored by default.
//!
//! Run only when explicitly provisioned:
//! `BRIDGE_QUALIFY_CODEX_EXE=<absolute codex executable> cargo test -p
//! bridge-adapters --test qualify_codex -- --ignored --nocapture`.
//!
//! Every App Server process here runs under the helper's own confinement
//! policy (no network, no child processes) with a cleared environment.
//! `CODEX_HOME` is a fresh, unpredictably named directory this test creates
//! (never an existing one); the owner and reader also use it as `HOME`,
//! while the product helper inherits normal `HOME`, as in production.
//! The test uses the owned Codex store and no model. The owner step creates
//! one thread in that store and
//! exits; the product helper then queues to it while no process has it
//! loaded; a separate confined reader lists the queue. Every process is
//! killed and reaped on every path (including panics), and each session
//! has one total time budget that notifications cannot extend.
//!
//! What a pass shows: against the loaded build, the product helper never
//! classifies a native error after its write as known-unsent (unpersisted
//! owned thread, missing thread), and any acceptance is backed by a native
//! queue readback. Positive queue acceptance needs a thread with a
//! persisted rollout, which a model-less owner cannot create on
//! 0.162.0-alpha.17.2; that case runs inside the bounded Codex model probe
//! (`qualification/codex-native-probe.cjs`, phase 3). Nothing here shows
//! model delivery, context, GUI consumption, lifecycle or caller identity.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bridge_adapters::codex::{HELPER_POLICY, Helper};
use bridge_core::dispatch::Outcome;
use serde_json::{Value, json};

/// Total budget of one confined App Server session.
const SESSION_BUDGET: Duration = Duration::from_secs(30);

/// A directory this test created; removed on drop only because it is ours.
struct OwnedDir(PathBuf);

impl OwnedDir {
    /// Creates a fresh, unpredictably named directory under the temp dir;
    /// fails rather than reuse anything that already exists.
    fn create() -> OwnedDir {
        let mut random = [0u8; 16];
        std::io::Read::read_exact(
            &mut std::fs::File::open("/dev/urandom").expect("urandom"),
            &mut random,
        )
        .expect("random name");
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("m2-codex-qual-{name}"));
        std::fs::create_dir(&path).expect("create a fresh owned directory");
        OwnedDir(path)
    }
}

impl Drop for OwnedDir {
    /// Removes the directory this test created.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A confined App Server child that is killed and reaped on drop.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    /// Kills (if still running) and waits, on every path.
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs one confined App Server session: sends `requests` in order (each
/// `(method, params)`; `initialized` follows `initialize` as a
/// notification) and returns every response by request order. The whole
/// session shares one budget; a missing response fails the test.
fn session(exe: &Path, home: &Path, requests: &[(&str, Value)]) -> Vec<Value> {
    let deadline = Instant::now() + SESSION_BUDGET;
    let mut guard = ChildGuard(
        Command::new("/usr/bin/sandbox-exec")
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
            .expect("start confined app-server"),
    );
    let mut stdin = guard.0.stdin.take().unwrap();
    let stdout = guard.0.stdout.take().unwrap();
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
            let left = deadline.saturating_duration_since(Instant::now());
            let line = lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no {method} response within the session budget"));
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
    responses
}

/// Real Codex: native errors after the helper's write are never
/// known-unsent, and any acceptance is backed by a native readback.
#[test]
#[ignore = "needs a provisioned real Codex build (BRIDGE_QUALIFY_CODEX_EXE)"]
fn real_codex_queue_only_helper_adds_to_an_unloaded_owned_thread() {
    let Some(exe) = std::env::var_os("BRIDGE_QUALIFY_CODEX_EXE").map(PathBuf::from) else {
        panic!("BRIDGE_QUALIFY_CODEX_EXE is not set; nothing was qualified");
    };
    let home = OwnedDir::create();
    let init = json!({"clientInfo": {"name": "agent_bridge_qual", "version": "0"}, "capabilities": {"experimentalApi": true}});

    // Owner step: create one thread in the owned store, then exit.
    let owner = session(
        &exe,
        &home.0,
        &[("initialize", init.clone()), ("thread/start", json!({}))],
    );
    let thread = owner[1]["result"]["thread"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("thread/start failed: {}", owner[1]))
        .to_string();
    println!("qualify: codex owned thread created");

    // Helper: the product's confined queue-only hand-off.
    let helper = Helper {
        sandbox: Path::new("/usr/bin/sandbox-exec"),
        executable: &exe,
        store: &home.0,
        timeout: Duration::from_secs(20),
    };
    // A model-less owned thread has no persisted rollout on this build
    // (root run on 0210a732: native -32603 "no rollout found"). Whatever the
    // native answer, it must never be classified as known-unsent: an error
    // after the write is unknown.
    let unpersisted = helper.queue_add(&thread, "agent-bridge-qual-1", "AGENT_BRIDGE_QUAL_MARKER");
    println!("qualify: unpersisted-thread outcome {unpersisted:?}");
    assert!(
        !matches!(unpersisted, Outcome::KnownUnsent { .. }),
        "{unpersisted:?}"
    );
    if matches!(unpersisted, Outcome::NativeAccepted { .. }) {
        // Acceptance must be backed by a native readback of the same item.
        let reader = session(
            &exe,
            &home.0,
            &[
                ("initialize", init.clone()),
                ("thread/queue/list", json!({"threadId": thread})),
            ],
        );
        let items = reader[1]["result"]["data"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        println!("qualify: queue/list items {}", items.len());
        assert!(
            items
                .iter()
                .any(|item| item["clientUserMessageId"] == "agent-bridge-qual-1"
                    && item.to_string().contains("AGENT_BRIDGE_QUAL_MARKER")),
            "{}",
            reader[1]
        );
    }

    // A thread that does not exist in the store: an error answer is never
    // known-unsent or accepted.
    let missing = helper.queue_add(
        "00000000-0000-7000-8000-000000000000",
        "agent-bridge-qual-2",
        "x",
    );
    println!("qualify: missing-thread outcome {missing:?}");
    assert!(
        matches!(missing, Outcome::OutcomeUnknown { .. }),
        "{missing:?}"
    );
}
