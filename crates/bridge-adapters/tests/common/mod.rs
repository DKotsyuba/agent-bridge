//! Shared lab for adapter integration tests: an owned temporary directory,
//! a qualified fixture harness profile, an in-memory custody store, the
//! real adapter channel and owned fixture harness processes.
//!
//! Nothing here touches a user's harness, store or session: every store is
//! a fresh directory under `TMPDIR`, every harness is a `bridge-fixture`
//! process started by the test.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use bridge_adapters::registry::{
    Profile, QualifiedExecutable, Registry, RegistryConfig, RelayExecutable, file_sha256,
};
use bridge_adapters::server::{ChannelServer, Custody, private_directory};
use bridge_core::dispatch::{AttemptRecord, DispatchTiming};
use bridge_core::{
    Envelope, EventId, Harness, Kind, Metadata, Mode, NativeAddress, Payload, Policy, PublisherId,
    Storage,
};
use serde_json::{Value, json};

/// Publisher identity of the synthetic test publisher.
pub const PUBLISHER: &str = "synthetic-pub";

/// Host id of the lab.
pub const HOST: &str = "lab-host";

/// Guard that removes its directory when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    /// A fresh owned directory under `TMPDIR`, short enough for socket
    /// paths.
    pub fn new(tag: &str) -> TempDir {
        let nonce = u32::from_ne_bytes(
            bridge_adapters::os::random_bytes().unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        let path = std::env::temp_dir().join(format!(
            "m2{tag}{}{:08x}",
            std::process::id() % 10_000,
            nonce
        ));
        std::fs::create_dir(&path).unwrap();
        TempDir(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    /// Removes the test-owned tree.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Resolved path of the fixture executable.
///
/// The registry refuses a build written or changed (mtime or ctime) in the
/// same whole second a process started or later (the loaded bytes are then
/// unproven), so when the fixture was linked this very second the call first waits,
/// honestly, until the clock is in a later second; any process started from it afterwards is born
/// strictly after its mtime and ctime. An older fixture costs nothing.
pub fn fixture_exe() -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let path = PathBuf::from(env!("CARGO_BIN_EXE_bridge-fixture"))
        .canonicalize()
        .unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let written = metadata.mtime().max(metadata.ctime());
    while i64::try_from(now() / 1000).unwrap() <= written {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    path
}

/// Path of the product hook executable.
pub fn hook_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bridge-hook"))
        .canonicalize()
        .unwrap()
}

/// Now in Unix epoch milliseconds.
pub fn now() -> u64 {
    bridge_core::service::current_unix_millis()
}

/// One lab: stores, registry, custody and the running channel.
pub struct Lab {
    /// Root directory (removed on drop).
    pub dir: TempDir,
    /// Claude test store.
    pub claude_store: PathBuf,
    /// Codex test store.
    pub codex_store: PathBuf,
    /// Channel socket.
    pub socket: PathBuf,
    /// Exact prepared fixture configuration for owned restart tests.
    pub config: RegistryConfig,
    /// The registry.
    pub registry: Arc<Mutex<Registry>>,
    /// The custody store.
    pub storage: Arc<Mutex<Storage>>,
    /// The running channel.
    pub channel: Option<ChannelServer>,
}

/// Builds a profile qualifying the fixture executable.
pub fn profile(namespace: &str, harness: Harness, store: &Path, sha256: &str) -> Profile {
    Profile {
        namespace: namespace.into(),
        harness,
        store: store.to_path_buf(),
        executables: vec![QualifiedExecutable {
            path: fixture_exe(),
            sha256: sha256.into(),
            version: "fixture".into(),
            inject: true,
            message: true,
        }],
    }
}

impl Lab {
    /// A lab whose profiles qualify the fixture with `sha256` (the real
    /// digest unless a test wants a mismatch).
    pub fn with_digest(tag: &str, sha256: Option<String>) -> Lab {
        let dir = TempDir::new(tag);
        let claude_store = dir.0.join("cs");
        let codex_store = dir.0.join("xs");
        std::fs::create_dir_all(&claude_store).unwrap();
        std::fs::create_dir_all(&codex_store).unwrap();
        let channel_dir = dir.0.join("ch");
        let owner = private_directory(&channel_dir).unwrap();
        let socket = channel_dir.join("c.sock");
        let sha = sha256.unwrap_or_else(|| file_sha256(&fixture_exe()).unwrap());
        let config = RegistryConfig {
            host_id: HOST.into(),
            profiles: vec![
                profile("claude-lab", Harness::ClaudeCode, &claude_store, &sha),
                profile("codex-lab", Harness::Codex, &codex_store, &sha),
            ],
            intermediates: ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"]
                .iter()
                .map(PathBuf::from)
                .collect(),
            max_call_age_ms: 600_000,
            relays: vec![RelayExecutable {
                path: fixture_exe(),
                sha256: sha.clone(),
            }],
            audiences: Vec::new(),
        };
        let registry = Arc::new(Mutex::new(Registry::new(config.clone(), owner).unwrap()));
        let limits = serde_json::from_value(json!({"max_admitted_events": 1000})).unwrap();
        let mut storage = Storage::open_in_memory(limits).unwrap();
        storage.register_source_tag(PUBLISHER, PUBLISHER).unwrap();
        let storage = Arc::new(Mutex::new(storage));
        let channel = ChannelServer::start(
            &socket,
            Arc::clone(&registry),
            Arc::clone(&storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap();
        Lab {
            dir,
            claude_store,
            codex_store,
            socket,
            registry,
            config,
            storage,
            channel: Some(channel),
        }
    }

    /// A lab with the real fixture digest.
    pub fn new(tag: &str) -> Lab {
        Lab::with_digest(tag, None)
    }

    /// The address of `session` in the Claude test store.
    pub fn claude_address(&self, session: &str) -> NativeAddress {
        NativeAddress::new(HOST, Harness::ClaudeCode, "claude-lab", session).unwrap()
    }

    /// The address of `thread` in the Codex test store.
    pub fn codex_address(&self, thread: &str) -> NativeAddress {
        NativeAddress::new(HOST, Harness::Codex, "codex-lab", thread).unwrap()
    }

    /// Publishes one synthetic event.
    pub fn publish(&self, event_id: &str, to: &NativeAddress, mode: Mode, payload: &str) {
        let envelope = Envelope::new(
            PublisherId::new(PUBLISHER).unwrap(),
            EventId::new(event_id).unwrap(),
            to.clone(),
            Kind::new("worker.completed").unwrap(),
            mode,
            Policy::KeepAll,
            Payload::new(payload).unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap();
        self.storage
            .lock()
            .unwrap()
            .publish(&envelope, now())
            .unwrap();
    }

    /// Tries to publish; returns the core error text on refusal.
    pub fn try_publish(
        &self,
        event_id: &str,
        to: &NativeAddress,
        mode: Mode,
    ) -> Result<(), String> {
        let envelope = Envelope::new(
            PublisherId::new(PUBLISHER).unwrap(),
            EventId::new(event_id).unwrap(),
            to.clone(),
            Kind::new("worker.completed").unwrap(),
            mode,
            Policy::KeepAll,
            Payload::new("x").unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap();
        self.storage
            .lock()
            .unwrap()
            .publish(&envelope, now())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// The newest attempt of an event.
    pub fn attempt(&self, event_id: &str) -> Option<AttemptRecord> {
        self.storage
            .lock()
            .unwrap()
            .latest_attempt(PUBLISHER, event_id)
            .unwrap()
    }
}

/// A running owned fixture harness process.
pub struct Harnessed {
    /// The process.
    pub child: Child,
    /// Command input.
    stdin: ChildStdin,
    /// Reply lines.
    stdout: BufReader<ChildStdout>,
}

impl Harnessed {
    /// Starts a CLI fixture harness whose store variable names `store`, stripping
    /// real Desktop capabilities so owned stand-ins cannot select the GUI route.
    pub fn start(harness: Harness, store: &Path) -> Harnessed {
        Self::start_with_app(harness, store, None)
    }

    /// Starts an owned Codex Desktop stand-in with its own native pipe capability;
    /// no installed application, frontend, or caller evidence is fabricated.
    pub fn start_desktop(store: &Path, pipe: &Path) -> Harnessed {
        Self::start_with_app(Harness::Codex, store, Some(pipe))
    }

    /// Starts the fixture with the specified store and optional owned Desktop pipe;
    /// inherited application capabilities are removed for CLI stand-ins.
    fn start_with_app(harness: Harness, store: &Path, pipe: Option<&Path>) -> Harnessed {
        let variable = match harness {
            Harness::Codex => "CODEX_HOME",
            Harness::ClaudeCode => "CLAUDE_CONFIG_DIR",
        };
        let mut command = Command::new(fixture_exe());
        command
            .arg("harness")
            .env(variable, store)
            .env_remove("CODEX_APP_TOOLS_PIPE_PATH")
            .env_remove("CODEX_MCP_NODE_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if let Some(pipe) = pipe {
            command.env("CODEX_APP_TOOLS_PIPE_PATH", pipe);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Harnessed {
            child,
            stdin,
            stdout,
        }
    }

    /// Sends one command and reads its reply.
    pub fn cmd(&mut self, command: Value) -> Value {
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    /// Runs the product hook for `payload` under this harness.
    pub fn hook(&mut self, socket: &Path, harness: Harness, payload: Value) -> Value {
        self.cmd(json!({
            "cmd": "hook", "bin": hook_exe(), "socket": socket,
            "harness": harness.as_str(), "payload": payload
        }))
    }

    /// Runs the hook with its stdout closed before it can print.
    pub fn hook_lost_stdout(&mut self, socket: &Path, harness: Harness, payload: Value) -> Value {
        self.cmd(json!({
            "cmd": "hook", "bin": hook_exe(), "socket": socket,
            "harness": harness.as_str(), "payload": payload, "close_stdout": true
        }))
    }

    /// Attests an MCP request's `_meta` from this harness's MCP child.
    pub fn mcp(&mut self, socket: &Path, meta: Value) -> Value {
        self.cmd(json!({"cmd": "mcp", "socket": socket, "meta": meta}))
    }

    /// Like [`Harnessed::mcp`] but also obtains a sealed proof.
    pub fn mcp_sealed(&mut self, socket: &Path, meta: Value) -> Value {
        self.cmd(json!({"cmd": "mcp", "socket": socket, "meta": meta, "seal": true}))
    }

    /// Ends the process and waits for it.
    pub fn stop(mut self) {
        let _ = writeln!(self.stdin, "{}", json!({"cmd": "exit"}));
        let _ = self.child.wait();
    }
}

/// A native hook payload.
pub fn hook(event: &str, session: &str) -> Value {
    json!({"hook_event_name": event, "session_id": session, "cwd": "/ignored"})
}

/// A tool hook payload, optionally from a child agent.
pub fn tool_hook(event: &str, session: &str, call: &str, agent: Option<&str>) -> Value {
    let mut value = json!({
        "hook_event_name": event, "session_id": session,
        "tool_use_id": call, "tool_name": "mcp__bridge__send"
    });
    if let Some(agent) = agent {
        value["agent_id"] = json!(agent);
    }
    value
}

/// Polls `check` for up to `millis`.
pub fn eventually(millis: u64, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(millis);
    while std::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    check()
}

/// Redeems a sealed proof from a relay process started directly by the
/// test (not a harness descendant).
pub fn relay_redeem(socket: &Path, proof: &str) -> Value {
    let mut child = Command::new(fixture_exe())
        .arg("relay")
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(proof.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}
