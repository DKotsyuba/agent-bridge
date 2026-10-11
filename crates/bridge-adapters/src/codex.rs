//! Codex `message` carrier: one `thread/queue/add` through an OS-confined,
//! queue-only App Server helper.
//!
//! The helper is the *qualified* Codex build of the recipient's binding,
//! started for exactly one hand-off as
//! `sandbox-exec -p HELPER_POLICY <codex> app-server --listen stdio://`
//! with a scrubbed environment whose `CODEX_HOME` is the attested store.
//! The policy denies all network access and any process creation after the
//! helper itself was exec'd. The driver below speaks only three methods —
//! `initialize`, the `initialized` notification and `thread/queue/add` for
//! the attested thread — so the helper never loads, resumes or starts the
//! recipient. A queue entry is native storage acceptance, not delivery;
//! `clientUserMessageId` correlates positively but never deduplicates, and
//! the helper's connection-local thread status (`notLoaded`) says nothing
//! about the recipient's activity, so it is never used as lifecycle.
//!
//! Outcome classification is conservative: a failure before the
//! `thread/queue/add` line was written is known-unsent; a native error
//! response refuses positively; silence, EOF or a timeout after the write
//! is an unknown outcome that is retained and never resent.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bridge_core::dispatch::{AttemptRecord, Attestation, DispatchCarrier, Outcome};
use bridge_core::{Harness, NativeAddress};
use serde_json::{Value, json};

use crate::registry::{RecipientBinding, Registry};
use crate::server::lock_registry;

/// macOS Seatbelt policy of the helper: everything the stock App Server
/// needs to read its store, but no network and no child processes.
pub const HELPER_POLICY: &str = "(version 1)(allow default)(deny network*)(deny process-fork)";

/// The only App Server methods the helper driver ever sends.
pub const HELPER_METHODS: [&str; 3] = ["initialize", "initialized", "thread/queue/add"];

/// Default bound for one helper exchange.
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(20);

/// The Codex queue-only message carrier.
pub struct CodexQueueCarrier {
    /// The protected registry (recipient bindings and qualified builds).
    registry: Arc<Mutex<Registry>>,
    /// The OS confinement launcher (`/usr/bin/sandbox-exec`).
    sandbox: PathBuf,
    /// Bound for one helper exchange.
    timeout: Duration,
}

impl CodexQueueCarrier {
    /// A carrier over `registry`, confining helpers with `sandbox`.
    pub fn new(registry: Arc<Mutex<Registry>>, sandbox: PathBuf, timeout: Duration) -> Self {
        CodexQueueCarrier {
            registry,
            sandbox,
            timeout,
        }
    }

    /// Re-attests the attempt's recipient and checks it is still the same
    /// endpoint epoch, returning the binding to hand off to.
    fn binding_for(
        &self,
        attempt: &AttemptRecord,
    ) -> Result<(NativeAddress, RecipientBinding), String> {
        let address = NativeAddress::parse(&attempt.fence.recipient).map_err(|e| e.to_string())?;
        if address.harness != Harness::Codex {
            return Err("not a Codex recipient".into());
        }
        let (_, binding) = lock_registry(&self.registry).attest_recipient(&address)?;
        if binding.epoch != attempt.fence.endpoint_epoch {
            return Err("the endpoint epoch changed since the reservation".into());
        }
        if !lock_registry(&self.registry).executable_qualified(&binding.executable) {
            return Err("the Codex build on disk is no longer the qualified build".into());
        }
        Ok((address, binding))
    }
}

impl DispatchCarrier for CodexQueueCarrier {
    /// Attests Codex recipients from the registry; anything else is not
    /// this carrier's (an error, which core treats as a hold).
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if recipient.harness != Harness::Codex {
            return Err("not a Codex recipient".into());
        }
        lock_registry(&self.registry)
            .attest_recipient(recipient)
            .map(|(attestation, _)| attestation)
    }

    /// Hands the frozen manifest to the attested thread's native queue.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        let (address, binding) = match self.binding_for(attempt) {
            Ok(found) => found,
            Err(reason) => {
                return Outcome::KnownUnsent {
                    evidence: format!("no helper started: {reason}"),
                };
            }
        };
        let client_id = format!(
            "agent-bridge-{}-{}",
            attempt.fence.attempt_seq,
            &attempt.fence.manifest_hash[..16.min(attempt.fence.manifest_hash.len())]
        );
        let helper = Helper {
            sandbox: &self.sandbox,
            executable: &binding.executable,
            store: &binding.store,
            timeout: self.timeout,
        };
        helper.queue_add(&address.native_session_id, &client_id, &attempt.manifest)
    }
}

/// One helper launch.
pub struct Helper<'a> {
    /// Confinement launcher.
    pub sandbox: &'a std::path::Path,
    /// Qualified Codex executable.
    pub executable: &'a std::path::Path,
    /// Attested store (`CODEX_HOME`).
    pub store: &'a std::path::Path,
    /// Exchange bound.
    pub timeout: Duration,
}

/// A running helper with its line reader.
struct Running {
    /// The confined helper process.
    child: Child,
    /// Its stdin (requests).
    stdin: ChildStdin,
    /// Lines from its stdout.
    lines: Receiver<String>,
    /// Next request id.
    next_id: u64,
}

impl Running {
    /// Writes one JSON-RPC message line.
    fn write(&mut self, message: &Value) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.stdin.write_all(&line)?;
        self.stdin.flush()
    }

    /// Sends one request of an allowlisted method; returns its id.
    fn request(&mut self, method: &str, params: Value) -> std::io::Result<u64> {
        if !HELPER_METHODS.contains(&method) {
            return Err(std::io::Error::other("method outside the helper allowlist"));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({"id": id, "method": method, "params": params}))?;
        Ok(id)
    }

    /// Waits for the response to `id` until `deadline`, skipping
    /// notifications; `None` on EOF or timeout.
    fn response(&self, id: u64, deadline: Instant) -> Option<Value> {
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(wait) {
                Ok(line) => {
                    let Ok(value) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if value.get("id").and_then(Value::as_u64) == Some(id)
                        && value.get("method").is_none()
                    {
                        return Some(value);
                    }
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Closes stdin and reaps the helper, killing it after a short grace.
    fn finish(mut self) {
        drop(self.stdin);
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Helper<'_> {
    /// Starts the confined helper.
    fn start(&self) -> std::io::Result<Running> {
        let mut command = Command::new(self.sandbox);
        command
            .args(["-p", HELPER_POLICY])
            .arg(self.executable)
            .args([
                "app-server",
                "--listen",
                "stdio://",
                "--strict-config",
                "-c",
                "analytics.enabled=false",
            ])
            .env_clear()
            .env("CODEX_HOME", self.store)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(home) = std::env::var_os("HOME") {
            command.env("HOME", home);
        }
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if line.len() > 1 << 20 || sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Running {
            child,
            stdin,
            lines,
            next_id: 1,
        })
    }

    /// Adds `text` to `thread_id`'s native queue with `client_id`.
    pub fn queue_add(&self, thread_id: &str, client_id: &str, text: &str) -> Outcome {
        let deadline = Instant::now() + self.timeout;
        let mut running = match self.start() {
            Ok(running) => running,
            Err(error) => {
                return Outcome::KnownUnsent {
                    evidence: format!("helper did not start: {error}"),
                };
            }
        };
        let initialized = running
            .request(
                "initialize",
                json!({
                    "clientInfo": {"name": "agent_bridge_queue", "version": env!("CARGO_PKG_VERSION")},
                    "capabilities": {"experimentalApi": true}
                }),
            )
            .ok()
            .and_then(|id| running.response(id, deadline));
        let ready = matches!(&initialized, Some(value) if value.get("result").is_some())
            && running
                .write(&json!({"method": "initialized", "params": {}}))
                .is_ok();
        if !ready {
            running.finish();
            return Outcome::KnownUnsent {
                evidence: "helper did not initialize; thread/queue/add was never written".into(),
            };
        }
        let id = match running.request(
            "thread/queue/add",
            json!({
                "threadId": thread_id,
                "clientUserMessageId": client_id,
                "input": [{"type": "text", "text": text}]
            }),
        ) {
            Ok(id) => id,
            Err(error) => {
                running.finish();
                // A failed write may have left part of the line in the pipe.
                return Outcome::OutcomeUnknown {
                    reason: format!("thread/queue/add write failed: {error}"),
                };
            }
        };
        let response = running.response(id, deadline);
        running.finish();
        match response {
            Some(value) if value.get("result").is_some() => Outcome::NativeAccepted {
                evidence: format!(
                    "native thread/queue/add accepted clientUserMessageId {client_id} (queue storage, not delivery)"
                ),
            },
            Some(value) => {
                let error = value
                    .get("error")
                    .cloned()
                    .unwrap_or(Value::Null)
                    .to_string();
                let mut error: String = error.chars().filter(|c| !c.is_control()).collect();
                error.truncate(300);
                Outcome::KnownUnsent {
                    evidence: format!("native thread/queue/add refused: {error}"),
                }
            }
            None => Outcome::OutcomeUnknown {
                reason: "thread/queue/add written without a native response".into(),
            },
        }
    }
}
