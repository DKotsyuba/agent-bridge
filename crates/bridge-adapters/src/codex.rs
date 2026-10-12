//! Codex `message` carrier: one `thread/queue/add` through an OS-confined,
//! queue-only App Server helper for CLI hosts. Application hosts use their
//! native message tool, preserving the application's cross-task source label.
//! The native pipe is read only from the attested harness OS environment;
//! after any native send begins no queue fallback or automatic replay occurs.
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
//! `thread/queue/add` line was written is known-unsent. After the write,
//! only a schema-valid success naming the same `clientUserMessageId` in its
//! `queuedSubmission` is native acceptance. Every native error response is
//! an unknown outcome: no error code or message of the loaded build is
//! qualified as proof that nothing was queued (a generic internal error can
//! follow a queue effect). Silence, EOF, a timeout or a malformed success
//! are unknown too. Unknown outcomes are retained and never resent.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bridge_core::dispatch::{AttemptRecord, Attestation, DispatchCarrier, Outcome};
use bridge_core::{Harness, NativeAddress};
use serde_json::{Value, json};

use crate::registry::{RecipientBinding, Registry, prefix_within};
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

    /// Hands the frozen manifest to the application's source-labelled native
    /// message route when the attested harness exposes it; CLI recipients use
    /// the confined queue helper. A selected application route never falls back
    /// after a failed or ambiguous exchange, preventing duplicate delivery.
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
            prefix_within(&attempt.fence.manifest_hash, 16)
        );
        if let Some(pipe) = crate::os::process_env(binding.harness.0, "CODEX_APP_TOOLS_PIPE_PATH") {
            if !crate::os::incarnation_alive(binding.harness.0, binding.harness.1) {
                return Outcome::KnownUnsent {
                    evidence: "the recipient harness ended before application delivery".into(),
                };
            }
            let Some(uid) = crate::os::process_facts(binding.harness.0).and_then(|facts| facts.uid)
            else {
                return Outcome::KnownUnsent {
                    evidence: "the recipient harness user is unavailable".into(),
                };
            };
            return crate::desktop::deliver(
                &PathBuf::from(pipe),
                &address.native_session_id,
                &client_id,
                &attempt.manifest,
                uid,
            );
        }
        let helper = Helper {
            sandbox: &self.sandbox,
            executable: &binding.executable,
            store: &binding.store,
            timeout: self.timeout,
        };
        helper.queue_add(&address.native_session_id, &client_id, &attempt.manifest)
    }
}

/// Classifies the native answer to a written `thread/queue/add`.
///
/// Only a success whose `queuedSubmission.clientUserMessageId` is
/// `client_id` is [`Outcome::NativeAccepted`] (with the native submission
/// id as evidence). A native error, a malformed success or no answer is
/// [`Outcome::OutcomeUnknown`]: the write happened, and no error of the
/// loaded build is qualified as proof of no queue effect.
pub fn classify_add(response: Option<&Value>, client_id: &str) -> Outcome {
    let bounded = |value: &Value| -> String {
        let text: String = value
            .to_string()
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        prefix_within(&text, 300).to_string()
    };
    let Some(response) = response else {
        return Outcome::OutcomeUnknown {
            reason: "thread/queue/add written without a native response".into(),
        };
    };
    if let Some(error) = response.get("error") {
        return Outcome::OutcomeUnknown {
            reason: format!(
                "native thread/queue/add error after the write, not qualified as no-acceptance: {}",
                bounded(error)
            ),
        };
    }
    let submission = &response["result"]["queuedSubmission"];
    match (
        submission["clientUserMessageId"].as_str(),
        submission["id"].as_str(),
    ) {
        (Some(echoed), Some(id)) if echoed == client_id => Outcome::NativeAccepted {
            evidence: format!(
                "native thread/queue/add accepted clientUserMessageId {client_id} as queued submission {} (queue storage, not delivery)",
                bounded(&Value::String(id.to_string()))
            ),
        },
        _ => Outcome::OutcomeUnknown {
            reason: format!(
                "thread/queue/add success without a matching queuedSubmission: {}",
                bounded(&response["result"])
            ),
        },
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
///
/// One total budget bounds everything: a watchdog kills the helper at the
/// deadline, which also unblocks a write stuck on a full pipe and ends the
/// reader. Dropping it (on every path, including a panic) closes stdin,
/// gives the helper a short grace, then kills and reaps it.
struct Running {
    /// The confined helper process, shared with the watchdog.
    child: Arc<Mutex<Child>>,
    /// Its stdin (requests); taken on drop.
    stdin: Option<ChildStdin>,
    /// Lines from its stdout.
    lines: Receiver<String>,
    /// Next request id.
    next_id: u64,
    /// Dropping this sender stops the watchdog.
    _watchdog: mpsc::Sender<()>,
}

impl Running {
    /// Writes one JSON-RPC message line.
    fn write(&mut self, message: &Value) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| std::io::Error::other("stdin closed"))?;
        stdin.write_all(&line)?;
        stdin.flush()
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
    /// notifications (which never extend the deadline); `None` on EOF or
    /// timeout.
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
}

impl Drop for Running {
    /// Closes stdin, waits up to 500 ms for exit, then kills and reaps.
    fn drop(&mut self) {
        drop(self.stdin.take());
        let grace = Instant::now() + Duration::from_millis(500);
        while Instant::now() < grace {
            let exited = self
                .child
                .lock()
                .map(|mut child| matches!(child.try_wait(), Ok(Some(_))))
                .unwrap_or(false);
            if exited {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Helper<'_> {
    /// Starts the confined helper with a watchdog at `deadline`.
    fn start(&self, deadline: Instant) -> std::io::Result<Running> {
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
        let child = Arc::new(Mutex::new(child));
        let (watchdog, stop) = mpsc::channel::<()>();
        let watched = Arc::clone(&child);
        std::thread::spawn(move || {
            let budget = deadline.saturating_duration_since(Instant::now());
            if let Err(RecvTimeoutError::Timeout) = stop.recv_timeout(budget)
                && let Ok(mut child) = watched.lock()
            {
                let _ = child.kill();
            }
        });
        Ok(Running {
            child,
            stdin: Some(stdin),
            lines,
            next_id: 1,
            _watchdog: watchdog,
        })
    }

    /// Adds `text` to `thread_id`'s native queue with `client_id`.
    pub fn queue_add(&self, thread_id: &str, client_id: &str, text: &str) -> Outcome {
        let deadline = Instant::now() + self.timeout;
        let mut running = match self.start(deadline) {
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
            drop(running);
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
                drop(running);
                // A failed write may have left part of the line in the pipe.
                return Outcome::OutcomeUnknown {
                    reason: format!("thread/queue/add write failed: {error}"),
                };
            }
        };
        let response = running.response(id, deadline);
        drop(running);
        classify_add(response.as_ref(), client_id)
    }
}

#[cfg(test)]
mod tests {
    //! Classification of native `thread/queue/add` answers.

    use super::*;

    /// Only a correlated `queuedSubmission` is acceptance; every native
    /// error (validation-like or internal) and a malformed success stay
    /// unknown, never known-unsent.
    #[test]
    fn only_correlated_success_is_acceptance() {
        let ok = json!({"id": 3, "result": {"queuedSubmission": {"id": "q-1", "clientUserMessageId": "c-1", "input": []}}});
        assert!(matches!(
            classify_add(Some(&ok), "c-1"),
            Outcome::NativeAccepted { .. }
        ));
        assert!(matches!(
            classify_add(Some(&ok), "c-2"),
            Outcome::OutcomeUnknown { .. }
        ));
        for answer in [
            json!({"id": 3, "error": {"code": -32603, "message": "failed to read thread: invalid thread-store request: no rollout found"}}),
            json!({"id": 3, "error": {"code": -32600, "message": "thread archived"}}),
            json!({"id": 3, "result": {}}),
        ] {
            assert!(
                matches!(
                    classify_add(Some(&answer), "c-1"),
                    Outcome::OutcomeUnknown { .. }
                ),
                "{answer}"
            );
        }
        assert!(matches!(
            classify_add(None, "c-1"),
            Outcome::OutcomeUnknown { .. }
        ));
    }

    /// Native text with multi-byte characters across the 300-byte bound
    /// (an error message, a malformed success) is cut on a character
    /// boundary, never panics, and stays unknown.
    #[test]
    fn unicode_native_text_is_bounded_without_panic() {
        // Each "é" is two bytes and each emoji four, so byte 300 falls inside
        // a character for some prefix length below.
        for pad in 0..4 {
            let message = format!("{}{}", "a".repeat(pad), "é🙂".repeat(120));
            let error = json!({"id": 3, "error": {"code": -32603, "message": message}});
            let malformed = json!({"id": 3, "result": {"note": message}});
            for answer in [error, malformed] {
                match classify_add(Some(&answer), "c-1") {
                    Outcome::OutcomeUnknown { reason } => assert!(reason.len() < 300 + 120),
                    other => panic!("{other:?}"),
                }
            }
        }
        let submission = format!("q-{}", "🙂".repeat(100));
        let ok = json!({"id": 3, "result": {"queuedSubmission": {"id": submission, "clientUserMessageId": "c-1", "input": []}}});
        assert!(matches!(
            classify_add(Some(&ok), "c-1"),
            Outcome::NativeAccepted { .. }
        ));
    }
}
