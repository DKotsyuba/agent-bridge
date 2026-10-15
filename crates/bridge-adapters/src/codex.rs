//! Codex `message` carrier: one `thread/queue/add` through an OS-confined,
//! queue-only App Server helper for CLI hosts. Application hosts use their
//! native message tool, preserving the application's cross-task source label.
//! The native pipe is read only from the attested harness OS environment;
//! after any native send begins no queue fallback or automatic replay occurs.
//! A recipient whose own environment names a native owner socket is instead
//! woken, only while positively idle, through that owner ([`crate::owner`]),
//! which is selected before the helper and application routes and has no
//! fallback to them.
//!
//! The helper is the Codex executable the recipient's binding records (a process
//! fact), started for exactly one hand-off as
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

use bridge_core::dispatch::{AttemptRecord, Attestation, DispatchCarrier, Lifecycle, Outcome};
use bridge_core::service::current_unix_millis;
use bridge_core::{Harness, Mode, NativeAddress};
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
    /// The protected registry (recipient bindings).
    registry: Arc<Mutex<Registry>>,
    /// The OS confinement launcher (`/usr/bin/sandbox-exec`).
    sandbox: PathBuf,
    /// Bound for one helper exchange.
    timeout: Duration,
    /// Protected adapter directory containing registered frontend sockets.
    desktop_directory: Option<PathBuf>,
    /// Test seam: runs at the last pre-write boundary of a gateway hand-off,
    /// after the proof was spent and the connection prepared, so a regression can
    /// change the world at exactly that point. Always absent in production.
    gateway_pause: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl CodexQueueCarrier {
    /// A carrier over `registry`, confining helpers with `sandbox`.
    pub fn new(registry: Arc<Mutex<Registry>>, sandbox: PathBuf, timeout: Duration) -> Self {
        CodexQueueCarrier {
            registry,
            sandbox,
            timeout,
            desktop_directory: None,
            gateway_pause: None,
        }
    }

    /// Installs a deterministic pause for race regressions: `pause` runs in a
    /// gateway hand-off after its one-shot proof was journaled as spent and the
    /// frontend connection and request frame are prepared, immediately before the
    /// final pre-write fence. Not part of any production configuration.
    #[doc(hidden)]
    pub fn with_gateway_pause(mut self, pause: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.gateway_pause = Some(pause);
        self
    }

    /// Enables application frontend discovery under the protected channel directory.
    pub fn with_desktop_directory(mut self, directory: PathBuf) -> Self {
        self.desktop_directory = Some(directory);
        self
    }

    /// Revalidates the MESSAGE-only recipient outside the registry lock, then
    /// checks the unchanged attempt epoch. Retired Desktop routes require their
    /// exact live frontend on both attest and send and never select a CLI helper.
    /// A native owner route wakes only a positively idle recipient, whatever the
    /// requested mode; helper and application routes keep their lifecycle rules.
    fn binding_for(
        &self,
        attempt: &AttemptRecord,
    ) -> Result<(NativeAddress, RecipientBinding, Route), String> {
        let address = NativeAddress::parse(&attempt.fence.recipient).map_err(|e| e.to_string())?;
        if address.harness != Harness::Codex {
            return Err("not a Codex recipient".into());
        }
        let (attestation, binding, route) = self.message_recipient(&address)?;
        if binding.epoch != attempt.fence.endpoint_epoch {
            return Err("the endpoint epoch changed since the reservation".into());
        }
        let lifecycle = attestation.lifecycle();
        let allowed = if matches!(route, Route::Owner(_)) {
            lifecycle == Lifecycle::Inactive
        } else {
            matches!(lifecycle, Lifecycle::Active | Lifecycle::Inactive)
                && (attempt.requested_mode != Mode::Auto || lifecycle == Lifecycle::Inactive)
        };
        if !allowed {
            return Err("recipient lifecycle changed before message hand-off".into());
        }
        Ok((address, binding, route))
    }

    /// Starts a background evidence refresh (never hashing here), then takes an
    /// owned registry snapshot, releases its lock, revalidates current
    /// OS/store/executable/transcript facts and requires an exact-harness frontend
    /// for application recipients. A recipient whose recorded incarnation ended is
    /// attested through the MESSAGE-only gateway (unique live Desktop frontend,
    /// fresh journaled epoch committed
    /// before the snapshot is re-read), and a live `Unknown` route carrying an
    /// unspent idle proof is attested `Inactive` only while that exact transcript
    /// proof reads back unchanged. Failure holds before reservation or sending;
    /// no native/history/status request or caller evidence is manufactured.
    /// A final locked equality check rejects even same-epoch lifecycle changes
    /// during validation/probing before returning to either attest or send.
    /// Returns the selected route with the snapshot, so send performs no
    /// further discovery after that check; invocation still verifies peers.
    /// A present native owner locator is selected before every legacy route and
    /// holds when it cannot be proven; an absent one leaves them unchanged.
    fn message_recipient(
        &self,
        address: &NativeAddress,
    ) -> Result<(Attestation, RecipientBinding, Route), String> {
        let mut candidate = { lock_registry(&self.registry).message_candidate(address)? };
        let result = if candidate.needs_gateway() {
            self.gateway_recipient(address, &mut candidate)?
        } else {
            candidate.validate()?
        };
        let route = checked_frontend(
            || {
                if let Some(socket) = crate::owner::locate(&self.registry, result.1.harness)? {
                    return if result.1.desktop_message_only {
                        Err("a retired recipient cannot use a native owner route".into())
                    } else {
                        Ok(Route::Owner(socket))
                    };
                }
                if result.1.desktop_message_only
                    || crate::os::process_env(result.1.harness.0, "CODEX_APP_TOOLS_PIPE_PATH")
                        .is_some()
                {
                    self.desktop_directory.as_ref()
                        .and_then(|directory| crate::desktop::frontend_for(directory, result.1.harness))
                        .map(Route::Application)
                        .ok_or_else(|| "registered Codex application frontend not available yet (transient hold)".into())
                } else {
                    Ok(Route::Helper)
                }
            },
            || lock_registry(&self.registry).message_current(&candidate),
        )?;
        Ok((result.0, result.1, route))
    }
}

impl CodexQueueCarrier {
    /// Attests the MESSAGE-only physical gateway of an idle Desktop address whose
    /// recorded harness incarnation ended ([`crate::registry`] gateway evidence):
    /// exactly one distinct live Desktop harness that qualifies for this binding
    /// (same executable, store and native pipe) must own a probe-verified
    /// frontend; zero or several hold. A gateway not yet committed for the
    /// current snapshot is committed with a fresh, larger endpoint epoch,
    /// journaled before the snapshot is re-read, so core fences it when the
    /// attestation is reserved and never after a send. The returned attestation is
    /// `Inactive`, MESSAGE-only and carries no caller or inject authority; every
    /// transcript, process and route fact is proven again here, on attest and on
    /// send.
    fn gateway_recipient(
        &self,
        address: &NativeAddress,
        candidate: &mut crate::registry::MessageCandidate,
    ) -> Result<(Attestation, RecipientBinding), String> {
        let directory = self
            .desktop_directory
            .as_ref()
            .ok_or("no application frontend directory for the gateway route")?;
        let mut qualified = crate::desktop::frontend_harnesses(directory)
            .into_iter()
            .filter(|harness| candidate.qualifies_gateway(*harness));
        let (Some(gateway), None) = (qualified.next(), qualified.next()) else {
            return Err(
                "no unique qualified live Desktop gateway for the idle recipient (hold)".into(),
            );
        };
        candidate.proves_idle()?;
        if candidate.committed_gateway() != Some(gateway) {
            lock_registry(&self.registry).commit_gateway(
                candidate,
                gateway,
                current_unix_millis(),
            )?;
            *candidate = lock_registry(&self.registry).message_candidate(address)?;
        }
        candidate.validate_gateway()
    }
}

impl DispatchCarrier for CodexQueueCarrier {
    /// Attests Codex MESSAGE recipients from fresh snapshot validation; anything else is not
    /// this carrier's (an error, which core treats as a hold). Application hosts
    /// also require a live compatible frontend before consuming any send attempt.
    ///
    /// A recipient whose own environment names a native owner socket is attested
    /// for that owner route ([`crate::owner`]) before any helper or application
    /// frontend is considered; it must be positively idle, and an unprovable,
    /// unreadable or malformed locator is an error (a hold) with no fallback.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if recipient.harness != Harness::Codex {
            return Err("not a Codex recipient".into());
        }
        let (attestation, _, _) = self.message_recipient(recipient)?;
        Ok(attestation)
    }

    /// Hands the frozen manifest to the application's source-labelled native
    /// message route when the attested harness exposes it; CLI recipients use
    /// the confined queue helper. A selected application route never falls back
    /// after a failed or ambiguous exchange, preventing duplicate delivery.
    ///
    /// A native owner route, selected before the helper and application routes
    /// when the recipient's environment names an owner socket, hands the
    /// manifest to that owner only for a positively idle recipient (whatever the
    /// requested mode), after at least 35 seconds of core budget are proven. A
    /// failure before the request is written is known-unsent; afterwards only a
    /// correlated, exactly shaped receipt is anything but an unknown outcome,
    /// which is retained and never resent or replaced by another route.
    ///
    /// An application hand-off through a gateway or idle-proof route first spends
    /// its one-shot proof in the route journal (an unrecordable spend sends
    /// nothing), then runs a fresh logical and transcript fence after the frontend
    /// connection and request frame are prepared and immediately before the first
    /// byte (zero bytes on any change). The proof is restored only after a
    /// known-unsent refusal while that fence passes again *and* the binding is
    /// exactly the one that stood right after the spend, and the journal accepts
    /// it; an accepted or possibly delivered hand-off never restores it.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        let (address, binding, route) = match self.binding_for(attempt) {
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
        match route {
            Route::Owner(socket) => {
                return crate::owner::deliver(
                    &self.registry,
                    &socket,
                    binding.harness,
                    Harness::Codex,
                    &crate::owner::Handoff {
                        thread_id: &address.native_session_id,
                        call_id: &client_id,
                        text: &attempt.manifest,
                        deadline_ms: attempt.deadline_ms,
                    },
                );
            }
            Route::Application(frontend) => {
                // A gateway hand-off spends its one-shot proof in the journal
                // before the first native byte: an unrecordable spend sends
                // nothing. A fresh logical and physical fence (binding, epoch,
                // incarnation, gateway qualification and the exact transcript
                // stamp) then runs after the durable reservation, at the last
                // pre-write boundary; any change is known-unsent with zero bytes
                // written. The proof is given back only after a refusal that
                // proves nothing was written *and* the same fence still holds.
                let fence = |proof: &crate::registry::WakeProof| -> Result<(), String> {
                    let candidate = lock_registry(&self.registry).message_candidate(&address)?;
                    candidate.revalidate_spent(binding.epoch, proof, binding.harness)?;
                    lock_registry(&self.registry).message_current(&candidate)
                };
                let spent = if binding.gateway {
                    match lock_registry(&self.registry).spend_wake(&address, binding.epoch) {
                        Ok(spent) => Some(spent),
                        Err(reason) => {
                            return Outcome::KnownUnsent {
                                evidence: format!(
                                    "gateway proof could not be recorded; nothing sent: {reason}"
                                ),
                            };
                        }
                    }
                } else {
                    None
                };
                let outcome = crate::desktop::via_frontend_checked(
                    &frontend,
                    binding.harness,
                    &address.native_session_id,
                    &client_id,
                    &attempt.manifest,
                    || {
                        if let Some(pause) = &self.gateway_pause {
                            pause();
                        }
                        spent.as_ref().map_or(Ok(()), |spent| fence(spent.proof()))
                    },
                );
                if let (Some(spent), Outcome::KnownUnsent { .. }) = (spent, &outcome)
                    && fence(spent.proof()).is_ok()
                {
                    lock_registry(&self.registry).restore_wake(&address, spent);
                }
                return outcome;
            }
            Route::Helper => {}
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

/// The one route a validated Codex MESSAGE hand-off takes; selected before any
/// native write and never replaced by another after a failed or ambiguous
/// exchange.
pub(crate) enum Route {
    /// The confined queue-only App Server helper (CLI recipients).
    Helper,
    /// The registered application frontend's source-labelled message tool.
    Application(PathBuf),
    /// The recipient's native owner socket, validated by [`crate::owner`].
    Owner(PathBuf),
}

/// Runs all route discovery/probing in `pick` before the final in-memory
/// binding confirmation in `confirm`. Returns what `pick` selected; either error
/// refuses the hand-off.
/// Callbacks must preserve that ordering and perform no native message writes.
/// This fence detects changes during selection, not cancellation after invocation.
pub(crate) fn checked_frontend<T>(
    pick: impl FnOnce() -> Result<T, String>,
    confirm: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    let selected = pick()?;
    confirm()?;
    Ok(selected)
}

/// Classifies the native answer to a written `thread/queue/add`.
///
/// Only a success whose `queuedSubmission.clientUserMessageId` is
/// `client_id` is [`Outcome::NativeAccepted`] (with the native submission
/// id as evidence). A native error, a malformed success or no answer is
/// [`Outcome::OutcomeUnknown`]: the write happened, and no error of the
/// Codex build counts as proof of no queue effect.
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
    /// Codex executable of the recipient's binding.
    pub executable: &'a std::path::Path,
    /// Attested store (`CODEX_HOME`).
    pub store: &'a std::path::Path,
    /// Exchange bound.
    pub timeout: Duration,
}

/// A running helper with its line reader.
///
/// Used by the confined CLI helper and the host-supplied signed Node client.
/// One total budget bounds everything: a watchdog kills the child at the
/// deadline, which also unblocks a write stuck on a full pipe and ends the
/// reader. Dropping it (on every path, including a panic) closes stdin,
/// gives the helper a short grace, then kills and reaps it.
pub(crate) struct Running {
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
    /// Starts one trusted command with piped protocol I/O and an absolute watchdog.
    /// The command must already have its executable, arguments, environment and
    /// confinement fixed by the carrier; no request-supplied command is accepted.
    /// Spawn/pipe errors refuse before writing. Drop always kills and reaps.
    pub(crate) fn start(mut command: Command, deadline: Instant) -> std::io::Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
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
    /// Writes one JSON-RPC message line.
    pub(crate) fn write(&mut self, message: &Value) -> std::io::Result<()> {
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
    pub(crate) fn response(&self, id: u64, deadline: Instant) -> Option<Value> {
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
        Running::start(command, deadline)
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
