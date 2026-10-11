//! Claude `message` carrier: authenticated native peer send with
//! `priority = "later"`, a stable daemon callback, and positive closure of
//! written-without-receipt hand-offs.
//!
//! The recipient is the exact harness process incarnation of the binding:
//! its session descriptor (`<store>/sessions/*.json`) must name the
//! attested session *and* that PID, and the inbox socket's kernel peer must
//! be that PID as this user, before the session's own peer token or any
//! frame is written. Only `later` is ever sent — `default`/`next` fold into
//! current work and `shouldQuery = false` still wakes a peer, so peer
//! inject is prohibited here; quiet inject is the root hook drain.
//!
//! Receipts: the user frame names a long-lived callback socket this daemon
//! keeps in the inbox's directory (the native reply-address rule). A
//! receipt is correlated by the attempt's unguessable message id (known
//! only to the recipient process through its authenticated inbox and to
//! this daemon); when the sender is still connected its kernel identity
//! must also be the recipient PID. The PID check is opportunistic because
//! the kernel no longer reports the PID of a peer that already closed. Within the short receipt window: `held` is a
//! non-terminal hold with a recheck deadline, `delivered` is native
//! acceptance, a refusal before any hold is known-unsent, and silence is
//! the ordinary `written_no_receipt`. Later receipts are recorded straight
//! into core: release after hold is acceptance; any negative after a hold
//! is an unknown outcome (no proof the loaded native classification means
//! no context acceptance). A written-without-receipt hand-off is closed
//! positively only when the session's own transcript contains the exact
//! manifest as a user message; an absent marker never retries. A daemon
//! restart forgets callbacks: core's recheck deadlines turn those attempts
//! into retained incidents, never replays.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::dispatch::{AttemptFence, AttemptRecord, Attestation, DispatchCarrier, Outcome};
use bridge_core::service::{current_unix_millis, log_event};
use bridge_core::{Harness, NativeAddress};
use serde_json::{Value, json};

use crate::os;
use crate::registry::Registry;
use crate::server::{Custody, lock_registry, with_custody};

/// Largest manifest the native inbox accepts in one message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Largest descriptor or key file read, in bytes.
const MAX_DESCRIPTOR_BYTES: u64 = 16 * 1024;

/// Most descriptor files scanned per send.
const MAX_DESCRIPTORS: usize = 512;

/// Largest receipt frame, in bytes.
const MAX_RECEIPT_BYTES: u64 = 4096;

/// Largest transcript tail searched for a closure marker, in bytes.
const MAX_TRANSCRIPT_TAIL: u64 = 8 << 20;

/// Timing of the Claude carrier.
#[derive(Debug, Clone, Copy)]
pub struct ClaudeTiming {
    /// How long `send` waits for a first receipt.
    pub receipt_wait: Duration,
    /// Recheck horizon of a held hand-off, in milliseconds.
    pub held_recheck_ms: u64,
    /// Deadline for positive closure of a written-without-receipt
    /// hand-off, in milliseconds.
    pub receipt_deadline_ms: u64,
}

impl Default for ClaudeTiming {
    /// 1.5 s first-receipt window, 10 min held recheck, 5 min closure.
    fn default() -> Self {
        ClaudeTiming {
            receipt_wait: Duration::from_millis(1_500),
            held_recheck_ms: 10 * 60_000,
            receipt_deadline_ms: 5 * 60_000,
        }
    }
}

/// What one in-flight hand-off waits for.
#[derive(Debug)]
enum Waiting {
    /// `send` is inside its receipt window.
    First(Sender<String>),
    /// Held natively; a later release or drop is expected.
    Held,
    /// Written without a receipt; closure by late receipt or transcript.
    NoReceipt {
        /// The exact manifest text.
        manifest: String,
        /// The session transcript, when the hooks reported one.
        transcript: Option<PathBuf>,
        /// Closure deadline (Unix epoch ms).
        deadline_ms: u64,
    },
}

/// One correlated hand-off.
#[derive(Debug)]
struct Pending {
    /// The attempt's fence.
    fence: AttemptFence,
    /// The only PID whose receipts count.
    recipient_pid: u32,
    /// What it waits for.
    waiting: Waiting,
}

/// Callback listeners and correlation shared by the carrier and its
/// background threads.
struct Hub {
    /// Custody for late outcomes.
    custody: Arc<dyn Custody>,
    /// In-flight hand-offs by message id.
    pending: Mutex<HashMap<String, Pending>>,
    /// Callback socket path per inbox directory.
    listeners: Mutex<HashMap<PathBuf, PathBuf>>,
    /// This user's uid.
    uid: u32,
    /// Random per-process secret (from the OS) that makes message ids and
    /// callback names unguessable.
    secret: [u8; 32],
}

/// One `later` frame to write.
#[derive(Clone, Copy)]
struct Frame<'a> {
    /// Inbox socket of the recipient.
    socket: &'a Path,
    /// Attested harness PID that must own the socket.
    pid: u32,
    /// The recipient's own peer token (never logged).
    token: &'a str,
    /// Recipient session id.
    session: &'a str,
    /// Attempt message id.
    msg_id: &'a str,
    /// Stable callback socket.
    from: &'a Path,
    /// Exact manifest text.
    manifest: &'a str,
}

/// The Claude `later` message carrier.
pub struct ClaudeLaterCarrier {
    /// The protected registry.
    registry: Arc<Mutex<Registry>>,
    /// Shared correlation state.
    hub: Arc<Hub>,
    /// Timing.
    timing: ClaudeTiming,
}

/// Reads an owned, regular, bounded JSON object (never through a symlink).
fn owned_json(path: &Path, uid: u32) -> Option<serde_json::Map<String, Value>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.len() > MAX_DESCRIPTOR_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_DESCRIPTOR_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    match serde_json::from_str(&text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Sorted entries of the store's session registry.
fn registry_entries(store: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(store.join("sessions"))
        .map(|entries| entries.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    paths.sort();
    paths.truncate(MAX_DESCRIPTORS * 2);
    paths
}

/// Finds the inbox socket of `session` owned by exactly `pid`.
fn inbox_socket(store: &Path, session: &str, pid: u32, uid: u32) -> Option<PathBuf> {
    registry_entries(store)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .take(MAX_DESCRIPTORS)
        .find_map(|path| {
            let map = owned_json(&path, uid)?;
            let matches = map.get("sessionId").and_then(Value::as_str) == Some(session)
                && map.get("pid").and_then(Value::as_u64) == Some(u64::from(pid));
            matches
                .then(|| map.get("messagingSocketPath")?.as_str().map(PathBuf::from))
                .flatten()
                .filter(|socket| socket.is_absolute())
        })
}

/// Reads the recipient process's own peer token (never logged).
fn peer_token(store: &Path, pid: u32, uid: u32) -> Option<String> {
    let prefix = format!("{pid}.");
    registry_entries(store)
        .into_iter()
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "key")
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
        })
        .find_map(|path| {
            owned_json(&path, uid)?
                .get("peerToken")?
                .as_str()
                .filter(|token| !token.is_empty() && token.len() <= 4096)
                .map(String::from)
        })
}

/// Parses one receipt line correlated to an attempt message id.
fn receipt(line: &str) -> Option<(String, String)> {
    let frame: Value = serde_json::from_str(line).ok()?;
    if frame.get("type")?.as_str()? != "control"
        || frame.get("action")?.as_str()? != "peer_message_status"
    {
        return None;
    }
    let status = frame.get("status")?.as_str()?;
    if !matches!(
        status,
        "held" | "delivered" | "denied" | "expired" | "refused" | "dropped"
    ) {
        return None;
    }
    Some((
        frame.get("orig_msg_id")?.as_str()?.to_string(),
        status.to_string(),
    ))
}

impl Hub {
    /// Returns this directory's stable callback socket, binding it and
    /// starting its listener on first use.
    fn callback_for(self: &Arc<Self>, directory: &Path) -> std::io::Result<PathBuf> {
        let mut listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(path) = listeners.get(directory)
            && std::fs::symlink_metadata(path).is_ok()
        {
            return Ok(path.clone());
        }
        let name = format!(
            "{}.sock",
            &self.derive(&format!("callback:{}", directory.display()))[..12]
        );
        let path = directory.join(name);
        let listener = UnixListener::bind(&path)?;
        let hub = Arc::clone(self);
        std::thread::Builder::new()
            .name("bridge-claude-callback".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    hub.accept_receipt(stream);
                }
            })?;
        listeners.insert(directory.to_path_buf(), path.clone());
        Ok(path)
    }

    /// Derives an unguessable per-purpose value from this hub's secret.
    fn derive(&self, purpose: &str) -> String {
        let mut material = self.secret.to_vec();
        material.extend_from_slice(purpose.as_bytes());
        crate::server::sha256_hex(&material)
    }

    /// Reads one bounded receipt connection and routes it.
    ///
    /// The kernel identity of a receipt peer is only readable while it is
    /// still connected; a native inbox may write and close first. A peer
    /// whose identity *is* readable must be this user and, per receipt,
    /// the recipient PID. Otherwise the receipt is bound only by the
    /// unguessable per-attempt message id, which only the recipient
    /// process (through its authenticated inbox) and this daemon know.
    fn accept_receipt(&self, stream: UnixStream) {
        let peer = os::peer_identity(&stream).ok();
        if peer.is_some_and(|peer| peer.uid != self.uid) {
            return;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut text = String::new();
        if (&stream)
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_string(&mut text)
            .is_err()
            || text.len() as u64 > MAX_RECEIPT_BYTES
        {
            return;
        }
        for line in text.lines() {
            if let Some((msg_id, status)) = receipt(line) {
                self.route(&msg_id, &status, peer.map(|peer| peer.pid));
            }
        }
    }

    /// Routes one correlated receipt; a known sender PID must be the
    /// recipient's.
    fn route(&self, msg_id: &str, status: &str, pid: Option<u32>) {
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = pending.get_mut(msg_id) else {
            return;
        };
        if pid.is_some_and(|pid| pid != entry.recipient_pid) {
            return;
        }
        let late = match &entry.waiting {
            Waiting::First(sender) => {
                let _ = sender.send(status.to_string());
                return;
            }
            Waiting::Held | Waiting::NoReceipt { .. } => match status {
                "delivered" => Outcome::NativeAccepted {
                    evidence: format!("late native receipt delivered for {msg_id}"),
                },
                "held" if matches!(entry.waiting, Waiting::NoReceipt { .. }) => {
                    entry.waiting = Waiting::Held;
                    Outcome::NativeHeld {
                        recheck_ms: current_unix_millis().saturating_add(10 * 60_000),
                    }
                }
                "held" => return,
                other => Outcome::OutcomeUnknown {
                    reason: format!(
                        "native {other} after a possible hand-off; no proof of no context acceptance"
                    ),
                },
            },
        };
        let fence = entry.fence.clone();
        if !matches!(late, Outcome::NativeHeld { .. }) {
            pending.remove(msg_id);
        }
        drop(pending);
        self.record(&fence, late);
    }

    /// Records one late outcome into core.
    fn record(&self, fence: &AttemptFence, outcome: Outcome) {
        let recorded = with_custody(self.custody.as_ref(), |storage| {
            storage.record_outcome(fence, outcome, current_unix_millis())
        });
        match recorded {
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                log_event(
                    "warn",
                    "claude_late_outcome_refused",
                    &[("error", &error.to_string())],
                );
            }
            None => log_event("warn", "claude_late_outcome_unrecorded", &[]),
        }
    }

    /// One closure pass over written-without-receipt hand-offs: a transcript
    /// containing the exact manifest as a user message closes positively;
    /// past the deadline the entry is forgotten (core already holds the
    /// recheck and raises the incident).
    fn close_pass(&self) {
        let now = current_unix_millis();
        let candidates: Vec<(String, AttemptFence, String, Option<PathBuf>, u64)> = {
            let pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending
                .iter()
                .filter_map(|(id, entry)| match &entry.waiting {
                    Waiting::NoReceipt {
                        manifest,
                        transcript,
                        deadline_ms,
                    } => Some((
                        id.clone(),
                        entry.fence.clone(),
                        manifest.clone(),
                        transcript.clone(),
                        *deadline_ms,
                    )),
                    _ => None,
                })
                .collect()
        };
        for (id, fence, manifest, transcript, deadline) in candidates {
            let found = transcript
                .as_deref()
                .is_some_and(|path| transcript_contains(path, &manifest, self.uid));
            if found {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
                self.record(
                    &fence,
                    Outcome::NativeAccepted {
                        evidence: format!(
                            "exact-session transcript holds the manifest {} as a user message",
                            &fence.manifest_hash[..16.min(fence.manifest_hash.len())]
                        ),
                    },
                );
            } else if now > deadline {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
            }
        }
    }
}

/// Whether the transcript's bounded tail holds `manifest` as the exact
/// content of a user message.
pub fn transcript_contains(path: &Path, manifest: &str, uid: u32) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.uid() != uid {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let start = metadata.len().saturating_sub(MAX_TRANSCRIPT_TAIL);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut text = String::new();
    if file
        .take(MAX_TRANSCRIPT_TAIL)
        .read_to_string(&mut text)
        .is_err()
    {
        return false;
    }
    text.lines().any(|line| {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let Some(message) = entry.get("message") else {
            return false;
        };
        if message.get("role").and_then(Value::as_str) != Some("user") {
            return false;
        }
        match message.get("content") {
            Some(Value::String(text)) => text == manifest,
            Some(Value::Array(parts)) => parts
                .iter()
                .any(|part| part.get("text").and_then(Value::as_str) == Some(manifest)),
            _ => false,
        }
    })
}

impl ClaudeLaterCarrier {
    /// A carrier over `registry` whose late outcomes go to `custody`.
    ///
    /// Starts one closure thread that lives as long as the process.
    pub fn new(
        registry: Arc<Mutex<Registry>>,
        custody: Arc<dyn Custody>,
        timing: ClaudeTiming,
    ) -> std::io::Result<Self> {
        let uid = os::process_facts(std::process::id())
            .and_then(|facts| facts.uid)
            .ok_or_else(|| std::io::Error::other("own uid unreadable"))?;
        let hub = Arc::new(Hub {
            custody,
            pending: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            uid,
            secret: os::random_bytes()?,
        });
        let closer = Arc::downgrade(&hub);
        std::thread::Builder::new()
            .name("bridge-claude-closure".into())
            .spawn(move || {
                while let Some(hub) = closer.upgrade() {
                    hub.close_pass();
                    drop(hub);
                    std::thread::sleep(Duration::from_secs(2));
                }
            })?;
        Ok(ClaudeLaterCarrier {
            registry,
            hub,
            timing,
        })
    }

    /// Writes the authenticated `later` frame of `frame`. On failure
    /// returns the outcome: known-unsent while no byte can have left,
    /// unknown once the write started.
    fn write_frames(&self, frame: &Frame<'_>) -> Result<(), Outcome> {
        let Frame {
            socket,
            pid,
            token,
            session,
            msg_id,
            from,
            manifest,
        } = *frame;
        let unsent = |evidence: String| Outcome::KnownUnsent { evidence };
        let mut stream = UnixStream::connect(socket)
            .map_err(|error| unsent(format!("inbox connect failed: {}", error.kind())))?;
        let peer = os::peer_identity(&stream)
            .map_err(|_| unsent("inbox peer identity unreadable".into()))?;
        if peer.pid != pid || peer.uid != self.hub.uid {
            return Err(unsent(
                "inbox endpoint is not the attested harness process".into(),
            ));
        }
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let frames = format!(
            "{}\n{}\n",
            json!({"type": "auth", "token": token}),
            json!({
                "type": "user",
                "session_id": session,
                "msg_id": msg_id,
                "from": format!("uds:{}", from.display()),
                "priority": "later",
                "message": {"role": "user", "content": manifest}
            })
        );
        // Once a byte may have left, failure is a possible hand-off.
        stream
            .write_all(frames.as_bytes())
            .map_err(|error| Outcome::OutcomeUnknown {
                reason: format!("inbox write interrupted: {}", error.kind()),
            })?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(())
    }
}

impl DispatchCarrier for ClaudeLaterCarrier {
    /// Attests Claude recipients from the registry; anything else is not
    /// this carrier's.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if recipient.harness != Harness::ClaudeCode {
            return Err("not a Claude recipient".into());
        }
        lock_registry(&self.registry)
            .attest_recipient(recipient)
            .map(|(attestation, _)| attestation)
    }

    /// One `later` hand-off of the frozen manifest.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        let unsent = |evidence: String| Outcome::KnownUnsent { evidence };
        let Ok(address) = NativeAddress::parse(&attempt.fence.recipient) else {
            return unsent("unparseable recipient".into());
        };
        let binding = match lock_registry(&self.registry).attest_recipient(&address) {
            Ok((_, binding)) => binding,
            Err(reason) => return unsent(format!("recipient not attested: {reason}")),
        };
        if binding.epoch != attempt.fence.endpoint_epoch {
            return unsent("the endpoint epoch changed since the reservation".into());
        }
        if attempt.manifest.len() > MAX_MESSAGE_BYTES {
            return Outcome::PermanentRefusal {
                reason: format!(
                    "manifest exceeds the native inbox bound of {MAX_MESSAGE_BYTES} bytes"
                ),
            };
        }
        let pid = binding.harness.0;
        let session = &address.native_session_id;
        let Some(socket) = inbox_socket(&binding.store, session, pid, self.hub.uid) else {
            return unsent("no inbox descriptor for the attested harness process".into());
        };
        let Some(token) = peer_token(&binding.store, pid, self.hub.uid) else {
            return unsent("the attested harness process has no peer token".into());
        };
        let Some(directory) = socket.parent() else {
            return unsent("inbox socket has no directory".into());
        };
        let callback = match self.hub.callback_for(directory) {
            Ok(path) => path,
            Err(error) => return unsent(format!("callback socket unavailable: {}", error.kind())),
        };
        let msg_id = format!(
            "bridge_{}_{}",
            attempt.fence.attempt_seq,
            &self.hub.derive(&format!(
                "msg:{}:{}",
                attempt.fence.attempt_seq, attempt.fence.manifest_hash
            ))[..32]
        );
        let (sender, first): (Sender<String>, Receiver<String>) = mpsc::channel();
        self.hub
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                msg_id.clone(),
                Pending {
                    fence: attempt.fence.clone(),
                    recipient_pid: pid,
                    waiting: Waiting::First(sender),
                },
            );
        let frame = Frame {
            socket: &socket,
            pid,
            token: &token,
            session,
            msg_id: &msg_id,
            from: &callback,
            manifest: &attempt.manifest,
        };
        if let Err(outcome) = self.write_frames(&frame) {
            self.hub
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&msg_id);
            return outcome;
        }
        let status = first.recv_timeout(self.timing.receipt_wait).ok();
        let now = current_unix_millis();
        let mut pending = self.hub.pending.lock().unwrap_or_else(|p| p.into_inner());
        match status.as_deref() {
            Some("held") => {
                if let Some(entry) = pending.get_mut(&msg_id) {
                    entry.waiting = Waiting::Held;
                }
                Outcome::NativeHeld {
                    recheck_ms: now.saturating_add(self.timing.held_recheck_ms),
                }
            }
            Some("delivered") => {
                pending.remove(&msg_id);
                Outcome::NativeAccepted {
                    evidence: format!("native receipt delivered for {msg_id}"),
                }
            }
            Some("dropped") => {
                pending.remove(&msg_id);
                Outcome::OutcomeUnknown {
                    reason: "native dropped receipt; context acceptance not excluded".into(),
                }
            }
            Some(other) => {
                pending.remove(&msg_id);
                Outcome::KnownUnsent {
                    evidence: format!("native inbox {other} the message before any hold"),
                }
            }
            None => {
                let deadline_ms = now.saturating_add(self.timing.receipt_deadline_ms);
                if let Some(entry) = pending.get_mut(&msg_id) {
                    entry.waiting = Waiting::NoReceipt {
                        manifest: attempt.manifest.clone(),
                        transcript: binding.transcript.clone(),
                        deadline_ms,
                    };
                }
                Outcome::WrittenNoReceipt {
                    evidence: format!(
                        "later frame {msg_id} written; no receipt yet (ordinary for an idle recipient)"
                    ),
                    receipt_deadline_ms: deadline_ms,
                }
            }
        }
    }
}
