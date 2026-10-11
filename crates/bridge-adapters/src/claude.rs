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
//! The descriptor also decides whether the message path exists at all: a
//! descriptor of exactly this session and PID without an inbox is positive
//! runtime disablement (a restricted Claude session ignores
//! `--messaging-socket-path`), so the message capability is withdrawn and
//! recorded in core before any further acceptance; a descriptor not yet
//! written is only a transient hold.
//!
//! Receipts: the user frame names a long-lived callback socket this daemon
//! keeps in the inbox's directory (the native reply-address rule). A
//! receipt is correlated by the attempt's unguessable message id (known
//! only to the recipient process through its authenticated inbox and to
//! this daemon) *and* by the sender's kernel identity, read first thing
//! after accept: it must be this user and the attested recipient PID. A
//! sender whose identity can no longer be read (it closed before the
//! daemon asked; the kernel stops reporting a closed peer's PID) is
//! ignored, fail closed — the attempt then stays held or unreceipted and
//! core raises the overdue incident. Within the short receipt window:
//! `held` is a
//! non-terminal hold with a recheck deadline, `delivered` is native
//! acceptance, a refusal before any hold is known-unsent, and silence is
//! the ordinary `written_no_receipt`. Later receipts are recorded straight
//! into core: release after hold is acceptance; any negative after a hold
//! is an unknown outcome (no proof the loaded native classification means
//! no context acceptance). A written-without-receipt hand-off is
//! reconciled against the addressed session's own native transcript: an
//! `enqueue` of the exact manifest is native acceptance, and a peer-origin
//! user entry naming this hand-off's callback and containing the exact
//! manifest is context evidence (shapes observed on Claude 2.1.296; no
//! message id is assumed in the transcript). Absent evidence never retries. A daemon
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
use bridge_core::recovery::EvidenceTier;
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
        /// The addressed native session id (transcript entries must match).
        session: String,
        /// This hand-off's `from` value (`uds:<callback>`); a peer entry
        /// must name it to count as this daemon's delivery.
        from: String,
        /// One member `(publisher, event_id)` of the frozen manifest, the
        /// handle core evidence is recorded against (it applies to the
        /// whole manifest).
        member: (String, String),
        /// Whether native queue acceptance was already recorded.
        enqueued: bool,
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

/// A bound callback socket path and its inode identity `(dev, ino)`.
type BoundCallback = (PathBuf, (u64, u64));

/// Callback listeners and correlation shared by the carrier and its
/// background threads.
struct Hub {
    /// Custody for late outcomes.
    custody: Arc<dyn Custody>,
    /// In-flight hand-offs by message id.
    pending: Mutex<HashMap<String, Pending>>,
    /// Callback socket path and its bound inode `(dev, ino)` per inbox
    /// directory; the inode lets drop remove only sockets this hub bound.
    listeners: Mutex<HashMap<PathBuf, BoundCallback>>,
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

/// What the session descriptor of the attested harness process says about
/// its native inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxState {
    /// The descriptor names an absolute inbox socket.
    Socket(PathBuf),
    /// The descriptor of exactly this session and PID exists but advertises
    /// no inbox: the loaded harness runs with messaging disabled (Claude
    /// 2.1.296 writes such a descriptor in a restricted session, where it
    /// ignores `--messaging-socket-path`). Positive runtime disablement.
    Disabled,
    /// No descriptor of this session and PID (not written yet, or the
    /// process is gone): transient or unknown, never "disabled" and never
    /// inactive.
    Absent,
}

/// Reads the inbox state of `session` owned by exactly `pid` from the
/// store's session registry (owned, regular, bounded files only).
pub fn inbox_state(store: &Path, session: &str, pid: u32, uid: u32) -> InboxState {
    registry_entries(store)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .take(MAX_DESCRIPTORS)
        .find_map(|path| {
            let map = owned_json(&path, uid)?;
            let matches = map.get("sessionId").and_then(Value::as_str) == Some(session)
                && map.get("pid").and_then(Value::as_u64) == Some(u64::from(pid));
            matches.then(|| match map.get("messagingSocketPath") {
                Some(Value::String(socket)) if Path::new(socket).is_absolute() => {
                    InboxState::Socket(PathBuf::from(socket))
                }
                None | Some(Value::Null) => InboxState::Disabled,
                // A malformed value is not a positive disablement.
                Some(_) => InboxState::Absent,
            })
        })
        .unwrap_or(InboxState::Absent)
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
        if let Some((path, _)) = listeners.get(directory)
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
        let bound = std::fs::symlink_metadata(&path)?;
        let identity = (bound.dev(), bound.ino());
        let hub = Arc::clone(self);
        std::thread::Builder::new()
            .name("bridge-claude-callback".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    hub.accept_receipt(stream);
                }
            })?;
        listeners.insert(directory.to_path_buf(), (path.clone(), identity));
        Ok(path)
    }

    /// Removes every callback socket this hub bound, only while the path is
    /// still the exact inode it bound (a replacement is never touched).
    fn remove_callbacks(&self) {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        for (path, identity) in listeners.values() {
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == *identity)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Derives an unguessable per-purpose value from this hub's secret.
    fn derive(&self, purpose: &str) -> String {
        let mut material = self.secret.to_vec();
        material.extend_from_slice(purpose.as_bytes());
        crate::server::sha256_hex(&material)
    }

    /// Reads one bounded receipt connection and routes it.
    ///
    /// The sender's kernel identity is read before anything else. A sender
    /// whose identity is unreadable (already closed) or of another user is
    /// ignored without reading: a receipt never counts without the
    /// recipient PID, whatever message id it names.
    fn accept_receipt(&self, stream: UnixStream) {
        let peer = match os::peer_identity(&stream) {
            Ok(peer) if peer.uid == self.uid => peer,
            Ok(_) => return,
            Err(_) => {
                log_event(
                    "warn",
                    "claude_receipt_unverifiable",
                    &[("reason", "sender identity unreadable; receipt ignored")],
                );
                return;
            }
        };
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
                self.route(&msg_id, &status, peer.pid);
            }
        }
    }

    /// Routes one correlated receipt from the kernel-identified sender
    /// `pid`, which must be the attempt's recipient PID.
    fn route(&self, msg_id: &str, status: &str, pid: u32) {
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = pending.get_mut(msg_id) else {
            return;
        };
        if pid != entry.recipient_pid {
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

    /// Records one positive evidence tier for an attempt in core.
    fn evidence(
        &self,
        fence: &AttemptFence,
        member: &(String, String),
        tier: EvidenceTier,
        detail: &str,
    ) {
        let recorded = with_custody(self.custody.as_ref(), |storage| {
            storage.record_evidence(
                &member.0,
                &member.1,
                fence.attempt_seq,
                tier,
                detail,
                current_unix_millis(),
            )
        });
        if !matches!(recorded, Some(Ok(_))) {
            log_event("warn", "claude_transcript_evidence_unrecorded", &[]);
        }
    }

    /// One reconciliation pass over written-without-receipt hand-offs against
    /// the addressed session's own native transcript.
    ///
    /// A user entry of that session whose native peer origin names this
    /// hand-off's `from` and whose content contains the exact manifest is
    /// context evidence (the manifest entered the conversation); it settles
    /// the attempt. A queue `enqueue` of that session whose content is the
    /// exact manifest is native acceptance; it is recorded once and the
    /// pass keeps looking for context until the deadline. Past the deadline
    /// the entry is forgotten (core holds the recheck and raises the
    /// incident). No message id is assumed to appear in the transcript, and
    /// absence never causes a resend.
    fn close_pass(&self) {
        let now = current_unix_millis();
        type Candidate = (
            String,
            AttemptFence,
            String,
            Option<PathBuf>,
            String,
            String,
            (String, String),
            bool,
            u64,
        );
        let candidates: Vec<Candidate> = {
            let pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending
                .iter()
                .filter_map(|(id, entry)| match &entry.waiting {
                    Waiting::NoReceipt {
                        manifest,
                        transcript,
                        session,
                        from,
                        member,
                        enqueued,
                        deadline_ms,
                    } => Some((
                        id.clone(),
                        entry.fence.clone(),
                        manifest.clone(),
                        transcript.clone(),
                        session.clone(),
                        from.clone(),
                        member.clone(),
                        *enqueued,
                        *deadline_ms,
                    )),
                    _ => None,
                })
                .collect()
        };
        for (id, fence, manifest, transcript, session, from, member, enqueued, deadline) in
            candidates
        {
            let found = transcript
                .as_deref()
                .map(|path| transcript_evidence(path, &manifest, self.uid, &session, &from))
                .unwrap_or_default();
            if found.context {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
                self.evidence(
                    &fence,
                    &member,
                    EvidenceTier::ContextObserved,
                    "native transcript of the attested session holds this daemon's peer message (origin from its callback) containing the exact manifest as conversation input",
                );
            } else if found.enqueued && !enqueued {
                if let Some(Pending {
                    waiting: Waiting::NoReceipt { enqueued, .. },
                    ..
                }) = self
                    .pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get_mut(&id)
                {
                    *enqueued = true;
                }
                self.evidence(
                    &fence,
                    &member,
                    EvidenceTier::NativeAccepted,
                    "native transcript of the attested session records an inbox enqueue of the exact manifest",
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

/// Positive transcript evidence for one hand-off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TranscriptEvidence {
    /// A peer-origin user entry from this hand-off's callback contains the
    /// exact manifest (the manifest entered the conversation).
    pub context: bool,
    /// A queue `enqueue` entry carries exactly the manifest (native inbox
    /// acceptance).
    pub enqueued: bool,
}

/// Scans the bounded tail of an owned transcript file for positive evidence
/// of one hand-off, using the entry shapes Claude 2.1.296 writes.
///
/// Context: `type == "user"`, `sessionId == session`,
/// `origin == {kind: "peer", from}` with this hand-off's `from`, and message
/// content (a string or text parts) containing the exact manifest (the
/// native inbox wraps it in its own peer framing). Enqueued:
/// `type == "queue-operation"`, `operation == "enqueue"`,
/// `sessionId == session`, content equal to the manifest (trailing
/// whitespace ignored). Anything else, including a matching text without
/// the peer origin, is no evidence. Unreadable, foreign-owned or non-regular
/// files yield none.
pub fn transcript_evidence(
    path: &Path,
    manifest: &str,
    uid: u32,
    session: &str,
    from: &str,
) -> TranscriptEvidence {
    let mut found = TranscriptEvidence::default();
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return found;
    };
    if !metadata.is_file() || metadata.uid() != uid || manifest.is_empty() {
        return found;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return found;
    };
    let start = metadata.len().saturating_sub(MAX_TRANSCRIPT_TAIL);
    let mut text = String::new();
    if file.seek(SeekFrom::Start(start)).is_err()
        || file
            .take(MAX_TRANSCRIPT_TAIL)
            .read_to_string(&mut text)
            .is_err()
    {
        return found;
    }
    for line in text.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if entry.get("sessionId").and_then(Value::as_str) != Some(session) {
            continue;
        }
        match entry.get("type").and_then(Value::as_str) {
            Some("user") => {
                let origin = &entry["origin"];
                if origin.get("kind").and_then(Value::as_str) != Some("peer")
                    || origin.get("from").and_then(Value::as_str) != Some(from)
                {
                    continue;
                }
                let content = &entry["message"]["content"];
                let contains = match content {
                    Value::String(text) => text.contains(manifest),
                    Value::Array(parts) => parts.iter().any(|part| {
                        part.get("text")
                            .and_then(Value::as_str)
                            .is_some_and(|text| text.contains(manifest))
                    }),
                    _ => false,
                };
                found.context |= contains;
            }
            Some("queue-operation") => {
                found.enqueued |= entry.get("operation").and_then(Value::as_str) == Some("enqueue")
                    && entry
                        .get("content")
                        .and_then(Value::as_str)
                        .is_some_and(|content| content.trim_end() == manifest.trim_end());
            }
            _ => {}
        }
    }
    found
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

impl Drop for ClaudeLaterCarrier {
    /// Removes the callback sockets this carrier bound in inbox
    /// directories, so a stopped daemon leaves no endpoint behind.
    /// Unresolved hand-offs stay with core (recheck deadlines, incidents).
    fn drop(&mut self) {
        self.hub.remove_callbacks();
    }
}

impl DispatchCarrier for ClaudeLaterCarrier {
    /// Attests Claude recipients from the registry; anything else is not
    /// this carrier's.
    ///
    /// The attested process's session descriptor decides the message path:
    /// a positively disabled inbox withdraws the message capability (also
    /// recorded in core, so later message publications refuse before
    /// acceptance) and is returned as such, so core holds visibly instead of
    /// treating the path as supported; a descriptor not yet written (absent)
    /// is a transient condition reported as an attestation error (a hold),
    /// never as disabled or inactive.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if recipient.harness != Harness::ClaudeCode {
            return Err("not a Claude recipient".into());
        }
        let (attestation, binding) = lock_registry(&self.registry).attest_recipient(recipient)?;
        match inbox_state(
            &binding.store,
            &recipient.native_session_id,
            binding.harness.0,
            self.hub.uid,
        ) {
            InboxState::Socket(_) => Ok(attestation),
            InboxState::Absent => Err(
                "the recipient has not advertised its native inbox yet (transient, not inactive)"
                    .into(),
            ),
            InboxState::Disabled => {
                let disabled = lock_registry(&self.registry)
                    .disable_message_for(recipient)
                    .ok_or_else(|| "recipient binding vanished".to_string())?;
                let observed = with_custody(self.hub.custody.as_ref(), |storage| {
                    storage.observe_binding(&disabled, current_unix_millis())
                });
                if !matches!(observed, Some(Ok(()))) {
                    log_event("warn", "claude_inbox_disablement_unrecorded", &[]);
                }
                Ok(disabled)
            }
        }
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
        let socket = match inbox_state(&binding.store, session, pid, self.hub.uid) {
            InboxState::Socket(socket) => socket,
            InboxState::Disabled => {
                return unsent(
                    "the attested harness process runs with its native inbox disabled".into(),
                );
            }
            InboxState::Absent => {
                return unsent("no inbox descriptor for the attested harness process".into());
            }
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
                        session: session.clone(),
                        from: format!("uds:{}", callback.display()),
                        member: attempt
                            .members
                            .first()
                            .map(|member| (member.publisher.clone(), member.event_id.clone()))
                            .unwrap_or_default(),
                        enqueued: false,
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

#[cfg(test)]
mod tests {
    //! Receipt authentication at the callback.

    use super::*;
    use bridge_core::Storage;

    /// A hub with one pending first-receipt wait for `recipient_pid`.
    fn hub_waiting(recipient_pid: u32) -> (Hub, Receiver<String>) {
        let limits = serde_json::from_value(json!({"max_admitted_events": 10})).unwrap();
        let custody: Arc<dyn Custody> =
            Arc::new(Mutex::new(Storage::open_in_memory(limits).unwrap()));
        let (sender, receiver) = mpsc::channel();
        let mut pending = HashMap::new();
        pending.insert(
            "msg-known".to_string(),
            Pending {
                fence: AttemptFence {
                    attempt_seq: 1,
                    recipient: "r".into(),
                    endpoint_epoch: 1,
                    manifest_hash: "h".into(),
                },
                recipient_pid,
                waiting: Waiting::First(sender),
            },
        );
        let hub = Hub {
            custody,
            pending: Mutex::new(pending),
            listeners: Mutex::new(HashMap::new()),
            uid: os::process_facts(std::process::id()).unwrap().uid.unwrap(),
            secret: [7; 32],
        };
        (hub, receiver)
    }

    /// Writes one receipt naming the known message id and returns the
    /// accepted server end; with `close_first` the sender is gone before
    /// the server accepts (its PID is no longer readable).
    fn receipt_stream(close_first: bool) -> (UnixStream, Option<UnixStream>) {
        let dir = std::env::temp_dir().join(format!(
            "m2rcpt{}{}",
            std::process::id(),
            &crate::server::sha256_hex(&os::random_bytes().unwrap())[..8]
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("c.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        let line = json!({"type":"control","action":"peer_message_status","orig_msg_id":"msg-known","status":"delivered"});
        writeln!(client, "{line}").unwrap();
        let kept = if close_first {
            drop(client);
            None
        } else {
            client.shutdown(std::net::Shutdown::Write).unwrap();
            Some(client)
        };
        let (server, _) = listener.accept().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        (server, kept)
    }

    /// A sender that closed before its identity was read is ignored even
    /// with the known message id and the right uid.
    #[test]
    fn disconnected_sender_with_known_id_is_ignored() {
        let (hub, receiver) = hub_waiting(std::process::id());
        let (server, _) = receipt_stream(true);
        hub.accept_receipt(server);
        assert!(
            receiver.try_recv().is_err(),
            "an unverifiable receipt was routed"
        );
    }

    /// A connected sender with the known id but another PID is ignored;
    /// the same receipt from the recipient PID is routed.
    #[test]
    fn connected_sender_must_be_the_recipient_pid() {
        let (hub, receiver) = hub_waiting(std::process::id() + 1);
        let (server, _kept) = receipt_stream(false);
        hub.accept_receipt(server);
        assert!(receiver.try_recv().is_err(), "a foreign PID was routed");
        let (hub, receiver) = hub_waiting(std::process::id());
        let (server, _kept) = receipt_stream(false);
        hub.accept_receipt(server);
        assert_eq!(receiver.try_recv().unwrap(), "delivered");
    }
}
