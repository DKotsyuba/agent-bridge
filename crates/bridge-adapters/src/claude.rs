//! Claude `message` carrier: authenticated native peer send with
//! `priority = "later"`, a callback socket unique to each attempt, and
//! positive closure of written-without-receipt hand-offs.
//!
//! A recipient whose own environment names a native owner socket is not sent
//! an inbox frame at all: it is woken, only while positively idle and with no
//! inbox descriptor needed, through that owner ([`crate::owner`]), selected
//! before this carrier's inbox route and without fallback to it.
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
//! written is only a transient hold. An inbox that appears later in the
//! same incarnation restores the message capability only when the harness
//! policy grants it (never a promotion). Every such change is recorded
//! in core first and applied to the registry only after that succeeded,
//! and only to the exact binding (epoch and incarnation) it was observed
//! under; withdrawn bindings the policy grants message to are re-checked every 2 s even
//! with no work pending, since publications refuse meanwhile.
//!
//! Receipts: the user frame names a callback socket this daemon binds in
//! the inbox's directory (the native reply-address rule) for this one
//! attempt only: its name derives from the attempt's message id, it is
//! unlinked when the attempt settles or expires, and at most
//! [`ClaudeTiming::max_callbacks`] exist at once (with all in use the
//! recipient is held at attestation, before core reserves an attempt). Earlier versions shared one callback per
//! daemon and inbox directory, so a historical peer entry of the same
//! session and manifest could settle a later attempt after a manual retry;
//! the per-attempt origin is what makes evidence per attempt. A receipt
//! on a callback is accepted only for that callback's own message id
//! (unguessable, known only to the recipient process through its
//! authenticated inbox and to this daemon) *and* only from the sender's
//! kernel identity, read first thing
//! after accept: it must be this user and the attested recipient PID. A
//! sender whose identity can no longer be read (it closed before the
//! daemon asked; the kernel stops reporting a closed peer's PID) is
//! ignored, fail closed — the attempt then stays held or unreceipted and
//! core raises the overdue incident. Within the short receipt window:
//! `held` is a
//! non-terminal hold with a recheck deadline, `delivered` is native
//! acceptance, any native negative status (a refusal included) is an unknown
//! outcome because it comes after the write and its no-effect meaning is not
//! qualified for the supported build (only local failures before any byte is
//! written are known-unsent), and silence is the ordinary `written_no_receipt`. Receipts that race the first one are
//! kept in order: a `held` followed by a terminal receipt inside the same
//! window settles on the terminal one (`delivered` accepted, any negative
//! unknown), so the second is never lost to the window's single waiter.
//! Contradictory receipts in one window (a different status after the first
//! terminal one, such as `delivered` then `held`) are an unknown outcome as
//! well. Nothing is retried automatically, and a delivery arriving later on
//! another connection after a negative was settled is ignored (the callback
//! is closed), leaving the unknown outcome and its incident.
//! Later receipts are recorded straight
//! into core: release after hold is acceptance; any negative after a hold
//! is an unknown outcome (no proof the loaded native classification means
//! no context acceptance). A written-without-receipt hand-off is
//! reconciled against the addressed session's own native transcript: only
//! a peer-origin user entry of that session naming this attempt's own
//! callback (`origin.from`) and containing the exact manifest is evidence
//! (context observed). A `queue-operation` `enqueue` carries no attempt
//! identity (the same manifest is re-sent on a retry), so it is not
//! evidence. Shapes observed on Claude 2.1.296; no message id is assumed in
//! the transcript. Absent evidence never retries. A daemon restart forgets
//! callbacks: core's recheck deadlines turn those attempts into retained
//! incidents, never replays.

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
use crate::registry::{RecipientBinding, Registry};
use crate::server::{Custody, lock_registry, with_custody};

/// Largest manifest the native inbox accepts in one message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 4096;

/// Largest descriptor or key file read, in bytes.
const MAX_DESCRIPTOR_BYTES: u64 = 16 * 1024;

/// Most descriptor files scanned per send.
const MAX_DESCRIPTORS: usize = 512;

/// Largest receipt frame, in bytes.
const MAX_RECEIPT_BYTES: u64 = 4096;

/// Default bound of per-attempt callback sockets live at once (see
/// [`ClaudeTiming::max_callbacks`]).
const MAX_CALLBACKS: usize = 64;

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
    /// Most per-attempt callback sockets (unsettled hand-offs) live at
    /// once. While all are in use, attestation holds the recipient
    /// visibly, so no attempt is reserved or consumed until a slot frees.
    pub max_callbacks: usize,
    /// Period of the background pass (transcript closure, expiry and the
    /// withdrawn-capability re-check).
    pub close_interval: Duration,
}

impl Default for ClaudeTiming {
    /// 1.5 s first-receipt window, 10 min held recheck, 5 min closure, 64
    /// callback slots, 2 s background pass.
    fn default() -> Self {
        ClaudeTiming {
            receipt_wait: Duration::from_millis(1_500),
            held_recheck_ms: 10 * 60_000,
            receipt_deadline_ms: 5 * 60_000,
            max_callbacks: MAX_CALLBACKS,
            close_interval: Duration::from_secs(2),
        }
    }
}

/// What one in-flight hand-off waits for.
#[derive(Debug)]
enum Waiting {
    /// `send` is inside its receipt window.
    First(Sender<String>),
    /// Held natively; a later release or drop is expected until the
    /// recheck horizon `until_ms` (Unix epoch ms), after which the hub
    /// forgets it (core raises the overdue incident).
    Held {
        /// Recheck horizon.
        until_ms: u64,
    },
    /// Written without a receipt; closure by late receipt or transcript.
    NoReceipt {
        /// The exact manifest text.
        manifest: String,
        /// The session transcript, when the hooks reported one.
        transcript: Option<PathBuf>,
        /// The addressed native session id (transcript entries must match).
        session: String,
        /// This hand-off's own `from` value (`uds:<per-attempt callback>`);
        /// a peer entry must name it to count as this attempt's delivery.
        from: String,
        /// One member `(publisher, event_id)` of the frozen manifest, the
        /// handle core evidence is recorded against (it applies to the
        /// whole manifest).
        member: (String, String),
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
    /// Per-attempt callback socket path and its bound inode `(dev, ino)`,
    /// keyed by the attempt's message id; the inode lets cleanup remove
    /// only sockets this hub bound. Bounded by `max_callbacks`.
    callbacks: Mutex<HashMap<String, BoundCallback>>,
    /// Bound of `callbacks` ([`ClaudeTiming::max_callbacks`]).
    max_callbacks: usize,
    /// Recheck horizon of a held hand-off in milliseconds
    /// ([`ClaudeTiming::held_recheck_ms`]); used by every path that holds,
    /// first-window or late.
    held_recheck_ms: u64,
    /// Serializes message capability changes (dispatch attestation and the
    /// periodic sweep), so an observation and its core record and registry
    /// commit are never interleaved with another change. Taken before, and
    /// never while holding, the registry or custody lock.
    sync: Mutex<()>,
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
    /// This attempt's own callback socket.
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

/// Sorted entries of the store's session registry that satisfy `keep`, at
/// most `MAX_DESCRIPTORS`.
///
/// `keep` is a name-only test applied while listing, before the bound, so
/// unrelated entries of a wide store can never push a wanted file out of
/// the bounded window; no file is opened here. Listing is one directory
/// pass (ponytail: O(entries) names, no I/O per entry; a per-process
/// subdirectory in the harness layout would make it O(1)).
fn registry_entries(store: &Path, keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(store.join("sessions"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| keep(path))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    paths.truncate(MAX_DESCRIPTORS);
    paths
}

/// Current native Claude session facts used only for recipient discovery.
/// No token, socket or caller authority is imported from this view.
#[derive(Debug)]
pub(crate) struct SessionHint {
    /// Native descriptor process id, still independently checked against the OS.
    pub pid: u32,
    /// Positive native idle/busy status; unknown or waiting descriptors cannot bootstrap.
    pub lifecycle: bridge_core::dispatch::Lifecycle,
    /// Descriptor modification time in Unix seconds; predating a process refuses PID reuse.
    pub written_at: i64,
}

/// Finds an owner-owned bounded native descriptor naming exactly `session` in
/// `store`. Only current interactive Claude sessions can bootstrap a recipient.
/// Returns no caller identity or credentials; registry must check UID, process
/// incarnation, marked-harness executable and native store before trusting it.
/// Unknown/approval statuses remain held, and files cannot make a PID live.
pub(crate) fn session_hint(store: &Path, session: &str, uid: u32) -> Option<SessionHint> {
    registry_entries(store, |p| p.extension().is_some_and(|x| x == "json"))
        .into_iter()
        .find_map(|path| {
            let map = owned_json(&path, uid)?;
            if map.get("sessionId")?.as_str()? != session
                || map.get("kind")?.as_str()? != "interactive"
            {
                return None;
            }
            let pid = u32::try_from(map.get("pid")?.as_u64()?)
                .ok()
                .filter(|p| *p > 0)?;
            let lifecycle = match map.get("status").and_then(Value::as_str) {
                Some("idle") => bridge_core::dispatch::Lifecycle::Inactive,
                Some("busy") => bridge_core::dispatch::Lifecycle::Active,
                _ => return None,
            };
            let written_at = std::fs::symlink_metadata(&path).ok()?.mtime();
            Some(SessionHint {
                pid,
                lifecycle,
                written_at,
            })
        })
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
///
/// Claude 2.1.296 writes one descriptor per process at
/// `<store>/sessions/<pid>.json`; that exact file is read first, so the
/// supported layout costs one bounded file read and is never starved by
/// other descriptors in a wide store. Only when it is missing, or does not
/// name exactly this session and PID, does the bounded legacy scan look for
/// a descriptor under another name (at most `MAX_DESCRIPTORS` JSON files
/// in sorted order). Nothing found is [`InboxState::Absent`].
pub fn inbox_state(store: &Path, session: &str, pid: u32, uid: u32) -> InboxState {
    let direct = store.join("sessions").join(format!("{pid}.json"));
    if let Some(state) = descriptor_state(&direct, session, pid, uid) {
        return state;
    }
    registry_entries(store, |path| {
        path.extension().is_some_and(|ext| ext == "json") && *path != direct
    })
    .into_iter()
    .find_map(|path| descriptor_state(&path, session, pid, uid))
    .unwrap_or(InboxState::Absent)
}

/// The inbox state one descriptor file gives for `session` and `pid`.
///
/// Returns `None` when the file is not an owned (`uid`), regular, bounded
/// JSON object naming exactly that session and PID. A named absolute
/// `messagingSocketPath` is [`InboxState::Socket`]; a missing or null one
/// is positive disablement; any other value is malformed and only
/// [`InboxState::Absent`] (never a disablement).
fn descriptor_state(path: &Path, session: &str, pid: u32, uid: u32) -> Option<InboxState> {
    let map = owned_json(path, uid)?;
    let matches = map.get("sessionId").and_then(Value::as_str) == Some(session)
        && map.get("pid").and_then(Value::as_u64) == Some(u64::from(pid));
    matches.then(|| match map.get("messagingSocketPath") {
        Some(Value::String(socket)) if Path::new(socket).is_absolute() => {
            InboxState::Socket(PathBuf::from(socket))
        }
        None | Some(Value::Null) => InboxState::Disabled,
        Some(_) => InboxState::Absent,
    })
}

/// Reads the recipient process's own peer token (never logged).
///
/// Only `<pid>.*.key` entries of exactly `pid` are candidates (selected by
/// name before the `MAX_DESCRIPTORS` bound, so a wide store cannot hide
/// them) and each must pass [`owned_json`]: an owned, regular, bounded
/// file, never a symlink. A token of another process is never read. No
/// candidate or no valid token is `None`.
fn peer_token(store: &Path, pid: u32, uid: u32) -> Option<String> {
    let prefix = format!("{pid}.");
    registry_entries(store, |path| {
        path.extension().is_some_and(|ext| ext == "key")
            && path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
    })
    .into_iter()
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
    /// Binds this hand-off's own callback socket in the inbox directory and
    /// starts its listener.
    ///
    /// One socket per attempt (named from this hub's secret and the
    /// attempt's message id) makes the native peer origin
    /// (`from = "uds:<path>"`) an attempt identity: transcript entries from
    /// any other attempt, including an earlier attempt of the same event
    /// with the same manifest, can never match this one. The listener only
    /// routes receipts naming this attempt's message id and stops once the
    /// attempt is released. At most `max_callbacks` are live at once;
    /// attestation holds before that bound is reached
    /// ([`Hub::callback_capacity`]), so the error here is only a defence.
    fn callback_for_attempt(
        self: &Arc<Self>,
        directory: &Path,
        msg_id: &str,
    ) -> std::io::Result<PathBuf> {
        let mut callbacks = self.callbacks.lock().unwrap_or_else(|p| p.into_inner());
        if callbacks.len() >= self.max_callbacks {
            return Err(std::io::Error::other("callback capacity reached"));
        }
        let name = format!("{}.sock", &self.derive(&format!("callback:{msg_id}"))[..12]);
        let path = directory.join(name);
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let bound = std::fs::symlink_metadata(&path)?;
        callbacks.insert(
            msg_id.to_string(),
            (path.clone(), (bound.dev(), bound.ino())),
        );
        drop(callbacks);
        let hub = Arc::downgrade(self);
        let expected = msg_id.to_string();
        std::thread::Builder::new()
            .name("bridge-claude-callback".into())
            .spawn(move || {
                while let Some(hub) = hub.upgrade() {
                    if !hub
                        .callbacks
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .contains_key(&expected)
                    {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            hub.accept_receipt(stream, &expected);
                        }
                        Err(_) => {
                            drop(hub);
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })?;
        Ok(path)
    }

    /// Unlinks one bound callback socket, only while the path is still the
    /// exact inode it bound (a replacement is never touched).
    fn unlink(bound: &BoundCallback) {
        let (path, identity) = bound;
        if std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == *identity)
        {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Forgets one hand-off: its pending entry and its callback socket (the
    /// listener stops on its next poll). Must not be called while holding
    /// the pending or callbacks lock.
    ///
    /// Returns whether this call removed the pending entry, so of two
    /// concurrent closers only one records the hand-off's outcome.
    fn release(&self, msg_id: &str) -> bool {
        let removed = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(msg_id)
            .is_some();
        let bound = self
            .callbacks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(msg_id);
        if let Some(bound) = bound {
            Hub::unlink(&bound);
        }
        removed
    }

    /// Whether a callback slot is free for the next hand-off; when all
    /// `max_callbacks` are in use, first releases held hand-offs past their
    /// recheck horizon ([`Hub::expire`]: memory only, no transcript or other
    /// file read, so
    /// this check stays cheap on every attestation; positive transcript
    /// closure stays with the background pass).
    ///
    /// Only the dispatching carrier binds callbacks, after its own
    /// attestation, and every other path only releases them, so a slot free
    /// here is still free at the following `send`.
    ///
    /// # Errors
    ///
    /// Every slot is held by an unsettled hand-off: a transient
    /// attestation hold (core records it visibly; no attempt is reserved or
    /// consumed, the payload stays pending).
    fn callback_capacity(&self) -> Result<(), String> {
        let full = || {
            self.callbacks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len()
                >= self.max_callbacks
        };
        if full() {
            self.expire(current_unix_millis());
        }
        if full() {
            return Err(format!(
                "all {} native callback slots are held by unsettled hand-offs (transient; no attempt consumed)",
                self.max_callbacks
            ));
        }
        Ok(())
    }

    /// Releases, in memory only, the held hand-offs past their recheck
    /// horizon at `now` (Unix epoch ms); core keeps their recheck deadlines
    /// and raises the incidents. Reads no file.
    ///
    /// Written-without-receipt hand-offs are deliberately left to the
    /// background pass ([`Hub::close_pass`]), which reads the transcript
    /// before releasing one past its deadline, so evidence appended after
    /// the previous pass, even across the deadline, is still recorded. Their
    /// slots free on a following transcript-first pass: the delay between
    /// passes is [`ClaudeTiming::close_interval`] (2 s by default), plus
    /// the time spent scanning transcripts. Meanwhile the recipient stays
    /// held at attestation with no attempt reserved.
    fn expire(&self, now: u64) {
        let expired: Vec<String> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter_map(|(id, entry)| match &entry.waiting {
                Waiting::Held { until_ms } if now > *until_ms => Some(id.clone()),
                _ => None,
            })
            .collect();
        for id in expired {
            self.release(&id);
        }
    }

    /// Records an attestation with a changed capability in core; returns
    /// whether core stored it (a refusal or unattached custody is logged).
    fn observe(&self, attestation: &Attestation) -> bool {
        let observed = with_custody(self.custody.as_ref(), |storage| {
            storage.observe_binding(attestation, current_unix_millis())
        });
        let stored = matches!(observed, Some(Ok(())));
        if !stored {
            log_event("warn", "claude_capability_change_unrecorded", &[]);
        }
        stored
    }

    /// Brings the message capability of `recipient` in line with what its
    /// attested harness process's session descriptor says now, under the
    /// registry snapshot `snapshot`.
    ///
    /// A positively disabled inbox withdraws message; an inbox advertised
    /// later by the same session and incarnation (native late binding)
    /// restores it, never beyond the harness policy's grant. A change
    /// is recorded in core first and applied to the registry only after
    /// that succeeded, so registry and core never disagree in the granting
    /// direction and a failed core write is simply retried by the next
    /// check (dispatch attestation or [`Hub::refresh_withdrawn`]). The
    /// registry commit re-checks the snapshot's epoch and incarnation, so
    /// an observation of a replaced incarnation never changes the renewed
    /// binding. Serialized by `sync`; the registry and custody locks are
    /// never held together.
    ///
    /// Returns the changed attestation, or `None` when nothing changed.
    ///
    /// # Errors
    ///
    /// Transient holds, never a capability verdict: no descriptor of this
    /// session and PID yet (or a malformed one), the change could not be
    /// recorded in core yet, or the binding was renewed or retired since
    /// the snapshot.
    fn sync_message(
        &self,
        registry: &Mutex<Registry>,
        recipient: &NativeAddress,
        snapshot: &RecipientBinding,
    ) -> Result<Option<Attestation>, String> {
        let _serial = self.sync.lock().unwrap_or_else(|p| p.into_inner());
        let message = match inbox_state(
            &snapshot.store,
            &recipient.native_session_id,
            snapshot.harness.0,
            self.uid,
        ) {
            InboxState::Socket(_) => true,
            InboxState::Disabled => false,
            InboxState::Absent => {
                return Err(
                    "the recipient has not advertised its native inbox yet (transient, not inactive)"
                        .into(),
                );
            }
        };
        let change = lock_registry(registry).message_change(recipient, snapshot, message)?;
        let Some(change) = change else {
            return Ok(None);
        };
        if !self.observe(&change) {
            return Err(
                "the message capability change could not be recorded in core yet (transient; retried)"
                    .into(),
            );
        }
        lock_registry(registry).commit_message(recipient, snapshot, message)?;
        log_event(
            "info",
            if message {
                "claude_message_restored"
            } else {
                "claude_message_withdrawn"
            },
            &[("recipient", &recipient.to_canonical_string())],
        );
        Ok(Some(change))
    }

    /// Re-checks every live Claude binding whose message capability was
    /// withdrawn although the harness policy grants it, independent of pending
    /// work: while message is withdrawn, publications refuse before
    /// acceptance, so no dispatch would ever re-attest the recipient. A late
    /// inbox restores message here (recorded in core first); a still
    /// disabled or absent inbox, a gone process or a failed core write
    /// leaves the binding for the next pass.
    fn refresh_withdrawn(&self, registry: &Mutex<Registry>) {
        let withdrawn = lock_registry(registry).message_withdrawn(Harness::ClaudeCode);
        for address in withdrawn {
            let attested = lock_registry(registry).attest_recipient(&address);
            if let Ok((_, snapshot)) = attested {
                let _ = self.sync_message(registry, &address, &snapshot);
            }
        }
    }

    /// Removes every callback socket this hub bound (exact inodes only) and
    /// stops their listeners.
    fn remove_callbacks(&self) {
        let drained: Vec<BoundCallback> = self
            .callbacks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .map(|(_, bound)| bound)
            .collect();
        for bound in &drained {
            Hub::unlink(bound);
        }
    }

    /// Derives an unguessable per-purpose value from this hub's secret.
    fn derive(&self, purpose: &str) -> String {
        let mut material = self.secret.to_vec();
        material.extend_from_slice(purpose.as_bytes());
        crate::server::sha256_hex(&material)
    }

    /// Reads one bounded receipt connection on the callback of `expected`
    /// (one attempt's message id) and routes it.
    ///
    /// The sender's kernel identity is read before anything else. A sender
    /// whose identity is unreadable (already closed) or of another user is
    /// ignored without reading: a receipt never counts without the
    /// recipient PID. Receipts naming any other message id are ignored.
    fn accept_receipt(&self, stream: UnixStream, expected: &str) {
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
        let statuses: Vec<String> = text
            .lines()
            .filter_map(receipt)
            .filter(|(msg_id, _)| msg_id == expected)
            .map(|(_, status)| status)
            .collect();
        self.route_batch(expected, &statuses, peer.pid);
    }

    /// Routes the receipts of one connection, in order, as one step.
    ///
    /// While `send` is inside its window all of them are queued for it
    /// under one hold of the pending lock, so frames that arrived together
    /// are always seen together (and judged by `send` as one window).
    /// Otherwise each goes through [`Hub::route`] separately.
    fn route_batch(&self, msg_id: &str, statuses: &[String], pid: u32) {
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = pending.get_mut(msg_id)
                && pid == entry.recipient_pid
                && let Waiting::First(sender) = &entry.waiting
            {
                for status in statuses {
                    let _ = sender.send(status.clone());
                }
                return;
            }
        }
        for status in statuses {
            self.route(msg_id, status, pid);
        }
    }

    /// Routes one correlated receipt from the kernel-identified sender
    /// `pid`, which must be the attempt's recipient PID.
    ///
    /// While `send` is inside its window the status is queued for it (under
    /// the pending lock, in arrival order; [`Hub::route_batch`] queues a
    /// whole connection at once); afterwards a `delivered` is
    /// acceptance, a `held` after silence holds until
    /// [`ClaudeTiming::held_recheck_ms`] from now, and any other status is
    /// an unknown outcome.
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
            Waiting::Held { .. } | Waiting::NoReceipt { .. } => match status {
                "delivered" => Outcome::NativeAccepted {
                    evidence: format!("late native receipt delivered for {msg_id}"),
                },
                "held" if matches!(entry.waiting, Waiting::NoReceipt { .. }) => {
                    let recheck_ms = current_unix_millis().saturating_add(self.held_recheck_ms);
                    entry.waiting = Waiting::Held {
                        until_ms: recheck_ms,
                    };
                    Outcome::NativeHeld { recheck_ms }
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
        let settled = !matches!(late, Outcome::NativeHeld { .. });
        drop(pending);
        if settled {
            self.release(msg_id);
        }
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

    /// One reconciliation pass over this hub's hand-offs.
    ///
    /// A written-without-receipt hand-off settles as context evidence when
    /// the addressed session's own transcript holds a user entry whose
    /// native peer origin is *this attempt's* callback and whose content
    /// contains the exact manifest. The native inbox `enqueue` entry is not
    /// used: it carries only the manifest, which an earlier attempt of the
    /// same event shares. Past its deadline a hand-off is forgotten (core
    /// holds the recheck and raises the incident), as is a held hand-off
    /// past its recheck horizon. Absence never causes a resend.
    fn close_pass(&self) {
        let now = current_unix_millis();
        /// One written-without-receipt hand-off copied out of the pending
        /// map, so transcripts are read without holding its lock: message
        /// id, attempt fence, exact manifest, transcript path (if reported),
        /// addressed session id, this attempt's own `from`
        /// (`uds:<callback>`), the core member `(publisher, event_id)` that
        /// evidence is recorded against, and the closure deadline (Unix
        /// epoch ms).
        type Candidate = (
            String,
            AttemptFence,
            String,
            Option<PathBuf>,
            String,
            String,
            (String, String),
            u64,
        );
        let mut expired = Vec::new();
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
                        deadline_ms,
                    } => Some((
                        id.clone(),
                        entry.fence.clone(),
                        manifest.clone(),
                        transcript.clone(),
                        session.clone(),
                        from.clone(),
                        member.clone(),
                        *deadline_ms,
                    )),
                    Waiting::Held { until_ms } if now > *until_ms => {
                        expired.push(id.clone());
                        None
                    }
                    _ => None,
                })
                .collect()
        };
        for id in expired {
            self.release(&id);
        }
        for (id, fence, manifest, transcript, session, from, member, deadline) in candidates {
            let found = transcript.as_deref().is_some_and(|path| {
                transcript_has_handoff(path, &manifest, self.uid, &session, &from)
            });
            if found && self.release(&id) {
                self.evidence(
                    &fence,
                    &member,
                    EvidenceTier::ContextObserved,
                    "native transcript of the attested session holds this attempt's peer message (origin from its own callback) containing the exact manifest as conversation input",
                );
            } else if now > deadline {
                self.release(&id);
            }
        }
    }
}

/// Whether the bounded tail of an owned transcript file holds positive
/// evidence of one hand-off, using the entry shape Claude 2.1.296 writes for
/// a delivered peer message.
///
/// Matches a `type == "user"` entry with `sessionId == session`,
/// `origin == {kind: "peer", from}` where `from` is this attempt's own
/// callback (`uds:<path>`), and message content (a string or text parts)
/// containing the exact manifest (the native inbox wraps it in its own peer
/// framing). Entries of other sessions, other senders or other attempts,
/// and entries without a peer origin, are no evidence. Unreadable,
/// foreign-owned or non-regular files yield none.
///
/// At most the last `MAX_TRANSCRIPT_TAIL` bytes are read. When the file is
/// longer, the first (possibly partial, possibly split inside a multibyte
/// character) line of that window is skipped, so only whole lines are
/// parsed and a large non-ASCII transcript still closes; a window with no
/// line break yields none. A line that is exactly at the cut (the byte
/// before the window is a line break) is whole and kept. Each whole line is
/// parsed as strict UTF-8 JSON bytes: a line with malformed UTF-8 is not
/// evidence (it is never repaired into text that could match the
/// manifest), and a suffix of a skipped partial line is never parsed.
pub fn transcript_has_handoff(
    path: &Path,
    manifest: &str,
    uid: u32,
    session: &str,
    from: &str,
) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.uid() != uid || manifest.is_empty() {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    // Read one byte before the tail so a cut exactly on a line start is
    // told from a cut inside a line; everything up to the first newline of
    // that window is a possibly partial line (and possibly a split
    // multibyte character) and is dropped, so the rest is whole lines.
    let start = metadata.len().saturating_sub(MAX_TRANSCRIPT_TAIL + 1);
    let mut bytes = Vec::new();
    if file.seek(SeekFrom::Start(start)).is_err()
        || file
            .take(MAX_TRANSCRIPT_TAIL + 1)
            .read_to_end(&mut bytes)
            .is_err()
    {
        return false;
    }
    if start > 0 {
        let Some(newline) = bytes.iter().position(|&byte| byte == b'\n') else {
            return false;
        };
        bytes.drain(..=newline);
    }
    bytes.split(|&byte| byte == b'\n').any(|line| {
        // Strict: a line with any invalid UTF-8 is not JSON, so no byte
        // sequence is ever repaired into manifest text.
        let Ok(entry) = serde_json::from_slice::<Value>(line) else {
            return false;
        };
        if entry.get("type").and_then(Value::as_str) != Some("user")
            || entry.get("sessionId").and_then(Value::as_str) != Some(session)
        {
            return false;
        }
        let origin = &entry["origin"];
        if origin.get("kind").and_then(Value::as_str) != Some("peer")
            || origin.get("from").and_then(Value::as_str) != Some(from)
        {
            return false;
        }
        match &entry["message"]["content"] {
            Value::String(text) => text.contains(manifest),
            Value::Array(parts) => parts.iter().any(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.contains(manifest))
            }),
            _ => false,
        }
    })
}

impl ClaudeLaterCarrier {
    /// A carrier over `registry` whose late outcomes go to `custody`.
    ///
    /// Starts one background thread that, every
    /// [`ClaudeTiming::close_interval`] (2 s by default) while the carrier
    /// lives, closes written-without-receipt and expired hand-offs and
    /// re-checks withdrawn message capabilities (`Hub::refresh_withdrawn`).
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
            callbacks: Mutex::new(HashMap::new()),
            max_callbacks: timing.max_callbacks,
            held_recheck_ms: timing.held_recheck_ms,
            sync: Mutex::new(()),
            uid,
            secret: os::random_bytes()?,
        });
        let closer = Arc::downgrade(&hub);
        let swept = Arc::clone(&registry);
        let interval = timing.close_interval;
        std::thread::Builder::new()
            .name("bridge-claude-closure".into())
            .spawn(move || {
                while let Some(hub) = closer.upgrade() {
                    hub.close_pass();
                    hub.refresh_withdrawn(&swept);
                    drop(hub);
                    std::thread::sleep(interval);
                }
            })?;
        Ok(ClaudeLaterCarrier {
            registry,
            hub,
            timing,
        })
    }

    /// Validates the native owner route of a recipient whose own environment
    /// names an owner socket: the shared message candidate is revalidated
    /// outside the registry lock (exact PID/start, UID, executable and home), the
    /// owner is proven the exact owner-relay direct parent, and
    /// a final locked equality check closes the selection. It needs no inbox
    /// descriptor. Every failure is a hold; there is no fallback to the inbox.
    fn owner_route(
        &self,
        recipient: &NativeAddress,
    ) -> Result<(Attestation, RecipientBinding, PathBuf), String> {
        crate::registry::refresh_stale(&self.registry);
        let candidate = { lock_registry(&self.registry).message_candidate(recipient)? };
        let (attestation, binding) = candidate.validate()?;
        let socket = crate::owner::locate(&self.registry, binding.harness)?
            .ok_or("native owner locator is no longer present")?;
        lock_registry(&self.registry).message_current(&candidate)?;
        Ok((attestation, binding, socket))
    }

    /// One native owner hand-off of the frozen manifest for an owner-routed
    /// recipient. The unchanged epoch and a positive idle lifecycle are
    /// required, whatever the requested mode; anything else, and every failure
    /// before the request is written, is known-unsent. No inbox frame, callback
    /// socket or second route is ever used after this route is selected.
    fn send_owner(&self, attempt: &AttemptRecord, address: &NativeAddress) -> Outcome {
        let (attestation, binding, socket) = match self.owner_route(address) {
            Ok(found) => found,
            Err(reason) => {
                return Outcome::KnownUnsent {
                    evidence: format!("native owner route not proven: {reason}"),
                };
            }
        };
        if binding.epoch != attempt.fence.endpoint_epoch
            || attestation.lifecycle() != bridge_core::dispatch::Lifecycle::Inactive
        {
            return Outcome::KnownUnsent {
                evidence: "recipient epoch or idle lifecycle changed before owner hand-off".into(),
            };
        }
        crate::owner::deliver(
            &self.registry,
            &socket,
            binding.harness,
            Harness::ClaudeCode,
            &crate::owner::Handoff {
                thread_id: &address.native_session_id,
                call_id: &format!(
                    "agent-bridge-{}-{}",
                    attempt.fence.attempt_seq,
                    crate::registry::prefix_within(&attempt.fence.manifest_hash, 16)
                ),
                text: &attempt.manifest,
                deadline_ms: attempt.deadline_ms,
            },
        )
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
    /// The attested process's session descriptor decides the message path
    /// (`Hub::sync_message`): a positively disabled inbox withdraws the
    /// message capability (recorded in core first, so later message
    /// publications refuse before acceptance) and is returned as such, so
    /// core holds visibly instead of treating the path as supported; an
    /// inbox advertised later by the same session and incarnation (native
    /// late binding) restores message, only if the harness policy grants it; a
    /// descriptor not yet written, or a malformed one,
    /// is a transient condition reported as an attestation error (a hold),
    /// never as disabled, enabled or inactive. While every callback slot is
    /// held by an unsettled hand-off the recipient is held too
    /// (`Hub::callback_capacity`), before core reserves an attempt.
    ///
    /// A recipient whose own environment names a native owner socket is attested
    /// through that owner route instead ([`crate::owner`]): it needs no session
    /// descriptor or inbox, requires the exact direct-parent owner running a
    /// trusted executable, and
    /// any unprovable, unreadable or malformed locator is an attestation error
    /// (a hold) with no fallback to the inbox route. Only a positively idle
    /// lifecycle may then be woken; an absent locator keeps the behavior above.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if recipient.harness != Harness::ClaudeCode {
            return Err("not a Claude recipient".into());
        }
        let (attestation, binding) = {
            let mut registry = lock_registry(&self.registry);
            registry.discover_claude_recipient(recipient)?;
            registry.attest_recipient(recipient)?
        };
        if crate::owner::locator(binding.harness.0)?.is_some() {
            return Ok(self.owner_route(recipient)?.0);
        }
        let changed = self.hub.sync_message(&self.registry, recipient, &binding)?;
        self.hub.callback_capacity()?;
        Ok(changed.unwrap_or(attestation))
    }

    /// One `later` hand-off of the frozen manifest.
    ///
    /// Waits up to [`ClaudeTiming::receipt_wait`] for the first receipt,
    /// then, under the pending lock that `Hub::route` also holds while it
    /// queues a receipt, collects every receipt that raced it. The first
    /// terminal receipt decides (`delivered` is accepted; any negative is
    /// an unknown outcome, since it follows the write), unless a later
    /// receipt of the window contradicts it (another status, or a `held`
    /// after it), which is unknown; `held` alone
    /// holds until [`ClaudeTiming::held_recheck_ms`]; silence is written
    /// without receipt. A hand-off is never repeated here.
    ///
    /// For an owner-routed recipient (its environment names a native owner
    /// socket) the frozen manifest instead goes through the native owner
    /// ([`crate::owner`]) and none of the above applies: the unchanged epoch and
    /// a positive idle lifecycle are required, whatever the requested mode, and
    /// every failure before the request is written (including an unreadable
    /// environment or a bad locator) is known-unsent. After the write only a
    /// correlated, exactly shaped receipt is anything but an unknown outcome,
    /// which is retained and never resent; no inbox frame, callback socket or
    /// second route is used after selection.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        let unsent = |evidence: String| Outcome::KnownUnsent { evidence };
        let Ok(address) = NativeAddress::parse(&attempt.fence.recipient) else {
            return unsent("unparseable recipient".into());
        };
        let binding = match lock_registry(&self.registry).attest_recipient(&address) {
            Ok((_, binding)) => binding,
            Err(reason) => return unsent(format!("recipient not attested: {reason}")),
        };
        match crate::owner::locator(binding.harness.0) {
            Ok(None) => {}
            Ok(Some(_)) => return self.send_owner(attempt, &address),
            Err(reason) => return unsent(reason),
        }
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
        let msg_id = format!(
            "bridge_{}_{}",
            attempt.fence.attempt_seq,
            &self.hub.derive(&format!(
                "msg:{}:{}",
                attempt.fence.attempt_seq, attempt.fence.manifest_hash
            ))[..32]
        );
        let callback = match self.hub.callback_for_attempt(directory, &msg_id) {
            Ok(path) => path,
            Err(error) => return unsent(format!("callback socket unavailable: {error}")),
        };
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
            self.hub.release(&msg_id);
            return outcome;
        }
        let mut receipts: Vec<String> = first
            .recv_timeout(self.timing.receipt_wait)
            .ok()
            .into_iter()
            .collect();
        let now = current_unix_millis();
        let mut pending = self.hub.pending.lock().unwrap_or_else(|p| p.into_inner());
        // `Hub::route` sends under this lock, so receipts that raced the
        // first one (a `held` followed at once by its release) are all in
        // the channel now, and every later one sees the state set below.
        receipts.extend(first.try_iter());
        // After the first terminal receipt, any different receipt (another
        // terminal status, or a `held`) contradicts it: a possible effect
        // was reported next to a refusal, so it cannot be a known non-send.
        let contradictory = receipts
            .iter()
            .position(|status| status != "held")
            .is_some_and(|first| receipts[first + 1..].iter().any(|s| *s != receipts[first]));
        // The first terminal receipt decides; `held` only when none came.
        let status = receipts
            .iter()
            .find(|status| status.as_str() != "held")
            .or(receipts.first())
            .map(String::as_str);
        let settled = |pending: std::sync::MutexGuard<'_, HashMap<String, Pending>>,
                       outcome: Outcome| {
            drop(pending);
            self.hub.release(&msg_id);
            outcome
        };
        match status {
            Some(_) if contradictory => settled(
                pending,
                Outcome::OutcomeUnknown {
                    reason: "contradictory native receipts in one window; no proof of no context acceptance"
                        .into(),
                },
            ),
            Some("held") => {
                let recheck_ms = now.saturating_add(self.timing.held_recheck_ms);
                if let Some(entry) = pending.get_mut(&msg_id) {
                    entry.waiting = Waiting::Held {
                        until_ms: recheck_ms,
                    };
                }
                Outcome::NativeHeld { recheck_ms }
            }
            Some("delivered") => settled(
                pending,
                Outcome::NativeAccepted {
                    evidence: format!("native receipt delivered for {msg_id}"),
                },
            ),
            Some("dropped") => settled(
                pending,
                Outcome::OutcomeUnknown {
                    reason: "native dropped receipt; context acceptance not excluded".into(),
                },
            ),
            // Any other native status is written after the hand-off: its
            // no-effect meaning is not qualified for the supported build,
            // so it is never known-unsent (only local failures before the
            // write are), and it is never retried automatically.
            Some(other) => settled(
                pending,
                Outcome::OutcomeUnknown {
                    reason: format!(
                        "native {other} after a possible hand-off; no proof of no context acceptance"
                    ),
                },
            ),
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
            callbacks: Mutex::new(HashMap::new()),
            max_callbacks: MAX_CALLBACKS,
            held_recheck_ms: 10 * 60_000,
            sync: Mutex::new(()),
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

    /// A receipt arriving on one attempt's own callback but naming another
    /// attempt's message id is ignored, even from the recipient PID.
    #[test]
    fn receipt_for_another_attempt_on_this_callback_is_ignored() {
        let (hub, receiver) = hub_waiting(std::process::id());
        let (server, _kept) = receipt_stream(false);
        hub.accept_receipt(server, "msg-other-attempt");
        assert!(
            receiver.try_recv().is_err(),
            "a foreign attempt's receipt was routed"
        );
    }

    /// A sender that closed before its identity was read is ignored even
    /// with the known message id and the right uid.
    #[test]
    fn disconnected_sender_with_known_id_is_ignored() {
        let (hub, receiver) = hub_waiting(std::process::id());
        let (server, _) = receipt_stream(true);
        hub.accept_receipt(server, "msg-known");
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
        hub.accept_receipt(server, "msg-known");
        assert!(receiver.try_recv().is_err(), "a foreign PID was routed");
        let (hub, receiver) = hub_waiting(std::process::id());
        let (server, _kept) = receipt_stream(false);
        hub.accept_receipt(server, "msg-known");
        assert_eq!(receiver.try_recv().unwrap(), "delivered");
    }
}

#[cfg(test)]
mod transcript_tests {
    //! Bounded transcript-tail evidence over large non-ASCII transcripts.

    use super::*;

    /// A transcript larger than the tail bound whose cut falls inside a
    /// multibyte character still yields the exact accepted marker of the
    /// right session and callback, and never evidence of another session
    /// or sender.
    #[test]
    fn multibyte_transcript_over_the_tail_bound_still_closes() {
        let dir = std::env::temp_dir().join(format!("m2tail{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        let entry = |session: &str, from: &str, manifest: &str| {
            json!({"type": "user", "sessionId": session, "origin": {"kind": "peer", "from": from},
                   "message": {"content": format!("peer says {manifest}")}})
            .to_string()
        };
        let mut text = format!("{{\"type\":\"x\",\"t\":\"{}\"}}\n", "€".repeat(3_000_000));
        text.push_str(&entry("other-session", "uds:/cb", "MANIFEST-1"));
        text.push('\n');
        text.push_str(&entry("sess", "uds:/other-cb", "MANIFEST-1"));
        text.push('\n');
        std::fs::write(&path, &text).unwrap();
        let uid = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let cut = bytes.len() - MAX_TRANSCRIPT_TAIL as usize;
        assert_eq!(bytes[cut] & 0xC0, 0x80, "the tail must start mid-character");

        // Only foreign evidence so far: nothing closes.
        assert!(!transcript_has_handoff(
            &path,
            "MANIFEST-1",
            uid,
            "sess",
            "uds:/cb"
        ));
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{}", entry("sess", "uds:/cb", "MANIFEST-1")).unwrap();
        assert!(transcript_has_handoff(
            &path,
            "MANIFEST-1",
            uid,
            "sess",
            "uds:/cb"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A peer entry as one transcript line.
    fn entry_line(session: &str, from: &str, content: &str) -> String {
        json!({"type": "user", "sessionId": session, "origin": {"kind": "peer", "from": from},
               "message": {"content": content}})
        .to_string()
    }

    /// This process's uid.
    fn own_uid() -> u32 {
        os::process_facts(std::process::id()).unwrap().uid.unwrap()
    }

    /// A line with malformed UTF-8 is never repaired into manifest text: a
    /// manifest that itself contains U+FFFD does not match the invalid
    /// bytes a lossy decoder would turn into it, while the same text
    /// validly encoded does close.
    #[test]
    fn malformed_utf8_never_becomes_manifest_text() {
        let dir = std::env::temp_dir().join(format!("m2bad{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        let manifest = "MANIFEST\u{fffd}2";
        let valid = entry_line("sess", "uds:/cb", &format!("peer says {manifest}"));
        let mut bytes = valid.replace('\u{fffd}', "\u{1}").into_bytes();
        let at = bytes.iter().position(|&byte| byte == 1).unwrap();
        bytes.splice(at..=at, [0xff]);
        bytes.push(b'\n');
        std::fs::write(&path, &bytes).unwrap();
        assert!(!transcript_has_handoff(
            &path,
            manifest,
            own_uid(),
            "sess",
            "uds:/cb"
        ));
        std::fs::write(&path, format!("{valid}\n")).unwrap();
        assert!(transcript_has_handoff(
            &path,
            manifest,
            own_uid(),
            "sess",
            "uds:/cb"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The cut decides which lines are whole: when the tail starts inside a
    /// line whose remainder is itself a complete valid entry, that remainder
    /// is not evidence; when the byte before the tail is a line break the
    /// first line is whole and closes.
    #[test]
    fn cut_suffix_is_skipped_but_a_line_at_the_cut_is_kept() {
        let dir = std::env::temp_dir().join(format!("m2cut{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        let bare = entry_line("sess", "uds:/cb", "MANIFEST-3");
        // Pad the entry so that it is exactly the tail plus its line break.
        let entry = entry_line(
            "sess",
            "uds:/cb",
            &format!(
                "MANIFEST-3{}",
                "x".repeat(MAX_TRANSCRIPT_TAIL as usize - 1 - bare.len(),)
            ),
        );
        assert_eq!(entry.len() as u64, MAX_TRANSCRIPT_TAIL - 1);
        let uid = own_uid();
        // The tail starts exactly at the entry, mid-line (after a space, so
        // the first line of the window is itself valid JSON): skipped.
        std::fs::write(&path, format!("garbage-prefix {entry}\n")).unwrap();
        assert!(!transcript_has_handoff(
            &path,
            "MANIFEST-3",
            uid,
            "sess",
            "uds:/cb"
        ));
        // The same entry after a line break is a whole line at the cut.
        std::fs::write(&path, format!("whole line\n{entry}\n")).unwrap();
        assert!(transcript_has_handoff(
            &path,
            "MANIFEST-3",
            uid,
            "sess",
            "uds:/cb"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
