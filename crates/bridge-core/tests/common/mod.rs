//! Shared test helpers: isolated temporary directories, event fixtures and
//! a scripted synthetic carrier.
//!
//! Nothing here touches an installed application or a working session: all
//! state is a fresh temporary database or an in-memory store, and the
//! carrier is a pure in-process script standing in for the native adapter.

use bridge_core::dispatch::{
    AttemptRecord, Attestation, Capabilities, DispatchCarrier, Lifecycle, Outcome,
};
use bridge_core::{
    Envelope, EventId, Harness, Kind, Limits, Metadata, Mode, NativeAddress, Payload, Policy,
    PublisherId, Storage, StreamId,
};

/// Monotonic per-process fixture identity; clock granularity cannot collide paths.
static NEXT_PATH_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Guard that removes its directory when dropped.
///
/// Every test owns a fresh directory under the system temp dir; no shared
/// or installed state is touched. Allowed dead code: shared by test
/// binaries that may not need every helper.
#[allow(dead_code)]
pub struct TempDir(std::path::PathBuf);

#[allow(dead_code)]
impl TempDir {
    /// Creates a fresh directory for the literal short test label `tag`.
    /// PID, time and a process counter distinguish concurrent calls even on
    /// coarse clocks. Panics rather than reusing an existing path; the guard
    /// owns this new directory until drop.
    pub fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "bridge-core-{}-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_PATH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create fresh temp dir");
        TempDir(path)
    }

    /// A path inside the directory.
    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    /// Removes the directory tree; test-isolated state only.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Builds a unique socket path under the configured temporary root for literal
/// static test label `tag`.
/// The process counter prevents clock-resolution collisions between parallel
/// calls. No path is created; the caller owns socket creation and cleanup.
/// The short `bl-` prefix retains the same tag, PID, timestamp and counter.
/// Panics if the system clock precedes the Unix epoch.
/// The caller must configure a root short enough for the generated basename and
/// the macOS AF_UNIX ceiling of about 104 bytes; no nested test tree is added.
#[allow(dead_code)]
pub fn short_socket(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bl-{}-{}-{}-{}.sock",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_PATH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

/// Waits until a client can connect to the socket, bounded to `budget`.
#[allow(dead_code)]
pub fn wait_listening(socket: &std::path::Path, budget: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

/// A Codex fixture recipient with the given native session id.
#[allow(dead_code)]
pub fn codex(session: &str) -> NativeAddress {
    NativeAddress::new("host-1", Harness::CODEX, "default", session).unwrap()
}

/// A keep_all envelope for `publisher` addressed to `recipient`.
#[allow(dead_code)]
pub fn keep_all(publisher: &str, event: &str, recipient: &NativeAddress, mode: Mode) -> Envelope {
    Envelope::new(
        PublisherId::new(publisher).unwrap(),
        EventId::new(event).unwrap(),
        recipient.clone(),
        Kind::new("worker.completed").unwrap(),
        mode,
        Policy::KeepAll,
        Payload::new(format!("synthetic result of {event}")).unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// A latest-snapshot envelope for one stream and revision.
#[allow(dead_code)]
pub fn latest(
    publisher: &str,
    event: &str,
    recipient: &NativeAddress,
    stream: &str,
    revision: u64,
) -> Envelope {
    let mut envelope = keep_all(publisher, event, recipient, Mode::Message);
    envelope.kind = Kind::new("diagnostics.view").unwrap();
    envelope.policy = Policy::Latest {
        stream: StreamId::new(stream).unwrap(),
        revision,
    };
    envelope
}

/// A batch-policy envelope for one group.
#[allow(dead_code)]
pub fn batched(publisher: &str, event: &str, recipient: &NativeAddress, group: &str) -> Envelope {
    let mut envelope = keep_all(publisher, event, recipient, Mode::Message);
    envelope.policy = Policy::Batch {
        group: group.to_string(),
    };
    envelope
}

/// Adds one metadata entry to an envelope (the hash follows the content).
#[allow(dead_code)]
pub fn with_meta(mut envelope: Envelope, key: &str, value: &str) -> Envelope {
    envelope.metadata.insert(key.to_string(), value.to_string());
    envelope
}

/// A verified-looking attestation of `recipient` acting as itself, with
/// both paths loaded.
#[allow(dead_code)]
pub fn attest(recipient: &NativeAddress, lifecycle: Lifecycle, epoch: u64) -> Attestation {
    Attestation::verified(
        recipient.clone(),
        recipient.native_session_id.clone(),
        epoch,
        lifecycle,
        Capabilities {
            inject: true,
            message: true,
        },
        "fixture-proof",
    )
    .unwrap()
}

/// An in-memory store with source tags registered for the fixture
/// publishers.
#[allow(dead_code)]
pub fn store() -> Storage {
    let mut storage = Storage::open_in_memory(Limits::new(1_000)).unwrap();
    register_tags(&mut storage);
    storage
}

/// Registers the fixture publishers' source tags.
#[allow(dead_code)]
pub fn register_tags(storage: &mut Storage) {
    for publisher in ["agent-run", "agent-ide", "agent-worktree"] {
        storage.register_source_tag(publisher, publisher).unwrap();
    }
}

/// A scripted synthetic carrier standing in for the native adapter.
///
/// Reports one attestation (or an attestation failure) and one outcome for
/// every hand-off, and records exactly what it was asked to send.
#[allow(dead_code)]
pub struct ScriptedCarrier {
    /// Lifecycle every attestation reports.
    pub lifecycle: Lifecycle,
    /// Endpoint epoch every attestation reports.
    pub epoch: u64,
    /// When set, attestation fails with this reason.
    pub attest_error: Option<String>,
    /// Outcome each send returns.
    pub outcome: Outcome,
    /// When true, `send` panics instead of returning.
    pub panic_on_send: bool,
    /// Every attempt record handed to `send`, in order.
    pub sends: Vec<AttemptRecord>,
}

#[allow(dead_code)]
impl ScriptedCarrier {
    /// A carrier reporting `lifecycle` at epoch 1 and one fixed outcome.
    pub fn new(lifecycle: Lifecycle, outcome: Outcome) -> Self {
        ScriptedCarrier {
            lifecycle,
            epoch: 1,
            attest_error: None,
            outcome,
            panic_on_send: false,
            sends: Vec::new(),
        }
    }

    /// The accepted outcome used by most fixtures.
    pub fn accepted() -> Outcome {
        Outcome::NativeAccepted {
            evidence: "queue id 1".to_string(),
        }
    }
}

impl DispatchCarrier for ScriptedCarrier {
    /// Returns this fixture's attestation for the recipient.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if let Some(reason) = &self.attest_error {
            return Err(reason.clone());
        }
        Ok(attest(recipient, self.lifecycle, self.epoch))
    }

    /// Applies this fixture's scripted outcome to the frozen attempt.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        self.sends.push(attempt.clone());
        assert!(!self.panic_on_send, "scripted carrier panic");
        self.outcome.clone()
    }
}
