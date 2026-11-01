//! Integration checks for durable custody storage.
//!
//! Every test uses isolated owned state: a fresh database file under a unique
//! temporary directory (or an in-memory database), never an installed or
//! shared store.

use std::path::PathBuf;
use std::process::Command;

use bridge_core::storage::EventState;
use bridge_core::{
    CoreError, Envelope, EventId, ExpiresAt, Harness, Kind, Limits, Metadata, Mode, NativeAddress,
    Payload, Policy, PublisherId, Storage, StreamId,
};

/// Guard that removes its directory when dropped.
///
/// Minimal local replacement for a tempfile dependency.
struct TempDir(PathBuf);

impl TempDir {
    /// Creates a unique directory under the system temp dir.
    fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "bridge-core-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    /// A database path inside the directory.
    fn db(&self) -> PathBuf {
        self.0.join("bridge.db")
    }
}

impl Drop for TempDir {
    /// Removes the directory tree; test-isolated state only.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A valid keep_all envelope with the given payload text and optional expiry.
fn keep_all(event: &str, payload: &str, expires_at: Option<ExpiresAt>) -> Envelope {
    Envelope::new(
        PublisherId::new("agent-run").unwrap(),
        EventId::new(event).unwrap(),
        NativeAddress::new("host-1", Harness::CODEX, "default", "thread-7").unwrap(),
        Kind::new("worker.completed").unwrap(),
        Mode::Message,
        Policy::KeepAll,
        Payload::new(payload).unwrap(),
        Metadata::new(),
        expires_at,
    )
    .unwrap()
}

/// A valid latest-snapshot envelope on `stream` at `revision`.
fn latest(event: &str, stream: &str, revision: u64) -> Envelope {
    Envelope::new(
        PublisherId::new("agent-ide").unwrap(),
        EventId::new(event).unwrap(),
        NativeAddress::new("host-1", Harness::CLAUDE_CODE, "default", "session-7").unwrap(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::Latest {
            stream: StreamId::new(stream).unwrap(),
            revision,
        },
        Payload::new("{\"view\":\"ok\"}").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// Publishing the same envelope twice returns the original custody
/// receipt with `replayed` set and consumes no new admission capacity.
#[test]
fn identical_replay_returns_original_receipt() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    let outcome = storage
        .publish(&keep_all("evt-1", "body", None), 1_000)
        .unwrap();
    assert!(!outcome.receipt.replayed);
    assert_eq!(outcome.receipt.acceptance_seq, 1);

    let replay = storage
        .publish(&keep_all("evt-1", "body", None), 9_999)
        .unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(
        replay.receipt.acceptance_seq,
        outcome.receipt.acceptance_seq
    );
    assert_eq!(replay.receipt.accepted_at_ms, 1_000);
    assert_eq!(replay.receipt.envelope_hash, outcome.receipt.envelope_hash);

    let looked_up = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("evt-1").unwrap(),
        )
        .unwrap()
        .expect("row exists");
    assert_eq!(looked_up.acceptance_seq, 1);
}

/// Republishing the same `(publisher, event id)` with different content
/// is refused as a conflict and leaves the original event untouched.
#[test]
fn changed_identity_content_conflicts() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&keep_all("evt-1", "body", None), 1_000)
        .unwrap();

    let conflicting = keep_all("evt-1", "different body", None);
    match storage.publish(&conflicting, 2_000) {
        Err(CoreError::Conflict {
            event_id,
            stored_hash,
            submitted_hash,
        }) => {
            assert_eq!(event_id, "evt-1");
            assert_ne!(stored_hash, submitted_hash);
        }
        other => panic!("expected conflict, got {other:?}"),
    }

    // The original event is untouched: replay of the original still works.
    let replay = storage
        .publish(&keep_all("evt-1", "body", None), 3_000)
        .unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(replay.receipt.acceptance_seq, 1);
}

/// The admission hard cap refuses new events explicitly; replays stay
/// admissible and terminal dispositions free capacity again.
#[test]
fn hard_cap_refuses_new_admission_until_capacity_frees() {
    let mut storage = Storage::open_in_memory(Limits::new(2)).unwrap();
    let past = ExpiresAt::from_unix_millis(2_000).unwrap();
    storage
        .publish(&keep_all("evt-1", "a", Some(past)), 1_000)
        .unwrap();
    storage
        .publish(&keep_all("evt-2", "b", Some(past)), 1_000)
        .unwrap();
    match storage.publish(&keep_all("evt-3", "c", None), 1_500) {
        Err(CoreError::Capacity { limit }) => assert!(limit.contains("max_admitted_events")),
        other => panic!("expected capacity refusal, got {other:?}"),
    }
    // An identical replay consumes no admission capacity even at the cap.
    assert!(
        storage
            .publish(&keep_all("evt-1", "a", Some(past)), 1_600)
            .unwrap()
            .receipt
            .replayed
    );
    // Terminal capacity frees admission for new events.
    assert_eq!(storage.expire_due(3_000).unwrap(), 2);
    let admitted = storage
        .publish(&keep_all("evt-3", "c", None), 3_500)
        .unwrap();
    assert!(!admitted.receipt.replayed);
}

/// A `latest` snapshot older than the durable watermark is admitted as
/// explicitly superseded, equal-revision content conflicts, and every
/// dedup entry is retained.
#[test]
fn latest_watermark_supersedes_stale_snapshots_and_retains_entries() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();

    let revision_12 = storage
        .publish(&latest("rev-12", "diag-1", 12), 1_000)
        .unwrap();
    assert_eq!(revision_12.receipt.state, EventState::Pending);

    let revision_11 = storage
        .publish(&latest("rev-11", "diag-1", 11), 2_000)
        .unwrap();
    assert_eq!(revision_11.receipt.state, EventState::Superseded);

    let revision_13 = storage
        .publish(&latest("rev-13", "diag-1", 13), 3_000)
        .unwrap();
    assert_eq!(revision_13.receipt.state, EventState::Pending);

    // 11 arriving again after 13 stays superseded: the watermark is durable.
    let stale_replay = storage
        .publish(&latest("rev-11", "diag-1", 11), 4_000)
        .unwrap();
    assert_eq!(stale_replay.receipt.state, EventState::Superseded);

    // Equal revision with different content conflicts.
    let mut equal_revision = latest("rev-13", "diag-1", 13);
    equal_revision.event_id = EventId::new("rev-13-alt").unwrap();
    equal_revision.payload = Payload::new("{\"view\":\"changed\"}").unwrap();
    match storage.publish(&equal_revision, 5_000) {
        Err(CoreError::Conflict { .. }) => {}
        other => panic!("expected equal-revision conflict, got {other:?}"),
    }

    // Every dedup entry is retained, including superseded snapshots.
    for event in ["rev-11", "rev-12", "rev-13"] {
        let row = storage
            .lookup(
                &PublisherId::new("agent-ide").unwrap(),
                &EventId::new(event).unwrap(),
            )
            .unwrap();
        assert!(row.is_some(), "{event} must be retained");
    }
}

/// Expiry applies only to still-pending events: superseded and other
/// dispositions are never re-marked, and expiry is not a delivery claim.
#[test]
fn expiry_marks_only_pending_events() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    // A pending event past its absolute expiry.
    storage
        .publish(
            &keep_all(
                "exp-1",
                "x",
                Some(ExpiresAt::from_unix_millis(5_000).unwrap()),
            ),
            1_000,
        )
        .unwrap();
    // A superseded snapshot whose stored expiry is past: expiry must not
    // touch it (it was never handed out, but the disposition is already
    // explicit and the dedup entry is not pending).
    storage
        .publish(&latest("diag-new", "diag-2", 2), 1_000)
        .unwrap();
    let mut stale = latest("diag-old", "diag-2", 1);
    stale.expires_at = Some(ExpiresAt::from_unix_millis(4_000).unwrap());
    let admitted = storage.publish(&stale, 1_000).unwrap();
    assert_eq!(admitted.receipt.state, EventState::Superseded);

    assert_eq!(storage.expire_due(6_000).unwrap(), 1);
    let expired = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("exp-1").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(expired.state, EventState::Expired);
    let untouched = storage
        .lookup(
            &PublisherId::new("agent-ide").unwrap(),
            &EventId::new("diag-old").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(untouched.state, EventState::Superseded);
}

/// Committed custody and the monotonic acceptance order survive closing
/// and reopening the database file.
#[test]
fn custody_survives_close_and_reopen() {
    let dir = TempDir::new("reopen");
    let db = dir.db();
    {
        let mut storage = Storage::open(&db, Limits::new(100)).unwrap();
        storage
            .publish(&keep_all("evt-1", "body", None), 1_234)
            .unwrap();
    }
    let mut reopened = Storage::open(&db, Limits::new(100)).unwrap();
    let replay = reopened
        .publish(&keep_all("evt-1", "body", None), 9_999)
        .unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(replay.receipt.accepted_at_ms, 1_234);
    // Acceptance order continues monotonically after reopen.
    let next = reopened
        .publish(&keep_all("evt-2", "body", None), 9_999)
        .unwrap();
    assert_eq!(next.receipt.acceptance_seq, 2);
}

/// Row shape the rollback and fault probes insert as a would-be partial
/// custody entry; the hash is a fixed marker value, deliberately not a real
/// envelope hash.
const GHOST_INSERT: &str = "INSERT INTO events (publisher_id, event_id, envelope_hash, \
     envelope_json, state, acceptance_seq, accepted_at_ms, expires_at_ms) \
     VALUES ('p', 'ghost', 'deadbeef', x'7b7d', 'pending', 42, 1, NULL)";

/// A rolled-back transaction leaves no partial event row, and later
/// publication starts from a clean slate.
#[test]
fn aborted_transaction_leaves_no_partial_row() {
    // Crash-before-commit window through SQLite's own atomicity on this
    // exact schema and settings: writes in an aborted transaction vanish,
    // and publication afterwards starts from a clean slate.
    use rusqlite::Connection;
    let dir = TempDir::new("rollback");
    let db = dir.db();
    let mut storage = Storage::open(&db, Limits::new(100)).unwrap();
    let raw = Connection::open(&db).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE;").unwrap();
    raw.execute(GHOST_INSERT, []).unwrap();
    raw.execute_batch("ROLLBACK;").unwrap();
    drop(raw);

    let ghost = storage
        .lookup(
            &PublisherId::new("p").unwrap(),
            &EventId::new("ghost").unwrap(),
        )
        .unwrap();
    assert!(ghost.is_none());
    let clean = storage
        .publish(&keep_all("evt-1", "body", None), 1_000)
        .unwrap();
    assert_eq!(clean.receipt.acceptance_seq, 1);
}

/// A child process aborted mid-transaction leaves no partial custody
/// after WAL recovery on reopen, and new events are admitted cleanly.
#[test]
fn fault_kill_during_commit_recovers_on_reopen() {
    // Real crash window: a child process aborts while holding an open write
    // transaction on this schema; WAL recovery on reopen must leave no
    // partial custody and admit new events cleanly.
    if let Ok(db) = std::env::var("BRIDGE_FAULT_DB") {
        let raw = rusqlite::Connection::open(&db).unwrap();
        raw.execute_batch("BEGIN IMMEDIATE;").unwrap();
        raw.execute(GHOST_INSERT, []).unwrap();
        std::process::abort();
    }

    let dir = TempDir::new("fault");
    let db = dir.db();
    // Create the schema with the production settings, then simulate a
    // writer dying mid-transaction against the same file.
    drop(Storage::open(&db, Limits::new(100)).unwrap());
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "fault_kill_during_commit_recovers_on_reopen",
            "--exact",
            "--nocapture",
        ])
        .env("BRIDGE_FAULT_DB", &db)
        .env("RUST_BACKTRACE", "0")
        .status()
        .unwrap();
    assert!(
        !child.success(),
        "child must crash before commit for the fault to be real"
    );

    let mut reopened = Storage::open(&db, Limits::new(100)).unwrap();
    let crashed = reopened
        .lookup(
            &PublisherId::new("p").unwrap(),
            &EventId::new("ghost").unwrap(),
        )
        .unwrap();
    assert!(
        crashed.is_none(),
        "aborted transaction must not leave custody"
    );
    let after = reopened
        .publish(&keep_all("after-crash", "body", None), 1_000)
        .unwrap();
    assert_eq!(after.receipt.acceptance_seq, 1);
}
