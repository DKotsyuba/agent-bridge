//! Schema migration and fence checks.
//!
//! Fixtures are built with the exact DDL earlier builds wrote (version 2 of
//! the publication foundation, version 3 of the first dispatch checkpoint)
//! and rows hashed with the canonical envelope code, then opened with the
//! current build. Accepted bytes, hashes and identifiers must survive; an
//! attempt that may have reached a carrier must never become dispatchable;
//! a refused or failed migration must leave the file untouched.

mod common;

use bridge_core::dispatch::{DispatchTiming, EffectiveMode, Lifecycle, Selection};
use bridge_core::recovery::DeliveryState;
use bridge_core::{CoreError, Envelope, EventState, Limits, Mode, Storage};
use common::{TempDir, attest, codex, keep_all, latest, register_tags};
use rusqlite::{Connection, params};

/// The version 2 DDL (publication foundation), verbatim.
const V2_DDL: &str = "
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events (
    publisher_id TEXT NOT NULL, event_id TEXT NOT NULL, envelope_hash TEXT NOT NULL,
    envelope_json BLOB NOT NULL, state TEXT NOT NULL, acceptance_seq INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL, expires_at_ms INTEGER,
    PRIMARY KEY (publisher_id, event_id));
CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE watermarks (
    publisher_id TEXT NOT NULL, recipient TEXT NOT NULL, kind TEXT NOT NULL,
    mode TEXT NOT NULL, project TEXT NOT NULL, task TEXT NOT NULL, stream_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (publisher_id, recipient, kind, mode, project, task, stream_id));
";

/// The version 3 DDL (first dispatch checkpoint), verbatim.
const V3_DDL: &str = "
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events (
    publisher_id TEXT NOT NULL, event_id TEXT NOT NULL, envelope_hash TEXT NOT NULL,
    envelope_json BLOB NOT NULL, state TEXT NOT NULL, acceptance_seq INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL, expires_at_ms INTEGER,
    recipient TEXT NOT NULL DEFAULT '', policy_class TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (publisher_id, event_id));
CREATE INDEX events_dispatch ON events (state, recipient, policy_class, acceptance_seq);
CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE watermarks (
    publisher_id TEXT NOT NULL, recipient TEXT NOT NULL, kind TEXT NOT NULL,
    mode TEXT NOT NULL, project TEXT NOT NULL, task TEXT NOT NULL, stream_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (publisher_id, recipient, kind, mode, project, task, stream_id));
CREATE TABLE attempts (
    attempt_seq INTEGER PRIMARY KEY, publisher_id TEXT NOT NULL, event_id TEXT NOT NULL,
    state TEXT NOT NULL, effective_mode TEXT NOT NULL, manifest_hash TEXT NOT NULL,
    lease_expires_ms INTEGER, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, note TEXT);
CREATE INDEX attempts_by_event ON attempts (publisher_id, event_id, attempt_seq);
CREATE TABLE incidents (
    incident_seq INTEGER PRIMARY KEY, publisher_id TEXT NOT NULL, event_id TEXT NOT NULL,
    kind TEXT NOT NULL, reason TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open',
    created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, next_check_ms INTEGER,
    review_deadline_ms INTEGER, blocked_dependents TEXT NOT NULL DEFAULT '[]', resolution TEXT);
CREATE INDEX incidents_open ON incidents (state, next_check_ms);
CREATE TABLE recipient_policies (
    recipient TEXT PRIMARY KEY, no_wake INTEGER NOT NULL, reason TEXT, set_ms INTEGER NOT NULL);
";

/// Inserts one event row exactly as the old builds wrote it.
fn insert_event(
    connection: &Connection,
    envelope: &Envelope,
    seq: i64,
    accepted_at_ms: i64,
    with_routing_columns: bool,
) {
    let hash = envelope.envelope_hash();
    if with_routing_columns {
        connection
            .execute(
                "INSERT INTO events (publisher_id, event_id, envelope_hash, envelope_json, state,
                     acceptance_seq, accepted_at_ms, expires_at_ms, recipient, policy_class)
                 VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, NULL, ?7, ?8)",
                params![
                    envelope.publisher.as_str(),
                    envelope.event_id.as_str(),
                    hash.as_str(),
                    envelope.canonical_bytes(),
                    seq,
                    accepted_at_ms,
                    envelope.recipient.to_canonical_string(),
                    envelope.policy.as_str(),
                ],
            )
            .unwrap();
    } else {
        connection
            .execute(
                "INSERT INTO events (publisher_id, event_id, envelope_hash, envelope_json, state,
                     acceptance_seq, accepted_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, NULL)",
                params![
                    envelope.publisher.as_str(),
                    envelope.event_id.as_str(),
                    hash.as_str(),
                    envelope.canonical_bytes(),
                    seq,
                    accepted_at_ms,
                ],
            )
            .unwrap();
    }
}

/// Reads the schema version row of a file.
fn version(path: &std::path::Path) -> String {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn version_two_databases_migrate_without_touching_accepted_bytes_or_identity() {
    let dir = TempDir::new("migrate-v2");
    let path = dir.path("bridge.db");
    let recipient = codex("thread-m");
    let plain = keep_all("agent-run", "old-keep", &recipient, Mode::Message);
    let snapshot = latest("agent-ide", "old-view", &recipient, "diag", 5);
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(V2_DDL).unwrap();
        connection
            .execute("INSERT INTO schema_meta VALUES ('schema_version', '2')", [])
            .unwrap();
        connection
            .execute("INSERT INTO counters VALUES ('acceptance_seq', 2)", [])
            .unwrap();
        insert_event(&connection, &plain, 1, 1_000, false);
        insert_event(&connection, &snapshot, 2, 1_100, false);
        connection
            .execute(
                "INSERT INTO watermarks VALUES (?1, ?2, 'diagnostics.view', 'message', '', '', 'diag', 5)",
                params!["agent-ide", recipient.to_canonical_string()],
            )
            .unwrap();
    }
    let before: Vec<(String, Vec<u8>, String)> = Connection::open(&path)
        .unwrap()
        .prepare("SELECT event_id, envelope_json, envelope_hash FROM events ORDER BY event_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    assert_eq!(version(&path), "4");
    let after: Vec<(String, Vec<u8>, String)> = Connection::open(&path)
        .unwrap()
        .prepare("SELECT event_id, envelope_json, envelope_hash FROM events ORDER BY event_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(before, after, "accepted bytes and hashes are immutable");

    // Identity survives: the original receipts replay unchanged, a changed
    // body still conflicts, and the stream watermark keeps rejecting stale
    // revisions.
    let replay = storage.publish(&plain, 9_000).unwrap().receipt;
    assert!(replay.replayed);
    assert_eq!((replay.acceptance_seq, replay.accepted_at_ms), (1, 1_000));
    assert!(matches!(
        storage.publish(
            &keep_all("agent-run", "old-keep", &recipient, Mode::Auto),
            9_001
        ),
        Err(CoreError::Conflict { .. })
    ));
    let stale = storage
        .publish(
            &latest("agent-ide", "older-view", &recipient, "diag", 4),
            9_002,
        )
        .unwrap();
    assert_eq!(stale.receipt.state, EventState::Superseded);
    // New acceptance numbers continue after the old ones (the stale
    // snapshot above consumed number 3).
    let fresh = storage
        .publish(
            &keep_all("agent-run", "new-keep", &recipient, Mode::Message),
            9_003,
        )
        .unwrap();
    assert_eq!(fresh.receipt.acceptance_seq, 4);

    // The migrated events are dispatchable (routing columns backfilled).
    register_tags(&mut storage);
    let Selection::Attempt(record) = storage
        .reserve_next(
            &attest(&recipient, Lifecycle::Inactive, 1),
            EffectiveMode::Message,
            10_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("migrated events must be dispatchable");
    };
    assert_eq!(record.members[0].event_id, "old-keep");
}

#[test]
fn version_three_attempts_that_may_have_reached_a_carrier_are_never_redispatched() {
    let dir = TempDir::new("migrate-v3");
    let path = dir.path("bridge.db");
    let recipient = codex("thread-v3");
    let events: Vec<(&str, Option<&str>)> = vec![
        ("evt-invoking", Some("invoking")),
        ("evt-held", Some("native_held")),
        ("evt-accepted", Some("native_accepted")),
        ("evt-unsent", Some("known_unsent")),
        ("evt-reserved", Some("reserved")),
        ("evt-fresh", None),
    ];
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(V3_DDL).unwrap();
        connection
            .execute("INSERT INTO schema_meta VALUES ('schema_version', '3')", [])
            .unwrap();
        connection
            .execute("INSERT INTO counters VALUES ('acceptance_seq', 6)", [])
            .unwrap();
        connection
            .execute("INSERT INTO counters VALUES ('attempt_seq', 5)", [])
            .unwrap();
        connection
            .execute("INSERT INTO counters VALUES ('incident_seq', 0)", [])
            .unwrap();
        for (index, (id, attempt)) in events.iter().enumerate() {
            let envelope = keep_all("agent-run", id, &recipient, Mode::Message);
            insert_event(&connection, &envelope, index as i64 + 1, 1_000, true);
            if let Some(state) = attempt {
                connection
                    .execute(
                        "INSERT INTO attempts (attempt_seq, publisher_id, event_id, state,
                             effective_mode, manifest_hash, lease_expires_ms, created_ms, updated_ms)
                         VALUES (?1, 'agent-run', ?2, ?3, 'message', 'h', NULL, 1000, 2000)",
                        params![index as i64 + 1, id, state],
                    )
                    .unwrap();
            }
        }
    }
    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    register_tags(&mut storage);
    let delivery = |id: &str| {
        storage
            .delivery_evidence("agent-run", id)
            .unwrap()
            .map_or(DeliveryState::Unhanded, |evidence| evidence.delivery)
    };
    assert_eq!(delivery("evt-invoking"), DeliveryState::Review);
    assert_eq!(delivery("evt-held"), DeliveryState::Review);
    assert_eq!(delivery("evt-accepted"), DeliveryState::Accepted);
    assert_eq!(delivery("evt-unsent"), DeliveryState::Unhanded);
    assert_eq!(delivery("evt-reserved"), DeliveryState::Unhanded);
    assert_eq!(delivery("evt-fresh"), DeliveryState::Unhanded);
    let incidents = storage.open_incidents(5_000, 10).unwrap();
    assert_eq!(incidents.len(), 2);
    assert!(
        incidents
            .iter()
            .all(|incident| incident.kind == "migrated_unverified")
    );

    // Only the three never-handed-off events are dispatchable.
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    let mut taken = Vec::new();
    while let Selection::Attempt(record) = storage
        .reserve_next(
            &inactive,
            EffectiveMode::Message,
            10_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    {
        taken.push(record.members[0].event_id.clone());
    }
    taken.sort();
    assert_eq!(taken, ["evt-fresh", "evt-reserved", "evt-unsent"]);
    // The old attempts are kept for audit.
    let audit: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM attempts_v3", [], |row| row.get(0))
        .unwrap();
    assert_eq!(audit, 5);
}

#[test]
fn unknown_versions_and_foreign_files_are_refused_untouched() {
    let dir = TempDir::new("migrate-refuse");
    for stored in ["1", "5", "garbage"] {
        let path = dir.path(&format!("v{stored}.db"));
        {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(V2_DDL).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_meta VALUES ('schema_version', ?1)",
                    [stored],
                )
                .unwrap();
        }
        assert!(matches!(
            Storage::open(&path, Limits::new(10)),
            Err(CoreError::Integrity(_))
        ));
        assert_eq!(
            version(&path),
            stored,
            "a refused open must not change the file"
        );
    }
    // A database that is not ours at all.
    let foreign = dir.path("foreign.db");
    Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE notes (body TEXT); INSERT INTO notes VALUES ('keep me');")
        .unwrap();
    assert!(matches!(
        Storage::open(&foreign, Limits::new(10)),
        Err(CoreError::Integrity(_))
    ));
    let notes: String = Connection::open(&foreign)
        .unwrap()
        .query_row("SELECT body FROM notes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(notes, "keep me");
}

#[test]
fn a_failing_migration_rolls_back_completely() {
    let dir = TempDir::new("migrate-rollback");
    let path = dir.path("bridge.db");
    let recipient = codex("thread-bad");
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(V2_DDL).unwrap();
        connection
            .execute("INSERT INTO schema_meta VALUES ('schema_version', '2')", [])
            .unwrap();
        let good = keep_all("agent-run", "good", &recipient, Mode::Message);
        insert_event(&connection, &good, 1, 1_000, false);
        // A row whose bytes no longer match its hash.
        let damaged = keep_all("agent-run", "damaged", &recipient, Mode::Message);
        insert_event(&connection, &damaged, 2, 1_001, false);
        connection
            .execute(
                "UPDATE events SET envelope_json = CAST('{}' AS BLOB) WHERE event_id = 'damaged'",
                [],
            )
            .unwrap();
    }
    assert!(matches!(
        Storage::open(&path, Limits::new(10)),
        Err(CoreError::Integrity(_))
    ));
    assert_eq!(version(&path), "2", "the failed migration changed nothing");
    let connection = Connection::open(&path).unwrap();
    let columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'delivery'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(columns, 0, "no partial schema change survived");
}

#[test]
fn a_busy_database_reports_a_retryable_error_and_changes_nothing() {
    let dir = TempDir::new("busy");
    let path = dir.path("bridge.db");
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    let recipient = codex("thread-busy");
    let envelope = keep_all("agent-run", "evt-busy", &recipient, Mode::Message);

    // Another process holds the write lock for longer than the busy timeout.
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = std::time::Instant::now();
    match storage.publish(&envelope, 1_000) {
        Err(CoreError::Busy(detail)) => assert!(!detail.is_empty()),
        other => panic!("expected a retryable busy error, got {other:?}"),
    }
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(4),
        "the busy timeout bounds the wait"
    );
    blocker.execute_batch("ROLLBACK").unwrap();

    // Nothing was accepted; the same key then succeeds exactly once.
    assert!(
        storage
            .lookup(&envelope.publisher, &envelope.event_id)
            .unwrap()
            .is_none()
    );
    assert!(!storage.publish(&envelope, 2_000).unwrap().receipt.replayed);
    assert!(storage.publish(&envelope, 2_001).unwrap().receipt.replayed);
}

#[test]
fn retained_history_hard_cap_refuses_admission_without_evicting_dedup() {
    let mut limits = Limits::new(2);
    limits.max_retained_events = 3;
    let mut storage = Storage::open_in_memory(limits).unwrap();
    let recipient = codex("thread-retained");
    // Superseded and delivered events stay as tombstones and count against
    // the retained cap, never against admission.
    storage
        .publish(&latest("agent-ide", "v2", &recipient, "diag", 2), 1)
        .unwrap();
    storage
        .publish(&latest("agent-ide", "v1", &recipient, "diag", 1), 2)
        .unwrap();
    storage
        .publish(&keep_all("agent-run", "k1", &recipient, Mode::Message), 3)
        .unwrap();
    assert!(matches!(
        storage.publish(&keep_all("agent-run", "k2", &recipient, Mode::Message), 4),
        Err(CoreError::Capacity { .. })
    ));
    // Identical replays of retained events still succeed at the cap.
    assert!(
        storage
            .publish(&latest("agent-ide", "v1", &recipient, "diag", 1), 5)
            .unwrap()
            .receipt
            .replayed
    );
}
