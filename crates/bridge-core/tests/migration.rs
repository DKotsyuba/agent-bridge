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
use bridge_core::recovery::{DeliveryState, IncidentState};
use bridge_core::types::{
    EventId, Harness, Kind, Metadata, NativeAddress, Payload, PublisherId, StreamId,
};
use bridge_core::{CoreError, Envelope, EventState, Limits, Mode, Policy, Storage};
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

/// A version 2 database migrates to the current schema without touching
/// accepted bytes, hashes, identifiers, acceptance order or timestamps;
/// only new columns are added and backfilled from the stored canonical
/// envelope, and normal publication/replay semantics hold afterwards.
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
    assert_eq!(version(&path), "6");
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

/// Migrating version 3 attempts keeps possible-carrier hand-offs in
/// review with retained incidents instead of redispatching them: only
/// never-invoked or positively known-unsent work becomes dispatchable,
/// and finished attempts keep their delivery tier.
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

/// Databases with unknown schema versions, garbage version rows or
/// foreign shapes are refused untouched: no byte of the file is changed
/// and the stored version stays readable after the refusal.
#[test]
fn unknown_versions_and_foreign_files_are_refused_untouched() {
    let dir = TempDir::new("migrate-refuse");
    for stored in ["1", "7", "garbage"] {
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
        let before = database_files(&path);
        assert!(matches!(
            Storage::open(&path, Limits::new(10)),
            Err(CoreError::Integrity(_))
        ));
        assert!(
            database_files(&path) == before,
            "refusal preserves every database byte and sidecar"
        );
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
    let before = database_files(&foreign);
    assert!(matches!(
        Storage::open(&foreign, Limits::new(10)),
        Err(CoreError::Integrity(_))
    ));
    assert!(
        database_files(&foreign) == before,
        "foreign database bytes and sidecars stay untouched"
    );
    let notes: String = Connection::open(&foreign)
        .unwrap()
        .query_row("SELECT body FROM notes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(notes, "keep me");
}

/// Captures the database and SQLite sidecars without opening SQLite itself;
/// missing sidecars remain distinct from empty ones and read failures panic.
fn database_files(path: &std::path::Path) -> Vec<Option<Vec<u8>>> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(
            |suffix| match std::fs::read(format!("{}{suffix}", path.display())) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("fixture snapshot failed: {error}"),
            },
        )
        .collect()
}

/// Refusal preserves durable bytes, journal mode and sidecar presence in each
/// journal mode, including a newer schema committed only in a live WAL. SQLite
/// may update advisory wal-index read marks (bytes 100..120), never DB/WAL data.
#[test]
fn unsupported_journal_modes_and_live_sidecars_are_preserved() {
    let dir = TempDir::new("journal-refusal");
    for mode in ["DELETE", "TRUNCATE", "PERSIST", "WAL"] {
        for foreign in [false, true] {
            let path = dir.path(&format!("{mode}-{foreign}.db"));
            let keeper = Connection::open(&path).unwrap();
            keeper.pragma_update(None, "journal_mode", mode).unwrap();
            keeper.execute_batch(if foreign {
                "CREATE TABLE notes(body TEXT); INSERT INTO notes VALUES('synthetic retained bytes');"
            } else {
                "CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version', '999');"
            }).unwrap();
            let before = database_files(&path);
            assert!(matches!(
                Storage::open(&path, Limits::new(10)),
                Err(CoreError::Integrity(_))
            ));
            let after = database_files(&path);
            assert!(
                [0, 1, 3]
                    .into_iter()
                    .all(|index| after[index] == before[index]),
                "refusal changed {mode} foreign={foreign} durable database, WAL or journal bytes"
            );
            assert_eq!(
                after[2].is_some(),
                before[2].is_some(),
                "SHM presence changed"
            );
            if let (Some(before), Some(after)) = (&before[2], &after[2]) {
                assert_eq!(before.len(), after.len());
                let differences: Vec<_> = before
                    .iter()
                    .zip(after)
                    .enumerate()
                    .filter(|(_, (left, right))| left != right)
                    .map(|(offset, (left, right))| (offset, *left, *right))
                    .collect();
                eprintln!("{mode} foreign={foreign} SHM read-mark differences: {differences:?}");
                assert!(
                    differences
                        .iter()
                        .all(|(offset, _, _)| (100..120).contains(offset))
                );
            }
            let after: String = keeper
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .unwrap();
            assert_eq!(after, mode.to_ascii_lowercase());
        }
    }
}

/// A migration that fails partway leaves no partial schema: the whole
/// upgrade rolls back, the stored version is unchanged, and the events
/// remain exactly as they were.
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

/// A concurrently locked database surfaces as an explicit retryable
/// busy error rather than data damage or a silent success; the stored
/// rows are unchanged after the refusal.
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

/// The retained-history hard cap refuses new admission explicitly
/// instead of evicting dedup history: identical replays of retained
/// events still return their original receipts at the cap.
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

/// A version 4 database gains the events.lineage_key column and the stream_lineages table:
/// no stored row changes and lineage fencing works immediately.
#[test]
fn version_four_databases_gain_lineages_additively() {
    let dir = TempDir::new("migrate-v4");
    let path = dir.path("v4.db");
    {
        let storage = Storage::open(&path, Limits::new(10)).unwrap();
        let connection = &rusqlite::Connection::open(&path).unwrap();
        drop(storage);
        connection
            .execute_batch(
                "DROP INDEX events_by_lineage;
                 DROP TABLE stream_lineages;
                 ALTER TABLE events DROP COLUMN lineage_key;
                 UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';",
            )
            .unwrap();
    }
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    assert_eq!(version(&path), "6");
    // Lineage fencing is live on the migrated database.
    let event = Envelope::new(
        PublisherId::new("agent-run").unwrap(),
        EventId::new("lin-1").unwrap(),
        NativeAddress::new("host-1", Harness::CODEX, "default", "thread-1").unwrap(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Message,
        Policy::Latest {
            stream: StreamId::new("diag").unwrap(),
            revision: 1,
        },
        Payload::new("{}").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap();
    storage.publish(&event, 1_000).unwrap();
    let mut other = event.clone();
    other.publisher = PublisherId::new("agent-ide").unwrap();
    other.event_id = EventId::new("lin-2").unwrap();
    assert!(matches!(
        storage.publish(&other, 2_000),
        Err(CoreError::Fence(_))
    ));
}

/// A v4 database with TWO historical producers on one lineage migrates to
/// an explicit ambiguous fence: every publisher is declined until an
/// operator resolves the authority; no owner is picked by arrival.
#[test]
fn ambiguous_legacy_lineages_fence_every_publisher_until_resolved() {
    let dir = TempDir::new("migrate-ambig");
    let path = dir.path("ambig.db");
    {
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        let mut envelope = lineage_event("source-a", "a1", 3);
        envelope.mode = Mode::Auto;
        storage.publish(&envelope, 1_000).unwrap();
        drop(storage);
        // Emulate true legacy ambiguity: a second historical producer's
        // watermark and event row exist from before lineage tracking.
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP INDEX events_by_lineage;
                 DROP TABLE stream_lineages;
                 ALTER TABLE events DROP COLUMN lineage_key;
                 UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';
                 INSERT INTO watermarks
                     (publisher_id, recipient, kind, mode, project, task, stream_id, revision)
                 VALUES ('source-b',
                         'host-1/codex/default/thread-7', 'diagnostics.view', 'auto',
                         '', '', 'diag', 7);
                 INSERT INTO events
                     (publisher_id, event_id, envelope_hash, envelope_json, state,
                      acceptance_seq, accepted_at_ms, recipient, policy_class, mode,
                      scope_key, revision)
                 VALUES ('source-b', 'b1', 'legacy', x'7b7d', 'superseded',
                         2, 1000, 'host-1/codex/default/thread-7', 'latest', 'auto',
                         '', 7);",
            )
            .unwrap();
    }

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    for publisher in ["source-a", "source-b", "source-c"] {
        let mut envelope = lineage_event(publisher, "late", 99);
        envelope.mode = Mode::Auto;
        assert!(
            matches!(
                storage.publish(&envelope, 2_000),
                Err(CoreError::Fence(detail)) if detail.contains("ambiguous")
            ),
            "{publisher} must be fenced on the ambiguous lineage"
        );
    }

    // An operator resolves the ambiguity; the resolved owner publishes.
    storage
        .transfer_lineage(
            &bridge_core::recovery::LineageScope {
                recipient: lineage_recipient(),
                kind: "diagnostics.view".into(),
                mode: "auto".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "source-c",
            "operator resolved the ambiguous legacy stream",
            "bridge-ops",
            2_500,
        )
        .unwrap();
    let mut resolved = lineage_event("source-c", "resolved-1", 1);
    resolved.mode = Mode::Auto;
    storage.publish(&resolved, 3_000).unwrap();
}

/// A compacted (purged-payload) latest event still backfills its lineage
/// from the retained watermark and fences a different producer.
#[test]
fn purged_latest_events_backfill_lineage_from_watermarks() {
    let dir = TempDir::new("migrate-purged");
    let path = dir.path("purged.db");
    {
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        let mut envelope = lineage_event("source-a", "keep-new", 2);
        envelope.mode = Mode::Auto;
        storage.publish(&envelope, 1_000).unwrap();
        let mut old = lineage_event("source-a", "purge-me", 1);
        old.mode = Mode::Auto;
        storage.publish(&old, 1_000).unwrap();
        // Compact the superseded member so its envelope bytes are gone.
        assert_eq!(storage.compact_payloads(0).unwrap(), 1);
        drop(storage);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP INDEX events_by_lineage;
                 DROP TABLE stream_lineages;
                 ALTER TABLE events DROP COLUMN lineage_key;
                 UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';",
            )
            .unwrap();
    }

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    let mut challenger = lineage_event("source-b", "b1", 1);
    challenger.mode = Mode::Auto;
    assert!(matches!(
        storage.publish(&challenger, 2_000),
        Err(CoreError::Fence(_))
    ));
    // The purged event itself keeps its dedup identity and disposition.
    let replay = storage
        .publish(&lineage_event("source-a", "purge-me", 1), 2_100)
        .unwrap();
    assert!(replay.receipt.replayed);
}

/// A version 2 database with a legacy latest producer migrates with the
/// lineage authority backfilled: a different producer is fenced.
#[test]
fn version_two_databases_backfill_lineage_authority() {
    let dir = TempDir::new("migrate-v2-lineage");
    let path = dir.path("v2l.db");
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(V2_DDL).unwrap();
        connection
            .execute("INSERT INTO schema_meta VALUES ('schema_version', '2')", [])
            .unwrap();
        let mut envelope = lineage_event("source-a", "legacy-a", 5);
        envelope.mode = Mode::Auto;
        let hash = envelope.envelope_hash().as_str().to_string();
        let bytes = envelope.canonical_bytes();
        connection
            .execute(
                "INSERT INTO events (publisher_id, event_id, envelope_hash, envelope_json,
                                     state, acceptance_seq, accepted_at_ms)
                 VALUES ('source-a', 'legacy-a', ?1, ?2, 'pending', 1, 1000)",
                rusqlite::params![hash, bytes],
            )
            .unwrap();
    }

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    let mut challenger = lineage_event("source-b", "b1", 1);
    challenger.mode = Mode::Auto;
    assert!(
        matches!(
            storage.publish(&challenger, 2_000),
            Err(CoreError::Fence(_))
        ),
        "a v2 legacy producer's stream must not be claimable by a different publisher"
    );
}

/// The lineage fixtures of this file: one recipient, one stream.
fn lineage_recipient() -> String {
    NativeAddress::new("host-1", Harness::CODEX, "default", "thread-7")
        .unwrap()
        .to_canonical_string()
}

/// A latest envelope on the fixture lineage.
fn lineage_event(publisher: &str, event: &str, revision: u64) -> Envelope {
    Envelope::new(
        PublisherId::new(publisher).unwrap(),
        EventId::new(event).unwrap(),
        NativeAddress::new("host-1", Harness::CODEX, "default", "thread-7").unwrap(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::Latest {
            stream: StreamId::new("diag").unwrap(),
            revision,
        },
        Payload::new("{\"view\":\"ok\"}").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// Pending work of an ambiguous migrated lineage is never selected: the
/// head is held with a retained incident instead of being dispatched, and
/// its bytes stay untouched.
#[test]
fn ambiguous_migrated_pending_work_is_held_not_dispatched() {
    let dir = TempDir::new("migrate-ambig-pending");
    let path = dir.path("pending.db");
    let mut pending = lineage_event("source-a", "a-pending", 3);
    pending.mode = Mode::Message;
    {
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        storage.publish(&pending, 1_000).unwrap();
        drop(storage);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP INDEX events_by_lineage;
                 DROP TABLE stream_lineages;
                 ALTER TABLE events DROP COLUMN lineage_key;
                 UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';
                 INSERT INTO watermarks
                     (publisher_id, recipient, kind, mode, project, task, stream_id, revision)
                 VALUES ('source-b',
                         'host-1/codex/default/thread-7', 'diagnostics.view', 'message',
                         '', '', 'diag', 7);",
            )
            .unwrap();
    }

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    storage.register_source_tag("source-a", "source-a").unwrap();
    let address = NativeAddress::new("host-1", Harness::CODEX, "default", "thread-7").unwrap();
    let attestation = attest(&address, Lifecycle::Inactive, 1);
    let selection = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            2_000,
            &DispatchTiming::default(),
        )
        .unwrap();
    assert!(matches!(selection, Selection::Idle), "{selection:?}");
    assert!(
        storage
            .open_incidents(2_000, 10)
            .unwrap()
            .iter()
            .any(|incident| incident.event_id == "a-pending"
                && incident.kind == "lineage_authority_lost")
    );
    let row = storage
        .lookup(&pending.publisher, &pending.event_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.envelope_hash, pending.envelope_hash());
}

/// The root witness scenario: a v4 database with ONE historical producer
/// migrates with the authority backfilled from retained evidence, so a
/// different producer's first publication is fenced without the original
/// producer having to publish again first.
#[test]
fn version_four_single_legacy_owner_fences_a_new_producer_immediately() {
    let dir = TempDir::new("migrate-v4-single");
    let path = dir.path("v4s.db");
    {
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        let mut envelope = lineage_event("source-a", "a12", 12);
        envelope.mode = Mode::Auto;
        storage.publish(&envelope, 1_000).unwrap();
        drop(storage);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP TABLE stream_lineages;
                 UPDATE schema_meta SET value = '4' WHERE key = 'schema_version';",
            )
            .unwrap();
    }

    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    let mut challenger = lineage_event("source-b", "b1", 1);
    challenger.mode = Mode::Auto;
    assert!(
        matches!(
            storage.publish(&challenger, 2_000),
            Err(CoreError::Fence(_))
        ),
        "a migrated legacy producer's stream must fence a different producer at once"
    );
    // The legacy producer itself still owns its stream.
    let mut owner = lineage_event("source-a", "a13", 13);
    owner.mode = Mode::Auto;
    storage.publish(&owner, 2_100).unwrap();
}

/// Inserts one raw version 3 incident exactly as the historical
/// `Storage::open_incident` wrote it (the `blocked_dependents` column keeps
/// its default).
fn insert_v3_incident(
    connection: &Connection,
    seq: i64,
    event: &str,
    kind: &str,
    reason: &str,
    state: &str,
    resolution: Option<&str>,
) {
    connection
        .execute(
            "INSERT INTO incidents (incident_seq, publisher_id, event_id, kind, reason, state,
                 created_ms, updated_ms, next_check_ms, review_deadline_ms, resolution)
             VALUES (?1, 'agent-run', ?2, ?3, ?4, ?5, 1500, 1600, 1500, 9000, ?6)",
            params![seq, event, kind, reason, state, resolution],
        )
        .unwrap();
}

/// One raw version 3 incident: number, event, kind, reason, state and
/// resolution (publisher is always `agent-run`).
type V3IncidentRow<'a> = (i64, &'a str, &'a str, &'a str, &'a str, Option<&'a str>);

/// Builds a version 3 database from `(event, newest attempt state)` rows and
/// raw incident inserts, with counters matching the highest incident number.
fn v3_database_with_incidents(
    path: &std::path::Path,
    events: &[(&str, Option<&str>)],
    incidents: &[V3IncidentRow<'_>],
) {
    let recipient = codex("thread-v3-incidents");
    let connection = Connection::open(path).unwrap();
    connection.execute_batch(V3_DDL).unwrap();
    connection
        .execute("INSERT INTO schema_meta VALUES ('schema_version', '3')", [])
        .unwrap();
    let highest = incidents.iter().map(|row| row.0).max().unwrap_or(0);
    for (name, value) in [
        ("acceptance_seq", events.len() as i64),
        ("attempt_seq", events.len() as i64),
        ("incident_seq", highest),
    ] {
        connection
            .execute("INSERT INTO counters VALUES (?1, ?2)", params![name, value])
            .unwrap();
    }
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
    for (seq, event, kind, reason, state, resolution) in incidents {
        insert_v3_incident(&connection, *seq, event, kind, reason, state, *resolution);
    }
}

/// Every legal open version 3 incident survives the migration with its
/// identity (number, kind, reason, dates) as a live incident, whatever its
/// kind: `unknown_handoff` incidents (which version 3 itself treated as
/// blocking, with or without an attempt record) keep their event in review
/// instead of making it dispatchable, a duplicate open row of the same kind
/// stays visible as a resolved pointer to the kept one, a
/// `held_unknown_lifecycle` incident stays open with no claim about what
/// happened (its event is review under an ambiguous attempt, dispatchable
/// only when it has no attempt evidence against it), and closed history keeps
/// its duplicate-risk record.
/// The old rows also stay in `incidents_v3`; no uncertain event is
/// dispatched and no duplicate `migrated_unverified` incident is added.
#[test]
fn every_open_version_three_incident_stays_visible_and_uncertain_events_stay_undispatchable() {
    let dir = TempDir::new("migrate-v3-all-incidents");
    let path = dir.path("bridge.db");
    v3_database_with_incidents(
        &path,
        &[
            ("evt-lifecycle", None),
            ("evt-api-unknown", None),
            ("evt-unsent-unknown", Some("known_unsent")),
            ("evt-note", None),
            ("evt-lost", Some("invoking")),
            ("evt-done", Some("native_accepted")),
            ("evt-hist", Some("known_unsent")),
            ("evt-plain", None),
            ("evt-held-lost", Some("invoking")),
        ],
        &[
            (
                1,
                "evt-lifecycle",
                "held_unknown_lifecycle",
                "lifecycle unknown",
                "open",
                None,
            ),
            (
                2,
                "evt-api-unknown",
                "unknown_handoff",
                "api reason",
                "open",
                None,
            ),
            (
                3,
                "evt-unsent-unknown",
                "unknown_handoff",
                "unsent reason",
                "open",
                None,
            ),
            (4, "evt-note", "operator_note", "custom note", "open", None),
            (
                5,
                "evt-lost",
                "unknown_handoff",
                "lease expired",
                "open",
                None,
            ),
            (
                6,
                "evt-lost",
                "unknown_handoff",
                "second report",
                "open",
                None,
            ),
            (
                7,
                "evt-done",
                "unknown_handoff",
                "late report",
                "open",
                None,
            ),
            (
                8,
                "evt-hist",
                "unknown_handoff",
                "old unknown",
                "disposed",
                Some("manual retry authorized: host log inconclusive"),
            ),
            (
                9,
                "evt-held-lost",
                "held_unknown_lifecycle",
                "ambiguous hold",
                "open",
                None,
            ),
        ],
    );
    for pass in 0..2 {
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        register_tags(&mut storage);
        let delivery = |storage: &Storage, id: &str| {
            storage
                .delivery_evidence("agent-run", id)
                .unwrap()
                .map_or(DeliveryState::Unhanded, |evidence| evidence.delivery)
        };
        for (id, expected) in [
            ("evt-lifecycle", DeliveryState::Unhanded),
            ("evt-api-unknown", DeliveryState::Review),
            ("evt-unsent-unknown", DeliveryState::Review),
            ("evt-note", DeliveryState::Unhanded),
            ("evt-lost", DeliveryState::Review),
            ("evt-done", DeliveryState::Accepted),
            ("evt-hist", DeliveryState::Unhanded),
            ("evt-plain", DeliveryState::Unhanded),
            ("evt-held-lost", DeliveryState::Review),
        ] {
            assert_eq!(delivery(&storage, id), expected, "{id}");
        }
        let all = storage.incidents(true, 5_000, 50).unwrap();
        let by_seq = |seq: u64| all.iter().find(|incident| incident.incident_seq == seq);
        let mut open: Vec<_> = all
            .iter()
            .filter(|incident| incident.state == IncidentState::Open)
            .map(|incident| {
                (
                    incident.incident_seq,
                    incident.kind.as_str(),
                    incident.reason.as_str(),
                )
            })
            .collect();
        open.sort_unstable();
        assert_eq!(
            open,
            [
                (1, "held_unknown_lifecycle", "lifecycle unknown"),
                (2, "unknown_handoff", "api reason"),
                (3, "unknown_handoff", "unsent reason"),
                (4, "operator_note", "custom note"),
                (5, "unknown_handoff", "lease expired"),
                (7, "unknown_handoff", "late report"),
                (9, "held_unknown_lifecycle", "ambiguous hold"),
                (
                    10,
                    "migrated_unverified",
                    "a version 3 attempt may have reached a carrier; reviewed disposition required",
                ),
            ],
            "old numbers, kinds and reasons stay live; no migrated_unverified duplicate"
        );
        // Held rows are carried open and unreinterpreted: no resolution text
        // claims anything about what was or was not handed off.
        assert!(by_seq(1).unwrap().resolution.is_none());
        assert!(by_seq(9).unwrap().resolution.is_none());
        let duplicate = by_seq(6).unwrap();
        assert_eq!(duplicate.state, IncidentState::Resolved);
        assert_eq!(duplicate.reason, "second report");
        assert!(
            duplicate
                .resolution
                .as_deref()
                .unwrap()
                .contains("incident 5")
        );
        let history = by_seq(8).unwrap();
        assert_eq!(history.state, IncidentState::Disposed);
        assert!(
            history.duplicate_risk,
            "the recorded duplicate risk survives"
        );
        assert!(by_seq(2).unwrap().created_ms == 1_500 && by_seq(2).unwrap().attempt_seq.is_none());

        let archived: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM incidents_v3", [], |row| row.get(0))
            .unwrap();
        assert_eq!(archived, 9, "the original rows stay as history");
        if pass == 0 {
            // The second open proves the migrated state is stable.
            continue;
        }

        // Only never-handed-off, non-uncertain events can be dispatched.
        let inactive = attest(&codex("thread-v3-incidents"), Lifecycle::Inactive, 1);
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
        assert_eq!(
            taken,
            ["evt-hist", "evt-lifecycle", "evt-note", "evt-plain"]
        );
    }
}
