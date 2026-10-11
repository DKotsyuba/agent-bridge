//! Durable schema definition and forward migration.
//!
//! The database carries one schema version in `schema_meta`. Opening a
//! database at the current version only ensures the tables exist; an older
//! supported version is migrated forward inside one `BEGIN IMMEDIATE`
//! transaction that never rewrites or drops accepted event bytes, hashes or
//! identifiers; an unknown or newer version is refused. A migration that
//! cannot prove an old attempt never reached a carrier marks the event for
//! review instead of making it dispatchable again.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::storage::{corrupt, scope_key};
use crate::types::{CoreError, Envelope};

/// Schema version written by this build.
///
/// Version 2 scoped latest watermarks. Version 3 added single-event dispatch
/// attempts, incidents and no-wake policies. Version 4 freezes an ordered
/// manifest with recipient, actor, endpoint epoch and granted capabilities
/// per attempt, adds the per-event delivery state, coalescing scope,
/// predecessor ordering, evidence, bindings, holds, source tags and the
/// operator audit log.
pub const SCHEMA_VERSION: u32 = 4;

/// Idempotent DDL of the current schema (tables whose shape did not change
/// between versions use `IF NOT EXISTS`; changed tables are created fresh or
/// migrated by [`migrate`]).
const CURRENT_DDL: &str = "
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO counters (name, value) VALUES
    ('acceptance_seq', 0), ('attempt_seq', 0), ('incident_seq', 0),
    ('evidence_seq', 0), ('audit_seq', 0), ('retained_events', 0);
CREATE TABLE IF NOT EXISTS events (
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    envelope_json BLOB NOT NULL,
    state TEXT NOT NULL,
    acceptance_seq INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER,
    recipient TEXT NOT NULL DEFAULT '',
    policy_class TEXT NOT NULL DEFAULT '',
    delivery TEXT NOT NULL DEFAULT 'unhanded',
    attempt_seq INTEGER,
    mode TEXT NOT NULL DEFAULT '',
    scope_key TEXT NOT NULL DEFAULT '',
    revision INTEGER,
    predecessor TEXT,
    predecessor_waived INTEGER NOT NULL DEFAULT 0,
    attempts_made INTEGER NOT NULL DEFAULT 0,
    not_before_ms INTEGER NOT NULL DEFAULT 0,
    duplicate_risk INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (publisher_id, event_id)
);
CREATE TABLE IF NOT EXISTS watermarks (
    publisher_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    project TEXT NOT NULL,
    task TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (publisher_id, recipient, kind, mode, project, task, stream_id)
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_seq INTEGER PRIMARY KEY,
    state TEXT NOT NULL,
    requested_mode TEXT NOT NULL,
    effective_mode TEXT NOT NULL,
    recipient TEXT NOT NULL,
    actor TEXT NOT NULL,
    endpoint_epoch INTEGER NOT NULL,
    granted TEXT NOT NULL,
    manifest TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    lease_expires_ms INTEGER,
    deadline_ms INTEGER NOT NULL,
    recheck_ms INTEGER,
    duplicate_risk INTEGER NOT NULL DEFAULT 0,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    note TEXT,
    proof_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attempt_members (
    attempt_seq INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    PRIMARY KEY (attempt_seq, ordinal)
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_seq INTEGER PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    attempt_seq INTEGER,
    kind TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    next_check_ms INTEGER,
    review_deadline_ms INTEGER,
    responsible TEXT NOT NULL DEFAULT '',
    resolution TEXT,
    resolved_ms INTEGER,
    duplicate_risk INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_seq INTEGER PRIMARY KEY,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    attempt_seq INTEGER NOT NULL,
    tier TEXT NOT NULL,
    detail TEXT NOT NULL,
    at_ms INTEGER NOT NULL,
    UNIQUE (publisher_id, event_id, attempt_seq, tier)
);
CREATE TABLE IF NOT EXISTS recipient_policies (
    recipient TEXT PRIMARY KEY,
    no_wake INTEGER NOT NULL,
    reason TEXT,
    set_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recipient_holds (
    recipient TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    since_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bindings (
    recipient TEXT PRIMARY KEY,
    endpoint_epoch INTEGER NOT NULL,
    inject_capable INTEGER NOT NULL,
    message_capable INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS source_tags (
    publisher_id TEXT PRIMARY KEY,
    tag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    audit_seq INTEGER PRIMARY KEY,
    at_ms INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    publisher_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_dispatch
    ON events (state, delivery, recipient, policy_class, acceptance_seq);
CREATE INDEX IF NOT EXISTS events_scope
    ON events (scope_key, state, delivery, revision) WHERE scope_key != '';
CREATE INDEX IF NOT EXISTS events_predecessor
    ON events (publisher_id, predecessor) WHERE predecessor IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_expiry
    ON events (expires_at_ms) WHERE state = 'pending' AND expires_at_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS attempts_open
    ON attempts (state, lease_expires_ms);
CREATE INDEX IF NOT EXISTS attempt_members_event
    ON attempt_members (publisher_id, event_id);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_one_open
    ON incidents (publisher_id, event_id, kind) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS incidents_by_state
    ON incidents (state, next_check_ms);
";

/// Creates or migrates the schema inside the caller's transaction.
///
/// A database with no `schema_meta` table must also have no other table
/// (anything else is a foreign file and is refused untouched). Version 2 and
/// 3 databases are migrated; the current version only has its idempotent DDL
/// re-applied; every other version is refused with
/// [`CoreError::Integrity`].
pub fn ensure(tx: &Transaction<'_>) -> Result<(), CoreError> {
    let has_meta: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        let tables: i64 = tx.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if tables != 0 {
            return Err(corrupt(
                "refusing a database that has tables but no schema_meta".into(),
            ));
        }
        tx.execute_batch(CURRENT_DDL)?;
        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        return Ok(());
    }
    let stored: Option<String> = tx
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match stored.as_deref().map(str::parse::<u32>) {
        Some(Ok(SCHEMA_VERSION)) => {
            tx.execute_batch(CURRENT_DDL)?;
            Ok(())
        }
        Some(Ok(version @ (2 | 3))) => migrate(tx, version),
        other => Err(corrupt(format!(
            "refusing database with schema version {other:?}; no migration path"
        ))),
    }
}

/// Migrates a version 2 or 3 database to the current version.
///
/// Event rows keep their bytes, hash, identifiers, state, acceptance order
/// and timestamps; only the new columns are added and backfilled from the
/// stored canonical envelope. Version 3 single-event attempts (which froze
/// no manifest) are kept in `attempts_v3` for audit; an event whose newest
/// attempt may have reached a carrier is marked `review` with an open
/// incident, an event whose attempt positively finished keeps that delivery
/// tier, and only a never-invoked or known-unsent event becomes dispatchable.
fn migrate(tx: &Transaction<'_>, from: u32) -> Result<(), CoreError> {
    if from == 3 {
        tx.execute_batch(
            "ALTER TABLE attempts RENAME TO attempts_v3;
             ALTER TABLE incidents RENAME TO incidents_v3;
             DROP INDEX IF EXISTS attempts_by_event;
             DROP INDEX IF EXISTS incidents_open;",
        )?;
    }
    if from == 2 {
        // Version 2 events carried neither the routing recipient nor the
        // policy class; both are backfilled from the stored envelope.
        tx.execute_batch(
            "ALTER TABLE events ADD COLUMN recipient TEXT NOT NULL DEFAULT '';
             ALTER TABLE events ADD COLUMN policy_class TEXT NOT NULL DEFAULT '';",
        )?;
    }
    // Columns that version 2/3 events lack; added before the DDL so the
    // current indexes can reference them.
    for (column, definition) in [
        ("delivery", "TEXT NOT NULL DEFAULT 'unhanded'"),
        ("attempt_seq", "INTEGER"),
        ("mode", "TEXT NOT NULL DEFAULT ''"),
        ("scope_key", "TEXT NOT NULL DEFAULT ''"),
        ("revision", "INTEGER"),
        ("predecessor", "TEXT"),
        ("predecessor_waived", "INTEGER NOT NULL DEFAULT 0"),
        ("attempts_made", "INTEGER NOT NULL DEFAULT 0"),
        ("not_before_ms", "INTEGER NOT NULL DEFAULT 0"),
        ("duplicate_risk", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        tx.execute_batch(&format!(
            "ALTER TABLE events ADD COLUMN {column} {definition};"
        ))?;
    }
    tx.execute_batch("DROP INDEX IF EXISTS events_dispatch;")?;
    tx.execute_batch(CURRENT_DDL)?;
    backfill_events(tx)?;
    if from == 3 {
        migrate_v3_attempts(tx)?;
    }
    let retained: i64 = tx.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    tx.execute(
        "UPDATE counters SET value = ?1 WHERE name = 'retained_events'",
        params![retained],
    )?;
    tx.execute(
        "UPDATE schema_meta SET value = ?1 WHERE key = 'schema_version'",
        params![SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

/// Backfills mode, coalescing scope, revision and predecessor of every event
/// whose canonical bytes are still present.
///
/// Rows whose payload was compacted keep the defaults: compaction only
/// touches superseded/expired events, which are never dispatched again.
fn backfill_events(tx: &Transaction<'_>) -> Result<(), CoreError> {
    let mut select = tx.prepare(
        "SELECT publisher_id, event_id, envelope_hash, envelope_json FROM events
         WHERE length(envelope_json) > 0",
    )?;
    let rows: Vec<(String, String, String, Vec<u8>)> = select
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<_, _>>()?;
    drop(select);
    for (publisher, event, stored_hash, bytes) in rows {
        let envelope = Envelope::from_canonical_bytes(&bytes).map_err(|error| {
            corrupt(format!(
                "stored envelope {publisher}/{event} is invalid: {error}"
            ))
        })?;
        if envelope.envelope_hash().as_str() != stored_hash {
            return Err(corrupt(format!(
                "stored envelope {publisher}/{event} no longer matches its hash"
            )));
        }
        let revision = match &envelope.policy {
            crate::types::Policy::Latest { revision, .. } => {
                Some(crate::storage::to_sql(*revision)?)
            }
            _ => None,
        };
        tx.execute(
            "UPDATE events SET mode = ?1, scope_key = ?2, revision = ?3, predecessor = ?4,
                 recipient = ?5, policy_class = ?6
             WHERE publisher_id = ?7 AND event_id = ?8",
            params![
                envelope.mode.as_str(),
                scope_key(&envelope),
                revision,
                envelope.metadata.get("predecessor"),
                envelope.recipient.to_canonical_string(),
                envelope.policy.as_str(),
                publisher,
                event,
            ],
        )?;
    }
    Ok(())
}

/// Maps each event's newest version 3 attempt onto the version 4 delivery
/// state and carries open incidents over.
fn migrate_v3_attempts(tx: &Transaction<'_>) -> Result<(), CoreError> {
    // Newest attempt state per event.
    let mut select = tx.prepare(
        "SELECT a.publisher_id, a.event_id, a.state FROM attempts_v3 a
         WHERE a.attempt_seq = (SELECT MAX(b.attempt_seq) FROM attempts_v3 b
                                WHERE b.publisher_id = a.publisher_id
                                  AND b.event_id = a.event_id)",
    )?;
    let rows: Vec<(String, String, String)> = select
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    drop(select);
    let now: i64 = tx.query_row(
        "SELECT COALESCE(MAX(updated_ms), 0) FROM attempts_v3",
        [],
        |r| r.get(0),
    )?;
    for (publisher, event, state) in rows {
        let delivery = match state.as_str() {
            "reserved" | "closed" | "known_unsent" => "unhanded",
            "native_accepted" => "accepted",
            "hook_submitted" => "hook_submitted",
            "permanent_refusal" => "refused",
            // invoking, native_held, outcome_unknown and anything else may
            // have reached a carrier: never dispatchable again unreviewed.
            _ => "review",
        };
        tx.execute(
            "UPDATE events SET delivery = ?1, attempts_made = 1
             WHERE publisher_id = ?2 AND event_id = ?3",
            params![delivery, publisher, event],
        )?;
        if delivery == "review" {
            tx.execute(
                "INSERT OR IGNORE INTO incidents
                     (incident_seq, publisher_id, event_id, attempt_seq, kind, reason, state,
                      created_ms, updated_ms, next_check_ms, review_deadline_ms)
                 VALUES ((SELECT value FROM counters WHERE name = 'incident_seq') + 1,
                         ?1, ?2, NULL, 'migrated_unverified',
                         'a version 3 attempt may have reached a carrier; reviewed disposition required',
                         'open', ?3, ?3, ?3, ?3)",
                params![publisher, event, now],
            )?;
            tx.execute(
                "UPDATE counters SET value = value + 1 WHERE name = 'incident_seq'",
                [],
            )?;
        }
    }
    // Keep the incident sequence ahead of every carried-over number.
    let max_incident: i64 = tx.query_row(
        "SELECT COALESCE(MAX(incident_seq), 0) FROM incidents_v3",
        [],
        |row| row.get(0),
    )?;
    let counter: i64 = tx.query_row(
        "SELECT value FROM counters WHERE name = 'incident_seq'",
        [],
        |row| row.get(0),
    )?;
    if max_incident > counter {
        tx.execute(
            "UPDATE counters SET value = ?1 WHERE name = 'incident_seq'",
            params![max_incident],
        )?;
    }
    Ok(())
}

/// Opens a diagnostic read of the stored schema version (for tests and
/// operator tooling); returns `None` for a database without `schema_meta`.
pub fn stored_version(connection: &Connection) -> Result<Option<u32>, CoreError> {
    let value: Option<String> = connection
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .or_else(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(ref text)) if text.contains("no such table") => {
                Ok(None)
            }
            other => Err(other),
        })?;
    Ok(value.and_then(|text| text.parse().ok()))
}
