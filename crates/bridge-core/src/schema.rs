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
/// operator audit log. Version 5 adds the per-event stream `lineage_key` and
/// the `stream_lineages` authority table (one producer owns each `latest`
/// lineage). Version 6 adds durable producer routes/request receipts, global
/// evidence-use claims, lifetime fences and scoped snapshot watermarks;
/// accepted legacy envelope bytes/hashes and possible effects stay unchanged.
pub const SCHEMA_VERSION: u32 = 6;

/// Backfills each migrated `latest` event's lineage key.
///
/// Intact envelopes are authoritative (their metadata and stream define
/// the lineage). Compacted events — which by construction are terminal
/// superseded/expired rows, never dispatchable — fall back to a watermark
/// join only where exactly one watermark row matches the event's
/// publisher/recipient/kind/mode tuple; an unmatchable row keeps an empty
/// key, meaning "lineage unknown": it stays retained and auditable but is
/// never dispatchable (compacted rows are terminal and never eligible), so an
/// unknown lineage cannot silently re-enter delivery after a migration.
fn backfill_event_lineage_keys(tx: &Transaction<'_>) -> Result<(), CoreError> {
    // The events table stores recipient and mode as columns but not kind;
    // intact envelopes supply kind, project, task and stream, while
    // compacted rows fall back to a watermark join on the stored columns
    // (publisher, recipient, mode) that accepts exactly one matching
    // watermark row.
    tx.execute_batch(
        "UPDATE events SET lineage_key =
             recipient || char(31)
             || COALESCE(json_extract(envelope_json, '$.kind'), '')
             || char(31) || mode || char(31)
             || COALESCE(json_extract(envelope_json, '$.metadata.project'), '')
             || char(31) || COALESCE(json_extract(envelope_json, '$.metadata.task'), '')
             || char(31) || json_extract(envelope_json, '$.policy.Latest.stream')
         WHERE policy_class = 'latest' AND lineage_key = ''
           AND CASE WHEN json_valid(envelope_json)
                    THEN json_extract(envelope_json, '$.policy.Latest.stream') END IS NOT NULL;
         UPDATE events SET lineage_key = COALESCE((
             SELECT events.recipient || char(31) || w.kind || char(31) || events.mode
                    || char(31) || w.project || char(31) || w.task || char(31) || w.stream_id
             FROM watermarks w
             WHERE w.publisher_id = events.publisher_id AND w.recipient = events.recipient
               AND w.mode = events.mode
               AND (SELECT COUNT(*) FROM watermarks x
                    WHERE x.publisher_id = events.publisher_id
                      AND x.recipient = events.recipient AND x.mode = events.mode) = 1
         ), '')
         WHERE policy_class = 'latest' AND lineage_key = ''
           AND CASE WHEN json_valid(envelope_json)
                    THEN json_extract(envelope_json, '$.policy.Latest.stream') END IS NULL;",
    )?;
    Ok(())
}

/// Backfills stream-lineage authority from durable historical evidence.
///
/// Called when a database predates lineage tracking (migrations from
/// versions 2, 3 and 4). The evidence is the union of the per-event
/// lineage keys (see [`backfill_event_lineage_keys`]) and the watermark
/// table, which every `latest` publication wrote and which retention never
/// evicts: per lineage (the coalescing scope without the publisher)
/// exactly one distinct historical producer across *both* sources backs
/// the owner; two or more distinct producers are an ambiguous legacy
/// stream and are recorded with an empty owner, which fences every new
/// admission and every pending dispatch until an operator resolves the
/// authority — an owner is never chosen by arrival time or revision.
/// Accepted bytes, ids, dedup entries, watermarks, attempts and evidence
/// are untouched.
fn backfill_lineages(tx: &Transaction<'_>) -> Result<(), CoreError> {
    tx.execute_batch(
        "WITH evidence (lineage_key, publisher_id) AS (
             SELECT lineage_key, publisher_id FROM events
             WHERE policy_class = 'latest' AND lineage_key != ''
             UNION
             SELECT recipient || char(31) || kind || char(31) || mode || char(31)
                    || project || char(31) || task || char(31) || stream_id,
                    publisher_id
             FROM watermarks
         )
         INSERT OR IGNORE INTO stream_lineages (lineage_key, owner, set_ms, note)
         SELECT lineage_key,
                CASE WHEN COUNT(*) = 1 THEN MIN(publisher_id) ELSE '' END,
                0,
                CASE WHEN COUNT(*) = 1
                     THEN 'owner backfilled from durable history (unambiguous single producer)'
                     ELSE 'ambiguous legacy producers; operator resolution required' END
         FROM evidence GROUP BY lineage_key;",
    )?;
    Ok(())
}

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
    lineage_key TEXT NOT NULL DEFAULT '',
    delivery_scope_key TEXT NOT NULL DEFAULT '',
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
CREATE TABLE IF NOT EXISTS stream_lineages (
    lineage_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    set_ms INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_by_lineage
    ON events (lineage_key, policy_class, delivery) WHERE lineage_key != '';
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
CREATE TABLE IF NOT EXISTS producer_scopes (
    producer TEXT NOT NULL, kind TEXT NOT NULL, identity_key TEXT NOT NULL,
    scope_key TEXT NOT NULL UNIQUE,
    PRIMARY KEY (producer, kind, identity_key)
);
CREATE TABLE IF NOT EXISTS return_routes (
    producer TEXT NOT NULL, operation_key TEXT NOT NULL,
    route_key TEXT NOT NULL UNIQUE, binding_hash TEXT NOT NULL,
    requested_json TEXT NOT NULL, caller_json TEXT NOT NULL,
    destination TEXT NOT NULL, constraints_json TEXT NOT NULL,
    caller_scope TEXT NOT NULL, destination_scope TEXT NOT NULL,
    created_ms INTEGER NOT NULL, expires_ms INTEGER, closed_ms INTEGER,
    PRIMARY KEY (producer, operation_key)
);
CREATE TABLE IF NOT EXISTS registration_requests (
    producer TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
    operation_key TEXT NOT NULL, receipt_json TEXT NOT NULL, use_key TEXT NOT NULL,
    PRIMARY KEY (producer, request_id)
);
CREATE TABLE IF NOT EXISTS evidence_uses (
    use_key TEXT PRIMARY KEY, producer TEXT NOT NULL, request_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS publication_intents (
    producer TEXT NOT NULL, event_id TEXT NOT NULL, intent_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (producer, event_id)
);
CREATE TABLE IF NOT EXISTS close_requests (
    producer TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (producer, request_id)
);
CREATE TABLE IF NOT EXISTS delivery_scopes (
    producer TEXT NOT NULL, scope_key TEXT NOT NULL,
    closed_ms INTEGER, action TEXT, receipt_json TEXT,
    PRIMARY KEY (producer, scope_key)
);
CREATE TABLE IF NOT EXISTS retire_requests (
    producer TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (producer, request_id)
);
CREATE TABLE IF NOT EXISTS scoped_watermarks (
    scope_key TEXT PRIMARY KEY, revision INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_lifetime
    ON events (publisher_id, delivery_scope_key, delivery);
";

/// Creates or migrates the schema inside the caller's transaction.
///
/// A database with no `schema_meta` table must also have no other table
/// (anything else is a foreign file and is refused untouched). Version 2, 3
/// and 4 databases are migrated forward with lineage backfill; version 5
/// gains only additive universal/lifetime tables and an empty lifetime column.
/// The current version only has its idempotent DDL
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
        Some(Ok(5)) => {
            add_delivery_scope(tx)?;
            tx.execute_batch(CURRENT_DDL)?;
            tx.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'schema_version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            Ok(())
        }
        // Version 4 databases lack the additive `events.lineage_key` column
        // and the stream_lineages table. The column is added before the
        // idempotent DDL (whose index references it); no stored row is
        // rewritten except the new key column, which is backfilled from
        // retained evidence.
        Some(Ok(4)) => {
            add_delivery_scope(tx)?;
            let has_key: bool = tx.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('events') WHERE name = 'lineage_key'",
                [],
                |row| row.get(0),
            )?;
            if !has_key {
                tx.execute_batch(
                    "ALTER TABLE events ADD COLUMN lineage_key TEXT NOT NULL DEFAULT '';",
                )?;
            }
            tx.execute_batch(CURRENT_DDL)?;
            backfill_event_lineage_keys(tx)?;
            backfill_lineages(tx)?;
            tx.execute(
                "UPDATE schema_meta SET value = ?1 WHERE key = 'schema_version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
            Ok(())
        }
        Some(Ok(version @ (2 | 3))) => migrate(tx, version),
        other => Err(corrupt(format!(
            "refusing database with schema version {other:?}; no migration path"
        ))),
    }
}

/// Migrates a version 2 or 3 database to the current version (version 4 has
/// its own additive step in [`ensure`]).
///
/// Event rows keep their bytes, hash, identifiers, state, acceptance order
/// and timestamps; only the new columns are added and backfilled from the
/// stored canonical envelope. Version 3 single-event attempts (which froze
/// no manifest) are kept in `attempts_v3` for audit; an event whose newest
/// attempt may have reached a carrier, or that has an open `unknown_handoff`
/// incident, is marked `review` with an open incident, an event whose
/// attempt positively finished keeps that delivery tier, and only a
/// never-invoked or known-unsent event without such an incident becomes
/// dispatchable.
/// The version 3 `incidents` table is renamed to `incidents_v3` and kept as
/// history; every row is also carried into the live table (see
/// [`migrate_v3_attempts`]).
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
        ("lineage_key", "TEXT NOT NULL DEFAULT ''"),
        ("delivery_scope_key", "TEXT NOT NULL DEFAULT ''"),
    ] {
        tx.execute_batch(&format!(
            "ALTER TABLE events ADD COLUMN {column} {definition};"
        ))?;
    }
    tx.execute_batch("DROP INDEX IF EXISTS events_dispatch;")?;
    tx.execute_batch(CURRENT_DDL)?;
    backfill_events(tx)?;
    backfill_event_lineage_keys(tx)?;
    backfill_lineages(tx)?;
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

/// Adds only the schema-six lifetime column to existing version-four/five
/// events; accepted envelope bytes and delivery evidence are untouched.
fn add_delivery_scope(tx: &Transaction<'_>) -> Result<(), CoreError> {
    let present: bool = tx.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('events') WHERE name = 'delivery_scope_key'",
        [],
        |row| row.get(0),
    )?;
    if !present {
        tx.execute_batch(
            "ALTER TABLE events ADD COLUMN delivery_scope_key TEXT NOT NULL DEFAULT '';",
        )?;
    }
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
/// state and carries every version 3 incident into the live table.
///
/// Version 3 (commit 58c0740, `Storage::open_incident`) let any code write an
/// incident of any `kind`; its own sources wrote `unknown_handoff` (an
/// `outcome_unknown` attempt or an expired invoking lease) and
/// `held_unknown_lifecycle`, and only an open `unknown_handoff` incident
/// blocked a new attempt (a kind's name proves nothing about what happened,
/// so no kind is closed or reinterpreted by the migration). Each `incidents_v3` row
/// is therefore copied to the live `incidents` table with its number, kind,
/// reason, state, dates, resolution and (when a manual retry was recorded)
/// its duplicate risk:
/// - an open row of any kind (including `held_unknown_lifecycle`) stays open,
///   so operators still see and resolve it with the original identity;
///   whether its event may be dispatched is decided only by the event's
///   current attempt evidence and by an open `unknown_handoff` incident;
/// - a further open row of the same event and kind becomes `resolved`,
///   pointing at the lowest-numbered open one (the live table allows one open
///   incident per event and kind); its original reason stays on the row.
///
/// An event whose newest attempt may have reached a carrier, or that has an
/// open `unknown_handoff` incident (even with no attempt record, which the
/// version 3 API allowed), is put in `review` and never becomes dispatchable
/// unreviewed. An event with a carried open `unknown_handoff` incident gets
/// no extra `migrated_unverified` incident; any other review event gets one.
/// The `incidents_v3` rows remain as history, and the incident counter
/// stays ahead of every carried number.
fn migrate_v3_attempts(tx: &Transaction<'_>) -> Result<(), CoreError> {
    // Keep the incident sequence ahead of every carried-over number first,
    // so newly synthesized incidents can never collide with an old one.
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
    tx.execute(
        "INSERT INTO incidents
             (incident_seq, publisher_id, event_id, attempt_seq, kind, reason, state,
              created_ms, updated_ms, next_check_ms, review_deadline_ms, responsible,
              resolution, resolved_ms, duplicate_risk)
         SELECT incident_seq, publisher_id, event_id, NULL, kind, reason,
                CASE WHEN NOT is_open THEN state
                     WHEN first_open < incident_seq THEN 'resolved'
                     ELSE 'open' END,
                created_ms, updated_ms, next_check_ms, review_deadline_ms,
                'source:' || publisher_id || '; operator',
                CASE WHEN NOT is_open THEN resolution
                     WHEN first_open < incident_seq THEN
                          'migration: duplicate of open incident ' || first_open
                          || ' (same event and kind); the original reason is kept on this row'
                     ELSE resolution END,
                CASE WHEN NOT is_open OR first_open < incident_seq THEN updated_ms END,
                COALESCE(resolution LIKE 'manual retry authorized%', 0)
         FROM (SELECT *, state NOT IN ('resolved', 'disposed') AS is_open,
                      MIN(incident_seq) OVER (
                          PARTITION BY publisher_id, event_id, kind,
                                       state NOT IN ('resolved', 'disposed')) AS first_open
               FROM incidents_v3)",
        [],
    )?;
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
        if delivery == "review" && !has_carried_unknown(tx, &publisher, &event)? {
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
    // An open `unknown_handoff` incident blocked version 3 dispatch whether
    // or not a newest attempt is recorded: that event must stay out of
    // rotation.
    tx.execute(
        "UPDATE events SET delivery = 'review'
         WHERE state = 'pending' AND delivery = 'unhanded'
           AND EXISTS (SELECT 1 FROM incidents i
                       WHERE i.publisher_id = events.publisher_id
                         AND i.event_id = events.event_id
                         AND i.kind = 'unknown_handoff' AND i.state = 'open')",
        [],
    )?;
    Ok(())
}

/// Whether the event already carries an open `unknown_handoff` incident
/// copied from version 3, which then stands in for the synthesized
/// `migrated_unverified` incident so the same uncertainty is not reported
/// twice.
///
/// `publisher` and `event` identify the event. Returns a storage error only
/// if the query fails.
fn has_carried_unknown(
    tx: &Transaction<'_>,
    publisher: &str,
    event: &str,
) -> Result<bool, CoreError> {
    Ok(tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM incidents
                        WHERE publisher_id = ?1 AND event_id = ?2
                          AND kind = 'unknown_handoff' AND state = 'open')",
        params![publisher, event],
        |row| row.get(0),
    )?)
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
