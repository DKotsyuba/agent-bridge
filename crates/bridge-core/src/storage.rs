//! Transactional durable custody storage for accepted events.
//!
//! One SQLite database owns the durable state of the Bridge core. Publication
//! is a single transaction: dedup lookup on `(publisher, event id)`, conflict
//! detection against the frozen envelope hash, admission check against the
//! configured hard cap, insertion of the immutable event, stream watermark
//! maintenance — then commit, and only then acknowledgement. A commit is
//! durable custody, not delivery: delivery states belong to the dispatch
//! task and are not modeled here beyond the dispositions this store owns
//! (`pending`, `superseded`, `expired`).

use std::path::Path;

use rusqlite::{Connection, TransactionBehavior, params};

use crate::types::{CoreError, Envelope, EnvelopeHash, Policy};

/// Storage schema version fenced by [`Storage::open`].
///
/// A database whose version differs is refused rather than migrated
/// implicitly; migration is a deliberate later-task operation.
const STORAGE_SCHEMA_VERSION: u32 = 1;

/// Operational limits applied at admission.
///
/// Bounds are explicit errors, never silent truncation or eviction. The hard
/// cap counts admitted (non-terminal) events: when it is reached, new
/// admission is refused explicitly rather than evicting dedup history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of admitted, not-yet-terminal events.
    pub max_admitted_events: usize,
}

impl Limits {
    /// Limits with the given hard cap.
    pub const fn new(max_admitted_events: usize) -> Self {
        Limits {
            max_admitted_events,
        }
    }
}

/// Durable state of a stored event, as owned by this storage layer.
///
/// Delivery-state transitions (reserved, invoking, native evidence tiers)
/// extend this vocabulary in the dispatch task; this layer only owns the
/// admission-time and retention dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    /// Accepted and awaiting dispatch.
    Pending,
    /// Explicitly superseded by a newer snapshot revision of the same
    /// stream; retained as a dedup entry, never dispatched.
    Superseded,
    /// Expired while still known-unhanded (pending); never dispatched after
    /// expiry and never used to claim a native side effect was recalled.
    Expired,
}

impl EventState {
    /// Storage text form.
    const fn as_str(self) -> &'static str {
        match self {
            EventState::Pending => "pending",
            EventState::Superseded => "superseded",
            EventState::Expired => "expired",
        }
    }
}

/// The custody receipt returned for an accepted or replayed event.
///
/// A committed receipt means the immutable event, its hash and its
/// disposition are durable. For a replay the fields describe the original
/// acceptance, and [`CustodyReceipt::replayed`] is `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyReceipt {
    /// Publisher whose event was accepted.
    pub publisher: String,
    /// Stable event id within that publisher.
    pub event_id: String,
    /// Frozen identity-content hash of the stored envelope.
    pub envelope_hash: EnvelopeHash,
    /// Monotonic acceptance order assigned at first admission.
    pub acceptance_seq: u64,
    /// Wall-clock acceptance time in Unix epoch milliseconds.
    pub accepted_at_ms: u64,
    /// Current durable state of the event.
    pub state: EventState,
    /// `true` when this call was an identical replay, not a new admission.
    pub replayed: bool,
}

/// Outcome of a publication attempt.
///
/// Either a fresh admission or an identical replay, both as a durable
/// receipt; conflicts and capacity refusals are [`CoreError`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// The durable custody receipt.
    pub receipt: CustodyReceipt,
}

/// The durable custody store.
///
/// Owns one SQLite connection; cheaply cloneable consumers should coordinate
/// at a higher level (the service task owns threading). Not `Sync`; open one
/// per thread if ever needed.
pub struct Storage {
    connection: Connection,
    limits: Limits,
}

impl Storage {
    /// Opens (creating if necessary) the database at `path` and applies the
    /// durable-settings and schema fence.
    ///
    /// WAL journaling with full synchronous writes: a committed custody
    /// receipt survives process crash and host restart. Refuses a database
    /// whose schema version differs from this build's storage schema
    /// version with
    /// [`CoreError::Storage`]-wrapped errors; no implicit migration.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, CoreError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Storage { connection, limits }.init_schema()
    }

    /// Opens an in-memory database; for tests and future in-process tools.
    ///
    /// Same settings and schema fence as [`Storage::open`]; durability
    /// obviously does not apply.
    pub fn open_in_memory(limits: Limits) -> Result<Self, CoreError> {
        let connection = Connection::open_in_memory()?;
        Storage { connection, limits }.init_schema()
    }

    /// Creates the v1 schema and the schema-version fence.
    ///
    /// Runs inside one transaction: either the fence row matches this build,
    /// or a foreign/unknown version refuses the open.
    fn init_schema(mut self) -> Result<Self, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS events (
                 publisher_id TEXT NOT NULL,
                 event_id TEXT NOT NULL,
                 envelope_hash TEXT NOT NULL,
                 envelope_json BLOB NOT NULL,
                 state TEXT NOT NULL,
                 acceptance_seq INTEGER NOT NULL,
                 accepted_at_ms INTEGER NOT NULL,
                 expires_at_ms INTEGER,
                 PRIMARY KEY (publisher_id, event_id)
             );
             CREATE TABLE IF NOT EXISTS counters (
                 name TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO counters (name, value) VALUES ('acceptance_seq', 0);
             CREATE TABLE IF NOT EXISTS watermarks (
                 stream_id TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL
             );",
        )?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .ok();
        match stored {
            None => {
                tx.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)",
                    params![STORAGE_SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(version) if version == STORAGE_SCHEMA_VERSION.to_string() => {}
            Some(version) => {
                return Err(CoreError::Storage(rusqlite::Error::InvalidParameterName(
                    format!("refusing database with schema version {version}"),
                )));
            }
        }
        tx.commit()?;
        Ok(self)
    }

    /// Publishes an envelope under durable custody, idempotently.
    ///
    /// One `BEGIN IMMEDIATE` transaction: dedup lookup, conflict detection,
    /// admission cap check, insertion, watermark maintenance, commit. The
    /// caller acknowledges only after this returns.
    ///
    /// Outcomes:
    /// - identical `(publisher, event id)` + equal hash: the original
    ///   receipt with `replayed = true`; consumes no admission capacity;
    /// - equal hash under a different revision-watermark situation is still
    ///   the same event and replays;
    /// - same key, different hash: [`CoreError::Conflict`], nothing written;
    /// - `latest` policy: equal revision with different content conflicts;
    ///   older revision than the watermark is admitted as `superseded`
    ///   (explicit disposition, dedup entry retained, watermark unchanged);
    /// - hard cap reached: [`CoreError::Capacity`], nothing written.
    ///
    /// `now_ms` is supplied by the caller (single clock source at the
    /// service edge) and used only for `accepted_at_ms`.
    pub fn publish(
        &mut self,
        envelope: &Envelope,
        now_ms: u64,
    ) -> Result<PublishOutcome, CoreError> {
        envelope.validate()?;
        let hash = envelope.envelope_hash();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) =
            Self::load_row(&tx, envelope_key(&envelope.publisher, &envelope.event_id))?
        {
            if existing.hash == hash.as_str() {
                return Ok(PublishOutcome {
                    receipt: CustodyReceipt {
                        publisher: envelope.publisher.as_str().to_string(),
                        event_id: envelope.event_id.as_str().to_string(),
                        envelope_hash: hash,
                        acceptance_seq: existing.acceptance_seq,
                        accepted_at_ms: existing.accepted_at_ms,
                        state: existing.state,
                        replayed: true,
                    },
                });
            }
            return Err(CoreError::Conflict {
                event_id: envelope.event_id.as_str().to_string(),
                stored_hash: existing.hash,
                submitted_hash: hash.as_str().to_string(),
            });
        }

        let state = Self::snapshot_state(&tx, envelope, &hash)?;
        if state == EventState::Pending {
            let admitted: i64 = tx.query_row(
                "SELECT COUNT(*) FROM events WHERE state = 'pending'",
                [],
                |row| row.get(0),
            )?;
            if admitted >= self.limits.max_admitted_events as i64 {
                return Err(CoreError::Capacity {
                    limit: format!("max_admitted_events {}", self.limits.max_admitted_events),
                });
            }
        }

        let acceptance_seq = Self::next_acceptance_seq(&tx)?;
        tx.execute(
            "INSERT INTO events
                 (publisher_id, event_id, envelope_hash, envelope_json, state,
                  acceptance_seq, accepted_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                envelope.publisher.as_str(),
                envelope.event_id.as_str(),
                hash.as_str(),
                envelope.canonical_bytes(),
                state.as_str(),
                acceptance_seq,
                now_ms as i64,
                envelope
                    .expires_at
                    .map(|expiry| expiry.unix_millis() as i64),
            ],
        )?;

        if let Policy::Latest { stream, revision } = &envelope.policy {
            tx.execute(
                "INSERT INTO watermarks (stream_id, revision) VALUES (?1, ?2)
                 ON CONFLICT (stream_id) DO UPDATE
                 SET revision = MAX(revision, excluded.revision)",
                params![stream.as_str(), *revision as i64],
            )?;
        }

        tx.commit()?;
        Ok(PublishOutcome {
            receipt: CustodyReceipt {
                publisher: envelope.publisher.as_str().to_string(),
                event_id: envelope.event_id.as_str().to_string(),
                envelope_hash: hash,
                acceptance_seq,
                accepted_at_ms: now_ms,
                state,
                replayed: false,
            },
        })
    }

    /// Looks up the current custody record for an event.
    ///
    /// Returns `None` when the event was never accepted. Replays and status
    /// lookups use the same durable row.
    pub fn lookup(
        &self,
        publisher: &crate::types::PublisherId,
        event_id: &crate::types::EventId,
    ) -> Result<Option<CustodyReceipt>, CoreError> {
        let row = Self::load_row(&self.connection, envelope_key(publisher, event_id))?;
        Ok(row.map(|existing| CustodyReceipt {
            publisher: publisher.as_str().to_string(),
            event_id: event_id.as_str().to_string(),
            envelope_hash: EnvelopeHash::from_hex(&existing.hash),
            acceptance_seq: existing.acceptance_seq,
            accepted_at_ms: existing.accepted_at_ms,
            state: existing.state,
            replayed: false,
        }))
    }

    /// Expires due pending events; returns how many were marked.
    ///
    /// Expiry applies only to events still known-unhanded (`pending`): a
    /// pending event past its absolute expiry becomes `expired`, an explicit
    /// disposition — never a claim that a possible native effect was
    /// recalled. Reserved/invoking/accepted states are never touched by this
    /// method; uncertain outcomes belong to the reconciler.
    pub fn expire_due(&self, now_ms: u64) -> Result<usize, CoreError> {
        let changed = self.connection.execute(
            "UPDATE events SET state = 'expired'
             WHERE state = 'pending' AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?1",
            params![now_ms as i64],
        )?;
        Ok(changed)
    }

    /// Decides the admission state for a new event from its policy.
    ///
    /// For `latest` snapshots: an equal revision with different content is a
    /// conflict; a revision older than the durable watermark is admitted as
    /// `superseded` so the dedup entry exists but the stale snapshot can
    /// never revive. All other policies admit as `pending`.
    fn snapshot_state(
        tx: &Connection,
        envelope: &Envelope,
        hash: &EnvelopeHash,
    ) -> Result<EventState, CoreError> {
        let Policy::Latest { stream, revision } = &envelope.policy else {
            return Ok(EventState::Pending);
        };
        let watermark: Option<i64> = tx
            .query_row(
                "SELECT revision FROM watermarks WHERE stream_id = ?1",
                params![stream.as_str()],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        match watermark {
            Some(stored) if stored == *revision as i64 => Err(CoreError::Conflict {
                event_id: envelope.event_id.as_str().to_string(),
                stored_hash: format!("stream revision {stored}"),
                submitted_hash: hash.as_str().to_string(),
            }),
            Some(stored) if stored > *revision as i64 => Ok(EventState::Superseded),
            _ => Ok(EventState::Pending),
        }
    }

    /// Reads a stored row by key, if present.
    ///
    /// Shared by publish (dedup lookup) and lookup (status); read-only.
    fn load_row(
        connection: &Connection,
        key: (&str, &str),
    ) -> Result<Option<StoredRow>, CoreError> {
        let mut statement = connection
            .prepare(
                "SELECT envelope_hash, state, acceptance_seq, accepted_at_ms
                 FROM events WHERE publisher_id = ?1 AND event_id = ?2",
            )
            .map_err(CoreError::from)?;
        let mut rows = statement
            .query(params![key.0, key.1])
            .map_err(CoreError::from)?;
        match rows.next().map_err(CoreError::from)? {
            None => Ok(None),
            Some(row) => Ok(Some(StoredRow {
                hash: row.get(0).map_err(CoreError::from)?,
                state: parse_state(row.get(1).map_err(CoreError::from)?),
                acceptance_seq: row.get::<_, i64>(2).map_err(CoreError::from)? as u64,
                accepted_at_ms: row.get::<_, i64>(3).map_err(CoreError::from)? as u64,
            })),
        }
    }

    /// Increments and returns the acceptance counter inside the caller's
    /// transaction.
    fn next_acceptance_seq(tx: &Connection) -> Result<u64, CoreError> {
        tx.execute(
            "UPDATE counters SET value = value + 1 WHERE name = 'acceptance_seq'",
            [],
        )?;
        let value: i64 = tx.query_row(
            "SELECT value FROM counters WHERE name = 'acceptance_seq'",
            [],
            |row| row.get(0),
        )?;
        Ok(value as u64)
    }
}

/// The `(publisher id, event id)` pair as plain strings for SQL parameters.
///
/// Keeps call sites readable without exposing the row shape.
fn envelope_key<'a>(
    publisher: &'a crate::types::PublisherId,
    event_id: &'a crate::types::EventId,
) -> (&'a str, &'a str) {
    (publisher.as_str(), event_id.as_str())
}

/// A stored event row as read back from the database.
struct StoredRow {
    /// Frozen identity-content hash (hex text as stored).
    hash: String,
    /// Durable state of the event.
    state: EventState,
    /// Monotonic acceptance order.
    acceptance_seq: u64,
    /// Acceptance wall clock in Unix epoch milliseconds.
    accepted_at_ms: u64,
}

/// Parses the storage text form of an event state.
///
/// Unknown values map to [`EventState::Pending`]; the schema fence plus this
/// layer being the only writer makes unknown values unreachable in practice.
fn parse_state(value: String) -> EventState {
    match value.as_str() {
        "superseded" => EventState::Superseded,
        "expired" => EventState::Expired,
        _ => EventState::Pending,
    }
}

impl EnvelopeHash {
    /// Wraps a stored 64-character lowercase hex hash.
    ///
    /// Trust boundary is the local database this layer wrote; no re-hashing.
    fn from_hex(value: &str) -> Self {
        EnvelopeHash(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    //! In-module checks for helpers not needing a database.

    use super::*;

    #[test]
    fn state_text_roundtrip() {
        assert_eq!(EventState::Pending.as_str(), "pending");
        assert_eq!(parse_state("superseded".into()), EventState::Superseded);
        assert_eq!(parse_state("expired".into()), EventState::Expired);
    }

    #[test]
    fn limits_are_plain_data() {
        let limits = Limits::new(7);
        assert_eq!(limits.max_admitted_events, 7);
    }
}
