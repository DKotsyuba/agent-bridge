//! Transactional durable custody storage for accepted events.
//!
//! One SQLite database owns the durable state of the Bridge core. Publication
//! is a single transaction: dedup lookup on `(publisher, event id)`, conflict
//! detection against the frozen envelope hash, admission checks against the
//! configured caps, insertion of the immutable event, stream watermark
//! maintenance and supersession of older pending snapshots — then commit,
//! and only then acknowledgement. A commit is durable custody, not delivery:
//! the custody disposition (`pending`, `superseded`, `expired`) is separate
//! from the per-event delivery state (`delivery`), which only the dispatch
//! module changes.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::framing::{self, check_renderable};
use crate::schema;
use crate::types::{
    CoreError, Envelope, EnvelopeHash, EventId, MAX_SQLITE_INT, Policy, PublisherId,
};

/// How long a statement waits for another connection's write lock before
/// the call fails with a retryable [`CoreError::Busy`].
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Default retained-row hard cap (dedup history is never evicted).
const DEFAULT_MAX_RETAINED: usize = 5_000_000;

/// Per-event delivery states, written only by the dispatch module.
///
/// `unhanded` is the only dispatchable state. `reserved` and `invoking`
/// belong to an open attempt; `held` is a non-terminal native condition;
/// `review` is an unresolved possible hand-off that is never replayed
/// automatically. `accepted`, `hook_submitted`, `refused` and `disposed`
/// are terminal for admission accounting (a `refused` or `disposed` event
/// additionally keeps its incident history).
pub(crate) mod delivery {
    /// Never handed to any path and eligible for reservation.
    pub const UNHANDED: &str = "unhanded";
    /// Owned by a reserved attempt that has not invoked.
    pub const RESERVED: &str = "reserved";
    /// Owned by an attempt persisted as invoking: a hand-off may exist.
    pub const INVOKING: &str = "invoking";
    /// Native side holds the event or a write has no receipt yet.
    pub const HELD: &str = "held";
    /// Possible hand-off with an unresolved outcome; manual resolution.
    pub const REVIEW: &str = "review";
    /// Native queue/inbox accepted (or later evidence confirmed it).
    pub const ACCEPTED: &str = "accepted";
    /// Hook payload handed out.
    pub const HOOK_SUBMITTED: &str = "hook_submitted";
    /// Permanently refused before acceptance.
    pub const REFUSED: &str = "refused";
    /// Closed by an audited operator disposition; never delivered.
    pub const DISPOSED: &str = "disposed";
    /// SQL list of the states that still count against admission caps.
    pub const NON_TERMINAL: &str = "('unhanded','reserved','invoking','held','review')";
}

/// Converts a `u64` to SQLite's signed INTEGER, refusing values that would
/// wrap negative.
pub(crate) fn to_sql(value: u64) -> Result<i64, CoreError> {
    i64::try_from(value).map_err(|_| {
        CoreError::InvalidEnvelope(format!(
            "value {value} exceeds the supported bound {MAX_SQLITE_INT}"
        ))
    })
}

/// Converts a stored signed INTEGER back to `u64`, refusing negatives.
///
/// Every counter, sequence and timestamp is written non-negative by this
/// layer; a negative read means corruption or a foreign writer and must not
/// wrap into a huge unsigned value.
pub(crate) fn from_sql(value: i64) -> Result<u64, CoreError> {
    u64::try_from(value).map_err(|_| {
        corrupt(format!(
            "stored value {value} is negative and cannot be an unsigned id or timestamp"
        ))
    })
}

/// Builds the integrity error for a violated stored invariant.
pub(crate) fn corrupt(detail: String) -> CoreError {
    CoreError::Integrity(detail)
}

/// Increments a named counter and returns the new value.
///
/// Refuses to cross the signed range instead of wrapping.
pub(crate) fn bump_counter(connection: &Connection, name: &str) -> Result<u64, CoreError> {
    let value: Option<i64> = connection
        .query_row(
            "UPDATE counters SET value = value + 1 WHERE name = ?1 AND value < ?2 RETURNING value",
            params![name, i64::MAX],
            |row| row.get(0),
        )
        .optional()?;
    match value {
        Some(value) => from_sql(value),
        None => Err(CoreError::Capacity {
            limit: format!("counter {name} is exhausted"),
        }),
    }
}

/// Counts rows with a scalar `COUNT(*)` query.
pub(crate) fn count(
    connection: &Connection,
    sql: &str,
    args: impl rusqlite::Params,
) -> Result<u64, CoreError> {
    let value: i64 = connection.query_row(sql, args, |row| row.get(0))?;
    from_sql(value)
}

/// Operational limits applied at admission.
///
/// Bounds are explicit errors, never silent truncation or eviction. The
/// global hard cap counts admitted events that are not yet terminal: when it
/// is reached, new admission is refused explicitly. The per-publisher item
/// quota and the per-recipient replaceable-snapshot quota implement
/// admission fairness: keep_all events are exempt from the snapshot quota so
/// a diagnostics flood cannot fill storage before independent completions.
/// `max_retained_events` bounds the dedup history itself, which is never
/// evicted: at that cap new admission is refused. The connection fields
/// bound the local service's threads and per-connection waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum number of admitted, not-yet-terminal events.
    pub max_admitted_events: usize,
    /// Maximum pending events per publisher (item quota).
    #[serde(default = "default_max_per_publisher")]
    pub max_pending_per_publisher: usize,
    /// Maximum pending `latest` snapshots per recipient; keep_all events
    /// do not count against this reserve.
    #[serde(default = "default_max_latest_per_recipient")]
    pub max_pending_latest_per_recipient: usize,
    /// Maximum retained event rows including all terminal tombstones.
    #[serde(default = "default_max_retained")]
    pub max_retained_events: usize,
    /// Maximum concurrently served socket connections (one thread each).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Milliseconds a connection may stay silent before it is closed.
    #[serde(default = "default_idle_ms")]
    pub idle_timeout_ms: u64,
    /// Milliseconds a started request line may take to arrive completely.
    #[serde(default = "default_request_ms")]
    pub request_timeout_ms: u64,
    /// Milliseconds a response write may block on a peer that does not read.
    #[serde(default = "default_write_ms")]
    pub write_timeout_ms: u64,
}

/// Default per-publisher item quota.
const fn default_max_per_publisher() -> usize {
    10_000
}

/// Default per-recipient snapshot quota.
const fn default_max_latest_per_recipient() -> usize {
    128
}

/// Default dedup-history hard cap.
const fn default_max_retained() -> usize {
    DEFAULT_MAX_RETAINED
}

/// Default connection cap.
const fn default_max_connections() -> usize {
    64
}

/// Default idle timeout.
const fn default_idle_ms() -> u64 {
    60_000
}

/// Default started-request timeout.
const fn default_request_ms() -> u64 {
    10_000
}

/// Default response write timeout.
const fn default_write_ms() -> u64 {
    10_000
}

impl Limits {
    /// Limits with the given global hard cap and default fairness quotas.
    pub const fn new(max_admitted_events: usize) -> Self {
        Limits {
            max_admitted_events,
            max_pending_per_publisher: default_max_per_publisher(),
            max_pending_latest_per_recipient: default_max_latest_per_recipient(),
            max_retained_events: default_max_retained(),
            max_connections: default_max_connections(),
            idle_timeout_ms: default_idle_ms(),
            request_timeout_ms: default_request_ms(),
            write_timeout_ms: default_write_ms(),
        }
    }

    /// Rejects limits that would make admission impossible or meaningless:
    /// every bound must be at least one, representable in SQLite, and the
    /// retained cap must not be below the admitted cap.
    pub fn validate(&self) -> Result<(), CoreError> {
        for (name, value) in [
            ("max_admitted_events", self.max_admitted_events),
            ("max_pending_per_publisher", self.max_pending_per_publisher),
            (
                "max_pending_latest_per_recipient",
                self.max_pending_latest_per_recipient,
            ),
            ("max_retained_events", self.max_retained_events),
        ] {
            if value == 0 || to_sql(value as u64).is_err() {
                return Err(CoreError::InvalidEnvelope(format!(
                    "limit {name} must be between 1 and {MAX_SQLITE_INT}"
                )));
            }
        }
        if self.max_retained_events < self.max_admitted_events {
            return Err(CoreError::InvalidEnvelope(
                "limit max_retained_events must not be below max_admitted_events".into(),
            ));
        }
        if !(1..=1024).contains(&self.max_connections) {
            return Err(CoreError::InvalidEnvelope(
                "limit max_connections must be between 1 and 1024".into(),
            ));
        }
        for (name, value) in [
            ("idle_timeout_ms", self.idle_timeout_ms),
            ("request_timeout_ms", self.request_timeout_ms),
            ("write_timeout_ms", self.write_timeout_ms),
        ] {
            if !(1..=600_000).contains(&value) {
                return Err(CoreError::InvalidEnvelope(format!(
                    "limit {name} must be between 1 and 600000"
                )));
            }
        }
        Ok(())
    }
}

/// Custody disposition of a stored event.
///
/// This is the admission-time and retention disposition owned by the
/// storage layer; the delivery tiers are reported separately (see
/// [`crate::recovery::DeliveryEvidence`]) and are never folded into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventState {
    /// Accepted; dispatch state is tracked separately.
    Pending,
    /// Explicitly superseded by a newer snapshot revision of the same
    /// stream; retained as a dedup entry, never dispatched.
    Superseded,
    /// Expired while still known-unhanded; never dispatched after expiry
    /// and never used to claim a native side effect was recalled.
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
/// acceptance, and [`CustodyReceipt::replayed`] is `true`. Deserialization
/// revalidates every field, so a receipt that was read from a socket or a
/// file is as trustworthy as one built here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawReceipt")]
pub struct CustodyReceipt {
    /// Publisher whose event was accepted.
    pub publisher: String,
    /// Stable event id within that publisher.
    pub event_id: String,
    /// Frozen identity-content hash of the stored envelope.
    pub envelope_hash: EnvelopeHash,
    /// Monotonic acceptance order assigned at first admission (at least 1).
    pub acceptance_seq: u64,
    /// Wall-clock acceptance time in Unix epoch milliseconds.
    pub accepted_at_ms: u64,
    /// Current custody disposition of the event.
    pub state: EventState,
    /// `true` when this call was an identical replay, not a new admission.
    pub replayed: bool,
}

/// Unvalidated wire shape of [`CustodyReceipt`].
#[derive(Deserialize)]
struct RawReceipt {
    /// Publisher as received.
    publisher: String,
    /// Event id as received.
    event_id: String,
    /// Hash as received (its own type validates the hex form).
    envelope_hash: EnvelopeHash,
    /// Acceptance order as received.
    acceptance_seq: u64,
    /// Acceptance time as received.
    accepted_at_ms: u64,
    /// Disposition as received.
    state: EventState,
    /// Replay flag as received.
    replayed: bool,
}

impl TryFrom<RawReceipt> for CustodyReceipt {
    type Error = CoreError;

    /// Validates identifiers and numeric ranges of a deserialized receipt.
    fn try_from(raw: RawReceipt) -> Result<Self, CoreError> {
        PublisherId::new(raw.publisher.clone())?;
        EventId::new(raw.event_id.clone())?;
        if raw.acceptance_seq == 0 || raw.acceptance_seq > MAX_SQLITE_INT {
            return Err(CoreError::InvalidEnvelope(
                "receipt acceptance_seq is out of range".into(),
            ));
        }
        if raw.accepted_at_ms > MAX_SQLITE_INT {
            return Err(CoreError::InvalidEnvelope(
                "receipt accepted_at_ms is out of range".into(),
            ));
        }
        Ok(CustodyReceipt {
            publisher: raw.publisher,
            event_id: raw.event_id,
            envelope_hash: raw.envelope_hash,
            acceptance_seq: raw.acceptance_seq,
            accepted_at_ms: raw.accepted_at_ms,
            state: raw.state,
            replayed: raw.replayed,
        })
    }
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
/// Owns one SQLite connection; callers coordinate at a higher level (the
/// service shares one store behind a mutex, and several processes may open
/// the same file because every write is an immediate transaction guarded by
/// a busy timeout). Not `Sync`; open one per thread when needed.
pub struct Storage {
    /// The single SQLite connection; crate-visible for the dispatch and
    /// recovery modules that share this store.
    pub(crate) connection: Connection,
    /// Admission limits applied by [`Storage::publish`].
    limits: Limits,
}

impl Storage {
    /// Opens (creating if necessary) the database at `path`, applies the
    /// durable settings and migrates or fences the schema.
    ///
    /// WAL journaling with full synchronous writes: a committed custody
    /// receipt survives process crash and host restart. An older supported
    /// schema is migrated forward without touching accepted bytes, hashes
    /// or identifiers; a newer or unknown schema is refused with
    /// [`CoreError::Integrity`]. Invalid limits are refused first.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, CoreError> {
        limits.validate()?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if mode != "wal" {
            return Err(corrupt(format!("database refused WAL journaling ({mode})")));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        Storage { connection, limits }.init_schema()
    }

    /// Opens an in-memory database; for tests and in-process tools.
    ///
    /// Same schema fence and limits validation as [`Storage::open`];
    /// durability obviously does not apply.
    pub fn open_in_memory(limits: Limits) -> Result<Self, CoreError> {
        limits.validate()?;
        let connection = Connection::open_in_memory()?;
        Storage { connection, limits }.init_schema()
    }

    /// The admission limits this store enforces.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Creates, migrates or fences the schema in one immediate transaction.
    fn init_schema(mut self) -> Result<Self, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        schema::ensure(&tx)?;
        tx.commit()?;
        Ok(self)
    }

    /// Starts an immediate (write-locking) transaction.
    pub(crate) fn begin(&mut self) -> Result<Transaction<'_>, CoreError> {
        Ok(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    /// Registers the allowlisted source tag for a publisher.
    ///
    /// The tag is the wrapper name Bridge renders around that publisher's
    /// events, chosen by the operator from the authenticated integration
    /// and never by the event. Re-registering the same tag is a no-op; a
    /// different tag for an existing publisher is refused so a published
    /// event can never be re-attributed to another source.
    pub fn register_source_tag(&mut self, publisher: &str, tag: &str) -> Result<(), CoreError> {
        PublisherId::new(publisher)?;
        framing::validate_tag(tag)?;
        let tx = self.begin()?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT tag FROM source_tags WHERE publisher_id = ?1",
                params![publisher],
                |row| row.get(0),
            )
            .optional()?;
        match stored {
            None => {
                tx.execute(
                    "INSERT INTO source_tags (publisher_id, tag) VALUES (?1, ?2)",
                    params![publisher, tag],
                )?;
            }
            Some(existing) if existing == tag => {}
            Some(existing) => {
                return Err(CoreError::InvalidEnvelope(format!(
                    "publisher {publisher} already has source tag {existing:?}"
                )));
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Publishes an envelope under durable custody, idempotently.
    ///
    /// One `BEGIN IMMEDIATE` transaction: dedup lookup, conflict detection,
    /// admission checks, insertion, watermark maintenance, supersession of
    /// older pending snapshots of the same scope, commit. The caller
    /// acknowledges only after this returns.
    ///
    /// Outcomes:
    /// - identical `(publisher, event id)` + equal hash: the original
    ///   receipt with `replayed = true`, consuming no admission capacity;
    /// - same key, different hash: [`CoreError::Conflict`], nothing written;
    /// - `latest` policy: equal revision with different content conflicts;
    ///   an older revision than the scope's watermark is admitted as
    ///   `superseded` (explicit disposition, dedup entry retained,
    ///   watermark unchanged); a newer revision supersedes the scope's
    ///   older pending, never-reserved snapshots;
    /// - a `predecessor` metadata value names an event of the same publisher
    ///   that this event must wait for; the predecessor may arrive later (the
    ///   dependent is accepted and held, never released by time), but a
    ///   dependency cycle is refused;
    /// - a recipient whose attested capabilities are known not to include a
    ///   path the mode needs (inject needs the inject path, message the
    ///   message path, auto both) is refused with
    ///   [`CoreError::Unsupported`] before acceptance;
    /// - an event that could never be rendered (forbidden controls, escaped
    ///   size over the manifest bound) is refused before acceptance;
    /// - a hard cap reached: [`CoreError::Capacity`], nothing written.
    ///
    /// `now_ms` is supplied by the caller (single clock source at the
    /// service edge) and used only for `accepted_at_ms`; values above the
    /// SQLite-safe bound are refused rather than cast.
    pub fn publish(
        &mut self,
        envelope: &Envelope,
        now_ms: u64,
    ) -> Result<PublishOutcome, CoreError> {
        envelope.validate()?;
        check_renderable(envelope)?;
        let now = to_sql(now_ms)?;
        let expiry = envelope
            .expires_at
            .map(|expiry| to_sql(expiry.unix_millis()))
            .transpose()?;
        let revision = match &envelope.policy {
            Policy::Latest { revision, .. } => Some(to_sql(*revision)?),
            _ => None,
        };
        let predecessor = envelope.metadata.get("predecessor");
        if let Some(predecessor) = predecessor {
            EventId::new(predecessor.clone())?;
            if predecessor == envelope.event_id.as_str() {
                return Err(CoreError::InvalidEnvelope(
                    "an event cannot be its own predecessor".into(),
                ));
            }
        }
        let hash = envelope.envelope_hash();
        let limits = self.limits;
        let tx = self.begin()?;

        if let Some(existing) =
            load_row(&tx, envelope.publisher.as_str(), envelope.event_id.as_str())?
        {
            if existing.hash == hash {
                return Ok(PublishOutcome {
                    receipt: existing.receipt(
                        envelope.publisher.as_str(),
                        envelope.event_id.as_str(),
                        true,
                    ),
                });
            }
            return Err(CoreError::Conflict {
                event_id: envelope.event_id.as_str().to_string(),
                stored_hash: existing.hash.as_str().to_string(),
                submitted_hash: hash.as_str().to_string(),
            });
        }

        if let Some(predecessor) = predecessor
            && creates_cycle(
                &tx,
                envelope.publisher.as_str(),
                envelope.event_id.as_str(),
                predecessor,
            )?
        {
            return Err(CoreError::InvalidEnvelope(format!(
                "predecessor {predecessor:?} would create a dependency cycle"
            )));
        }
        check_supported(&tx, envelope)?;

        let state = snapshot_state(&tx, envelope, &hash)?;
        if count(
            &tx,
            "SELECT value FROM counters WHERE name = 'retained_events'",
            [],
        )? >= limits.max_retained_events as u64
        {
            return Err(CoreError::Capacity {
                limit: format!("max_retained_events {}", limits.max_retained_events),
            });
        }
        if state == EventState::Pending {
            check_admission(&tx, envelope, &limits)?;
        }

        let acceptance_seq = bump_counter(&tx, "acceptance_seq")?;
        bump_counter(&tx, "retained_events")?;
        let scope = scope_key(envelope);
        tx.execute(
            "INSERT INTO events
                 (publisher_id, event_id, envelope_hash, envelope_json, state,
                  acceptance_seq, accepted_at_ms, expires_at_ms, recipient, policy_class,
                  mode, scope_key, revision, predecessor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                envelope.publisher.as_str(),
                envelope.event_id.as_str(),
                hash.as_str(),
                envelope.canonical_bytes(),
                state.as_str(),
                to_sql(acceptance_seq)?,
                now,
                expiry,
                envelope.recipient.to_canonical_string(),
                envelope.policy.as_str(),
                envelope.mode.as_str(),
                scope,
                revision,
                predecessor,
            ],
        )?;

        if let (Policy::Latest { stream, .. }, Some(revision)) = (&envelope.policy, revision) {
            tx.execute(
                "INSERT INTO watermarks
                     (publisher_id, recipient, kind, mode, project, task, stream_id, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (publisher_id, recipient, kind, mode, project, task, stream_id)
                 DO UPDATE SET revision = MAX(revision, excluded.revision)",
                params![
                    envelope.publisher.as_str(),
                    envelope.recipient.to_canonical_string(),
                    envelope.kind.as_str(),
                    envelope.mode.as_str(),
                    envelope.metadata.get("project").map_or("", String::as_str),
                    envelope.metadata.get("task").map_or("", String::as_str),
                    stream.as_str(),
                    revision,
                ],
            )?;
            if state == EventState::Pending {
                // Only never-handed-off older snapshots are replaced; an
                // attempt already reserved or beyond keeps its manifest.
                tx.execute(
                    "UPDATE events SET state = 'superseded'
                     WHERE scope_key = ?1 AND state = 'pending' AND delivery = 'unhanded'
                       AND revision < ?2",
                    params![scope, revision],
                )?;
            }
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
    /// lookups use the same durable row, so the disposition reflects later
    /// supersession or expiry while the acceptance fields stay original.
    pub fn lookup(
        &self,
        publisher: &PublisherId,
        event_id: &EventId,
    ) -> Result<Option<CustodyReceipt>, CoreError> {
        Ok(
            load_row(&self.connection, publisher.as_str(), event_id.as_str())?
                .map(|row| row.receipt(publisher.as_str(), event_id.as_str(), false)),
        )
    }

    /// Expires due pending events; returns how many were marked.
    ///
    /// Expiry applies only to events still known-unhanded: a pending,
    /// unreserved event past its absolute expiry becomes `expired`, an
    /// explicit disposition — never a claim that a possible native effect
    /// was recalled. Reserved, invoking, held and uncertain events are never
    /// touched here. `now_ms` above the SQLite-safe bound is refused.
    pub fn expire_due(&self, now_ms: u64) -> Result<usize, CoreError> {
        let changed = self.connection.execute(
            "UPDATE events SET state = 'expired'
             WHERE state = 'pending' AND delivery = 'unhanded'
               AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?1",
            params![to_sql(now_ms)?],
        )?;
        Ok(changed)
    }

    /// Drops payload bytes of old superseded and expired events, keeping
    /// dedup identity.
    ///
    /// Only `superseded` and `expired` events (terminal, resolved
    /// dispositions) beyond the newest `keep_newest` lose their envelope
    /// bytes; the row, frozen hash and state remain so an identical replay
    /// still returns the original receipt and dedup history is never
    /// evicted. Delivered, held and uncertain events always keep their
    /// bytes. Returns how many payloads were compacted.
    pub fn compact_payloads(&mut self, keep_newest: usize) -> Result<usize, CoreError> {
        let tx = self.begin()?;
        let compacted = tx.execute(
            "UPDATE events SET envelope_json = x''
             WHERE state IN ('superseded','expired') AND length(envelope_json) > 0
               AND delivery = 'unhanded'
               AND acceptance_seq < COALESCE((
                 SELECT MIN(s.acceptance_seq) FROM (
                   SELECT acceptance_seq FROM events e
                   WHERE e.state IN ('superseded','expired')
                   ORDER BY e.acceptance_seq DESC LIMIT ?1
                 ) s
               ), 9223372036854775807)",
            params![to_sql(keep_newest as u64)?],
        )?;
        tx.commit()?;
        Ok(compacted)
    }
}

/// Longest predecessor chain followed when checking for cycles.
const MAX_CHAIN: usize = 1_000;

/// Whether making `predecessor` the predecessor of `event_id` would close a
/// dependency cycle through already accepted events.
///
/// Follows the chain of declared predecessors from `predecessor`; reaching
/// `event_id` is a cycle, a missing or independent link ends the walk. A
/// chain longer than [`MAX_CHAIN`] is refused as a cycle-equivalent
/// anomaly, so the walk is bounded.
fn creates_cycle(
    tx: &Connection,
    publisher: &str,
    event_id: &str,
    predecessor: &str,
) -> Result<bool, CoreError> {
    let mut current = predecessor.to_string();
    for _ in 0..MAX_CHAIN {
        if current == event_id {
            return Ok(true);
        }
        let next: Option<Option<String>> = tx
            .query_row(
                "SELECT predecessor FROM events WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, current],
                |row| row.get(0),
            )
            .optional()?;
        match next {
            Some(Some(next)) => current = next,
            Some(None) | None => return Ok(false),
        }
    }
    Ok(true)
}

/// Refuses an event whose mode needs a path its recipient is known not to
/// support.
///
/// Support is known only after an adapter attested the recipient's loaded
/// capabilities ([`Storage::observe_binding`] or any dispatch); an
/// unknown recipient is accepted. This is a permanent condition, distinct
/// from the transient holds applied at dispatch time.
fn check_supported(tx: &Connection, envelope: &Envelope) -> Result<(), CoreError> {
    let recipient = envelope.recipient.to_canonical_string();
    let known: Option<(bool, bool)> = tx
        .query_row(
            "SELECT inject_capable, message_capable FROM bindings WHERE recipient = ?1",
            params![recipient],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((inject, message)) = known else {
        return Ok(());
    };
    let (needs_inject, needs_message) = match envelope.mode {
        crate::types::Mode::Inject => (true, false),
        crate::types::Mode::Message => (false, true),
        crate::types::Mode::Auto => (true, true),
    };
    if (needs_inject && !inject) || (needs_message && !message) {
        return Err(CoreError::Unsupported(format!(
            "recipient {recipient} does not support mode {} (inject: {inject}, message: {message})",
            envelope.mode.as_str()
        )));
    }
    Ok(())
}

/// Applies the admission caps for a new pending event.
///
/// Counts only events that are not yet terminal, so delivered events do not
/// consume admission capacity (they remain as dedup tombstones under the
/// retained cap). Snapshot quota applies to `latest` only; keep_all is
/// exempt.
fn check_admission(tx: &Connection, envelope: &Envelope, limits: &Limits) -> Result<(), CoreError> {
    let non_terminal = delivery::NON_TERMINAL;
    let admitted = count(
        tx,
        &format!(
            "SELECT COUNT(*) FROM events WHERE state = 'pending' AND delivery IN {non_terminal}"
        ),
        [],
    )?;
    if admitted >= limits.max_admitted_events as u64 {
        return Err(CoreError::Capacity {
            limit: format!("max_admitted_events {}", limits.max_admitted_events),
        });
    }
    let per_publisher = count(
        tx,
        &format!(
            "SELECT COUNT(*) FROM events
             WHERE state = 'pending' AND delivery IN {non_terminal} AND publisher_id = ?1"
        ),
        params![envelope.publisher.as_str()],
    )?;
    if per_publisher >= limits.max_pending_per_publisher as u64 {
        return Err(CoreError::Capacity {
            limit: format!(
                "max_pending_per_publisher {}",
                limits.max_pending_per_publisher
            ),
        });
    }
    if matches!(envelope.policy, Policy::Latest { .. }) {
        let snapshots = count(
            tx,
            "SELECT COUNT(*) FROM events
             WHERE state = 'pending' AND delivery = 'unhanded' AND policy_class = 'latest'
               AND recipient = ?1",
            params![envelope.recipient.to_canonical_string()],
        )?;
        if snapshots >= limits.max_pending_latest_per_recipient as u64 {
            return Err(CoreError::Capacity {
                limit: format!(
                    "max_pending_latest_per_recipient {} (keep_all is exempt)",
                    limits.max_pending_latest_per_recipient
                ),
            });
        }
    }
    Ok(())
}

/// Decides the admission state for a new event from its policy.
///
/// For `latest` snapshots the durable watermark is scoped by the full
/// coalescing group — publisher, exact recipient, kind, requested mode,
/// declared project/task metadata and stream — so independent publishers,
/// recipients or scopes never inherit each other's watermark. Within one
/// scope: an equal revision with different content is a conflict; a
/// revision older than the watermark is admitted as `superseded` so the
/// dedup entry exists but the stale snapshot can never revive. All other
/// policies admit as `pending`.
fn snapshot_state(
    tx: &Connection,
    envelope: &Envelope,
    hash: &EnvelopeHash,
) -> Result<EventState, CoreError> {
    let Policy::Latest { stream, revision } = &envelope.policy else {
        return Ok(EventState::Pending);
    };
    let revision = to_sql(*revision)?;
    let watermark: Option<i64> = tx
        .query_row(
            "SELECT revision FROM watermarks
             WHERE publisher_id = ?1 AND recipient = ?2 AND kind = ?3
               AND mode = ?4 AND project = ?5 AND task = ?6 AND stream_id = ?7",
            params![
                envelope.publisher.as_str(),
                envelope.recipient.to_canonical_string(),
                envelope.kind.as_str(),
                envelope.mode.as_str(),
                envelope.metadata.get("project").map_or("", String::as_str),
                envelope.metadata.get("task").map_or("", String::as_str),
                stream.as_str(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    match watermark {
        Some(stored) if stored == revision => Err(CoreError::Conflict {
            event_id: envelope.event_id.as_str().to_string(),
            stored_hash: format!("stream revision {stored}"),
            submitted_hash: hash.as_str().to_string(),
        }),
        Some(stored) if stored > revision => Ok(EventState::Superseded),
        _ => Ok(EventState::Pending),
    }
}

/// The coalescing scope key of an envelope, or empty when it never
/// coalesces.
///
/// Scope = publisher, exact recipient, kind, requested mode, declared
/// project and task, policy class and stream (`latest`) or group (`batch`).
/// The fields cannot contain control characters, so the unit-separator
/// joiner is injective. `keep_all` events return an empty key.
pub(crate) fn scope_key(envelope: &Envelope) -> String {
    let (class, discriminator) = match &envelope.policy {
        Policy::KeepAll => return String::new(),
        Policy::Latest { stream, .. } => ("latest", stream.as_str()),
        Policy::Batch { group } => ("batch", group.as_str()),
    };
    [
        envelope.publisher.as_str(),
        &envelope.recipient.to_canonical_string(),
        envelope.kind.as_str(),
        envelope.mode.as_str(),
        envelope.metadata.get("project").map_or("", String::as_str),
        envelope.metadata.get("task").map_or("", String::as_str),
        class,
        discriminator,
    ]
    .join("\u{1f}")
}

/// A stored event row as read back for dedup and status.
pub(crate) struct StoredRow {
    /// Frozen identity-content hash.
    pub hash: EnvelopeHash,
    /// Custody disposition.
    pub state: EventState,
    /// Monotonic acceptance order.
    pub acceptance_seq: u64,
    /// Acceptance wall clock in Unix epoch milliseconds.
    pub accepted_at_ms: u64,
}

impl StoredRow {
    /// Builds the receipt for this row.
    fn receipt(&self, publisher: &str, event_id: &str, replayed: bool) -> CustodyReceipt {
        CustodyReceipt {
            publisher: publisher.to_string(),
            event_id: event_id.to_string(),
            envelope_hash: self.hash.clone(),
            acceptance_seq: self.acceptance_seq,
            accepted_at_ms: self.accepted_at_ms,
            state: self.state,
            replayed,
        }
    }
}

/// Reads a stored row by key, if present.
///
/// Every stored value is strictly validated before use: an unknown state
/// text, a malformed hash or a negative counter/timestamp is an integrity
/// error, never a silently wrapped value.
pub(crate) fn load_row(
    connection: &Connection,
    publisher: &str,
    event_id: &str,
) -> Result<Option<StoredRow>, CoreError> {
    let row: Option<(String, String, i64, i64)> = connection
        .query_row(
            "SELECT envelope_hash, state, acceptance_seq, accepted_at_ms
             FROM events WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((hash, state, acceptance_seq, accepted_at_ms)) = row else {
        return Ok(None);
    };
    Ok(Some(StoredRow {
        hash: EnvelopeHash::try_from(hash).map_err(|error| corrupt(error.to_string()))?,
        state: parse_state(&state)?,
        acceptance_seq: from_sql(acceptance_seq)?,
        accepted_at_ms: from_sql(accepted_at_ms)?,
    }))
}

/// Parses the storage text form of an event state.
///
/// Strict: only the three texts this layer writes are accepted; anything
/// else (a foreign or corrupted row) is an integrity error rather than a
/// defaulted state.
fn parse_state(value: &str) -> Result<EventState, CoreError> {
    match value {
        "pending" => Ok(EventState::Pending),
        "superseded" => Ok(EventState::Superseded),
        "expired" => Ok(EventState::Expired),
        other => Err(corrupt(format!("unknown stored event state {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    //! In-module checks for helpers not needing a database.

    use super::*;

    #[test]
    fn state_text_roundtrip_is_strict() {
        assert_eq!(EventState::Pending.as_str(), "pending");
        assert_eq!(parse_state("superseded").unwrap(), EventState::Superseded);
        assert_eq!(parse_state("expired").unwrap(), EventState::Expired);
        assert!(
            parse_state("foreign").is_err(),
            "unknown stored state must be refused, never defaulted"
        );
        assert_eq!(from_sql(0).unwrap(), 0);
        assert!(from_sql(-1).is_err());
        assert!(to_sql(u64::MAX).is_err());
        assert_eq!(to_sql(MAX_SQLITE_INT).unwrap(), i64::MAX);
    }

    #[test]
    fn limits_are_validated() {
        assert!(Limits::new(7).validate().is_ok());
        assert!(Limits::new(0).validate().is_err());
        let mut limits = Limits::new(7);
        limits.max_retained_events = 3;
        assert!(limits.validate().is_err());
        limits.max_retained_events = usize::MAX;
        assert!(limits.validate().is_err());
    }
}
