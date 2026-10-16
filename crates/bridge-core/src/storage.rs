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

/// Validates/migrates a rollback-journal database under an exclusive lock
/// retained through the WAL transition. Returns whether the connection must
/// be reopened to release SQLite's persistent exclusive WAL lock. Existing
/// WAL files need no journal mutation and are validated by `init_schema`.
/// Unsupported schemas fail before any journal-mode or schema write; SQLite
/// lock failures propagate. The caller sets the busy and synchronous policy.
fn enable_wal(connection: &mut Connection) -> Result<bool, CoreError> {
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if mode == "wal" {
        return Ok(false);
    }
    connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    schema::ensure(&tx)?;
    tx.commit()?;
    // locking_mode=EXCLUSIVE retains the validated file's lock after COMMIT,
    // so no writer can replace its schema between validation and WAL setup.
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if mode != "wal" {
        return Err(corrupt(format!("database refused WAL journaling ({mode})")));
    }
    Ok(true)
}

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
/// The top quarter of the global cap (at least one slot, for every valid cap)
/// is additionally reserved for keep_all: `latest` and `batch` events are
/// refused once the cap minus that reserve is reached, so many recipients or
/// publishers together cannot exhaust it. A cap of one therefore admits no
/// `latest` or `batch` event at all; the configured cap is never exceeded.
/// `max_retained_events` bounds the dedup history itself, which is never
/// evicted: at that cap new admission is refused. The connection fields
/// bound the local service's threads and per-connection waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum number of admitted, not-yet-terminal events; the last
    /// `max(1, cap / 4)` slots admit keep_all events only (so cap 1 admits
    /// only keep_all, cap 2 one snapshot, cap 3 two).
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
    /// One immutable shared in-memory producer authority for this boot.
    pub(crate) producer_authorizer: Option<std::sync::Arc<crate::ProducerAuthorizer>>,
    /// Durable v1 identity admission capacities, never a product job TTL.
    pub(crate) universal_limits: crate::UniversalLimits,
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
    /// Schema ownership is checked under the actual mutation lock before
    /// changing journal mode; refusal preserves durable DB/WAL/journal bytes,
    /// mode and sidecar presence, except that SQLite may first roll back its
    /// own hot rollback journal to the last committed content and remove that
    /// journal before schema inspection. This recovery never authorizes Bridge
    /// migration or journal conversion for an unsupported schema. SQLite may
    /// rebuild advisory WAL-index/SHM state; these are not durable data.
    /// Close-checkpointing is disabled before every file connection's first
    /// access until its schema is accepted, preserving refused orphan WAL.
    /// Success restores normal checkpoint-on-close behavior and shared access.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, CoreError> {
        limits.validate()?;
        let path = path.as_ref();
        let mut connection = Connection::open(path)?;
        connection.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        if enable_wal(&mut connection)? {
            // SQLite cannot release an exclusive WAL lock by changing
            // locking_mode to NORMAL; reopen for ordinary shared operation.
            drop(connection);
            connection = Connection::open(path)?;
            connection.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )?;
            connection.busy_timeout(BUSY_TIMEOUT)?;
            connection.pragma_update(None, "synchronous", "FULL")?;
        }
        let storage = Storage {
            connection,
            limits,
            producer_authorizer: None,
            universal_limits: crate::UniversalLimits::default(),
        }
        .init_schema()?;
        storage.connection.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            false,
        )?;
        Ok(storage)
    }

    /// Opens an in-memory database; for tests and in-process tools.
    ///
    /// Same schema fence and limits validation as [`Storage::open`];
    /// durability obviously does not apply.
    pub fn open_in_memory(limits: Limits) -> Result<Self, CoreError> {
        limits.validate()?;
        let connection = Connection::open_in_memory()?;
        Storage {
            connection,
            limits,
            producer_authorizer: None,
            universal_limits: crate::UniversalLimits::default(),
        }
        .init_schema()
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
    ///   message path, auto at least one loaded path) is refused with
    ///   [`CoreError::Unsupported`] before acceptance; an admitted auto event
    ///   has its effective path selected and gated at dispatch, where an
    ///   unloaded effective path is a visible hold with no native effect;
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
        let limits = self.limits;
        let tx = self.begin()?;
        let outcome = publish_in(&tx, envelope, now_ms, limits, "")?;
        tx.commit()?;
        Ok(outcome)
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

/// Inserts or recovers canonical custody inside the caller's transaction.
/// The caller owns commit/ack uncertainty. Empty lifetime preserves legacy
/// keys; a validated producer lifetime isolates latest/batch and lineage keys.
/// The caller validates envelope and renderability before calling; this helper
/// owns admission/state changes and never commits the caller's transaction.
pub(crate) fn publish_in(
    tx: &Connection,
    envelope: &Envelope,
    now_ms: u64,
    limits: Limits,
    lifetime: &str,
) -> Result<PublishOutcome, CoreError> {
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

    if let Some(existing) = load_row(tx, envelope.publisher.as_str(), envelope.event_id.as_str())? {
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
            tx,
            envelope.publisher.as_str(),
            envelope.event_id.as_str(),
            predecessor,
        )?
    {
        return Err(CoreError::InvalidEnvelope(format!(
            "predecessor {predecessor:?} would create a dependency cycle"
        )));
    }
    check_supported(tx, envelope)?;
    let lineage_key = lineage_gate(tx, envelope, now_ms, lifetime)?;

    let state = snapshot_state(tx, envelope, &hash, lifetime)?;
    if count(
        tx,
        "SELECT value FROM counters WHERE name = 'retained_events'",
        [],
    )? >= limits.max_retained_events as u64
    {
        return Err(CoreError::Capacity {
            limit: format!("max_retained_events {}", limits.max_retained_events),
        });
    }
    if state == EventState::Pending {
        check_admission(tx, envelope, &limits)?;
    }

    let acceptance_seq = bump_counter(tx, "acceptance_seq")?;
    bump_counter(tx, "retained_events")?;
    let scope = scoped_scope_key(envelope, lifetime);
    tx.execute(
        "INSERT INTO events
                 (publisher_id, event_id, envelope_hash, envelope_json, state,
                  acceptance_seq, accepted_at_ms, expires_at_ms, recipient, policy_class,
                  mode, scope_key, revision, predecessor, lineage_key, delivery_scope_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
            lineage_key,
            lifetime,
        ],
    )?;

    if let (Policy::Latest { stream, .. }, Some(revision)) = (&envelope.policy, revision) {
        if lifetime.is_empty() {
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
        } else {
            tx.execute(
                    "INSERT INTO scoped_watermarks (scope_key, revision) VALUES (?1, ?2)
                     ON CONFLICT (scope_key) DO UPDATE SET revision = MAX(revision, excluded.revision)",
                    params![scope, revision],
                )?;
        }
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

/// Whether making `predecessor` the predecessor of `event_id` would close a
/// dependency cycle through already accepted events. The walk ends on a
/// missing/independent link; more than MAX_CHAIN links refuses as an anomaly.
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
/// `inject` needs the inject path and `message` the message path. `auto`
/// resolves per dispatch to whichever path the observed lifecycle selects
/// (see `dispatch::resolve_mode`), so it needs only that at least one path is
/// loaded; the effective path is gated again at dispatch, where an unloaded
/// path is a visible hold with no native effect.
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
    let supported = match envelope.mode {
        crate::types::Mode::Inject => inject,
        crate::types::Mode::Message => message,
        crate::types::Mode::Auto => inject || message,
    };
    if !supported {
        return Err(CoreError::Unsupported(format!(
            "recipient {recipient} does not support mode {} (inject: {inject}, message: {message})",
            envelope.mode.as_str()
        )));
    }
    Ok(())
}

/// Share of the global admission cap, as a divisor, reserved for keep_all.
const KEEP_ALL_RESERVE_DIVISOR: usize = 4;

/// Number of admission slots at the top of the global cap that only
/// keep_all events may take: `max_admitted_events / 4` rounded down but never
/// below one, so every valid cap (at least one) keeps a critical slot. The
/// result never exceeds the cap, so `cap - reserve` cannot underflow.
fn keep_all_reserve(limits: &Limits) -> usize {
    (limits.max_admitted_events / KEEP_ALL_RESERVE_DIVISOR).max(1)
}

/// Applies the admission caps for a new pending event.
///
/// Counts only events that are not yet terminal, so delivered events do not
/// consume admission capacity (they remain as dedup tombstones under the
/// retained cap). Snapshot quota applies to `latest` only; keep_all is
/// exempt. The top slots of the global cap (see [`keep_all_reserve`]; at
/// least one) are reserved: only keep_all may take them, so replaceable or
/// batchable traffic from any number of recipients and publishers can never
/// leave keep_all with no admission capacity. With a cap of one no
/// non-keep_all event is admitted: it gets [`CoreError::Capacity`] before
/// acceptance. Nothing already admitted is evicted to make room.
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
    let reserve = keep_all_reserve(limits);
    if !matches!(envelope.policy, Policy::KeepAll)
        && admitted >= (limits.max_admitted_events - reserve) as u64
    {
        return Err(CoreError::Capacity {
            limit: format!(
                "max_admitted_events {} (last {reserve} reserved for keep_all)",
                limits.max_admitted_events
            ),
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
    lifetime: &str,
) -> Result<EventState, CoreError> {
    let Policy::Latest { stream, revision } = &envelope.policy else {
        return Ok(EventState::Pending);
    };
    let revision = to_sql(*revision)?;
    let watermark: Option<i64> = if lifetime.is_empty() {
        tx.query_row(
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
        .optional()?
    } else {
        tx.query_row(
            "SELECT revision FROM scoped_watermarks WHERE scope_key = ?1",
            params![scoped_scope_key(envelope, lifetime)],
            |row| row.get(0),
        )
        .optional()?
    };
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

/// Enforces the one-authority producer-lineage rule for `latest` streams.
///
/// The lineage key is the coalescing scope *without* the publisher: exact
/// recipient, kind, requested mode, declared project/task and stream. The
/// unscoped legacy key stays exact; a producer-owned v1 lifetime additionally
/// includes its producer and lifetime so independent lifetimes cannot merge.
/// first authenticated publisher to publish into that lineage claims it
/// durably; every other publisher's `latest` publication is declined
/// before acceptance with [`CoreError::Fence`] naming the current owner —
/// there is no implicit multisource interleave and no implicit handover.
/// Authority passes only through an audited operator transition
/// ([`Storage::transfer_lineage`]), which never rewrites event ids,
/// watermarks, attempts or evidence: the old producer's watermark stays,
/// so its late stale revisions can never revive, and its already-accepted
/// or uncertain events keep their content and delivery state untouched.
///
/// `keep_all` and `batch` events never claim or check lineage; publisher
/// identity itself is always the Bridge-stamped grant identity, never
/// caller metadata.
fn lineage_gate(
    tx: &Connection,
    envelope: &Envelope,
    now_ms: u64,
    lifetime: &str,
) -> Result<String, CoreError> {
    let Policy::Latest { stream, .. } = &envelope.policy else {
        return Ok(String::new());
    };
    let lineage_key = lineage_key(
        &envelope.recipient.to_canonical_string(),
        envelope.kind.as_str(),
        envelope.mode.as_str(),
        envelope.metadata.get("project").map_or("", String::as_str),
        envelope.metadata.get("task").map_or("", String::as_str),
        stream.as_str(),
    );
    let lineage_key = if lifetime.is_empty() {
        lineage_key
    } else {
        [lineage_key.as_str(), envelope.publisher.as_str(), lifetime].join("\u{1f}")
    };
    let owner: Option<String> = tx
        .query_row(
            "SELECT owner FROM stream_lineages WHERE lineage_key = ?1",
            params![lineage_key],
            |row| row.get(0),
        )
        .optional()?;
    match owner {
        None => {
            tx.execute(
                "INSERT INTO stream_lineages (lineage_key, owner, set_ms, note)
                 VALUES (?1, ?2, ?3, 'claimed by first authenticated publication')",
                params![lineage_key, envelope.publisher.as_str(), to_sql(now_ms)?],
            )?;
            Ok(lineage_key)
        }
        Some(owner) if owner == envelope.publisher.as_str() => Ok(lineage_key),
        Some(owner) if owner.is_empty() => Err(CoreError::Fence(format!(
            "stream lineage {} has ambiguous historical producers; an operator must \
             resolve the authority before anyone publishes this stream",
            redact_lineage(&lineage_key)
        ))),
        Some(owner) => Err(CoreError::Fence(format!(
            "stream lineage {} is owned by {owner}; an audited operator transition is \
             required before another producer publishes this stream",
            redact_lineage(&lineage_key)
        ))),
    }
}

/// Builds the lineage key: the coalescing group without the publisher.
///
/// Unit-separator joined like [`scope_key`]; injective for the same
/// reason.
pub(crate) fn lineage_key(
    recipient: &str,
    kind: &str,
    mode: &str,
    project: &str,
    task: &str,
    stream: &str,
) -> String {
    [recipient, kind, mode, project, task, stream].join("\u{1f}")
}

/// Renders a lineage key for an error without dumping every component.
fn redact_lineage(key: &str) -> String {
    key.split('\u{1f}')
        .next_back()
        .unwrap_or("stream")
        .to_string()
}

/// Reports why an event's dispatch is blocked by current lineage
/// ownership, if it is.
///
/// `None` for events outside lineage tracking (`lineage_key` empty) or
/// whose publisher still owns its lineage. A `Some(reason)` means the
/// event must not be selected or invoked now: the publisher lost
/// authority (audited transfer) or the lineage is an ambiguous migration
/// record. Already-invoking or delivered attempts are never touched by
/// this check — possible effects are not recalled.
pub(crate) fn lineage_block(
    tx: &Connection,
    publisher: &str,
    lineage_key: &str,
) -> Result<Option<String>, CoreError> {
    if lineage_key.is_empty() {
        return Ok(None);
    }
    let owner: Option<String> = tx
        .query_row(
            "SELECT owner FROM stream_lineages WHERE lineage_key = ?1",
            params![lineage_key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match owner.as_deref() {
        None => None,
        Some(owner) if owner == publisher => None,
        Some("") => Some(format!(
            "lineage {} has ambiguous historical producers; an operator must resolve \
             authority before this event can be dispatched",
            redact_lineage(lineage_key)
        )),
        Some(owner) => Some(format!(
            "lineage {} is now owned by {owner}; the producer lost authority over this \
             stream (audited operator resolution required)",
            redact_lineage(lineage_key)
        )),
    })
}

/// Holds one unhanded latest event whose producer lost lineage authority,
/// visibly and durably, with a retained incident.
///
/// The event's bytes, id, hash and any attempt evidence stay untouched;
/// only its delivery moves to `held`, so it cannot be silently dropped or
/// silently dispatched. An operator resolves it with the existing audited
/// disposition path. Idempotent per event while an open incident exists.
pub(crate) fn hold_for_lineage(
    tx: &Connection,
    publisher: &str,
    event_id: &str,
    reason: &str,
    now_ms: u64,
) -> Result<(), CoreError> {
    tx.execute(
        "UPDATE events SET delivery = 'held'
         WHERE publisher_id = ?1 AND event_id = ?2
           AND state = 'pending' AND delivery IN ('unhanded', 'reserved')",
        params![publisher, event_id],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO incidents
             (incident_seq, publisher_id, event_id, kind, reason, state,
              created_ms, updated_ms, next_check_ms, review_deadline_ms,
              responsible, resolution)
         VALUES (
           (SELECT value FROM counters WHERE name = 'incident_seq') + 1,
           ?1, ?2, 'lineage_authority_lost', ?3, 'open', ?4, ?4, ?4, ?4 + 3600000,
           'operator', NULL)",
        params![publisher, event_id, reason, to_sql(now_ms)?],
    )?;
    tx.execute(
        "UPDATE counters SET value = value + 1 WHERE name = 'incident_seq'",
        [],
    )?;
    Ok(())
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

/// Adds a validated producer-owned lifetime to a coalescing key.
/// Empty lifetime is byte-for-byte legacy behavior; keep_all never coalesces.
pub(crate) fn scoped_scope_key(envelope: &Envelope, lifetime: &str) -> String {
    let scope = scope_key(envelope);
    if scope.is_empty() || lifetime.is_empty() {
        scope
    } else {
        [scope.as_str(), lifetime].join("\u{1f}")
    }
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
    //! Isolated helper checks, including a real SQLite schema ownership race.

    use super::*;

    /// A real writer changes ownership while the opener contends for its lock.
    /// Contention must refuse without WAL mutation; a fresh attempt must fence
    /// the newly committed version. The busy callback proves actual contention
    /// and aborts it so the writer can commit without a lock-upgrade deadlock.
    #[test]
    fn wal_setup_fences_schema_changed_by_a_contending_writer() {
        use std::sync::atomic::{AtomicBool, Ordering};
        /// Set only by this test's opener after SQLite reports lock contention.
        static WAITING: AtomicBool = AtomicBool::new(false);
        /// Signals actual contention and refuses rather than holding a read lock.
        fn busy(_attempt: i32) -> bool {
            WAITING.store(true, Ordering::SeqCst);
            false
        }
        let path = std::env::temp_dir().join(format!(
            "schema-race-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut owner = Connection::open(&path).unwrap();
        let tx = owner
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        schema::ensure(&tx).unwrap();
        tx.commit().unwrap();
        owner
            .execute_batch(
                "BEGIN IMMEDIATE; UPDATE schema_meta SET value='999' WHERE key='schema_version'",
            )
            .unwrap();
        WAITING.store(false, Ordering::SeqCst);
        let opened_path = path.clone();
        let opener = std::thread::spawn(move || {
            let mut connection = Connection::open(opened_path).unwrap();
            connection.busy_handler(Some(busy)).unwrap();
            enable_wal(&mut connection)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !WAITING.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        let observed = WAITING.load(Ordering::SeqCst);
        let result = opener.join().unwrap();
        owner.execute_batch("COMMIT").unwrap();
        let mut next = Connection::open(&path).unwrap();
        let rechecked = enable_wal(&mut next);
        drop(next);
        let mode: String = owner
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        drop(owner);
        std::fs::remove_file(&path).unwrap();
        assert!(
            observed,
            "the opener actually waited for the mutating writer"
        );
        assert!(matches!(result, Err(CoreError::Busy(_))));
        assert!(matches!(rechecked, Err(CoreError::Integrity(_))));
        assert_eq!(
            mode, "delete",
            "refusal cannot enable WAL after a stale check"
        );
        assert!(!path.with_extension("db-wal").exists());
        assert!(!path.with_extension("db-shm").exists());
    }

    /// A preflight read can become stale before the mutation transaction.
    /// Another thread commits a newer version after that read; the real lock
    /// must observe it and refuse without changing bytes, mode or sidecars.
    #[test]
    fn wal_setup_rechecks_a_stale_preflight_under_the_mutation_lock() {
        let path = std::env::temp_dir().join(format!(
            "schema-stale-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut owner = Connection::open(&path).unwrap();
        let tx = owner
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        schema::ensure(&tx).unwrap();
        tx.commit().unwrap();
        let mut stale = Connection::open(&path).unwrap();
        assert_eq!(
            schema::stored_version(&stale).unwrap(),
            Some(schema::SCHEMA_VERSION)
        );
        std::thread::spawn(move || {
            owner
                .execute(
                    "UPDATE schema_meta SET value='999' WHERE key='schema_version'",
                    [],
                )
                .unwrap();
        })
        .join()
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let result = enable_wal(&mut stale);
        let mode: String = stale
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        drop(stale);
        let after = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(CoreError::Integrity(_))));
        assert_eq!(mode, "delete");
        assert!(
            after == before,
            "a stale preflight cannot authorize any write"
        );
        assert!(!path.with_extension("db-wal").exists());
        assert!(!path.with_extension("db-shm").exists());
        assert!(!path.with_extension("db-journal").exists());
    }

    /// Stored state text parses round-trip strictly: unknown values are
    /// errors, never defaults.
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
    /// Limits are validated on construction: non-zero caps only.
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
