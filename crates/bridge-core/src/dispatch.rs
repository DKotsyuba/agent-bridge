//! Fenced dispatch attempts over an ordered, frozen manifest.
//!
//! One attempt owns an ordered list of pending events of one recipient. It
//! freezes — before anything can leave the process — the exact recipient,
//! the actual actor, the endpoint epoch, the granted capabilities, the
//! effective path, the rendered manifest bytes with their hash, and the
//! hand-off deadline. The attempt is first `reserved` under a lease, then
//! persisted as `invoking` *before* any possible hand-off (a socket write
//! or a hook payload reply), and only afterwards offered to a carrier or
//! returned to a hook. Outcomes are distinct evidence tiers — never one
//! boolean "delivered".
//!
//! Uncertainty is owned, never retried blindly: an expired `invoking`
//! deadline or a carrier reporting uncertainty becomes `outcome_unknown`
//! plus a retained incident, and the event is never dispatched again until
//! an audited operator authorization records the possible duplicate risk. A
//! reservation that could not invoke is reclaimed without review, and a
//! positively known-unsent attempt is closed before the bounded automatic
//! retry. Nothing here invokes a real native host: the [`DispatchCarrier`]
//! trait is the contract-faithful substitute for the `bridge-native-host`
//! interface.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::framing::{MAX_FRAMED_BYTES, frame_manifest};
use crate::recovery::{bound_text, open_incident_in, record_evidence_row, resolve_hold_incidents};
use crate::storage::{Storage, bump_counter, corrupt, delivery, from_sql, to_sql};
use crate::types::{CoreError, Envelope, Mode, NativeAddress, sha256_hex};

/// A keep_all event is treated as this much older than it is when ordering
/// candidates, so a snapshot that has waited longer than the boost is
/// served before newer keep_all traffic (non-starvation) while keep_all
/// still wins among events of similar age.
const KEEP_ALL_BOOST_MS: i64 = 30_000;

/// Largest number of events frozen into one manifest.
const MAX_MANIFEST_MEMBERS: usize = 32;

/// Automatic attempts allowed for one event before it is refused as
/// exhausted. Manual authorization resets the budget.
const MAX_AUTOMATIC_ATTEMPTS: u32 = 5;

/// Delay before the first automatic retry of a known-unsent attempt;
/// doubled for every further attempt up to [`RETRY_CAP_MS`].
const RETRY_BASE_MS: u64 = 1_000;

/// Longest automatic retry delay.
const RETRY_CAP_MS: u64 = 300_000;

/// Longest accepted recheck horizon for a held or unreceipted hand-off.
const MAX_RECHECK_MS: u64 = 24 * 3_600_000;

/// Longest accepted lease or hand-off window.
const MAX_WINDOW_MS: u64 = 24 * 3_600_000;

/// Effective delivery path chosen for one attempt.
///
/// `Auto` is resolved into one of these before any hand-off; the requested
/// mode stays immutable on the event and both are recorded on the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveMode {
    /// Native hook at a natural context point; never wakes the recipient.
    Inject,
    /// Native queue/message carrier.
    Message,
}

impl EffectiveMode {
    /// Storage/wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            EffectiveMode::Inject => "inject",
            EffectiveMode::Message => "message",
        }
    }

    /// Parses the storage text form strictly (no default).
    pub(crate) fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "inject" => Ok(EffectiveMode::Inject),
            "message" => Ok(EffectiveMode::Message),
            other => Err(corrupt(format!("unknown effective mode {other:?}"))),
        }
    }
}

/// Durable state of one dispatch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    /// Reserved under a lease; not yet handed to any carrier.
    Reserved,
    /// Persisted before a possible hand-off; side effects may exist.
    Invoking,
    /// Native queue/inbox accepted the hand-off.
    NativeAccepted,
    /// Native side holds the event non-terminally; recheck by deadline.
    NativeHeld,
    /// The write completed without a receipt (ordinary for an idle
    /// recipient); positive closure is awaited before alerting.
    WrittenNoReceipt,
    /// Hook payload handed out; model context not yet proven.
    HookSubmitted,
    /// Positively known never-sent; ordinary bounded retry may follow.
    KnownUnsent,
    /// Possible hand-off with unknown effect; never automatically retried.
    OutcomeUnknown,
    /// Carrier refused permanently before acceptance.
    PermanentRefusal,
    /// Reclaimed reservation that never invoked.
    Closed,
}

impl AttemptState {
    /// Storage text form.
    pub const fn as_str(self) -> &'static str {
        match self {
            AttemptState::Reserved => "reserved",
            AttemptState::Invoking => "invoking",
            AttemptState::NativeAccepted => "native_accepted",
            AttemptState::NativeHeld => "native_held",
            AttemptState::WrittenNoReceipt => "written_no_receipt",
            AttemptState::HookSubmitted => "hook_submitted",
            AttemptState::KnownUnsent => "known_unsent",
            AttemptState::OutcomeUnknown => "outcome_unknown",
            AttemptState::PermanentRefusal => "permanent_refusal",
            AttemptState::Closed => "closed",
        }
    }

    /// Parses the storage text form strictly; unknown texts are integrity
    /// errors, never defaults.
    pub(crate) fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "reserved" => Ok(AttemptState::Reserved),
            "invoking" => Ok(AttemptState::Invoking),
            "native_accepted" => Ok(AttemptState::NativeAccepted),
            "native_held" => Ok(AttemptState::NativeHeld),
            "written_no_receipt" => Ok(AttemptState::WrittenNoReceipt),
            "hook_submitted" => Ok(AttemptState::HookSubmitted),
            "known_unsent" => Ok(AttemptState::KnownUnsent),
            "outcome_unknown" => Ok(AttemptState::OutcomeUnknown),
            "permanent_refusal" => Ok(AttemptState::PermanentRefusal),
            "closed" => Ok(AttemptState::Closed),
            other => Err(corrupt(format!("unknown attempt state {other:?}"))),
        }
    }

    /// Whether a hand-off may exist while the attempt is in this state.
    pub const fn possibly_handed_off(self) -> bool {
        !matches!(
            self,
            AttemptState::Reserved
                | AttemptState::KnownUnsent
                | AttemptState::PermanentRefusal
                | AttemptState::Closed
        )
    }
}

/// The recipient lifecycle observation used to resolve `auto` and to gate
/// every invocation.
///
/// Only [`Lifecycle::Active`] and [`Lifecycle::Inactive`] are positive
/// observations. Disconnected, not-loaded and unobservable recipients are
/// [`Lifecycle::Unknown`]; a pending approval or input prompt is
/// [`Lifecycle::AwaitingInput`]. Neither of the last two is ever inactive,
/// and neither may trigger a wake, a message or a permission answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Recipient is working; auto selects inject.
    Active,
    /// Recipient is idle; auto selects message.
    Inactive,
    /// Recipient waits for an approval or input; hold, never answer or wake.
    AwaitingInput,
    /// Disconnected, not loaded or unobservable: hold, never wake.
    Unknown,
}

/// Native paths the adapter has loaded and may use for this recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// A qualified root hook can drain inject events.
    pub inject: bool,
    /// A qualified native queue operation can accept messages.
    pub message: bool,
}

impl Capabilities {
    /// Frozen text form recorded on the attempt (for example
    /// `inject,message`; `none` when neither is granted).
    pub fn as_text(&self) -> String {
        match (self.inject, self.message) {
            (true, true) => "inject,message".to_string(),
            (true, false) => "inject".to_string(),
            (false, true) => "message".to_string(),
            (false, false) => "none".to_string(),
        }
    }

    /// Whether the given path is granted.
    pub const fn allows(&self, mode: EffectiveMode) -> bool {
        match mode {
            EffectiveMode::Inject => self.inject,
            EffectiveMode::Message => self.message,
        }
    }
}

/// An adapter's attestation of one recipient endpoint at one instant.
///
/// Only the protected native adapter binding may create one, through
/// [`Attestation::verified`], after it validated the exact acting actor, the
/// logical address, the endpoint epoch and the current lifecycle. The type
/// has no public fields and no `Deserialize`, so neither a request body nor
/// a configuration file can mint it; a label, a PID or an environment value
/// is never native proof. Core then fails closed on anything inconsistent —
/// an actor that is not the addressed actor, a mismatched address, a stale
/// epoch or a missing capability. Core cannot itself prove that the adapter's
/// evidence is genuine: that proof lives in the adapter, and its reference is
/// frozen on every attempt for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Exact logical address of the attested session.
    pub(crate) address: NativeAddress,
    /// Native identifier of the actor that is actually acting.
    pub(crate) actor_id: String,
    /// Monotonically fenced endpoint epoch of the live binding.
    pub(crate) endpoint_epoch: u64,
    /// Current lifecycle observation of the addressed session.
    pub(crate) lifecycle: Lifecycle,
    /// Loaded, qualified capabilities for this binding.
    pub(crate) capabilities: Capabilities,
    /// Reference to the protected binding record that validated the above.
    pub(crate) proof_ref: String,
}

impl Attestation {
    /// Builds the attestation of one verified endpoint observation.
    ///
    /// To be called only by the protected adapter binding, after it
    /// validated every argument against native evidence. `actor_id` is the
    /// exact native identifier of the acting actor (a Codex thread id, a
    /// Claude session id for the root actor, a Claude agent id for a child);
    /// it must equal the address's own native session id for the attempt to
    /// be allowed, so a child actor sharing a root session can never drain
    /// root-context data, while a child with its own attested address
    /// receives its own. `endpoint_epoch` is at least 1. `proof_ref` names
    /// the protected binding record (non-empty, at most 256 bytes, no
    /// control characters) and is frozen on the attempt.
    pub fn verified(
        address: NativeAddress,
        actor_id: impl Into<String>,
        endpoint_epoch: u64,
        lifecycle: Lifecycle,
        capabilities: Capabilities,
        proof_ref: impl Into<String>,
    ) -> Result<Self, CoreError> {
        address.validate()?;
        let actor_id = actor_id.into();
        let proof_ref = proof_ref.into();
        for (field, value) in [("actor_id", &actor_id), ("proof_ref", &proof_ref)] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(CoreError::InvalidEnvelope(format!(
                    "{field} must be 1 to 256 bytes without control characters"
                )));
            }
        }
        if endpoint_epoch == 0 || endpoint_epoch > crate::types::MAX_SQLITE_INT {
            return Err(CoreError::InvalidEnvelope(
                "endpoint_epoch must be between 1 and the supported bound".into(),
            ));
        }
        Ok(Attestation {
            address,
            actor_id,
            endpoint_epoch,
            lifecycle,
            capabilities,
            proof_ref,
        })
    }

    /// The attested logical address.
    pub fn address(&self) -> &NativeAddress {
        &self.address
    }

    /// The native identifier of the acting actor.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// The attested endpoint epoch.
    pub fn endpoint_epoch(&self) -> u64 {
        self.endpoint_epoch
    }

    /// The attested lifecycle observation.
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }
}

/// The capability that owns one attempt's transitions.
///
/// Handed only to the code that reserved the attempt; every transition
/// verifies every field against the stored row, so a stale or forged fence
/// refuses without a new invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptFence {
    /// Monotonic attempt number within the store.
    pub attempt_seq: u64,
    /// Canonical address text of the recipient the attempt is bound to.
    pub recipient: String,
    /// Endpoint epoch the attempt was reserved under.
    pub endpoint_epoch: u64,
    /// Hash of the frozen manifest bytes.
    pub manifest_hash: String,
}

/// One event frozen into an attempt's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRef {
    /// Publisher of the member event.
    pub publisher: String,
    /// Event id of the member event.
    pub event_id: String,
    /// Frozen envelope hash of the member event at reservation time.
    pub envelope_hash: String,
}

/// One durable attempt as read back from storage.
///
/// Everything a carrier or hook may emit is in this record; core never lets
/// a caller substitute different bytes, a different recipient or a different
/// path after the reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    /// The fence owning this attempt.
    pub fence: AttemptFence,
    /// Current durable state.
    pub state: AttemptState,
    /// Requested mode of the head event (`auto` stays `auto`).
    pub requested_mode: Mode,
    /// Effective path chosen for this attempt.
    pub effective_mode: EffectiveMode,
    /// Frozen native identifier of the actor that acted.
    pub actor: String,
    /// Frozen reference to the protected binding proof of the attestation.
    pub proof_ref: String,
    /// Frozen text of the granted capabilities.
    pub granted: String,
    /// Ordered member events frozen into the manifest.
    pub members: Vec<MemberRef>,
    /// The exact source-wrapped, escaped bytes handed to the carrier.
    pub manifest: String,
    /// Absolute deadline after which a silent `invoking` attempt becomes
    /// an unknown outcome (Unix epoch milliseconds).
    pub deadline_ms: u64,
    /// Reservation lease deadline while `reserved`.
    pub lease_expires_ms: Option<u64>,
    /// Recheck deadline while held or written without receipt.
    pub recheck_ms: Option<u64>,
    /// Whether an earlier possible hand-off of a member was manually
    /// authorized to be repeated (possible duplicate).
    pub duplicate_risk: bool,
    /// Creation time in Unix epoch milliseconds.
    pub created_ms: u64,
    /// Last update time in Unix epoch milliseconds.
    pub updated_ms: u64,
    /// Free-form evidence/audit note (never a secret).
    pub note: Option<String>,
}

/// A carrier outcome with its evidence tier.
///
/// Mirrors the `bridge-native-host` outcome taxonomy: acceptance is
/// positive evidence only, holds are non-terminal with a recheck deadline,
/// refusal is permanent before acceptance, known-unsent needs positive proof
/// that nothing was written, and unknown means a possible hand-off whose
/// effect cannot be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Native queue/inbox accepted; `evidence` names the positive fact.
    NativeAccepted {
        /// Positive evidence description (tier, not prose proof).
        evidence: String,
    },
    /// Held non-terminally; recheck no later than `recheck_ms`.
    NativeHeld {
        /// Recheck deadline in Unix epoch milliseconds.
        recheck_ms: u64,
    },
    /// The write completed but no receipt exists yet; positive closure is
    /// attempted before `receipt_deadline_ms`, then it becomes an incident.
    WrittenNoReceipt {
        /// What was written and how it can be confirmed.
        evidence: String,
        /// Deadline in Unix epoch milliseconds for positive closure.
        receipt_deadline_ms: u64,
    },
    /// Hook payload handed out after a full flush; submission evidence.
    HookSubmitted {
        /// Submission evidence description.
        evidence: String,
    },
    /// Positively known never-sent (the carrier proved no write happened).
    KnownUnsent {
        /// How non-sending was established; must be non-empty.
        evidence: String,
    },
    /// Possible hand-off, unknown effect; retained for reconciliation.
    OutcomeUnknown {
        /// Why the outcome could not be established.
        reason: String,
    },
    /// Permanent refusal before acceptance.
    PermanentRefusal {
        /// Refusal reason.
        reason: String,
    },
}

/// Selects timing windows of one dispatch drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchTiming {
    /// How long a reservation may wait to be invoked before it is reclaimed.
    pub lease_ms: u64,
    /// How long after invocation a silent attempt waits before it becomes an
    /// unknown outcome (the hook or carrier hand-off deadline).
    pub handoff_ms: u64,
}

impl Default for DispatchTiming {
    /// Thirty seconds to invoke, sixty seconds to hand off.
    fn default() -> Self {
        DispatchTiming {
            lease_ms: 30_000,
            handoff_ms: 60_000,
        }
    }
}

impl DispatchTiming {
    /// Refuses zero or day-exceeding windows.
    fn validate(&self) -> Result<(), CoreError> {
        for (name, value) in [("lease_ms", self.lease_ms), ("handoff_ms", self.handoff_ms)] {
            if value == 0 || value > MAX_WINDOW_MS {
                return Err(CoreError::InvalidEnvelope(format!(
                    "dispatch timing {name} must be between 1 and {MAX_WINDOW_MS}"
                )));
            }
        }
        Ok(())
    }
}

/// What a reservation attempt found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// An attempt was reserved (or, for a hook drain, already invoking).
    Attempt(Box<AttemptRecord>),
    /// No eligible pending work for this recipient and path.
    Idle,
    /// Eligible work exists but is held, visibly, for this reason; nothing
    /// was reserved and nothing may be woken.
    Held(String),
}

/// What a fenced invocation request resulted in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invoked {
    /// `invoking` is durably persisted; the carrier may now hand off.
    Invoking(Box<AttemptRecord>),
    /// Conditions changed between reservation and invocation; the
    /// reservation was released untouched and nothing was invoked.
    Released(String),
}

/// Contract-faithful substitute for the `bridge-native-host` interface.
///
/// The real adapter module provides attested addresses, loaded capabilities,
/// endpoint epochs, qualified message operations and immutable evidence;
/// this trait carries exactly the observations and outcomes core dispatch
/// needs, so tests drive synthetic carriers and real adapters implement the
/// same contract. Inject delivery does not use a carrier: a qualified hook
/// calls [`Storage::drain_inject`] itself. Implementations must never touch
/// a working session on behalf of a test.
pub trait DispatchCarrier {
    /// Attests the recipient endpoint right now.
    ///
    /// Called before a reservation and once more immediately before
    /// invocation (a cheap recheck). An error means the endpoint cannot be
    /// attested; core treats it as a hold, never as inactive.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String>;

    /// Performs the one hand-off of the frozen attempt.
    ///
    /// Called at most once per attempt, after `invoking` is durable. The
    /// carrier must send exactly [`AttemptRecord::manifest`] to the
    /// attested endpoint; any return (including a panic, which the driver
    /// converts to an unknown outcome) is reconciled as evidence and never
    /// silently retried.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome;
}

/// Result of one [`dispatch_message`] drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchReport {
    /// Nothing eligible for the message path.
    Idle,
    /// Eligible work is held for the given visible reason.
    Held(String),
    /// A hand-off was attempted and recorded.
    Sent {
        /// The attempt's durable state after the outcome was recorded.
        state: AttemptState,
        /// Number of events frozen into the manifest.
        events: usize,
    },
}

/// One selected pending event, for diagnostics and operator listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// Publisher of the event.
    pub publisher: String,
    /// Event id.
    pub event_id: String,
    /// Policy class name (keep_all / latest / batch).
    pub policy_class: String,
}

/// Resolves the effective path for one event from its requested mode and
/// the recipient's observed lifecycle.
///
/// `inject` and `message` stay themselves; `auto` selects inject while
/// active and message while inactive. Disconnected, awaiting-input and
/// unobservable recipients never resolve: the caller must hold, never wake.
pub fn resolve_mode(requested: Mode, lifecycle: Lifecycle) -> Option<EffectiveMode> {
    match (requested, lifecycle) {
        (Mode::Inject, _) => Some(EffectiveMode::Inject),
        (Mode::Message, _) => Some(EffectiveMode::Message),
        (Mode::Auto, Lifecycle::Active) => Some(EffectiveMode::Inject),
        (Mode::Auto, Lifecycle::Inactive) => Some(EffectiveMode::Message),
        (Mode::Auto, Lifecycle::AwaitingInput | Lifecycle::Unknown) => None,
    }
}

/// Locks the shared store, recovering from a poisoned mutex.
///
/// Every mutation is one SQLite transaction, so a panic in another thread
/// can leave no half-applied state behind; continuing is safe.
pub fn lock_storage(storage: &Mutex<Storage>) -> MutexGuard<'_, Storage> {
    storage
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The SQL predicate selecting events a path may take right now.
///
/// Parameters: `?1` recipient text, `?2` current time. An event is eligible
/// when it is pending and unhanded, past its retry delay, not expired, and
/// either independent or released by its predecessor (a superseded
/// predecessor, one with positive delivery evidence, an audited
/// disposition, or an operator waiver — never time alone).
const ELIGIBLE: &str = "e.state = 'pending' AND e.delivery = 'unhanded' AND e.recipient = ?1
    AND e.not_before_ms <= ?2 AND (e.expires_at_ms IS NULL OR e.expires_at_ms > ?2)
    AND (e.predecessor IS NULL OR e.predecessor_waived = 1 OR EXISTS (
        SELECT 1 FROM events p
        WHERE p.publisher_id = e.publisher_id AND p.event_id = e.predecessor
          AND (p.state = 'superseded'
               OR p.delivery IN ('accepted', 'hook_submitted', 'disposed'))))
    AND NOT EXISTS (SELECT 1 FROM delivery_scopes s
        WHERE s.producer = e.publisher_id AND s.scope_key = e.delivery_scope_key
          AND s.closed_ms IS NOT NULL AND s.action = 'retire_unhanded')";

/// The requested modes a path may take for the observed lifecycle.
///
/// Inject takes inject and auto events. Message takes message events, and
/// auto events only while the recipient is positively inactive (an active
/// recipient's auto events wait for the natural hook).
const fn path_modes(mode: EffectiveMode, lifecycle: Lifecycle) -> &'static str {
    match (mode, lifecycle) {
        (EffectiveMode::Inject, _) => "('inject','auto')",
        (EffectiveMode::Message, Lifecycle::Inactive) => "('message','auto')",
        (EffectiveMode::Message, _) => "('message')",
    }
}

/// All requested modes a path could ever take, for hold visibility.
const fn widest_modes(mode: EffectiveMode) -> &'static str {
    match mode {
        EffectiveMode::Inject => "('inject','auto')",
        EffectiveMode::Message => "('message','auto')",
    }
}

/// Retry delay after the given number of failed automatic attempts.
fn retry_delay_ms(attempts_made: u32) -> u64 {
    RETRY_BASE_MS
        .saturating_mul(1u64 << attempts_made.saturating_sub(1).min(20))
        .min(RETRY_CAP_MS)
}

/// Reads the stored endpoint epoch fence for a recipient, if any.
fn stored_epoch(connection: &Connection, recipient: &str) -> Result<Option<u64>, CoreError> {
    let value: Option<i64> = connection
        .query_row(
            "SELECT endpoint_epoch FROM bindings WHERE recipient = ?1",
            params![recipient],
            |row| row.get(0),
        )
        .optional()?;
    value.map(from_sql).transpose()
}

/// Records an attested epoch and the loaded capabilities, refusing a stale
/// epoch.
///
/// An equal epoch is the same endpoint; a greater epoch is a legitimate
/// renewal of the same logical session and fences every older attempt; a
/// smaller epoch is a stale endpoint and is refused before any
/// reservation. The capabilities are remembered so that publication can
/// refuse a mode this recipient is known not to support.
fn fence_binding(
    tx: &Transaction<'_>,
    attestation: &Attestation,
    now_ms: u64,
) -> Result<(), CoreError> {
    let recipient = attestation.address.to_canonical_string();
    let epoch = attestation.endpoint_epoch;
    if let Some(stored) = stored_epoch(tx, &recipient)?
        && epoch < stored
    {
        return Err(CoreError::Fence(format!(
            "stale endpoint epoch {epoch} for {recipient}; current epoch is {stored}"
        )));
    }
    tx.execute(
        "INSERT INTO bindings
             (recipient, endpoint_epoch, inject_capable, message_capable, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (recipient) DO UPDATE
           SET endpoint_epoch = excluded.endpoint_epoch,
               inject_capable = excluded.inject_capable,
               message_capable = excluded.message_capable,
               updated_ms = excluded.updated_ms",
        params![
            recipient,
            to_sql(epoch)?,
            attestation.capabilities.inject,
            attestation.capabilities.message,
            to_sql(now_ms)?
        ],
    )?;
    Ok(())
}

/// Evaluates the attestation, pause and capability gates for a path.
///
/// Returns the visible hold reason when invocation must not happen. The
/// durable no-wake policy blocks the message path (which includes `auto`
/// resolved to message); it does not block a hook drain, which never wakes
/// the recipient. The acting actor must be the addressed actor (its native
/// id equals the address's session id): another actor sharing the session
/// never consumes the addressee's data, and that is a refusal, not a hold.
fn gate(
    tx: &Connection,
    attestation: &Attestation,
    mode: EffectiveMode,
) -> Result<Option<String>, CoreError> {
    if attestation.actor_id != attestation.address.native_session_id {
        return Err(CoreError::Fence(format!(
            "actor {} is not the addressed actor of {}; root-context data is never \
             consumed by another actor",
            attestation.actor_id,
            attestation.address.to_canonical_string()
        )));
    }
    if !attestation.capabilities.allows(mode) {
        return Ok(Some(format!(
            "capability {} is not loaded for this recipient",
            mode.as_str()
        )));
    }
    match (mode, attestation.lifecycle) {
        (EffectiveMode::Inject, Lifecycle::Active) => {}
        (EffectiveMode::Inject, other) => {
            return Ok(Some(format!(
                "inject needs an active recipient; observed {other:?}"
            )));
        }
        (EffectiveMode::Message, Lifecycle::Active | Lifecycle::Inactive) => {}
        (EffectiveMode::Message, Lifecycle::AwaitingInput) => {
            return Ok(Some(
                "recipient is awaiting approval or input; no message is sent".to_string(),
            ));
        }
        (EffectiveMode::Message, Lifecycle::Unknown) => {
            return Ok(Some(
                "recipient lifecycle is unknown, disconnected or not loaded; no wake".to_string(),
            ));
        }
    }
    if mode == EffectiveMode::Message {
        let recipient = attestation.address.to_canonical_string();
        let paused: Option<(Option<String>, i64)> = tx
            .query_row(
                "SELECT reason, no_wake FROM recipient_policies WHERE recipient = ?1",
                params![recipient],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((reason, 1)) = paused {
            return Ok(Some(format!(
                "no-wake policy active: {}",
                reason.unwrap_or_else(|| "paused".to_string())
            )));
        }
    }
    Ok(None)
}

/// Records or clears the visible hold of a recipient.
///
/// A hold exists only while eligible work is waiting; it keeps its original
/// start time so age is measured from the first held observation.
fn set_hold(
    tx: &Connection,
    recipient: &str,
    reason: Option<&str>,
    now_ms: u64,
) -> Result<(), CoreError> {
    match reason {
        Some(reason) => {
            tx.execute(
                "INSERT INTO recipient_holds (recipient, reason, since_ms, updated_ms)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT (recipient) DO UPDATE
                   SET reason = excluded.reason, updated_ms = excluded.updated_ms",
                params![recipient, reason, to_sql(now_ms)?],
            )?;
        }
        None => {
            tx.execute(
                "DELETE FROM recipient_holds WHERE recipient = ?1",
                params![recipient],
            )?;
            resolve_hold_incidents(tx, recipient, now_ms)?;
        }
    }
    Ok(())
}

/// Loads and integrity-checks a stored envelope.
///
/// The canonical bytes must parse, validate, hash to the stored hash and
/// name the expected key; anything else is an integrity error and the event
/// is never dispatched from those bytes.
fn load_envelope(
    connection: &Connection,
    publisher: &str,
    event_id: &str,
) -> Result<Envelope, CoreError> {
    let (bytes, hash): (Vec<u8>, String) = connection
        .query_row(
            "SELECT envelope_json, envelope_hash FROM events
             WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                CoreError::Fence(format!("no such event {publisher}/{event_id}"))
            }
            other => CoreError::from(other),
        })?;
    if bytes.is_empty() {
        return Err(corrupt(format!(
            "payload of {publisher}/{event_id} was compacted and cannot be dispatched"
        )));
    }
    let envelope = Envelope::from_canonical_bytes(&bytes)
        .map_err(|error| corrupt(format!("stored {publisher}/{event_id} is invalid: {error}")))?;
    if envelope.envelope_hash().as_str() != hash
        || envelope.publisher.as_str() != publisher
        || envelope.event_id.as_str() != event_id
    {
        return Err(corrupt(format!(
            "stored {publisher}/{event_id} no longer matches its frozen hash or key"
        )));
    }
    Ok(envelope)
}

/// Moves an event whose stored form cannot be dispatched out of rotation.
///
/// The event is marked `refused` with a retained incident so the operator
/// sees it, dependents stay blocked on it, and the rest of the traffic
/// proceeds.
fn quarantine(
    tx: &Transaction<'_>,
    publisher: &str,
    event_id: &str,
    reason: &str,
    now_ms: u64,
) -> Result<(), CoreError> {
    tx.execute(
        "UPDATE events SET delivery = ?1, attempt_seq = NULL
         WHERE publisher_id = ?2 AND event_id = ?3 AND delivery = 'unhanded'",
        params![delivery::REFUSED, publisher, event_id],
    )?;
    open_incident_in(
        tx,
        publisher,
        event_id,
        None,
        "storage_integrity",
        reason,
        now_ms,
    )?;
    Ok(())
}

/// Reads the registered source tag for a publisher.
fn source_tag(connection: &Connection, publisher: &str) -> Result<Option<String>, CoreError> {
    Ok(connection
        .query_row(
            "SELECT tag FROM source_tags WHERE publisher_id = ?1",
            params![publisher],
            |row| row.get(0),
        )
        .optional()?)
}

/// Loads a full attempt record, or `None` when the attempt does not exist.
pub(crate) fn load_attempt(
    connection: &Connection,
    attempt_seq: u64,
) -> Result<Option<AttemptRecord>, CoreError> {
    /// One `attempts` row in `SELECT` order: state, requested mode, effective
    /// mode, recipient, actor, endpoint epoch, granted capabilities, manifest,
    /// manifest hash, lease expiry, deadline, recheck, duplicate-risk flag,
    /// created, updated, note and proof reference. Text columns are parsed
    /// into typed values afterwards; a malformed one is a corrupt-store error.
    type Row = (
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        Option<i64>,
        i64,
        Option<i64>,
        i64,
        i64,
        i64,
        Option<String>,
        String,
    );
    let row: Option<Row> = connection
        .query_row(
            "SELECT state, requested_mode, effective_mode, recipient, actor, endpoint_epoch,
                    granted, manifest, manifest_hash, lease_expires_ms, deadline_ms,
                    recheck_ms, duplicate_risk, created_ms, updated_ms, note, proof_ref
             FROM attempts WHERE attempt_seq = ?1",
            params![to_sql(attempt_seq)?],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()?;
    let Some((
        state,
        requested,
        effective,
        recipient,
        actor,
        epoch,
        granted,
        manifest,
        manifest_hash,
        lease,
        deadline,
        recheck,
        risk,
        created,
        updated,
        note,
        proof_ref,
    )) = row
    else {
        return Ok(None);
    };
    let mut members_statement = connection.prepare(
        "SELECT publisher_id, event_id, envelope_hash FROM attempt_members
         WHERE attempt_seq = ?1 ORDER BY ordinal",
    )?;
    let members: Vec<MemberRef> = members_statement
        .query_map(params![to_sql(attempt_seq)?], |row| {
            Ok(MemberRef {
                publisher: row.get(0)?,
                event_id: row.get(1)?,
                envelope_hash: row.get(2)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(Some(AttemptRecord {
        fence: AttemptFence {
            attempt_seq,
            recipient,
            endpoint_epoch: from_sql(epoch)?,
            manifest_hash,
        },
        state: AttemptState::parse(&state)?,
        requested_mode: Mode::parse(&requested)
            .map_err(|error| corrupt(format!("stored requested mode: {error}")))?,
        effective_mode: EffectiveMode::parse(&effective)?,
        actor,
        proof_ref,
        granted,
        members,
        manifest,
        deadline_ms: from_sql(deadline)?,
        lease_expires_ms: lease.map(from_sql).transpose()?,
        recheck_ms: recheck.map(from_sql).transpose()?,
        duplicate_risk: risk != 0,
        created_ms: from_sql(created)?,
        updated_ms: from_sql(updated)?,
        note,
    }))
}

/// Loads the attempt named by a fence and verifies every fence field.
fn verified_attempt(
    connection: &Connection,
    fence: &AttemptFence,
) -> Result<AttemptRecord, CoreError> {
    let record = load_attempt(connection, fence.attempt_seq)?
        .ok_or_else(|| CoreError::Fence(format!("no such attempt {}", fence.attempt_seq)))?;
    if record.fence != *fence {
        return Err(CoreError::Fence(format!(
            "fence mismatch on attempt {}: recipient, epoch or manifest differ from the stored attempt",
            fence.attempt_seq
        )));
    }
    Ok(record)
}

/// Sets the delivery state of every member still owned by an attempt.
fn set_member_delivery(
    tx: &Connection,
    attempt_seq: u64,
    new_delivery: &str,
    keep_owner: bool,
) -> Result<(), CoreError> {
    tx.execute(
        "UPDATE events SET delivery = ?1,
             attempt_seq = CASE WHEN ?2 THEN attempt_seq ELSE NULL END
         WHERE attempt_seq = ?3 AND (publisher_id, event_id) IN
               (SELECT publisher_id, event_id FROM attempt_members WHERE attempt_seq = ?3)",
        params![new_delivery, keep_owner, to_sql(attempt_seq)?],
    )?;
    Ok(())
}

/// Closes an uninvoked reservation and returns its members to rotation.
///
/// The reservation never counted as an automatic attempt, so the retry
/// budget is restored.
pub(crate) fn release_reservation(
    tx: &Connection,
    attempt_seq: u64,
    note: &str,
    now_ms: u64,
) -> Result<(), CoreError> {
    tx.execute(
        "UPDATE events SET delivery = 'unhanded', attempt_seq = NULL,
             attempts_made = MAX(attempts_made - 1, 0)
         WHERE attempt_seq = ?1 AND delivery = 'reserved'",
        params![to_sql(attempt_seq)?],
    )?;
    tx.execute(
        "UPDATE attempts SET state = 'closed', note = ?1, updated_ms = ?2, lease_expires_ms = NULL
         WHERE attempt_seq = ?3 AND state = 'reserved'",
        params![note, to_sql(now_ms)?, to_sql(attempt_seq)?],
    )?;
    Ok(())
}

/// Reserves the next attempt inside the caller's transaction.
///
/// Shared by [`Storage::reserve_next`] and [`Storage::drain_inject`]; see
/// the former for the full rules.
fn reserve_in(
    tx: &Transaction<'_>,
    attestation: &Attestation,
    mode: EffectiveMode,
    now_ms: u64,
    timing: &DispatchTiming,
) -> Result<Selection, CoreError> {
    attestation.address.validate()?;
    let recipient = attestation.address.to_canonical_string();
    let now = to_sql(now_ms)?;
    fence_binding(tx, attestation, now_ms)?;
    let hold = gate(tx, attestation, mode)?;
    if let Some(reason) = hold {
        let waiting: bool = tx.query_row(
            &format!(
                "SELECT EXISTS (SELECT 1 FROM events e WHERE {ELIGIBLE} AND e.mode IN {})",
                widest_modes(mode)
            ),
            params![recipient, now],
            |row| row.get(0),
        )?;
        if waiting {
            set_hold(tx, &recipient, Some(&reason), now_ms)?;
            return Ok(Selection::Held(reason));
        }
        set_hold(tx, &recipient, None, now_ms)?;
        return Ok(Selection::Idle);
    }

    let modes = path_modes(mode, attestation.lifecycle);
    // Head selection loop: a `latest` head whose producer lost lineage
    // authority is held visibly (delivery + retained incident) and skipped,
    // so stale old-producer snapshots can never be selected after an
    // audited transfer or an ambiguous migration. The loop is bounded by
    // the eligible set size.
    let (head_publisher, head_event, policy_class, scope) = loop {
        let head: Option<(String, String, String, String, String)> = tx
            .query_row(
                &format!(
                    "SELECT e.publisher_id, e.event_id, e.policy_class, e.scope_key, e.lineage_key
                     FROM events e
                     WHERE {ELIGIBLE} AND e.mode IN {modes}
                     ORDER BY e.accepted_at_ms
                              - CASE e.policy_class WHEN 'keep_all' THEN {KEEP_ALL_BOOST_MS} ELSE 0 END,
                              e.acceptance_seq
                     LIMIT 1"
                ),
                params![recipient, now],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((publisher, event, policy_class, scope, lineage_key)) = head else {
            set_hold(tx, &recipient, None, now_ms)?;
            return Ok(Selection::Idle);
        };
        if policy_class == "latest"
            && let Some(reason) = crate::storage::lineage_block(tx, &publisher, &lineage_key)?
        {
            crate::storage::hold_for_lineage(tx, &publisher, &event, &reason, now_ms)?;
            continue;
        }
        break (publisher, event, policy_class, scope);
    };

    let mut candidates = vec![(head_publisher.clone(), head_event.clone())];
    if policy_class == "batch" {
        let mut statement = tx.prepare(&format!(
            "SELECT e.publisher_id, e.event_id FROM events e
             WHERE {ELIGIBLE} AND e.mode IN {modes} AND e.scope_key = ?3
             ORDER BY e.acceptance_seq LIMIT {MAX_MANIFEST_MEMBERS}"
        ))?;
        candidates = statement
            .query_map(params![recipient, now, scope], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<_, _>>()?;
    }

    let mut members: Vec<(String, String, Envelope, String)> = Vec::new();
    for (publisher, event_id) in candidates {
        let envelope = match load_envelope(tx, &publisher, &event_id) {
            Ok(envelope) => envelope,
            Err(CoreError::Integrity(reason)) => {
                if members.is_empty() {
                    quarantine(tx, &publisher, &event_id, &reason, now_ms)?;
                    return Ok(Selection::Held(format!(
                        "event {publisher}/{event_id} was quarantined: {reason}"
                    )));
                }
                continue;
            }
            Err(other) => return Err(other),
        };
        let Some(tag) = source_tag(tx, &publisher)? else {
            if members.is_empty() {
                let reason = format!("publisher {publisher} has no registered source tag");
                set_hold(tx, &recipient, Some(&reason), now_ms)?;
                return Ok(Selection::Held(reason));
            }
            continue;
        };
        members.push((publisher, event_id, envelope, tag));
        let trial: Vec<(&str, &Envelope)> = members
            .iter()
            .map(|(_, _, envelope, tag)| (tag.as_str(), envelope))
            .collect();
        if frame_manifest(&trial).is_err() {
            if members.len() == 1 {
                let (publisher, event_id, _, _) = members.remove(0);
                let reason = format!("event {publisher}/{event_id} cannot be framed");
                quarantine(tx, &publisher, &event_id, &reason, now_ms)?;
                return Ok(Selection::Held(reason));
            }
            members.pop();
            break;
        }
    }
    let framed: Vec<(&str, &Envelope)> = members
        .iter()
        .map(|(_, _, envelope, tag)| (tag.as_str(), envelope))
        .collect();
    let manifest = frame_manifest(&framed)?;
    debug_assert!(manifest.len() <= MAX_FRAMED_BYTES);
    let manifest_hash = sha256_hex(manifest.as_bytes());
    let requested_mode = members[0].2.mode;

    let mut duplicate_risk = false;
    for (publisher, event_id, _, _) in &members {
        let risk: i64 = tx.query_row(
            "SELECT duplicate_risk FROM events WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
            |row| row.get(0),
        )?;
        duplicate_risk |= risk != 0;
    }

    let attempt_seq = bump_counter(tx, "attempt_seq")?;
    let lease = now_ms.saturating_add(timing.lease_ms);
    let deadline = now_ms.saturating_add(timing.handoff_ms);
    tx.execute(
        "INSERT INTO attempts
             (attempt_seq, state, requested_mode, effective_mode, recipient, actor,
              endpoint_epoch, granted, manifest, manifest_hash, lease_expires_ms,
              deadline_ms, recheck_ms, duplicate_risk, created_ms, updated_ms, note, proof_ref)
         VALUES (?1, 'reserved', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?13, NULL, ?14)",
        params![
            to_sql(attempt_seq)?,
            requested_mode.as_str(),
            mode.as_str(),
            recipient,
            attestation.actor_id,
            to_sql(attestation.endpoint_epoch)?,
            attestation.capabilities.as_text(),
            manifest,
            manifest_hash,
            to_sql(lease)?,
            to_sql(deadline)?,
            duplicate_risk,
            now,
            attestation.proof_ref,
        ],
    )?;
    for (ordinal, (publisher, event_id, envelope, _)) in members.iter().enumerate() {
        tx.execute(
            "INSERT INTO attempt_members (attempt_seq, ordinal, publisher_id, event_id, envelope_hash)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                to_sql(attempt_seq)?,
                to_sql(ordinal as u64)?,
                publisher,
                event_id,
                envelope.envelope_hash().as_str(),
            ],
        )?;
        tx.execute(
            "UPDATE events SET delivery = 'reserved', attempt_seq = ?1,
                 attempts_made = attempts_made + 1
             WHERE publisher_id = ?2 AND event_id = ?3",
            params![to_sql(attempt_seq)?, publisher, event_id],
        )?;
    }
    set_hold(tx, &recipient, None, now_ms)?;
    let record = load_attempt(tx, attempt_seq)?
        .ok_or_else(|| corrupt("a freshly inserted attempt disappeared".into()))?;
    Ok(Selection::Attempt(Box::new(record)))
}

/// Flips a validated reservation to `invoking` inside the caller's
/// transaction.
fn invoke_in(tx: &Connection, attempt_seq: u64, now_ms: u64) -> Result<(), CoreError> {
    // A reservation is not a handoff. Both paths enforce the same durable
    // retirement fence immediately before committing possible native effect.
    let retired: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM attempt_members m JOIN events e
           ON e.publisher_id = m.publisher_id AND e.event_id = m.event_id
         JOIN delivery_scopes s ON s.producer = e.publisher_id
           AND s.scope_key = e.delivery_scope_key
         WHERE m.attempt_seq = ?1 AND s.closed_ms IS NOT NULL
           AND s.action = 'retire_unhanded')",
        params![to_sql(attempt_seq)?],
        |row| row.get(0),
    )?;
    if retired {
        return Err(CoreError::Fence(
            "producer delivery scope retired before invoking".into(),
        ));
    }
    tx.execute(
        "UPDATE attempts SET state = 'invoking', lease_expires_ms = NULL, updated_ms = ?1
         WHERE attempt_seq = ?2 AND state = 'reserved'",
        params![to_sql(now_ms)?, to_sql(attempt_seq)?],
    )?;
    set_member_delivery(tx, attempt_seq, delivery::INVOKING, true)
}

impl Storage {
    /// Records an attested endpoint without dispatching anything.
    ///
    /// An adapter calls this when a session connects or renews, so the
    /// loaded capabilities and the endpoint epoch are known before the first
    /// event arrives: publication then refuses, before acceptance, a mode this
    /// recipient is known not to support, and a stale endpoint is fenced.
    /// A stale epoch is a [`CoreError::Fence`] refusal.
    pub fn observe_binding(
        &mut self,
        attestation: &Attestation,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let tx = self.begin()?;
        fence_binding(&tx, attestation, now_ms)?;
        tx.commit()?;
        Ok(())
    }

    /// Reserves the next attempt for one recipient on one path.
    ///
    /// Runs in one transaction. Fails closed on a stale endpoint epoch or a
    /// non-addressed actor ([`CoreError::Fence`]). A pause (message path),
    /// an unloaded capability, an unknown or disconnected recipient or a
    /// pending approval are returned as a visible [`Selection::Held`] with a
    /// durable hold record — never as an invocation. Otherwise the most
    /// urgent eligible pending event is chosen (keep_all first, aged
    /// snapshots not starved; dependents wait for their predecessors;
    /// expired events are never taken), batch siblings are frozen with it
    /// in acceptance order, the manifest is rendered under each member's
    /// registered source tag, and the attempt is stored as `reserved` with
    /// recipient, actor, endpoint epoch, granted capabilities, effective
    /// path, manifest bytes, manifest hash and hand-off deadline.
    ///
    /// The path decides the requested modes taken: the message path takes
    /// `message` events and, only for a positively inactive recipient,
    /// `auto` events; the inject path takes `inject` and `auto` events and
    /// needs an active recipient.
    pub fn reserve_next(
        &mut self,
        attestation: &Attestation,
        mode: EffectiveMode,
        now_ms: u64,
        timing: &DispatchTiming,
    ) -> Result<Selection, CoreError> {
        timing.validate()?;
        let tx = self.begin()?;
        let selection = reserve_in(&tx, attestation, mode, now_ms, timing)?;
        tx.commit()?;
        Ok(selection)
    }

    /// Drains the inject path for a hook: reserve and persist `invoking`
    /// in one transaction.
    ///
    /// The returned attempt is already `invoking`, so the caller may write
    /// [`AttemptRecord::manifest`] to the hook reply only after this
    /// returns: the possible hand-off is committed before any payload
    /// leaves. On any error or hold nothing was committed and no payload may
    /// be written. The hook then reports `HookSubmitted` with
    /// [`Storage::record_outcome`] after a full flush; silence past the
    /// deadline becomes an unknown outcome, never a re-offer.
    pub fn drain_inject(
        &mut self,
        attestation: &Attestation,
        now_ms: u64,
        timing: &DispatchTiming,
    ) -> Result<Selection, CoreError> {
        timing.validate()?;
        let tx = self.begin()?;
        let selection = reserve_in(&tx, attestation, EffectiveMode::Inject, now_ms, timing)?;
        let selection = match selection {
            Selection::Attempt(record) => {
                invoke_in(&tx, record.fence.attempt_seq, now_ms)?;
                let invoking = load_attempt(&tx, record.fence.attempt_seq)?
                    .ok_or_else(|| corrupt("an invoking attempt disappeared".into()))?;
                Selection::Attempt(Box::new(invoking))
            }
            other => other,
        };
        tx.commit()?;
        Ok(selection)
    }

    /// Persists `invoking` for a reserved attempt before any hand-off.
    ///
    /// Re-verifies the whole fence, the lease, the stored endpoint epoch,
    /// the fresh attestation (same address, same epoch, addressed actor,
    /// capability, lifecycle and pause), and that every member is still
    /// pending and unexpired. If a condition changed since the reservation
    /// the attempt is released untouched and [`Invoked::Released`] explains
    /// why; nothing was invoked. A forged or stale fence, a wrong state or
    /// an expired lease is a [`CoreError::Fence`] refusal.
    pub fn mark_invoking(
        &mut self,
        fence: &AttemptFence,
        attestation: &Attestation,
        now_ms: u64,
    ) -> Result<Invoked, CoreError> {
        let tx = self.begin()?;
        let record = verified_attempt(&tx, fence)?;
        if record.state != AttemptState::Reserved {
            return Err(CoreError::Fence(format!(
                "attempt {} is {}, not reserved",
                fence.attempt_seq,
                record.state.as_str()
            )));
        }
        if let Some(deadline) = record.lease_expires_ms
            && deadline <= now_ms
        {
            return Err(CoreError::Fence(format!(
                "attempt {} lease expired at {deadline}",
                fence.attempt_seq
            )));
        }
        let release = |tx: Transaction<'_>, reason: String| -> Result<Invoked, CoreError> {
            release_reservation(&tx, fence.attempt_seq, &reason, now_ms)?;
            tx.commit()?;
            Ok(Invoked::Released(reason))
        };
        if attestation.address.to_canonical_string() != record.fence.recipient
            || attestation.endpoint_epoch != record.fence.endpoint_epoch
        {
            return release(
                tx,
                "the attested endpoint no longer matches the reserved address or epoch".into(),
            );
        }
        if stored_epoch(&tx, &record.fence.recipient)? != Some(record.fence.endpoint_epoch) {
            return release(
                tx,
                "the endpoint epoch advanced since the reservation".into(),
            );
        }
        if let Some(reason) = gate(&tx, attestation, record.effective_mode)? {
            return release(tx, reason);
        }
        if record.effective_mode == EffectiveMode::Message
            && record.requested_mode == Mode::Auto
            && attestation.lifecycle != Lifecycle::Inactive
        {
            return release(
                tx,
                "the recipient is no longer inactive; auto waits for its hook".into(),
            );
        }
        // Cheap pre-invocation lineage authority fence: a `latest` member
        // whose producer lost the lineage between reservation and now is
        // held visibly (bytes and any evidence untouched) and the
        // reservation — still uninvoked — is released untouched.
        {
            let mut statement = tx.prepare(
                "SELECT m.publisher_id, m.event_id, e.lineage_key FROM attempt_members m
                 JOIN events e ON e.publisher_id = m.publisher_id AND e.event_id = m.event_id
                 WHERE m.attempt_seq = ?1 AND e.policy_class = 'latest'
                   AND e.lineage_key != ''",
            )?;
            let members: Vec<(String, String, String)> = statement
                .query_map(params![to_sql(fence.attempt_seq)?], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<Result<_, _>>()?;
            drop(statement);
            for (publisher, event_id, lineage_key) in members {
                if let Some(reason) = crate::storage::lineage_block(&tx, &publisher, &lineage_key)?
                {
                    crate::storage::hold_for_lineage(&tx, &publisher, &event_id, &reason, now_ms)?;
                    return release(tx, reason);
                }
            }
        }
        let live: i64 = tx.query_row(
            "SELECT COUNT(*) FROM attempt_members m JOIN events e
               ON e.publisher_id = m.publisher_id AND e.event_id = m.event_id
             WHERE m.attempt_seq = ?1 AND e.state = 'pending' AND e.delivery = 'reserved'
               AND e.attempt_seq = ?1
               AND (e.expires_at_ms IS NULL OR e.expires_at_ms > ?2)",
            params![to_sql(fence.attempt_seq)?, to_sql(now_ms)?],
            |row| row.get(0),
        )?;
        if usize::try_from(live) != Ok(record.members.len()) {
            return release(
                tx,
                "a member expired or changed since the reservation".into(),
            );
        }
        invoke_in(&tx, fence.attempt_seq, now_ms)?;
        let invoking = load_attempt(&tx, fence.attempt_seq)?
            .ok_or_else(|| corrupt("an invoking attempt disappeared".into()))?;
        tx.commit()?;
        Ok(Invoked::Invoking(Box::new(invoking)))
    }

    /// Releases a reservation that will not be invoked (for example when
    /// the fresh attestation failed). Only a `reserved` attempt can be
    /// released; an invoking one is never reclaimed without review.
    pub fn release_attempt(
        &mut self,
        fence: &AttemptFence,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let tx = self.begin()?;
        let record = verified_attempt(&tx, fence)?;
        if record.state != AttemptState::Reserved {
            return Err(CoreError::Fence(format!(
                "attempt {} is {}; only a reserved attempt can be released",
                fence.attempt_seq,
                record.state.as_str()
            )));
        }
        release_reservation(&tx, fence.attempt_seq, reason, now_ms)?;
        tx.commit()?;
        Ok(())
    }

    /// Records a carrier or hook outcome for an attempt.
    ///
    /// From `invoking`, `native_held` or `written_no_receipt` any outcome
    /// is accepted; the evidence tier is appended to the event's evidence
    /// log, member delivery states follow the tier, and
    /// - `OutcomeUnknown` opens a retained incident (never retried);
    /// - `PermanentRefusal` opens an incident and blocks dependents until
    ///   an audited disposition;
    /// - `KnownUnsent` needs non-empty positive evidence, closes the
    ///   attempt before settling each member it still owns. Outside a retired
    ///   lifetime, the bounded retry delay/budget applies, or a replaced
    ///   snapshot is superseded. In a `retire_unhanded` lifetime, a member with
    ///   any retained possible-effect history stays in review with an incident;
    ///   only proved zero-effect work is disposed. Neither returns to rotation.
    ///
    /// Evidence is retained for every frozen member; disposed or newer-owned
    /// members and their incidents are unchanged.
    ///
    /// A late outcome for an `outcome_unknown` attempt may only be positive
    /// (accepted, hook submitted, known-unsent with proof, refusal): it
    /// resolves that attempt's own incident without another send. If an audited
    /// retry has since given the events to a newer attempt, the late outcome is
    /// kept as evidence only: it never closes, opens or changes the newer
    /// attempt's incidents or delivery state. A held or unreceipted
    /// outcome is rechecked by `recheck_ms`, clamped to a day.
    pub fn record_outcome(
        &mut self,
        fence: &AttemptFence,
        outcome: Outcome,
        now_ms: u64,
    ) -> Result<AttemptRecord, CoreError> {
        let tx = self.begin()?;
        let record = verified_attempt(&tx, fence)?;
        let late = record.state == AttemptState::OutcomeUnknown;
        match record.state {
            AttemptState::Invoking
            | AttemptState::NativeHeld
            | AttemptState::WrittenNoReceipt
            | AttemptState::OutcomeUnknown => {}
            other => {
                return Err(CoreError::Fence(format!(
                    "attempt {} is {}; it cannot take an outcome",
                    fence.attempt_seq,
                    other.as_str()
                )));
            }
        }
        if late
            && !matches!(
                outcome,
                Outcome::NativeAccepted { .. }
                    | Outcome::HookSubmitted { .. }
                    | Outcome::KnownUnsent { .. }
                    | Outcome::PermanentRefusal { .. }
            )
        {
            return Err(CoreError::Fence(format!(
                "attempt {} is already outcome_unknown; only positive late evidence is accepted",
                fence.attempt_seq
            )));
        }
        apply_outcome(&tx, &record, outcome, now_ms)?;
        let updated = load_attempt(&tx, fence.attempt_seq)?
            .ok_or_else(|| corrupt("an attempt disappeared".into()))?;
        tx.commit()?;
        Ok(updated)
    }

    /// Reads one attempt by number, if it exists.
    pub fn attempt(&self, attempt_seq: u64) -> Result<Option<AttemptRecord>, CoreError> {
        load_attempt(&self.connection, attempt_seq)
    }

    /// Reads the newest attempt that includes the event, if any.
    pub fn latest_attempt(
        &self,
        publisher: &str,
        event_id: &str,
    ) -> Result<Option<AttemptRecord>, CoreError> {
        let seq: Option<i64> = self
            .connection
            .query_row(
                "SELECT MAX(attempt_seq) FROM attempt_members
                 WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, event_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        match seq {
            Some(seq) => load_attempt(&self.connection, from_sql(seq)?),
            None => Ok(None),
        }
    }

    /// Lists recipients that currently have eligible unhanded work for the
    /// dispatch loop (bounded by `limit`), as one window of a rotation.
    ///
    /// The full order is: healthy recipients first, oldest waiting event
    /// first; recipients under a visible hold follow, least recently
    /// rechecked first. The window starts just after `after` (the last
    /// recipient of the previous window, or `None` for the start) and
    /// wraps around to the start of the order. Recipients whose work the
    /// message path cannot take right now (inject-only, active auto,
    /// predecessor-blocked, paused) keep unchanged sort keys, so for a
    /// stable set of recipients consecutive windows advance through the whole
    /// order and cannot stay pinned to the same `limit` recipients (tested
    /// with `ceil(n / limit)` windows for a static set). The sort keys move
    /// as work progresses (a recheck refreshes a hold, handling the oldest
    /// event ages a recipient), which can reorder recipients between
    /// windows, so no exact coverage bound is promised for a changing
    /// workload. An `after` that no longer has work restarts from the
    /// beginning. Retired `retire_unhanded` lifetimes are excluded, including
    /// unhanded rows left by older builds; diagnostics expose their fence.
    pub fn recipients_with_work(
        &self,
        now_ms: u64,
        limit: usize,
        after: Option<&NativeAddress>,
    ) -> Result<Vec<NativeAddress>, CoreError> {
        let mut statement = self.connection.prepare(
            "WITH work AS (
                 SELECT e.recipient AS recipient, h.recipient IS NOT NULL AS held,
                        COALESCE(h.updated_ms, MIN(e.accepted_at_ms)) AS waiting_since
                 FROM events e
                 LEFT JOIN recipient_holds h ON h.recipient = e.recipient
                 WHERE e.state = 'pending' AND e.delivery = 'unhanded' AND e.not_before_ms <= ?1
                   AND (e.expires_at_ms IS NULL OR e.expires_at_ms > ?1)
                   AND NOT EXISTS (SELECT 1 FROM delivery_scopes s
                       WHERE s.producer = e.publisher_id AND s.scope_key = e.delivery_scope_key
                         AND s.closed_ms IS NOT NULL AND s.action = 'retire_unhanded')
                 GROUP BY e.recipient)
             SELECT recipient FROM work
             ORDER BY ((held, waiting_since, recipient) <=
                       (SELECT c.held, c.waiting_since, c.recipient FROM work c
                        WHERE c.recipient = ?3)),
                      held, waiting_since, recipient
             LIMIT ?2",
        )?;
        let texts: Vec<String> = statement
            .query_map(
                params![
                    to_sql(now_ms)?,
                    to_sql(limit as u64)?,
                    after.map(NativeAddress::to_canonical_string)
                ],
                |row| row.get(0),
            )?
            .collect::<Result<_, _>>()?;
        texts
            .iter()
            .map(|text| {
                NativeAddress::parse(text)
                    .map_err(|error| corrupt(format!("stored recipient {text:?}: {error}")))
            })
            .collect()
    }

    /// Selects the next dispatchable pending events for one recipient with
    /// keep_all priority and anti-starvation aging, for diagnostics.
    ///
    /// Ignores mode, lifecycle and path gating; superseded, expired,
    /// reserved and handed-off events and retired lifetimes are never listed.
    pub fn next_pending(
        &self,
        recipient: &str,
        limit: usize,
    ) -> Result<Vec<PendingEvent>, CoreError> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT publisher_id, event_id, policy_class FROM events e
             WHERE state = 'pending' AND delivery = 'unhanded' AND recipient = ?1
               AND NOT EXISTS (SELECT 1 FROM delivery_scopes s
                   WHERE s.producer = e.publisher_id AND s.scope_key = e.delivery_scope_key
                     AND s.closed_ms IS NOT NULL AND s.action = 'retire_unhanded')
             ORDER BY accepted_at_ms
                      - CASE policy_class WHEN 'keep_all' THEN {KEEP_ALL_BOOST_MS} ELSE 0 END,
                      acceptance_seq
             LIMIT ?2"
        ))?;
        let rows = statement
            .query_map(params![recipient, to_sql(limit as u64)?], |row| {
                Ok(PendingEvent {
                    publisher: row.get(0)?,
                    event_id: row.get(1)?,
                    policy_class: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }
}

/// Applies an outcome to an attempt and its members inside the caller's
/// transaction.
///
/// Every outcome changes each member's delivery state and raises incidents
/// only while this attempt still owns that member, and only
/// closes incidents that this attempt raised. The attempt row and its
/// evidence tier are always recorded.
pub(crate) fn apply_outcome(
    tx: &Transaction<'_>,
    record: &AttemptRecord,
    outcome: Outcome,
    now_ms: u64,
) -> Result<(), CoreError> {
    let seq = record.fence.attempt_seq;
    let now = to_sql(now_ms)?;
    let (state, tier, detail, recheck) = match &outcome {
        Outcome::NativeAccepted { evidence } => (
            AttemptState::NativeAccepted,
            "native_accepted",
            evidence.clone(),
            None,
        ),
        Outcome::NativeHeld { recheck_ms } => (
            AttemptState::NativeHeld,
            "native_held",
            format!("held; recheck by {recheck_ms}"),
            Some(clamp_recheck(*recheck_ms, now_ms)),
        ),
        Outcome::WrittenNoReceipt {
            evidence,
            receipt_deadline_ms,
        } => (
            AttemptState::WrittenNoReceipt,
            "written_no_receipt",
            evidence.clone(),
            Some(clamp_recheck(*receipt_deadline_ms, now_ms)),
        ),
        Outcome::HookSubmitted { evidence } => (
            AttemptState::HookSubmitted,
            "hook_emitted",
            evidence.clone(),
            None,
        ),
        Outcome::KnownUnsent { evidence } => {
            if evidence.trim().is_empty() {
                return Err(CoreError::InvalidEnvelope(
                    "known-unsent needs positive evidence that nothing was written".into(),
                ));
            }
            (
                AttemptState::KnownUnsent,
                "known_unsent",
                evidence.clone(),
                None,
            )
        }
        Outcome::OutcomeUnknown { reason } => (
            AttemptState::OutcomeUnknown,
            "unknown",
            reason.clone(),
            None,
        ),
        Outcome::PermanentRefusal { reason } => (
            AttemptState::PermanentRefusal,
            "refused",
            reason.clone(),
            None,
        ),
    };
    let detail = bound_text(&detail);
    tx.execute(
        "UPDATE attempts SET state = ?1, note = ?2, updated_ms = ?3, recheck_ms = ?4
         WHERE attempt_seq = ?5",
        params![
            state.as_str(),
            format!("{tier}: {detail}"),
            now,
            recheck.map(to_sql).transpose()?,
            to_sql(seq)?,
        ],
    )?;
    for member in &record.members {
        record_evidence_row(
            tx,
            &member.publisher,
            &member.event_id,
            seq,
            tier,
            &detail,
            now_ms,
        )?;
    }

    // Snapshot ownership before terminal transitions clear it. Evidence above
    // covers every frozen member; state and incidents below cover only owners.
    let mut owned_members = Vec::new();
    for member in &record.members {
        let owns: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM events WHERE publisher_id = ?1 AND event_id = ?2 AND attempt_seq = ?3)",
            params![member.publisher, member.event_id, to_sql(seq)?],
            |row| row.get(0),
        )?;
        if owns {
            owned_members.push(member);
        }
    }
    match state {
        AttemptState::NativeAccepted => {
            set_member_delivery(tx, seq, delivery::ACCEPTED, false)?;
            resolve_attempt_incidents(
                tx,
                record,
                &owned_members,
                "positive evidence: native accepted",
                now_ms,
            )?;
        }
        AttemptState::HookSubmitted => {
            set_member_delivery(tx, seq, delivery::HOOK_SUBMITTED, false)?;
            resolve_attempt_incidents(
                tx,
                record,
                &owned_members,
                "positive evidence: hook emitted",
                now_ms,
            )?;
        }
        AttemptState::NativeHeld | AttemptState::WrittenNoReceipt => {
            set_member_delivery(tx, seq, delivery::HELD, true)?;
        }
        AttemptState::OutcomeUnknown => {
            set_member_delivery(tx, seq, delivery::REVIEW, true)?;
            for member in &owned_members {
                open_incident_in(
                    tx,
                    &member.publisher,
                    &member.event_id,
                    Some(seq),
                    "unknown_handoff",
                    &detail,
                    now_ms,
                )?;
            }
        }
        AttemptState::PermanentRefusal => {
            set_member_delivery(tx, seq, delivery::REFUSED, false)?;
            resolve_attempt_incidents(
                tx,
                record,
                &owned_members,
                "positive evidence: refused before acceptance",
                now_ms,
            )?;
            // A refusal of an attempt that no longer owns its events is
            // evidence only; it must not raise an incident on the newer one.
            for member in &owned_members {
                open_incident_in(
                    tx,
                    &member.publisher,
                    &member.event_id,
                    Some(seq),
                    "permanent_refusal",
                    &detail,
                    now_ms,
                )?;
            }
        }
        AttemptState::KnownUnsent => {
            return_unsent(tx, record, now_ms)?;
            resolve_attempt_incidents(
                tx,
                record,
                &owned_members,
                "positive evidence: known unsent",
                now_ms,
            )?;
        }
        AttemptState::Reserved | AttemptState::Invoking | AttemptState::Closed => {
            return Err(corrupt("an outcome mapped to a non-outcome state".into()));
        }
    }
    Ok(())
}

/// Clamps a recheck deadline into `(now, now + MAX_RECHECK_MS]`.
fn clamp_recheck(requested_ms: u64, now_ms: u64) -> u64 {
    requested_ms.clamp(
        now_ms.saturating_add(1),
        now_ms.saturating_add(MAX_RECHECK_MS),
    )
}

/// Closes the open incidents that belong to one attempt's members with a
/// positive resolution, for outcomes that settle the uncertainty.
///
/// `members` is the ownership snapshot taken before terminal transitions.
/// Only incidents raised by this attempt (or unattributed ones, such as a
/// `migrated_unverified` incident that predates attempt numbering) close; a
/// newer attempt's incident on the same event stays open, so a late outcome
/// for an older attempt can never hide the newer attempt's uncertainty.
fn resolve_attempt_incidents(
    tx: &Connection,
    record: &AttemptRecord,
    members: &[&MemberRef],
    resolution: &str,
    now_ms: u64,
) -> Result<(), CoreError> {
    for member in members {
        tx.execute(
            "UPDATE incidents SET state = 'resolved', resolution = ?1, updated_ms = ?2,
                 resolved_ms = ?2
             WHERE publisher_id = ?3 AND event_id = ?4 AND state = 'open'
               AND (attempt_seq IS NULL OR attempt_seq = ?5)
               AND kind IN ('unknown_handoff', 'held_overdue', 'receipt_overdue',
                            'migrated_unverified')",
            params![
                resolution,
                to_sql(now_ms)?,
                member.publisher,
                member.event_id,
                to_sql(record.fence.attempt_seq)?
            ],
        )?;
    }
    Ok(())
}

/// Returns the members of a positively unsent attempt to rotation.
///
/// The attempt is already closed. Only members still owned by it change.
/// Retired lifetimes dispose zero-effect members or retain all possible
/// historical effects in review with an incident; they never reenter rotation.
/// Other members get the bounded retry delay;
/// one that has used its automatic budget is refused with an incident; a
/// snapshot that a newer revision has meanwhile replaced is superseded
/// instead of retried.
fn return_unsent(
    tx: &Transaction<'_>,
    record: &AttemptRecord,
    now_ms: u64,
) -> Result<(), CoreError> {
    for member in &record.members {
        let row: Option<(i64, String, Option<i64>, bool)> = tx
            .query_row(
                "SELECT e.attempts_made, e.scope_key, e.revision, EXISTS (
                 SELECT 1 FROM delivery_scopes s WHERE s.producer = e.publisher_id
                 AND s.scope_key = e.delivery_scope_key AND s.closed_ms IS NOT NULL
                 AND s.action = 'retire_unhanded') FROM events e
             WHERE e.publisher_id = ?1 AND e.event_id = ?2 AND e.attempt_seq = ?3",
                params![
                    member.publisher,
                    member.event_id,
                    to_sql(record.fence.attempt_seq)?
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((attempts, scope, revision, retired)) = row else {
            continue;
        };
        if retired {
            // Clear this known-unsent attempt's current state before consulting
            // the shared conservative history predicate; older effects remain.
            tx.execute(
                "UPDATE events SET delivery = 'unhanded', attempt_seq = NULL
                        WHERE publisher_id = ?1 AND event_id = ?2 AND attempt_seq = ?3",
                params![
                    member.publisher,
                    member.event_id,
                    to_sql(record.fence.attempt_seq)?
                ],
            )?;
            let possible: bool = tx.query_row(
                &format!(
                    "SELECT {} FROM events e WHERE e.publisher_id = ?1 AND e.event_id = ?2",
                    crate::universal::POSSIBLE_EFFECT
                ),
                params![member.publisher, member.event_id],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE events SET delivery = ?1 WHERE publisher_id = ?2 AND event_id = ?3",
                params![
                    if possible {
                        delivery::REVIEW
                    } else {
                        delivery::DISPOSED
                    },
                    member.publisher,
                    member.event_id
                ],
            )?;
            if possible {
                open_incident_in(
                    tx,
                    &member.publisher,
                    &member.event_id,
                    Some(record.fence.attempt_seq),
                    "retired_possible_effect",
                    "retired lifetime retains historical possible effects; automatic delivery is fenced",
                    now_ms,
                )?;
            }
            continue;
        }
        let attempts = u32::try_from(from_sql(attempts)?).unwrap_or(u32::MAX);
        let newer: bool = match revision {
            Some(revision) => tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM events WHERE scope_key = ?1 AND revision > ?2
                                  AND state != 'superseded')",
                params![scope, revision],
                |row| row.get(0),
            )?,
            None => false,
        };
        if newer {
            tx.execute(
                "UPDATE events SET state = 'superseded', delivery = 'unhanded', attempt_seq = NULL
                 WHERE publisher_id = ?1 AND event_id = ?2",
                params![member.publisher, member.event_id],
            )?;
        } else if attempts >= MAX_AUTOMATIC_ATTEMPTS {
            tx.execute(
                "UPDATE events SET delivery = 'refused', attempt_seq = NULL
                 WHERE publisher_id = ?1 AND event_id = ?2",
                params![member.publisher, member.event_id],
            )?;
            open_incident_in(
                tx,
                &member.publisher,
                &member.event_id,
                Some(record.fence.attempt_seq),
                "retries_exhausted",
                &format!("{attempts} automatic attempts ended known-unsent"),
                now_ms,
            )?;
        } else {
            tx.execute(
                "UPDATE events SET delivery = 'unhanded', attempt_seq = NULL, not_before_ms = ?1
                 WHERE publisher_id = ?2 AND event_id = ?3",
                params![
                    to_sql(now_ms.saturating_add(retry_delay_ms(attempts)))?,
                    member.publisher,
                    member.event_id
                ],
            )?;
        }
    }
    Ok(())
}

/// Attests a recipient through a carrier, converting a carrier panic into
/// an attestation failure.
///
/// A panicking `attest` is contained to this recipient: the caller treats
/// the returned error exactly like any other failed attestation (a visible
/// hold, or a released reservation), so one carrier defect can neither end
/// the pass for other recipients nor be mistaken for an inactive or
/// accepting endpoint. The panic payload is not copied into the reason.
pub(crate) fn attest_guarded(
    carrier: &mut dyn DispatchCarrier,
    recipient: &NativeAddress,
) -> Result<Attestation, String> {
    catch_unwind(AssertUnwindSafe(|| carrier.attest(recipient)))
        .unwrap_or_else(|_| Err("the carrier panicked during attestation".to_string()))
}

/// Drives one message-path dispatch for a recipient through a carrier.
///
/// Sequence: attest -> reserve (fenced, lease-bound, frozen manifest) ->
/// attest again (cheap recheck) -> persist `invoking` -> one carrier send
/// -> record the evidence tier. The storage lock is held only inside each
/// storage step, never across carrier calls. An attestation failure, a
/// pause, an unknown or disconnected recipient and a pending approval are
/// visible holds that invoke nothing; an attestation panic counts as an
/// attestation failure (the panic is contained, never propagated); a panic during the hand-off
/// is recorded as an unknown outcome. `clock` supplies Unix epoch milliseconds and is read
/// before each step.
pub fn dispatch_message(
    storage: &Mutex<Storage>,
    carrier: &mut dyn DispatchCarrier,
    recipient: &NativeAddress,
    clock: &dyn Fn() -> u64,
    timing: &DispatchTiming,
) -> Result<DispatchReport, CoreError> {
    let attestation = match attest_guarded(carrier, recipient) {
        Ok(attestation) => attestation,
        Err(reason) => {
            let reason = format!("endpoint attestation failed: {reason}");
            lock_storage(storage).record_hold(recipient, &reason, clock())?;
            return Ok(DispatchReport::Held(reason));
        }
    };
    if attestation.address != *recipient {
        let reason = "attested address does not match the recipient".to_string();
        lock_storage(storage).record_hold(recipient, &reason, clock())?;
        return Ok(DispatchReport::Held(reason));
    }
    let selection = lock_storage(storage).reserve_next(
        &attestation,
        EffectiveMode::Message,
        clock(),
        timing,
    )?;
    let reserved = match selection {
        Selection::Idle => return Ok(DispatchReport::Idle),
        Selection::Held(reason) => return Ok(DispatchReport::Held(reason)),
        Selection::Attempt(record) => record,
    };
    let fresh = match attest_guarded(carrier, recipient) {
        Ok(fresh) => fresh,
        Err(reason) => {
            let reason = format!("endpoint attestation failed before invocation: {reason}");
            lock_storage(storage).release_attempt(&reserved.fence, &reason, clock())?;
            return Ok(DispatchReport::Held(reason));
        }
    };
    let invoking = match lock_storage(storage).mark_invoking(&reserved.fence, &fresh, clock())? {
        Invoked::Invoking(record) => record,
        Invoked::Released(reason) => return Ok(DispatchReport::Held(reason)),
    };
    let outcome = catch_unwind(AssertUnwindSafe(|| carrier.send(&invoking))).unwrap_or_else(|_| {
        Outcome::OutcomeUnknown {
            reason: "the carrier panicked during the hand-off".to_string(),
        }
    });
    let recorded = lock_storage(storage).record_outcome(&invoking.fence, outcome, clock())?;
    Ok(DispatchReport::Sent {
        state: recorded.state,
        events: recorded.members.len(),
    })
}
