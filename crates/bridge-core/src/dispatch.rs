//! Fenced dispatch attempts, evidence tiers and unknown-outcome custody.
//!
//! One pending event receives one frozen attempt at a time: the attempt is
//! reserved under a fence, persisted as `invoking` *before* any possible
//! hand-off, and only then offered to a delivery carrier. Outcomes are
//! recorded as distinct evidence tiers — native queue acceptance, hold with
//! recheck, hook submission, positively known-unsent, outcome-unknown and
//! permanent refusal — never as one boolean "delivered".
//!
//! Uncertainty is owned, never retried blindly: an expired `invoking` lease
//! or a carrier reporting uncertainty becomes `outcome_unknown` plus a
//! retained incident, and a new attempt for that event is refused until an
//! audited manual authorization records the possible duplicate risk. Only a
//! reservation that could not invoke is safely reclaimable without review.
//! Positively known-unsent closes its attempt and may follow the ordinary
//! bounded retry policy.
//!
//! The [`DispatchCarrier`] trait is this crate's contract-faithful
//! substitute for the `bridge-native-host` interface (M-002): real adapters
//! implement the same observations and outcomes; tests provide synthetic
//! carriers. Nothing here invokes a real native host.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::storage::Storage;
use crate::types::{CoreError, Envelope, Mode, NativeAddress};

/// Effective delivery path chosen for one attempt.
///
/// `Auto` is resolved into one of these before any hand-off; the requested
/// mode stays immutable on the event and both are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveMode {
    /// Native hook at a natural context point.
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
    /// Hook payload handed out; model context not yet proven.
    HookSubmitted,
    /// Positively known never-sent; ordinary bounded retry may follow.
    KnownUnsent,
    /// Possible hand-off with unknown effect; never automatically retried.
    OutcomeUnknown,
    /// Carrier refused permanently before acceptance.
    PermanentRefusal,
    /// Terminal bookkeeping state for a finished or reclaimed attempt.
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
            AttemptState::HookSubmitted => "hook_submitted",
            AttemptState::KnownUnsent => "known_unsent",
            AttemptState::OutcomeUnknown => "outcome_unknown",
            AttemptState::PermanentRefusal => "permanent_refusal",
            AttemptState::Closed => "closed",
        }
    }

    /// Parses the storage text form strictly.
    ///
    /// Unknown texts are errors, never defaults.
    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "reserved" => Ok(AttemptState::Reserved),
            "invoking" => Ok(AttemptState::Invoking),
            "native_accepted" => Ok(AttemptState::NativeAccepted),
            "native_held" => Ok(AttemptState::NativeHeld),
            "hook_submitted" => Ok(AttemptState::HookSubmitted),
            "known_unsent" => Ok(AttemptState::KnownUnsent),
            "outcome_unknown" => Ok(AttemptState::OutcomeUnknown),
            "permanent_refusal" => Ok(AttemptState::PermanentRefusal),
            "closed" => Ok(AttemptState::Closed),
            other => Err(CoreError::Storage(rusqlite::Error::InvalidParameterName(
                format!("unknown attempt state {other:?}"),
            ))),
        }
    }
}

/// The capability that owns one attempt's transitions.
///
/// Handed only to the code that reserved the attempt; every transition
/// verifies the fence against the stored row, so a stale or forged fence
/// refuses without a new invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptFence {
    /// Monotonic attempt number within the store.
    pub attempt_seq: u64,
    /// Publisher of the attempted event.
    pub publisher: String,
    /// Event id of the attempted event.
    pub event_id: String,
}

/// One durable attempt row as read back from storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    /// The fence owning this attempt.
    pub fence: AttemptFence,
    /// Current durable state.
    pub state: AttemptState,
    /// Effective path chosen for this attempt.
    pub effective_mode: EffectiveMode,
    /// Hash of the frozen manifest handed (or about to be handed) over.
    pub manifest_hash: String,
    /// Lease deadline for reserved/invoking attempts, if any.
    pub lease_expires_ms: Option<u64>,
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
/// refusal is permanent before acceptance, and unknown means a possible
/// hand-off whose effect cannot be established.
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
    /// Hook payload handed out; submission evidence recorded.
    HookSubmitted {
        /// Submission evidence description.
        evidence: String,
    },
    /// Positively known never-sent (reservation never invoked, or the
    /// carrier proved no write happened).
    KnownUnsent {
        /// How non-sending was established.
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

impl Outcome {
    /// Maps the outcome to its attempt state and note text.
    fn state_and_note(&self) -> (AttemptState, String) {
        match self {
            Outcome::NativeAccepted { evidence } => (
                AttemptState::NativeAccepted,
                format!("accepted: {evidence}"),
            ),
            Outcome::NativeHeld { recheck_ms } => (
                AttemptState::NativeHeld,
                format!("held; recheck by {recheck_ms}"),
            ),
            Outcome::HookSubmitted { evidence } => (
                AttemptState::HookSubmitted,
                format!("hook submitted: {evidence}"),
            ),
            Outcome::KnownUnsent { evidence } => (
                AttemptState::KnownUnsent,
                format!("known unsent: {evidence}"),
            ),
            Outcome::OutcomeUnknown { reason } => (
                AttemptState::OutcomeUnknown,
                format!("outcome unknown: {reason}"),
            ),
            Outcome::PermanentRefusal { reason } => {
                (AttemptState::PermanentRefusal, format!("refused: {reason}"))
            }
        }
    }
}

/// The recipient lifecycle observation used to resolve `auto`.
///
/// `Unknown` covers disconnected and not-loaded observations: none of them
/// is inactive, and none of them may trigger a wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Recipient is working; auto selects inject.
    Active,
    /// Recipient is idle; auto selects message.
    Inactive,
    /// Disconnected, not loaded or unobservable: hold, never wake.
    Unknown,
}

/// The carrier outcome of one send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierOutcome {
    /// Hand-off positively accepted by the carrier.
    Accepted {
        /// Positive evidence description.
        evidence: String,
    },
    /// Held non-terminally with a recheck deadline.
    Held {
        /// Recheck deadline in Unix epoch milliseconds.
        recheck_ms: u64,
    },
    /// Refused permanently before any possible effect.
    Refused {
        /// Refusal reason.
        reason: String,
    },
    /// Possible hand-off whose effect cannot be established.
    Unknown {
        /// Why the outcome is unknown.
        reason: String,
    },
}

/// Contract-faithful substitute for the `bridge-native-host` interface.
///
/// The real adapter module (M-002) provides attested addresses, loaded
/// capabilities, endpoint epochs, qualified inject/message operations and
/// immutable evidence; this trait carries exactly the observations and
/// outcomes core dispatch needs, so tests drive synthetic carriers and the
/// real adapters implement the same contract. Implementations must be
/// deterministic per test and must never touch a working session.
pub trait DispatchCarrier {
    /// Observes the recipient's current lifecycle for auto selection.
    ///
    /// Errors carry the reason the observation failed; a failed observation
    /// is treated as [`Lifecycle::Unknown`], never as inactive.
    fn observe(&mut self, recipient: &NativeAddress) -> Result<Lifecycle, String>;

    /// Performs one hand-off of already-framed bytes for one event.
    ///
    /// Called at most once per attempt; the driver has already persisted
    /// `invoking`, so any return (including a panic-simulating error) is
    /// reconciled as evidence, never silently retried.
    fn send(&mut self, mode: EffectiveMode, envelope_hash: &str, framed: &str) -> CarrierOutcome;
}

/// Result of one dispatch drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResult {
    /// The attempt's durable state after the drive.
    pub state: AttemptState,
    /// The effective mode that was (or would be) used.
    pub effective_mode: EffectiveMode,
    /// Whether any hand-off possibly occurred.
    pub possibly_handed_off: bool,
}

impl Storage {
    /// Reserves the next dispatch attempt for a pending event.
    ///
    /// Refuses when the event is unknown or not pending, when an open
    /// attempt already owns it (an `outcome_unknown` attempt additionally
    /// requires an audited manual authorization with recorded duplicate
    /// risk), or when the recipient is under a durable no-wake policy
    /// (pause blocks auto AND message). The reservation carries a lease;
    /// only a reservation that never invokes may be reclaimed by lease
    /// expiry without review.
    pub fn reserve_attempt(
        &mut self,
        publisher: &str,
        event_id: &str,
        effective_mode: EffectiveMode,
        manifest_hash: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<AttemptRecord, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let event_state: Option<String> = tx
            .query_row(
                "SELECT state FROM events WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, event_id],
                |row| row.get(0),
            )
            .optional()?;
        match event_state.as_deref() {
            None => {
                return Err(CoreError::Fence(format!(
                    "no such event {publisher}/{event_id}"
                )));
            }
            Some("pending") => {}
            Some(other) => {
                return Err(CoreError::Fence(format!(
                    "event {publisher}/{event_id} is {other}, not dispatchable"
                )));
            }
        }

        let open: Option<(i64, String)> = tx
            .query_row(
                "SELECT attempt_seq, state FROM attempts
                 WHERE publisher_id = ?1 AND event_id = ?2 AND state NOT IN
                   ('closed','known_unsent','native_accepted','permanent_refusal',
                    'hook_submitted','outcome_unknown')
                 ORDER BY attempt_seq DESC LIMIT 1",
                params![publisher, event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match open {
            None => {}
            Some((seq, state)) => {
                return Err(CoreError::Fence(format!(
                    "attempt {seq} still owns event {publisher}/{event_id} in state {state}"
                )));
            }
        }

        // Manual retry authorization for possible-handoff events: an open
        // outcome_unknown incident without an audit record blocks a new
        // attempt; with one, the duplicate risk stays recorded on the
        // incident.
        let unauthorized: Option<i64> = tx
            .query_row(
                "SELECT incident_seq FROM incidents
                 WHERE publisher_id = ?1 AND event_id = ?2
                   AND kind = 'unknown_handoff' AND state = 'open'
                   AND resolution IS NULL
                 LIMIT 1",
                params![publisher, event_id],
                |row| row.get(0),
            )
            .optional()?;
        if unauthorized.is_some() {
            return Err(CoreError::Fence(format!(
                "event {publisher}/{event_id} has an unresolved unknown-handoff incident; \
                 audited manual authorization required before another attempt"
            )));
        }

        let recipient = Self::recipient_of(&tx, publisher, event_id)?;

        // Dependent ordering: an event declaring a predecessor (metadata
        // key "predecessor", same publisher) waits until that predecessor
        // reached a reviewed disposition. An uncertain command is never
        // silently overtaken by its dependent; time alone never releases
        // the dependency.
        let predecessor: Option<String> = tx
            .query_row(
                "SELECT COALESCE(json_extract(envelope_json, '$.metadata.predecessor'), '')
                 FROM events WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .filter(|value| !value.is_empty());
        if let Some(predecessor_id) = predecessor {
            let predecessor_state: Option<String> = tx
                .query_row(
                    "SELECT state FROM events WHERE publisher_id = ?1 AND event_id = ?2",
                    params![publisher, predecessor_id],
                    |row| row.get(0),
                )
                .optional()?;
            let resolved =
                matches!(
                    predecessor_state.as_deref(),
                    Some("expired") | Some("superseded")
                ) || Self::predecessor_attempt_resolved(&tx, publisher, &predecessor_id)?;
            if !resolved {
                return Err(CoreError::PolicyHold {
                    recipient,
                    reason: format!(
                        "event depends on {publisher}/{predecessor_id}, which is not yet resolved \
                         (state {:?}); an explicit audited disposition or the required evidence \
                         tier must precede this dependent",
                        predecessor_state.unwrap_or_else(|| "unknown".into())
                    ),
                });
            }
        }

        let paused: Option<(String, i64)> = tx
            .query_row(
                "SELECT reason, no_wake FROM recipient_policies WHERE recipient = ?1",
                params![recipient],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((reason, 1)) = paused {
            return Err(CoreError::PolicyHold {
                recipient,
                reason: format!("no-wake policy active: {reason}"),
            });
        }

        tx.execute(
            "UPDATE counters SET value = value + 1 WHERE name = 'attempt_seq'",
            [],
        )?;
        let attempt_seq: i64 = tx.query_row(
            "SELECT value FROM counters WHERE name = 'attempt_seq'",
            [],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO attempts
                 (attempt_seq, publisher_id, event_id, state, effective_mode,
                  manifest_hash, lease_expires_ms, created_ms, updated_ms, note)
             VALUES (?1, ?2, ?3, 'reserved', ?4, ?5, ?6, ?7, ?7, NULL)",
            params![
                attempt_seq,
                publisher,
                event_id,
                effective_mode.as_str(),
                manifest_hash,
                now_ms + lease_ms,
                now_ms as i64,
            ],
        )?;
        tx.commit()?;
        Ok(AttemptRecord {
            fence: AttemptFence {
                attempt_seq: attempt_seq as u64,
                publisher: publisher.to_string(),
                event_id: event_id.to_string(),
            },
            state: AttemptState::Reserved,
            effective_mode,
            manifest_hash: manifest_hash.to_string(),
            lease_expires_ms: Some(now_ms + lease_ms),
            created_ms: now_ms,
            updated_ms: now_ms,
            note: None,
        })
    }

    /// Persists `invoking` for a reserved attempt before any hand-off.
    ///
    /// Verifies the fence and the reservation; a stale fence, a foreign
    /// state or an expired lease refuses without invoking anything.
    pub fn mark_invoking(
        &mut self,
        fence: &AttemptFence,
        now_ms: u64,
    ) -> Result<AttemptRecord, CoreError> {
        self.transition(fence, now_ms, |record| {
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
            Ok((AttemptState::Invoking, None))
        })
    }

    /// Records a carrier outcome for an invoking attempt.
    ///
    /// `outcome_unknown` additionally opens (or refreshes) a retained
    /// incident with reason, age, next check and review deadline, and marks
    /// the event's possible-duplicate risk for any later manual retry.
    pub fn record_outcome(
        &mut self,
        fence: &AttemptFence,
        outcome: Outcome,
        now_ms: u64,
    ) -> Result<AttemptRecord, CoreError> {
        let (state, note) = outcome.state_and_note();
        let record = self.transition(fence, now_ms, |record| {
            if record.state != AttemptState::Invoking {
                return Err(CoreError::Fence(format!(
                    "attempt {} is {}, not invoking",
                    fence.attempt_seq,
                    record.state.as_str()
                )));
            }
            Ok((state, Some(note)))
        })?;
        if state == AttemptState::OutcomeUnknown {
            let reason = match &outcome {
                Outcome::OutcomeUnknown { reason } => reason.clone(),
                _ => unreachable!("state checked above"),
            };
            self.open_incident(
                &fence.publisher,
                &fence.event_id,
                "unknown_handoff",
                &reason,
                now_ms,
                now_ms + 3_600_000,
                &[],
            )?;
        }
        Ok(record)
    }

    /// Expires reserved/invoking leases; returns how many were handled.
    ///
    /// A `reserved` attempt past its lease never invoked anything and is
    /// closed as reclaimable (the event stays pending and may be reserved
    /// again). An `invoking` attempt past its lease may have handed off:
    /// it becomes `outcome_unknown` with a retained incident and is never
    /// automatically retried.
    pub fn expire_attempt_leases(&mut self, now_ms: u64) -> Result<usize, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reclaimed = tx.execute(
            "UPDATE attempts SET state = 'closed',
                 note = 'lease expired before invocation; reclaimed', updated_ms = ?1
             WHERE state = 'reserved' AND lease_expires_ms IS NOT NULL AND lease_expires_ms <= ?1",
            params![now_ms as i64],
        )?;
        let mut unknown_rows = tx.prepare(
            "SELECT attempt_seq, publisher_id, event_id FROM attempts
             WHERE state = 'invoking' AND lease_expires_ms IS NOT NULL AND lease_expires_ms <= ?1",
        )?;
        let expired: Vec<(i64, String, String)> = unknown_rows
            .query_map(params![now_ms as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        drop(unknown_rows);
        for (seq, publisher, event) in &expired {
            tx.execute(
                "UPDATE attempts SET state = 'outcome_unknown',
                     note = 'invoking lease expired; possible handoff', updated_ms = ?1
                 WHERE attempt_seq = ?2",
                params![now_ms as i64, seq],
            )?;
            tx.execute(
                "INSERT INTO incidents
                     (incident_seq, publisher_id, event_id, kind, reason, state,
                      created_ms, updated_ms, next_check_ms, review_deadline_ms,
                      blocked_dependents, resolution)
                 VALUES (
                   (SELECT value FROM counters WHERE name = 'incident_seq') + 1,
                   ?1, ?2, 'unknown_handoff',
                   'invoking lease expired; effect cannot be established', 'open',
                   ?3, ?3, ?3, ?3 + 3600000, '[]', NULL)",
                params![publisher, event, now_ms as i64],
            )?;
            tx.execute(
                "UPDATE counters SET value = value + 1 WHERE name = 'incident_seq'",
                [],
            )?;
        }
        tx.commit()?;
        Ok(reclaimed + expired.len())
    }

    /// Opens (or refreshes) a retained incident for an event.
    ///
    /// Incidents carry reason, age (created/updated), next check, review
    /// deadline and blocked dependents; they are the operator-visible
    /// surface for everything not silently absorbed.
    pub fn open_incident(
        &mut self,
        publisher: &str,
        event_id: &str,
        kind: &str,
        reason: &str,
        now_ms: u64,
        review_deadline_ms: u64,
        blocked_dependents: &[String],
    ) -> Result<u64, CoreError> {
        let dependents = serde_json::to_string(blocked_dependents).map_err(|error| {
            CoreError::Storage(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
        })?;
        self.connection.execute(
            "INSERT INTO incidents
                 (incident_seq, publisher_id, event_id, kind, reason, state,
                  created_ms, updated_ms, next_check_ms, review_deadline_ms,
                  blocked_dependents, resolution)
             VALUES (
               (SELECT value FROM counters WHERE name = 'incident_seq') + 1,
               ?1, ?2, ?3, ?4, 'open', ?5, ?5, ?5, ?6, ?7, NULL)",
            params![
                publisher,
                event_id,
                kind,
                reason,
                now_ms as i64,
                review_deadline_ms as i64,
                dependents
            ],
        )?;
        self.connection.execute(
            "UPDATE counters SET value = value + 1 WHERE name = 'incident_seq'",
            [],
        )?;
        let seq: i64 = self.connection.query_row(
            "SELECT value FROM counters WHERE name = 'incident_seq'",
            [],
            |row| row.get(0),
        )?;
        Ok(seq as u64)
    }

    /// Resolves an open incident with positive evidence, or records an
    /// audited disposition.
    ///
    /// `resolution` states the positive fact (exact-address/content
    /// evidence) or the audited decision; it never merely cites silence.
    pub fn resolve_incident(
        &mut self,
        incident_seq: u64,
        resolution: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let changed = self.connection.execute(
            "UPDATE incidents SET state = 'resolved', resolution = ?1, updated_ms = ?2
             WHERE incident_seq = ?3 AND state = 'open'",
            params![resolution, now_ms as i64, incident_seq as i64],
        )?;
        if changed == 0 {
            return Err(CoreError::Fence(format!(
                "incident {incident_seq} is not open"
            )));
        }
        Ok(())
    }

    /// Records an audited manual authorization for another attempt of the
    /// same event after a possible hand-off.
    ///
    /// The possible-duplicate risk stays on the incident forever; this only
    /// unblocks reservation, it never replays anything by itself.
    pub fn authorize_manual_retry(
        &mut self,
        publisher: &str,
        event_id: &str,
        audit_note: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let changed = self.connection.execute(
            "UPDATE incidents SET resolution = ?1, updated_ms = ?2,
                 state = 'disposed'
             WHERE publisher_id = ?3 AND event_id = ?4
               AND kind = 'unknown_handoff' AND state = 'open'",
            params![
                format!("manual retry authorized: {audit_note}"),
                now_ms as i64,
                publisher,
                event_id
            ],
        )?;
        if changed == 0 {
            return Err(CoreError::Fence(format!(
                "no open unknown-handoff incident for {publisher}/{event_id}"
            )));
        }
        Ok(())
    }

    /// Lists open incidents (operator-visible recovery state).
    ///
    /// Ordered by next check; newest first within the same deadline.
    pub fn open_incidents(&self) -> Result<Vec<OpenIncident>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT incident_seq, publisher_id, event_id, kind, reason, created_ms,
                    updated_ms, next_check_ms, review_deadline_ms, blocked_dependents
             FROM incidents WHERE state = 'open' ORDER BY next_check_ms, incident_seq DESC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(OpenIncident {
                    incident_seq: row.get::<_, i64>(0)? as u64,
                    publisher: row.get(1)?,
                    event_id: row.get(2)?,
                    kind: row.get(3)?,
                    reason: row.get(4)?,
                    created_ms: row.get::<_, i64>(5)? as u64,
                    updated_ms: row.get::<_, i64>(6)? as u64,
                    next_check_ms: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                    review_deadline_ms: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                    blocked_dependents: row.get(9)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Sets or clears the durable no-wake policy for one recipient.
    ///
    /// The policy covers auto AND message: while set, reservation refuses
    /// with the recorded reason; existing already-possible effects are
    /// never undone.
    pub fn set_no_wake(
        &mut self,
        recipient: &str,
        no_wake: bool,
        reason: Option<&str>,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        if no_wake {
            self.connection.execute(
                "INSERT INTO recipient_policies (recipient, no_wake, reason, set_ms)
                 VALUES (?1, 1, ?2, ?3)
                 ON CONFLICT (recipient) DO UPDATE
                   SET no_wake = 1, reason = ?2, set_ms = ?3",
                params![recipient, reason, now_ms as i64],
            )?;
        } else {
            self.connection.execute(
                "DELETE FROM recipient_policies WHERE recipient = ?1",
                params![recipient],
            )?;
        }
        Ok(())
    }

    /// Reads the newest attempt record for an event, if any.
    pub fn latest_attempt(
        &self,
        publisher: &str,
        event_id: &str,
    ) -> Result<Option<AttemptRecord>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT attempt_seq, state, effective_mode, manifest_hash, lease_expires_ms,
                    created_ms, updated_ms, note
             FROM attempts WHERE publisher_id = ?1 AND event_id = ?2
             ORDER BY attempt_seq DESC LIMIT 1",
        )?;
        let row = statement
            .query_row(params![publisher, event_id], |row| {
                Ok(attempt_from_row(
                    row.get::<_, i64>(0)? as u64,
                    publisher.to_string(),
                    event_id.to_string(),
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    row.get::<_, i64>(5)? as u64,
                    row.get::<_, i64>(6)? as u64,
                    row.get(7)?,
                ))
            })
            .optional()?;
        Ok(row)
    }

    /// Applies one fenced transition inside a transaction.
    ///
    /// The closure receives the current record and returns the new state
    /// plus an optional note; fence mismatch and state mismatch refuse.
    fn transition(
        &mut self,
        fence: &AttemptFence,
        now_ms: u64,
        change: impl FnOnce(&AttemptRecord) -> Result<(AttemptState, Option<String>), CoreError>,
    ) -> Result<AttemptRecord, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(
            String,
            String,
            String,
            String,
            Option<i64>,
            i64,
            i64,
            Option<String>,
        )> = tx
            .query_row(
                "SELECT publisher_id, event_id, state, effective_mode, lease_expires_ms,
                        created_ms, updated_ms, note
                 FROM attempts WHERE attempt_seq = ?1",
                params![fence.attempt_seq as i64],
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
                    ))
                },
            )
            .optional()?;
        let Some((stored_publisher, stored_event, state, mode, lease, created, updated, note)) =
            current
        else {
            return Err(CoreError::Fence(format!(
                "no such attempt {}",
                fence.attempt_seq
            )));
        };
        if stored_publisher != fence.publisher || stored_event != fence.event_id {
            return Err(CoreError::Fence(format!(
                "fence mismatch on attempt {}: stored {stored_publisher}/{stored_event}",
                fence.attempt_seq
            )));
        }
        let mut record = attempt_from_row(
            fence.attempt_seq,
            fence.publisher.clone(),
            fence.event_id.clone(),
            state,
            mode,
            String::new(),
            lease.map(|v| v as u64),
            created as u64,
            updated as u64,
            note,
        );
        // manifest_hash re-read separately to keep the row tuple flat.
        record.manifest_hash = tx.query_row(
            "SELECT manifest_hash FROM attempts WHERE attempt_seq = ?1",
            params![fence.attempt_seq as i64],
            |row| row.get(0),
        )?;
        let (new_state, new_note) = change(&record)?;
        let merged_note = match (record.note, new_note) {
            (_, Some(note)) => Some(note),
            (note, None) => note,
        };
        tx.execute(
            "UPDATE attempts SET state = ?1, note = ?2, updated_ms = ?3
             WHERE attempt_seq = ?4",
            params![
                new_state.as_str(),
                merged_note,
                now_ms as i64,
                fence.attempt_seq as i64
            ],
        )?;
        tx.commit()?;
        Ok(AttemptRecord {
            state: new_state,
            note: merged_note,
            updated_ms: now_ms,
            ..record
        })
    }

    /// Checks whether the predecessor's newest attempt carries positive or
    /// explicitly-refused evidence (acceptance, hook submission,
    /// known-unsent or permanent refusal).
    ///
    /// A pending, reserved, invoking, held, unknown or absent attempt is
    /// not resolution; `outcome_unknown` additionally leaves an incident
    /// that the review path owns.
    fn predecessor_attempt_resolved(
        tx: &Connection,
        publisher: &str,
        predecessor_id: &str,
    ) -> Result<bool, CoreError> {
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM attempts WHERE publisher_id = ?1 AND event_id = ?2
                 ORDER BY attempt_seq DESC LIMIT 1",
                params![publisher, predecessor_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(matches!(
            state.as_deref(),
            Some("native_accepted")
                | Some("hook_submitted")
                | Some("known_unsent")
                | Some("permanent_refusal")
        ))
    }

    /// Reads the canonical recipient of a stored event.
    fn recipient_of(
        connection: &Connection,
        publisher: &str,
        event_id: &str,
    ) -> Result<String, CoreError> {
        connection
            .query_row(
                "SELECT recipient FROM events WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, event_id],
                |row| row.get(0),
            )
            .map_err(CoreError::from)
    }
}

/// One open incident as exposed to operators and status surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenIncident {
    /// Incident number.
    pub incident_seq: u64,
    /// Publisher of the affected event.
    pub publisher: String,
    /// Affected event id.
    pub event_id: String,
    /// Incident kind (unknown_handoff, held, ...).
    pub kind: String,
    /// Why the incident exists; never silence.
    pub reason: String,
    /// When the incident was opened (Unix epoch milliseconds).
    pub created_ms: u64,
    /// Last update (age evidence).
    pub updated_ms: u64,
    /// Next reconciliation check deadline, if scheduled.
    pub next_check_ms: Option<u64>,
    /// Human review deadline, if the kind requires it.
    pub review_deadline_ms: Option<u64>,
    /// JSON array of blocked dependent event ids.
    pub blocked_dependents: String,
}

/// Builds an [`AttemptRecord`] from raw stored columns.
///
/// Keeps row-mapping in one place; strict parsing throughout.
fn attempt_from_row(
    attempt_seq: u64,
    publisher: String,
    event_id: String,
    state: String,
    mode: String,
    manifest_hash: String,
    lease_expires_ms: Option<u64>,
    created_ms: u64,
    updated_ms: u64,
    note: Option<String>,
) -> AttemptRecord {
    AttemptRecord {
        fence: AttemptFence {
            attempt_seq,
            publisher,
            event_id,
        },
        state: AttemptState::parse(&state).expect("storage wrote a known attempt state"),
        effective_mode: match mode.as_str() {
            "inject" => EffectiveMode::Inject,
            _ => EffectiveMode::Message,
        },
        manifest_hash,
        lease_expires_ms,
        created_ms,
        updated_ms,
        note,
    }
}

/// Resolves the effective mode for one attempt from the requested mode and
/// the recipient's observed lifecycle.
///
/// `inject` and `message` stay themselves; `auto` selects inject while
/// active and message while inactive. `Unknown` (disconnected, not loaded,
/// unobservable) never resolves: the caller must hold, never wake.
pub fn resolve_mode(requested: Mode, lifecycle: Lifecycle) -> Option<EffectiveMode> {
    match (requested, lifecycle) {
        (Mode::Inject, _) => Some(EffectiveMode::Inject),
        (Mode::Message, _) => Some(EffectiveMode::Message),
        (Mode::Auto, Lifecycle::Active) => Some(EffectiveMode::Inject),
        (Mode::Auto, Lifecycle::Inactive) => Some(EffectiveMode::Message),
        (Mode::Auto, Lifecycle::Unknown) => None,
    }
}

/// One in-memory dispatch drive over a carrier substitute.
///
/// Full sequence: reserve (fenced, lease-bound) -> resolve auto from the
/// carrier's lifecycle observation -> persist `invoking` BEFORE any
/// hand-off -> one carrier send -> record the evidence-tier outcome. Never
/// both paths for one attempt; an unresolvable lifecycle or a paused
/// recipient releases the reservation (never invoked, safely reclaimable)
/// and returns a hold; an unknown carrier result records `outcome_unknown`
/// and an incident. The manifest hash is the frozen identity of what is
/// handed over; `frame` supplies the bytes.
pub fn dispatch_one(
    storage: &mut Storage,
    carrier: &mut dyn DispatchCarrier,
    envelope: &Envelope,
    frame: &dyn Fn(&Envelope, EffectiveMode) -> Result<String, CoreError>,
    now_ms: u64,
    lease_ms: u64,
) -> Result<DispatchResult, CoreError> {
    let publisher = envelope.publisher.as_str();
    let event_id = envelope.event_id.as_str();
    let manifest_hash = envelope.envelope_hash().as_str().to_string();

    let lifecycle = carrier
        .observe(&envelope.recipient)
        .unwrap_or(Lifecycle::Unknown);
    let Some(effective_mode) = resolve_mode(envelope.mode, lifecycle) else {
        // Hold visibly: release the reservation untouched and surface the
        // reason as a retained incident. Nothing was invoked.
        storage.open_incident(
            publisher,
            event_id,
            "held_unknown_lifecycle",
            "recipient lifecycle unknown; no invocation attempted",
            now_ms,
            now_ms + 3_600_000,
            &[],
        )?;
        return Ok(DispatchResult {
            state: AttemptState::Closed,
            effective_mode: EffectiveMode::Message,
            possibly_handed_off: false,
        });
    };

    let reservation = storage.reserve_attempt(
        publisher,
        event_id,
        effective_mode,
        &manifest_hash,
        now_ms,
        lease_ms,
    )?;
    let invoking = storage.mark_invoking(&reservation.fence, now_ms)?;
    let framed = frame(envelope, effective_mode)?;
    let outcome = match carrier.send(effective_mode, &manifest_hash, &framed) {
        CarrierOutcome::Accepted { evidence } => Outcome::NativeAccepted { evidence },
        CarrierOutcome::Held { recheck_ms } => Outcome::NativeHeld { recheck_ms },
        CarrierOutcome::Refused { reason } => Outcome::PermanentRefusal { reason },
        CarrierOutcome::Unknown { reason } => Outcome::OutcomeUnknown { reason },
    };
    let final_record = storage.record_outcome(&invoking.fence, outcome, now_ms)?;
    Ok(DispatchResult {
        state: final_record.state,
        effective_mode,
        possibly_handed_off: true,
    })
}

/// One selected pending event for dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// Publisher of the event.
    pub publisher: String,
    /// Event id.
    pub event_id: String,
    /// Policy class name (keep_all / latest / batch).
    pub policy_class: String,
}

impl Storage {
    /// Selects the next dispatchable pending events for one recipient with
    /// keep_all priority.
    ///
    /// `keep_all` events (independent completions, commands, questions,
    /// decisions) are returned before replaceable snapshots so a
    /// diagnostics flood cannot starve critical traffic; within the same
    /// class, acceptance order decides. Superseded and expired events are
    /// never selected, and events with an open attempt are filtered by the
    /// reservation check when dispatch actually runs.
    pub fn next_pending(
        &self,
        recipient: &str,
        limit: usize,
    ) -> Result<Vec<PendingEvent>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT publisher_id, event_id, policy_class FROM events
             WHERE state = 'pending' AND recipient = ?1
             ORDER BY CASE policy_class WHEN 'keep_all' THEN 0 ELSE 1 END,
                      acceptance_seq
             LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![recipient, limit as i64], |row| {
                Ok(PendingEvent {
                    publisher: row.get(0)?,
                    event_id: row.get(1)?,
                    policy_class: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Drops payload bytes of old terminal events, keeping dedup identity.
    ///
    /// Only `superseded` and `expired` (terminal, resolved dispositions)
    /// events beyond the newest `keep_newest` per class lose their
    /// envelope bytes; the row, frozen hash and state remain so identical
    /// replay still returns the original receipt and dedup history is
    /// never evicted. Returns how many payloads were compacted.
    pub fn compact_payloads(&mut self, keep_newest: usize) -> Result<usize, CoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let compacted = tx.execute(
            "UPDATE events SET envelope_json = x''
             WHERE state IN ('superseded','expired') AND length(envelope_json) > 0
               AND acceptance_seq < COALESCE((
                 SELECT MIN(s.acceptance_seq) FROM (
                   SELECT acceptance_seq FROM events e
                   WHERE e.state IN ('superseded','expired')
                   ORDER BY e.acceptance_seq DESC LIMIT ?1
                 ) s
               ), 9223372036854775807)",
            params![keep_newest as i64],
        )?;
        tx.commit()?;
        Ok(compacted)
    }
}
