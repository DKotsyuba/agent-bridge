//! Evidence tiers, retained incidents and audited operator recovery.
//!
//! The core is the single source of truth for everything an operator or a
//! status surface shows: incidents, their age, deadlines, responsible
//! source and blocked dependents are computed from the same rows dispatch
//! writes, never copied into a second store. Recovery after an uncertain
//! hand-off is always an explicit, audited decision on the *same* event —
//! a manual retry that records the possible duplicate risk, a disposition
//! that releases dependents without claiming delivery, or positive late
//! evidence that settles the uncertainty without another send. Nothing in
//! this module re-sends anything by itself.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::dispatch::{
    AttemptState, EffectiveMode, Outcome, apply_outcome, load_attempt, release_reservation,
};
use crate::storage::{Storage, bump_counter, corrupt, count, delivery, from_sql, to_sql};
use crate::types::{
    CoreError, Kind, Metadata, Mode, NativeAddress, PublisherId, StreamId, validate_metadata,
};

/// How long a new incident waits for review before it is overdue.
const REVIEW_WINDOW_MS: u64 = 3_600_000;

/// Interval between reconciliation checks of an open incident.
const CHECK_INTERVAL_MS: u64 = 300_000;

/// How long a recipient may stay held before the hold becomes an incident.
const HOLD_INCIDENT_AFTER_MS: u64 = 600_000;

/// Largest number of rows one maintenance step handles in a transaction.
const MAINTENANCE_BATCH: i64 = 500;

/// Largest stored length of free-form evidence and audit text.
const MAX_TEXT_BYTES: usize = 512;

/// Bounds free-form text to [`MAX_TEXT_BYTES`] at a character boundary.
///
/// History must stay bounded however large a carrier's message is; the
/// start of the text is kept.
pub(crate) fn bound_text(text: &str) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text.to_string();
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// Validates operator-supplied text: non-empty, bounded, no controls.
fn operator_text(field: &str, value: &str) -> Result<(), CoreError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(CoreError::InvalidEnvelope(format!(
            "{field} must be 1 to 256 bytes without control characters"
        )));
    }
    Ok(())
}

/// Per-event delivery state as exposed to status surfaces.
///
/// Separate from custody: an event is `Unhanded` until some path may have
/// taken it, and only `Accepted` / `HookSubmitted` carry positive handoff
/// evidence; `Review` is an unresolved possible hand-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Never handed to any path; eligible once its conditions hold.
    Unhanded,
    /// Frozen into a reserved attempt that has not invoked.
    Reserved,
    /// An attempt is invoking; a hand-off may exist.
    Invoking,
    /// Held by the native side or written without a receipt yet.
    Held,
    /// Possible hand-off with an unresolved outcome; manual resolution.
    Review,
    /// Native queue or inbox accepted it.
    Accepted,
    /// A hook payload was handed out.
    HookSubmitted,
    /// Permanently refused before acceptance (incident retained).
    Refused,
    /// Closed by an audited operator disposition; no further automatic Core dispatch.
    /// A prior possible hand-off is not undone or disproved, and processing is not proved.
    Disposed,
}

impl DeliveryState {
    /// Parses the storage text form strictly.
    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            delivery::UNHANDED => Ok(DeliveryState::Unhanded),
            delivery::RESERVED => Ok(DeliveryState::Reserved),
            delivery::INVOKING => Ok(DeliveryState::Invoking),
            delivery::HELD => Ok(DeliveryState::Held),
            delivery::REVIEW => Ok(DeliveryState::Review),
            delivery::ACCEPTED => Ok(DeliveryState::Accepted),
            delivery::HOOK_SUBMITTED => Ok(DeliveryState::HookSubmitted),
            delivery::REFUSED => Ok(DeliveryState::Refused),
            delivery::DISPOSED => Ok(DeliveryState::Disposed),
            other => Err(corrupt(format!("unknown delivery state {other:?}"))),
        }
    }
}

/// One distinct piece of delivery evidence.
///
/// Bridge persisting an event is implicit (the custody receipt). The tiers
/// below are never interchangeable: queue acceptance is not context, and
/// context is not business processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    /// The native queue or inbox accepted the hand-off.
    NativeAccepted,
    /// The native side holds the event non-terminally.
    NativeHeld,
    /// A hook payload was handed out after a full flush.
    HookEmitted,
    /// The write completed but no receipt exists yet.
    WrittenNoReceipt,
    /// The model context was observed to contain the payload.
    ContextObserved,
    /// The application processed the event.
    ApplicationProcessed,
    /// Positive proof that nothing was written.
    KnownUnsent,
    /// The addressed actor presented the recipient-only receipt token. A
    /// distinct, optional tier: it proves possession of that token and
    /// nothing more — never context, processing or business completion,
    /// and its absence never causes a repeat. Recorded as an annotation; it
    /// does not settle an attempt.
    ReceiptTokenPossession,
    /// Permanent refusal before acceptance.
    Refused,
    /// The outcome could not be established.
    Unknown,
}

impl EvidenceTier {
    /// Storage text form.
    pub const fn as_str(self) -> &'static str {
        match self {
            EvidenceTier::NativeAccepted => "native_accepted",
            EvidenceTier::NativeHeld => "native_held",
            EvidenceTier::HookEmitted => "hook_emitted",
            EvidenceTier::WrittenNoReceipt => "written_no_receipt",
            EvidenceTier::ContextObserved => "context_observed",
            EvidenceTier::ApplicationProcessed => "application_processed",
            EvidenceTier::KnownUnsent => "known_unsent",
            EvidenceTier::ReceiptTokenPossession => "receipt_token_possession",
            EvidenceTier::Refused => "refused",
            EvidenceTier::Unknown => "unknown",
        }
    }

    /// Parses the storage text form strictly.
    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "native_accepted" => Ok(EvidenceTier::NativeAccepted),
            "native_held" => Ok(EvidenceTier::NativeHeld),
            "hook_emitted" => Ok(EvidenceTier::HookEmitted),
            "written_no_receipt" => Ok(EvidenceTier::WrittenNoReceipt),
            "context_observed" => Ok(EvidenceTier::ContextObserved),
            "application_processed" => Ok(EvidenceTier::ApplicationProcessed),
            "known_unsent" => Ok(EvidenceTier::KnownUnsent),
            "receipt_token_possession" => Ok(EvidenceTier::ReceiptTokenPossession),
            "refused" => Ok(EvidenceTier::Refused),
            "unknown" => Ok(EvidenceTier::Unknown),
            other => Err(corrupt(format!("unknown evidence tier {other:?}"))),
        }
    }
}

/// What recording late evidence did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceEffect {
    /// The same tier was already recorded for the attempt; nothing changed.
    AlreadyRecorded,
    /// The evidence was kept; the attempt no longer owns the event (or has
    /// already settled), so its delivery state is unchanged.
    Recorded,
    /// The evidence settled a held or uncertain attempt; the event's
    /// delivery state is now the carried value.
    Applied(DeliveryState),
}

/// Lifecycle of a retained incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    /// Needs reconciliation or a human decision.
    Open,
    /// Settled by positive evidence.
    Resolved,
    /// Closed by a manual retry authorization with recorded duplicate risk.
    Authorized,
    /// Closed by an audited disposition.
    Disposed,
}

impl IncidentState {
    /// Parses the storage text form strictly.
    fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "open" => Ok(IncidentState::Open),
            "resolved" => Ok(IncidentState::Resolved),
            "authorized" => Ok(IncidentState::Authorized),
            "disposed" => Ok(IncidentState::Disposed),
            other => Err(corrupt(format!("unknown incident state {other:?}"))),
        }
    }
}

/// One retained incident, with everything an operator needs to act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentView {
    /// Incident number.
    pub incident_seq: u64,
    /// Publisher of the affected event.
    pub publisher: String,
    /// Affected event id.
    pub event_id: String,
    /// Attempt the incident arose from, when one exists.
    pub attempt_seq: Option<u64>,
    /// Incident class: `unknown_handoff`, `held_overdue`, `receipt_overdue`,
    /// `permanent_refusal`, `retries_exhausted`, `recipient_held`,
    /// `predecessor_missing` (a dependent waits for a predecessor that was
    /// never accepted), `predecessor_expired` (the awaited predecessor
    /// expired before delivery; only an audited waiver or disposition
    /// releases the dependent), `storage_integrity`, `migrated_unverified` or
    /// `lineage_authority_lost` (an unhanded event whose producer lost the
    /// stream lineage through an audited transfer or an ambiguous
    /// migration).
    pub kind: String,
    /// Current state.
    pub state: IncidentState,
    /// Why the incident exists; never silence.
    pub reason: String,
    /// When the incident was opened (Unix epoch milliseconds).
    pub created_ms: u64,
    /// Last update (Unix epoch milliseconds).
    pub updated_ms: u64,
    /// Milliseconds since `created_ms` at the time of the read.
    pub age_ms: u64,
    /// Next reconciliation check, when scheduled.
    pub next_check_ms: Option<u64>,
    /// Human review deadline, when the kind requires one.
    pub review_deadline_ms: Option<u64>,
    /// Who is responsible for resolving it (source and operator).
    pub responsible: String,
    /// Event ids blocked behind this event, computed from live state.
    pub blocked_dependents: Vec<String>,
    /// Whether a repeat of this event carries a recorded duplicate risk.
    pub duplicate_risk: bool,
    /// How it was settled, once it is no longer open.
    pub resolution: Option<String>,
}

/// One finite incident-scan page, ordered by immutable incident number.
///
/// Row state, age and dependents are live facts, not a snapshot. New numbers
/// above `through_seq` belong to a subsequent scan; reads have no effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentPage {
    /// At most 200 incident views in strictly increasing sequence order.
    pub incidents: Vec<IncidentView>,
    /// Highest retained number captured at the start of this finite scan.
    pub through_seq: u64,
    /// Last returned number when more matching rows remain; otherwise absent.
    pub next_after_seq: Option<u64>,
}

impl IncidentPage {
    /// Rejects out-of-range, unordered, over-cap or inconsistent decoded pages.
    ///
    /// Request-specific lower bounds, filter and limit are checked by the client.
    pub fn validate(&self) -> Result<(), CoreError> {
        check_ranges(&[self.through_seq])?;
        if self.incidents.len() > 200 {
            return Err(CoreError::InvalidEnvelope(
                "incident page exceeds 200 rows".into(),
            ));
        }
        let mut previous = 0;
        for incident in &self.incidents {
            incident.validate()?;
            if incident.incident_seq <= previous || incident.incident_seq > self.through_seq {
                return Err(CoreError::InvalidEnvelope(
                    "incident page is out of sequence bounds".into(),
                ));
            }
            previous = incident.incident_seq;
        }
        if self.next_after_seq.is_some_and(|next| {
            self.incidents.is_empty() || next != previous || next >= self.through_seq
        }) {
            return Err(CoreError::InvalidEnvelope(
                "incident page continuation is inconsistent".into(),
            ));
        }
        Ok(())
    }
}

/// Exact retained event facts for protected operator inspection.
///
/// This owns no payload bytes and cannot expire, collect or recall anything.
/// Custody dispositions and storage eligibility never establish native recall.
/// Deserialized receipts/evidence retain their existing validation and bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionView {
    /// Original durable identity/hash/acceptance and current custody disposition.
    pub receipt: crate::storage::CustodyReceipt,
    /// Existing bounded delivery evidence; absent for ordinary unhanded work.
    pub delivery: Option<DeliveryEvidence>,
    /// Original absolute expiry in Unix milliseconds, absent when never set.
    pub expires_at_ms: Option<u64>,
    /// Current serialized-envelope storage bytes, without disclosing them.
    pub envelope_bytes: u64,
    /// Zero envelope bytes with the immutable dedup row/hash still retained.
    pub payload_compacted: bool,
    /// Nonempty terminal unhanded payload passes the logical GC state guard.
    ///
    /// The keep-newest retention policy may still retain an eligible payload.
    pub gc_eligible: bool,
    /// Stored revision of this latest event's full scope, even after compaction.
    ///
    /// Absent for non-latest events or when no watermark was recorded.
    pub latest_watermark: Option<u64>,
}

impl RetentionView {
    /// Rejects invalid ranges and contradictory decoded compaction/GC flags.
    ///
    /// No flag can describe handed or pending work as compacted or GC-eligible.
    pub fn validate(&self) -> Result<(), CoreError> {
        let mut numbers = vec![self.envelope_bytes];
        numbers.extend(self.expires_at_ms);
        numbers.extend(self.latest_watermark);
        check_ranges(&numbers)?;
        let terminal = matches!(
            self.receipt.state,
            crate::storage::EventState::Superseded | crate::storage::EventState::Expired
        );
        let unhanded = self
            .delivery
            .as_ref()
            .is_none_or(|view| view.delivery == DeliveryState::Unhanded);
        if self.expires_at_ms == Some(0)
            || self.latest_watermark == Some(0)
            || self.payload_compacted != (self.envelope_bytes == 0)
            || (self.payload_compacted && !(terminal && unhanded))
            || self.gc_eligible != (terminal && unhanded && self.envelope_bytes > 0)
        {
            return Err(CoreError::InvalidEnvelope(
                "retention facts are inconsistent".into(),
            ));
        }
        Ok(())
    }
}

/// One entry of an event's evidence log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Attempt the evidence concerns.
    pub attempt_seq: u64,
    /// Evidence tier.
    pub tier: EvidenceTier,
    /// What was observed (bounded, never a secret).
    pub detail: String,
    /// When it was recorded (Unix epoch milliseconds).
    pub at_ms: u64,
}

/// Summary of the newest attempt of an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSummary {
    /// Attempt number.
    pub attempt_seq: u64,
    /// Attempt state.
    pub state: AttemptState,
    /// Requested mode of the head event.
    pub requested_mode: Mode,
    /// Effective path.
    pub effective_mode: EffectiveMode,
    /// Frozen actor text.
    pub actor: String,
    /// Frozen endpoint epoch.
    pub endpoint_epoch: u64,
    /// Frozen manifest hash.
    pub manifest_hash: String,
    /// Hand-off deadline.
    pub deadline_ms: u64,
    /// Whether this attempt repeats a possible hand-off by manual decision.
    pub duplicate_risk: bool,
}

/// Compact view of an event's open incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentSummary {
    /// Incident number.
    pub incident_seq: u64,
    /// Incident class.
    pub kind: String,
    /// Why it exists.
    pub reason: String,
    /// Review deadline, when set.
    pub review_deadline_ms: Option<u64>,
}

/// The delivery evidence of one event, as exposed to its publisher.
///
/// Custody is reported separately by the receipt. Absent tiers mean
/// "not available", never delivered: `tiers` lists exactly what was
/// recorded. The first three fields keep their original wire names and
/// meaning for early consumers; everything after them is additive and
/// optional on the wire. Deserialization revalidates every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDeliveryEvidence")]
pub struct DeliveryEvidence {
    /// State name of the newest attempt, or `none` before any attempt.
    pub attempt_state: String,
    /// Effective mode name of the newest attempt, or `none`.
    pub effective_mode: String,
    /// Evidence/audit note of the newest attempt, when one was recorded.
    pub note: Option<String>,
    /// Per-event delivery state.
    pub delivery: DeliveryState,
    /// Automatic attempts made so far.
    pub attempts_made: u32,
    /// Newest attempt, when one exists.
    pub attempt: Option<AttemptSummary>,
    /// Recorded evidence tiers in order (bounded to the newest entries).
    pub tiers: Vec<EvidenceEntry>,
    /// The open incident, when one exists.
    pub incident: Option<IncidentSummary>,
    /// Visible reason the recipient is held, while the event waits.
    pub hold_reason: Option<String>,
    /// Predecessor this event still waits for.
    pub blocked_by: Option<String>,
}

/// Unvalidated wire shape of [`DeliveryEvidence`].
#[derive(Deserialize)]
struct RawDeliveryEvidence {
    /// Legacy attempt state name as received.
    attempt_state: String,
    /// Legacy effective mode name as received.
    effective_mode: String,
    /// Legacy note as received.
    note: Option<String>,
    /// Delivery state as received; absent on early daemons.
    #[serde(default)]
    delivery: Option<DeliveryState>,
    /// Attempt count as received.
    #[serde(default)]
    attempts_made: u32,
    /// Newest attempt as received.
    #[serde(default)]
    attempt: Option<AttemptSummary>,
    /// Evidence tiers as received.
    #[serde(default)]
    tiers: Vec<EvidenceEntry>,
    /// Open incident as received.
    #[serde(default)]
    incident: Option<IncidentSummary>,
    /// Hold reason as received.
    #[serde(default)]
    hold_reason: Option<String>,
    /// Awaited predecessor as received.
    #[serde(default)]
    blocked_by: Option<String>,
}

impl TryFrom<RawDeliveryEvidence> for DeliveryEvidence {
    type Error = CoreError;

    /// Accepts only known attempt and mode names, a bounded tier list and
    /// bounded text fields.
    fn try_from(raw: RawDeliveryEvidence) -> Result<Self, CoreError> {
        if raw.attempt_state != "none" {
            AttemptState::parse(&raw.attempt_state)?;
        }
        if raw.effective_mode != "none" {
            EffectiveMode::parse(&raw.effective_mode)?;
        }
        let oversized = |text: &Option<String>| text.as_ref().is_some_and(|t| t.len() > 4096);
        if raw.tiers.len() > 64
            || oversized(&raw.note)
            || oversized(&raw.hold_reason)
            || oversized(&raw.blocked_by)
        {
            return Err(CoreError::InvalidEnvelope(
                "delivery evidence exceeds its bounds".into(),
            ));
        }
        let mut numbers: Vec<u64> = raw
            .tiers
            .iter()
            .flat_map(|entry| [entry.attempt_seq, entry.at_ms])
            .collect();
        if let Some(attempt) = &raw.attempt {
            numbers.extend([
                attempt.attempt_seq,
                attempt.endpoint_epoch,
                attempt.deadline_ms,
            ]);
        }
        if let Some(incident) = &raw.incident {
            numbers.push(incident.incident_seq);
            numbers.extend(incident.review_deadline_ms);
        }
        check_ranges(&numbers)?;
        Ok(DeliveryEvidence {
            attempt_state: raw.attempt_state,
            effective_mode: raw.effective_mode,
            note: raw.note,
            delivery: raw.delivery.unwrap_or(DeliveryState::Unhanded),
            attempts_made: raw.attempts_made,
            attempt: raw.attempt,
            tiers: raw.tiers,
            incident: raw.incident,
            hold_reason: raw.hold_reason,
            blocked_by: raw.blocked_by,
        })
    }
}

/// Refuses numbers that could not have come from storage (above the
/// SQLite-safe bound), so a decoded status never carries a value that a
/// signed cast would have wrapped.
fn check_ranges(numbers: &[u64]) -> Result<(), CoreError> {
    if numbers.iter().any(|&n| n > crate::types::MAX_SQLITE_INT) {
        return Err(CoreError::InvalidEnvelope(
            "a decoded number is out of the supported range".into(),
        ));
    }
    Ok(())
}

impl IncidentView {
    /// Revalidates an incident decoded from the wire: identifiers, number
    /// ranges and bounded text and lists.
    pub fn validate(&self) -> Result<(), CoreError> {
        crate::types::PublisherId::new(self.publisher.clone())?;
        crate::types::EventId::new(self.event_id.clone())?;
        let mut numbers = vec![
            self.incident_seq,
            self.created_ms,
            self.updated_ms,
            self.age_ms,
        ];
        numbers.extend(self.attempt_seq);
        numbers.extend(self.next_check_ms);
        numbers.extend(self.review_deadline_ms);
        check_ranges(&numbers)?;
        if self.reason.len() > 4096
            || self.responsible.len() > 1024
            || self.kind.len() > 64
            || self.blocked_dependents.len() > 200
            || self
                .resolution
                .as_ref()
                .is_some_and(|text| text.len() > 4096)
        {
            return Err(CoreError::InvalidEnvelope(
                "incident exceeds its bounds".into(),
            ));
        }
        for dependent in &self.blocked_dependents {
            crate::types::EventId::new(dependent.clone())?;
        }
        Ok(())
    }
}

impl HoldView {
    /// Revalidates a hold decoded from the wire: a well-formed canonical
    /// recipient, number ranges and bounded text.
    pub fn validate(&self) -> Result<(), CoreError> {
        NativeAddress::parse(&self.recipient)?;
        check_ranges(&[self.since_ms, self.updated_ms])?;
        if self.reason.len() > 4096 {
            return Err(CoreError::InvalidEnvelope("hold exceeds its bounds".into()));
        }
        Ok(())
    }
}

/// One visible recipient hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldView {
    /// Canonical recipient address text.
    pub recipient: String,
    /// Why eligible work is held.
    pub reason: String,
    /// When the hold began.
    pub since_ms: u64,
    /// Last observation of the hold.
    pub updated_ms: u64,
}

/// What one maintenance pass changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaintenanceReport {
    /// Pending events marked expired.
    pub expired_events: usize,
    /// Uninvoked reservations returned to rotation.
    pub reclaimed_reservations: usize,
    /// Invoking attempts past their deadline, now unknown outcomes.
    pub unknown_handoffs: usize,
    /// Held or unreceipted attempts that became overdue incidents.
    pub overdue_rechecks: usize,
    /// New incidents raised for long recipient holds, predecessors that
    /// never arrived and dependents blocked behind an expired predecessor.
    pub escalated_holds: usize,
}

/// Opens or refreshes the one open incident of a kind for an event;
/// returns `true` when it was newly opened.
///
/// The partial unique index keeps at most one open incident per
/// `(publisher, event, kind)`, so repeated reconciliation is idempotent and
/// cannot flood the operator surface.
pub(crate) fn open_incident_in(
    tx: &Connection,
    publisher: &str,
    event_id: &str,
    attempt_seq: Option<u64>,
    kind: &str,
    reason: &str,
    now_ms: u64,
) -> Result<bool, CoreError> {
    let existed: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM incidents
                        WHERE publisher_id = ?1 AND event_id = ?2 AND kind = ?3 AND state = 'open')",
        params![publisher, event_id, kind],
        |row| row.get(0),
    )?;
    let seq = bump_counter(tx, "incident_seq")?;
    let now = to_sql(now_ms)?;
    tx.execute(
        "INSERT INTO incidents
             (incident_seq, publisher_id, event_id, attempt_seq, kind, reason, state,
              created_ms, updated_ms, next_check_ms, review_deadline_ms, responsible)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?7, ?8, ?9, ?10)
         ON CONFLICT (publisher_id, event_id, kind) WHERE state = 'open'
         DO UPDATE SET reason = excluded.reason, updated_ms = excluded.updated_ms,
                       attempt_seq = COALESCE(excluded.attempt_seq, attempt_seq)",
        params![
            to_sql(seq)?,
            publisher,
            event_id,
            attempt_seq.map(to_sql).transpose()?,
            kind,
            bound_text(reason),
            now,
            to_sql(now_ms.saturating_add(CHECK_INTERVAL_MS))?,
            to_sql(now_ms.saturating_add(REVIEW_WINDOW_MS))?,
            format!("source:{publisher}; operator"),
        ],
    )?;
    Ok(!existed)
}

/// Appends one evidence row; returns `false` when the same tier was
/// already recorded for the attempt.
pub(crate) fn record_evidence_row(
    tx: &Connection,
    publisher: &str,
    event_id: &str,
    attempt_seq: u64,
    tier: &str,
    detail: &str,
    now_ms: u64,
) -> Result<bool, CoreError> {
    let seq = bump_counter(tx, "evidence_seq")?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO evidence
             (evidence_seq, publisher_id, event_id, attempt_seq, tier, detail, at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            to_sql(seq)?,
            publisher,
            event_id,
            to_sql(attempt_seq)?,
            tier,
            bound_text(detail),
            to_sql(now_ms)?,
        ],
    )?;
    Ok(inserted == 1)
}

/// Identifies one stream lineage: the coalescing scope without the
/// publisher.
///
/// `recipient` is the canonical address text; `project` and `task` are
/// the declared scope values, empty when none. Two publishers publishing
/// `latest` snapshots into the same [`LineageScope`] are in one lineage:
/// the first authenticated producer owns it and any other is declined
/// until an audited [`Storage::transfer_lineage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageScope {
    /// Canonical recipient address text.
    pub recipient: String,
    /// Event kind.
    pub kind: String,
    /// Requested delivery mode name.
    pub mode: String,
    /// Declared project scope, empty when none.
    pub project: String,
    /// Declared task scope, empty when none.
    pub task: String,
    /// The authoritative stream id.
    pub stream: String,
}

/// One operator audit row, newest first, for verification surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Who performed the action (operator publisher id).
    pub actor: String,
    /// What was done (pause, resume, transfer_lineage, ...).
    pub action: String,
    /// Publisher the action concerns, when applicable.
    pub publisher_id: String,
    /// Event the action concerns, when applicable.
    pub event_id: String,
    /// The audited detail; never a credential.
    pub detail: String,
}

/// Appends an operator audit row.
fn audit(
    tx: &Connection,
    now_ms: u64,
    actor: &str,
    action: &str,
    publisher: &str,
    event_id: &str,
    detail: &str,
) -> Result<(), CoreError> {
    let seq = bump_counter(tx, "audit_seq")?;
    tx.execute(
        "INSERT INTO audit (audit_seq, at_ms, actor, action, publisher_id, event_id, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            to_sql(seq)?,
            to_sql(now_ms)?,
            actor,
            action,
            publisher,
            event_id,
            bound_text(detail),
        ],
    )?;
    Ok(())
}

/// Reads an event's delivery state, owning attempt and incident presence.
fn event_state(
    tx: &Connection,
    publisher: &str,
    event_id: &str,
) -> Result<(DeliveryState, Option<u64>), CoreError> {
    let row: Option<(String, Option<i64>)> = tx
        .query_row(
            "SELECT delivery, attempt_seq FROM events WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (state, owner) =
        row.ok_or_else(|| CoreError::Fence(format!("no such event {publisher}/{event_id}")))?;
    Ok((
        DeliveryState::parse(&state)?,
        owner.map(from_sql).transpose()?,
    ))
}

impl Storage {
    /// Records or clears the visible hold for a recipient on the message
    /// path (used when attestation fails before a reservation is possible).
    ///
    /// A hold is recorded only while eligible message-path work is waiting;
    /// otherwise any stale hold is cleared.
    pub fn record_hold(
        &mut self,
        recipient: &NativeAddress,
        reason: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let text = recipient.to_canonical_string();
        let tx = self.begin()?;
        let waiting: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM events
                            WHERE state = 'pending' AND delivery = 'unhanded' AND recipient = ?1
                              AND mode IN ('message', 'auto')
                              AND (expires_at_ms IS NULL OR expires_at_ms > ?2))",
            params![text, to_sql(now_ms)?],
            |row| row.get(0),
        )?;
        if waiting {
            tx.execute(
                "INSERT INTO recipient_holds (recipient, reason, since_ms, updated_ms)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT (recipient) DO UPDATE
                   SET reason = excluded.reason, updated_ms = excluded.updated_ms",
                params![text, bound_text(reason), to_sql(now_ms)?],
            )?;
        } else {
            tx.execute(
                "DELETE FROM recipient_holds WHERE recipient = ?1",
                params![text],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Lists visible recipient holds, oldest first (bounded by `limit`).
    pub fn holds(&self, limit: usize) -> Result<Vec<HoldView>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT recipient, reason, since_ms, updated_ms FROM recipient_holds
             ORDER BY since_ms LIMIT ?1",
        )?;
        let rows: Vec<(String, String, i64, i64)> = statement
            .query_map(params![to_sql(limit as u64)?], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(recipient, reason, since, updated)| {
                Ok(HoldView {
                    recipient,
                    reason,
                    since_ms: from_sql(since)?,
                    updated_ms: from_sql(updated)?,
                })
            })
            .collect()
    }

    /// Reads exact custody, expiry, payload and scoped-watermark storage facts.
    ///
    /// `publisher` and `event_id` use their existing validated identifier
    /// domains; an unaccepted key returns `None`. A local read transaction
    /// joins the existing receipt/evidence with envelope length and retained
    /// latest scope, including compacted rows. No payload bytes are loaded or
    /// returned. Legacy eight-field scopes read `watermarks`; a lifetime's
    /// nine-field scope must match its stored lifetime and reads only its
    /// full-key `scoped_watermarks` row. No scope is guessed or truncated.
    /// No expiry, GC, delivery or incident mutation occurs.
    /// Eligibility is only the existing terminal-unhanded nonempty guard;
    /// keep-newest may retain it and nothing here establishes native recall.
    /// Invalid identifiers, malformed retained scope or corrupt rows fail.
    pub fn retention(
        &self,
        publisher: &str,
        event_id: &str,
    ) -> Result<Option<RetentionView>, CoreError> {
        let publisher_id = PublisherId::new(publisher)?;
        let event = crate::types::EventId::new(event_id)?;
        let publisher = publisher_id.as_str();
        let event_id = event.as_str();
        let tx = self.connection.unchecked_transaction()?;
        let Some(receipt) = self.lookup(&publisher_id, &event)? else {
            return Ok(None);
        };
        let delivery = self.delivery_evidence(publisher, event_id)?;
        let (expiry, bytes, policy, scope, lifetime): (Option<i64>, i64, String, String, String) = tx.query_row(
            "SELECT expires_at_ms, length(envelope_json), policy_class, scope_key, delivery_scope_key
             FROM events WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        let latest_watermark = if policy == "latest" {
            let fields: Vec<_> = scope.split('\u{1f}').collect();
            if fields.len() != if lifetime.is_empty() { 8 } else { 9 }
                || fields[0] != publisher
                || fields[6] != "latest"
                || (!lifetime.is_empty() && fields[8] != lifetime)
            {
                return Err(corrupt("invalid retained latest scope".into()));
            }
            let revision: Option<i64> = if lifetime.is_empty() {
                tx.query_row(
                    "SELECT revision FROM watermarks
                 WHERE publisher_id = ?1 AND recipient = ?2 AND kind = ?3
                   AND mode = ?4 AND project = ?5 AND task = ?6 AND stream_id = ?7",
                    params![
                        fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[7]
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
            } else {
                tx.query_row(
                    "SELECT revision FROM scoped_watermarks WHERE scope_key = ?1",
                    params![scope],
                    |row| row.get(0),
                )
                .optional()?
            };
            revision.map(from_sql).transpose()?
        } else {
            None
        };
        let envelope_bytes = from_sql(bytes)?;
        let terminal = matches!(
            receipt.state,
            crate::storage::EventState::Superseded | crate::storage::EventState::Expired
        );
        let unhanded = delivery
            .as_ref()
            .is_none_or(|view| view.delivery == DeliveryState::Unhanded);
        let view = RetentionView {
            receipt,
            delivery,
            expires_at_ms: expiry.map(from_sql).transpose()?,
            envelope_bytes,
            payload_compacted: envelope_bytes == 0,
            gc_eligible: terminal && unhanded && envelope_bytes > 0,
            latest_watermark,
        };
        view.validate()?;
        tx.commit()?;
        Ok(Some(view))
    }

    /// Lists incidents, newest-deadline-first for open ones.
    ///
    /// With `include_closed` false only open incidents are returned, in
    /// check order. Age and blocked dependents are computed from live state
    /// at `now_ms`; the list is bounded by `limit`.
    pub fn incidents(
        &self,
        include_closed: bool,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<IncidentView>, CoreError> {
        self.incident_listing(include_closed, now_ms, limit, None)
    }

    /// Reads a bounded stable-number page without changing incident state.
    ///
    /// `after_seq` is exclusive and defaults to zero at the caller. An absent
    /// `through_seq` requires zero `after_seq` and captures the current highest
    /// retained number. Supplied bounds must be nonnegative SQLite integers,
    /// ordered and no higher than retained history. `limit` clamps to 1..200.
    /// Rows/filter/age/dependents are live within one read transaction; new
    /// numbers above the high-water bound wait for a subsequent scan. Errors
    /// reject invalid cursors, time or corrupt storage without mutation.
    pub fn incidents_page(
        &self,
        include_closed: bool,
        now_ms: u64,
        limit: usize,
        after_seq: u64,
        through_seq: Option<u64>,
    ) -> Result<IncidentPage, CoreError> {
        to_sql(now_ms)?;
        to_sql(after_seq)?;
        if let Some(through) = through_seq {
            to_sql(through)?;
        } else if after_seq != 0 {
            return Err(CoreError::InvalidEnvelope(
                "continuation requires through_seq".into(),
            ));
        }
        let tx = self.connection.unchecked_transaction()?;
        let high = from_sql(tx.query_row(
            "SELECT COALESCE(MAX(incident_seq), 0) FROM incidents",
            [],
            |row| row.get(0),
        )?)?;
        let through_seq = through_seq.unwrap_or(high);
        if after_seq > through_seq || through_seq > high {
            return Err(CoreError::InvalidEnvelope(
                "incident cursor exceeds scan bounds".into(),
            ));
        }
        let limit = limit.clamp(1, 200);
        let mut incidents = self.incident_listing(
            include_closed,
            now_ms,
            limit + 1,
            Some((after_seq, through_seq)),
        )?;
        let more = incidents.len() > limit;
        incidents.truncate(limit);
        let next_after_seq = more.then(|| incidents.last().expect("nonempty page").incident_seq);
        let page = IncidentPage {
            incidents,
            through_seq,
            next_after_seq,
        };
        page.validate()?;
        tx.commit()?;
        Ok(page)
    }

    /// Loads incident rows for legacy check order or a finite sequence window.
    ///
    /// `bounds` absent preserves legacy ordering; present selects strictly
    /// ascending numbers in its exclusive-lower/inclusive-upper range.
    /// `limit` bounds decoded rows; age uses `now_ms` and dependents remain
    /// bounded to 50. Invalid stored identifiers/ranges propagate as errors.
    fn incident_listing(
        &self,
        include_closed: bool,
        now_ms: u64,
        limit: usize,
        bounds: Option<(u64, u64)>,
    ) -> Result<Vec<IncidentView>, CoreError> {
        let order = if bounds.is_some() {
            "incident_seq"
        } else {
            "(state = 'open') DESC, next_check_ms, incident_seq"
        };
        let (after_seq, through_seq) = bounds.map_or((None, None), |(after, through)| {
            (Some(after), Some(through))
        });
        let filter = if include_closed {
            "1 = 1"
        } else {
            "state = 'open'"
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT incident_seq, publisher_id, event_id, attempt_seq, kind, state, reason,
                    created_ms, updated_ms, next_check_ms, review_deadline_ms, responsible,
                    duplicate_risk, resolution
             FROM incidents WHERE {filter}
               AND (?2 IS NULL OR incident_seq > ?2) AND (?3 IS NULL OR incident_seq <= ?3)
             ORDER BY {order} LIMIT ?1"
        ))?;
        /// One `incidents` row in `SELECT` order: incident number, publisher,
        /// event, attempt, kind, state, reason, created, updated, next check,
        /// review deadline, responsible parties, duplicate-risk flag and
        /// resolution. States are parsed into [`IncidentState`] afterwards.
        type Row = (
            i64,
            String,
            String,
            Option<i64>,
            String,
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
            String,
            i64,
            Option<String>,
        );
        let rows: Vec<Row> = statement
            .query_map(
                params![
                    to_sql(limit as u64)?,
                    after_seq.map(to_sql).transpose()?,
                    through_seq.map(to_sql).transpose()?
                ],
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
                    ))
                },
            )?
            .collect::<Result<_, _>>()?;
        let mut views = Vec::with_capacity(rows.len());
        for (
            seq,
            publisher,
            event_id,
            attempt,
            kind,
            state,
            reason,
            created,
            updated,
            next,
            deadline,
            responsible,
            risk,
            resolution,
        ) in rows
        {
            let created_ms = from_sql(created)?;
            views.push(IncidentView {
                incident_seq: from_sql(seq)?,
                blocked_dependents: self.blocked_dependents(&publisher, &event_id, 50)?,
                publisher,
                event_id,
                attempt_seq: attempt.map(from_sql).transpose()?,
                kind,
                state: IncidentState::parse(&state)?,
                reason,
                created_ms,
                updated_ms: from_sql(updated)?,
                age_ms: now_ms.saturating_sub(created_ms),
                next_check_ms: next.map(from_sql).transpose()?,
                review_deadline_ms: deadline.map(from_sql).transpose()?,
                responsible,
                duplicate_risk: risk != 0,
                resolution,
            });
        }
        Ok(views)
    }

    /// Lists open incidents (operator-visible recovery state), bounded.
    pub fn open_incidents(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<IncidentView>, CoreError> {
        self.incidents(false, now_ms, limit)
    }

    /// Lists events that wait for the given event, from live state.
    ///
    /// Direct dependents still unhanded and not waived, in acceptance order
    /// (bounded by `limit`); an uncertain command blocks exactly these.
    pub fn blocked_dependents(
        &self,
        publisher: &str,
        event_id: &str,
        limit: usize,
    ) -> Result<Vec<String>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT event_id FROM events
             WHERE publisher_id = ?1 AND predecessor = ?2 AND state = 'pending'
               AND delivery = 'unhanded' AND predecessor_waived = 0
             ORDER BY acceptance_seq LIMIT ?3",
        )?;
        let rows = statement
            .query_map(params![publisher, event_id, to_sql(limit as u64)?], |row| {
                row.get(0)
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Reads the delivery evidence of an event for its publisher.
    ///
    /// Returns `None` when the event was never accepted. Reports distinct
    /// tiers, the newest attempt, the open incident, the visible hold and
    /// the predecessor still awaited; none of it is a delivered flag. An old
    /// unhanded row in a retired lifetime reports a visible scope fence even
    /// when no recipient-wide hold exists; it cannot reenter dispatch.
    pub fn delivery_evidence(
        &self,
        publisher: &str,
        event_id: &str,
    ) -> Result<Option<DeliveryEvidence>, CoreError> {
        let row: Option<(String, i64, String, Option<String>, i64, bool)> = self
            .connection
            .query_row(
                "SELECT delivery, attempts_made, recipient, predecessor, predecessor_waived,
                     EXISTS (SELECT 1 FROM delivery_scopes s
                         WHERE s.producer = e.publisher_id AND s.scope_key = e.delivery_scope_key
                           AND s.closed_ms IS NOT NULL AND s.action = 'retire_unhanded')
                 FROM events e WHERE publisher_id = ?1 AND event_id = ?2",
                params![publisher, event_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((state, attempts, recipient, predecessor, waived, retired)) = row else {
            return Ok(None);
        };
        let state = DeliveryState::parse(&state)?;
        let latest = self.latest_attempt(publisher, event_id)?;
        let legacy_note = latest.as_ref().and_then(|record| record.note.clone());
        let attempt = latest.map(|record| AttemptSummary {
            attempt_seq: record.fence.attempt_seq,
            state: record.state,
            requested_mode: record.requested_mode,
            effective_mode: record.effective_mode,
            actor: record.actor,
            endpoint_epoch: record.fence.endpoint_epoch,
            manifest_hash: record.fence.manifest_hash,
            deadline_ms: record.deadline_ms,
            duplicate_risk: record.duplicate_risk,
        });
        let mut statement = self.connection.prepare(
            "SELECT attempt_seq, tier, detail, at_ms FROM (
                 SELECT evidence_seq, attempt_seq, tier, detail, at_ms FROM evidence
                 WHERE publisher_id = ?1 AND event_id = ?2
                 ORDER BY evidence_seq DESC LIMIT 64)
             ORDER BY evidence_seq",
        )?;
        let tier_rows: Vec<(i64, String, String, i64)> = statement
            .query_map(params![publisher, event_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<_, _>>()?;
        let tiers = tier_rows
            .into_iter()
            .map(|(attempt_seq, tier, detail, at)| {
                Ok(EvidenceEntry {
                    attempt_seq: from_sql(attempt_seq)?,
                    tier: EvidenceTier::parse(&tier)?,
                    detail,
                    at_ms: from_sql(at)?,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let incident = self
            .connection
            .query_row(
                "SELECT incident_seq, kind, reason, review_deadline_ms FROM incidents
                 WHERE publisher_id = ?1 AND event_id = ?2 AND state = 'open'
                 ORDER BY incident_seq LIMIT 1",
                params![publisher, event_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(seq, kind, reason, deadline)| {
                Ok::<_, CoreError>(IncidentSummary {
                    incident_seq: from_sql(seq)?,
                    kind,
                    reason,
                    review_deadline_ms: deadline.map(from_sql).transpose()?,
                })
            })
            .transpose()?;
        let hold_reason = if state == DeliveryState::Unhanded && retired {
            Some("delivery scope retired; automatic delivery and manual retry are fenced".into())
        } else if state == DeliveryState::Unhanded {
            self.connection
                .query_row(
                    "SELECT reason FROM recipient_holds WHERE recipient = ?1",
                    params![recipient],
                    |row| row.get(0),
                )
                .optional()?
        } else {
            None
        };
        let blocked_by = match predecessor {
            Some(predecessor) if state == DeliveryState::Unhanded && waived == 0 => {
                let released: bool = self.connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM events
                                    WHERE publisher_id = ?1 AND event_id = ?2
                                      AND (state = 'superseded'
                                           OR delivery IN ('accepted','hook_submitted','disposed')))",
                    params![publisher, predecessor],
                    |row| row.get(0),
                )?;
                (!released).then_some(predecessor)
            }
            _ => None,
        };
        if attempt.is_none()
            && tiers.is_empty()
            && incident.is_none()
            && hold_reason.is_none()
            && blocked_by.is_none()
            && state == DeliveryState::Unhanded
        {
            return Ok(None);
        }
        Ok(Some(DeliveryEvidence {
            attempt_state: attempt
                .as_ref()
                .map_or_else(|| "none".to_string(), |a| a.state.as_str().to_string()),
            effective_mode: attempt.as_ref().map_or_else(
                || "none".to_string(),
                |a| a.effective_mode.as_str().to_string(),
            ),
            note: legacy_note,
            delivery: state,
            attempts_made: u32::try_from(from_sql(attempts)?).unwrap_or(u32::MAX),
            attempt,
            tiers,
            incident,
            hold_reason,
            blocked_by,
        }))
    }

    /// Records late positive evidence for an attempt.
    ///
    /// Evidence is appended to the event's log even when attempt ownership
    /// has changed. If the attempt still owns the event and is invoking,
    /// held, written without receipt or an unknown outcome, the evidence
    /// settles it at its declared tier without another send: native
    /// acceptance, context observation and application processing mark the
    /// event accepted, hook emission marks it hook-submitted, and
    /// known-unsent settles each still-owned member: ordinary lifetimes use
    /// the bounded retry policy, while `retire_unhanded` lifetimes retain any
    /// historical possible effect in review with an incident or dispose only
    /// proved zero-effect work; retired members never return to rotation.
    /// Evidence applies to the whole frozen manifest, including members now
    /// disposed or owned by a newer attempt, whose state/incidents stay unchanged.
    /// `detail` must name
    /// the observed fact. Tiers other than these are produced only by
    /// [`Storage::record_outcome`].
    pub fn record_evidence(
        &mut self,
        publisher: &str,
        event_id: &str,
        attempt_seq: u64,
        tier: EvidenceTier,
        detail: &str,
        now_ms: u64,
    ) -> Result<EvidenceEffect, CoreError> {
        if detail.trim().is_empty() {
            return Err(CoreError::InvalidEnvelope(
                "evidence must name the observed fact".into(),
            ));
        }
        let outcome = match tier {
            EvidenceTier::NativeAccepted
            | EvidenceTier::ContextObserved
            | EvidenceTier::ApplicationProcessed => Some(Outcome::NativeAccepted {
                evidence: detail.to_string(),
            }),
            EvidenceTier::HookEmitted => Some(Outcome::HookSubmitted {
                evidence: detail.to_string(),
            }),
            EvidenceTier::KnownUnsent => Some(Outcome::KnownUnsent {
                evidence: detail.to_string(),
            }),
            EvidenceTier::ReceiptTokenPossession => None,
            other => {
                return Err(CoreError::InvalidEnvelope(format!(
                    "{} is not accepted as late evidence",
                    other.as_str()
                )));
            }
        };
        let tx = self.begin()?;
        let record = load_attempt(&tx, attempt_seq)?
            .ok_or_else(|| CoreError::Fence(format!("no such attempt {attempt_seq}")))?;
        if !record
            .members
            .iter()
            .any(|member| member.publisher == publisher && member.event_id == event_id)
        {
            return Err(CoreError::Fence(format!(
                "attempt {attempt_seq} does not include {publisher}/{event_id}"
            )));
        }
        if !record_evidence_row(
            &tx,
            publisher,
            event_id,
            attempt_seq,
            tier.as_str(),
            detail,
            now_ms,
        )? {
            return Ok(EvidenceEffect::AlreadyRecorded);
        }
        let (current, owner) = event_state(&tx, publisher, event_id)?;
        let settles = owner == Some(attempt_seq)
            && matches!(
                current,
                DeliveryState::Invoking | DeliveryState::Held | DeliveryState::Review
            )
            && matches!(
                record.state,
                AttemptState::Invoking
                    | AttemptState::NativeHeld
                    | AttemptState::WrittenNoReceipt
                    | AttemptState::OutcomeUnknown
            );
        let effect = match outcome {
            Some(outcome) if settles => {
                apply_outcome(&tx, &record, outcome, now_ms)?;
                EvidenceEffect::Applied(event_state(&tx, publisher, event_id)?.0)
            }
            _ => EvidenceEffect::Recorded,
        };
        tx.commit()?;
        Ok(effect)
    }

    /// Authorizes one more attempt of the *same* event after an unresolved
    /// possible hand-off.
    ///
    /// Allowed only for an event in review or held (an unresolved possible
    /// hand-off). The open incidents close as `authorized` with the
    /// operator, the note and `duplicate_risk` recorded permanently; the
    /// event returns to rotation with a fresh automatic budget, and its next
    /// attempt carries the duplicate-risk flag. This never replays by
    /// itself. A `retire_unhanded` lifetime permanently fences retry; refusal
    /// preserves incidents, evidence and audit history without mutation.
    pub fn authorize_manual_retry(
        &mut self,
        publisher: &str,
        event_id: &str,
        operator: &str,
        note: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        operator_text("operator", operator)?;
        operator_text("note", note)?;
        let tx = self.begin()?;
        let (current, owner) = event_state(&tx, publisher, event_id)?;
        if !matches!(current, DeliveryState::Review | DeliveryState::Held) {
            return Err(CoreError::Fence(format!(
                "event {publisher}/{event_id} has no unresolved possible hand-off to retry"
            )));
        }
        let retired: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM events e JOIN delivery_scopes s
                 ON s.producer = e.publisher_id AND s.scope_key = e.delivery_scope_key
             WHERE e.publisher_id = ?1 AND e.event_id = ?2
               AND s.closed_ms IS NOT NULL AND s.action = 'retire_unhanded')",
            params![publisher, event_id],
            |row| row.get(0),
        )?;
        if retired {
            return Err(CoreError::Fence(
                "retired delivery scope cannot be retried".into(),
            ));
        }
        let resolution = format!("manual retry authorized by {operator}: {note}");
        tx.execute(
            "UPDATE incidents SET state = 'authorized', resolution = ?1, updated_ms = ?2,
                 resolved_ms = ?2, duplicate_risk = 1
             WHERE publisher_id = ?3 AND event_id = ?4 AND state = 'open'",
            params![resolution, to_sql(now_ms)?, publisher, event_id],
        )?;
        if let Some(owner) = owner {
            tx.execute(
                "UPDATE attempts SET state = 'outcome_unknown', updated_ms = ?1,
                     note = 'superseded by an audited manual retry'
                 WHERE attempt_seq = ?2 AND state IN ('native_held', 'written_no_receipt')",
                params![to_sql(now_ms)?, to_sql(owner)?],
            )?;
        }
        tx.execute(
            "UPDATE events SET delivery = 'unhanded', attempt_seq = NULL, duplicate_risk = 1,
                 attempts_made = 0, not_before_ms = ?1
             WHERE publisher_id = ?2 AND event_id = ?3",
            params![to_sql(now_ms)?, publisher, event_id],
        )?;
        audit(
            &tx,
            now_ms,
            operator,
            "manual_retry",
            publisher,
            event_id,
            &resolution,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Closes an event with an audited disposition, without claiming
    /// delivery.
    ///
    /// Allowed for events in review, held, refused or still unhanded
    /// (cancellation before any hand-off); an event that is reserved or
    /// invoking is in flight and refuses. Open incidents close as
    /// `disposed`, and dependents are released by the disposition (an
    /// audited gap), never by time.
    pub fn dispose_event(
        &mut self,
        publisher: &str,
        event_id: &str,
        operator: &str,
        note: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        operator_text("operator", operator)?;
        operator_text("note", note)?;
        let tx = self.begin()?;
        let (current, _) = event_state(&tx, publisher, event_id)?;
        if !matches!(
            current,
            DeliveryState::Review
                | DeliveryState::Held
                | DeliveryState::Refused
                | DeliveryState::Unhanded
        ) {
            return Err(CoreError::Fence(format!(
                "event {publisher}/{event_id} is {current:?} and cannot be disposed"
            )));
        }
        let resolution = format!("disposed by {operator}: {note}");
        tx.execute(
            "UPDATE incidents SET state = 'disposed', resolution = ?1, updated_ms = ?2,
                 resolved_ms = ?2
             WHERE publisher_id = ?3 AND event_id = ?4 AND state = 'open'",
            params![resolution, to_sql(now_ms)?, publisher, event_id],
        )?;
        tx.execute(
            "UPDATE events SET delivery = 'disposed', attempt_seq = NULL
             WHERE publisher_id = ?1 AND event_id = ?2",
            params![publisher, event_id],
        )?;
        audit(
            &tx,
            now_ms,
            operator,
            "dispose",
            publisher,
            event_id,
            &resolution,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Waives an event's predecessor dependency with an audited reason.
    ///
    /// For a predecessor that never arrived or that was expired: the
    /// dependent is released explicitly, never by elapsed time.
    pub fn waive_predecessor(
        &mut self,
        publisher: &str,
        event_id: &str,
        operator: &str,
        note: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        operator_text("operator", operator)?;
        operator_text("note", note)?;
        let tx = self.begin()?;
        let changed = tx.execute(
            "UPDATE events SET predecessor_waived = 1
             WHERE publisher_id = ?1 AND event_id = ?2 AND predecessor IS NOT NULL
               AND predecessor_waived = 0",
            params![publisher, event_id],
        )?;
        tx.execute(
            "UPDATE incidents SET state = 'disposed', resolved_ms = ?1, updated_ms = ?1,
                 resolution = ?2
             WHERE publisher_id = ?3 AND event_id = ?4
               AND kind IN ('predecessor_missing', 'predecessor_expired')
               AND state = 'open'",
            params![
                to_sql(now_ms)?,
                format!("predecessor waived by {operator}: {note}"),
                publisher,
                event_id
            ],
        )?;
        if changed == 0 {
            return Err(CoreError::Fence(format!(
                "event {publisher}/{event_id} has no unwaived predecessor"
            )));
        }
        audit(
            &tx,
            now_ms,
            operator,
            "waive_predecessor",
            publisher,
            event_id,
            note,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reads the most recent audit rows, newest first.
    ///
    /// Bounded by `limit`; intended for operator/test verification of
    /// audited transitions. Details never contain credentials.
    pub fn audit_entries(&self, limit: usize) -> Result<Vec<AuditEntry>, CoreError> {
        let mut statement = self.connection.prepare(
            "SELECT actor, action, publisher_id, event_id, detail FROM audit
             ORDER BY audit_seq DESC LIMIT ?1",
        )?;
        let rows = statement
            .query_map(params![to_sql(limit as u64)?], |row| {
                Ok(AuditEntry {
                    actor: row.get(0)?,
                    action: row.get(1)?,
                    publisher_id: row.get(2)?,
                    event_id: row.get(3)?,
                    detail: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// Transfers a stream lineage's authoritative producer, audited.
    ///
    /// The lineage is [`LineageScope`] — the coalescing scope without the
    /// publisher. Every scope field is validated with the same domain rules
    /// publication uses ([`NativeAddress::parse`], [`Kind::new`],
    /// [`Mode::parse`], [`StreamId::new`] and the project/task metadata
    /// rules), and the lineage key is built from the *canonical* forms, so
    /// a differently spelled but equivalent recipient addresses the same
    /// lineage and no separator or control byte can alias another one.
    ///
    /// The transfer records the new owner with the operator's note and
    /// nothing else: event ids, both producers' watermarks, attempts and
    /// evidence stay exactly as they are. Other producers' still unhanded
    /// or reserved `latest` events in the lineage are held visibly (with a
    /// retained `lineage_authority_lost` incident) so they are never
    /// selected or invoked afterwards, and their further `latest`
    /// publications are declined. The new owner starts its own monotonic
    /// revisions without inheriting or resetting anyone's watermark. A
    /// lineage no producer claimed yet may be pre-declared the same way,
    /// and an ambiguous migrated lineage (empty owner) is resolved by it.
    ///
    /// A possible or unknown native effect cannot be recalled. The
    /// handover is therefore refused with [`CoreError::Fence`], changing
    /// nothing, while any other producer's event in the lineage is
    /// `invoking`, in `review`, or held by the native side. Closed historical
    /// lineage incidents do not exempt a new native hold from this fence.
    /// The operator first resolves each one with the audited disposition
    /// (`dispose_event`) or retry authorization, then repeats the transfer.
    ///
    /// Returns the previous owner (empty for an ambiguous legacy lineage),
    /// or `None` when the lineage had none.
    pub fn transfer_lineage(
        &mut self,
        scope: &LineageScope,
        new_owner: &str,
        note: &str,
        operator: &str,
        now_ms: u64,
    ) -> Result<Option<String>, CoreError> {
        let recipient = NativeAddress::parse(&scope.recipient)?.to_canonical_string();
        PublisherId::new(new_owner.to_string())?;
        let kind = Kind::new(scope.kind.to_string())?;
        let mode = Mode::parse(&scope.mode)?;
        let stream = StreamId::new(scope.stream.to_string())?;
        // Project and task follow exactly the publication metadata rules,
        // so a scope cannot smuggle separator or control bytes into a
        // lineage key or target a different lineage through a collision.
        let mut scope_metadata = Metadata::new();
        if !scope.project.is_empty() {
            scope_metadata.insert("project".to_string(), scope.project.clone());
        }
        if !scope.task.is_empty() {
            scope_metadata.insert("task".to_string(), scope.task.clone());
        }
        validate_metadata(&scope_metadata)?;
        operator_text("operator", operator)?;
        operator_text("note", note)?;
        let lineage_key = crate::storage::lineage_key(
            &recipient,
            kind.as_str(),
            mode.as_str(),
            &scope.project,
            &scope.task,
            stream.as_str(),
        );
        let tx = self.begin()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT owner FROM stream_lineages WHERE lineage_key = ?1",
                params![lineage_key],
                |row| row.get(0),
            )
            .optional()?;
        let handover = previous.as_deref() != Some(new_owner);
        if handover {
            let unresolved: Option<(String, String)> = tx
                .query_row(
                    "SELECT e.publisher_id, e.event_id FROM events e
                     WHERE e.lineage_key = ?1 AND e.policy_class = 'latest'
                       AND e.publisher_id != ?2
                       AND (e.delivery IN ('invoking', 'review')
                            OR (e.delivery = 'held' AND NOT EXISTS (
                                SELECT 1 FROM incidents i
                                WHERE i.publisher_id = e.publisher_id
                                  AND i.event_id = e.event_id
                                  AND i.kind = 'lineage_authority_lost'
                                  AND i.state = 'open')))
                     ORDER BY e.acceptance_seq LIMIT 1",
                    params![lineage_key, new_owner],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((publisher, event_id)) = unresolved {
                return Err(CoreError::Fence(format!(
                    "event {publisher}/{event_id} in this lineage has a possible or unknown \
                     native effect that cannot be recalled; dispose or resolve it with an \
                     audited operator decision before handing the stream to {new_owner}"
                )));
            }
        }
        tx.execute(
            "INSERT INTO stream_lineages (lineage_key, owner, set_ms, note)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (lineage_key) DO UPDATE
               SET owner = excluded.owner, set_ms = excluded.set_ms, note = excluded.note",
            params![lineage_key, new_owner, to_sql(now_ms)?, note],
        )?;
        // Other producers' still-unhanded `latest` work in this lineage is
        // held visibly: bytes and any attempt evidence stay, but stale
        // snapshots of a transferred stream are never selected or invoked
        // afterwards. The unsafe states were refused above, so nothing
        // already handed off is touched.
        if handover {
            let mut statement = tx.prepare(
                "SELECT publisher_id, event_id FROM events
                 WHERE lineage_key = ?1 AND policy_class = 'latest'
                   AND publisher_id != ?2
                   AND state = 'pending' AND delivery IN ('unhanded', 'reserved')",
            )?;
            let stale: Vec<(String, String)> = statement
                .query_map(params![lineage_key, new_owner], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<Result<_, _>>()?;
            drop(statement);
            for (publisher, event_id) in stale {
                crate::storage::hold_for_lineage(
                    &tx,
                    &publisher,
                    &event_id,
                    &format!("lineage authority transferred to {new_owner}: {note}"),
                    now_ms,
                )?;
            }
        }
        audit(
            &tx,
            now_ms,
            operator,
            "transfer_lineage",
            new_owner,
            "",
            &format!(
                "lineage {} -> {new_owner} (previously {}): {note}",
                stream.as_str(),
                previous.as_deref().unwrap_or("none")
            ),
        )?;
        tx.commit()?;
        Ok(previous)
    }

    /// Sets or clears the durable no-wake policy for one recipient.
    ///
    /// The policy blocks the message path (including `auto` resolved to
    /// message) at reservation *and* again immediately before invocation;
    /// an already possible hand-off is never undone. A hook drain never
    /// wakes the recipient and is not blocked. Every change is audited.
    pub fn set_no_wake(
        &mut self,
        recipient: &str,
        no_wake: bool,
        reason: Option<&str>,
        operator: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        NativeAddress::parse(recipient)?;
        operator_text("operator", operator)?;
        if let Some(reason) = reason {
            operator_text("reason", reason)?;
        }
        let tx = self.begin()?;
        if no_wake {
            tx.execute(
                "INSERT INTO recipient_policies (recipient, no_wake, reason, set_ms)
                 VALUES (?1, 1, ?2, ?3)
                 ON CONFLICT (recipient) DO UPDATE
                   SET no_wake = 1, reason = excluded.reason, set_ms = excluded.set_ms",
                params![recipient, reason, to_sql(now_ms)?],
            )?;
        } else {
            tx.execute(
                "DELETE FROM recipient_policies WHERE recipient = ?1",
                params![recipient],
            )?;
        }
        audit(
            &tx,
            now_ms,
            operator,
            if no_wake { "pause" } else { "resume" },
            "",
            recipient,
            reason.unwrap_or(""),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Reconciles leases and rechecks, bounded per call.
    ///
    /// A `reserved` attempt past its lease never invoked and is reclaimed
    /// (the events return to rotation). An `invoking` attempt past its
    /// hand-off deadline may have handed off: it becomes `outcome_unknown`
    /// with a retained incident and is never retried automatically. A held
    /// or unreceipted attempt past its recheck deadline becomes an overdue
    /// incident (the event stays held; nothing is resent). Returns
    /// `(reclaimed, unknown, overdue)`.
    pub fn expire_attempt_leases(
        &mut self,
        now_ms: u64,
    ) -> Result<(usize, usize, usize), CoreError> {
        let now = to_sql(now_ms)?;
        let tx = self.begin()?;
        let reserved: Vec<i64> = tx
            .prepare(
                "SELECT attempt_seq FROM attempts
                 WHERE state = 'reserved' AND lease_expires_ms IS NOT NULL
                   AND lease_expires_ms <= ?1 ORDER BY attempt_seq LIMIT ?2",
            )?
            .query_map(params![now, MAINTENANCE_BATCH], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for seq in &reserved {
            release_reservation(
                &tx,
                from_sql(*seq)?,
                "lease expired before invocation; reclaimed",
                now_ms,
            )?;
        }
        let invoking: Vec<i64> = tx
            .prepare(
                "SELECT attempt_seq FROM attempts
                 WHERE state = 'invoking' AND deadline_ms <= ?1 ORDER BY attempt_seq LIMIT ?2",
            )?
            .query_map(params![now, MAINTENANCE_BATCH], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for seq in &invoking {
            let record = load_attempt(&tx, from_sql(*seq)?)?
                .ok_or_else(|| corrupt("an invoking attempt disappeared".into()))?;
            apply_outcome(
                &tx,
                &record,
                Outcome::OutcomeUnknown {
                    reason: "hand-off deadline passed; the effect cannot be established".into(),
                },
                now_ms,
            )?;
        }
        let rechecks: Vec<i64> = tx
            .prepare(
                "SELECT attempt_seq FROM attempts
                 WHERE state IN ('native_held', 'written_no_receipt')
                   AND recheck_ms IS NOT NULL AND recheck_ms <= ?1
                 ORDER BY attempt_seq LIMIT ?2",
            )?
            .query_map(params![now, MAINTENANCE_BATCH], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for seq in &rechecks {
            let record = load_attempt(&tx, from_sql(*seq)?)?
                .ok_or_else(|| corrupt("a held attempt disappeared".into()))?;
            let (kind, reason) = if record.state == AttemptState::WrittenNoReceipt {
                (
                    "receipt_overdue",
                    "the write has no positive receipt by its deadline",
                )
            } else {
                (
                    "held_overdue",
                    "the native side still holds the event past its recheck deadline",
                )
            };
            for member in &record.members {
                open_incident_in(
                    &tx,
                    &member.publisher,
                    &member.event_id,
                    Some(record.fence.attempt_seq),
                    kind,
                    reason,
                    now_ms,
                )?;
            }
            tx.execute(
                "UPDATE attempts SET recheck_ms = ?1, updated_ms = ?2 WHERE attempt_seq = ?3",
                params![
                    to_sql(now_ms.saturating_add(REVIEW_WINDOW_MS))?,
                    now,
                    to_sql(record.fence.attempt_seq)?
                ],
            )?;
        }
        tx.commit()?;
        Ok((reserved.len(), invoking.len(), rechecks.len()))
    }

    /// Runs one bounded reconciliation pass: expiry of unhanded events,
    /// lease and recheck handling, and escalation of long recipient holds,
    /// missing predecessors and expired predecessors to incidents.
    pub fn run_maintenance(&mut self, now_ms: u64) -> Result<MaintenanceReport, CoreError> {
        let expired_events = self.expire_due(now_ms)?;
        let (reclaimed_reservations, unknown_handoffs, overdue_rechecks) =
            self.expire_attempt_leases(now_ms)?;
        let escalated_holds = self.escalate_holds(now_ms)?;
        Ok(MaintenanceReport {
            expired_events,
            reclaimed_reservations,
            unknown_handoffs,
            overdue_rechecks,
            escalated_holds,
        })
    }

    /// Escalates holds older than the hold threshold to incidents on the
    /// recipient's oldest waiting event and resolves stale ones.
    ///
    /// Also raises `predecessor_missing` for a dependent whose predecessor
    /// was never accepted (after the hold threshold) and
    /// `predecessor_expired` for one whose predecessor expired before
    /// delivery (at once; expiry is final). Neither releases the dependent;
    /// both close when the dependent is waived, disposed or no longer
    /// waiting, and `predecessor_expired` also closes (and is not raised
    /// again) once the predecessor reaches a state that satisfies the dispatch
    /// dependency rule (accepted, hook-submitted or disposed),
    /// with a neutral resolution text that claims no particular decision.
    /// Returns how many incidents were newly opened.
    ///
    /// Each candidate query is bounded by `MAINTENANCE_BATCH` and skips
    /// items that already have an open incident of its kind, so a backlog
    /// larger than one batch is exposed over successive passes instead of
    /// re-selecting the same oldest items forever; an incident that was
    /// closed (resolved, disposed or authorized) no longer suppresses its
    /// item, and nothing here ever releases a dependent.
    fn escalate_holds(&mut self, now_ms: u64) -> Result<usize, CoreError> {
        let threshold = to_sql(now_ms.saturating_sub(HOLD_INCIDENT_AFTER_MS))?;
        let tx = self.begin()?;
        let holds: Vec<(String, String)> = tx
            .prepare(
                "SELECT h.recipient, h.reason FROM recipient_holds h
                 WHERE h.since_ms <= ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM incidents i
                       WHERE i.kind = 'recipient_held' AND i.state = 'open'
                         AND (i.publisher_id, i.event_id) = (
                             SELECT o.publisher_id, o.event_id FROM events o
                             WHERE o.state = 'pending' AND o.delivery = 'unhanded'
                               AND o.recipient = h.recipient
                             ORDER BY o.acceptance_seq LIMIT 1))
                 ORDER BY h.since_ms LIMIT ?2",
            )?
            .query_map(params![threshold, MAINTENANCE_BATCH], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut escalated = 0;
        let missing: Vec<(String, String, String)> = tx
            .prepare(
                "SELECT e.publisher_id, e.event_id, e.predecessor FROM events e
                 WHERE e.state = 'pending' AND e.delivery = 'unhanded'
                   AND e.predecessor IS NOT NULL AND e.predecessor_waived = 0
                   AND e.accepted_at_ms <= ?1
                   AND NOT EXISTS (SELECT 1 FROM events p
                                   WHERE p.publisher_id = e.publisher_id
                                     AND p.event_id = e.predecessor)
                   AND NOT EXISTS (SELECT 1 FROM incidents i
                                   WHERE i.publisher_id = e.publisher_id
                                     AND i.event_id = e.event_id
                                     AND i.kind = 'predecessor_missing' AND i.state = 'open')
                 ORDER BY e.acceptance_seq LIMIT ?2",
            )?
            .query_map(params![threshold, MAINTENANCE_BATCH], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        for (publisher, event_id, predecessor) in missing {
            if open_incident_in(
                &tx,
                &publisher,
                &event_id,
                None,
                "predecessor_missing",
                &format!("waiting for predecessor {predecessor}, which has not been accepted"),
                now_ms,
            )? {
                escalated += 1;
            }
        }
        // A predecessor that expired before delivery can never produce the
        // evidence its dependent waits for; the dependent keeps its order
        // and becomes an explicit incident until an audited waiver or
        // disposition.
        let expired: Vec<(String, String, String)> = tx
            .prepare(
                "SELECT e.publisher_id, e.event_id, e.predecessor FROM events e
                 JOIN events p ON p.publisher_id = e.publisher_id AND p.event_id = e.predecessor
                 WHERE e.state = 'pending' AND e.delivery = 'unhanded'
                   AND e.predecessor_waived = 0 AND p.state = 'expired'
                   AND p.delivery NOT IN ('accepted', 'hook_submitted', 'disposed')
                   AND NOT EXISTS (SELECT 1 FROM incidents i
                                   WHERE i.publisher_id = e.publisher_id
                                     AND i.event_id = e.event_id
                                     AND i.kind = 'predecessor_expired' AND i.state = 'open')
                 ORDER BY e.acceptance_seq LIMIT ?1",
            )?
            .query_map(params![MAINTENANCE_BATCH], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<_, _>>()?;
        for (publisher, event_id, predecessor) in expired {
            if open_incident_in(
                &tx,
                &publisher,
                &event_id,
                None,
                "predecessor_expired",
                &format!(
                    "predecessor {predecessor} expired before delivery; an audited waiver or disposition is required"
                ),
                now_ms,
            )? {
                escalated += 1;
            }
        }
        tx.execute(
            "UPDATE incidents SET state = 'resolved', resolved_ms = ?1, updated_ms = ?1,
                 resolution = 'the predecessor was accepted'
             WHERE kind = 'predecessor_missing' AND state = 'open'
               AND EXISTS (SELECT 1 FROM events e JOIN events p
                             ON p.publisher_id = e.publisher_id AND p.event_id = e.predecessor
                           WHERE e.publisher_id = incidents.publisher_id
                             AND e.event_id = incidents.event_id)",
            params![to_sql(now_ms)?],
        )?;
        // Once the predecessor reaches a releasing delivery state, the
        // dispatch eligibility rule releases its dependent on its own; the
        // incident closes without asserting which outcome satisfied the rule.
        tx.execute(
            "UPDATE incidents SET state = 'resolved', resolved_ms = ?1, updated_ms = ?1,
                 resolution = 'the predecessor now satisfies the dispatch dependency rule (accepted, hook-submitted or disposed)'
             WHERE kind = 'predecessor_expired' AND state = 'open'
               AND EXISTS (SELECT 1 FROM events e JOIN events p
                             ON p.publisher_id = e.publisher_id AND p.event_id = e.predecessor
                           WHERE e.publisher_id = incidents.publisher_id
                             AND e.event_id = incidents.event_id
                             AND p.delivery IN ('accepted', 'hook_submitted', 'disposed'))",
            params![to_sql(now_ms)?],
        )?;
        // A dependent that expired, was disposed or was waived no longer waits.
        tx.execute(
            "UPDATE incidents SET state = 'resolved', resolved_ms = ?1, updated_ms = ?1,
                 resolution = 'the dependent is no longer waiting'
             WHERE kind IN ('predecessor_missing', 'predecessor_expired') AND state = 'open'
               AND NOT EXISTS (SELECT 1 FROM events e
                               WHERE e.publisher_id = incidents.publisher_id
                                 AND e.event_id = incidents.event_id
                                 AND e.state = 'pending' AND e.delivery = 'unhanded'
                                 AND e.predecessor_waived = 0)",
            params![to_sql(now_ms)?],
        )?;
        for (recipient, reason) in holds {
            let oldest: Option<(String, String)> = tx
                .query_row(
                    "SELECT publisher_id, event_id FROM events
                     WHERE state = 'pending' AND delivery = 'unhanded' AND recipient = ?1
                     ORDER BY acceptance_seq LIMIT 1",
                    params![recipient],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((publisher, event_id)) = oldest
                && open_incident_in(
                    &tx,
                    &publisher,
                    &event_id,
                    None,
                    "recipient_held",
                    &format!("recipient {recipient} is held: {reason}"),
                    now_ms,
                )?
            {
                escalated += 1;
            }
        }
        tx.commit()?;
        Ok(escalated)
    }

    /// Counts currently open incidents (operator count surface).
    pub fn open_incident_count(&self) -> Result<u64, CoreError> {
        count(
            &self.connection,
            "SELECT COUNT(*) FROM incidents WHERE state = 'open'",
            params![],
        )
    }

    /// Counts events in `state` for diagnostics and protected operator totals.
    pub fn count_delivery(&self, state: DeliveryState) -> Result<u64, CoreError> {
        let text = match state {
            DeliveryState::Unhanded => delivery::UNHANDED,
            DeliveryState::Reserved => delivery::RESERVED,
            DeliveryState::Invoking => delivery::INVOKING,
            DeliveryState::Held => delivery::HELD,
            DeliveryState::Review => delivery::REVIEW,
            DeliveryState::Accepted => delivery::ACCEPTED,
            DeliveryState::HookSubmitted => delivery::HOOK_SUBMITTED,
            DeliveryState::Refused => delivery::REFUSED,
            DeliveryState::Disposed => delivery::DISPOSED,
        };
        count(
            &self.connection,
            "SELECT COUNT(*) FROM events WHERE delivery = ?1",
            params![text],
        )
    }
}

/// Resolves open `recipient_held` incidents of a recipient whose hold
/// cleared; called when a reservation succeeds.
pub(crate) fn resolve_hold_incidents(
    tx: &Connection,
    recipient: &str,
    now_ms: u64,
) -> Result<(), CoreError> {
    tx.execute(
        "UPDATE incidents SET state = 'resolved', resolved_ms = ?1, updated_ms = ?1,
             resolution = 'hold cleared: the recipient became dispatchable'
         WHERE kind = 'recipient_held' AND state = 'open'
           AND (publisher_id, event_id) IN
               (SELECT publisher_id, event_id FROM events WHERE recipient = ?2)",
        params![to_sql(now_ms)?, recipient],
    )?;
    Ok(())
}
