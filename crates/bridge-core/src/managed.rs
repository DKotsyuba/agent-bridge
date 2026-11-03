//! Durable root delivery and retained failure reports, separate from envelope identity.
//!
//! Only grant-authorized ingress supplies the verified sender. Feedback is an
//! ordinary bounded MESSAGE with no return sender, so failures cannot recurse.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dispatch::release_reservation;
use crate::storage::{from_sql, publish_in, to_sql};
use crate::{
    CoreError, Envelope, EventId, Kind, Metadata, Mode, NativeAddress, Payload, Policy,
    PublishOutcome, Storage,
};

/// Maximum native invocations of a best-effort feedback notice.
pub const MAX_SENDS: u32 = 5;
/// Maximum lifetime of a best-effort feedback notice, in milliseconds.
pub const DELIVERY_WINDOW_MS: u64 = 5 * 60_000;
/// Maximum original/report records processed in one maintenance transaction.
const BATCH: usize = 200;

/// Trusted relay-supplied origin; never extracted from event metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSender {
    /// Exact attested caller address; service checks the grant's callback scope.
    pub address: NativeAddress,
    /// Root caller's stable request identity, used only in the fixed notice.
    pub request_id: String,
}

/// Durable result of stopping automatic delivery; never proof of reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReport {
    /// `failed` means positive no-effect history; `unconfirmed` preserves uncertainty.
    pub outcome: String,
    /// Safe fixed reason describing why automation stopped.
    pub reason: String,
    /// Unix milliseconds when automation stopped; late evidence stays separate.
    pub completed_at_ms: u64,
    /// Native invocations including busy receipts, saturated at `u32::MAX`.
    pub sends_made: u32,
    /// Deterministic notice identity, absent for notices themselves.
    pub feedback_event_id: Option<String>,
    /// Notice admission/delivery state, never a claim that the sender read it.
    pub feedback_state: String,
}

impl DeliveryReport {
    /// Revalidates bounded fields and state names received from an untrusted socket.
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if !matches!(self.outcome.as_str(), "failed" | "unconfirmed")
            || self.reason.len() > 256
            || self.completed_at_ms > crate::MAX_SQLITE_INT
            || !matches!(
                self.feedback_state.as_str(),
                "pending"
                    | "queued"
                    | "unavailable"
                    | "accepted"
                    | "hook_submitted"
                    | "unconfirmed"
                    | "failed"
                    | "none"
            )
        {
            return Err(CoreError::InvalidEnvelope(
                "invalid bounded delivery report".into(),
            ));
        }
        if let Some(id) = &self.feedback_event_id {
            EventId::new(id)?;
        }
        Ok(())
    }
}

/// Installs policy only for newly committed custody, preserving old replay/hash semantics.
impl Storage {
    /// Atomically publishes a root event and binds its attested sender and explicit expiry.
    /// Existing legacy custody replays unchanged and never acquires a guessed origin.
    /// New managed replays must keep the same sender and request id.
    pub fn publish_managed(
        &mut self,
        envelope: &Envelope,
        sender: &ManagedSender,
        now_ms: u64,
    ) -> Result<PublishOutcome, CoreError> {
        envelope.validate()?;
        if !matches!(envelope.policy, Policy::KeepAll) {
            return Err(CoreError::InvalidEnvelope(
                "managed delivery requires keep_all".into(),
            ));
        }
        crate::framing::check_renderable(envelope)?;
        sender.address.validate()?;
        if sender.request_id.is_empty()
            || sender.request_id.len() > 128
            || !sender
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(CoreError::InvalidEnvelope(
                "invalid managed request identity".into(),
            ));
        }
        let limits = self.limits();
        let (tx, admission) = self.begin_admission()?;
        let result = publish_in(&tx, envelope, now_ms, limits, "", admission)?;
        let address = sender.address.to_canonical_string();
        if result.receipt.replayed {
            let previous: Option<(Option<String>, String)> = tx.query_row(
                "SELECT feedback_sender,request_id FROM managed_deliveries WHERE publisher_id=?1 AND event_id=?2",
                params![envelope.publisher.as_str(), envelope.event_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            if previous.is_some_and(|old| old != (Some(address.clone()), sender.request_id.clone()))
            {
                return Err(CoreError::Fence(
                    "managed origin does not match original custody".into(),
                ));
            }
        } else {
            let deadline = envelope
                .expires_at
                .map_or(crate::MAX_SQLITE_INT, |expires| expires.unix_millis());
            tx.execute("INSERT INTO managed_deliveries(publisher_id,event_id,feedback_sender,request_id,deadline_ms)
                VALUES(?1,?2,?3,?4,?5)", params![envelope.publisher.as_str(),envelope.event_id.as_str(),
                address,sender.request_id,to_sql(deadline)?])?;
        }
        tx.commit()?;
        Ok(result)
    }

    /// Stops exhausted managed work and admits retained feedback within a finite lifetime.
    /// Native I/O is always performed later, outside this transaction, by normal carriers.
    pub(crate) fn maintain_managed(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let limits = self.limits();
        let tx = self.begin()?;
        complete_in(&tx, now_ms)?;
        tx.commit()?;
        let (tx, admission) = self.begin_admission()?;
        let pending: Vec<(String,String,String,String,i64)> = tx.prepare(
            "SELECT publisher_id,event_id,feedback_sender,request_id,completed_ms FROM managed_deliveries
             WHERE notice_state='pending' ORDER BY completed_ms,publisher_id,event_id LIMIT ?1")?
            .query_map(params![BATCH], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?
            .collect::<Result<_,_>>()?;
        for (publisher, event, sender, request, completed) in pending {
            let completed = from_sql(completed)?;
            if now_ms >= completed.saturating_add(DELIVERY_WINDOW_MS) {
                tx.execute("UPDATE managed_deliveries SET notice_state='unavailable' WHERE publisher_id=?1 AND event_id=?2",
                    params![publisher,event])?;
                continue;
            }
            let outcome: String = tx.query_row(
                "SELECT outcome FROM managed_deliveries WHERE publisher_id=?1 AND event_id=?2",
                params![publisher, event],
                |r| r.get(0),
            )?;
            let notice = feedback_id(&publisher, &event);
            let body = format!(
                "Bridge delivery {} for request {}. Automatic delivery stopped. The original message and evidence are retained. Check bridge_status with the same request_id.{}",
                if outcome == "failed" {
                    "failed"
                } else {
                    "is unconfirmed"
                },
                request,
                if outcome == "unconfirmed" {
                    " The recipient may have received it; do not resend automatically."
                } else {
                    ""
                }
            );
            let envelope = Envelope::new(
                crate::PublisherId::new(&publisher)?,
                EventId::new(&notice)?,
                NativeAddress::parse(&sender)?,
                Kind::new("bridge.delivery_report")?,
                Mode::Message,
                Policy::KeepAll,
                Payload::new(body)?,
                Metadata::new(),
                None,
            )?;
            // A failure to admit a best-effort notice never rolls back the original report.
            tx.execute_batch("SAVEPOINT feedback_admission")?;
            let admitted = publish_in(&tx, &envelope, now_ms, limits, "", admission);
            match admitted {
                Ok(receipt) if !receipt.receipt.replayed => {
                    tx.execute(
                        "INSERT INTO managed_deliveries(publisher_id,event_id,deadline_ms)
                        VALUES(?1,?2,?3)",
                        params![
                            publisher,
                            notice,
                            to_sql(completed.saturating_add(DELIVERY_WINDOW_MS))?
                        ],
                    )?;
                    tx.execute(
                        "UPDATE managed_deliveries SET notice_state='queued',notice_event_id=?1
                        WHERE publisher_id=?2 AND event_id=?3",
                        params![notice, publisher, event],
                    )?;
                    tx.execute_batch("RELEASE feedback_admission")?;
                }
                Ok(_) => {
                    tx.execute_batch("ROLLBACK TO feedback_admission; RELEASE feedback_admission")?;
                    tx.execute("UPDATE managed_deliveries SET notice_state='unavailable' WHERE publisher_id=?1 AND event_id=?2",
                        params![publisher,event])?;
                }
                Err(CoreError::Capacity { .. } | CoreError::Busy(_)) => {
                    tx.execute_batch("ROLLBACK TO feedback_admission; RELEASE feedback_admission")?;
                }
                Err(CoreError::Unsupported(_) | CoreError::Conflict { .. }) => {
                    tx.execute_batch("ROLLBACK TO feedback_admission; RELEASE feedback_admission")?;
                    tx.execute("UPDATE managed_deliveries SET notice_state='unavailable' WHERE publisher_id=?1 AND event_id=?2",
                        params![publisher,event])?;
                }
                Err(error) => return Err(error),
            }
        }
        tx.commit()?;
        Ok(())
    }
}

/// Stable notice identity in the original producer realm; never user metadata.
fn feedback_id(publisher: &str, event: &str) -> String {
    let digest = Sha256::digest(format!("{publisher}\n{event}\n").as_bytes());
    format!(
        "feedback-{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Reads a retained report and its notice's current evidence without native I/O.
pub(crate) fn report_in(
    connection: &Connection,
    publisher: &str,
    event: &str,
) -> Result<Option<DeliveryReport>, CoreError> {
    let row: Option<(String,String,i64,u32,Option<String>,String)> = connection.query_row(
        "SELECT outcome,reason,completed_ms,sends_made,notice_event_id,notice_state FROM managed_deliveries
         WHERE publisher_id=?1 AND event_id=?2 AND outcome IN('failed','unconfirmed')",
        params![publisher,event],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((outcome, reason, completed, sends, feedback_event_id, mut feedback_state)) = row
    else {
        return Ok(None);
    };
    if let Some(notice) = &feedback_event_id {
        let (result,delivery):(String,String) = connection.query_row(
            "SELECT m.outcome,e.delivery FROM managed_deliveries m JOIN events e USING(publisher_id,event_id)
             WHERE m.publisher_id=?1 AND m.event_id=?2",params![publisher,notice],|r| Ok((r.get(0)?,r.get(1)?)))?;
        feedback_state = if matches!(delivery.as_str(), "accepted" | "hook_submitted") {
            delivery
        } else if result == "active" {
            "queued".into()
        } else {
            result
        };
    }
    Ok(Some(DeliveryReport {
        outcome,
        reason,
        completed_at_ms: from_sql(completed)?,
        sends_made: sends,
        feedback_event_id,
        feedback_state,
    }))
}

/// One bounded completion candidate, in the SELECT order below: publisher,
/// event, delivery, owning attempt, sends, deadline and feedback-origin presence.
type CompletionCandidate = (String, String, String, Option<i64>, u32, i64, bool);

/// Records completion without erasing historical possible effects. Active root
/// originals use only their explicit expiry, including rows written by older
/// versions; feedback notices retain their stored deadline and attempt limit.
/// In-flight invocations keep their native attempt/fence when archived unconfirmed.
pub(crate) fn complete_in(tx: &Transaction<'_>, now_ms: u64) -> Result<(), CoreError> {
    let rows: Vec<CompletionCandidate> = tx.prepare(
        "SELECT e.publisher_id,e.event_id,e.delivery,e.attempt_seq,m.sends_made,
         CASE WHEN m.feedback_sender IS NULL THEN m.deadline_ms ELSE COALESCE(e.expires_at_ms,?3) END,
         m.feedback_sender IS NOT NULL FROM events e JOIN managed_deliveries m USING(publisher_id,event_id)
         WHERE m.outcome='active'
         AND (e.delivery NOT IN('held','invoking') OR
              CASE WHEN m.feedback_sender IS NULL THEN m.deadline_ms ELSE COALESCE(e.expires_at_ms,?3) END<=?1)
         AND (e.delivery IN('accepted','hook_submitted','refused','review','disposed') OR
              CASE WHEN m.feedback_sender IS NULL THEN m.deadline_ms ELSE COALESCE(e.expires_at_ms,?3) END<=?1 OR
              (m.feedback_sender IS NULL AND m.sends_made>=5) OR e.state!='pending')
         ORDER BY 6,e.publisher_id,e.event_id LIMIT ?2")?
        .query_map(params![to_sql(now_ms)?,BATCH,to_sql(crate::MAX_SQLITE_INT)?],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?
        .collect::<Result<_,_>>()?;
    for (publisher, event, mut delivery, owner, sends, deadline, has_sender) in rows {
        let deadline = from_sql(deadline)?;
        if matches!(delivery.as_str(), "accepted" | "hook_submitted") {
            tx.execute("UPDATE managed_deliveries SET outcome='accepted',completed_ms=?1 WHERE publisher_id=?2 AND event_id=?3",
                params![to_sql(now_ms)?,publisher,event])?;
            continue;
        }
        // Before the lifetime deadline, five calls alone never stop a held fifth call.
        if matches!(delivery.as_str(), "invoking" | "held") && now_ms < deadline {
            continue;
        }
        if delivery == "reserved"
            && let Some(seq) = owner
        {
            release_reservation(
                tx,
                from_sql(seq)?,
                "bounded delivery deadline reached before invocation",
                now_ms,
            )?;
            delivery = "unhanded".into();
        }
        let possible: bool = tx.query_row(
            &format!(
                "SELECT {} FROM events e WHERE publisher_id=?1 AND event_id=?2",
                crate::universal::POSSIBLE_EFFECT
            ),
            params![publisher, event],
            |r| r.get(0),
        )?;
        let outcome = if possible { "unconfirmed" } else { "failed" };
        let reason = if possible {
            "Automatic delivery stopped; native handoff remains unconfirmed"
        } else if !has_sender && sends >= MAX_SENDS {
            "Five native attempts ended with positive no-send evidence"
        } else if now_ms >= deadline {
            "Delivery deadline reached before native acceptance"
        } else if delivery == "refused" {
            "Native delivery was refused before acceptance"
        } else {
            "Automatic delivery stopped before native acceptance"
        };
        if delivery == "held"
            && let Some(seq) = owner
        {
            // Keep the native fence and late-positive callback compatibility.
            tx.execute("UPDATE attempts SET state='outcome_unknown',recheck_ms=NULL,updated_ms=?1,
                    note='bounded delivery deadline; native outcome unconfirmed' WHERE attempt_seq=?2
                    AND state IN('native_held','written_no_receipt')",params![to_sql(now_ms)?,seq])?;
        }
        tx.execute(
            "UPDATE events SET delivery='disposed' WHERE publisher_id=?1 AND event_id=?2",
            params![publisher, event],
        )?;
        tx.execute("UPDATE incidents SET state='disposed',resolved_ms=?1,updated_ms=?1,
            resolution='automatic bounded delivery stopped; evidence retained' WHERE publisher_id=?2 AND event_id=?3 AND state='open'",
            params![to_sql(now_ms)?,publisher,event])?;
        tx.execute(
            "UPDATE managed_deliveries SET outcome=?1,reason=?2,completed_ms=?3,
            notice_state=?4,completion_seq=?7 WHERE publisher_id=?5 AND event_id=?6 AND outcome='active'",
            params![
                outcome,
                reason,
                to_sql(now_ms)?,
                if has_sender { "pending" } else { "none" },
                publisher,
                event,
                to_sql(crate::storage::bump_counter(tx, "managed_completion_seq")?)?
            ],
        )?;
        crate::recovery::audit(
            tx,
            now_ms,
            "bounded-delivery",
            "dispose",
            &publisher,
            &event,
            reason,
        )?;
    }
    Ok(())
}

/// Maximum retained failure reports in a sender's read-only page.
pub const REPORT_PAGE_SIZE: usize = 20;

/// One durable result addressed to an exact sender, without the original payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderReport {
    /// Monotonic completion identity; independent of publication order.
    pub completion_seq: u64,
    /// Original immutable event identity in the authenticated producer realm.
    pub event_id: String,
    /// Sender's original request identity for exact status reconciliation.
    pub request_id: String,
    /// Historical completion result and current best-effort notice evidence.
    pub report: DeliveryReport,
}

/// Read-only page of a sender's retained delivery failures, never an acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderReportPage {
    /// At most twenty reports ordered by first completion.
    pub reports: Vec<SenderReport>,
    /// Last returned completion when more rows exist; otherwise the scan is complete.
    pub next_after_seq: Option<u64>,
}

impl SenderReportPage {
    /// Rejects oversized, unordered or malformed pages received over a socket.
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        let mut previous = 0;
        if self.reports.len() > REPORT_PAGE_SIZE {
            return Err(CoreError::InvalidEnvelope(
                "oversized sender report page".into(),
            ));
        }
        for item in &self.reports {
            if item.completion_seq <= previous
                || item.completion_seq > crate::MAX_SQLITE_INT
                || item.request_id.is_empty()
                || item.request_id.len() > 128
                || !item
                    .request_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            {
                return Err(CoreError::InvalidEnvelope(
                    "invalid sender report identity".into(),
                ));
            }
            EventId::new(&item.event_id)?;
            item.report.validate()?;
            previous = item.completion_seq;
        }
        if self
            .next_after_seq
            .is_some_and(|cursor| self.reports.len() != REPORT_PAGE_SIZE || cursor != previous)
        {
            return Err(CoreError::InvalidEnvelope(
                "invalid sender report cursor".into(),
            ));
        }
        Ok(())
    }
}

impl Storage {
    /// Reads retained completed reports for one producer and exact native sender.
    /// The authenticated ingress supplies both scopes; this read never acknowledges,
    /// deletes or retries a report. The cursor follows completion order, so an older
    /// publication completing later is still visible on the next page.
    pub fn sender_reports(
        &self,
        publisher: &str,
        sender: &NativeAddress,
        after_seq: u64,
    ) -> Result<SenderReportPage, CoreError> {
        crate::PublisherId::new(publisher)?;
        sender.validate()?;
        let rows: Vec<(i64, String, String)> = self
            .connection
            .prepare(
                "SELECT completion_seq,event_id,request_id FROM managed_deliveries
             WHERE publisher_id=?1 AND feedback_sender=?2 AND completion_seq>?3
             AND outcome IN('failed','unconfirmed') ORDER BY completion_seq LIMIT ?4",
            )?
            .query_map(
                params![
                    publisher,
                    sender.to_canonical_string(),
                    to_sql(after_seq)?,
                    REPORT_PAGE_SIZE + 1
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?
            .collect::<Result<_, _>>()?;
        let has_more = rows.len() > REPORT_PAGE_SIZE;
        let reports = rows
            .into_iter()
            .take(REPORT_PAGE_SIZE)
            .map(|(seq, event_id, request_id)| {
                let report =
                    report_in(&self.connection, publisher, &event_id)?.ok_or_else(|| {
                        crate::storage::corrupt("completed sender report disappeared".into())
                    })?;
                Ok(SenderReport {
                    completion_seq: crate::storage::from_sql(seq)?,
                    event_id,
                    request_id,
                    report,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let next_after_seq = if has_more {
            reports.last().map(|row| row.completion_seq)
        } else {
            None
        };
        let page = SenderReportPage {
            reports,
            next_after_seq,
        };
        page.validate()?;
        Ok(page)
    }
}
