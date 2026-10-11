//! Protected operator view over the core's retained incidents and the
//! explicit same-event recovery decisions.
//!
//! The core owns every incident, hold, audit record and decision
//! (`bridge_core::recovery`); this module adds no second incident store.
//! It reads incidents through an operator grant and annotates each with a
//! category and the next human action, so the classes the policy keeps
//! apart stay apart:
//!
//! - `unknown`: a possible hand-off with an unknown result
//!   (`unknown_handoff`, `migrated_unverified`) — never resent
//!   automatically;
//! - `overdue`: a non-terminal native hold or a written-without-receipt
//!   hand-off past its deadline (`held_overdue`, `receipt_overdue`). A
//!   *routine* written-without-receipt within its deadline is not an
//!   incident and is not listed, so it never buries the exceptional cases;
//! - `held`: the recipient itself is held (unknown/disconnected/paused);
//! - `refused`: known non-acceptance (`permanent_refusal`,
//!   `retries_exhausted`);
//! - `integrity`: storage integrity;
//! - `lineage`: a producer lost authority over a `latest` stream lineage
//!   by an audited transfer (`lineage_authority_lost`); its held event is
//!   not dispatched while another producer owns the lineage and is never
//!   replayed automatically. It is usually closed by an audited
//!   disposition; an explicit transfer back followed by an audited retry
//!   (with its recorded duplicate risk) is the other deliberate path.
//!
//! Recovery decisions are sent to the core, which applies and audits them
//! under the operator grant identity. A manual retry repeats the *same*
//! event and the core records the duplicate risk forever; this module
//! refuses to send one unless the operator explicitly accepted that risk.
//! Lost answers to decisions are never resent (the client reports
//! `transport`; re-read the incidents or counts to see the outcome).
//! Before any request, [`check`] refuses blank notes and reasons and a
//! lineage scope or new producer that fails the core's public validators;
//! the core still validates the final operator text (length, controls)
//! itself, alone decides ownership and refuses a handover over a possible
//! native effect.

use bridge_client::{
    BridgeClient, EvidenceTier, IncidentView, Kind, LineageScope, Metadata, Mode, NativeAddress,
    ProtocolError, PublisherId, StreamId,
};
use serde::Serialize;

/// One incident with its operator annotations.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentReport {
    /// The core's incident, unchanged.
    #[serde(flatten)]
    pub incident: IncidentView,
    /// `unknown`, `overdue`, `held`, `refused`, `integrity`, `lineage` or
    /// `other`.
    pub category: &'static str,
    /// The next human action for this kind.
    pub next_action: &'static str,
}

/// Category and next action for an incident kind.
pub fn classify(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "unknown_handoff" | "migrated_unverified" => (
            "unknown",
            "possible hand-off with unknown result: look for positive exact-session evidence and record it (evidence); otherwise decide dispose or retry --accept-duplicate-risk. Never resent automatically.",
        ),
        "held_overdue" => (
            "overdue",
            "native hold past its recheck deadline: check the recipient session; record positive evidence or dispose.",
        ),
        "receipt_overdue" => (
            "overdue",
            "written without receipt past its deadline: check the exact-session marker/receipt; record positive evidence or dispose. Absence is not proof of non-delivery.",
        ),
        "recipient_held" => (
            "held",
            "recipient unknown, disconnected or paused: restore or resume the exact session, or dispose its waiting events.",
        ),
        "permanent_refusal" | "retries_exhausted" => (
            "refused",
            "this attempt was refused; an earlier hand-off may remain unknown. Inspect the retained evidence, then dispose this event with an audited note. Refused events cannot be retried; retry --accept-duplicate-risk applies only to review or held events. A new notification requires a separate explicit decision and does not resolve an earlier possible effect.",
        ),
        "storage_integrity" => (
            "integrity",
            "storage integrity problem: stop the service and inspect the database; do not retry.",
        ),
        "lineage_authority_lost" => (
            "lineage",
            "this producer lost authority over the stream lineage by an audited transfer; its event is held, is not dispatched while another producer owns the lineage and is never replayed automatically. Confirm the current owner with the producers. Usually dispose this event with an audited note and let the current owner publish fresh snapshots; only if the original producer must be authoritative again, transfer the lineage back explicitly and then decide an audited retry with its recorded duplicate risk. A producer without current authority is not treated as current.",
        ),
        _ => ("other", "inspect the event and decide explicitly."),
    }
}

/// Annotates incidents in the order the core returned them.
pub fn report(incidents: Vec<IncidentView>) -> Vec<IncidentReport> {
    incidents
        .into_iter()
        .map(|incident| {
            let (category, next_action) = classify(&incident.kind);
            IncidentReport {
                incident,
                category,
                next_action,
            }
        })
        .collect()
}

/// One explicit operator decision.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Another attempt of the same event; `accept_duplicate_risk` must be
    /// `true` or the decision is refused locally before any request.
    Retry {
        /// Publisher of the event.
        publisher: String,
        /// The event.
        event_id: String,
        /// Audit note.
        note: String,
        /// The operator's explicit acceptance of a possible duplicate.
        accept_duplicate_risk: bool,
    },
    /// Close the event with an audited disposition (never delivery).
    Dispose {
        /// Publisher of the event.
        publisher: String,
        /// The event.
        event_id: String,
        /// Audit note.
        note: String,
    },
    /// Waive a missing or expired predecessor of a dependent event.
    Waive {
        /// Publisher of the dependent event.
        publisher: String,
        /// The dependent event.
        event_id: String,
        /// Audit note.
        note: String,
    },
    /// Record positive late evidence for one attempt.
    Evidence {
        /// Publisher of the event.
        publisher: String,
        /// The event.
        event_id: String,
        /// The attempt.
        attempt_seq: u64,
        /// The evidence tier.
        tier: EvidenceTier,
        /// The observed fact.
        detail: String,
    },
    /// Durable no-wake policy for a recipient.
    Pause {
        /// The recipient.
        recipient: NativeAddress,
        /// Why.
        reason: String,
    },
    /// Clear the no-wake policy.
    Resume {
        /// The recipient.
        recipient: NativeAddress,
    },
    /// Drained service stop.
    Shutdown,
    /// Audited handover of a stream lineage to `new_publisher`.
    TransferLineage {
        /// The full lineage scope (canonical recipient, kind, mode,
        /// project, task, stream; project and task empty when undeclared).
        scope: LineageScope,
        /// The producer that becomes authoritative.
        new_publisher: String,
        /// Audit note.
        note: String,
    },
}

/// Checks a decision's local rules, before any connection or request.
///
/// Refuses (class `invalid`) an empty note or reason, a retry without
/// explicit duplicate-risk acceptance and a lineage transfer whose scope
/// or new producer fails [`check_scope`].
pub fn check(decision: &Decision) -> Result<(), ProtocolError> {
    let refuse = |detail: String| {
        Err(ProtocolError {
            class: "invalid".into(),
            detail,
        })
    };
    match decision {
        Decision::Retry {
            accept_duplicate_risk: false,
            ..
        } => refuse(
            "a manual retry repeats the same event and may duplicate it; pass --accept-duplicate-risk"
                .into(),
        ),
        Decision::Retry { note, .. }
        | Decision::Dispose { note, .. }
        | Decision::Waive { note, .. }
        | Decision::TransferLineage { note, .. }
            if note.trim().is_empty() =>
        {
            refuse("an audit note is required".into())
        }
        Decision::Pause { reason, .. } if reason.trim().is_empty() => {
            refuse("a pause reason is required".into())
        }
        Decision::TransferLineage {
            scope,
            new_publisher,
            ..
        } => check_scope(scope, new_publisher).or_else(refuse),
        _ => Ok(()),
    }
}

/// Applies one decision through the operator grant.
///
/// Runs [`check`] first (nothing is sent on a local refusal); otherwise the
/// core's answer is returned unchanged. Each decision is sent at most once
/// (a lost answer is a `transport` error, see [`failure_text`]).
pub fn apply(
    client: &mut BridgeClient,
    token: &str,
    decision: &Decision,
) -> Result<(), ProtocolError> {
    check(decision)?;
    match decision {
        Decision::Retry {
            publisher,
            event_id,
            note,
            ..
        } => client.authorize_retry(token, publisher, event_id, note),
        Decision::Dispose {
            publisher,
            event_id,
            note,
        } => client.dispose(token, publisher, event_id, note),
        Decision::Waive {
            publisher,
            event_id,
            note,
        } => client.waive_predecessor(token, publisher, event_id, note),
        Decision::Evidence {
            publisher,
            event_id,
            attempt_seq,
            tier,
            detail,
        } => client.record_evidence(token, publisher, event_id, *attempt_seq, *tier, detail),
        Decision::Pause { recipient, reason } => client.pause(token, recipient, reason),
        Decision::Resume { recipient } => client.resume(token, recipient),
        Decision::Shutdown => client.shutdown(token),
        Decision::TransferLineage {
            scope,
            new_publisher,
            note,
        } => client.transfer_lineage(token, scope, new_publisher, note),
    }
}

/// Checks a lineage scope and the new producer with the core's public
/// validators before any request: canonical-parseable recipient, kind, mode,
/// stream and publisher id, and project/task as metadata values (each may
/// be empty when undeclared). Returns the first violation.
pub fn check_scope(scope: &LineageScope, new_publisher: &str) -> Result<(), String> {
    NativeAddress::parse(&scope.recipient).map_err(|error| format!("recipient: {error}"))?;
    Kind::new(scope.kind.clone()).map_err(|error| format!("kind: {error}"))?;
    Mode::parse(&scope.mode).map_err(|error| format!("mode: {error}"))?;
    StreamId::new(scope.stream.clone()).map_err(|error| format!("stream: {error}"))?;
    PublisherId::new(new_publisher.to_string())
        .map_err(|error| format!("new publisher: {error}"))?;
    let mut declared = Metadata::new();
    for (key, value) in [("project", &scope.project), ("task", &scope.task)] {
        if !value.is_empty() {
            declared.insert(key.to_string(), value.clone());
        }
    }
    bridge_core::validate_metadata(&declared).map_err(|error| format!("scope: {error}"))
}

/// Operator-facing text for a refused or failed *mutating* decision. A
/// `transport` failure means the request may already have been applied:
/// the text says so and that nothing is resent; every other class is the
/// core's (or the local validation's) refusal unchanged. Read-only
/// queries use [`read_failure_text`] instead.
pub fn failure_text(error: &ProtocolError) -> String {
    if error.class == "transport" {
        format!(
            "outcome unknown: the request may have been applied ({}); it was not resent. Re-read incidents and counts before deciding again.",
            error.detail
        )
    } else {
        error.to_string()
    }
}

/// Operator-facing text for a failed read-only query (counts, incidents,
/// holds). A `transport` failure leaves the current data unknown — nothing
/// was changed by the query (the client may have repeated a repeatable
/// read once); every other class is the core's refusal unchanged.
pub fn read_failure_text(error: &ProtocolError) -> String {
    if error.class == "transport" {
        format!(
            "read failed: the current data is unknown ({}); nothing was changed by this query",
            error.detail
        )
    } else {
        error.to_string()
    }
}

/// Parses an evidence tier name (the core's storage names).
pub fn parse_tier(name: &str) -> Option<EvidenceTier> {
    [
        EvidenceTier::NativeAccepted,
        EvidenceTier::NativeHeld,
        EvidenceTier::HookEmitted,
        EvidenceTier::WrittenNoReceipt,
        EvidenceTier::ContextObserved,
        EvidenceTier::ApplicationProcessed,
        EvidenceTier::KnownUnsent,
        EvidenceTier::ReceiptTokenPossession,
        EvidenceTier::Refused,
        EvidenceTier::Unknown,
    ]
    .into_iter()
    .find(|tier| tier.as_str() == name)
}

#[cfg(test)]
mod tests {
    //! Classification keeps the policy's classes apart.

    use super::*;

    /// Unknown, overdue, held and refused states keep separate classes, and
    /// unknown handoffs are never resent.
    #[test]
    fn unknown_overdue_and_held_stay_distinct() {
        assert_eq!(classify("unknown_handoff").0, "unknown");
        assert_eq!(classify("receipt_overdue").0, "overdue");
        assert_eq!(classify("held_overdue").0, "overdue");
        assert_eq!(classify("recipient_held").0, "held");
        assert_eq!(classify("retries_exhausted").0, "refused");
        assert!(
            classify("retries_exhausted")
                .1
                .contains("Refused events cannot be retried")
        );
        assert!(classify("unknown_handoff").1.contains("Never resent"));
    }

    /// Lost lineage authority is its own class with only conditional, audited
    /// next steps and no automatic replay.
    #[test]
    fn lineage_loss_is_its_own_class_without_replay() {
        let (category, next) = classify("lineage_authority_lost");
        assert_eq!(category, "lineage");
        assert!(next.contains("not dispatched while another producer owns the lineage"));
        assert!(next.contains("never replayed automatically"));
        // The deliberate alternative is conditional and audited, never a
        // plain replay.
        assert!(next.contains("transfer the lineage back explicitly"));
        assert!(next.contains("audited retry with its recorded duplicate risk"));
        assert!(!next.contains("never dispatched"));
    }

    /// A lineage transfer needs a valid scope, a new publisher and a non-blank
    /// note, and is checked before any request is made.
    #[test]
    fn transfers_are_checked_before_any_request() {
        let scope = LineageScope {
            recipient: "lab/claude-code/store/session".into(),
            kind: "view.snapshot".into(),
            mode: "inject".into(),
            project: String::new(),
            task: String::new(),
            stream: "s1".into(),
        };
        let transfer = |scope: LineageScope, publisher: &str, note: &str| {
            check(&Decision::TransferLineage {
                scope,
                new_publisher: publisher.into(),
                note: note.into(),
            })
        };
        assert!(transfer(scope.clone(), "producer-b", "handover").is_ok());
        assert!(transfer(scope.clone(), "producer-b", " \n").is_err());
        assert!(transfer(scope.clone(), "", "handover").is_err());
        for broken in [
            LineageScope {
                recipient: "not-an-address".into(),
                ..scope.clone()
            },
            LineageScope {
                mode: "teleport".into(),
                ..scope.clone()
            },
            LineageScope {
                stream: String::new(),
                ..scope.clone()
            },
            LineageScope {
                task: "a\u{1}b".into(),
                ..scope.clone()
            },
        ] {
            let refused = transfer(broken, "producer-b", "handover").unwrap_err();
            assert_eq!(refused.class, "invalid");
        }
        let lost = ProtocolError {
            class: "transport".into(),
            detail: "closed".into(),
        };
        assert!(failure_text(&lost).contains("outcome unknown"));
        let read = read_failure_text(&lost);
        assert!(read.contains("read failed") && !read.contains("may have been applied"));
    }

    /// Known evidence tier names parse to their tier and unknown names are
    /// rejected.
    #[test]
    fn tier_names_round_trip() {
        assert_eq!(
            parse_tier("native_accepted"),
            Some(EvidenceTier::NativeAccepted)
        );
        assert_eq!(parse_tier("delivered"), None);
    }
}
