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
//! - `integrity`: storage integrity.
//!
//! Recovery decisions are sent to the core, which applies and audits them
//! under the operator grant identity. A manual retry repeats the *same*
//! event and the core records the duplicate risk forever; this module
//! refuses to send one unless the operator explicitly accepted that risk.
//! Lost answers to decisions are never resent (the client reports
//! `transport`; re-read the incidents to see the outcome).

use bridge_client::{BridgeClient, EvidenceTier, IncidentView, NativeAddress, ProtocolError};
use serde::Serialize;

/// One incident with its operator annotations.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentReport {
    /// The core's incident, unchanged.
    #[serde(flatten)]
    pub incident: IncidentView,
    /// `unknown`, `overdue`, `held`, `refused`, `integrity` or `other`.
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
            "known non-acceptance: fix the recipient or carrier, then dispose or authorize a retry.",
        ),
        "storage_integrity" => (
            "integrity",
            "storage integrity problem: stop the service and inspect the database; do not retry.",
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
}

/// Applies one decision through the operator grant.
///
/// Refuses locally (class `invalid`) an empty note or reason, and a retry
/// without explicit duplicate-risk acceptance; otherwise the core's answer
/// is returned unchanged.
pub fn apply(
    client: &mut BridgeClient,
    token: &str,
    decision: &Decision,
) -> Result<(), ProtocolError> {
    let refuse = |detail: &str| ProtocolError {
        class: "invalid".into(),
        detail: detail.into(),
    };
    match decision {
        Decision::Retry {
            accept_duplicate_risk: false,
            ..
        } => Err(refuse(
            "a manual retry repeats the same event and may duplicate it; pass --accept-duplicate-risk",
        )),
        Decision::Retry { note, .. }
        | Decision::Dispose { note, .. }
        | Decision::Waive { note, .. }
            if note.trim().is_empty() =>
        {
            Err(refuse("an audit note is required"))
        }
        Decision::Pause { reason, .. } if reason.trim().is_empty() => {
            Err(refuse("a pause reason is required"))
        }
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

    #[test]
    fn unknown_overdue_and_held_stay_distinct() {
        assert_eq!(classify("unknown_handoff").0, "unknown");
        assert_eq!(classify("receipt_overdue").0, "overdue");
        assert_eq!(classify("held_overdue").0, "overdue");
        assert_eq!(classify("recipient_held").0, "held");
        assert_eq!(classify("retries_exhausted").0, "refused");
        assert!(classify("unknown_handoff").1.contains("Never resent"));
    }

    #[test]
    fn tier_names_round_trip() {
        assert_eq!(
            parse_tier("native_accepted"),
            Some(EvidenceTier::NativeAccepted)
        );
        assert_eq!(parse_tier("delivered"), None);
    }
}
