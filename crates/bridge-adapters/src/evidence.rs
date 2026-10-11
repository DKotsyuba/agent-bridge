//! Distinct native evidence tiers as immutable records.
//!
//! Bridge persisted, native queue/inbox accepted, hook payload handed
//! out, model context observed and application processed are **separate**
//! kinds of evidence. A zero exit, completed job, queued receipt or
//! rendered text is not an interchangeable `delivered = true`. This module
//! gives each tier its own constructor path and keeps records immutable:
//! evidence is appended, never rewritten or downgraded.

/// One tier of native-side evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceTier {
    /// The native queue or inbox accepted the event (storage acceptance;
    /// says nothing about consumption).
    NativeAccepted,
    /// The native side is holding the event (nonterminal, with a recheck
    /// trigger and eventual receipt/unknown handling).
    Held,
    /// A hook payload was handed out and flushed (positive adapter
    /// evidence; not atomically proof of host context acceptance).
    Emitted,
    /// The recipient's model context was observed to contain the payload.
    ContextObserved,
    /// The receiving application processed the payload's business meaning.
    Processed,
}

impl EvidenceTier {
    /// Canonical tier name for records and status output.
    pub const fn as_str(self) -> &'static str {
        match self {
            EvidenceTier::NativeAccepted => "native_accepted",
            EvidenceTier::Held => "held",
            EvidenceTier::Emitted => "emitted",
            EvidenceTier::ContextObserved => "context_observed",
            EvidenceTier::Processed => "processed",
        }
    }

    /// Whether this tier alone may justify calling an attempt accepted
    /// for reporting.
    ///
    /// Only [`EvidenceTier::ContextObserved`] and
    /// [`EvidenceTier::Processed`] do: queue acceptance, holds and
    /// emission are earlier, weaker tiers by construction.
    pub const fn proves_delivery(self) -> bool {
        matches!(
            self,
            EvidenceTier::ContextObserved | EvidenceTier::Processed
        )
    }
}

/// One immutable evidence record.
///
/// Records are created complete and never mutated; later observations are
/// new records in the [`EvidenceLog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Which tier this record is.
    pub tier: EvidenceTier,
    /// The event the evidence is about (publisher-stable id).
    pub event_id: String,
    /// Digest of the payload bytes the evidence refers to.
    pub payload_digest: String,
    /// Unix epoch milliseconds of the observation.
    pub at_ms: u64,
    /// Bounded human-readable detail (empty allowed).
    pub detail: String,
}

impl EvidenceRecord {
    /// Builds a record; tier, event and digest are required, detail may be
    /// empty.
    pub fn new(
        tier: EvidenceTier,
        event_id: impl Into<String>,
        payload_digest: impl Into<String>,
        at_ms: u64,
        detail: impl Into<String>,
    ) -> Self {
        EvidenceRecord {
            tier,
            event_id: event_id.into(),
            payload_digest: payload_digest.into(),
            at_ms,
            detail: detail.into(),
        }
    }
}

/// Append-only log of evidence records for one or more events.
///
/// The log never rewrites or reorders history (append order is record
/// order); queries return immutable references. There is deliberately no
/// remove, update or "mark delivered" operation.
#[derive(Debug, Default)]
pub struct EvidenceLog {
    records: Vec<EvidenceRecord>,
}

impl EvidenceLog {
    /// Appends one record; returns its index for reference.
    pub fn append(&mut self, record: EvidenceRecord) -> usize {
        self.records.push(record);
        self.records.len() - 1
    }

    /// All records for one event, in append order.
    pub fn for_event(&self, event_id: &str) -> Vec<&EvidenceRecord> {
        self.records
            .iter()
            .filter(|record| record.event_id == event_id)
            .collect()
    }

    /// The strongest tier recorded for one event, if any.
    ///
    /// Tier strength order is by what it proves: nothing, then
    /// NativeAccepted/Held/Emitted (none proves delivery), then
    /// ContextObserved, then Processed.
    pub fn strongest(&self, event_id: &str) -> Option<EvidenceTier> {
        let mut strongest: Option<EvidenceTier> = None;
        for record in self.for_event(event_id) {
            let stronger = match strongest {
                None => true,
                Some(current) => record.tier > current,
            };
            if stronger {
                strongest = Some(record.tier);
            }
        }
        strongest
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for tier distinctness and append-only behavior.

    use super::*;

    #[test]
    fn tiers_stay_distinct_and_only_context_or_processed_prove_delivery() {
        assert!(!EvidenceTier::NativeAccepted.proves_delivery());
        assert!(!EvidenceTier::Held.proves_delivery());
        assert!(!EvidenceTier::Emitted.proves_delivery());
        assert!(EvidenceTier::ContextObserved.proves_delivery());
        assert!(EvidenceTier::Processed.proves_delivery());
    }

    #[test]
    fn log_is_append_only_and_reports_strongest_tier() {
        let mut log = EvidenceLog::default();
        log.append(EvidenceRecord::new(
            EvidenceTier::NativeAccepted,
            "evt-1",
            "digest-1",
            1_000,
            "queue entry accepted",
        ));
        log.append(EvidenceRecord::new(
            EvidenceTier::Emitted,
            "evt-1",
            "digest-1",
            2_000,
            "hook stdout flushed",
        ));
        assert_eq!(log.strongest("evt-1"), Some(EvidenceTier::Emitted));
        assert_eq!(log.for_event("evt-1").len(), 2);
        assert_eq!(log.strongest("evt-2"), None);
        log.append(EvidenceRecord::new(
            EvidenceTier::ContextObserved,
            "evt-1",
            "digest-1",
            3_000,
            "marker observed in exact session",
        ));
        assert_eq!(log.strongest("evt-1"), Some(EvidenceTier::ContextObserved));
    }
}
