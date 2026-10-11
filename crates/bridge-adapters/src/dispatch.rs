//! Adapter side of the consumed `bridge-dispatch` contract.
//!
//! The core issues a fenced attempt capability for an exact
//! actor/recipient/endpoint epoch and frozen manifest. This module is the
//! adapter layer's half of that boundary: it validates the fence before any
//! invocation, and it owns the attempt gate that keeps "one possibly
//! accepted automatic attempt per event" true even under duplicate
//! dispatch, crashes and lost acknowledgements.
//!
//! Rules encoded here (all from the agreed revision 1 text):
//! - stale epoch/actor/permission/deadline refuses **without invocation**;
//! - never invoke both paths for one event;
//! - unknown stays retained — no automatic replay after a possible
//!   handoff, no timer-, ack-, helper-exit- or lease-driven reoffer;
//! - positively known-unsent closes its attempt before any bounded retry.

use std::collections::BTreeMap;

use bridge_core::EnvelopeHash;

use crate::attest::{ActorId, AttestedBinding};

/// The frozen manifest of one dispatch attempt, as issued by the core.
///
/// A summary of the core-issued attempt capability: which event, which
/// recipient and actor, under which endpoint epoch, with which effective
/// carrier and digest, and until when. The adapter never mutates it; a
/// change anywhere is a new attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// Publisher-stable event id (identity only, never a freshness signal).
    pub event_id: String,
    /// Frozen identity-content hash of the envelope being delivered.
    pub envelope_hash: EnvelopeHash,
    /// Canonical address string of the exact recipient.
    pub recipient: String,
    /// The actor the attempt is fenced to.
    pub actor: ActorId,
    /// Endpoint binding epoch the attempt was issued under.
    pub binding_epoch: crate::attest::BindingEpoch,
    /// The single effective carrier for this attempt.
    pub carrier: crate::auto::CarrierName,
    /// Absolute Unix epoch millisecond deadline for starting the invocation.
    pub deadline_ms: u64,
}

/// Why a fenced attempt was refused before any invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceRefusal {
    /// The attempt's epoch no longer matches the binding.
    StaleEpoch,
    /// The attempt is fenced to a different actor than the binding serves.
    ActorMismatch,
    /// The attempt deadline has passed; nothing was invoked.
    DeadlineExceeded,
    /// The loaded adapter lacks permission/capability for this carrier.
    Permission,
}

/// Validates a fenced attempt against the current binding.
///
/// Pure check with no effects: epoch equality, actor equality, carrier
/// capability and deadline. Any failure is a [`FenceRefusal`] and the
/// caller must not invoke anything — a new invocation requires the core to
/// issue a new attempt.
pub fn validate_fence(
    attempt: &Attempt,
    binding: &AttestedBinding,
    now_ms: u64,
) -> Result<(), FenceRefusal> {
    if !binding.accepts_epoch(attempt.binding_epoch) {
        return Err(FenceRefusal::StaleEpoch);
    }
    if binding.actor != attempt.actor {
        return Err(FenceRefusal::ActorMismatch);
    }
    if now_ms > attempt.deadline_ms {
        return Err(FenceRefusal::DeadlineExceeded);
    }
    if !binding
        .capabilities
        .carrier(attempt.carrier.as_str())
        .usable()
    {
        return Err(FenceRefusal::Permission);
    }
    Ok(())
}

/// Terminal outcome of one attempt as observed by the adapter.
///
/// The distinction that matters: `PossiblyAccepted` (evidence of handoff
/// exists but completion is unknown) keeps the event retained with no
/// automatic replay, while `PositivelyUnsent` (proved never invoked or
/// never accepted) closes the attempt and permits a bounded retry policy
/// at the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The native side positively accepted the event (queue acceptance,
    /// held receipt, or full hook emission acknowledgement).
    Accepted,
    /// A handoff may have happened (possible reply/stdout, lost ack, lease
    /// expiry, helper exit, late result); retained, needs reconciliation.
    PossiblyAccepted { reason: &'static str },
    /// Positively established the native side never received the event;
    /// the attempt is closed before any retry.
    PositivelyUnsent { reason: &'static str },
    /// A permanent refusal (unsupported capability, archived target,
    /// invalid recipient); no retry of this attempt.
    Refused { reason: &'static str },
}

/// Per-event attempt gate enforcing the single automatic attempt rule.
///
/// Tracks, per event key, whether an automatic attempt has ever reached a
/// possibly-accepted-or-beyond state. Duplicate dispatches of the same
/// event while such an attempt exists are denied; positively-unsent
/// outcomes close the attempt so the core's bounded retry can issue a new
/// one. Manual recovery is explicit and outside this type: it happens in
/// the core with recorded possible-duplicate risk, never here.
#[derive(Debug, Default)]
pub struct AttemptGate {
    open: BTreeMap<String, AttemptOutcome>,
}

impl AttemptGate {
    /// Tries to open the automatic attempt for one event key.
    ///
    /// `Ok(())` when no possibly-accepted attempt exists (a fresh event, or
    /// one whose previous attempt closed as positively unsent or refused);
    /// `Err` repeats the reason the previous attempt stays retained, which
    /// the caller reports without invoking anything.
    pub fn begin(&mut self, event_key: &str) -> Result<(), AttemptOutcome> {
        match self.open.get(event_key) {
            None
            | Some(AttemptOutcome::PositivelyUnsent { .. })
            | Some(AttemptOutcome::Refused { .. }) => {
                self.open.insert(
                    event_key.to_string(),
                    AttemptOutcome::PossiblyAccepted {
                        reason: "attempt opened; invocation not yet observed",
                    },
                );
                Ok(())
            }
            Some(outcome) => Err(outcome.clone()),
        }
    }

    /// Records the observed outcome of the attempt previously opened with
    /// [`AttemptGate::begin`].
    ///
    /// Overwrites the gate's provisional entry; the mapping itself is
    /// total — every carrier result funnels into exactly one outcome.
    pub fn record(&mut self, event_key: &str, outcome: AttemptOutcome) {
        self.open.insert(event_key.to_string(), outcome);
    }

    /// The current recorded outcome for one event key, if any.
    pub fn current(&self, event_key: &str) -> Option<&AttemptOutcome> {
        self.open.get(event_key)
    }
}

#[cfg(test)]
mod tests {
    //! Unit checks for fence validation and the attempt gate.

    use super::*;
    use crate::attest::{
        ActorRole, BindingEpoch, Capability, EndpointEvidence, LoadedCapabilities,
    };
    use crate::auto::CarrierName;
    use bridge_core::{
        Envelope, EnvelopeHash, EventId, Harness, Kind, Metadata, Mode, NativeAddress, Payload,
        Policy, PublisherId,
    };

    /// A real envelope hash; `EnvelopeHash` cannot be forged by hand.
    fn hash() -> EnvelopeHash {
        Envelope::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new("evt-1").unwrap(),
            NativeAddress::new("h", Harness::Codex, "store", "t-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Message,
            Policy::KeepAll,
            Payload::new("body").unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap()
        .envelope_hash()
    }

    fn binding(epoch: u64) -> AttestedBinding {
        let mut capabilities = LoadedCapabilities::default();
        capabilities
            .carriers
            .insert("inject", Capability::Supported);
        capabilities
            .carriers
            .insert("message", Capability::Supported);
        AttestedBinding {
            address: NativeAddress::new("h", Harness::Codex, "store", "t-1").unwrap(),
            actor: ActorId::root("t-1").unwrap(),
            epoch: BindingEpoch(epoch),
            evidence: EndpointEvidence {
                pid: 1,
                endpoint_path: "/tmp/e.sock".into(),
                observed_at_ms: 0,
            },
            capabilities,
        }
    }

    fn attempt(epoch: u64) -> Attempt {
        Attempt {
            event_id: "evt-1".into(),
            envelope_hash: hash(),
            recipient: "h/codex/store/t-1".into(),
            actor: ActorId::root("t-1").unwrap(),
            binding_epoch: BindingEpoch(epoch),
            carrier: CarrierName::Message,
            deadline_ms: 10_000,
        }
    }

    #[test]
    fn stale_epoch_actor_and_deadline_refuse_without_invocation() {
        let current = binding(2);
        assert_eq!(validate_fence(&attempt(2), &current, 0), Ok(()));
        assert_eq!(
            validate_fence(&attempt(1), &current, 0),
            Err(FenceRefusal::StaleEpoch)
        );
        let mut late = attempt(2);
        late.deadline_ms = 100;
        assert_eq!(
            validate_fence(&late, &current, 200),
            Err(FenceRefusal::DeadlineExceeded)
        );
        let mut foreign = attempt(2);
        foreign.actor = ActorId {
            role: ActorRole::Child,
            native_id: "other".into(),
        };
        assert_eq!(
            validate_fence(&foreign, &current, 0),
            Err(FenceRefusal::ActorMismatch)
        );
        let mut unsupported = binding(2);
        unsupported
            .capabilities
            .carriers
            .insert("message", Capability::Unsupported("helper absent"));
        assert_eq!(
            validate_fence(&attempt(2), &unsupported, 0),
            Err(FenceRefusal::Permission)
        );
    }

    #[test]
    fn one_possibly_accepted_automatic_attempt_per_event() {
        let mut gate = AttemptGate::default();
        assert!(gate.begin("k").is_ok());
        // A duplicate dispatch while the attempt is open is denied, with
        // the retained reason repeated.
        assert!(matches!(
            gate.begin("k"),
            Err(AttemptOutcome::PossiblyAccepted { .. })
        ));
        // Possible handoff stays retained: no second automatic attempt.
        gate.record(
            "k",
            AttemptOutcome::PossiblyAccepted {
                reason: "lost hook acknowledgement",
            },
        );
        assert!(matches!(
            gate.begin("k"),
            Err(AttemptOutcome::PossiblyAccepted { .. })
        ));
        // Positively unsent closes the attempt; a bounded retry may open a
        // new one.
        gate.record(
            "k",
            AttemptOutcome::PositivelyUnsent {
                reason: "helper refused before any write",
            },
        );
        assert!(gate.begin("k").is_ok());
        // Positive acceptance is terminal for automatic attempts too.
        gate.record("k", AttemptOutcome::Accepted);
        assert!(matches!(gate.begin("k"), Err(AttemptOutcome::Accepted)));
        // Independent events do not interfere.
        assert!(gate.begin("other").is_ok());
    }
}
