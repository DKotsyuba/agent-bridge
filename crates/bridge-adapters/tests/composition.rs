//! Adapter composition tests with a synthetic publisher over real custody.
//!
//! One synthetic publisher publishes through the real `bridge-core`
//! custody storage (an isolated temporary database); the adapter layer
//! then selects a path, validates the fence, runs the attempt gate and
//! records evidence tiers. These tests pin the cross-crate obligations of
//! the `bridge-native-host` and `bridge-dispatch` revision 1 contracts:
//! unknown stays retained, never both paths, one automatic attempt,
//! distinct evidence tiers, and the accepted (recorded, not eliminated)
//! auto timing race.

mod common;

use bridge_adapters::attest::{
    ActorId, AttestedBinding, BindingEpoch, Capability, EndpointEvidence, LoadedCapabilities,
};
use bridge_adapters::auto::{CarrierName, Selection, select};
use bridge_adapters::claude::{HeldCallback, HeldTracker, MessageId};
use bridge_adapters::codex::attempt_outcome;
use bridge_adapters::codex::{Correlation, QueueOutcome, correlate};
use bridge_adapters::dispatch::{Attempt, AttemptGate, AttemptOutcome, FenceRefusal};
use bridge_adapters::evidence::{EvidenceLog, EvidenceTier};
use bridge_adapters::lifecycle::{
    LifecycleState, NoWakePolicy, Observation, ObservationSource, guard_invocation,
};
use bridge_core::{
    Envelope, EventId, Harness, Kind, Limits, Metadata, Mode, NativeAddress, Payload, Policy,
    PublisherId, Storage,
};

use common::TempDir;

/// A synthetic publisher's event, built exactly as a real one would be.
fn envelope(mode: Mode, payload: &str) -> Envelope {
    let mut metadata = Metadata::new();
    metadata.insert("project".to_string(), "agent-bridge".to_string());
    Envelope::new(
        PublisherId::new("synthetic-publisher").unwrap(),
        EventId::new("evt-compose-1").unwrap(),
        NativeAddress::new("host-1", Harness::Codex, "store", "thread-1").unwrap(),
        Kind::new("worker.completed").unwrap(),
        mode,
        Policy::KeepAll,
        Payload::new(payload).unwrap(),
        metadata,
        None,
    )
    .unwrap()
}

/// The attested binding the composition runs against.
fn binding(epoch: u64) -> AttestedBinding {
    let mut capabilities = LoadedCapabilities::default();
    capabilities
        .carriers
        .insert("inject", Capability::Supported);
    capabilities
        .carriers
        .insert("message", Capability::Supported);
    AttestedBinding {
        address: NativeAddress::new("host-1", Harness::Codex, "store", "thread-1").unwrap(),
        actor: ActorId::root("thread-1").unwrap(),
        epoch: BindingEpoch(epoch),
        evidence: EndpointEvidence {
            pid: 4242,
            endpoint_path: "/tmp/composition.sock".into(),
            observed_at_ms: 1_000,
        },
        capabilities,
    }
}

fn observation(state: LifecycleState, at_ms: u64) -> Observation {
    Observation {
        state,
        source: ObservationSource::OwnerSession,
        binding_epoch: BindingEpoch(1),
        observed_at_ms: at_ms,
    }
}

#[test]
fn synthetic_publisher_flows_through_custody_into_one_path() {
    let dir = TempDir::new("compose");
    let mut storage = Storage::open(dir.path("custody.db"), Limits::new(100)).unwrap();
    let event = envelope(Mode::Auto, "composition payload");
    let outcome = storage.publish(&event, 1_000).unwrap();
    assert!(!outcome.receipt.replayed);
    // Identical replay is the same custody, not a second event.
    let replay = storage.publish(&event, 1_100).unwrap();
    assert!(replay.receipt.replayed);

    let current = binding(1);
    let policy = NoWakePolicy::default();

    // Active recipient: auto selects inject, never message too.
    let (selection, basis) = select(
        Mode::Auto,
        &observation(LifecycleState::Active, 1_200),
        1_200,
        500,
        current.epoch,
        &current.address.to_canonical_string(),
        &policy,
    );
    assert_eq!(selection, Selection::Invoke(CarrierName::Inject));
    assert_eq!(basis.effective_state, LifecycleState::Active);

    // The attempt is fenced and validated before any invocation.
    let attempt = Attempt {
        event_id: event.event_id.as_str().to_string(),
        envelope_hash: event.envelope_hash(),
        recipient: current.address.to_canonical_string(),
        actor: current.actor.clone(),
        binding_epoch: current.epoch,
        carrier: CarrierName::Inject,
        deadline_ms: 9_999,
    };
    assert_eq!(
        bridge_adapters::dispatch::validate_fence(&attempt, &current, 1_300),
        Ok(())
    );
    // A stale epoch from a pre-renewal attempt refuses without invocation.
    let stale = Attempt {
        binding_epoch: BindingEpoch(0),
        ..attempt.clone()
    };
    assert_eq!(
        bridge_adapters::dispatch::validate_fence(&stale, &current, 1_300),
        Err(FenceRefusal::StaleEpoch)
    );

    // One automatic attempt; a duplicate dispatch is denied.
    let mut gate = AttemptGate::default();
    let key = format!("{}:{}", event.publisher.as_str(), event.event_id.as_str());
    assert!(gate.begin(&key).is_ok());
    assert!(matches!(
        gate.begin(&key),
        Err(AttemptOutcome::PossiblyAccepted { .. })
    ));

    // Hook emission is positive adapter evidence, and only that.
    let mut log = EvidenceLog::default();
    log.append(bridge_adapters::evidence::EvidenceRecord::new(
        EvidenceTier::Emitted,
        key.clone(),
        event.envelope_hash().as_str().to_string(),
        1_400,
        "hook stdout flushed",
    ));
    assert_eq!(log.strongest(&key), Some(EvidenceTier::Emitted));
    gate.record(&key, AttemptOutcome::Accepted);
    assert!(matches!(gate.begin(&key), Err(AttemptOutcome::Accepted)));
}

#[test]
fn idle_recipient_selects_message_and_queue_evidence_stays_weak() {
    let current = binding(1);
    let policy = NoWakePolicy::default();
    let (selection, basis) = select(
        Mode::Auto,
        &observation(LifecycleState::Idle, 2_000),
        2_000,
        500,
        current.epoch,
        &current.address.to_canonical_string(),
        &policy,
    );
    assert_eq!(selection, Selection::Invoke(CarrierName::Message));
    // The race is recorded: the basis shows what was observed and when.
    assert_eq!(basis.effective_state, LifecycleState::Idle);
    assert_eq!(basis.observed_at_ms, 2_000);

    // Queue acceptance maps to possibly-accepted, and correlation is
    // never deduplication.
    let outcome = attempt_outcome(&QueueOutcome::NativeAccepted {
        client_user_message_id: "cu-1".into(),
    });
    assert!(matches!(outcome, AttemptOutcome::PossiblyAccepted { .. }));
    assert_eq!(
        correlate("cu-1", true, false),
        Correlation::Present {
            deduplicates: false
        }
    );
    let mut gate = AttemptGate::default();
    gate.begin("k").unwrap();
    gate.record("k", outcome);
    assert!(matches!(
        gate.begin("k"),
        Err(AttemptOutcome::PossiblyAccepted { .. })
    ));
}

#[test]
fn unknown_states_hold_and_never_become_message() {
    let current = binding(1);
    let policy = NoWakePolicy::default();
    for state in [
        LifecycleState::Unknown,
        LifecycleState::Disconnected,
        LifecycleState::Archived,
        LifecycleState::PermissionWait,
    ] {
        let (selection, _) = select(
            Mode::Auto,
            &observation(state, 2_000),
            2_000,
            500,
            current.epoch,
            &current.address.to_canonical_string(),
            &policy,
        );
        assert!(matches!(selection, Selection::Hold(_)), "{state:?}");
        // And the message carrier alone is equally blocked.
        assert!(matches!(
            guard_invocation(
                &current.address.to_canonical_string(),
                CarrierName::Message,
                state,
                &policy
            ),
            bridge_adapters::lifecycle::GuardDecision::Hold(_)
        ));
    }
}

#[test]
fn claude_held_flow_resolves_through_epoch_bound_callbacks() {
    let mut tracker = HeldTracker::default();
    let msg = MessageId("m-compose".into());
    tracker.held(BindingEpoch(1), &msg);
    let mut log = EvidenceLog::default();
    log.append(bridge_adapters::evidence::EvidenceRecord::new(
        EvidenceTier::Held,
        "held-event",
        "digest-held",
        1_000,
        "held under epoch 1",
    ));
    // Release under the bound epoch closes held positively.
    assert!(tracker.callback(BindingEpoch(1), &msg, HeldCallback::Released));
    log.append(bridge_adapters::evidence::EvidenceRecord::new(
        EvidenceTier::ContextObserved,
        "held-event",
        "digest-held",
        1_200,
        "released into context",
    ));
    assert_eq!(
        log.strongest("held-event"),
        Some(EvidenceTier::ContextObserved)
    );
    assert!(EvidenceTier::ContextObserved.proves_delivery());
}
