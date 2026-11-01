//! Integration checks for fenced dispatch over a frozen manifest: auth of
//! the endpoint, reservation and invocation fencing, evidence tiers,
//! uncertainty custody, ordering, coalescing, expiry and restart recovery.
//!
//! All carriers are synthetic; all state is isolated (fresh temporary
//! databases or in-memory stores). No native host is touched.

mod common;

use std::sync::{Arc, Barrier, Mutex};

use bridge_core::dispatch::{
    AttemptFence, AttemptState, Attestation, Capabilities, DispatchCarrier, DispatchReport,
    DispatchTiming, EffectiveMode, Invoked, Lifecycle, Outcome, Selection, dispatch_message,
    resolve_mode,
};
use bridge_core::framing::PROVENANCE_STATEMENT;
use bridge_core::recovery::{DeliveryState, EvidenceEffect, EvidenceTier, IncidentState};
use bridge_core::{CoreError, EventState, ExpiresAt, Limits, Mode, NativeAddress, Storage};
use common::{
    ScriptedCarrier, TempDir, attest, batched, codex, keep_all, latest, register_tags, store,
    with_meta,
};
use sha2::{Digest, Sha256};

/// Default windows used by most checks.
fn timing() -> DispatchTiming {
    DispatchTiming::default()
}

/// Late batch evidence settles only members still owned by the old attempt.
/// Disposed members and newer invoking, accepted or unknown attempts retain
/// their states and incidents; every original member still receives evidence.
#[test]
fn late_batch_outcomes_fence_each_member_independently() {
    for sibling in ["disposed", "invoking", "accepted", "unknown"] {
        for refusal in [false, true] {
            let mut storage = store();
            let recipient = codex("batch-owner");
            let attestation = attest(&recipient, Lifecycle::Inactive, 1);
            for id in ["a", "b"] {
                storage
                    .publish(&batched("agent-run", id, &recipient, "pair"), 1000)
                    .unwrap();
            }
            let first = attempt(
                storage
                    .reserve_next(&attestation, EffectiveMode::Message, 2000, &timing())
                    .unwrap(),
            );
            assert_eq!(first.members.len(), 2);
            storage
                .mark_invoking(&first.fence, &attestation, 2001)
                .unwrap();
            storage
                .record_outcome(
                    &first.fence,
                    Outcome::OutcomeUnknown {
                        reason: "fixture lost receipt".into(),
                    },
                    2002,
                )
                .unwrap();
            if sibling == "disposed" {
                storage
                    .dispose_event("agent-run", "a", "operator", "fixture decision", 3000)
                    .unwrap();
            } else {
                storage
                    .authorize_manual_retry("agent-run", "a", "operator", "fixture retry", 3000)
                    .unwrap();
                let second = attempt(
                    storage
                        .reserve_next(&attestation, EffectiveMode::Message, 3001, &timing())
                        .unwrap(),
                );
                assert_eq!(second.members.len(), 1);
                storage
                    .mark_invoking(&second.fence, &attestation, 3002)
                    .unwrap();
                let outcome = match sibling {
                    "accepted" => Some(Outcome::NativeAccepted {
                        evidence: "fixture queue accepted".into(),
                    }),
                    "unknown" => Some(Outcome::OutcomeUnknown {
                        reason: "fixture newer lost receipt".into(),
                    }),
                    _ => None,
                };
                if let Some(outcome) = outcome {
                    storage
                        .record_outcome(&second.fence, outcome, 3003)
                        .unwrap();
                }
            }
            let before = storage
                .delivery_evidence("agent-run", "a")
                .unwrap()
                .unwrap();
            let incidents = storage
                .incidents(true, 4000, 100)
                .unwrap()
                .into_iter()
                .filter(|row| row.event_id == "a")
                .collect::<Vec<_>>();
            if refusal {
                storage
                    .record_outcome(
                        &first.fence,
                        Outcome::PermanentRefusal {
                            reason: "fixture old refusal".into(),
                        },
                        4000,
                    )
                    .unwrap();
            } else {
                storage
                    .record_evidence(
                        "agent-run",
                        "b",
                        first.fence.attempt_seq,
                        EvidenceTier::KnownUnsent,
                        "fixture old helper never wrote",
                        4000,
                    )
                    .unwrap();
            }
            let after = storage
                .delivery_evidence("agent-run", "a")
                .unwrap()
                .unwrap();
            assert_eq!(
                after.delivery, before.delivery,
                "sibling {sibling}, refusal {refusal}"
            );
            assert_eq!(after.attempts_made, before.attempts_made);
            if sibling != "disposed" {
                assert_eq!(
                    after.attempt, before.attempt,
                    "the newer attempt is untouched"
                );
            }
            assert_eq!(
                storage
                    .incidents(true, 4000, 100)
                    .unwrap()
                    .into_iter()
                    .filter(|row| row.event_id == "a")
                    .collect::<Vec<_>>(),
                incidents
            );
            for id in ["a", "b"] {
                assert!(
                    storage
                        .delivery_evidence("agent-run", id)
                        .unwrap()
                        .unwrap()
                        .tiers
                        .iter()
                        .any(|entry| entry.attempt_seq == first.fence.attempt_seq
                            && entry.tier
                                == if refusal {
                                    EvidenceTier::Refused
                                } else {
                                    EvidenceTier::KnownUnsent
                                })
                );
            }
        }
    }
}

/// Unwraps a reserved or invoking attempt from a selection.
fn attempt(selection: Selection) -> bridge_core::dispatch::AttemptRecord {
    match selection {
        Selection::Attempt(record) => *record,
        other => panic!("expected an attempt, got {other:?}"),
    }
}

/// Runs one message-path dispatch at a fixed instant.
fn drive(
    storage: &Mutex<Storage>,
    carrier: &mut ScriptedCarrier,
    recipient: &NativeAddress,
    now: u64,
) -> DispatchReport {
    dispatch_message(storage, carrier, recipient, &|| now, &timing()).unwrap()
}

/// A reservation freezes the recipient, actor, endpoint epoch, framing
/// path, manifest bytes and deadline; nothing else can claim the event
/// meanwhile.
#[test]
fn reserved_attempt_freezes_recipient_actor_epoch_path_manifest_and_deadline() {
    let mut storage = store();
    let recipient = codex("thread-1");
    let envelope = keep_all("agent-run", "evt-1", &recipient, Mode::Auto);
    storage.publish(&envelope, 1_000).unwrap();

    let record = attempt(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 7),
                EffectiveMode::Message,
                2_000,
                &timing(),
            )
            .unwrap(),
    );
    assert_eq!(record.state, AttemptState::Reserved);
    assert_eq!(record.fence.recipient, recipient.to_canonical_string());
    assert_eq!(record.fence.endpoint_epoch, 7);
    assert_eq!(record.actor, "thread-1", "the exact native actor is frozen");
    assert_eq!(record.proof_ref, "fixture-proof");
    assert_eq!(record.granted, "inject,message");
    assert_eq!(record.effective_mode, EffectiveMode::Message);
    assert_eq!(record.requested_mode, Mode::Auto, "requested mode is kept");
    assert_eq!(record.deadline_ms, 62_000);
    assert_eq!(record.lease_expires_ms, Some(32_000));
    assert_eq!(record.members.len(), 1);
    assert_eq!(
        record.members[0].envelope_hash,
        envelope.envelope_hash().as_str()
    );
    assert!(
        record
            .manifest
            .contains("<agent-run event=\"evt-1\" kind=\"worker.completed\" source=\"agent-run\">"),
        "the frozen manifest includes the stamped issuer provenance: {}",
        record.manifest
    );
    assert!(record.manifest.contains(PROVENANCE_STATEMENT));
    assert_eq!(
        record.fence.manifest_hash,
        format!("{:x}", Sha256::digest(record.manifest.as_bytes()))
    );
    // The stored row is exactly what the reservation returned.
    assert_eq!(
        storage.attempt(record.fence.attempt_seq).unwrap().unwrap(),
        record
    );
    assert_eq!(
        storage.count_delivery(DeliveryState::Reserved).unwrap(),
        1,
        "the event is owned by the attempt"
    );
}

/// `auto` resolves to exactly one effective path from the observed
/// lifecycle and the attempt records it; the other path is never taken.
#[test]
fn auto_resolves_from_lifecycle_and_never_takes_both_paths() {
    assert_eq!(
        resolve_mode(Mode::Auto, Lifecycle::Active),
        Some(EffectiveMode::Inject)
    );
    assert_eq!(
        resolve_mode(Mode::Auto, Lifecycle::Inactive),
        Some(EffectiveMode::Message)
    );
    assert_eq!(resolve_mode(Mode::Auto, Lifecycle::Unknown), None);
    assert_eq!(resolve_mode(Mode::Auto, Lifecycle::AwaitingInput), None);

    let mut storage = store();
    let recipient = codex("thread-a");
    storage
        .publish(
            &keep_all("agent-run", "auto-1", &recipient, Mode::Auto),
            1_000,
        )
        .unwrap();

    // An active recipient's auto event waits for its natural hook: the
    // message path finds nothing and never wakes the recipient.
    assert_eq!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Active, 1),
                EffectiveMode::Message,
                2_000,
                &timing()
            )
            .unwrap(),
        Selection::Idle
    );
    // The hook drains it on the inject path, already invoking.
    let drained = attempt(
        storage
            .drain_inject(&attest(&recipient, Lifecycle::Active, 1), 3_000, &timing())
            .unwrap(),
    );
    assert_eq!(drained.effective_mode, EffectiveMode::Inject);
    assert_eq!(drained.state, AttemptState::Invoking);
    // Once taken, the other path can never take the same event.
    assert_eq!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                4_000,
                &timing()
            )
            .unwrap(),
        Selection::Idle
    );

    // An inactive recipient gets message, and a hook claiming inject for an
    // inactive recipient is held, not served.
    storage
        .publish(
            &keep_all("agent-run", "auto-2", &recipient, Mode::Auto),
            5_000,
        )
        .unwrap();
    match storage
        .drain_inject(
            &attest(&recipient, Lifecycle::Inactive, 1),
            6_000,
            &timing(),
        )
        .unwrap()
    {
        Selection::Held(reason) => assert!(reason.contains("active"), "{reason}"),
        other => panic!("inject for an inactive recipient must hold, got {other:?}"),
    }
    let message = attempt(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                6_000,
                &timing(),
            )
            .unwrap(),
    );
    assert_eq!(message.effective_mode, EffectiveMode::Message);
    assert_eq!(message.members[0].event_id, "auto-2");
}

/// Unknown, awaiting or unloaded recipients hold visibly with a
/// retained incident and no carrier invocation: none of them counts as
/// inactive.
#[test]
fn unknown_awaiting_or_unloaded_recipients_hold_visibly_without_invoking() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-hold");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "held-1", &recipient, Mode::Auto),
            1_000,
        )
        .unwrap();

    for lifecycle in [Lifecycle::Unknown, Lifecycle::AwaitingInput] {
        let mut carrier = ScriptedCarrier::new(lifecycle, ScriptedCarrier::accepted());
        match drive(&shared, &mut carrier, &recipient, 2_000) {
            DispatchReport::Held(reason) => {
                assert!(
                    reason.contains("unknown") || reason.contains("approval"),
                    "{reason}"
                );
            }
            other => panic!("expected a hold for {lifecycle:?}, got {other:?}"),
        }
        assert!(carrier.sends.is_empty(), "never invoked for {lifecycle:?}");
    }
    let storage = shared.lock().unwrap();
    assert_eq!(storage.holds(10).unwrap().len(), 1, "the hold is visible");
    let evidence = storage
        .delivery_evidence("agent-run", "held-1")
        .unwrap()
        .unwrap();
    assert!(evidence.hold_reason.is_some());
    assert_eq!(evidence.delivery, DeliveryState::Unhanded);
    assert!(
        storage
            .latest_attempt("agent-run", "held-1")
            .unwrap()
            .is_none()
    );
    drop(storage);

    // A failed attestation is a hold too, never an assumption of idleness.
    let mut broken = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    broken.attest_error = Some("endpoint unreachable".into());
    assert!(matches!(
        drive(&shared, &mut broken, &recipient, 3_000),
        DispatchReport::Held(reason) if reason.contains("attestation failed")
    ));
    assert!(broken.sends.is_empty());

    // An unloaded capability holds as well (message path not granted).
    let limited = Attestation::verified(
        recipient.clone(),
        "thread-hold",
        1,
        Lifecycle::Inactive,
        Capabilities {
            inject: true,
            message: false,
        },
        "fixture-proof",
    )
    .unwrap();
    assert!(matches!(
        shared
            .lock()
            .unwrap()
            .reserve_next(&limited, EffectiveMode::Message, 4_000, &timing())
            .unwrap(),
        Selection::Held(reason) if reason.contains("not loaded")
    ));
}

/// The `invoking` state is committed before the carrier acts — proven
/// by a second connection reading the attempt state during the hand-off —
/// and the manifest bytes match the frozen reservation.
#[test]
fn invoking_is_durable_before_the_carrier_can_act_and_carries_the_frozen_bytes() {
    // A second connection reads the attempt DURING the carrier call: it must
    // already be invoking with exactly the manifest the carrier receives.
    let dir = TempDir::new("dispatch-probe");
    let db = dir.path("bridge.db");
    let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    let recipient = codex("thread-9");
    storage
        .publish(
            &keep_all("agent-run", "evt-probe", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let shared = Mutex::new(storage);

    /// Carrier that reads the stored attempt row at the moment of the hand-off.
    struct Probing {
        /// Path of the test's own database file, opened on a second connection.
        db: std::path::PathBuf,
        /// The `(state, manifest)` of the newest stored attempt seen during `send`.
        seen: Arc<Mutex<Option<(String, String)>>>,
    }
    impl DispatchCarrier for Probing {
        /// Returns this fixture's attestation for the recipient.
        fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
            Ok(attest(recipient, Lifecycle::Inactive, 1))
        }
        /// Applies this fixture's scripted outcome to the frozen attempt.
        fn send(&mut self, attempt: &bridge_core::dispatch::AttemptRecord) -> Outcome {
            let connection = rusqlite::Connection::open(&self.db).unwrap();
            let row: (String, String) = connection
                .query_row(
                    "SELECT state, manifest FROM attempts ORDER BY attempt_seq DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(row.1, attempt.manifest, "stored bytes == sent bytes");
            *self.seen.lock().unwrap() = Some(row);
            ScriptedCarrier::accepted()
        }
    }
    let seen = Arc::new(Mutex::new(None));
    let mut carrier = Probing {
        db: db.clone(),
        seen: Arc::clone(&seen),
    };
    let report = dispatch_message(&shared, &mut carrier, &recipient, &|| 2_000, &timing()).unwrap();
    assert!(matches!(
        report,
        DispatchReport::Sent {
            state: AttemptState::NativeAccepted,
            events: 1
        }
    ));
    assert_eq!(
        seen.lock().unwrap().as_ref().map(|row| row.0.as_str()),
        Some("invoking"),
        "invoking must be committed before the carrier can act"
    );
}

/// A hook drain commits `invoking` before any payload is returned, and
/// an attestation for a different actor cannot drain root-held data.
#[test]
fn hook_drain_commits_invoking_before_payload_and_other_actors_cannot_drain() {
    let dir = TempDir::new("hook-drain");
    let db = dir.path("bridge.db");
    let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    let recipient = codex("root-1");
    storage
        .publish(
            &keep_all("agent-run", "evt-hook", &recipient, Mode::Inject),
            1_000,
        )
        .unwrap();

    // A child actor sharing the root session is refused and nothing changes.
    let child = Attestation::verified(
        recipient.clone(),
        "child-agent-9",
        1,
        Lifecycle::Active,
        Capabilities {
            inject: true,
            message: true,
        },
        "fixture-proof",
    )
    .unwrap();
    match storage.drain_inject(&child, 2_000, &timing()) {
        Err(CoreError::Fence(detail)) => assert!(detail.contains("child-agent-9"), "{detail}"),
        other => panic!("a child must not drain root data, got {other:?}"),
    }
    assert!(
        storage
            .latest_attempt("agent-run", "evt-hook")
            .unwrap()
            .is_none()
    );

    // The verified addressed actor drains; the commit is visible to another
    // connection before the payload is returned to the caller.
    let drained = attempt(
        storage
            .drain_inject(&attest(&recipient, Lifecycle::Active, 3), 3_000, &timing())
            .unwrap(),
    );
    let other = rusqlite::Connection::open(&db).unwrap();
    let state: String = other
        .query_row(
            "SELECT state FROM attempts WHERE attempt_seq = ?1",
            [i64::try_from(drained.fence.attempt_seq).unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "invoking");
    assert!(drained.manifest.contains("evt-hook"));

    // A hook that never reports is NOT re-offered: the deadline turns the
    // silent attempt into an unknown outcome with a retained incident.
    let report = storage.run_maintenance(3_000 + 60_000).unwrap();
    assert_eq!(report.unknown_handoffs, 1);
    assert_eq!(
        storage
            .drain_inject(&attest(&recipient, Lifecycle::Active, 3), 70_000, &timing())
            .unwrap(),
        Selection::Idle
    );
    let incidents = storage.open_incidents(70_000, 10).unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, "unknown_handoff");
}

/// A hook acknowledgement after a full flush is recorded as hook-tier
/// evidence only, never as native queue acceptance or model-context
/// proof.
#[test]
fn hook_submission_after_flush_is_hook_tier_evidence_only() {
    let mut storage = store();
    let recipient = codex("root-2");
    storage
        .publish(
            &keep_all("agent-run", "evt-flush", &recipient, Mode::Inject),
            1_000,
        )
        .unwrap();
    let drained = attempt(
        storage
            .drain_inject(&attest(&recipient, Lifecycle::Active, 1), 2_000, &timing())
            .unwrap(),
    );
    let settled = storage
        .record_outcome(
            &drained.fence,
            Outcome::HookSubmitted {
                evidence: "stdout fully flushed".into(),
            },
            2_500,
        )
        .unwrap();
    assert_eq!(settled.state, AttemptState::HookSubmitted);
    let evidence = storage
        .delivery_evidence("agent-run", "evt-flush")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.delivery, DeliveryState::HookSubmitted);
    assert_eq!(evidence.tiers.len(), 1);
    assert_eq!(evidence.tiers[0].tier, EvidenceTier::HookEmitted);
    assert!(
        evidence
            .tiers
            .iter()
            .all(|tier| tier.tier != EvidenceTier::ContextObserved),
        "hook emission is never context evidence"
    );
}

/// A possibly-handed-off attempt becomes `outcome_unknown` with a
/// retained incident; further dispatch is refused until an audited
/// manual authorization records the duplicate risk.
#[test]
fn unknown_outcome_is_retained_and_never_auto_retried_until_audited_authorization() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-4");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "evt-unknown", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();

    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::OutcomeUnknown {
            reason: "socket write may have landed".into(),
        },
    );
    assert!(matches!(
        drive(&shared, &mut carrier, &recipient, 2_000),
        DispatchReport::Sent {
            state: AttemptState::OutcomeUnknown,
            ..
        }
    ));

    // Neither time nor another drive replays it.
    let mut retry = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    for now in [3_000, 9_000_000] {
        shared.lock().unwrap().run_maintenance(now).unwrap();
        assert_eq!(
            drive(&shared, &mut retry, &recipient, now),
            DispatchReport::Idle
        );
    }
    assert!(retry.sends.is_empty());

    let mut storage = shared.lock().unwrap();
    let incidents = storage.open_incidents(5_000, 10).unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, "unknown_handoff");
    assert_eq!(incidents[0].state, IncidentState::Open);
    assert_eq!(incidents[0].responsible, "source:agent-run; operator");
    assert!(incidents[0].review_deadline_ms.is_some());
    assert_eq!(incidents[0].age_ms, 3_000);
    let evidence = storage
        .delivery_evidence("agent-run", "evt-unknown")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.delivery, DeliveryState::Review);

    // The operator authorizes another attempt of the SAME event; the
    // duplicate risk stays recorded on the incident and the next attempt.
    storage
        .authorize_manual_retry(
            "agent-run",
            "evt-unknown",
            "ops-1",
            "reviewed the host log",
            10_000,
        )
        .unwrap();
    drop(storage);
    let mut manual = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    assert!(matches!(
        drive(&shared, &mut manual, &recipient, 11_000),
        DispatchReport::Sent {
            state: AttemptState::NativeAccepted,
            ..
        }
    ));
    assert!(
        manual.sends[0].duplicate_risk,
        "possible duplicate recorded"
    );
    let storage = shared.lock().unwrap();
    let all = storage.incidents(true, 12_000, 10).unwrap();
    assert_eq!(all[0].state, IncidentState::Authorized);
    assert!(all[0].duplicate_risk);
    assert!(all[0].resolution.as_deref().unwrap().contains("ops-1"));
}

/// Positively known-unsent closes its attempt and a bounded retry
/// budget admits later attempts, never an unbounded resend loop.
#[test]
fn known_unsent_closes_the_attempt_then_retries_with_a_bounded_budget() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-5");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "evt-unsent", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::KnownUnsent {
            evidence: "carrier proved no write happened".into(),
        },
    );

    // Attempt times follow the doubling delay: 1s, 2s, 4s, 8s.
    let mut now = 2_000;
    let mut first_seq = None;
    for expected_delay in [1_000, 2_000, 4_000, 8_000] {
        assert!(matches!(
            drive(&shared, &mut carrier, &recipient, now),
            DispatchReport::Sent {
                state: AttemptState::KnownUnsent,
                ..
            }
        ));
        let storage = shared.lock().unwrap();
        let latest_attempt = storage
            .latest_attempt("agent-run", "evt-unsent")
            .unwrap()
            .unwrap();
        // The old attempt is closed (known-unsent) BEFORE any retry exists.
        assert_eq!(latest_attempt.state, AttemptState::KnownUnsent);
        first_seq.get_or_insert(latest_attempt.fence.attempt_seq);
        drop(storage);
        // Not before its delay...
        assert_eq!(
            drive(&shared, &mut carrier, &recipient, now + expected_delay - 1),
            DispatchReport::Idle
        );
        now += expected_delay;
    }
    // The fifth known-unsent exhausts the automatic budget: the event is
    // refused with a retained incident instead of looping forever.
    assert!(matches!(
        drive(&shared, &mut carrier, &recipient, now),
        DispatchReport::Sent {
            state: AttemptState::KnownUnsent,
            ..
        }
    ));
    let storage = shared.lock().unwrap();
    let evidence = storage
        .delivery_evidence("agent-run", "evt-unsent")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.delivery, DeliveryState::Refused);
    assert_eq!(evidence.attempts_made, 5);
    assert_eq!(carrier.sends.len(), 5);
    assert!(
        storage
            .open_incidents(now, 10)
            .unwrap()
            .iter()
            .any(|incident| incident.kind == "retries_exhausted")
    );
    assert_ne!(
        first_seq.unwrap(),
        carrier.sends.last().unwrap().fence.attempt_seq
    );
}

/// Known-unsent classification requires positive proof; silence never
/// implies non-delivery.
#[test]
fn known_unsent_requires_positive_proof() {
    let mut storage = store();
    let recipient = codex("thread-proof");
    storage
        .publish(
            &keep_all("agent-run", "evt-proof", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let reserved = attempt(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                2_000,
                &timing(),
            )
            .unwrap(),
    );
    storage
        .mark_invoking(
            &reserved.fence,
            &attest(&recipient, Lifecycle::Inactive, 1),
            2_100,
        )
        .unwrap();
    assert!(
        storage
            .record_outcome(
                &reserved.fence,
                Outcome::KnownUnsent {
                    evidence: "  ".into()
                },
                2_200
            )
            .is_err(),
        "silence is not proof of non-delivery"
    );
    assert_eq!(
        storage
            .latest_attempt("agent-run", "evt-proof")
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Invoking
    );
}

/// An expired reservation that never invoked is reclaimed; an expired
/// `invoking` lease becomes `outcome_unknown` with an incident and stays
/// non-redispatchable.
#[test]
fn leases_reclaim_only_uninvoked_reservations_and_invoking_expires_to_unknown() {
    let mut storage = store();
    let recipient = codex("thread-6");
    for id in ["evt-res", "evt-inv"] {
        storage
            .publish(&keep_all("agent-run", id, &recipient, Mode::Message), 1_000)
            .unwrap();
    }
    let short = DispatchTiming {
        lease_ms: 1_000,
        handoff_ms: 1_000,
    };
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    // Two separate reservations: the first stays reserved, the second is
    // invoked.
    let reserved = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 1_000, &short)
            .unwrap(),
    );
    let invoking = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 1_000, &short)
            .unwrap(),
    );
    storage
        .mark_invoking(&invoking.fence, &inactive, 1_100)
        .unwrap();

    let report = storage.run_maintenance(5_000).unwrap();
    assert_eq!(report.reclaimed_reservations, 1);
    assert_eq!(report.unknown_handoffs, 1);

    assert_eq!(
        storage
            .attempt(reserved.fence.attempt_seq)
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Closed
    );
    assert_eq!(
        storage
            .attempt(invoking.fence.attempt_seq)
            .unwrap()
            .unwrap()
            .state,
        AttemptState::OutcomeUnknown
    );
    let reclaimed_id = &reserved.members[0].event_id;
    let unknown_id = &invoking.members[0].event_id;
    let reclaimed = storage
        .delivery_evidence("agent-run", reclaimed_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reclaimed.delivery,
        DeliveryState::Unhanded,
        "a reclaimed reservation is simply unhanded again"
    );
    assert_eq!(reclaimed.attempt_state, "closed");
    assert_eq!(reclaimed.attempts_made, 0, "the retry budget is restored");
    assert_eq!(
        storage
            .delivery_evidence("agent-run", unknown_id)
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Review
    );
    // Idempotent reconciliation.
    assert_eq!(storage.run_maintenance(6_000).unwrap().unknown_handoffs, 0);
    // The reclaimed event may be reserved again; the uncertain one never.
    let again = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 6_000, &timing())
            .unwrap(),
    );
    assert_eq!(&again.members[0].event_id, reclaimed_id);
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 6_000, &timing())
            .unwrap(),
        Selection::Idle
    );
}

/// Stale, forged or fabricated fences refuse the transition without
/// invoking anything.
#[test]
fn stale_and_forged_fences_refuse_without_new_invocation() {
    let mut storage = store();
    let recipient = codex("thread-8");
    storage
        .publish(
            &keep_all("agent-run", "evt-fence", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let inactive = attest(&recipient, Lifecycle::Inactive, 4);
    let reserved = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 1_000, &timing())
            .unwrap(),
    );

    let forgeries = [
        AttemptFence {
            recipient: "host-1/codex/default/other".into(),
            ..reserved.fence.clone()
        },
        AttemptFence {
            endpoint_epoch: 5,
            ..reserved.fence.clone()
        },
        AttemptFence {
            manifest_hash: "0".repeat(64),
            ..reserved.fence.clone()
        },
        AttemptFence {
            attempt_seq: 999_999,
            ..reserved.fence.clone()
        },
    ];
    for forged in &forgeries {
        assert!(
            matches!(
                storage.mark_invoking(forged, &inactive, 1_100),
                Err(CoreError::Fence(_))
            ),
            "forged fence {forged:?} must refuse"
        );
        assert!(matches!(
            storage.record_outcome(forged, ScriptedCarrier::accepted(), 1_100),
            Err(CoreError::Fence(_))
        ));
    }
    assert_eq!(
        storage
            .attempt(reserved.fence.attempt_seq)
            .unwrap()
            .unwrap()
            .state,
        AttemptState::Reserved,
        "no forged call changed the attempt"
    );
    // A reserved attempt cannot take an outcome: nothing was invoked.
    assert!(matches!(
        storage.record_outcome(&reserved.fence, ScriptedCarrier::accepted(), 1_100),
        Err(CoreError::Fence(_))
    ));
    // An expired lease refuses to invoke.
    assert!(matches!(
        storage.mark_invoking(&reserved.fence, &inactive, 1_000 + 30_000),
        Err(CoreError::Fence(detail)) if detail.contains("lease expired")
    ));
}

/// A stale endpoint epoch or changed conditions release the reservation
/// untouched: nothing was invoked, so reclaiming it is safe.
#[test]
fn stale_endpoint_epochs_and_changed_conditions_release_the_reservation_untouched() {
    let mut storage = store();
    let recipient = codex("thread-epoch");
    storage
        .publish(
            &keep_all("agent-run", "evt-epoch", &recipient, Mode::Auto),
            1_000,
        )
        .unwrap();
    let inactive = attest(&recipient, Lifecycle::Inactive, 3);
    let reserved = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
    );

    // A stale endpoint (older epoch) cannot reserve anything.
    assert!(matches!(
        storage.reserve_next(
            &attest(&recipient, Lifecycle::Inactive, 2),
            EffectiveMode::Message,
            2_100,
            &timing()
        ),
        Err(CoreError::Fence(detail)) if detail.contains("stale endpoint epoch")
    ));

    // A renewed endpoint (newer epoch) fences the old reservation: it is
    // released and nothing is invoked.
    let renewed = attest(&recipient, Lifecycle::Inactive, 4);
    match storage
        .mark_invoking(&reserved.fence, &renewed, 2_200)
        .unwrap()
    {
        Invoked::Released(reason) => assert!(reason.contains("epoch"), "{reason}"),
        other => panic!("expected release, got {other:?}"),
    }
    assert!(matches!(
        storage.mark_invoking(&reserved.fence, &renewed, 2_300),
        Err(CoreError::Fence(detail)) if detail.contains("not reserved")
    ));

    // The recipient became active between reservation and invocation: auto
    // waits for its hook instead of messaging an active recipient.
    let second = attempt(
        storage
            .reserve_next(&renewed, EffectiveMode::Message, 3_000, &timing())
            .unwrap(),
    );
    assert!(matches!(
        storage
            .mark_invoking(&second.fence, &attest(&recipient, Lifecycle::Active, 4), 3_100)
            .unwrap(),
        Invoked::Released(reason) if reason.contains("no longer inactive")
    ));

    // A pause between reservation and invocation blocks the invocation.
    let third = attempt(
        storage
            .reserve_next(&renewed, EffectiveMode::Message, 4_000, &timing())
            .unwrap(),
    );
    storage
        .set_no_wake(
            &recipient.to_canonical_string(),
            true,
            Some("owner is working"),
            "ops-1",
            4_050,
        )
        .unwrap();
    assert!(matches!(
        storage.mark_invoking(&third.fence, &renewed, 4_100).unwrap(),
        Invoked::Released(reason) if reason.contains("no-wake")
    ));
    let evidence = storage
        .delivery_evidence("agent-run", "evt-epoch")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.delivery, DeliveryState::Unhanded);
    assert_eq!(evidence.attempt_state, "closed");
    assert_eq!(
        evidence.attempts_made, 0,
        "releases restore the retry budget"
    );
}

/// The durable no-wake policy blocks the message path at reservation and
/// invocation while a natural hook drain stays available; already
/// possible effects are never undone.
#[test]
fn no_wake_policy_blocks_the_message_path_but_not_a_hook_drain() {
    let mut storage = store();
    let recipient = codex("thread-p");
    storage
        .publish(
            &keep_all("agent-run", "evt-msg", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "evt-auto", &recipient, Mode::Auto),
            1_000,
        )
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "evt-inject", &recipient, Mode::Inject),
            1_000,
        )
        .unwrap();
    storage
        .set_no_wake(
            &recipient.to_canonical_string(),
            true,
            Some("owner paused the session"),
            "ops-1",
            1_500,
        )
        .unwrap();

    // Message and auto-as-message are held with the recorded reason.
    match storage
        .reserve_next(
            &attest(&recipient, Lifecycle::Inactive, 1),
            EffectiveMode::Message,
            2_000,
            &timing(),
        )
        .unwrap()
    {
        Selection::Held(reason) => assert!(reason.contains("paused"), "{reason}"),
        other => panic!("expected a pause hold, got {other:?}"),
    }
    // A natural hook never wakes anyone, so it is not blocked.
    let drained = attempt(
        storage
            .drain_inject(&attest(&recipient, Lifecycle::Active, 1), 2_100, &timing())
            .unwrap(),
    );
    assert_eq!(drained.effective_mode, EffectiveMode::Inject);

    // Resuming releases the held message events.
    storage
        .set_no_wake(
            &recipient.to_canonical_string(),
            false,
            None,
            "ops-1",
            3_000,
        )
        .unwrap();
    let message = attempt(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                3_100,
                &timing(),
            )
            .unwrap(),
    );
    assert_eq!(message.effective_mode, EffectiveMode::Message);
}

/// keep_all events of similar age win the dispatch head, while aged
/// replaceable snapshots are not starved indefinitely.
#[test]
fn keep_all_wins_among_similar_age_but_aged_snapshots_are_not_starved() {
    let recipient = codex("thread-q");
    // Similar age: keep_all first.
    let mut storage = store();
    storage
        .publish(&latest("agent-ide", "view-1", &recipient, "diag", 1), 1_000)
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "critical-1", &recipient, Mode::Message),
            1_001,
        )
        .unwrap();
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    let first = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
    );
    assert_eq!(first.members[0].event_id, "critical-1");

    // A snapshot that has waited longer than the aging boost beats newer
    // keep_all traffic.
    let mut storage = store();
    storage
        .publish(
            &latest("agent-ide", "view-old", &recipient, "diag", 1),
            1_000,
        )
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "critical-late", &recipient, Mode::Message),
            100_000,
        )
        .unwrap();
    let first = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 101_000, &timing())
            .unwrap(),
    );
    assert_eq!(first.members[0].event_id, "view-old");
}

/// The per-recipient snapshot quota reserves admission capacity so a
/// diagnostics flood cannot crowd out keep_all traffic.
#[test]
fn snapshot_quota_reserves_admission_capacity_for_keep_all() {
    let mut limits = Limits::new(100);
    limits.max_pending_latest_per_recipient = 3;
    let mut storage = Storage::open_in_memory(limits).unwrap();
    register_tags(&mut storage);
    let recipient = codex("thread-quota");
    for revision in 1..=3 {
        // Distinct streams so none supersedes another.
        storage
            .publish(
                &latest(
                    "agent-ide",
                    &format!("view-{revision}"),
                    &recipient,
                    &format!("s{revision}"),
                    1,
                ),
                1_000,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.publish(&latest("agent-ide", "view-4", &recipient, "s4", 1), 1_000),
        Err(CoreError::Capacity { .. })
    ));
    // keep_all is exempt from the snapshot reserve and still admitted.
    storage
        .publish(
            &keep_all("agent-run", "critical-1", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    // A different recipient's snapshot stream is independent.
    storage
        .publish(
            &latest("agent-ide", "other-1", &codex("thread-other"), "s1", 1),
            1_000,
        )
        .unwrap();
    let queue = storage
        .next_pending(&recipient.to_canonical_string(), 10)
        .unwrap();
    assert_eq!(queue[0].event_id, "critical-1");
    assert_eq!(queue.len(), 4);
}

/// Events declaring a predecessor wait for its evidence tier or an
/// audited disposition, while unrelated traffic keeps progressing.
#[test]
fn dependents_wait_for_predecessor_evidence_and_unrelated_traffic_progresses() {
    let mut storage = store();
    let recipient = codex("thread-dep");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    // The dependent arrives BEFORE its predecessor: accepted and held.
    storage
        .publish(
            &with_meta(
                keep_all("agent-run", "cmd-2", &recipient, Mode::Message),
                "predecessor",
                "cmd-1",
            ),
            1_000,
        )
        .unwrap();
    let held = storage
        .delivery_evidence("agent-run", "cmd-2")
        .unwrap()
        .unwrap();
    assert_eq!(held.blocked_by.as_deref(), Some("cmd-1"));

    // Unrelated traffic is not blocked behind the dependent.
    storage
        .publish(
            &keep_all("agent-run", "other", &recipient, Mode::Message),
            1_100,
        )
        .unwrap();
    let first = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
    );
    assert_eq!(first.members[0].event_id, "other");
    storage
        .mark_invoking(&first.fence, &inactive, 2_001)
        .unwrap();
    storage
        .record_outcome(&first.fence, ScriptedCarrier::accepted(), 2_002)
        .unwrap();

    // The predecessor arrives; the dependent still waits for evidence.
    storage
        .publish(
            &keep_all("agent-run", "cmd-1", &recipient, Mode::Message),
            3_000,
        )
        .unwrap();
    let cmd1 = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 3_100, &timing())
            .unwrap(),
    );
    assert_eq!(cmd1.members[0].event_id, "cmd-1");
    // While the predecessor is reserved, invoking, held, unknown... the
    // dependent never overtakes it.
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 3_200, &timing())
            .unwrap(),
        Selection::Idle
    );
    storage
        .mark_invoking(&cmd1.fence, &inactive, 3_300)
        .unwrap();
    storage
        .record_outcome(
            &cmd1.fence,
            Outcome::OutcomeUnknown {
                reason: "may have landed".into(),
            },
            3_400,
        )
        .unwrap();
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 9_000_000, &timing())
            .unwrap(),
        Selection::Idle,
        "time alone never releases a dependent behind an uncertain command"
    );
    let incidents = storage.open_incidents(9_000_000, 10).unwrap();
    assert_eq!(incidents[0].blocked_dependents, vec!["cmd-2".to_string()]);

    // Positive late evidence for the predecessor releases the dependent.
    storage
        .record_evidence(
            "agent-run",
            "cmd-1",
            cmd1.fence.attempt_seq,
            EvidenceTier::NativeAccepted,
            "queue entry found with the exact client id",
            9_000_100,
        )
        .unwrap();
    let released = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 9_000_200, &timing())
            .unwrap(),
    );
    assert_eq!(released.members[0].event_id, "cmd-2");
}

/// An audited disposition or an operator waiver releases blocked
/// dependents, and dependency cycles are refused rather than deadlocked.
#[test]
fn audited_disposition_or_waiver_releases_dependents_and_cycles_are_refused() {
    let mut storage = store();
    let recipient = codex("thread-gap");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    storage
        .publish(
            &with_meta(
                keep_all("agent-run", "dep-a", &recipient, Mode::Message),
                "predecessor",
                "never-arrives",
            ),
            1_000,
        )
        .unwrap();
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
        Selection::Idle
    );
    // A long wait for a predecessor that never arrived becomes an incident.
    let report = storage.run_maintenance(1_000 + 700_000).unwrap();
    assert_eq!(report.escalated_holds, 1);
    assert_eq!(
        storage.open_incidents(800_000, 10).unwrap()[0].kind,
        "predecessor_missing"
    );
    // An audited waiver (never time) releases the dependent.
    storage
        .waive_predecessor(
            "agent-run",
            "dep-a",
            "ops-1",
            "the source confirmed it was canceled",
            800_000,
        )
        .unwrap();
    assert!(storage.open_incidents(800_001, 10).unwrap().is_empty());
    let released = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 800_100, &timing())
            .unwrap(),
    );
    assert_eq!(released.members[0].event_id, "dep-a");

    // Cycles through accepted events are refused at publication.
    storage
        .publish(
            &with_meta(
                keep_all("agent-run", "cyc-a", &recipient, Mode::Message),
                "predecessor",
                "cyc-b",
            ),
            900_000,
        )
        .unwrap();
    assert!(matches!(
        storage.publish(
            &with_meta(keep_all("agent-run", "cyc-b", &recipient, Mode::Message), "predecessor", "cyc-a"),
            900_001,
        ),
        Err(CoreError::InvalidEnvelope(detail)) if detail.contains("cycle")
    ));
    assert!(matches!(
        storage.publish(
            &with_meta(
                keep_all("agent-run", "self", &recipient, Mode::Message),
                "predecessor",
                "self"
            ),
            900_002,
        ),
        Err(CoreError::InvalidEnvelope(_))
    ));
}

/// Batch manifests keep member order, ids and content losslessly with
/// per-member wrappers, and unrelated scopes stay isolated.
#[test]
fn batch_manifests_are_ordered_lossless_and_scopes_stay_isolated() {
    let mut storage = store();
    let recipient = codex("thread-batch");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    for id in ["b-1", "b-2", "b-3"] {
        storage
            .publish(&batched("agent-run", id, &recipient, "group-a"), 1_000)
            .unwrap();
    }
    // Other scopes must never join the manifest: another group, another
    // project, another publisher with the same group name.
    storage
        .publish(&batched("agent-run", "g2-1", &recipient, "group-b"), 1_001)
        .unwrap();
    storage
        .publish(
            &with_meta(
                batched("agent-run", "proj-1", &recipient, "group-a"),
                "project",
                "other",
            ),
            1_002,
        )
        .unwrap();
    storage
        .publish(&batched("agent-ide", "ide-1", &recipient, "group-a"), 1_003)
        .unwrap();

    let first = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
    );
    let ids: Vec<&str> = first.members.iter().map(|m| m.event_id.as_str()).collect();
    assert_eq!(ids, ["b-1", "b-2", "b-3"], "ordered, lossless, one scope");
    assert!(first.manifest.starts_with("<bridge-batch count=\"3\">"));
    for id in ids {
        assert!(first.manifest.contains(&format!("event=\"{id}\"")));
    }
    // The rest follow as their own manifests.
    let mut remaining = Vec::new();
    while let Selection::Attempt(record) = storage
        .reserve_next(&inactive, EffectiveMode::Message, 2_100, &timing())
        .unwrap()
    {
        assert_eq!(record.members.len(), 1, "each other scope is alone");
        remaining.push(record.members[0].event_id.clone());
    }
    remaining.sort();
    assert_eq!(remaining, ["g2-1", "ide-1", "proj-1"]);
}

/// Supersession replaces only pending snapshots; reserved or beyond,
/// the frozen manifest keeps its bytes.
#[test]
fn latest_supersedes_only_pending_snapshots_and_inflight_manifests_are_immutable() {
    let mut storage = store();
    let recipient = codex("thread-latest");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    storage
        .publish(&latest("agent-ide", "v1", &recipient, "diag", 1), 1_000)
        .unwrap();
    let receipt = storage
        .publish(&latest("agent-ide", "v2", &recipient, "diag", 2), 1_001)
        .unwrap()
        .receipt;
    assert_eq!(receipt.state, EventState::Pending);
    // v1 was replaced while still known-unhanded.
    let v1 = storage
        .lookup(
            &bridge_core::PublisherId::new("agent-ide").unwrap(),
            &bridge_core::EventId::new("v1").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(v1.state, EventState::Superseded);

    // v2 goes in flight; its frozen manifest does not change when v3 lands.
    let inflight = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap(),
    );
    assert_eq!(inflight.members[0].event_id, "v2");
    storage
        .publish(&latest("agent-ide", "v3", &recipient, "diag", 3), 2_100)
        .unwrap();
    let stored = storage
        .attempt(inflight.fence.attempt_seq)
        .unwrap()
        .unwrap();
    assert_eq!(stored.manifest, inflight.manifest);
    assert_eq!(stored.state, AttemptState::Reserved);

    // If the in-flight snapshot is positively known unsent it is replaced
    // by the newer revision instead of being retried.
    storage
        .mark_invoking(&inflight.fence, &inactive, 2_200)
        .unwrap();
    storage
        .record_outcome(
            &inflight.fence,
            Outcome::KnownUnsent {
                evidence: "no write was issued".into(),
            },
            2_300,
        )
        .unwrap();
    let v2 = storage
        .lookup(
            &bridge_core::PublisherId::new("agent-ide").unwrap(),
            &bridge_core::EventId::new("v2").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(v2.state, EventState::Superseded);
    let next = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_400, &timing())
            .unwrap(),
    );
    assert_eq!(next.members[0].event_id, "v3");
}

/// A stale revision arriving after a newer one stays superseded across a
/// restart: the watermark is durable.
#[test]
fn stale_revision_never_revives_across_restart() {
    let dir = TempDir::new("latest-restart");
    let db = dir.path("bridge.db");
    let recipient = codex("thread-restart-latest");
    {
        let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
        storage
            .publish(&latest("agent-ide", "v12", &recipient, "diag", 12), 1_000)
            .unwrap();
    }
    let mut reopened = Storage::open(&db, Limits::new(10)).unwrap();
    let stale = reopened
        .publish(&latest("agent-ide", "v11", &recipient, "diag", 11), 2_000)
        .unwrap();
    assert_eq!(stale.receipt.state, EventState::Superseded);
    assert!(matches!(
        reopened.publish(&latest("agent-ide", "v12b", &recipient, "diag", 12), 2_001),
        Err(CoreError::Conflict { .. })
    ));
}

/// Expiry marks only never-handed-off events; an attempt that may have
/// reached a carrier is never expired into a delivery claim.
#[test]
fn expiry_applies_only_before_hand_off() {
    let mut storage = store();
    let recipient = codex("thread-expiry");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    let mut expiring = keep_all("agent-run", "exp-pending", &recipient, Mode::Message);
    expiring.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(5_000).unwrap());
    storage.publish(&expiring, 1_000).unwrap();
    // An expired event is never selected, even before maintenance runs.
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 6_000, &timing())
            .unwrap(),
        Selection::Idle
    );
    assert_eq!(storage.run_maintenance(6_000).unwrap().expired_events, 1);

    // Reserved but not yet invoked when it expires: released, then expired.
    let mut racing = keep_all("agent-run", "exp-race", &recipient, Mode::Message);
    racing.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(9_000).unwrap());
    storage.publish(&racing, 7_000).unwrap();
    let reserved = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 7_100, &timing())
            .unwrap(),
    );
    assert!(matches!(
        storage
            .mark_invoking(&reserved.fence, &inactive, 9_500)
            .unwrap(),
        Invoked::Released(_)
    ));
    assert_eq!(storage.expire_due(9_600).unwrap(), 1);

    // Once invoking, an event never expires: a possible hand-off is not
    // recalled by the clock.
    let mut inflight = keep_all("agent-run", "exp-inflight", &recipient, Mode::Message);
    inflight.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(12_000).unwrap());
    storage.publish(&inflight, 10_000).unwrap();
    let reserved = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 10_100, &timing())
            .unwrap(),
    );
    storage
        .mark_invoking(&reserved.fence, &inactive, 10_200)
        .unwrap();
    assert_eq!(storage.expire_due(50_000).unwrap(), 0);
}

/// Held and written-no-receipt hand-offs are non-terminal tiers with
/// overdue escalation to incidents and positive closure, never silent
/// losses.
#[test]
fn held_and_unreceipted_hand_offs_are_nonterminal_with_overdue_incidents_and_positive_closure() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-held");
    for id in ["held-1", "noreceipt-1"] {
        shared
            .lock()
            .unwrap()
            .publish(&keep_all("agent-run", id, &recipient, Mode::Message), 1_000)
            .unwrap();
    }
    let mut held = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::NativeHeld { recheck_ms: 10_000 },
    );
    assert!(matches!(
        drive(&shared, &mut held, &recipient, 2_000),
        DispatchReport::Sent {
            state: AttemptState::NativeHeld,
            ..
        }
    ));
    let mut written = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::WrittenNoReceipt {
            evidence: "idle session accepted the write".into(),
            receipt_deadline_ms: 20_000,
        },
    );
    assert!(matches!(
        drive(&shared, &mut written, &recipient, 2_100),
        DispatchReport::Sent {
            state: AttemptState::WrittenNoReceipt,
            ..
        }
    ));

    let mut storage = shared.lock().unwrap();
    // Neither is an alarm before its deadline; neither is delivered.
    assert_eq!(storage.run_maintenance(9_999).unwrap().overdue_rechecks, 0);
    for id in ["held-1", "noreceipt-1"] {
        assert_eq!(
            storage
                .delivery_evidence("agent-run", id)
                .unwrap()
                .unwrap()
                .delivery,
            DeliveryState::Held
        );
    }
    // Past its recheck deadline the held event becomes ONE incident, once.
    assert_eq!(storage.run_maintenance(10_000).unwrap().overdue_rechecks, 1);
    assert_eq!(storage.run_maintenance(10_500).unwrap().overdue_rechecks, 0);
    // Past the receipt deadline the unreceipted write is a separate class.
    assert_eq!(storage.run_maintenance(20_000).unwrap().overdue_rechecks, 1);
    let kinds: Vec<String> = storage
        .open_incidents(20_000, 10)
        .unwrap()
        .into_iter()
        .map(|incident| incident.kind)
        .collect();
    assert!(kinds.contains(&"held_overdue".to_string()));
    assert!(kinds.contains(&"receipt_overdue".to_string()));

    // Nothing is replayed while held; positive evidence closes both.
    let held_attempt = storage
        .latest_attempt("agent-run", "held-1")
        .unwrap()
        .unwrap();
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "held-1",
                held_attempt.fence.attempt_seq,
                EvidenceTier::NativeAccepted,
                "queue entry confirmed",
                21_000
            )
            .unwrap(),
        EvidenceEffect::Applied(DeliveryState::Accepted)
    );
    let written_attempt = storage
        .latest_attempt("agent-run", "noreceipt-1")
        .unwrap()
        .unwrap();
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "noreceipt-1",
                written_attempt.fence.attempt_seq,
                EvidenceTier::NativeAccepted,
                "exact-session marker and digest found",
                21_100
            )
            .unwrap(),
        EvidenceEffect::Applied(DeliveryState::Accepted)
    );
    assert!(storage.open_incidents(22_000, 10).unwrap().is_empty());
    // Idempotent: the same tier is recorded once.
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "held-1",
                held_attempt.fence.attempt_seq,
                EvidenceTier::NativeAccepted,
                "queue entry confirmed",
                21_200
            )
            .unwrap(),
        EvidenceEffect::AlreadyRecorded
    );
}

/// Late positive evidence resolves an unknown outcome without any
/// resend and never rewrites a newer attempt's state.
#[test]
fn late_evidence_resolves_unknown_without_resend_and_never_rewrites_a_newer_attempt() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-late");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "evt-late", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let mut unknown = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::OutcomeUnknown {
            reason: "helper exited without a result".into(),
        },
    );
    drive(&shared, &mut unknown, &recipient, 2_000);

    // Case A: positive late evidence settles it at the declared tier.
    let mut storage = shared.lock().unwrap();
    let first = storage
        .latest_attempt("agent-run", "evt-late")
        .unwrap()
        .unwrap();
    // Receipt-token possession is an annotation only: it never settles.
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "evt-late",
                first.fence.attempt_seq,
                EvidenceTier::ReceiptTokenPossession,
                "actor presented the recipient-only token",
                2_500
            )
            .unwrap(),
        EvidenceEffect::Recorded
    );
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "evt-late")
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Review
    );
    // A model-claimed or unsupported tier cannot be recorded as late evidence.
    assert!(
        storage
            .record_evidence(
                "agent-run",
                "evt-late",
                first.fence.attempt_seq,
                EvidenceTier::Unknown,
                "x",
                2_600
            )
            .is_err()
    );
    // Evidence for another event's attempt is refused.
    assert!(
        storage
            .record_evidence(
                "agent-run",
                "someone-else",
                first.fence.attempt_seq,
                EvidenceTier::NativeAccepted,
                "x",
                2_600
            )
            .is_err()
    );

    // Case B: the operator already authorized a retry; the older attempt's
    // late evidence is kept but does not rewrite the newer attempt's state.
    storage
        .authorize_manual_retry(
            "agent-run",
            "evt-late",
            "ops-2",
            "host log inconclusive",
            3_000,
        )
        .unwrap();
    drop(storage);
    let mut manual = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::NativeHeld {
            recheck_ms: 500_000,
        },
    );
    drive(&shared, &mut manual, &recipient, 4_000);
    let mut storage = shared.lock().unwrap();
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "evt-late",
                first.fence.attempt_seq,
                EvidenceTier::NativeAccepted,
                "found the first message in the queue",
                5_000
            )
            .unwrap(),
        EvidenceEffect::Recorded
    );
    let evidence = storage
        .delivery_evidence("agent-run", "evt-late")
        .unwrap()
        .unwrap();
    assert_eq!(
        evidence.delivery,
        DeliveryState::Held,
        "newer attempt owns the event"
    );
    assert!(evidence.tiers.iter().any(|entry| {
        entry.attempt_seq == first.fence.attempt_seq && entry.tier == EvidenceTier::NativeAccepted
    }));
}

/// Positive late evidence settles the uncertain attempt exactly once,
/// with no second send of the original event.
#[test]
fn late_positive_evidence_settles_an_unknown_without_any_second_send() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-settle");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "evt-settle", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let mut unknown = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::OutcomeUnknown {
            reason: "lost acknowledgement".into(),
        },
    );
    drive(&shared, &mut unknown, &recipient, 2_000);
    let mut storage = shared.lock().unwrap();
    let seq = storage
        .latest_attempt("agent-run", "evt-settle")
        .unwrap()
        .unwrap()
        .fence
        .attempt_seq;
    assert_eq!(
        storage
            .record_evidence(
                "agent-run",
                "evt-settle",
                seq,
                EvidenceTier::NativeAccepted,
                "queue entry confirmed",
                3_000
            )
            .unwrap(),
        EvidenceEffect::Applied(DeliveryState::Accepted)
    );
    assert!(storage.open_incidents(3_000, 10).unwrap().is_empty());
    let closed = storage.incidents(true, 3_000, 10).unwrap();
    assert_eq!(closed[0].state, IncidentState::Resolved);
    assert!(
        closed[0]
            .resolution
            .as_deref()
            .unwrap()
            .contains("native accepted")
    );
    drop(storage);
    let mut again = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    assert_eq!(
        drive(&shared, &mut again, &recipient, 4_000),
        DispatchReport::Idle
    );
    assert!(
        again.sends.is_empty(),
        "settled evidence never causes a resend"
    );
}

/// A carrier panic during the hand-off is recorded as an unknown
/// outcome with retained evidence, never as a silent failure or resend.
#[test]
fn a_panicking_carrier_is_recorded_as_an_unknown_outcome() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-panic");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "evt-panic", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let mut carrier = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    carrier.panic_on_send = true;
    assert!(matches!(
        drive(&shared, &mut carrier, &recipient, 2_000),
        DispatchReport::Sent {
            state: AttemptState::OutcomeUnknown,
            ..
        }
    ));
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .open_incidents(2_000, 10)
            .unwrap()
            .len(),
        1
    );
}

/// A permanent refusal blocks the event's dependents until an audited
/// disposition decides their fate.
#[test]
fn a_permanent_refusal_blocks_dependents_until_an_audited_disposition() {
    let shared = Mutex::new(store());
    let recipient = codex("thread-refuse");
    {
        let mut storage = shared.lock().unwrap();
        storage
            .publish(
                &keep_all("agent-run", "ref-1", &recipient, Mode::Message),
                1_000,
            )
            .unwrap();
        storage
            .publish(
                &with_meta(
                    keep_all("agent-run", "ref-2", &recipient, Mode::Message),
                    "predecessor",
                    "ref-1",
                ),
                1_001,
            )
            .unwrap();
    }
    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::PermanentRefusal {
            reason: "the thread is archived".into(),
        },
    );
    drive(&shared, &mut carrier, &recipient, 2_000);
    assert_eq!(
        drive(&shared, &mut carrier, &recipient, 3_000),
        DispatchReport::Idle
    );
    let mut storage = shared.lock().unwrap();
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "ref-1")
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Refused
    );
    assert_eq!(
        storage.open_incidents(3_000, 10).unwrap()[0].kind,
        "permanent_refusal"
    );
    storage
        .dispose_event(
            "agent-run",
            "ref-1",
            "ops-1",
            "recipient retired; drop the pair",
            4_000,
        )
        .unwrap();
    drop(storage);
    let mut next = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    assert!(matches!(
        drive(&shared, &mut next, &recipient, 5_000),
        DispatchReport::Sent { .. }
    ));
    assert_eq!(next.sends[0].members[0].event_id, "ref-2");
}

/// Corrupted stored bytes quarantine their event while other traffic
/// keeps progressing; the damage never spreads silently.
#[test]
fn corrupted_stored_bytes_are_quarantined_and_other_traffic_progresses() {
    let dir = TempDir::new("corrupt");
    let db = dir.path("bridge.db");
    let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    let recipient = codex("thread-corrupt");
    storage
        .publish(
            &keep_all("agent-run", "bad", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "forged", &recipient, Mode::Message),
            1_001,
        )
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "good", &recipient, Mode::Message),
            1_002,
        )
        .unwrap();
    // A foreign writer damages the stored bytes of one event and rewrites
    // the content of another into perfectly valid JSON: the frozen hash,
    // not the syntax, is what protects accepted bytes.
    let foreign = rusqlite::Connection::open(&db).unwrap();
    foreign
        .execute(
            "UPDATE events SET envelope_json = CAST('{}' AS BLOB) WHERE event_id = 'bad'",
            [],
        )
        .unwrap();
    foreign
        .execute(
            "UPDATE events SET envelope_json = CAST(REPLACE(CAST(envelope_json AS TEXT),
                 'synthetic result of forged', 'FORGED CONTENT') AS BLOB)
             WHERE event_id = 'forged'",
            [],
        )
        .unwrap();
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    for _ in 0..2 {
        match storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_000, &timing())
            .unwrap()
        {
            Selection::Held(reason) => assert!(reason.contains("quarantined"), "{reason}"),
            other => panic!("expected quarantine, got {other:?}"),
        }
    }
    for id in ["bad", "forged"] {
        assert_eq!(
            storage
                .delivery_evidence("agent-run", id)
                .unwrap()
                .unwrap()
                .delivery,
            DeliveryState::Refused
        );
    }
    let incidents = storage.open_incidents(2_000, 10).unwrap();
    assert_eq!(incidents.len(), 2);
    assert!(incidents.iter().all(|i| i.kind == "storage_integrity"));
    let next = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 2_100, &timing())
            .unwrap(),
    );
    assert_eq!(next.members[0].event_id, "good");
    assert!(!next.manifest.contains("FORGED"));
}

/// An event whose publisher has no registered source tag holds instead
/// of guessing a wrapper; framing authority is never invented.
#[test]
fn unregistered_source_tag_holds_instead_of_guessing_a_wrapper() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let recipient = codex("thread-tag");
    storage
        .publish(
            &keep_all("agent-run", "evt-tag", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    match storage
        .reserve_next(
            &attest(&recipient, Lifecycle::Inactive, 1),
            EffectiveMode::Message,
            2_000,
            &timing(),
        )
        .unwrap()
    {
        Selection::Held(reason) => assert!(reason.contains("source tag"), "{reason}"),
        other => panic!("expected a hold, got {other:?}"),
    }
    // A publisher can never be re-attributed to another tag.
    storage
        .register_source_tag("agent-run", "agent-run")
        .unwrap();
    assert!(
        storage
            .register_source_tag("agent-run", "agent-ide")
            .is_err()
    );
}

/// A hold past its escalation deadline becomes a visible incident and
/// clears only when the hold itself clears.
#[test]
fn long_holds_escalate_to_an_incident_that_clears_with_the_hold() {
    let mut storage = store();
    let recipient = codex("thread-longhold");
    storage
        .publish(
            &keep_all("agent-run", "evt-longhold", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Unknown, 1),
                EffectiveMode::Message,
                1_000,
                &timing()
            )
            .unwrap(),
        Selection::Held(_)
    ));
    assert_eq!(
        storage
            .run_maintenance(1_000 + 599_000)
            .unwrap()
            .escalated_holds,
        0
    );
    assert_eq!(
        storage
            .run_maintenance(1_000 + 600_000)
            .unwrap()
            .escalated_holds,
        1
    );
    assert_eq!(
        storage
            .run_maintenance(1_000 + 600_500)
            .unwrap()
            .escalated_holds,
        0
    );
    assert_eq!(
        storage.open_incidents(700_000, 10).unwrap()[0].kind,
        "recipient_held"
    );
    // Recovery of the recipient clears the hold and its incident.
    let reserved = attempt(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                700_000,
                &timing(),
            )
            .unwrap(),
    );
    assert_eq!(reserved.members[0].event_id, "evt-longhold");
    assert!(storage.holds(10).unwrap().is_empty());
    assert!(storage.open_incidents(700_001, 10).unwrap().is_empty());
}

/// An attestation of `recipient` with exactly the given loaded paths.
fn attest_with(
    recipient: &NativeAddress,
    lifecycle: Lifecycle,
    inject: bool,
    message: bool,
) -> Attestation {
    Attestation::verified(
        recipient.clone(),
        recipient.native_session_id.clone(),
        1,
        lifecycle,
        Capabilities { inject, message },
        "fixture-proof",
    )
    .unwrap()
}

/// Modes the recipient is known not to support are refused before
/// acceptance, while an unknown recipient is accepted pending
/// attestation. `auto` needs only that at least one path is loaded: it
/// resolves per dispatch and its effective path is gated there.
#[test]
fn unsupported_modes_are_refused_before_acceptance_but_unknown_recipients_are_accepted() {
    let mut storage = store();
    let recipient = codex("thread-caps");
    // Before any attestation nothing is known: accepted.
    storage
        .publish(
            &keep_all("agent-run", "caps-0", &recipient, Mode::Auto),
            1_000,
        )
        .unwrap();
    // The adapter attests that only message is loaded: inject is refused,
    // auto resolves to message and is admitted, message is admitted.
    storage
        .observe_binding(
            &attest_with(&recipient, Lifecycle::Inactive, false, true),
            2_000,
        )
        .unwrap();
    assert!(
        matches!(
            storage.publish(
                &keep_all("agent-run", "caps-inject", &recipient, Mode::Inject),
                3_000
            ),
            Err(CoreError::Unsupported(_))
        ),
        "inject needs the inject path"
    );
    for mode in [Mode::Auto, Mode::Message] {
        storage
            .publish(
                &keep_all("agent-run", &format!("caps-{mode:?}"), &recipient, mode),
                3_000,
            )
            .unwrap();
    }
    // With neither path loaded every mode is refused before custody.
    storage
        .observe_binding(
            &attest_with(&recipient, Lifecycle::Inactive, false, false),
            3_500,
        )
        .unwrap();
    for mode in [Mode::Inject, Mode::Message, Mode::Auto] {
        let id = format!("caps-none-{mode:?}");
        assert!(
            matches!(
                storage.publish(&keep_all("agent-run", &id, &recipient, mode), 3_600),
                Err(CoreError::Unsupported(_))
            ),
            "{mode:?} has no loaded path"
        );
        assert!(
            storage
                .lookup(
                    &bridge_core::PublisherId::new("agent-run").unwrap(),
                    &bridge_core::EventId::new(&id).unwrap()
                )
                .unwrap()
                .is_none(),
            "{mode:?} was never accepted"
        );
    }
    // Unsupported is permanent and distinct from a transient hold: the
    // adapter re-attesting with the inject path loaded lifts the refusal.
    storage
        .observe_binding(&attest(&recipient, Lifecycle::Active, 1), 4_000)
        .unwrap();
    assert!(
        storage
            .publish(
                &keep_all("agent-run", "caps-after", &recipient, Mode::Auto),
                5_000
            )
            .is_ok()
    );
}

/// An admitted `auto` event of a message-only recipient follows the
/// lifecycle: positively inactive resolves to the message path and reserves
/// one attempt; active resolves to inject, which is not loaded, so nothing is
/// reserved or sent and the message path never takes it.
#[test]
fn auto_for_a_message_only_recipient_follows_the_lifecycle_without_effect() {
    let mut storage = store();
    let inactive = codex("thread-auto-idle");
    let active = codex("thread-auto-busy");
    for (recipient, lifecycle, event) in [
        (&inactive, Lifecycle::Inactive, "auto-idle"),
        (&active, Lifecycle::Active, "auto-busy"),
    ] {
        let attestation = attest_with(recipient, lifecycle, false, true);
        storage.observe_binding(&attestation, 1_000).unwrap();
        storage
            .publish(&keep_all("agent-run", event, recipient, Mode::Auto), 2_000)
            .unwrap();
    }
    let reserved = attempt(
        storage
            .reserve_next(
                &attest_with(&inactive, Lifecycle::Inactive, false, true),
                EffectiveMode::Message,
                3_000,
                &timing(),
            )
            .unwrap(),
    );
    assert_eq!(reserved.requested_mode, Mode::Auto);
    assert_eq!(reserved.effective_mode, EffectiveMode::Message);

    let busy = attest_with(&active, Lifecycle::Active, false, true);
    assert!(matches!(
        storage
            .reserve_next(&busy, EffectiveMode::Message, 3_000, &timing())
            .unwrap(),
        Selection::Idle
    ));
    assert!(matches!(
        storage
            .reserve_next(&busy, EffectiveMode::Inject, 3_000, &timing())
            .unwrap(),
        Selection::Held(reason) if reason.contains("not loaded")
    ));
    assert!(
        storage
            .latest_attempt("agent-run", "auto-idle")
            .unwrap()
            .is_some(),
        "the inactive recipient's event has its attempt"
    );
    assert!(
        storage
            .latest_attempt("agent-run", "auto-busy")
            .unwrap()
            .is_none(),
        "the active recipient's event has no attempt and no native effect"
    );
}

/// Two racing reservations for one recipient resolve to exactly one
/// winner; the loser is refused without invocation.
#[test]
fn exactly_one_of_two_racing_reservations_wins() {
    let dir = TempDir::new("race");
    let db = dir.path("bridge.db");
    let recipient = codex("thread-race");
    {
        let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
        register_tags(&mut storage);
        storage
            .publish(
                &keep_all("agent-run", "evt-race", &recipient, Mode::Message),
                1_000,
            )
            .unwrap();
    }
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let db = db.clone();
            let recipient = recipient.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
                barrier.wait();
                storage
                    .reserve_next(
                        &attest(&recipient, Lifecycle::Inactive, 1),
                        EffectiveMode::Message,
                        2_000,
                        &DispatchTiming::default(),
                    )
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<Selection> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners = results
        .iter()
        .filter(|selection| matches!(selection, Selection::Attempt(_)))
        .count();
    assert_eq!(
        winners, 1,
        "one possibly-handed-off attempt per event: {results:?}"
    );
}

/// A restart resumes held and uncertain state exactly as it was, with
/// reconciliation converting expired invoking leases to retained
/// unknowns and never replaying them.
#[test]
fn restart_resumes_held_and_uncertain_state_without_replay() {
    let dir = TempDir::new("dispatch-restart");
    let db = dir.path("bridge.db");
    let recipient = codex("thread-r");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    {
        let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
        register_tags(&mut storage);
        storage
            .publish(
                &keep_all("agent-run", "evt-restart", &recipient, Mode::Message),
                1_000,
            )
            .unwrap();
        let short = DispatchTiming {
            lease_ms: 500,
            handoff_ms: 500,
        };
        let reserved = attempt(
            storage
                .reserve_next(&inactive, EffectiveMode::Message, 1_000, &short)
                .unwrap(),
        );
        storage
            .mark_invoking(&reserved.fence, &inactive, 1_100)
            .unwrap();
        // The process dies here: invoking is durable, no outcome recorded.
    }
    let mut reopened = Storage::open(&db, Limits::new(10)).unwrap();
    assert_eq!(reopened.run_maintenance(5_000).unwrap().unknown_handoffs, 1);
    let attempt_record = reopened
        .latest_attempt("agent-run", "evt-restart")
        .unwrap()
        .unwrap();
    assert_eq!(attempt_record.state, AttemptState::OutcomeUnknown);
    assert_eq!(reopened.open_incidents(5_000, 10).unwrap().len(), 1);
    assert_eq!(reopened.run_maintenance(6_000).unwrap().unknown_handoffs, 0);
    assert_eq!(
        reopened
            .reserve_next(&inactive, EffectiveMode::Message, 7_000, &timing())
            .unwrap(),
        Selection::Idle
    );
    // Custody itself survived the restart untouched.
    let replay = reopened
        .publish(
            &keep_all("agent-run", "evt-restart", &recipient, Mode::Message),
            8_000,
        )
        .unwrap();
    assert!(replay.receipt.replayed);
}

/// Payload compaction keeps dedup identity and original receipts while
/// never touching delivered or uncertain events.
#[test]
fn compaction_keeps_dedup_identity_and_never_touches_delivered_or_uncertain_events() {
    let mut storage = store();
    let recipient = codex("thread-c");
    storage
        .publish(&latest("agent-ide", "new", &recipient, "diag", 2), 1_000)
        .unwrap();
    storage
        .publish(&latest("agent-ide", "old", &recipient, "diag", 1), 1_001)
        .unwrap();
    storage
        .publish(
            &keep_all("agent-run", "kept", &recipient, Mode::Message),
            1_002,
        )
        .unwrap();
    assert_eq!(storage.compact_payloads(0).unwrap(), 1);
    // The compacted superseded entry still dedups identical replays and
    // still reports its original disposition.
    let replay = storage
        .publish(&latest("agent-ide", "old", &recipient, "diag", 1), 9_000)
        .unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(replay.receipt.state, EventState::Superseded);
    // A different body under the compacted id is still a conflict.
    assert!(matches!(
        storage.publish(&latest("agent-ide", "old", &recipient, "diag", 5), 9_001),
        Err(CoreError::Conflict { .. })
    ));
}

/// A held recipient cannot starve healthy ones: the dispatch listing
/// keeps serving other recipients.
#[test]
fn held_recipients_cannot_starve_healthy_ones_in_the_dispatch_listing() {
    let mut storage = store();
    // Twenty recipients that stay held (oldest work), one healthy newcomer.
    for index in 0..20 {
        let held = codex(&format!("held-{index}"));
        storage
            .publish(
                &keep_all("agent-run", &format!("old-{index}"), &held, Mode::Message),
                1_000,
            )
            .unwrap();
        assert!(matches!(
            storage
                .reserve_next(
                    &attest(&held, Lifecycle::Unknown, 1),
                    EffectiveMode::Message,
                    2_000 + index,
                    &timing()
                )
                .unwrap(),
            Selection::Held(_)
        ));
    }
    let healthy = codex("healthy");
    storage
        .publish(
            &keep_all("agent-run", "new-1", &healthy, Mode::Message),
            50_000,
        )
        .unwrap();

    let listed = storage.recipients_with_work(60_000, 5, None).unwrap();
    assert_eq!(
        listed[0], healthy,
        "a healthy recipient is served before held ones"
    );
    // Held recipients rotate: the least recently rechecked comes first.
    assert_eq!(listed[1], codex("held-0"));
    assert_eq!(listed.len(), 5, "the listing is bounded");
}

/// Concurrent publishers and dispatch drives on one database lose no
/// events and produce no torn state.
#[test]
fn concurrent_publishers_and_dispatch_share_one_database_without_losing_events() {
    let dir = TempDir::new("dispatch-concurrent");
    let db = dir.path("bridge.db");
    {
        let mut storage = Storage::open(&db, Limits::new(1_000)).unwrap();
        register_tags(&mut storage);
    }
    let barrier = Arc::new(Barrier::new(3));
    let recipient = codex("thread-cc");
    let publishers: Vec<_> = ["agent-run", "agent-ide"]
        .into_iter()
        .map(|publisher| {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            let recipient = recipient.clone();
            std::thread::spawn(move || {
                let mut storage = Storage::open(&db, Limits::new(1_000)).unwrap();
                barrier.wait();
                for index in 0..20 {
                    storage
                        .publish(
                            &keep_all(
                                publisher,
                                &format!("evt-{index}"),
                                &recipient,
                                Mode::Message,
                            ),
                            1_000 + index,
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    let dispatcher = {
        let db = db.clone();
        let barrier = Arc::clone(&barrier);
        let recipient = recipient.clone();
        std::thread::spawn(move || {
            let shared = Mutex::new(Storage::open(&db, Limits::new(1_000)).unwrap());
            let mut carrier =
                ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
            barrier.wait();
            for tick in 0..200 {
                let _ = dispatch_message(
                    &shared,
                    &mut carrier,
                    &recipient,
                    &|| 100_000 + tick,
                    &timing(),
                );
            }
            carrier.sends
        })
    };
    for handle in publishers {
        handle.join().expect("publisher thread panicked");
    }
    let mut sends = dispatcher.join().expect("dispatcher thread panicked");

    // Drain whatever the racing dispatcher did not reach.
    let shared = Mutex::new(Storage::open(&db, Limits::new(1_000)).unwrap());
    let mut carrier = ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted());
    while matches!(
        drive(&shared, &mut carrier, &recipient, 500_000),
        DispatchReport::Sent { .. }
    ) {}
    sends.extend(carrier.sends);
    let mut delivered: Vec<(String, String)> = sends
        .iter()
        .flat_map(|record| {
            record
                .members
                .iter()
                .map(|member| (member.publisher.clone(), member.event_id.clone()))
        })
        .collect();
    delivered.sort();
    let unique = delivered.len();
    delivered.dedup();
    assert_eq!(delivered.len(), 40, "every event was handed off");
    assert_eq!(unique, 40, "and exactly once");
}

/// A late OUTCOME (not only late evidence) for an older attempt, delivered
/// after an audited retry produced a newer unknown attempt, must neither
/// close the newer attempt's incident nor open an incident or change the
/// delivery state of the event that the newer attempt now owns.
#[test]
fn a_late_outcome_for_an_older_attempt_never_touches_the_newer_attempts_incident() {
    for (index, late) in [
        Outcome::NativeAccepted {
            evidence: "found the first message in the queue".into(),
        },
        Outcome::KnownUnsent {
            evidence: "the helper log shows no write".into(),
        },
        Outcome::PermanentRefusal {
            reason: "the first host refused it".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let event = format!("evt-late-outcome-{index}");
        let shared = Mutex::new(store());
        let recipient = codex(&format!("thread-late-outcome-{index}"));
        shared
            .lock()
            .unwrap()
            .publish(
                &keep_all("agent-run", &event, &recipient, Mode::Message),
                1_000,
            )
            .unwrap();
        let unknown = || {
            ScriptedCarrier::new(
                Lifecycle::Inactive,
                Outcome::OutcomeUnknown {
                    reason: "helper exited without a result".into(),
                },
            )
        };
        drive(&shared, &mut unknown(), &recipient, 2_000);
        let mut storage = shared.lock().unwrap();
        let first = storage
            .latest_attempt("agent-run", &event)
            .unwrap()
            .unwrap();
        storage
            .authorize_manual_retry("agent-run", &event, "ops-3", "host log inconclusive", 3_000)
            .unwrap();
        drop(storage);
        drive(&shared, &mut unknown(), &recipient, 4_000);

        let mut storage = shared.lock().unwrap();
        let second = storage
            .latest_attempt("agent-run", &event)
            .unwrap()
            .unwrap();
        assert_ne!(second.fence.attempt_seq, first.fence.attempt_seq);
        storage.record_outcome(&first.fence, late, 5_000).unwrap();

        let open = storage.open_incidents(5_000, 10).unwrap();
        assert_eq!(open.len(), 1, "only the newer attempt's incident is open");
        assert_eq!(open[0].kind, "unknown_handoff");
        assert_eq!(open[0].attempt_seq, Some(second.fence.attempt_seq));
        assert_eq!(
            storage
                .delivery_evidence("agent-run", &event)
                .unwrap()
                .unwrap()
                .delivery,
            DeliveryState::Review,
            "the newer unknown attempt still owns the event"
        );
    }
}

/// The dispatch listing is a rotating window: each call continues after the
/// previous window, wraps at the end, and restarts when the cursor
/// recipient has no work left.
#[test]
fn recipient_listing_rotates_through_every_recipient_with_work() {
    let mut storage = store();
    let names: Vec<NativeAddress> = (0..5).map(|index| codex(&format!("rot-{index}"))).collect();
    for (index, recipient) in names.iter().enumerate() {
        storage
            .publish(
                &keep_all(
                    "agent-run",
                    &format!("rot-evt-{index}"),
                    recipient,
                    Mode::Inject,
                ),
                1_000 + index as u64,
            )
            .unwrap();
    }
    let first = storage.recipients_with_work(5_000, 2, None).unwrap();
    assert_eq!(first, names[0..2]);
    let second = storage
        .recipients_with_work(5_000, 2, first.last())
        .unwrap();
    assert_eq!(second, names[2..4]);
    let third = storage
        .recipients_with_work(5_000, 2, second.last())
        .unwrap();
    assert_eq!(third, [names[4].clone(), names[0].clone()], "wraps around");
    let gone = codex("no-work-left");
    assert_eq!(
        storage.recipients_with_work(5_000, 2, Some(&gone)).unwrap(),
        names[0..2],
        "an unknown cursor restarts the rotation"
    );
}

/// Snapshot floods across many recipients and publishers can never use the
/// protected global keep_all reserve: replaceable work stops a quarter of
/// the global cap early, keep_all still fills the cap, nothing admitted is
/// evicted, and the total cap holds.
#[test]
fn global_cap_keeps_a_protected_reserve_for_keep_all_across_recipients() {
    let mut limits = Limits::new(100);
    limits.max_pending_latest_per_recipient = 3;
    let mut storage = Storage::open_in_memory(limits).unwrap();
    register_tags(&mut storage);
    let mut snapshots = 0;
    'flood: for round in 0..3 {
        for index in 0..40 {
            let publisher = if index % 2 == 0 {
                "agent-ide"
            } else {
                "agent-run"
            };
            let recipient = codex(&format!("flood-{index}"));
            let outcome = storage.publish(
                &latest(
                    publisher,
                    &format!("flood-{index}-{round}"),
                    &recipient,
                    &format!("stream-{index}-{round}"),
                    1,
                ),
                1_000,
            );
            match outcome {
                Ok(_) => snapshots += 1,
                Err(CoreError::Capacity { limit }) => {
                    assert!(limit.contains("keep_all"), "{limit}");
                    break 'flood;
                }
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
    }
    assert_eq!(snapshots, 75, "snapshots stop at the cap minus the reserve");
    for index in 0..25 {
        storage
            .publish(
                &keep_all(
                    "agent-run",
                    &format!("critical-{index}"),
                    &codex(&format!("flood-{}", index % 40)),
                    Mode::Message,
                ),
                2_000,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.publish(
            &keep_all(
                "agent-run",
                "critical-over",
                &codex("flood-0"),
                Mode::Message
            ),
            2_000
        ),
        Err(CoreError::Capacity { .. })
    ));
    assert_eq!(
        storage.count_delivery(DeliveryState::Unhanded).unwrap(),
        100,
        "the total cap holds and no admitted event was evicted"
    );
}

/// A dependent whose predecessor expired before delivery keeps its order
/// (it is never released by time or by the expiry itself) but is no longer
/// silent: maintenance raises one actionable incident that names the
/// blocked event, and only an audited waiver releases it.
#[test]
fn an_expired_predecessor_raises_an_incident_and_only_a_waiver_releases_the_dependent() {
    let mut storage = store();
    let recipient = codex("thread-expired-dep");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    let mut predecessor = keep_all("agent-run", "pred-1", &recipient, Mode::Message);
    predecessor.expires_at = Some(ExpiresAt::from_unix_millis(2_000).unwrap());
    storage.publish(&predecessor, 1_000).unwrap();
    storage
        .publish(
            &with_meta(
                keep_all("agent-run", "dep-1", &recipient, Mode::Message),
                "predecessor",
                "pred-1",
            ),
            1_001,
        )
        .unwrap();

    let report = storage.run_maintenance(3_000).unwrap();
    assert_eq!(report.expired_events, 1);
    assert_eq!(
        report.escalated_holds, 1,
        "one new incident for the dependent"
    );
    let incidents = storage.open_incidents(3_000, 10).unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, "predecessor_expired");
    assert_eq!(incidents[0].event_id, "dep-1");
    assert!(
        incidents[0].reason.contains("pred-1"),
        "{}",
        incidents[0].reason
    );
    // A repeat pass neither duplicates the incident nor releases the event.
    assert_eq!(storage.run_maintenance(3_500).unwrap().escalated_holds, 0);
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 4_000, &timing())
            .unwrap(),
        Selection::Idle,
        "expiry alone never releases the dependent"
    );
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "dep-1")
            .unwrap()
            .unwrap()
            .blocked_by
            .as_deref(),
        Some("pred-1")
    );

    storage
        .waive_predecessor(
            "agent-run",
            "dep-1",
            "ops-1",
            "the source confirmed the predecessor is obsolete",
            5_000,
        )
        .unwrap();
    assert!(storage.open_incidents(5_001, 10).unwrap().is_empty());
    let released = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 5_100, &timing())
            .unwrap(),
    );
    assert_eq!(released.members[0].event_id, "dep-1");
}

/// Every valid positive global cap keeps at least one slot for keep_all:
/// `latest` and `batch` may take only `cap - max(1, cap / 4)` slots (none at
/// cap 1, which refuses them before acceptance), keep_all still fills the
/// configured cap exactly, and the cap itself is never raised.
#[test]
fn every_positive_global_cap_reserves_at_least_one_keep_all_slot() {
    for (cap, snapshot_slots) in [(1, 0), (2, 1), (3, 2), (8, 6)] {
        for policy in ["latest", "batch"] {
            let mut storage = Storage::open_in_memory(Limits::new(cap)).unwrap();
            register_tags(&mut storage);
            let mut admitted = 0;
            for index in 0..cap + 2 {
                let recipient = codex(&format!("tiny-{index}"));
                let id = format!("{policy}-{index}");
                let envelope = if policy == "latest" {
                    latest("agent-ide", &id, &recipient, &format!("s{index}"), 1)
                } else {
                    batched("agent-ide", &id, &recipient, &format!("g{index}"))
                };
                match storage.publish(&envelope, 1_000) {
                    Ok(_) => admitted += 1,
                    Err(CoreError::Capacity { limit }) => {
                        assert!(limit.contains("keep_all"), "cap {cap} {policy}: {limit}");
                    }
                    Err(other) => panic!("cap {cap} {policy}: unexpected {other:?}"),
                }
            }
            assert_eq!(admitted, snapshot_slots, "cap {cap} {policy}");
            for index in 0..cap - snapshot_slots {
                storage
                    .publish(
                        &keep_all(
                            "agent-run",
                            &format!("critical-{index}"),
                            &codex("tiny-0"),
                            Mode::Message,
                        ),
                        2_000,
                    )
                    .unwrap_or_else(|error| panic!("cap {cap} {policy}: keep_all {error:?}"));
            }
            assert!(matches!(
                storage.publish(
                    &keep_all(
                        "agent-run",
                        "critical-over",
                        &codex("tiny-0"),
                        Mode::Message
                    ),
                    2_000
                ),
                Err(CoreError::Capacity { .. })
            ));
            assert_eq!(
                storage.count_delivery(DeliveryState::Unhanded).unwrap(),
                cap as u64,
                "cap {cap} {policy}: total capacity is exactly the configured cap"
            );
        }
    }
}

/// Maintenance escalation is bounded per pass (500 candidates), so it must
/// make progress across passes: dependents blocked behind a missing or an
/// expired predecessor, and long recipient holds, beyond the first batch
/// are exposed by the next passes without duplicating or reopening the
/// incidents raised earlier, and every such dependent stays blocked.
#[test]
fn bounded_maintenance_exposes_every_blocked_dependent_and_hold_across_passes() {
    /// Items per scenario: more than one 500-row maintenance batch.
    const TOTAL: usize = 520;
    /// Maintenance instant, past the hold-escalation threshold of every item.
    const NOW: u64 = 800_000;
    // Asserts the multi-pass progression for one kind and returns nothing:
    // 500 new incidents, then the remaining 20, then none, all distinct.
    let check = |storage: &mut Storage, kind: &str| {
        for expected in [500, TOTAL - 500, 0] {
            assert_eq!(
                storage.run_maintenance(NOW).unwrap().escalated_holds,
                expected,
                "{kind}: new incidents in this pass"
            );
        }
        let incidents: Vec<_> = storage
            .incidents(true, NOW, 2_000)
            .unwrap()
            .into_iter()
            .filter(|incident| incident.kind == kind)
            .collect();
        assert_eq!(incidents.len(), TOTAL, "{kind}: one incident per item");
        assert!(
            incidents
                .iter()
                .all(|incident| incident.state == IncidentState::Open),
            "{kind}: all stay open"
        );
        let mut events: Vec<_> = incidents.iter().map(|i| i.event_id.clone()).collect();
        events.sort();
        events.dedup();
        assert_eq!(events.len(), TOTAL, "{kind}: no duplicate incidents");
    };
    let recipient = codex("thread-bounded-maintenance");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);

    // Dependents of predecessors that never arrived.
    let mut storage = Storage::open_in_memory(Limits::new(5_000)).unwrap();
    for index in 0..TOTAL {
        storage
            .publish(
                &with_meta(
                    keep_all(
                        "agent-run",
                        &format!("dep-{index:04}"),
                        &recipient,
                        Mode::Message,
                    ),
                    "predecessor",
                    &format!("never-{index:04}"),
                ),
                1_000,
            )
            .unwrap();
    }
    check(&mut storage, "predecessor_missing");
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, NOW, &timing())
            .unwrap(),
        Selection::Idle,
        "every blocked dependent stays blocked"
    );

    // Dependents of one predecessor that expired before delivery.
    let mut storage = Storage::open_in_memory(Limits::new(5_000)).unwrap();
    let mut predecessor = keep_all("agent-run", "pred", &recipient, Mode::Message);
    predecessor.expires_at = Some(ExpiresAt::from_unix_millis(2_000).unwrap());
    storage.publish(&predecessor, 1_000).unwrap();
    for index in 0..TOTAL {
        storage
            .publish(
                &with_meta(
                    keep_all(
                        "agent-run",
                        &format!("dep-{index:04}"),
                        &recipient,
                        Mode::Message,
                    ),
                    "predecessor",
                    "pred",
                ),
                1_001,
            )
            .unwrap();
    }
    check(&mut storage, "predecessor_expired");
    assert_eq!(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, NOW, &timing())
            .unwrap(),
        Selection::Idle,
        "every blocked dependent stays blocked"
    );

    // Long holds on many recipients.
    let mut storage = Storage::open_in_memory(Limits::new(5_000)).unwrap();
    for index in 0..TOTAL {
        let held = codex(&format!("held-{index:04}"));
        storage
            .publish(
                &keep_all(
                    "agent-run",
                    &format!("evt-{index:04}"),
                    &held,
                    Mode::Message,
                ),
                1_000,
            )
            .unwrap();
        storage
            .record_hold(&held, "no carrier attests", 1_000)
            .unwrap();
    }
    check(&mut storage, "recipient_held");
}

/// An audited disposition of the EXPIRED predecessor makes its dependent
/// eligible (the same rule the dispatch selection applies), so the dependent's
/// `predecessor_expired` incident closes as resolved and is never reopened;
/// nothing is released or replayed by maintenance itself.
#[test]
fn disposing_the_expired_predecessor_closes_the_dependent_incident_without_reopening() {
    let mut storage = store();
    let recipient = codex("thread-expired-disposed");
    let inactive = attest(&recipient, Lifecycle::Inactive, 1);
    let mut predecessor = keep_all("agent-run", "pred-d", &recipient, Mode::Message);
    predecessor.expires_at = Some(ExpiresAt::from_unix_millis(2_000).unwrap());
    storage.publish(&predecessor, 1_000).unwrap();
    storage
        .publish(
            &with_meta(
                keep_all("agent-run", "dep-d", &recipient, Mode::Message),
                "predecessor",
                "pred-d",
            ),
            1_001,
        )
        .unwrap();
    assert_eq!(storage.run_maintenance(3_000).unwrap().escalated_holds, 1);
    assert_eq!(storage.open_incidents(3_000, 10).unwrap().len(), 1);

    storage
        .dispose_event(
            "agent-run",
            "pred-d",
            "ops-1",
            "the source canceled it",
            4_000,
        )
        .unwrap();
    assert_eq!(
        storage.run_maintenance(5_000).unwrap().escalated_holds,
        0,
        "the disposed predecessor no longer blocks, so nothing is raised"
    );
    assert!(storage.open_incidents(5_000, 10).unwrap().is_empty());
    let closed = storage.incidents(true, 5_000, 10).unwrap();
    let incident = closed
        .iter()
        .find(|incident| incident.event_id == "dep-d")
        .unwrap();
    assert_eq!(incident.state, IncidentState::Resolved);
    let resolution = incident.resolution.as_deref().unwrap();
    assert!(
        resolution.contains("dispatch dependency rule"),
        "{resolution}"
    );
    assert!(
        !resolution.contains("audited"),
        "the text claims no particular decision: {resolution}"
    );
    // A further pass neither reopens it nor opens a duplicate.
    assert_eq!(storage.run_maintenance(6_000).unwrap().escalated_holds, 0);
    assert_eq!(
        storage.incidents(true, 6_000, 10).unwrap().len(),
        closed.len()
    );
    // The existing eligibility rule, not maintenance, releases the dependent.
    let released = attempt(
        storage
            .reserve_next(&inactive, EffectiveMode::Message, 7_000, &timing())
            .unwrap(),
    );
    assert_eq!(released.members[0].event_id, "dep-d");
}

/// More than five proven busy deferrals retain the original event until a
/// fresh idle endpoint accepts it once; no replacement event or refusal is made.
#[test]
fn deferred_known_unsent_waits_past_retry_budget_then_delivers() {
    let shared = Mutex::new(store());
    let recipient = codex("deferred-owner");
    shared
        .lock()
        .unwrap()
        .publish(
            &keep_all("agent-run", "deferred-event", &recipient, Mode::Message),
            1_000,
        )
        .unwrap();
    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Inactive,
        Outcome::DeferredKnownUnsent {
            evidence: "fixture owner proved not_idle before native input".into(),
        },
    );
    let mut now = 2_000;
    for _ in 0..8 {
        assert!(matches!(
            drive(&shared, &mut carrier, &recipient, now),
            DispatchReport::Sent {
                state: AttemptState::KnownUnsent,
                ..
            }
        ));
        let storage = shared.lock().unwrap();
        let evidence = storage
            .delivery_evidence("agent-run", "deferred-event")
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.delivery,
            DeliveryState::Unhanded,
            "temporary recipient state must not permanently refuse queued work"
        );
        assert!(storage.open_incidents(now, 10).unwrap().is_empty());
        drop(storage);
        now += 30_000;
    }
    carrier.outcome = ScriptedCarrier::accepted();
    assert!(matches!(
        drive(&shared, &mut carrier, &recipient, now),
        DispatchReport::Sent {
            state: AttemptState::NativeAccepted,
            events: 1
        }
    ));
    assert_eq!(carrier.sends.len(), 9);
    assert!(
        carrier
            .sends
            .iter()
            .all(|attempt| attempt.manifest == carrier.sends[0].manifest)
    );
    let storage = shared.lock().unwrap();
    let evidence = storage
        .delivery_evidence("agent-run", "deferred-event")
        .unwrap()
        .unwrap();
    assert_eq!(evidence.delivery, DeliveryState::Accepted);
    assert_eq!(
        evidence.attempts_made, 1,
        "only the eligible handoff consumes the budget"
    );
}

/// Busy deferrals preserve an earlier real failure charge, while subsequent
/// ordinary failures still exhaust at five and uncertain sends never retry.
#[test]
fn deferred_known_unsent_preserves_failure_and_unknown_boundaries() {
    for uncertain in [false, true] {
        let shared = Mutex::new(store());
        let recipient = codex("deferred-budget");
        shared
            .lock()
            .unwrap()
            .publish(
                &keep_all(
                    "agent-run",
                    "deferred-budget-event",
                    &recipient,
                    Mode::Message,
                ),
                1_000,
            )
            .unwrap();
        let mut carrier = ScriptedCarrier::new(
            Lifecycle::Inactive,
            Outcome::KnownUnsent {
                evidence: "fixture transport failed before write".into(),
            },
        );
        let mut now = 2_000;
        drive(&shared, &mut carrier, &recipient, now);
        carrier.outcome = Outcome::DeferredKnownUnsent {
            evidence: "fixture correlated busy refusal before native effect".into(),
        };
        for _ in 0..8 {
            now += 30_000;
            drive(&shared, &mut carrier, &recipient, now);
            let storage = shared.lock().unwrap();
            let evidence = storage
                .delivery_evidence("agent-run", "deferred-budget-event")
                .unwrap()
                .unwrap();
            assert_eq!(evidence.attempts_made, 1);
            assert_eq!(evidence.delivery, DeliveryState::Unhanded);
        }
        carrier.outcome = if uncertain {
            Outcome::OutcomeUnknown {
                reason: "fixture receipt lost after write".into(),
            }
        } else {
            Outcome::KnownUnsent {
                evidence: "fixture ordinary transport failure".into(),
            }
        };
        for _ in 0..4 {
            now += 30_000;
            drive(&shared, &mut carrier, &recipient, now);
        }
        let sends = carrier.sends.len();
        now += 300_000;
        assert!(!matches!(
            drive(&shared, &mut carrier, &recipient, now),
            DispatchReport::Sent { .. }
        ));
        assert_eq!(carrier.sends.len(), sends);
        let storage = shared.lock().unwrap();
        let evidence = storage
            .delivery_evidence("agent-run", "deferred-budget-event")
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.delivery,
            if uncertain {
                DeliveryState::Review
            } else {
                DeliveryState::Refused
            }
        );
        assert_eq!(evidence.attempts_made, if uncertain { 2 } else { 5 });
    }
}
