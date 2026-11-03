//! Synthetic regressions for bounded native sends and nonrecursive sender reports.
mod common;

use bridge_core::dispatch::{
    AttemptFence, DispatchTiming, EffectiveMode, Invoked, Lifecycle, Outcome, Selection,
};
use bridge_core::managed::{DELIVERY_WINDOW_MS, DeliveryReport, ManagedSender};
use bridge_core::recovery::{DeliveryState, EvidenceTier};
use bridge_core::{Limits, Mode, Storage};
use common::{TempDir, attest, codex, keep_all, register_tags, store};

/// An attested fixture sender whose address is distinct from the recipient.
fn sender() -> ManagedSender {
    ManagedSender {
        address: codex("sender"),
        request_id: "request-1".into(),
    }
}

/// A delivery report has its own bounded hand-off deadline without recursion.
#[test]
fn managed_feedback_attempt_keeps_its_own_deadline() {
    let mut storage = store();
    let recipient = codex("recipient");
    let envelope = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage
        .publish_managed(&envelope, &sender(), 1_000)
        .unwrap();
    storage.run_maintenance(301_000).unwrap();
    let notice = report(&storage).feedback_event_id.unwrap();
    let attestation = attest(&sender().address, Lifecycle::Inactive, 1);
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            600_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected pending delivery report");
    };
    assert_eq!(attempt.members[0].event_id, notice);
    assert_eq!(attempt.deadline_ms, 601_000);
}

/// Reserves and commits one native invocation without touching a real carrier.
fn invoke(
    storage: &mut Storage,
    event_recipient: &bridge_core::NativeAddress,
    now: u64,
) -> AttemptFence {
    let attestation = attest(event_recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(record) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            now,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected native reservation");
    };
    assert!(matches!(
        storage
            .mark_invoking(&record.fence, &attestation, now)
            .unwrap(),
        Invoked::Invoking(_)
    ));
    record.fence
}

/// Retained authoritative report for the fixture original.
fn report(storage: &Storage) -> DeliveryReport {
    storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap()
        .report
        .unwrap()
}

/// Fifth actual no-send closes the original and failed feedback cannot recurse.
#[test]
fn managed_fifth_failure_retains_message_and_bounds_feedback_without_recursion() {
    let mut storage = store();
    let recipient = codex("recipient");
    let envelope = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&envelope, &sender(), 1000).unwrap();
    for i in 0..5 {
        let now = 2000 + i * 20_000;
        let fence = invoke(&mut storage, &recipient, now);
        storage
            .record_outcome(
                &fence,
                Outcome::KnownUnsent {
                    evidence: "fixture proved no write".into(),
                },
                now + 1,
            )
            .unwrap();
    }
    let result = report(&storage);
    assert_eq!(result.outcome, "failed");
    assert_eq!(result.sends_made, 5);
    assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
    assert!(
        storage
            .next_pending(&recipient.to_canonical_string(), 10)
            .unwrap()
            .is_empty()
    );
    storage.run_maintenance(90_000).unwrap();
    let notice = report(&storage).feedback_event_id.unwrap();
    assert_eq!(
        storage
            .next_pending(&sender().address.to_canonical_string(), 10)
            .unwrap()
            .len(),
        1
    );
    let fence = invoke(&mut storage, &sender().address, 91_000);
    assert!(
        !storage
            .attempt(fence.attempt_seq)
            .unwrap()
            .unwrap()
            .manifest
            .contains(envelope.payload.as_str())
    );
    storage
        .record_outcome(
            &fence,
            Outcome::OutcomeUnknown {
                reason: "fixture lost feedback receipt".into(),
            },
            91_001,
        )
        .unwrap();
    for now in [100_000, 500_000, 900_000] {
        storage.run_maintenance(now).unwrap();
    }
    assert_eq!(report(&storage).feedback_state, "unconfirmed");
    assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 2);
    assert!(
        storage
            .next_pending(&sender().address.to_canonical_string(), 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        storage
            .delivery_evidence("agent-run", &notice)
            .unwrap()
            .unwrap()
            .report
            .unwrap()
            .feedback_event_id
            .is_none()
    );
    assert!(
        storage
            .retention("agent-run", "original")
            .unwrap()
            .unwrap()
            .envelope_bytes
            > 0
    );
    assert_eq!(storage.compact_payloads(0).unwrap(), 0);
    assert!(
        storage
            .publish_managed(&envelope, &sender(), 1_000_000)
            .unwrap()
            .receipt
            .replayed
    );
    assert_eq!(report(&storage).sends_made, 5);
}

/// Unavailable recipients and positive busy deferrals share the absolute limit.
#[test]
fn managed_unavailable_and_busy_stop_at_five_minutes() {
    for busy in [false, true] {
        let mut storage = store();
        let recipient = codex("recipient");
        storage
            .publish_managed(
                &keep_all("agent-run", "original", &recipient, Mode::Message),
                &sender(),
                1000,
            )
            .unwrap();
        if busy {
            let fence = invoke(&mut storage, &recipient, 2000);
            storage
                .record_outcome(
                    &fence,
                    Outcome::DeferredKnownUnsent {
                        evidence: "fixture busy; no effect".into(),
                    },
                    2001,
                )
                .unwrap();
        }
        storage
            .run_maintenance(1000 + DELIVERY_WINDOW_MS - 1)
            .unwrap();
        assert!(
            storage
                .delivery_evidence("agent-run", "original")
                .unwrap()
                .and_then(|e| e.report)
                .is_none()
        );
        storage.run_maintenance(1000 + DELIVERY_WINDOW_MS).unwrap();
        assert_eq!(report(&storage).outcome, "failed");
        assert_eq!(report(&storage).sends_made, u32::from(busy));
        assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
        storage
            .run_maintenance(1000 + 2 * DELIVERY_WINDOW_MS)
            .unwrap();
        assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 2);
        assert_eq!(report(&storage).feedback_state, "failed");
        assert!(
            storage
                .retention("agent-run", "original")
                .unwrap()
                .unwrap()
                .envelope_bytes
                > 0
        );
    }
}

/// Refunded busy receipts still count as actual native calls and stop at five.
#[test]
fn managed_busy_refunds_never_allow_a_sixth_native_call() {
    let mut storage = store();
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1000,
        )
        .unwrap();
    for i in 0..5 {
        let fence = invoke(&mut storage, &recipient, 2000 + i * 2000);
        storage
            .record_outcome(
                &fence,
                Outcome::DeferredKnownUnsent {
                    evidence: "fixture busy; no write".into(),
                },
                2001 + i * 2000,
            )
            .unwrap();
    }
    assert_eq!(report(&storage).sends_made, 5);
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap()
            .attempts_made,
        0
    );
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                90_000,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
}

/// An unknown effect stops immediately, late evidence improves truth without requeue.
#[test]
fn managed_unknown_is_unconfirmed_and_late_evidence_cannot_restart_delivery() {
    for accepted in [false, true] {
        let mut storage = Storage::open_in_memory(Limits::new(1)).unwrap();
        register_tags(&mut storage);
        let recipient = codex("recipient");
        storage
            .publish_managed(
                &keep_all("agent-run", "original", &recipient, Mode::Message),
                &sender(),
                1000,
            )
            .unwrap();
        let fence = invoke(&mut storage, &recipient, 2000);
        storage
            .record_outcome(
                &fence,
                Outcome::OutcomeUnknown {
                    reason: "fixture uncertain".into(),
                },
                2001,
            )
            .unwrap();
        assert_eq!(report(&storage).outcome, "unconfirmed");
        assert_eq!(report(&storage).sends_made, 1);
        assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
        storage
            .record_evidence(
                "agent-run",
                "original",
                fence.attempt_seq,
                if accepted {
                    EvidenceTier::NativeAccepted
                } else {
                    EvidenceTier::KnownUnsent
                },
                "fixture positive late evidence",
                3000,
            )
            .unwrap();
        assert_eq!(report(&storage).outcome, "unconfirmed");
        assert!(
            storage
                .next_pending(&recipient.to_canonical_string(), 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            storage
                .delivery_evidence("agent-run", "original")
                .unwrap()
                .unwrap()
                .delivery,
            if accepted {
                DeliveryState::Accepted
            } else {
                DeliveryState::Disposed
            }
        );
        storage
            .publish(
                &keep_all("agent-run", "new-admission", &recipient, Mode::Message),
                4000,
            )
            .unwrap();
    }
}

/// Native holds time out conservatively and old fences still accept positive receipts.
#[test]
fn managed_native_hold_deadline_retains_uncertainty_and_callback_fence() {
    let mut storage = store();
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1000,
        )
        .unwrap();
    let fence = invoke(&mut storage, &recipient, 2000);
    storage
        .record_outcome(&fence, Outcome::NativeHeld { recheck_ms: 50_000 }, 2001)
        .unwrap();
    storage.run_maintenance(1000 + DELIVERY_WINDOW_MS).unwrap();
    assert_eq!(report(&storage).outcome, "unconfirmed");
    storage
        .record_outcome(
            &fence,
            Outcome::NativeAccepted {
                evidence: "fixture late queue receipt".into(),
            },
            400_000,
        )
        .unwrap();
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Accepted
    );
    assert_eq!(report(&storage).outcome, "unconfirmed");
}

/// Restart, replay and old legacy rows preserve immutable bytes and origin association.
#[test]
fn managed_restart_and_legacy_replay_never_enroll_old_rows_or_reset_deadline() {
    let dir = TempDir::new("managed");
    let recipient = codex("recipient");
    let original = keep_all("agent-run", "original", &recipient, Mode::Message);
    let legacy = keep_all("agent-run", "legacy", &recipient, Mode::Message);
    let hash = original.envelope_hash();
    {
        let mut storage = Storage::open(dir.path("db"), Limits::new(10)).unwrap();
        register_tags(&mut storage);
        storage.publish_managed(&original, &sender(), 1000).unwrap();
        storage.publish(&legacy, 1000).unwrap();
    }
    let mut storage = Storage::open(dir.path("db"), Limits::new(10)).unwrap();
    assert!(
        storage
            .publish_managed(&original, &sender(), 100_000)
            .unwrap()
            .receipt
            .replayed
    );
    assert!(
        storage
            .publish_managed(&legacy, &sender(), 100_000)
            .unwrap()
            .receipt
            .replayed
    );
    let mut foreign = sender();
    foreign.address = codex("other-sender");
    assert!(
        storage
            .publish_managed(&original, &foreign, 100_001)
            .is_err()
    );
    storage.run_maintenance(1000 + DELIVERY_WINDOW_MS).unwrap();
    assert_eq!(report(&storage).outcome, "failed");
    assert_eq!(
        storage
            .publish_managed(&original, &sender(), 400_000)
            .unwrap()
            .receipt
            .envelope_hash,
        hash
    );
    assert!(
        storage
            .delivery_evidence("agent-run", "legacy")
            .unwrap()
            .and_then(|e| e.report)
            .is_none()
    );
    assert_eq!(
        storage
            .next_pending(&recipient.to_canonical_string(), 10)
            .unwrap()[0]
            .event_id,
        "legacy"
    );
}

/// Full admission/history caps cannot roll back original completion or lose its report.
#[test]
fn managed_report_survives_feedback_admission_capacity_and_expires_pending_notice() {
    let mut limits = Limits::new(1);
    limits.max_retained_events = 1;
    let mut storage = Storage::open_in_memory(limits).unwrap();
    register_tags(&mut storage);
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1000,
        )
        .unwrap();
    storage.run_maintenance(301_000).unwrap();
    assert_eq!(report(&storage).feedback_state, "pending");
    assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
    storage.run_maintenance(601_000).unwrap();
    assert_eq!(report(&storage).feedback_state, "unavailable");
    assert!(
        storage
            .retention("agent-run", "original")
            .unwrap()
            .unwrap()
            .envelope_bytes
            > 0
    );
}

/// Expired reserved work cannot invoke, and in-flight work is never cancelled unsafely.
#[test]
fn managed_deadline_fences_reservation_but_preserves_inflight_outcome() {
    for invoking in [false, true] {
        let mut storage = store();
        let recipient = codex("recipient");
        storage
            .publish_managed(
                &keep_all("agent-run", "original", &recipient, Mode::Message),
                &sender(),
                1000,
            )
            .unwrap();
        let attestation = attest(&recipient, Lifecycle::Inactive, 1);
        let timing = DispatchTiming {
            lease_ms: 500_000,
            handoff_ms: 500_000,
        };
        let Selection::Attempt(record) = storage
            .reserve_next(&attestation, EffectiveMode::Message, 2000, &timing)
            .unwrap()
        else {
            panic!("reservation");
        };
        if invoking {
            storage
                .mark_invoking(&record.fence, &attestation, 2001)
                .unwrap();
        }
        storage.run_maintenance(301_000).unwrap();
        if invoking {
            assert_eq!(report(&storage).outcome, "unconfirmed");
            assert_eq!(storage.count_delivery(DeliveryState::Invoking).unwrap(), 0);
            assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
            storage
                .record_outcome(
                    &record.fence,
                    Outcome::KnownUnsent {
                        evidence: "fixture no write after long call".into(),
                    },
                    302_000,
                )
                .unwrap();
        } else {
            assert!(
                storage
                    .mark_invoking(&record.fence, &attestation, 301_001)
                    .is_err()
            );
        }
        assert_eq!(
            report(&storage).outcome,
            if invoking { "unconfirmed" } else { "failed" }
        );
        storage.run_maintenance(600_000).unwrap();
        assert_eq!(storage.count_delivery(DeliveryState::Review).unwrap(), 0);
    }
}

/// A carrier lease expiring after automatic archival cannot reopen active incidents.
#[test]
fn managed_archived_inflight_lease_keeps_report_without_reopening_incident() {
    let mut storage = store();
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1000,
        )
        .unwrap();
    let fence = invoke(&mut storage, &recipient, 2000);
    storage.run_maintenance(301_000).unwrap();
    assert_eq!(report(&storage).outcome, "unconfirmed");
    assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
    assert_eq!(storage.open_incident_count().unwrap(), 0);
    storage
        .record_outcome(
            &fence,
            Outcome::NativeAccepted {
                evidence: "late correlated acceptance".into(),
            },
            400_000,
        )
        .unwrap();
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Accepted
    );
    assert_eq!(report(&storage).outcome, "unconfirmed");
    assert_eq!(storage.open_incident_count().unwrap(), 0);
}

/// Sender pages are scoped, finite, repeatable and retain reports after notices expire.
#[test]
fn managed_sender_report_pages_survive_notice_failure_without_cross_sender_disclosure() {
    let mut storage = store();
    let recipient = codex("offline");
    let origin = sender();
    for i in 0..23 {
        let mut own = origin.clone();
        own.request_id = format!("own-{i}");
        storage
            .publish_managed(
                &keep_all("agent-run", &format!("own-{i}"), &recipient, Mode::Message),
                &own,
                1000,
            )
            .unwrap();
    }
    let other = ManagedSender {
        address: codex("someone-else"),
        request_id: "foreign".into(),
    };
    storage
        .publish_managed(
            &keep_all("agent-run", "foreign", &recipient, Mode::Message),
            &other,
            1000,
        )
        .unwrap();
    storage
        .publish_managed(
            &keep_all("agent-ide", "other-producer", &recipient, Mode::Message),
            &origin,
            1000,
        )
        .unwrap();
    storage.run_maintenance(301_000).unwrap();
    storage.run_maintenance(601_000).unwrap();
    let first = storage
        .sender_reports("agent-run", &origin.address, 0)
        .unwrap();
    assert_eq!(first.reports.len(), 20);
    assert!(
        first
            .reports
            .iter()
            .all(|item| item.request_id.starts_with("own-"))
    );
    assert!(
        first
            .reports
            .iter()
            .all(|item| item.report.feedback_state == "failed")
    );
    let cursor = first.next_after_seq.unwrap();
    let second = storage
        .sender_reports("agent-run", &origin.address, cursor)
        .unwrap();
    assert_eq!(second.reports.len(), 3);
    assert!(second.next_after_seq.is_none());
    assert!(
        second
            .reports
            .iter()
            .all(|item| item.completion_seq > cursor)
    );
    assert_eq!(
        storage
            .sender_reports("agent-run", &origin.address, 0)
            .unwrap(),
        first
    );
    assert!(
        !serde_json::to_string(&first)
            .unwrap()
            .contains("synthetic result")
    );
    assert_eq!(
        storage
            .sender_reports("agent-run", &other.address, 0)
            .unwrap()
            .reports
            .len(),
        1
    );
    assert!(
        storage
            .sender_reports("agent-run", &codex("empty"), 0)
            .unwrap()
            .reports
            .is_empty()
    );
    assert_eq!(
        storage
            .sender_reports("agent-ide", &origin.address, 0)
            .unwrap()
            .reports
            .len(),
        1
    );
    assert!(
        storage
            .sender_reports("agent-run", &origin.address, u64::MAX)
            .is_err()
    );
    assert_eq!(storage.count_delivery(DeliveryState::Unhanded).unwrap(), 0);
}

/// A later completion remains visible after a cursor even for an older publication.
#[test]
fn managed_sender_report_cursor_follows_completion_order_across_restart() {
    let dir = TempDir::new("report-order");
    let mut storage = Storage::open(dir.path("db"), Limits::new(100)).unwrap();
    register_tags(&mut storage);
    let origin = sender();
    storage
        .publish_managed(
            &keep_all("agent-run", "older", &codex("slow"), Mode::Message),
            &origin,
            1000,
        )
        .unwrap();
    let mut second = origin.clone();
    second.request_id = "second".into();
    storage
        .publish_managed(
            &keep_all("agent-run", "newer", &codex("fast"), Mode::Message),
            &second,
            1100,
        )
        .unwrap();
    let fence = invoke(&mut storage, &codex("fast"), 2000);
    storage
        .record_outcome(
            &fence,
            Outcome::OutcomeUnknown {
                reason: "fixture uncertain".into(),
            },
            2001,
        )
        .unwrap();
    let first = storage
        .sender_reports("agent-run", &origin.address, 0)
        .unwrap();
    assert_eq!(first.reports[0].event_id, "newer");
    let cursor = first.reports[0].completion_seq;
    storage.run_maintenance(301_000).unwrap();
    drop(storage);
    let storage = Storage::open(dir.path("db"), Limits::new(100)).unwrap();
    let later = storage
        .sender_reports("agent-run", &origin.address, cursor)
        .unwrap();
    assert_eq!(later.reports.len(), 1);
    assert_eq!(later.reports[0].event_id, "older");
    assert!(later.reports[0].completion_seq > cursor);
    assert_eq!(
        storage
            .sender_reports("agent-run", &origin.address, 0)
            .unwrap()
            .reports
            .len(),
        2
    );
}

/// A late hold after archival cannot reopen an incident or renew automatic rechecks.
#[test]
fn managed_late_hold_after_deadline_never_reopens_recovery_work() {
    for written in [false, true] {
        let mut storage = store();
        let recipient = codex("late-held");
        let mut envelope = keep_all("agent-run", "original", &recipient, Mode::Message);
        envelope.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(10_000).unwrap());
        storage.publish_managed(&envelope, &sender(), 1000).unwrap();
        let fence = invoke(&mut storage, &recipient, 2000);
        storage.run_maintenance(10_000).unwrap();
        assert_eq!(report(&storage).outcome, "unconfirmed");
        let outcome = if written {
            Outcome::WrittenNoReceipt {
                evidence: "fixture wrote before timeout".into(),
                receipt_deadline_ms: 12_000,
            }
        } else {
            Outcome::NativeHeld { recheck_ms: 12_000 }
        };
        storage.record_outcome(&fence, outcome, 11_000).unwrap();
        storage.run_maintenance(12_000).unwrap();
        assert_eq!(storage.open_incident_count().unwrap(), 0);
        assert_eq!(storage.expire_attempt_leases(1_000_000).unwrap(), (0, 0, 0));
        assert!(
            storage
                .next_pending(&recipient.to_canonical_string(), 10)
                .unwrap()
                .is_empty()
        );
        storage
            .record_outcome(
                &fence,
                Outcome::NativeAccepted {
                    evidence: "fixture late acceptance".into(),
                },
                13_000,
            )
            .unwrap();
        assert_eq!(report(&storage).outcome, "unconfirmed");
        assert_eq!(
            storage
                .delivery_evidence("agent-run", "original")
                .unwrap()
                .unwrap()
                .delivery,
            DeliveryState::Accepted
        );
    }
}

/// Legacy expiry and payload compaction cannot delete a managed message awaiting its report.
#[test]
fn managed_payload_survives_legacy_expiry_and_compaction() {
    let mut storage = store();
    let recipient = codex("offline");
    let mut envelope = keep_all("agent-run", "original", &recipient, Mode::Message);
    envelope.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(2000).unwrap());
    storage.publish_managed(&envelope, &sender(), 1000).unwrap();
    assert_eq!(storage.expire_due(2000).unwrap(), 0);
    let mut expired = envelope.clone();
    expired.event_id = bridge_core::EventId::new("initially-expired").unwrap();
    storage.publish_managed(&expired, &sender(), 3000).unwrap();
    assert_eq!(storage.compact_payloads(0).unwrap(), 0);
    assert!(
        storage
            .retention("agent-run", "initially-expired")
            .unwrap()
            .unwrap()
            .envelope_bytes
            > 0
    );
    assert!(
        storage
            .retention("agent-run", "original")
            .unwrap()
            .unwrap()
            .envelope_bytes
            > 0
    );
    storage.run_maintenance(2000).unwrap();
    assert_eq!(report(&storage).outcome, "failed");
    assert_eq!(storage.compact_payloads(0).unwrap(), 0);
    assert!(
        storage
            .retention("agent-run", "original")
            .unwrap()
            .unwrap()
            .envelope_bytes
            > 0
    );
}

/// Managed root attempts are capped at their immutable deadline, unlike SDK work.
#[test]
fn managed_attempt_deadline_is_capped_and_blocks_late_invocation() {
    let mut storage = store();
    let recipient = codex("recipient");
    let managed = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&managed, &sender(), 1_000).unwrap();
    let attestation = attest(&recipient, Lifecycle::Inactive, 7);
    let cutoff = 1_000 + DELIVERY_WINDOW_MS;
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            cutoff - 10,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("managed attempt")
    };
    assert_eq!(attempt.deadline_ms, cutoff);
    assert!(matches!(
        storage.mark_invoking(&attempt.fence, &attestation, cutoff),
        Err(bridge_core::CoreError::Fence(_))
    ));
    assert_eq!(
        storage
            .attempt(attempt.fence.attempt_seq)
            .unwrap()
            .unwrap()
            .deadline_ms,
        cutoff
    );
    storage.run_maintenance(cutoff).unwrap();
    assert_eq!(report(&storage).sends_made, 0);
    assert_eq!(report(&storage).outcome, "failed");

    let ordinary_recipient = codex("ordinary");
    storage
        .publish(
            &keep_all("agent-run", "ordinary", &ordinary_recipient, Mode::Message),
            2_000,
        )
        .unwrap();
    let a = attest(&ordinary_recipient, Lifecycle::Inactive, 8);
    let Selection::Attempt(ordinary) = storage
        .reserve_next(
            &a,
            EffectiveMode::Message,
            cutoff - 10,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("ordinary attempt")
    };
    assert_eq!(
        ordinary.deadline_ms,
        cutoff - 10 + DispatchTiming::default().handoff_ms
    );
}

/// Frozen feedback remains pending and is admitted after its recipient thaws.
#[test]
fn managed_feedback_waits_for_recipient_unfreeze() {
    let mut storage = store();
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1_000,
        )
        .unwrap();
    storage.freeze_recipient(&sender().address).unwrap();
    let cutoff = 1_000 + DELIVERY_WINDOW_MS;
    storage.run_maintenance(cutoff).unwrap();
    assert_eq!(report(&storage).feedback_state, "pending");
    assert!(
        storage
            .next_pending(&sender().address.to_canonical_string(), 10)
            .unwrap()
            .is_empty()
    );
    storage.unfreeze_recipient(&sender().address).unwrap();
    storage.run_maintenance(cutoff + 1).unwrap();
    assert_eq!(report(&storage).feedback_state, "queued");
    assert_eq!(
        storage
            .next_pending(&sender().address.to_canonical_string(), 10)
            .unwrap()
            .len(),
        1
    );
}

/// Epoch allocation accounts for retained attempts even after bindings disappear.
#[test]
fn maximum_endpoint_epoch_includes_historical_attempts_and_rejects_corruption() {
    let dir = TempDir::new("epoch-maximum");
    let path = dir.path("state.db");
    let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
    register_tags(&mut storage);
    assert_eq!(storage.max_endpoint_epoch().unwrap(), 0);
    let one = codex("one");
    let two = codex("two");
    storage
        .observe_binding(&attest(&one, Lifecycle::Inactive, 5), 1_000)
        .unwrap();
    assert_eq!(storage.max_endpoint_epoch().unwrap(), 5);
    storage
        .publish(&keep_all("agent-run", "epoch", &two, Mode::Message), 1_001)
        .unwrap();
    let attestation = attest(&two, Lifecycle::Inactive, 12);
    let Selection::Attempt(_) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_002,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("epoch reservation")
    };
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "DELETE FROM bindings WHERE recipient=?1",
        [two.to_canonical_string()],
    )
    .unwrap();
    assert_eq!(storage.max_endpoint_epoch().unwrap(), 12);
    db.execute("UPDATE bindings SET endpoint_epoch=-1", [])
        .unwrap();
    assert!(matches!(
        storage.max_endpoint_epoch(),
        Err(bridge_core::CoreError::Integrity(_))
    ));
}

/// Managed replays and their original sender fence survive a recipient freeze.
#[test]
fn frozen_managed_original_preserves_replay_and_sender_conflicts() {
    let mut storage = store();
    let recipient = codex("recipient");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let first = storage.publish_managed(&event, &sender(), 1_000).unwrap();
    storage.freeze_recipient(&recipient).unwrap();
    let replay = storage.publish_managed(&event, &sender(), 2_000).unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(replay.receipt.acceptance_seq, first.receipt.acceptance_seq);
    let other_sender = ManagedSender {
        address: codex("other"),
        ..sender()
    };
    assert!(matches!(
        storage.publish_managed(&event, &other_sender, 2_000),
        Err(bridge_core::CoreError::Fence(_))
    ));
    assert!(matches!(
        storage.publish_managed(
            &keep_all("agent-run", "new", &recipient, Mode::Message),
            &sender(),
            2_000
        ),
        Err(bridge_core::CoreError::Busy(_))
    ));
}
