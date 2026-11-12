//! Synthetic regressions for bounded native sends and nonrecursive sender reports.
use crate::common;

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

/// Gives a synthetic envelope an absolute Unix-millisecond expiry.
fn with_expiry(mut envelope: bridge_core::Envelope, expiry: u64) -> bridge_core::Envelope {
    envelope.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(expiry).unwrap());
    envelope
}

/// A delivery report has its own bounded hand-off deadline without recursion.
#[test]
fn managed_feedback_attempt_keeps_its_own_deadline() {
    let mut storage = store();
    let recipient = codex("recipient");
    let envelope = with_expiry(
        keep_all("agent-run", "original", &recipient, Mode::Message),
        301_000,
    );
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
    invoke_on_epoch(storage, event_recipient, now, 1)
}

/// Reserves and commits a synthetic invocation at a given attested epoch.
fn invoke_on_epoch(
    storage: &mut Storage,
    event_recipient: &bridge_core::NativeAddress,
    now: u64,
    epoch: u64,
) -> AttemptFence {
    let attestation = attest(event_recipient, Lifecycle::Inactive, epoch);
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

/// Explicit expiry retains the original and uncertain feedback cannot recurse.
#[test]
fn managed_expiry_retains_message_and_bounds_feedback_without_recursion() {
    let mut storage = store();
    let recipient = codex("recipient");
    let envelope = with_expiry(
        keep_all("agent-run", "original", &recipient, Mode::Message),
        3_000,
    );
    storage.publish_managed(&envelope, &sender(), 1000).unwrap();
    storage.run_maintenance(3_000).unwrap();
    let result = report(&storage);
    assert_eq!(result.outcome, "failed");
    assert_eq!(result.sends_made, 0);
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
    assert_eq!(report(&storage).sends_made, 0);
}

/// Explicit expiry closes both unavailable and positively deferred originals.
#[test]
fn managed_unavailable_and_busy_stop_at_explicit_expiry() {
    for busy in [false, true] {
        let mut storage = store();
        let recipient = codex("recipient");
        storage
            .publish_managed(
                &with_expiry(
                    keep_all("agent-run", "original", &recipient, Mode::Message),
                    301_000,
                ),
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

/// Refunded busy feedback receipts still stop at five native calls.
#[test]
fn managed_feedback_busy_refunds_never_allow_a_sixth_native_call() {
    let mut storage = store();
    let recipient = codex("recipient");
    storage
        .publish_managed(
            &with_expiry(
                keep_all("agent-run", "original", &recipient, Mode::Message),
                1_500,
            ),
            &sender(),
            1000,
        )
        .unwrap();
    storage.run_maintenance(1_500).unwrap();
    let notice = report(&storage).feedback_event_id.unwrap();
    for i in 0..5 {
        let fence = invoke(&mut storage, &sender().address, 2000 + i * 2000);
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
    assert_eq!(report(&storage).feedback_state, "failed");
    let notice_report = storage
        .delivery_evidence("agent-run", &notice)
        .unwrap()
        .unwrap()
        .report
        .unwrap();
    assert_eq!(notice_report.sends_made, 5);
    assert_eq!(
        notice_report.reason,
        "Five native attempts ended with positive no-send evidence"
    );
    assert_eq!(
        storage
            .delivery_evidence("agent-run", &notice)
            .unwrap()
            .unwrap()
            .report
            .unwrap()
            .sends_made,
        5
    );
    assert_eq!(
        storage
            .delivery_evidence("agent-run", &notice)
            .unwrap()
            .unwrap()
            .attempts_made,
        0
    );
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&sender().address, Lifecycle::Inactive, 1),
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
            &with_expiry(
                keep_all("agent-run", "original", &recipient, Mode::Message),
                301_000,
            ),
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
    let original = with_expiry(
        keep_all("agent-run", "original", &recipient, Mode::Message),
        301_000,
    );
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
            &with_expiry(
                keep_all("agent-run", "original", &recipient, Mode::Message),
                301_000,
            ),
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
                &with_expiry(
                    keep_all("agent-run", "original", &recipient, Mode::Message),
                    301_000,
                ),
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
            &with_expiry(
                keep_all("agent-run", "original", &recipient, Mode::Message),
                301_000,
            ),
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
                &with_expiry(
                    keep_all("agent-run", &format!("own-{i}"), &recipient, Mode::Message),
                    301_000,
                ),
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
            &with_expiry(
                keep_all("agent-run", "foreign", &recipient, Mode::Message),
                301_000,
            ),
            &other,
            1000,
        )
        .unwrap();
    storage
        .publish_managed(
            &with_expiry(
                keep_all("agent-ide", "other-producer", &recipient, Mode::Message),
                301_000,
            ),
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
            &with_expiry(
                keep_all("agent-run", "older", &codex("slow"), Mode::Message),
                301_000,
            ),
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
    let managed = with_expiry(
        keep_all("agent-run", "original", &recipient, Mode::Message),
        301_000,
    );
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
        Ok(Invoked::Released(_))
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
            &with_expiry(
                keep_all("agent-run", "original", &recipient, Mode::Message),
                301_000,
            ),
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

/// An older active root survives its old deadline and restart, keeps its exact
/// custody identity and admission slot, and reaches the carrier when available.
#[test]
fn wake_retains_active_legacy_original_after_long_idle_and_restart() {
    let dir = TempDir::new("wake-legacy");
    let path = dir.path("db");
    let recipient = codex("offline");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let mut storage = Storage::open(&path, Limits::new(1)).unwrap();
    register_tags(&mut storage);
    let receipt = storage
        .publish_managed(&event, &sender(), 1_000)
        .unwrap()
        .receipt;
    drop(storage);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE managed_deliveries SET deadline_ms=301000 WHERE event_id='original'",
        [],
    )
    .unwrap();
    drop(db);
    let mut storage = Storage::open(&path, Limits::new(1)).unwrap();
    let now = 86_400_000;
    storage.run_maintenance(now).unwrap();
    assert_eq!(storage.count_delivery(DeliveryState::Unhanded).unwrap(), 1);
    assert!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .and_then(|e| e.report)
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
    assert!(matches!(
        storage.publish_managed(
            &keep_all("agent-run", "new", &recipient, Mode::Message),
            &sender(),
            now
        ),
        Err(bridge_core::CoreError::Capacity { .. })
    ));
    let replay = storage
        .publish_managed(&event, &sender(), now)
        .unwrap()
        .receipt;
    assert!(replay.replayed);
    assert_eq!(replay.acceptance_seq, receipt.acceptance_seq);
    assert_eq!(replay.envelope_hash, receipt.envelope_hash);
    let mut foreign = sender();
    foreign.request_id = "other-request".into();
    assert!(matches!(
        storage.publish_managed(&event, &foreign, now),
        Err(bridge_core::CoreError::Fence(_))
    ));
    let fence = invoke(&mut storage, &recipient, now + 1);
    let attempt = storage.attempt(fence.attempt_seq).unwrap().unwrap();
    assert_eq!(attempt.members[0].event_id, "original");
    storage
        .record_outcome(
            &fence,
            Outcome::NativeAccepted {
                evidence: "fixture accepted".into(),
            },
            now + 2,
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
}

/// Explicit expiry later than five minutes fences the old active row at the
/// sender's actual deadline, including a reservation made just before expiry.
#[test]
fn wake_respects_explicit_expiry_after_legacy_deadline() {
    let dir = TempDir::new("wake-expiry");
    let path = dir.path("db");
    let recipient = codex("expires");
    let mut event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let cutoff = 900_000;
    event.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(cutoff).unwrap());
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    drop(storage);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE managed_deliveries SET deadline_ms=301000 WHERE event_id='original'",
        [],
    )
    .unwrap();
    drop(db);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    storage.run_maintenance(400_000).unwrap();
    assert!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .and_then(|e| e.report)
            .is_none()
    );
    let attestation = attest(&recipient, Lifecycle::Inactive, 1);
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            cutoff - 10,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("expected reservation before expiry")
    };
    assert_eq!(attempt.deadline_ms, cutoff);
    assert!(!matches!(
        storage.mark_invoking(&attempt.fence, &attestation, cutoff),
        Ok(Invoked::Invoking(_))
    ));
    storage.run_maintenance(cutoff).unwrap();
    assert_eq!(report(&storage).outcome, "failed");
    assert_eq!(report(&storage).sends_made, 0);
    assert_eq!(storage.count_delivery(DeliveryState::Disposed).unwrap(), 1);
}

/// Both proven no-send outcomes may retry past five with increasing delay;
/// a later uncertain hand-off is retained once and never automatically retried.
#[test]
fn wake_retries_known_unsent_past_five_then_fences_unknown() {
    let dir = TempDir::new("report-compat");
    let path = dir.path("db");
    let mut storage = Storage::open(&path, Limits::new(1_000)).unwrap();
    register_tags(&mut storage);
    let recipient = codex("retry");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    let spacing = DELIVERY_WINDOW_MS + 1;
    for i in 0..12 {
        let now = 2_000 + i * spacing;
        let fence = invoke_on_epoch(&mut storage, &recipient, now, i / 4 + 1);
        let outcome = if i % 2 == 0 {
            Outcome::KnownUnsent {
                evidence: "fixture proved no write".into(),
            }
        } else {
            Outcome::DeferredKnownUnsent {
                evidence: "fixture busy; no write".into(),
            }
        };
        storage.record_outcome(&fence, outcome, now + 1).unwrap();
        let evidence = storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap();
        assert_eq!(evidence.delivery, DeliveryState::Unhanded);
        assert!(evidence.report.is_none());
        assert!(matches!(
            storage
                .reserve_next(
                    &attest(&recipient, Lifecycle::Inactive, i / 4 + 1),
                    EffectiveMode::Message,
                    now + 2,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
        if i == 1 || i == 9 {
            let before_retry = if i == 1 { now + 1_002 } else { now + 299_999 };
            assert!(matches!(
                storage
                    .reserve_next(
                        &attest(&recipient, Lifecycle::Inactive, i / 4 + 1),
                        EffectiveMode::Message,
                        before_retry,
                        &DispatchTiming::default()
                    )
                    .unwrap(),
                Selection::Idle
            ));
        }
    }
    let now = 2_000 + 12 * spacing;
    let fence = invoke_on_epoch(&mut storage, &recipient, now, 4);
    storage
        .record_outcome(
            &fence,
            Outcome::OutcomeUnknown {
                reason: "fixture lost receipt".into(),
            },
            now + 1,
        )
        .unwrap();
    let status = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    let result = status.report.as_ref().unwrap();
    assert_eq!(result.outcome, "unconfirmed");
    assert_eq!(result.sends_made, 5);
    assert!(
        result
            .reason
            .contains("at least 13 native attempts; compatibility count capped at 5")
    );
    assert!(result.reason.len() <= 256);
    let wire = bridge_core::Response::Status {
        receipt: None,
        delivery: Some(Box::new(status.clone())),
    };
    let decoded: bridge_core::Response =
        serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
    decoded.validate().unwrap();
    let mut invalid_status = status.clone();
    invalid_status.report.as_mut().unwrap().sends_made = 6;
    assert!(
        serde_json::from_slice::<bridge_core::DeliveryEvidence>(
            &serde_json::to_vec(&invalid_status).unwrap()
        )
        .is_err()
    );
    let page = storage
        .sender_reports("agent-run", &sender().address, 0)
        .unwrap();
    assert_eq!(page.reports[0].report, *result);
    let mut invalid_page = page.clone();
    invalid_page.reports[0].report.sends_made = 6;
    assert!(
        bridge_core::Response::SenderReports { page: invalid_page }
            .validate()
            .is_err()
    );
    bridge_core::Response::SenderReports { page }
        .validate()
        .unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let stored: (u32, String) = db.query_row(
        "SELECT sends_made,reason FROM managed_deliveries WHERE publisher_id='agent-run' AND event_id='original'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(stored.0, 13);
    assert_eq!(
        result.reason,
        format!(
            "{}; at least 13 native attempts; compatibility count capped at 5",
            stored.1
        )
    );
    storage.run_maintenance(now + spacing).unwrap();
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 4),
                EffectiveMode::Message,
                now + spacing,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
    assert_eq!(
        storage
            .sender_reports("agent-run", &sender().address, 0)
            .unwrap()
            .reports[0]
            .request_id,
        sender().request_id
    );
}

/// Historical completed originals are never reopened when old deadlines are ignored.
#[test]
fn wake_never_revives_historical_disposed_original() {
    let dir = TempDir::new("wake-disposed");
    let path = dir.path("db");
    let recipient = codex("old");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    drop(storage);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE events SET delivery='disposed' WHERE event_id='original'",
        [],
    )
    .unwrap();
    db.execute("UPDATE managed_deliveries SET outcome='failed',reason='previously completed',completed_ms=301000,deadline_ms=301000,completion_seq=1 WHERE event_id='original'", []).unwrap();
    drop(db);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    storage.run_maintenance(900_000).unwrap();
    assert_eq!(
        storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap()
            .delivery,
        DeliveryState::Disposed
    );
    assert_eq!(report(&storage).reason, "previously completed");
    assert!(
        storage
            .publish_managed(&event, &sender(), 900_000)
            .unwrap()
            .receipt
            .replayed
    );
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                900_001,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
}

/// A manual duplicate-risk retry followed by no-send retains the earlier
/// possible effect and cannot create another automatic attempt.
#[test]
fn wake_known_unsent_after_manual_retry_preserves_prior_uncertainty() {
    let mut storage = store();
    let recipient = codex("prior-effect");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    let first = invoke(&mut storage, &recipient, 2_000);
    storage
        .record_outcome(&first, Outcome::NativeHeld { recheck_ms: 50_000 }, 2_001)
        .unwrap();
    storage
        .authorize_manual_retry(
            "agent-run",
            "original",
            "fixture",
            "accepted duplicate risk",
            3_000,
        )
        .unwrap();
    let second = invoke(&mut storage, &recipient, 3_001);
    storage
        .record_outcome(
            &second,
            Outcome::KnownUnsent {
                evidence: "second attempt did not write".into(),
            },
            3_002,
        )
        .unwrap();
    assert_eq!(report(&storage).outcome, "unconfirmed");
    assert_eq!(report(&storage).sends_made, 2);
    storage.run_maintenance(1_000_000).unwrap();
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                1_000_001,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
}

/// Repeated proven no-sends preserve the original identity until a later
/// positive native acceptance, even after five attempts and five minutes.
#[test]
fn wake_known_unsent_retries_eventually_deliver_original() {
    let mut storage = store();
    let recipient = codex("eventual");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let receipt = storage
        .publish_managed(&event, &sender(), 1_000)
        .unwrap()
        .receipt;
    for i in 0..6 {
        let now = 2_000 + i * (DELIVERY_WINDOW_MS + 1);
        let fence = invoke_on_epoch(&mut storage, &recipient, now, i / 4 + 1);
        storage
            .record_outcome(
                &fence,
                Outcome::KnownUnsent {
                    evidence: "fixture no native write".into(),
                },
                now + 1,
            )
            .unwrap();
    }
    let now = 2_000 + 6 * (DELIVERY_WINDOW_MS + 1);
    let fence = invoke_on_epoch(&mut storage, &recipient, now, 2);
    let attempt = storage.attempt(fence.attempt_seq).unwrap().unwrap();
    assert_eq!(attempt.members[0].event_id, "original");
    storage
        .record_outcome(
            &fence,
            Outcome::NativeAccepted {
                evidence: "fixture accepted original".into(),
            },
            now + 1,
        )
        .unwrap();
    let delivered = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    assert_eq!(delivered.delivery, DeliveryState::Accepted);
    assert!(delivered.report.is_none());
    let replay = storage
        .publish_managed(&event, &sender(), now + 2)
        .unwrap()
        .receipt;
    assert!(replay.replayed);
    assert_eq!(replay.acceptance_seq, receipt.acceptance_seq);
    assert_eq!(replay.envelope_hash, receipt.envelope_hash);
}

/// A bounded number of proven no-sends per attested epoch preserves custody,
/// persists a visible hold across restart, and permits a new attested epoch.
#[test]
fn wake_limits_no_send_attempts_per_epoch_without_disposal() {
    let dir = TempDir::new("epoch-budget");
    let path = dir.path("db");
    let recipient = codex("per-epoch");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    let receipt = storage
        .publish_managed(&event, &sender(), 1_000)
        .unwrap()
        .receipt;
    for i in 0..5 {
        let now = 2_000 + i * (DELIVERY_WINDOW_MS + 1);
        let fence = invoke(&mut storage, &recipient, now);
        let outcome = if i % 2 == 0 {
            Outcome::KnownUnsent {
                evidence: "fixture proved no write".into(),
            }
        } else {
            Outcome::DeferredKnownUnsent {
                evidence: "fixture busy; no write".into(),
            }
        };
        storage.record_outcome(&fence, outcome, now + 1).unwrap();
    }
    let state = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    assert_eq!(state.delivery, DeliveryState::Unhanded);
    assert!(state.report.is_none());
    assert_eq!(
        state.incident.as_ref().map(|item| item.kind.as_str()),
        Some("managed_retry_epoch_exhausted")
    );
    let last = state.attempt.unwrap().attempt_seq;
    drop(storage);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    let later = 10_000_000;
    for now in [later, later + 100_000, later + 1_000_000] {
        storage.run_maintenance(now).unwrap();
        assert!(matches!(
            storage
                .reserve_next(
                    &attest(&recipient, Lifecycle::Inactive, 1),
                    EffectiveMode::Message,
                    now,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
        assert_eq!(
            storage
                .latest_attempt("agent-run", "original")
                .unwrap()
                .unwrap()
                .fence
                .attempt_seq,
            last
        );
    }
    let new_epoch = attest(&recipient, Lifecycle::Inactive, 2);
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &new_epoch,
            EffectiveMode::Message,
            later + 2_000_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("new epoch must permit delivery")
    };
    assert!(matches!(
        storage
            .mark_invoking(&attempt.fence, &new_epoch, later + 2_000_000)
            .unwrap(),
        Invoked::Invoking(_)
    ));
    storage
        .record_outcome(
            &attempt.fence,
            Outcome::NativeAccepted {
                evidence: "fixture accepted original".into(),
            },
            later + 2_000_001,
        )
        .unwrap();
    let state = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    assert_eq!(state.delivery, DeliveryState::Accepted);
    assert!(state.incident.is_none());
    let replay = storage
        .publish_managed(&event, &sender(), later + 2_000_002)
        .unwrap()
        .receipt;
    assert!(replay.replayed);
    assert_eq!(replay.acceptance_seq, receipt.acceptance_seq);
    assert_eq!(replay.envelope_hash, receipt.envelope_hash);
}

/// Constructs the protected adapter's internal resume route tag for tests.
fn resume_attest(
    recipient: &bridge_core::NativeAddress,
    epoch: u64,
) -> bridge_core::dispatch::Attestation {
    bridge_core::dispatch::Attestation::verified(
        recipient.clone(),
        recipient.native_session_id.clone(),
        epoch,
        Lifecycle::Inactive,
        bridge_core::dispatch::Capabilities {
            inject: false,
            message: true,
        },
        "codex-live-resume:fixture",
    )
    .unwrap()
}

/// A positive resume remains distinct from zero-effect evidence, preserves the
/// old failure budget, and cannot wake the same event again on another epoch.
/// A separate event may resume; the old event stays eligible on a loaded route.
#[test]
fn resume_history_blocks_same_event_but_allows_new_and_loaded_delivery() {
    for managed in [false, true] {
        let dir = TempDir::new("resume-history");
        let path = dir.path("db");
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        register_tags(&mut storage);
        let recipient = codex("resume-history");
        let old = keep_all("agent-run", "original", &recipient, Mode::Message);
        if managed {
            storage.publish_managed(&old, &sender(), 1_000).unwrap();
        } else {
            storage.publish(&old, 1_000).unwrap();
        }
        let first_route = resume_attest(&recipient, 1);
        for i in 0..3 {
            let now = 2_000 + i * 20_000;
            let Selection::Attempt(attempt) = storage
                .reserve_next(
                    &first_route,
                    EffectiveMode::Message,
                    now,
                    &DispatchTiming::default(),
                )
                .unwrap()
            else {
                panic!("first epoch reservation")
            };
            storage
                .mark_invoking(&attempt.fence, &first_route, now)
                .unwrap();
            storage
                .record_outcome(
                    &attempt.fence,
                    Outcome::KnownUnsent {
                        evidence: "fixture no native write".into(),
                    },
                    now + 1,
                )
                .unwrap();
        }
        let now = 80_000;
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &first_route,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("resume reservation")
        };
        storage
            .mark_invoking(&attempt.fence, &first_route, now)
            .unwrap();
        storage
            .observe_binding(&resume_attest(&recipient, 2), now + 1)
            .unwrap();
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "fixture correlated resume".into(),
                },
                now + 2,
            )
            .unwrap();
        let evidence = storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap();
        assert_eq!(evidence.delivery, DeliveryState::Unhanded);
        assert_eq!(evidence.attempts_made, 3);
        assert_eq!(evidence.tiers.len(), 3);
        assert!(
            evidence
                .note
                .unwrap()
                .starts_with("resume_accepted_no_message:")
        );
        let loaded = attest(&recipient, Lifecycle::Inactive, 2);
        assert!(matches!(
            storage
                .reserve_next(
                    &loaded,
                    EffectiveMode::Message,
                    now + 1_001,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
        let Selection::Attempt(fast) = storage
            .reserve_next(
                &loaded,
                EffectiveMode::Message,
                now + 1_002,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("new epoch must retry at one second")
        };
        assert_eq!(fast.members[0].event_id, "original");
        storage
            .release_attempt(&fast.fence, "fixture route change", now + 1_002)
            .unwrap();
        drop(storage);
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        let second_route = resume_attest(&recipient, 2);
        assert!(matches!(
            storage
                .reserve_next(
                    &second_route,
                    EffectiveMode::Message,
                    now + 1_003,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
        let fresh = keep_all("agent-run", "new", &recipient, Mode::Message);
        if managed {
            let mut new_sender = sender();
            new_sender.request_id = "new-request".into();
            storage
                .publish_managed(&fresh, &new_sender, now + 1_004)
                .unwrap();
        } else {
            storage.publish(&fresh, now + 1_004).unwrap();
        }
        let Selection::Attempt(new_attempt) = storage
            .reserve_next(
                &second_route,
                EffectiveMode::Message,
                now + 1_004,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("new event may resume")
        };
        assert_eq!(new_attempt.members[0].event_id, "new");
        storage
            .mark_invoking(&new_attempt.fence, &second_route, now + 1_004)
            .unwrap();
        storage
            .record_outcome(
                &new_attempt.fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "fixture new event resume".into(),
                },
                now + 1_005,
            )
            .unwrap();
        let Selection::Attempt(old_attempt) = storage
            .reserve_next(
                &loaded,
                EffectiveMode::Message,
                now + 1_006,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("loaded route must deliver old event")
        };
        assert_eq!(old_attempt.members[0].event_id, "original");
        storage
            .mark_invoking(&old_attempt.fence, &loaded, now + 1_006)
            .unwrap();
        storage
            .record_outcome(
                &old_attempt.fence,
                Outcome::NativeAccepted {
                    evidence: "fixture accepted message".into(),
                },
                now + 1_007,
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
    }
}

/// On the same epoch a positive resume retains earlier failure backoff;
/// an untagged route or missing receipt evidence cannot claim this result.
#[test]
fn resume_same_epoch_backoff_and_receipt_validation() {
    let mut storage = store();
    let recipient = codex("resume-same");
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    let route = resume_attest(&recipient, 1);
    for i in 0..3 {
        let now = 2_000 + i * 20_000;
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &route,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("reservation")
        };
        storage.mark_invoking(&attempt.fence, &route, now).unwrap();
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::KnownUnsent {
                    evidence: "fixture no native write".into(),
                },
                now + 1,
            )
            .unwrap();
    }
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &route,
            EffectiveMode::Message,
            80_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("resume reservation")
    };
    storage
        .mark_invoking(&attempt.fence, &route, 80_000)
        .unwrap();
    assert!(
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: String::new()
                },
                80_001
            )
            .is_err()
    );
    storage
        .record_outcome(
            &attempt.fence,
            Outcome::ResumeAcceptedNoMessage {
                evidence: "fixture receipt".into(),
            },
            80_001,
        )
        .unwrap();
    let loaded = attest(&recipient, Lifecycle::Inactive, 1);
    assert!(matches!(
        storage
            .reserve_next(
                &loaded,
                EffectiveMode::Message,
                84_000,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
    assert!(matches!(
        storage
            .reserve_next(
                &loaded,
                EffectiveMode::Message,
                84_001,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Attempt(_)
    ));

    let mut storage = store();
    let event = keep_all("agent-run", "original", &recipient, Mode::Message);
    storage.publish_managed(&event, &sender(), 1_000).unwrap();
    let fence = invoke(&mut storage, &recipient, 2_000);
    assert!(
        storage
            .record_outcome(
                &fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "untrusted route".into()
                },
                2_001
            )
            .is_err()
    );
    storage
        .record_outcome(
            &fence,
            Outcome::OutcomeUnknown {
                reason: "fixture uncertain".into(),
            },
            2_002,
        )
        .unwrap();
    assert!(
        storage
            .record_outcome(
                &fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "late resume".into()
                },
                2_003
            )
            .is_err()
    );
    assert_eq!(report(&storage).outcome, "unconfirmed");
}

/// A resume-tag transition between reservation and invocation never starts the
/// frozen message under a route whose history gate was not applied.
#[test]
fn resume_route_change_releases_before_native_invocation() {
    for initial_resume in [false, true] {
        let mut storage = store();
        let recipient = codex("route-change");
        storage
            .publish_managed(
                &keep_all("agent-run", "original", &recipient, Mode::Message),
                &sender(),
                1_000,
            )
            .unwrap();
        let loaded = attest(&recipient, Lifecycle::Inactive, 1);
        let resume = resume_attest(&recipient, 1);
        let (initial, fresh) = if initial_resume {
            (&resume, &loaded)
        } else {
            (&loaded, &resume)
        };
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                initial,
                EffectiveMode::Message,
                2_000,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("reservation")
        };
        assert!(matches!(
            storage.mark_invoking(&attempt.fence, fresh, 2_001).unwrap(),
            Invoked::Released(_)
        ));
        assert_eq!(storage.count_delivery(DeliveryState::Unhanded).unwrap(), 1);
    }
}

/// Repeated pre-invocation releases on one epoch cannot grow history without
/// bound; a newly attested epoch restores delivery of the retained original.
#[test]
fn wake_limits_closed_reservations_until_new_epoch() {
    let mut storage = store();
    let recipient = codex("reservation-race");
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1_000,
        )
        .unwrap();
    let first = attest(&recipient, Lifecycle::Inactive, 1);
    for now in 2_000..2_020 {
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &first,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("reservation")
        };
        storage
            .release_attempt(&attempt.fence, "fixture attestation changed", now)
            .unwrap();
    }
    let last = storage
        .latest_attempt("agent-run", "original")
        .unwrap()
        .unwrap()
        .fence
        .attempt_seq;
    assert!(matches!(
        storage
            .reserve_next(
                &first,
                EffectiveMode::Message,
                3_000,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
    let held = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    assert_eq!(held.delivery, DeliveryState::Unhanded);
    assert!(held.report.is_none());
    assert_eq!(held.incident.unwrap().kind, "managed_retry_epoch_exhausted");
    assert_eq!(
        storage
            .latest_attempt("agent-run", "original")
            .unwrap()
            .unwrap()
            .fence
            .attempt_seq,
        last
    );
    let second = attest(&recipient, Lifecycle::Inactive, 2);
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &second,
            EffectiveMode::Message,
            4_000,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("new epoch")
    };
    storage
        .mark_invoking(&attempt.fence, &second, 4_000)
        .unwrap();
    storage
        .record_outcome(
            &attempt.fence,
            Outcome::NativeAccepted {
                evidence: "fixture delivered original".into(),
            },
            4_001,
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
}

/// An existing active original with five historical no-sends receives the new
/// epoch hold even when no incident was saved by the older implementation.
#[test]
fn wake_existing_exhausted_epoch_is_held_without_new_attempt() {
    let dir = TempDir::new("old-epoch-budget");
    let path = dir.path("db");
    let recipient = codex("prior-budget");
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    register_tags(&mut storage);
    storage
        .publish_managed(
            &keep_all("agent-run", "original", &recipient, Mode::Message),
            &sender(),
            1_000,
        )
        .unwrap();
    for i in 0..5 {
        let now = 2_000 + i * (DELIVERY_WINDOW_MS + 1);
        let fence = invoke(&mut storage, &recipient, now);
        storage
            .record_outcome(
                &fence,
                Outcome::KnownUnsent {
                    evidence: "fixture did not send".into(),
                },
                now + 1,
            )
            .unwrap();
    }
    let last = storage
        .latest_attempt("agent-run", "original")
        .unwrap()
        .unwrap()
        .fence
        .attempt_seq;
    drop(storage);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE incidents SET state='resolved' WHERE kind='managed_retry_epoch_exhausted'",
        [],
    )
    .unwrap();
    drop(db);
    let mut storage = Storage::open(&path, Limits::new(10)).unwrap();
    assert!(matches!(
        storage
            .reserve_next(
                &attest(&recipient, Lifecycle::Inactive, 1),
                EffectiveMode::Message,
                10_000_000,
                &DispatchTiming::default()
            )
            .unwrap(),
        Selection::Idle
    ));
    let held = storage
        .delivery_evidence("agent-run", "original")
        .unwrap()
        .unwrap();
    assert_eq!(held.delivery, DeliveryState::Unhanded);
    assert_eq!(held.incident.unwrap().kind, "managed_retry_epoch_exhausted");
    assert_eq!(
        storage
            .latest_attempt("agent-run", "original")
            .unwrap()
            .unwrap()
            .fence
            .attempt_seq,
        last
    );
}

/// A successful resume cannot erase an earlier possible message hand-off,
/// including an explicitly authorized duplicate-risk retry for producer-v1.
#[test]
fn resume_does_not_requeue_prior_possible_message_effect() {
    for managed in [false, true] {
        let mut storage = store();
        let recipient = codex("resume-prior");
        let event = keep_all("agent-run", "original", &recipient, Mode::Message);
        if managed {
            storage.publish_managed(&event, &sender(), 1_000).unwrap();
        } else {
            storage.publish(&event, 1_000).unwrap();
        }
        let first = invoke(&mut storage, &recipient, 2_000);
        storage
            .record_outcome(&first, Outcome::NativeHeld { recheck_ms: 50_000 }, 2_001)
            .unwrap();
        storage
            .authorize_manual_retry(
                "agent-run",
                "original",
                "fixture",
                "accepted duplicate risk",
                3_000,
            )
            .unwrap();
        let route = resume_attest(&recipient, 1);
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &route,
                EffectiveMode::Message,
                3_001,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("authorized reservation")
        };
        storage
            .mark_invoking(&attempt.fence, &route, 3_001)
            .unwrap();
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "fixture correlated resume".into(),
                },
                3_002,
            )
            .unwrap();
        let evidence = storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap();
        if managed {
            assert_eq!(evidence.report.unwrap().outcome, "unconfirmed");
        } else {
            assert_eq!(evidence.delivery, DeliveryState::Review);
            assert_eq!(
                evidence.incident.unwrap().kind,
                "resume_prior_message_effect"
            );
        }
        assert!(matches!(
            storage
                .reserve_next(
                    &attest(&recipient, Lifecycle::Inactive, 2),
                    EffectiveMode::Message,
                    500_000,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
    }
}

/// A new attested epoch arriving after the resume result shortens only that
/// unsent message's delay, preserving prior failure counts and unknown fences.
#[test]
fn resume_late_epoch_observation_shortens_backoff() {
    for managed in [false, true] {
        let mut storage = store();
        let recipient = codex("late-epoch");
        let event = keep_all("agent-run", "original", &recipient, Mode::Message);
        if managed {
            storage.publish_managed(&event, &sender(), 1_000).unwrap();
        } else {
            storage.publish(&event, 1_000).unwrap();
        }
        let resume = resume_attest(&recipient, 1);
        for i in 0..3 {
            let now = 2_000 + i * 20_000;
            let Selection::Attempt(attempt) = storage
                .reserve_next(
                    &resume,
                    EffectiveMode::Message,
                    now,
                    &DispatchTiming::default(),
                )
                .unwrap()
            else {
                panic!("reservation")
            };
            storage.mark_invoking(&attempt.fence, &resume, now).unwrap();
            storage
                .record_outcome(
                    &attempt.fence,
                    Outcome::KnownUnsent {
                        evidence: "fixture did not send".into(),
                    },
                    now + 1,
                )
                .unwrap();
        }
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &resume,
                EffectiveMode::Message,
                80_000,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("resume reservation")
        };
        storage
            .mark_invoking(&attempt.fence, &resume, 80_000)
            .unwrap();
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::ResumeAcceptedNoMessage {
                    evidence: "fixture correlated resume".into(),
                },
                80_001,
            )
            .unwrap();
        let newer = attest(&recipient, Lifecycle::Inactive, 2);
        storage.observe_binding(&newer, 80_101).unwrap();
        assert_eq!(
            storage
                .delivery_evidence("agent-run", "original")
                .unwrap()
                .unwrap()
                .attempts_made,
            3
        );
        assert!(matches!(
            storage
                .reserve_next(
                    &newer,
                    EffectiveMode::Message,
                    81_100,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
        let Selection::Attempt(next) = storage
            .reserve_next(
                &newer,
                EffectiveMode::Message,
                81_101,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("new epoch must release delayed message")
        };
        assert_eq!(next.members[0].event_id, "original");
    }
}

/// A positive resume callback arriving after the handoff lease expired is
/// accepted without settling or retrying the unknown message handoff.
#[test]
fn late_resume_after_expired_invocation_preserves_unknown() {
    for managed in [false, true] {
        let mut storage = store();
        let recipient = codex("late-resume");
        let event = keep_all("agent-run", "original", &recipient, Mode::Message);
        if managed {
            storage.publish_managed(&event, &sender(), 1_000).unwrap();
        } else {
            storage.publish(&event, 1_000).unwrap();
        }
        let attestation = resume_attest(&recipient, 1);
        let timing = DispatchTiming {
            lease_ms: 1_000,
            handoff_ms: 1_000,
        };
        let Selection::Attempt(attempt) = storage
            .reserve_next(&attestation, EffectiveMode::Message, 2_000, &timing)
            .unwrap()
        else {
            panic!("resume reservation")
        };
        storage
            .mark_invoking(&attempt.fence, &attestation, 2_000)
            .unwrap();
        assert_eq!(storage.expire_attempt_leases(3_000).unwrap(), (0, 1, 0));
        let before = storage
            .delivery_evidence("agent-run", "original")
            .unwrap()
            .unwrap();
        assert_eq!(before.attempt_state, "outcome_unknown");
        for now in [3_001, 3_002] {
            let record = storage
                .record_outcome(
                    &attempt.fence,
                    Outcome::ResumeAcceptedNoMessage {
                        evidence: "fixture correlated late receipt".into(),
                    },
                    now,
                )
                .unwrap();
            assert_eq!(
                record.state,
                bridge_core::dispatch::AttemptState::OutcomeUnknown
            );
            assert_eq!(
                storage
                    .delivery_evidence("agent-run", "original")
                    .unwrap()
                    .unwrap(),
                before
            );
        }
        let newer = attest(&recipient, Lifecycle::Inactive, 2);
        assert!(matches!(
            storage
                .reserve_next(
                    &newer,
                    EffectiveMode::Message,
                    5_000,
                    &DispatchTiming::default()
                )
                .unwrap(),
            Selection::Idle
        ));
    }
}
