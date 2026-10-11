//! Integration checks for fenced dispatch, evidence tiers, no-wake
//! policy, fairness, compaction and restart recovery.
//!
//! All carriers are synthetic; all state is isolated (fresh temporary
//! databases, unique sockets never used here). No native host is touched.

mod common;

use std::sync::{Arc, Mutex};

use bridge_core::dispatch::{
    AttemptFence, AttemptState, CarrierOutcome, DispatchCarrier, Lifecycle, Outcome, dispatch_one,
    resolve_mode,
};
use bridge_core::{
    CoreError, Envelope, EventId, Harness, Kind, Limits, Metadata, Mode, NativeAddress, Payload,
    Policy, PublisherId, Storage, StreamId,
};
use common::TempDir;

/// A scripted synthetic carrier standing in for the native adapter.
struct ScriptedCarrier {
    /// Lifecycle each observe call reports.
    lifecycle: Lifecycle,
    /// Outcome each send call returns.
    outcome: CarrierOutcome,
    /// Recorded (mode, hash) hand-offs.
    sends: Vec<(String, String)>,
}

impl ScriptedCarrier {
    /// A carrier that always reports one lifecycle and one outcome.
    fn new(lifecycle: Lifecycle, outcome: CarrierOutcome) -> Self {
        ScriptedCarrier {
            lifecycle,
            outcome,
            sends: Vec::new(),
        }
    }
}

impl DispatchCarrier for ScriptedCarrier {
    fn observe(&mut self, _recipient: &NativeAddress) -> Result<Lifecycle, String> {
        Ok(self.lifecycle)
    }

    fn send(
        &mut self,
        mode: bridge_core::dispatch::EffectiveMode,
        hash: &str,
        _framed: &str,
    ) -> CarrierOutcome {
        self.sends
            .push((mode.as_str().to_string(), hash.to_string()));
        self.outcome.clone()
    }
}

/// A keep_all envelope addressed to one synthetic recipient.
fn keep_all(event: &str, recipient: &str) -> Envelope {
    Envelope::new(
        PublisherId::new("agent-run").unwrap(),
        EventId::new(event).unwrap(),
        NativeAddress::new("host-1", Harness::Codex, "default", recipient).unwrap(),
        Kind::new("worker.completed").unwrap(),
        Mode::Auto,
        Policy::KeepAll,
        Payload::new("synthetic result").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// A latest-snapshot envelope for one stream/revision.
fn latest(event: &str, recipient: &str, stream: &str, revision: u64) -> Envelope {
    Envelope::new(
        PublisherId::new("agent-ide").unwrap(),
        EventId::new(event).unwrap(),
        NativeAddress::new("host-1", Harness::ClaudeCode, "default", recipient).unwrap(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::Latest {
            stream: StreamId::new(stream).unwrap(),
            revision,
        },
        Payload::new("{\"view\":\"ok\"}").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// Minimal framing closure for the driver.
fn frame(
    _envelope: &Envelope,
    _mode: bridge_core::dispatch::EffectiveMode,
) -> Result<String, CoreError> {
    Ok("framed".to_string())
}

#[test]
fn auto_resolves_from_lifecycle_and_never_both_paths() {
    assert_eq!(
        resolve_mode(Mode::Auto, Lifecycle::Active),
        Some(bridge_core::dispatch::EffectiveMode::Inject)
    );
    assert_eq!(
        resolve_mode(Mode::Auto, Lifecycle::Inactive),
        Some(bridge_core::dispatch::EffectiveMode::Message)
    );
    assert_eq!(resolve_mode(Mode::Auto, Lifecycle::Unknown), None);

    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-1", "thread-1");
    storage.publish(&envelope, 1_000).unwrap();

    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Active,
        CarrierOutcome::Accepted {
            evidence: "queue id 1".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut carrier, &envelope, &frame, 2_000, 5_000).unwrap();
    assert_eq!(result.state, AttemptState::NativeAccepted);
    assert_eq!(carrier.sends.len(), 1, "exactly one hand-off per attempt");
    assert_eq!(carrier.sends[0].0, "inject");

    let attempt = storage
        .latest_attempt("agent-run", "evt-1")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, AttemptState::NativeAccepted);
    assert_eq!(attempt.effective_mode.as_str(), "inject");
}

#[test]
fn inactive_selects_message_and_unknown_holds_without_invoking() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-2", "thread-2");
    storage.publish(&envelope, 1_000).unwrap();

    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Inactive,
        CarrierOutcome::Accepted {
            evidence: "queue id 2".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut carrier, &envelope, &frame, 2_000, 5_000).unwrap();
    assert_eq!(result.state, AttemptState::NativeAccepted);
    assert_eq!(carrier.sends[0].0, "message");

    // Unknown lifecycle: hold visibly, never invoke, never wake.
    let held = keep_all("evt-3", "thread-3");
    storage.publish(&held, 1_000).unwrap();
    let mut unknown = ScriptedCarrier::new(
        Lifecycle::Unknown,
        CarrierOutcome::Accepted {
            evidence: "must not happen".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut unknown, &held, &frame, 2_000, 5_000).unwrap();
    assert!(!result.possibly_handed_off);
    assert!(unknown.sends.is_empty(), "no carrier call on unknown state");
    let incidents = storage.open_incidents().unwrap();
    assert!(
        incidents
            .iter()
            .any(|incident| incident.kind == "held_unknown_lifecycle"
                && incident.event_id == "evt-3"),
        "held recipient must surface a retained incident"
    );
}

#[test]
fn invoking_is_durable_before_any_handoff() {
    // A second connection reads the attempt state DURING the carrier call:
    // it must already be 'invoking', proving the write happens before the
    // possible side effect.
    let dir = TempDir::new("dispatch-crash");
    let db = dir.path("bridge.db");
    let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
    let envelope = keep_all("evt-crash", "thread-9");
    storage.publish(&envelope, 1_000).unwrap();
    let db_path = db.clone();

    struct ProbingCarrier {
        db: std::path::PathBuf,
        state_seen: Arc<Mutex<Option<String>>>,
    }
    impl DispatchCarrier for ProbingCarrier {
        fn observe(&mut self, _recipient: &NativeAddress) -> Result<Lifecycle, String> {
            Ok(Lifecycle::Active)
        }
        fn send(
            &mut self,
            _mode: bridge_core::dispatch::EffectiveMode,
            _hash: &str,
            _framed: &str,
        ) -> CarrierOutcome {
            let connection = rusqlite::Connection::open(&self.db).unwrap();
            let state: String = connection
                .query_row(
                    "SELECT state FROM attempts ORDER BY attempt_seq DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            *self.state_seen.lock().unwrap() = Some(state);
            CarrierOutcome::Accepted {
                evidence: "probed".into(),
            }
        }
    }

    let seen = Arc::new(Mutex::new(None));
    let mut carrier = ProbingCarrier {
        db: db_path,
        state_seen: Arc::clone(&seen),
    };
    dispatch_one(&mut storage, &mut carrier, &envelope, &frame, 2_000, 5_000).unwrap();
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("invoking"),
        "invoking must be committed before the carrier can act"
    );
}

#[test]
fn unknown_outcome_is_retained_and_never_auto_retried() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-unknown", "thread-4");
    storage.publish(&envelope, 1_000).unwrap();

    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Active,
        CarrierOutcome::Unknown {
            reason: "socket write may have landed".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut carrier, &envelope, &frame, 2_000, 5_000).unwrap();
    assert_eq!(result.state, AttemptState::OutcomeUnknown);

    // A second drive of the same event refuses without audited manual
    // authorization — no automatic replay after a possible hand-off.
    let mut retry = ScriptedCarrier::new(
        Lifecycle::Active,
        CarrierOutcome::Accepted {
            evidence: "must not happen".into(),
        },
    );
    match dispatch_one(&mut storage, &mut retry, &envelope, &frame, 9_000, 5_000) {
        Err(CoreError::Fence(detail)) => {
            assert!(detail.contains("unknown-handoff"), "unexpected: {detail}")
        }
        other => panic!("expected fence refusal, got {other:?}"),
    }
    assert!(retry.sends.is_empty());

    // The incident is retained with reason and review deadline.
    let incidents = storage.open_incidents().unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, "unknown_handoff");
    assert!(incidents[0].review_deadline_ms.is_some());

    // Audited manual authorization unblocks exactly one more attempt and
    // keeps the duplicate risk recorded.
    storage
        .authorize_manual_retry("agent-run", "evt-unknown", "operator reviewed", 10_000)
        .unwrap();
    let mut manual = ScriptedCarrier::new(
        Lifecycle::Active,
        CarrierOutcome::Accepted {
            evidence: "accepted on manual retry".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut manual, &envelope, &frame, 11_000, 5_000).unwrap();
    assert_eq!(result.state, AttemptState::NativeAccepted);
}

#[test]
fn known_unsent_closes_attempt_and_allows_bounded_retry() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-unsent", "thread-5");
    storage.publish(&envelope, 1_000).unwrap();

    let reserved = storage
        .reserve_attempt(
            "agent-run",
            "evt-unsent",
            bridge_core::dispatch::EffectiveMode::Message,
            envelope.envelope_hash().as_str(),
            1_000,
            60_000,
        )
        .unwrap();
    storage.mark_invoking(&reserved.fence, 1_100).unwrap();
    storage
        .record_outcome(
            &reserved.fence,
            Outcome::KnownUnsent {
                evidence: "carrier proved no write".into(),
            },
            1_200,
        )
        .unwrap()
        .state;
    let attempt = storage
        .latest_attempt("agent-run", "evt-unsent")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, AttemptState::KnownUnsent);

    // Positively known-unsent follows the ordinary bounded retry policy.
    let second = storage
        .reserve_attempt(
            "agent-run",
            "evt-unsent",
            bridge_core::dispatch::EffectiveMode::Message,
            envelope.envelope_hash().as_str(),
            2_000,
            60_000,
        )
        .unwrap();
    assert_ne!(second.fence.attempt_seq, reserved.fence.attempt_seq);
}

#[test]
fn expired_leases_reclaim_only_uninvoked_reservations() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let reclaimable = keep_all("evt-res", "thread-6");
    let uncertain = keep_all("evt-unc", "thread-7");
    storage.publish(&reclaimable, 1_000).unwrap();
    storage.publish(&uncertain, 1_000).unwrap();

    // Reserved but never invoked: reclaimable by lease expiry.
    storage
        .reserve_attempt(
            "agent-run",
            "evt-res",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            1_000,
            1_000,
        )
        .unwrap();
    // Invoking with a lease: expiry means possible hand-off.
    let invoking = storage
        .reserve_attempt(
            "agent-run",
            "evt-unc",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            1_000,
            1_000,
        )
        .unwrap();
    storage.mark_invoking(&invoking.fence, 1_100).unwrap();

    assert_eq!(storage.expire_attempt_leases(5_000).unwrap(), 2);

    let reclaimed = storage
        .latest_attempt("agent-run", "evt-res")
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.state, AttemptState::Closed);
    let unknown = storage
        .latest_attempt("agent-run", "evt-unc")
        .unwrap()
        .unwrap();
    assert_eq!(unknown.state, AttemptState::OutcomeUnknown);
    assert!(
        storage
            .open_incidents()
            .unwrap()
            .iter()
            .any(|incident| incident.event_id == "evt-unc")
    );

    // The reclaimed event may reserve again; the uncertain one may not.
    assert!(
        storage
            .reserve_attempt(
                "agent-run",
                "evt-res",
                bridge_core::dispatch::EffectiveMode::Message,
                "h",
                6_000,
                60_000
            )
            .is_ok()
    );
    assert!(matches!(
        storage.reserve_attempt(
            "agent-run",
            "evt-unc",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            6_000,
            60_000
        ),
        Err(CoreError::Fence(_))
    ));
}

#[test]
fn stale_fences_refuse_without_new_invocation() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-fence", "thread-8");
    storage.publish(&envelope, 1_000).unwrap();
    let reserved = storage
        .reserve_attempt(
            "agent-run",
            "evt-fence",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            1_000,
            60_000,
        )
        .unwrap();

    // A forged fence with the wrong event id refuses.
    let forged = AttemptFence {
        attempt_seq: reserved.fence.attempt_seq,
        publisher: "agent-run".into(),
        event_id: "other-event".into(),
    };
    assert!(matches!(
        storage.mark_invoking(&forged, 1_100),
        Err(CoreError::Fence(_))
    ));
    // A fabricated attempt number refuses.
    let fabricated = AttemptFence {
        attempt_seq: 999_999,
        publisher: "agent-run".into(),
        event_id: "evt-fence".into(),
    };
    assert!(matches!(
        storage.mark_invoking(&fabricated, 1_100),
        Err(CoreError::Fence(_))
    ));
    // Expired lease refuses to invoke.
    let expired_envelope = keep_all("evt-expired", "thread-8b");
    storage.publish(&expired_envelope, 1_000).unwrap();
    let _ = storage
        .reserve_attempt(
            "agent-run",
            "evt-expired",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            1_000,
            100,
        )
        .unwrap();
    assert!(storage.expire_attempt_leases(2_000).unwrap() >= 1);
    let envelope_expired = keep_all("evt-expired2", "thread-8b");
    storage.publish(&envelope_expired, 1_000).unwrap();
    let short_lease = storage
        .reserve_attempt(
            "agent-run",
            "evt-expired2",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            2_100,
            100,
        )
        .unwrap();
    assert!(matches!(
        storage.mark_invoking(&short_lease.fence, 5_000),
        Err(CoreError::Fence(_))
    ));
}

#[test]
fn no_wake_policy_blocks_auto_and_message() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let envelope = keep_all("evt-pause", "thread-p");
    let recipient = envelope.recipient.to_canonical_string();
    storage.publish(&envelope, 1_000).unwrap();

    storage
        .set_no_wake(&recipient, true, Some("owner paused the session"), 1_500)
        .unwrap();
    for mode in [Mode::Auto, Mode::Message, Mode::Inject] {
        let mut paused_envelope = keep_all("evt-pause", "thread-p");
        paused_envelope.mode = mode;
        let mut carrier = ScriptedCarrier::new(
            Lifecycle::Active,
            CarrierOutcome::Accepted {
                evidence: "must not happen".into(),
            },
        );
        match dispatch_one(
            &mut storage,
            &mut carrier,
            &paused_envelope,
            &frame,
            2_000,
            5_000,
        ) {
            Err(CoreError::PolicyHold { reason, .. }) => {
                assert!(reason.contains("paused"), "unexpected reason: {reason}")
            }
            other => panic!("expected policy hold for {mode:?}, got {other:?}"),
        }
        assert!(carrier.sends.is_empty());
    }

    storage.set_no_wake(&recipient, false, None, 3_000).unwrap();
    let mut carrier = ScriptedCarrier::new(
        Lifecycle::Active,
        CarrierOutcome::Accepted {
            evidence: "queue id".into(),
        },
    );
    let result = dispatch_one(&mut storage, &mut carrier, &envelope, &frame, 3_100, 5_000).unwrap();
    assert_eq!(result.state, AttemptState::NativeAccepted);
}

#[test]
fn keep_all_has_priority_and_snapshot_quota_reserves_capacity() {
    let mut limits = Limits::new(100);
    limits.max_pending_latest_per_recipient = 3;
    let mut storage = Storage::open_in_memory(limits).unwrap();

    // A flood of replaceable snapshots for one recipient.
    for revision in 1..=3 {
        storage
            .publish(
                &latest(&format!("view-{revision}"), "thread-q", "diag", revision),
                1_000,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.publish(&latest("view-4", "thread-q", "diag", 4), 1_000),
        Err(CoreError::Capacity { .. })
    ));
    // keep_all is exempt from the snapshot reserve and still admitted.
    storage
        .publish(&keep_all("critical-1", "thread-q"), 1_000)
        .unwrap();
    // A different recipient's snapshot stream is independent.
    storage
        .publish(&latest("other-1", "thread-q2", "diag", 1), 1_000)
        .unwrap();

    // Selection returns keep_all before replaceable snapshots. The views
    // were published under the Claude-Code fixture recipient; keep_all
    // under the Codex one; each address selects its own queue with
    // keep_all first inside it.
    let codex_queue = storage
        .next_pending(
            &NativeAddress::new("host-1", Harness::Codex, "default", "thread-q")
                .unwrap()
                .to_canonical_string(),
            10,
        )
        .unwrap();
    assert_eq!(codex_queue[0].event_id, "critical-1");
    assert_eq!(codex_queue[0].policy_class, "keep_all");

    let claude_queue = storage
        .next_pending(
            &NativeAddress::new("host-1", Harness::ClaudeCode, "default", "thread-q")
                .unwrap()
                .to_canonical_string(),
            10,
        )
        .unwrap();
    assert_eq!(claude_queue.len(), 3);
    assert!(
        claude_queue
            .iter()
            .all(|event| event.event_id.starts_with("view-"))
    );
}

#[test]
fn compaction_keeps_dedup_identity() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&latest("new", "thread-c", "diag", 2), 1_000)
        .unwrap();
    storage
        .publish(&latest("old", "thread-c", "diag", 1), 1_000)
        .unwrap();
    assert_eq!(storage.compact_payloads(0).unwrap(), 1);

    // The compacted superseded entry still dedups identical replays and
    // still reports its original disposition.
    let replay = storage
        .publish(&latest("old", "thread-c", "diag", 1), 9_000)
        .unwrap();
    assert!(replay.receipt.replayed);
    assert_eq!(replay.receipt.state, bridge_core::EventState::Superseded);
}

#[test]
fn restart_resumes_held_and_uncertain_state() {
    let dir = TempDir::new("dispatch-restart");
    let db = dir.path("bridge.db");
    let envelope = keep_all("evt-restart", "thread-r");
    {
        let mut storage = Storage::open(&db, Limits::new(10)).unwrap();
        storage.publish(&envelope, 1_000).unwrap();
        let reserved = storage
            .reserve_attempt(
                "agent-run",
                "evt-restart",
                bridge_core::dispatch::EffectiveMode::Message,
                envelope.envelope_hash().as_str(),
                1_000,
                500,
            )
            .unwrap();
        storage.mark_invoking(&reserved.fence, 1_100).unwrap();
    }

    // A later daemon reopens the same database: nothing was lost, and the
    // reconciliation pass converts the expired invoking lease into a
    // retained unknown with an incident — never a blind retry.
    let mut reopened = Storage::open(&db, Limits::new(10)).unwrap();
    assert_eq!(reopened.expire_attempt_leases(5_000).unwrap(), 1);
    let attempt = reopened
        .latest_attempt("agent-run", "evt-restart")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, AttemptState::OutcomeUnknown);
    assert_eq!(reopened.open_incidents().unwrap().len(), 1);
    // Re-running reconciliation is idempotent.
    assert_eq!(reopened.expire_attempt_leases(6_000).unwrap(), 0);

    // Custody itself survived the restart untouched.
    let replay = reopened.publish(&envelope, 7_000).unwrap();
    assert!(replay.receipt.replayed);
}

#[test]
fn concurrent_publishers_on_one_database() {
    use std::sync::Barrier;
    let dir = TempDir::new("dispatch-concurrent");
    let db = dir.path("bridge.db");
    Storage::open(&db, Limits::new(1000)).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = ["publisher-a", "publisher-b"]
        .iter()
        .map(|publisher| {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            let publisher = publisher.to_string();
            std::thread::spawn(move || {
                let mut storage = Storage::open(&db, Limits::new(1000)).unwrap();
                barrier.wait();
                for index in 0..10 {
                    let envelope = Envelope::new(
                        PublisherId::new(publisher.clone()).unwrap(),
                        EventId::new(format!("evt-{index}")).unwrap(),
                        NativeAddress::new("host-1", Harness::Codex, "default", "thread-cc")
                            .unwrap(),
                        Kind::new("worker.completed").unwrap(),
                        Mode::Message,
                        Policy::KeepAll,
                        Payload::new("x").unwrap(),
                        Metadata::new(),
                        None,
                    )
                    .unwrap();
                    storage.publish(&envelope, 1_000).unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("publisher thread panicked");
    }

    let storage = Storage::open(&db, Limits::new(1000)).unwrap();
    for publisher in ["publisher-a", "publisher-b"] {
        for index in 0..10 {
            let row = storage
                .lookup(
                    &PublisherId::new(publisher).unwrap(),
                    &EventId::new(format!("evt-{index}")).unwrap(),
                )
                .unwrap();
            assert!(row.is_some(), "{publisher}/evt-{index} lost");
        }
    }
}

/// A dependent command waits for its declared predecessor's resolution.
#[test]
fn dependent_ordering_waits_for_predecessor() {
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let mut predecessor = keep_all("cmd-1", "thread-dep");
    let mut dependent = keep_all("cmd-2", "thread-dep");
    dependent
        .metadata
        .insert("predecessor".into(), "cmd-1".into());
    storage.publish(&predecessor, 1_000).unwrap();
    storage.publish(&dependent, 1_000).unwrap();

    // The predecessor is still pending: the dependent must hold.
    match storage.reserve_attempt(
        "agent-run",
        "cmd-2",
        bridge_core::dispatch::EffectiveMode::Message,
        "h",
        2_000,
        60_000,
    ) {
        Err(CoreError::PolicyHold { reason, .. }) => {
            assert!(reason.contains("cmd-1"), "unexpected reason: {reason}")
        }
        other => panic!("expected dependency hold, got {other:?}"),
    }

    // Once the predecessor carries positive evidence, the dependent may go.
    let fence = storage
        .reserve_attempt(
            "agent-run",
            "cmd-1",
            bridge_core::dispatch::EffectiveMode::Message,
            "h",
            2_000,
            60_000,
        )
        .unwrap();
    storage.mark_invoking(&fence.fence, 2_100).unwrap();
    storage
        .record_outcome(
            &fence.fence,
            Outcome::NativeAccepted {
                evidence: "queue id".into(),
            },
            2_200,
        )
        .unwrap();
    assert!(
        storage
            .reserve_attempt(
                "agent-run",
                "cmd-2",
                bridge_core::dispatch::EffectiveMode::Message,
                "h",
                3_000,
                60_000
            )
            .is_ok()
    );
}
