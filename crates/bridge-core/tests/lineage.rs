//! Producer-lineage authority checks for `latest` streams: one
//! authenticated producer owns a lineage scope (the coalescing group
//! without the publisher), handover is an audited operator transition, and
//! neither side's watermarks, event ids, attempts nor evidence are ever
//! rewritten.
//!
//! All state is isolated synthetic fixtures; publishers authenticate
//! through fixture grants, never through event metadata.

mod common;

use std::time::Duration;

use bridge_client::BridgeClient;
use bridge_core::dispatch::{
    Attestation, DispatchTiming, EffectiveMode, Lifecycle, Outcome, Selection,
};
use bridge_core::service::{self, Config, GrantConfig, PublishBody};
use bridge_core::types::{Envelope, EventId, Kind, Metadata, Payload, PublisherId, StreamId};
use bridge_core::{CoreError, EventState, Harness, Limits, Mode, NativeAddress, Policy, Storage};
use common::{TempDir, attest, short_socket, wait_listening};

/// Fixture first-producer token.
const RUN_TOKEN: &str = "lin-run-publisher-token-0001";
/// Fixture second-producer token.
const IDE_TOKEN: &str = "lin-ide-publisher-token-0002";
/// Fixture operator token.
const OPS_TOKEN: &str = "lin-operator-token-0000003";

/// The shared recipient of the lineage.
fn recipient() -> NativeAddress {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7").unwrap()
}

/// A config with two producer grants (different publishers) and one
/// operator grant, both producers allowed the same lineage dimensions.
fn config(dir: &TempDir) -> Config {
    let allowed = vec![recipient().to_canonical_string()];
    Config {
        universal_limits: bridge_core::UniversalLimits::default(),
        database: dir.path("bridge.db"),
        socket: short_socket("lin"),
        limits: Limits::new(1_000),
        grants: vec![
            GrantConfig {
                producer_v1: None,
                token: RUN_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: allowed.clone(),
                kinds: vec!["diagnostics.view".to_string()],
                modes: vec!["auto".into()],
                policies: vec!["keep_all".into(), "latest".into(), "batch".into()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: IDE_TOKEN.to_string(),
                publisher: "agent-ide".to_string(),
                recipients: allowed,
                kinds: vec!["diagnostics.view".to_string()],
                modes: vec!["auto".into()],
                policies: vec!["keep_all".into(), "latest".into(), "batch".into()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: OPS_TOKEN.to_string(),
                publisher: "bridge-ops".to_string(),
                recipients: vec![],
                kinds: vec![],
                modes: vec![],
                policies: vec![],
                admin: true,
            },
        ],
    }
}

/// A latest-snapshot body on `diag` at `revision` with optional project.
fn latest_body(event: &str, revision: u64) -> PublishBody {
    PublishBody {
        event_id: event.to_string(),
        recipient: recipient(),
        kind: "diagnostics.view".to_string(),
        mode: Mode::Auto,
        policy: Policy::Latest {
            stream: StreamId::new("diag").unwrap(),
            revision,
        },
        payload: "{\"view\":\"ok\"}".to_string(),
        metadata: Default::default(),
        expires_at: None,
    }
}

/// A direct-storage envelope for the same lineage, from either publisher.
fn latest_envelope(publisher: &str, event: &str, revision: u64) -> Envelope {
    Envelope::new(
        PublisherId::new(publisher).unwrap(),
        EventId::new(event).unwrap(),
        recipient(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::Latest {
            stream: StreamId::new("diag").unwrap(),
            revision,
        },
        Payload::new("{\"view\":\"ok\"}").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// A direct-storage latest envelope requested in message mode.
fn message_envelope(publisher: &str, event: &str, revision: u64) -> Envelope {
    let mut envelope = latest_envelope(publisher, event, revision);
    envelope.mode = Mode::Message;
    envelope
}

/// The first producer claims the lineage; a second producer is declined
/// before publication with nothing stored and no quota consumed.
#[test]
fn first_producer_claims_and_second_is_declined_before_publication() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&latest_envelope("agent-run", "run-1", 10), 1_000)
        .unwrap();

    let before = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("run-1").unwrap(),
        )
        .unwrap()
        .unwrap();
    match storage.publish(&latest_envelope("agent-ide", "ide-1", 1), 2_000) {
        Err(CoreError::Fence(detail)) => {
            assert!(
                detail.contains("agent-run") && detail.contains("operator transition"),
                "unexpected refusal: {detail}"
            );
        }
        other => panic!("expected lineage fence, got {other:?}"),
    }

    // Nothing from the second producer was stored, and its event id stays
    // free for a scope it may own.
    assert!(
        storage
            .lookup(
                &PublisherId::new("agent-ide").unwrap(),
                &EventId::new("ide-1").unwrap()
            )
            .unwrap()
            .is_none()
    );
    // The owner's custody is untouched.
    let after = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("run-1").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(before, after);

    // keep_all and batch never claim or consult the lineage.
    let keep_all = Envelope::new(
        PublisherId::new("agent-ide").unwrap(),
        EventId::new("ide-keep").unwrap(),
        recipient(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::KeepAll,
        Payload::new("note").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap();
    let batch = Envelope::new(
        PublisherId::new("agent-ide").unwrap(),
        EventId::new("ide-batch").unwrap(),
        recipient(),
        Kind::new("diagnostics.view").unwrap(),
        Mode::Auto,
        Policy::Batch {
            group: "g".to_string(),
        },
        Payload::new("note").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap();
    assert!(storage.publish(&keep_all, 3_000).is_ok());
    assert!(storage.publish(&batch, 3_000).is_ok());
}

/// An audited operator transfer moves authority: the new owner publishes,
/// the old owner is fenced from further lineage publications, and
/// everything already accepted keeps its exact state.
#[test]
fn audited_transfer_moves_authority_and_fences_the_previous_owner() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&latest_envelope("agent-run", "run-a", 10), 1_000)
        .unwrap();
    // A second, older run snapshot still pending (its own watermark rule).
    storage
        .publish(&latest_envelope("agent-run", "run-b", 5), 1_100)
        .unwrap();

    let previous = storage
        .transfer_lineage(
            &bridge_core::recovery::LineageScope {
                recipient: recipient().to_canonical_string(),
                kind: "diagnostics.view".into(),
                mode: "auto".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "agent-ide",
            "owner-led handover after review",
            "bridge-ops",
            2_000,
        )
        .unwrap();
    assert_eq!(previous.as_deref(), Some("agent-run"));

    // The new owner publishes freely; its revisions are its own sequence.
    storage
        .publish(&latest_envelope("agent-ide", "ide-1", 1), 2_100)
        .unwrap();

    // The previous owner is fenced even at a fresh higher revision: no
    // late revival through a new admission.
    match storage.publish(&latest_envelope("agent-run", "run-late", 99), 2_200) {
        Err(CoreError::Fence(detail)) => {
            assert!(detail.contains("agent-ide"), "unexpected refusal: {detail}")
        }
        other => panic!("expected fence on previous owner, got {other:?}"),
    }

    // Already-accepted events keep their identity and dispositions; the
    // run-a snapshot is still pending with its original hash.
    let run_a = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("run-a").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(run_a.state, EventState::Pending);
    assert_eq!(
        run_a.envelope_hash,
        latest_envelope("agent-run", "run-a", 10).envelope_hash()
    );
    // run-b (older revision under run's own watermark) stays superseded —
    // the handover did not reset or re-evaluate anyone's watermark.
    let run_b = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("run-b").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(run_b.state, EventState::Superseded);

    // The new owner's own watermark governs its stream: a stale new-owner
    // revision is superseded, an equal revision conflicts.
    let stale = storage
        .publish(&latest_envelope("agent-ide", "ide-0", 0), 2_300)
        .unwrap();
    assert_eq!(stale.receipt.state, EventState::Superseded);
    // The supported declared signal is a new stream id: a different
    // lineage with its own claim and revisions.
    let mut fresh = latest_envelope("agent-run", "fresh-1", 1);
    fresh.policy = Policy::Latest {
        stream: StreamId::new("diag-2").unwrap(),
        revision: 1,
    };
    assert_eq!(
        storage.publish(&fresh, 3_000).unwrap().receipt.state,
        EventState::Pending
    );
    let mut equal = latest_envelope("agent-ide", "ide-eq", 1);
    equal.payload = Payload::new("{\"view\":\"changed\"}").unwrap();
    assert!(matches!(
        storage.publish(&equal, 2_400),
        Err(CoreError::Conflict { .. })
    ));
}

/// Lineage authority, both watermarks and the fence survive a restart,
/// and the new owner inherits neither the old watermark nor a reset.
#[test]
fn lineages_and_watermarks_survive_restart_without_inheritance_or_reset() {
    let dir = TempDir::new("lin-restart");
    let db = dir.path("bridge.db");
    {
        let mut storage = Storage::open(&db, Limits::new(100)).unwrap();
        storage
            .publish(&latest_envelope("agent-run", "run-1", 10), 1_000)
            .unwrap();
        storage
            .transfer_lineage(
                &bridge_core::recovery::LineageScope {
                    recipient: recipient().to_canonical_string(),
                    kind: "diagnostics.view".into(),
                    mode: "auto".into(),
                    project: String::new(),
                    task: String::new(),
                    stream: "diag".into(),
                },
                "agent-ide",
                "restart-safe handover",
                "bridge-ops",
                1_500,
            )
            .unwrap();
        // New owner at revision 1: pending (no inheritance of run's 10).
        let admitted = storage
            .publish(&latest_envelope("agent-ide", "ide-1", 1), 1_600)
            .unwrap();
        assert_eq!(admitted.receipt.state, EventState::Pending);
    }

    let mut reopened = Storage::open(&db, Limits::new(100)).unwrap();
    // The fence survived: the previous owner is still declined.
    assert!(matches!(
        reopened.publish(&latest_envelope("agent-run", "run-late", 11), 9_000),
        Err(CoreError::Fence(_))
    ));
    // The new owner's watermark survived: revision 0 is superseded after
    // restart, equal revision conflicts.
    let stale = reopened
        .publish(&latest_envelope("agent-ide", "ide-0", 0), 9_100)
        .unwrap();
    assert_eq!(stale.receipt.state, EventState::Superseded);
    let mut equal = latest_envelope("agent-ide", "ide-eq", 1);
    equal.payload = Payload::new("{\"view\":\"changed\"}").unwrap();
    assert!(matches!(
        reopened.publish(&equal, 9_200),
        Err(CoreError::Conflict { .. })
    ));
    // Custody and lineage replay identically.
    let replay = reopened
        .publish(&latest_envelope("agent-run", "run-1", 10), 9_300)
        .unwrap();
    assert!(replay.receipt.replayed);
}

/// Independent lineage scopes stay isolated: a different recipient,
/// project, task or stream never trips another lineage's fence.
#[test]
fn independent_lineage_scopes_stay_isolated() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&latest_envelope("agent-run", "run-1", 10), 1_000)
        .unwrap();

    // Different stream: free for the second producer.
    let mut other_stream = latest_envelope("agent-ide", "ide-stream", 1);
    if let Policy::Latest { stream, .. } = &mut other_stream.policy {
        *stream = StreamId::new("telemetry").unwrap();
    }
    assert!(storage.publish(&other_stream, 1_100).is_ok());

    // Different project scope: free.
    let mut other_project = latest_envelope("agent-ide", "ide-project", 1);
    other_project
        .metadata
        .insert("project".to_string(), "other".to_string());
    assert!(storage.publish(&other_project, 1_200).is_ok());

    // Different task scope: free.
    let mut other_task = latest_envelope("agent-ide", "ide-task", 1);
    other_task
        .metadata
        .insert("task".to_string(), "other".to_string());
    assert!(storage.publish(&other_task, 1_300).is_ok());

    // Different kind: a different coalescing domain entirely.
    let mut other_kind = latest_envelope("agent-ide", "ide-kind", 1);
    other_kind.kind = Kind::new("telemetry.view").unwrap();
    assert!(storage.publish(&other_kind, 1_400).is_ok());

    // Same lineage again: still fenced.
    assert!(matches!(
        storage.publish(&latest_envelope("agent-ide", "ide-same", 1), 1_500),
        Err(CoreError::Fence(_))
    ));
}

/// Only operator grants transfer lineage; publishers and unknown tokens
/// are refused, and the transfer is audited.
#[test]
fn lineage_transfer_rights_are_operator_only_and_audited() {
    let dir = TempDir::new("lin-wire");
    let config = config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = BridgeClient::connect(&socket).unwrap();
    client
        .publish(RUN_TOKEN, &latest_body("run-1", 10))
        .unwrap();

    // A publisher token cannot transfer.
    let error = client
        .transfer_lineage(
            RUN_TOKEN,
            &bridge_core::recovery::LineageScope {
                recipient: recipient().to_canonical_string(),
                kind: "diagnostics.view".into(),
                mode: "auto".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "agent-ide",
            "self-serving handover",
        )
        .unwrap_err();
    assert_eq!(error.class, "forbidden");

    // The operator transfers, and the second publisher takes over.
    client
        .transfer_lineage(
            OPS_TOKEN,
            &bridge_core::recovery::LineageScope {
                recipient: recipient().to_canonical_string(),
                kind: "diagnostics.view".into(),
                mode: "auto".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "agent-ide",
            "owner-led handover after review",
        )
        .unwrap();
    client.publish(IDE_TOKEN, &latest_body("ide-1", 1)).unwrap();

    // The first publisher is now fenced over the wire, before custody.
    let error = client
        .publish(RUN_TOKEN, &latest_body("run-late", 99))
        .unwrap_err();
    assert_eq!(error.class, "fence");
    running.with_storage(|storage| {
        assert!(
            storage
                .lookup(
                    &PublisherId::new("agent-run").unwrap(),
                    &EventId::new("run-late").unwrap()
                )
                .unwrap()
                .is_none(),
            "fenced publication must store nothing"
        );
        let transfers: Vec<_> = storage
            .audit_entries(10)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.action == "transfer_lineage")
            .collect();
        assert_eq!(
            transfers.len(),
            1,
            "the transfer must be audited exactly once"
        );
        assert_eq!(transfers[0].publisher_id, "agent-ide");
        assert!(
            transfers[0].detail.contains("agent-run"),
            "audit names the lineage change"
        );
    });

    running.shutdown();
    running.join();
}

/// Uncertain hand-offs keep their evidence across a transfer: the old
/// owner's invoking/unknown attempt is neither replayed nor rewritten.
#[test]
fn uncertain_attempts_survive_transfer_without_replay() {
    // The shared fixture store registers both publishers' source tags,
    // which dispatch requires before it will frame and reserve anything.
    let mut storage = common::store();
    // Message mode: eligible for the message-path selection below without
    // depending on lifecycle resolution (auto is covered elsewhere).
    let mut event = latest_envelope("agent-run", "run-unc", 10);
    event.mode = Mode::Message;
    storage.publish(&event, 1_000).unwrap();
    let attestation: Attestation = attest(&recipient(), Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_100,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("nothing to reserve");
    };
    assert_eq!(reserved.members[0].event_id, "run-unc");
    storage
        .mark_invoking(&reserved.fence, &attestation, 1_200)
        .unwrap();
    storage
        .record_outcome(
            &reserved.fence,
            Outcome::OutcomeUnknown {
                reason: "socket write may have landed".into(),
            },
            1_300,
        )
        .unwrap();

    let scope = bridge_core::recovery::LineageScope {
        recipient: recipient().to_canonical_string(),
        kind: "diagnostics.view".into(),
        mode: "message".into(),
        project: String::new(),
        task: String::new(),
        stream: "diag".into(),
    };
    // A possible native effect cannot be recalled: the handover is refused
    // and nothing changes until the operator resolves the unknown.
    assert!(matches!(
        storage.transfer_lineage(&scope, "agent-ide", "overtake unknown", "bridge-ops", 2_000),
        Err(CoreError::Fence(detail)) if detail.contains("run-unc")
    ));
    assert!(matches!(
        storage.publish(&message_envelope("agent-ide", "ide-early", 1), 2_050),
        Err(CoreError::Fence(_))
    ));
    let attempt = storage
        .latest_attempt("agent-run", "run-unc")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state.as_str(), "outcome_unknown");
    assert!(
        storage
            .open_incidents(2_000, 10)
            .unwrap()
            .iter()
            .any(|incident| incident.event_id == "run-unc")
    );
    // The event is still not redispatchable without audited authorization.
    match storage.reserve_next(
        &attestation,
        EffectiveMode::Message,
        2_100,
        &DispatchTiming::default(),
    ) {
        Ok(Selection::Idle) | Ok(Selection::Held(_)) => {}
        other => panic!("uncertain event must not be redispatched: {other:?}"),
    }

    // The supported audited disposition closes the unknown without
    // claiming delivery; the handover then proceeds and the retained
    // attempt evidence stays exactly as it was.
    storage
        .dispose_event(
            "agent-run",
            "run-unc",
            "bridge-ops",
            "operator verified the carrier and accepts the loss",
            2_200,
        )
        .unwrap();
    storage
        .transfer_lineage(
            &scope,
            "agent-ide",
            "handover after disposition",
            "bridge-ops",
            2_300,
        )
        .unwrap();
    let attempt = storage
        .latest_attempt("agent-run", "run-unc")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state.as_str(), "outcome_unknown");
}

/// An invoking attempt (a hand-off may be in flight) blocks the handover
/// exactly like an unresolved unknown.
#[test]
fn invoking_attempts_refuse_the_handover() {
    let mut storage = common::store();
    let mut event = latest_envelope("agent-run", "run-live", 10);
    event.mode = Mode::Message;
    storage.publish(&event, 1_000).unwrap();
    let attestation: Attestation = attest(&recipient(), Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_100,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("nothing to reserve");
    };
    storage
        .mark_invoking(&reserved.fence, &attestation, 1_200)
        .unwrap();
    let scope = bridge_core::recovery::LineageScope {
        recipient: recipient().to_canonical_string(),
        kind: "diagnostics.view".into(),
        mode: "message".into(),
        project: String::new(),
        task: String::new(),
        stream: "diag".into(),
    };
    assert!(matches!(
        storage.transfer_lineage(
            &scope,
            "agent-ide",
            "overtake invoking",
            "bridge-ops",
            1_300
        ),
        Err(CoreError::Fence(_))
    ));
    assert!(matches!(
        storage.publish(&message_envelope("agent-ide", "ide-1", 1), 1_400),
        Err(CoreError::Fence(_))
    ));
}

/// A reservation made BEFORE the transfer is fenced at invocation time:
/// the still-uninvoked attempt is released untouched and the event held.
#[test]
fn reserved_before_transfer_is_fenced_before_invocation() {
    let mut storage = common::store();
    let mut event = latest_envelope("agent-run", "run-res", 12);
    event.mode = Mode::Message;
    storage.publish(&event, 1_000).unwrap();
    let attestation: Attestation = attest(&recipient(), Lifecycle::Inactive, 1);
    let Selection::Attempt(reserved) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_100,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("nothing to reserve");
    };

    storage
        .transfer_lineage(
            &bridge_core::recovery::LineageScope {
                recipient: recipient().to_canonical_string(),
                kind: "diagnostics.view".into(),
                mode: "message".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "agent-ide",
            "handover while a reservation was outstanding",
            "bridge-ops",
            1_500,
        )
        .unwrap();

    // The reservation is still uninvoked: invoking it now is fenced and
    // released untouched (no hand-off, no replay).
    match storage.mark_invoking(&reserved.fence, &attestation, 1_600) {
        Ok(bridge_core::dispatch::Invoked::Released(reason)) => {
            assert!(reason.contains("lineage"), "unexpected release: {reason}")
        }
        other => panic!("expected release, got {other:?}"),
    }
    // The event is held visibly with a retained incident; its bytes and
    // hash are untouched.
    let row = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("run-res").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.envelope_hash, event.envelope_hash());
    assert!(
        storage
            .open_incidents(1_600, 10)
            .unwrap()
            .iter()
            .any(|incident| incident.event_id == "run-res"
                && incident.kind == "lineage_authority_lost")
    );
    // Restart does not replay it: selection skips held work.
    match storage.reserve_next(
        &attestation,
        EffectiveMode::Message,
        9_000,
        &DispatchTiming::default(),
    ) {
        Ok(Selection::Idle) | Ok(Selection::Held(_)) => {}
        other => panic!("held lineage event must not be selected: {other:?}"),
    }
}

/// Already-invoking, native-accepted and uncertain old-owner attempts are
/// never recalled or replayed by a transfer; keep_all is unaffected.
#[test]
fn possible_effects_and_keep_all_survive_transfer_untouched() {
    let mut storage = common::store();
    let keep = |event: &str| {
        Envelope::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new(event).unwrap(),
            recipient(),
            Kind::new("diagnostics.view").unwrap(),
            Mode::Message,
            Policy::KeepAll,
            Payload::new("note").unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap()
    };
    // Two keep_all events: the first is delivered before the handover, the
    // second stays unhanded and must keep flowing afterwards.
    storage.publish(&keep("run-keep-1"), 1_000).unwrap();
    let mut invoking_event = latest_envelope("agent-run", "run-inv", 12);
    invoking_event.mode = Mode::Message;
    storage.publish(&invoking_event, 1_000).unwrap();

    let attestation: Attestation = attest(&recipient(), Lifecycle::Inactive, 1);
    let drive = |storage: &mut Storage, expected: &str, at: u64| {
        let Selection::Attempt(reserved) = storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                at,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("nothing to reserve");
        };
        assert_eq!(reserved.members[0].event_id, expected);
        storage
            .mark_invoking(&reserved.fence, &attestation, at + 1)
            .unwrap();
        storage
            .record_outcome(
                &reserved.fence,
                Outcome::NativeAccepted {
                    evidence: format!("queue id for {expected}"),
                },
                at + 2,
            )
            .unwrap();
    };
    // keep_all wins the head selection by design, so it is delivered
    // first; the latest hand-off happens second and is accepted. The
    // still-unhanded keep_all is published only afterwards so it cannot
    // win this setup selection.
    drive(&mut storage, "run-keep-1", 1_050);
    drive(&mut storage, "run-inv", 1_100);
    storage.publish(&keep("run-keep-2"), 1_400).unwrap();

    storage
        .transfer_lineage(
            &bridge_core::recovery::LineageScope {
                recipient: recipient().to_canonical_string(),
                kind: "diagnostics.view".into(),
                mode: "message".into(),
                project: String::new(),
                task: String::new(),
                stream: "diag".into(),
            },
            "agent-ide",
            "handover after the old owner's accepted send",
            "bridge-ops",
            1_500,
        )
        .unwrap();

    // The accepted attempt and its evidence are untouched.
    let attempt = storage
        .latest_attempt("agent-run", "run-inv")
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state.as_str(), "native_accepted");
    // keep_all from the old owner is still dispatchable.
    let Selection::Attempt(next) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_600,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("keep_all must remain dispatchable");
    };
    assert_eq!(next.members[0].event_id, "run-keep-2");
}

/// Same-publisher lineage changes are an honestly unsupported condition:
/// a producer re-declaring a stream after its own reset cannot be
/// detected from durable evidence, and the docs say so.
#[test]
fn same_publisher_lineage_reset_is_documented_unsupported() {
    // Within one publisher, revisions are compared against that
    // publisher's own watermark: a lower revision after a reset is
    // superseded, never treated as a new lineage. There is no durable
    // signal distinguishing a reset from staleness, so core refuses to
    // guess; this pins the actual behavior.
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    storage
        .publish(&latest_envelope("agent-run", "hi-12", 12), 1_000)
        .unwrap();
    let stale = storage
        .publish(&latest_envelope("agent-run", "lo-1", 1), 2_000)
        .unwrap();
    assert_eq!(stale.receipt.state, EventState::Superseded);
}

/// TransferLineage scope fields are validated at the public boundary:
/// stream shape and project/task metadata rules, so separator, control or
/// oversized values cannot collide into another lineage.
#[test]
fn transfer_lineage_validates_scope_fields() {
    let mut storage = Storage::open_in_memory(Limits::new(100)).unwrap();
    let scope = |stream: &str, project: &str, task: &str| bridge_core::recovery::LineageScope {
        recipient: recipient().to_canonical_string(),
        kind: "diagnostics.view".into(),
        mode: "auto".into(),
        project: project.into(),
        task: task.into(),
        stream: stream.into(),
    };
    // A valid transfer passes.
    storage
        .transfer_lineage(
            &scope("diag", "", ""),
            "agent-ide",
            "note",
            "bridge-ops",
            1_000,
        )
        .unwrap();

    // StreamId's documented domain is non-empty, bounded and free of
    // control characters: a space is a legal stream id, while a control
    // byte (including the unit separator used inside lineage keys) is not.
    storage
        .transfer_lineage(&scope("bad stream", "", ""), "agent-ide", "n", "ops", 1_050)
        .unwrap();
    assert!(
        storage
            .transfer_lineage(
                &scope("bad\u{1f}stream", "", ""),
                "agent-ide",
                "n",
                "ops",
                1_100
            )
            .is_err()
    );
    assert!(
        storage
            .transfer_lineage(&scope("", "", ""), "agent-ide", "n", "ops", 1_100)
            .is_err()
    );
    // Control characters and oversized values in project/task refuse.
    assert!(
        storage
            .transfer_lineage(
                &scope("diag", "bad\u{1f}sep", ""),
                "agent-ide",
                "n",
                "ops",
                1_200
            )
            .is_err()
    );
    assert!(
        storage
            .transfer_lineage(
                &scope("diag", "", "bad\u{1}ctl"),
                "agent-ide",
                "n",
                "ops",
                1_300
            )
            .is_err()
    );
    let oversized = "x".repeat(257);
    assert!(
        storage
            .transfer_lineage(
                &scope("diag", &oversized, ""),
                "agent-ide",
                "n",
                "ops",
                1_400
            )
            .is_err()
    );
    // A non-canonical recipient refuses (cannot target a lineage through
    // a malformed address).
    let mut bad_recipient = scope("diag", "", "");
    bad_recipient.recipient = "host-1/codex".into();
    assert!(
        storage
            .transfer_lineage(&bad_recipient, "agent-ide", "n", "ops", 1_500)
            .is_err()
    );
    // Every remaining field is checked against its own domain contract.
    let with_kind = |kind: &str| {
        let mut variant = scope("diag", "", "");
        variant.kind = kind.to_string();
        variant
    };
    let mut unknown_mode = scope("diag", "", "");
    unknown_mode.mode = "AUTO".into();
    let variants = [
        (
            "oversized stream",
            scope(&"s".repeat(257), "", ""),
            "agent-ide",
        ),
        ("oversized task", scope("diag", "", &oversized), "agent-ide"),
        ("empty kind", with_kind(""), "agent-ide"),
        ("oversized kind", with_kind(&"k".repeat(65)), "agent-ide"),
        ("control kind", with_kind("kind\u{1f}x"), "agent-ide"),
        ("unknown mode", unknown_mode, "agent-ide"),
        ("control new owner", scope("diag", "", ""), "agent\u{1}ide"),
        ("empty new owner", scope("diag", "", ""), ""),
    ];
    for (label, variant, owner) in variants {
        assert!(
            storage
                .transfer_lineage(&variant, owner, "n", "ops", 1_600)
                .is_err(),
            "{label} must be refused"
        );
    }
    assert!(
        storage
            .transfer_lineage(
                &scope("diag", "", ""),
                "agent-ide",
                "bad\u{1}note",
                "ops",
                1_700
            )
            .is_err()
    );
    assert!(
        storage
            .transfer_lineage(&scope("diag", "", ""), "agent-ide", "n", "ops\nx", 1_700)
            .is_err()
    );
}

/// A recipient spelled differently but equal after canonicalization
/// addresses the same lineage: the transfer cannot be bypassed (or
/// misdirected) through percent-escape case.
#[test]
fn transfer_lineage_uses_the_canonical_recipient() {
    let mut storage = common::store();
    let slashed = NativeAddress::new("host-1", Harness::Codex, "default", "thread/7").unwrap();
    let mut event = latest_envelope("agent-run", "run-slash", 3);
    event.recipient = slashed.clone();
    storage.publish(&event, 1_000).unwrap();
    let lowercase = slashed.to_canonical_string().replace("%2F", "%2f");
    assert_ne!(lowercase, slashed.to_canonical_string());
    let scope = bridge_core::recovery::LineageScope {
        recipient: lowercase,
        kind: "diagnostics.view".into(),
        mode: "auto".into(),
        project: String::new(),
        task: String::new(),
        stream: "diag".into(),
    };
    assert_eq!(
        storage
            .transfer_lineage(&scope, "agent-ide", "canonical", "bridge-ops", 1_500)
            .unwrap()
            .as_deref(),
        Some("agent-run")
    );
    let mut stale = latest_envelope("agent-run", "run-slash-2", 4);
    stale.recipient = slashed;
    assert!(matches!(
        storage.publish(&stale, 2_000),
        Err(CoreError::Fence(_))
    ));
}

/// A closed old lineage incident cannot waive the fence for a new native
/// hold after an audited retry. All state is in memory; the synthetic
/// provider records no real native effect and no process is spawned.
#[test]
fn closed_lineage_incident_does_not_waive_a_new_native_hold() {
    let mut storage = common::store();
    let mut event = latest_envelope("agent-run", "run-history", 12);
    event.mode = Mode::Message;
    storage.publish(&event, 1_000).unwrap();
    let scope = bridge_core::recovery::LineageScope {
        recipient: recipient().to_canonical_string(),
        kind: "diagnostics.view".into(),
        mode: "message".into(),
        project: String::new(),
        task: String::new(),
        stream: "diag".into(),
    };
    storage
        .transfer_lineage(&scope, "agent-ide", "uninvoked transfer", "ops", 1_100)
        .unwrap();
    storage
        .transfer_lineage(&scope, "agent-run", "return authority", "ops", 1_200)
        .unwrap();
    storage
        .authorize_manual_retry("agent-run", "run-history", "ops", "retry held work", 1_300)
        .unwrap();
    let attestation = attest(&recipient(), Lifecycle::Inactive, 1);
    let Selection::Attempt(attempt) = storage
        .reserve_next(
            &attestation,
            EffectiveMode::Message,
            1_400,
            &DispatchTiming::default(),
        )
        .unwrap()
    else {
        panic!("nothing to reserve");
    };
    storage
        .mark_invoking(&attempt.fence, &attestation, 1_500)
        .unwrap();
    storage
        .record_outcome(
            &attempt.fence,
            Outcome::NativeHeld { recheck_ms: 16_000 },
            1_600,
        )
        .unwrap();
    assert!(matches!(
        storage.transfer_lineage(
            &scope,
            "agent-ide",
            "must not overtake new hold",
            "ops",
            1_700
        ),
        Err(CoreError::Fence(_))
    ));
    assert!(matches!(
        storage.publish(&message_envelope("agent-ide", "ide-history", 1), 1_800),
        Err(CoreError::Fence(_))
    ));
    assert_eq!(
        storage
            .latest_attempt("agent-run", "run-history")
            .unwrap()
            .unwrap()
            .state
            .as_str(),
        "native_held"
    );
}
