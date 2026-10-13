//! Peer-consumption surface checks: the conditional receipt-token tier's actual
//! scope, operator counts, stable incident pages, exact retention facts, and
//! trusted issuer
//! provenance. Revision-2 reads are exercised through the public typed client.
//!
//! All state is isolated synthetic fixtures; no real session, adapter or
//! credential is touched.

mod common;

use std::time::Duration;

use bridge_client::{BridgeClient, EvidenceTier};
use bridge_core::dispatch::{
    Attestation, DispatchTiming, EffectiveMode, Lifecycle, Outcome, Selection,
};
use bridge_core::framing::frame;
use bridge_core::service::{self, Config, GrantConfig, PublishBody};
use bridge_core::types::{Envelope, EventId, Kind, Metadata, Payload, PublisherId};
use bridge_core::{Harness, Limits, Mode, NativeAddress, Policy};
use common::{TempDir, attest, short_socket, wait_listening};

/// Fixture publisher token.
const RUN_TOKEN: &str = "peer-run-publisher-token-0001";
/// Fixture operator token.
const OPS_TOKEN: &str = "peer-operator-token-0000003";
/// Isolated ordinary root-backend grant; never an operator credential.
const ROOT_TOKEN: &str = "peer-root-backend-token-0004";

/// The recipient every grant may use.
fn recipient() -> NativeAddress {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7").unwrap()
}

/// An isolated file store/socket with publisher, root-backend and operator grants.
///
/// The publisher may produce latest snapshots; the root backend is keep-all only.
/// Neither non-operator realm may read operator pages or retained foreign facts.
fn config(dir: &TempDir) -> Config {
    Config {
        universal_limits: bridge_core::UniversalLimits::default(),
        database: dir.path("bridge.db"),
        socket: short_socket("peer"),
        limits: Limits::new(1_000),
        grants: vec![
            GrantConfig {
                producer_v1: None,
                token: RUN_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: vec![recipient().to_canonical_string()],
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".into(), "auto".into()],
                policies: vec!["keep_all".into(), "latest".into()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: ROOT_TOKEN.to_string(),
                publisher: "bridge-root".into(),
                recipients: vec![recipient().to_canonical_string()],
                kinds: vec!["worker.completed".into()],
                modes: vec!["message".into()],
                policies: vec!["keep_all".into()],
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

/// A valid publish body.
fn body(event: &str) -> PublishBody {
    PublishBody {
        event_id: event.to_string(),
        recipient: recipient(),
        kind: "worker.completed".to_string(),
        mode: Mode::Message,
        policy: Policy::KeepAll,
        payload: "synthetic result".to_string(),
        metadata: Default::default(),
        expires_at: None,
    }
}

/// A minimal envelope mirroring the published body, for framing checks.
fn envelope(event: &str, metadata: Metadata) -> Envelope {
    Envelope::new(
        PublisherId::new("agent-run").unwrap(),
        EventId::new(event).unwrap(),
        recipient(),
        Kind::new("worker.completed").unwrap(),
        Mode::Message,
        Policy::KeepAll,
        Payload::new("synthetic result").unwrap(),
        metadata,
        None,
    )
    .unwrap()
}

/// Starts a service and waits until it listens.
fn started(config: Config) -> service::Running {
    let running = service::start(config).unwrap();
    assert!(wait_listening(
        running.socket_path(),
        Duration::from_secs(5)
    ));
    running
}

/// Drives one already-published message to a synthetic native hold at `now`.
/// Uses the owned service store and returns its durable attempt number.
fn drive_to_held(running: &service::Running, event: &str, now: u64) -> u64 {
    drive_outcome(
        running,
        event,
        now,
        Outcome::NativeHeld {
            recheck_ms: now + 60_000,
        },
    )
}

/// Drives the next fixture event through reservation/invocation to `outcome`.
///
/// The exact `event` must be next eligible; `now` pins Unix milliseconds.
/// Only the isolated service store changes; no actual carrier is invoked.
/// Returns the attempt number and panics on an unexpected event/state.
fn drive_outcome(running: &service::Running, event: &str, now: u64, outcome: Outcome) -> u64 {
    running.with_storage(|storage| {
        let attestation: Attestation = attest(&recipient(), Lifecycle::Inactive, 1);
        let Selection::Attempt(reserved) = storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("nothing to reserve for {event}");
        };
        assert_eq!(reserved.members[0].event_id, event);
        storage
            .mark_invoking(&reserved.fence, &attestation, now + 1)
            .unwrap();
        storage
            .record_outcome(&reserved.fence, outcome, now + 2)
            .unwrap();
        reserved.fence.attempt_seq
    })
}

/// Scope basis: no producer contract in the current standalone delivery
/// predeclares a receipt tier, so receipt-token possession is a review
/// annotation only — it never settles an attempt, closes an incident,
/// releases dependents, or appears anywhere a recipient could echo it.
#[test]
fn receipt_token_possession_is_annotation_only_without_predeclared_contract() {
    let dir = TempDir::new("peer-ack");
    let running = started(config(&dir));
    let socket = running.socket_path().to_path_buf();

    let mut client = BridgeClient::connect(&socket).unwrap();
    client.publish(RUN_TOKEN, &body("evt-held")).unwrap();
    let attempt_seq = drive_to_held(&running, "evt-held", 1_000);

    // An operator records token possession as late evidence.
    client
        .record_evidence(
            OPS_TOKEN,
            "agent-run",
            "evt-held",
            attempt_seq,
            EvidenceTier::ReceiptTokenPossession,
            "token seen in rendered recipient output",
        )
        .unwrap();

    // The attempt stays held; nothing was settled, released or closed.
    running.with_storage(|storage| {
        let attempt = storage
            .latest_attempt("agent-run", "evt-held")
            .unwrap()
            .expect("attempt exists");
        assert_eq!(
            attempt.state.as_str(),
            "native_held",
            "annotation must not settle a held attempt"
        );
        let held = storage
            .count_delivery(bridge_core::recovery::DeliveryState::Held)
            .unwrap();
        assert_eq!(held, 1, "event must still be in the held tier");
    });

    // No token is issued or rendered anywhere: framing carries no token
    // material and receipts expose no token field.
    let framed = frame("agent-run", &envelope("evt-held", Metadata::new())).unwrap();
    assert!(!framed.to_lowercase().contains("token"));
    let receipt_json = serde_json::to_value(
        client
            .status(RUN_TOKEN, "evt-held")
            .unwrap()
            .0
            .expect("custody receipt exists"),
    )
    .unwrap();
    assert!(
        !receipt_json.to_string().to_lowercase().contains("token"),
        "receipts must not carry token material: {receipt_json}"
    );

    running.shutdown();
    running.join();
}

/// Operator counts: routine losses (held, review) and open incidents are
/// countable through the protected protocol without enumerating payloads;
/// publisher grants are refused.
#[test]
fn operator_counts_expose_routine_losses_without_enumeration() {
    let dir = TempDir::new("peer-counts");
    let running = started(config(&dir));
    let socket = running.socket_path().to_path_buf();

    let mut client = BridgeClient::connect(&socket).unwrap();
    client.publish(RUN_TOKEN, &body("evt-a")).unwrap();
    client.publish(RUN_TOKEN, &body("evt-b")).unwrap();
    drive_to_held(&running, "evt-a", 1_000);

    let counts = client.counts(OPS_TOKEN).unwrap();
    assert_eq!(counts.unhanded, 1, "evt-b is still unhanded");
    assert_eq!(counts.held, 1, "evt-a is held (routine loss tier)");
    // Held alone is a routine tier, not an incident: the counts view is
    // exactly what keeps it visible without burying it under alarms.
    assert_eq!(counts.open_incidents, 0);

    // Publisher grants cannot read counts.
    let error = client.counts(RUN_TOKEN).unwrap_err();
    assert_eq!(error.class, "forbidden");

    running.shutdown();
    running.join();
}

/// Real Core/public client pages reach incident 201 behind a full first page.
///
/// Pinned future time and owned state exercise auth-before-cursor validation,
/// stable high-water traversal across insertion/closure, open/all filters,
/// final/reset semantics, zero/large limit clamps and unchanged legacy bounds.
#[test]
fn operator_incident_pages_reach_backlog_and_validate_scan_bounds() {
    let dir = TempDir::new("peer-pages");
    let running = started(config(&dir));
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    let now = service::current_unix_millis() + 1_000_000;
    let empty = client
        .incidents_page(OPS_TOKEN, true, Some(0), 0, None)
        .unwrap();
    assert!(empty.incidents.is_empty());
    assert_eq!(empty.through_seq, 0);
    assert_eq!(empty.next_after_seq, None);
    for (token, class) in [
        (RUN_TOKEN, "forbidden"),
        (ROOT_TOKEN, "forbidden"),
        ("wrong-token", "auth"),
    ] {
        assert_eq!(
            client
                .incidents_page(token, true, None, u64::MAX, None)
                .unwrap_err()
                .class,
            class
        );
    }
    for index in 1..=201 {
        let event = format!("page-{index}");
        client.publish(RUN_TOKEN, &body(&event)).unwrap();
        drive_outcome(
            &running,
            &event,
            now,
            Outcome::OutcomeUnknown {
                reason: "fixture unknown".into(),
            },
        );
    }
    assert_eq!(
        client.incidents(OPS_TOKEN, false, Some(999)).unwrap().len(),
        200
    );
    let first = client
        .incidents_page(OPS_TOKEN, true, Some(999), 0, None)
        .unwrap();
    assert_eq!(first.incidents.len(), 200);
    assert_eq!(first.through_seq, 201);
    assert_eq!(first.next_after_seq, Some(200));
    assert_eq!(
        first
            .incidents
            .iter()
            .map(|row| row.incident_seq)
            .collect::<Vec<_>>(),
        (1..=200).collect::<Vec<_>>()
    );

    let omitted = client
        .incidents_page(OPS_TOKEN, true, Some(200), 200, Some(201))
        .unwrap();
    assert_eq!(omitted.incidents.len(), 1);
    assert_eq!(omitted.incidents[0].incident_seq, 201);
    assert_eq!(
        omitted.incidents[0].state,
        bridge_core::recovery::IncidentState::Open
    );
    let default_page = client
        .incidents_page(OPS_TOKEN, true, None, 0, None)
        .unwrap();
    assert_eq!(default_page.incidents.len(), 100);
    assert_eq!(default_page.next_after_seq, Some(100));
    for (token, class) in [
        (RUN_TOKEN, "forbidden"),
        (ROOT_TOKEN, "forbidden"),
        ("wrong-token", "auth"),
    ] {
        assert_eq!(
            client
                .incidents_page(token, true, None, 0, None)
                .unwrap_err()
                .class,
            class
        );
    }
    // Close the omitted row, then add a new one: neither can change scan bounds.
    client
        .dispose(OPS_TOKEN, "agent-run", "page-201", "fixture disposition")
        .unwrap();
    client.publish(RUN_TOKEN, &body("page-202")).unwrap();
    drive_outcome(
        &running,
        "page-202",
        now,
        Outcome::OutcomeUnknown {
            reason: "fixture new row".into(),
        },
    );
    let tail = client
        .incidents_page(OPS_TOKEN, true, Some(200), 200, Some(first.through_seq))
        .unwrap();
    assert_eq!(tail.incidents.len(), 1);
    assert_eq!(tail.incidents[0].incident_seq, 201);
    assert_eq!(
        tail.incidents[0].state,
        bridge_core::recovery::IncidentState::Disposed
    );
    assert_eq!(tail.next_after_seq, None);
    let open_tail = client
        .incidents_page(OPS_TOKEN, false, None, 200, Some(201))
        .unwrap();
    assert!(open_tail.incidents.is_empty());
    assert_eq!(open_tail.next_after_seq, None);
    let reset = client
        .incidents_page(OPS_TOKEN, true, Some(200), 0, None)
        .unwrap();
    assert_eq!(reset.through_seq, 202);
    let reset_tail = client
        .incidents_page(OPS_TOKEN, true, Some(200), 200, Some(202))
        .unwrap();
    assert_eq!(
        reset_tail
            .incidents
            .iter()
            .map(|row| row.incident_seq)
            .collect::<Vec<_>>(),
        vec![201, 202]
    );
    assert_eq!(
        client
            .incidents_page(OPS_TOKEN, true, Some(0), 0, None)
            .unwrap()
            .incidents
            .len(),
        1
    );
    for (after, through) in [
        (1, None),
        (203, Some(202)),
        (0, Some(203)),
        (u64::MAX, Some(202)),
        (0, Some(u64::MAX)),
    ] {
        assert_eq!(
            client
                .incidents_page(OPS_TOKEN, true, None, after, through)
                .unwrap_err()
                .class,
            "invalid"
        );
    }
    assert_eq!(client.counts(OPS_TOKEN).unwrap().open_incidents, 201);
    running.shutdown();
    running.join();
}

/// Exact public retention facts preserve protected payloads and dedup history.
///
/// Synthetic accepted/unknown attempts keep bytes past expiry and compaction.
/// Terminal unhanded rows alone become tombstones; scoped watermarks and frozen
/// replay identities survive collection/restart, without payload disclosure.
#[test]
fn operator_retention_shows_terminal_gc_without_recalling_native_effects() {
    let dir = TempDir::new("peer-retention");
    let configuration = config(&dir);
    let running = started(configuration.clone());
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    let now = service::current_unix_millis() + 1_000_000;
    assert!(
        client
            .retention(OPS_TOKEN, "agent-run", "absent")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client.retention(OPS_TOKEN, "", "").unwrap_err().class,
        "invalid"
    );
    for (token, class) in [
        (RUN_TOKEN, "forbidden"),
        (ROOT_TOKEN, "forbidden"),
        ("wrong-token", "auth"),
    ] {
        assert_eq!(client.retention(token, "", "").unwrap_err().class, class);
    }
    for (event, outcome) in [
        (
            "unknown",
            Outcome::OutcomeUnknown {
                reason: "fixture unknown".into(),
            },
        ),
        (
            "accepted",
            Outcome::NativeAccepted {
                evidence: "fixture queue acceptance".into(),
            },
        ),
    ] {
        let mut request = body(event);
        request.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(now + 100).unwrap());
        client.publish(RUN_TOKEN, &request).unwrap();
        drive_outcome(&running, event, now, outcome);
    }
    let mut expiring = body("expired");
    expiring.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(now + 100).unwrap());
    client.publish(RUN_TOKEN, &expiring).unwrap();
    let mut old = body("latest-old");
    old.policy = Policy::Latest {
        stream: bridge_core::StreamId::new("fixture-stream").unwrap(),
        revision: 11,
    };
    old.metadata.insert("project".into(), "project-a".into());
    old.metadata.insert("task".into(), "task-a".into());
    let original = client.publish(RUN_TOKEN, &old).unwrap();
    let mut newest = old.clone();
    newest.event_id = "latest-new".into();
    newest.policy = Policy::Latest {
        stream: bridge_core::StreamId::new("fixture-stream").unwrap(),
        revision: 12,
    };
    newest.expires_at = Some(bridge_core::ExpiresAt::from_unix_millis(now + 100).unwrap());
    client.publish(RUN_TOKEN, &newest).unwrap();
    let mut foreign = old.clone();
    foreign.event_id = "other-scope".into();
    foreign.policy = Policy::Latest {
        stream: bridge_core::StreamId::new("fixture-stream").unwrap(),
        revision: 50,
    };
    foreign
        .metadata
        .insert("project".into(), "project-b".into());
    client.publish(RUN_TOKEN, &foreign).unwrap();
    running.with_storage(|storage| assert_eq!(storage.expire_due(now + 200).unwrap(), 2));
    let counts_before = client.counts(OPS_TOKEN).unwrap();
    let expired = client
        .retention(OPS_TOKEN, "agent-run", "expired")
        .unwrap()
        .unwrap();
    assert_eq!(expired.receipt.state, bridge_core::EventState::Expired);
    assert_eq!(expired.expires_at_ms, Some(now + 100));
    assert!(expired.gc_eligible && !expired.payload_compacted);
    for (token, class) in [
        (RUN_TOKEN, "forbidden"),
        (ROOT_TOKEN, "forbidden"),
        ("wrong-token", "auth"),
    ] {
        assert_eq!(
            client
                .retention(token, "agent-run", "expired")
                .unwrap_err()
                .class,
            class
        );
    }
    let before = client
        .retention(OPS_TOKEN, "agent-run", "latest-old")
        .unwrap()
        .unwrap();
    assert_eq!(before.receipt.state, bridge_core::EventState::Superseded);
    assert_eq!(before.latest_watermark, Some(12));
    assert!(before.gc_eligible && before.envelope_bytes > 0);
    assert_eq!(
        client
            .retention(OPS_TOKEN, "agent-run", "other-scope")
            .unwrap()
            .unwrap()
            .latest_watermark,
        Some(50)
    );
    assert_eq!(client.counts(OPS_TOKEN).unwrap(), counts_before);
    running.with_storage(|storage| assert_eq!(storage.compact_payloads(0).unwrap(), 3));
    let tombstone = client
        .retention(OPS_TOKEN, "agent-run", "latest-old")
        .unwrap()
        .unwrap();
    assert!(tombstone.payload_compacted && !tombstone.gc_eligible);
    assert_eq!(tombstone.envelope_bytes, 0);
    assert_eq!(tombstone.latest_watermark, Some(12));
    assert_eq!(tombstone.receipt.envelope_hash, original.envelope_hash);
    let json = serde_json::to_string(&tombstone).unwrap();
    assert!(
        !json.contains("synthetic result")
            && !json.contains(RUN_TOKEN)
            && !json.contains(OPS_TOKEN)
    );
    for (event, state) in [
        ("unknown", bridge_core::recovery::DeliveryState::Review),
        ("accepted", bridge_core::recovery::DeliveryState::Accepted),
    ] {
        let protected = client
            .retention(OPS_TOKEN, "agent-run", event)
            .unwrap()
            .unwrap();
        assert!(
            protected.envelope_bytes > 0 && !protected.payload_compacted && !protected.gc_eligible
        );
        assert_eq!(protected.expires_at_ms, Some(now + 100));
        assert_eq!(protected.receipt.state, bridge_core::EventState::Pending);
        assert_eq!(protected.delivery.unwrap().delivery, state);
    }
    let replay = client.publish(RUN_TOKEN, &old).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.acceptance_seq, original.acceptance_seq);
    let mut changed = old.clone();
    changed.payload = "changed".into();
    assert_eq!(
        client.publish(RUN_TOKEN, &changed).unwrap_err().class,
        "conflict"
    );
    running.shutdown();
    running.join();
    let restarted = started(configuration);
    let mut client = BridgeClient::connect(restarted.socket_path()).unwrap();
    assert_eq!(
        client
            .retention(OPS_TOKEN, "agent-run", "latest-old")
            .unwrap()
            .unwrap(),
        tombstone
    );
    assert!(client.publish(RUN_TOKEN, &old).unwrap().replayed);
    assert_eq!(client.counts(OPS_TOKEN).unwrap().review, 1);
    assert_eq!(client.counts(OPS_TOKEN).unwrap().accepted, 1);
    restarted.shutdown();
    restarted.join();
}

/// Framing provenance: the rendered `source` is the Bridge-stamped
/// publisher identity; caller metadata can never forge or replace it.
#[test]
fn framing_renders_trusted_issuer_provenance_only() {
    let mut metadata = Metadata::new();
    metadata.insert("sender_harness".to_string(), "claude-code".into());
    metadata.insert("sender_session".to_string(), "session-forged".into());
    metadata.insert("source".to_string(), "root-orchestrator".into());
    let framed = frame("agent-run", &envelope("evt-prov", metadata)).unwrap();

    assert!(
        framed.contains("source=\"agent-run\""),
        "stamped issuer must be rendered: {framed}"
    );
    assert!(
        !framed.contains("session-forged"),
        "metadata must never be rendered as provenance: {framed}"
    );
    assert!(
        !framed.contains("root-orchestrator"),
        "a metadata 'source' key must not override the stamped issuer: {framed}"
    );
    assert!(!framed.contains("sender_harness"));
}
