//! Peer-consumption surface checks requested by the interfaces Module
//! (M-006): the conditional receipt-token tier's actual scope, operator
//! counts for routine losses, and trusted issuer provenance in framing.
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

/// The recipient every grant may use.
fn recipient() -> NativeAddress {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7").unwrap()
}

/// A config with one publisher grant and one operator grant.
fn config(dir: &TempDir) -> Config {
    Config {
        database: dir.path("bridge.db"),
        socket: short_socket("peer"),
        limits: Limits::new(1_000),
        grants: vec![
            GrantConfig {
                token: RUN_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: vec![recipient().to_canonical_string()],
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".into(), "auto".into()],
                policies: vec!["keep_all".into()],
                admin: false,
            },
            GrantConfig {
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

/// Drives one event's message attempt to a held outcome through the
/// service's own store, as an embedded adapter would.
fn drive_to_held(running: &service::Running, event: &str, now: u64) -> u64 {
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
            panic!("nothing to reserve for {event}")
        };
        assert_eq!(reserved.members[0].event_id, event);
        storage
            .mark_invoking(&reserved.fence, &attestation, now + 1)
            .unwrap();
        storage
            .record_outcome(
                &reserved.fence,
                Outcome::NativeHeld {
                    recheck_ms: now + 60_000,
                },
                now + 2,
            )
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
