//! Regression checks for the audited trust-boundary findings F01, F02,
//! F07 and F08, exercising only the public API at the boundaries where the
//! faults were reproduced (canonical decode, direct deserialization,
//! storage admission), not just constructors.

mod common;

use bridge_core::{
    Envelope, EventId, ExpiresAt, Harness, Kind, Limits, MAX_SQLITE_INT, Metadata, Mode,
    NativeAddress, Payload, Policy, PublisherId, Storage, StreamId,
};

/// A latest-snapshot envelope in an independent publisher/recipient scope.
fn event(publisher: &str, recipient: &str, id: &str, revision: u64) -> Envelope {
    Envelope::new(
        PublisherId::new(publisher).unwrap(),
        EventId::new(id).unwrap(),
        NativeAddress::new("host", Harness::CODEX, "namespace", recipient).unwrap(),
        Kind::new("diagnostics").unwrap(),
        Mode::Inject,
        Policy::Latest {
            stream: StreamId::new("same-local-stream").unwrap(),
            revision,
        },
        Payload::new("synthetic view").unwrap(),
        Metadata::new(),
        None,
    )
    .unwrap()
}

/// F01: independent publishers/recipients with one shared stream name must
/// not inherit each other's watermark. Reproduced false Superseded at the
/// audited candidate.
#[test]
fn independent_publisher_recipient_streams_do_not_inherit_watermarks() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let first = store
        .publish(&event("publisher-a", "session-a", "event-a", 10), 1)
        .unwrap();
    let second = store
        .publish(&event("publisher-b", "session-b", "event-b", 1), 2)
        .unwrap();
    assert_eq!(
        first.receipt.state, second.receipt.state,
        "independent publisher/recipient must not inherit another scope's watermark"
    );
    assert_eq!(first.receipt.state, bridge_core::EventState::Pending);
}

/// F01: the declared coalescing dimensions (kind, project/task scope) also
/// isolate watermarks within one publisher/recipient/stream.
#[test]
fn coalescing_scope_dimensions_isolate_watermarks() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let base = event("publisher", "session", "high", 10);
    store.publish(&base, 1).unwrap();

    // Same stream, same publisher/recipient, different kind: independent.
    let mut other_kind = event("publisher", "session", "low-kind", 1);
    other_kind.kind = Kind::new("telemetry").unwrap();
    let admitted = store.publish(&other_kind, 2).unwrap();
    assert_eq!(admitted.receipt.state, bridge_core::EventState::Pending);

    // Same scope, different project metadata: independent.
    let mut other_project = event("publisher", "session", "low-project", 1);
    other_project
        .metadata
        .insert("project".into(), "other".into());
    let admitted = store.publish(&other_project, 3).unwrap();
    assert_eq!(admitted.receipt.state, bridge_core::EventState::Pending);

    // Truly same scope, lower revision: explicit superseded (correct).
    let stale = store
        .publish(&event("publisher", "session", "low-same", 1), 4)
        .unwrap();
    assert_eq!(stale.receipt.state, bridge_core::EventState::Superseded);
}

/// F02: each untrusted serialized component passes the same validation as
/// construction, through canonical decode AND raw deserialization.
#[test]
fn serialized_components_are_revalidated() {
    let baseline = serde_json::to_value(event("publisher", "recipient", "event", 1)).unwrap();
    let invalid = [
        ("event_id", serde_json::json!("")),
        ("publisher", serde_json::json!("")),
        ("kind", serde_json::json!("k".repeat(65))),
        ("payload", serde_json::json!("p".repeat(65537))),
        ("expires_at", serde_json::json!(0)),
    ];
    let mut admitted = Vec::new();
    for (field, value) in invalid {
        let mut malformed = baseline.clone();
        malformed[field] = value;
        if Envelope::from_canonical_bytes(&serde_json::to_vec(&malformed).unwrap()).is_ok() {
            admitted.push(field);
        }
        // Raw deserialization must not smuggle the same value past storage.
        if let Ok(envelope) = serde_json::from_value::<Envelope>(malformed) {
            let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
            if store.publish(&envelope, 1).is_ok() {
                admitted.push(field);
            }
        }
    }
    assert!(
        admitted.is_empty(),
        "invalid serialized fields admitted: {admitted:?}"
    );
}

/// F07: accepted path namespaces survive their canonical address round
/// trip.
#[test]
fn native_path_namespace_roundtrips() {
    let address =
        NativeAddress::new("host", Harness::CODEX, "/synthetic/native/store", "session").unwrap();
    assert_eq!(
        NativeAddress::parse(&address.to_canonical_string()).unwrap(),
        address
    );
}

/// F07: distinct component tuples have distinct canonical text identities.
#[test]
fn native_component_boundaries_are_lossless() {
    let left = NativeAddress::new("host", Harness::CODEX, "a/b", "c").unwrap();
    let right = NativeAddress::new("host", Harness::CODEX, "a", "b/c").unwrap();
    assert_ne!(
        left.to_canonical_string(),
        right.to_canonical_string(),
        "slash concatenation must not be lossy"
    );
    // Percent signs themselves must not corrupt round trips.
    let tricky = NativeAddress::new("host", Harness::CODEX, "a%2Fb", "c%25").unwrap();
    assert_eq!(
        NativeAddress::parse(&tricky.to_canonical_string()).unwrap(),
        tricky
    );
    // Malformed escapes are refused, not defaulted.
    assert!(NativeAddress::parse("host/codex/na%2/x").is_err());
    assert!(NativeAddress::parse("host/codex/ok/x/extra").is_err());
}

/// F08: out-of-range revision values are refused at construction, at
/// canonical decode and at raw deserialization; 1<<63 must never wrap into
/// apparent staleness, and the boundary value itself stays admissible.
#[test]
fn unsigned_revision_never_wraps_to_stale() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    store
        .publish(&event("publisher", "recipient", "first", 1), 1)
        .unwrap();
    let mut oversized = event("publisher", "recipient", "second", 1);
    oversized.policy = Policy::Latest {
        stream: StreamId::new("same-local-stream").unwrap(),
        revision: 1 << 63,
    };
    assert!(
        oversized.validate().is_err(),
        "a revision above the SQLite-safe bound is refused"
    );
    assert!(
        store.publish(&oversized, 2).is_err(),
        "and never reaches the signed cast"
    );
    // The same value is refused when it arrives as bytes.
    let mut value = serde_json::to_value(event("publisher", "recipient", "third", 1)).unwrap();
    value["policy"]["Latest"]["revision"] = serde_json::json!(1u64 << 63);
    assert!(serde_json::from_value::<Envelope>(value.clone()).is_err());
    assert!(Envelope::from_canonical_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    // The boundary value itself stays admissible as a newer revision.
    let admitted = store
        .publish(&event("publisher", "recipient", "edge", MAX_SQLITE_INT), 4)
        .unwrap();
    assert_eq!(admitted.receipt.state, bridge_core::EventState::Pending);
}

/// F08: expiry above the SQLite-safe bound is refused before any cast, at
/// construction and at deserialization; the boundary value keeps ordering.
#[test]
fn expiry_bound_is_enforced_before_cast() {
    assert!(ExpiresAt::from_unix_millis(1 << 63).is_err());
    assert!(ExpiresAt::from_unix_millis(0).is_err());
    assert!(serde_json::from_value::<ExpiresAt>(serde_json::json!(1u64 << 63)).is_err());
    assert!(serde_json::from_value::<ExpiresAt>(serde_json::json!(0)).is_err());
    let mut envelope = event("publisher", "recipient", "expiry-bound", 1);
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    envelope.expires_at = Some(ExpiresAt::from_unix_millis(MAX_SQLITE_INT).unwrap());
    assert!(store.publish(&envelope, 1).is_ok());
}

/// Deserialized receipts, hashes, addresses and delivery evidence pass the
/// same validation as their constructors: no field range or shape is
/// trusted because it arrived over a socket or from a file.
#[test]
fn deserialized_status_and_receipts_are_revalidated() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    let good = serde_json::to_value(
        store
            .publish(&event("publisher", "recipient", "receipt", 1), 5)
            .unwrap()
            .receipt,
    )
    .unwrap();
    assert!(serde_json::from_value::<bridge_core::CustodyReceipt>(good.clone()).is_ok());
    for (field, value) in [
        ("acceptance_seq", serde_json::json!(0)),
        ("acceptance_seq", serde_json::json!(1u64 << 63)),
        ("accepted_at_ms", serde_json::json!(1u64 << 63)),
        ("envelope_hash", serde_json::json!("not-a-hash")),
        ("envelope_hash", serde_json::json!("A".repeat(64))),
        ("publisher", serde_json::json!("")),
        ("event_id", serde_json::json!("bad\u{1}id")),
        ("state", serde_json::json!("delivered")),
    ] {
        let mut malformed = good.clone();
        malformed[field] = value;
        assert!(
            serde_json::from_value::<bridge_core::CustodyReceipt>(malformed).is_err(),
            "receipt field {field} must be revalidated"
        );
    }
    // Addresses cannot skip the component rules either.
    assert!(
        serde_json::from_value::<NativeAddress>(serde_json::json!({
            "host_id": "", "harness": "Codex",
            "native_store_namespace": "n", "native_session_id": "s"
        }))
        .is_err()
    );
    // Delivery evidence accepts only known names and bounded lists.
    let evidence = serde_json::json!({
        "attempt_state": "native_accepted", "effective_mode": "message", "note": null
    });
    assert!(serde_json::from_value::<bridge_core::DeliveryEvidence>(evidence).is_ok());
    for malformed in [
        serde_json::json!({"attempt_state": "delivered", "effective_mode": "message", "note": null}),
        serde_json::json!({"attempt_state": "none", "effective_mode": "teleport", "note": null}),
        serde_json::json!({"attempt_state": "none", "effective_mode": "none", "note": null,
            "delivery": "teleported"}),
    ] {
        assert!(serde_json::from_value::<bridge_core::DeliveryEvidence>(malformed).is_err());
    }
}
