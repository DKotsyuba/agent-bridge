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
        NativeAddress::new("host", Harness::Codex, "namespace", recipient).unwrap(),
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
        NativeAddress::new("host", Harness::Codex, "/synthetic/native/store", "session").unwrap();
    assert_eq!(
        NativeAddress::parse(&address.to_canonical_string()).unwrap(),
        address
    );
}

/// F07: distinct component tuples have distinct canonical text identities.
#[test]
fn native_component_boundaries_are_lossless() {
    let left = NativeAddress::new("host", Harness::Codex, "a/b", "c").unwrap();
    let right = NativeAddress::new("host", Harness::Codex, "a", "b/c").unwrap();
    assert_ne!(
        left.to_canonical_string(),
        right.to_canonical_string(),
        "slash concatenation must not be lossy"
    );
    // Percent signs themselves must not corrupt round trips.
    let tricky = NativeAddress::new("host", Harness::Codex, "a%2Fb", "c%25").unwrap();
    assert_eq!(
        NativeAddress::parse(&tricky.to_canonical_string()).unwrap(),
        tricky
    );
    // Malformed escapes are refused, not defaulted.
    assert!(NativeAddress::parse("host/codex/na%2/x").is_err());
    assert!(NativeAddress::parse("host/codex/ok/x/extra").is_err());
}

/// F08: out-of-range revision values are refused (or would need unsigned
/// ordering); 1<<63 must never wrap into apparent staleness.
#[test]
fn unsigned_revision_never_wraps_to_stale() {
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    store
        .publish(&event("publisher", "recipient", "first", 1), 1)
        .unwrap();
    // Either outcome is compliant: explicit refusal at the cast bound, or
    // acceptance-as-newer; silently stale or wrapped is not.
    if let Ok(second) = store.publish(&event("publisher", "recipient", "second", 1 << 63), 2) {
        assert_eq!(
            second.receipt.state,
            bridge_core::EventState::Pending,
            "accepted newer revision wrapped to stale"
        );
    }
    // The bound is explicit at the admission edge, and the boundary value
    // itself stays admissible as a newer revision.
    assert!(
        store
            .publish(&event("publisher", "recipient", "bounded", 1 << 63), 3)
            .is_err(),
        "revision above the SQLite-safe bound must be refused before the cast"
    );
    let admitted = store
        .publish(&event("publisher", "recipient", "edge", MAX_SQLITE_INT), 4)
        .unwrap();
    assert_eq!(admitted.receipt.state, bridge_core::EventState::Pending);
}

/// F08: expiry above the SQLite-safe bound is refused before any cast.
#[test]
fn expiry_bound_is_enforced_before_cast() {
    // Construction keeps unbounded u64; admission refuses above the bound.
    let oversized = ExpiresAt::from_unix_millis(1 << 63).unwrap();
    assert_eq!(oversized.unix_millis(), 1 << 63);
    let mut envelope = event("publisher", "recipient", "expiry-bound", 1);
    envelope.expires_at = Some(oversized);
    let mut store = Storage::open_in_memory(Limits::new(10)).unwrap();
    assert!(
        store.publish(&envelope, 1).is_err(),
        "oversized expiry must be refused at admission"
    );
    // At the boundary value, ordering stays correct.
    envelope.expires_at = Some(ExpiresAt::from_unix_millis(MAX_SQLITE_INT).unwrap());
    assert!(store.publish(&envelope, 1).is_ok());
}
