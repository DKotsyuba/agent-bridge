//! Strict read-only native observation/resolution wire boundaries.
use bridge_protocol::*;
use serde_json::json;

/// A bounded synthetic expected tuple; never reads a real process or store.
fn resolution() -> ResolveRecipientParams {
    ResolveRecipientParams {
        host: Host::ClaudeCode,
        native_session_id: "session/one".into(),
        expected_store: "/private/synthetic-store".into(),
        expected_harness_pid: 23,
        expected_harness_start_time_secs: 42,
    }
}

/// Request ranges, strict fields, canonical response identity and read error
/// semantics reject malformed, foreign and mutation-shaped replies.
#[test]
fn observation_wire_boundary() {
    let request = Request::new(
        "read",
        Secret::new("fixture-secret"),
        Operation::ResolveRecipient(resolution()),
    )
    .unwrap();
    assert!(request.reconciliation().is_none());
    assert!(!format!("{request:?}").contains("synthetic-store"));
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    let response = Response::ok(
        "read",
        OperationResult::ResolveRecipient(ResolveRecipientResult {
            sampled_at_ms: 1,
            resolution: RecipientResolution::Resolved {
                address: "host/claude-code/namespace/session%2Fone".into(),
            },
        }),
    );
    let good = serde_json::to_value(&response).unwrap();
    assert!(decode_response(&serde_json::to_vec(&good).unwrap(), &request).is_ok());
    for (field, value) in [
        ("sampled_at_ms", json!(0)),
        ("sampled_at_ms", json!(u64::MAX)),
        (
            "resolution",
            json!({"state":"resolved","address":"host/codex/namespace/session%2Fone"}),
        ),
        (
            "resolution",
            json!({"state":"resolved","address":"host/claude-code/namespace/other"}),
        ),
        (
            "resolution",
            json!({"state":"resolved","address":"host/claude-code/namespace/session%2fone"}),
        ),
        (
            "resolution",
            json!({"state":"unavailable","address":"private"}),
        ),
    ] {
        let mut bad = good.clone();
        bad["result"]["value"][field] = value;
        assert!(
            decode_response(&serde_json::to_vec(&bad).unwrap(), &request).is_err(),
            "{field}"
        );
    }
    let mut bad_id = good.clone();
    bad_id["request_id"] = json!("another");
    assert!(decode_response(&serde_json::to_vec(&bad_id).unwrap(), &request).is_err());
    let raw = serde_json::to_value(&request).unwrap();
    for (field, value) in [
        ("expected_store", json!("relative")),
        ("expected_store", json!("/store/../other")),
        ("expected_store", json!("/store/./other")),
        ("expected_store", json!("/store//other")),
        ("expected_store", json!("/store/")),
        ("expected_store", json!(format!("/{}", "a".repeat(4096)))),
        ("expected_harness_pid", json!(0)),
        ("expected_harness_pid", json!(i32::MAX as u64 + 1)),
        ("expected_harness_start_time_secs", json!(0)),
        ("expected_harness_start_time_secs", json!(u64::MAX)),
        ("native_session_id", json!("a".repeat(257))),
        ("native_session_id", json!("session\n")),
        ("extra", json!(true)),
    ] {
        let mut bad = raw.clone();
        bad["params"][field] = value;
        assert!(
            decode_request(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{field}"
        );
    }
    let observe = Request::new(
        "read",
        Secret::new("fixture-secret"),
        Operation::ObserveRecipient(ObserveRecipientParams {
            address: "host/codex/store/session%2fone".into(),
        }),
    )
    .unwrap();
    let observed = Response::ok(
        "read",
        OperationResult::ObserveRecipient(RecipientObservation {
            address: "host/codex/store/session%2Fone".into(),
            sampled_at_ms: 2,
            observation: RecipientObservationState::Observed {
                lifecycle: RecipientLifecycle::Unknown,
                capabilities: RecipientCapabilities {
                    inject: false,
                    message: true,
                },
            },
        }),
    );
    assert!(decode_response(&encode_response(&observed).unwrap(), &observe).is_ok());
    assert!(decode_response(&encode_response(&observed).unwrap(), &request).is_err());
    let mut extra = serde_json::to_value(&observed).unwrap();
    extra["result"]["value"]["observation"] = json!({"state":"unavailable","lifecycle":"inactive"});
    assert!(decode_response(&serde_json::to_vec(&extra).unwrap(), &observe).is_err());
    let mut foreign = observed.clone();
    if let Some(OperationResult::ObserveRecipient(r)) = &mut foreign.result {
        r.address = "host/codex/store/other".into();
    }
    assert!(decode_response(&encode_response(&foreign).unwrap(), &observe).is_err());
    let error = Response::error(
        "read",
        ApiError {
            class: ErrorClass::Unavailable,
            reason: "unavailable".into(),
            retry_hint: RetryHint::Never,
            effect: Some(MutationEffect::NotCommitted),
            reconciliation: None,
            detail: "Read refused".into(),
        },
    );
    assert!(decode_response(&encode_response(&error).unwrap(), &observe).is_err());
}
