//! One public wire boundary control spanning strict input and immutable output.
use bridge_protocol::*;
use serde_json::{Value, json};

/// Reusable accepted fixture set; contains only intentionally synthetic credentials.
fn fixtures() -> Vec<Request> {
    serde_json::from_str::<Vec<Value>>(include_str!("wire-v1.json"))
        .unwrap()
        .into_iter()
        .map(|v| decode_request(&serde_json::to_vec(&v).unwrap()).unwrap())
        .collect()
}
/// Exact normalized custody acknowledgement for a supplied synthetic publication.
fn receipt(p: &PublishParams) -> EventReceipt {
    let address = match &p.destination {
        Destination::Address { address } => NativeAddress::parse(address).unwrap().canonical(),
        _ => "local/codex/store/session".into(),
    };
    EventReceipt {
        producer: "synthetic-producer".into(),
        event_id: p.event_id.clone(),
        intent_hash: publication_intent_fingerprint(p).unwrap(),
        envelope_hash: "a".repeat(64),
        accepted_at_ms: 10,
        acceptance_seq: 1,
        destination: FrozenDestination {
            address,
            route_key: None,
            caller_scope: None,
            destination_scope: None,
        },
    }
}
/// The decisive public control rejects genuine malformed/altered immutable replies.
#[test]
fn public_wire_boundary() {
    let all = fixtures();
    for request in &all {
        let bytes = encode_request(request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), *request);
        assert!(!format!("{request:?}").contains("fixture-secret"));
    }
    let mut register = match all[1].operation.clone() {
        Operation::RegisterCall(p) => p,
        _ => unreachable!(),
    };
    let base = registration_request_fingerprint(&register).unwrap();
    register.evidence = None;
    register.allowed_modes = Some(vec![Mode::Message]);
    assert_eq!(registration_request_fingerprint(&register).unwrap(), base);
    register.allowed_kinds = Some(vec!["*".into()]);
    assert_ne!(registration_request_fingerprint(&register).unwrap(), base);
    register.allowed_modes = Some(vec![Mode::Message, Mode::Inject]);
    let a = registration_request_fingerprint(&register).unwrap();
    register.allowed_modes = Some(vec![Mode::Inject, Mode::Message]);
    assert_eq!(registration_request_fingerprint(&register).unwrap(), a);
    let mut publication = match all[2].operation.clone() {
        Operation::Publish(p) => p,
        _ => unreachable!(),
    };
    let request = &all[2];
    let good = Response::ok(
        &request.request_id,
        OperationResult::Publish(PublishResult {
            receipt: receipt(&publication),
            replayed: false,
        }),
    );
    let bytes = encode_response(&good).unwrap();
    assert_eq!(decode_response(&bytes, request).unwrap(), good);
    publication.payload = Payload::new("changed body").unwrap();
    let changed = Request::new(
        &request.request_id,
        Secret::new("fixture-secret"),
        Operation::Publish(publication),
    )
    .unwrap();
    assert!(decode_response(&bytes, &changed).is_err());
    let mut wrong = good.clone();
    wrong.request_id = "other-call".into();
    assert!(wrong.validate_for(request).is_err());
    let bad = [
        r#"{"api_version":1,"api_version":1,"request_id":"x","credential":"s","op":"capabilities","params":{}}"#,
        r#"{"api_version":1,"request_id":"x","credential":"s","op":"capabilities","params":{"producer":"forged"}}"#,
        r#"{"api_version":2,"request_id":"x","credential":"s","op":"capabilities","params":{}}"#,
        r#"{"api_version":1,"request_id":"x","credential":"s","op":"register_call","params":{"operation_key":"o","evidence":{"type":"native","host":"codex","metadata":{"a":1,"a":2}}}}"#,
    ];
    for raw in bad {
        assert!(
            decode_request(raw.as_bytes()).is_err(),
            "invalid frame accepted"
        );
    }
    let mut extra = serde_json::to_value(&good).unwrap();
    extra["error"] = json!({"class":"auth","reason":"refused","retry_hint":"never","effect":null,"reconciliation":null,"detail":"safe"});
    assert!(decode_response(&serde_json::to_vec(&extra).unwrap(), request).is_err());
    let parsed = NativeAddress::parse("h%2fx/codex/s%25t/thread%2fchild").unwrap();
    assert_eq!(parsed.canonical(), "h%2Fx/codex/s%25t/thread%2Fchild");
    assert!(NativeAddress::parse("h/codex/s/x%GG").is_err());
    assert!(Payload::new("x\u{85}").is_err());
    let mut oversized = match all[2].operation.clone() {
        Operation::Publish(p) => p,
        _ => unreachable!(),
    };
    oversized.kind = "k".repeat(65);
    assert!(oversized.validate().is_err());
    let evidence = format!("{:?}", all[1]);
    assert!(!evidence.contains("native-thread"));
}
