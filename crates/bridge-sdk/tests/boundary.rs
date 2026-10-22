//! One real Unix boundary control for retries, uncertainty, deadlines and redaction.
use bridge_sdk::bridge_protocol::*;
use bridge_sdk::{Client, ClientError, Config, TransportOutcome, extract_native_evidence};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

/// A trusted plugin's exact per-call context is supported; vendor session-only,
/// model-argument, malformed and mixed-host candidates never become evidence.
#[test]
fn opencode_plugin_metadata_requires_a_complete_separate_contract() {
    let native = serde_json::json!({"ai.opencode/sessionID":"ses_native","ai.agent_bridge/toolCallID":"call_native"});
    assert!(extract_native_evidence(Host::OpenCode, &native).is_ok());
    assert_eq!(
        serde_json::to_value(Host::OpenCode).unwrap(),
        serde_json::json!("opencode")
    );
    for invalid in [
        serde_json::json!({"ai.opencode/sessionID":"ses_native"}),
        serde_json::json!({"arguments":native}),
        serde_json::json!({"ai.opencode/sessionID":"ses_native","ai.agent_bridge/toolCallID":""}),
        serde_json::json!({"ai.opencode/sessionID":"ses_native","ai.agent_bridge/toolCallID":"call_native","claudecode/toolUseId":"other"}),
        serde_json::json!({"ai.opencode/sessionID":"ses_native","ai.agent_bridge/toolCallID":"call_native","callId":"other"}),
    ] {
        assert!(extract_native_evidence(Host::OpenCode, &invalid).is_err());
    }
    assert!(extract_native_evidence(Host::Codex, &native).is_err());
    assert!(extract_native_evidence(Host::ClaudeCode, &native).is_err());
}

/// Synthetic publication fixture, deliberately unrelated to any consumer product.
fn publication() -> PublishParams {
    PublishParams {
        destination: Destination::Address {
            address: "local/codex/store/session".into(),
        },
        event_id: "independent-event".into(),
        kind: "independent.kind".into(),
        payload: Payload::new("never-log-this-body").unwrap(),
        mode: Mode::Message,
        policy: Policy::KeepAll,
        metadata: Metadata::new(),
        expires_at_ms: None,
        delivery_scope_key: None,
    }
}
/// Correlated contract response; this substitute owns no store/native business logic.
fn acknowledge(request: &Request) -> Vec<u8> {
    let p = match &request.operation {
        Operation::Publish(p) => p,
        _ => panic!("fixture expected publication"),
    };
    let receipt = EventReceipt {
        producer: "independent-producer".into(),
        event_id: p.event_id.clone(),
        intent_hash: publication_intent_fingerprint(p).unwrap(),
        envelope_hash: "a".repeat(64),
        accepted_at_ms: 10,
        acceptance_seq: 1,
        destination: FrozenDestination {
            address: "local/codex/store/session".into(),
            route_key: None,
            caller_scope: None,
            destination_scope: None,
        },
    };
    let mut bytes = encode_response(&Response::ok(
        &request.request_id,
        OperationResult::Publish(PublishResult {
            receipt,
            replayed: true,
        }),
    ))
    .unwrap();
    bytes.push(b'\n');
    bytes
}
/// Names a test-private socket beneath the explicitly configured, absolute
/// `TMPDIR` (no system fallback); it must be short enough for a Unix socket.
fn path(name: &str) -> PathBuf {
    let base = PathBuf::from(std::env::var_os("TMPDIR").expect("explicit task TMPDIR required"));
    assert!(base.is_absolute(), "TMPDIR must be an absolute directory");
    base.join(format!("sdk-{}-{name}.sock", std::process::id()))
}

/// Both read methods use only the adapter socket; lost ACK retries preserve the
/// exact request and mismatched replies remain read failures without reconciliation.
/// Calling this synchronous client inside a Tokio task must not nest block_on or
/// panic while creating/releasing the private peer-credential driver.
#[test]
fn native_observation_sdk_boundary() {
    let socket = path("observations");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let mut original = String::new();
        let (stream, _) = listener.accept().unwrap();
        BufReader::new(stream).read_line(&mut original).unwrap();
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request = decode_request(line.trim_end().as_bytes()).unwrap();
            let result = if step == 0 {
                assert_eq!(line, original, "lost read ACK must not change identity");
                assert!(matches!(request.operation, Operation::ObserveRecipient(_)));
                OperationResult::ObserveRecipient(RecipientObservation {
                    address: "host/codex/store/session".into(),
                    sampled_at_ms: 1,
                    observation: RecipientObservationState::Unavailable,
                })
            } else {
                assert!(matches!(request.operation, Operation::ResolveRecipient(_)));
                OperationResult::ResolveRecipient(ResolveRecipientResult {
                    sampled_at_ms: 1,
                    resolution: RecipientResolution::Resolved {
                        address: format!(
                            "host/codex/store/{}",
                            if step == 1 { "session" } else { "foreign" }
                        ),
                    },
                })
            };
            let mut bytes = encode_response(&Response::ok(&request.request_id, result)).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
        }
    });
    let client = Client::new(
        Config::new(
            &socket,
            path("unused-core"),
            Secret::new("fixture-secret"),
            Duration::from_secs(2),
        )
        .unwrap(),
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .block_on(async {
                client.observe_recipient(
                    "observe",
                    ObserveRecipientParams {
                        address: "host/codex/store/session".into(),
                    },
                )
            })
            .unwrap()
            .observation,
        RecipientObservationState::Unavailable
    );
    let params = ResolveRecipientParams {
        host: Host::Codex,
        native_session_id: "session".into(),
        expected_store: "/private/synthetic".into(),
        expected_harness_pid: 23,
        expected_harness_start_time_secs: 42,
    };
    assert!(matches!(
        client
            .resolve_recipient("resolve", params.clone())
            .unwrap()
            .resolution,
        RecipientResolution::Resolved { .. }
    ));
    assert!(matches!(
        client.resolve_recipient("foreign", params),
        Err(ClientError::Transport {
            outcome: TransportOutcome::ReadFailed,
            reconciliation: None,
            ..
        })
    ));
    worker.join().unwrap();
    fs::remove_file(socket).unwrap();
}
/// One reusable public control exercises real streams, not an artificial transport trait.
#[test]
fn public_sdk_boundary() {
    let socket = path("retry");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let mut first = String::new();
        let (stream, _) = listener.accept().unwrap();
        BufReader::new(stream).read_line(&mut first).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut second = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut second)
            .unwrap();
        assert_eq!(first, second, "retry changed immutable request");
        let request = decode_request(second.trim_end().as_bytes()).unwrap();
        stream.write_all(&acknowledge(&request)).unwrap();
    });
    let config = Config::new(
        &socket,
        &socket,
        Secret::new("never-log-this-credential"),
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(!format!("{config:?}").contains("never-log-this-credential"));
    let client = Client::new(config).unwrap();
    let received = client.publish("stable-request", publication()).unwrap();
    assert!(received.replayed);
    worker.join().unwrap();
    fs::remove_file(&socket).unwrap();

    let socket = path("lost");
    let listener = UnixListener::bind(&socket).unwrap();
    let owned = socket.clone();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut text = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut text)
            .unwrap();
        drop(listener);
        fs::remove_file(owned).unwrap();
        drop(stream);
    });
    let client = Client::new(
        Config::new(
            &socket,
            &socket,
            Secret::new("never-log-this-credential"),
            Duration::from_secs(1),
        )
        .unwrap(),
    )
    .unwrap();
    let error = client.publish("stable-request", publication()).unwrap_err();
    worker.join().unwrap();
    assert!(
        matches!(
            error,
            ClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                reconciliation: Some(ReconciliationKey::Event { .. }),
                ..
            }
        ),
        "earlier unknown masked by later connect failure"
    );
    let diagnostic = format!("{error:?}");
    assert!(!diagnostic.contains("never-log-this-credential"));
    assert!(!diagnostic.contains("never-log-this-body"));

    let socket = path("reject");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        let mut frame = String::new();
        BufReader::new(first).read_line(&mut frame).unwrap();
        let (mut second, _) = listener.accept().unwrap();
        let mut replay = String::new();
        BufReader::new(second.try_clone().unwrap())
            .read_line(&mut replay)
            .unwrap();
        assert_eq!(frame, replay);
        let request = decode_request(replay.trim_end().as_bytes()).unwrap();
        let response = Response::error(
            &request.request_id,
            ApiError {
                class: ErrorClass::Auth,
                reason: "revoked".into(),
                retry_hint: RetryHint::Never,
                effect: Some(MutationEffect::NotCommitted),
                reconciliation: request.reconciliation(),
                detail: "retry credential rejected before original lookup".into(),
            },
        );
        let mut bytes = encode_response(&response).unwrap();
        bytes.push(b'\n');
        second.write_all(&bytes).unwrap();
    });
    let client = Client::new(
        Config::new(
            &socket,
            &socket,
            Secret::new("credential"),
            Duration::from_secs(1),
        )
        .unwrap(),
    )
    .unwrap();
    let error = client.publish("stable-request", publication()).unwrap_err();
    worker.join().unwrap();
    fs::remove_file(&socket).unwrap();
    assert!(
        matches!(
            error,
            ClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                reconciliation: Some(ReconciliationKey::Event { .. }),
                ..
            }
        ),
        "later request refusal erased earlier mutation uncertainty"
    );

    let socket = path("slow");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut text = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut text)
            .unwrap();
        for _ in 0..30 {
            if stream.write_all(b" ").is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let mut config = Config::new(
        &socket,
        &socket,
        Secret::new("credential"),
        Duration::from_millis(70),
    )
    .unwrap();
    config.reconnect_once = false;
    let client = Client::new(config).unwrap();
    let start = Instant::now();
    let error = client.publish("stable-request", publication()).unwrap_err();
    let elapsed = start.elapsed();
    assert!(matches!(
        error,
        ClientError::Transport {
            outcome: TransportOutcome::OutcomeUnknown,
            ..
        }
    ));
    assert!(
        elapsed < Duration::from_millis(300),
        "partial traffic renewed deadline"
    );
    worker.join().unwrap();
    fs::remove_file(&socket).unwrap();

    let client = Client::new(
        Config::new(
            &socket,
            &socket,
            Secret::new("credential"),
            Duration::from_millis(50),
        )
        .unwrap(),
    )
    .unwrap();
    let error = client.publish("stable-request", publication()).unwrap_err();
    assert!(matches!(
        error,
        ClientError::Transport {
            outcome: TransportOutcome::NotSent,
            ..
        }
    ));
    let native = serde_json::json!({"threadId":"native-thread","callId":"native-call","x-codex-turn-metadata":{}});
    assert!(extract_native_evidence(Host::Codex, &native).is_ok());
    let mixed = serde_json::json!({"threadId":"native-thread","callId":"native-call","x-codex-turn-metadata":{},"claudecode/toolUseId":"other"});
    assert!(extract_native_evidence(Host::Codex, &mixed).is_err());
    assert!(
        extract_native_evidence(
            Host::Codex,
            &serde_json::json!({"arguments":{"threadId":"native-thread"}})
        )
        .is_err()
    );
}

/// A service that answers and closes at once is read on the first connection: the answer is
/// returned and no second connection (a replayed request) is ever made.
#[test]
fn immediate_close_after_answer_is_not_retried() {
    let socket = path("fast-close");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let request = decode_request(line.trim_end().as_bytes()).unwrap();
        let mut stream = stream;
        stream.write_all(&acknowledge(&request)).unwrap();
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        // Give a retry every chance to arrive before checking that none did.
        thread::sleep(Duration::from_millis(200));
        assert!(listener.accept().is_err(), "the request was replayed");
    });
    let client = Client::new(
        Config::new(
            &socket,
            &socket,
            Secret::new("never-log-this-credential"),
            Duration::from_secs(1),
        )
        .unwrap(),
    )
    .unwrap();
    let received = client.publish("fast-close", publication()).unwrap();
    assert!(received.replayed);
    worker.join().unwrap();
    fs::remove_file(&socket).unwrap();
}
