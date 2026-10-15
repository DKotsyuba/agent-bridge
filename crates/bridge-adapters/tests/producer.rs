//! Universal native-provider boundary tests over owned kernel processes and
//! the actual core SQLite store. No consumer code or installed session is used.
mod common;

use bridge_adapters::registry::{BackendAudience, RelayExecutable};
use bridge_adapters::server::{ChannelServer, Custody};
use bridge_core::dispatch::DispatchTiming;
use bridge_core::{GrantConfig, Harness, ProducerAuthorizer, ProducerPolicy};
use bridge_protocol::*;
use common::*;
use serde_json::{Value, json};
use std::sync::Arc;

/// Private synthetic credential used only inside the owned fixture namespace.
const TOKEN: &str = "owned-fixture-producer-credential";
/// An arbitrary producer name; production code contains no corresponding branch.
const PRODUCER: &str = "unseen-producer-x";

/// Configures one actual core authority and optional generic backend audience.
fn lab(assertions: bool) -> Lab {
    let mut lab = Lab::new("v1");
    let grant: GrantConfig = serde_json::from_value(json!({
        "token": TOKEN, "publisher": PRODUCER, "recipients": ["*"],
        "kinds": ["*"], "modes": ["message", "inject"], "policies": ["keep_all"],
        "producer_v1": {"registration": true, "reply_policies": ["self", "shared_session"],
            "native_scopes": ["*"], "assertion_audiences": if assertions {vec!["aud-local"]} else {Vec::<&str>::new()}}
    })).unwrap();
    assert!(
        grant
            .producer_v1
            .as_ref()
            .is_some_and(|policy: &ProducerPolicy| policy.registration)
    );
    {
        let mut store = lab.storage.lock().unwrap();
        store
            .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&[grant]).unwrap()))
            .unwrap();
        store.register_source_tag(PRODUCER, PRODUCER).unwrap();
    }
    if assertions {
        lab.channel.take().unwrap().stop();
        lab.config.audiences.push(BackendAudience {
            name: "aud-local".into(),
            producer: PRODUCER.into(),
            executable: RelayExecutable {
                path: fixture_exe(),
                sha256: bridge_adapters::registry::file_sha256(&fixture_exe()).unwrap(),
            },
        });
        let owner =
            bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
        lab.registry = Arc::new(std::sync::Mutex::new(
            bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
        ));
        lab.channel = Some(
            ChannelServer::start(
                &lab.socket,
                Arc::clone(&lab.registry),
                Arc::clone(&lab.storage) as Arc<dyn Custody>,
                DispatchTiming::default(),
            )
            .unwrap(),
        );
    }
    lab
}

/// Builds one generic registration from the original synthetic host metadata.
fn registration(id: &str, op: &str, call: &str) -> Request {
    Request::new(
        id,
        Secret::new(TOKEN),
        Operation::RegisterCall(RegisterCallParams {
            operation_key: op.into(),
            evidence: Some(CallEvidence::Native {
                host: Host::ClaudeCode,
                metadata: serde_json::from_value(json!({"claudecode/toolUseId": call})).unwrap(),
            }),
            reply_policy: ReplyPolicy::SelfActor,
            allowed_modes: None,
            allowed_kinds: None,
            max_payload_bytes: None,
            route_expires_at_ms: None,
            assertion_audience: None,
            invocation_key: None,
        }),
    )
    .unwrap()
}

/// Sends a public frame from a descendant of a marked harness process, preserving genuine
/// kernel ancestry. Typed decoding keeps secrets redacted in test diagnostics.
fn call(
    harness: &mut Harnessed,
    socket: &std::path::Path,
    request: &Request,
    direct: bool,
) -> Response {
    let value = harness.cmd(json!({"cmd": if direct {"v1_direct"} else {"v1"},
        "socket": socket, "request": serde_json::to_value(request).unwrap()}));
    decode_response(&serde_json::to_vec(&value).unwrap(), request).expect("typed provider response")
}

/// Extracts only typed registration data; failure messages never print wire secrets.
fn registered(response: Response) -> RegistrationResult {
    match response.result {
        Some(OperationResult::RegisterCall(result)) => result,
        _ => panic!("registration failed: {:?}", response.error),
    }
}

/// Exact receipt recovery precedes proof use; new requests need fresh evidence,
/// operation bindings stay immutable, and shared-address children remain distinct.
#[test]
fn registration_replay_and_actual_child_scope_are_independent() {
    let lab = lab(false);
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "session"),
    );
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "call1", None),
    );
    let request = registration("request1", "operation1", "call1");
    let initial = registered(call(&mut harness, &lab.socket, &request, false));
    let replay = registered(call(&mut harness, &lab.socket, &request, false));
    assert_eq!(replay.receipt, initial.receipt);
    assert_eq!(replay.evidence_state, CallerEvidenceState::Historical);
    assert!(replay.assertion.is_none());
    let changed = registration("request1", "changed-operation", "call1");
    assert_eq!(
        call(&mut harness, &lab.socket, &changed, false)
            .error
            .unwrap()
            .class,
        ErrorClass::Conflict
    );
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "call2", None),
    );
    let fresh = registered(call(
        &mut harness,
        &lab.socket,
        &registration("request2", "operation1", "call2"),
        false,
    ));
    assert_eq!(fresh.receipt.route_key, initial.receipt.route_key);
    assert_eq!(fresh.receipt.request_id, "request2");
    assert_eq!(fresh.receipt.caller_scope, initial.receipt.caller_scope);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "child-call", Some("child-a")),
    );
    let mut child = registration("child-self", "child-operation", "child-call");
    assert!(!call(&mut harness, &lab.socket, &child, false).success);
    child.request_id = "child-shared".into();
    if let Operation::RegisterCall(params) = &mut child.operation {
        params.reply_policy = ReplyPolicy::SharedSession;
    }
    let child = registered(call(&mut harness, &lab.socket, &child, false));
    assert_ne!(child.receipt.caller_scope, initial.receipt.caller_scope);
    assert_eq!(
        child.receipt.destination_scope,
        initial.receipt.destination_scope
    );
    harness.stop();
}

/// Known outer-wrapper and missing/non-MCP observations refuse v1 without
/// spending native evidence; the legacy attestation contract remains intact.
#[test]
fn unsupported_host_paths_do_not_consume_native_observations() {
    let lab = lab(false);
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    for (index, name) in [Some("functions.exec"), Some("shell"), None]
        .into_iter()
        .enumerate()
    {
        let id = format!("call-{index}");
        let mut payload = tool_hook("PreToolUse", "session", &id, None);
        payload["tool_name"] = name.map_or(Value::Null, |value| json!(value));
        harness.hook(&lab.socket, Harness::ClaudeCode, payload);
        let response = call(
            &mut harness,
            &lab.socket,
            &registration(&format!("r-{index}"), &format!("op-{index}"), &id),
            false,
        );
        assert_eq!(response.error.unwrap().reason, "unsupported_host_path");
        assert_eq!(
            harness.mcp(&lab.socket, json!({"claudecode/toolUseId": id}))["ok"]["role"],
            "root"
        );
    }
    harness.stop();
}

/// Generic audience and invocation linkage are checked before spending; exact
/// same backend/request retry preserves the original context and expiry.
#[test]
fn configured_audience_consumes_once_and_replay_never_renews() {
    let lab = lab(true);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "assert-call", None),
    );
    let mut request = registration("assert-registration", "assert-operation", "assert-call");
    if let Operation::RegisterCall(params) = &mut request.operation {
        params.assertion_audience = Some("aud-local".into());
        params.invocation_key = Some("invocation-a".into());
    }
    let registered = registered(call(&mut source, &lab.socket, &request, false));
    let assertion = registered.assertion.expect("actual assertion issued");
    let mut backend = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let mut consume = Request::new(
        "consume-a",
        Secret::new(TOKEN),
        Operation::ConsumeAssertion(ConsumeAssertionParams {
            assertion_key: assertion.assertion_key,
            invocation_key: "wrong-invocation".into(),
        }),
    )
    .unwrap();
    assert!(!call(&mut backend, &lab.socket, &consume, true).success);
    if let Operation::ConsumeAssertion(params) = &mut consume.operation {
        params.invocation_key = "invocation-a".into();
    }
    let first = call(&mut backend, &lab.socket, &consume, true);
    let replay = call(&mut backend, &lab.socket, &consume, true);
    assert_eq!(first.result, replay.result);
    if let Some(OperationResult::ConsumeAssertion(result)) = &first.result {
        assert_eq!(result.state, InvocationValidity::Current);
        assert_eq!(
            result.receipt.context.expires_at_ms,
            assertion.expires_at_ms
        );
    } else {
        panic!("actual consumption missing");
    }
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "session"),
    );
    let historical = call(&mut backend, &lab.socket, &consume, true);
    assert!(matches!(
        historical.result,
        Some(OperationResult::ConsumeAssertion(ConsumeResult {
            state: InvocationValidity::Historical,
            ..
        }))
    ));
    consume.request_id = "different-consumer-request".into();
    assert!(!call(&mut backend, &lab.socket, &consume, true).success);
    source.stop();
    backend.stop();
}

/// Sealed transfer retains actual child/origin facts and original single-use
/// identity; committed retry recovers historically after the proof is consumed.
#[test]
fn sealed_registration_replay_does_not_redeem_twice() {
    let lab = lab(false);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "sealed-call", None),
    );
    let issued = source.mcp_sealed(&lab.socket, json!({"claudecode/toolUseId": "sealed-call"}));
    let proof = issued["proof"].as_str().expect("owned sealed source");
    let mut backend = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let mut request = registration("sealed-registration", "sealed-operation", "unused");
    if let Operation::RegisterCall(params) = &mut request.operation {
        params.evidence = Some(CallEvidence::Sealed {
            proof: Secret::new(proof),
        });
    }
    let initial = registered(call(&mut backend, &lab.socket, &request, true));
    let replay = registered(call(&mut backend, &lab.socket, &request, true));
    assert_eq!(initial.receipt, replay.receipt);
    assert_eq!(replay.evidence_state, CallerEvidenceState::Historical);
    request.request_id = "another-registration".into();
    assert!(!call(&mut backend, &lab.socket, &request, true).success);
    source.stop();
    backend.stop();
}

/// Restart preserves committed routing while losing native source evidence and
/// assertions honestly; receipt recovery never reconstructs current authority.
#[test]
fn registry_restart_recovers_receipt_but_requires_fresh_source() {
    let mut lab = lab(false);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "restart-call", None),
    );
    let request = registration("restart-registration", "restart-operation", "restart-call");
    let initial = registered(call(&mut source, &lab.socket, &request, false));
    lab.channel.take().unwrap().stop();
    let owner = bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
    lab.registry = Arc::new(std::sync::Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let historical = registered(call(&mut source, &lab.socket, &request, false));
    assert_eq!(historical.receipt, initial.receipt);
    assert_eq!(historical.evidence_state, CallerEvidenceState::Historical);
    let missing = registration("missing-source", "new-operation", "restart-call");
    assert_eq!(
        call(&mut source, &lab.socket, &missing, false)
            .error
            .unwrap()
            .reason,
        "needs_new_attestation"
    );
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "fresh-call", None),
    );
    let fresh = registered(call(
        &mut source,
        &lab.socket,
        &registration("fresh-registration", "restart-operation", "fresh-call"),
        false,
    ));
    assert_eq!(fresh.receipt.route_key, initial.receipt.route_key);
    assert_eq!(fresh.receipt.caller_scope, initial.receipt.caller_scope);
    source.stop();
}

/// Expired consumption is historical and daemon boot loss cannot restore an
/// assertion from retained routes, even with the same authenticated producer.
#[test]
fn assertion_expiry_and_boot_loss_do_not_reconstruct_authority() {
    let mut lab = lab(true);
    lab.channel.take().unwrap().stop();
    lab.config.max_call_age_ms = 3_000;
    let owner = bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
    lab.registry = Arc::new(std::sync::Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let mut backend = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "ttl-call", None),
    );
    let mut request = registration("ttl-registration", "ttl-operation", "ttl-call");
    if let Operation::RegisterCall(params) = &mut request.operation {
        params.assertion_audience = Some("aud-local".into());
        params.invocation_key = Some("ttl-invocation".into());
    }
    let assertion = registered(call(&mut source, &lab.socket, &request, false))
        .assertion
        .unwrap();
    let consume = Request::new(
        "ttl-consumption",
        Secret::new(TOKEN),
        Operation::ConsumeAssertion(ConsumeAssertionParams {
            assertion_key: assertion.assertion_key,
            invocation_key: "ttl-invocation".into(),
        }),
    )
    .unwrap();
    assert!(call(&mut backend, &lab.socket, &consume, true).success);
    let remaining = assertion.expires_at_ms.saturating_sub(now());
    std::thread::sleep(std::time::Duration::from_millis(remaining + 20));
    let historical = call(&mut backend, &lab.socket, &consume, true);
    assert!(matches!(
        historical.result,
        Some(OperationResult::ConsumeAssertion(ConsumeResult {
            state: InvocationValidity::Historical,
            ..
        }))
    ));
    lab.channel.take().unwrap().stop();
    lab.registry = Arc::new(std::sync::Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    assert_eq!(
        call(&mut backend, &lab.socket, &consume, true)
            .error
            .unwrap()
            .reason,
        "needs_new_attestation"
    );
    let recovered = registered(call(&mut source, &lab.socket, &request, false));
    assert_eq!(recovered.evidence_state, CallerEvidenceState::Historical);
    assert!(recovered.assertion.is_none());
    source.stop();
    backend.stop();
}

/// The host tag cannot disguise protected metadata of another host; malformed
/// unknown operations and recognized unsupported versions refuse without use.
#[test]
fn mixed_host_and_unknown_operation_refuse_without_source_use() {
    let lab = lab(false);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "mixed-call", None),
    );
    let mut wrong = registration("mixed-registration", "mixed-operation", "mixed-call");
    if let Operation::RegisterCall(params) = &mut wrong.operation
        && let Some(CallEvidence::Native { host, .. }) = &mut params.evidence
    {
        *host = Host::Codex;
    }
    assert_eq!(
        call(&mut source, &lab.socket, &wrong, false)
            .error
            .unwrap()
            .class,
        ErrorClass::Forbidden
    );
    for (version, operation, expected) in [
        (1, "future-operation", "invalid"),
        (2, "capabilities", "unsupported"),
    ] {
        let response = source.cmd(json!({"cmd": "v1_direct", "socket": lab.socket,
            "request": {"api_version": version, "request_id": "unsupported-request", "credential": TOKEN,
                "op": operation, "params": {}}}));
        assert_eq!(response["error"]["class"], expected);
    }
    let valid = registration("mixed-registration", "mixed-operation", "mixed-call");
    assert!(call(&mut source, &lab.socket, &valid, false).success);
    source.stop();
}

/// A frontend discards a begun registration response; exact retry recovers the
/// authoritative receipt and never spends native evidence a second time.
#[test]
fn registration_ack_loss_recovers_original_custody() {
    let lab = lab(false);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "ack-call", None),
    );
    let request = registration("ack-registration", "ack-operation", "ack-call");
    let lost = source.cmd(json!({"cmd": "v1", "socket": lab.socket, "lose_ack": true,
        "request": serde_json::to_value(&request).unwrap()}));
    assert_eq!(lost["outcome_unknown"], true);
    let replay = registered(call(&mut source, &lab.socket, &request, false));
    assert_eq!(replay.evidence_state, CallerEvidenceState::Historical);
    assert_eq!(replay.receipt.request_id, "ack-registration");
    assert_eq!(
        source.mcp(&lab.socket, json!({"claudecode/toolUseId": "ack-call"}))["err"],
        "duplicate"
    );
    source.stop();
}

/// Controlled custody failure window, never a substitute persistence algorithm.
#[derive(Clone, Copy)]
enum CommitFault {
    /// Await the controller while sibling native attestation runs.
    Pause,
    /// Kill the serving thread after claim but before any custody commit.
    Before,
    /// Kill it after real commit but before native claim finalization/response.
    After,
}

/// Test-only custody gate pauses one actual native commit without copying any
/// persistence algorithm. No registry/storage lock is held while awaiting release.
struct CommitGate {
    /// Selected controlled failure window.
    fault: CommitFault,
    /// Real authoritative SQLite store.
    storage: Arc<std::sync::Mutex<bridge_core::Storage>>,
    /// Number of future calls until the actual commit closure is paused.
    countdown: std::sync::atomic::AtomicUsize,
    /// Owned barrier witness, contains no credential/caller payload.
    ready_file: std::path::PathBuf,
    /// Root test releases the commit after observing the independent legacy call.
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl Custody for CommitGate {
    /// Executes the unchanged real core action after the optional gate. Selected
    /// Before/After faults deliberately panic outside the storage lock; the
    /// real committed rows and unresolved registry claims remain observable.
    fn run(&self, action: &mut dyn FnMut(&mut bridge_core::Storage)) -> bool {
        use std::sync::atomic::Ordering;
        let gated = self
            .countdown
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                (value > 0).then(|| value - 1)
            })
            .is_ok_and(|value| value == 1);
        if gated {
            std::fs::write(&self.ready_file, b"reserved").unwrap();
            if matches!(self.fault, CommitFault::Before) {
                panic!("controlled precommit worker death");
            }
            if matches!(self.fault, CommitFault::Pause) {
                let _ = self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5));
            }
        }
        action(&mut self.storage.lock().unwrap());
        if gated && matches!(self.fault, CommitFault::After) {
            panic!("controlled postcommit worker death");
        }
        true
    }
}

/// While native registration is between claim and custody, a genuine sibling
/// legacy frontend cannot spend the same observation; only commit finalizes it.
#[test]
fn reservation_blocks_legacy_attestation_until_real_commit() {
    let mut lab = lab(false);
    lab.channel.take().unwrap().stop();
    let ready_file = lab.dir.0.join("claim-ready");
    let result_file = lab.dir.0.join("legacy-result");
    let (release, receiver) = std::sync::mpsc::channel();
    let gate = Arc::new(CommitGate {
        fault: CommitFault::Pause,
        storage: Arc::clone(&lab.storage),
        countdown: std::sync::atomic::AtomicUsize::new(0),
        ready_file: ready_file.clone(),
        release: std::sync::Mutex::new(receiver),
    });
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&gate) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "reserved-call", None),
    );
    gate.countdown.store(3, std::sync::atomic::Ordering::SeqCst);
    let request = registration(
        "reserved-registration",
        "reserved-operation",
        "reserved-call",
    );
    let socket = lab.socket.clone();
    let ready = ready_file.clone();
    let result = result_file.clone();
    let worker = std::thread::spawn(move || {
        let outcome = source.cmd(json!({"cmd": "v1_and_legacy", "socket": socket,
            "request": serde_json::to_value(&request).unwrap(), "meta": {"claudecode/toolUseId": "reserved-call"},
            "claim_ready_file": ready, "legacy_result_file": result}));
        (source, outcome)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    while !result_file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let legacy = std::fs::read_to_string(&result_file)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let _ = release.send(());
    let (mut source, outcome) = worker.join().unwrap();
    assert_eq!(legacy.unwrap()["err"], "unavailable");
    assert_eq!(outcome["first"]["success"], true);
    assert_eq!(
        source.mcp(
            &lab.socket,
            json!({"claudecode/toolUseId": "reserved-call"})
        )["err"],
        "duplicate"
    );
    source.stop();
}

/// A positively available different current origin cannot adopt an existing
/// registration; comparison remains nonconsuming for the other genuine call.
#[test]
fn committed_replay_with_different_current_origin_conflicts() {
    let lab = lab(false);
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "first-session", "origin-first", None),
    );
    let first = registration("origin-registration", "origin-operation", "origin-first");
    let initial = registered(call(&mut source, &lab.socket, &first, false));
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "other-session", "origin-other", None),
    );
    let different = registration("origin-registration", "origin-operation", "origin-other");
    assert_eq!(
        call(&mut source, &lab.socket, &different, false)
            .error
            .unwrap()
            .reason,
        "caller_scope_conflict"
    );
    let own = registered(call(
        &mut source,
        &lab.socket,
        &registration("other-registration", "other-operation", "origin-other"),
        false,
    ));
    assert_ne!(initial.receipt.caller_scope, own.receipt.caller_scope);
    source.stop();
}

/// Actual worker death on either side of the real custody commit leaves source
/// claims fenced; only a retained matching commit permits historical recovery.
#[test]
fn worker_death_before_and_after_commit_reconciles_without_reuse() {
    for fault in [CommitFault::Before, CommitFault::After] {
        let mut lab = lab(false);
        lab.channel.take().unwrap().stop();
        let (_, receiver) = std::sync::mpsc::channel();
        let gate = Arc::new(CommitGate {
            fault,
            storage: Arc::clone(&lab.storage),
            countdown: std::sync::atomic::AtomicUsize::new(0),
            ready_file: lab.dir.0.join("crash-ready"),
            release: std::sync::Mutex::new(receiver),
        });
        lab.channel = Some(
            ChannelServer::start(
                &lab.socket,
                Arc::clone(&lab.registry),
                Arc::clone(&gate) as Arc<dyn Custody>,
                DispatchTiming::default(),
            )
            .unwrap(),
        );
        let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
        source.hook(
            &lab.socket,
            Harness::ClaudeCode,
            tool_hook("PreToolUse", "session", "crash-call", None),
        );
        gate.countdown.store(3, std::sync::atomic::Ordering::SeqCst);
        let request = registration("crash-registration", "crash-operation", "crash-call");
        let lost = source.cmd(json!({"cmd": "v1", "socket": lab.socket, "request": serde_json::to_value(&request).unwrap()}));
        assert!(lost.get("error").is_some());
        assert_eq!(
            source.mcp(&lab.socket, json!({"claudecode/toolUseId": "crash-call"}))["err"],
            "unavailable"
        );
        let recovered = call(&mut source, &lab.socket, &request, false);
        match fault {
            CommitFault::After => {
                assert_eq!(
                    registered(recovered).evidence_state,
                    CallerEvidenceState::Historical
                );
                assert_eq!(
                    source.mcp(&lab.socket, json!({"claudecode/toolUseId": "crash-call"}))["err"],
                    "duplicate"
                );
            }
            CommitFault::Before => {
                assert_eq!(
                    recovered.error.unwrap().effect,
                    Some(MutationEffect::Unknown)
                );
                lab.channel.take().unwrap().stop();
                let owner =
                    bridge_adapters::server::private_directory(lab.socket.parent().unwrap())
                        .unwrap();
                lab.registry = Arc::new(std::sync::Mutex::new(
                    bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
                ));
                lab.channel = Some(
                    ChannelServer::start(
                        &lab.socket,
                        Arc::clone(&lab.registry),
                        Arc::clone(&lab.storage) as Arc<dyn Custody>,
                        DispatchTiming::default(),
                    )
                    .unwrap(),
                );
                assert_eq!(
                    call(&mut source, &lab.socket, &request, false)
                        .error
                        .unwrap()
                        .reason,
                    "needs_new_attestation"
                );
            }
            CommitFault::Pause => unreachable!("crash control"),
        }
        source.stop();
    }
}

/// Sealing a real native observation near its original deadline must not extend
/// v1 registration/assertion validity. Absolute observed-time scheduling controls
/// the expiry window; legacy proof redemption keeps its established lifetime.
#[test]
fn sealed_transfer_does_not_extend_original_observation_validity() {
    let mut lab = lab(true);
    lab.channel.take().unwrap().stop();
    lab.config.max_call_age_ms = 3_000;
    let owner = bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
    lab.registry = Arc::new(std::sync::Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let mut backend = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    source.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "session", "original-expiry", None),
    );
    // First protected observation created this epoch at its actual observation time.
    let observed = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&lab.claude_address("session"))
        .unwrap()
        .1
        .epoch;
    std::thread::sleep(std::time::Duration::from_millis(
        (observed + 1_000).saturating_sub(now()),
    ));
    let issued = source.mcp_sealed(
        &lab.socket,
        json!({"claudecode/toolUseId": "original-expiry"}),
    );
    let proof = issued["proof"].as_str().expect("real sealed proof");
    std::thread::sleep(std::time::Duration::from_millis(
        (observed + 3_500).saturating_sub(now()),
    ));
    let mut request = registration("expired-sealed", "expired-operation", "unused");
    if let Operation::RegisterCall(params) = &mut request.operation {
        params.evidence = Some(CallEvidence::Sealed {
            proof: Secret::new(proof),
        });
        params.assertion_audience = Some("aud-local".into());
        params.invocation_key = Some("expired-invocation".into());
    }
    assert!(!call(&mut backend, &lab.socket, &request, true).success);
    let params = match &request.operation {
        Operation::RegisterCall(params) => params,
        _ => unreachable!(),
    };
    assert!(
        lab.storage
            .lock()
            .unwrap()
            .registration_replay(TOKEN, &request.request_id, params)
            .unwrap()
            .is_none()
    );
    assert_eq!(relay_redeem(&lab.socket, proof)["ok"]["role"], "root");
    source.stop();
    backend.stop();
}

/// Actual inject confirmation honors short and longer-than-initial read windows;
/// small fragments cannot renew a short configured handoff deadline.
#[test]
fn hook_confirmation_preserves_each_configured_absolute_budget() {
    for (handoff_ms, delay_ms, gap_ms, submitted) in [
        (100, 250, 0, false),
        (100, 0, 70, false),
        (10_000, 5_500, 0, true),
    ] {
        let mut lab = lab(false);
        lab.channel.take().unwrap().stop();
        let timing = DispatchTiming {
            handoff_ms,
            ..DispatchTiming::default()
        };
        lab.channel = Some(
            ChannelServer::start(
                &lab.socket,
                Arc::clone(&lab.registry),
                Arc::clone(&lab.storage) as Arc<dyn Custody>,
                timing,
            )
            .unwrap(),
        );
        let mut source = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
        source.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "session"),
        );
        lab.publish(
            "flush-window",
            &lab.claude_address("session"),
            bridge_core::Mode::Inject,
            "owned hidden handoff",
        );
        let result = source.cmd(json!({"cmd": "delayed_hook", "socket": lab.socket, "harness": "ClaudeCode",
            "payload": tool_hook("PostToolUse", "session", "flush-call", None), "delay_ms": delay_ms, "fragment_gap_ms": gap_ms}));
        assert_eq!(result["inject"], true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while lab
            .attempt("flush-window")
            .is_some_and(|record| record.state == bridge_core::dispatch::AttemptState::Invoking)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            lab.attempt("flush-window").unwrap().state,
            if submitted {
                bridge_core::dispatch::AttemptState::HookSubmitted
            } else {
                bridge_core::dispatch::AttemptState::OutcomeUnknown
            }
        );
        source.stop();
    }
}
