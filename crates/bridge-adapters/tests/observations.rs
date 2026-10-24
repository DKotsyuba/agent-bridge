//! Exact read-grant controls over owned synthetic native processes and sockets.
mod common;
use bridge_core::{GrantConfig, Harness, ProducerAuthorizer};
use bridge_protocol::*;
use common::*;
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    sync::Arc,
};

/// Fixture-only read credential, never an installed deployment credential.
const TOKEN: &str = "synthetic-observation-grant";

/// Installs an explicit read-only grant with independently controlled scopes.
fn lab(enabled: bool, recipients: &[&str], scopes: &[&str]) -> Lab {
    let lab = Lab::new("ob");
    let grant: GrantConfig = serde_json::from_value(json!({
        "token":TOKEN,"publisher":"observer","recipients":recipients,
        "kinds":["*"],"modes":["message"],"policies":["keep_all"],
        "producer_v1":{"host_observations":enabled,"native_scopes":scopes}
    }))
    .unwrap();
    lab.storage
        .lock()
        .unwrap()
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&[grant]).unwrap()))
        .unwrap();
    lab
}

/// Performs one actual producer read from this test process with strict decoding.
fn read(lab: &Lab, operation: Operation) -> Response {
    let request = Request::new("read", Secret::new(TOKEN), operation).unwrap();
    let mut stream = UnixStream::connect(&lab.socket).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(&encode_request(&request).unwrap())
        .unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    decode_response(line.trim_end().as_bytes(), &request).unwrap()
}

/// Extracts an exact typed observation without exposing private lookup inputs.
fn observation(lab: &Lab, address: &str) -> RecipientObservationState {
    match read(
        lab,
        Operation::ObserveRecipient(ObserveRecipientParams {
            address: address.into(),
        }),
    )
    .result
    {
        Some(OperationResult::ObserveRecipient(r)) => r.observation,
        _ => panic!("expected observation result"),
    }
}

/// Explicit feature permission and both scope allowlists precede binding lookup;
/// core never advertises adapter-only reads even when its grant enables them.
#[test]
fn observation_grant_precedes_registry_lookup() {
    assert!(
        !serde_json::from_value::<bridge_core::ProducerPolicy>(json!({}))
            .unwrap()
            .host_observations
    );
    for (enabled, recipients, scopes) in [
        (false, vec!["*"], vec!["*"]),
        (true, vec!["other/codex/store/session"], vec!["*"]),
        (true, vec!["*"], vec!["other/codex/store"]),
    ] {
        let lab = lab(enabled, &recipients, &scopes);
        let core = lab.storage.lock().unwrap().capabilities_v1(TOKEN).unwrap();
        assert!(!core.features.host_observations);
        assert!(
            !core
                .operations
                .iter()
                .any(|op| op == "observe_recipient" || op == "resolve_recipient")
        );
        // A forbidden observation must complete while another owner holds the
        // registry lock: even a missing recipient must not reach that lookup.
        let locked = lab.registry.lock().unwrap();
        let result = read(
            &lab,
            Operation::ObserveRecipient(ObserveRecipientParams {
                address: "lab-host/codex/codex-lab/session".into(),
            }),
        );
        assert_eq!(result.error.as_ref().unwrap().class, ErrorClass::Forbidden);
        assert!(result.error.unwrap().effect.is_none());
        if !enabled {
            let result = read(
                &lab,
                Operation::ResolveRecipient(ResolveRecipientParams {
                    host: Host::Codex,
                    native_session_id: "session".into(),
                    expected_store: "/private/synthetic".into(),
                    expected_harness_pid: 1,
                    expected_harness_start_time_secs: 1,
                }),
            );
            assert_eq!(result.error.unwrap().class, ErrorClass::Forbidden);
        }
        drop(locked);
    }
}

/// Every supported harness resolves only the protected current process tuple;
/// unknown/input-wait are preserved, stale stores/PIDs/births and retirement fail
/// closed. Reads leave existing endpoint epochs and native admission intact.
#[test]
fn observation_exact_native_binding() {
    let lab = lab(true, &["*"], &["*"]);
    let capabilities = read(&lab, Operation::Capabilities(CapabilitiesParams {}));
    let Some(OperationResult::Capabilities(caps)) = capabilities.result else {
        panic!("capabilities");
    };
    assert!(caps.features.host_observations);
    assert!(
        caps.operations.contains(&"observe_recipient".into())
            && caps.operations.contains(&"resolve_recipient".into())
    );
    for (harness, host, store, address) in [
        (
            Harness::CODEX,
            Host::Codex,
            &lab.codex_store,
            lab.codex_address("session"),
        ),
        (
            Harness::CLAUDE_CODE,
            Host::ClaudeCode,
            &lab.claude_store,
            lab.claude_address("session"),
        ),
        (
            Harness::OPENCODE,
            Host::OpenCode,
            &lab.opencode_store,
            lab.opencode_address("session"),
        ),
    ] {
        let canonical = address.to_canonical_string();
        assert_eq!(
            observation(&lab, &canonical),
            RecipientObservationState::Unavailable
        );
        let mut process = Harnessed::start(harness, store);
        let mut initial = hook("SessionStart", "session");
        initial["source"] = json!("compact");
        process.hook(&lab.socket, harness, initial);
        let facts = bridge_adapters::os::process_facts(process.child.id()).unwrap();
        let params = ResolveRecipientParams {
            host,
            native_session_id: "session".into(),
            expected_store: store.to_str().unwrap().into(),
            expected_harness_pid: facts.pid,
            expected_harness_start_time_secs: facts.start_time,
        };
        for (event, lifecycle) in [
            ("SessionStart", RecipientLifecycle::Unknown),
            ("UserPromptSubmit", RecipientLifecycle::Active),
            ("Stop", RecipientLifecycle::Inactive),
            ("PermissionRequest", RecipientLifecycle::AwaitingInput),
        ] {
            let mut payload = hook(event, "session");
            payload["source"] = json!("compact");
            process.hook(&lab.socket, harness, payload);
            assert!(
                matches!(observation(&lab, &canonical), RecipientObservationState::Observed { lifecycle: actual, .. } if actual == lifecycle)
            );
            let reply = read(&lab, Operation::ResolveRecipient(params.clone()));
            assert!(
                matches!(reply.result, Some(OperationResult::ResolveRecipient(ResolveRecipientResult { resolution: RecipientResolution::Resolved { address }, .. })) if address == canonical)
            );
        }
        for change in 0..4 {
            let mut mismatch = params.clone();
            match change {
                0 => mismatch.expected_store.push_str("-other"),
                1 => mismatch.expected_harness_pid = i32::MAX as u32,
                2 => mismatch.expected_harness_start_time_secs += 1,
                _ => mismatch.native_session_id = "missing".into(),
            }
            assert!(matches!(
                read(&lab, Operation::ResolveRecipient(mismatch)).result,
                Some(OperationResult::ResolveRecipient(ResolveRecipientResult {
                    resolution: RecipientResolution::Unavailable,
                    ..
                }))
            ));
        }
        if harness == Harness::CLAUDE_CODE {
            process.hook(
                &lab.socket,
                harness,
                tool_hook("PreToolUse", "session", "unspent", None),
            );
            assert!(matches!(
                observation(&lab, &canonical),
                RecipientObservationState::Observed { .. }
            ));
            assert!(read(&lab, Operation::ResolveRecipient(params.clone())).success);
            let native = json!({"claudecode/toolUseId":"unspent"});
            assert_eq!(
                process.mcp(&lab.socket, native.clone())["ok"]["role"],
                "root"
            );
            assert_eq!(process.mcp(&lab.socket, native)["err"], "duplicate");
        }
        process.hook(&lab.socket, harness, hook("SessionEnd", "session"));
        assert_eq!(
            observation(&lab, &canonical),
            RecipientObservationState::Unavailable
        );
        assert!(matches!(
            read(&lab, Operation::ResolveRecipient(params)).result,
            Some(OperationResult::ResolveRecipient(ResolveRecipientResult {
                resolution: RecipientResolution::Unavailable,
                ..
            }))
        ));
    }
}
