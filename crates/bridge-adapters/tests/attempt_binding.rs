//! B1 protected-channel tests using only owned same-UID fixture processes.
#![cfg(target_os = "linux")]
use crate::common;

use bridge_adapters::registry::{
    BackendAudience, ManagedTools, Registry, RelayExecutable, RunReader, file_sha256,
};
use bridge_adapters::server::{ChannelServer, Custody, private_directory};
use bridge_core::dispatch::DispatchTiming;
use bridge_core::{GrantConfig, Harness, ProducerAuthorizer};
use common::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Synthetic test credentials, never associated with installed services.
const PRODUCER_TOKEN: &str = "synthetic-producer-credential-only";
/// Distinct synthetic configured Run reader credential.
const READER_TOKEN: &str = "synthetic-run-reader-credential-only";
/// Synthetic producer identity.
const PRODUCER: &str = "pool-fixture";
/// Synthetic Run reader identity.
const READER: &str = "run-fixture";
/// Synthetic launch UUID.
const LAUNCH: &str = "01234567-89ab-4cde-8fab-0123456789ab";
/// Synthetic complete security digest.
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Creates a distinct owned executable build by appending inert fixture bytes.
fn distinct_fixture(lab: &Lab, label: &str) -> RelayExecutable {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = lab.dir.0.join(format!("bridge-fixture-{label}"));
    std::fs::copy(fixture_exe(), &path).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(label.as_bytes())
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let written = metadata.mtime().max(metadata.ctime());
    while i64::try_from(now() / 1000).unwrap() <= written {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    RelayExecutable {
        sha256: file_sha256(&path).unwrap(),
        path,
    }
}

/// Installs two isolated producer grants and explicit protected executable routes.
fn lab() -> Lab {
    lab_with_other_producer(false)
}

/// Optionally includes a second isolated producer for scope-conflict tests.
fn lab_with_other_producer(include_other: bool) -> Lab {
    let mut lab = Lab::new("b1");
    let grant = |token: &str, name: &str, policy: Value| -> GrantConfig {
        serde_json::from_value(json!({"token":token,"publisher":name,"recipients":["*"],"kinds":["*"],"modes":["message","inject"],"policies":["keep_all"],"producer_v1":policy})).unwrap()
    };
    let mut grants = vec![
        grant(
            PRODUCER_TOKEN,
            PRODUCER,
            json!({"registration":true,"native_scopes":["*"],"assertion_audiences":["backend"],"delivery_scopes":true}),
        ),
        grant(READER_TOKEN, READER, json!({})),
    ];
    if include_other {
        grants.push(grant(
            "synthetic-other-producer-token", "other-pool",
            json!({"registration":true,"native_scopes":["*"],"assertion_audiences":["backend"],"delivery_scopes":true}),
        ));
        grants.push(grant(
            "synthetic-readonly-producer-token",
            "other-pool",
            json!({"assertion_audiences":["backend"],"delivery_scopes":false}),
        ));
    }
    lab.storage
        .lock()
        .unwrap()
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&grants).unwrap()))
        .unwrap();
    lab.channel.take().unwrap().stop();
    let exe = RelayExecutable {
        path: fixture_exe(),
        sha256: file_sha256(&fixture_exe()).unwrap(),
    };
    let consumer = distinct_fixture(&lab, "consumer");
    let reader = distinct_fixture(&lab, "reader");
    lab.config.audiences.push(BackendAudience {
        name: "backend".into(),
        producer: PRODUCER.into(),
        executable: consumer,
    });
    lab.config.run_readers.push(RunReader {
        producer: PRODUCER.into(),
        reader: READER.into(),
        executable: reader,
    });
    lab.config.managed_tools.push(ManagedTools {
        producer: PRODUCER.into(),
        server: "pool".into(),
        commands: vec!["vote".into()],
        frontend: exe,
    });
    restart(&mut lab);
    lab
}

/// Restarts only this owned channel, registry and its private route journal.
fn restart(lab: &mut Lab) {
    if let Some(channel) = lab.channel.take() {
        channel.stop();
    }
    let owner = private_directory(lab.socket.parent().unwrap()).unwrap();
    lab.registry = Arc::new(Mutex::new(
        Registry::new(lab.config.clone(), owner).unwrap(),
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

/// Starts the distinct configured Run-reader fixture build.
fn start_reader(lab: &Lab) -> Harnessed {
    Harnessed::start_from(
        &lab.config.run_readers[0].executable.path,
        Harness::CLAUDE_CODE,
        &lab.claude_store,
    )
}

/// Starts the distinct configured consumer fixture build.
fn start_consumer(lab: &Lab) -> Harnessed {
    Harnessed::start_from(
        &lab.config.audiences[0].executable.path,
        Harness::CLAUDE_CODE,
        &lab.claude_store,
    )
}

/// Builds a synthetic versioned request.
fn request(token: &str, request_id: &str, op: &str, params: Value) -> Value {
    json!({"api_version":1,"request_id":request_id,"credential":token,"op":op,"params":params})
}

/// Exchanges a request through a fixture child or directly as a fixture reader.
fn call(harness: &mut Harnessed, lab: &Lab, request: Value, direct: bool) -> Value {
    harness.cmd(
        json!({"cmd":if direct {"v1_direct"} else {"b1"},"socket":lab.socket,"request":request}),
    )
}

/// Exchanges a managed request from one persistent stdio frontend PID.
fn session_call(harness: &mut Harnessed, request: Value) -> Value {
    harness.cmd(json!({"cmd":"b1_session_request","request":request}))
}

/// Extracts the managed result without printing credentials or returned keys.
fn value(response: &Value) -> &Value {
    &response["result"]["value"]
}

/// A shared executable is usable by a newly started detached resident, while
/// the actual frontend and any consumer beneath a managed harness are refused.
/// The bootstrap point and frontend incarnation survive a Bridge restart.
#[test]
fn same_build_frontend_and_consumer_require_distinct_process_roles() {
    let mut lab = Lab::new("shared-roles");
    let executable = RelayExecutable {
        path: fixture_exe(),
        sha256: file_sha256(&fixture_exe()).unwrap(),
    };
    // This process predates first managed enable and must be relaunched.
    let mut early =
        Harnessed::start_from(&executable.path, Harness::CLAUDE_CODE, &lab.claude_store);
    let reader_executable = distinct_fixture(&lab, "shared-reader");
    let separate_executable = distinct_fixture(&lab, "preexisting-separate-consumer");
    let mut early_separate = Harnessed::start_from(
        &separate_executable.path,
        Harness::CLAUDE_CODE,
        &lab.claude_store,
    );
    let grant = |token: &str, name: &str, policy: Value| -> GrantConfig {
        serde_json::from_value(json!({"token":token,"publisher":name,"recipients":["*"],"kinds":["*"],"modes":["message","inject"],"policies":["keep_all"],"producer_v1":policy})).unwrap()
    };
    let grants = [
        grant(
            PRODUCER_TOKEN,
            PRODUCER,
            json!({"registration":true,"native_scopes":["*"],"assertion_audiences":["backend","isolated"],"delivery_scopes":true}),
        ),
        grant(READER_TOKEN, READER, json!({})),
    ];
    lab.storage
        .lock()
        .unwrap()
        .install_producer_authorizer(Arc::new(ProducerAuthorizer::new(&grants).unwrap()))
        .unwrap();
    lab.config.audiences.push(BackendAudience {
        name: "backend".into(),
        producer: PRODUCER.into(),
        executable: executable.clone(),
    });
    lab.config.audiences.push(BackendAudience {
        name: "isolated".into(),
        producer: PRODUCER.into(),
        executable: separate_executable,
    });
    lab.config.managed_tools.push(ManagedTools {
        producer: PRODUCER.into(),
        server: "pool".into(),
        commands: vec!["vote".into()],
        frontend: executable.clone(),
    });
    lab.config.run_readers.push(RunReader {
        producer: PRODUCER.into(),
        reader: READER.into(),
        executable: reader_executable,
    });
    restart(&mut lab);

    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);
    let separate_abort = request(
        PRODUCER_TOKEN,
        "separate-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"separate-consume","invocation_key":"separate-inv","security_digest":DIGEST,"audience":"isolated"}),
    );
    assert_eq!(
        value(&call(&mut early_separate, &lab, separate_abort, true))["value"]["aborted"],
        true
    );
    pre(&mut source, &lab, "expired-role-call", "mcp__pool__vote");
    let expire_prepare = request(
        PRODUCER_TOKEN,
        "expired-role-prepare",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"expired-role-inv","command_name":"vote","native_proof":proof("expired-role-call")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, expire_prepare, false))["status"],
        "ok"
    );
    lab.registry
        .lock()
        .unwrap()
        .fixture_expire_managed(
            now()
                .saturating_add(lab.config.max_call_age_ms)
                .saturating_add(1),
        )
        .unwrap();
    let expired_consume = request(
        PRODUCER_TOKEN,
        "expired-role-consume",
        "consume_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"assertion_key":"expired-key","invocation_key":"expired-role-inv","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut early, &lab, expired_consume, true))["error"]["code"],
        "relaunch_required"
    );
    pre(&mut source, &lab, "shared-call", "mcp__pool__vote");
    let session = source.cmd(json!({"cmd":"b1_session_start","socket":lab.socket}));
    let frontend_pid = session["pid"].as_u64().unwrap();
    let prepare = request(
        PRODUCER_TOKEN,
        "shared-prepare",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"shared-inv","command_name":"vote","native_proof":proof("shared-call")}),
    );
    let prepared = session_call(&mut source, prepare);
    assert_eq!(value(&prepared)["status"], "ok");
    let reference = value(&prepared)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap()
        .to_string();
    let register = request(
        PRODUCER_TOKEN,
        "shared-register",
        "register_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"bridge_context_ref":reference,"invocation_key":"shared-inv","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"shared-nonce","native_proof":proof("shared-call")}),
    );
    let registered = session_call(&mut source, register);
    assert_eq!(value(&registered)["status"], "ok");
    let key = value(&registered)["value"]["assertion_key"]
        .as_str()
        .unwrap()
        .to_string();
    let consume = request(
        PRODUCER_TOKEN,
        "shared-consume",
        "consume_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"assertion_key":key,"invocation_key":"shared-inv","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&session_call(&mut source, consume.clone()))["error"]["code"],
        "peer_not_authorized"
    );
    assert_eq!(
        value(&call(&mut source, &lab, consume.clone(), false))["error"]["code"],
        "peer_not_authorized"
    );
    assert_eq!(
        value(&call(&mut source, &lab, consume.clone(), true))["error"]["code"],
        "peer_not_authorized"
    );
    let nested = source
        .cmd(json!({"cmd":"b1","socket":lab.socket,"request":consume.clone(),"nested_depth":12}));
    assert_eq!(value(&nested)["error"]["code"], "peer_not_authorized");
    let mut unobserved =
        Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    assert_eq!(
        value(&call(&mut unobserved, &lab, consume.clone(), false))["error"]["code"],
        "peer_not_authorized"
    );
    let early_result = call(&mut early, &lab, consume.clone(), true);
    assert_eq!(value(&early_result)["error"]["code"], "relaunch_required");
    assert_eq!(value(&early_result)["error"]["recovery"], "none");

    // Only the resident process is restarted; it uses the very same build.
    early.stop();
    let mut resident =
        Harnessed::start_from(&executable.path, Harness::CLAUDE_CODE, &lab.claude_store);
    let consumed = call(&mut resident, &lab, consume.clone(), true);
    assert_eq!(value(&consumed)["value"]["validity"], "current");
    let role_path = lab
        .socket
        .with_extension("bindings.json")
        .with_extension("frontend-roles.json");
    let before: Value = serde_json::from_slice(&std::fs::read(&role_path).unwrap()).unwrap();
    assert!(
        before["frontends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["pid"] == frontend_pid)
    );
    restart(&mut lab);
    let after: Value = serde_json::from_slice(&std::fs::read(&role_path).unwrap()).unwrap();
    assert_eq!(before["initialized_ticks"], after["initialized_ticks"]);
    assert!(
        after["frontends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["pid"] == frontend_pid)
    );
    let lookup = request(
        PRODUCER_TOKEN,
        "shared-lookup",
        "observation_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"shared-consume","invocation_key":"shared-inv","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut resident, &lab, lookup.clone(), true))["value"]["validity"],
        "historical"
    );
    assert_eq!(
        value(&session_call(&mut source, lookup))["error"]["code"],
        "peer_not_authorized"
    );
    assert_eq!(source.cmd(json!({"cmd":"b1_session_stop"}))["ok"], true);

    // Losing the independent role table establishes a new bootstrap point,
    // so the formerly valid same-build resident must be started again.
    lab.channel.take().unwrap().stop();
    std::fs::remove_file(&role_path).unwrap();
    restart(&mut lab);
    let again = request(
        PRODUCER_TOKEN,
        "shared-lookup-after-loss",
        "observation_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"shared-consume","invocation_key":"shared-inv","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut resident, &lab, again.clone(), true))["error"]["code"],
        "relaunch_required"
    );
    resident.stop();
    std::thread::sleep(std::time::Duration::from_millis(25));
    let mut replacement =
        Harnessed::start_from(&executable.path, Harness::CLAUDE_CODE, &lab.claude_store);
    assert_eq!(
        value(&call(&mut replacement, &lab, again, true))["value"]["validity"],
        "historical"
    );
}

/// Discovery does not refuse a genuine stdio harness merely because two
/// configured marker/store combinations identify the same ancestor; the
/// protected hook and exact native proof still select the actual actor.
#[test]
fn frontend_with_overlapping_harness_markers_remains_qualified() {
    let lab = lab();
    let mut source = Harnessed::start_with_dual_stores(&lab.claude_store, &lab.codex_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "dual-marker-call", "mcp__pool__vote");
    let prepare = request(
        PRODUCER_TOKEN,
        "dual-marker-prepare",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"dual-marker-inv","command_name":"vote","native_proof":proof("dual-marker-call")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, prepare, false))["status"],
        "ok"
    );
}

/// A future or corrupt role journal cannot authorize managed operations and
/// never prevents independent legacy hook routing.
#[test]
fn invalid_frontend_role_journal_fences_managed_only() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let mut reader = start_reader(&lab);
    let (store, _) = discover(&mut source, &lab);
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"legacy-role"})
        )["status"],
        0
    );
    lab.channel.take().unwrap().stop();
    let path = lab
        .socket
        .with_extension("bindings.json")
        .with_extension("frontend-roles.json");
    let mut journal: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    journal["schema"] = json!(2);
    let future = serde_json::to_vec(&journal).unwrap();
    std::fs::write(&path, &future).unwrap();
    restart(&mut lab);
    let discovery = request(
        READER_TOKEN,
        "corrupt-role-discovery",
        "attempt_binding_capabilities_v1",
        json!({"version":1}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, discovery, true))["error"]["code"],
        "recovery_required"
    );
    let abort = request(
        PRODUCER_TOKEN,
        "corrupt-role-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"corrupt-role","invocation_key":"corrupt-role","security_digest":DIGEST,"audience":"backend"}),
    );
    let refused = call(&mut consumer, &lab, abort, true);
    assert_eq!(value(&refused)["error"]["code"], "recovery_required");
    assert_eq!(value(&refused)["error"]["recovery"], "operator");
    assert_eq!(std::fs::read(&path).unwrap(), future);
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"Stop","session_id":"legacy-role"})
        )["status"],
        0
    );
    assert_eq!(
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("legacy-role"))
            .unwrap()
            .0
            .lifecycle(),
        bridge_core::dispatch::Lifecycle::Inactive
    );
}

/// A failed role commit fences managed authority but leaves legacy hooks live;
/// restarting reloads the last committed role table without inventing proof.
#[test]
fn failed_frontend_role_commit_fences_managed_only() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let (store, _) = discover(&mut source, &lab);
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"role-fault"})
        )["status"],
        0
    );
    let original = lab
        .registry
        .lock()
        .unwrap()
        .fixture_fail_frontend_role_commit();
    let abort = request(
        PRODUCER_TOKEN,
        "role-fault-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"role-fault","invocation_key":"role-fault","security_digest":DIGEST,"audience":"backend"}),
    );
    let failed = call(&mut consumer, &lab, abort.clone(), true);
    assert_eq!(value(&failed)["error"]["code"], "recovery_required");
    assert_eq!(value(&failed)["error"]["recovery"], "same_key_lookup");
    lab.registry
        .lock()
        .unwrap()
        .fixture_restore_frontend_role_commit(original);
    assert_eq!(
        value(&call(&mut consumer, &lab, abort.clone(), true))["error"]["recovery"],
        "same_key_lookup"
    );
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"Stop","session_id":"role-fault"})
        )["status"],
        0
    );
    assert_eq!(
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("role-fault"))
            .unwrap()
            .0
            .lifecycle(),
        bridge_core::dispatch::Lifecycle::Inactive
    );
    restart(&mut lab);
    assert_eq!(
        value(&call(&mut consumer, &lab, abort, true))["value"]["aborted"],
        true
    );
}

/// Builds protected metadata for one synthetic Claude MCP call.
fn proof(call: &str) -> Value {
    json!({"type":"native","host":"claude_code","metadata":{"claudecode/toolUseId":call}})
}

/// Issues the real protected hook with a specific exact MCP tool name.
fn pre(harness: &mut Harnessed, lab: &Lab, call_id: &str, tool: &str) {
    let response = harness.hook(&lab.socket, Harness::CLAUDE_CODE, json!({"hook_event_name":"PreToolUse","session_id":"session","tool_use_id":call_id,"tool_name":tool}));
    assert_eq!(response["status"], 0);
}

/// Discovers the durable ID through the protected channel.
fn discover(harness: &mut Harnessed, lab: &Lab) -> (String, String) {
    let reply = call(
        harness,
        lab,
        request(
            PRODUCER_TOKEN,
            "discover",
            "attempt_binding_capabilities_v1",
            json!({"version":1}),
        ),
        false,
    );
    assert_eq!(value(&reply)["status"], "ok");
    (
        value(&reply)["value"]["store_id"]
            .as_str()
            .unwrap()
            .to_string(),
        value(&reply)["value"]["issuer_epoch"]
            .as_str()
            .unwrap()
            .to_string(),
    )
}

/// Discovery grants no authority: the stdio frontend and the pinned audience
/// resident both receive it, any unpinned peer or unconfigured producer is
/// refused, and the resident keeps every frontend-only refusal.
#[test]
fn discovery_answers_pinned_resident_without_granting_authority() {
    let lab = lab_with_other_producer(true);
    let discovery = |id: &str, token: &str| {
        request(
            token,
            id,
            "attempt_binding_capabilities_v1",
            json!({"version":1}),
        )
    };
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);

    let mut resident = start_consumer(&lab);
    let reply = call(
        &mut resident,
        &lab,
        discovery("resident-discover", PRODUCER_TOKEN),
        true,
    );
    assert_eq!(value(&reply)["status"], "ok");
    let found = &value(&reply)["value"];
    assert_eq!(found["version"], 1);
    assert_eq!(found["store_id"], json!(store));
    assert_eq!(found["issuer_epoch"], json!(issuer));
    let capabilities = found["capabilities"].as_array().unwrap();
    assert!(capabilities.contains(&json!("attempt_launch_v1")));
    assert!(capabilities.contains(&json!("run_actor_lookup_v1")));
    // No owner-v2 route is configured, so none is advertised to anyone.
    assert!(!capabilities.contains(&json!("managed_owner_v2")));
    // The frontend is still answered after the resident discovered.
    discover(&mut source, &lab);

    // An unpinned executable cannot use the producer credential to discover.
    let mut reader = start_reader(&lab);
    let mut foreign = Harnessed::start_from(
        &distinct_fixture(&lab, "foreign-resident").path,
        Harness::CLAUDE_CODE,
        &lab.claude_store,
    );
    for (name, harness) in [("reader", &mut reader), ("foreign", &mut foreign)] {
        let refused = call(
            harness,
            &lab,
            discovery(&format!("{name}-discover"), PRODUCER_TOKEN),
            true,
        );
        assert_eq!(value(&refused)["error"]["code"], "peer_not_authorized");
        assert!(value(&refused)["value"].is_null());
    }
    // A producer without a managed route is not answered, even to a pinned build.
    let unconfigured = call(
        &mut resident,
        &lab,
        discovery("unconfigured-discover", "synthetic-other-producer-token"),
        true,
    );
    assert_eq!(value(&unconfigured)["error"]["code"], "peer_not_authorized");

    // Discovery never widens authority: frontend-only operations stay refused.
    let prepare = request(
        PRODUCER_TOKEN,
        "resident-prepare",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"resident-inv","command_name":"vote","native_proof":proof("resident-call")}),
    );
    let refused = call(&mut resident, &lab, prepare, true);
    assert_eq!(value(&refused)["status"], "error");
    assert!(
        ["peer_not_authorized", "transport_unsupported"]
            .contains(&value(&refused)["error"]["code"].as_str().unwrap())
    );
    let register = request(
        PRODUCER_TOKEN,
        "resident-register",
        "register_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"bridge_context_ref":"x","invocation_key":"resident-inv","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"n","native_proof":proof("resident-call")}),
    );
    assert_eq!(
        value(&call(&mut resident, &lab, register, true))["status"],
        "error"
    );
}

/// Launch must have been in the original exec environment, and the exact
/// configured native tool name must agree with the command name.
#[test]
fn launch_env_direct_checked_and_exact_tool_mapping() {
    let lab = lab();
    let mut absent = Harnessed::start(Harness::CLAUDE_CODE, &lab.claude_store);
    let (store, issuer) = discover(&mut absent, &lab);
    pre(&mut absent, &lab, "missing", "mcp__pool__vote");
    let params = |call: &str, command: &str| json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":format!("inv-{call}"),"command_name":command,"native_proof":proof(call)});
    let mut invalid = params("missing", "vote");
    invalid["version"] = json!(2);
    assert_eq!(
        value(&call(
            &mut absent,
            &lab,
            request(
                PRODUCER_TOKEN,
                "bad-version",
                "prepare_native_context_v1",
                invalid
            ),
            false
        ))["error"]["code"],
        "unsupported_version"
    );
    let mut invalid = params("missing", "vote");
    invalid["expected_store_id"] = json!(format!("different-{store}"));
    assert_eq!(
        value(&call(
            &mut absent,
            &lab,
            request(
                PRODUCER_TOKEN,
                "bad-store",
                "prepare_native_context_v1",
                invalid
            ),
            false
        ))["error"]["code"],
        "recovery_required"
    );
    let mut invalid = params("missing", "vote");
    invalid["unknown"] = json!(true);
    assert_eq!(
        value(&call(
            &mut absent,
            &lab,
            request(
                PRODUCER_TOKEN,
                "bad-field",
                "prepare_native_context_v1",
                invalid
            ),
            false
        ))["status"],
        "error"
    );
    let mut invalid = params("missing", "vote");
    invalid["expected_issuer_epoch"] = json!("old-issuer");
    assert_eq!(
        value(&call(
            &mut absent,
            &lab,
            request(
                PRODUCER_TOKEN,
                "bad-issuer",
                "prepare_native_context_v1",
                invalid
            ),
            false
        ))["error"]["code"],
        "assertion_stale"
    );
    let missing = call(
        &mut absent,
        &lab,
        request(
            PRODUCER_TOKEN,
            "missing",
            "prepare_native_context_v1",
            params("missing", "vote"),
        ),
        false,
    );
    assert_eq!(value(&missing)["error"]["code"], "attempt_not_ready");
    absent.stop();
    let mut present = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    pre(&mut present, &lab, "missing", "mcp__pool__vote");
    let no_repair = call(
        &mut present,
        &lab,
        request(
            PRODUCER_TOKEN,
            "no-repair",
            "prepare_native_context_v1",
            params("missing", "vote"),
        ),
        false,
    );
    assert_eq!(value(&no_repair)["error"]["code"], "attempt_not_ready");
    pre(&mut present, &lab, "wrong", "mcp__pool__not_vote");
    let wrong = call(
        &mut present,
        &lab,
        request(
            PRODUCER_TOKEN,
            "wrong",
            "prepare_native_context_v1",
            params("wrong", "vote"),
        ),
        false,
    );
    assert_eq!(value(&wrong)["error"]["code"], "route_mismatch");
    pre(&mut present, &lab, "right", "mcp__pool__vote");
    let right = call(
        &mut present,
        &lab,
        request(
            PRODUCER_TOKEN,
            "right",
            "prepare_native_context_v1",
            params("right", "vote"),
        ),
        false,
    );
    assert_eq!(value(&right)["status"], "ok");
}

/// Consumption is durable before ACK; restart makes the original receipt
/// historical, and abort persists its fence before a delayed consume arrives.
#[test]
fn bridge_restart_consume_lookup_and_consume_abort_delayed() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut backend = start_consumer(&lab);
    let mut reader = start_reader(&lab);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "nonstdio", "mcp__pool__vote");
    let nonstdio = request(
        PRODUCER_TOKEN,
        "nonstdio",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"nonstdio","command_name":"vote","native_proof":proof("nonstdio")}),
    );
    let refused =
        source.cmd(json!({"cmd":"b1","socket":lab.socket,"request":nonstdio,"non_stdio":true}));
    assert_eq!(value(&refused)["error"]["code"], "transport_unsupported");
    pre(&mut source, &lab, "call-a", "mcp__pool__vote");
    let prep = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "prepare-a",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"inv-a","command_name":"vote","native_proof":proof("call-a")}),
        ),
        false,
    );
    assert_eq!(value(&prep)["status"], "ok");
    let wrong_frontend = request(
        PRODUCER_TOKEN,
        "wrong-frontend",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"wrong-frontend","command_name":"vote","native_proof":proof("call-a")}),
    );
    assert_eq!(
        value(&call(&mut backend, &lab, wrong_frontend, true))["error"]["code"],
        "peer_not_authorized"
    );
    let duplicate_call = request(
        PRODUCER_TOKEN,
        "second-inv",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"inv-second","command_name":"vote","native_proof":proof("call-a")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, duplicate_call, false))["error"]["code"],
        "invocation_spent"
    );
    let reference = value(&prep)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let bootstrap = call(
        &mut reader,
        &lab,
        request(
            READER_TOKEN,
            "bootstrap",
            "context_lookup_v1",
            json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"bridge_context_ref":reference,"invocation_key":"inv-a"}),
        ),
        true,
    );
    let unauthorized = call(
        &mut backend,
        &lab,
        request(
            PRODUCER_TOKEN,
            "bad-reader",
            "context_lookup_v1",
            json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"bridge_context_ref":reference,"invocation_key":"inv-a"}),
        ),
        true,
    );
    assert_eq!(value(&unauthorized)["error"]["code"], "peer_not_authorized");
    let wrong_reader = request(
        READER_TOKEN,
        "wrong-reader",
        "context_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"bridge_context_ref":reference,"invocation_key":"inv-a"}),
    );
    assert_eq!(
        value(&call(&mut backend, &lab, wrong_reader.clone(), true))["error"]["code"],
        "peer_not_authorized"
    );
    assert_eq!(
        value(&call(&mut source, &lab, wrong_reader, false))["error"]["code"],
        "peer_not_authorized"
    );
    assert_eq!(value(&bootstrap)["value"]["validity"], "current");
    assert_eq!(
        value(&bootstrap)["value"]["observation"]["launch_id"],
        LAUNCH
    );
    let registration_request = request(
        PRODUCER_TOKEN,
        "register-a",
        "register_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"bridge_context_ref":reference,"invocation_key":"inv-a","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"nonce-a","native_proof":proof("call-a")}),
    );
    let registration = call(&mut source, &lab, registration_request.clone(), false);
    assert_eq!(value(&registration)["status"], "ok");
    for (field, changed) in [
        ("security_digest", json!("b".repeat(64))),
        ("nonce", json!("changed")),
        ("audience", json!("foreign")),
    ] {
        let mut modified = registration_request.clone();
        modified["params"][field] = changed;
        assert_eq!(
            value(&call(&mut source, &lab, modified, false))["status"],
            "error"
        );
    }
    let key = value(&registration)["value"]["assertion_key"]
        .as_str()
        .unwrap();
    let consume = request(
        PRODUCER_TOKEN,
        "consume-a",
        "consume_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"assertion_key":key,"invocation_key":"inv-a","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, consume.clone(), false))["status"],
        "error"
    );
    assert_eq!(
        value(&call(&mut reader, &lab, consume.clone(), true))["status"],
        "error"
    );
    let first = call(&mut backend, &lab, consume.clone(), true);
    assert_eq!(value(&first)["value"]["validity"], "current");
    assert!(
        lab.registry
            .lock()
            .unwrap()
            .fixture_evict_spent_call("call-a")
    );
    pre(&mut source, &lab, "call-a", "mcp__pool__vote");
    let repeated_source = request(
        PRODUCER_TOKEN,
        "repeat-source",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"repeat-source","command_name":"vote","native_proof":proof("call-a")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, repeated_source, false))["error"]["code"],
        "invocation_spent"
    );
    let mut different_request = consume.clone();
    different_request["request_id"] = json!("consume-other");
    assert_eq!(
        value(&call(&mut backend, &lab, different_request, true))["error"]["code"],
        "invocation_spent"
    );
    let receipt = value(&first)["value"]["receipt"].clone();
    restart(&mut lab);
    let lookup = request(
        READER_TOKEN,
        "lookup-a",
        "observation_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"consume-a","invocation_key":"inv-a","security_digest":DIGEST}),
    );
    let historical = call(&mut reader, &lab, lookup.clone(), true);
    assert_eq!(value(&historical)["value"]["validity"], "historical");
    assert_eq!(value(&historical)["value"]["receipt"], receipt);
    let persisted = std::fs::read(
        lab.socket
            .with_extension("bindings.json")
            .with_extension("attempts.json"),
    )
    .unwrap();
    assert!(
        !persisted
            .windows(reference.len())
            .any(|part| part == reference.as_bytes())
    );
    assert!(
        !persisted
            .windows(key.len())
            .any(|part| part == key.as_bytes())
    );
    let abort = request(
        PRODUCER_TOKEN,
        "abort-a",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"consume-a","invocation_key":"inv-a","security_digest":DIGEST,"audience":"backend"}),
    );
    let aborted = call(&mut backend, &lab, abort.clone(), true);
    assert_eq!(value(&aborted)["value"]["receipt"], receipt);
    assert_eq!(
        value(&call(&mut reader, &lab, lookup.clone(), true))["value"]["aborted"],
        true
    );
    assert_eq!(
        value(&call(&mut backend, &lab, consume.clone(), true))["value"]["aborted"],
        true
    );
    let retire = request(
        READER_TOKEN,
        "retire-a",
        "retire_attempt_namespace_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"issuer_epoch":issuer,"retirement_key":"retire-a"}),
    );
    let (_, current_issuer) = discover(&mut source, &lab);
    let mut current_retire = retire.clone();
    current_retire["params"]["issuer_epoch"] = json!(current_issuer);
    assert_eq!(
        value(&call(&mut reader, &lab, current_retire, true))["error"]["code"],
        "intent_conflict"
    );
    assert_eq!(
        value(&call(&mut backend, &lab, retire.clone(), true))["error"]["code"],
        "peer_not_authorized"
    );
    let retired = call(&mut reader, &lab, retire.clone(), true);
    assert_eq!(value(&retired)["value"]["retired_count"], 1);
    let replayed_abort = call(&mut backend, &lab, abort.clone(), true);
    assert_eq!(value(&replayed_abort)["value"]["aborted"], true);
    assert!(value(&replayed_abort)["value"]["receipt"].is_null());
    let empty_retire = request(
        READER_TOKEN,
        "retire-empty",
        "retire_attempt_namespace_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"issuer_epoch":"empty-old-issuer","retirement_key":"retire-empty"}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, empty_retire.clone(), true))["error"]["code"],
        "binding_unavailable"
    );
    let mut changed_retire = retire.clone();
    changed_retire["params"]["issuer_epoch"] = json!("different-old-issuer");
    assert_eq!(
        value(&call(&mut reader, &lab, changed_retire, true))["error"]["code"],
        "intent_conflict"
    );
    assert_eq!(
        value(&call(&mut reader, &lab, retire.clone(), true)),
        value(&retired)
    );
    assert_eq!(
        value(&call(&mut reader, &lab, lookup, true))["error"]["code"],
        "assertion_historical"
    );
    assert_eq!(
        value(&call(&mut backend, &lab, consume, true))["error"]["code"],
        "aborted"
    );
    pre(&mut source, &lab, "call-a", "mcp__pool__vote");
    let retired_source = request(
        PRODUCER_TOKEN,
        "retired-source",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":current_issuer,"invocation_key":"retired-source","command_name":"vote","native_proof":proof("call-a")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, retired_source, false))["error"]["code"],
        "invocation_spent"
    );
    let absent = request(
        PRODUCER_TOKEN,
        "abort-b",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"consume-b","invocation_key":"inv-b","security_digest":DIGEST,"audience":"backend"}),
    );
    assert_eq!(
        value(&call(&mut backend, &lab, absent.clone(), true))["value"]["aborted"],
        true
    );
    let delayed_consume = request(
        PRODUCER_TOKEN,
        "consume-b",
        "consume_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"assertion_key":"unissued-key","invocation_key":"inv-b","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut backend, &lab, delayed_consume, true))["error"]["code"],
        "aborted"
    );
    restart(&mut lab);
    assert_eq!(
        value(&call(&mut reader, &lab, empty_retire, true))["error"]["code"],
        "binding_unavailable"
    );
    assert_eq!(
        value(&call(&mut backend, &lab, abort, true))["value"]["aborted"],
        true
    );
    assert_eq!(
        value(&call(&mut reader, &lab, retire, true)),
        value(&retired)
    );
    assert_eq!(
        value(&call(&mut backend, &lab, absent, true))["value"]["aborted"],
        true
    );
    let (_, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "call-b", "mcp__pool__vote");
    let delayed = request(
        PRODUCER_TOKEN,
        "prepare-b",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"inv-b","command_name":"vote","native_proof":proof("call-b")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, delayed, false))["error"]["code"],
        "aborted"
    );
}

/// A fresh process at the same native address cannot make an older observation
/// current, even when it reuses the native call ID and session label.
#[test]
fn stale_incarnation_and_process_address_reuse() {
    let lab = lab();
    let mut old = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut reader = start_reader(&lab);
    let (store, issuer) = discover(&mut old, &lab);
    pre(&mut old, &lab, "same-call", "mcp__pool__vote");
    let params = |invocation: &str| json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":invocation,"command_name":"vote","native_proof":proof("same-call")});
    let original = call(
        &mut old,
        &lab,
        request(
            PRODUCER_TOKEN,
            "old-prep",
            "prepare_native_context_v1",
            params("old-inv"),
        ),
        false,
    );
    assert_eq!(value(&original)["status"], "ok");
    let reference = value(&original)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let lookup = request(
        READER_TOKEN,
        "old-context",
        "context_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"bridge_context_ref":reference,"invocation_key":"old-inv"}),
    );
    let current_context = call(&mut reader, &lab, lookup.clone(), true);
    assert_eq!(value(&current_context)["value"]["validity"], "current");
    let actor_lookup = request(
        READER_TOKEN,
        "old-actor",
        "run_actor_lookup_v1",
        json!({"version":1,
        "expected_store_id":store,"producer":PRODUCER,"incarnation":value(&current_context)["value"]["observation"]["incarnation"],"launch_id":LAUNCH}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, actor_lookup.clone(), true))["value"]["state"],
        "current"
    );
    old.stop();
    assert_eq!(
        value(&call(&mut reader, &lab, actor_lookup.clone(), true))["value"]["state"],
        "historical"
    );
    assert_eq!(
        value(&call(&mut reader, &lab, lookup.clone(), true))["value"]["validity"],
        "historical"
    );
    assert_eq!(
        value(&call(&mut reader, &lab, actor_lookup, true))["value"]["state"],
        "unavailable"
    );
    let mut replacement = Harnessed::start_with_launch(
        Harness::CLAUDE_CODE,
        &lab.claude_store,
        "11234567-89ab-4cde-8fab-0123456789ab",
    );
    pre(&mut replacement, &lab, "same-call", "mcp__pool__vote");
    let fresh = call(
        &mut replacement,
        &lab,
        request(
            PRODUCER_TOKEN,
            "new-prep",
            "prepare_native_context_v1",
            params("new-inv"),
        ),
        false,
    );
    assert_eq!(value(&fresh)["status"], "ok");
    assert_eq!(
        value(&call(&mut reader, &lab, lookup, true))["error"]["code"],
        "assertion_historical"
    );
}

/// Managed hook, caller join, and recovery remain on the same full identity
/// even when synthetic legacy seconds disagree; no epoch is replaced.
#[test]
fn managed_full_identity_ignores_legacy_seconds_without_renewal() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut reader = start_reader(&lab);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "skew-a", "mcp__pool__vote");
    lab.registry
        .lock()
        .unwrap()
        .fixture_skew_legacy_seconds(&lab.claude_address("session"), "skew-a");
    let recipient_epoch = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&lab.claude_address("session"))
        .expect("managed recipient ignores legacy seconds")
        .0
        .endpoint_epoch();
    let prepare = |call: &str, invocation: &str| {
        request(
            PRODUCER_TOKEN,
            invocation,
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":invocation,"command_name":"vote","native_proof":proof(call)}),
        )
    };
    let first = call(&mut source, &lab, prepare("skew-a", "skew-inv-a"), false);
    assert_eq!(value(&first)["status"], "ok");
    let reference = value(&first)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let lookup = |reference: &str, invocation: &str| {
        request(
            READER_TOKEN,
            "lookup-skew",
            "context_lookup_v1",
            json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"bridge_context_ref":reference,"invocation_key":invocation}),
        )
    };
    let original = call(&mut reader, &lab, lookup(reference, "skew-inv-a"), true);
    assert_eq!(value(&original)["value"]["validity"], "current");
    let epoch = value(&original)["value"]["observation"]["actor"]["epoch"]
        .as_u64()
        .unwrap();
    assert_eq!(epoch, recipient_epoch);
    source.hook(&lab.socket, Harness::CLAUDE_CODE, hook("Stop", "session"));
    assert_eq!(
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("session"))
            .unwrap()
            .0
            .endpoint_epoch(),
        epoch
    );
    pre(&mut source, &lab, "skew-b", "mcp__pool__vote");
    let second = call(&mut source, &lab, prepare("skew-b", "skew-inv-b"), false);
    assert_eq!(value(&second)["status"], "ok");
    let second_ref = value(&second)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let next = call(&mut reader, &lab, lookup(second_ref, "skew-inv-b"), true);
    assert_eq!(
        value(&next)["value"]["observation"]["actor"]["epoch"],
        epoch
    );
    assert_eq!(
        value(&call(
            &mut reader,
            &lab,
            lookup(reference, "skew-inv-a"),
            true
        ))["value"]["validity"],
        "current"
    );
    restart(&mut lab);
    pre(&mut source, &lab, "skew-c", "mcp__pool__vote");
    let stale = call(&mut source, &lab, prepare("skew-c", "skew-inv-c"), false);
    assert_eq!(value(&stale)["error"]["code"], "assertion_stale");
    let (_, new_issuer) = discover(&mut source, &lab);
    let recovered = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "skew-inv-c",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":new_issuer,"invocation_key":"skew-inv-c","command_name":"vote","native_proof":proof("skew-c")}),
        ),
        false,
    );
    assert_eq!(value(&recovered)["status"], "ok");
}

/// Owner selection verifies the same kernel incarnation and direct-parent
/// relationship even if the legacy seconds field has been synthetically skewed.
#[test]
fn managed_owner_lookup_ignores_legacy_seconds() {
    use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
    use bridge_core::dispatch::DispatchCarrier;
    let lab = lab();
    let mut native = Harnessed::start_owned(
        Harness::CLAUDE_CODE,
        &lab.claude_store,
        &lab.dir.0.join("ow"),
    );
    native.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        hook("SessionStart", "owner-session"),
    );
    native.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        hook("Stop", "owner-session"),
    );
    let address = lab.claude_address("owner-session");
    lab.registry
        .lock()
        .unwrap()
        .fixture_skew_binding_seconds(&address);
    let mut carrier = ClaudeLaterCarrier::new(
        Arc::clone(&lab.registry),
        Arc::clone(&lab.storage) as Arc<dyn Custody>,
        ClaudeTiming::default(),
    )
    .unwrap();
    let attestation = carrier
        .attest(&address)
        .expect("full managed owner identity");
    assert_eq!(
        attestation.lifecycle(),
        bridge_core::dispatch::Lifecycle::Inactive
    );
}

/// A historical seconds-only route can remain available to legacy clients but
/// cannot become managed evidence until a new original hook captures identity.
#[test]
fn historical_active_route_never_promotes_seconds_to_managed_identity() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    pre(&mut source, &lab, "old-call", "mcp__pool__vote");
    lab.channel.take().unwrap().stop();
    let journal = lab.socket.with_extension("bindings.json");
    let mut old: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
    old["schema"] = json!(1);
    old.as_object_mut().unwrap().remove("store_id");
    old.as_object_mut().unwrap().remove("attempts");
    old.as_object_mut().unwrap().remove("root_launches");
    for row in old["bindings"].as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("managed_incarnation");
    }
    std::fs::write(&journal, serde_json::to_vec(&old).unwrap()).unwrap();
    restart(&mut lab);
    let migrated: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
    assert_eq!(migrated["schema"], 4);
    assert!(migrated["bindings"][0].get("managed_incarnation").is_none());
    let (store, issuer) = discover(&mut source, &lab);
    let prepare = |call: &str, invocation: &str| {
        request(
            PRODUCER_TOKEN,
            invocation,
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":invocation,"command_name":"vote","native_proof":proof(call)}),
        )
    };
    let historical = call(&mut source, &lab, prepare("old-call", "old-intent"), false);
    assert_eq!(value(&historical)["error"]["code"], "binding_unavailable");
    pre(&mut source, &lab, "fresh-call", "mcp__pool__vote");
    let fresh = call(
        &mut source,
        &lab,
        prepare("fresh-call", "fresh-intent"),
        false,
    );
    assert_eq!(value(&fresh)["status"], "ok");
    let renewed: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
    assert!(renewed["bindings"][0]["managed_incarnation"].is_object());
}

/// Codex MCP correlation uses the same original capture and exact command mapping.
#[test]
fn codex_managed_original_hook() {
    let lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CODEX, &lab.codex_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);
    source.hook(&lab.socket, Harness::CODEX, json!({"hook_event_name":"PreToolUse","session_id":"thread","tool_use_id":"codex-call","tool_name":"mcp__pool__vote"}));
    let native = json!({"type":"native","host":"codex","metadata":{"threadId":"thread","callId":"codex-call","x-codex-turn-metadata":{}}});
    let response = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "codex-prepare",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"codex-inv","command_name":"vote","native_proof":native}),
        ),
        false,
    );
    assert_eq!(value(&response)["status"], "ok");
}

/// Codex presents seg(server) (`agent-pool` as `agent_pool`) and only that
/// name maps; Claude presents the raw server and only the raw name maps.
#[test]
fn hyphenated_server_names_follow_each_harness() {
    let mut lab = lab();
    lab.config.managed_tools[0].server = "agent-pool".into();
    restart(&mut lab);
    let mut codex = Harnessed::start_with_launch(Harness::CODEX, &lab.codex_store, LAUNCH);
    let (store, issuer) = discover(&mut codex, &lab);
    let prepare = |harness: &mut Harnessed, key: &str, native: Value| {
        let response = call(
            harness,
            &lab,
            request(
                PRODUCER_TOKEN,
                key,
                "prepare_native_context_v1",
                json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":key,"command_name":"vote","native_proof":native}),
            ),
            false,
        );
        value(&response).clone()
    };
    let codex_proof = |call: &str| json!({"type":"native","host":"codex","metadata":{"threadId":"thread","callId":call,"x-codex-turn-metadata":{}}});
    for (call_id, tool) in [
        ("codex-raw", "mcp__agent-pool__vote"),
        ("codex-seg", "mcp__agent_pool__vote"),
    ] {
        codex.hook(&lab.socket, Harness::CODEX, json!({"hook_event_name":"PreToolUse","session_id":"thread","tool_use_id":call_id,"tool_name":tool}));
    }
    assert_eq!(
        prepare(&mut codex, "codex-raw", codex_proof("codex-raw"))["error"]["code"],
        "route_mismatch"
    );
    assert_eq!(
        prepare(&mut codex, "codex-seg", codex_proof("codex-seg"))["status"],
        "ok"
    );
    codex.stop();
    let mut claude = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    pre(&mut claude, &lab, "claude-seg", "mcp__agent_pool__vote");
    pre(&mut claude, &lab, "claude-raw", "mcp__agent-pool__vote");
    assert_eq!(
        prepare(&mut claude, "claude-seg", proof("claude-seg"))["error"]["code"],
        "route_mismatch"
    );
    assert_eq!(
        prepare(&mut claude, "claude-raw", proof("claude-raw"))["status"],
        "ok"
    );
}

/// A Claude child sharing the root session cannot become a managed root actor.
#[test]
fn claude_child_is_not_managed_root() {
    let lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);
    source.hook(&lab.socket, Harness::CLAUDE_CODE, json!({"hook_event_name":"PreToolUse","session_id":"session","agent_id":"child","tool_use_id":"child-call","tool_name":"mcp__pool__vote"}));
    let response = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "child-prepare",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"child-inv","command_name":"vote","native_proof":proof("child-call")}),
        ),
        false,
    );
    assert_eq!(value(&response)["error"]["code"], "actor_mismatch");
}

/// Expiry and registration/consumption serialize at the Bridge writer: once
/// the synthetic expiry fence commits, late requests cannot spend the call.
#[test]
fn expiry_fences_late_registration_and_consumption() {
    let lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "expire-call", "mcp__pool__vote");
    let prepared = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "expire-prepare",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"expire-inv","command_name":"vote","native_proof":proof("expire-call")}),
        ),
        false,
    );
    assert_eq!(value(&prepared)["status"], "ok");
    let reference = value(&prepared)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    lab.registry
        .lock()
        .unwrap()
        .fixture_expire_managed(
            now()
                .saturating_add(lab.config.max_call_age_ms)
                .saturating_add(1),
        )
        .unwrap();
    let registration = request(
        PRODUCER_TOKEN,
        "late-register",
        "register_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"bridge_context_ref":reference,"invocation_key":"expire-inv","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"late","native_proof":proof("expire-call")}),
    );
    assert_eq!(
        value(&call(&mut source, &lab, registration, false))["error"]["code"],
        "invocation_spent"
    );
    let consume = request(
        PRODUCER_TOKEN,
        "late-consume",
        "consume_launch_assertion_v1",
        json!({"version":1,"expected_store_id":store,"assertion_key":"unissued-key","invocation_key":"expire-inv","security_digest":DIGEST}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, consume, true))["error"]["code"],
        "invocation_spent"
    );
    let abort = request(
        PRODUCER_TOKEN,
        "expire-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"late-consume","invocation_key":"expire-inv","security_digest":DIGEST,"audience":"backend"}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, abort.clone(), true))["value"]["aborted"],
        true
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, abort, true))["value"]["aborted"],
        true
    );
}

/// Removing any required managed component makes even an absent-key abort
/// unavailable rather than creating durable state under partial configuration.
#[test]
fn incomplete_managed_configuration_refuses_durable_operations() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let (store, _) = discover(&mut source, &lab);
    lab.config.run_readers.clear();
    restart(&mut lab);
    let abort = request(
        PRODUCER_TOKEN,
        "partial-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"partial","invocation_key":"partial","security_digest":DIGEST,"audience":"backend"}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, abort, true))["error"]["code"],
        "capability_missing"
    );
}

/// Idle maintenance scrubs expired secret keys without releasing the
/// registered invocation or requiring another native hook.
#[test]
fn idle_expiry_scrubs_registered_secret() {
    let mut lab = lab();
    lab.config.max_call_age_ms = 8_000;
    restart(&mut lab);
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "idle-call", "mcp__pool__vote");
    let prepared = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "idle-prepare",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"idle-inv","command_name":"vote","native_proof":proof("idle-call")}),
        ),
        false,
    );
    let reference = value(&prepared)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let registered = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "idle-register",
            "register_launch_assertion_v1",
            json!({"version":1,"expected_store_id":store,"bridge_context_ref":reference,"invocation_key":"idle-inv","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"idle-nonce","native_proof":proof("idle-call")}),
        ),
        false,
    );
    let key = value(&registered)["value"]["assertion_key"]
        .as_str()
        .unwrap();
    let journal = lab
        .socket
        .with_extension("bindings.json")
        .with_extension("attempts.json");
    assert!(
        std::fs::read(&journal)
            .unwrap()
            .windows(key.len())
            .any(|part| part == key.as_bytes())
    );
    assert!(eventually(12_000, || {
        std::fs::read(&journal)
            .is_ok_and(|bytes| !bytes.windows(key.len()).any(|part| part == key.as_bytes()))
    }));
    let ledger: Value = serde_json::from_slice(&std::fs::read(journal).unwrap()).unwrap();
    assert_eq!(ledger["ledger"]["contexts"].as_array().unwrap().len(), 1);
    assert_eq!(ledger["ledger"]["contexts"][0]["sealed"], true);
}

/// An uncertain managed commit fences B1 but leaves legacy hook persistence
/// and recipient lookup available on the independently stored route journal.
#[test]
fn failed_managed_commit_does_not_poison_legacy_hook() {
    let lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let (store, _) = discover(&mut source, &lab);
    source.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        hook("SessionStart", "legacy-session"),
    );
    lab.registry.lock().unwrap().fixture_fail_managed_commit();
    let abort = request(
        PRODUCER_TOKEN,
        "fault-abort",
        "consume_launch_assertion_abort_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"consume_request_id":"fault-request","invocation_key":"fault-inv","security_digest":DIGEST,"audience":"backend"}),
    );
    let failed = call(&mut consumer, &lab, abort, true);
    assert_eq!(value(&failed)["error"]["recovery"], "same_key_lookup");
    let hook_result = source.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        hook("Stop", "legacy-session"),
    );
    assert_eq!(hook_result["status"], 0);
    assert_eq!(
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("legacy-session"))
            .unwrap()
            .0
            .lifecycle(),
        bridge_core::dispatch::Lifecycle::Inactive
    );
}

/// Executes typed SDK methods as the exact configured reader process against
/// the real protected channel. All evidence and credentials are synthetic.
#[test]
fn sdk_b1_client_against_protected_server() {
    use bridge_sdk::{
        AttemptClientError, AttemptServerPin, Client, Config,
        bridge_protocol::{Secret, attempt::*},
    };
    use std::io::{Read, Write};
    if std::env::var_os("BRIDGE_SDK_B1_CHILD").is_none()
        && std::env::var_os("BRIDGE_SDK_B1_PARENT").is_none()
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = common::TempDir::new("sdk-main");
        let executable = directory.0.join("server-test");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = common::loader_free_command(&executable)
            .args([
                "--exact",
                exact_test("sdk_b1_client_against_protected_server").as_str(),
                "--nocapture",
            ])
            .env("BRIDGE_SDK_B1_PARENT", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned SDK server test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    if std::env::var_os("BRIDGE_SDK_B1_CHILD").is_some() {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        let input: Value = serde_json::from_str(&input).unwrap();
        let socket = input["socket"].as_str().unwrap();
        let store = input["store"].as_str().unwrap();
        let issuer = input["issuer"].as_str().unwrap();
        let reference = Secret::new(input["reference"].as_str().unwrap());
        let server_pin = AttemptServerPin::new(
            input["server_exe"].as_str().unwrap(),
            input["server_sha"].as_str().unwrap(),
        )
        .unwrap();
        let client = Client::new(
            Config::new(
                socket,
                socket,
                Secret::new(READER_TOKEN),
                std::time::Duration::from_secs(30),
            )
            .unwrap(),
        )
        .unwrap();
        let capabilities = client
            .attempt_binding_capabilities_v1(
                "sdk-discover",
                &server_pin,
                AttemptCapabilitiesParamsV1 { version: 1 },
            )
            .unwrap();
        assert_eq!(capabilities.store_id, store);
        assert_eq!(capabilities.issuer_epoch, issuer);
        let context = client
            .context_lookup_v1(
                "sdk-context",
                &server_pin,
                ContextLookupParamsV1 {
                    version: 1,
                    expected_store_id: store.into(),
                    producer: PRODUCER.into(),
                    bridge_context_ref: reference.clone(),
                    invocation_key: "sdk-inv".into(),
                },
            )
            .unwrap();
        assert_eq!(context.observation.launch_id, LAUNCH);
        assert_eq!(context.validity, ValidityV1::Current);
        let status = client
            .run_actor_recovery_status_v1(
                "sdk-actor-status",
                &server_pin,
                bridge_sdk::bridge_protocol::managed_owner::RunActorLookupParamsV1 {
                    version: 1,
                    expected_store_id: store.into(),
                    producer: PRODUCER.into(),
                    incarnation: context.observation.incarnation.clone(),
                    launch_id: LAUNCH.into(),
                },
            )
            .unwrap();
        assert_eq!(
            status.state,
            bridge_sdk::bridge_protocol::managed_owner::RunActorRecoveryStateV1::Current
        );
        let lookup = client
            .observation_lookup_v1(
                "sdk-lookup",
                &server_pin,
                ObservationLookupParamsV1 {
                    version: 1,
                    expected_store_id: store.into(),
                    producer: PRODUCER.into(),
                    consume_request_id: "sdk-consume".into(),
                    invocation_key: "sdk-inv".into(),
                    security_digest: DIGEST.into(),
                },
            )
            .unwrap();
        assert_eq!(lookup.receipt.observation, context.observation);
        assert_eq!(lookup.validity, ValidityV1::Current);
        let native_proof: bridge_sdk::bridge_protocol::CallEvidence =
            serde_json::from_value(proof("sdk-call")).unwrap();
        let denied = |result: Result<(), AttemptClientError>| {
            assert!(matches!(result, Err(AttemptClientError::Refused(_))))
        };
        denied(
            client
                .prepare_native_context_v1(
                    "sdk-denied-prepare",
                    &server_pin,
                    PrepareNativeContextParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        expected_issuer_epoch: issuer.into(),
                        invocation_key: "sdk-other".into(),
                        command_name: "vote".into(),
                        native_proof: native_proof.clone(),
                    },
                )
                .map(|_| ()),
        );
        denied(
            client
                .register_launch_assertion_v1(
                    "sdk-denied-register",
                    &server_pin,
                    RegisterLaunchAssertionParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        bridge_context_ref: reference,
                        invocation_key: "sdk-inv".into(),
                        command_name: "vote".into(),
                        security_digest: DIGEST.into(),
                        audience: "backend".into(),
                        nonce: "sdk-nonce".into(),
                        native_proof,
                    },
                )
                .map(|_| ()),
        );
        denied(
            client
                .consume_launch_assertion_v1(
                    "sdk-denied-consume",
                    &server_pin,
                    ConsumeLaunchAssertionParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        assertion_key: Secret::new("invalid-key"),
                        invocation_key: "sdk-inv".into(),
                        security_digest: DIGEST.into(),
                    },
                )
                .map(|_| ()),
        );
        denied(
            client
                .consume_launch_assertion_abort_v1(
                    "sdk-denied-abort",
                    &server_pin,
                    ConsumeAbortParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        producer: PRODUCER.into(),
                        consume_request_id: "sdk-consume".into(),
                        invocation_key: "sdk-inv".into(),
                        security_digest: DIGEST.into(),
                        audience: "backend".into(),
                    },
                )
                .map(|_| ()),
        );
        denied(
            client
                .retire_attempt_namespace_v1(
                    "sdk-denied-retire",
                    &server_pin,
                    RetireAttemptNamespaceParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        producer: PRODUCER.into(),
                        issuer_epoch: issuer.into(),
                        retirement_key: "sdk-retire".into(),
                    },
                )
                .map(|_| ()),
        );
        denied(
            client
                .compact_managed_owner_scope_v1(
                    "sdk-denied-compact",
                    &server_pin,
                    bridge_sdk::bridge_protocol::managed_owner::CompactManagedOwnerScopeParamsV1 {
                        version: 1,
                        expected_store_id: store.into(),
                        audience: "backend".into(),
                        producer_scope: "scope".into(),
                    },
                )
                .map(|_| ()),
        );
        return;
    }
    let mut lab = lab();
    let reader_exe = lab.dir.0.join("sdk-reader-test");
    std::fs::copy(std::env::current_exe().unwrap(), &reader_exe).unwrap();
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::set_permissions(&reader_exe, std::fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = std::fs::metadata(&reader_exe).unwrap();
    let written = metadata.mtime().max(metadata.ctime());
    lab.config.run_readers[0].executable = RelayExecutable {
        sha256: file_sha256(&reader_exe).unwrap(),
        path: reader_exe.clone(),
    };
    restart(&mut lab);
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut consumer = start_consumer(&lab);
    let (store, issuer) = discover(&mut source, &lab);
    pre(&mut source, &lab, "sdk-call", "mcp__pool__vote");
    let prepared = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "sdk-prepare",
            "prepare_native_context_v1",
            json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"sdk-inv","command_name":"vote","native_proof":proof("sdk-call")}),
        ),
        false,
    );
    assert_eq!(value(&prepared)["status"], "ok");
    let reference = value(&prepared)["value"]["bridge_context_ref"]
        .as_str()
        .unwrap();
    let registered = call(
        &mut source,
        &lab,
        request(
            PRODUCER_TOKEN,
            "sdk-register",
            "register_launch_assertion_v1",
            json!({"version":1,"expected_store_id":store,"bridge_context_ref":reference,"invocation_key":"sdk-inv","command_name":"vote","security_digest":DIGEST,"audience":"backend","nonce":"sdk-nonce","native_proof":proof("sdk-call")}),
        ),
        false,
    );
    assert_eq!(value(&registered)["status"], "ok");
    let key = value(&registered)["value"]["assertion_key"]
        .as_str()
        .unwrap();
    let consumed = call(
        &mut consumer,
        &lab,
        request(
            PRODUCER_TOKEN,
            "sdk-consume",
            "consume_launch_assertion_v1",
            json!({"version":1,"expected_store_id":store,"assertion_key":key,"invocation_key":"sdk-inv","security_digest":DIGEST}),
        ),
        true,
    );
    assert_eq!(value(&consumed)["status"], "ok");
    while i64::try_from(now() / 1000).unwrap() <= written {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut child = common::loader_free_command(&reader_exe)
        .args([
            "--exact",
            exact_test("sdk_b1_client_against_protected_server").as_str(),
            "--nocapture",
        ])
        .env("BRIDGE_SDK_B1_CHILD", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let server_exe = std::env::current_exe().unwrap();
    let server_sha = file_sha256(&server_exe).unwrap();
    let input = json!({"socket":lab.socket,"store":store,"issuer":issuer,"reference":reference,"server_exe":server_exe,"server_sha":server_sha});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "synthetic SDK child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The pinned SDK retirement method reaches a real owned core server, keeps
/// exact replay semantics and leaves sibling scopes independently retireable.
#[test]
fn sdk_pinned_scope_retirement_against_owned_core() {
    use bridge_sdk::{
        AttemptClientError, AttemptServerPin, Client, Config,
        bridge_protocol::{RetireDeliveryScopeParams, RetirementAction, Secret},
    };
    if std::env::var_os("BRIDGE_PINNED_RETIRE_CHILD").is_none() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("pinned-retire-parent");
        let executable = dir.0.join("owned-core-test");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = common::loader_free_command(&executable)
            .args([
                "--exact",
                exact_test("sdk_pinned_scope_retirement_against_owned_core").as_str(),
                "--nocapture",
            ])
            .env("BRIDGE_PINNED_RETIRE_CHILD", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "owned pinned-core test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = TempDir::new("pinned-retire-core");
    let socket = dir.0.join("core.sock");
    let grant: GrantConfig =
        serde_json::from_value(json!({"token":PRODUCER_TOKEN,"publisher":PRODUCER,
        "recipients":["*"],"kinds":["*"],"modes":["message"],"policies":["keep_all"],
        "producer_v1":{"delivery_scopes":true}}))
        .unwrap();
    let running = bridge_core::service::start(bridge_core::service::Config {
        database: dir.0.join("core.db"),
        socket: socket.clone(),
        limits: bridge_core::Limits::new(10),
        grants: vec![grant],
        universal_limits: bridge_core::UniversalLimits::default(),
    })
    .unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let pin = AttemptServerPin::new(&executable, file_sha256(&executable).unwrap()).unwrap();
    let client = Client::new(
        Config::new(
            dir.0.join("unused-registration.sock"),
            &socket,
            Secret::new(PRODUCER_TOKEN),
            std::time::Duration::from_secs(30),
        )
        .unwrap(),
    )
    .unwrap();
    let params = RetireDeliveryScopeParams {
        scope_key: "pool/store/pool/member".into(),
        action: RetirementAction::RetireUnhanded,
    };
    let first = client
        .retire_delivery_scope_pinned("pinned-retire", &pin, params.clone())
        .unwrap();
    assert_eq!(first.receipt.scope_key, params.scope_key);
    assert!(!first.replayed);
    let replay = client
        .retire_delivery_scope_pinned("pinned-retire", &pin, params.clone())
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(first.receipt, replay.receipt);
    let sibling = RetireDeliveryScopeParams {
        scope_key: "pool/store/pool/member/final-notice".into(),
        action: RetirementAction::RetireUnhanded,
    };
    assert!(
        !client
            .retire_delivery_scope_pinned("pinned-sibling", &pin, sibling)
            .unwrap()
            .replayed
    );
    let changed = RetireDeliveryScopeParams {
        scope_key: params.scope_key,
        action: RetirementAction::Preserve,
    };
    assert!(matches!(
        client.retire_delivery_scope_pinned("pinned-retire", &pin, changed),
        Err(AttemptClientError::Service(_))
    ));
    running.shutdown();
    running.join();
}

/// A Run reader observes the original root launch from SessionStart even when
/// the resumed process has not called Pool; foreign peers and reused identity
/// cannot obtain a current actor.
#[test]
fn run_actor_lookup_current_unavailable_and_issuer_restart() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut reader = start_reader(&lab);
    let mut consumer = start_consumer(&lab);
    let (store, _) = discover(&mut source, &lab);
    let hook = source.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        json!({"hook_event_name":"SessionStart","session_id":"session"}),
    );
    assert_eq!(hook["status"], 0);
    let pid = source.child.id();
    let uid = bridge_adapters::os::process_facts(pid)
        .unwrap()
        .uid
        .unwrap();
    let process = bridge_adapters::os::attempt::kernel_incarnation(pid, uid).unwrap();
    let incarnation = json!({"host_id":lab.config.host_id,"boot_id":process.boot_id,"pid_namespace_inode":process.pid_namespace_inode,"uid":uid,"pid":pid,"start_ticks":process.start_ticks});
    let query = request(
        READER_TOKEN,
        "actor-query",
        "run_actor_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
    );
    let current = call(&mut reader, &lab, query.clone(), true);
    assert_eq!(value(&current)["value"]["state"], "current");
    assert_eq!(value(&current)["value"]["actor"]["native_id"], "session");
    assert_eq!(value(&current)["value"]["incarnation"], incarnation);
    let mut wrong_launch = query.clone();
    wrong_launch["params"]["launch_id"] = json!("11234567-89ab-4cde-8fab-0123456789ab");
    assert_eq!(
        value(&call(&mut reader, &lab, wrong_launch, true))["value"]["state"],
        "unavailable"
    );
    let mut reused = query.clone();
    reused["params"]["incarnation"]["start_ticks"] = json!(process.start_ticks + 1);
    assert_eq!(
        value(&call(&mut reader, &lab, reused, true))["value"]["state"],
        "unavailable"
    );
    let mut foreign = query.clone();
    foreign["credential"] = json!(PRODUCER_TOKEN);
    assert_eq!(
        value(&call(&mut consumer, &lab, foreign, true))["error"]["code"],
        "peer_not_authorized"
    );
    restart(&mut lab);
    assert_eq!(
        value(&call(&mut reader, &lab, query.clone(), true))["value"]["state"],
        "unavailable"
    );
    let mut status = query.clone();
    status["op"] = json!("run_actor_recovery_status_v1");
    assert_eq!(
        value(&call(&mut reader, &lab, status.clone(), true))["value"]["state"],
        "awaiting_root_hook"
    );
    // SessionStart renews the actor epoch, so it cannot re-arm the former actor.
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"session"})
        )["status"],
        0
    );
    assert_eq!(
        value(&call(&mut reader, &lab, query.clone(), true))["value"]["state"],
        "unavailable"
    );
    assert_eq!(
        value(&call(&mut reader, &lab, status, true))["value"]["state"],
        "relaunch_required"
    );
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"second-session"})
        )["status"],
        0
    );
    assert_eq!(
        value(&call(&mut reader, &lab, query, true))["value"]["state"],
        "unavailable"
    );
    // A capture that was originally missing never becomes current, including
    // after its failed observation and binding survive a daemon restart.
    let mut missing = Harnessed::start(Harness::CLAUDE_CODE, &lab.claude_store);
    assert_eq!(
        missing.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"missing-session"})
        )["status"],
        0
    );
    let missing_pid = missing.child.id();
    let missing_kernel =
        bridge_adapters::os::attempt::kernel_incarnation(missing_pid, uid).unwrap();
    let missing_incarnation = json!({"host_id":lab.config.host_id,"boot_id":missing_kernel.boot_id,
        "pid_namespace_inode":missing_kernel.pid_namespace_inode,"uid":uid,"pid":missing_pid,"start_ticks":missing_kernel.start_ticks});
    let missing_query = request(
        READER_TOKEN,
        "missing-status",
        "run_actor_recovery_status_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":missing_incarnation,"launch_id":LAUNCH}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, missing_query.clone(), true))["value"]["state"],
        "relaunch_required"
    );
    restart(&mut lab);
    assert_eq!(
        missing.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"Stop","session_id":"missing-session"})
        )["status"],
        0
    );
    assert_eq!(
        value(&call(&mut reader, &lab, missing_query, true))["value"]["state"],
        "relaunch_required"
    );
}

/// Historical schema-three routes have no original root capture and therefore
/// cannot gain managed actor authority from a later same-process hook.
#[test]
fn schema_three_live_root_requires_relaunch() {
    let mut lab = lab();
    let mut source = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    let mut reader = start_reader(&lab);
    let (store, _) = discover(&mut source, &lab);
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"session"})
        )["status"],
        0
    );
    let pid = source.child.id();
    let uid = bridge_adapters::os::process_facts(pid)
        .unwrap()
        .uid
        .unwrap();
    let process = bridge_adapters::os::attempt::kernel_incarnation(pid, uid).unwrap();
    let incarnation = json!({"host_id":lab.config.host_id,"boot_id":process.boot_id,
        "pid_namespace_inode":process.pid_namespace_inode,"uid":uid,"pid":pid,"start_ticks":process.start_ticks});
    lab.channel.take().unwrap().stop();
    let journal = lab.socket.with_extension("bindings.json");
    let mut old: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
    old["schema"] = json!(3);
    old.as_object_mut().unwrap().remove("root_launches");
    std::fs::write(&journal, serde_json::to_vec(&old).unwrap()).unwrap();
    restart(&mut lab);
    let status = request(
        READER_TOKEN,
        "schema-three-status",
        "run_actor_recovery_status_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, status.clone(), true))["value"]["state"],
        "relaunch_required"
    );
    assert_eq!(
        source.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"Stop","session_id":"session"})
        )["status"],
        0
    );
    assert_eq!(
        value(&call(&mut reader, &lab, status, true))["value"]["state"],
        "relaunch_required"
    );
}

/// One synthetic managed dispatch is one effect; exact replay, unknown ACK,
/// known-unsent retries and an absent v2 endpoint never fall back to v1.
#[test]
fn managed_owner_v2_exact_effect_and_no_legacy_fallback() {
    use bridge_adapters::registry::ManagedOwnerRoute;
    use bridge_protocol::managed_owner::{OutboxIntentV1, RouteV1, egress_intent_digest};
    use sha2::{Digest, Sha256};
    let mut lab = lab_with_other_producer(true);
    let owner_exe = distinct_fixture(&lab, "managed-owner");
    let run_home = lab.dir.0.join("run-v2");
    let uid = bridge_adapters::os::process_facts(std::process::id())
        .unwrap()
        .uid
        .unwrap();
    let run_route = RouteV1 {
        component_store_id: "store_run".into(),
        route_id: "run-route".into(),
        worker_uid: uid,
    };
    let pool_route = RouteV1 {
        component_store_id: "pool-store".into(),
        route_id: "pool-route".into(),
        worker_uid: uid,
    };
    let mut bootstrap = Harnessed::start(Harness::CLAUDE_CODE, &lab.claude_store);
    let (store, _) = discover(&mut bootstrap, &lab);
    drop(bootstrap);
    let bridge_route = RouteV1 {
        component_store_id: store.clone(),
        route_id: "bridge-route".into(),
        worker_uid: uid,
    };
    lab.config.owner_v2_routes.push(ManagedOwnerRoute {
        producer: PRODUCER.into(),
        audience: "backend".into(),
        producer_scopes: vec!["scope".into(), "compact-scope".into()],
        producer_scope_prefixes: vec!["pool/store/pool/".into()],
        run_home: run_home.clone(),
        run_route: run_route.clone(),
        pool_route,
        bridge_route: bridge_route.clone(),
        run_executable: owner_exe.clone(),
    });
    let other_frontend = distinct_fixture(&lab, "other-frontend");
    let other_backend = distinct_fixture(&lab, "other-backend");
    let other_reader = distinct_fixture(&lab, "other-reader");
    lab.config.managed_tools.push(ManagedTools {
        producer: "other-pool".into(),
        server: "other-server".into(),
        commands: vec!["vote".into()],
        frontend: other_frontend,
    });
    lab.config.audiences.push(BackendAudience {
        name: "backend".into(),
        producer: "other-pool".into(),
        executable: other_backend.clone(),
    });
    lab.config.run_readers.push(RunReader {
        producer: "other-pool".into(),
        reader: "other-reader".into(),
        executable: other_reader,
    });
    let mut other_route = lab.config.owner_v2_routes[0].clone();
    other_route.producer = "other-pool".into();
    other_route.producer_scopes = vec!["other-scope".into()];
    other_route.producer_scope_prefixes = vec!["other/".into()];
    lab.config.owner_v2_routes.push(other_route);
    let mut overlapping = lab.config.clone();
    overlapping.owner_v2_routes[1].producer_scopes = vec!["scope".into()];
    assert!(Registry::new(overlapping, uid).is_err());
    restart(&mut lab);
    let mut native = Harnessed::start_owned_v2(
        &owner_exe.path,
        Harness::CLAUDE_CODE,
        &lab.claude_store,
        &run_home,
        LAUNCH,
        true,
    );
    let mut reader = start_reader(&lab);
    let mut consumer = start_consumer(&lab);
    let (restored_store, _) = discover(&mut native, &lab);
    assert_eq!(store, restored_store);
    let capabilities = call(
        &mut reader,
        &lab,
        request(
            READER_TOKEN,
            "owner-capabilities",
            "attempt_binding_capabilities_v1",
            json!({"version":1}),
        ),
        true,
    );
    assert!(
        value(&capabilities)["value"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("managed_owner_v2"))
    );
    assert!(
        value(&capabilities)["value"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("run_actor_lookup_v1"))
    );
    // The pinned audience resident discovers the same owner-v2 route.
    let resident = call(
        &mut consumer,
        &lab,
        request(
            PRODUCER_TOKEN,
            "owner-resident-capabilities",
            "attempt_binding_capabilities_v1",
            json!({"version":1}),
        ),
        true,
    );
    assert_eq!(value(&resident)["status"], "ok");
    assert_eq!(value(&resident)["value"]["store_id"], json!(store));
    assert!(
        value(&resident)["value"]["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("managed_owner_v2"))
    );
    assert_eq!(
        native.hook(
            &lab.socket,
            Harness::CLAUDE_CODE,
            json!({"hook_event_name":"SessionStart","session_id":"session"})
        )["status"],
        0
    );
    let pid = native.cmd(json!({"cmd":"owner_log"}))["harness_pid"]
        .as_u64()
        .unwrap() as u32;
    let kernel = bridge_adapters::os::attempt::kernel_incarnation(pid, uid).unwrap();
    let incarnation = json!({"host_id":lab.config.host_id,"boot_id":kernel.boot_id,"pid_namespace_inode":kernel.pid_namespace_inode,"uid":uid,"pid":pid,"start_ticks":kernel.start_ticks});
    let actor_query = request(
        READER_TOKEN,
        "owner-actor",
        "run_actor_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
    );
    let actor_result = call(&mut reader, &lab, actor_query, true);
    assert_eq!(value(&actor_result)["value"]["state"], "current");
    let actor = value(&actor_result)["value"]["actor"].clone();
    let attempt = json!({"run_store_id":"store_run","lineage_root_id":"root","execution_id":"execution","sequence":1,"attempt_id":"attempt","launch_id":LAUNCH});
    let receipt = json!({"receipt_id":"run-receipt","purpose":"egress","lineage_root_id":"root","bound_execution_id":"execution","attempt":attempt,"incarnation":incarnation,"actor":actor,"successor_proof":{"lineage_root_id":"root","bound_execution_id":"execution","current_execution_id":"execution","chain":[{"execution_id":"execution","parent_execution_id":null,"sequence":1}]}});
    native.cmd(json!({"cmd":"owner_set_receipt","receipt":receipt.clone()}));
    let message = "synthetic managed message";
    let build = |effect: &str, request_id: &str| {
        let intent: OutboxIntentV1 = serde_json::from_value(json!({"effect_id":effect,"producer_scope":"scope","event_key":"event","payload_sha256":format!("{:x}",Sha256::digest(message.as_bytes())),"payload_length":message.len(),"target_binding":{"pool_store_id":"pool-store","pool_id":"pool","member_id":"member","binding_generation":1,"attempt":attempt,"actor":actor,"run_route":run_route,"bridge_route":bridge_route},"expected_incarnation":incarnation,"bridge_route":bridge_route,"mode":"message","retention":"keep_all"})).unwrap();
        let digest = egress_intent_digest(&intent).unwrap();
        request(
            PRODUCER_TOKEN,
            request_id,
            "publish_managed_owner_v1",
            json!({"version":1,"expected_store_id":store,"audience":"backend","run_receipt_id":"run-receipt","outbox_intent":intent,"effect_digest":digest,"text":message}),
        )
    };
    let mut other =
        Harnessed::start_from(&other_backend.path, Harness::CLAUDE_CODE, &lab.claude_store);
    let mut squat = build("squat-effect", "squat-publish");
    squat["credential"] = json!("synthetic-other-producer-token");
    assert_eq!(
        value(&call(&mut other, &lab, squat.clone(), true))["error"]["code"],
        "peer_not_authorized"
    );
    squat["op"] = json!("abort_managed_owner_v1");
    assert_eq!(
        value(&call(&mut other, &lab, squat, true))["error"]["code"],
        "peer_not_authorized"
    );
    let squat_lookup = request(
        "synthetic-other-producer-token",
        "squat-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"squat-effect","effect_digest":"a".repeat(64)}),
    );
    assert_eq!(
        value(&call(&mut other, &lab, squat_lookup, true))["error"]["code"],
        "peer_not_authorized"
    );
    for operation in ["lookup_managed_owner_v1", "compact_managed_owner_scope_v1"] {
        let mut params = json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"pool/store/pool/member"});
        if operation == "lookup_managed_owner_v1" {
            params["effect_id"] = json!("prefix-squat");
            params["effect_digest"] = json!("a".repeat(64));
        }
        let request = request(
            "synthetic-other-producer-token",
            "prefix-squat-read",
            operation,
            params,
        );
        assert_eq!(
            value(&call(&mut other, &lab, request, true))["error"]["code"],
            "peer_not_authorized"
        );
    }
    let mut prefix_squat = build("prefix-squat", "prefix-squat-publish");
    prefix_squat["credential"] = json!("synthetic-other-producer-token");
    prefix_squat["params"]["outbox_intent"]["producer_scope"] = json!("pool/store/pool/member");
    let squat_intent: OutboxIntentV1 =
        serde_json::from_value(prefix_squat["params"]["outbox_intent"].clone()).unwrap();
    prefix_squat["params"]["effect_digest"] = json!(egress_intent_digest(&squat_intent).unwrap());
    assert_eq!(
        value(&call(&mut other, &lab, prefix_squat.clone(), true))["error"]["code"],
        "peer_not_authorized"
    );
    prefix_squat["op"] = json!("abort_managed_owner_v1");
    assert_eq!(
        value(&call(&mut other, &lab, prefix_squat, true))["error"]["code"],
        "peer_not_authorized"
    );
    let mut unprivileged = build("unprivileged-abort", "unprivileged-abort");
    unprivileged["credential"] = json!("synthetic-readonly-producer-token");
    unprivileged["op"] = json!("abort_managed_owner_v1");
    unprivileged["params"]["outbox_intent"]["producer_scope"] = json!("other-scope");
    let unprivileged_intent: OutboxIntentV1 =
        serde_json::from_value(unprivileged["params"]["outbox_intent"].clone()).unwrap();
    let unprivileged_digest = egress_intent_digest(&unprivileged_intent).unwrap();
    unprivileged["params"]["effect_digest"] = json!(unprivileged_digest);
    assert_eq!(
        value(&call(&mut other, &lab, unprivileged, true))["error"]["code"],
        "capability_missing"
    );
    let absent = request(
        "synthetic-other-producer-token",
        "unprivileged-check",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"other-scope","effect_id":"unprivileged-abort","effect_digest":unprivileged_digest}),
    );
    assert_eq!(
        value(&call(&mut other, &lab, absent, true))["error"]["code"],
        "binding_unavailable"
    );
    // A live captured root is inert after Bridge restart until a fresh hook
    // proves the same process, session and original actor epoch.
    restart(&mut lab);
    let status = request(
        READER_TOKEN,
        "restart-status",
        "run_actor_recovery_status_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, status.clone(), true))["value"]["state"],
        "awaiting_root_hook"
    );
    let before_hook = build("restart-before-hook", "restart-before-hook");
    assert_eq!(
        value(&call(&mut consumer, &lab, before_hook, true))["value"]["reason"],
        "actor_mismatch"
    );
    pre(&mut native, &lab, "restart-root-hook", "mcp__pool__vote");
    assert_eq!(
        value(&call(&mut reader, &lab, status, true))["value"]["state"],
        "current"
    );
    let restored_actor = call(
        &mut reader,
        &lab,
        request(
            READER_TOKEN,
            "restored-actor",
            "run_actor_lookup_v1",
            json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
        ),
        true,
    );
    assert_eq!(value(&restored_actor)["value"]["actor"], actor);
    native.cmd(json!({"cmd":"owner_script","mode":"claude_accept"}));
    let accepted = build("effect-a", "dispatch-a");
    assert_eq!(
        value(&call(&mut consumer, &lab, accepted.clone(), true))["value"]["state"],
        "accepted"
    );
    let mut replay = accepted.clone();
    replay["request_id"] = json!("dispatch-a-replay");
    assert_eq!(
        value(&call(&mut consumer, &lab, replay, true))["value"]["state"],
        "accepted"
    );
    assert_eq!(
        native.cmd(json!({"cmd":"owner_log"}))["v2_frames"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let lookup = request(
        PRODUCER_TOKEN,
        "effect-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-a","effect_digest":accepted["params"]["effect_digest"]}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, lookup, true))["value"]["state"],
        "accepted"
    );
    let mut changed = build("effect-a", "dispatch-conflict");
    changed["params"]["outbox_intent"]["event_key"] = json!("different-event");
    let changed_intent: OutboxIntentV1 =
        serde_json::from_value(changed["params"]["outbox_intent"].clone()).unwrap();
    changed["params"]["effect_digest"] = json!(egress_intent_digest(&changed_intent).unwrap());
    assert_eq!(
        value(&call(&mut consumer, &lab, changed, true))["error"]["code"],
        "intent_conflict"
    );
    native.cmd(json!({"cmd":"owner_script","mode":"known_unsent:not_idle"}));
    let deferred = build("effect-b", "dispatch-b");
    assert_eq!(
        value(&call(&mut consumer, &lab, deferred.clone(), true))["value"]["state"],
        "known_unsent"
    );
    native.cmd(json!({"cmd":"owner_script","mode":"claude_accept"}));
    let mut retried = deferred;
    retried["request_id"] = json!("dispatch-b-retry");
    assert_eq!(
        value(&call(&mut consumer, &lab, retried, true))["value"]["state"],
        "accepted"
    );
    native.cmd(json!({"cmd":"owner_script","mode":"known_unsent:qualification_pending"}));
    let qualification = build("effect-q", "dispatch-q");
    let pending = call(&mut consumer, &lab, qualification.clone(), true);
    assert_eq!(value(&pending)["value"]["state"], "known_unsent");
    assert_eq!(value(&pending)["value"]["reason"], "qualification_pending");
    native.cmd(json!({"cmd":"owner_script","mode":"claude_accept"}));
    let mut qualification_retry = qualification;
    qualification_retry["request_id"] = json!("dispatch-q-retry");
    assert_eq!(
        value(&call(&mut consumer, &lab, qualification_retry, true))["value"]["state"],
        "accepted"
    );
    // A still-running execution pinned to an older Bridge build refuses with
    // the closed reason `attempt_mismatch`: a definitive pre-handoff refusal
    // that is reported as `known_unsent`, never as a malformed reply.
    native.cmd(json!({"cmd":"owner_script","mode":"known_unsent:attempt_mismatch"}));
    let mismatch = build("effect-m", "dispatch-m");
    let refused = call(&mut consumer, &lab, mismatch.clone(), true);
    assert_eq!(value(&refused)["value"]["state"], "known_unsent");
    assert_eq!(value(&refused)["value"]["reason"], "attempt_mismatch");
    let mismatch_lookup = request(
        PRODUCER_TOKEN,
        "mismatch-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-m","effect_digest":mismatch["params"]["effect_digest"]}),
    );
    let looked_up = call(&mut consumer, &lab, mismatch_lookup, true);
    assert_eq!(value(&looked_up)["value"]["state"], "known_unsent");
    assert_eq!(value(&looked_up)["value"]["reason"], "attempt_mismatch");
    native.cmd(json!({"cmd":"owner_script","mode":"silent"}));
    let unknown = build("effect-c", "dispatch-c");
    assert_eq!(
        value(&call(&mut consumer, &lab, unknown.clone(), true))["value"]["state"],
        "unknown"
    );
    let before = native.cmd(json!({"cmd":"owner_log"}));
    assert_eq!(before["v2_frames"].as_array().unwrap().len(), 7);
    let mut unknown_replay = unknown.clone();
    unknown_replay["request_id"] = json!("dispatch-c-replay");
    assert_eq!(
        value(&call(&mut consumer, &lab, unknown_replay.clone(), true))["value"]["state"],
        "unknown"
    );
    let after_unknown_replay = native.cmd(json!({"cmd":"owner_log"}));
    assert_eq!(
        after_unknown_replay["v2_frames"].as_array().unwrap().len(),
        7
    );
    assert_eq!(after_unknown_replay["run_queries"], before["run_queries"]);
    let unknown_lookup = request(
        PRODUCER_TOKEN,
        "unknown-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-c","effect_digest":unknown["params"]["effect_digest"]}),
    );
    // Run absence is only a snapshot: it never changes Bridge's unknown state.
    assert_eq!(
        value(&call(&mut consumer, &lab, unknown_lookup.clone(), true))["value"]["state"],
        "unknown"
    );
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-c","effect":{"state":"known_unsent","protocol":null,"native_id":null,"reason":"not_idle","effect_digest":unknown["params"]["effect_digest"]}}));
    assert_eq!(
        value(&call(&mut consumer, &lab, unknown_lookup, true))["value"]["state"],
        "unknown"
    );
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-c","effect":{"state":"unknown","protocol":null,"native_id":null,"reason":"native_uncertain","effect_digest":unknown["params"]["effect_digest"]}}));
    let mut abort_unknown = unknown.clone();
    abort_unknown["op"] = json!("abort_managed_owner_v1");
    abort_unknown["request_id"] = json!("abort-c");
    assert_eq!(
        value(&call(&mut consumer, &lab, abort_unknown, true))["value"]["state"],
        "unknown"
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt["actor"]["native_id"] = json!("different-session");
    native.cmd(json!({"cmd":"owner_set_receipt","receipt":wrong_receipt}));
    let denied = build("effect-e", "dispatch-e");
    let denied_result = call(&mut consumer, &lab, denied.clone(), true);
    assert_eq!(value(&denied_result)["value"]["state"], "known_unsent");
    assert_eq!(value(&denied_result)["value"]["reason"], "unavailable");
    assert_eq!(
        native.cmd(json!({"cmd":"owner_log"}))["v2_frames"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    native.cmd(json!({"cmd":"owner_set_receipt","receipt":receipt}));
    native.cmd(json!({"cmd":"owner_script","mode":"claude_accept"}));
    let mut denied_retry = denied;
    denied_retry["request_id"] = json!("dispatch-e-retry");
    assert_eq!(
        value(&call(&mut consumer, &lab, denied_retry, true))["value"]["state"],
        "accepted"
    );
    native.cmd(json!({"cmd":"owner_script","mode":"wrong_effect"}));
    let wrong_reply = build("effect-f", "dispatch-f");
    assert_eq!(
        value(&call(&mut consumer, &lab, wrong_reply.clone(), true))["value"]["state"],
        "unknown"
    );
    let mut wrong_reply_replay = wrong_reply;
    wrong_reply_replay["request_id"] = json!("dispatch-f-replay");
    assert_eq!(
        value(&call(&mut consumer, &lab, wrong_reply_replay, true))["value"]["state"],
        "unknown"
    );
    // Only the authenticated Run receipt can resolve the original uncertainty.
    let wrong_effect = build("effect-f", "effect-f-original");
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-f","effect":{"state":"accepted","protocol":"claude_input","native_id":"run-receipt-id","reason":null,"effect_digest":wrong_effect["params"]["effect_digest"],"reply_effect_id":"other-effect"}}));
    let bad_resolve = request(
        PRODUCER_TOKEN,
        "resolve-bad",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-f","effect_digest":wrong_effect["params"]["effect_digest"]}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, bad_resolve.clone(), true))["value"]["state"],
        "unknown"
    );
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-f","effect":{"state":"accepted","protocol":"claude_input","native_id":"run-receipt-id","reason":null,"effect_digest":wrong_effect["params"]["effect_digest"],"reply_store_id":"store_wrong"}}));
    assert_eq!(
        value(&call(&mut consumer, &lab, bad_resolve, true))["value"]["state"],
        "unknown"
    );
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-f","effect":{"state":"accepted","protocol":"claude_input","native_id":"run-receipt-id","reason":null,"effect_digest":wrong_effect["params"]["effect_digest"]}}));
    let resolve = request(
        PRODUCER_TOKEN,
        "resolve-f",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-f","effect_digest":wrong_effect["params"]["effect_digest"]}),
    );
    let resolved = call(&mut consumer, &lab, resolve, true);
    assert_eq!(value(&resolved)["value"]["state"], "accepted");
    assert_eq!(value(&resolved)["value"]["native_id"], "run-receipt-id");
    // Abort before publication installs both Bridge and Run fences; a delayed
    // publish returns the same abort without a native request.
    let delayed = build("effect-h", "dispatch-h");
    let mut abort_first = delayed.clone();
    abort_first["op"] = json!("abort_managed_owner_v1");
    abort_first["request_id"] = json!("abort-h");
    assert_eq!(
        value(&call(&mut consumer, &lab, abort_first.clone(), true))["value"]["state"],
        "aborted"
    );
    let mut changed_abort = abort_first.clone();
    changed_abort["params"]["outbox_intent"]["event_key"] = json!("changed-abort-intent");
    let changed_abort_intent: OutboxIntentV1 =
        serde_json::from_value(changed_abort["params"]["outbox_intent"].clone()).unwrap();
    changed_abort["params"]["effect_digest"] =
        json!(egress_intent_digest(&changed_abort_intent).unwrap());
    assert_eq!(
        value(&call(&mut consumer, &lab, changed_abort, true))["error"]["code"],
        "intent_conflict"
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, delayed, true))["value"]["state"],
        "aborted"
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, abort_first, true))["value"]["state"],
        "aborted"
    );
    // Hold the receipt response after reservation, abort on a separate
    // authenticated connection, then release the in-flight publisher. The
    // last custody recheck must stop it before any owner frame is written.
    let query_count = native.cmd(json!({"cmd":"owner_log"}))["run_queries"]
        .as_u64()
        .unwrap();
    native.cmd(json!({"cmd":"owner_hold_receipt","held":true}));
    let racing_publish = build("effect-race", "dispatch-race");
    let mut racing_abort = racing_publish.clone();
    racing_abort["op"] = json!("abort_managed_owner_v1");
    racing_abort["request_id"] = json!("abort-race");
    let mut competing = start_consumer(&lab);
    std::thread::scope(|scope| {
        let publisher = scope.spawn(|| call(&mut consumer, &lab, racing_publish, true));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        while native.cmd(json!({"cmd":"owner_log"}))["run_queries"]
            .as_u64()
            .unwrap()
            <= query_count
        {
            assert!(
                std::time::Instant::now() < deadline,
                "publisher did not reach the receipt gate"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            value(&call(&mut competing, &lab, racing_abort, true))["value"]["state"],
            "aborted"
        );
        native.cmd(json!({"cmd":"owner_hold_receipt","held":false}));
        let cancelled = publisher.join().unwrap();
        assert_eq!(value(&cancelled)["value"]["state"], "known_unsent");
        assert_eq!(value(&cancelled)["value"]["reason"], "cancelled");
    });
    let before = native.cmd(json!({"cmd":"owner_log"}));
    assert_eq!(before["v2_frames"].as_array().unwrap().len(), 9);
    let effects: Vec<_> = before["v2_frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|frame| frame["outbox_intent"]["effect_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        effects,
        [
            "effect-a", "effect-b", "effect-b", "effect-q", "effect-q", "effect-m", "effect-c",
            "effect-e", "effect-f"
        ]
    );
    let mut wrong_route = build("effect-route", "dispatch-route");
    wrong_route["params"]["outbox_intent"]["bridge_route"]["route_id"] =
        json!("another-bridge-route");
    wrong_route["params"]["outbox_intent"]["target_binding"]["bridge_route"]["route_id"] =
        json!("another-bridge-route");
    let wrong_intent: OutboxIntentV1 =
        serde_json::from_value(wrong_route["params"]["outbox_intent"].clone()).unwrap();
    wrong_route["params"]["effect_digest"] = json!(egress_intent_digest(&wrong_intent).unwrap());
    assert_eq!(
        value(&call(&mut consumer, &lab, wrong_route, true))["error"]["code"],
        "capability_missing"
    );
    let route_check = native.cmd(json!({"cmd":"owner_log"}));
    assert_eq!(route_check["v2_frames"].as_array().unwrap().len(), 9);
    assert_eq!(route_check["run_queries"], before["run_queries"]);

    // Dynamic prefixes cover every managed custody operation, while retiring
    // one exact scope cannot close its separate final-notice descendant.
    for scope in [
        "pool/store/pool/",
        "pool/store/pool//member",
        "pool/store/pools/member",
    ] {
        let lookup = request(
            PRODUCER_TOKEN,
            "prefix-boundary",
            "lookup_managed_owner_v1",
            json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":scope,"effect_id":"missing","effect_digest":"a".repeat(64)}),
        );
        assert_eq!(
            value(&call(&mut consumer, &lab, lookup, true))["error"]["code"],
            "peer_not_authorized"
        );
    }
    let member_scope = "pool/store/pool/member";
    let mut prefix_publish = build("prefix-effect", "prefix-dispatch");
    prefix_publish["params"]["outbox_intent"]["producer_scope"] = json!(member_scope);
    let prefix_intent: OutboxIntentV1 =
        serde_json::from_value(prefix_publish["params"]["outbox_intent"].clone()).unwrap();
    let prefix_digest = egress_intent_digest(&prefix_intent).unwrap();
    prefix_publish["params"]["effect_digest"] = json!(prefix_digest);
    native.cmd(json!({"cmd":"owner_script","mode":"claude_accept"}));
    assert_eq!(
        value(&call(&mut consumer, &lab, prefix_publish.clone(), true))["value"]["state"],
        "accepted"
    );
    let prefix_lookup = request(
        PRODUCER_TOKEN,
        "prefix-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":member_scope,"effect_id":"prefix-effect","effect_digest":prefix_digest}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, prefix_lookup, true))["value"]["state"],
        "accepted"
    );
    let mut prefix_abort = prefix_publish;
    prefix_abort["op"] = json!("abort_managed_owner_v1");
    prefix_abort["request_id"] = json!("prefix-abort");
    assert_eq!(
        value(&call(&mut consumer, &lab, prefix_abort, true))["value"]["state"],
        "accepted"
    );
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":member_scope,"effect_id":"prefix-effect",
        "effect":{"state":"accepted","protocol":"claude_input","native_id":"fresh-native-id","reason":null,"effect_digest":prefix_digest}}));
    lab.storage
        .lock()
        .unwrap()
        .retire_delivery_scope(
            PRODUCER_TOKEN,
            "prefix-retire",
            &bridge_protocol::RetireDeliveryScopeParams {
                scope_key: member_scope.into(),
                action: bridge_protocol::RetirementAction::RetireUnhanded,
            },
            &|| now(),
        )
        .unwrap();
    let prefix_compact = request(
        PRODUCER_TOKEN,
        "prefix-compact",
        "compact_managed_owner_scope_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":member_scope}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, prefix_compact, true))["value"]["compacted"],
        1
    );
    let mut notice = build("prefix-notice", "notice-dispatch");
    notice["params"]["outbox_intent"]["producer_scope"] =
        json!("pool/store/pool/member/final-notice");
    let notice_intent: OutboxIntentV1 =
        serde_json::from_value(notice["params"]["outbox_intent"].clone()).unwrap();
    notice["params"]["effect_digest"] = json!(egress_intent_digest(&notice_intent).unwrap());
    assert_eq!(
        value(&call(&mut consumer, &lab, notice, true))["value"]["state"],
        "accepted"
    );

    // Scoped compaction uses the authenticated Run endpoint for each terminal
    // receipt and leaves uncertain rows and the durable closed-scope fence.
    use bridge_core::owner_v2::{OwnerEffect, OwnerEffectResult};
    use bridge_protocol::managed_owner::{ManagedOwnerStateV1, canonical_value};
    use bridge_protocol::{RetireDeliveryScopeParams, RetirementAction};
    let selected = &lab.config.owner_v2_routes[0];
    let target = serde_json::to_value((
        &selected.producer,
        &selected.audience,
        &selected.run_home,
        &selected.run_route,
        &selected.pool_route,
        &selected.bridge_route,
    ))
    .unwrap();
    let mut route_bytes = b"agent-mcp/bridge/owner-route/v1\0".to_vec();
    route_bytes.extend(canonical_value(&target).unwrap());
    let route_fingerprint = format!("{:x}", Sha256::digest(&route_bytes));
    let mut digests = Vec::new();
    {
        let mut storage = lab.storage.lock().unwrap();
        for (name, result) in [
            (
                "compact-unsent",
                OwnerEffectResult {
                    state: ManagedOwnerStateV1::KnownUnsent,
                    protocol: None,
                    native_id: None,
                    reason: Some("not_idle".into()),
                },
            ),
            (
                "compact-accepted",
                OwnerEffectResult {
                    state: ManagedOwnerStateV1::Accepted,
                    protocol: Some("claude_input".into()),
                    native_id: Some("compact-receipt".into()),
                    reason: None,
                },
            ),
            (
                "compact-aborted",
                OwnerEffectResult {
                    state: ManagedOwnerStateV1::Aborted,
                    protocol: None,
                    native_id: None,
                    reason: None,
                },
            ),
            (
                "compact-unknown",
                OwnerEffectResult {
                    state: ManagedOwnerStateV1::Unknown,
                    protocol: None,
                    native_id: None,
                    reason: Some("native_uncertain".into()),
                },
            ),
        ] {
            let mut intent: OutboxIntentV1 =
                serde_json::from_value(build(name, name)["params"]["outbox_intent"].clone())
                    .unwrap();
            intent.producer_scope = "compact-scope".into();
            let digest = egress_intent_digest(&intent).unwrap();
            let row = OwnerEffect {
                producer: PRODUCER,
                audience: "backend",
                intent: &intent,
                digest: &digest,
                run_receipt_id: "run-receipt",
                route_fingerprint: &route_fingerprint,
                call_id: name,
                text: message,
            };
            if result.state == ManagedOwnerStateV1::Aborted {
                storage.owner_v2_begin_abort(&row).unwrap();
                storage
                    .owner_v2_apply_run_result("compact-scope", name, &digest, &result)
                    .unwrap();
            } else {
                storage.owner_v2_reserve(&row).unwrap();
                storage
                    .owner_v2_finish("compact-scope", name, name, &result)
                    .unwrap();
            }
            digests.push((name, digest));
        }
        storage
            .retire_delivery_scope(
                PRODUCER_TOKEN,
                "compact-scope-retire",
                &RetireDeliveryScopeParams {
                    scope_key: "compact-scope".into(),
                    action: RetirementAction::RetireUnhanded,
                },
                &|| now(),
            )
            .unwrap();
    }
    let compact = request(
        PRODUCER_TOKEN,
        "compact-pass",
        "compact_managed_owner_scope_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"compact-scope"}),
    );
    let first = call(&mut consumer, &lab, compact.clone(), true);
    assert_eq!(value(&first)["value"]["compacted"], 1);
    assert_eq!(value(&first)["value"]["remaining"], 3);
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"compact-scope","effect_id":"compact-accepted",
        "effect":{"state":"accepted","protocol":"claude_input","native_id":"compact-receipt","reason":null,"effect_digest":digests[1].1}}));
    // Each pass checks at most one terminal Run receipt. Other scopes may have
    // advanced the shared cursor, so allow a complete rotation to reach this
    // accepted effect without weakening the exact receipt requirement.
    let mut second = call(&mut consumer, &lab, compact.clone(), true);
    for _ in 0..2 {
        if value(&second)["value"]["compacted"] != 0 {
            break;
        }
        assert_eq!(value(&second)["value"]["remaining"], 3);
        second = call(&mut consumer, &lab, compact.clone(), true);
    }
    assert_eq!(value(&second)["value"]["compacted"], 1);
    assert_eq!(value(&second)["value"]["remaining"], 2);
    native.cmd(json!({"cmd":"owner_set_effect","producer_scope":"compact-scope","effect_id":"compact-aborted",
        "effect":{"state":"aborted","protocol":null,"native_id":null,"reason":null,"effect_digest":digests[2].1}}));
    let mut third = call(&mut consumer, &lab, compact.clone(), true);
    if value(&third)["value"]["compacted"] == 0 {
        assert_eq!(value(&third)["value"]["remaining"], 2);
        third = call(&mut consumer, &lab, compact.clone(), true);
    }
    assert_eq!(value(&third)["value"]["compacted"], 1);
    assert_eq!(value(&third)["value"]["remaining"], 1);
    let gone = request(
        PRODUCER_TOKEN,
        "compacted-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"compact-scope","effect_id":"compact-accepted","effect_digest":digests[1].1}),
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, gone, true))["error"]["recovery"],
        "operator"
    );
    let mut delayed = build("compact-accepted", "compact-delayed");
    delayed["params"]["outbox_intent"]["producer_scope"] = json!("compact-scope");
    let delayed_intent: OutboxIntentV1 =
        serde_json::from_value(delayed["params"]["outbox_intent"].clone()).unwrap();
    delayed["params"]["effect_digest"] = json!(egress_intent_digest(&delayed_intent).unwrap());
    assert_eq!(
        value(&call(&mut consumer, &lab, delayed, true))["error"]["code"],
        "aborted"
    );
    let before_rotation = native.cmd(json!({"cmd":"owner_log"}));

    // A changed immutable route is operator-visible, while an authorized Run
    // executable rotation keeps the original target fingerprint recoverable.
    lab.config.owner_v2_routes[0].run_route.route_id = "changed-run-route".into();
    restart(&mut lab);
    let mut changed_route_abort = unknown.clone();
    changed_route_abort["op"] = json!("abort_managed_owner_v1");
    changed_route_abort["request_id"] = json!("abort-changed-route");
    let refused = call(&mut consumer, &lab, changed_route_abort, true);
    assert_eq!(value(&refused)["error"]["code"], "recovery_required");
    assert_eq!(value(&refused)["error"]["recovery"], "operator");
    lab.config.owner_v2_routes[0].run_route.route_id = "run-route".into();
    let alternate_home = lab.dir.0.join("alternate-run-home");
    std::fs::create_dir(&alternate_home).unwrap();
    lab.config.owner_v2_routes[0].run_home = alternate_home;
    restart(&mut lab);
    let rotated_lookup = request(
        PRODUCER_TOKEN,
        "rotation-lookup",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-c","effect_digest":unknown["params"]["effect_digest"]}),
    );
    let mismatch = call(&mut consumer, &lab, rotated_lookup.clone(), true);
    assert_eq!(value(&mismatch)["error"]["code"], "recovery_required");
    assert_eq!(value(&mismatch)["error"]["recovery"], "operator");
    let accepted_mismatch = request(
        PRODUCER_TOKEN,
        "accepted-route-mismatch",
        "lookup_managed_owner_v1",
        json!({"version":1,"expected_store_id":store,"audience":"backend","producer_scope":"scope","effect_id":"effect-a","effect_digest":accepted["params"]["effect_digest"]}),
    );
    let refused = call(&mut consumer, &lab, accepted_mismatch, true);
    assert_eq!(value(&refused)["error"]["code"], "recovery_required");
    assert_eq!(value(&refused)["error"]["recovery"], "operator");
    lab.config.owner_v2_routes[0].run_home = run_home.clone();
    let new_build = distinct_fixture(&lab, "rotated-run");
    std::fs::remove_file(run_home.join("attempt-receipts.sock")).unwrap();
    let mut rotated = Harnessed::start_receipt_only(&new_build.path, &run_home);
    rotated.cmd(json!({"cmd":"owner_set_effect","producer_scope":"scope","effect_id":"effect-c",
        "effect":{"state":"accepted","protocol":"claude_input","native_id":"rotated-run-receipt","reason":null,"effect_digest":unknown["params"]["effect_digest"]}}));
    lab.config.owner_v2_routes[0].run_executable = new_build;
    restart(&mut lab);
    let recovered = call(&mut consumer, &lab, rotated_lookup, true);
    assert_eq!(value(&recovered)["value"]["state"], "accepted");
    assert_eq!(
        value(&recovered)["value"]["native_id"],
        "rotated-run-receipt"
    );
    // An unavailable Run abort never clears the local fence or allows a late
    // publication to start a new owner write.
    std::fs::remove_file(run_home.join("attempt-receipts.sock")).unwrap();
    let delayed_pending = build("effect-i", "dispatch-i");
    let mut abort_pending = delayed_pending.clone();
    abort_pending["op"] = json!("abort_managed_owner_v1");
    abort_pending["request_id"] = json!("abort-i");
    assert_eq!(
        value(&call(&mut consumer, &lab, abort_pending, true))["value"]["state"],
        "unknown"
    );
    assert_eq!(
        value(&call(&mut consumer, &lab, delayed_pending, true))["value"]["state"],
        "unknown"
    );
    std::fs::remove_file(run_home.join("v2.sock")).unwrap();
    let missing = build("effect-d", "dispatch-d");
    let refused = call(&mut consumer, &lab, missing, true);
    assert_eq!(value(&refused)["value"]["state"], "known_unsent");
    assert_eq!(value(&refused)["value"]["reason"], "capability_missing");
    let after = native.cmd(json!({"cmd":"owner_log"}));
    assert_eq!(after["frames"].as_array().unwrap().len(), 0);
    assert_eq!(after["probes"], 0);
    assert_eq!(after["run_queries"], before_rotation["run_queries"]);
    restart(&mut lab);
    assert_eq!(
        value(&call(&mut consumer, &lab, unknown_replay, true))["value"]["state"],
        "accepted"
    );
    assert_eq!(
        native.cmd(json!({"cmd":"owner_log"}))["v2_frames"]
            .as_array()
            .unwrap()
            .len(),
        11
    );
}

/// If the first root capture is missing and its route commit is uncertain,
/// later B2 roots stay unavailable while independent B1 calls still work.
#[test]
fn missing_root_capture_with_failed_route_commit_never_repairs() {
    let lab = lab();
    let mut missing = Harnessed::start(Harness::CLAUDE_CODE, &lab.claude_store);
    let mut reader = start_reader(&lab);
    let (store, issuer) = discover(&mut missing, &lab);
    let original = lab.registry.lock().unwrap().fixture_fail_route_commit();
    let refused = missing.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        json!({"hook_event_name":"SessionStart","session_id":"first"}),
    );
    assert_eq!(refused["status"], 0);
    assert!(
        refused["stderr"]
            .as_str()
            .is_some_and(|message| message.contains("refused"))
    );
    lab.registry
        .lock()
        .unwrap()
        .fixture_restore_route_commit(original);
    let mut valid = Harnessed::start_with_launch(Harness::CLAUDE_CODE, &lab.claude_store, LAUNCH);
    pre(&mut valid, &lab, "fault-root-call", "mcp__pool__vote");
    let pid = valid.child.id();
    let uid = bridge_adapters::os::process_facts(pid)
        .unwrap()
        .uid
        .unwrap();
    let process = bridge_adapters::os::attempt::kernel_incarnation(pid, uid).unwrap();
    let incarnation = json!({"host_id":lab.config.host_id,"boot_id":process.boot_id,"pid_namespace_inode":process.pid_namespace_inode,"uid":uid,"pid":pid,"start_ticks":process.start_ticks});
    let actor = request(
        READER_TOKEN,
        "fault-root-actor",
        "run_actor_lookup_v1",
        json!({"version":1,"expected_store_id":store,"producer":PRODUCER,"incarnation":incarnation,"launch_id":LAUNCH}),
    );
    assert_eq!(
        value(&call(&mut reader, &lab, actor, true))["value"]["state"],
        "unavailable"
    );
    let prepare = request(
        PRODUCER_TOKEN,
        "fault-root-prepare",
        "prepare_native_context_v1",
        json!({"version":1,"expected_store_id":store,"expected_issuer_epoch":issuer,"invocation_key":"fault-root-inv","command_name":"vote","native_proof":proof("fault-root-call")}),
    );
    assert_eq!(
        value(&call(&mut valid, &lab, prepare, false))["status"],
        "ok"
    );
}

/// Exact libtest name of a test defined in this module: integration tests run as
/// modules of the crate's single `it` binary, so the name carries the module path.
fn exact_test(name: &str) -> String {
    match module_path!().split_once("::") {
        Some((_, module)) => format!("{module}::{name}"),
        None => name.to_owned(),
    }
}
