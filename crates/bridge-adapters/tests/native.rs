//! Adapter boundary tests over real owned processes.
//!
//! Each test runs the real adapter channel, the real `bridge-hook`
//! binary and real core custody, with `bridge-fixture` processes standing
//! in for harnesses, Claude inboxes and the Codex App Server. They verify
//! the trust boundaries and the evidence each carrier records; they do
//! not establish delivery to, or context in, a real model.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_adapters::RegistryAttestor;
use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
use bridge_adapters::codex::CodexQueueCarrier;
use bridge_adapters::registry::{CallerAttestor, PresentedMeta, SealedProof, Unattested};
use bridge_adapters::server::Custody;
use bridge_core::dispatch::{AttemptState, DispatchReport, DispatchTiming, dispatch_message};
use bridge_core::{Harness, Mode, Storage};
use common::*;
use serde_json::json;

/// The workspace gate runs the first-party plugin's synthetic Node lifecycle
/// contract without native sessions, sockets, credentials or model inference.
#[test]
fn opencode_plugin_synthetic_lifecycle_contract() {
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    assert!(std::path::Path::new(&node).is_absolute());
    let output = std::process::Command::new(node)
        .arg("--expose-gc")
        .arg("--test")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/plugins/opencode/index.test.js"
        ))
        .output()
        .expect("synthetic plugin test starts");
    assert!(
        output.status.success(),
        "synthetic plugin lifecycle contract failed"
    );
}

/// Claude `_meta` for a tool-use id.
fn claude_meta(call: &str) -> serde_json::Value {
    json!({"claudecode/toolUseId": call, "progressToken": 1})
}

/// OpenCode's trusted plugin context joins the actual same-session native hook
/// once; vendor session-only metadata, wrong sessions and consumed calls refuse.
/// Session discovery is unknown, only actual Stop is idle, and feed loss revokes
/// readiness. Enabling unqualified hook injection is rejected at configuration.
#[test]
fn opencode_plugin_call_joins_only_its_actual_owned_session() {
    let lab = Lab::new("ocm");
    let mut harness = Harnessed::start(Harness::OpenCode, &lab.opencode_store);
    let started = harness.hook(
        &lab.socket,
        Harness::OpenCode,
        hook("SessionStart", "ses-root"),
    );
    assert_eq!(started["status"], 0, "{started}");
    use bridge_core::dispatch::Lifecycle::{Active, Inactive, Unknown};
    for (event, expected) in [
        ("SessionStart", Unknown),
        ("OpenCodeActivity", Active),
        ("Stop", Inactive),
        ("OpenCodeUnknown", Unknown),
    ] {
        harness.hook(&lab.socket, Harness::OpenCode, hook(event, "ses-root"));
        let actual = lab
            .registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.opencode_address("ses-root"))
            .unwrap()
            .0
            .lifecycle();
        assert_eq!(actual, expected, "{event}");
    }
    let mut invalid = lab.config.clone();
    invalid
        .harnesses
        .iter_mut()
        .find(|policy| policy.harness == Harness::OpenCode)
        .unwrap()
        .inject = true;
    let owner = bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
    assert!(bridge_adapters::Registry::new(invalid, owner).is_err());
    harness.hook(
        &lab.socket,
        Harness::OpenCode,
        tool_hook("PreToolUse", "ses-root", "call-root", None),
    );
    let native =
        json!({"ai.opencode/sessionID":"ses-root","ai.agent_bridge/toolCallID":"call-root"});
    assert_eq!(
        harness.mcp(&lab.socket, json!({"ai.opencode/sessionID":"ses-root"}))["err"],
        "not_evidence"
    );
    assert_eq!(
        harness.mcp(
            &lab.socket,
            json!({"ai.opencode/sessionID":"ses-other","ai.agent_bridge/toolCallID":"call-root"})
        )["err"],
        "conflicting"
    );
    let accepted = harness.mcp(&lab.socket, native.clone());
    assert_eq!(accepted["ok"]["role"], "root", "{accepted}");
    assert_eq!(accepted["ok"]["native_id"], "ses-root");
    assert_eq!(
        accepted["ok"]["address"],
        lab.opencode_address("ses-root").to_canonical_string()
    );
    assert_eq!(accepted["ok"]["may_act_as_address"], true);
    assert_eq!(harness.mcp(&lab.socket, native)["err"], "duplicate");
    harness.stop();
}

/// Root and subagent callers join exactly one single-use record; replay, unknown, mixed-host and renewed-epoch ids refuse.
#[test]
fn claude_root_and_child_callers_join_single_use_records() {
    let lab = Lab::new("cc");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let reply = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-1"),
    );
    assert_eq!(reply["status"], 0);
    assert_eq!(reply["stdout"], "");

    // Root call joins exactly one record and is the addressed actor.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-1", "tu-root", None),
    );
    let root = harness.mcp(&lab.socket, claude_meta("tu-root"));
    assert_eq!(root["ok"]["role"], "root", "{root}");
    assert_eq!(root["ok"]["native_id"], "sess-1");
    assert_eq!(root["ok"]["may_act_as_address"], true);
    assert_eq!(
        root["ok"]["address"],
        lab.claude_address("sess-1").to_canonical_string()
    );

    // Replaying the same per-call id is a duplicate.
    assert_eq!(
        harness.mcp(&lab.socket, claude_meta("tu-root"))["err"],
        "duplicate"
    );

    // A subagent shares the session id but is a distinct child actor that
    // may not act as the address.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-1", "tu-child", Some("agent-a")),
    );
    let child = harness.mcp(&lab.socket, claude_meta("tu-child"));
    assert_eq!(child["ok"]["role"], "child", "{child}");
    assert_eq!(child["ok"]["native_id"], "agent-a");
    assert_eq!(child["ok"]["may_act_as_address"], false);

    // Unknown ids, mixed host metadata and Codex metadata for a Claude
    // harness all refuse.
    assert_eq!(
        harness.mcp(&lab.socket, claude_meta("tu-unknown"))["err"],
        "missing"
    );
    assert_eq!(
        harness.mcp(
            &lab.socket,
            json!({"claudecode/toolUseId": "tu-x", "threadId": "t", "callId": "c"})
        )["err"],
        "not_evidence"
    );
    assert_eq!(
        harness.mcp(
            &lab.socket,
            json!({"threadId": "sess-1", "callId": "tu-root", "x-codex-turn-metadata": {}})
        )["err"],
        "not_evidence"
    );

    // Renewal (a new SessionStart) invalidates records of the old epoch.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-1", "tu-old", None),
    );
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-1"),
    );
    assert_eq!(
        harness.mcp(&lab.socket, claude_meta("tu-old"))["err"],
        "stale"
    );
    harness.stop();
}

/// Callers outside a marked harness process and a relabeled harness are refused,
/// while a harness in an unlisted store and one beside a relay with a wrong digest
/// register (neither a store path nor a relay digest is a recipient trust input).
#[test]
fn non_harness_callers_and_relabeled_harnesses_refuse_while_unlisted_stores_register() {
    let lab = Lab::new("nh");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-2"),
    );
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-2", "tu-1", None),
    );

    // The test process is not a harness-launched MCP server: its claim of
    // a real recorded id is still refused.
    let attestor = RegistryAttestor::new(&lab.socket, Duration::from_secs(5), 600_000);
    let meta = PresentedMeta::Claude {
        tool_use_id: "tu-1".into(),
    };
    assert_eq!(
        attestor.attest(&meta, now()).unwrap_err().class(),
        "not_evidence"
    );
    // The fail-closed default provider refuses everything.
    assert_eq!(
        Unattested.attest(&meta, now()).unwrap_err().class(),
        "caller_unattested"
    );
    // The record was not consumed by the refused attempts.
    assert_eq!(
        harness.mcp(&lab.socket, claude_meta("tu-1"))["ok"]["role"],
        "root"
    );
    // The hook command's harness label (an argv value) cannot relabel a
    // Claude harness as Codex: the process carries no Codex product marker.
    let relabeled = harness.hook(&lab.socket, Harness::Codex, hook("SessionStart", "sess-2"));
    assert!(
        relabeled["stderr"]
            .as_str()
            .unwrap()
            .contains("not_evidence"),
        "{relabeled}"
    );
    harness.stop();

    // A harness in a store no configuration names registers from its own hook:
    // no store path or executable is predeclared.
    let foreign = lab.dir.0.join("foreign-store");
    std::fs::create_dir_all(&foreign).unwrap();
    let mut stranger = Harnessed::start(Harness::ClaudeCode, &foreign);
    let reply = stranger.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-3"),
    );
    assert_eq!(reply["status"], 0, "{reply}");
    assert!(
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("sess-3"))
            .is_ok(),
        "the dynamic store's session is a bound recipient"
    );
    stranger.stop();

    // The digests configured for Bridge's own relay are irrelevant to a native
    // recipient: a wrong relay digest does not refuse a harness.
    let mismatched = Lab::with_digest("uq", Some("0".repeat(64)));
    let mut harness = Harnessed::start(Harness::ClaudeCode, &mismatched.claude_store);
    let reply = harness.hook(
        &mismatched.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-4"),
    );
    assert_eq!(reply["status"], 0, "{reply}");
    harness.stop();
}

/// Only the root context point receives the frozen, escaped manifest; a subagent hook never drains root data.
#[test]
fn root_hook_drains_manifest_first_and_children_never_drain() {
    let lab = Lab::new("rd");
    let address = lab.claude_address("sess-5");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-5"),
    );
    lab.publish(
        "evt-inject",
        &address,
        Mode::Inject,
        "build <finished> & green",
    );

    // A subagent's natural context point never consumes root data.
    let child = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-5", "tu-c", Some("agent-b")),
    );
    assert_eq!(child["stdout"], "");
    assert!(lab.attempt("evt-inject").is_none());

    // The root's PostToolUse receives the escaped, source-wrapped manifest.
    let root = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-5", "tu-r", None),
    );
    let printed: serde_json::Value =
        serde_json::from_str(root["stdout"].as_str().unwrap().trim()).unwrap();
    assert_eq!(
        printed["hookSpecificOutput"]["hookEventName"],
        "PostToolUse"
    );
    let context = printed["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(
        context.contains("build &lt;finished&gt; &amp; green"),
        "{context}"
    );
    assert!(context.contains(PUBLISHER));
    let attempt = lab.attempt("evt-inject").unwrap();
    assert_eq!(attempt.state, AttemptState::HookSubmitted);
    assert_eq!(
        attempt.manifest, context,
        "the frozen manifest is exactly what was printed"
    );
    assert_eq!(attempt.actor, "sess-5");

    // Nothing is offered twice.
    let again = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-5", "tu-r2", None),
    );
    assert_eq!(again["stdout"], "");
    harness.stop();
}

/// A reply the hook could not print is a retained unknown outcome and is never offered again.
#[test]
fn lost_hook_reply_is_retained_unknown_and_never_reoffered() {
    let lab = Lab::new("lr");
    let address = lab.claude_address("sess-6");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-6"),
    );
    lab.publish("evt-lost", &address, Mode::Inject, "payload");
    let reply = harness.hook_lost_stdout(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-6", "tu-1", None),
    );
    assert_eq!(reply["status"], 0, "the harness survives: {reply}");
    assert!(eventually(3_000, || {
        lab.attempt("evt-lost")
            .is_some_and(|a| a.state == AttemptState::OutcomeUnknown)
    }));
    let next = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-6", "tu-2", None),
    );
    assert_eq!(
        next["stdout"], "",
        "an unknown hand-off is never re-offered"
    );
    let incidents = lab
        .storage
        .lock()
        .unwrap()
        .incidents(false, now(), 10)
        .unwrap();
    assert!(
        incidents
            .iter()
            .any(|i| i.event_id == "evt-lost" && i.kind == "unknown_handoff")
    );
    harness.stop();
}

/// Unknown, permission-wait, paused and disconnected recipients hold messages; an active Auto recipient waits for its own context hook instead of using the message carrier.
#[test]
fn lifecycle_holds_unknown_input_waits_pause_and_ended_sessions() {
    let lab = Lab::new("lh");
    let address = lab.claude_address("sess-7");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let timing = DispatchTiming::default();

    // No binding yet: unknown, never inactive.
    lab.publish("evt-auto", &address, Mode::Auto, "auto payload");
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(matches!(report, DispatchReport::Held(_)), "{report:?}");

    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-7", "behavior": "delivered"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-7"),
    );
    // Active: auto waits for the hook, the message path takes nothing.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("UserPromptSubmit", "sess-7"),
    );
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(!matches!(report, DispatchReport::Sent { .. }), "{report:?}");
    // A permission request holds; it is never answered or woken.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("PermissionRequest", "sess-7"),
    );
    lab.publish("evt-msg", &address, Mode::Message, "message payload");
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(matches!(report, DispatchReport::Held(_)), "{report:?}");
    // Idle but paused: the durable no-wake policy holds.
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-7"));
    let recipient = address.to_canonical_string();
    lab.storage
        .lock()
        .unwrap()
        .set_no_wake(&recipient, true, Some("owner pause"), "operator", now())
        .unwrap();
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(matches!(report, DispatchReport::Held(_)), "{report:?}");
    assert!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    lab.storage
        .lock()
        .unwrap()
        .set_no_wake(&recipient, false, None, "operator", now())
        .unwrap();

    // The harness process ends: disconnected is unknown, not inactive.
    harness.stop();
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(matches!(report, DispatchReport::Held(_)), "{report:?}");
}

/// Claude later: held then released by the recipient, forged receipts ignored, silence closed only by the exact transcript marker.
#[test]
fn claude_later_held_release_receipts_and_transcript_closure() {
    let lab = Lab::new("cl");
    let address = lab.claude_address("sess-8");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let timing = ClaudeTiming {
        receipt_wait: Duration::from_millis(800),
        ..ClaudeTiming::default()
    };
    let mut carrier = ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, timing).unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-8", "behavior": "held"}));
    let transcript = lab.claude_store.join("projects").join("t.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, "").unwrap();
    let mut start = hook("SessionStart", "sess-8");
    start["transcript_path"] = json!(transcript);
    harness.hook(&lab.socket, Harness::ClaudeCode, start);
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-8"));

    // Held is non-terminal; a later release from the recipient closes it.
    lab.publish("evt-held", &address, Mode::Message, "held payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeHeld,
                ..
            }
        ),
        "{report:?}"
    );
    let frames = harness.cmd(json!({"cmd": "frames"}));
    let frame = &frames["frames"][0];
    assert_eq!(frame["priority"], "later");
    assert!(frame.get("shouldQuery").is_none());
    assert_eq!(frame["session_id"], "sess-8");
    let msg_id = frame["msg_id"].as_str().unwrap().to_string();
    assert_eq!(
        frame["message"]["content"],
        lab.attempt("evt-held").unwrap().manifest
    );
    // A receipt from another, still-connected process (this test) is
    // ignored even with the right message id.
    let from = frame["from"]
        .as_str()
        .unwrap()
        .strip_prefix("uds:")
        .unwrap()
        .to_string();
    {
        use std::io::Write;
        let mut forged = std::os::unix::net::UnixStream::connect(&from).unwrap();
        let line = json!({"type":"control","action":"peer_message_status","orig_msg_id":msg_id,"status":"delivered"});
        writeln!(forged, "{line}").unwrap();
        forged.shutdown(std::net::Shutdown::Write).unwrap();
        std::thread::sleep(Duration::from_millis(300));
    }
    // A guessed message id from a closed sender is ignored too, and so is
    // the *known* message id from a sender that disconnects at once.
    for id in ["bridge_1_guess", msg_id.as_str()] {
        use std::io::Write;
        let mut closed = std::os::unix::net::UnixStream::connect(&from).unwrap();
        let line = json!({"type":"control","action":"peer_message_status","orig_msg_id":id,"status":"delivered"});
        writeln!(closed, "{line}").unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        lab.attempt("evt-held").unwrap().state,
        AttemptState::NativeHeld
    );
    harness.cmd(json!({"cmd": "receipt", "msg_id": msg_id, "status": "delivered"}));
    assert!(eventually(3_000, || lab.attempt("evt-held").unwrap().state
        == AttemptState::NativeAccepted));

    // Silence is the ordinary written-without-receipt; only the exact
    // manifest in the session's own transcript closes it positively.
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-8", "behavior": "none"}));
    lab.publish("evt-quiet", &address, Mode::Message, "quiet payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::WrittenNoReceipt,
                ..
            }
        ),
        "{report:?}"
    );
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(
        lab.attempt("evt-quiet").unwrap().state,
        AttemptState::WrittenNoReceipt
    );
    let manifest = lab.attempt("evt-quiet").unwrap().manifest;
    let frames = harness.cmd(json!({"cmd": "frames"}));
    let from = frames["frames"][1]["from"].as_str().unwrap().to_string();
    let tiers = |event: &str| -> Vec<String> {
        let evidence = lab
            .storage
            .lock()
            .unwrap()
            .delivery_evidence(PUBLISHER, event)
            .unwrap()
            .unwrap();
        evidence
            .tiers
            .iter()
            .map(|entry| entry.tier.as_str().to_string())
            .collect()
    };
    // Native shapes (Claude 2.1.296) that are NOT this hand-off's evidence:
    // the manifest without a peer origin, a peer origin from another sender,
    // another session's entry.
    let wrapped = format!(
        "Another Claude session sent a message:\n{manifest}\n\nThis came from another Claude session."
    );
    let decoys = [
        json!({"type": "user", "sessionId": "sess-8", "message": {"role": "user", "content": wrapped}}),
        json!({"type": "user", "sessionId": "sess-8", "origin": {"kind": "peer", "from": "uds:/elsewhere.sock"}, "message": {"role": "user", "content": wrapped}}),
        json!({"type": "user", "sessionId": "other", "origin": {"kind": "peer", "from": from}, "message": {"role": "user", "content": wrapped}}),
    ];
    let text: String = decoys.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(&transcript, &text).unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(
        lab.attempt("evt-quiet").unwrap().state,
        AttemptState::WrittenNoReceipt
    );
    // The native enqueue carries no attempt identity, so it settles nothing;
    // only the peer-origin entry from this attempt's own callback is context.
    let enqueue = json!({"type": "queue-operation", "operation": "enqueue", "sessionId": "sess-8", "content": manifest});
    std::fs::write(&transcript, format!("{text}{enqueue}\n")).unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(!tiers("evt-quiet").contains(&"native_accepted".to_string()));
    assert!(!tiers("evt-quiet").contains(&"context_observed".to_string()));
    let peer = json!({"type": "user", "sessionId": "sess-8", "isMeta": true, "origin": {"kind": "peer", "from": from}, "message": {"role": "user", "content": wrapped}});
    std::fs::write(&transcript, format!("{text}{enqueue}\n{peer}\n")).unwrap();
    assert!(eventually(6_000, || tiers("evt-quiet")
        .contains(&"context_observed".to_string())));
    harness.stop();
}

/// A recipient whose loaded harness positively runs without a native inbox
/// loses the message capability: the waiting message holds visibly (no
/// attempt) and later message publications are refused before acceptance.
/// A not-yet-written descriptor is only a transient hold, never disabled.
#[test]
fn disabled_inbox_refuses_before_acceptance_and_absent_inbox_only_holds() {
    let lab = Lab::new("di");
    let address = lab.claude_address("sess-di");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-di"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-di"));

    // Absent descriptor: held, nothing invoked, capability kept.
    lab.publish("evt-absent", &address, Mode::Message, "absent payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(matches!(report, DispatchReport::Held(_)), "{report:?}");
    assert!(lab.attempt("evt-absent").is_none());
    lab.try_publish("evt-still-accepted", &address, Mode::Message)
        .unwrap();

    // Positively disabled: the descriptor of this session and PID exists
    // without an inbox.
    harness.cmd(json!({"cmd": "descriptor_disabled", "session_id": "sess-di"}));
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(report, DispatchReport::Held(ref reason) if reason.contains("capability")),
        "{report:?}"
    );
    assert!(lab.attempt("evt-absent").is_none());
    let refused = lab
        .try_publish("evt-after-disable", &address, Mode::Message)
        .unwrap_err();
    assert!(
        refused.contains("unsupported") || refused.contains("capab"),
        "{refused}"
    );
    // inject stays supported.
    lab.try_publish("evt-inject-ok", &address, Mode::Inject)
        .unwrap();

    // Native late binding: the same session and incarnation now advertises
    // its inbox. Message is restored (the build is qualified for it), the
    // held events go out exactly once each, and new publications are
    // accepted again.
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-di", "behavior": "delivered"}));
    let mut sent = 0;
    for _ in 0..4 {
        match dispatch_message(
            &lab.storage,
            &mut carrier,
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap()
        {
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                events,
            } => sent += events,
            DispatchReport::Idle => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(sent, 2, "evt-absent and evt-still-accepted, once each");
    lab.try_publish("evt-after-restore", &address, Mode::Message)
        .unwrap();
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    let frames = harness.cmd(json!({"cmd": "frames"}));
    assert_eq!(
        frames["frames"].as_array().unwrap().len(),
        3,
        "no duplicate hand-off"
    );
    harness.stop();
}

/// A harness whose message carrier the host disabled stays without message even
/// when its inbox is advertised: a late inbox never promotes beyond what the
/// policy and host allow.
#[test]
fn late_inbox_never_promotes_a_disabled_message_capability() {
    let lab = Lab::new("np");
    lab.registry
        .lock()
        .unwrap()
        .disable_message(Harness::ClaudeCode);
    let address = lab.claude_address("sess-np");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-np", "behavior": "delivered"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-np"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-np"));
    assert!(
        lab.try_publish("evt-np-1", &address, Mode::Message)
            .is_err()
    );
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert_eq!(report, DispatchReport::Idle);
    assert!(
        lab.try_publish("evt-np-2", &address, Mode::Message)
            .is_err()
    );
    assert!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    harness.stop();
}

/// Custody that does not run the next `failures` actions (as an unattached
/// or failing store would), then runs every action on the lab's store.
struct FlakyCustody {
    /// The lab's store.
    inner: Arc<Mutex<Storage>>,
    /// Actions still to refuse.
    failures: AtomicUsize,
    /// Actions refused so far.
    refused: AtomicUsize,
}

impl Custody for FlakyCustody {
    /// Refuses (returns `false` without running `action`) while
    /// `failures` is positive, decrementing it; otherwise runs `action` on
    /// the lab's store.
    fn run(&self, action: &mut dyn FnMut(&mut Storage)) -> bool {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            self.refused.fetch_add(1, Ordering::SeqCst);
            return false;
        }
        self.inner.run(action)
    }
}

/// A message capability withdrawn by a disabled inbox comes back when the
/// same session and incarnation later advertises its inbox although no
/// event is pending (the withdrawal-triggering event was disposed, and
/// publications refuse meanwhile, so no dispatch would re-attest) and no
/// hook arrives; a one-shot failed core write of the restore is retried
/// rather than leaving the registry and core apart. The next publication
/// is then accepted and handed off once.
#[test]
fn withdrawn_message_recovers_from_a_late_inbox_without_pending_work() {
    let lab = Lab::new("wr");
    let address = lab.claude_address("sess-wr");
    let custody = Arc::new(FlakyCustody {
        inner: Arc::clone(&lab.storage),
        failures: AtomicUsize::new(0),
        refused: AtomicUsize::new(0),
    });
    let mut carrier = ClaudeLaterCarrier::new(
        Arc::clone(&lab.registry),
        Arc::clone(&custody) as Arc<dyn Custody>,
        ClaudeTiming::default(),
    )
    .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-wr"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-wr"));
    harness.cmd(json!({"cmd": "descriptor_disabled", "session_id": "sess-wr"}));
    lab.publish("evt-trigger", &address, Mode::Message, "trigger payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(report, DispatchReport::Held(ref reason) if reason.contains("capability")),
        "{report:?}"
    );
    // The waiter that triggered the withdrawal goes away: nothing pending.
    lab.storage
        .lock()
        .unwrap()
        .dispose_event(
            PUBLISHER,
            "evt-trigger",
            "operator",
            "regression: no pending work",
            now(),
        )
        .unwrap();
    assert!(
        lab.try_publish("evt-refused", &address, Mode::Message)
            .is_err()
    );
    // Late inbox, no hook, no work; the first core write of the restore
    // fails once.
    custody.failures.store(1, Ordering::SeqCst);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-wr", "behavior": "delivered"}));
    let mut tries = 0;
    assert!(eventually(10_000, || {
        tries += 1;
        lab.try_publish(&format!("evt-late-{tries}"), &address, Mode::Message)
            .is_ok()
    }));
    assert_eq!(
        custody.refused.load(Ordering::SeqCst),
        1,
        "the failed restore write was retried"
    );
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                events: 1
            }
        ),
        "{report:?}"
    );
    assert_eq!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    harness.stop();
}

/// An observation taken under an old incarnation's snapshot never changes
/// the renewed binding of the same session: the old process's disabled
/// inbox cannot withdraw message from the new, verified incarnation,
/// which keeps receiving.
#[test]
fn an_old_incarnation_snapshot_never_changes_a_renewed_binding() {
    let lab = Lab::new("os");
    let address = lab.claude_address("sess-os");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut first = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    first.cmd(json!({"cmd": "descriptor_disabled", "session_id": "sess-os"}));
    first.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-os"),
    );
    let (_, old) = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&address)
        .unwrap();
    first.stop();
    let mut second = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    second.cmd(json!({"cmd": "inbox", "session_id": "sess-os", "behavior": "delivered"}));
    second.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-os"),
    );
    second.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-os"));
    {
        let mut registry = lab.registry.lock().unwrap();
        assert!(registry.message_change(&address, &old, false).is_err());
        assert!(registry.commit_message(&address, &old, false).is_err());
    }
    lab.publish(
        "evt-new",
        &address,
        Mode::Message,
        "new incarnation payload",
    );
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    second.stop();
}

/// When every callback slot is held by an unsettled hand-off, the next
/// message is held visibly before any attempt: no attempt is reserved or
/// consumed and its payload stays pending, however often dispatch runs.
/// Once a slot frees (the earlier hand-off settles) it is handed off once.
#[test]
fn full_callback_slots_hold_without_consuming_attempts() {
    let lab = Lab::new("cs");
    let address = lab.claude_address("sess-cs");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let timing = ClaudeTiming {
        receipt_wait: Duration::from_millis(100),
        max_callbacks: 2,
        ..ClaudeTiming::default()
    };
    let mut carrier = ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, timing).unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-cs", "behavior": "none"}));
    let transcript = lab.claude_store.join("projects").join("cs.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, "").unwrap();
    let mut start = hook("SessionStart", "sess-cs");
    start["transcript_path"] = json!(transcript);
    harness.hook(&lab.socket, Harness::ClaudeCode, start);
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-cs"));
    let dispatch = |carrier: &mut ClaudeLaterCarrier| {
        dispatch_message(
            &lab.storage,
            carrier,
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap()
    };
    for event in ["evt-1", "evt-2"] {
        lab.publish(event, &address, Mode::Message, event);
        let report = dispatch(&mut carrier);
        assert!(
            matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::WrittenNoReceipt,
                    ..
                }
            ),
            "{report:?}"
        );
    }
    lab.publish("evt-3", &address, Mode::Message, "evt-3");
    for _ in 0..4 {
        let report = dispatch(&mut carrier);
        assert!(
            matches!(report, DispatchReport::Held(ref reason) if reason.contains("callback slots")),
            "{report:?}"
        );
        assert!(lab.attempt("evt-3").is_none(), "no attempt consumed");
    }
    let frames = harness.cmd(json!({"cmd": "frames"}));
    assert_eq!(frames["frames"].as_array().unwrap().len(), 2);
    // The first hand-off settles through its own transcript entry.
    let from = frames["frames"][0]["from"].as_str().unwrap().to_string();
    let manifest = lab.attempt("evt-1").unwrap().manifest;
    let entry = json!({"type": "user", "sessionId": "sess-cs", "origin": {"kind": "peer", "from": from}, "message": {"role": "user", "content": manifest}});
    std::fs::write(&transcript, format!("{entry}\n")).unwrap();
    assert!(eventually(10_000, || matches!(
        dispatch(&mut carrier),
        DispatchReport::Sent {
            state: AttemptState::WrittenNoReceipt,
            ..
        }
    )));
    assert_eq!(lab.attempt("evt-3").unwrap().fence.attempt_seq, 3);
    assert_eq!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        3,
        "handed off once"
    );
    harness.stop();
}

/// Under full callback slots the attestation-time capacity check reads no
/// transcript and frees only held hand-offs past their recheck horizon;
/// written-without-receipt slots are left to the background pass, which
/// reads the transcript before releasing one past its deadline. Positive
/// evidence that appears after a hand-off's closure deadline but before the
/// next background pass is therefore still recorded as context; its slot
/// then frees and the waiting message is handed off once, never earlier
/// (no attempt meanwhile).
#[test]
fn capacity_check_reads_no_transcript_and_keeps_late_evidence() {
    let lab = Lab::new("ce");
    let address = lab.claude_address("sess-ce");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-ce", "behavior": "none"}));
    let transcript = lab.claude_store.join("projects").join("ce.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, "").unwrap();
    let mut start = hook("SessionStart", "sess-ce");
    start["transcript_path"] = json!(transcript);
    harness.hook(&lab.socket, Harness::ClaudeCode, start);
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-ce"));
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let interval = Duration::from_secs(5);
    let timing = ClaudeTiming {
        receipt_wait: Duration::from_millis(100),
        receipt_deadline_ms: 1_000,
        max_callbacks: 2,
        close_interval: interval,
        ..ClaudeTiming::default()
    };
    // The background pass runs once now, then every `interval`.
    let mut carrier = ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, timing).unwrap();
    let next_pass = std::time::Instant::now() + interval;
    let dispatch = |carrier: &mut ClaudeLaterCarrier| {
        dispatch_message(
            &lab.storage,
            carrier,
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap()
    };
    let context = |event: &str| {
        lab.storage
            .lock()
            .unwrap()
            .delivery_evidence(PUBLISHER, event)
            .unwrap()
            .unwrap()
            .tiers
            .iter()
            .any(|tier| tier.tier.as_str() == "context_observed")
    };
    for event in ["evt-1", "evt-2"] {
        lab.publish(event, &address, Mode::Message, event);
        assert!(matches!(
            dispatch(&mut carrier),
            DispatchReport::Sent {
                state: AttemptState::WrittenNoReceipt,
                ..
            }
        ));
    }
    let past_deadline = std::time::Instant::now() + Duration::from_millis(1_300);
    lab.publish("evt-3", &address, Mode::Message, "evt-3");
    std::thread::sleep(past_deadline.saturating_duration_since(std::time::Instant::now()));
    // Positive evidence for the first hand-off appears after its deadline,
    // before the next background pass.
    let frames = harness.cmd(json!({"cmd": "frames"}));
    let from = frames["frames"][0]["from"].as_str().unwrap().to_string();
    let manifest = lab.attempt("evt-1").unwrap().manifest;
    let entry = json!({"type": "user", "sessionId": "sess-ce", "origin": {"kind": "peer", "from": from}, "message": {"role": "user", "content": manifest}});
    std::fs::write(&transcript, format!("{entry}\n")).unwrap();
    let held = dispatch(&mut carrier);
    let no_attempt = lab.attempt("evt-3").is_none();
    let context_before_pass = context("evt-1");
    assert!(
        std::time::Instant::now() + Duration::from_millis(500) < next_pass,
        "setup outran the background-pass window; the control would not discriminate"
    );
    // The background pass reads the transcript before releasing the slot.
    assert!(
        eventually(10_000, || context("evt-1")),
        "positive evidence that appeared across the deadline was lost"
    );
    assert!(
        matches!(held, DispatchReport::Held(ref reason) if reason.contains("callback slots")),
        "dispatched before the background pass: {held:?}"
    );
    assert!(no_attempt, "no attempt consumed while the slots were full");
    assert!(!context_before_pass, "the capacity check read a transcript");
    assert!(eventually(10_000, || matches!(
        dispatch(&mut carrier),
        DispatchReport::Sent {
            state: AttemptState::WrittenNoReceipt,
            ..
        }
    )));
    assert_eq!(lab.attempt("evt-3").unwrap().fence.attempt_seq, 3);
    assert_eq!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        3,
        "handed off once"
    );
    harness.stop();
}

/// The exact per-process descriptor `sessions/<pid>.json` is found even
/// when more than the legacy scan bound of other owned descriptors sort
/// before it in a wide store.
#[test]
fn direct_pid_descriptor_is_not_starved_by_a_wide_store() {
    let lab = Lab::new("wd");
    let address = lab.claude_address("sess-wd");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let sessions = lab.claude_store.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    for index in 0..600 {
        std::fs::write(
            sessions.join(format!("0000{index:04}.json")),
            json!({"sessionId": format!("other-{index}"), "pid": 1, "messagingSocketPath": null})
                .to_string(),
        )
        .unwrap();
    }
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-wd", "behavior": "delivered"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-wd"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-wd"));
    lab.publish("evt-wd", &address, Mode::Message, "wide store payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    harness.stop();
}

/// Evidence is per attempt: after an audited manual retry of the same event
/// (same session, same manifest), the earlier attempt's peer entry — whether
/// already in the transcript or appended late — cannot settle the new
/// attempt, because each attempt has its own callback origin; the new
/// attempt's own entry does.
#[test]
fn earlier_attempt_evidence_cannot_settle_a_retried_attempt() {
    let lab = Lab::new("ra");
    let address = lab.claude_address("sess-ra");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-ra", "behavior": "none"}));
    let transcript = lab.claude_store.join("projects").join("ra.jsonl");
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, "").unwrap();
    let mut start = hook("SessionStart", "sess-ra");
    start["transcript_path"] = json!(transcript);
    harness.hook(&lab.socket, Harness::ClaudeCode, start);
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-ra"));
    lab.publish("evt-retry", &address, Mode::Message, "retry payload");
    let first = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            first,
            DispatchReport::Sent {
                state: AttemptState::WrittenNoReceipt,
                ..
            }
        ),
        "{first:?}"
    );
    let attempt_one = lab.attempt("evt-retry").unwrap();
    lab.storage
        .lock()
        .unwrap()
        .authorize_manual_retry(
            PUBLISHER,
            "evt-retry",
            "operator",
            "regression: audited retry",
            now(),
        )
        .unwrap();
    let second = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            second,
            DispatchReport::Sent {
                state: AttemptState::WrittenNoReceipt,
                ..
            }
        ),
        "{second:?}"
    );
    let attempt_two = lab.attempt("evt-retry").unwrap();
    assert_ne!(attempt_one.fence.attempt_seq, attempt_two.fence.attempt_seq);
    assert_eq!(
        attempt_one.manifest, attempt_two.manifest,
        "same event, same manifest"
    );
    let frames = harness.cmd(json!({"cmd": "frames"}));
    let from_one = frames["frames"][0]["from"].as_str().unwrap().to_string();
    let from_two = frames["frames"][1]["from"].as_str().unwrap().to_string();
    assert_ne!(
        from_one, from_two,
        "each attempt has its own callback origin"
    );
    let entry = |from: &str| {
        json!({"type": "user", "sessionId": "sess-ra", "origin": {"kind": "peer", "from": from},
               "message": {"role": "user", "content": format!("Another Claude session sent a message:
{}
", attempt_two.manifest)}})
    };
    let context_for = |seq: u64| {
        let evidence = lab
            .storage
            .lock()
            .unwrap()
            .delivery_evidence(PUBLISHER, "evt-retry")
            .unwrap()
            .unwrap();
        evidence
            .tiers
            .iter()
            .any(|tier| tier.attempt_seq == seq && tier.tier.as_str() == "context_observed")
    };
    // Historical entry of the first attempt.
    std::fs::write(
        &transcript,
        format!(
            "{}
",
            entry(&from_one)
        ),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    // A delayed copy of the first attempt's entry appended after the retry.
    std::fs::write(
        &transcript,
        format!(
            "{}
{}
",
            entry(&from_one),
            entry(&from_one)
        ),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        !context_for(attempt_two.fence.attempt_seq),
        "old evidence settled the retried attempt"
    );
    assert_eq!(
        lab.attempt("evt-retry").unwrap().state,
        AttemptState::WrittenNoReceipt
    );
    // The retried attempt's own entry settles it.
    std::fs::write(
        &transcript,
        format!(
            "{}
{}
{}
",
            entry(&from_one),
            entry(&from_one),
            entry(&from_two)
        ),
    )
    .unwrap();
    assert!(eventually(6_000, || context_for(
        attempt_two.fence.attempt_seq
    )));
    harness.stop();
}

/// Losing the callback (carrier restart) never resends; core turns the overdue hold into an incident.
#[test]
fn lost_callback_after_restart_stays_retained_without_replay() {
    let lab = Lab::new("rs");
    let address = lab.claude_address("sess-9");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-9", "behavior": "held"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-9"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-9"));
    lab.publish("evt-restart", &address, Mode::Message, "restart payload");
    {
        let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
        let mut carrier =
            ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
                .unwrap();
        dispatch_message(
            &lab.storage,
            &mut carrier,
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap();
        // The carrier (and its callback memory) goes away: a restart.
    }
    // Its callback socket left the inbox directory with it; only the
    // fixture inbox's own socket remains.
    let sockets: Vec<String> = std::fs::read_dir(lab.claude_store.join("sessions"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".sock"))
        .collect();
    assert_eq!(sockets.len(), 1, "{sockets:?}");
    assert!(sockets[0].ends_with(".inbox.sock"));
    assert_eq!(
        lab.attempt("evt-restart").unwrap().state,
        AttemptState::NativeHeld
    );
    // A fresh carrier never resends a possibly handed event.
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut fresh =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let report = dispatch_message(
        &lab.storage,
        &mut fresh,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert_eq!(report, DispatchReport::Idle);
    assert_eq!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Past the recheck deadline core turns it into a retained incident.
    let attempt = lab.attempt("evt-restart").unwrap();
    lab.storage
        .lock()
        .unwrap()
        .run_maintenance(attempt.recheck_ms.unwrap() + 1)
        .unwrap();
    let incidents = lab
        .storage
        .lock()
        .unwrap()
        .incidents(false, now(), 10)
        .unwrap();
    assert!(
        incidents.iter().any(|i| i.event_id == "evt-restart"),
        "{incidents:?}"
    );
    harness.stop();
}

/// Writes the fake App Server behavior and probe port.
fn codex_setup(lab: &Lab, behavior: &str, port: u16) {
    std::fs::write(lab.codex_store.join("behavior"), behavior).unwrap();
    std::fs::write(lab.codex_store.join("probe_port"), port.to_string()).unwrap();
    let _ = std::fs::remove_file(lab.codex_store.join("probe.json"));
}

/// The Codex helper runs confined (negative probe plus positive control) and classifies accept, refusal and silence.
#[test]
fn codex_queue_helper_is_confined_and_classifies_outcomes() {
    let lab = Lab::new("cx");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = lab.codex_address("thread-root");
    let mut harness = Harnessed::start(Harness::Codex, &lab.codex_store);
    harness.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "thread-root"),
    );
    harness.hook(&lab.socket, Harness::Codex, hook("Stop", "thread-root"));
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/usr/bin/sandbox-exec".into(),
        Duration::from_secs(10),
    );
    let timing = DispatchTiming::default();

    codex_setup(&lab, "accept", port);
    lab.publish("evt-q1", &address, Mode::Message, "queued payload");
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    let queued: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(lab.codex_store.join("queue.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(queued["threadId"], "thread-root");
    assert_eq!(
        queued["input"][0]["text"],
        lab.attempt("evt-q1").unwrap().manifest
    );
    // Actual OS confinement inside the launched helper: no network, no
    // child process.
    let probe: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(lab.codex_store.join("probe.json")).unwrap())
            .unwrap();
    assert_eq!(
        probe,
        json!({"network_connected": false, "child_spawned": false})
    );
    // Positive control: the same probe outside the confinement can reach
    // the listener and spawn a child, so the negative result is the
    // policy's doing.
    {
        use std::io::Write;
        let mut unconfined = std::process::Command::new(fixture_exe())
            .arg("app-server")
            .env("CODEX_HOME", &lab.codex_store)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = unconfined.stdin.take().unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"id": 1, "method": "initialize", "params": {}})
        )
        .unwrap();
        drop(stdin);
        unconfined.wait().unwrap();
    }
    let control: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(lab.codex_store.join("probe.json")).unwrap())
            .unwrap();
    assert_eq!(
        control,
        json!({"network_connected": true, "child_spawned": true})
    );

    // Native errors after the write (validation-like or internal after a
    // queue effect) and a success without a correlated submission are all
    // unknown: retained, never known-unsent, never retried.
    for (event, behavior) in [
        ("evt-q2", "refuse"),
        ("evt-q2i", "internal"),
        ("evt-q2m", "malformed"),
    ] {
        codex_setup(&lab, behavior, port);
        lab.publish(event, &address, Mode::Message, "refused payload");
        let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        assert!(
            matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::OutcomeUnknown,
                    ..
                }
            ),
            "{behavior}: {report:?}"
        );
    }

    codex_setup(&lab, "silent", port);
    let mut slow = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/usr/bin/sandbox-exec".into(),
        Duration::from_secs(2),
    );
    lab.publish("evt-q3", &address, Mode::Message, "silent payload");
    let report = dispatch_message(&lab.storage, &mut slow, &address, &now, &timing).unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::OutcomeUnknown,
                ..
            }
        ),
        "{report:?}"
    );
    drop(listener);
    harness.stop();
}

/// A Codex child thread drains only its own address and its caller join needs its own thread id.
#[test]
fn codex_child_thread_has_its_own_address_and_drains_only_its_own() {
    let lab = Lab::new("ct");
    let mut harness = Harnessed::start(Harness::Codex, &lab.codex_store);
    harness.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "thread-r"),
    );
    let child_start = json!({"hook_event_name": "SessionStart", "session_id": "thread-r", "agent_id": "thread-c"});
    harness.hook(&lab.socket, Harness::Codex, child_start);
    lab.publish(
        "evt-root",
        &lab.codex_address("thread-r"),
        Mode::Inject,
        "for the root",
    );
    lab.publish(
        "evt-child",
        &lab.codex_address("thread-c"),
        Mode::Inject,
        "for the child",
    );

    let child = harness.hook(
        &lab.socket,
        Harness::Codex,
        tool_hook("PostToolUse", "thread-r", "call-c", Some("thread-c")),
    );
    assert!(
        child["stdout"].as_str().unwrap().contains("for the child"),
        "{child}"
    );
    assert!(
        lab.attempt("evt-root").is_none(),
        "the child never drains the root"
    );

    // Codex caller: threadId must be the recorded actor of the call id.
    harness.hook(
        &lab.socket,
        Harness::Codex,
        tool_hook("PreToolUse", "thread-r", "call-x", Some("thread-c")),
    );
    let wrong = harness.mcp(
        &lab.socket,
        json!({"threadId": "thread-r", "callId": "call-x", "x-codex-turn-metadata": {}}),
    );
    assert_eq!(wrong["err"], "conflicting", "{wrong}");
    harness.hook(
        &lab.socket,
        Harness::Codex,
        tool_hook("PreToolUse", "thread-r", "call-y", Some("thread-c")),
    );
    let right = harness.mcp(
        &lab.socket,
        json!({"threadId": "thread-c", "callId": "call-y", "x-codex-turn-metadata": {}}),
    );
    assert_eq!(
        right["ok"]["address"],
        lab.codex_address("thread-c").to_canonical_string(),
        "{right}"
    );
    assert_eq!(right["ok"]["may_act_as_address"], true);
    harness.stop();
}

/// A message capability unavailable on the host refuses publication before acceptance.
#[test]
fn unsupported_message_capability_refuses_before_acceptance() {
    let lab = Lab::new("us");
    lab.registry.lock().unwrap().disable_message(Harness::Codex);
    let mut harness = Harnessed::start(Harness::Codex, &lab.codex_store);
    harness.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "thread-u"),
    );
    let address = lab.codex_address("thread-u");
    let refused = lab
        .try_publish("evt-u", &address, Mode::Message)
        .unwrap_err();
    assert!(
        refused.contains("unsupported") || refused.contains("capab"),
        "{refused}"
    );
    // inject stays supported.
    lab.try_publish("evt-i", &address, Mode::Inject).unwrap();
    harness.stop();
}

/// A second live harness process cannot take over a bound session; a later renewal fences old records.
#[test]
fn a_second_live_incarnation_cannot_take_over_a_bound_session() {
    let lab = Lab::new("ti");
    let mut first = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    first.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-10"),
    );
    let mut second = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let reply = second.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-10"),
    );
    assert!(
        reply["stderr"].as_str().unwrap().contains("conflicting"),
        "{reply}"
    );
    // After the first ends, the session may be renewed by the second with a
    // larger epoch; the first's records are stale.
    first.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-10", "tu-a", None),
    );
    let old_epoch = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&lab.claude_address("sess-10"))
        .unwrap()
        .1
        .epoch;
    first.stop();
    second.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-10"),
    );
    let new_epoch = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&lab.claude_address("sess-10"))
        .unwrap()
        .1
        .epoch;
    assert!(new_epoch > old_epoch);
    assert_eq!(
        second.mcp(&lab.socket, claude_meta("tu-a"))["err"],
        "missing"
    );
    second.stop();
}

/// Sealed proofs redeem once, only in a configured relay, and go stale on renewal.
#[test]
fn sealed_proof_relays_registry_facts_once_to_a_configured_relay() {
    let lab = Lab::new("sp");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-11"),
    );
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-11", "tu-s1", Some("agent-z")),
    );
    let frontend = harness.mcp_sealed(&lab.socket, claude_meta("tu-s1"));
    let proof = frontend["proof"].as_str().unwrap().to_string();
    assert_eq!(frontend["ok"]["relayed"], false);

    // The test process is not a configured relay: refused before the proof
    // is even looked up.
    let attestor = RegistryAttestor::new(&lab.socket, Duration::from_secs(5), 600_000);
    let foreign = attestor.attest(
        &PresentedMeta::sealed(SealedProof::from_wire(proof.clone())),
        now(),
    );
    assert_eq!(foreign.unwrap_err().class(), "not_evidence");

    // A fresh proof redeems once in the relay with exactly the registry's
    // facts (child agent-z, not acting as the address).
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-11", "tu-s2", Some("agent-z")),
    );
    let proof = harness.mcp_sealed(&lab.socket, claude_meta("tu-s2"))["proof"]
        .as_str()
        .unwrap()
        .to_string();
    let relayed = relay_redeem(&lab.socket, &proof);
    assert_eq!(relayed["ok"]["native_id"], "agent-z", "{relayed}");
    assert_eq!(relayed["ok"]["role"], "child");
    assert_eq!(relayed["ok"]["relayed"], true);
    assert_eq!(relayed["ok"]["may_act_as_address"], false);
    assert_eq!(
        relay_redeem(&lab.socket, &proof)["err"],
        "missing",
        "single use"
    );
    assert_eq!(relay_redeem(&lab.socket, "00")["err"], "missing");

    // Renewal between sealing and redemption makes the proof stale.
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-11", "tu-s3", None),
    );
    let proof = harness.mcp_sealed(&lab.socket, claude_meta("tu-s3"))["proof"]
        .as_str()
        .unwrap()
        .to_string();
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-11"),
    );
    assert_eq!(relay_redeem(&lab.socket, &proof)["err"], "stale");
    harness.stop();
}

/// One total budget bounds the Codex helper: a notification flood never
/// extends it and a helper that stops reading cannot block the write past
/// it; both possibly-written hand-offs end unknown, never accepted.
#[test]
fn codex_helper_total_budget_survives_floods_and_stalled_writes() {
    let lab = Lab::new("cb");
    let address = lab.codex_address("thread-b");
    let mut harness = Harnessed::start(Harness::Codex, &lab.codex_store);
    harness.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "thread-b"),
    );
    harness.hook(&lab.socket, Harness::Codex, hook("Stop", "thread-b"));
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/usr/bin/sandbox-exec".into(),
        Duration::from_secs(2),
    );
    let timing = DispatchTiming::default();
    // Larger than a pipe buffer once escaped, so a non-reading helper blocks
    // the write.
    let big = format!("{}{}", "x".repeat(20_000), "<".repeat(15_000));
    for (event, behavior) in [("evt-flood", "flood"), ("evt-stall", "stall")] {
        codex_setup(&lab, behavior, 9);
        lab.publish(event, &address, Mode::Message, &big);
        let started = std::time::Instant::now();
        let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        let took = started.elapsed();
        assert!(
            matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::OutcomeUnknown,
                    ..
                }
            ),
            "{behavior}: {report:?}"
        );
        assert!(took < Duration::from_secs(5), "{behavior} took {took:?}");
    }
    harness.stop();
}

/// The real `bridge-native-daemon` composition: the probe MCP server
/// launched by the harness attests its root caller from `_meta`, publishes
/// through the core socket, and the root's own `PostToolUse` hook receives
/// the marker as context; the publisher's status shows the hand-off.
#[test]
fn daemon_composition_hands_probe_context_to_the_root_hook() {
    let dir = TempDir::new("dc");
    let store = dir.0.join("s");
    std::fs::create_dir(&store).unwrap();
    let channel_dir = dir.0.join("ch");
    bridge_adapters::server::private_directory(&channel_dir).unwrap();
    let channel = channel_dir.join("c.sock");
    let core = dir.0.join("core.sock");
    let evidence = dir.0.join("probe.jsonl");
    let token = "probe-token-0123456789abcdef";
    let token_file = dir.0.join("publisher.token");
    std::fs::write(&token_file, token).unwrap();
    std::fs::set_permissions(
        &token_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let address =
        bridge_core::NativeAddress::new(HOST, Harness::ClaudeCode, "claude-lab", "sess-d").unwrap();
    let config = format!(
        r#"database = "{db}"
socket = "{core}"
[limits]
max_admitted_events = 100
[[grant]]
token = "{token}"
publisher = "probe-pub"
recipients = ["{recipient}"]
kinds = ["bridge.probe"]
modes = ["inject", "message"]
policies = ["keep_all"]
[adapters]
channel = "{channel}"
host_id = "{HOST}"
[[adapters.harnesses]]
harness = "ClaudeCode"
namespace = "claude-lab"
inject = true
message = true
executable_markers = ["bridge-fixture"]
"#,
        db = dir.0.join("b.db").display(),
        core = core.display(),
        recipient = address.to_canonical_string(),
        channel = channel.display(),
    );
    let config_path = dir.0.join("bridge.toml");
    std::fs::write(&config_path, config).unwrap();
    let mut daemon = std::process::Command::new(env!("CARGO_BIN_EXE_bridge-native-daemon"))
        .arg(&config_path)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(eventually(5_000, || channel.exists() && core.exists()));

    let mut harness = Harnessed::start(Harness::ClaudeCode, &store);
    harness.hook(
        &channel,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-d"),
    );
    harness.hook(
        &channel,
        Harness::ClaudeCode,
        hook("UserPromptSubmit", "sess-d"),
    );
    harness.hook(
        &channel,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-d", "tu-d1", None),
    );
    let reply = harness.cmd(json!({
        "cmd": "mcp_server",
        "args": [channel, core, token_file, evidence],
        "requests": [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "bridge_probe", "arguments": {"claim": "I am root"},
                "_meta": {"claudecode/toolUseId": "tu-d1"}}}
        ]
    }));
    let text = reply["responses"][2]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("root"), "{reply}");
    assert!(
        !text.contains("BRIDGE_CTX_"),
        "the marker never travels in the tool result"
    );
    let record: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&evidence)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    let marker = record["marker"].as_str().unwrap().to_string();
    assert!(record["publish"].get("Published").is_some(), "{record}");

    let post = harness.hook(
        &channel,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-d", "tu-d1", None),
    );
    assert!(post["stdout"].as_str().unwrap().contains(&marker), "{post}");
    // Tool annotations: only bridge_me claims to be read-only.
    let tools = reply["responses"][1]["result"]["tools"]
        .as_array()
        .unwrap()
        .clone();
    let read_only = |name: &str| {
        tools.iter().find(|tool| tool["name"] == name).unwrap()["annotations"]["readOnlyHint"]
            .clone()
    };
    assert_eq!(read_only("bridge_me"), json!(true));
    assert_eq!(read_only("bridge_probe"), json!(false));
    assert_eq!(read_only("bridge_unlisted"), json!(false));
    // bridge_me attests the root without publishing; bridge_unlisted only
    // records that it ran (what a host refusal must prevent).
    harness.hook(
        &channel,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "sess-d", "tu-d2", None),
    );
    let second = harness.cmd(json!({
        "cmd": "mcp_server",
        "args": [channel, core, token_file, evidence],
        "requests": [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "bridge_me", "arguments": {}, "_meta": {"claudecode/toolUseId": "tu-d2"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_unlisted", "arguments": {}}}
        ]
    }));
    assert!(
        second["responses"][1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("root"),
        "{second}"
    );
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&evidence)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let me = records.iter().find(|r| r["tool"] == "bridge_me").unwrap();
    assert_eq!(me["caller"]["role"], "root");
    assert!(
        me.get("marker").is_none() && me.get("publish").is_none(),
        "{me}"
    );
    assert!(
        records
            .iter()
            .any(|r| r["tool"] == "bridge_unlisted" && r["unlisted_called"] == true)
    );
    // A probe's tool subset: only the named tools are listed, and a call to
    // any other one is refused without running or recording anything.
    let before = std::fs::read_to_string(&evidence).unwrap().lines().count();
    let subset = harness.cmd(json!({
        "cmd": "mcp_server",
        "args": [channel, core, token_file, evidence, "bridge_probe"],
        "requests": [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "bridge_unlisted", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "bridge_me", "arguments": {}}}
        ]
    }));
    let listed: Vec<&str> = subset["responses"][1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["bridge_probe"], "{subset}");
    assert!(subset["responses"][2]["error"].is_object(), "{subset}");
    assert!(subset["responses"][3]["error"].is_object(), "{subset}");
    assert_eq!(
        std::fs::read_to_string(&evidence).unwrap().lines().count(),
        before,
        "a tool outside the subset never runs"
    );
    let event = record["event_id"].as_str().unwrap();
    let status = std::process::Command::new(fixture_exe())
        .args([
            "status",
            core.to_str().unwrap(),
            token_file.to_str().unwrap(),
            event,
        ])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&status.stdout).to_string();
    assert!(status.contains("Status"), "{status}");
    // A token file readable by group or others is refused before any request.
    std::fs::set_permissions(
        &token_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    let refused = std::process::Command::new(fixture_exe())
        .args([
            "status",
            core.to_str().unwrap(),
            token_file.to_str().unwrap(),
            event,
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(5));
    assert!(refused.stdout.is_empty());
    harness.stop();
    std::process::Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(daemon.wait().unwrap().success());
}

/// Lifecycle of a recipient as the message carrier would see it.
fn recipient_lifecycle(lab: &Lab, session: &str) -> bridge_core::dispatch::Lifecycle {
    let registry = lab.registry.lock().unwrap();
    let (attestation, _) = registry
        .attest_recipient(&lab.claude_address(session))
        .expect("bound recipient");
    attestation.lifecycle()
}

/// A binding first seen through an event that is not a positive root idle/active observation (child events, unrelated notifications, compaction restarts) stays unknown, fresh or renewed; positive root events still transition.
#[test]
fn first_event_without_positive_root_evidence_is_never_inactive() {
    use bridge_core::dispatch::Lifecycle::{Active, AwaitingInput, Inactive, Unknown};
    let lab = Lab::new("lf");
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    let claude = Harness::ClaudeCode;
    let child = |event: &str, session: &str| {
        let mut payload = hook(event, session);
        payload["agent_id"] = json!("agent-a");
        payload
    };
    let note = |session: &str, kind: &str| {
        let mut payload = hook("Notification", session);
        payload["notification_type"] = json!(kind);
        payload
    };

    // Fresh bindings created by events that say nothing about the root.
    for (session, payload) in [
        ("s-sub", child("SubagentStop", "s-sub")),
        ("s-cstop", child("Stop", "s-cstop")),
        ("s-cend", child("SessionEnd", "s-cend")),
        ("s-note", note("s-note", "auth_success")),
        ("s-cidle", {
            let mut payload = note("s-cidle", "idle_prompt");
            payload["agent_id"] = json!("agent-a");
            payload
        }),
        ("s-compact", {
            let mut payload = hook("SessionStart", "s-compact");
            payload["source"] = json!("compact");
            payload
        }),
    ] {
        harness.hook(&lab.socket, claude, payload);
        assert_eq!(recipient_lifecycle(&lab, session), Unknown, "{session}");
    }

    // Positive root observations still move the state, and unrelated
    // events afterwards keep the last positive state.
    harness.hook(&lab.socket, claude, hook("SessionStart", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Inactive);
    harness.hook(&lab.socket, claude, hook("UserPromptSubmit", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Active);
    harness.hook(&lab.socket, claude, child("SubagentStop", "s-pos"));
    harness.hook(&lab.socket, claude, note("s-pos", "auth_success"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Active);
    harness.hook(&lab.socket, claude, hook("PermissionRequest", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), AwaitingInput);
    harness.hook(&lab.socket, claude, hook("Stop", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Inactive);
    harness.hook(&lab.socket, claude, child("Stop", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Inactive);
    harness.hook(&lab.socket, claude, hook("UserPromptSubmit", "s-pos"));
    harness.hook(&lab.socket, claude, note("s-pos", "idle_prompt"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Inactive);

    // A renewed binding (root session ended, then a first unrelated event)
    // restarts as unknown rather than inheriting or defaulting to idle.
    harness.hook(&lab.socket, claude, hook("SessionEnd", "s-pos"));
    harness.hook(&lab.socket, claude, child("SubagentStop", "s-pos"));
    assert_eq!(recipient_lifecycle(&lab, "s-pos"), Unknown);
    harness.stop();
}

/// Dispatches one message to `session` after `prepare` shaped the store's `sessions` directory, returning the report and the frames the fixture inbox received.
fn dispatch_with_store(
    tag: &str,
    session: &str,
    prepare: impl FnOnce(&std::path::Path, u32),
) -> (DispatchReport, usize) {
    let lab = Lab::new(tag);
    let address = lab.claude_address(session);
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": session, "behavior": "delivered"}));
    prepare(&lab.claude_store.join("sessions"), harness.child.id());
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", session),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", session));
    lab.publish("evt-tok", &address, Mode::Message, "token payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    let frames = harness.cmd(json!({"cmd": "frames"}))["frames"]
        .as_array()
        .unwrap()
        .len();
    harness.stop();
    (report, frames)
}

/// The recipient's own `<pid>.*.key` peer token is found when more than the scan bound of other session-registry entries sort before it.
#[test]
fn peer_token_is_not_starved_by_a_wide_store() {
    let (report, frames) = dispatch_with_store("wt", "sess-wt", |sessions, _| {
        for index in 0..1_200 {
            std::fs::write(
                sessions.join(format!("0{index:05}.other.key")),
                json!({"peerToken": "foreign-token"}).to_string(),
            )
            .unwrap();
        }
    });
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(frames, 1);
}

/// Another process's token and an unsafe (symlinked) token of the right process are never used: nothing is sent.
#[test]
fn foreign_and_symlinked_peer_tokens_are_refused() {
    let (report, frames) = dispatch_with_store("ft", "sess-ft", |sessions, pid| {
        let own = sessions.join(format!("{pid}.fixture.key"));
        let valid = std::fs::read_to_string(&own).unwrap();
        std::fs::remove_file(&own).unwrap();
        // Right content under another process's name, and a symlink under
        // the right name.
        std::fs::write(sessions.join(format!("{}.fixture.key", pid + 1)), &valid).unwrap();
        let target = sessions.join("target.txt");
        std::fs::write(&target, valid).unwrap();
        std::os::unix::fs::symlink(&target, sessions.join(format!("{pid}.link.key"))).unwrap();
    });
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::KnownUnsent,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(frames, 0);
}

/// Dispatches one message to a fixture inbox that answers with the receipt sequence `behavior`, returning the report, the stored attempt state and the number of frames the inbox received.
fn dispatch_with_receipts(
    tag: &str,
    behavior: &str,
) -> (DispatchReport, Option<AttemptState>, usize) {
    let lab = Lab::new(tag);
    let session = format!("sess-{tag}");
    let address = lab.claude_address(&session);
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let timing = ClaudeTiming {
        receipt_wait: Duration::from_millis(3_000),
        ..ClaudeTiming::default()
    };
    let mut carrier = ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, timing).unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": session, "behavior": behavior}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", &session),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", &session));
    lab.publish("evt-rc", &address, Mode::Message, "receipt payload");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    // Let any receipt that raced the first one reach the hub.
    std::thread::sleep(Duration::from_millis(500));
    let state = lab.attempt("evt-rc").map(|attempt| attempt.state);
    let frames = harness.cmd(json!({"cmd": "frames"}))["frames"]
        .as_array()
        .unwrap()
        .len();
    harness.stop();
    (report, state, frames)
}

/// A `held` receipt followed at once by its terminal receipt, both inside the first-receipt window, settles on the terminal evidence instead of leaving the attempt held, and nothing is resent.
#[test]
fn held_then_terminal_receipts_in_the_first_window_settle_once() {
    let (report, state, frames) = dispatch_with_receipts("hd", "held,delivered");
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(state, Some(AttemptState::NativeAccepted));
    assert_eq!(frames, 1);

    let (report, state, frames) = dispatch_with_receipts("hr", "held,dropped");
    let refused = dispatch_with_receipts("hf", "held,refused");
    assert!(
        matches!(
            refused.0,
            DispatchReport::Sent {
                state: AttemptState::OutcomeUnknown,
                ..
            }
        ),
        "{:?}",
        refused.0
    );
    assert_eq!(
        (refused.1, refused.2),
        (Some(AttemptState::OutcomeUnknown), 1)
    );
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::OutcomeUnknown,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(state, Some(AttemptState::OutcomeUnknown));
    assert_eq!(frames, 1);
}

/// Both hold paths (first-window `held` and a late `held` after silence) use the configured recheck horizon, not a fixed ten minutes.
#[test]
fn held_recheck_horizon_honors_the_configured_timing_on_both_paths() {
    let horizon = 3_600_000;
    let lab = Lab::new("hz");
    let address = lab.claude_address("sess-hz");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let timing = ClaudeTiming {
        receipt_wait: Duration::from_millis(800),
        held_recheck_ms: horizon,
        ..ClaudeTiming::default()
    };
    let mut carrier = ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, timing).unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-hz", "behavior": "held"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-hz"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-hz"));
    let near_horizon = |event: &str| {
        let recheck = lab.attempt(event).unwrap().recheck_ms.unwrap();
        recheck.abs_diff(now() + horizon) < 60_000
    };

    // First-window hold.
    lab.publish("evt-first", &address, Mode::Message, "first");
    dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert_eq!(
        lab.attempt("evt-first").unwrap().state,
        AttemptState::NativeHeld
    );
    assert!(near_horizon("evt-first"));

    // Late hold: silence first, then the recipient reports `held`.
    let first_frames = harness.cmd(json!({"cmd": "frames"}))["frames"]
        .as_array()
        .unwrap()
        .len();
    let first_msg = harness.cmd(json!({"cmd": "frames"}))["frames"][0]["msg_id"]
        .as_str()
        .unwrap()
        .to_string();
    harness.cmd(json!({"cmd": "receipt", "msg_id": first_msg, "status": "delivered"}));
    assert!(eventually(3_000, || lab
        .attempt("evt-first")
        .unwrap()
        .state
        == AttemptState::NativeAccepted));
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-hz", "behavior": "none"}));
    lab.publish("evt-late", &address, Mode::Message, "late");
    dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert_eq!(
        lab.attempt("evt-late").unwrap().state,
        AttemptState::WrittenNoReceipt
    );
    let late_msg = harness.cmd(json!({"cmd": "frames"}))["frames"][first_frames]["msg_id"]
        .as_str()
        .unwrap()
        .to_string();
    harness.cmd(json!({"cmd": "receipt", "msg_id": late_msg, "status": "held"}));
    assert!(eventually(3_000, || lab.attempt("evt-late").unwrap().state
        == AttemptState::NativeHeld));
    assert!(near_horizon("evt-late"));
    harness.stop();
}

/// Lifecycle and endpoint epoch of the binding at `address`.
fn binding_state(
    lab: &Lab,
    address: &bridge_core::NativeAddress,
) -> (bridge_core::dispatch::Lifecycle, u64) {
    let registry = lab.registry.lock().unwrap();
    let (attestation, _) = registry.attest_recipient(address).expect("bound recipient");
    (attestation.lifecycle(), attestation.endpoint_epoch())
}

/// Only the owner's own non-compact `SessionStart` establishes idleness and renews the binding: a Claude child's `SessionStart`, and a root `compact` restart, keep the owner's lifecycle, epoch and call records; startup, resume and clear renew with a larger epoch; a Codex child owns its separate address.
#[test]
fn only_an_own_non_compact_session_start_renews_or_idles_the_owner() {
    use bridge_core::dispatch::Lifecycle::{Active, AwaitingInput, Inactive, Unknown};
    let lab = Lab::new("ss");
    let claude = Harness::ClaudeCode;
    let mut harness = Harnessed::start(claude, &lab.claude_store);
    let start = |session: &str, agent: Option<&str>, source: Option<&str>| {
        let mut payload = hook("SessionStart", session);
        if let Some(agent) = agent {
            payload["agent_id"] = json!(agent);
        }
        if let Some(source) = source {
            payload["source"] = json!(source);
        }
        payload
    };

    // A child's SessionStart that creates the binding says nothing about
    // the owner.
    let fresh = lab.claude_address("s-fresh");
    harness.hook(&lab.socket, claude, start("s-fresh", Some("agent-a"), None));
    assert_eq!(binding_state(&lab, &fresh).0, Unknown);

    // An active owner: a child SessionStart and a compact restart keep the
    // lifecycle, the epoch and the unconsumed call record.
    let owner = lab.claude_address("s-own");
    harness.hook(&lab.socket, claude, start("s-own", None, Some("startup")));
    assert_eq!(binding_state(&lab, &owner).0, Inactive);
    harness.hook(&lab.socket, claude, hook("UserPromptSubmit", "s-own"));
    let (lifecycle, epoch) = binding_state(&lab, &owner);
    assert_eq!(lifecycle, Active);
    for (step, wait) in [("child", Active), ("compact", Active)] {
        harness.hook(
            &lab.socket,
            claude,
            tool_hook("PreToolUse", "s-own", &format!("tu-{step}"), None),
        );
        let payload = match step {
            "child" => start("s-own", Some("agent-a"), None),
            _ => start("s-own", None, Some("compact")),
        };
        harness.hook(&lab.socket, claude, payload);
        assert_eq!(binding_state(&lab, &owner), (wait, epoch), "{step}");
        let caller = harness.mcp(&lab.socket, claude_meta(&format!("tu-{step}")));
        assert_eq!(caller["ok"]["role"], "root", "{step}: {caller}");
        assert_eq!(caller["ok"]["may_act_as_address"], true);
    }
    // The same while the owner awaits input.
    harness.hook(&lab.socket, claude, hook("PermissionRequest", "s-own"));
    for payload in [
        start("s-own", Some("agent-a"), None),
        start("s-own", None, Some("compact")),
    ] {
        harness.hook(&lab.socket, claude, payload);
        assert_eq!(binding_state(&lab, &owner), (AwaitingInput, epoch));
    }

    // Real owner startup, resume and clear renew with a larger epoch and
    // are idle.
    let mut previous = epoch;
    for source in ["startup", "resume", "clear"] {
        harness.hook(&lab.socket, claude, hook("UserPromptSubmit", "s-own"));
        harness.hook(&lab.socket, claude, start("s-own", None, Some(source)));
        let (lifecycle, epoch) = binding_state(&lab, &owner);
        assert_eq!(lifecycle, Inactive, "{source}");
        assert!(epoch > previous, "{source} must renew the epoch");
        previous = epoch;
    }
    harness.stop();

    // A Codex child is its own owner at its own address; the root's state
    // is unaffected.
    let mut codex = Harnessed::start(Harness::Codex, &lab.codex_store);
    let root = lab.codex_address("thread-r");
    let child = lab.codex_address("thread-c");
    codex.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "thread-r"),
    );
    codex.hook(
        &lab.socket,
        Harness::Codex,
        hook("UserPromptSubmit", "thread-r"),
    );
    let root_before = binding_state(&lab, &root);
    assert_eq!(root_before.0, Active);
    let mut child_start = hook("SessionStart", "thread-r");
    child_start["agent_id"] = json!("thread-c");
    codex.hook(&lab.socket, Harness::Codex, child_start);
    assert_eq!(binding_state(&lab, &child).0, Inactive);
    assert_eq!(binding_state(&lab, &root), root_before);
    codex.stop();
}

/// Receipts of one window: a native negative (alone or repeated) and contradictory receipts (a refusal next to a delivery or a hold) are an unknown outcome, never known-unsent; single or repeated delivery and plain holds keep their exact classification; nothing is resent.
#[test]
fn contradictory_receipts_in_one_window_are_unknown_not_known_unsent() {
    use AttemptState::{NativeAccepted, NativeHeld, OutcomeUnknown};
    let table = [
        ("refused", OutcomeUnknown),
        ("delivered", NativeAccepted),
        ("refused,refused", OutcomeUnknown),
        ("delivered,delivered", NativeAccepted),
        ("held,held", NativeHeld),
        ("refused,delivered", OutcomeUnknown),
        ("delivered,refused", OutcomeUnknown),
        ("refused,held", OutcomeUnknown),
        ("delivered,held", OutcomeUnknown),
    ];
    for (index, (behavior, expected)) in table.into_iter().enumerate() {
        let (report, state, frames) = dispatch_with_receipts(&format!("cr{index}"), behavior);
        assert!(
            matches!(report, DispatchReport::Sent { state: reported, .. } if reported == expected),
            "{behavior}: {report:?}"
        );
        assert_eq!(state, Some(expected), "{behavior}");
        assert_eq!(frames, 1, "{behavior}: a hand-off is never repeated");
    }
}

/// A native negative status after the write is not proof that nothing was handed off: the attempt is an unknown outcome, so a delivery that arrives later on another connection (after the callback closed) cannot be turned into an automatic second hand-off.
#[test]
fn native_refusal_after_the_write_is_unknown_and_never_repeats() {
    let lab = Lab::new("nr");
    let address = lab.claude_address("sess-nr");
    let custody = Arc::clone(&lab.storage) as Arc<dyn Custody>;
    let mut carrier =
        ClaudeLaterCarrier::new(Arc::clone(&lab.registry), custody, ClaudeTiming::default())
            .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    harness.cmd(json!({"cmd": "inbox", "session_id": "sess-nr", "behavior": "refused"}));
    harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-nr"),
    );
    harness.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "sess-nr"));
    lab.publish("evt-nr", &address, Mode::Message, "refused payload");
    let timing = DispatchTiming::default();
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::OutcomeUnknown,
                ..
            }
        ),
        "{report:?}"
    );
    // The delivery the refusal did not exclude arrives later on another
    // connection; the attempt stays unknown and nothing is sent again.
    let frames = harness.cmd(json!({"cmd": "frames"}));
    let msg_id = frames["frames"][0]["msg_id"].as_str().unwrap().to_string();
    harness.cmd(json!({"cmd": "receipt", "msg_id": msg_id, "status": "delivered"}));
    std::thread::sleep(Duration::from_millis(500));
    for _ in 0..3 {
        let again = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        assert!(!matches!(again, DispatchReport::Sent { .. }), "{again:?}");
    }
    assert_eq!(
        lab.attempt("evt-nr").unwrap().state,
        AttemptState::OutcomeUnknown
    );
    assert_eq!(
        harness.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "no automatic repeat of a possible hand-off"
    );
    harness.stop();
}

/// The production signed-parent layout authenticates its inherited descriptor,
/// reaches one fixed host call, and returns its exact receipt without child auth inheritance.
#[test]
fn signed_parent_private_channel_delivers_one_message() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};
    let Some(node) = std::env::var_os("BRIDGE_TEST_NODE") else {
        eprintln!("signed parent check skipped: BRIDGE_TEST_NODE missing");
        return;
    };
    let dir = TempDir::new("sp");
    let channel = dir.0.join("c.sock");
    let listener = UnixListener::bind(&channel).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let daemon = std::thread::spawn(move || {
        let mut peers = Vec::new();
        while !stopping.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => peers.push(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
        peers
    });
    let pipe = dir.0.join("h.sock");
    let host = UnixListener::bind(&pipe).unwrap();
    let native = std::thread::spawn(move || {
        let (mut stream, _) = host.accept().unwrap();
        for id in [1, 2] {
            let mut head = [0; 4];
            stream.read_exact(&mut head).unwrap();
            let n = u32::from_le_bytes(head) as usize;
            assert!(n < 131072);
            let mut body = vec![0; n];
            stream.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["id"], id);
            if id == 2 {
                assert_eq!(
                    request["params"]["arguments"],
                    json!({"threadId":"owned-thread","prompt":"marker"})
                );
            }
            let result = if id == 1 {
                json!({"tools":[{"name":"send_message_to_thread","namespace":"codex_app"}]})
            } else {
                json!({"success":true})
            };
            let bytes =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
        }
    });
    let mut child = Command::new(node)
        .arg("-e")
        .arg(include_str!("../assets/desktop-client.cjs"))
        .arg("--")
        .arg(fixture_exe())
        .arg("desktop-child")
        .arg(&channel)
        .env("CODEX_APP_TOOLS_PIPE_PATH", &pipe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");
    let me = bridge_adapters::os::process_facts(std::process::id()).unwrap();
    let path = bridge_adapters::desktop::frontend_for(&dir.0, (me.pid, me.start_time)).unwrap();
    // Simulate a daemon upgrade while its signed primary MCP process stays open.
    let pid = path
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('-')
        .next()
        .unwrap();
    let older = dir.0.join(format!("ui2-previous-{pid}.sock"));
    std::fs::rename(&path, &older).unwrap();
    let path = bridge_adapters::desktop::frontend_for(&dir.0, (me.pid, me.start_time)).unwrap();
    assert_eq!(path, older);
    let result = bridge_adapters::desktop::via_frontend(
        &path,
        (me.pid, me.start_time),
        "owned-thread",
        "bridge-call",
        "marker",
    );
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(
        matches!(
            result,
            bridge_core::dispatch::Outcome::NativeAccepted { .. }
        ),
        "{result:?}"
    );
    native.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    drop(daemon.join().unwrap());
}

/// A fresh daemon registry restores only the same verified live session, without
/// another recipient hook/MCP call; new fences reach core and caller proofs do not survive.
#[test]
fn recipient_routes_recover_after_restart_without_recipient_activity() {
    use bridge_adapters::server::private_directory;
    use bridge_adapters::{ChannelServer, Registry};
    use std::os::unix::fs::PermissionsExt;
    let mut lab = Lab::new("jr");
    let address = lab.claude_address("live-idle");
    let mut receiver = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    receiver.cmd(json!({"cmd":"inbox","session_id":"live-idle","behavior":"delivered"}));
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "live-idle"),
    );
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        tool_hook("PreToolUse", "live-idle", "old-call", None),
    );
    receiver.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", "live-idle"));
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "waiting"),
    );
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("PermissionRequest", "waiting"),
    );
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "ended"),
    );
    receiver.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionEnd", "ended"),
    );
    let old_epoch = lab
        .registry
        .lock()
        .unwrap()
        .attest_recipient(&address)
        .unwrap()
        .1
        .epoch;
    lab.channel.take().unwrap().stop();
    let owner = private_directory(lab.socket.parent().unwrap()).unwrap();
    let restored = Arc::new(Mutex::new(
        Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&restored),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let attestation = restored.lock().unwrap().attest_recipient(&address).unwrap();
    assert!(attestation.1.epoch > old_epoch);
    assert_eq!(
        attestation.0.lifecycle(),
        bridge_core::dispatch::Lifecycle::Inactive
    );
    assert_eq!(
        restored
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("waiting"))
            .unwrap()
            .0
            .lifecycle(),
        bridge_core::dispatch::Lifecycle::AwaitingInput
    );
    assert!(
        restored
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address("ended"))
            .is_err()
    );
    // No hook or bridge_me was emitted by the receiver after the restart.
    lab.publish("after-restart", &address, Mode::Message, "recovered route");
    let mut carrier = ClaudeLaterCarrier::new(
        Arc::clone(&restored),
        Arc::clone(&lab.storage) as Arc<dyn Custody>,
        ClaudeTiming::default(),
    )
    .unwrap();
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(
        matches!(
            report,
            DispatchReport::Sent {
                state: AttemptState::NativeAccepted,
                ..
            }
        ),
        "{report:?}"
    );
    assert_eq!(
        receiver.cmd(json!({"cmd":"frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        receiver.mcp(&lab.socket, claude_meta("old-call"))["err"],
        "missing"
    );
    drop(carrier);
    lab.channel.take().unwrap().stop();
    // A harness the policy no longer serves cannot be resurrected by private
    // cached metadata.
    let mut changed = lab.config.clone();
    changed
        .harnesses
        .retain(|policy| policy.harness != Harness::ClaudeCode);
    let journal = lab.socket.with_extension("bindings.json");
    let cached = std::fs::read(&journal).unwrap();
    let mut unqualified = Registry::new(changed, owner).unwrap();
    assert!(
        unqualified
            .attach_journal(&journal, now())
            .unwrap()
            .is_empty()
    );
    std::fs::write(&journal, &cached).unwrap();
    receiver.stop();
    let mut dead = Registry::new(lab.config.clone(), owner).unwrap();
    assert!(dead.attach_journal(&journal, now()).unwrap().is_empty());
    std::fs::write(&journal, &cached).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut foreign = Registry::new(lab.config.clone(), owner).unwrap();
    assert!(foreign.attach_journal(&journal, now()).is_err());
}

/// Root-end eligibility never overrides input/unknown/active state, CLI/Claude
/// retirement, missing/changed/archived/symlink transcripts, the current harness
/// process and policy,
/// exact harness frontend or operator no-wake. Every refused dispatch has zero
/// attempts and zero native connections, including legacy journal recovery.
#[test]
fn desktop_idle_end_negative_evidence_never_sends() {
    use bridge_adapters::server::private_directory;
    use bridge_adapters::{ChannelServer, Registry};
    use std::os::unix::{fs::symlink, net::UnixListener};
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    for case in [
        "active",
        "permission",
        "unknown",
        "cli",
        "claude",
        "missing",
        "moved",
        "archived",
        "symlink",
        "foreign",
        "swapped",
        "invalid_path",
        "missing_at_end",
        "build",
        "store",
        "harness",
        "other_harness",
        "absent_frontend",
        "legacy",
        "renewed",
        "no_wake",
    ] {
        let mut lab = Lab::new("idlehold");
        let harness = if case == "claude" {
            Harness::ClaudeCode
        } else {
            Harness::Codex
        };
        let store = if harness == Harness::Codex {
            &lab.codex_store
        } else {
            &lab.claude_store
        };
        let transcript = store.join("sessions").join("held.jsonl");
        std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        std::fs::write(&transcript, "").unwrap();
        let pipe = lab.dir.0.join("native.sock");
        let host = UnixListener::bind(&pipe).unwrap();
        host.set_nonblocking(true).unwrap();
        let mut receiver = if matches!(case, "cli" | "claude") {
            Harnessed::start(harness, store)
        } else {
            Harnessed::start_desktop(store, &pipe)
        };
        if !matches!(case, "cli" | "claude" | "absent_frontend" | "other_harness") {
            receiver.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
        }
        let mut sibling = if case == "other_harness" {
            let mut sibling = Harnessed::start_desktop(store, &pipe);
            sibling.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
            Some(sibling)
        } else {
            None
        };
        let address = if harness == Harness::Codex {
            lab.codex_address("held")
        } else {
            lab.claude_address("held")
        };
        let mut start = hook(
            if case == "unknown" {
                "SubagentStop"
            } else {
                "SessionStart"
            },
            "held",
        );
        start["transcript_path"] = json!(transcript);
        if case == "invalid_path" {
            start["transcript_path"] = json!(lab.dir.0.join("outside.jsonl"));
        }
        receiver.hook(&lab.socket, harness, start);
        if case != "unknown" {
            receiver.hook(
                &lab.socket,
                harness,
                hook(
                    match case {
                        "active" => "UserPromptSubmit",
                        "permission" => "PermissionRequest",
                        _ => "Stop",
                    },
                    "held",
                ),
            );
        }
        if case == "missing_at_end" {
            std::fs::remove_file(&transcript).unwrap();
        }
        receiver.hook(&lab.socket, harness, hook("SessionEnd", "held"));
        assert!(
            lab.registry
                .lock()
                .unwrap()
                .attest_recipient(&address)
                .is_err()
        );
        match case {
            "missing_at_end" => std::fs::write(&transcript, "").unwrap(),
            "swapped" => {
                let replacement = transcript.with_extension("replacement");
                std::fs::write(&replacement, "").unwrap();
                std::fs::rename(replacement, &transcript).unwrap();
            }
            "renewed" => {
                receiver.hook(&lab.socket, harness, hook("SessionStart", "held"));
                receiver.hook(&lab.socket, harness, hook("PermissionRequest", "held"));
                let snapshot: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(lab.socket.with_extension("bindings.json")).unwrap(),
                )
                .unwrap();
                assert!(
                    snapshot["bindings"][0]
                        .get("desktop_idle_message")
                        .is_none()
                );
            }
            "missing" => std::fs::remove_file(&transcript).unwrap(),
            "moved" | "archived" => {
                let destination = lab.codex_store.join("archived_sessions");
                std::fs::create_dir_all(&destination).unwrap();
                std::fs::rename(&transcript, destination.join("held.jsonl")).unwrap();
            }
            "symlink" => {
                let retained = lab.codex_store.join("sessions").join("other.jsonl");
                std::fs::rename(&transcript, &retained).unwrap();
                symlink(&retained, &transcript).unwrap();
            }
            "foreign" => {
                let outside = lab.dir.0.join("foreign.jsonl");
                std::fs::rename(&transcript, &outside).unwrap();
                symlink(&outside, &transcript).unwrap();
            }
            "no_wake" => {
                lab.storage
                    .lock()
                    .unwrap()
                    .set_no_wake(
                        &address.to_canonical_string(),
                        true,
                        Some("owner pause"),
                        "operator",
                        now(),
                    )
                    .unwrap();
            }
            _ => {}
        }
        if matches!(case, "build" | "store" | "harness" | "legacy") {
            lab.channel.take().unwrap().stop();
            let journal = lab.socket.with_extension("bindings.json");
            let mut snapshot: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
            if case == "legacy" {
                snapshot["bindings"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("desktop_idle_message");
                snapshot["bindings"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("desktop_idle_transcript");
            } else if case == "harness" {
                snapshot["bindings"][0]["harness"][1] = json!(0);
            } else if case == "store" {
                snapshot["bindings"][0]["store"] = json!(lab.claude_store);
            }
            std::fs::write(&journal, serde_json::to_vec(&snapshot).unwrap()).unwrap();
            let mut config = lab.config.clone();
            if case == "build" {
                config
                    .harnesses
                    .retain(|policy| policy.harness != Harness::Codex);
            }
            let owner = private_directory(lab.socket.parent().unwrap()).unwrap();
            lab.registry = Arc::new(Mutex::new(Registry::new(config, owner).unwrap()));
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
        let mut carrier = CodexQueueCarrier::new(
            Arc::clone(&lab.registry),
            "/absent-helper".into(),
            Duration::from_secs(1),
        )
        .with_desktop_directory(lab.socket.parent().unwrap().into());
        lab.publish("held-event", &address, Mode::Message, "must remain held");
        let report = dispatch_message(
            &lab.storage,
            &mut carrier,
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap();
        assert!(
            !matches!(report, DispatchReport::Sent { .. }),
            "{case}: {report:?}"
        );
        assert!(
            lab.attempt("held-event").is_none(),
            "{case}: consumed attempt"
        );
        assert!(
            matches!(host.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "{case}: native connection"
        );
        receiver.stop();
        if let Some(sibling) = sibling.take() {
            sibling.stop();
        }
    }
}

/// A symlink alias of a store is never a bindable store (only a canonical path
/// is), while the same store under its canonical path binds, stays eligible for
/// ordinary MESSAGE attestation and keeps its inject capability. This exercises
/// fresh carrier validation; retired transcript path rules are separate.
#[test]
fn codex_live_store_alias_is_refused_and_the_canonical_store_keeps_capabilities() {
    use bridge_core::dispatch::{DispatchCarrier, Lifecycle, Selection};
    use std::os::unix::fs::symlink;
    let lab = Lab::new("storealias");
    let alias = lab.dir.0.join("codex-alias");
    symlink(&lab.codex_store, &alias).unwrap();
    let mut aliased = Harnessed::start(Harness::Codex, &alias);
    let refused = aliased.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "aliased-live"),
    );
    assert!(
        refused["stderr"].as_str().unwrap().contains("not_evidence"),
        "{refused}"
    );
    aliased.stop();
    let mut receiver = Harnessed::start(Harness::Codex, &lab.codex_store);
    let address = lab.codex_address("aliased-live");
    let admitted = receiver.hook(
        &lab.socket,
        Harness::Codex,
        hook("SessionStart", "aliased-live"),
    );
    assert_eq!(admitted["status"], 0);
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    );
    let attestation = carrier.attest(&address).unwrap();
    assert_eq!(attestation.lifecycle(), Lifecycle::Inactive);
    receiver.hook(
        &lab.socket,
        Harness::Codex,
        hook("UserPromptSubmit", "aliased-live"),
    );
    lab.publish(
        "alias-auto",
        &address,
        Mode::Auto,
        "aliased inject capability",
    );
    let active = carrier.attest(&address).unwrap();
    assert_eq!(active.lifecycle(), Lifecycle::Active);
    let inject = lab
        .storage
        .lock()
        .unwrap()
        .drain_inject(&active, now(), &DispatchTiming::default())
        .unwrap();
    match inject {
        Selection::Attempt(record) => assert_eq!(record.granted, "inject,message"),
        other => panic!("active auto must retain inject capability: {other:?}"),
    }
    receiver.stop();
}

/// How the mock Codex application host answers the one `send_message_to_thread`.
#[derive(Clone, Copy, PartialEq)]
enum GatewayHost {
    /// Positive success receipt.
    Accept,
    /// Read the call, then drop the connection without any receipt.
    Lose,
    /// Offer no message tool at all: the frontend answers known-unsent before any
    /// message call exists.
    Missing,
}

/// Serves one mock native host connection (inventory, then exactly one message
/// call for `thread`) and counts calls; panics on an unexpected shape. With
/// `lock`, that directory is made read-only the moment the call is read, so the
/// daemon cannot journal anything after the hand-off began.
fn gateway_host(
    host: std::os::unix::net::UnixListener,
    thread: &'static str,
    calls: Arc<AtomicUsize>,
    answer: GatewayHost,
    lock: Option<std::path::PathBuf>,
) -> std::thread::JoinHandle<()> {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    std::thread::spawn(move || {
        let (mut stream, _) = host.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        for id in [1, 2] {
            let mut head = [0; 4];
            stream.read_exact(&mut head).unwrap();
            let mut bytes = vec![0; u32::from_le_bytes(head) as usize];
            stream.read_exact(&mut bytes).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request["id"], id);
            let result = if id == 1 {
                if answer == GatewayHost::Missing {
                    json!({"tools":[]})
                } else {
                    json!({"tools":[{"name":"send_message_to_thread","namespace":"codex_app"}]})
                }
            } else {
                assert_eq!(request["params"]["arguments"]["threadId"], thread);
                assert_eq!(request["params"]["callerSource"], "codex");
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(directory) = &lock {
                    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500))
                        .unwrap();
                }
                if answer == GatewayHost::Lose {
                    return;
                }
                json!({"success":true})
            };
            let bytes =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
            stream
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
            if answer == GatewayHost::Missing {
                return;
            }
        }
    })
}

/// Writes a native-shaped rollout for `thread` (a `session_meta` header naming
/// it, then two events) inside the Codex test store and returns its path.
fn gateway_rollout(lab: &Lab, thread: &str) -> std::path::PathBuf {
    let path = lab
        .codex_store
        .join("sessions")
        .join(format!("rollout-{thread}.jsonl"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        format!(
            "{}\n{}\n{}\n",
            json!({"type":"session_meta","payload":{"id":thread}}),
            json!({"type":"event_msg","payload":{"type":"user_message"}}),
            json!({"type":"event_msg","payload":{"type":"task_complete"}}),
        ),
    )
    .unwrap();
    path
}

/// Drives one owned Desktop stand-in through a session start and a positive owner
/// `Stop` for `thread`, the state an idle thread is left in.
fn gateway_idle(harness: &mut Harnessed, lab: &Lab, thread: &str, transcript: &std::path::Path) {
    let mut start = hook("SessionStart", thread);
    start["transcript_path"] = json!(transcript);
    harness.hook(&lab.socket, Harness::Codex, start);
    harness.hook(&lab.socket, Harness::Codex, hook("Stop", thread));
}

/// The first binding row of the private route journal.
fn gateway_journal(lab: &Lab) -> serde_json::Value {
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(lab.socket.with_extension("bindings.json")).unwrap())
            .unwrap();
    snapshot["bindings"][0].clone()
}

/// A queued message to a positively idle Desktop thread is delivered exactly once
/// through the current Desktop frontend after the application restarted (a new
/// harness incarnation with no hook), without any receiver `bridge_me`, hook or
/// new source event: the old incarnation is dead, the binding gets a fresh epoch,
/// the route stays MESSAGE-only without caller authority, and the one-shot proof is
/// spent so a second event holds. It holds both for a binding that was never ended
/// and for one retired by `SessionEnd` after the same positive idle (the existing
/// narrow Desktop exception). Synthetic native-owner input only.
#[test]
fn idle_codex_thread_is_woken_through_the_new_gateway_after_restart() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    for ended in [false, true] {
        let lab = Lab::new("gw");
        let pipe = lab.dir.0.join("native.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let native = gateway_host(
            UnixListener::bind(&pipe).unwrap(),
            "gw",
            Arc::clone(&calls),
            GatewayHost::Accept,
            None,
        );
        let transcript = gateway_rollout(&lab, "gw");
        let address = lab.codex_address("gw");
        let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
        gateway_idle(&mut first, &lab, "gw", &transcript);
        if ended {
            first.hook(&lab.socket, Harness::Codex, hook("SessionEnd", "gw"));
        }
        let before = gateway_journal(&lab);
        assert!(before.get("wake").is_some(), "positive idle was stamped");
        first.stop();
        // Process start times have whole-second resolution: the new harness must
        // be born in a later second than the one it replaces.
        std::thread::sleep(Duration::from_millis(1100));
        let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
        second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
        assert!(
            lab.registry
                .lock()
                .unwrap()
                .attest_recipient(&address)
                .is_err(),
            "the ordinary route stays closed: the recorded incarnation is gone"
        );
        lab.publish("gw-msg", &address, Mode::Message, "gateway wake marker");
        let mut carrier = CodexQueueCarrier::new(
            Arc::clone(&lab.registry),
            "/absent-helper".into(),
            Duration::from_secs(1),
        )
        .with_desktop_directory(lab.socket.parent().unwrap().into());
        let timing = DispatchTiming::default();
        let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        assert!(
            matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::NativeAccepted),
            "ended={ended}: {report:?}"
        );
        native.join().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let after = gateway_journal(&lab);
        assert!(after["epoch"].as_u64() > before["epoch"].as_u64());
        assert!(after.get("wake").is_none(), "the proof is spent");
        let attempt = lab.attempt("gw-msg").unwrap();
        assert_eq!(
            attempt.fence.endpoint_epoch,
            after["epoch"].as_u64().unwrap()
        );
        assert!(
            second.mcp(
                &lab.socket,
                json!({"threadId":"gw","callId":"none","x-codex-turn-metadata":{}})
            )["err"]
                .is_string(),
            "the gateway grants no caller evidence"
        );
        lab.publish("gw-msg-2", &address, Mode::Message, "second marker");
        for _ in 0..2 {
            assert!(!matches!(
                dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap(),
                DispatchReport::Sent { .. }
            ));
        }
        assert!(lab.attempt("gw-msg-2").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        second.stop();
    }
}

/// Every state that is not exactly "idle, same unchanged thread, one qualified
/// live gateway" holds with no attempt and no native connection: grown, replaced,
/// rewritten, unnamed or other-thread transcripts, active, awaiting-input and ended-while-active
/// sessions, a missing, duplicate or other-store gateway, a still-live old
/// incarnation and an operator no-wake.
#[test]
fn idle_gateway_holds_every_unproven_state_without_a_native_connection() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    for case in [
        "grown",
        "replaced",
        "rewritten",
        "no_header",
        "other_thread",
        "active",
        "permission",
        "ended_active",
        "no_frontend",
        "older_gateway",
        "duplicate",
        "other_store",
        "live_old",
        "no_wake",
    ] {
        let lab = Lab::new("gwneg");
        let pipe = lab.dir.0.join("native.sock");
        let host = UnixListener::bind(&pipe).unwrap();
        host.set_nonblocking(true).unwrap();
        let transcript = gateway_rollout(&lab, "gw");
        match case {
            "no_header" => std::fs::write(&transcript, "").unwrap(),
            "other_thread" => {
                std::fs::write(
                    &transcript,
                    format!(
                        "{}\n",
                        json!({"type":"session_meta","payload":{"id":"other"}})
                    ),
                )
                .unwrap();
            }
            _ => {}
        }
        let address = lab.codex_address("gw");
        // A live Desktop harness (with its frontend) that started BEFORE the one that
        // held the address: a gateway must be strictly newer, so it never qualifies.
        let older = (case == "older_gateway").then(|| {
            let mut older = Harnessed::start_desktop(&lab.codex_store, &pipe);
            older.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
            std::thread::sleep(Duration::from_millis(1100));
            older
        });
        let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
        gateway_idle(&mut first, &lab, "gw", &transcript);
        match case {
            "active" => {
                first.hook(&lab.socket, Harness::Codex, hook("UserPromptSubmit", "gw"));
            }
            "permission" => {
                first.hook(&lab.socket, Harness::Codex, hook("PermissionRequest", "gw"));
            }
            "ended_active" => {
                first.hook(&lab.socket, Harness::Codex, hook("UserPromptSubmit", "gw"));
                first.hook(&lab.socket, Harness::Codex, hook("SessionEnd", "gw"));
            }
            "no_wake" => lab
                .storage
                .lock()
                .unwrap()
                .set_no_wake(
                    &address.to_canonical_string(),
                    true,
                    Some("owner pause"),
                    "operator",
                    now(),
                )
                .unwrap(),
            _ => {}
        }
        let mut first = Some(first);
        if case != "live_old" {
            first.take().unwrap().stop();
        }
        match case {
            "grown" => {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&transcript)
                    .unwrap();
                writeln!(
                    file,
                    "{}",
                    json!({"type":"event_msg","payload":{"type":"x"}})
                )
                .unwrap();
            }
            "replaced" => {
                let copy = transcript.with_extension("copy");
                std::fs::copy(&transcript, &copy).unwrap();
                std::fs::rename(&copy, &transcript).unwrap();
            }
            "rewritten" => {
                let mut bytes = std::fs::read(&transcript).unwrap();
                let last = bytes.len() - 3;
                bytes[last] = b'Z';
                std::fs::write(&transcript, bytes).unwrap();
            }
            _ => {}
        }
        // Whole-second process start times: later-born gateways, so a hold below
        // is never an artifact of the same-second birth fence.
        std::thread::sleep(Duration::from_millis(1100));
        let mut gateways = Vec::new();
        let (count, store) = match case {
            "no_frontend" | "live_old" | "older_gateway" => (0, &lab.codex_store),
            "duplicate" => (2, &lab.codex_store),
            "other_store" => (1, &lab.claude_store),
            _ => (1, &lab.codex_store),
        };
        for _ in 0..count {
            let mut gateway = Harnessed::start_desktop(store, &pipe);
            gateway.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
            gateways.push(gateway);
        }
        let mut carrier = CodexQueueCarrier::new(
            Arc::clone(&lab.registry),
            "/absent-helper".into(),
            Duration::from_secs(1),
        )
        .with_desktop_directory(lab.socket.parent().unwrap().into());
        lab.publish("gw-held", &address, Mode::Message, "must not send");
        let timing = DispatchTiming::default();
        for _ in 0..2 {
            let report =
                dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
            assert!(
                !matches!(report, DispatchReport::Sent { .. }),
                "{case}: {report:?}"
            );
        }
        assert!(lab.attempt("gw-held").is_none(), "{case}: no attempt");
        assert!(
            matches!(host.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "{case}: no native connection"
        );
        for gateway in gateways {
            gateway.stop();
        }
        if let Some(first) = first {
            first.stop();
        }
        drop(older);
    }
}

/// A hand-off lost after the request was written is an unknown outcome that is
/// retained and never resent; the one-shot proof was journaled as spent before the
/// write, so a daemon restart cannot revive it for a different queued message;
/// and a failed epoch commit never leaves a usable route (the first attempt
/// holds, the next one after the journal works succeeds).
#[test]
fn gateway_commit_failure_holds_and_unknown_hand_off_spends_the_proof() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    let mut lab = Lab::new("gwlost");
    let pipe = lab.dir.0.join("native.sock");
    let calls = Arc::new(AtomicUsize::new(0));
    let native = gateway_host(
        UnixListener::bind(&pipe).unwrap(),
        "gw",
        Arc::clone(&calls),
        GatewayHost::Lose,
        Some(lab.socket.parent().unwrap().to_path_buf()),
    );
    let transcript = gateway_rollout(&lab, "gw");
    let address = lab.codex_address("gw");
    let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
    gateway_idle(&mut first, &lab, "gw", &transcript);
    first.stop();
    std::thread::sleep(Duration::from_millis(1100));
    let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
    second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    )
    .with_desktop_directory(lab.socket.parent().unwrap().into());
    lab.publish("gw-lost", &address, Mode::Message, "lost marker");
    let timing = DispatchTiming::default();
    let directory = lab.socket.parent().unwrap().to_path_buf();
    let epoch = gateway_journal(&lab)["epoch"].as_u64().unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
    let held = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(held, DispatchReport::Held(_)), "{held:?}");
    assert_eq!(gateway_journal(&lab)["epoch"].as_u64().unwrap(), epoch);
    assert!(lab.attempt("gw-lost").is_none());
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(
        matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::OutcomeUnknown),
        "{report:?}"
    );
    native.join().unwrap();
    // The spend was journaled before the write; the directory went read-only when
    // the call was read, so nothing could have been written afterwards.
    lab.publish("gw-next", &address, Mode::Message, "next marker");
    for _ in 0..2 {
        assert!(!matches!(
            dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap(),
            DispatchReport::Sent { .. }
        ));
    }
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        gateway_journal(&lab).get("wake").is_none(),
        "the spend reached the journal before the hand-off"
    );
    // A restart drops the gone incarnation with its proof: nothing resurrects.
    lab.channel.take().unwrap().stop();
    let owner = bridge_adapters::server::private_directory(&directory).unwrap();
    lab.registry = Arc::new(Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        bridge_adapters::ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    )
    .with_desktop_directory(directory.clone());
    for _ in 0..2 {
        assert!(!matches!(
            dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap(),
            DispatchReport::Sent { .. }
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        lab.attempt("gw-lost").unwrap().state,
        AttemptState::OutcomeUnknown
    );
    assert!(lab.attempt("gw-next").is_none());
    second.stop();
}

/// A hand-off lost after the request was written, with the journal fully writable
/// (the read-only-directory variant above is separate coverage): the native host
/// observes exactly one effect, the outcome is unknown and retained, and the
/// durable journal holds NO wake proof afterwards (an unknown outcome never gives
/// the one-shot proof back). A different queued event is then neither handed off
/// nor re-homed, before and after a daemon restart; the host's listener stays open
/// so a wrongly resurrected route would be seen as a second connection. The journal
/// assertion is the essential one: it does not depend on core withholding a second
/// event.
#[test]
fn lost_ack_with_a_writable_journal_leaves_no_wake_proof_and_never_rehomes() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    let mut lab = Lab::new("gwack");
    let pipe = lab.dir.0.join("native.sock");
    let listener = UnixListener::bind(&pipe).unwrap();
    let probe = listener.try_clone().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let native = gateway_host(listener, "gw", Arc::clone(&calls), GatewayHost::Lose, None);
    let transcript = gateway_rollout(&lab, "gw");
    let address = lab.codex_address("gw");
    let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
    gateway_idle(&mut first, &lab, "gw", &transcript);
    first.stop();
    std::thread::sleep(Duration::from_millis(1100));
    let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
    second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
    let directory = lab.socket.parent().unwrap().to_path_buf();
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    )
    .with_desktop_directory(directory.clone());
    lab.publish("gw-ack", &address, Mode::Message, "ack marker");
    let timing = DispatchTiming::default();
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(
        matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::OutcomeUnknown),
        "{report:?}"
    );
    native.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one native effect");
    assert!(
        gateway_journal(&lab).get("wake").is_none(),
        "an unknown outcome never restores the spent proof in the durable journal"
    );
    // The host stays listening (non-blocking probe): any further hand-off is seen.
    probe.set_nonblocking(true).unwrap();
    lab.publish("gw-other", &address, Mode::Message, "other marker");
    for _ in 0..2 {
        assert!(!matches!(
            dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap(),
            DispatchReport::Sent { .. }
        ));
    }
    assert!(
        matches!(probe.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no second native connection for a different event"
    );
    assert!(lab.attempt("gw-other").is_none());
    // After a daemon restart nothing is re-homed either.
    lab.channel.take().unwrap().stop();
    let owner = bridge_adapters::server::private_directory(&directory).unwrap();
    lab.registry = Arc::new(Mutex::new(
        bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        bridge_adapters::ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    )
    .with_desktop_directory(directory);
    for _ in 0..2 {
        assert!(!matches!(
            dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap(),
            DispatchReport::Sent { .. }
        ));
    }
    assert!(
        matches!(probe.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no native connection after the restart"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        lab.attempt("gw-ack").unwrap().state,
        AttemptState::OutcomeUnknown
    );
    assert!(lab.attempt("gw-other").is_none());
    second.stop();
}

/// Concurrent attestations and sends of one idle recipient race to commit the
/// gateway: exactly one commit and one native hand-off happen.
#[test]
fn gateway_commit_and_hand_off_race_delivers_once() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    let lab = Lab::new("gwrace");
    let pipe = lab.dir.0.join("native.sock");
    let calls = Arc::new(AtomicUsize::new(0));
    let native = gateway_host(
        UnixListener::bind(&pipe).unwrap(),
        "gw",
        Arc::clone(&calls),
        GatewayHost::Accept,
        None,
    );
    let transcript = gateway_rollout(&lab, "gw");
    let address = lab.codex_address("gw");
    let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
    gateway_idle(&mut first, &lab, "gw", &transcript);
    first.stop();
    std::thread::sleep(Duration::from_millis(1100));
    let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
    second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
    lab.publish("gw-race", &address, Mode::Message, "race marker");
    let sent = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let registry = Arc::clone(&lab.registry);
            let storage = Arc::clone(&lab.storage);
            let address = address.clone();
            let directory = lab.socket.parent().unwrap().to_path_buf();
            let sent = Arc::clone(&sent);
            std::thread::spawn(move || {
                let mut carrier = CodexQueueCarrier::new(
                    registry,
                    "/absent-helper".into(),
                    Duration::from_secs(1),
                )
                .with_desktop_directory(directory);
                let timing = DispatchTiming::default();
                if let Ok(DispatchReport::Sent { .. }) =
                    dispatch_message(&storage, &mut carrier, &address, &now, &timing)
                {
                    sent.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    native.join().unwrap();
    assert_eq!(sent.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        lab.attempt("gw-race").unwrap().state,
        AttemptState::NativeAccepted
    );
    second.stop();
}

/// An unspent idle proof survives a daemon restart that happens while the
/// application is down: the journal keeps the gone incarnation as a gateway
/// candidate only because it carries the proof, and the queued message is still
/// delivered once through the new Desktop frontend. A stamp that no longer matches
/// (the transcript grew while the daemon was down) holds instead.
#[test]
fn unspent_gateway_proof_survives_a_daemon_restart() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    for grown in [false, true] {
        let mut lab = Lab::new("gwrst");
        let pipe = lab.dir.0.join("native.sock");
        let host = UnixListener::bind(&pipe).unwrap();
        host.set_nonblocking(true).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let transcript = gateway_rollout(&lab, "gw");
        let address = lab.codex_address("gw");
        let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
        gateway_idle(&mut first, &lab, "gw", &transcript);
        first.stop();
        lab.channel.take().unwrap().stop();
        let directory = lab.socket.parent().unwrap().to_path_buf();
        let owner = bridge_adapters::server::private_directory(&directory).unwrap();
        lab.registry = Arc::new(Mutex::new(
            bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap(),
        ));
        lab.channel = Some(
            bridge_adapters::ChannelServer::start(
                &lab.socket,
                Arc::clone(&lab.registry),
                Arc::clone(&lab.storage) as Arc<dyn Custody>,
                DispatchTiming::default(),
            )
            .unwrap(),
        );
        if grown {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                file,
                "{}",
                json!({"type":"event_msg","payload":{"type":"x"}})
            )
            .unwrap();
        }
        let native = (!grown).then(|| {
            host.set_nonblocking(false).unwrap();
            gateway_host(
                host.try_clone().unwrap(),
                "gw",
                Arc::clone(&calls),
                GatewayHost::Accept,
                None,
            )
        });
        std::thread::sleep(Duration::from_millis(1100));
        let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
        second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
        lab.publish("gw-rst", &address, Mode::Message, "restart marker");
        let mut carrier = CodexQueueCarrier::new(
            Arc::clone(&lab.registry),
            "/absent-helper".into(),
            Duration::from_secs(1),
        )
        .with_desktop_directory(directory);
        let timing = DispatchTiming::default();
        let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        if grown {
            assert!(!matches!(report, DispatchReport::Sent { .. }), "{report:?}");
            assert!(lab.attempt("gw-rst").is_none());
        } else {
            assert!(
                matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::NativeAccepted),
                "{report:?}"
            );
            native.unwrap().join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        second.stop();
    }
}

/// The last pre-write fence: after the one-shot proof is journaled as spent and
/// the frontend connection is prepared, any change of the world (the thread's
/// transcript grows, or a new hook of the thread renews the binding as active or
/// awaiting input) makes the hand-off known-unsent with zero native bytes, keeps
/// the proof spent and never restores unchecked old evidence; the control with no
/// change delivers once. The pause seam runs at exactly that boundary.
#[test]
fn gateway_state_change_after_the_reservation_sends_zero_native_bytes() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    for case in ["control", "transcript", "active_hook", "permission_hook"] {
        let lab = Lab::new("gwfence");
        let pipe = lab.dir.0.join("native.sock");
        let listener = UnixListener::bind(&pipe).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let (native, host) = if case == "control" {
            (
                Some(gateway_host(
                    listener,
                    "gw",
                    Arc::clone(&calls),
                    GatewayHost::Accept,
                    None,
                )),
                None,
            )
        } else {
            listener.set_nonblocking(true).unwrap();
            (None, Some(listener))
        };
        let transcript = gateway_rollout(&lab, "gw");
        let address = lab.codex_address("gw");
        let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
        gateway_idle(&mut first, &lab, "gw", &transcript);
        first.stop();
        std::thread::sleep(Duration::from_millis(1100));
        let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
        second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
        let second = Arc::new(Mutex::new(second));
        let change = {
            let second = Arc::clone(&second);
            let socket = lab.socket.clone();
            let transcript = transcript.clone();
            Arc::new(move || match case {
                "transcript" => {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&transcript)
                        .unwrap();
                    writeln!(
                        file,
                        "{}",
                        json!({"type":"event_msg","payload":{"type":"x"}})
                    )
                    .unwrap();
                }
                "active_hook" => {
                    second.lock().unwrap().hook(
                        &socket,
                        Harness::Codex,
                        hook("UserPromptSubmit", "gw"),
                    );
                }
                "permission_hook" => {
                    second.lock().unwrap().hook(
                        &socket,
                        Harness::Codex,
                        hook("PermissionRequest", "gw"),
                    );
                }
                _ => {}
            })
        };
        let mut carrier = CodexQueueCarrier::new(
            Arc::clone(&lab.registry),
            "/absent-helper".into(),
            Duration::from_secs(1),
        )
        .with_desktop_directory(lab.socket.parent().unwrap().into())
        .with_gateway_pause(change);
        lab.publish("gw-fence", &address, Mode::Message, "fence marker");
        let timing = DispatchTiming::default();
        let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
        if case == "control" {
            assert!(
                matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::NativeAccepted),
                "{report:?}"
            );
            native.unwrap().join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        } else {
            assert!(
                matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::KnownUnsent),
                "{case}: {report:?}"
            );
            assert!(
                matches!(host.unwrap().accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "{case}: zero native connection"
            );
            assert!(
                gateway_journal(&lab).get("wake").is_none(),
                "{case}: the spent proof is not restored over changed evidence"
            );
        }
        // The carrier's pause seam shares the harness handle: release it first.
        drop(carrier);
        Arc::try_unwrap(second)
            .ok()
            .unwrap()
            .into_inner()
            .unwrap()
            .stop();
    }
}

/// A hand-off refused before any native write (the host offers no message tool)
/// gives the one-shot proof back only because the fence passes again and the
/// binding is exactly the one that stood after the spend: the journal holds the
/// proof again with the same committed gateway, no native call was made, and the
/// attempt is a known-unsent one.
#[test]
fn known_unsent_gateway_hand_off_restores_the_unchanged_proof() {
    use std::os::unix::net::UnixListener;
    let node = std::env::var("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    let lab = Lab::new("gwrs");
    let pipe = lab.dir.0.join("native.sock");
    let calls = Arc::new(AtomicUsize::new(0));
    let native = gateway_host(
        UnixListener::bind(&pipe).unwrap(),
        "gw",
        Arc::clone(&calls),
        GatewayHost::Missing,
        None,
    );
    let transcript = gateway_rollout(&lab, "gw");
    let address = lab.codex_address("gw");
    let mut first = Harnessed::start_desktop(&lab.codex_store, &pipe);
    gateway_idle(&mut first, &lab, "gw", &transcript);
    first.stop();
    std::thread::sleep(Duration::from_millis(1100));
    let mut second = Harnessed::start_desktop(&lab.codex_store, &pipe);
    second.cmd(json!({"cmd":"desktop_frontend","node":node,"channel":lab.socket}));
    lab.publish("gw-unsent", &address, Mode::Message, "unsent marker");
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/absent-helper".into(),
        Duration::from_secs(1),
    )
    .with_desktop_directory(lab.socket.parent().unwrap().into());
    let timing = DispatchTiming::default();
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
    assert!(
        matches!(report, DispatchReport::Sent { state, .. } if state == AttemptState::KnownUnsent),
        "{report:?}"
    );
    native.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no message call was made");
    let row = gateway_journal(&lab);
    assert!(
        row.get("wake").is_some(),
        "the unchanged proof was given back: {row}"
    );
    assert_eq!(
        row["wake"]["gateway"].as_array().map(Vec::len),
        Some(2),
        "with its committed gateway: {row}"
    );
    second.stop();
}

/// A fresh session in an arbitrary runtime store that no configuration names
/// registers from its own lifecycle hook with no pre-enrollment, is journaled and
/// survives a daemon restart, and every unsound shape is refused before any state
/// changes: a store closed to writers is required (group-writable refused), the
/// store must be a canonical path (a symlink and a non-canonical spelling are
/// refused), the ancestor must carry a product marker (an unmarked process is not
/// a harness), the session id must be a bounded identifier without controls, the
/// event must be a supported lifecycle event, and an equal session id from a
/// second live store is a conflict that leaves the first binding untouched.
#[test]
fn a_fresh_session_in_an_unlisted_runtime_store_registers_from_its_hook() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let lab = Lab::new("dyn");
    let mkdir = |name: &str, mode: u32| {
        let path = lab.dir.0.join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path.canonicalize().unwrap()
    };
    let bound = |session: &str| {
        lab.registry
            .lock()
            .unwrap()
            .attest_recipient(&lab.claude_address(session))
            .is_ok()
    };
    let refused = |reply: &serde_json::Value, class: &str| {
        assert!(
            reply["stderr"].as_str().unwrap().contains(class),
            "{class}: {reply}"
        );
    };

    // The positive path: an unlisted, ordinary 0755 store.
    let store = mkdir("dyn-store", 0o755);
    let mut harness = Harnessed::start(Harness::ClaudeCode, &store);
    let reply = harness.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "dyn-1"),
    );
    assert_eq!(reply["status"], 0, "{reply}");
    assert!(bound("dyn-1"));
    let journal = lab.socket.with_extension("bindings.json");
    let saved = std::fs::read_to_string(&journal).unwrap();
    assert!(saved.contains("dyn-1") && saved.contains(store.to_str().unwrap()));

    // A cold daemon restart restores the live route from the journal alone.
    let owner = bridge_adapters::server::private_directory(lab.socket.parent().unwrap()).unwrap();
    let mut restarted = bridge_adapters::Registry::new(lab.config.clone(), owner).unwrap();
    let restored = restarted.attach_journal(&journal, now()).unwrap();
    assert!(
        restored
            .iter()
            .any(|a| a.address().native_session_id == "dyn-1"),
        "the live dynamic-store route survives a restart"
    );

    // An equal session id from a second live store is a conflict.
    let second_store = mkdir("dyn-second", 0o755);
    let mut second = Harnessed::start(Harness::ClaudeCode, &second_store);
    refused(
        &second.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "dyn-1"),
        ),
        "conflicting",
    );
    second.stop();

    // Unsound stores and processes.
    let writable = mkdir("dyn-writable", 0o775);
    let mut h = Harnessed::start(Harness::ClaudeCode, &writable);
    refused(
        &h.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "w-1"),
        ),
        "not_evidence",
    );
    h.stop();
    let link = lab.dir.0.join("dyn-link");
    symlink(&store, &link).unwrap();
    let mut h = Harnessed::start(Harness::ClaudeCode, &link);
    refused(
        &h.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "l-1"),
        ),
        "not_evidence",
    );
    h.stop();
    let dotted = store.join("..").join("dyn-store");
    let mut h = Harnessed::start(Harness::ClaudeCode, &dotted);
    refused(
        &h.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "d-1"),
        ),
        "not_evidence",
    );
    h.stop();
    let mut unmarked = Harnessed::start_unmarked(&lab.dir.0.join("plain-tool"), &store);
    refused(
        &unmarked.hook(
            &lab.socket,
            Harness::ClaudeCode,
            hook("SessionStart", "u-1"),
        ),
        "not_evidence",
    );
    unmarked.stop();

    // Bad session ids and unsupported lifecycle events on a good store.
    for session in ["", "a\nb", &"x".repeat(300)] {
        refused(
            &harness.hook(
                &lab.socket,
                Harness::ClaudeCode,
                hook("SessionStart", session),
            ),
            "not_evidence",
        );
    }
    refused(
        &harness.hook(&lab.socket, Harness::ClaudeCode, hook("Bogus", "dyn-2")),
        "not_evidence",
    );
    for session in ["w-1", "l-1", "d-1", "u-1", "dyn-2"] {
        assert!(!bound(session), "{session:?} must not be bound");
    }
    assert!(bound("dyn-1"), "the first binding is untouched");
    harness.stop();
}

/// A configuration that still carries the removed `[[adapters.owner_relays]]`
/// table starts the daemon normally, grants nothing for it and reports it in the
/// daemon log as one explicit `legacy_owner_relays_ignored` migration warning, a legacy profile keeps its established `legacy_profile_migrated` event, and a
/// current configuration logs no such event.
#[test]
fn daemon_logs_legacy_owner_relays_as_ignored_and_a_current_config_does_not() {
    use std::io::Read;
    // `mode`: "owner" (legacy owner_relays), "profile" (legacy profile) or "current".
    let run = |mode: &str| -> String {
        let dir = TempDir::new(mode);
        let channel_dir = dir.0.join("ch");
        bridge_adapters::server::private_directory(&channel_dir).unwrap();
        let channel = channel_dir.join("c.sock");
        let core = dir.0.join("core.sock");
        let config = format!(
            r#"database = "{db}"
socket = "{core}"
[limits]
max_admitted_events = 100
[[grant]]
token = "legacy-log-token-0123456789abcdef"
publisher = "probe-pub"
recipients = ["*"]
kinds = ["bridge.probe"]
modes = ["message"]
policies = ["keep_all"]
[adapters]
channel = "{channel}"
host_id = "{HOST}"
{policy}{owner}"#,
            db = dir.0.join("b.db").display(),
            core = core.display(),
            channel = channel.display(),
            policy = if mode == "profile" {
                "[[adapters.profiles]]\nnamespace = \"claude-lab\"\nharness = \"ClaudeCode\"\nstore = \"/old/store\"\n[[adapters.profiles.executables]]\npath = \"/old/claude\"\nsha256 = \"00\"\nversion = \"1\"\ninject = true\nmessage = true\n"
            } else {
                "[[adapters.harnesses]]\nharness = \"ClaudeCode\"\nnamespace = \"claude-lab\"\ninject = true\nmessage = true\n"
            },
            owner = if mode == "owner" {
                "[[adapters.owner_relays]]\npath = \"/old/native-owner\"\nsha256 = \"00\"\n"
            } else {
                ""
            },
        );
        let config_path = dir.0.join("bridge.toml");
        std::fs::write(&config_path, config).unwrap();
        let mut daemon = std::process::Command::new(env!("CARGO_BIN_EXE_bridge-native-daemon"))
            .arg(&config_path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        assert!(eventually(10_000, || channel.exists() && core.exists()));
        daemon.kill().unwrap();
        let mut log = String::new();
        daemon
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut log)
            .unwrap();
        let _ = daemon.wait();
        log
    };
    let legacy = run("owner");
    assert!(
        legacy.contains("\"event\":\"legacy_owner_relays_ignored\""),
        "{legacy}"
    );
    assert!(legacy.contains("1 [[adapters.owner_relays]] entry ignored"));
    assert!(!legacy.contains("legacy_profile_migrated"), "{legacy}");
    // A legacy profile keeps its established event name and does not look like owner_relays.
    let profile = run("profile");
    assert!(
        profile.contains("\"event\":\"legacy_profile_migrated\""),
        "{profile}"
    );
    assert!(
        !profile.contains("legacy_owner_relays_ignored"),
        "{profile}"
    );
    let current = run("current");
    assert!(
        !current.contains("legacy_owner_relays_ignored") && !current.contains("legacy_profile"),
        "{current}"
    );
}
