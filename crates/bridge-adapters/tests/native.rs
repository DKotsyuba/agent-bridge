//! Adapter boundary tests over real owned processes.
//!
//! Each test runs the real adapter channel, the real `bridge-hook`
//! binary and real core custody, with `bridge-fixture` processes standing
//! in for harnesses, Claude inboxes and the Codex App Server. They verify
//! the trust boundaries and the evidence each carrier records; they do
//! not establish delivery to, or context in, a real model.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bridge_adapters::RegistryAttestor;
use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
use bridge_adapters::codex::CodexQueueCarrier;
use bridge_adapters::registry::{CallerAttestor, PresentedMeta, SealedProof, Unattested};
use bridge_adapters::server::Custody;
use bridge_core::dispatch::{AttemptState, DispatchReport, DispatchTiming, dispatch_message};
use bridge_core::{Harness, Mode};
use common::*;
use serde_json::json;

/// Claude `_meta` for a tool-use id.
fn claude_meta(call: &str) -> serde_json::Value {
    json!({"claudecode/toolUseId": call, "progressToken": 1})
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

/// Callers outside a qualified harness, harnesses with a foreign store and builds with a wrong digest are refused.
#[test]
fn non_harness_callers_wrong_store_and_unqualified_builds_refuse() {
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
    // Claude harness as Codex: its own store is not the Codex profile's.
    let relabeled = harness.hook(&lab.socket, Harness::Codex, hook("SessionStart", "sess-2"));
    assert!(
        relabeled["stderr"]
            .as_str()
            .unwrap()
            .contains("not_evidence"),
        "{relabeled}"
    );
    harness.stop();

    // A harness whose own store is not a configured profile is refused.
    let foreign = lab.dir.0.join("foreign-store");
    std::fs::create_dir_all(&foreign).unwrap();
    let mut stranger = Harnessed::start(Harness::ClaudeCode, &foreign);
    let reply = stranger.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-3"),
    );
    assert!(
        reply["stderr"].as_str().unwrap().contains("not_evidence"),
        "{reply}"
    );
    stranger.stop();

    // A build whose digest is not the qualified digest is refused.
    let unqualified = Lab::with_digest("uq", Some("0".repeat(64)));
    let mut harness = Harnessed::start(Harness::ClaudeCode, &unqualified.claude_store);
    let reply = harness.hook(
        &unqualified.socket,
        Harness::ClaudeCode,
        hook("SessionStart", "sess-4"),
    );
    assert!(
        reply["stderr"].as_str().unwrap().contains("not_evidence"),
        "{reply}"
    );
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

/// Unknown, active, permission-wait, paused and disconnected recipients never receive a message.
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
    // The native enqueue of the exact manifest is native acceptance; the
    // peer-origin entry from this hand-off's callback is context.
    let enqueue = json!({"type": "queue-operation", "operation": "enqueue", "sessionId": "sess-8", "content": manifest});
    std::fs::write(&transcript, format!("{text}{enqueue}\n")).unwrap();
    assert!(eventually(6_000, || tiers("evt-quiet")
        .contains(&"native_accepted".to_string())));
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
    let sha = bridge_adapters::registry::file_sha256(&fixture_exe()).unwrap();
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
[[adapters.profiles]]
namespace = "claude-lab"
harness = "ClaudeCode"
store = "{store}"
[[adapters.profiles.executables]]
path = "{exe}"
sha256 = "{sha}"
version = "fixture"
inject = true
message = true
"#,
        db = dir.0.join("b.db").display(),
        core = core.display(),
        recipient = address.to_canonical_string(),
        channel = channel.display(),
        store = store.display(),
        exe = fixture_exe().display(),
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

/// Runs one root drain under a profile whose version label is `label` and
/// returns the drained attempt's frozen proof reference. Panics (fails the
/// test) if the registry panics: the hook then gets no answer.
fn drain_proof_with_label(label: &str) -> String {
    let dir = TempDir::new("vl");
    let store = dir.0.join("s");
    std::fs::create_dir(&store).unwrap();
    let channel_dir = dir.0.join("ch");
    let owner = bridge_adapters::server::private_directory(&channel_dir).unwrap();
    let socket = channel_dir.join("c.sock");
    let sha = bridge_adapters::registry::file_sha256(&fixture_exe()).unwrap();
    let mut profile = profile("claude-lab", Harness::ClaudeCode, &store, &sha);
    profile.executables[0].version = label.to_string();
    let config = bridge_adapters::registry::RegistryConfig {
        host_id: HOST.into(),
        profiles: vec![profile],
        intermediates: ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
        max_call_age_ms: 600_000,
        relays: Vec::new(),
    };
    let registry = Arc::new(std::sync::Mutex::new(
        bridge_adapters::Registry::new(config, owner).unwrap(),
    ));
    let limits = serde_json::from_value(json!({"max_admitted_events": 10})).unwrap();
    let mut storage = bridge_core::Storage::open_in_memory(limits).unwrap();
    storage.register_source_tag(PUBLISHER, PUBLISHER).unwrap();
    let storage = Arc::new(std::sync::Mutex::new(storage));
    let _channel = bridge_adapters::ChannelServer::start(
        &socket,
        Arc::clone(&registry),
        Arc::clone(&storage) as Arc<dyn Custody>,
        DispatchTiming::default(),
    )
    .unwrap();
    let mut harness = Harnessed::start(Harness::ClaudeCode, &store);
    let start = harness.hook(&socket, Harness::ClaudeCode, hook("SessionStart", "sess-v"));
    assert_eq!(start["stderr"], "", "{start}");
    let address =
        bridge_core::NativeAddress::new(HOST, Harness::ClaudeCode, "claude-lab", "sess-v").unwrap();
    let envelope = bridge_core::Envelope::new(
        bridge_core::PublisherId::new(PUBLISHER).unwrap(),
        bridge_core::EventId::new("evt-label").unwrap(),
        address,
        bridge_core::Kind::new("worker.completed").unwrap(),
        Mode::Inject,
        bridge_core::Policy::KeepAll,
        bridge_core::Payload::new("label payload").unwrap(),
        bridge_core::Metadata::new(),
        None,
    )
    .unwrap();
    storage.lock().unwrap().publish(&envelope, now()).unwrap();
    let post = harness.hook(
        &socket,
        Harness::ClaudeCode,
        tool_hook("PostToolUse", "sess-v", "tu-v", None),
    );
    harness.stop();
    assert!(
        post["stdout"].as_str().unwrap().contains("label payload"),
        "{post}"
    );
    storage
        .lock()
        .unwrap()
        .latest_attempt(PUBLISHER, "evt-label")
        .unwrap()
        .unwrap()
        .proof_ref
}

/// A configured version label of any UTF-8 never panics the registry: an
/// emoji-only label longer than the 256-byte proof bound, at four
/// paddings, puts byte 256 inside a 4-byte character for at least one of
/// them whatever the PID/start-time digits; every hook is admitted, the
/// root drain hands the manifest, and the frozen proof reference stays
/// within core's bound, cut on a character boundary.
#[test]
fn multibyte_version_label_is_bounded_in_proof_references() {
    for pad in 0..4 {
        let label = format!("{}{}", "x".repeat(pad), "🙂".repeat(80));
        assert!(label.len() > 256);
        let proof = drain_proof_with_label(&label);
        assert!(proof.len() <= 256, "{}", proof.len());
        assert!(proof.contains("🙂"), "{proof}");
    }
}
