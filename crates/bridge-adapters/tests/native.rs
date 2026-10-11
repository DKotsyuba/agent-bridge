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
    // A guessed message id from a closed sender is ignored too.
    {
        use std::io::Write;
        let mut guessed = std::os::unix::net::UnixStream::connect(&from).unwrap();
        let line = json!({"type":"control","action":"peer_message_status","orig_msg_id":"bridge_1_guess","status":"delivered"});
        writeln!(guessed, "{line}").unwrap();
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
    let line = json!({"type": "user", "message": {"role": "user", "content": manifest}});
    std::fs::write(&transcript, format!("{line}\n")).unwrap();
    assert!(eventually(6_000, || lab
        .attempt("evt-quiet")
        .unwrap()
        .state
        == AttemptState::NativeAccepted));
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

    codex_setup(&lab, "refuse", port);
    lab.publish("evt-q2", &address, Mode::Message, "refused payload");
    let report = dispatch_message(&lab.storage, &mut carrier, &address, &now, &timing).unwrap();
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

    codex_setup(&lab, "silent", port);
    let mut slow = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/usr/bin/sandbox-exec".into(),
        Duration::from_secs(2),
    );
    lab.publish("evt-q3", &address, Mode::Message, "silent payload");
    // evt-q2 waits for its retry delay; evt-q3 is the next attempt.
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
