//! Native-owner wake route boundary tests over real owned processes.
//!
//! A scripted stand-in owner (a fixture process) is the exact direct parent of
//! a stand-in harness; the real adapter channel, hooks, registry, core custody
//! and the real Codex and Claude carriers run unchanged. The tests prove the
//! route's fences and outcome mapping; they do not establish a native turn or
//! context in a real model.

mod common;

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
use bridge_adapters::codex::CodexQueueCarrier;
use bridge_adapters::server::Custody;
use bridge_core::dispatch::{
    AttemptState, DispatchCarrier, DispatchReport, DispatchTiming, EffectiveMode, Outcome,
    Selection, dispatch_message,
};
use bridge_core::{Harness, Mode, NativeAddress};
use common::*;
use serde_json::{Value, json};

/// The session identifier every rig addresses.
const SESSION: &str = "owned-1";

/// One scripted owner, its direct-child harness, the carrier under test and
/// the legacy queue/inbox observers that must stay untouched.
struct Rig {
    /// The lab (stores, registry, custody, channel).
    lab: Lab,
    /// The owner process; commands to the harness are forwarded.
    native: Harnessed,
    /// Which native product the harness stands in for.
    harness: Harness,
    /// Recipient address.
    address: NativeAddress,
    /// The real carrier of that harness.
    carrier: Box<dyn DispatchCarrier>,
    /// Owner socket path (`o.sock` in a private directory).
    socket: PathBuf,
}

impl Rig {
    /// Starts an owner and harness, binds the recipient through real hooks and
    /// leaves it positively idle (`Stop`). The registry names no owner path or
    /// digest. Legacy routes are armed: a fake Claude inbox that would accept, a
    /// Codex helper that would queue.
    fn new(tag: &str, harness: Harness) -> Rig {
        Rig::with_owner_exe(tag, harness, None)
    }

    /// Like [`Rig::new`] with the owner process started from `owner_exe` (a copy
    /// of the fixture) while its harness child still runs the shared fixture, so
    /// only the owner executable can be made unsafe or changed.
    fn with_owner_exe(tag: &str, harness: Harness, owner_exe: Option<&Path>) -> Rig {
        let lab = Lab::new(tag);
        let store = match harness {
            Harness::Codex => lab.codex_store.clone(),
            Harness::ClaudeCode => lab.claude_store.clone(),
            Harness::OpenCode => lab.opencode_store.clone(),
        };
        let directory = lab.dir.0.join("ow");
        let mut native = match owner_exe {
            Some(exe) => Harnessed::start_owned_from(exe, harness, &store, &directory),
            None => Harnessed::start_owned(harness, &store, &directory),
        };
        let address = match harness {
            Harness::Codex => lab.codex_address(SESSION),
            Harness::ClaudeCode => lab.claude_address(SESSION),
            Harness::OpenCode => lab.opencode_address(SESSION),
        };
        let carrier: Box<dyn DispatchCarrier> = match harness {
            Harness::OpenCode => Box::new(bridge_adapters::opencode::OpenCodeOwnerCarrier::new(
                Arc::clone(&lab.registry),
            )),
            Harness::Codex => {
                std::fs::write(lab.codex_store.join("behavior"), "accept").unwrap();
                std::fs::write(lab.codex_store.join("probe_port"), "9").unwrap();
                Box::new(CodexQueueCarrier::new(
                    Arc::clone(&lab.registry),
                    "/usr/bin/sandbox-exec".into(),
                    Duration::from_secs(10),
                ))
            }
            Harness::ClaudeCode => {
                native.cmd(json!({"cmd": "inbox", "session_id": SESSION, "behavior": "delivered"}));
                Box::new(
                    ClaudeLaterCarrier::new(
                        Arc::clone(&lab.registry),
                        Arc::clone(&lab.storage) as Arc<dyn Custody>,
                        ClaudeTiming::default(),
                    )
                    .unwrap(),
                )
            }
        };
        let mut rig = Rig {
            socket: directory.join("o.sock"),
            lab,
            native,
            harness,
            address,
            carrier,
        };
        rig.hook("SessionStart");
        rig.hook("Stop");
        rig
    }

    /// Fires one real hook of the recipient session through the harness.
    fn hook(&mut self, event: &str) {
        let reply = self
            .native
            .hook(&self.lab.socket, self.harness, common::hook(event, SESSION));
        assert_eq!(reply["status"], 0, "{reply}");
    }

    /// Chooses the receipt the scripted owner answers next requests with.
    fn script(&mut self, mode: &str) {
        self.native
            .cmd(json!({"cmd": "owner_script", "mode": mode}));
    }

    /// The owner's observation log (`probes`, strict `frames`, `harness_pid`).
    fn log(&mut self) -> Value {
        self.native.cmd(json!({"cmd": "owner_log"}))
    }

    /// Number of request frames the owner received.
    fn frames(&mut self) -> usize {
        self.log()["frames"].as_array().unwrap().len()
    }

    /// Frames received by the armed legacy path: Codex helper queue entries or
    /// Claude inbox frames. Must stay zero whenever the owner route is selected.
    fn legacy(&mut self) -> usize {
        match self.harness {
            Harness::Codex => std::fs::read_to_string(self.lab.codex_store.join("queue.jsonl"))
                .map(|text| text.lines().count())
                .unwrap_or(0),
            Harness::ClaudeCode => self.native.cmd(json!({"cmd": "frames"}))["frames"]
                .as_array()
                .map_or(0, Vec::len),
            Harness::OpenCode => 0,
        }
    }

    /// Publishes `payload` and drives one message-path dispatch.
    fn send(&mut self, event: &str, mode: Mode, payload: &str) -> DispatchReport {
        self.lab.publish(event, &self.address, mode, payload);
        dispatch_message(
            &self.lab.storage,
            self.carrier.as_mut(),
            &self.address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap()
    }

    /// The durable attempt state of an event, if it was ever attempted.
    fn state(&self, event: &str) -> Option<AttemptState> {
        self.lab.attempt(event).map(|attempt| attempt.state)
    }

    /// The accepting script for this harness.
    fn accept(&self) -> &'static str {
        match self.harness {
            Harness::Codex => "codex_accept",
            Harness::ClaudeCode => "claude_accept",
            Harness::OpenCode => "opencode_accept",
        }
    }
}

/// All supported harnesses: a positively idle recipient gets exactly one closed
/// six-key frame carrying the frozen manifest and exact native identity; the
/// accepted receipt is native acceptance; a second dispatch sends nothing
/// more; Auto and Message both use the owner route; no legacy queue or inbox
/// is used, and Claude needs no inbox descriptor.
#[test]
fn idle_owner_receives_one_exact_frame_for_supported_harnesses() {
    for harness in [Harness::Codex, Harness::ClaudeCode, Harness::OpenCode] {
        let mut rig = Rig::new("ow1", harness);
        if harness == Harness::ClaudeCode {
            // No descriptor may be needed: a descriptor-less Claude is held by
            // the legacy route but is woken through its owner.
            let sessions = rig.lab.claude_store.join("sessions");
            let _ = std::fs::remove_dir_all(sessions);
        }
        rig.script(rig.accept());
        let report = rig.send("evt-1", Mode::Message, "wake marker");
        assert!(
            matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::NativeAccepted,
                    ..
                }
            ),
            "{harness:?}: {report:?}"
        );
        let log = rig.log();
        let frames = log["frames"].as_array().unwrap();
        assert_eq!(frames.len(), 1, "{harness:?}");
        let frame = frames[0].as_object().unwrap();
        let mut keys: Vec<_> = frame.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "call_id",
                "native_pid",
                "native_start_time",
                "text",
                "thread_id",
                "wake_only"
            ]
        );
        let attempt = rig.lab.attempt("evt-1").unwrap();
        assert_eq!(frame["thread_id"], SESSION);
        assert_eq!(frame["text"], attempt.manifest.as_str());
        assert_eq!(frame["wake_only"], true);
        assert!(
            frame["call_id"]
                .as_str()
                .unwrap()
                .starts_with("agent-bridge-")
        );
        let pid = log["harness_pid"].as_u64().unwrap();
        assert_eq!(frame["native_pid"], pid);
        let facts = bridge_adapters::os::process_facts(pid as u32).unwrap();
        assert_eq!(frame["native_start_time"], facts.start_time);
        assert_eq!(rig.legacy(), 0, "{harness:?}: legacy route must stay idle");

        // Nothing more is sent for the accepted event.
        let again = dispatch_message(
            &rig.lab.storage,
            rig.carrier.as_mut(),
            &rig.address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap();
        assert!(!matches!(again, DispatchReport::Sent { .. }), "{again:?}");
        assert_eq!(rig.frames(), 1);

        // Auto resolves to the message path for a positively idle recipient.
        let auto = rig.send("evt-2", Mode::Auto, "auto marker");
        assert!(
            matches!(
                auto,
                DispatchReport::Sent {
                    state: AttemptState::NativeAccepted,
                    ..
                }
            ),
            "{auto:?}"
        );
        assert_eq!(rig.frames(), 2);
        assert_eq!(rig.legacy(), 0);
        rig.native.stop();
    }
}

/// Every receipt shape maps conservatively after the write: a correlated,
/// finitely coded refusal is known-unsent; all other deviations and every
/// unknown are retained as outcome-unknown, and an unknown attempt is never
/// sent again nor routed through the legacy queue or inbox.
#[test]
fn receipts_after_the_write_map_conservatively_and_never_resend() {
    let cases: [(&str, bool); 16] = [
        ("known_unsent:not_idle", true),
        ("known_unsent:awaiting_input", true),
        ("known_unsent:budget", true),
        ("known_unsent:conflict", true),
        ("known_unsent:free text", false),
        ("unknown:native_uncertain", false),
        ("unknown:channel_failed", false),
        ("silent", false),
        ("wrong_call", false),
        ("extra_key", false),
        ("dup_key", false),
        ("garbage", false),
        ("claude_accept", false),
        ("codex_accept", false),
        ("opencode_accept", false),
        ("known_unsent:", false),
    ];
    for harness in [Harness::Codex, Harness::ClaudeCode, Harness::OpenCode] {
        for (mode, known_unsent) in cases {
            let wrong_protocol = match harness {
                Harness::Codex => matches!(mode, "claude_accept" | "opencode_accept"),
                Harness::ClaudeCode => matches!(mode, "codex_accept" | "opencode_accept"),
                Harness::OpenCode => matches!(mode, "codex_accept" | "claude_accept"),
            };
            let right_protocol = matches!(
                (harness, mode),
                (Harness::Codex, "codex_accept")
                    | (Harness::ClaudeCode, "claude_accept")
                    | (Harness::OpenCode, "opencode_accept")
            );
            if right_protocol {
                continue;
            }
            let mut rig = Rig::new("ow2", harness);
            rig.script(mode);
            let report = rig.send("evt-r", Mode::Message, "marker");
            let expected = if known_unsent {
                AttemptState::KnownUnsent
            } else {
                AttemptState::OutcomeUnknown
            };
            assert!(
                matches!(report, DispatchReport::Sent { state, .. } if state == expected),
                "{harness:?} {mode} wrong_protocol={wrong_protocol}: {report:?}"
            );
            assert_eq!(rig.frames(), 1, "{harness:?} {mode}");
            // Repeated drives never resend and never reach a legacy route.
            for _ in 0..3 {
                let _ = dispatch_message(
                    &rig.lab.storage,
                    rig.carrier.as_mut(),
                    &rig.address,
                    &now,
                    &DispatchTiming::default(),
                );
            }
            if !known_unsent {
                assert_eq!(rig.frames(), 1, "{harness:?} {mode}: no resend");
                assert_eq!(rig.state("evt-r"), Some(AttemptState::OutcomeUnknown));
            }
            assert_eq!(rig.legacy(), 0, "{harness:?} {mode}: no fallback");
            rig.native.stop();
        }
    }
}

/// A foreign listener standing where the owner socket should be. It counts the
/// connections that deliver at least one byte, and is shut down and joined
/// deterministically instead of being left blocked in `accept`.
struct Watch {
    /// Set to ask the listener thread to drain pending connections and exit.
    stop: Arc<AtomicBool>,
    /// Connections that delivered at least one byte.
    seen: Arc<AtomicUsize>,
    /// The listener thread; taken by [`Watch::finish`].
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watch {
    /// Serves `listener` on a thread that polls without blocking, reads each
    /// accepted connection for at most 300 ms, and after `stop` is set makes
    /// one last pass over the connections already queued before exiting.
    fn start(listener: UnixListener) -> Watch {
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let (flag, counter) = (Arc::clone(&stop), Arc::clone(&seen));
        let thread = std::thread::spawn(move || {
            loop {
                let stopping = flag.load(Ordering::SeqCst);
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_millis(300)))
                            .unwrap();
                        let mut byte = [0; 1];
                        if stream.read(&mut byte).unwrap_or(0) > 0 {
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Err(_) if stopping => break,
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Watch {
            stop,
            seen,
            thread: Some(thread),
        }
    }

    /// Stops the listener, joins its thread (every connection queued before the
    /// call has been examined by then) and returns how many sent a byte.
    fn finish(mut self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
        self.seen.load(Ordering::SeqCst)
    }
}

impl Drop for Watch {
    /// Asks a listener that was never finished (a failed assertion) to exit.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Every unprovable or non-idle condition sends nothing: no owner frame, no
/// legacy queue entry, no inbox frame. Covers active, awaiting-input and
/// ended recipients, a stopped harness, a dead
/// owner, a replaced socket (the new listener sees no byte), a symlinked
/// locator and a socket that is not private.
#[test]
fn unprovable_or_non_idle_recipients_send_nothing_and_never_fall_back() {
    let cases = [
        "active",
        "awaiting",
        "ended",
        "harness_stopped",
        "owner_dead",
        "replaced",
        "symlinked",
        "loose_mode",
    ];
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        for case in cases {
            let mut rig = Rig::new("ow3", harness);
            rig.script(rig.accept());
            let mut watch: Option<Watch> = None;
            match case {
                "active" => rig.hook("UserPromptSubmit"),
                "awaiting" => rig.hook("PermissionRequest"),
                "ended" => rig.hook("SessionEnd"),
                "harness_stopped" => {
                    rig.native.cmd(json!({"cmd": "owner_stop_harness"}));
                }
                "owner_dead" => {
                    rig.native.cmd(json!({"cmd": "owner_die"}));
                }
                "replaced" | "symlinked" => {
                    // A different process (this test) now answers at the
                    // locator path; it is not the harness's direct parent.
                    let other = rig.socket.with_file_name("x.sock");
                    let _ = std::fs::remove_file(&rig.socket);
                    let listener = UnixListener::bind(if case == "replaced" {
                        &rig.socket
                    } else {
                        &other
                    })
                    .unwrap();
                    if case == "symlinked" {
                        std::os::unix::fs::symlink(&other, &rig.socket).unwrap();
                    }
                    watch = Some(Watch::start(listener));
                }
                "loose_mode" => {
                    std::fs::set_permissions(&rig.socket, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                _ => {}
            }
            let report = rig.send("evt-n", Mode::Message, "marker");
            assert!(
                !matches!(
                    report,
                    DispatchReport::Sent {
                        state: AttemptState::NativeAccepted
                            | AttemptState::OutcomeUnknown
                            | AttemptState::WrittenNoReceipt,
                        ..
                    }
                ),
                "{harness:?} {case}: {report:?}"
            );
            let bytes = watch.take().map_or(0, Watch::finish);
            assert_eq!(
                bytes, 0,
                "{harness:?} {case}: the foreign listener got a byte"
            );
            // A dead owner cannot be queried; its harness exits with it.
            if case != "owner_dead" {
                assert_eq!(rig.frames(), 0, "{harness:?} {case}");
                assert_eq!(rig.legacy(), 0, "{harness:?} {case}: no fallback");
            }
            rig.native.stop();
        }
    }
}

/// The send path itself re-validates and guards before writing: a changed
/// endpoint epoch and a core attempt with less than 35 seconds left are
/// known-unsent with zero frames, while 35 seconds or more send exactly once.
#[test]
fn send_fences_epoch_and_remaining_budget_before_any_write() {
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        let mut rig = Rig::new("ow4", harness);
        rig.script(rig.accept());
        let attestation = rig.carrier.attest(&rig.address).unwrap();
        rig.lab
            .publish("evt-g", &rig.address, Mode::Message, "guarded");
        let record = match rig
            .lab
            .storage
            .lock()
            .unwrap()
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                now(),
                &DispatchTiming::default(),
            )
            .unwrap()
        {
            Selection::Attempt(record) => *record,
            other => panic!("{other:?}"),
        };
        let mut stale = record.clone();
        stale.fence.endpoint_epoch += 1;
        let mut short = record.clone();
        short.deadline_ms = now() + 34_000;
        let mut expired = record.clone();
        expired.deadline_ms = now().saturating_sub(1);
        for (label, attempt) in [("epoch", stale), ("short", short), ("expired", expired)] {
            let outcome = rig.carrier.send(&attempt);
            assert!(
                matches!(outcome, Outcome::KnownUnsent { .. }),
                "{harness:?} {label}: {outcome:?}"
            );
            assert_eq!(rig.frames(), 0, "{harness:?} {label}");
        }
        let mut enough = record.clone();
        enough.deadline_ms = now() + 60_000;
        let outcome = rig.carrier.send(&enough);
        assert!(
            matches!(outcome, Outcome::NativeAccepted { .. }),
            "{harness:?}: {outcome:?}"
        );
        assert_eq!(rig.frames(), 1);
        rig.native.stop();
    }
}

/// JSON escaping of the frozen manifest is accounted for: quotes, backslashes,
/// newlines and non-ASCII text in a large payload round-trip byte-exact in the
/// request, and the encoded frame is larger than the decoded text.
#[test]
fn escaped_large_manifest_round_trips_exactly() {
    let payload = "\"\\\n\t\u{e9}\u{1F600}".repeat(4_000);
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        let mut rig = Rig::new("ow5", harness);
        rig.script(rig.accept());
        let report = rig.send("evt-big", Mode::Message, &payload);
        assert!(
            matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::NativeAccepted,
                    ..
                }
            ),
            "{harness:?}: {report:?}"
        );
        let attempt = rig.lab.attempt("evt-big").unwrap();
        let log = rig.log();
        let text = log["frames"][0]["text"].as_str().unwrap();
        assert_eq!(text, attempt.manifest);
        assert!(text.len() > 40_000);
        rig.native.stop();
    }
}

/// An absent owner locator leaves legacy behavior untouched even when an owner
/// is running: a plain Codex harness still queues through the helper
/// and a plain Claude harness still receives its inbox frame.
#[test]
fn absent_locator_preserves_legacy_routes() {
    let lab = Lab::new("ow6");
    let mut codex = Harnessed::start(Harness::Codex, &lab.codex_store);
    std::fs::write(lab.codex_store.join("behavior"), "accept").unwrap();
    std::fs::write(lab.codex_store.join("probe_port"), "9").unwrap();
    codex.hook(&lab.socket, Harness::Codex, hook("SessionStart", SESSION));
    codex.hook(&lab.socket, Harness::Codex, hook("Stop", SESSION));
    let address = lab.codex_address(SESSION);
    let mut carrier = CodexQueueCarrier::new(
        Arc::clone(&lab.registry),
        "/usr/bin/sandbox-exec".into(),
        Duration::from_secs(10),
    );
    lab.publish("evt-l", &address, Mode::Message, "legacy marker");
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
    let queued = std::fs::read_to_string(lab.codex_store.join("queue.jsonl")).unwrap();
    assert_eq!(queued.lines().count(), 1);

    let mut claude = Harnessed::start(Harness::ClaudeCode, &lab.claude_store);
    claude.cmd(json!({"cmd": "inbox", "session_id": SESSION, "behavior": "delivered"}));
    claude.hook(
        &lab.socket,
        Harness::ClaudeCode,
        hook("SessionStart", SESSION),
    );
    claude.hook(&lab.socket, Harness::ClaudeCode, hook("Stop", SESSION));
    let address = lab.claude_address(SESSION);
    let mut carrier = ClaudeLaterCarrier::new(
        Arc::clone(&lab.registry),
        Arc::clone(&lab.storage) as Arc<dyn Custody>,
        ClaudeTiming::default(),
    )
    .unwrap();
    lab.publish("evt-c", &address, Mode::Message, "legacy marker");
    let report = dispatch_message(
        &lab.storage,
        &mut carrier,
        &address,
        &now,
        &DispatchTiming::default(),
    )
    .unwrap();
    assert!(matches!(report, DispatchReport::Sent { .. }), "{report:?}");
    assert_eq!(
        claude.cmd(json!({"cmd": "frames"}))["frames"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    codex.stop();
    claude.stop();
}

/// Unknown metadata is not absence: an exited process and (for a non-root
/// test user) a root-owned process whose environment cannot be read are errors
/// for the owner locator lookup, while a readable environment without the
/// variable is positive absence and one naming it yields the locator.
#[test]
fn unreadable_environment_is_not_positive_absence() {
    use std::process::{Command, Stdio};
    let spawn = |variable: (&str, &str)| {
        Command::new(fixture_exe())
            .arg("harness")
            .env_clear()
            .env(variable.0, variable.1)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let name = "BRIDGE_NATIVE_OWNER_SOCKET";
    let mut named = spawn((name, "/x"));
    let mut plain = spawn(("OTHER", "1"));
    assert_eq!(
        bridge_adapters::os::process_env_checked(named.id(), name)
            .unwrap()
            .unwrap(),
        "/x"
    );
    assert!(
        bridge_adapters::os::process_env_checked(plain.id(), name)
            .unwrap()
            .is_none()
    );
    let me = bridge_adapters::os::process_facts(std::process::id()).unwrap();
    if me.uid != Some(0) {
        assert!(bridge_adapters::os::process_env_checked(1, name).is_err());
    }
    let gone = named.id();
    for child in [&mut named, &mut plain] {
        drop(child.stdin.take());
        child.wait().unwrap();
    }
    assert!(bridge_adapters::os::process_env_checked(gone, name).is_err());
}

/// A PRESENT owner locator whose value is not valid UTF-8 is never positive
/// absence: with the legacy Codex helper queue and Claude inbox both armed and
/// the recipient positively idle, nothing is delivered through either legacy
/// route (the attempt is held), whereas a genuinely absent locator (see
/// `absent_locator_preserves_legacy_routes`) still delivers through them.
#[test]
fn present_non_utf8_locator_holds_and_never_falls_back() {
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        let lab = Lab::new("ow7");
        let store = match harness {
            Harness::Codex => lab.codex_store.clone(),
            Harness::ClaudeCode => lab.claude_store.clone(),
            Harness::OpenCode => lab.opencode_store.clone(),
        };
        let mut native = Harnessed::start_with_locator(harness, &store, b"/not-utf8-\xff\xfe.sock");
        let (address, mut carrier): (NativeAddress, Box<dyn DispatchCarrier>) = match harness {
            Harness::OpenCode => (
                lab.opencode_address(SESSION),
                Box::new(bridge_adapters::opencode::OpenCodeOwnerCarrier::new(
                    Arc::clone(&lab.registry),
                )),
            ),
            Harness::Codex => {
                std::fs::write(lab.codex_store.join("behavior"), "accept").unwrap();
                std::fs::write(lab.codex_store.join("probe_port"), "9").unwrap();
                (
                    lab.codex_address(SESSION),
                    Box::new(CodexQueueCarrier::new(
                        Arc::clone(&lab.registry),
                        "/usr/bin/sandbox-exec".into(),
                        Duration::from_secs(10),
                    )),
                )
            }
            Harness::ClaudeCode => {
                native.cmd(json!({"cmd": "inbox", "session_id": SESSION, "behavior": "delivered"}));
                (
                    lab.claude_address(SESSION),
                    Box::new(
                        ClaudeLaterCarrier::new(
                            Arc::clone(&lab.registry),
                            Arc::clone(&lab.storage) as Arc<dyn Custody>,
                            ClaudeTiming::default(),
                        )
                        .unwrap(),
                    ),
                )
            }
        };
        for event in ["SessionStart", "Stop"] {
            let reply = native.hook(&lab.socket, harness, hook(event, SESSION));
            assert_eq!(reply["status"], 0, "{reply}");
        }
        lab.publish("evt-u", &address, Mode::Message, "legacy marker");
        let report = dispatch_message(
            &lab.storage,
            carrier.as_mut(),
            &address,
            &now,
            &DispatchTiming::default(),
        )
        .unwrap();
        assert!(
            !matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::NativeAccepted
                        | AttemptState::OutcomeUnknown
                        | AttemptState::WrittenNoReceipt,
                    ..
                }
            ),
            "{harness:?}: {report:?}"
        );
        let legacy = match harness {
            Harness::Codex => std::fs::read_to_string(lab.codex_store.join("queue.jsonl"))
                .map(|text| text.lines().count())
                .unwrap_or(0),
            Harness::ClaudeCode => native.cmd(json!({"cmd": "frames"}))["frames"]
                .as_array()
                .map_or(0, Vec::len),
            Harness::OpenCode => 0,
        };
        assert_eq!(legacy, 0, "{harness:?}: no legacy fallback");
        native.stop();
    }
}

/// A same-user owner process that is NOT the exact direct parent of the attested
/// harness is refused with no effect. A second scripted owner (the same
/// fixture executable, older than the harness, same user) has its socket
/// moved over the locator path, so every other fence (canonical private path,
/// mode, user, owner executable, start order) passes and only the direct-parent
/// fence can refuse it; the forged owner must receive no request frame.
#[test]
fn non_parent_owner_is_refused_with_no_effect() {
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        let forged_dir = TempDir::new("ow8");
        let lab_store = TempDir::new("ow8s");
        let forged_directory = forged_dir.0.join("fo");
        let mut forged = Harnessed::start_owned(harness, &lab_store.0, &forged_directory);
        forged.cmd(json!({"cmd": "owner_script", "mode": match harness {
            Harness::Codex => "codex_accept",
            Harness::ClaudeCode => "claude_accept",
            Harness::OpenCode => "opencode_accept",
        }}));
        std::thread::sleep(Duration::from_millis(1100));
        let mut rig = Rig::new("ow8", harness);
        rig.script(rig.accept());
        std::fs::remove_file(&rig.socket).unwrap();
        std::fs::rename(forged_directory.join("o.sock"), &rig.socket).unwrap();
        let report = rig.send("evt-f", Mode::Message, "forged owner marker");
        assert!(
            !matches!(
                report,
                DispatchReport::Sent {
                    state: AttemptState::NativeAccepted
                        | AttemptState::OutcomeUnknown
                        | AttemptState::WrittenNoReceipt,
                    ..
                }
            ),
            "{harness:?}: {report:?}"
        );
        let seen = forged.cmd(json!({"cmd": "owner_log"}));
        assert_eq!(
            seen["frames"].as_array().unwrap().len(),
            0,
            "{harness:?}: the forged owner received a request"
        );
        assert_eq!(rig.frames(), 0, "{harness:?}");
        assert_eq!(rig.legacy(), 0, "{harness:?}: no fallback");
        forged.stop();
        rig.native.stop();
    }
}

/// The owner route needs no predeclared owner path or digest (the lab names
/// none), but the owner's own executable must be trusted and unchanged since the
/// owner started: from a private copy of the fixture the control delivers once,
/// then making the running owner's file group-writable, or merely changing its
/// status time again, refuses the next attempt before any request byte is
/// written, with no owner frame and no legacy fallback.
#[test]
fn unsafe_or_changed_owner_executable_is_refused_with_no_effect() {
    use std::os::unix::fs::PermissionsExt;
    for harness in [Harness::Codex, Harness::ClaudeCode] {
        for (label, mode) in [("group-writable", 0o775), ("status change only", 0o755)] {
            let dir = TempDir::new("ow9");
            let owner_exe = dir.0.join("bridge-fixture-owner");
            std::fs::copy(fixture_exe(), &owner_exe).unwrap();
            std::fs::set_permissions(&owner_exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            // The owner must start in a later second than its file's last change.
            std::thread::sleep(Duration::from_millis(1100));
            let mut rig = Rig::with_owner_exe("ow9", harness, Some(&owner_exe));
            rig.script(rig.accept());
            let control = rig.send("evt-ok", Mode::Message, "control");
            assert!(
                matches!(
                    control,
                    DispatchReport::Sent {
                        state: AttemptState::NativeAccepted,
                        ..
                    }
                ),
                "{harness:?} {label}: an unchanged trusted owner delivers: {control:?}"
            );
            assert_eq!(rig.frames(), 1);
            std::fs::set_permissions(&owner_exe, std::fs::Permissions::from_mode(mode)).unwrap();
            let report = rig.send("evt-bad", Mode::Message, "must not reach the owner");
            assert!(
                !matches!(
                    report,
                    DispatchReport::Sent {
                        state: AttemptState::NativeAccepted
                            | AttemptState::OutcomeUnknown
                            | AttemptState::WrittenNoReceipt,
                        ..
                    }
                ),
                "{harness:?} {label}: {report:?}"
            );
            assert_eq!(rig.frames(), 1, "{harness:?} {label}: no new owner frame");
            assert_eq!(rig.legacy(), 0, "{harness:?} {label}: no fallback");
            rig.native.stop();
        }
    }
}
