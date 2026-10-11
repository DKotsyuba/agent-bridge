//! Confinement and hook fault-envelope tests over real owned processes.
//!
//! These tests spawn the crate's own fixture binary (`bridge-fixture`) as
//! the Codex queue helper and the root hook transport, driving the exact
//! fault envelope from `docs/acceptance.md` A07/A22: crashes before and
//! after payload reply, partial stdout, signal death, late return, helper
//! environment scrubbing and archived-target refusal. Status files and
//! exit codes persist in the test's isolated temp directory.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use bridge_adapters::attest::{ActorId, AttestedCaller, BindingEpoch, ProtectedChannel};
use bridge_adapters::codex::{HelperSpec, QueueOutcome};
use bridge_adapters::hook::{
    DrainOutcome, DrainRequest, EmittedFlush, HandoffManifest, HookDrain, HookEvent, HookFault,
};
use bridge_adapters::lifecycle::GuardDecision;
use bridge_core::{Harness, NativeAddress};

use common::{TempDir, digest};

/// Path of the owned fixture binary, provided by cargo for `[[bin]]`s.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bridge-fixture"))
}

/// The confined Codex helper invocation under test.
fn run_helper(mode: &str, dir: &TempDir, env: &[(&str, &str)]) -> (String, Option<i32>) {
    let spec = HelperSpec {
        executable: fixture(),
        store_path: Path::new("/fixture-store/store.db").to_path_buf(),
    };
    let payload = dir.path("payload.txt");
    std::fs::write(&payload, "queue payload body").unwrap();
    let status = dir.path("helper-status.txt");
    let mut command = Command::new(&spec.executable);
    command
        .args([
            mode,
            &spec.store_path.to_string_lossy(),
            "thread-1",
            &payload.to_string_lossy(),
            &status.to_string_lossy(),
        ])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let output = command.output().expect("spawn fixture helper");
    let recorded = std::fs::read_to_string(&status).unwrap_or_default();
    (recorded, output.status.code())
}

#[test]
fn codex_helper_accepts_only_scrubbed_launches() {
    let dir = TempDir::new("codex-clean");
    // The production argv shape (verb-first, no shell) is exactly what
    // HelperSpec::argv produces for the same arguments.
    let spec = HelperSpec {
        executable: fixture(),
        store_path: Path::new("/fixture-store/store.db").to_path_buf(),
    };
    assert_eq!(
        spec.argv("thread-1", &dir.path("payload.txt")),
        vec![
            "add".to_string(),
            "/fixture-store/store.db".to_string(),
            "thread-1".to_string(),
            dir.path("payload.txt").to_string_lossy().into_owned(),
        ]
    );
    let (status, code) = run_helper("codex-helper", &dir, &[("PATH", "/usr/bin:/bin")]);
    assert_eq!(code, Some(0));
    assert!(
        status.starts_with("queue-accepted thread-1 cu-"),
        "{status}"
    );
    // A contaminated environment is a confinement violation the helper
    // itself reports and refuses (exit 3), never silently accepts.
    let dir = TempDir::new("codex-contaminated");
    let (status, code) = run_helper(
        "codex-helper",
        &dir,
        &[("PATH", "/usr/bin:/bin"), ("CODEX_THREAD_ID", "foreign")],
    );
    assert_eq!(code, Some(3));
    assert!(status.starts_with("confinement-violation"), "{status}");
    // Archived targets refuse publication and hold.
    let dir = TempDir::new("codex-archived");
    let (status, code) = run_helper("codex-helper-archived", &dir, &[("PATH", "/usr/bin:/bin")]);
    assert_eq!(code, Some(0));
    assert_eq!(status.trim(), "archived-refused");
    // The spec's executable must itself be allowlisted before any spawn.
    assert!(spec.validate_against(&[fixture()]).is_ok());
    assert!(spec.validate_against(&[]).is_err());
}

#[test]
fn codex_outcomes_map_through_the_attempt_gate() {
    use bridge_adapters::codex::attempt_outcome;
    use bridge_adapters::dispatch::{AttemptGate, AttemptOutcome};
    let dir = TempDir::new("codex-gate");
    let (status, _) = run_helper("codex-helper", &dir, &[("PATH", "/usr/bin:/bin")]);
    let client_id = status.trim().split(' ').nth(2).unwrap().to_string();
    let outcome = attempt_outcome(&QueueOutcome::NativeAccepted {
        client_user_message_id: client_id,
    });
    assert!(matches!(outcome, AttemptOutcome::PossiblyAccepted { .. }));
    let mut gate = AttemptGate::default();
    assert!(gate.begin("evt-queue").is_ok());
    gate.record("evt-queue", outcome);
    // Queue acceptance is storage acceptance: a duplicate dispatch is
    // denied while the attempt stands, with no second invocation.
    assert!(matches!(
        gate.begin("evt-queue"),
        Err(AttemptOutcome::PossiblyAccepted { .. })
    ));
}

/// Root caller fixture for drain requests.
fn root_caller() -> AttestedCaller {
    AttestedCaller {
        address: NativeAddress::new("h", Harness::ClaudeCode, "store", "sess-root").unwrap(),
        actor: ActorId::root("sess-root").unwrap(),
        epoch: BindingEpoch(1),
        observed_at_ms: 1_000,
        channel: ProtectedChannel::ClaudePreToolUse,
    }
}

/// Runs one hook-transport fixture through the drain with a real process.
fn drain_with_fixture(
    mode: &str,
    dir: &TempDir,
    payload: &str,
    deadline_ms: u64,
) -> Result<DrainOutcome, bridge_adapters::AdapterError> {
    let caller = root_caller();
    let payload_path = dir.path("hook-payload.txt");
    std::fs::write(&payload_path, payload).unwrap();
    let status_path = dir.path("hook-status.txt");
    let digest = digest(payload);
    let manifest = HandoffManifest {
        event_id: "evt-hook".into(),
        recipient: caller.address.to_canonical_string(),
        actor_native_id: caller.actor.native_id.clone(),
        payload_digest: digest.clone(),
        hook_event: HookEvent::PostToolUse,
        committed_at_ms: 1_500,
    };
    let request = DrainRequest {
        caller: &caller,
        event: HookEvent::PostToolUse,
        at_ms: 1_500,
        deadline_ms,
    };
    HookDrain::drain(
        &request,
        manifest,
        GuardDecision::Allow,
        |manifest| {
            // The commit persists the handoff before any payload exists;
            // the committed manifest file is the persisted log.
            std::fs::write(
                dir.path("committed-manifest.txt"),
                format!("{} {}", manifest.event_id, manifest.payload_digest),
            )
            .map_err(|_| "commit write failed")?;
            Ok(())
        },
        |manifest| {
            let started = Instant::now();
            let output = Command::new(fixture())
                .args([
                    mode,
                    &dir.path("hook-payload.txt").to_string_lossy(),
                    &status_path.to_string_lossy(),
                ])
                .output()
                .expect("spawn fixture hook");
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let late = started.elapsed().as_millis() as u64 > 200;
            match output.status.code() {
                Some(0) if late => Err(HookFault::LateReturn),
                Some(0) if stdout == payload => Ok(EmittedFlush {
                    payload_digest: manifest.payload_digest.clone(),
                }),
                Some(1) if stdout.is_empty() => Err(HookFault::CrashBeforeReply),
                Some(1) => Err(HookFault::CrashAfterPartialStdout),
                Some(_) => Err(HookFault::Busy),
                None => Err(HookFault::Killed),
            }
        },
    )
}

#[test]
fn hook_fault_envelope_maps_conservatively_over_real_processes() {
    // Full flush after commit: positive emission evidence.
    let dir = TempDir::new("hook-emit");
    let outcome = drain_with_fixture("hook-emit", &dir, "hook payload body", 5_000).unwrap();
    assert!(matches!(outcome, DrainOutcome::Emitted { .. }));
    assert!(dir.path("committed-manifest.txt").is_file());
    assert_eq!(
        std::fs::read_to_string(dir.path("hook-status.txt"))
            .unwrap()
            .trim(),
        "emitted"
    );

    // Crash before any reply, after commit: uncertain emission, retained.
    let dir = TempDir::new("hook-crash");
    let outcome =
        drain_with_fixture("hook-crash-before-reply", &dir, "hook payload body", 5_000).unwrap();
    assert!(matches!(outcome, DrainOutcome::UncertainEmission { .. }));
    assert!(dir.path("committed-manifest.txt").is_file());

    // Partial stdout then death: uncertain emission.
    let dir = TempDir::new("hook-partial");
    let outcome =
        drain_with_fixture("hook-partial-stdout", &dir, "hook payload body", 5_000).unwrap();
    assert!(matches!(outcome, DrainOutcome::UncertainEmission { .. }));

    // Signal death: uncertain emission.
    let dir = TempDir::new("hook-killed");
    let outcome = drain_with_fixture("hook-killed", &dir, "hook payload body", 5_000).unwrap();
    assert!(matches!(outcome, DrainOutcome::UncertainEmission { .. }));

    // Late return past the drain deadline: uncertain emission. The
    // request deadline stays generous; lateness is classified by the
    // transport's own elapsed time versus the 200 ms fixture budget.
    let dir = TempDir::new("hook-late");
    let outcome = drain_with_fixture("hook-late", &dir, "hook payload body", 5_000).unwrap();
    assert!(matches!(outcome, DrainOutcome::UncertainEmission { .. }));
    assert_eq!(
        std::fs::read_to_string(dir.path("hook-status.txt"))
            .unwrap()
            .trim(),
        "late-return"
    );
}

#[test]
fn children_never_drain_and_guards_hold() {
    use bridge_adapters::attest::ActorRole;
    let dir = TempDir::new("hook-child");
    let mut child = root_caller();
    child.actor = ActorId::child("agent-child").unwrap();
    assert_eq!(child.actor.role, ActorRole::Child);
    let payload_path = dir.path("hook-payload.txt");
    std::fs::write(&payload_path, "body").unwrap();
    let request = DrainRequest {
        caller: &child,
        event: HookEvent::UserPromptSubmit,
        at_ms: 1_500,
        deadline_ms: 5_000,
    };
    let manifest = HandoffManifest {
        event_id: "evt-child".into(),
        recipient: child.address.to_canonical_string(),
        actor_native_id: "root-actor".into(),
        payload_digest: digest("body"),
        hook_event: HookEvent::UserPromptSubmit,
        committed_at_ms: 1_500,
    };
    let result = HookDrain::drain(
        &request,
        manifest,
        GuardDecision::Allow,
        |_| unreachable!("commit must not run"),
        |_| unreachable!("emit must not run"),
    );
    assert!(matches!(
        result,
        Err(bridge_adapters::AdapterError::ChildRefused(_))
    ));
    // A held guard drains nothing and commits nothing.
    let caller = root_caller();
    let request = DrainRequest {
        caller: &caller,
        event: HookEvent::PostToolUse,
        at_ms: 1_500,
        deadline_ms: 5_000,
    };
    let manifest = HandoffManifest {
        event_id: "evt-held".into(),
        recipient: caller.address.to_canonical_string(),
        actor_native_id: caller.actor.native_id.clone(),
        payload_digest: digest("body"),
        hook_event: HookEvent::PostToolUse,
        committed_at_ms: 1_500,
    };
    let outcome = HookDrain::drain(
        &request,
        manifest,
        GuardDecision::Hold("explicit no-wake policy entry"),
        |_| unreachable!("commit must not run under a hold"),
        |_| unreachable!("emit must not run under a hold"),
    )
    .unwrap();
    assert!(matches!(outcome, DrainOutcome::NotHanded { .. }));
}
