//! Operator counts, lineage transfer and the doctor recovery summary over a
//! real core service (schema 5) and the real `bridge` CLI.
//!
//! Synthetic publishers and recipients only; every socket, database and
//! token is a fresh file in an exclusively created `/tmp` scratch tree. No
//! native harness, model or network is involved.

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use bridge_client::{
    BridgeClient, EventId, Harness, Kind, LineageScope, Mode, NativeAddress, Payload, Policy,
    PublishRequest, StreamId,
};
use bridge_core::service::{Config, GrantConfig, start_with_carriers};
use bridge_interfaces::doctor;
use serde_json::{Value, json};

/// Producer A's publisher token (test-only).
const PRODUCER_A: &str = "producer-a-token-0123456789";

/// Producer B's publisher token (test-only).
const PRODUCER_B: &str = "producer-b-token-0123456789";

/// Operator token (test-only).
const OPERATOR: &str = "operator-token-for-counts-01";

/// The one synthetic recipient.
fn recipient() -> NativeAddress {
    NativeAddress::new("lab", Harness::ClaudeCode, "store", "session").unwrap()
}

/// An exclusively created scratch tree removed (only it) on drop.
struct Scratch(PathBuf);

impl Scratch {
    /// Creates `/tmp/bio<12 random hex>` with mode `0700`.
    fn new() -> Scratch {
        for _ in 0..16 {
            let random = bridge_adapters::os::random_bytes().unwrap();
            let suffix: String = random[..6].iter().map(|b| format!("{b:02x}")).collect();
            let dir = PathBuf::from(format!("/tmp/bio{suffix}"));
            if std::fs::create_dir(&dir).is_ok() {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                return Scratch(dir.canonicalize().unwrap());
            }
        }
        panic!("no free scratch name");
    }
}

impl Drop for Scratch {
    /// Removes the scratch tree.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes a 0600 file.
fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A running core plus interfaces configurations for two credentials.
struct Lab {
    /// Scratch owner (dropped last).
    scratch: Scratch,
    /// Core socket.
    socket: PathBuf,
    /// Interfaces configuration using the operator token.
    operator_config: PathBuf,
    /// Interfaces configuration whose "operator" token is a publisher's.
    publisher_config: PathBuf,
    /// The running core.
    core: Option<Arc<bridge_core::Running>>,
}

impl Drop for Lab {
    /// Stops the core.
    fn drop(&mut self) {
        if let Some(core) = self.core.take() {
            core.shutdown();
            if let Ok(core) = Arc::try_unwrap(core) {
                core.join();
            }
        }
    }
}

/// Writes an interfaces configuration for `socket` with `token`.
fn interfaces(dir: &Path, name: &str, socket: &Path, token: &str) -> PathBuf {
    let token_file = dir.join(format!("{name}.token"));
    private(&token_file, token);
    let path = dir.join(format!("{name}.toml"));
    private(
        &path,
        &format!(
            "core_socket = \"{}\"\n[operator]\ntoken_file = \"{}\"\n",
            socket.display(),
            token_file.display()
        ),
    );
    path
}

/// Starts a core with two `latest` producers and an operator grant.
fn lab() -> Lab {
    let scratch = Scratch::new();
    let dir = scratch.0.clone();
    let socket = dir.join("core.sock");
    let producer = |token: &str, name: &str| GrantConfig {
        token: token.into(),
        publisher: name.into(),
        recipients: vec![recipient().to_canonical_string()],
        kinds: vec!["view.snapshot".into(), "note".into()],
        modes: vec!["inject".into(), "message".into()],
        policies: vec!["latest".into(), "keep_all".into()],
        admin: false,
    };
    let core = start_with_carriers(
        Config {
            database: dir.join("bridge.db"),
            socket: socket.clone(),
            limits: serde_json::from_value(json!({"max_admitted_events": 1000})).unwrap(),
            grants: vec![
                producer(PRODUCER_A, "producer-a"),
                producer(PRODUCER_B, "producer-b"),
                GrantConfig {
                    token: OPERATOR.into(),
                    publisher: "bridge-ops".into(),
                    recipients: vec![],
                    kinds: vec![],
                    modes: vec![],
                    policies: vec![],
                    admin: true,
                },
            ],
        },
        Vec::new(),
    )
    .unwrap();
    Lab {
        operator_config: interfaces(&dir, "operator", &socket, OPERATOR),
        publisher_config: interfaces(&dir, "publisher", &socket, PRODUCER_A),
        socket,
        core: Some(Arc::new(core)),
        scratch,
    }
}

/// Runs the real `bridge` CLI; returns exit code, stdout JSON and stderr.
fn cli(args: &[&str]) -> (i32, Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_bridge"))
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The lineage scope of stream `stream` for the synthetic recipient.
fn scope(stream: &str) -> LineageScope {
    LineageScope {
        recipient: recipient().to_canonical_string(),
        kind: "view.snapshot".into(),
        mode: "inject".into(),
        project: String::new(),
        task: String::new(),
        stream: stream.into(),
    }
}

/// Producer A publishes revision 1 of `stream`.
fn publish_latest(client: &mut BridgeClient, stream: &str) {
    let body = PublishRequest::new(
        EventId::new(format!("a-{stream}")).unwrap(),
        recipient(),
        Kind::new("view.snapshot").unwrap(),
        Mode::Inject,
        Policy::Latest {
            stream: StreamId::new(stream).unwrap(),
            revision: 1,
        },
        Payload::new("snapshot").unwrap(),
    )
    .into_body()
    .unwrap();
    client.publish(PRODUCER_A, &body).unwrap();
}

/// The `recovery.pending` check of a doctor run over `config`.
fn recovery(config: &Path) -> doctor::Check {
    doctor::run(&doctor::DoctorInput {
        config: Some(config.to_path_buf()),
        ..Default::default()
    })
    .into_iter()
    .find(|check| check.name == "recovery.pending")
    .unwrap()
}

/// Checks real CLI totals, audited transfers and honest coverage beyond the 200-incident sample; owns and cleans its core fixture.
#[test]
fn counts_lineage_transfer_and_bounded_incident_samples() {
    let lab = lab();
    let config = lab.operator_config.to_str().unwrap();
    // Empty core: complete zero counts, doctor says empty.
    let (code, empty, _) = cli(&["operator", config, "counts"]);
    assert_eq!(code, 0);
    let fields = empty["counts"].as_object().unwrap();
    assert_eq!(fields.len(), 10, "all ten public fields: {empty}");
    assert!(fields.values().all(|value| value == 0));
    assert_eq!(recovery(&lab.operator_config).status, "ok");

    // A paused recipient's pending event: counted, no incident, not "ok".
    let mut client = BridgeClient::connect(&lab.socket).unwrap();
    client
        .pause(OPERATOR, &recipient(), "synthetic pause")
        .unwrap();
    let paused = PublishRequest::new(
        EventId::new("paused-note").unwrap(),
        recipient(),
        Kind::new("note").unwrap(),
        Mode::Inject,
        Policy::KeepAll,
        Payload::new("waits").unwrap(),
    )
    .into_body()
    .unwrap();
    client.publish(PRODUCER_A, &paused).unwrap();
    let (_, counted, _) = cli(&["operator", config, "counts"]);
    let pending = counted["counts"]["unhanded"].as_u64().unwrap()
        + counted["counts"]["held"].as_u64().unwrap();
    assert_eq!(pending, 1, "{counted}");
    assert_eq!(counted["counts"]["open_incidents"], 0);
    let waiting = recovery(&lab.operator_config);
    assert_eq!(
        waiting.status, "warn",
        "routine work is not reported as clear"
    );
    assert_eq!(waiting.detail["state"], "routine_waiting");

    // Lineage transfer through the CLI: the obsolete producer's pending
    // snapshot is held with a lineage incident.
    publish_latest(&mut client, "s000");
    let (code, applied, stderr) = cli(&[
        "operator",
        config,
        "transfer-lineage",
        "--recipient",
        &recipient().to_canonical_string(),
        "--kind",
        "view.snapshot",
        "--mode",
        "inject",
        "--project",
        "",
        "--task",
        "",
        "--stream",
        "s000",
        "--new-publisher",
        "producer-b",
        "--note",
        "producer-b now owns the view",
    ]);
    assert_eq!(code, 0, "{applied} {stderr}");
    let (_, listed, _) = cli(&["operator", config, "incidents"]);
    let lineage = listed["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|incident| incident["kind"] == "lineage_authority_lost")
        .cloned()
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(lineage["category"], "lineage");
    let next = lineage["next_action"].as_str().unwrap();
    assert!(next.contains("not dispatched while another producer owns the lineage"));
    assert!(next.contains("never replayed automatically"));
    assert!(next.contains("transfer the lineage back explicitly"));

    // More than 200 open incidents: totals from counts, a bounded sample.
    for index in 1..=200 {
        let stream = format!("s{index:03}");
        publish_latest(&mut client, &stream);
        client
            .transfer_lineage(OPERATOR, &scope(&stream), "producer-b", "bulk handover")
            .unwrap();
    }
    let (_, totals, _) = cli(&["operator", config, "counts"]);
    assert_eq!(totals["counts"]["open_incidents"], 201, "{totals}");
    let attention = recovery(&lab.operator_config);
    assert_eq!(attention.status, "warn");
    assert_eq!(attention.detail["state"], "attention");
    assert_eq!(attention.detail["open_incidents"], 201);
    assert_eq!(attention.detail["incident_sample"]["sampled"], 200);
    assert_eq!(
        attention.detail["incident_sample"]["sample_complete"],
        false
    );
    assert_eq!(
        attention.detail["incident_sample"]["by_category"]["lineage"],
        200
    );
    drop(client);
    let _ = &lab.scratch;
}

/// Checks authorization, credential and argument refusals stay explicit unknown data instead of empty totals; owns and cleans its core fixture.
#[test]
fn refusals_stay_explicit_and_never_become_zero() {
    let lab = lab();
    let operator = lab.operator_config.to_str().unwrap();
    // A publisher credential is refused by the core, unchanged.
    let publisher = lab.publisher_config.to_str().unwrap();
    let (code, _, stderr) = cli(&["operator", publisher, "counts"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("forbidden"), "{stderr}");
    let refused = recovery(&lab.publisher_config);
    assert_eq!(refused.status, "fail");
    assert_eq!(refused.detail["state"], "unknown");
    // An unreadable token: explicit failure, never a zero summary.
    std::fs::set_permissions(
        lab.scratch.0.join("operator.token"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let unreadable = recovery(&lab.operator_config);
    assert_eq!(unreadable.status, "fail");
    assert_eq!(unreadable.detail["state"], "unknown");
    std::fs::set_permissions(
        lab.scratch.0.join("operator.token"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // Malformed scope or blank note: refused before any request; the core
    // never sees it (counts unchanged, no audit effect).
    let base = |stream: &str, note: &str| -> Vec<String> {
        [
            "operator",
            operator,
            "transfer-lineage",
            "--recipient",
            &recipient().to_canonical_string(),
            "--kind",
            "view.snapshot",
            "--mode",
            "inject",
            "--project",
            "",
            "--task",
            "",
            "--stream",
            stream,
            "--new-publisher",
            "producer-b",
            "--note",
            note,
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    };
    for (stream, note) in [("s1", "   "), ("", "valid note"), ("s1\u{1}", "valid note")] {
        let args = base(stream, note);
        let (code, _, stderr) = cli(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert_ne!(code, 0, "{stream:?}/{note:?}");
        assert!(!stderr.contains("core unreachable"), "{stderr}");
    }
    let mut bad_mode = base("s1", "note");
    bad_mode[8] = "teleport".into();
    let (code, _, _) = cli(&bad_mode.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(code, 3, "a malformed scope is an invalid invocation");
    let (_, counts, _) = cli(&["operator", operator, "counts"]);
    assert!(
        counts["counts"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v == 0)
    );
}

/// Checks each mutation and read is sent once to a recording socket and a lost answer preserves mutation uncertainty versus unknown read data.
#[test]
fn a_lost_answer_is_reported_unknown_and_never_resent() {
    let scratch = Scratch::new();
    let socket = scratch.0.join("silent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // A fake core that reads each request line and closes without answering.
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut line = String::new();
                    let _ = BufReader::new(stream).read_line(&mut line);
                    let op: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    requests.push(op["op"].as_str().unwrap_or("?").to_string());
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        requests
    });
    let config = interfaces(&scratch.0, "silent", &socket, OPERATOR);
    let config = config.to_str().unwrap();
    let (code, _, stderr) = cli(&[
        "operator", config, "dispose", "p", "e", "--note", "close it",
    ]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("outcome unknown") && stderr.contains("not resent"),
        "{stderr}"
    );
    let (code, _, stderr) = cli(&[
        "operator",
        config,
        "transfer-lineage",
        "--recipient",
        &recipient().to_canonical_string(),
        "--kind",
        "view.snapshot",
        "--mode",
        "inject",
        "--project",
        "",
        "--task",
        "",
        "--stream",
        "s1",
        "--new-publisher",
        "producer-b",
        "--note",
        "handover",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("outcome unknown"), "{stderr}");
    // A lost answer to a read-only query is unknown data, not a possibly
    // applied change.
    let (code, _, stderr) = cli(&["operator", config, "counts"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("read failed"), "{stderr}");
    assert!(!stderr.contains("may have been applied"), "{stderr}");
    let requests = server.join().unwrap();
    assert_eq!(
        requests,
        ["dispose", "transfer_lineage", "counts"],
        "each sent exactly once"
    );
}

/// Checks blank notes, malformed lineage and unaccepted retry risk open zero connections to the owned recording socket.
#[test]
fn invalid_decisions_never_contact_the_core() {
    let scratch = Scratch::new();
    let socket = scratch.0.join("recording.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = interfaces(&scratch.0, "recording", &socket, OPERATOR);
    let config = config.to_str().unwrap();
    let address = recipient().to_canonical_string();
    let transfer = |stream: &str, note: &str| -> (i32, String) {
        let (code, _, stderr) = cli(&[
            "operator",
            config,
            "transfer-lineage",
            "--recipient",
            &address,
            "--kind",
            "view.snapshot",
            "--mode",
            "inject",
            "--project",
            "",
            "--task",
            "",
            "--stream",
            stream,
            "--new-publisher",
            "producer-b",
            "--note",
            note,
        ]);
        (code, stderr)
    };
    // A valid scope with a blank note passes argument parsing and scope
    // validation; only the pre-connect check stops it.
    let (code, stderr) = transfer("s1", "   ");
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("audit note is required"), "{stderr}");
    let (code, _) = transfer("", "handover");
    assert_eq!(code, 3, "a malformed scope is an invalid invocation");
    let (code, _, stderr) = cli(&["operator", config, "dispose", "p", "e", "--note", " "]);
    assert_eq!(code, 2, "{stderr}");
    let (code, _, stderr) = cli(&["operator", config, "retry", "p", "e", "--note", "risky"]);
    assert_eq!(code, 2, "a retry without risk acceptance: {stderr}");
    // Every CLI process has exited: count what reached the socket at all.
    let mut accepted = 0;
    while listener.accept().is_ok() {
        accepted += 1;
    }
    assert_eq!(
        accepted, 0,
        "a locally refused decision opened a connection"
    );
}

/// Checks actual CLI transfers preserve core authorization and native-effect fences without changing held events or lineage authority.
#[test]
fn non_admin_and_fenced_transfers_are_refused_by_the_core() {
    use bridge_core::dispatch::{
        Attestation, Capabilities, DispatchTiming, EffectiveMode, Lifecycle, Outcome, Selection,
    };
    let lab = lab();
    let operator = lab.operator_config.to_str().unwrap();
    let publisher = lab.publisher_config.to_str().unwrap();
    let mut client = BridgeClient::connect(&lab.socket).unwrap();
    // Producer A's message-mode snapshot is handed to the native side and
    // held there: a possible native effect the core must fence.
    let body = PublishRequest::new(
        EventId::new("a-fenced").unwrap(),
        recipient(),
        Kind::new("view.snapshot").unwrap(),
        Mode::Message,
        Policy::Latest {
            stream: StreamId::new("fenced").unwrap(),
            revision: 1,
        },
        Payload::new("snapshot").unwrap(),
    )
    .into_body()
    .unwrap();
    client.publish(PRODUCER_A, &body).unwrap();
    let core = lab.core.as_ref().unwrap();
    core.with_storage(|storage| {
        let now = bridge_core::service::current_unix_millis();
        let attestation = Attestation::verified(
            recipient(),
            recipient().native_session_id,
            1,
            Lifecycle::Inactive,
            Capabilities {
                inject: false,
                message: true,
            },
            "synthetic-fixture-proof",
        )
        .unwrap();
        let Selection::Attempt(attempt) = storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("nothing reserved");
        };
        storage
            .mark_invoking(&attempt.fence, &attestation, now + 1)
            .unwrap();
        storage
            .record_outcome(
                &attempt.fence,
                Outcome::NativeHeld {
                    recheck_ms: 600_000,
                },
                now + 2,
            )
            .unwrap();
    });
    let scope = |config: &str| -> (i32, String) {
        let address = recipient().to_canonical_string();
        let (code, _, stderr) = cli(&[
            "operator",
            config,
            "transfer-lineage",
            "--recipient",
            &address,
            "--kind",
            "view.snapshot",
            "--mode",
            "message",
            "--project",
            "",
            "--task",
            "",
            "--stream",
            "fenced",
            "--new-publisher",
            "producer-b",
            "--note",
            "handover",
        ]);
        (code, stderr)
    };
    let (code, stderr) = scope(publisher);
    assert_eq!(code, 2);
    assert!(stderr.contains("forbidden"), "{stderr}");
    let (code, stderr) = scope(operator);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("fence"),
        "core fence refusal passed through: {stderr}"
    );
    let (_, counts, _) = cli(&["operator", operator, "counts"]);
    let fields = counts["counts"].as_object().unwrap();
    assert_eq!(fields.len(), 10, "{counts}");
    assert_eq!(
        counts["counts"]["held"], 1,
        "the held event is unchanged: {counts}"
    );
    let (_, listed, _) = cli(&["operator", operator, "incidents"]);
    assert!(
        listed["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|incident| incident["kind"] != "lineage_authority_lost"),
        "a refused transfer holds nothing: {listed}"
    );
}
