//! Operator counts, lineage transfer and the doctor recovery summary over a
//! real core service with its current schema and the real `bridge` CLI.
//!
//! Synthetic publishers and recipients only; every socket, database and
//! token is a fresh file in an exclusively created scratch tree under the
//! configured temporary root. No
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
    /// Exclusively creates `bio<12 random hex>` under the configured temporary
    /// root with mode `0700`; panics after 16 failed creation attempts. The root
    /// must leave room for sockets within macOS's approximately 104-byte ceiling.
    /// Drop removes only the returned canonical tree.
    /// Entropy, permission-setting or canonicalization failures panic immediately.
    fn new() -> Scratch {
        for _ in 0..16 {
            let random = bridge_adapters::os::random_bytes().unwrap();
            let suffix: String = random[..6].iter().map(|b| format!("{b:02x}")).collect();
            let dir = std::env::temp_dir().join(format!("bio{suffix}"));
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
        producer_v1: None,
    };
    let core = start_with_carriers(
        Config {
            database: dir.join("bridge.db"),
            socket: socket.clone(),
            limits: serde_json::from_value(json!({"max_admitted_events": 1000})).unwrap(),
            universal_limits: Default::default(),
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
                    producer_v1: None,
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

/// Checks real CLI totals, audited transfers, honest sample coverage and
/// durable page fairness beyond 200 terminal reports across insertion,
/// closure and process restart; owns and cleans its real core fixture.
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
    // All first 200 already have terminal report outcomes. The CLI must
    // persist its page cursor and reach 201 on the next invocation without
    // touching Telegram or repeating those records.
    let first_page = client
        .incidents_page(OPERATOR, true, Some(200), 0, None)
        .unwrap();
    let ledger_path = lab.scratch.0.join("notify-ledger.json");
    let mut ledger = bridge_interfaces::notify::Ledger {
        backend: lab.socket.display().to_string(),
        ..bridge_interfaces::notify::Ledger::default()
    };
    for incident in &first_page.incidents {
        ledger.entries.insert(
            incident.incident_seq,
            bridge_interfaces::notify::Entry {
                identity: bridge_interfaces::notify::incident_identity(incident),
                state: if incident.incident_seq % 3 == 0 {
                    bridge_interfaces::notify::NoteState::Sending
                } else if incident.incident_seq % 3 == 1 {
                    bridge_interfaces::notify::NoteState::ProviderAccepted
                } else {
                    bridge_interfaces::notify::NoteState::PossibleSend
                },
                attempts: 1,
                updated_ms: 1,
                detail: "prior report".into(),
                not_before_ms: None,
            },
        );
    }
    ledger.save(&ledger_path).unwrap();
    let notify_config = lab.scratch.0.join("notify.toml");
    let token_file = lab.scratch.0.join("notify.token");
    private(&token_file, OPERATOR);
    private(
        &notify_config,
        &format!(
            "core_socket = \"{}\"\n[operator]\ntoken_file = \"{}\"\n[notify]\nledger = \"{}\"\n",
            lab.socket.display(),
            token_file.display(),
            ledger_path.display()
        ),
    );
    let (code, page1, stderr) = cli(&["notify", notify_config.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(page1["coverage"]["rows"], 200);
    assert_eq!(page1["coverage"]["scan_complete"], false);
    assert!(
        page1["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|line| line["requested_now"] == false)
    );
    // Insert beyond the captured high-water and close a previously reported
    // row between passes; it is positively pruned on the next full scan.
    publish_latest(&mut client, "s201");
    client
        .transfer_lineage(OPERATOR, &scope("s201"), "producer-b", "new row")
        .unwrap();
    client
        .dispose(OPERATOR, "producer-a", "a-s000", "closed row")
        .unwrap();
    let (code, page2, stderr) = cli(&["notify", notify_config.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        page2["incidents"][0]["incident_seq"], 201,
        "backlog row must be reached"
    );
    assert_eq!(
        page2["coverage"]["rows"], 1,
        "new insertion belongs to next high-water scan"
    );
    assert_eq!(page2["coverage"]["scan_complete"], true);
    let loaded = bridge_interfaces::notify::Ledger::load(&ledger_path).unwrap();
    assert!(loaded.entries.contains_key(&201));
    assert!(!loaded.entries.contains_key(&202));
    assert!(
        loaded.entries.contains_key(&1),
        "absence from this page cannot prune a report"
    );
    assert_eq!((loaded.after_seq, loaded.through_seq), (0, None));
    let (code, page3, stderr) = cli(&["notify", notify_config.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(page3["coverage"]["through_seq"], 202);
    assert!(
        !bridge_interfaces::notify::Ledger::load(&ledger_path)
            .unwrap()
            .entries
            .contains_key(&1),
        "matching authoritative closed row prunes even after a scan reset"
    );
    let (code, page4, stderr) = cli(&["notify", notify_config.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        page4["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line["incident_seq"] == 202)
    );
    let loaded = bridge_interfaces::notify::Ledger::load(&ledger_path).unwrap();
    assert!(loaded.entries.contains_key(&202));
    assert_eq!(
        loaded.entries[&2].state,
        bridge_interfaces::notify::NoteState::PossibleSend
    );
    assert_eq!(
        loaded.entries[&3].state,
        bridge_interfaces::notify::NoteState::PossibleSend
    );
    assert_eq!(
        loaded.entries[&4].state,
        bridge_interfaces::notify::NoteState::ProviderAccepted
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

/// One synthetic open incident (`seq`) as the wire shape of a core listing.
fn incident_in(seq: u64, state: &str) -> bridge_client::IncidentView {
    serde_json::from_value(json!({
        "incident_seq": seq, "publisher": "p", "event_id": format!("e{seq}"),
        "attempt_seq": 1, "kind": "unknown_handoff", "state": state, "reason": "lost reply",
        "created_ms": 1, "updated_ms": 1, "age_ms": 5000, "next_check_ms": null,
        "review_deadline_ms": null, "responsible": "p/operator",
        "blocked_dependents": [], "duplicate_risk": false, "resolution": null
    }))
    .unwrap()
}

/// One synthetic open incident (`seq`).
fn open_incident(seq: u64) -> bridge_client::IncidentView {
    incident_in(seq, "open")
}

/// Checks `bridge notify` prunes a ledger tombstone only on the core's closed row of the same incident, never because a capped listing (whose count matches it) does not show it.
#[test]
fn notify_prunes_only_on_a_closed_row_of_the_same_incident() {
    use bridge_core::service::Response;
    use bridge_interfaces::notify::{Entry, Ledger, NoteState};
    let scratch = Scratch::new();
    let socket = scratch.0.join("capped.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // A faithful partial page contains open 1 and positively closed 98;
    // open 99 is beyond this page's cursor. Its accepted/possible report
    // must survive absence while the matching closed identity is pruned.
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let Ok((stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut stream = stream;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let op: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                let answer = match op["op"].as_str() {
                    Some("incidents_page") => Response::IncidentsPage {
                        page: bridge_client::IncidentPage {
                            incidents: vec![open_incident(1), incident_in(98, "disposed")],
                            through_seq: 99,
                            next_after_seq: Some(98),
                        },
                    },
                    Some("incidents") if op["include_closed"] == true => Response::Incidents {
                        incidents: vec![open_incident(1), incident_in(98, "disposed")],
                    },
                    Some("incidents") => Response::Incidents {
                        incidents: vec![open_incident(1)],
                    },
                    _ => Response::Counts {
                        counts: serde_json::from_value(json!({
                            "unhanded": 0, "reserved": 0, "invoking": 0, "held": 0,
                            "review": 1, "accepted": 0, "hook_submitted": 0, "refused": 0,
                            "disposed": 0, "open_incidents": 1
                        }))
                        .unwrap(),
                    },
                };
                use std::io::Write;
                let _ = writeln!(stream, "{}", serde_json::to_string(&answer).unwrap());
                line.clear();
            }
        }
    });
    let ledger_path = scratch.0.join("ledger.json");
    let mut ledger = Ledger {
        backend: socket.display().to_string(),
        ..Ledger::default()
    };
    for (seq, event) in [(99, "e99"), (98, "e98")] {
        ledger.entries.insert(
            seq,
            Entry {
                identity: format!("p/{event}/unknown_handoff/1"),
                state: NoteState::PossibleSend,
                attempts: 1,
                updated_ms: 1,
                detail: "an earlier run may have sent this".into(),
                not_before_ms: None,
            },
        );
    }
    ledger.save(&ledger_path).unwrap();
    let token_file = scratch.0.join("n.token");
    private(&token_file, OPERATOR);
    let config = scratch.0.join("n.toml");
    private(
        &config,
        &format!(
            "core_socket = \"{}\"\n[operator]\ntoken_file = \"{}\"\n[notify]\nledger = \"{}\"\n",
            socket.display(),
            token_file.display(),
            ledger_path.display()
        ),
    );
    let (code, _, stderr) = cli(&["notify", config.to_str().unwrap()]);
    assert_eq!(code, 0, "{stderr}");
    let ledger = Ledger::load(&ledger_path).unwrap();
    assert!(
        ledger.entries.contains_key(&99),
        "a displaced open incident's tombstone was pruned by absence: {ledger:?}"
    );
    assert!(
        !ledger.entries.contains_key(&98),
        "the core's closed row of the same incident did not prune it: {ledger:?}"
    );
    drop(server);
}

/// Checks unknown flags and surplus or missing positionals exit 3 before any connection while valid forms still connect.
#[test]
fn unknown_flags_and_wrong_positions_exit_3_before_connecting() {
    let scratch = Scratch::new();
    let socket = scratch.0.join("recording.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = interfaces(&scratch.0, "recording", &socket, OPERATOR);
    let config = config.to_str().unwrap();
    let address = recipient().to_canonical_string();
    let zeros = "0".repeat(64);
    let invalid: Vec<Vec<&str>> = vec![
        vec!["operator", config, "incidents", "--limt", "5"],
        vec!["operator", config, "incidents", "extra"],
        vec!["operator", config, "counts", "--limit", "5"],
        vec!["operator", config, "holds", "--all"],
        vec!["operator", config, "shutdown", "extra"],
        vec![
            "operator", config, "pause", &address, "junk", "--reason", "r",
        ],
        vec![
            "operator", config, "pause", &address, "--reason", "r", "--note", "n",
        ],
        vec!["operator", config, "resume", &address, "--reason", "r"],
        vec!["operator", config, "dispose", "p", "e", "x", "--note", "n"],
        vec![
            "operator",
            config,
            "dispose",
            "p",
            "e",
            "--note",
            "n",
            "--accept-duplicate-risk",
        ],
        vec![
            "operator", config, "retry", "p", "e", "--note", "n", "--detail", "d",
        ],
        vec![
            "operator",
            config,
            "evidence",
            "p",
            "e",
            "1",
            "native_accepted",
            "x",
            "--detail",
            "d",
        ],
        vec!["notify", config, "extra"],
        vec!["notify", config, "--all"],
        vec!["version", "extra"],
        vec!["doctor", "extra"],
        vec!["doctor", "--hom", "/x"],
        vec!["rollback", "--home", "/x", "extra"],
        vec![
            "service", "stop", "core", "--home", "/x", "--state", "/y", "--config", "/z",
        ],
        vec!["verify", "/x", "--bundle", "/y"],
        vec!["package", "--from", "/x", "--out", "/y", "--bogus", "1"],
        vec![
            "self-install",
            "--bundle",
            "/x",
            "--home",
            "/h",
            "--bin-dir",
            "/b",
            "--sums-sha256",
            zeros.as_str(),
            "--bogus",
            "1",
        ],
    ];
    for args in &invalid {
        let (code, _, stderr) = cli(args);
        assert_eq!(code, 3, "{args:?}: {stderr}");
    }
    let mut accepted = 0;
    while listener.accept().is_ok() {
        accepted += 1;
    }
    assert_eq!(accepted, 0, "an invalid invocation opened a connection");
    // Valid forms keep their flags: they pass argument validation and reach
    // the (unreachable) core, failing as an operation (2), not as usage (3).
    let missing = scratch.0.join("absent.sock");
    let absent = interfaces(&scratch.0, "absent", &missing, OPERATOR);
    let absent = absent.to_str().unwrap();
    for args in [
        vec!["operator", absent, "incidents", "--all", "--limit", "5"],
        vec!["operator", absent, "holds", "--limit", "5"],
        vec!["operator", absent, "counts"],
        vec!["operator", absent, "pause", &address, "--reason", "r"],
        vec!["operator", absent, "resume", &address],
        vec!["operator", absent, "shutdown"],
        vec![
            "operator",
            absent,
            "retry",
            "p",
            "e",
            "--note",
            "n",
            "--accept-duplicate-risk",
        ],
        vec!["operator", absent, "dispose", "p", "e", "--note", "n"],
        vec!["operator", absent, "waive", "p", "e", "--note", "n"],
        vec![
            "operator",
            absent,
            "evidence",
            "p",
            "e",
            "1",
            "native_accepted",
            "--detail",
            "d",
        ],
    ] {
        let (code, _, stderr) = cli(&args);
        assert_eq!(code, 2, "{args:?}: {stderr}");
    }
}

/// Checks the status of a real core event keeps its earlier possible hand-off through a duplicate-risk manual retry whose later attempt was known-unsent, before and after the audited disposition.
#[test]
fn a_later_known_unsent_attempt_never_erases_an_earlier_unknown_hand_off() {
    use bridge_core::dispatch::{
        Attestation, Capabilities, DispatchTiming, EffectiveMode, Lifecycle, Outcome, Selection,
    };
    use bridge_interfaces::root::status_view;
    let lab = lab();
    let operator = lab.operator_config.to_str().unwrap();
    let mut client = BridgeClient::connect(&lab.socket).unwrap();
    let publish = |client: &mut BridgeClient, id: &str| {
        let body = PublishRequest::new(
            EventId::new(id).unwrap(),
            recipient(),
            Kind::new("note").unwrap(),
            Mode::Message,
            Policy::KeepAll,
            Payload::new("body").unwrap(),
        )
        .into_body()
        .unwrap();
        client.publish(PRODUCER_A, &body).unwrap();
    };
    let view = |client: &mut BridgeClient, id: &str| -> Value {
        let (_, delivery) = client.status(PRODUCER_A, id).unwrap();
        status_view(delivery.as_ref())
    };
    publish(&mut client, "retried");
    publish(&mut client, "never-handed");
    // A real event nothing has touched is truthfully not handed.
    let untouched = view(&mut client, "never-handed");
    assert_eq!(untouched["native"], "not_handed", "{untouched}");
    assert!(untouched["uncertainty"].is_null(), "{untouched}");

    let core = lab.core.as_ref().unwrap();
    // One dispatch of the event "retried": hand it off and record `outcome`.
    let attempt = |outcome: Outcome, offset: u64| {
        core.with_storage(|storage| {
            let now = bridge_core::service::current_unix_millis() + offset;
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
                .record_outcome(&attempt.fence, outcome, now + 2)
                .unwrap();
        });
    };
    // Attempt A: a possible hand-off with an unknown effect (Review).
    attempt(
        Outcome::OutcomeUnknown {
            reason: "lost reply".into(),
        },
        0,
    );
    let review = view(&mut client, "retried");
    assert_eq!(review["native"], "unknown", "{review}");
    assert_eq!(review["uncertainty"]["manual_resolution_required"], true);
    // The operator explicitly accepts the duplicate risk and retries.
    let (code, _, stderr) = cli(&[
        "operator",
        operator,
        "retry",
        "producer-a",
        "retried",
        "--note",
        "owner accepts a duplicate",
        "--accept-duplicate-risk",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let authorized = view(&mut client, "retried");
    assert_eq!(authorized["delivery"]["state"], "unhanded", "{authorized}");
    assert_eq!(
        authorized["native"], "unknown",
        "A's effect survives the retry: {authorized}"
    );
    assert_eq!(authorized["uncertainty"]["automatic_resend"], false);
    // Attempt B is positively known-unsent; A's possible effect still stands.
    attempt(
        Outcome::KnownUnsent {
            evidence: "carrier proved nothing was written".into(),
        },
        60_000,
    );
    let after_b = view(&mut client, "retried");
    assert_eq!(after_b["native"], "unknown", "{after_b}");
    assert!(!after_b["uncertainty"].is_null(), "{after_b}");
    // The audited disposition closes the workflow without erasing it.
    let (code, _, stderr) = cli(&[
        "operator",
        operator,
        "dispose",
        "producer-a",
        "retried",
        "--note",
        "closing",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let disposed = view(&mut client, "retried");
    assert_eq!(disposed["delivery"]["state"], "disposed", "{disposed}");
    assert_eq!(disposed["native"], "unknown", "{disposed}");
    assert_eq!(disposed["uncertainty"]["disposed"], true, "{disposed}");
    assert_eq!(disposed["uncertainty"]["automatic_resend"], false);
    // Disposing the untouched event leaves no hand-off record to read, which
    // cannot be told apart from a closed legacy possible hand-off: unknown.
    let (code, _, stderr) = cli(&[
        "operator",
        operator,
        "dispose",
        "producer-a",
        "never-handed",
        "--note",
        "cancel",
    ]);
    assert_eq!(code, 0, "{stderr}");
    let cancelled = view(&mut client, "never-handed");
    assert_eq!(cancelled["delivery"]["state"], "disposed", "{cancelled}");
    assert_eq!(cancelled["native"], "unknown", "{cancelled}");
}

/// Hands the oldest pending event of the synthetic recipient to a stand-in
/// carrier on the lab's real core at `now + offset_ms` and records `outcome`.
fn dispatch_once(lab: &Lab, outcome: bridge_core::dispatch::Outcome, offset_ms: u64) {
    use bridge_core::dispatch::{
        Attestation, Capabilities, DispatchTiming, EffectiveMode, Lifecycle, Selection,
    };
    lab.core.as_ref().unwrap().with_storage(|storage| {
        let now = bridge_core::service::current_unix_millis() + offset_ms;
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
            panic!("nothing reserved at +{offset_ms} ms");
        };
        storage
            .mark_invoking(&attempt.fence, &attestation, now + 1)
            .unwrap();
        storage
            .record_outcome(&attempt.fence, outcome, now + 2)
            .unwrap();
    });
}

/// Checks a real core event refused after an unknown attempt and an audited duplicate-risk retry (permanent refusal, or retries exhausted) never reports `refused` alone, while a plain refusal still does.
#[test]
fn a_refusal_after_a_duplicate_risk_retry_never_hides_the_earlier_unknown_hand_off() {
    use bridge_core::dispatch::Outcome;
    use bridge_interfaces::root::status_view;
    let status = |lab: &Lab| -> Value {
        let mut client = BridgeClient::connect(&lab.socket).unwrap();
        let (_, delivery) = client.status(PRODUCER_A, "chain").unwrap();
        status_view(delivery.as_ref())
    };
    let publish = |lab: &Lab| {
        let body = PublishRequest::new(
            EventId::new("chain").unwrap(),
            recipient(),
            Kind::new("note").unwrap(),
            Mode::Message,
            Policy::KeepAll,
            Payload::new("body").unwrap(),
        )
        .into_body()
        .unwrap();
        BridgeClient::connect(&lab.socket)
            .unwrap()
            .publish(PRODUCER_A, &body)
            .unwrap();
    };
    // Control: a plain permanent refusal is `refused`.
    let plain = lab();
    publish(&plain);
    dispatch_once(
        &plain,
        Outcome::PermanentRefusal {
            reason: "carrier refused".into(),
        },
        0,
    );
    let view = status(&plain);
    assert_eq!(view["delivery"]["state"], "refused", "{view}");
    assert_eq!(view["native"], "refused", "{view}");
    assert!(
        !view["uncertainty"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("earlier attempt may also"),
        "{view}"
    );
    for scenario in ["permanent_refusal", "retries_exhausted"] {
        let lab = lab();
        let operator = lab.operator_config.to_str().unwrap().to_string();
        publish(&lab);
        dispatch_once(
            &lab,
            Outcome::OutcomeUnknown {
                reason: "lost reply".into(),
            },
            0,
        );
        let (code, _, stderr) = cli(&[
            "operator",
            &operator,
            "retry",
            "producer-a",
            "chain",
            "--note",
            "owner accepts a duplicate",
            "--accept-duplicate-risk",
        ]);
        assert_eq!(code, 0, "{scenario}: {stderr}");
        if scenario == "permanent_refusal" {
            dispatch_once(
                &lab,
                Outcome::PermanentRefusal {
                    reason: "carrier refused".into(),
                },
                10_000_000_000,
            );
        } else {
            for round in 1..=5u64 {
                dispatch_once(
                    &lab,
                    Outcome::KnownUnsent {
                        evidence: "carrier proved nothing was written".into(),
                    },
                    round * 10_000_000_000,
                );
            }
        }
        let view = status(&lab);
        assert_eq!(view["delivery"]["state"], "refused", "{scenario}: {view}");
        assert_eq!(view["uncertainty"]["incident_kind"], scenario, "{view}");
        assert_eq!(view["native"], "unknown", "{scenario}: {view}");
        let reason = view["uncertainty"]["reason"].as_str().unwrap();
        assert!(reason.contains("earlier attempt may also"), "{view}");
        assert_eq!(view["uncertainty"]["automatic_resend"], false, "{view}");
        let (code, incidents, stderr) = cli(&["operator", &operator, "incidents"]);
        assert_eq!(code, 0, "{stderr}");
        let next = incidents["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|incident| incident["kind"] == scenario)
            .unwrap()["next_action"]
            .as_str()
            .unwrap();
        assert!(next.contains("Refused events cannot be retried"), "{next}");
        assert!(next.contains("dispose"), "{next}");
        let (code, _, stderr) = cli(&[
            "operator",
            &operator,
            "dispose",
            "producer-a",
            "chain",
            "--note",
            "follow supported refusal guidance",
        ]);
        assert_eq!(code, 0, "{scenario}: {stderr}");
        let disposed = status(&lab);
        assert_eq!(disposed["delivery"]["state"], "disposed");
        assert_eq!(
            disposed["native"], "unknown",
            "disposition does not recall the earlier possible effect"
        );
    }
}

/// Protected exact retention reads expose expiry, tombstones and scoped
/// watermarks without payloads or mutation; possible/native effects retain
/// bytes through actual compaction, and publisher credentials refuse.
#[test]
fn operator_retention_reports_storage_without_recall_or_payload_disclosure() {
    let lab = lab();
    let mut client = BridgeClient::connect(&lab.socket).unwrap();
    let latest = |id: &str, revision| {
        PublishRequest::new(
            EventId::new(id).unwrap(),
            recipient(),
            Kind::new("view.snapshot").unwrap(),
            Mode::Message,
            Policy::Latest {
                stream: StreamId::new("retention").unwrap(),
                revision,
            },
            Payload::new("private original payload").unwrap(),
        )
        .into_body()
        .unwrap()
    };
    let old = latest("old", 1);
    let receipt = client.publish(PRODUCER_A, &old).unwrap();
    client.publish(PRODUCER_A, &latest("uncertain", 2)).unwrap();
    dispatch_once(
        &lab,
        bridge_core::dispatch::Outcome::OutcomeUnknown {
            reason: "lost answer".into(),
        },
        0,
    );
    let accepted = PublishRequest::new(
        EventId::new("accepted").unwrap(),
        recipient(),
        Kind::new("note").unwrap(),
        Mode::Message,
        Policy::KeepAll,
        Payload::new("private accepted payload").unwrap(),
    )
    .into_body()
    .unwrap();
    client.publish(PRODUCER_A, &accepted).unwrap();
    dispatch_once(
        &lab,
        bridge_core::dispatch::Outcome::NativeAccepted {
            evidence: "faithful carrier acceptance".into(),
        },
        0,
    );
    let expiry = bridge_core::service::current_unix_millis() + 60_000;
    let expired = PublishRequest::new(
        EventId::new("expired").unwrap(),
        recipient(),
        Kind::new("note").unwrap(),
        Mode::Message,
        Policy::KeepAll,
        Payload::new("private expiring payload").unwrap(),
    )
    .with_expires_at(bridge_client::ExpiresAt::from_unix_millis(expiry).unwrap())
    .into_body()
    .unwrap();
    client.publish(PRODUCER_A, &expired).unwrap();
    lab.core
        .as_ref()
        .unwrap()
        .with_storage(|storage| storage.expire_due(expiry + 1))
        .unwrap();
    let config = lab.operator_config.to_str().unwrap();
    let (code, old_view, stderr) = cli(&["operator", config, "retention", "producer-a", "old"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(old_view["retention"]["receipt"]["state"], "superseded");
    assert_eq!(old_view["retention"]["latest_watermark"], 2);
    assert_eq!(old_view["retention"]["gc_eligible"], true);
    assert_eq!(old_view["retention"]["payload_compacted"], false);
    assert!(old_view["retention"]["envelope_bytes"].as_u64().unwrap() > 0);
    assert!(!old_view.to_string().contains("private original payload"));
    assert!(
        old_view["note"]
            .as_str()
            .unwrap()
            .contains("not native recall")
    );
    let (code, missing, stderr) = cli(&["operator", config, "retention", "producer-a", "missing"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(missing["retention"].is_null());
    let (code, expired_view, stderr) =
        cli(&["operator", config, "retention", "producer-a", "expired"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(expired_view["retention"]["expires_at_ms"], expiry);
    assert_eq!(expired_view["retention"]["receipt"]["state"], "expired");
    assert_eq!(expired_view["retention"]["gc_eligible"], true);
    assert_eq!(
        client.publish(PRODUCER_A, &old).unwrap().envelope_hash,
        receipt.envelope_hash,
        "reads preserve replay identity"
    );
    lab.core
        .as_ref()
        .unwrap()
        .with_storage(|storage| storage.compact_payloads(0))
        .unwrap();
    for id in ["old", "expired"] {
        let (code, compacted, stderr) = cli(&["operator", config, "retention", "producer-a", id]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(compacted["retention"]["payload_compacted"], true);
        assert_eq!(compacted["retention"]["envelope_bytes"], 0);
        assert_eq!(compacted["retention"]["gc_eligible"], false);
        if id == "old" {
            assert_eq!(compacted["retention"]["latest_watermark"], 2);
        }
    }
    for id in ["uncertain", "accepted"] {
        let (code, protected, stderr) = cli(&["operator", config, "retention", "producer-a", id]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(protected["retention"]["payload_compacted"], false);
        assert_eq!(protected["retention"]["gc_eligible"], false);
        assert!(protected["retention"]["envelope_bytes"].as_u64().unwrap() > 0);
        assert!(!protected.to_string().contains("private accepted payload"));
    }
    let publisher_config = interfaces(
        &lab.scratch.0,
        "retention-publisher",
        &lab.socket,
        PRODUCER_A,
    );
    let (code, _, stderr) = cli(&[
        "operator",
        publisher_config.to_str().unwrap(),
        "retention",
        "producer-a",
        "old",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("forbidden"));
    assert_eq!(
        client.publish(PRODUCER_A, &old).unwrap().envelope_hash,
        receipt.envelope_hash,
        "compacted tombstone retains original replay"
    );
}
