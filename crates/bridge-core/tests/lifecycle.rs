//! Integration checks for the service lifecycle and the operator realm:
//! socket ownership, bounded connections and timeouts, shutdown fencing,
//! OS-signal shutdown, credential hygiene, operator recovery over the wire
//! and carrier-driven delivery.
//!
//! All state is isolated: fresh temporary directories, private short-lived
//! sockets, a daemon binary spawned on its own socket. No real session,
//! installed application or credential is touched.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bridge_client::{BridgeClient, EvidenceTier};
use bridge_core::dispatch::{
    AttemptRecord, AttemptState, Attestation, Capabilities, DispatchCarrier, DispatchTiming,
    EffectiveMode, Lifecycle, Outcome, Selection,
};
use bridge_core::service::{self, Config, GrantConfig, PublishBody, Request, Response, Token};
use bridge_core::{Harness, Limits, Mode, NativeAddress, Policy, Storage};
use common::{ScriptedCarrier, TempDir, attest, short_socket, wait_listening};

/// Fixture publisher token.
const RUN_TOKEN: &str = "life-run-publisher-token-0001";
/// Fixture second publisher token.
const IDE_TOKEN: &str = "life-ide-publisher-token-0002";
/// Fixture operator token.
const OPS_TOKEN: &str = "life-operator-token-000003";

/// The recipient every grant may use.
fn recipient() -> NativeAddress {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7").unwrap()
}

/// A config with two publisher grants and one operator grant.
fn config(dir: &TempDir, tag: &str) -> Config {
    let allowed = vec![recipient().to_canonical_string()];
    Config {
        universal_limits: bridge_core::UniversalLimits::default(),
        database: dir.path("bridge.db"),
        socket: short_socket(tag),
        limits: Limits::new(1_000),
        grants: vec![
            GrantConfig {
                producer_v1: None,
                token: RUN_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: allowed.clone(),
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".into(), "auto".into(), "inject".into()],
                policies: vec!["keep_all".into(), "latest".into(), "batch".into()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: IDE_TOKEN.to_string(),
                publisher: "agent-ide".to_string(),
                recipients: allowed,
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".into()],
                policies: vec!["keep_all".into()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: OPS_TOKEN.to_string(),
                publisher: "bridge-ops".to_string(),
                recipients: vec![],
                kinds: vec![],
                modes: vec![],
                policies: vec![],
                admin: true,
            },
        ],
    }
}

/// A valid publish body.
fn body(event: &str) -> PublishBody {
    PublishBody {
        event_id: event.to_string(),
        recipient: recipient(),
        kind: "worker.completed".to_string(),
        mode: Mode::Message,
        policy: Policy::KeepAll,
        payload: "synthetic worker result".to_string(),
        metadata: Default::default(),
        expires_at: None,
    }
}

/// Starts a service and waits until it listens.
fn started(config: Config) -> service::Running {
    let running = service::start(config).unwrap();
    assert!(wait_listening(
        running.socket_path(),
        Duration::from_secs(5)
    ));
    running
}

/// Sends one raw line and reads one response line.
fn raw(socket: &Path, line: &str) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

/// Drives one message attempt to the given outcome through the running
/// service's own store, as an adapter embedded in the process would.
fn drive_to(running: &service::Running, event: &str, outcome: Outcome, now: u64) -> AttemptRecord {
    running.with_storage(|storage| {
        let attestation = attest(&recipient(), Lifecycle::Inactive, 1);
        let Selection::Attempt(reserved) = storage
            .reserve_next(
                &attestation,
                EffectiveMode::Message,
                now,
                &DispatchTiming::default(),
            )
            .unwrap()
        else {
            panic!("nothing to reserve for {event}");
        };
        assert_eq!(reserved.members[0].event_id, event);
        storage
            .mark_invoking(&reserved.fence, &attestation, now + 1)
            .unwrap();
        storage
            .record_outcome(&reserved.fence, outcome, now + 2)
            .unwrap()
    })
}

/// The operator realm is disjoint from publisher grants and serves the
/// core's own incident state over the wire: publishers cannot read or
/// mutate recovery, and operators see real incidents only.
#[test]
fn operator_realm_is_disjoint_and_serves_the_cores_own_incident_state() {
    let dir = TempDir::new("life-operator");
    let running = started(config(&dir, "op"));
    let socket = running.socket_path().to_path_buf();
    let mut client = BridgeClient::connect(&socket).unwrap();
    client.publish(RUN_TOKEN, &body("evt-u")).unwrap();
    client.publish(RUN_TOKEN, &body("evt-d")).unwrap();
    drive_to(
        &running,
        "evt-u",
        Outcome::OutcomeUnknown {
            reason: "helper exited without a result".into(),
        },
        service::current_unix_millis(),
    );

    // Realms: a publisher cannot reach operator operations; an operator
    // cannot publish or read publisher status.
    assert_eq!(
        client.incidents(RUN_TOKEN, false, None).unwrap_err().class,
        "forbidden"
    );
    assert_eq!(
        client.holds(RUN_TOKEN, None).unwrap_err().class,
        "forbidden"
    );
    assert_eq!(client.shutdown(RUN_TOKEN).unwrap_err().class, "forbidden");
    assert_eq!(
        client.publish(OPS_TOKEN, &body("evt-x")).unwrap_err().class,
        "forbidden"
    );
    assert_eq!(
        client.status(OPS_TOKEN, "evt-u").unwrap_err().class,
        "forbidden"
    );
    assert_eq!(
        client
            .authorize_retry(RUN_TOKEN, "agent-run", "evt-u", "self service")
            .unwrap_err()
            .class,
        "forbidden"
    );

    // The operator surface is the core's own state: reason, age, deadline,
    // responsible source and blocked dependents.
    let incidents = client.incidents(OPS_TOKEN, false, Some(10)).unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, "unknown_handoff");
    assert_eq!(incidents[0].publisher, "agent-run");
    assert!(incidents[0].reason.contains("helper exited"));
    assert!(incidents[0].review_deadline_ms.is_some());
    assert_eq!(incidents[0].responsible, "source:agent-run; operator");

    // The publisher sees its own distinct tiers, never a delivered flag.
    let (receipt, delivery) = client.status(RUN_TOKEN, "evt-u").unwrap();
    assert!(receipt.is_some());
    let delivery = delivery.unwrap();
    assert_eq!(
        delivery.attempt_state, "outcome_unknown",
        "legacy field kept"
    );
    assert_eq!(delivery.effective_mode, "message", "legacy field kept");
    assert!(delivery.incident.is_some());
    assert_eq!(delivery.tiers.len(), 1);
    // Another publisher sees nothing of it.
    let (foreign, none) = client.status(IDE_TOKEN, "evt-u").unwrap();
    assert!(foreign.is_none() && none.is_none());

    // Audited same-event recovery: duplicate risk recorded, no new shadow
    // state, and a second authorization is refused.
    client
        .authorize_retry(
            OPS_TOKEN,
            "agent-run",
            "evt-u",
            "operator reviewed the host log",
        )
        .unwrap();
    assert_eq!(
        client
            .authorize_retry(OPS_TOKEN, "agent-run", "evt-u", "again")
            .unwrap_err()
            .class,
        "fence"
    );
    let closed = client.incidents(OPS_TOKEN, true, None).unwrap();
    assert!(closed[0].duplicate_risk);
    assert_eq!(
        client
            .status(RUN_TOKEN, "evt-u")
            .unwrap()
            .1
            .unwrap()
            .delivery,
        bridge_core::recovery::DeliveryState::Unhanded
    );

    // Disposition and positive late evidence over the wire.
    let attempt = drive_to(
        &running,
        "evt-u",
        Outcome::OutcomeUnknown {
            reason: "lost acknowledgement again".into(),
        },
        service::current_unix_millis(),
    );
    client
        .record_evidence(
            OPS_TOKEN,
            "agent-run",
            "evt-u",
            attempt.fence.attempt_seq,
            EvidenceTier::NativeAccepted,
            "queue entry confirmed by the operator",
        )
        .unwrap();
    assert!(client.incidents(OPS_TOKEN, false, None).unwrap().is_empty());
    client
        .dispose(OPS_TOKEN, "agent-run", "evt-d", "producer canceled it")
        .unwrap();

    // Pause and resume are audited operator decisions.
    client
        .pause(OPS_TOKEN, &recipient(), "owner is at the keyboard")
        .unwrap();
    client.resume(OPS_TOKEN, &recipient()).unwrap();
    running.shutdown();
    running.join();

    let connection = rusqlite::Connection::open(dir.path("bridge.db")).unwrap();
    let mut statement = connection
        .prepare("SELECT actor, action FROM audit ORDER BY audit_seq")
        .unwrap();
    let rows: Vec<(String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let actions: Vec<&str> = rows.iter().map(|(_, action)| action.as_str()).collect();
    assert_eq!(actions, ["manual_retry", "dispose", "pause", "resume"]);
    assert!(rows.iter().all(|(actor, _)| actor == "bridge-ops"));
}

/// A carrier shared with the test so sends can be observed after it moved
/// into the service.
struct Shared(Arc<Mutex<ScriptedCarrier>>);

impl DispatchCarrier for Shared {
    /// Returns this fixture's attestation for the recipient.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        self.0.lock().unwrap().attest(recipient)
    }

    /// Applies this fixture's scripted outcome to the frozen attempt.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        self.0.lock().unwrap().send(attempt)
    }
}

/// Registered synthetic carriers deliver over the message path and the
/// durable pause policy is respected end to end through the service.
#[test]
fn registered_carriers_deliver_over_the_message_path_and_respect_pause() {
    let dir = TempDir::new("life-carrier");
    let script = Arc::new(Mutex::new(ScriptedCarrier::new(
        Lifecycle::Inactive,
        ScriptedCarrier::accepted(),
    )));
    let running = service::start_with_carriers(
        config(&dir, "carrier"),
        vec![Box::new(Shared(Arc::clone(&script)))],
    )
    .unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));
    let mut client = BridgeClient::connect(&socket).unwrap();

    // The operator pauses first: nothing is sent, and the hold is visible.
    client
        .pause(OPS_TOKEN, &recipient(), "owner is working")
        .unwrap();
    client.publish(RUN_TOKEN, &body("evt-paused")).unwrap();
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        script.lock().unwrap().sends.is_empty(),
        "pause blocks the message path"
    );
    let holds = client.holds(OPS_TOKEN, None).unwrap();
    assert_eq!(holds.len(), 1);
    assert!(holds[0].reason.contains("no-wake"), "{}", holds[0].reason);

    // Resuming lets the maintenance loop deliver it exactly once.
    client.resume(OPS_TOKEN, &recipient()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let (_, delivery) = client.status(RUN_TOKEN, "evt-paused").unwrap();
        if delivery.is_some_and(|d| d.attempt_state == "native_accepted") {
            break;
        }
        assert!(Instant::now() < deadline, "the carrier never delivered");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(1_500));
    let sends = script.lock().unwrap().sends.clone();
    assert_eq!(sends.len(), 1, "exactly one hand-off");
    assert_eq!(sends[0].state, AttemptState::Invoking);
    assert!(
        sends[0]
            .manifest
            .contains("<agent-run event=\"evt-paused\"")
    );
    assert_eq!(sends[0].actor, "thread-7");

    running.shutdown();
    running.join();
}

/// A carrier whose attestation panics for the first few calls.
struct Flaky {
    /// Remaining panicking attestations.
    panics_left: u32,
    /// The well-behaved carrier used afterwards.
    inner: ScriptedCarrier,
}

impl DispatchCarrier for Flaky {
    /// Returns this fixture's attestation for the recipient.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        if self.panics_left > 0 {
            self.panics_left -= 1;
            panic!("scripted attestation panic");
        }
        self.inner.attest(recipient)
    }

    /// Applies this fixture's scripted outcome to the frozen attempt.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        self.inner.send(attempt)
    }
}

/// A panicking carrier attestation is contained: the recovery loop
/// continues and the event stays retained.
#[test]
fn a_panicking_carrier_attestation_does_not_end_the_recovery_loop() {
    let dir = TempDir::new("life-panic");
    let running = service::start_with_carriers(
        config(&dir, "panic"),
        vec![Box::new(Flaky {
            panics_left: 2,
            inner: ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted()),
        })],
    )
    .unwrap();
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    client.publish(RUN_TOKEN, &body("evt-flaky")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (_, delivery) = client.status(RUN_TOKEN, "evt-flaky").unwrap();
        if delivery.is_some_and(|d| d.attempt_state == "native_accepted") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the loop must survive carrier panics and still deliver"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    running.shutdown();
    running.join();
}

/// A carrier whose hand-off blocks until the test releases it.
struct Hanging {
    /// Receives the release signal; the sender lives in the test.
    release: std::sync::mpsc::Receiver<()>,
}

impl DispatchCarrier for Hanging {
    /// Returns this fixture's attestation for the recipient.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        Ok(attest(recipient, Lifecycle::Inactive, 1))
    }

    /// Applies this fixture's scripted outcome (attempt ignored).
    fn send(&mut self, _attempt: &AttemptRecord) -> Outcome {
        let _ = self.release.recv();
        ScriptedCarrier::accepted()
    }
}

/// A carrier that never returns cannot make the stop unbounded; the
/// event stays retained for review.
#[test]
fn a_hanging_carrier_cannot_make_the_stop_unbounded_and_stays_retained() {
    let dir = TempDir::new("life-hang");
    let (release, wait) = std::sync::mpsc::channel();
    let running = service::start_with_carriers(
        config(&dir, "hang"),
        vec![Box::new(Hanging { release: wait })],
    )
    .unwrap();
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    client.publish(RUN_TOKEN, &body("evt-hang")).unwrap();
    // Wait until the hand-off is in progress (invoking is durable).
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let (_, delivery) = client.status(RUN_TOKEN, "evt-hang").unwrap();
        if delivery.is_some_and(|d| d.attempt_state == "invoking") {
            break;
        }
        assert!(Instant::now() < deadline, "the hand-off never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    running.shutdown();
    let started = Instant::now();
    running.join();
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "a stuck carrier must not make the stop unbounded"
    );
    // The possibly handed-off event is still invoking: retained, not lost
    // and not replayed.
    let connection = rusqlite::Connection::open(dir.path("bridge.db")).unwrap();
    let state: String = connection
        .query_row("SELECT state FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "invoking");
    drop(release); // lets the detached thread finish
}

/// A fake daemon answering every request with one fixed line.
fn fake_daemon(path: &Path, answer: Vec<u8>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = String::new();
            let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut request);
            let _ = stream.write_all(&answer);
        }
    })
}

/// Valid custody receipts acknowledge only the exact requested identity and bytes.
/// Own fake endpoints return real storage receipts; a matching receipt passes,
/// while unrelated publication or status receipts cannot release sender intent.
/// Client custody acknowledgements bind to the exact requested event
/// bytes: a wrong-event acknowledgement reports the mismatch, never a
/// false success.
#[test]
fn client_acknowledgements_are_bound_to_requested_event_bytes() {
    let request = body("requested-event");
    let expected = bridge_core::Envelope::new(
        bridge_core::PublisherId::new("agent-run").unwrap(),
        bridge_core::EventId::new(request.event_id.clone()).unwrap(),
        request.recipient.clone(),
        bridge_core::Kind::new(request.kind.clone()).unwrap(),
        request.mode,
        request.policy.clone(),
        bridge_core::Payload::new(request.payload.clone()).unwrap(),
        request.metadata.clone(),
        request.expires_at,
    )
    .unwrap();
    let mut other_id = expected.clone();
    other_id.event_id = bridge_core::EventId::new("other-event").unwrap();
    let mut other_bytes = expected.clone();
    other_bytes.payload = bridge_core::Payload::new("different immutable bytes").unwrap();
    for (tag, envelope, valid) in [
        ("matching-ack", expected, true),
        ("wrong-id-ack", other_id.clone(), false),
        ("wrong-bytes-ack", other_bytes, false),
    ] {
        let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
        let receipt = storage.publish(&envelope, 1).unwrap().receipt;
        let mut line = serde_json::to_vec(&Response::Published { receipt }).unwrap();
        line.push(b'\n');
        let socket = short_socket(tag);
        let server = fake_daemon(&socket, line);
        let result = BridgeClient::connect(&socket)
            .unwrap()
            .publish(RUN_TOKEN, &request);
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(result.is_ok(), valid, "{tag}: {result:?}");
    }
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    let receipt = storage.publish(&other_id, 1).unwrap().receipt;
    let mut line = serde_json::to_vec(&Response::Status {
        receipt: Some(receipt),
        delivery: None,
    })
    .unwrap();
    line.push(b'\n');
    let socket = short_socket("wrong-status-id");
    let server = fake_daemon(&socket, line);
    let result = BridgeClient::connect(&socket)
        .unwrap()
        .status(RUN_TOKEN, &request.event_id);
    server.join().unwrap();
    std::fs::remove_file(&socket).unwrap();
    assert!(
        result.is_err(),
        "Status for another event was accepted: {result:?}"
    );
}

/// The client distrusts invalid, oversized or malformed responses
/// instead of misreading them as success.
#[test]
fn the_client_distrusts_invalid_oversized_and_malformed_responses() {
    // An incident listing with a number no storage could have produced.
    let socket = short_socket("fake-range");
    let mut line = serde_json::to_vec(&serde_json::json!({"Incidents": {"incidents": [{
        "incident_seq": 1u64 << 63, "publisher": "agent-run", "event_id": "e",
        "attempt_seq": null, "kind": "unknown_handoff", "state": "open", "reason": "r",
        "created_ms": 1, "updated_ms": 1, "age_ms": 0, "next_check_ms": null,
        "review_deadline_ms": null, "responsible": "x", "blocked_dependents": [],
        "duplicate_risk": false, "resolution": null}]}}))
    .unwrap();
    line.push(b'\n');
    let server = fake_daemon(&socket, line);
    let mut client = BridgeClient::connect(&socket).unwrap();
    let error = client.incidents(OPS_TOKEN, false, None).unwrap_err();
    assert_eq!(error.class, "transport");
    assert!(
        error.detail.contains("invalid response"),
        "{}",
        error.detail
    );
    server.join().unwrap();
    let _ = std::fs::remove_file(&socket);

    // A receipt whose hash is not a hash.
    let socket = short_socket("fake-hash");
    let mut line = serde_json::to_vec(&serde_json::json!({"Published": {"receipt": {
        "publisher": "agent-run", "event_id": "e", "envelope_hash": "nope",
        "acceptance_seq": 1, "accepted_at_ms": 1, "state": "pending", "replayed": false}}}))
    .unwrap();
    line.push(b'\n');
    let server = fake_daemon(&socket, line);
    let mut client = BridgeClient::connect(&socket).unwrap();
    assert_eq!(
        client.publish(RUN_TOKEN, &body("e")).unwrap_err().class,
        "transport"
    );
    server.join().unwrap();
    let _ = std::fs::remove_file(&socket);

    // An unterminated response far beyond the cap is cut off, not buffered.
    let socket = short_socket("fake-flood");
    let server = fake_daemon(&socket, vec![b'a'; 5 * 1024 * 1024]);
    let mut client = BridgeClient::connect(&socket).unwrap();
    let error = client.status(RUN_TOKEN, "e").unwrap_err();
    assert_eq!(error.class, "transport");
    let _ = server.join();
    let _ = std::fs::remove_file(&socket);
}

/// Public clients reject structurally invalid or request-misbound operator replies.
///
/// Owned fake sockets return otherwise valid pages/retention records. Correct
/// controls pass; wrong bounds/order/filter/limit/identity and contradictory
/// GC/compaction facts fail as transport errors, without trusting sender state.
#[test]
fn operator_responses_are_validated_and_bound_to_exact_queries() {
    let incident = serde_json::json!({
        "incident_seq": 1, "publisher": "agent-run", "event_id": "e",
        "attempt_seq": null, "kind": "unknown_handoff", "state": "open", "reason": "r",
        "created_ms": 1, "updated_ms": 1, "age_ms": 0, "next_check_ms": null,
        "review_deadline_ms": null, "responsible": "operator", "blocked_dependents": [],
        "duplicate_risk": false, "resolution": null
    });
    let mut second = incident.clone();
    second["incident_seq"] = 2.into();
    let page = serde_json::json!({"IncidentsPage": {"page": {
        "incidents": [incident.clone(), second.clone()], "through_seq": 3, "next_after_seq": 2
    }}});
    let mut unordered = page.clone();
    unordered["IncidentsPage"]["page"]["incidents"] = serde_json::json!([second, incident]);
    let mut closed = page.clone();
    closed["IncidentsPage"]["page"]["incidents"][0]["state"] = "disposed".into();
    let mut bad_cursor = page.clone();
    bad_cursor["IncidentsPage"]["page"]["next_after_seq"] = 1.into();
    let mut overflow = page.clone();
    overflow["IncidentsPage"]["page"]["through_seq"] = (1u64 << 63).into();
    for (answer, after, through, include_closed, limit, valid) in [
        (page.clone(), 0, 3, true, 2, true),
        (page.clone(), 1, 3, true, 2, false),
        (page.clone(), 0, 4, true, 2, false),
        (page, 0, 3, true, 1, false),
        (closed.clone(), 0, 3, true, 2, true),
        (closed, 0, 3, false, 2, false),
        (unordered, 0, 3, true, 2, false),
        (bad_cursor, 0, 3, true, 2, false),
        (overflow, 0, 3, true, 2, false),
    ] {
        let mut line = serde_json::to_vec(&answer).unwrap();
        line.push(b'\n');
        let socket = short_socket("fake-operator-page");
        let server = fake_daemon(&socket, line);
        let result = BridgeClient::connect(&socket).unwrap().incidents_page(
            OPS_TOKEN,
            include_closed,
            Some(limit),
            after,
            Some(through),
        );
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(result.is_ok(), valid, "{answer}: {result:?}");
        if !valid {
            assert_eq!(result.unwrap_err().class, "transport");
        }
    }

    let request = body("retained");
    let envelope = bridge_core::Envelope::new(
        bridge_core::PublisherId::new("agent-run").unwrap(),
        bridge_core::EventId::new(&request.event_id).unwrap(),
        request.recipient.clone(),
        bridge_core::Kind::new(&request.kind).unwrap(),
        request.mode,
        request.policy.clone(),
        bridge_core::Payload::new(&request.payload).unwrap(),
        request.metadata.clone(),
        request.expires_at,
    )
    .unwrap();
    let mut storage = Storage::open_in_memory(Limits::new(10)).unwrap();
    storage.publish(&envelope, 1).unwrap();
    let retention = storage.retention("agent-run", "retained").unwrap().unwrap();
    let valid = serde_json::json!({"Retention": {"retention": retention}});
    let mut absent = valid.clone();
    absent["Retention"]["retention"] = serde_json::Value::Null;
    let mut foreign = valid.clone();
    foreign["Retention"]["retention"]["receipt"]["event_id"] = "other-event".into();
    let mut foreign_publisher = valid.clone();
    foreign_publisher["Retention"]["retention"]["receipt"]["publisher"] = "other-publisher".into();
    let mut compacted = valid.clone();
    compacted["Retention"]["retention"]["payload_compacted"] = true.into();
    let mut eligible = valid.clone();
    eligible["Retention"]["retention"]["gc_eligible"] = true.into();
    let mut invalid_range = valid.clone();
    invalid_range["Retention"]["retention"]["envelope_bytes"] = (1u64 << 63).into();
    for (answer, accepted) in [
        (valid, true),
        (absent, true),
        (foreign, false),
        (foreign_publisher, false),
        (compacted, false),
        (eligible, false),
        (invalid_range, false),
    ] {
        let mut line = serde_json::to_vec(&answer).unwrap();
        line.push(b'\n');
        let socket = short_socket("fake-operator-retention");
        let server = fake_daemon(&socket, line);
        let result =
            BridgeClient::connect(&socket)
                .unwrap()
                .retention(OPS_TOKEN, "agent-run", "retained");
        server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(result.is_ok(), accepted, "{answer}: {result:?}");
        if !accepted {
            assert_eq!(result.unwrap_err().class, "transport");
        }
    }
}

/// Unsupported modes are refused over the wire before acceptance, with
/// no custody row created.
#[test]
fn unsupported_modes_are_refused_over_the_wire_before_acceptance() {
    let dir = TempDir::new("life-unsupported");
    let running = started(config(&dir, "unsupported"));
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    running.with_storage(|storage| {
        let message_only = Attestation::verified(
            recipient(),
            "thread-7",
            1,
            Lifecycle::Inactive,
            Capabilities {
                inject: false,
                message: true,
            },
            "fixture-proof",
        )
        .unwrap();
        storage.observe_binding(&message_only, 1_000).unwrap();
    });
    let mut inject = body("evt-inject");
    inject.mode = Mode::Inject;
    assert_eq!(
        client.publish(RUN_TOKEN, &inject).unwrap_err().class,
        "unsupported"
    );
    // auto resolves per dispatch and needs only one loaded path.
    let mut auto = body("evt-auto");
    auto.mode = Mode::Auto;
    client.publish(RUN_TOKEN, &auto).unwrap();
    client.publish(RUN_TOKEN, &body("evt-msg")).unwrap();
    running.shutdown();
    running.join();
    let storage = Storage::open(dir.path("bridge.db"), Limits::new(1_000)).unwrap();
    let publisher = bridge_core::PublisherId::new("agent-run").unwrap();
    assert!(
        storage
            .lookup(
                &publisher,
                &bridge_core::EventId::new("evt-inject").unwrap()
            )
            .unwrap()
            .is_none(),
        "an unsupported event is never accepted"
    );
}

/// After the stop request, new work is fenced while every acknowledged
/// publish remains durable in storage.
#[test]
fn shutdown_fences_new_work_and_every_acknowledged_publish_is_durable() {
    let dir = TempDir::new("life-fence");
    let running = started(config(&dir, "fence"));
    let socket = running.socket_path().to_path_buf();
    let workers: Vec<_> = (0..4)
        .map(|worker| {
            let socket = socket.clone();
            std::thread::spawn(move || {
                let mut client = BridgeClient::connect(&socket).unwrap();
                let mut acknowledged = Vec::new();
                for index in 0..10_000 {
                    let id = format!("w{worker}-{index}");
                    match client.publish(RUN_TOKEN, &body(&id)) {
                        Ok(_) => acknowledged.push(id),
                        Err(_) => break,
                    }
                }
                acknowledged
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    running.shutdown();
    // The fence holds from the moment shutdown returns: count rows now.
    let count_events = || -> i64 {
        rusqlite::Connection::open(dir.path("bridge.db"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap()
    };
    let at_stop = count_events();
    let acknowledged: Vec<String> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    running.join();
    assert_eq!(
        count_events(),
        at_stop,
        "no publish may be accepted after the stop returned"
    );
    assert!(at_stop > 0, "the workers made progress before the stop");
    let connection = rusqlite::Connection::open(dir.path("bridge.db")).unwrap();
    for id in &acknowledged {
        let present: bool = connection
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM events WHERE event_id = ?1)",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(present, "acknowledged event {id} must be durable");
    }
}

/// Idle and stalled connections are closed within their timeouts and
/// ordinary clients reconnect cleanly.
#[test]
fn idle_and_stalled_connections_are_closed_and_clients_reconnect() {
    let dir = TempDir::new("life-timeouts");
    let mut config = config(&dir, "timeouts");
    config.limits.idle_timeout_ms = 300;
    config.limits.request_timeout_ms = 300;
    let running = started(config);
    let socket = running.socket_path().to_path_buf();

    // A silent connection is closed without any unsolicited bytes.
    let mut idle = UnixStream::connect(&socket).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buffer = Vec::new();
    let started_at = Instant::now();
    let read = idle.read_to_end(&mut buffer).unwrap();
    assert_eq!(read, 0, "an idle close must not write a line");
    assert!(started_at.elapsed() < Duration::from_secs(2));

    // A half-written request cannot hold the connection.
    let mut stalled = UnixStream::connect(&socket).unwrap();
    stalled.write_all(b"{\"op\":\"stat").unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reply = String::new();
    let _ = stalled.read_to_string(&mut reply);
    assert!(reply.is_empty() || reply.contains("timed out"), "{reply:?}");

    // The client recovers from the service closing its idle connection.
    let mut client = BridgeClient::connect(&socket).unwrap();
    client.publish(RUN_TOKEN, &body("evt-before")).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    client.publish(RUN_TOKEN, &body("evt-after")).unwrap();
    assert!(client.status(RUN_TOKEN, "evt-after").unwrap().0.is_some());

    running.shutdown();
    running.join();
}

/// Concurrent connections beyond the configured cap are refused
/// admission while earlier clients keep working.
#[test]
fn connection_admission_is_bounded_by_the_configured_cap() {
    let dir = TempDir::new("life-cap");
    let mut config = config(&dir, "cap");
    config.limits.max_connections = 3;
    let running = started(config);
    let socket = running.socket_path().to_path_buf();
    let status = format!(
        "{}\n",
        serde_json::to_string(&Request::Status {
            token: Token::new(RUN_TOKEN),
            event_id: "evt".into()
        })
        .unwrap()
    );
    let mut held: Vec<UnixStream> = Vec::new();
    for _ in 0..3 {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(status.as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.contains("Status"), "{line}");
        held.push(stream);
    }
    // The fourth is dropped by admission, not served.
    let mut extra = UnixStream::connect(&socket).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let _ = extra.write_all(status.as_bytes());
    let mut buffer = String::new();
    let _ = extra.read_to_string(&mut buffer);
    assert!(
        buffer.is_empty(),
        "admission must drop it unserved: {buffer:?}"
    );
    // Freeing a slot admits a new connection again.
    held.pop();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut again = UnixStream::connect(&socket).unwrap();
        again.write_all(status.as_bytes()).unwrap();
        again
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        let served = BufReader::new(again)
            .read_line(&mut line)
            .is_ok_and(|n| n > 0);
        if served {
            break;
        }
        assert!(Instant::now() < deadline, "a freed slot was never reused");
        std::thread::sleep(Duration::from_millis(50));
    }
    running.shutdown();
    running.join();
}

/// Socket ownership preserves foreign paths (regular files, symlinks,
/// directories) and the stop removes only the inode this instance
/// bound.
#[test]
fn socket_ownership_preserves_foreign_paths_and_only_removes_its_own_inode() {
    let dir = TempDir::new("life-owner");

    // A symlink is foreign, even when it points at a file or nowhere.
    let sentinel = dir.path("sentinel.txt");
    std::fs::write(&sentinel, b"owner bytes").unwrap();
    for target in [sentinel.clone(), dir.path("does-not-exist")] {
        let mut config = config(&dir, "link");
        config.socket = dir.path("link.sock");
        std::os::unix::fs::symlink(&target, &config.socket).unwrap();
        assert!(service::start(config.clone()).is_err());
        assert!(
            std::fs::symlink_metadata(&config.socket)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink must survive"
        );
        std::fs::remove_file(&config.socket).unwrap();
    }
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"owner bytes");

    // A socket we cannot prove stale (connect is refused for another
    // reason than "nobody listens") is preserved and startup refuses.
    let unreachable = short_socket("noperm");
    drop(UnixListener::bind(&unreachable).unwrap());
    std::fs::set_permissions(
        &unreachable,
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    let mut config_unreachable = config(&dir, "noperm");
    config_unreachable.socket = unreachable.clone();
    assert!(service::start(config_unreachable).is_err());
    assert!(
        unreachable.exists(),
        "an unprovable endpoint is never removed"
    );
    std::fs::set_permissions(
        &unreachable,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    std::fs::remove_file(&unreachable).unwrap();

    // Another process replaced our endpoint while we ran: our stop must
    // leave the successor's socket in place.
    let running = started(config(&dir, "inode"));
    let socket = running.socket_path().to_path_buf();
    std::fs::remove_file(&socket).unwrap();
    let successor = UnixListener::bind(&socket).unwrap();
    running.shutdown();
    running.join();
    assert!(
        socket.exists(),
        "the successor's endpoint must survive our stop"
    );
    drop(successor);
    std::fs::remove_file(&socket).unwrap();
}

/// Two racing starts on one endpoint never replace a live daemon: the
/// second refuses and the first keeps its socket.
#[test]
fn racing_starts_on_one_endpoint_never_replace_a_live_daemon() {
    for stale in [false, true] {
        let dir = TempDir::new("life-race");
        let socket = short_socket("race");
        if stale {
            // A socket left behind by a killed daemon.
            drop(UnixListener::bind(&socket).unwrap());
        }
        let barrier = Arc::new(std::sync::Barrier::new(6));
        let attempts: Vec<_> = (0..6)
            .map(|index| {
                let mut contender = config(&dir, "race");
                contender.socket = socket.clone();
                contender.database = dir.path(&format!("contender-{index}.db"));
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    service::start(contender)
                })
            })
            .collect();
        let mut winners = Vec::new();
        let mut losers = 0;
        for attempt in attempts {
            match attempt.join().unwrap() {
                Ok(running) => winners.push(running),
                Err(_) => losers += 1,
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "exactly one daemon owns the endpoint (stale: {stale})"
        );
        assert_eq!(losers, 5);
        let winner = winners.pop().unwrap();
        // The winner is the one actually reachable, and a loser's failure
        // did not remove or replace its socket.
        assert!(wait_listening(&socket, Duration::from_secs(5)));
        let mut client = BridgeClient::connect(&socket).unwrap();
        client.publish(RUN_TOKEN, &body("evt-race")).unwrap();
        winner.shutdown();
        winner.join();
        assert!(!socket.exists());
        // Losers never touched their databases beyond what a start needs.
        let touched = (0..6)
            .filter(|index| dir.path(&format!("contender-{index}.db")).exists())
            .count();
        assert_eq!(touched, 1, "only the winner opened its database");
        let _ = std::fs::remove_file(format!("{}.lock", socket.display()));
    }
}

/// The daemon exits 0 on SIGTERM after a drained stop and never logs
/// configuration secrets, including on parse failure.
#[test]
fn daemon_exits_cleanly_on_sigterm_and_never_logs_config_secrets() {
    let dir = TempDir::new("life-daemon");
    let config = config(&dir, "sigterm");
    let socket = config.socket.clone();
    let config_path = dir.path("daemon.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_bridge-daemon");
    let mut child = std::process::Command::new(binary)
        .arg(&config_path)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_listening(&socket, Duration::from_secs(10)));
    let mut client = BridgeClient::connect(&socket).unwrap();
    client.publish(RUN_TOKEN, &body("evt-signal")).unwrap();

    let killed = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "SIGTERM must stop the daemon");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success(),
        "a signalled stop is a clean stop: {status:?}"
    );
    assert!(
        !socket.exists(),
        "the socket is removed on a signalled stop"
    );
    // The accepted event survived.
    let storage = Storage::open(dir.path("bridge.db"), Limits::new(1_000)).unwrap();
    assert!(
        storage
            .lookup(
                &bridge_core::PublisherId::new("agent-run").unwrap(),
                &bridge_core::EventId::new("evt-signal").unwrap()
            )
            .unwrap()
            .is_some()
    );

    // A broken configuration must not echo the secrets it contains.
    let broken = dir.path("broken.toml");
    std::fs::write(
        &broken,
        "database = \"/tmp/x.db\"\nsocket = \"/tmp/x.sock\"\n[limits]\nmax_admitted_events = 10\n\
         [[grant]]\ntoken = 1234567890123456789\npublisher = \"CANARY-PUBLISHER-SECRET\" nope\n",
    )
    .unwrap();
    let output = std::process::Command::new(binary)
        .arg(&broken)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("config_parse_failed"), "{log}");
    assert!(!log.contains("CANARY-PUBLISHER-SECRET"), "{log}");
    assert!(!log.contains("1234567890123456789"), "{log}");
}

/// Malformed grants refuse startup before any request is served.
#[test]
fn grant_configuration_is_validated_before_anything_is_served() {
    let dir = TempDir::new("life-grants");
    let reject = |mutate: &dyn Fn(&mut Config)| {
        let mut bad = config(&dir, "badgrant");
        mutate(&mut bad);
        assert!(service::start(bad.clone()).is_err());
        assert!(
            !bad.socket.exists(),
            "a refused start must not bind a socket"
        );
    };
    reject(&|c| c.grants[0].token = "short".into());
    reject(&|c| c.grants[1].token = c.grants[0].token.clone());
    reject(&|c| {
        c.grants[2]
            .recipients
            .push(recipient().to_canonical_string())
    });
    reject(&|c| c.grants[0].publisher = "not a valid wrapper tag".into());
    reject(&|c| c.limits.max_connections = 0);
    reject(&|c| c.limits.idle_timeout_ms = 0);
}

/// Both TOML grant table spellings parse and missing limits take their
/// documented defaults.
#[test]
fn both_toml_grant_table_names_parse_and_limits_default_sensibly() {
    let grant = "token = \"0123456789abcdef-token\"\npublisher = \"agent-run\"\n\
                 recipients = []\nkinds = []\nmodes = []\npolicies = []\n";
    for table in ["grant", "grants"] {
        let text = format!(
            "database = \"/tmp/a.db\"\nsocket = \"/tmp/a.sock\"\n\
             [limits]\nmax_admitted_events = 5\n[[{table}]]\n{grant}"
        );
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.grants.len(), 1);
        assert_eq!(parsed.limits.max_connections, 64, "defaults apply");
        assert!(parsed.limits.validate().is_ok());
    }
}

/// Token credentials never appear in debug output or error details.
#[test]
fn credentials_never_appear_in_debug_output_or_error_details() {
    let secret = "CANARY-TOKEN-0123456789ABCDEF";
    let request = Request::Shutdown {
        token: Token::new(secret),
    };
    assert!(!format!("{request:?}").contains(secret));
    let grant = GrantConfig {
        producer_v1: None,
        token: secret.to_string(),
        publisher: "agent-run".into(),
        recipients: vec![],
        kinds: vec![],
        modes: vec![],
        policies: vec![],
        admin: false,
    };
    assert!(!format!("{grant:?}").contains(secret));
    // The wire form is unchanged: a plain JSON string.
    assert!(serde_json::to_string(&request).unwrap().contains(secret));

    let dir = TempDir::new("life-redact");
    let running = started(config(&dir, "redact"));
    let socket = running.socket_path().to_path_buf();
    let broken = format!("{{\"op\":\"publish\",\"token\":\"{secret}\",\"event\":");
    match raw(&socket, &broken) {
        Response::Error { class, detail } => {
            assert_eq!(class, "unsupported");
            assert!(!detail.contains(secret), "{detail}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    let unknown = format!("{{\"op\":\"{secret}\",\"token\":\"x\"}}");
    match raw(&socket, &unknown) {
        Response::Error { detail, .. } => assert!(!detail.contains(secret), "{detail}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    running.shutdown();
    running.join();
}

/// A canonical Codex address for the multi-recipient service checks.
fn thread(name: &str) -> NativeAddress {
    NativeAddress::new("host-1", Harness::Codex, "default", name).unwrap()
}

/// Waits until `event` reports `native_accepted` or the budget runs out.
fn wait_accepted(client: &mut BridgeClient, event: &str, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let (_, delivery) = client.status(RUN_TOKEN, event).unwrap();
        if delivery.is_some_and(|d| d.attempt_state == "native_accepted") {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Recipients whose pending work the message path can never take (here
/// inject-only events) must not occupy the bounded dispatch listing
/// forever: a seventeenth, younger recipient with real message work is
/// still served by the service loop.
#[test]
fn quiet_inject_only_recipients_cannot_starve_a_later_message_recipient() {
    let dir = TempDir::new("life-fair");
    let quiet: Vec<NativeAddress> = (0..16)
        .map(|index| thread(&format!("quiet-{index:02}")))
        .collect();
    let busy = thread("zz-busy");
    let mut cfg = config(&dir, "fair");
    cfg.grants[0].recipients = quiet
        .iter()
        .chain([&busy])
        .map(NativeAddress::to_canonical_string)
        .collect();
    let script = Arc::new(Mutex::new(ScriptedCarrier::new(
        Lifecycle::Inactive,
        ScriptedCarrier::accepted(),
    )));
    let running =
        service::start_with_carriers(cfg, vec![Box::new(Shared(Arc::clone(&script)))]).unwrap();
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    for (index, address) in quiet.iter().enumerate() {
        let mut inject = body(&format!("evt-quiet-{index:02}"));
        inject.recipient = address.clone();
        inject.mode = Mode::Inject;
        client.publish(RUN_TOKEN, &inject).unwrap();
        std::thread::sleep(Duration::from_millis(3));
    }
    let mut work = body("evt-busy");
    work.recipient = busy;
    client.publish(RUN_TOKEN, &work).unwrap();

    assert!(
        wait_accepted(&mut client, "evt-busy", Duration::from_secs(10)),
        "the younger message recipient starved behind quiet inject-only recipients"
    );
    assert_eq!(script.lock().unwrap().sends.len(), 1);
    running.shutdown();
    running.join();
}

/// A carrier whose attestation panics for one recipient on every call.
struct Poisoned {
    /// The recipient whose attestation always panics.
    bad: NativeAddress,
    /// The well-behaved carrier used for every other recipient.
    inner: ScriptedCarrier,
}

impl DispatchCarrier for Poisoned {
    /// Panics for the poisoned recipient; otherwise attests normally.
    fn attest(&mut self, recipient: &NativeAddress) -> Result<Attestation, String> {
        assert!(
            *recipient != self.bad,
            "scripted persistent attestation panic"
        );
        self.inner.attest(recipient)
    }

    /// Applies this fixture's scripted outcome to the frozen attempt.
    fn send(&mut self, attempt: &AttemptRecord) -> Outcome {
        self.inner.send(attempt)
    }
}

/// A carrier attestation that panics on every pass for one recipient is
/// isolated to that recipient: the recipient shows a visible hold and its
/// event stays unaccepted, while another recipient still gets delivered.
#[test]
fn a_persistently_panicking_attestation_is_isolated_to_its_recipient() {
    let dir = TempDir::new("life-poison");
    let (bad, good) = (thread("a-bad"), thread("b-good"));
    let mut cfg = config(&dir, "poison");
    cfg.grants[0].recipients = vec![bad.to_canonical_string(), good.to_canonical_string()];
    let running = service::start_with_carriers(
        cfg,
        vec![Box::new(Poisoned {
            bad: bad.clone(),
            inner: ScriptedCarrier::new(Lifecycle::Inactive, ScriptedCarrier::accepted()),
        })],
    )
    .unwrap();
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    let mut first = body("evt-bad");
    first.recipient = bad;
    client.publish(RUN_TOKEN, &first).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    let mut second = body("evt-good");
    second.recipient = good;
    client.publish(RUN_TOKEN, &second).unwrap();

    assert!(
        wait_accepted(&mut client, "evt-good", Duration::from_secs(10)),
        "a persistent attestation panic for one recipient stopped other deliveries"
    );
    let (_, bad_status) = client.status(RUN_TOKEN, "evt-bad").unwrap();
    assert!(
        bad_status.is_none_or(|d| d.attempt_state != "native_accepted"),
        "a panicking attestation must never fabricate native acceptance"
    );
    let holds = client.holds(OPS_TOKEN, None).unwrap();
    assert_eq!(holds.len(), 1, "the poisoned recipient is visibly held");
    assert!(holds[0].reason.contains("panicked"), "{}", holds[0].reason);
    running.shutdown();
    running.join();
}

/// A carrier whose attestation always refuses with one fixed reason.
struct Refusing {
    /// The refusal text this carrier reports for every recipient.
    reason: &'static str,
}

impl DispatchCarrier for Refusing {
    /// Always refuses to attest, with the fixed reason.
    fn attest(&mut self, _recipient: &NativeAddress) -> Result<Attestation, String> {
        Err(self.reason.to_string())
    }

    /// Never reached: a refused attestation must not lead to a hand-off.
    fn send(&mut self, _attempt: &AttemptRecord) -> Outcome {
        unreachable!("a refusing carrier is never asked to send")
    }
}

/// When several carriers refuse a recipient, the visible hold keeps every
/// carrier's reason (bounded), not only the last one, so the meaningful
/// refusal of the matching carrier ("the harness process is gone") is not
/// hidden by an unrelated carrier's "not my harness" answer. Nothing is
/// attempted for the recipient.
#[test]
fn a_hold_keeps_every_carriers_refusal_reason_and_attempts_nothing() {
    let dir = TempDir::new("life-reasons");
    let running = service::start_with_carriers(
        config(&dir, "reasons"),
        vec![
            Box::new(Refusing {
                reason: "harness process is gone",
            }),
            Box::new(Refusing {
                reason: "not a Claude recipient",
            }),
        ],
    )
    .unwrap();
    let mut client = BridgeClient::connect(running.socket_path()).unwrap();
    client.publish(RUN_TOKEN, &body("evt-dead")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let reason = loop {
        if let Some(hold) = client.holds(OPS_TOKEN, None).unwrap().first() {
            break hold.reason.clone();
        }
        assert!(Instant::now() < deadline, "no hold was recorded");
        std::thread::sleep(Duration::from_millis(100));
    };
    running.shutdown();
    running.join();
    assert!(reason.contains("harness process is gone"), "{reason}");
    assert!(reason.contains("not a Claude recipient"), "{reason}");
    let connection = rusqlite::Connection::open(dir.path("bridge.db")).unwrap();
    let attempts: i64 = connection
        .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempts, 0, "a refused endpoint is never handed anything");
}
