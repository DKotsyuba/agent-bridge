//! Integration checks for the authenticated publisher service (T-004) and
//! the daemon binary scaffold (T-001/F10).
//!
//! All state is isolated: fresh temporary directories for the database and
//! socket; the binary test spawns its own daemon on a private socket.

mod common;

use std::time::{Duration, Instant};

use bridge_core::service::{self, Config, GrantConfig, PublishBody, Response};
use bridge_core::{
    EventId, ExpiresAt, Harness, Limits, Mode, NativeAddress, Policy, PublisherId, Storage,
    StreamId,
};
use common::TempDir;

/// A fixed synthetic grant token; test fixture data only.
const GRANT_TOKEN: &str = "6f6f-test-grant-token-0001";
const ADMIN_TOKEN: &str = "6f6f-admin-grant-token-0001";
const OTHER_TOKEN: &str = "6f6f-other-grant-token-0002";

/// The canonical recipient the grant allows.
fn recipient_text() -> String {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7")
        .unwrap()
        .to_canonical_string()
}

/// A short, unique socket path: macOS limits AF_UNIX paths to ~104 bytes,
/// so test sockets cannot live inside the deep per-test temp directory.
fn short_socket(tag: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "/tmp/bridge-svc-{}-{}-{}.sock",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// A minimal daemon config with a publisher grant and an admin grant.
fn test_config(dir: &TempDir) -> Config {
    Config {
        database: dir.path("bridge.db"),
        socket: short_socket("t"),
        limits: Limits::new(100),
        grants: vec![
            GrantConfig {
                token: GRANT_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: vec![recipient_text()],
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".to_string(), "auto".to_string()],
                policies: vec!["keep_all".to_string(), "latest".to_string()],
                admin: false,
            },
            GrantConfig {
                token: ADMIN_TOKEN.to_string(),
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

/// A valid publish body for the allowed grant.
fn body(event: &str) -> PublishBody {
    PublishBody {
        event_id: event.to_string(),
        recipient: NativeAddress::new("host-1", Harness::Codex, "default", "thread-7").unwrap(),
        kind: "worker.completed".to_string(),
        mode: Mode::Message,
        policy: Policy::KeepAll,
        payload: "synthetic worker result".to_string(),
        metadata: Default::default(),
        expires_at: None,
    }
}

/// Sends one raw ndjson request over a fresh connection and reads the
/// response line; for tests that must speak below the typed client.
fn raw_round_trip(socket: &std::path::Path, request_json: &str) -> Response {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    stream.write_all(request_json.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// Waits until a client can connect to the socket, bounded to `budget`.
fn wait_listening(socket: &std::path::Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn publish_and_identical_replay_over_ipc() {
    let dir = TempDir::new("svc-replay");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let first = client.publish(GRANT_TOKEN, &body("evt-1")).unwrap();
    assert!(!first.replayed);
    assert_eq!(first.publisher, "agent-run");
    assert_eq!(first.state, bridge_core::EventState::Pending);

    // Lost-response retry: identical body returns the original receipt.
    let replay = client.publish(GRANT_TOKEN, &body("evt-1")).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.acceptance_seq, first.acceptance_seq);

    // Changed content under the same id is a conflict, never an overwrite.
    let mut changed = body("evt-1");
    changed.payload = "different content".to_string();
    let error = client.publish(GRANT_TOKEN, &changed).unwrap_err();
    assert_eq!(error.class, "conflict");

    running.shutdown();
    running.join();
}

#[test]
fn authentication_precedes_custody_and_disclosure() {
    let dir = TempDir::new("svc-auth");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    // Wrong token: refused before any custody write...
    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let error = client.publish(OTHER_TOKEN, &body("evt-auth")).unwrap_err();
    assert_eq!(error.class, "auth");
    // ...and before any status disclosure.
    let error = client.status(OTHER_TOKEN, "evt-auth").unwrap_err();
    assert_eq!(error.class, "auth");

    // Storage really has no row: the event was never accepted.
    let storage = Storage::open(dir.path("bridge.db"), Limits::new(100)).unwrap();
    assert!(
        storage
            .lookup(
                &PublisherId::new("agent-run").unwrap(),
                &EventId::new("evt-auth").unwrap()
            )
            .unwrap()
            .is_none()
    );

    // Non-admin grant cannot stop the daemon.
    let error = client.shutdown(GRANT_TOKEN).unwrap_err();
    assert_eq!(error.class, "forbidden");

    running.shutdown();
    running.join();
}

#[test]
fn grant_allowlists_are_enforced_before_acceptance() {
    let dir = TempDir::new("svc-grants");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();

    let mut wrong_recipient = body("evt-r");
    wrong_recipient.recipient =
        NativeAddress::new("host-1", Harness::Codex, "default", "thread-999").unwrap();
    assert_eq!(
        client
            .publish(GRANT_TOKEN, &wrong_recipient)
            .unwrap_err()
            .class,
        "forbidden"
    );

    let mut wrong_kind = body("evt-k");
    wrong_kind.kind = "telemetry".to_string();
    assert_eq!(
        client.publish(GRANT_TOKEN, &wrong_kind).unwrap_err().class,
        "forbidden"
    );

    let mut wrong_mode = body("evt-m");
    wrong_mode.mode = Mode::Inject;
    assert_eq!(
        client.publish(GRANT_TOKEN, &wrong_mode).unwrap_err().class,
        "forbidden"
    );

    // A policy the grant does not carry is a known unsupported capability,
    // refused before acceptance.
    let mut wrong_policy = body("evt-p");
    wrong_policy.policy = Policy::Batch {
        group: "g".to_string(),
    };
    assert_eq!(
        client
            .publish(GRANT_TOKEN, &wrong_policy)
            .unwrap_err()
            .class,
        "forbidden"
    );

    // Invalid content is refused as invalid, still without custody.
    let mut invalid = body("evt-i");
    invalid.event_id = String::new();
    assert_eq!(
        client.publish(GRANT_TOKEN, &invalid).unwrap_err().class,
        "invalid"
    );

    let storage = Storage::open(dir.path("bridge.db"), Limits::new(100)).unwrap();
    for event in ["evt-r", "evt-k", "evt-m", "evt-p", "evt-i"] {
        assert!(
            storage
                .lookup(
                    &PublisherId::new("agent-run").unwrap(),
                    &EventId::new(event).unwrap()
                )
                .unwrap()
                .is_none(),
            "{event} must not have been accepted"
        );
    }

    running.shutdown();
    running.join();
}

#[test]
fn status_discloses_only_the_callers_own_events() {
    let dir = TempDir::new("svc-status");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    client.publish(GRANT_TOKEN, &body("evt-own")).unwrap();

    // The owning publisher sees its custody state.
    let own = client.status(GRANT_TOKEN, "evt-own").unwrap().unwrap();
    assert_eq!(own.event_id, "evt-own");

    // Another publisher's token never discloses it (its publisher scope
    // has no such event), even with the event id known.
    let response = raw_round_trip(
        &socket,
        &serde_json::json!({"op": "status", "token": ADMIN_TOKEN, "event_id": "evt-own"})
            .to_string(),
    );
    match response {
        Response::Status { receipt } => assert!(receipt.is_none()),
        other => panic!("expected empty status, got {other:?}"),
    }

    // Unknown ids are simply absent, not an error.
    assert!(client.status(GRANT_TOKEN, "evt-never").unwrap().is_none());

    running.shutdown();
    running.join();
}

#[test]
fn malformed_and_unknown_requests_are_refused() {
    let dir = TempDir::new("svc-malformed");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    // Unparseable line.
    match raw_round_trip(&socket, "this is not json") {
        Response::Error { class, .. } => assert_eq!(class, "unsupported"),
        other => panic!("expected error, got {other:?}"),
    }
    // Unknown operation.
    match raw_round_trip(
        &socket,
        &serde_json::json!({"op": "reset_everything", "token": GRANT_TOKEN}).to_string(),
    ) {
        Response::Error { class, .. } => assert_eq!(class, "unsupported"),
        other => panic!("expected error, got {other:?}"),
    }

    running.shutdown();
    running.join();
}

#[test]
fn shutdown_is_bounded_and_cleans_the_socket() {
    let dir = TempDir::new("svc-shutdown");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    client.shutdown(ADMIN_TOKEN).unwrap();

    let started = Instant::now();
    running.join();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "drained shutdown must be bounded"
    );
    assert!(!socket.exists(), "socket file must be removed on stop");
}

#[test]
fn daemon_binary_serves_and_stops_cleanly() {
    let dir = TempDir::new("svc-binary");
    let mut config = test_config(&dir);
    let socket = short_socket("bin");
    config.socket = socket.clone();
    let config_text = toml::to_string(&config).unwrap();
    let config_path = dir.path("daemon.toml");
    std::fs::write(&config_path, config_text).unwrap();

    let binary = env!("CARGO_BIN_EXE_bridge-daemon");
    let mut child = std::process::Command::new(binary)
        .arg(&config_path)
        .spawn()
        .unwrap();
    assert!(
        wait_listening(&socket, Duration::from_secs(10)),
        "daemon must become reachable within a bounded startup"
    );

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let receipt = client.publish(GRANT_TOKEN, &body("evt-binary")).unwrap();
    assert_eq!(receipt.publisher, "agent-run");
    client.shutdown(ADMIN_TOKEN).unwrap();

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "daemon must exit 0 after drained shutdown"
    );
    assert!(!socket.exists());
}

#[test]
fn latest_snapshots_flow_through_the_service_with_scoped_watermarks() {
    let dir = TempDir::new("svc-latest");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let mut first = body("view-12");
    first.policy = Policy::Latest {
        stream: StreamId::new("diag-1").unwrap(),
        revision: 12,
    };
    first.mode = Mode::Auto;
    let receipt = client.publish(GRANT_TOKEN, &first).unwrap();
    assert_eq!(receipt.state, bridge_core::EventState::Pending);

    let mut stale = body("view-11");
    stale.policy = Policy::Latest {
        stream: StreamId::new("diag-1").unwrap(),
        revision: 11,
    };
    stale.mode = Mode::Auto;
    let receipt = client.publish(GRANT_TOKEN, &stale).unwrap();
    assert_eq!(receipt.state, bridge_core::EventState::Superseded);

    running.shutdown();
    running.join();
}

/// A config whose grant is malformed must refuse to start at all.
#[test]
fn malformed_grant_refuses_startup() {
    let dir = TempDir::new("svc-badgrant");
    let mut config = test_config(&dir);
    config.grants[0]
        .recipients
        .push("not/an/address".to_string());
    assert!(service::start(config).is_err());
}

/// Expiry still flows through IPC and pending-only expiry holds after
/// service-mediated publication.
#[test]
fn expiry_flows_through_the_service() {
    let dir = TempDir::new("svc-expiry");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let mut expiring = body("evt-exp");
    expiring.expires_at = Some(ExpiresAt::from_unix_millis(1_000).unwrap());
    client.publish(GRANT_TOKEN, &expiring).unwrap();
    running.shutdown();
    running.join();

    let storage = Storage::open(dir.path("bridge.db"), Limits::new(100)).unwrap();
    assert_eq!(storage.expire_due(2_000).unwrap(), 1);
    let row = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("evt-exp").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.state, bridge_core::EventState::Expired);
}
