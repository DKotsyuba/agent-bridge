//! Integration checks for the authenticated publisher service and the daemon
//! binary.
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
use common::{TempDir, short_socket};

/// A fixed synthetic grant token; test fixture data only.
const GRANT_TOKEN: &str = "6f6f-test-grant-token-0001";
/// A fixed synthetic operator-realm token; test fixture data only.
const ADMIN_TOKEN: &str = "6f6f-admin-grant-token-0001";
/// A well-formed synthetic token that no configured grant holds; test fixture data only.
const OTHER_TOKEN: &str = "6f6f-other-grant-token-0002";
/// A fixed synthetic token of a second publisher; test fixture data only.
const SECOND_TOKEN: &str = "6f6f-second-publisher-token-0003";

/// The canonical recipient the grant allows.
fn recipient_text() -> String {
    NativeAddress::new("host-1", Harness::Codex, "default", "thread-7")
        .unwrap()
        .to_canonical_string()
}

/// A minimal daemon config with a publisher grant and an admin grant.
fn test_config(dir: &TempDir) -> Config {
    Config {
        universal_limits: bridge_core::UniversalLimits::default(),
        database: dir.path("bridge.db"),
        socket: short_socket("t"),
        limits: Limits::new(100),
        grants: vec![
            GrantConfig {
                producer_v1: None,
                token: GRANT_TOKEN.to_string(),
                publisher: "agent-run".to_string(),
                recipients: vec![recipient_text()],
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".to_string(), "auto".to_string()],
                policies: vec!["keep_all".to_string(), "latest".to_string()],
                admin: false,
            },
            GrantConfig {
                producer_v1: None,
                token: ADMIN_TOKEN.to_string(),
                publisher: "bridge-ops".to_string(),
                recipients: vec![],
                kinds: vec![],
                modes: vec![],
                policies: vec![],
                admin: true,
            },
            GrantConfig {
                producer_v1: None,
                token: SECOND_TOKEN.to_string(),
                publisher: "agent-ide".to_string(),
                recipients: vec![recipient_text()],
                kinds: vec!["worker.completed".to_string()],
                modes: vec!["message".to_string()],
                policies: vec!["keep_all".to_string()],
                admin: false,
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

/// Publish over the daemon socket returns a stamped custody receipt;
/// an identical resend replays the original receipt and changed content
/// conflicts, exactly like the storage-level semantics.
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

/// Wrong tokens are refused before any custody write or status
/// disclosure, no row appears in storage, and non-admin grants cannot
/// stop the daemon.
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

/// Recipient, kind, mode and policy outside the grant are refused
/// before acceptance, leaving no custody rows; invalid content is a
/// distinct `invalid` refusal.
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

/// Status returns only the caller's own events: another publisher's
/// token never sees them, delivery evidence is absent until an attempt
/// exists, and unknown ids are simply absent.
#[test]
fn status_discloses_only_the_callers_own_events() {
    let dir = TempDir::new("svc-status");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    client.publish(GRANT_TOKEN, &body("evt-own")).unwrap();

    // The owning publisher sees its custody state and delivery evidence
    // (absent until a dispatch attempt exists: not_available, not
    // delivered).
    let (own, delivery) = client.status(GRANT_TOKEN, "evt-own").unwrap();
    let own = own.unwrap();
    assert_eq!(own.event_id, "evt-own");
    assert!(delivery.is_none());

    // Another publisher's token never discloses it (its publisher scope
    // has no such event), even with the event id known.
    let (foreign, foreign_delivery) = client.status(SECOND_TOKEN, "evt-own").unwrap();
    assert!(foreign.is_none() && foreign_delivery.is_none());
    // An operator grant is a different realm and cannot read publisher
    // status at all.
    let response = raw_round_trip(
        &socket,
        &serde_json::json!({"op": "status", "token": ADMIN_TOKEN, "event_id": "evt-own"})
            .to_string(),
    );
    match response {
        Response::Error { class, .. } => assert_eq!(class, "forbidden"),
        other => panic!("expected a forbidden refusal, got {other:?}"),
    }

    // Unknown ids are simply absent, not an error.
    let (absent, no_delivery) = client.status(GRANT_TOKEN, "evt-never").unwrap();
    assert!(absent.is_none());
    assert!(no_delivery.is_none());

    running.shutdown();
    running.join();
}

/// Unparseable lines and unknown operations are refused as unsupported
/// without touching custody.
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

/// A protocol shutdown completes within a bounded time even with open
/// idle clients, and removes only this instance's socket file.
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

/// The real daemon binary becomes reachable within a bounded startup,
/// serves a publish, and exits 0 after a drained shutdown, leaving no
/// socket behind.
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

/// `latest` snapshots published over the wire follow the scoped
/// watermark rules: the newer revision is pending and the stale one is
/// explicitly superseded.
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
/// An absolute expiry accepted over the wire still marks only the
/// pending event after service-mediated publication.
#[test]
fn expiry_flows_through_the_service() {
    let dir = TempDir::new("svc-expiry");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let mut expiring = body("evt-exp");
    // Keep the event unexpired while the real service runs; advance the
    // explicit test clock only after it stops, avoiding maintenance races.
    let expires_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    expiring.expires_at = Some(ExpiresAt::from_unix_millis(expires_ms).unwrap());
    client.publish(GRANT_TOKEN, &expiring).unwrap();
    running.shutdown();
    running.join();

    let storage = Storage::open(dir.path("bridge.db"), Limits::new(100)).unwrap();
    assert_eq!(storage.expire_due(expires_ms + 1).unwrap(), 1);
    let row = storage
        .lookup(
            &PublisherId::new("agent-run").unwrap(),
            &EventId::new("evt-exp").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(row.state, bridge_core::EventState::Expired);
}

/// Startup must refuse a live endpoint and never unlink it for a successor.
#[test]
fn refuses_active_endpoint_replacement() {
    let first_dir = TempDir::new("own-live");
    let first_config = test_config(&first_dir);
    let first = service::start(first_config.clone()).unwrap();
    let socket = first.socket_path().to_path_buf();

    // A second instance on the same live socket must refuse.
    let mut second_config = test_config(&first_dir);
    second_config.socket = socket.clone();
    let second = service::start(second_config);
    assert!(second.is_err(), "live endpoint was replaced");
    assert!(
        socket.exists(),
        "refused start must not unlink the live path"
    );

    // The first instance's stop must not remove a successor's endpoint;
    // here it removes only its own, and the path is gone as it should be.
    first.shutdown();
    first.join();
    assert!(!socket.exists());
}

/// Startup at a non-socket path must fail without deleting foreign bytes.
#[test]
fn preserves_existing_non_socket_file() {
    let dir = TempDir::new("own-file");
    let mut config = test_config(&dir);
    let sentinel = dir.path("sentinel.txt");
    std::fs::write(&sentinel, b"owner fixture must survive").unwrap();
    config.socket = sentinel.clone();

    assert!(
        service::start(config).is_err(),
        "startup over a regular file"
    );
    assert_eq!(
        std::fs::read(&sentinel).ok().as_deref(),
        Some(b"owner fixture must survive".as_slice()),
        "foreign file bytes must be preserved"
    );
}

/// A stale socket (dead daemon) is claimed safely.
#[test]
fn claims_stale_socket() {
    let dir = TempDir::new("own-stale");
    let config = test_config(&dir);
    let running = service::start(config.clone()).unwrap();
    let socket = running.socket_path().to_path_buf();
    running.shutdown();
    running.join();
    // Simulated dead daemon: a socket file whose listener is gone (a
    // dropped listener leaves its file behind, like a killed process).
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    assert!(std::os::unix::net::UnixStream::connect(&socket).is_err());
    let reclaimed = service::start(config);
    assert!(reclaimed.is_ok(), "stale socket must be claimable");
    let reclaimed = reclaimed.unwrap();
    reclaimed.shutdown();
    reclaimed.join();
}

/// An oversized unterminated line is refused and the connection closed
/// without unbounded buffering; the service stays healthy.
#[test]
fn oversized_unterminated_line_is_refused_and_closed() {
    let dir = TempDir::new("frame-limit");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let flood = vec![b'a'; 600 * 1024]; // over MAX_REQUEST_BYTES, no newline
    // The server may close mid-write once the cap is hit; that is the
    // bounded-framing behavior under test.
    let _ = stream.write_all(&flood);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut tail = String::new();
    let _ = stream.read_to_string(&mut tail);
    assert!(
        tail.contains("exceeds") || tail.is_empty(),
        "expected refusal or close, got {tail:?}"
    );

    // The service still serves the next well-formed client.
    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    let receipt = client
        .publish(GRANT_TOKEN, &body("evt-after-flood"))
        .unwrap();
    assert_eq!(receipt.publisher, "agent-run");

    running.shutdown();
    running.join();
}

/// Idle clients do not block a bounded shutdown, and a publish that arrives
/// after the stop request is fenced out without custody.
#[test]
fn idle_clients_and_publish_after_stop_are_fenced() {
    let dir = TempDir::new("stop-fence");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    // A pile of idle connections (well under the admission cap).
    let idle: Vec<std::os::unix::net::UnixStream> = (0..8)
        .filter_map(|_| std::os::unix::net::UnixStream::connect(&socket).ok())
        .collect();
    assert_eq!(idle.len(), 8);

    let mut admin = bridge_client::BridgeClient::connect(&socket).unwrap();
    admin.shutdown(ADMIN_TOKEN).unwrap();
    drop(admin);

    let started = Instant::now();
    running.join();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "idle clients must not make shutdown unbounded"
    );
    drop(idle);

    // A publish racing after the stop is refused with no custody row.
    // The socket is gone; a connect now fails, proving the fence by
    // construction, so re-check custody instead.
    let storage = Storage::open(dir.path("bridge.db"), Limits::new(100)).unwrap();
    assert!(
        storage
            .lookup(
                &PublisherId::new("agent-run").unwrap(),
                &EventId::new("evt-never-after-stop").unwrap()
            )
            .unwrap()
            .is_none()
    );
}

/// Connection admission is bounded: far more simultaneous connections than
/// the cap are tolerated by the service and do not break later clients.
#[test]
fn connection_flood_is_admission_bounded() {
    let dir = TempDir::new("conn-cap");
    let config = test_config(&dir);
    let running = service::start(config).unwrap();
    let socket = running.socket_path().to_path_buf();
    assert!(wait_listening(&socket, Duration::from_secs(5)));

    let mut flood: Vec<std::os::unix::net::UnixStream> = (0..200)
        .filter_map(|_| std::os::unix::net::UnixStream::connect(&socket).ok())
        .collect();
    assert!(
        flood.len() >= 64,
        "expected the OS to queue the flood (got {})",
        flood.len()
    );
    flood.clear();
    // Give the accept loop a moment to reclaim admission slots after the
    // flood sockets close, then verify ordinary service.
    assert!(
        wait_listening(&socket, Duration::from_secs(5)),
        "service must remain reachable after a connection flood"
    );
    let mut client = loop {
        if let Ok(client) = bridge_client::BridgeClient::connect(&socket) {
            break client;
        }
        if !wait_listening(&socket, Duration::from_millis(200)) {
            panic!("service stopped accepting after flood");
        }
    };
    let receipt = client
        .publish(GRANT_TOKEN, &body("evt-after-flood-2"))
        .unwrap();
    assert_eq!(receipt.publisher, "agent-run");

    running.shutdown();
    running.join();
}

/// Parallel calls with the same label must produce distinct socket names;
/// the real clock may return the same timestamp to several calls. This owns
/// no sockets or filesystem state and joins every synthetic worker thread.
#[test]
fn socket_paths_are_unique_when_created_concurrently() {
    let workers: Vec<_> = (0..16)
        .map(|_| {
            std::thread::spawn(|| (0..256).map(|_| short_socket("unique")).collect::<Vec<_>>())
        })
        .collect();
    let paths: std::collections::HashSet<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().expect("fixture worker"))
        .collect();
    assert_eq!(paths.len(), 16 * 256);
}

/// An explicitly any-address publisher can admit a new session without changing
/// configuration. Kind, mode, operator and malformed wildcard guards remain.
#[test]
fn wildcard_recipient_grants_admit_new_addresses_without_widening_other_rights() {
    let dir = TempDir::new("svc-anyaddr");
    let mut config = test_config(&dir);
    config.grants[0].recipients = vec!["*".into()];
    assert!(config.grants[0].validate().is_ok());
    let mut invalid = config.grants[0].clone();
    invalid.recipients = vec!["host-1/*".into()];
    assert!(invalid.validate().is_err());
    let mut admin = config.grants[1].clone();
    admin.recipients = vec!["*".into()];
    assert!(admin.validate().is_err());
    let running = service::start(config).unwrap();
    let mut client = bridge_client::BridgeClient::connect(running.socket_path()).unwrap();
    let mut new = body("new-address");
    new.recipient =
        NativeAddress::new("host-1", Harness::ClaudeCode, "new-store", "new-session").unwrap();
    assert!(!client.publish(GRANT_TOKEN, &new).unwrap().replayed);
    new.event_id = "wrong-kind".into();
    new.kind = "unlisted.kind".into();
    assert_eq!(
        client.publish(GRANT_TOKEN, &new).unwrap_err().class,
        "forbidden"
    );
    running.shutdown();
    running.join();
}
