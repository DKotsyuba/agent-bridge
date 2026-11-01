//! Real CLI/config/socket controls using only synthetic isolated state. No
//! installed daemon, native recipient, model, provider or network is contacted.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use bridge_core::observation::MAX_OBSERVATION_BYTES;
use bridge_core::service::{Config, GrantConfig, PublishBody};
use bridge_core::{Harness, Limits, Mode, NativeAddress, Policy};
use serde_json::{Value, json};

/// Exclusively owned short scratch path, also suitable for macOS Unix sockets.
struct Scratch(PathBuf);

impl Scratch {
    /// Creates a private directory inside the caller's allocated temporary root.
    fn new() -> Self {
        let random = bridge_adapters::os::random_bytes().unwrap();
        let suffix: String = random[..6].iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("bov{suffix}"));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    /// Removes only this fixture's exclusively owned tree.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writes a synthetic private config or credential with the production mode.
fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Runs the actual fixed helper with a closed stdin pipe. Requires exactly one
/// compact JSON output line, no raw stderr, and the complete encoded frame cap.
fn cli(args: &[&str], input: &[u8]) -> (i32, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bridge"))
        .arg("observe")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty(), "no raw error output");
    assert!(output.stdout.len() <= MAX_OBSERVATION_BYTES);
    assert_eq!(output.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

/// One strict helper request line for a fixed operation and parameters.
fn input(operation: &str, params: Value) -> Vec<u8> {
    format!(
        "{}\n",
        json!({"schema_version":1,"operation":operation,"params":params})
    )
    .into_bytes()
}

/// Dedicated observer config works for all four operations and finite pages;
/// missing/misbound observer credentials never borrow the available admin token.
#[test]
fn observe_cli_is_explicit_read_only_and_content_free() {
    let scratch = Scratch::new();
    let socket = scratch.0.join("c.sock");
    let credential = "synthetic-observer-credential";
    let admin = "synthetic-operator-credential";
    let producer = "synthetic-publisher-credential";
    let grant = |token: &str, admin, diagnostics| GrantConfig {
        managed_feedback: false,
        token: token.into(),
        publisher: if diagnostics {
            "observer"
        } else if admin {
            "operator"
        } else {
            "producer"
        }
        .into(),
        recipients: if admin || diagnostics {
            vec![]
        } else {
            vec!["*".into()]
        },
        kinds: if admin || diagnostics {
            vec![]
        } else {
            vec!["note".into()]
        },
        modes: if admin || diagnostics {
            vec![]
        } else {
            vec!["message".into()]
        },
        policies: if admin || diagnostics {
            vec![]
        } else {
            vec!["keep_all".into()]
        },
        admin,
        diagnostics,
        producer_v1: None,
    };
    let core = bridge_core::start_service(Config {
        database: scratch.0.join("bridge.db"),
        socket: socket.clone(),
        limits: Limits::new(100),
        grants: vec![
            grant(credential, false, true),
            grant(admin, true, false),
            grant(producer, false, false),
        ],
        universal_limits: Default::default(),
    })
    .unwrap();
    let config = scratch.0.join("interfaces.toml");
    let token_file = scratch.0.join("observer.token");
    let admin_file = scratch.0.join("operator.token");
    private(&token_file, credential);
    private(&admin_file, admin);
    let config_text = format!(
        "core_socket = {:?}\n[observer]\ntoken_file = {:?}\n[operator]\ntoken_file = {:?}\n",
        socket, token_file, admin_file
    );
    private(&config, &config_text);
    let args = ["--config", config.to_str().unwrap()];
    let mut client = bridge_client::BridgeClient::connect(&socket).unwrap();
    for seq in 0..3 {
        client
            .publish(
                producer,
                &PublishBody {
                    event_id: format!("event-{seq}"),
                    recipient: NativeAddress::new(
                        "PRIVATE_HOST",
                        Harness::CODEX,
                        "PRIVATE_STORE",
                        "PRIVATE_SESSION",
                    )
                    .unwrap(),
                    kind: "note".into(),
                    mode: Mode::Message,
                    policy: Policy::KeepAll,
                    payload: "PRIVATE_BODY_SECRET".into(),
                    metadata: Default::default(),
                    expires_at: None,
                },
            )
            .unwrap();
    }
    for (op, kind) in [
        ("identity", "identity"),
        ("overview", "bridge_overview"),
        ("deliveries", "delivery_page"),
        ("incidents", "incident_page"),
    ] {
        let (code, value) = cli(&args, &input(op, json!({})));
        assert_eq!(code, 0, "{value}");
        assert_eq!(value["kind"], kind);
        assert_eq!(value["schema_version"], 1);
        assert!(value.get("data").is_some());
        assert!(value.get("error").is_none());
        let encoded = value.to_string();
        for secret in [
            "PRIVATE_",
            credential,
            admin,
            producer,
            "token_file",
            "envelope_json",
            "native_session_id",
        ] {
            assert!(!encoded.contains(secret), "{secret}");
        }
        assert!(!encoded.contains("\"payload\":"));
    }
    let (_, first) = cli(&args, &input("deliveries", json!({"limit":2})));
    assert_eq!(first["data"]["deliveries"].as_array().unwrap().len(), 2);
    assert_eq!(first["data"]["next_after_seq"], 2);
    let (_, last) = cli(
        &args,
        &input(
            "deliveries",
            json!({"limit":2,"after_seq":2,"through_seq":3}),
        ),
    );
    assert_eq!(last["data"]["deliveries"].as_array().unwrap().len(), 1);
    assert!(last["data"]["next_after_seq"].is_null());
    let (_, before) = cli(&args, &input("overview", json!({})));
    for secret in [admin, producer, "unknown-fixture-credential"] {
        private(&token_file, secret);
        let (code, value) = cli(&args, &input("identity", json!({})));
        assert_eq!(code, 2);
        assert_eq!(value["error"]["code"], "observer_denied");
        assert_eq!(value["error"]["outcome"], "blocked");
        assert!(value.get("data").is_none());
    }
    private(&token_file, credential);
    private(
        &config,
        &format!(
            "core_socket = {:?}\n[operator]\ntoken_file = {:?}\n",
            socket, admin_file
        ),
    );
    let (_, value) = cli(&args, &input("identity", json!({})));
    assert_eq!(value["error"]["code"], "observer_unconfigured");
    private(&config, &config_text);
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        cli(&args, &input("identity", json!({}))).1["error"]["code"],
        "invalid_credential"
    );
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (_, after) = cli(&args, &input("overview", json!({})));
    assert_eq!(before["data"], after["data"]);
    assert!(
        core.with_storage(|s| s.audit_entries(100).unwrap())
            .is_empty()
    );
    assert!(core.is_running());
    core.shutdown();
    core.join();
    assert!(!socket.exists());
    let (_, value) = cli(&args, &input("identity", json!({})));
    assert_eq!(value["error"]["outcome"], "unavailable");
    assert!(!socket.exists(), "helper cannot start or recover a daemon");
}

/// Closed argv/stdin/schema rejects malformed or arbitrary operations with one
/// generic error line and no connection, echoed secrets or successful data.
#[test]
fn observe_cli_refuses_malformed_frames_and_missing_configuration() {
    let identity = input("identity", json!({}));
    assert_eq!(
        cli(&[], &identity).1["error"]["code"],
        "observer_unconfigured"
    );
    for args in [
        vec!["--config", "relative"],
        vec!["--method", "publish"],
        vec!["--config", "/ABS/config", "--token", "PRIVATE_ARG"],
    ] {
        let (code, value) = cli(&args, &identity);
        assert_eq!(code, 2);
        assert_eq!(value["error"]["code"], "invalid_arguments");
        assert!(!value.to_string().contains("PRIVATE_ARG"));
    }
    let frames = [
        Vec::new(), b"not JSON PRIVATE_SECRET\n".to_vec(), b"{\"schema_version\":1}\n".to_vec(),
        b"{\"schema_version\":2,\"operation\":\"identity\",\"params\":{}}\n".to_vec(),
        b"{\"schema_version\":1,\"operation\":\"identity\",\"params\":{},\"token\":\"PRIVATE_SECRET\"}\n".to_vec(),
        input("identity",json!({"token":"PRIVATE_SECRET"})),input("publish",json!({})),
        b"{}\n{}\n".to_vec(), b"{}".to_vec(),vec![0xff,b'\n'],
        vec![b'x';bridge_interfaces::observe::MAX_INPUT_BYTES+1],
    ];
    for frame in frames {
        let (code, value) = cli(&[], &frame);
        assert_eq!(code, 2);
        assert!(value.get("error").is_some());
        assert!(value.get("data").is_none());
        assert!(!value.to_string().contains("PRIVATE_SECRET"));
    }
}
