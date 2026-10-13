//! Cross-process composition of the root surface with the real core
//! service, the real adapter registry and channel, and the real
//! `bridge-root-mcp` and `bridge-root-relay` executables.
//!
//! Evidence level: contract wiring over real kernel identities, NOT native
//! host qualification. The harness is a labeled stand-in: this very test
//! executable re-run with `BRIDGE_IF_ROLE=harness`, qualified in an owned
//! test profile by its own path and SHA-256. Its hooks are this executable
//! re-run with `BRIDGE_IF_ROLE=hook` calling the product hook client
//! (`ChannelClient::run_hook`) with Claude-shaped hook JSON. The frontend is
//! started by the stand-in harness through `/bin/sh`, so the registry
//! attests it as a harness descendant exactly as for a real harness, and
//! the relay is a configured relay executable started by the test. Every
//! store, socket, database and token is a fresh owned file under the configured
//! temporary root.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_adapters::ChannelClient;
use bridge_adapters::registry::{
    CallerAttestor, Profile, QualifiedExecutable, Registry, RegistryConfig, RelayExecutable,
    SealedProof, Unattested, file_sha256,
};
use bridge_adapters::server::{ChannelServer, Custody, private_directory};
use bridge_client::BridgeClient;
use bridge_core::dispatch::DispatchTiming;
use bridge_core::service::{Config, GrantConfig, start_with_carriers};
use bridge_core::{Harness, NativeAddress};
use bridge_interfaces::config::InterfacesConfig;
use bridge_interfaces::root::{RelayRequest, RootRelay, call_relay};
use serde_json::{Value, json};

/// Root publisher grant token of the relay (test-only value).
const ROOT_TOKEN: &str = "root-relay-token-0123456789";

/// Operator grant token (test-only value).
const OPERATOR_TOKEN: &str = "operator-token-0123456789ab";

/// Host id of the lab.
const HOST: &str = "lab";

/// Claude store namespace of the lab.
const NAMESPACE: &str = "claude-lab";

/// Second Claude store namespace of the lab (same harness build).
const NAMESPACE2: &str = "claude-lab2";

/// Role dispatcher: a no-op test normally; the harness or hook role when
/// re-run by the composition test.
#[test]
fn role_entry() {
    match std::env::var("BRIDGE_IF_ROLE").as_deref() {
        Ok("harness") => harness_loop(),
        Ok("hook") => hook_role(),
        _ => return,
    }
    std::process::exit(0);
}

/// Stand-in harness: one JSON command per stdin line, one `@@`-prefixed
/// JSON answer per command on stdout.
fn harness_loop() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return };
        let command: Value = serde_json::from_str(&line).unwrap();
        let answer = match command["cmd"].as_str().unwrap() {
            "hook" => {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "role_entry",
                        "--nocapture",
                        "--test-threads",
                        "1",
                    ])
                    .env("BRIDGE_IF_ROLE", "hook")
                    .env("HOOK_SOCKET", command["socket"].as_str().unwrap())
                    .env(
                        if command["lost"] == true {
                            "HOOK_LOST"
                        } else {
                            "HOOK_KEEP"
                        },
                        "1",
                    )
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(command["payload"].to_string().as_bytes())
                    .unwrap();
                let mut out = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut out)
                    .unwrap();
                child.wait().unwrap();
                json!({"stdout": out})
            }
            "mcp" => {
                let mut child = Command::new("/bin/sh")
                    .args(["-c", r#""$0" "$1" "$2""#])
                    .arg(command["bin"].as_str().unwrap())
                    .arg(command["channel"].as_str().unwrap())
                    .arg(command["relay"].as_str().unwrap())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let mut input = child.stdin.take().unwrap();
                for request in command["requests"].as_array().unwrap() {
                    writeln!(input, "{request}").unwrap();
                }
                drop(input);
                let mut out = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut out)
                    .unwrap();
                child.wait().unwrap();
                let lines: Vec<Value> = out
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                json!({"responses": lines})
            }
            other => json!({"error": other}),
        };
        writeln!(stdout, "@@{answer}").unwrap();
        stdout.flush().unwrap();
    }
}

/// A hook stdout that is already gone (the harness lost the reply).
struct LostStdout;

impl Write for LostStdout {
    /// Always fails: nothing reaches the harness.
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    /// Always fails.
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// Hook role: forwards stdin JSON to the channel with the product hook
/// client and prints what the hook would print. With `HOOK_LOST` set the
/// hook's stdout fails, so the drained reply is never confirmed.
fn hook_role() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let client = ChannelClient::new(
        std::env::var("HOOK_SOCKET").unwrap(),
        Duration::from_secs(5),
    );
    let mut out = Vec::new();
    let run = if std::env::var_os("HOOK_LOST").is_some() {
        client.run_hook(Harness::ClaudeCode, &input, &mut LostStdout)
    } else {
        client.run_hook(Harness::ClaudeCode, &input, &mut out)
    };
    print!("@@HOOK{}@@{:?}", String::from_utf8_lossy(&out), run);
}

/// A running stand-in harness.
struct Harnessed {
    /// The process.
    child: Child,
    /// Command input.
    stdin: ChildStdin,
    /// Answers.
    stdout: BufReader<ChildStdout>,
}

impl Harnessed {
    /// Starts the stand-in with `CLAUDE_CONFIG_DIR=store`.
    fn start(store: &Path) -> Harnessed {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "role_entry",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("BRIDGE_IF_ROLE", "harness")
            .env("CLAUDE_CONFIG_DIR", store)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Harnessed {
            child,
            stdin,
            stdout,
        }
    }

    /// One command and its answer (libtest noise lines are skipped).
    fn cmd(&mut self, command: Value) -> Value {
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "harness ended"
            );
            // libtest prints `test role_entry ... ` without a newline first.
            if let Some(start) = line.find("@@") {
                return serde_json::from_str(line[start + 2..].trim_end()).unwrap();
            }
        }
    }
}

impl Drop for Harnessed {
    /// Ends the stand-in.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The lab: core service, registry/channel, relay process and paths.
struct Lab {
    /// Root directory.
    dir: PathBuf,
    /// Claude store of the stand-in harness.
    store: PathBuf,
    /// A second Claude store (namespace [`NAMESPACE2`]) whose sessions may
    /// reuse the same native ids.
    store2: PathBuf,
    /// Adapter channel socket.
    channel_socket: PathBuf,
    /// Relay socket.
    relay_socket: PathBuf,
    /// Core socket.
    core_socket: PathBuf,
    /// Interfaces configuration file.
    config_path: PathBuf,
    /// The relay process.
    relay: Child,
    /// The channel server.
    channel: Option<ChannelServer>,
    /// The core service.
    core: Option<Arc<bridge_core::Running>>,
}

impl Drop for Lab {
    /// Stops everything and removes the owned tree.
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-TERM", &self.relay.id().to_string()])
            .status();
        let _ = self.relay.wait();
        if let Some(channel) = self.channel.take() {
            channel.stop();
        }
        if let Some(core) = self.core.take() {
            core.shutdown();
            if let Ok(core) = Arc::try_unwrap(core) {
                core.join();
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Canonical address of a lab Claude session.
fn claude(session: &str) -> NativeAddress {
    NativeAddress::new(HOST, Harness::ClaudeCode, NAMESPACE, session).unwrap()
}

/// Structured recipient argument for a session.
fn recipient(session: &str) -> Value {
    json!({"host_id": HOST, "harness": "claude-code",
           "native_store_namespace": NAMESPACE, "native_session_id": session})
}

/// Writes a 0600 secret file.
fn secret(path: &Path, value: &str) {
    std::fs::write(path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Exclusively creates `bi<tag><12 random hex>` under the configured temporary
/// root with mode `0700`, where `tag` is the literal test label. Never reuses or
/// clears an existing path; panics on non-collision errors or after 16 collisions.
/// The root must leave room for descendant sockets within macOS's approximately
/// 104-byte ceiling; the lab owns cleanup of the returned canonical directory.
fn scratch(tag: &str) -> PathBuf {
    for _ in 0..16 {
        let random = bridge_adapters::os::random_bytes().unwrap();
        let suffix: String = random[..6].iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("bi{tag}{suffix}"));
        match std::fs::create_dir(&dir) {
            Ok(()) => {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                return dir.canonicalize().unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("cannot create scratch: {error}"),
        }
    }
    panic!("no free scratch name");
}

/// Builds and starts the lab in a fresh scratch directory (removed, only
/// it, when the lab drops).
fn lab(tag: &str) -> Lab {
    lab_with_addresses(tag, false)
}

/// Builds the existing process lab; `any` enables any canonical recipient and
/// concise message defaults solely in the new policy test. Legacy labs retain
/// their original exact grants and forbidden kind/mode cases. When the inherited
/// Desktop capabilities select the signed Node frontend, only its exact canonical
/// executable is admitted as an intermediate; the stand-in harness still must
/// match its qualified executable digest and owned store. A different selected
/// frontend or unavailable executable panics before starting the registry.
fn lab_with_addresses(tag: &str, any: bool) -> Lab {
    let dir = scratch(tag);
    let store = dir.join("cs");
    std::fs::create_dir_all(&store).unwrap();
    let store2 = dir.join("cs2");
    std::fs::create_dir_all(&store2).unwrap();
    let core_socket = dir.join("core.sock");
    let grants = vec![
        GrantConfig {
            token: ROOT_TOKEN.into(),
            publisher: "bridge-root".into(),
            recipients: if any {
                vec!["*".into()]
            } else {
                ["s1", "s2"]
                    .iter()
                    .map(|session| claude(session).to_canonical_string())
                    .collect()
            },
            kinds: if any {
                vec!["root.note".into(), "bridge.message".into()]
            } else {
                vec!["root.note".into()]
            },
            modes: if any {
                vec!["inject".into(), "auto".into(), "message".into()]
            } else {
                vec!["inject".into(), "auto".into()]
            },
            policies: vec!["keep_all".into()],
            admin: false,
            producer_v1: None,
        },
        GrantConfig {
            token: OPERATOR_TOKEN.into(),
            publisher: "bridge-ops".into(),
            recipients: vec![],
            kinds: vec![],
            modes: vec![],
            policies: vec![],
            admin: true,
            producer_v1: None,
        },
    ];
    let core = Arc::new(
        start_with_carriers(
            Config {
                database: dir.join("bridge.db"),
                socket: core_socket.clone(),
                limits: serde_json::from_value(json!({"max_admitted_events": 1000})).unwrap(),
                universal_limits: Default::default(),
                grants,
            },
            Vec::new(),
        )
        .unwrap(),
    );
    let channel_dir = dir.join("ch");
    let owner = private_directory(&channel_dir).unwrap();
    let channel_socket = channel_dir.join("c.sock");
    let harness_exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let relay_exe = PathBuf::from(env!("CARGO_BIN_EXE_bridge-root-relay"))
        .canonicalize()
        .unwrap();
    let mut intermediates: Vec<_> = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(node) = std::env::var_os("CODEX_APP_TOOLS_PIPE_PATH")
        .and_then(|_| std::env::var_os("CODEX_MCP_NODE_PATH"))
    {
        let node = PathBuf::from(node).canonicalize().unwrap();
        let signed =
            PathBuf::from("/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node")
                .canonicalize()
                .unwrap();
        assert_eq!(node, signed, "unexpected Desktop frontend executable");
        intermediates.push(node);
    }
    let registry = Registry::new(
        RegistryConfig {
            host_id: HOST.into(),
            profiles: [(NAMESPACE, &store), (NAMESPACE2, &store2)]
                .into_iter()
                .map(|(namespace, store)| Profile {
                    namespace: namespace.into(),
                    harness: Harness::ClaudeCode,
                    store: store.clone(),
                    executables: vec![QualifiedExecutable {
                        sha256: file_sha256(&harness_exe).unwrap(),
                        path: harness_exe.clone(),
                        version: "stand-in".into(),
                        inject: true,
                        message: false,
                    }],
                })
                .collect(),
            intermediates,
            max_call_age_ms: 600_000,
            relays: vec![RelayExecutable {
                sha256: file_sha256(&relay_exe).unwrap(),
                path: relay_exe.clone(),
            }],
            audiences: Vec::new(),
        },
        owner,
    )
    .unwrap();
    let channel = ChannelServer::start(
        &channel_socket,
        Arc::new(Mutex::new(registry)),
        Arc::clone(&core) as Arc<dyn Custody>,
        DispatchTiming::default(),
    )
    .unwrap();
    let relay_dir = dir.join("rl");
    private_directory(&relay_dir).unwrap();
    let relay_socket = relay_dir.join("r.sock");
    let token_file = relay_dir.join("token");
    secret(&token_file, ROOT_TOKEN);
    let operator_file = relay_dir.join("operator");
    secret(&operator_file, OPERATOR_TOKEN);
    let config_path = dir.join("interfaces.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"core_socket = "{core}"
[operator]
token_file = "{operator}"
[notify]
ledger = "{ledger}"
[root]
socket = "{relay}"
token_file = "{token}"
channel = "{channel}"
max_body_bytes = 64
[[root.callers]]
host_id = "{HOST}"
harness = "claude-code"
native_store_namespace = "{NAMESPACE}"
recipients = ["{s1}", "{s2}"]
modes = ["inject", "auto"]
kinds = ["root.note"]
[[root.callers]]
host_id = "{HOST}"
harness = "claude-code"
native_store_namespace = "{NAMESPACE2}"
recipients = ["{s2}"]
modes = ["inject"]
kinds = ["root.note"]
"#,
            core = core_socket.display(),
            operator = operator_file.display(),
            ledger = dir.join("ledger.json").display(),
            relay = relay_socket.display(),
            token = token_file.display(),
            channel = channel_socket.display(),
            s1 = claude("s1").to_canonical_string(),
            s2 = claude("s2").to_canonical_string(),
        ),
    )
    .unwrap();
    if any {
        let text = std::fs::read_to_string(&config_path).unwrap();
        let text = text
            .replace(
                &format!(
                    "recipients = [\"{}\", \"{}\"]",
                    claude("s1").to_canonical_string(),
                    claude("s2").to_canonical_string()
                ),
                "recipients = [\"*\"]",
            )
            .replace(
                "modes = [\"inject\", \"auto\"]",
                "modes = [\"inject\", \"auto\", \"message\"]",
            )
            .replace(
                "kinds = [\"root.note\"]",
                "kinds = [\"root.note\", \"bridge.message\"]",
            );
        std::fs::write(&config_path, text).unwrap();
    }
    let relay = Command::new(&relay_exe)
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::os::unix::net::UnixStream::connect(&relay_socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Lab {
        dir,
        store,
        store2,
        channel_socket,
        relay_socket,
        core_socket,
        config_path,
        relay,
        channel: Some(channel),
        core: Some(core),
    }
}

impl Lab {
    /// Runs one hook payload through the stand-in harness.
    fn hook(&self, harness: &mut Harnessed, payload: Value) -> String {
        harness.cmd(json!({"cmd": "hook", "socket": self.channel_socket, "payload": payload}))
            ["stdout"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Runs one hook whose stdout is lost before it can print.
    fn hook_lost(&self, harness: &mut Harnessed, payload: Value) -> String {
        harness.cmd(
            json!({"cmd": "hook", "socket": self.channel_socket, "payload": payload, "lost": true}),
        )["stdout"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Runs the real `bridge` CLI with this lab's configuration; returns
    /// the exit code and parsed stdout (or `null`).
    fn cli(&self, args: &[&str]) -> (i32, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_bridge"))
            .args(args.iter().map(|arg| {
                if *arg == "@config" {
                    self.config_path.display().to_string()
                } else {
                    (*arg).to_string()
                }
            }))
            .output()
            .unwrap();
        (
            output.status.code().unwrap_or(-1),
            serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
        )
    }

    /// Records a `PreToolUse` for `call` (optionally from a child agent),
    /// then runs one `tools/call` through the real frontend with that
    /// call's `_meta`; returns the tool result.
    fn call(
        &self,
        harness: &mut Harnessed,
        session: &str,
        call: &str,
        agent: Option<&str>,
        tool: &str,
        arguments: Value,
    ) -> Value {
        let mut payload = json!({"hook_event_name": "PreToolUse", "session_id": session,
                                 "tool_use_id": call, "tool_name": format!("mcp__bridge__{tool}")});
        if let Some(agent) = agent {
            payload["agent_id"] = json!(agent);
        }
        self.hook(harness, payload);
        self.frontend(
            harness,
            json!({"claudecode/toolUseId": call}),
            tool,
            arguments,
        )
    }

    /// One `tools/call` through the real frontend with explicit `_meta`.
    fn frontend(
        &self,
        harness: &mut Harnessed,
        meta: Value,
        tool: &str,
        arguments: Value,
    ) -> Value {
        let mut params = json!({"name": tool, "arguments": arguments});
        if !meta.is_null() {
            params["_meta"] = meta;
        }
        let answer = harness.cmd(json!({
            "cmd": "mcp",
            "bin": env!("CARGO_BIN_EXE_bridge-root-mcp"),
            "channel": self.channel_socket,
            "relay": self.relay_socket,
            "requests": [
                {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params},
            ],
        }));
        answer["responses"][1]["result"].clone()
    }
}

/// The class of a refused tool result (or `ok`).
fn class(result: &Value) -> String {
    if result["isError"] == true {
        result["structuredContent"]["error"]
            .as_str()
            .unwrap()
            .to_string()
    } else {
        "ok".into()
    }
}

/// The root tools over a real core and adapter carry the attested caller, refuse
/// replayed, missing, mixed and subagent calls, and keep `bridge_send` bounded,
/// allowlisted, idempotent and custody-only until the recipient hook drains it.
#[test]
fn root_tools_compose_with_core_and_adapter_attestation() {
    let lab = lab("c");
    let mut harness = Harnessed::start(&lab.store);
    for session in ["s1", "s2"] {
        lab.hook(
            &mut harness,
            json!({"hook_event_name": "SessionStart", "session_id": session, "cwd": "/ignored"}),
        );
    }

    // me: the registry-attested root caller, never an argument.
    let me = lab.call(&mut harness, "s1", "call-me", None, "bridge_me", json!({}));
    assert_eq!(class(&me), "ok", "{me}");
    let caller = &me["structuredContent"]["caller"];
    assert_eq!(caller["canonical"], claude("s1").to_canonical_string());
    assert_eq!(caller["role"], "root");
    assert_eq!(me["structuredContent"]["permitted"]["policy"], "keep_all");

    // The consumed call record cannot be replayed.
    let replay = lab.frontend(
        &mut harness,
        json!({"claudecode/toolUseId": "call-me"}),
        "bridge_me",
        json!({}),
    );
    assert_eq!(class(&replay), "caller_duplicate");
    // Unknown call id, no _meta at all, foreign-host fields: refused.
    let missing = lab.frontend(
        &mut harness,
        json!({"claudecode/toolUseId": "never"}),
        "bridge_me",
        json!({}),
    );
    assert_eq!(class(&missing), "caller_missing");
    let bare = lab.frontend(&mut harness, Value::Null, "bridge_me", json!({}));
    assert_eq!(class(&bare), "caller_not_evidence");
    let mixed = lab.frontend(
        &mut harness,
        json!({"claudecode/toolUseId": "x", "threadId": "t"}),
        "bridge_me",
        json!({}),
    );
    assert_eq!(class(&mixed), "caller_not_evidence");

    // A subagent sharing the root session is refused, never redirected.
    let child = lab.call(&mut harness, "s1", "call-child", Some("agent-7"), "bridge_send", json!({
        "request_id": "c1", "recipient": recipient("s2"), "kind": "root.note", "mode": "inject", "body": "x"}));
    assert_eq!(class(&child), "forbidden");

    // Model-asserted identity is not a field: closed schema refuses.
    let forged = lab.call(
        &mut harness,
        "s1",
        "call-forged",
        None,
        "bridge_me",
        json!({"caller": "s2"}),
    );
    assert_eq!(class(&forged), "invalid");

    // Send: keep_all custody to an exact allowlisted recipient.
    let send_args = json!({"request_id": "r1", "recipient": recipient("s2"), "kind": "root.note",
                           "mode": "inject", "body": "hello <b>"});
    let sent = lab.call(
        &mut harness,
        "s1",
        "call-send-1",
        None,
        "bridge_send",
        send_args.clone(),
    );
    assert_eq!(class(&sent), "ok", "{sent}");
    assert_eq!(sent["structuredContent"]["custody"]["state"], "accepted");
    assert_eq!(sent["structuredContent"]["custody"]["replayed"], false);
    let again = lab.call(
        &mut harness,
        "s1",
        "call-send-2",
        None,
        "bridge_send",
        send_args.clone(),
    );
    assert_eq!(
        again["structuredContent"]["custody"]["replayed"], true,
        "idempotent replay"
    );
    let mut changed = send_args.clone();
    changed["body"] = json!("different");
    let conflict = lab.call(
        &mut harness,
        "s1",
        "call-send-3",
        None,
        "bridge_send",
        changed,
    );
    assert_eq!(class(&conflict), "conflict");

    // Bounds and allowlists.
    let mut big = send_args.clone();
    big["request_id"] = json!("r-big");
    big["body"] = json!("x".repeat(65));
    assert_eq!(
        class(&lab.call(&mut harness, "s1", "call-big", None, "bridge_send", big)),
        "oversize"
    );
    let mut stranger = send_args.clone();
    stranger["request_id"] = json!("r-x");
    stranger["recipient"] = recipient("s9");
    assert_eq!(
        class(&lab.call(&mut harness, "s1", "call-x", None, "bridge_send", stranger)),
        "forbidden"
    );
    let mut message = send_args.clone();
    message["request_id"] = json!("r-m");
    message["mode"] = json!("message");
    assert_eq!(
        class(&lab.call(&mut harness, "s1", "call-m", None, "bridge_send", message)),
        "forbidden"
    );
    let mut expired = send_args.clone();
    expired["request_id"] = json!("r-e");
    expired["expires_at_ms"] = json!(1);
    assert_eq!(
        class(&lab.call(&mut harness, "s1", "call-e", None, "bridge_send", expired)),
        "expired"
    );

    // Before any hook drain: custody only, no native or context claim.
    let before = lab.call(
        &mut harness,
        "s1",
        "call-st-1",
        None,
        "bridge_status",
        json!({"request_id": "r1"}),
    );
    assert_eq!(before["structuredContent"]["custody"]["state"], "accepted");
    assert_eq!(
        before["structuredContent"]["native"], "not_handed",
        "{before}"
    );
    assert_eq!(before["structuredContent"]["context"], "not_available");

    // The recipient's natural hook drains the framed, escaped event.
    let drained = lab.hook(
        &mut harness,
        json!({"hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": "hi"}),
    );
    assert!(drained.contains("bridge-root"), "{drained}");
    assert!(drained.contains("hello &lt;b&gt;"), "{drained}");
    let after = lab.call(
        &mut harness,
        "s1",
        "call-st-2",
        None,
        "bridge_status",
        json!({"request_id": "r1"}),
    );
    assert_eq!(
        after["structuredContent"]["native"], "hook_emitted",
        "{after}"
    );
    assert_eq!(after["structuredContent"]["context"], "not_available");

    // Status is own-request only: the recipient cannot read the sender's id.
    let foreign = lab.call(
        &mut harness,
        "s2",
        "call-st-3",
        None,
        "bridge_status",
        json!({"request_id": "r1"}),
    );
    assert_eq!(
        foreign["structuredContent"]["custody"]["state"],
        "not_found"
    );

    // A forged proof presented directly to the relay is refused.
    let direct = call_relay(
        &lab.relay_socket,
        &RelayRequest {
            proof: SealedProof::from_wire("00".repeat(32)),
            tool: "bridge_me".into(),
            arguments: json!({}),
        },
    );
    assert_eq!(
        serde_json::to_value(&direct).unwrap()["class"],
        "caller_missing"
    );

    // The relay's core credential is a keep_all publisher grant only: no
    // operator, enumeration or coalescing power over direct RPC.
    let mut client = BridgeClient::connect(&lab.core_socket).unwrap();
    assert!(client.incidents(ROOT_TOKEN, false, None).is_err());
    assert!(client.shutdown(ROOT_TOKEN).is_err());
    let latest = bridge_client::PublishRequest::new(
        bridge_client::EventId::new("direct-latest").unwrap(),
        claude("s2"),
        bridge_client::Kind::new("root.note").unwrap(),
        bridge_client::Mode::Inject,
        bridge_client::Policy::Latest {
            stream: bridge_client::StreamId::new("s").unwrap(),
            revision: 1,
        },
        bridge_client::Payload::new("x").unwrap(),
    )
    .into_body()
    .unwrap();
    assert_eq!(
        client.publish(ROOT_TOKEN, &latest).unwrap_err().class,
        "forbidden"
    );
    assert!(client.incidents(OPERATOR_TOKEN, false, None).is_ok());
    drop(harness);
}

/// A hook reply that never arrives leaves the native tier unknown and a manual
/// incident, and the payload is never resent.
#[test]
fn lost_hook_reply_stays_a_manual_incident_without_resend() {
    let lab = lab("u");
    let mut harness = Harnessed::start(&lab.store);
    for session in ["s1", "s2"] {
        lab.hook(
            &mut harness,
            json!({"hook_event_name": "SessionStart", "session_id": session, "cwd": "/ignored"}),
        );
    }
    let sent = lab.call(
        &mut harness,
        "s1",
        "u-send",
        None,
        "bridge_send",
        json!({
        "request_id": "u1", "recipient": recipient("s2"), "kind": "root.note",
        "mode": "inject", "body": "possibly delivered"}),
    );
    assert_eq!(class(&sent), "ok", "{sent}");
    // The drain hands the payload to a hook whose stdout is gone.
    lab.hook_lost(
        &mut harness,
        json!({"hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": "hi"}),
    );
    let mut status = Value::Null;
    for attempt in 0..60 {
        status = lab.call(
            &mut harness,
            "s1",
            &format!("u-st-{attempt}"),
            None,
            "bridge_status",
            json!({"request_id": "u1"}),
        );
        if status["structuredContent"]["native"] == "unknown" {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let view = &status["structuredContent"];
    assert_eq!(view["native"], "unknown", "{status}");
    assert_eq!(view["uncertainty"]["manual_resolution_required"], true);
    assert_eq!(view["uncertainty"]["automatic_resend"], false);

    // The next natural hook does not re-offer the uncertain event.
    let next = lab.hook(
        &mut harness,
        json!({"hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": "again"}),
    );
    assert!(!next.contains("possibly delivered"), "{next}");

    // Operator view through the real CLI: retained, classified, actionable.
    let (code, listed) = lab.cli(&["operator", "@config", "incidents"]);
    assert_eq!(code, 0, "{listed}");
    let incident = listed["incidents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|incident| incident["kind"] == "unknown_handoff")
        .cloned()
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(incident["category"], "unknown");
    assert!(
        incident["next_action"]
            .as_str()
            .unwrap()
            .contains("Never resent")
    );
    let publisher = incident["publisher"].as_str().unwrap().to_string();
    let event = incident["event_id"].as_str().unwrap().to_string();

    // Owner notification with no channel: visibly not notified.
    let (code, notified) = lab.cli(&["notify", "@config"]);
    assert_eq!(code, 0, "{notified}");
    assert_eq!(notified["channel"], "unconfigured");
    let line = &notified["incidents"][0];
    assert_eq!(line["notification"], "known_unsent");
    assert_eq!(line["owner_read"], "unknown");
    assert!(line["detail"].as_str().unwrap().contains("not notified"));

    // A same-event retry needs explicit duplicate-risk acceptance.
    let (code, _) = lab.cli(&[
        "operator", "@config", "retry", &publisher, &event, "--note", "x",
    ]);
    assert_eq!(code, 2, "refused without --accept-duplicate-risk");
    let (_, still) = lab.cli(&["operator", "@config", "incidents"]);
    assert!(
        still["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["kind"] == "unknown_handoff")
    );

    // An audited disposition closes it without claiming delivery.
    let (code, applied) = lab.cli(&[
        "operator",
        "@config",
        "dispose",
        &publisher,
        &event,
        "--note",
        "owner confirmed receipt out of band",
    ]);
    assert_eq!(code, 0, "{applied}");
    let after = lab.call(
        &mut harness,
        "s1",
        "u-st-final",
        None,
        "bridge_status",
        json!({"request_id": "u1"}),
    );
    // The disposition closes the workflow but never claims non-delivery: the
    // earlier possible hand-off stays unknown, with its uncertainty kept.
    assert_eq!(after["structuredContent"]["native"], "unknown", "{after}");
    assert_eq!(
        after["structuredContent"]["delivery"]["state"], "disposed",
        "{after}"
    );
    assert_eq!(
        after["structuredContent"]["uncertainty"]["disposed"], true,
        "{after}"
    );
    assert_eq!(
        after["structuredContent"]["uncertainty"]["automatic_resend"], false,
        "{after}"
    );
    let (_, closed) = lab.cli(&["operator", "@config", "incidents", "--all"]);
    assert!(
        closed["incidents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["kind"] == "unknown_handoff" && i["state"] == "disposed")
    );
    drop(harness);
}

/// Equal session ids in different native stores are distinct callers: neither
/// replays nor sees the other's events.
#[test]
fn equal_session_ids_in_two_stores_never_share_events() {
    let lab = lab("n");
    // Two stand-in harnesses, one per store, each with a root session
    // whose native id is the same `s1`.
    let mut first = Harnessed::start(&lab.store);
    let mut second = Harnessed::start(&lab.store2);
    let start = |session: &str| json!({"hook_event_name": "SessionStart", "session_id": session, "cwd": "/ignored"});
    lab.hook(&mut first, start("s1"));
    lab.hook(&mut first, start("s2"));
    lab.hook(&mut second, start("s1"));
    let send = json!({"request_id": "same", "recipient": recipient("s2"), "kind": "root.note",
                      "mode": "inject", "body": "same body"});
    let from_first = lab.call(&mut first, "s1", "n-1", None, "bridge_send", send.clone());
    let from_second = lab.call(&mut second, "s1", "n-2", None, "bridge_send", send.clone());
    assert_eq!(class(&from_first), "ok", "{from_first}");
    assert_eq!(class(&from_second), "ok", "{from_second}");
    let (one, two) = (
        &from_first["structuredContent"]["custody"],
        &from_second["structuredContent"]["custody"],
    );
    assert_eq!(one["replayed"], false);
    assert_eq!(
        two["replayed"], false,
        "a foreign store's caller is not a replay"
    );
    assert_ne!(one["envelope_hash"], two["envelope_hash"]);
    // Each caller sees exactly its own event.
    let me_second = lab.call(&mut second, "s1", "n-3", None, "bridge_me", json!({}));
    assert_eq!(
        me_second["structuredContent"]["caller"]["address"]["native_store_namespace"],
        NAMESPACE2
    );
    let status_second = lab.call(
        &mut second,
        "s1",
        "n-4",
        None,
        "bridge_status",
        json!({"request_id": "same"}),
    );
    assert_eq!(
        status_second["structuredContent"]["custody"]["envelope_hash"],
        two["envelope_hash"]
    );
    let status_first = lab.call(
        &mut first,
        "s1",
        "n-5",
        None,
        "bridge_status",
        json!({"request_id": "same"}),
    );
    assert_eq!(
        status_first["structuredContent"]["custody"]["envelope_hash"],
        one["envelope_hash"]
    );
    // Both events reach the recipient, one per natural hook, as two
    // distinct framed events.
    let prompt = json!({"hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": "hi"});
    let drained = [
        lab.hook(&mut first, prompt.clone()),
        lab.hook(&mut first, prompt),
    ];
    let ids: std::collections::BTreeSet<&str> = drained
        .iter()
        .filter_map(|out| out.split("event=\\\"").nth(1))
        .filter_map(|rest| rest.split('\\').next())
        .collect();
    assert_eq!(ids.len(), 2, "{drained:?}");
    assert!(
        drained.iter().all(|out| out.contains("same body")),
        "{drained:?}"
    );
    drop((first, second));
}

/// A relay whose attestor yields no evidence answers `caller_unattested` and
/// forwards nothing.
#[test]
fn relay_without_a_provider_fails_closed() {
    let dir = scratch("n");
    let config = InterfacesConfig::load(&{
        let path = dir.join("interfaces.toml");
        std::fs::write(
            &path,
            r#"core_socket = "/nonexistent/core.sock"
[root]
socket = "/nonexistent/r.sock"
token_file = "/nonexistent/token"
[[root.callers]]
host_id = "lab"
harness = "claude-code"
native_store_namespace = "claude-lab"
recipients = []
modes = []
kinds = []
"#,
        )
        .unwrap();
        path
    })
    .unwrap();
    let relay = RootRelay::new(
        config.core_socket,
        config.root.unwrap(),
        "unused-token-value-0000".into(),
        Box::new(Unattested) as Box<dyn CallerAttestor>,
    );
    let answer = relay.handle(
        RelayRequest {
            proof: SealedProof::from_wire("ab".repeat(32)),
            tool: "bridge_me".into(),
            arguments: json!({}),
        },
        1,
    );
    assert_eq!(
        serde_json::to_value(&answer).unwrap()["class"],
        "caller_unattested"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An accepted immutable send replays after its original expiry; a changed
/// envelope still conflicts, a new expired identity refuses without custody,
/// and current recipient authorization is checked before either lookup.
#[test]
fn expired_replays_preserve_custody_without_admitting_new_expired_events() {
    let lab = lab("exp");
    let mut harness = Harnessed::start(&lab.store);
    lab.hook(
        &mut harness,
        json!({"hook_event_name": "SessionStart", "session_id": "s1", "cwd": "/ignored"}),
    );
    let expiry = bridge_core::service::current_unix_millis() + 5000;
    let args = json!({"request_id":"expiry", "recipient":recipient("s2"), "kind":"root.note", "mode":"inject", "body":"same", "expires_at_ms":expiry});
    let sent = lab.call(
        &mut harness,
        "s1",
        "exp-send",
        None,
        "bridge_send",
        args.clone(),
    );
    assert_eq!(class(&sent), "ok", "{sent}");
    std::thread::sleep(Duration::from_millis(
        expiry.saturating_sub(bridge_core::service::current_unix_millis()) + 20,
    ));
    let replay = lab.call(
        &mut harness,
        "s1",
        "exp-replay",
        None,
        "bridge_send",
        args.clone(),
    );
    assert_eq!(class(&replay), "ok", "{replay}");
    assert_eq!(replay["structuredContent"]["custody"]["replayed"], true);
    for field in ["envelope_hash", "accepted_at_ms"] {
        assert_eq!(
            replay["structuredContent"]["custody"][field],
            sent["structuredContent"]["custody"][field]
        );
    }
    let mut changed = args.clone();
    changed["body"] = json!("changed");
    assert_eq!(
        class(&lab.call(
            &mut harness,
            "s1",
            "exp-conflict",
            None,
            "bridge_send",
            changed
        )),
        "conflict"
    );
    let mut foreign = args.clone();
    foreign["recipient"] = recipient("s9");
    assert_eq!(
        class(&lab.call(
            &mut harness,
            "s1",
            "exp-foreign",
            None,
            "bridge_send",
            foreign
        )),
        "forbidden"
    );
    let mut new = args;
    new["request_id"] = json!("new-expired");
    assert_eq!(
        class(&lab.call(&mut harness, "s1", "exp-new", None, "bridge_send", new)),
        "expired"
    );
    let status = lab.call(
        &mut harness,
        "s1",
        "exp-status",
        None,
        "bridge_status",
        json!({"request_id":"new-expired"}),
    );
    assert_eq!(status["structuredContent"]["custody"]["state"], "not_found");
}

/// The concise address/message API admits a previously unlisted session through
/// the real frontend, sealed native identity, relay and core. The generated
/// request id is returned, supports explicit replay, and altered data conflicts.
#[test]
fn address_message_send_needs_no_per_session_configuration() {
    let lab = lab_with_addresses("ad", true);
    let mut harness = Harnessed::start(&lab.store);
    lab.hook(
        &mut harness,
        json!({"hook_event_name":"SessionStart","session_id":"s1","cwd":"/ignored"}),
    );
    let args =
        json!({"address":claude("brand-new-session").to_canonical_string(),"message":"hello"});
    let sent = lab.call(
        &mut harness,
        "s1",
        "short-send",
        None,
        "bridge_send",
        args.clone(),
    );
    assert_eq!(class(&sent), "ok", "{sent}");
    let id = sent["structuredContent"]["request_id"].as_str().unwrap();
    assert!(id.starts_with("call-") && id.len() <= 128);
    let mut replay = args;
    replay["request_id"] = json!(id);
    let repeated = lab.call(
        &mut harness,
        "s1",
        "short-replay",
        None,
        "bridge_send",
        replay.clone(),
    );
    assert_eq!(class(&repeated), "ok", "{repeated}");
    assert_eq!(repeated["structuredContent"]["custody"]["replayed"], true);
    replay["message"] = json!("different");
    assert_eq!(
        class(&lab.call(
            &mut harness,
            "s1",
            "short-conflict",
            None,
            "bridge_send",
            replay
        )),
        "conflict"
    );
    let bad = lab.call(
        &mut harness,
        "s1",
        "bad-address",
        None,
        "bridge_send",
        json!({"address":"broken","message":"hi"}),
    );
    assert_eq!(class(&bad), "invalid");
}
