//! Owned fixture process for adapter tests; not a product component.
//!
//! Integration tests start it to play the parts that must be real
//! processes with real kernel identities:
//!
//! - `bridge-fixture harness`: a stand-in harness process. Tests qualify
//!   this executable in a test profile and start it with the profile's
//!   store in `CLAUDE_CONFIG_DIR`/`CODEX_HOME`. It reads JSON commands on
//!   stdin, one per line, and answers one JSON line each:
//!   - `{"cmd":"hook","bin":..,"socket":..,"harness":..,"payload":{..},
//!     "close_stdout":bool}` runs the real `bridge-hook` as its child
//!     (through `/bin/sh`), feeding the payload; answers its stdout and
//!     exit status. `close_stdout` closes the hook's stdout before it can
//!     print (a lost reply).
//!   - `{"cmd":"mcp","socket":..,"meta":{..}}` runs `bridge-fixture mcp`
//!     as its child (a harness-launched MCP server) and answers its
//!     attestation result.
//!   - `{"cmd":"inbox","behavior":..,"session_id":..}` starts a fake
//!     Claude inbox owned by this process and writes its descriptor and
//!     key into `$CLAUDE_CONFIG_DIR/sessions`. Behaviors: `held`,
//!     `delivered`, `refused`, `none`.
//!   - `{"cmd":"frames"}` answers the user frames the inbox received.
//!   - `{"cmd":"descriptor_disabled","session_id":..}` writes this process's
//!     session descriptor without any inbox (messaging disabled).
//!   - `{"cmd":"receipt","msg_id":..,"status":..,"close":bool}` sends a late
//!     receipt to the frame's callback from this process, staying connected
//!     until read unless `close` (disconnect at once: unverifiable sender).
//!   - `{"cmd":"mcp_server","args":[channel,core,token,evidence],"requests":[..]}`
//!     runs `bridge-fixture mcp-server` as its child, sends the JSON-RPC
//!     requests and answers the responses of those with an id.
//!   - `{"cmd":"exit"}` exits.
//! - `bridge-fixture mcp <socket>` (or `mcp-seal`) with `_meta` JSON on
//!   stdin: attests through `RegistryAttestor` (sealing a proof) and prints
//!   the result. The harness `mcp` command takes `"seal": true`.
//! - `bridge-fixture relay <socket>` with a sealed proof on stdin: redeems
//!   it as a relay and prints the result.
//! - `bridge-fixture publish <core> <token-file> <recipient> <mode> <event>
//!   <payload>` and `bridge-fixture status <core> <token-file> <event>`:
//!   one publisher request to the core socket (synthetic probe grant),
//!   printing the response. `bridge-fixture pause <core> <admin-token-file>
//!   <recipient> on|off` sets or clears the no-wake policy (synthetic
//!   operator grant). Every `*-token-file` is an owned 0600 file; tokens
//!   never appear in argv.
//! - `bridge-fixture queue-add <sandbox> <codex> <store> <thread>
//!   <client-id> <text-file>`: one product `Helper::queue_add`, printing
//!   its classified outcome (root-run Codex queue qualification).
//! - `bridge-fixture mcp-server <channel> <core> <token-file> <evidence>
//!   [<tools>]`: a minimal MCP stdio server with the probe tools for
//!   root-run native probes (see `qualification/`); `<tools>` is a
//!   comma-separated subset to expose (default: all).
//! - `bridge-fixture app-server ...`: a fake Codex App Server speaking the
//!   queue-only subset; records `thread/queue/add` params to
//!   `$CODEX_HOME/queue.jsonl`. `$CODEX_HOME/behavior` = `refuse` answers
//!   an error, `internal` records the item then answers an internal error,
//!   `malformed` answers a success without `queuedSubmission`, `silent` never
//!   answers the add, `flood` also streams
//!   notifications forever after `initialize`, and `stall` stops reading
//!   stdin after `initialize`. On `initialize` it probes
//!   its own confinement (TCP connect to the port in
//!   `$CODEX_HOME/probe_port`, spawning `/usr/bin/true`) and records the
//!   results in `$CODEX_HOME/probe.json`.

use std::io::{BufRead, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_adapters::RegistryAttestor;
use bridge_adapters::registry::{
    CallerAttestor, CorrelationError, PresentedMeta, SealedProof, VerifiedCaller,
};
use serde_json::{Value, json};

/// Fake inbox state shared with its listener thread.
#[derive(Default)]
struct Inbox {
    /// Received user frames.
    frames: Vec<Value>,
    /// Callback path per message id.
    callbacks: Vec<(String, String)>,
    /// Current receipt behavior (`held`, `delivered`, `refused`, `none`).
    behavior: String,
    /// Whether the listener already runs.
    started: bool,
}

/// Sends one receipt frame to a `uds:` callback.
///
/// By default the sender half-closes and stays connected until the
/// receiver closes, so its kernel identity stays readable. With `close`
/// it disconnects immediately after writing (an unverifiable sender).
/// `status` may be a comma-separated sequence (`held,delivered`), sent as
/// consecutive frames of the one connection, so ordered receipts reach the
/// carrier back to back.
fn send_receipt(from: &str, msg_id: &str, status: &str, close: bool) -> bool {
    let Some(path) = from.strip_prefix("uds:") else {
        return false;
    };
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    let frames: String = status
        .split(',')
        .map(|status| {
            let frame = json!({"type":"control","action":"peer_message_status","orig_msg_id":msg_id,"status":status});
            format!("{frame}\n")
        })
        .collect();
    if stream.write_all(frames.as_bytes()).is_err() {
        return false;
    }
    if !close {
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = std::io::copy(&mut stream, &mut std::io::sink());
    }
    true
}

/// Starts the fake inbox and writes its descriptor and key; a repeated
/// call only changes the receipt behavior.
fn start_inbox(state: Arc<Mutex<Inbox>>, session: &str, behavior: String) -> Value {
    {
        let mut inbox = state.lock().unwrap();
        inbox.behavior = behavior;
        if inbox.started {
            return json!({"ok": true});
        }
        inbox.started = true;
    }
    let store = PathBuf::from(std::env::var_os("CLAUDE_CONFIG_DIR").expect("store env"));
    let sessions = store.join("sessions");
    std::fs::create_dir_all(&sessions).expect("sessions dir");
    let pid = std::process::id();
    let socket = sessions.join(format!("{pid}.inbox.sock"));
    let listener = UnixListener::bind(&socket).expect("inbox bind");
    let token = format!("fixture-token-{pid}");
    std::fs::write(
        sessions.join(format!("{pid}.json")),
        json!({"sessionId": session, "pid": pid, "messagingSocketPath": socket}).to_string(),
    )
    .expect("descriptor");
    std::fs::write(
        sessions.join(format!("{pid}.fixture.key")),
        json!({"peerToken": token}).to_string(),
    )
    .expect("key");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut text = String::new();
            let _ = (&stream).take(1 << 20).read_to_string(&mut text);
            let mut lines = text.lines();
            let auth: Value = lines
                .next()
                .and_then(|l| serde_json::from_str(l).ok())
                .unwrap_or(Value::Null);
            if auth["token"] != json!(token) {
                continue;
            }
            for line in lines {
                let Ok(frame) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let msg_id = frame["msg_id"].as_str().unwrap_or_default().to_string();
                let from = frame["from"].as_str().unwrap_or_default().to_string();
                let behavior = {
                    let mut inbox = state.lock().unwrap();
                    inbox.frames.push(frame.clone());
                    inbox.callbacks.push((msg_id.clone(), from.clone()));
                    inbox.behavior.clone()
                };
                if behavior != "none" {
                    send_receipt(&from, &msg_id, &behavior, false);
                }
            }
        }
    });
    json!({"ok": true, "socket": socket})
}

/// Runs the harness command loop.
fn harness() {
    let inbox = Arc::new(Mutex::new(Inbox::default()));
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(command) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let reply = match command["cmd"].as_str().unwrap_or_default() {
            "hook" => run_hook(&command),
            "mcp" => run_mcp(&command),
            "mcp_server" => run_mcp_server(&command),
            "inbox" => start_inbox(
                Arc::clone(&inbox),
                command["session_id"].as_str().unwrap_or_default(),
                command["behavior"].as_str().unwrap_or("none").to_string(),
            ),
            "frames" => json!({"frames": inbox.lock().unwrap().frames}),
            "descriptor_disabled" => {
                // A session descriptor of this process that advertises no
                // inbox (as a restricted Claude session writes).
                let store =
                    PathBuf::from(std::env::var_os("CLAUDE_CONFIG_DIR").expect("store env"));
                let sessions = store.join("sessions");
                std::fs::create_dir_all(&sessions).expect("sessions dir");
                let pid = std::process::id();
                std::fs::write(
                    sessions.join(format!("{pid}.json")),
                    json!({"sessionId": command["session_id"], "pid": pid}).to_string(),
                )
                .expect("descriptor");
                json!({"ok": true})
            }
            "receipt" => {
                let msg_id = command["msg_id"].as_str().unwrap_or_default();
                let from = inbox
                    .lock()
                    .unwrap()
                    .callbacks
                    .iter()
                    .find(|(id, _)| id == msg_id)
                    .map(|(_, from)| from.clone())
                    .unwrap_or_default();
                json!({"sent": send_receipt(&from, msg_id, command["status"].as_str().unwrap_or_default(), command["close"].as_bool() == Some(true))})
            }
            "exit" => return,
            _ => json!({"error": "unknown command"}),
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
}

/// Runs the real hook binary as a child through `/bin/sh`.
fn run_hook(command: &Value) -> Value {
    let script = r#""$0" "$1" "$2""#;
    let mut child = Command::new("/bin/sh")
        .args(["-c", script])
        .arg(command["bin"].as_str().unwrap_or_default())
        .arg(command["socket"].as_str().unwrap_or_default())
        .arg(command["harness"].as_str().unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    let mut stdout_pipe = child.stdout.take().expect("hook stdout");
    if command["close_stdout"].as_bool() == Some(true) {
        drop(stdout_pipe);
        return finish_closed(child, command);
    }
    let payload = command["payload"].to_string();
    let mut stdin = child.stdin.take().expect("hook stdin");
    let _ = stdin.write_all(payload.as_bytes());
    drop(stdin);
    let mut out = String::new();
    let _ = stdout_pipe.read_to_string(&mut out);
    let mut err = String::new();
    let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut err));
    let status = child.wait().map(|s| s.code()).ok().flatten();
    json!({"stdout": out, "stderr": err, "status": status})
}

/// Feeds the hook whose stdout was already closed, then reaps it.
fn finish_closed(mut child: std::process::Child, command: &Value) -> Value {
    let payload = command["payload"].to_string();
    let mut stdin = child.stdin.take().expect("hook stdin");
    let _ = stdin.write_all(payload.as_bytes());
    drop(stdin);
    let mut err = String::new();
    let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut err));
    let status = child.wait().map(|s| s.code()).ok().flatten();
    json!({"stdout": "", "stderr": err, "status": status, "closed": true})
}

/// Runs `bridge-fixture mcp-server` as a child (the harness's MCP server),
/// sends `requests` (JSON-RPC objects) and answers the response lines of
/// those that carry an id.
fn run_mcp_server(command: &Value) -> Value {
    let exe = std::env::current_exe().expect("own exe");
    let mut child = Command::new(exe)
        .arg("mcp-server")
        .args(
            command["args"]
                .as_array()
                .map(|args| {
                    args.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mcp-server");
    let mut stdin = child.stdin.take().expect("mcp-server stdin");
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("mcp-server stdout"));
    let mut responses = Vec::new();
    for request in command["requests"].as_array().cloned().unwrap_or_default() {
        let _ = writeln!(stdin, "{request}");
        let _ = stdin.flush();
        if request.get("id").is_some() {
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            responses.push(serde_json::from_str::<Value>(&line).unwrap_or(Value::Null));
        }
    }
    drop(stdin);
    let _ = child.wait();
    json!({"responses": responses})
}

/// Runs `bridge-fixture mcp` as a child (the harness's MCP server).
fn run_mcp(command: &Value) -> Value {
    let exe = std::env::current_exe().expect("own exe");
    let mut child = Command::new(exe)
        .arg(if command["seal"].as_bool() == Some(true) {
            "mcp-seal"
        } else {
            "mcp"
        })
        .arg(command["socket"].as_str().unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let _ = child
        .stdin
        .take()
        .expect("mcp stdin")
        .write_all(command["meta"].to_string().as_bytes());
    let output = child.wait_with_output().expect("mcp output");
    serde_json::from_slice(&output.stdout).unwrap_or(json!({"error": "no mcp output"}))
}

/// Renders an attestation result (or its refusal class) as one JSON line.
fn render(result: Result<(VerifiedCaller, Option<String>), CorrelationError>) -> Value {
    match result {
        Ok((caller, proof)) => json!({
            "ok": {
                "address": caller.address().to_canonical_string(),
                "role": caller.role(),
                "native_id": caller.native_id(),
                "epoch": caller.epoch(),
                "may_act_as_address": caller.may_act_as_address(),
                "relayed": caller.relayed(),
            },
            "proof": proof,
        }),
        Err(error) => json!({"err": error.class()}),
    }
}

/// The MCP-server stand-in (a harness-launched frontend): attest native
/// `_meta` from stdin through the registry, optionally sealing, and print.
fn mcp(socket: &str, seal: bool) {
    let mut text = String::new();
    let _ = std::io::stdin().read_to_string(&mut text);
    let meta: serde_json::Map<String, Value> = serde_json::from_str(&text).unwrap_or_default();
    let now = bridge_core::service::current_unix_millis();
    let attestor = RegistryAttestor::new(Path::new(socket), Duration::from_secs(5), 600_000);
    let result = PresentedMeta::from_mcp_meta(&meta).and_then(|meta| {
        if seal {
            attestor
                .attest_sealed(&meta, now)
                .map(|(caller, proof)| (caller, Some(proof.as_str().to_string())))
        } else {
            attestor.attest(&meta, now).map(|caller| (caller, None))
        }
    });
    println!("{}", render(result));
}

/// The relay stand-in (not a harness descendant): redeem a sealed proof
/// read from stdin and print.
fn relay(socket: &str) {
    let mut proof = String::new();
    let _ = std::io::stdin().read_to_string(&mut proof);
    let now = bridge_core::service::current_unix_millis();
    let attestor = RegistryAttestor::new(Path::new(socket), Duration::from_secs(5), 600_000);
    let meta = PresentedMeta::sealed(SealedProof::from_wire(proof.trim()));
    println!(
        "{}",
        render(attestor.attest(&meta, now).map(|caller| (caller, None)))
    );
}

/// The fake Codex App Server (queue-only subset).
fn app_server() {
    let home = PathBuf::from(std::env::var_os("CODEX_HOME").expect("CODEX_HOME"));
    let behavior = std::fs::read_to_string(home.join("behavior")).unwrap_or_default();
    let mut stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = message["id"].clone();
        match message["method"].as_str().unwrap_or_default() {
            "initialize" => {
                probe_confinement(&home);
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"id": id, "result": {"userAgent": "fixture"}})
                );
                let _ = stdout.flush();
                match behavior.trim() {
                    "flood" => {
                        std::thread::spawn(|| {
                            loop {
                                println!(
                                    "{}",
                                    json!({"method": "thread/status/changed", "params": {}})
                                );
                                std::thread::sleep(Duration::from_millis(2));
                            }
                        });
                    }
                    "stall" => std::thread::sleep(Duration::from_secs(60)),
                    _ => {}
                }
            }
            "thread/queue/add" => {
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(home.join("queue.jsonl"))
                    .expect("queue log");
                let _ = writeln!(log, "{}", message["params"]);
                match behavior.trim() {
                    "silent" | "flood" => continue,
                    "refuse" => {
                        let _ = writeln!(
                            stdout,
                            "{}",
                            json!({"id": id, "error": {"code": -32600, "message": "thread archived"}})
                        );
                    }
                    // The item is already recorded: an internal error after a
                    // queue effect.
                    "internal" => {
                        let _ = writeln!(
                            stdout,
                            "{}",
                            json!({"id": id, "error": {"code": -32603, "message": "internal error"}})
                        );
                    }
                    "malformed" => {
                        let _ = writeln!(stdout, "{}", json!({"id": id, "result": {}}));
                    }
                    _ => {
                        let submission = json!({
                            "id": format!("q-{id}"),
                            "clientUserMessageId": message["params"]["clientUserMessageId"],
                            "input": message["params"]["input"],
                        });
                        let _ = writeln!(
                            stdout,
                            "{}",
                            json!({"id": id, "result": {"queuedSubmission": submission}})
                        );
                    }
                }
            }
            _ => {}
        }
        let _ = stdout.flush();
    }
}

/// Records whether this process can reach the network or spawn a child.
fn probe_confinement(home: &Path) {
    let port = std::fs::read_to_string(home.join("probe_port")).unwrap_or_default();
    let network = match port.trim().parse::<u16>() {
        Ok(port) => std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
        Err(_) => false,
    };
    let child = Command::new("/usr/bin/true").status().is_ok();
    let _ = std::fs::write(
        home.join("probe.json"),
        json!({"network_connected": network, "child_spawned": child}).to_string(),
    );
}

/// Sends one request line to the core service socket and returns the
/// response line as JSON.
fn core_call(core: &str, request: &bridge_core::Request) -> Value {
    let Ok(mut stream) = UnixStream::connect(core) else {
        return json!({"error": "core socket unreachable"});
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let line = serde_json::to_string(request).expect("request encodes");
    if writeln!(stream, "{line}").is_err() {
        return json!({"error": "core write failed"});
    }
    let mut response = String::new();
    let _ = std::io::BufReader::new(&stream).read_line(&mut response);
    serde_json::from_str(&response).unwrap_or(json!({"error": "no core response"}))
}

/// Publishes one keep_all event with a synthetic publisher grant token.
fn publish(
    core: &str,
    token: &str,
    recipient: &str,
    mode: &str,
    event_id: &str,
    payload: &str,
) -> Value {
    let (Ok(recipient), Ok(mode)) = (
        bridge_core::NativeAddress::parse(recipient),
        bridge_core::Mode::parse(mode),
    ) else {
        return json!({"error": "invalid recipient or mode"});
    };
    core_call(
        core,
        &bridge_core::Request::Publish {
            token: bridge_core::service::Token::new(token),
            event: Box::new(bridge_core::PublishBody {
                event_id: event_id.into(),
                recipient,
                kind: "bridge.probe".into(),
                mode,
                policy: bridge_core::Policy::KeepAll,
                payload: payload.into(),
                metadata: bridge_core::Metadata::new(),
                expires_at: None,
            }),
        },
    )
}

/// Sets (`on`) or clears the durable no-wake policy of a recipient with a
/// synthetic operator grant token.
fn pause(core: &str, token: &str, recipient: &str, on: bool) -> Value {
    let Ok(recipient) = bridge_core::NativeAddress::parse(recipient) else {
        return json!({"error": "invalid recipient"});
    };
    let token = bridge_core::service::Token::new(token);
    core_call(
        core,
        &if on {
            bridge_core::Request::Pause {
                token,
                recipient,
                reason: "native qualification probe pause".into(),
            }
        } else {
            bridge_core::Request::Resume { token, recipient }
        },
    )
}

/// Reads the publisher's own status of one event.
fn status(core: &str, token: &str, event_id: &str) -> Value {
    core_call(
        core,
        &bridge_core::Request::Status {
            token: bridge_core::service::Token::new(token),
            event_id: event_id.into(),
        },
    )
}

/// Every tool `mcp-server` can expose, in listing order.
const PROBE_TOOLS: [&str; 3] = ["bridge_probe", "bridge_me", "bridge_unlisted"];

/// A minimal MCP stdio server for root-run native probes, with three tools:
///
/// - `bridge_probe` (not read-only: it publishes): attests its caller from
///   the request's `_meta` through the registry (this process must be the
///   harness-launched MCP server); when the caller may act as its address,
///   publishes one `inject` event with a fresh marker to that address, so
///   the call's own `PostToolUse` hook can hand it to the model.
/// - `bridge_me` (`readOnlyHint: true`): attests its caller and records it;
///   it publishes nothing, so a probe controls publication externally.
/// - `bridge_unlisted` (`readOnlyHint: false`, `destructiveHint: true`): a
///   negative control for host tool approval. It does nothing but record
///   `unlisted_called`; a probe that expects the host to refuse it fails if
///   that record ever appears.
///
/// Only the tools named in `exposed` are listed; a call to any other
/// name is answered with an error and never runs or records anything, so a
/// probe's closed tool inventory holds without host-side filtering.
///
/// Every call appends one JSON line with the tool name to `evidence`. A
/// marker is written only there, never into the tool result. Model
/// arguments are recorded but never used as identity.
fn mcp_server(channel: &str, core: &str, token: &str, evidence: &str, exposed: &[&str]) {
    let attestor = RegistryAttestor::new(Path::new(channel), Duration::from_secs(5), 600_000);
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(evidence)
        .expect("evidence file");
    let mut stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = message["id"].clone();
        let result = match message["method"].as_str().unwrap_or_default() {
            "initialize" => json!({
                "protocolVersion": message["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "bridge-probe", "version": env!("CARGO_PKG_VERSION")}
            }),
            "ping" => json!({}),
            "tools/list" => {
                let tools = json!([
                {
                    "name": "bridge_probe",
                    "description": "Agent Bridge native qualification probe. Call with an empty object.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false}
                },
                {
                    "name": "bridge_me",
                    "description": "Agent Bridge caller attestation (read-only). Call with an empty object.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}
                },
                {
                    "name": "bridge_unlisted",
                    "description": "Agent Bridge approval negative control. Call with an empty object.",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false}
                }
                ]);
                let listed: Vec<&Value> = tools
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|tool| exposed.iter().any(|name| tool["name"] == *name))
                    .collect();
                json!({"tools": listed})
            }
            "tools/call"
                if !exposed
                    .iter()
                    .any(|name| message["params"]["name"] == *name) =>
            {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "unknown tool"}})
                );
                let _ = stdout.flush();
                continue;
            }
            "tools/call" if message["params"]["name"] == "bridge_unlisted" => {
                let record = json!({"at": bridge_core::service::current_unix_millis(), "tool": "bridge_unlisted", "unlisted_called": true});
                let _ = writeln!(log, "{record}");
                json!({"content": [{"type": "text", "text": "bridge_unlisted ran"}]})
            }
            "tools/call" => {
                let tool = message["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let meta = message["params"]["_meta"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                let now = bridge_core::service::current_unix_millis();
                let attested = PresentedMeta::from_mcp_meta(&meta)
                    .and_then(|meta| attestor.attest(&meta, now));
                let mut record = json!({
                    "at": now,
                    "tool": tool,
                    "meta_keys": meta.keys().collect::<Vec<_>>(),
                    "arguments_ignored": message["params"]["arguments"],
                });
                let text = match attested {
                    Ok(caller) => {
                        record["caller"] = json!({
                            "address": caller.address().to_canonical_string(),
                            "role": caller.role(),
                            "native_id": caller.native_id(),
                            "epoch": caller.epoch(),
                            "may_act_as_address": caller.may_act_as_address(),
                        });
                        if caller.may_act_as_address() && tool == "bridge_probe" {
                            let marker = format!(
                                "BRIDGE_CTX_{}",
                                bridge_adapters::os::random_bytes().expect("random")[..6]
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<String>()
                            );
                            let event_id = format!("probe-inject-{now}");
                            record["marker"] = json!(marker);
                            record["event_id"] = json!(event_id);
                            record["publish"] = publish(
                                core,
                                token,
                                &caller.address().to_canonical_string(),
                                "inject",
                                &event_id,
                                &format!("Synthetic Bridge qualification context marker {marker}."),
                            );
                        }
                        format!("{tool} attested role={}", record["caller"]["role"])
                    }
                    Err(error) => {
                        record["refused"] = json!(error.class());
                        format!("{tool} refused: {}", error.class())
                    }
                };
                let _ = writeln!(log, "{record}");
                json!({"content": [{"type": "text", "text": text}]})
            }
            _ if message.get("id").is_none() => continue,
            _ => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
                );
                let _ = stdout.flush();
                continue;
            }
        };
        let _ = writeln!(
            stdout,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        );
        let _ = stdout.flush();
    }
}

/// Reads a synthetic grant token from an owned credential file.
///
/// The file must be a regular file (not a symlink) owned by this user with
/// no group or other permission bits, at most 4 KiB; its trimmed content is
/// the token. Anything else exits with status 5 and a message that never
/// contains file content. Tokens are never taken from argv.
fn credential(path: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    let own = bridge_adapters::os::process_facts(std::process::id()).and_then(|facts| facts.uid);
    let usable = std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file()
            && Some(metadata.uid()) == own
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 4096
    });
    let token = usable
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
        .map(|text| text.trim().to_string())
        .filter(|token| !token.is_empty());
    match token {
        Some(token) => token,
        None => {
            eprintln!("credential file refused: must be an owned 0600 regular file");
            std::process::exit(5);
        }
    }
}

/// Runs the product's confined Codex helper once and prints its outcome.
fn queue_add(
    sandbox: &str,
    codex: &str,
    store: &str,
    thread: &str,
    client_id: &str,
    text_file: &str,
) {
    let text = std::fs::read_to_string(text_file).unwrap_or_default();
    let helper = bridge_adapters::codex::Helper {
        sandbox: Path::new(sandbox),
        executable: Path::new(codex),
        store: Path::new(store),
        timeout: Duration::from_secs(30),
    };
    let outcome = helper.queue_add(thread, client_id, &text);
    let (kind, detail) = match &outcome {
        bridge_core::dispatch::Outcome::NativeAccepted { evidence } => {
            ("native_accepted", evidence.clone())
        }
        bridge_core::dispatch::Outcome::KnownUnsent { evidence } => {
            ("known_unsent", evidence.clone())
        }
        bridge_core::dispatch::Outcome::OutcomeUnknown { reason } => {
            ("outcome_unknown", reason.clone())
        }
        other => ("other", format!("{other:?}")),
    };
    println!("{}", json!({"outcome": kind, "detail": detail}));
}

/// Mode dispatch.
/// Runs an owned Rust child of the signed frontend, publishing only its relay
/// readiness and waiting for stdin EOF so the parent process has a bounded test lifetime.
fn desktop_child(channel: &str) {
    let _guard = bridge_adapters::desktop::start_frontend(Path::new(channel))
        .unwrap()
        .unwrap();
    println!("ready");
    std::io::stdout().flush().unwrap();
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("harness") => harness(),
        Some("desktop-child") => desktop_child(args.get(2).unwrap()),
        Some("mcp") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), false),
        Some("mcp-seal") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), true),
        Some("relay") => relay(args.get(2).map(String::as_str).unwrap_or_default()),
        Some("app-server") => app_server(),
        Some("publish") if args.len() == 8 => {
            println!(
                "{}",
                publish(
                    &args[2],
                    &credential(&args[3]),
                    &args[4],
                    &args[5],
                    &args[6],
                    &args[7]
                )
            );
        }
        Some("status") if args.len() == 5 => {
            println!("{}", status(&args[2], &credential(&args[3]), &args[4]));
        }
        Some("pause") if args.len() == 6 => {
            println!(
                "{}",
                pause(&args[2], &credential(&args[3]), &args[4], args[5] == "on")
            );
        }
        Some("mcp-server") if args.len() == 6 || args.len() == 7 => {
            let exposed: Vec<&str> = match args.get(6) {
                Some(list) => list.split(',').collect(),
                None => PROBE_TOOLS.to_vec(),
            };
            mcp_server(
                &args[2],
                &args[3],
                &credential(&args[4]),
                &args[5],
                &exposed,
            );
        }
        Some("queue-add") if args.len() == 8 => {
            queue_add(&args[2], &args[3], &args[4], &args[5], &args[6], &args[7]);
        }
        _ => {
            eprintln!(
                "usage: bridge-fixture harness | mcp <socket> | relay <socket> | app-server | publish <core> <token-file> <recipient> <mode> <event> <payload> | status <core> <token-file> <event> | pause <core> <admin-token-file> <recipient> on|off | mcp-server <channel> <core> <token-file> <evidence> [<tools>] | queue-add <sandbox> <codex> <store> <thread> <client-id> <text-file>"
            );
            std::process::exit(2);
        }
    }
}
