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
//! - `bridge-fixture publish <core> <token> <recipient> <mode> <event>
//!   <payload>` and `bridge-fixture status <core> <token> <event>`: one
//!   publisher request to the core socket (synthetic probe grant), printing
//!   the response. `bridge-fixture pause <core> <admin-token> <recipient>
//!   on|off` sets or clears the no-wake policy (synthetic operator grant).
//! - `bridge-fixture mcp-server <channel> <core> <token> <evidence>`: a
//!   minimal MCP stdio server with one `bridge_probe` tool for root-run
//!   native probes (see `qualification/`).
//! - `bridge-fixture app-server ...`: a fake Codex App Server speaking the
//!   queue-only subset; records `thread/queue/add` params to
//!   `$CODEX_HOME/queue.jsonl`. `$CODEX_HOME/behavior` = `refuse` answers
//!   an error, `silent` never answers the add, `flood` also streams
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
fn send_receipt(from: &str, msg_id: &str, status: &str, close: bool) -> bool {
    let Some(path) = from.strip_prefix("uds:") else {
        return false;
    };
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    let frame = json!({"type":"control","action":"peer_message_status","orig_msg_id":msg_id,"status":status});
    if stream.write_all(format!("{frame}\n").as_bytes()).is_err() {
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
                    _ => {
                        let _ = writeln!(stdout, "{}", json!({"id": id, "result": {}}));
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

/// A minimal MCP stdio server with one tool, `bridge_probe`, for root-run
/// native probes.
///
/// Each call attests its caller from the request's `_meta` through the
/// registry (this process must be the harness-launched MCP server). When
/// the caller may act as its address, it publishes one `inject` event with
/// a fresh marker to that address, so the call's own `PostToolUse` hook can
/// hand it to the model. The marker is written only to the evidence file
/// (`evidence`, JSON lines), never into the tool result, so a model that
/// reports it saw it through the hook context. Model arguments are
/// recorded but never used as identity.
fn mcp_server(channel: &str, core: &str, token: &str, evidence: &str) {
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
            "tools/list" => json!({"tools": [{
                "name": "bridge_probe",
                "description": "Agent Bridge native qualification probe. Call with an empty object.",
                "inputSchema": {"type": "object", "properties": {}}
            }]}),
            "tools/call" => {
                let meta = message["params"]["_meta"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                let now = bridge_core::service::current_unix_millis();
                let attested = PresentedMeta::from_mcp_meta(&meta)
                    .and_then(|meta| attestor.attest(&meta, now));
                let mut record = json!({
                    "at": now,
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
                        if caller.may_act_as_address() {
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
                        format!("bridge_probe attested role={}", record["caller"]["role"])
                    }
                    Err(error) => {
                        record["refused"] = json!(error.class());
                        format!("bridge_probe refused: {}", error.class())
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

/// Mode dispatch.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("harness") => harness(),
        Some("mcp") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), false),
        Some("mcp-seal") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), true),
        Some("relay") => relay(args.get(2).map(String::as_str).unwrap_or_default()),
        Some("app-server") => app_server(),
        Some("publish") if args.len() == 8 => {
            println!(
                "{}",
                publish(&args[2], &args[3], &args[4], &args[5], &args[6], &args[7])
            );
        }
        Some("status") if args.len() == 5 => println!("{}", status(&args[2], &args[3], &args[4])),
        Some("pause") if args.len() == 6 => {
            println!("{}", pause(&args[2], &args[3], &args[4], args[5] == "on"));
        }
        Some("mcp-server") if args.len() == 6 => mcp_server(&args[2], &args[3], &args[4], &args[5]),
        _ => {
            eprintln!(
                "usage: bridge-fixture harness | mcp <socket> | relay <socket> | app-server | publish <core> <token> <recipient> <mode> <event> <payload> | status <core> <token> <event> | pause <core> <admin-token> <recipient> on|off | mcp-server <channel> <core> <token> <evidence>"
            );
            std::process::exit(2);
        }
    }
}
