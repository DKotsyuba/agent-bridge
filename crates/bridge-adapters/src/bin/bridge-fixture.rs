//! Owned fixture process for adapter tests; not a product component.
//!
//! Integration tests start it to play the parts that must be real
//! processes with real kernel identities:
//!
//! - `bridge-fixture harness`: a stand-in harness process. Tests name its
//!   path in a harness policy marker (`executable_markers`) and start it with
//!   the store in `CLAUDE_CONFIG_DIR`/`CODEX_HOME`. It reads JSON commands on
//!   stdin, one per line, and answers one JSON line each:
//!   - `{"cmd":"hook","bin":..,"socket":..,"harness":..,"payload":{..},
//!     "close_stdout":bool}` runs the real `bridge-hook` as its child
//!     (through `/bin/sh`), feeding the payload; answers its stdout and
//!     exit status. `close_stdout` closes the hook's stdout before it can
//!     print (a lost reply).
//!   - `{"cmd":"mcp","socket":..,"meta":{..}}` runs `bridge-fixture mcp`
//!     as its child (a harness-launched MCP server) and answers its
//!     attestation result.
//!   - `{"cmd":"desktop_frontend","node":..,"channel":..}` starts one
//!     test-provisioned Node primary and its Rust typed relay under this exact
//!     harness. Both inputs are UTF-8 paths; the native mock pipe is inherited
//!     from this harness, never supplied by the command. Answers `ok` only
//!     after reading `ready`. Missing inputs, spawn/read errors or wrong
//!     readiness panic. Call once; stdin EOF or exit closes/reaps the child.
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
//!   - `{"cmd":"exit"}` closes/reaps an owned Desktop child, then exits.
//! - `bridge-fixture owner <directory>`: a scripted stand-in native owner. It
//!   binds `<directory>/o.sock` (private directory, mode 0600), starts
//!   `bridge-fixture harness` (or the executable named by
//!   `BRIDGE_FIXTURE_HARNESS_EXE`) as its direct child with `BRIDGE_NATIVE_OWNER_SOCKET`
//!   set, forwards every other stdin command to that child and answers its reply,
//!   and answers the owner commands `owner_script` (`mode`: the receipt the next
//!   requests get), `owner_log` (probe connections, the strict request
//!   frames received and the harness child's pid), `owner_stop_harness` (ends only the harness child) and
//!   `owner_die` (the owner exits at once, leaving the harness orphaned).
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

use std::io::{BufRead, BufReader, Read, Write};
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

/// Serves line-delimited fixture commands from stdin and replies on stdout.
/// Malformed JSON is skipped; unknown commands return an error. The optional
/// desktop_frontend command requires UTF-8 node/channel paths, inherits this
/// harness's mock pipe, and replies only after child readiness; missing inputs,
/// spawn/read failure or unexpected readiness panic. Tests call it at most once.
/// The harness owns the child stdin until EOF/exit, then closes it and waits for
/// reaping. Other commands and their inputs are listed in the module inventory.
fn harness() {
    let inbox = Arc::new(Mutex::new(Inbox::default()));
    // Owned independent Desktop frontend lives under this exact harness.
    let mut frontend = None;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(command) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let reply = match command["cmd"].as_str().unwrap_or_default() {
            "desktop_frontend" => {
                frontend = Some(start_desktop_frontend(&command));
                json!({"ok": true})
            }
            "hook" => run_hook(&command),
            "delayed_hook" => run_delayed_hook(&command),
            "mcp" => run_mcp(&command),
            "v1" => run_v1_frontend(&command),
            "v1_and_legacy" => run_v1_and_legacy(&command),
            "v1_direct" => core_call(
                command["socket"].as_str().unwrap_or_default(),
                &command["request"],
            ),
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
            "exit" => break,
            _ => json!({"error": "unknown command"}),
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
    if let Some(mut child) = frontend {
        drop(child.stdin.take());
        let _ = child.wait();
    }
}

/// State of the scripted owner shared with its listener thread.
#[derive(Default)]
struct OwnerState {
    /// Receipt behavior for the next requests (see `owner_receipt`).
    mode: String,
    /// Connections that closed without sending a request (liveness probes).
    probes: u64,
    /// Strict request frames received, in order.
    frames: Vec<Value>,
}

/// Renders the scripted receipt bytes for `mode` answering `request`, or
/// `None` when the owner must stay silent. Modes: `codex_accept`,
/// `claude_accept`, `opencode_accept`, `known_unsent:<reason>`, `unknown:<reason>`, `wrong_call`,
/// `extra_key`, `dup_key`, `garbage`, `silent` and `stall`.
fn owner_receipt(mode: &str, request: &Value) -> Option<Vec<u8>> {
    let call = request["call_id"].as_str().unwrap_or_default();
    let accept = |protocol: &str| json!({"call_id":call,"state":"accepted","protocol":protocol,"native_id":"fresh-native-id","reason":null});
    let refuse = |state: &str, reason: &str| json!({"call_id":call,"state":state,"protocol":null,"native_id":null,"reason":reason});
    let value = match mode.split_once(':').unwrap_or((mode, "")) {
        ("codex_accept", _) => accept("codex_turn"),
        ("claude_accept", _) => accept("claude_input"),
        ("opencode_accept", _) => accept("opencode_input"),
        ("known_unsent", reason) => refuse("known_unsent", reason),
        ("unknown", reason) => refuse("unknown", reason),
        ("wrong_call", _) => {
            let mut value = accept("codex_turn");
            value["call_id"] = json!("another-call");
            value
        }
        ("extra_key", _) => {
            let mut value = accept("codex_turn");
            value["version"] = json!(1);
            value
        }
        ("dup_key", _) => {
            return Some(
                format!(
                    r#"{{"call_id":"{call}","state":"accepted","state":"accepted","protocol":"codex_turn","native_id":"x","reason":null}}"#
                )
                .into_bytes(),
            );
        }
        ("garbage", _) => return Some(b"not json".to_vec()),
        _ => return None,
    };
    Some(value.to_string().into_bytes())
}

/// Serves the scripted owner socket: one request per connection, recorded
/// strictly (the six agreed keys only) and answered per the current mode.
/// A connection that closes before any byte is a liveness probe.
fn owner_serve(listener: UnixListener, state: Arc<Mutex<OwnerState>>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut head = [0; 4];
            if stream.read_exact(&mut head).is_err() {
                state.lock().unwrap().probes += 1;
                return;
            }
            let mut body = vec![0; u32::from_le_bytes(head) as usize];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            let Ok(request) = serde_json::from_slice::<Value>(&body) else {
                return;
            };
            let mode = {
                let mut state = state.lock().unwrap();
                state.frames.push(request.clone());
                state.mode.clone()
            };
            if mode == "stall" {
                std::thread::sleep(Duration::from_secs(40));
                return;
            }
            if let Some(bytes) = owner_receipt(&mode, &request) {
                let _ = stream.write_all(&(bytes.len() as u32).to_le_bytes());
                let _ = stream.write_all(&bytes);
            }
        });
    }
}

/// The scripted stand-in owner process: binds its socket, starts the harness as
/// its direct child and multiplexes owner commands with harness forwarding.
fn owner(directory: &str) {
    use std::os::unix::fs::PermissionsExt;
    let socket = Path::new(directory).join("o.sock");
    let listener = UnixListener::bind(&socket).expect("owner socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let state = Arc::new(Mutex::new(OwnerState::default()));
    let served = Arc::clone(&state);
    std::thread::spawn(move || owner_serve(listener, served));
    let harness_exe = std::env::var_os("BRIDGE_FIXTURE_HARNESS_EXE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_exe().expect("self"));
    let mut child = Command::new(harness_exe)
        .arg("harness")
        .env("BRIDGE_NATIVE_OWNER_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("harness child");
    let mut to_child = child.stdin.take();
    let mut from_child = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let command: Value = serde_json::from_str(&line).unwrap_or_default();
        let reply = match command["cmd"].as_str().unwrap_or_default() {
            "owner_script" => {
                state.lock().unwrap().mode = command["mode"].as_str().unwrap_or_default().into();
                json!({"ok": true})
            }
            "owner_log" => {
                let state = state.lock().unwrap();
                json!({"probes": state.probes, "frames": state.frames, "harness_pid": child.id()})
            }
            "owner_stop_harness" => {
                drop(to_child.take());
                let _ = child.wait();
                json!({"ok": true})
            }
            "owner_die" => {
                // Acknowledge first so the driving test reads a reply, then
                // vanish without reaping the harness child.
                let _ = writeln!(stdout, "{}", json!({"ok": true}));
                let _ = stdout.flush();
                std::process::exit(0);
            }
            _ => {
                let mut answer = String::new();
                let forwarded = to_child.as_mut().is_some_and(|input| {
                    writeln!(input, "{line}")
                        .and_then(|()| input.flush())
                        .is_ok()
                });
                if forwarded && from_child.read_line(&mut answer).unwrap_or(0) > 0 {
                    serde_json::from_str(&answer).unwrap_or_default()
                } else {
                    json!({"error": "harness gone"})
                }
            }
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
        if command["cmd"] == "exit" {
            break;
        }
    }
    drop(to_child);
    let _ = child.wait();
}

/// Starts an owned Node primary and Rust typed relay under this fixture harness,
/// inheriting only the fixture's native mock pipe. `node` and `channel` name
/// test-provisioned resources; readiness is required before returning the child.
/// The harness retains stdin and closes/reaps the child on its own shutdown.
fn start_desktop_frontend(command: &Value) -> std::process::Child {
    let mut child = Command::new(command["node"].as_str().expect("node"))
        .arg("-e")
        .arg(include_str!("../../assets/desktop-client.cjs"))
        .arg("--")
        .arg(std::env::current_exe().expect("fixture"))
        .arg("desktop-child")
        .arg(command["channel"].as_str().expect("channel"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("frontend");
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("ready pipe"))
        .read_line(&mut line)
        .expect("read readiness");
    assert_eq!(line.trim(), "ready");
    child
}

/// Runs an owned qualified hook peer with controlled confirmation latency.
/// The child uses the public native hook/flush wire; delay settings are fixture
/// timing controls, never caller identity or production protocol fields.
fn run_delayed_hook(command: &Value) -> Value {
    let mut child = Command::new(std::env::current_exe().expect("own executable"))
        .arg("delayed-hook")
        .arg(command["socket"].as_str().unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("controlled hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(command.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("controlled hook output");
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

/// Emits one real hook frame, receives the exact inject reply, then confirms its
/// digest after a controlled delay or fragmented-gap schedule. It never prints
/// hidden context. Result records whether reply/confirmation I/O succeeded;
/// authoritative attempt state remains in actual core custody. EOF/setup errors
/// refuse the fixture, and no generic hook framework or sender fallback exists.
fn delayed_hook(socket: &str) {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    let command: Value = serde_json::from_slice(&bytes).unwrap();
    let mut stream = UnixStream::connect(socket).expect("owned hook socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    writeln!(
        stream,
        "{}",
        json!({"op": "hook", "harness": command["harness"], "payload": command["payload"]})
    )
    .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(&stream)
        .read_line(&mut line)
        .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    let Some(digest) = response["digest"].as_str() else {
        println!("{}", json!({"inject": false}));
        return;
    };
    std::thread::sleep(Duration::from_millis(
        command["delay_ms"].as_u64().unwrap_or(0),
    ));
    let confirmation = format!("{}\n", json!({"op": "flushed", "digest": digest}));
    let mut sent = true;
    let gap = command["fragment_gap_ms"].as_u64().unwrap_or(0);
    if gap == 0 {
        sent = stream.write_all(confirmation.as_bytes()).is_ok();
    } else {
        let third = confirmation.len() / 3;
        for (index, part) in confirmation.as_bytes().chunks(third).enumerate() {
            if index > 0 {
                std::thread::sleep(Duration::from_millis(gap));
            }
            if stream.write_all(part).is_err() {
                sent = false;
                break;
            }
        }
    }
    println!("{}", json!({"inject": true, "confirmation_written": sent}));
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

/// Runs one owned harness descendant that exchanges a public producer frame.
/// Synthetic metadata originates in the test; kernel ancestry remains genuine.
fn run_v1_frontend(command: &Value) -> Value {
    let mut child = Command::new(std::env::current_exe().expect("own executable"))
        .arg(if command["lose_ack"].as_bool() == Some(true) {
            "v1-lost-ack"
        } else {
            "v1-frontend"
        })
        .arg(command["socket"].as_str().unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("owned v1 frontend");
    let _ = child
        .stdin
        .take()
        .expect("frontend input")
        .write_all(command["request"].to_string().as_bytes());
    let output = child.wait_with_output().expect("owned frontend output");
    serde_json::from_slice(&output.stdout).unwrap_or(json!({"error": "frontend response missing"}))
}

/// Runs genuine sibling frontends for a controlled reservation/legacy race.
/// The legacy result file is owned test evidence, never a credential or proof.
fn run_v1_and_legacy(command: &Value) -> Value {
    let mut first = Command::new(std::env::current_exe().expect("own executable"))
        .arg("v1-frontend")
        .arg(command["socket"].as_str().unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("owned frontend");
    first
        .stdin
        .take()
        .unwrap()
        .write_all(command["request"].to_string().as_bytes())
        .unwrap();
    // The controller starts legacy only after the claim-ready gate appears.
    let gate = Path::new(command["claim_ready_file"].as_str().unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !gate.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let legacy = run_mcp(command);
    let _ = std::fs::write(
        command["legacy_result_file"].as_str().unwrap(),
        legacy.to_string(),
    );
    let output = first.wait_with_output().expect("owned frontend response");
    json!({"first": serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null), "legacy": legacy})
}

/// Exchanges exactly one typed public producer request under the owned frontend
/// kernel identity. It adds no caller fields and uses no private registration op.
fn v1_frontend(socket: &str, lose_ack: bool) {
    let mut bytes = Vec::new();
    let _ = std::io::stdin()
        .take(bridge_protocol::MAX_REGISTRATION_BYTES as u64 + 1)
        .read_to_end(&mut bytes);
    match bridge_protocol::decode_request(&bytes) {
        Ok(request) if lose_ack => {
            let mut stream = UnixStream::connect(socket).expect("owned channel");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("owned deadline");
            let mut encoded = bridge_protocol::encode_request(&request).expect("typed request");
            encoded.push(b'\n');
            stream.write_all(&encoded).expect("owned write");
            let mut prefix = [0_u8; 1];
            let observed = stream.read_exact(&mut prefix).is_ok();
            // First response byte proves a response began, but never gives the
            // frontend a correlated receipt. Deliberately discard the rest.
            println!("{}", json!({"outcome_unknown": observed}));
        }
        Ok(request) => println!("{}", core_call(socket, &request)),
        Err(_) => println!("{}", json!({"error": "invalid fixture request"})),
    }
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
fn core_call<T: serde::Serialize>(core: &str, request: &T) -> Value {
    let Ok(mut stream) = UnixStream::connect(core) else {
        return json!({"error": "core socket unreachable"});
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let line = serde_json::to_string(request).expect("request encodes");
    if writeln!(stream, "{line}").is_err() {
        return json!({"error": "core write failed"});
    }
    let mut response = String::new();
    let _ = std::io::BufReader::new(&stream)
        .take(bridge_protocol::MAX_RESPONSE_BYTES as u64 + 1)
        .read_line(&mut response);
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

/// Runs the owned minimal MCP stdio probe loop on stdin/stdout. `channel`
/// and `core` are explicit protected local endpoints; `token` is privately
/// loaded by the caller and never logged. `evidence` is an owned append-only
/// file. Legacy mode (`universal=None`) exposes only the `exposed` subset of
/// three built-in tools:
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
/// With `universal=Some(config)`, list its single runtime-configured opaque
/// tool name and require that name in `exposed`. Calls preserve actual framework
/// `_meta` separately from arguments, register/publish using the public wire and
/// return/log bounded receipt-only facts. Hidden payload file content never
/// enters tool results, prompts, ordinary evidence or argument-based identity.
/// Legacy mode records arguments but does not use them as identity; its marker
/// is confined to the owned evidence file and the actual injected context.
/// Unknown tool/method calls refuse; malformed lines are ignored, EOF ends the
/// loop, and owned file/process setup failures panic the fixture. Successful
/// responses flush stdout. This is test orchestration, never an MCP framework.
fn mcp_server(
    channel: &str,
    core: &str,
    token: &str,
    evidence: &str,
    exposed: &[&str],
    universal: Option<&UniversalProbe>,
) {
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
            "tools/list" if universal.is_some() => {
                let config = universal.expect("matched universal probe");
                json!({"tools": [{"name": config.tool_name,
                    "description": "Run the configured owned universal protocol check with an empty object.",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
                    "annotations": {"readOnlyHint": false, "destructiveHint": false, "openWorldHint": false}}]})
            }
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
            "tools/call" if universal.is_some() => {
                let config = universal.expect("matched universal probe");
                let meta = message["params"]["_meta"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                let result = universal_probe(channel, core, token, config, meta);
                let _ = writeln!(
                    log,
                    "{}",
                    json!({"tool": config.tool_name, "result": result})
                );
                json!({"content": [{"type": "text", "text": result.to_string()}]})
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

/// Runtime configuration for an owned generic qualification producer. Values
/// are chosen after common artifact freeze; no name/kind catalog is compiled.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UniversalProbe {
    /// Opaque configured MCP tool name; arguments contain no route or identity.
    tool_name: String,
    /// Stable registration request persisted in this owned fixture configuration.
    request_id: String,
    /// Opaque producer operation incarnation.
    operation_key: String,
    /// Stable custody identity, independent of the outer exchange request ID.
    event_id: String,
    /// Arbitrary permitted producer event kind.
    kind: String,
    /// Private hidden payload file; contents never appear in probe tool results.
    payload_file: String,
    /// Concrete requested delivery mode for the natural host verification.
    mode: bridge_protocol::Mode,
}

/// Exchanges one public v1 frame and validates exact operation/receipt binding.
/// Uses the existing fixture Unix sender; no SDK/core/private operation required.
/// Errors are bounded static fixture categories, never body/proof/credential text.
fn universal_exchange(
    socket: &str,
    request: &bridge_protocol::Request,
) -> Result<bridge_protocol::OperationResult, &'static str> {
    let response = core_call(socket, request);
    let bytes = serde_json::to_vec(&response).map_err(|_| "response encoding failed")?;
    let response =
        bridge_protocol::decode_response(&bytes, request).map_err(|_| "v1 response refused")?;
    response.result.ok_or("v1 request refused")
}

/// Registers from actual separated framework metadata, then publishes hidden
/// payload through the returned route. No model argument, cwd or env is identity.
/// Result contains receipt facts only; hidden payload visibility is independent.
fn universal_probe(
    channel: &str,
    core: &str,
    token: &str,
    config: &UniversalProbe,
    metadata: serde_json::Map<String, Value>,
) -> Value {
    use bridge_protocol::*;
    let host = match PresentedMeta::from_mcp_meta(&metadata) {
        Ok(PresentedMeta::Codex { .. }) => Host::Codex,
        Ok(PresentedMeta::Claude { .. }) => Host::ClaudeCode,
        Ok(PresentedMeta::OpenCode { .. }) => Host::OpenCode,
        _ => return json!({"error": "native evidence candidate refused"}),
    };
    let request = Request::new(
        &config.request_id,
        Secret::new(token),
        Operation::RegisterCall(RegisterCallParams {
            operation_key: config.operation_key.clone(),
            evidence: Some(CallEvidence::Native { host, metadata }),
            reply_policy: ReplyPolicy::SelfActor,
            allowed_modes: Some(vec![config.mode]),
            allowed_kinds: None,
            max_payload_bytes: None,
            route_expires_at_ms: None,
            assertion_audience: None,
            invocation_key: None,
        }),
    );
    let Ok(request) = request else {
        return json!({"error": "registration configuration refused"});
    };
    let Ok(OperationResult::RegisterCall(registration)) = universal_exchange(channel, &request)
    else {
        return json!({"error": "registration refused"});
    };
    let payload = match std::fs::read_to_string(&config.payload_file)
        .ok()
        .and_then(|value| Payload::new(value).ok())
    {
        Some(payload) => payload,
        None => return json!({"error": "payload file refused"}),
    };
    let request = Request::new(
        format!("publish-{}", config.request_id),
        Secret::new(token),
        Operation::Publish(PublishParams {
            destination: Destination::Route {
                route_key: registration.receipt.route_key.clone(),
            },
            event_id: config.event_id.clone(),
            kind: config.kind.clone(),
            payload,
            mode: config.mode,
            policy: Policy::KeepAll,
            metadata: Metadata::new(),
            expires_at_ms: None,
            delivery_scope_key: None,
        }),
    );
    let Ok(request) = request else {
        return json!({"error": "publication configuration refused"});
    };
    match universal_exchange(core, &request) {
        Ok(OperationResult::Publish(result)) => json!({"registration": registration.receipt,
            "assertion_present": registration.assertion.is_some(), "publication": result.receipt}),
        _ => json!({"error": "publication refused", "registration": registration.receipt}),
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

/// Dispatches owned fixture modes using each match arm's argument handling.
/// Missing/unrecognized modes and rejected length-guarded arms reach static
/// usage and exit two. Unguarded arms can ignore extra argv, default missing
/// positions to empty strings, or panic when a required path is unwrapped
/// (`desktop-child`). Credential-bearing modes load private owned token files,
/// never token values from argv. Modes perform the documented
/// stdio, socket, owned-file or child-process actions, terminate at input EOF
/// where applicable, and panic on fixture setup failures; no global install,
/// consumer configuration, authority inference from model arguments or network
/// package fetching is performed.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("harness") => harness(),
        Some("owner") => owner(args.get(2).map(String::as_str).unwrap_or_default()),
        Some("delayed-hook") => delayed_hook(args.get(2).map(String::as_str).unwrap_or_default()),
        Some("desktop-child") => desktop_child(args.get(2).unwrap()),
        Some("mcp") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), false),
        Some("mcp-seal") => mcp(args.get(2).map(String::as_str).unwrap_or_default(), true),
        Some("relay") => relay(args.get(2).map(String::as_str).unwrap_or_default()),
        Some("v1-frontend") => {
            v1_frontend(args.get(2).map(String::as_str).unwrap_or_default(), false)
        }
        Some("v1-lost-ack") => {
            v1_frontend(args.get(2).map(String::as_str).unwrap_or_default(), true)
        }
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
                None,
            );
        }
        Some("universal-mcp") if args.len() == 7 => {
            let config: UniversalProbe = serde_json::from_str(
                &std::fs::read_to_string(&args[6]).expect("owned probe config"),
            )
            .expect("probe configuration");
            mcp_server(
                &args[2],
                &args[3],
                &credential(&args[4]),
                &args[5],
                &[config.tool_name.as_str()],
                Some(&config),
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
