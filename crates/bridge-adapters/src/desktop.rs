//! Source-labelled Codex application delivery through its native tools pipe.
//!
//! The pipe is inherited only by the application-authorized MCP frontend.
//! The daemon hands off through its protected typed frontend relay, whose
//! kernel ancestry must match the attested recipient harness incarnation.
//! The supplied signed Node runtime sends `tools/list` and exactly
//! `send_message_to_thread`, using
//! the same host contract as agent-run. It never accepts a pipe, tool name,
//! namespace, or caller identity from message payloads. A single deadline
//! bounds connect, every partial read/write and framing; failures after the
//! message request starts are unknown and never fall back to a second route.

use std::io::{Read, Write};
#[cfg(test)]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bridge_core::dispatch::Outcome;
use serde_json::{Value, json};

use crate::os;

/// Maximum native-host response bytes, matching the application's contract.
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Total delivery deadline, including the read-only inventory request.
const HOST_TIMEOUT: Duration = Duration::from_secs(8);

/// Connects a native Unix pipe under `deadline`, canceling a stalled connect.
/// Returns a blocking stream after removing it from the temporary reactor.
/// I/O, runtime creation and elapsed-deadline failures return an error.
fn connect(pipe: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let stream = runtime.block_on(async {
        tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            tokio::net::UnixStream::connect(pipe),
        )
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
    })?;
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// Reads exactly `bytes.len()` bytes without renewing the absolute deadline.
/// EOF, socket failure or expiration refuses the frame; partial bytes are not used.
/// macOS can reject SO_RCVTIMEO after a peer closes despite buffered reply bytes;
/// in that case only a nonblocking drain is attempted, never an unbounded read.
fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let n = match stream.set_read_timeout(Some(remaining(deadline)?)) {
            Ok(()) => stream.read(bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                stream.set_nonblocking(true)?;
                let read = stream.read(bytes);
                stream.set_nonblocking(false)?;
                read?
            }
            Err(error) => return Err(error),
        };
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}

/// Returns the positive remaining deadline budget, or a timeout error.
fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(std::io::ErrorKind::TimedOut.into())
    } else {
        Ok(duration)
    }
}

/// Delivers one message using the application-supplied signed `node` runtime.
/// The native tools pipe rejects unsigned Rust clients on macOS; the installed
/// host capability, rather than a caller-selected executable, supplies `node`.
/// Its inherited host context is preserved: clearing the MCP environment causes
/// the native pipe to close before tool discovery. No environment values are logged.
/// `pipe` is the inherited native socket, `owner_uid` its required file owner,
/// and remaining inputs are the adapter's frozen target, attempt id and manifest.
/// One closed stdin request selects no methods; the embedded script owns fixed
/// tools/list and send_message_to_thread calls. The existing child watchdog
/// bounds every write/read and kills/reaps on all exits. Missing capabilities
/// and pre-call failures are known-unsent; missing/negative post-call receipts
/// are unknown. No raw host diagnostics, pipe paths or body enter evidence.
#[cfg(test)]
fn deliver(
    node: &Path,
    pipe: &Path,
    thread_id: &str,
    call_id: &str,
    text: &str,
    owner_uid: u32,
) -> Outcome {
    if !node.is_absolute()
        || !node.is_file()
        || !pipe.is_absolute()
        || !std::fs::symlink_metadata(pipe).is_ok_and(|m| {
            m.uid() == owner_uid && std::os::unix::fs::FileTypeExt::is_socket(&m.file_type())
        })
    {
        return Outcome::KnownUnsent {
            evidence: "Codex signed runtime or native socket is unqualified; nothing sent".into(),
        };
    }
    let deadline = Instant::now() + HOST_TIMEOUT;
    let mut command = std::process::Command::new(node);
    command
        .arg("-e")
        .arg(include_str!("../assets/desktop-client.cjs"))
        .env("CODEX_APP_TOOLS_PIPE_PATH", pipe);
    let mut child = match crate::codex::Running::start(command, deadline) {
        Ok(child) => child,
        Err(_) => {
            return Outcome::KnownUnsent {
                evidence: "Codex signed client did not start; nothing sent".into(),
            };
        }
    };
    if child
        .write(&json!({"thread_id":thread_id,"call_id":call_id,"text":text}))
        .is_err()
    {
        return Outcome::OutcomeUnknown {
            reason: "signed client request may have been written; no automatic resend".into(),
        };
    }
    match child.response(1, deadline).map(|v| v["result"].clone()) {
        Some(v) if v["state"] == "accepted" => Outcome::NativeAccepted { evidence: format!("Codex application send_message_to_thread accepted {call_id}; source-labelled native route") },
        Some(v) if v["state"] == "known_unsent" => Outcome::KnownUnsent { evidence: "Codex application message tool unavailable; nothing sent".into() },
        _ => Outcome::OutcomeUnknown { reason: "Codex signed client may have called the native message tool without positive acceptance; never resend or fall back".into() },
    }
}

#[cfg(test)]
mod tests {
    //! Real Unix-socket native-host framing and conservative outcome controls.
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Returns the prepared absolute Node test runtime; missing provision is an
    /// explicit skipped host-transport check, never an implicit install or PATH fallback.
    fn test_node() -> Option<std::path::PathBuf> {
        let node = std::env::var_os("BRIDGE_TEST_NODE").map(std::path::PathBuf::from);
        if node.is_none() {
            eprintln!("native client check skipped: BRIDGE_TEST_NODE is not provisioned");
        }
        node
    }

    /// Reads one complete trusted mock request using the production framing bound.
    fn request(stream: &mut UnixStream) -> Value {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut head = [0; 4];
        read_exact(stream, &mut head, deadline).unwrap();
        let size = u32::from_le_bytes(head) as usize;
        assert!(size <= MAX_FRAME_BYTES);
        let mut bytes = vec![0; size];
        read_exact(stream, &mut bytes, deadline).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Writes one trusted fixture response with the application's native framing.
    fn reply(stream: &mut UnixStream, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
    }

    /// One fixed message tool call, exact destination and source metadata are
    /// mandatory. Missing discovery is known-unsent; lost, negative and
    /// miscorrelated answers after the call are unknown, never resent.
    #[test]
    fn native_delivery_has_one_scoped_call_and_conservative_receipts() {
        let Some(node) = test_node() else {
            return;
        };
        let uid = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        for case in ["accepted", "lost", "negative", "wrong_id", "missing"] {
            let entropy = os::random_bytes().unwrap();
            let name = format!(
                "bd{:x}{:x}.s",
                u64::from_le_bytes(entropy[..8].try_into().unwrap()),
                std::process::id()
            );
            let path = std::env::temp_dir().join(name);
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let inventory = request(&mut stream);
                assert_eq!(inventory["method"], "tools/list");
                assert_eq!(inventory["params"], json!({"threadStartKind":"all"}));
                let tools = if case == "missing" {
                    json!([])
                } else {
                    json!([{"name":"send_message_to_thread","namespace":"codex_app"}])
                };
                reply(
                    &mut stream,
                    json!({"jsonrpc":"2.0","id":1,"result":{"tools":tools}}),
                );
                if case == "missing" {
                    return;
                }
                let call = request(&mut stream);
                assert_eq!(call["method"], "tools/call");
                assert_eq!(
                    call["params"],
                    json!({"arguments":{"threadId":"owned-thread","prompt":"marker"},"callerSource":"codex","callId":"bridge-call","namespace":"codex_app","threadId":"owned-thread","tool":"send_message_to_thread","turnId":"bridge-call"})
                );
                if case == "lost" {
                    return;
                }
                reply(
                    &mut stream,
                    json!({"jsonrpc":"2.0","id":if case=="wrong_id" {3} else {2},"result":{"success":case!="negative"}}),
                );
                // There is no second tool call or ordinary-queue fallback.
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).unwrap(), 0);
            });
            let result = deliver(&node, &path, "owned-thread", "bridge-call", "marker", uid);
            assert!(
                match case {
                    "accepted" => matches!(result, Outcome::NativeAccepted { .. }),
                    "missing" => matches!(result, Outcome::KnownUnsent { .. }),
                    _ => matches!(result, Outcome::OutcomeUnknown { .. }),
                },
                "{case}: {result:?}"
            );
            server.join().unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }

    /// The typed frontend relay preserves exact host arguments and returns native
    /// acceptance through real kernel-identified sockets, without environment edits.
    #[test]
    fn frontend_handoff_reaches_one_native_message_call() {
        let Some(node) = test_node() else {
            return;
        };
        let entropy = os::random_bytes().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "bf{:x}",
            u64::from_le_bytes(entropy[..8].try_into().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let channel = dir.join("c.sock");
        let daemon = UnixListener::bind(&channel).unwrap();
        let channel_peer = std::thread::spawn(move || daemon.accept().unwrap().0);
        let pipe = dir.join("h.sock");
        let host = UnixListener::bind(&pipe).unwrap();
        let native = std::thread::spawn(move || {
            let (mut stream, _) = host.accept().unwrap();
            assert_eq!(request(&mut stream)["method"], "tools/list");
            reply(
                &mut stream,
                json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"send_message_to_thread","namespace":"codex_app"}]}}),
            );
            let call = request(&mut stream);
            assert_eq!(
                call["params"]["arguments"],
                json!({"threadId":"owned-thread","prompt":"marker"})
            );
            assert_eq!(call["params"]["callerSource"], "codex");
            reply(
                &mut stream,
                json!({"jsonrpc":"2.0","id":2,"result":{"success":true}}),
            );
        });
        let parent = &os::ancestry(std::process::id())[1];
        let incarnation = (parent.pid, parent.start_time);
        let stale = dir.join(format!(
            "{}{:010}.sock",
            frontend_prefix(),
            std::process::id()
        ));
        drop(UnixListener::bind(&stale).unwrap());
        assert!(frontend_for(&dir, incarnation).is_none());
        let guard = start_frontend_with_pipe(&channel, pipe, node)
            .unwrap()
            .unwrap();
        let result = via_frontend(
            &guard.path,
            (parent.pid, parent.start_time),
            "owned-thread",
            "bridge-call",
            "marker",
        );
        assert!(
            matches!(result, Outcome::NativeAccepted { .. }),
            "{result:?}"
        );
        native.join().unwrap();
        drop(channel_peer.join().unwrap());
        drop(guard);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Partial reads cannot renew the shared timeout, preventing slow frames
    /// from keeping a hand-off alive beyond its absolute deadline.
    #[test]
    fn partial_reads_do_not_renew_the_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let send = std::thread::spawn(move || {
            for _ in 0..4 {
                let _ = writer.write_all(&[1]);
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let started = Instant::now();
        assert!(
            read_exact(
                &mut reader,
                &mut [0; 4],
                started + Duration::from_millis(45)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        drop(reader);
        send.join().unwrap();
    }
}

/// Returns the compiled frontend build's private socket prefix. Rolling upgrades
/// prefer their own client implementation; compatible signed primary clients
/// survive daemon-only upgrades. Local tests use the fixed dev label, never runtime
/// environment values supplied by a request or changed after compilation.
fn frontend_prefix() -> String {
    format!(
        "ui2-{}-",
        option_env!("BRIDGE_BUILD_LABEL").unwrap_or("dev")
    )
}

/// Lifetime guard for the app-authorized MCP frontend's private delivery relay.
/// Dropping it removes only its owned socket; the process exit ends its worker.
/// The worker holds the host endpoint solely in memory and accepts only the
/// actual current adapter daemon identified through the private channel socket.
pub struct FrontendRelay {
    /// Exclusively bound relay endpoint, under the protected adapter directory.
    path: std::path::PathBuf,
}

impl Drop for FrontendRelay {
    /// Unlinks only this instance's socket; never removes its parent directory.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Replaces the app-launched MCP process with the supplied signed Node frontend,
/// preserving its PID and inherited host context as agent-run does. The frontend
/// starts the same Rust binary with capability variables removed and a private
/// descriptor; missing app capabilities are ordinary CLI operation. Exec errors
/// return a fixed error before opening a delivery relay, never an unsigned fallback.
pub fn exec_frontend() -> std::io::Result<()> {
    let (Some(pipe), Some(node)) = (
        std::env::var_os("CODEX_APP_TOOLS_PIPE_PATH"),
        std::env::var_os("CODEX_MCP_NODE_PATH"),
    ) else {
        return Ok(());
    };
    if !Path::new(&pipe).is_absolute()
        || !Path::new(&node).is_absolute()
        || !Path::new(&node).is_file()
    {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    Err(std::process::Command::new(node)
        .arg("-e")
        .arg(include_str!("../assets/desktop-client.cjs"))
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(std::env::args_os().skip(1))
        .exec())
}

/// Starts a typed message-only relay inside the harness-launched MCP frontend
/// when it receives the application's native pipe capability. The native host
/// sees the registered frontend as its caller, rather than the resident daemon.
/// A missing pipe returns None (ordinary CLI host); missing signed Node or binding failures error.
/// The listener receives no arbitrary host methods, namespace or identity fields.
pub fn start_frontend(channel: &Path) -> std::io::Result<Option<FrontendRelay>> {
    let Some(parent) = std::env::var_os("BRIDGE_DESKTOP_PARENT_PID") else {
        return Ok(None);
    };
    let parent: u32 = parent
        .to_str()
        .and_then(|p| p.parse().ok())
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    if os::process_facts(std::process::id()).and_then(|p| p.parent) != Some(parent) {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fd/3")?;
    let fd: std::os::fd::OwnedFd = file.into();
    let stream = UnixStream::from(fd);
    let peer = os::peer_identity(&stream)?;
    if peer.pid != parent
        || os::process_facts(std::process::id()).and_then(|p| p.uid) != Some(peer.uid)
    {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let parent = Arc::new(Mutex::new(Some(stream)));
    start_frontend_with_delivery(channel, move |request, _owner| {
        let mut guard = match parent.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Outcome::OutcomeUnknown {
                    reason: "signed frontend channel state unavailable; never resend".into(),
                };
            }
        };
        let Some(stream) = guard.as_mut() else {
            return Outcome::KnownUnsent {
                evidence: "signed frontend channel closed before sending".into(),
            };
        };
        let deadline = Instant::now() + HOST_TIMEOUT;
        let result = exchange(
            stream,
            &json!({"thread_id":request.thread_id,"call_id":request.call_id,"text":request.text}),
            deadline,
        );
        match result {
            Ok(v) if v["call_id"] == request.call_id && v["state"] == "accepted" => {
                Outcome::NativeAccepted {
                    evidence: format!("signed Codex frontend accepted {}", request.call_id),
                }
            }
            Ok(v) if v["call_id"] == request.call_id && v["state"] == "known_unsent" => {
                Outcome::KnownUnsent {
                    evidence: "Codex application refused before message send".into(),
                }
            }
            _ => {
                guard.take();
                Outcome::OutcomeUnknown { reason: "signed frontend request lacks a correlated receipt; channel closed, never resent".into() }
            }
        }
    })
}

/// Exchanges one bounded typed frontend frame under one absolute deadline.
/// Returns decoded JSON or an I/O/JSON error; callers conservatively retain any
/// failure after write and check their own connection or explicit correlation.
fn exchange(stream: &mut UnixStream, request: &Value, deadline: Instant) -> std::io::Result<Value> {
    let body = serde_json::to_vec(request)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&(body.len() as u32).to_le_bytes())?;
    stream.write_all(&body)?;
    let mut head = [0; 4];
    read_exact(stream, &mut head, deadline)?;
    let n = u32::from_le_bytes(head) as usize;
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0; n];
    read_exact(stream, &mut body, deadline)?;
    Ok(serde_json::from_slice(&body)?)
}

/// Binds the protected frontend relay to an authorized host pipe and signed runtime.
/// This helper isolates endpoint injection in owned tests without mutating the
/// process environment; production passes only its inherited capability.
#[cfg(test)]
fn start_frontend_with_pipe(
    channel: &Path,
    pipe: std::path::PathBuf,
    node: std::path::PathBuf,
) -> std::io::Result<Option<FrontendRelay>> {
    start_frontend_with_delivery(channel, move |request, owner| {
        deliver(
            &node,
            &pipe,
            &request.thread_id,
            &request.call_id,
            &request.text,
            owner,
        )
    })
}

/// Serves authenticated daemon requests through one fixed delivery callback.
/// The callback receives only the closed frozen manifest and kernel owner uid;
/// all peer checks and listener lifetime remain shared by production and tests.
fn start_frontend_with_delivery(
    channel: &Path,
    delivery: impl Fn(&FrontendRequest, u32) -> Outcome + Send + 'static,
) -> std::io::Result<Option<FrontendRelay>> {
    let parent = channel.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let path = parent.join(format!("{}{}.sock", frontend_prefix(), std::process::id()));
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let channel = channel.to_path_buf();
    std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut stream) = accepted else {
                break;
            };
            let outcome = (|| -> std::io::Result<Outcome> {
                let peer = os::peer_identity(&stream)?;
                let daemon = UnixStream::connect(&channel)?;
                let owner = os::peer_identity(&daemon)?;
                if peer != owner {
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                let deadline = Instant::now() + HOST_TIMEOUT;
                let mut header = [0; 4];
                read_exact(&mut stream, &mut header, deadline)?;
                let n = u32::from_le_bytes(header) as usize;
                if n == 0 || n > MAX_FRAME_BYTES {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                let mut body = vec![0; n];
                read_exact(&mut stream, &mut body, deadline)?;
                let request: FrontendRequest = serde_json::from_slice(&body)?;
                if request.thread_id.is_empty()
                    || request.call_id.is_empty()
                    || request.text.len() > bridge_core::framing::MAX_FRAMED_BYTES
                {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                Ok(delivery(&request, owner.uid))
            })();
            let value = match outcome {
                Ok(Outcome::NativeAccepted { evidence }) => {
                    json!({"state":"accepted","detail":evidence})
                }
                Ok(Outcome::KnownUnsent { evidence }) => {
                    json!({"state":"known_unsent","detail":evidence})
                }
                Ok(Outcome::OutcomeUnknown { reason }) => {
                    json!({"state":"unknown","detail":reason})
                }
                _ => {
                    json!({"state":"known_unsent","detail":"frontend caller or request refused before host send"})
                }
            };
            if let Ok(bytes) = serde_json::to_vec(&value) {
                let _ = stream.set_write_timeout(Some(HOST_TIMEOUT));
                let _ = stream.write_all(&(bytes.len() as u32).to_le_bytes());
                let _ = stream.write_all(&bytes);
            }
        }
    });
    Ok(Some(FrontendRelay { path }))
}

/// Closed daemon-to-frontend request. The daemon owns exact target and attempt
/// identity; text is the already frozen source-framed manifest, never a tool call.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FrontendRequest {
    /// Attested recipient native session identifier.
    thread_id: String,
    /// Existing attempt correlation identifier; never a fresh retry id.
    call_id: String,
    /// Frozen escaped manifest with the external-data provenance statement.
    text: String,
}

/// Finds a live Bridge frontend socket belonging to the exact recipient harness
/// incarnation. Only kernel PID/ancestry and the protected channel directory are
/// used; filenames are not identity. A bounded, read-only connection probe skips
/// dead sockets even when their filename PID was reused. Only signed-client
/// protocol endpoints are preferred from this build; older labelled endpoints
/// remain eligible only under a primary Node process. The native application still
/// enforces its signed-client authorization; a filename grants no authority.
/// The sending connection
/// is independently rechecked below; probing never writes a request.
pub fn frontend_for(directory: &Path, harness: (u32, u64)) -> Option<std::path::PathBuf> {
    let prefix = frontend_prefix();
    // ponytail: bounded 512-entry scan; maintain a live index if this ceiling matters.
    let mut entries: Vec<_> = std::fs::read_dir(directory)
        .ok()?
        .take(512)
        .flatten()
        .collect();
    entries.sort_by_key(|entry| !entry.file_name().to_string_lossy().starts_with(&prefix));
    let deadline = Instant::now() + HOST_TIMEOUT;
    for entry in entries {
        let name = entry.file_name();
        let name = name.to_str()?;
        let Some(pid) = name
            .strip_prefix("ui2-")
            .and_then(|n| n.strip_suffix(".sock"))
            .and_then(|n| n.rsplit_once('-'))
            .and_then(|(_, pid)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        let chain = os::ancestry(pid);
        if !chain
            .iter()
            .skip(1)
            .any(|p| (p.pid, p.start_time) == harness)
            || (!name.starts_with(&prefix)
                && !chain
                    .get(1)
                    .and_then(|p| p.exe.as_ref())
                    .and_then(|exe| exe.file_name())
                    .is_some_and(|name| name == "node"))
        {
            continue;
        }
        // A dead socket can share a reused PID with a current harness child.
        // Probe without writing; EOF cannot initiate a native message.
        if let Ok(stream) = connect(&entry.path(), deadline)
            && os::peer_identity(&stream).is_ok_and(|peer| peer.pid == pid)
        {
            return Some(entry.path());
        }
    }
    None
}

/// Delivers once through a registered frontend for `harness`. A connection or
/// peer mismatch is known-unsent; after any request write the result is unknown
/// unless a valid typed receipt says accepted/known-unsent. No host/queue fallback.
pub fn via_frontend(
    path: &Path,
    harness: (u32, u64),
    thread_id: &str,
    call_id: &str,
    text: &str,
) -> Outcome {
    let deadline = Instant::now() + HOST_TIMEOUT + Duration::from_secs(2);
    let mut stream = match connect(path, deadline) {
        Ok(s) => s,
        Err(_) => {
            return Outcome::KnownUnsent {
                evidence: "registered Codex frontend unavailable before sending".into(),
            };
        }
    };
    let trusted = os::peer_identity(&stream).is_ok_and(|p| {
        os::ancestry(p.pid)
            .iter()
            .skip(1)
            .any(|a| (a.pid, a.start_time) == harness)
    });
    if !trusted {
        return Outcome::KnownUnsent {
            evidence: "Codex frontend is not owned by the attested recipient harness".into(),
        };
    }
    let result = (|| -> std::io::Result<Value> {
        let body =
            serde_json::to_vec(&json!({"thread_id":thread_id,"call_id":call_id,"text":text}))?;
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        stream.write_all(&(body.len() as u32).to_le_bytes())?;
        stream.write_all(&body)?;
        let mut head = [0; 4];
        read_exact(&mut stream, &mut head, deadline)?;
        let n = u32::from_le_bytes(head) as usize;
        if n == 0 || n > MAX_FRAME_BYTES {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut body = vec![0; n];
        read_exact(&mut stream, &mut body, deadline)?;
        Ok(serde_json::from_slice(&body)?)
    })();
    match result {
        Ok(v) if v["state"]=="accepted" => Outcome::NativeAccepted{evidence:format!("Codex application frontend accepted {call_id}; source-labelled native route")},
        Ok(v) if v["state"]=="known_unsent" => Outcome::KnownUnsent{evidence:v["detail"].as_str().unwrap_or("frontend refused before host send").to_string()},
        _ => Outcome::OutcomeUnknown{reason:"Codex frontend hand-off may have reached the application; no fallback or automatic resend".into()},
    }
}
