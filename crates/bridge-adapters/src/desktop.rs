//! Source-labelled Codex application delivery through its native tools pipe.
//!
//! The pipe is inherited only by the application-authorized MCP frontend.
//! The daemon hands off through its protected typed frontend relay, whose
//! kernel ancestry must match the attested recipient harness incarnation.
//! This client sends `tools/list` and exactly `send_message_to_thread`, using
//! the same host contract as agent-run. It never accepts a pipe, tool name,
//! namespace, or caller identity from message payloads. A single deadline
//! bounds connect, every partial read/write and framing; failures after the
//! message request starts are unknown and never fall back to a second route.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
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
fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let n = stream.read(bytes)?;
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

/// Exchanges one correlated native-host JSON-RPC frame with a four-byte
/// little-endian length prefix. Bounds JSON bytes before allocation and checks
/// version, response id and result shape. All failures return an I/O error;
/// diagnostics contain no message, pipe, credentials or host error text.
fn rpc(
    stream: &mut UnixStream,
    id: u64,
    method: &str,
    params: Value,
    deadline: Instant,
) -> std::io::Result<Value> {
    let raw =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
    if raw.len() > MAX_FRAME_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut frame = (raw.len() as u32).to_le_bytes().to_vec();
    frame.extend(raw);
    let mut bytes = frame.as_slice();
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let n = stream.write(bytes)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        bytes = &bytes[n..];
    }
    let mut header = [0; 4];
    read_exact(stream, &mut header, deadline)?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut reply = vec![0; size];
    read_exact(stream, &mut reply, deadline)?;
    let value: Value = serde_json::from_slice(&reply)?;
    if value["jsonrpc"] != "2.0"
        || value["id"] != id
        || value.get("error").is_some()
        || !value["result"].is_object()
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(value["result"].clone())
}

/// Delivers `text` once to the attested `thread_id` through `pipe`, with
/// `call_id` as host correlation identity and `owner_uid` as the expected
/// server user. Parameters are adapter-owned facts, never arbitrary passthrough.
/// Read-only discovery failures are known-unsent. A positive host success is
/// native acceptance, not context/processing evidence; any other outcome after
/// starting tools/call is unknown. The pipe path and raw host diagnostics never
/// appear in evidence, and there is no ordinary-queue fallback on failure.
pub fn deliver(pipe: &Path, thread_id: &str, call_id: &str, text: &str, owner_uid: u32) -> Outcome {
    if !pipe.is_absolute() {
        return Outcome::KnownUnsent {
            evidence: "Codex application pipe path is not absolute; nothing sent".into(),
        };
    }
    let deadline = Instant::now() + HOST_TIMEOUT;
    let mut stream = match connect(pipe, deadline) {
        Ok(stream) => stream,
        Err(_) => {
            return Outcome::KnownUnsent {
                evidence: "Codex application pipe unavailable before sending".into(),
            };
        }
    };
    if !os::peer_identity(&stream).is_ok_and(|peer| peer.uid == owner_uid) {
        return Outcome::KnownUnsent {
            evidence: "Codex application pipe has an unqualified owner".into(),
        };
    }
    let namespace = rpc(
        &mut stream,
        1,
        "tools/list",
        json!({"threadStartKind":"all"}),
        deadline,
    )
    .ok()
    .and_then(|result| {
        result["tools"]
            .as_array()
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|tool| tool["name"] == "send_message_to_thread")
            })
            .cloned()
    })
    .and_then(|tool| {
        tool["namespace"]
            .as_str()
            .filter(|name| !name.is_empty() && name.len() <= 256)
            .map(str::to_owned)
    });
    let Some(namespace) = namespace else {
        return Outcome::KnownUnsent {
            evidence: "Codex application message tool unavailable; nothing sent".into(),
        };
    };
    let result = rpc(
        &mut stream,
        2,
        "tools/call",
        json!({
            "arguments":{"threadId":thread_id,"prompt":text},
            "callerSource":"codex","callId":call_id,"namespace":namespace,
            "threadId":thread_id,"tool":"send_message_to_thread","turnId":call_id
        }),
        deadline,
    );
    match result {
        Ok(value) if value["success"] == true => Outcome::NativeAccepted { evidence: format!("Codex application send_message_to_thread accepted {call_id}; source-labelled native route") },
        _ => Outcome::OutcomeUnknown { reason: "Codex application message request may have been written without positive native acceptance; never resend or use a fallback".into() },
    }
}

#[cfg(test)]
mod tests {
    //! Real Unix-socket native-host framing and conservative outcome controls.
    use super::*;
    use std::os::unix::net::UnixListener;

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
            let result = deliver(&path, "owned-thread", "bridge-call", "marker", uid);
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

/// Starts a typed message-only relay inside the harness-launched MCP frontend
/// when it receives the application's native pipe capability. The native host
/// sees the registered frontend as its caller, rather than the resident daemon.
/// A missing capability returns None (ordinary CLI host); binding failure errors.
/// The listener receives no arbitrary host methods, namespace or identity fields.
pub fn start_frontend(channel: &Path) -> std::io::Result<Option<FrontendRelay>> {
    let Some(pipe) = std::env::var_os("CODEX_APP_TOOLS_PIPE_PATH") else {
        return Ok(None);
    };
    start_frontend_with_pipe(channel, std::path::PathBuf::from(pipe))
}

/// Binds the protected frontend relay to an already-authorized native host pipe.
/// This helper isolates endpoint injection in owned tests without mutating the
/// process environment; production passes only its inherited capability.
fn start_frontend_with_pipe(
    channel: &Path,
    pipe: std::path::PathBuf,
) -> std::io::Result<Option<FrontendRelay>> {
    let parent = channel.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let path = parent.join(format!("ui-{}.sock", std::process::id()));
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
                Ok(deliver(
                    &pipe,
                    &request.thread_id,
                    &request.call_id,
                    &request.text,
                    owner.uid,
                ))
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
/// used; filenames are not identity. The connected socket is rechecked below.
pub fn frontend_for(directory: &Path, harness: (u32, u64)) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(directory).ok()?;
    for entry in entries.take(512).flatten() {
        let name = entry.file_name();
        let name = name.to_str()?;
        let Some(pid) = name
            .strip_prefix("ui-")
            .and_then(|n| n.strip_suffix(".sock"))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if os::ancestry(pid)
            .iter()
            .skip(1)
            .any(|p| (p.pid, p.start_time) == harness)
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
