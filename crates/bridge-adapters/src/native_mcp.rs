//! Transparent OpenCode MCP transport preserving the frontend direct native parent.
//! Only that kernel-verified native process supplies protected ToolContext;
//! ordinary MCP arguments never identify callers.

use crate::{os, server};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::{fd::AsFd, unix::process::CommandExt};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::Duration,
};

/// The pinned native client's own complete NDJSON frame limit, including newline.
const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Finite private control, bootstrap readiness and flush allowance; never retries effects.
const IO_TIME: Duration = Duration::from_secs(5);

/// Actual protected executor context, retained only until its original execution ends.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    /// Actual native session, independently echoed in the client's MCP metadata.
    session_id: String,
    /// Actual ToolContext.id; the unchanged Bridge registry still joins its hook.
    call_id: String,
    /// Unprefixed method from the native MCP tool definition.
    tool: String,
    /// Executed arguments used only for exact correlation, never as caller authority.
    arguments: Value,
}

/// Parent-only control; wrong namespaces, overlap and unrelated ends refuse.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    /// Install the current protected executor after its per-server lane is acquired.
    Begin {
        /// Exact original MCP namespace.
        server: String,
        /// Actual native execution context.
        context: Context,
    },
    /// Clear only the same completed or cancelled executor.
    End {
        /// Exact original MCP namespace.
        server: String,
        /// Native invocation being ended.
        call_id: String,
    },
}

/// Complete private transport events; payloads deliberately have no Debug output.
enum Event {
    /// MCP input from the original client.
    Client(Vec<u8>),
    /// MCP output from the original backend.
    Backend(Vec<u8>),
    /// An owned stream ended.
    Closed,
    /// A bounded reader or writer failed.
    Failed(io::Error),
    /// Kernel-validated parent control and its acknowledgement.
    Control(Control, mpsc::SyncSender<bool>),
}

/// Safe per-call refusal; possible prior writes stay distinct from missing input.
#[derive(Debug)]
enum ContextFault {
    /// No protected native invocation was supplied.
    Unavailable,
    /// Protected invocation and actual wire request disagree.
    Mismatch,
    /// This native invocation may already have reached its backend.
    AlreadyForwarded,
}

/// Managed endpoint guard; never unlinks a replacement inode.
struct SocketGuard {
    /// Exact owned socket.
    path: PathBuf,
    /// Device identity at bind.
    device: u64,
    /// Inode identity at bind.
    inode: u64,
}
impl Drop for SocketGuard {
    /// Remove only this unchanged socket when its proxy exits.
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Bootstrap-owned transport worker; setup/exec failures kill and reap this child.
/// Successful exec retains frontend ancestry; worker EOF ends its process lifetime.
struct Sidecar(Child);
impl Drop for Sidecar {
    /// Signal only the actual owned Child handle and always reap it.
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Derives a bounded resource name; neither the PID nor hash grants authority.
pub fn socket_path(directory: &Path, native_pid: u32, server: &str) -> PathBuf {
    let digest = format!("{:x}", Sha256::digest(server.as_bytes()));
    directory.join(format!("mcp-{native_pid}-{}.sock", &digest[..20]))
}

/// Reads one bounded complete frame; partial EOF and oversize fail before forwarding.
fn frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let n = reader
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(io::Error::other("invalid native MCP frame"));
    }
    Ok(Some(bytes))
}

/// Readers own no subprocess; they cannot outlive this CLI process. Bounded queues
/// prevent unlimited buffering. Backend/parent closure terminates the proxy process.
fn pump<R: Read + Send + 'static>(input: R, send: SyncSender<Event>, client: bool) {
    thread::spawn(move || {
        let mut input = BufReader::new(input);
        loop {
            let event = match frame(&mut input) {
                Ok(Some(bytes)) => {
                    if client {
                        Event::Client(bytes)
                    } else {
                        Event::Backend(bytes)
                    }
                }
                Ok(None) => Event::Closed,
                Err(e) => Event::Failed(e),
            };
            let stop = matches!(event, Event::Closed | Event::Failed(_));
            if send.send(event).is_err() || stop {
                return;
            }
        }
    });
}

/// A bounded output lane keeps the main loop responsive to EOF even if a peer
/// stops reading. Saturation closes the transport rather than replaying an effect.
fn writer<W: Write + Send + 'static>(
    mut output: W,
    send: SyncSender<Event>,
) -> (
    SyncSender<Vec<u8>>,
    mpsc::Receiver<Result<(), io::ErrorKind>>,
) {
    let (queue, frames) = mpsc::sync_channel::<Vec<u8>>(8);
    let (finished, done) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut result = Ok(());
        for bytes in frames {
            if let Err(e) = output.write_all(&bytes).and_then(|()| output.flush()) {
                result = Err(e.kind());
                let _ = send.send(Event::Failed(e));
                break;
            }
        }
        let _ = finished.send(result);
    });
    (queue, done)
}

/// Checks identifier shape; caller authority still comes from parent credentials and native hooks.
fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

/// Enrich exactly one matching native call, preserving arguments and every existing
/// metadata field. Consume before any possible backend write; never retry effects.
fn enrich(value: &mut Value, active: &mut Option<(Context, bool)>) -> Result<(), ContextFault> {
    if value.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(());
    }
    let (context, used) = active.as_mut().ok_or(ContextFault::Unavailable)?;
    let p = value
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .ok_or(ContextFault::Mismatch)?;
    let matches = p.get("name").and_then(Value::as_str) == Some(context.tool.as_str())
        && p.get("arguments").map_or_else(
            || {
                context
                    .arguments
                    .as_object()
                    .is_some_and(|object| object.is_empty())
            },
            |arguments| arguments == &context.arguments,
        );
    let m = p
        .get_mut("_meta")
        .and_then(Value::as_object_mut)
        .ok_or(ContextFault::Mismatch)?;
    if *used {
        return Err(ContextFault::AlreadyForwarded);
    }
    if !matches
        || m.get("ai.opencode/sessionID").and_then(Value::as_str)
            != Some(context.session_id.as_str())
        || m.get("ai.agent_bridge/toolCallID")
            .is_some_and(|v| v.as_str() != Some(context.call_id.as_str()))
    {
        return Err(ContextFault::Mismatch);
    }
    m.insert("ai.agent_bridge/toolCallID".into(), json!(context.call_id));
    *used = true;
    Ok(())
}

/// Applies already authenticated control to the one current native executor.
fn apply(request: Control, namespace: &str, active: &mut Option<(Context, bool)>) -> bool {
    match request {
        Control::Begin { server, context }
            if server == namespace
                && active.is_none()
                && identifier(&context.session_id)
                && identifier(&context.call_id)
                && identifier(&context.tool)
                && context.arguments.is_object() =>
        {
            *active = Some((context, false));
            true
        }
        Control::End { server, call_id }
            if server == namespace
                && active.as_ref().is_some_and(|(c, _)| c.call_id == call_id) =>
        {
            *active = None;
            true
        }
        _ => false,
    }
}

/// Acquires a lifetime lease before touching an endpoint. Only a recorded stale
/// endpoint of the same native-parent incarnation may be replaced on reconnect.
fn endpoint(
    directory: &Path,
    native: &os::ProcessFacts,
    name: &str,
) -> io::Result<(UnixListener, fs::File, SocketGuard)> {
    let uid = server::private_directory(directory)?;
    if native.uid != Some(uid) {
        return Err(io::Error::other("native parent ownership mismatch"));
    }
    let path = socket_path(directory, native.pid, name);
    let lease_path = path.with_extension("lock");
    let mut lease = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&lease_path)?;
    let opened = lease.metadata()?;
    let linked = fs::symlink_metadata(&lease_path)?;
    if !linked.is_file()
        || linked.uid() != uid
        || linked.mode() & 0o077 != 0
        || opened.dev() != linked.dev()
        || opened.ino() != linked.ino()
    {
        return Err(io::Error::other("unsafe native context lease"));
    }
    lease
        .try_lock()
        .map_err(|_| io::Error::other("native context endpoint occupied"))?;
    let identity = format!(
        "bridge-native-mcp-v1 {} {} {name}\n",
        native.pid, native.start_time
    );
    let mut prior = String::new();
    Read::by_ref(&mut lease)
        .take(1024)
        .read_to_string(&mut prior)?;
    if path.exists() {
        if prior != identity || !fs::symlink_metadata(&path)?.file_type().is_socket() {
            return Err(io::Error::other("unmanaged native context endpoint"));
        }
        if UnixStream::connect(&path).is_ok() {
            return Err(io::Error::other("native context endpoint active"));
        }
        fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let m = fs::symlink_metadata(&path)?;
    let guard = SocketGuard {
        path,
        device: m.dev(),
        inode: m.ino(),
    };
    lease.set_len(0)?;
    lease.seek(SeekFrom::Start(0))?;
    lease.write_all(identity.as_bytes())?;
    lease.sync_all()?;
    Ok((listener, lease, guard))
}

/// Admit control only from the frontend native parent PID/UID/birth.
/// Descendants and same-user sibling processes cannot provide native context.
fn control(mut stream: UnixStream, native: &os::ProcessFacts, send: &SyncSender<Event>) {
    let accepted = (|| -> io::Result<bool> {
        stream.set_read_timeout(Some(IO_TIME))?;
        stream.set_write_timeout(Some(IO_TIME))?;
        let peer = os::peer_identity(&stream)?;
        if peer.pid != native.pid
            || Some(peer.uid) != native.uid
            || !os::incarnation_alive(native.pid, native.start_time)
        {
            return Ok(false);
        }
        let bytes = frame(&mut BufReader::new(&mut stream))?
            .ok_or_else(|| io::Error::other("missing context"))?;
        let request: Control =
            serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid context"))?;
        let (reply, result) = mpsc::sync_channel(1);
        send.send(Event::Control(request, reply))
            .map_err(|_| io::Error::other("transport ended"))?;
        result.recv_timeout(IO_TIME).map_err(io::Error::other)
    })();
    let _ = stream.write_all(if matches!(accepted, Ok(true)) {
        b"{\"ok\":true}\n"
    } else {
        b"{\"ok\":false}\n"
    });
}

/// Readiness handshake consumed before exec; never exposed as an MCP frame.
const READY: &[u8] = b"bridge-mcp-ready-v1\n";

/// Replace this bootstrap with the original absolute MCP backend, preserving its
/// PID and direct native parent. Arguments are private context directory, namespace,
/// backend and its original arguments. A private socket pair carries backend I/O
/// through the owned worker, whose original stdin/stdout stay with the native client.
/// Wait for actual endpoint readiness before exec; setup/exec failures reap the
/// worker and return an error. No tool request or permission check is replayed.
pub fn run(arguments: &[String]) -> io::Result<()> {
    if arguments.len() < 3 || !Path::new(&arguments[2]).is_absolute() || !identifier(&arguments[1])
    {
        return Err(io::Error::other("invalid native proxy arguments"));
    }
    let (mut backend, worker) = UnixStream::pair()?;
    let _worker = Sidecar(
        Command::new(std::env::current_exe()?)
            .arg("mcp-proxy-sidecar")
            .args(&arguments[..2])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::from(std::os::fd::OwnedFd::from(worker)))
            .spawn()?,
    );
    backend.set_read_timeout(Some(IO_TIME))?;
    let mut ready = [0_u8; READY.len()];
    backend.read_exact(&mut ready)?;
    if ready != READY {
        return Err(io::Error::other("native MCP worker readiness refused"));
    }
    backend.set_read_timeout(None)?;
    let input = backend.try_clone()?;
    Err(Command::new(&arguments[2])
        .args(&arguments[3..])
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(input)))
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(backend)))
        .stderr(Stdio::inherit())
        .exec())
}

/// Internal CLI worker, not a caller identity issuer. Arguments are private context
/// directory and namespace. Descriptor2 is the bootstrap-created private socket;
/// its kernel peer must be the same live frontend parent. Actual ToolContext is
/// accepted only from that frontend's kernel-observed native parent PID/UID/birth.
/// Native client stdin/stdout and backend socket stay bounded and persistent;
/// failure/EOF closes the worker, never signals or retries its frontend parent.
pub fn run_sidecar(arguments: &[String]) -> io::Result<()> {
    if arguments.len() != 2 || !Path::new(&arguments[0]).is_absolute() || !identifier(&arguments[1])
    {
        return Err(io::Error::other("invalid native proxy arguments"));
    }
    let own = os::process_facts(std::process::id())
        .ok_or_else(|| io::Error::other("missing ancestry"))?;
    let frontend = own
        .parent
        .and_then(os::process_facts)
        .ok_or_else(|| io::Error::other("missing frontend parent"))?;
    let parent = frontend
        .parent
        .and_then(os::process_facts)
        .ok_or_else(|| io::Error::other("missing native parent"))?;
    let mut transport = UnixStream::from(io::stderr().as_fd().try_clone_to_owned()?);
    let peer = os::peer_identity(&transport)?;
    if peer.pid != frontend.pid
        || Some(peer.uid) != frontend.uid
        || !os::incarnation_alive(frontend.pid, frontend.start_time)
    {
        return Err(io::Error::other(
            "native MCP private transport ownership mismatch",
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    let (listener, _lease, socket_guard) =
        endpoint(Path::new(&arguments[0]), &parent, &arguments[1])?;
    transport.write_all(READY)?;
    transport.flush()?;
    let input = transport.try_clone()?;
    let output = transport;
    let (send, events) = mpsc::sync_channel(16);
    pump(io::stdin(), send.clone(), true);
    pump(output, send.clone(), false);
    let (backend, input_done) = writer(input, send.clone());
    let (client, output_done) = writer(io::stdout(), send.clone());
    let stopping = stop.clone();
    let control_thread = thread::spawn(move || {
        while !stopping.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if stopping.load(Ordering::Acquire) {
                        break;
                    }
                    control(stream, &parent, &send);
                }
                Err(e) => {
                    let _ = send.send(Event::Failed(e));
                    return;
                }
            }
        }
    });
    let mut active = None;
    let mut outcome = (|| -> io::Result<()> {
        while !stop.load(Ordering::Acquire) {
            let event = match events.recv_timeout(Duration::from_millis(50)) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            match event {
                Event::Client(bytes) => {
                    let mut value: Value = serde_json::from_slice(&bytes)
                        .map_err(|_| io::Error::other("invalid MCP input"))?;
                    let destination = match enrich(&mut value, &mut active) {
                        Ok(()) => &backend,
                        Err(error) => {
                            let (message, effect) = match error {
                                ContextFault::AlreadyForwarded => (
                                    "Native invocation already forwarded; reconcile the original request, do not replay",
                                    "outcome_unknown",
                                ),
                                ContextFault::Unavailable | ContextFault::Mismatch => (
                                    "Native invocation context unavailable or mismatched; request not forwarded",
                                    "not_forwarded",
                                ),
                            };
                            value = json!({"jsonrpc":"2.0","id":value.get("id").cloned().unwrap_or(Value::Null),"error":{"code":-32000,"message":message,"data":{"effect":effect}}});
                            &client
                        }
                    };
                    let mut bytes = serde_json::to_vec(&value)?;
                    bytes.push(b'\n');
                    if bytes.len() > MAX_FRAME {
                        return Err(io::Error::other(
                            "native MCP enriched frame exceeds host limit",
                        ));
                    }
                    destination
                        .try_send(bytes)
                        .map_err(|_| io::Error::other("native MCP output unavailable"))?;
                }
                Event::Backend(bytes) => client
                    .try_send(bytes)
                    .map_err(|_| io::Error::other("native MCP output unavailable"))?,
                Event::Control(request, reply) => {
                    let _ = reply.send(apply(request, &arguments[1], &mut active));
                }
                Event::Closed => break,
                Event::Failed(error) => return Err(error),
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Release);
    let _ = UnixStream::connect(&socket_guard.path);
    drop(events);
    drop(backend);
    drop(client);
    let input_flushed = matches!(input_done.recv_timeout(IO_TIME), Ok(Ok(())));
    let output_flushed = matches!(output_done.recv_timeout(IO_TIME), Ok(Ok(())));
    if outcome.is_ok() && (!input_flushed || !output_flushed) {
        outcome = Err(io::Error::other("native MCP flush incomplete"));
    }
    let _ = control_thread.join();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    /// One synthetic protected context; never issued as production caller authority.
    fn context() -> Context {
        Context {
            session_id: "ses-native".into(),
            call_id: "call-native".into(),
            tool: "probe".into(),
            arguments: json!({"value":7}),
        }
    }
    /// Original vendor metadata contains a native session but deliberately no Bridge call ID.
    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe","arguments":{"value":7},"_meta":{"ai.opencode/sessionID":"ses-native","other":"preserved"}}})
    }
    /// A real executor context supplies exactly one call ID without rewriting model arguments.
    #[test]
    fn protected_context_enriches_one_matching_call() {
        let mut value = request();
        let arguments = value["params"]["arguments"].clone();
        let mut active = Some((context(), false));
        enrich(&mut value, &mut active).unwrap();
        assert_eq!(
            value["params"]["_meta"]["ai.agent_bridge/toolCallID"],
            "call-native"
        );
        assert_eq!(value["params"]["_meta"]["other"], "preserved");
        assert_eq!(value["params"]["arguments"], arguments);
        assert!(enrich(&mut request(), &mut active).is_err());
    }
    /// Missing, stale, overlapping or mismatched origins never produce substitute evidence.
    #[test]
    fn native_context_refuses_mismatch_and_unrelated_cleanup() {
        assert!(enrich(&mut request(), &mut None).is_err());
        for pointer in [
            "/params/name",
            "/params/arguments/value",
            "/params/_meta/ai.opencode~1sessionID",
            "/params/_meta/ai.agent_bridge~1toolCallID",
        ] {
            let mut value = request();
            if pointer.ends_with("toolCallID") {
                value["params"]["_meta"]["ai.agent_bridge/toolCallID"] = json!("wrong");
            } else {
                *value.pointer_mut(pointer).unwrap() = json!("wrong");
            }
            assert!(enrich(&mut value, &mut Some((context(), false))).is_err());
        }
        let mut active = None;
        assert!(apply(
            Control::Begin {
                server: "pool".into(),
                context: context()
            },
            "pool",
            &mut active
        ));
        assert!(!apply(
            Control::Begin {
                server: "pool".into(),
                context: context()
            },
            "pool",
            &mut active
        ));
        assert!(!apply(
            Control::End {
                server: "other".into(),
                call_id: "call-native".into()
            },
            "pool",
            &mut active
        ));
        assert!(!apply(
            Control::End {
                server: "pool".into(),
                call_id: "wrong".into()
            },
            "pool",
            &mut active
        ));
        assert!(apply(
            Control::End {
                server: "pool".into(),
                call_id: "call-native".into()
            },
            "pool",
            &mut active
        ));
        assert!(active.is_none());
    }
    /// Frames never consume a following request or accept a partial line.
    #[test]
    fn framing_preserves_boundaries_and_refuses_partial_input() {
        let mut input = BufReader::new(std::io::Cursor::new(b"one\ntwo\n"));
        assert_eq!(frame(&mut input).unwrap().unwrap(), b"one\n");
        assert_eq!(frame(&mut input).unwrap().unwrap(), b"two\n");
        assert!(frame(&mut input).unwrap().is_none());
        assert!(frame(&mut BufReader::new(std::io::Cursor::new(b"partial"))).is_err());
        assert!(
            frame(&mut BufReader::new(std::io::Cursor::new(vec![
                b'x';
                MAX_FRAME + 1
            ])))
            .is_err()
        );
    }
    /// A scripted slow sink exposes the real bounded writer queue without a timing guess.
    struct SlowSink {
        /// Signals when the first actual write begins.
        ready: mpsc::SyncSender<()>,
        /// Releases that write; absent after the first write.
        gate: Option<mpsc::Receiver<()>>,
    }
    impl Write for SlowSink {
        /// Blocks exactly the first write behind an explicit test handshake.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(gate) = self.gate.take() {
                let _ = self.ready.send(());
                let _ = gate.recv();
            }
            Ok(bytes.len())
        }
        /// In-memory scripted sink has no independent buffered data.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    /// A failing sink counts attempts so a transport error cannot be silently replayed.
    struct FailedSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Write for FailedSink {
        /// Fails the first write; another call would violate the no-retry contract.
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture sink ended",
            ))
        }
        /// No bytes are buffered by this fixture.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    /// Queue saturation is bounded; a closed/failing consumer is observed once and not retried.
    #[test]
    fn writer_bounds_slow_consumers_and_does_not_retry_failure() {
        let (send, _events) = mpsc::sync_channel(16);
        let (ready, started) = mpsc::sync_channel(1);
        let (release, gate) = mpsc::sync_channel(1);
        let (queue, done) = writer(
            SlowSink {
                ready,
                gate: Some(gate),
            },
            send.clone(),
        );
        queue.try_send(vec![1]).unwrap();
        started.recv_timeout(IO_TIME).unwrap();
        for _ in 0..8 {
            queue.try_send(vec![2]).unwrap();
        }
        assert!(matches!(
            queue.try_send(vec![3]),
            Err(mpsc::TrySendError::Full(_))
        ));
        drop(queue);
        release.send(()).unwrap();
        assert_eq!(done.recv_timeout(IO_TIME).unwrap(), Ok(()));
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (queue, done) = writer(FailedSink(calls.clone()), send);
        queue.try_send(vec![1]).unwrap();
        assert_eq!(
            done.recv_timeout(IO_TIME).unwrap(),
            Err(io::ErrorKind::BrokenPipe)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(queue.try_send(vec![2]).is_err());
    }
}
