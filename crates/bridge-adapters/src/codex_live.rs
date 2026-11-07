//! Linux App Server transport for an already attested Codex process.
//!
//! Only a route with a protected idle proof or a one-shot cold claim may resume
//! an unloaded thread.
//! A retired binding may also receive MESSAGE without resuming while the same
//! live server freshly confirms its thread is loaded and idle.
//! An unconfirmed resume or message write has an unknown outcome and is not retried.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bridge_core::Mode;
use bridge_core::dispatch::Outcome;
use bridge_core::service::current_unix_millis;
use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, client::client_with_config, protocol::WebSocketConfig};

use crate::os;
use crate::registry::RecipientBinding;

/// Maximum assembled frame or message size in bytes.
const LIMIT: usize = 1 << 20;

/// A socket path and frozen process incarnation selected by discovery.
#[derive(Clone)]
pub(crate) struct Endpoint {
    /// Canonical, protected socket path.
    path: PathBuf,
    /// Process and session facts captured by recipient validation.
    binding: RecipientBinding,
    /// Local process owner required of the socket peer.
    uid: u32,
}

/// The native thread states in which a message can be considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// The native thread is idle.
    Idle,
    /// The thread is active without a pending user interaction.
    Active,
    /// The exact stored thread is not loaded in this server.
    NotLoaded,
}

/// Validates an owned private directory without following its final symlink.
fn private_directory(path: &Path, uid: u32) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "native control directory unavailable")?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err("native control directory is not private and owned".into());
    }
    if fs::canonicalize(path).map_err(|_| "native control directory unresolved")? != path {
        return Err("native control directory is not canonical".into());
    }
    Ok(())
}

/// Finds only the recipient's own control socket; malformed presence is an error.
pub(crate) fn locate(binding: &RecipientBinding) -> Result<Option<Endpoint>, String> {
    let uid = os::process_facts(std::process::id())
        .and_then(|f| f.uid)
        .ok_or("process owner unavailable")?;
    let store = fs::canonicalize(&binding.store).map_err(|_| "recipient store unavailable")?;
    let dir = store.join("app-server-control");
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("native control directory unavailable".into()),
        Ok(_) => private_directory(&dir, uid)?,
    }
    let source = dir.join("app-server-control.sock");
    let meta = match fs::symlink_metadata(&source) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("native control socket unavailable".into()),
        Ok(m) => m,
    };
    if meta.uid() != uid || !(meta.file_type().is_socket() || meta.file_type().is_symlink()) {
        return Err("native control socket has invalid ownership or type".into());
    }
    let path = fs::canonicalize(&source).map_err(|_| "native control socket unresolved")?;
    let parent = path.parent().ok_or("native control socket has no parent")?;
    private_directory(parent, uid)?;
    let target = fs::symlink_metadata(&path).map_err(|_| "native control socket unavailable")?;
    if !target.file_type().is_socket() || target.uid() != uid || target.mode() & 0o777 != 0o600 {
        return Err("native control socket is not owned mode 0600".into());
    }
    let endpoint = Endpoint {
        path,
        binding: binding.clone(),
        uid,
    };
    let stream = os::connect_unix(&endpoint.path, Instant::now() + Duration::from_secs(3))
        .map_err(|_| "native control socket connection failed")?;
    endpoint.verify_peer(&stream)?;
    Ok(Some(endpoint))
}

impl Endpoint {
    /// Checks the kernel peer and its frozen process incarnation.
    fn verify_peer(&self, stream: &UnixStream) -> Result<(), String> {
        let peer = os::peer_identity(stream).map_err(|_| "native control peer unavailable")?;
        let facts =
            os::process_facts(self.binding.harness.0).ok_or("native process unavailable")?;
        if peer.pid != self.binding.harness.0
            || peer.uid != self.uid
            || facts.uid != Some(self.uid)
            || facts.start_time != self.binding.harness.1
            || facts.exe.as_deref() != Some(self.binding.executable.as_path())
        {
            return Err("native control peer incarnation changed".into());
        }
        Ok(())
    }

    /// Reads metadata only, under one connection and exchange timeout.
    pub(crate) fn state(&self, thread: &str, timeout: Duration) -> Result<State, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("invalid timeout")?;
        let mut ws = self.open(deadline)?;
        read_state(&mut ws, thread, 2).map_err(|_| "native thread state unavailable".into())
    }

    /// Reads the latest completed turn between identical idle/unloaded
    /// observations from the verified peer. An empty ID denotes no turns.
    pub(crate) fn latest_completed(
        &self,
        thread: &str,
        timeout: Duration,
    ) -> Result<(State, String), String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("invalid timeout")?;
        let mut ws = self.open(deadline)?;
        let before =
            read_state(&mut ws, thread, 2).map_err(|_| "native thread state unavailable")?;
        if !matches!(before, State::Idle | State::NotLoaded) {
            return Err("native thread is not idle or unloaded".into());
        }
        request(
            &mut ws,
            json!({"id":3,"method":"thread/turns/list","params":{
                "threadId":thread,"limit":1,"sortDirection":"desc","itemsView":"notLoaded"
            }}),
        )?;
        let reply = response(&mut ws, 3)?;
        if reply.get("error").is_some() {
            return Err("native latest turn unavailable".into());
        }
        let turns = reply
            .pointer("/result/data")
            .and_then(Value::as_array)
            .ok_or("native latest turn unavailable")?;
        let turn_id = match turns.as_slice() {
            [] => String::new(),
            [turn] => {
                let id = turn
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| valid_id(id))
                    .ok_or("native latest turn has invalid id")?;
                if turn.get("status").and_then(Value::as_str) != Some("completed")
                    || !turn.get("error").is_none_or(Value::is_null)
                {
                    return Err("native latest turn changed or is unfinished".into());
                }
                id.to_owned()
            }
            _ => return Err("native latest turn unavailable".into()),
        };
        let after =
            read_state(&mut ws, thread, 4).map_err(|_| "native thread state unavailable")?;
        if before != after
            || self.verify_peer(&ws.get_ref().stream).is_err()
            || Instant::now() >= deadline
        {
            return Err("native thread or peer changed during observation".into());
        }
        Ok((after, turn_id))
    }

    /// Verifies the exact latest completed turn, or no turns if expected is empty.
    pub(crate) fn completed_state(
        &self,
        thread: &str,
        expected_turn: &str,
        timeout: Duration,
    ) -> Result<State, String> {
        let (state, turn_id) = self.latest_completed(thread, timeout)?;
        if turn_id != expected_turn {
            return Err("native latest turn changed or is unfinished".into());
        }
        Ok(state)
    }

    /// Opens and initializes a deadline-bound WebSocket to the verified peer.
    fn open(&self, deadline: Instant) -> Result<WebSocket<DeadlineStream>, String> {
        let stream = os::connect_unix(&self.path, deadline).map_err(|_| "native connect failed")?;
        self.verify_peer(&stream)?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(LIMIT))
            .max_frame_size(Some(LIMIT))
            .write_buffer_size(0)
            .max_write_buffer_size(LIMIT + 1024);
        let (mut ws, _) = client_with_config(
            "ws://localhost/",
            DeadlineStream { stream, deadline },
            Some(config),
        )
        .map_err(|_| "native WebSocket handshake failed")?;
        request(
            &mut ws,
            json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"agent_bridge_live","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}}}),
        )?;
        let reply = response(&mut ws, 1)?;
        if !reply.get("result").is_some_and(Value::is_object) || reply.get("error").is_some() {
            return Err("native initialization refused".into());
        }
        request(&mut ws, json!({"method":"initialized","params":{}}))?;
        Ok(ws)
    }
}

/// Stream wrapper that reapplies the remaining absolute deadline to each syscall.
struct DeadlineStream {
    /// Connected kernel socket.
    stream: UnixStream,
    /// Absolute monotonic I/O deadline.
    deadline: Instant,
}
impl DeadlineStream {
    /// Returns a positive remaining time or a timeout error.
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(remaining)
        }
    }
}
impl Read for DeadlineStream {
    /// Reads without allowing successive calls to extend the deadline.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}
impl Write for DeadlineStream {
    /// Writes without allowing successive calls to extend the deadline.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }
    /// Flushes the underlying stream within the remaining deadline.
    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()
    }
}

/// Writes a bounded JSON message, withholding native payloads from errors.
fn request(ws: &mut WebSocket<DeadlineStream>, value: Value) -> Result<(), String> {
    let text = value.to_string();
    if text.len() > LIMIT {
        return Err("native request exceeds limit".into());
    }
    ws.send(Message::Text(text.into()))
        .map_err(|_| "native request failed".into())
}

/// Waits for one exact response, ignoring notifications but refusing requests.
fn response(ws: &mut WebSocket<DeadlineStream>, id: u64) -> Result<Value, String> {
    loop {
        if Instant::now() >= ws.get_ref().deadline {
            return Err("native response timed out".into());
        }
        match ws.read().map_err(|_| "native response unavailable")? {
            Message::Text(text) => {
                let v: Value =
                    serde_json::from_str(&text).map_err(|_| "malformed native response")?;
                if v.get("method").is_some() {
                    if v.get("id").is_some() {
                        return Err("native server requested input".into());
                    }
                    continue;
                }
                if v.get("id").and_then(Value::as_u64) != Some(id) {
                    return Err("native response id mismatch".into());
                }
                return Ok(v);
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            _ => return Err("unexpected native frame".into()),
        }
    }
}

/// Separates a lifecycle hold from other failures before the handoff.
enum StateError {
    /// The native lifecycle requires holding the message.
    Lifecycle,
    /// Preflight failed before a trustworthy lifecycle was obtained.
    Other,
}

/// Reads the requested thread's native lifecycle, rejecting pending interaction.
fn read_state(
    ws: &mut WebSocket<DeadlineStream>,
    thread: &str,
    id: u64,
) -> Result<State, StateError> {
    request(
        ws,
        json!({"id":id,"method":"thread/read","params":{"threadId":thread,"includeTurns":false}}),
    )
    .map_err(|_| StateError::Other)?;
    let result = response(ws, id).map_err(|_| StateError::Other)?;
    if result.get("error").is_some()
        || result.pointer("/result/thread/id").and_then(Value::as_str) != Some(thread)
    {
        return Err(StateError::Other);
    }
    let status = &result["result"]["thread"]["status"];
    match status.get("type").and_then(Value::as_str) {
        Some("idle")
            if status
                .get("activeFlags")
                .is_none_or(|flags| flags.as_array().is_some_and(Vec::is_empty)) =>
        {
            Ok(State::Idle)
        }
        Some("active")
            if status
                .get("activeFlags")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty) =>
        {
            Ok(State::Active)
        }
        Some("notLoaded")
            if status
                .get("activeFlags")
                .is_none_or(|flags| flags.as_array().is_some_and(Vec::is_empty)) =>
        {
            Ok(State::NotLoaded)
        }
        _ => Err(StateError::Lifecycle),
    }
}

/// Frozen message and the absolute core deadline in Unix milliseconds.
pub(crate) struct Handoff<'a> {
    /// Native thread identifier.
    pub thread: &'a str,
    /// Frozen client message identifier.
    pub client_id: &'a str,
    /// Frozen message text.
    pub text: &'a str,
    /// Requested dispatch mode.
    pub mode: Mode,
    /// Permit the qualified retired route after its pre-resume claim succeeds.
    pub allow_resume: bool,
    /// Require a fresh loaded idle state and never send to an active thread.
    pub require_idle: bool,
    /// Expected latest completed turn, or empty for no turns, before resuming.
    pub cold_expected_turn: Option<&'a str>,
    /// Absolute core deadline in Unix milliseconds.
    pub deadline_ms: u64,
    /// Maximum duration of this exchange.
    pub timeout: Duration,
}

/// Performs one handoff, fencing native mutations and classifying uncertain receipts.
pub(crate) fn deliver(
    endpoint: &Endpoint,
    handoff: &Handoff<'_>,
    pre_resume: impl FnOnce() -> Result<(), String>,
    mut final_check: impl FnMut() -> Result<(), String>,
) -> Outcome {
    let budget = Duration::from_millis(handoff.deadline_ms.saturating_sub(current_unix_millis()))
        .min(handoff.timeout);
    let Some(deadline) = Instant::now().checked_add(budget) else {
        return Outcome::KnownUnsent {
            evidence: "invalid native deadline; nothing sent".into(),
        };
    };
    let mut ws = match endpoint.open(deadline) {
        Ok(ws) => ws,
        Err(_) => {
            return Outcome::KnownUnsent {
                evidence: "native connection failed before handoff".into(),
            };
        }
    };
    let mut resumed = false;
    match read_state(&mut ws, handoff.thread, 2) {
        Ok(State::Idle | State::Active) if handoff.cold_expected_turn.is_some() => {
            return Outcome::DeferredKnownUnsent {
                evidence: "native recipient is no longer unloaded; nothing sent".into(),
            };
        }
        Ok(State::Idle) if !handoff.allow_resume => {
            if handoff.require_idle
                && (endpoint.verify_peer(&ws.get_ref().stream).is_err()
                    || final_check().is_err()
                    || Instant::now() >= deadline
                    || !matches!(read_state(&mut ws, handoff.thread, 5), Ok(State::Idle)))
            {
                return Outcome::DeferredKnownUnsent {
                    evidence: "retired native recipient is no longer idle; nothing sent".into(),
                };
            }
        }
        Ok(State::Idle) if handoff.allow_resume => {
            if endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || Instant::now() >= deadline
                || pre_resume().is_err()
                || endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || final_check().is_err()
                || Instant::now() >= deadline
                || !matches!(read_state(&mut ws, handoff.thread, 5), Ok(State::Idle))
            {
                return Outcome::DeferredKnownUnsent {
                    evidence: "retired native recipient is no longer proven idle; nothing sent"
                        .into(),
                };
            }
        }
        Ok(State::Active)
            if !handoff.allow_resume && !handoff.require_idle && handoff.mode == Mode::Message => {}
        Ok(State::NotLoaded) => {
            if !handoff.allow_resume
                || handoff.cold_expected_turn.is_none()
                || endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || Instant::now() >= deadline
                || pre_resume().is_err()
            {
                return Outcome::DeferredKnownUnsent {
                    evidence: "native resume is not qualified; nothing sent".into(),
                };
            }
            if handoff.cold_expected_turn.is_some_and(|expected_turn| {
                Instant::now() >= deadline
                    || !matches!(
                        endpoint.completed_state(
                            handoff.thread,
                            expected_turn,
                            deadline.saturating_duration_since(Instant::now()),
                        ),
                        Ok(State::NotLoaded)
                    )
            }) {
                return Outcome::DeferredKnownUnsent {
                    evidence: "native episode changed before resume; nothing sent".into(),
                };
            }
            // Proof persistence may have taken time. Recheck the exact spent
            // snapshot and kernel peer immediately before the resume write.
            if endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || final_check().is_err()
                || Instant::now() >= deadline
                || !matches!(read_state(&mut ws, handoff.thread, 6), Ok(State::NotLoaded))
                || endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || final_check().is_err()
                || Instant::now() >= deadline
            {
                return Outcome::DeferredKnownUnsent {
                    evidence: "native recipient changed before resume; nothing sent".into(),
                };
            }
            let resume = json!({"id":4,"method":"thread/resume","params":{"threadId":handoff.thread,"excludeTurns":true}});
            if request(&mut ws, resume).is_err()
                || !response(&mut ws, 4).is_ok_and(|value| {
                    value.get("error").is_none()
                        && value.pointer("/result/thread/id").and_then(Value::as_str)
                            == Some(handoff.thread)
                })
            {
                return Outcome::OutcomeUnknown {
                    reason: "native resume has no valid correlated receipt".into(),
                };
            }
            resumed = true;
            // SessionStart may renew the epoch during resume. Never send under
            // the old attempt if the complete frozen registry snapshot changed.
            if endpoint.verify_peer(&ws.get_ref().stream).is_err()
                || final_check().is_err()
                || Instant::now() >= deadline
            {
                return Outcome::ResumeAcceptedNoMessage {
                    evidence: "native resume accepted; recipient changed before message".into(),
                };
            }
            if !matches!(read_state(&mut ws, handoff.thread, 5), Ok(State::Idle)) {
                return Outcome::ResumeAcceptedNoMessage {
                    evidence: "native resume accepted; thread is not idle before message".into(),
                };
            }
        }
        Ok(State::Idle | State::Active) | Err(StateError::Lifecycle) => {
            return Outcome::DeferredKnownUnsent {
                evidence: "native lifecycle unavailable or changed before handoff".into(),
            };
        }
        Err(StateError::Other) if handoff.cold_expected_turn.is_some() => {
            return Outcome::DeferredKnownUnsent {
                evidence: "native recipient state unavailable; nothing sent".into(),
            };
        }
        Err(StateError::Other) => {
            return Outcome::KnownUnsent {
                evidence: "native thread read failed before handoff".into(),
            };
        }
    }
    let payload = json!({"id":3,"method":"turn/start","params":{"threadId":handoff.thread,"clientUserMessageId":handoff.client_id,"input":[{"type":"text","text":handoff.text}]}}).to_string();
    if payload.len() > LIMIT || Instant::now() >= deadline {
        return if resumed {
            Outcome::ResumeAcceptedNoMessage {
                evidence: "native resume accepted; message limit or deadline reached".into(),
            }
        } else if handoff.allow_resume {
            Outcome::DeferredKnownUnsent {
                evidence: "retired native handoff exceeded its limit before writing".into(),
            }
        } else {
            Outcome::KnownUnsent {
                evidence: "native handoff exceeded its limit before writing".into(),
            }
        };
    }
    // Recheck the same frozen binding immediately before the message write.
    if endpoint.verify_peer(&ws.get_ref().stream).is_err()
        || final_check().is_err()
        || Instant::now() >= deadline
    {
        return if resumed {
            Outcome::ResumeAcceptedNoMessage {
                evidence: "native resume accepted; recipient changed before message".into(),
            }
        } else {
            Outcome::DeferredKnownUnsent {
                evidence: "native recipient changed before handoff; nothing sent".into(),
            }
        };
    }
    if ws.send(Message::Text(payload.into())).is_err() {
        return Outcome::OutcomeUnknown {
            reason: "native handoff write began without a receipt".into(),
        };
    }
    match response(&mut ws, 3) {
        Ok(value) if valid_turn(&value) => Outcome::NativeAccepted {
            evidence: "native turn/start accepted a turn (not processing confirmation)".into(),
        },
        _ => Outcome::OutcomeUnknown {
            reason: "native handoff has no valid correlated receipt".into(),
        },
    }
}

/// Checks that a native identifier is nonempty, bounded, and free of controls.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
}

/// Checks the correlated receipt identity/status and bounded opaque item metadata.
fn valid_turn(value: &Value) -> bool {
    if value.get("error").is_some() {
        return false;
    }
    let t = &value["result"]["turn"];
    t.get("id").and_then(Value::as_str).is_some_and(valid_id)
        && matches!(
            t.get("status").and_then(Value::as_str),
            Some("completed" | "interrupted" | "failed" | "inProgress")
        )
        && t.get("items")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().all(valid_item))
        && t.get("error").is_none_or(Value::is_null)
        && ["completedAt", "durationMs", "startedAt"]
            .iter()
            .all(|key| {
                t.get(key)
                    .is_none_or(|v| v.is_null() || v.as_i64().is_some())
            })
        && t.get("rootTurnId")
            .is_none_or(|v| v.is_null() || v.is_string())
        && t.get("itemsView")
            .is_none_or(|v| matches!(v.as_str(), Some("notLoaded" | "summary" | "full")))
}

/// Checks bounded display-item identities without interpreting their payloads.
/// The exact RPC response's turn identity/status establish native acceptance;
/// unrelated tool output, messages and other display fields grant no authority.
fn valid_item(item: &Value) -> bool {
    ["id", "type"]
        .iter()
        .all(|key| item.get(key).and_then(Value::as_str).is_some_and(valid_id))
}

#[cfg(test)]
mod tests {
    //! Synthetic native socket exchanges, without a real Codex process.
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    /// Unique fixture suffix within the test process.
    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Creates a private socket with this test process as the attested peer.
    fn fixture() -> (PathBuf, UnixListener, RecipientBinding) {
        let dir = std::env::temp_dir().join(format!(
            "live-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let control = dir.join("app-server-control");
        fs::create_dir(&control).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        let target_dir = std::env::temp_dir()
            .parent()
            .unwrap()
            .join(dir.file_name().unwrap());
        fs::create_dir(&target_dir).unwrap();
        fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = target_dir.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(socket, control.join("app-server-control.sock")).unwrap();
        let facts = os::process_facts(std::process::id()).unwrap();
        let binding = RecipientBinding {
            harness: (facts.pid, facts.start_time),
            epoch: 1,
            store: dir.clone(),
            executable: facts.exe.unwrap(),
            transcript: None,
            desktop_message_only: false,
            gateway: false,
        };
        (dir, listener, binding)
    }

    /// Runs one scripted protocol exchange and returns whether a mutation arrived.
    fn exchange(status: Value, reply: Option<Value>, fence: bool, mode: Mode) -> (Outcome, bool) {
        exchange_thread(status, reply, fence, mode, "thread-1", false)
    }

    /// Exchanges with a chosen thread ID in the preflight response.
    fn exchange_thread(
        status: Value,
        reply: Option<Value>,
        fence: bool,
        mode: Mode,
        returned_thread: &'static str,
        allow_resume: bool,
    ) -> (Outcome, bool) {
        let (dir, listener, binding) = fixture();
        let worker = thread::spawn(move || {
            drop(listener.accept().unwrap().0); // discovery peer verification
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            let init = ws.read().unwrap();
            assert!(init.to_text().unwrap().contains("initialize"));
            ws.send(Message::Text(
                json!({"id":1,"result":{}}).to_string().into(),
            ))
            .unwrap();
            let _initialized = ws.read().unwrap();
            let read = ws.read().unwrap();
            assert!(read.to_text().unwrap().contains("thread/read"));
            ws.send(Message::Text(
                json!({"id":2,"result":{"thread":{"id":returned_thread,"status":status}}})
                    .to_string()
                    .into(),
            ))
            .unwrap();
            match ws.read() {
                Ok(Message::Text(text)) if text.contains("turn/start") => {
                    if let Some(reply) = reply {
                        ws.send(Message::Text(reply.to_string().into())).unwrap();
                    }
                    true
                }
                _ => false,
            }
        });
        let endpoint = locate(&binding).unwrap().unwrap();
        let handoff = Handoff {
            thread: "thread-1",
            client_id: "client-1",
            text: "hello",
            mode,
            allow_resume,
            require_idle: false,
            cold_expected_turn: None,
            deadline_ms: current_unix_millis() + 3000,
            timeout: Duration::from_secs(3),
        };
        let outcome = deliver(
            &endpoint,
            &handoff,
            || Err("not eligible".into()),
            || {
                if fence { Ok(()) } else { Err("changed".into()) }
            },
        );
        let wrote = worker.join().unwrap();
        let target_dir = std::env::temp_dir()
            .parent()
            .unwrap()
            .join(dir.file_name().unwrap());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(target_dir).unwrap();
        (outcome, wrote)
    }

    /// A correlated valid turn accepts; changed lifecycle or fence sends nothing.
    #[test]
    fn native_handoff_classifies_receipts_and_fences() {
        let valid =
            json!({"id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}});
        let (result, wrote) = exchange(
            json!({"type":"idle"}),
            Some(valid.clone()),
            true,
            Mode::Auto,
        );
        assert!(wrote && matches!(result, Outcome::NativeAccepted { .. }));
        let (result, wrote) = exchange(
            json!({"type":"active","activeFlags":[]}),
            Some(
                json!({"id":3,"result":{"turn":{"id":"turn-1","items":[{"id":"item-1","type":"mcpToolCall","tool":"fixture","result":{"content":[]}}],"status":"inProgress"}}}),
            ),
            true,
            Mode::Message,
        );
        assert!(wrote && matches!(result, Outcome::NativeAccepted { .. }));
        let (result, wrote) = exchange_thread(
            json!({"type":"idle"}),
            None,
            true,
            Mode::Message,
            "other-thread",
            false,
        );
        assert!(!wrote && matches!(result, Outcome::KnownUnsent { .. }));
        for reply in [
            json!({"id":3,"error":{"code":-1,"message":"no"}}),
            json!({"id":3,"result":{"turn":{"id":"turn-1","items":[{"type":"agentMessage"}],"status":"inProgress"}}}),
        ] {
            let (result, wrote) =
                exchange(json!({"type":"idle"}), Some(reply), true, Mode::Message);
            assert!(wrote && matches!(result, Outcome::OutcomeUnknown { .. }));
        }
        let (result, wrote) = exchange(
            json!({"type":"active","activeFlags":[]}),
            Some(valid),
            true,
            Mode::Auto,
        );
        assert!(!wrote && matches!(result, Outcome::DeferredKnownUnsent { .. }));
        let (result, wrote) = exchange(
            json!({"type":"active","activeFlags":["waitingOnApproval"]}),
            None,
            true,
            Mode::Message,
        );
        assert!(!wrote && matches!(result, Outcome::DeferredKnownUnsent { .. }));
        let (result, wrote) = exchange(json!({"type":"notLoaded"}), None, true, Mode::Message);
        assert!(!wrote && matches!(result, Outcome::DeferredKnownUnsent { .. }));
        for status in [
            json!({"type":"idle"}),
            json!({"type":"active","activeFlags":[]}),
        ] {
            let (result, wrote) =
                exchange_thread(status, None, true, Mode::Message, "thread-1", true);
            assert!(!wrote && matches!(result, Outcome::DeferredKnownUnsent { .. }));
        }
        let (result, wrote) = exchange(json!({"type":"idle"}), None, false, Mode::Message);
        assert!(!wrote && matches!(result, Outcome::DeferredKnownUnsent { .. }));
        let (result, wrote) = exchange(json!({"type":"idle"}), None, true, Mode::Message);
        assert!(wrote && matches!(result, Outcome::OutcomeUnknown { .. }));
        let (result, wrote) = exchange(
            json!({"type":"idle"}),
            Some(
                json!({"id":4,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}),
            ),
            true,
            Mode::Message,
        );
        assert!(wrote && matches!(result, Outcome::OutcomeUnknown { .. }));
    }

    /// A recipient that starts waiting after eligibility is deferred without a mutation.
    #[test]
    fn lifecycle_changes_after_idle_probe_are_deferred() {
        let (dir, listener, binding) = fixture();
        let worker = thread::spawn(move || {
            drop(listener.accept().unwrap().0); // discovery peer verification
            let mut mutations = 0;
            for status in [
                json!({"type":"idle"}),
                json!({"type":"active","activeFlags":["waitingOnApproval"]}),
            ] {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let init = ws.read().unwrap();
                assert!(init.to_text().unwrap().contains("initialize"));
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let _initialized = ws.read().unwrap();
                let read = ws.read().unwrap();
                assert!(read.to_text().unwrap().contains("thread/read"));
                ws.send(Message::Text(
                    json!({"id":2,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                if matches!(ws.read(), Ok(Message::Text(text)) if text.contains("turn/start")) {
                    mutations += 1;
                }
            }
            mutations
        });
        let endpoint = locate(&binding).unwrap().unwrap();
        let initial = endpoint.state("thread-1", Duration::from_secs(3)).unwrap();
        let handoff = Handoff {
            thread: "thread-1",
            client_id: "client-1",
            text: "hello",
            mode: Mode::Auto,
            allow_resume: false,
            require_idle: false,
            cold_expected_turn: None,
            deadline_ms: current_unix_millis() + 3000,
            timeout: Duration::from_secs(3),
        };
        let outcome = deliver(
            &endpoint,
            &handoff,
            || Err("not eligible".into()),
            || Ok(()),
        );
        let mutations = worker.join().unwrap();
        let target_dir = std::env::temp_dir()
            .parent()
            .unwrap()
            .join(dir.file_name().unwrap());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(target_dir).unwrap();
        assert_eq!(initial, State::Idle);
        assert!(matches!(outcome, Outcome::DeferredKnownUnsent { .. }));
        assert_eq!(mutations, 0);
    }

    /// The latest episode is either one valid completed turn or an empty list,
    /// surrounded by identical idle/unloaded observations from the same peer.
    #[test]
    fn completed_state_rejects_changed_turn_and_pending_input() {
        for case in [
            "ready",
            "idle",
            "exact",
            "empty",
            "empty_exact",
            "empty_wrong",
            "nonempty_wrong",
            "wrong_turn",
            "running",
            "changed",
            "approval",
            "active",
            "initial_approval",
            "idle_flags",
            "unloaded_flags",
            "multiple",
            "invalid_empty",
            "invalid_long",
            "invalid_control",
            "missing_id",
            "turn_error",
            "rpc_error",
            "malformed",
            "error_null",
        ] {
            let (dir, listener, binding) = fixture();
            let worker = thread::spawn(move || {
                drop(listener.accept().unwrap().0);
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let _ = ws.read().unwrap();
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let _ = ws.read().unwrap();
                let _ = ws.read().unwrap();
                let first = match case {
                    "active" => json!({"type":"active","activeFlags":[]}),
                    "initial_approval" => {
                        json!({"type":"active","activeFlags":["waitingOnApproval"]})
                    }
                    "idle_flags" => json!({"type":"idle","activeFlags":["waitingOnApproval"]}),
                    "unloaded_flags" => {
                        json!({"type":"notLoaded","activeFlags":["waitingOnApproval"]})
                    }
                    "idle" => json!({"type":"idle"}),
                    _ => json!({"type":"notLoaded"}),
                };
                ws.send(Message::Text(
                    json!({"id":2,"result":{"thread":{"id":"thread-1","status":first}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(list)) = ws.read() else {
                    return;
                };
                let list: Value = serde_json::from_str(&list).unwrap();
                assert_eq!(list["method"], "thread/turns/list", "{case}");
                assert_eq!(
                    list["params"],
                    json!({"threadId":"thread-1","limit":1,"sortDirection":"desc","itemsView":"notLoaded"}),
                    "{case}"
                );
                let data = match case {
                    "empty" | "empty_exact" | "empty_wrong" => json!([]),
                    "multiple" => json!([
                        {"id":"turn-1","status":"completed"},
                        {"id":"turn-2","status":"completed"}
                    ]),
                    "invalid_empty" => json!([{"id":"","status":"completed"}]),
                    "invalid_long" => json!([{"id":"x".repeat(257),"status":"completed"}]),
                    "invalid_control" => json!([{"id":"turn\n1","status":"completed"}]),
                    "missing_id" => json!([{"status":"completed"}]),
                    "running" => json!([{"id":"turn-1","status":"inProgress"}]),
                    "turn_error" => json!([{"id":"turn-1","status":"completed","error":{}}]),
                    "error_null" => json!([{"id":"turn-1","status":"completed","error":null}]),
                    "wrong_turn" => json!([{"id":"other","status":"completed"}]),
                    _ => json!([{"id":"turn-1","status":"completed"}]),
                };
                let reply = if case == "malformed" {
                    "{".into()
                } else if case == "rpc_error" {
                    json!({"id":3,"result":{"data":data},"error":{}}).to_string()
                } else {
                    json!({"id":3,"result":{"data":data}}).to_string()
                };
                ws.send(Message::Text(reply.into())).unwrap();
                let Ok(Message::Text(read)) = ws.read() else {
                    return;
                };
                let read: Value = serde_json::from_str(&read).unwrap();
                assert_eq!(read["method"], "thread/read", "{case}");
                let last = match case {
                    "changed" => json!({"type":"idle"}),
                    "approval" => json!({"type":"active","activeFlags":["waitingOnApproval"]}),
                    "idle" => json!({"type":"idle"}),
                    _ => json!({"type":"notLoaded"}),
                };
                ws.send(Message::Text(
                    json!({"id":4,"result":{"thread":{"id":"thread-1","status":last}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                assert!(
                    !matches!(ws.read(), Ok(Message::Text(_))),
                    "{case}: unexpected native write"
                );
            });
            let endpoint = locate(&binding).unwrap().unwrap();
            let result = match case {
                "exact" | "wrong_turn" | "empty_wrong" => endpoint
                    .completed_state("thread-1", "turn-1", Duration::from_secs(3))
                    .map(|state| (state, "turn-1".to_owned())),
                "empty_exact" | "nonempty_wrong" => endpoint
                    .completed_state("thread-1", "", Duration::from_secs(3))
                    .map(|state| (state, String::new())),
                _ => endpoint.latest_completed("thread-1", Duration::from_secs(3)),
            };
            worker.join().unwrap();
            let target_dir = std::env::temp_dir()
                .parent()
                .unwrap()
                .join(dir.file_name().unwrap());
            fs::remove_dir_all(dir).unwrap();
            fs::remove_dir_all(target_dir).unwrap();
            match case {
                "ready" | "exact" | "error_null" => {
                    assert_eq!(
                        result.unwrap(),
                        (State::NotLoaded, "turn-1".into()),
                        "{case}"
                    );
                }
                "idle" => assert_eq!(result.unwrap(), (State::Idle, "turn-1".into())),
                "empty" | "empty_exact" => {
                    assert_eq!(result.unwrap(), (State::NotLoaded, String::new()), "{case}");
                }
                _ => assert!(result.is_err(), "{case}: {result:?}"),
            }
        }
    }

    /// A retired proofless binding may send only while the loaded native thread
    /// remains idle; an unknown result is never reported as a safe refusal.
    #[test]
    fn retired_loaded_idle_without_proof_never_resumes_or_sends_when_busy() {
        for case in ["idle", "changed", "active", "unloaded", "approval", "lost"] {
            let (dir, listener, binding) = fixture();
            let worker = thread::spawn(move || {
                drop(listener.accept().unwrap().0);
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let _ = ws.read().unwrap();
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let _ = ws.read().unwrap();
                let _ = ws.read().unwrap();
                let status = match case {
                    "active" => json!({"type":"active","activeFlags":[]}),
                    "unloaded" => json!({"type":"notLoaded"}),
                    "approval" => json!({"type":"active","activeFlags":["waitingOnApproval"]}),
                    _ => json!({"type":"idle"}),
                };
                ws.send(Message::Text(
                    json!({"id":2,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(read)) = ws.read() else {
                    return false;
                };
                let read: Value = serde_json::from_str(&read).unwrap();
                assert_eq!(read["method"], "thread/read", "{case}");
                let status = if case == "changed" {
                    json!({"type":"active","activeFlags":[]})
                } else {
                    json!({"type":"idle"})
                };
                ws.send(Message::Text(
                    json!({"id":5,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(next)) = ws.read() else {
                    return false;
                };
                let next: Value = serde_json::from_str(&next).unwrap();
                assert_eq!(next["method"], "turn/start", "{case}");
                if case != "lost" {
                    ws.send(Message::Text(json!({"id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}).to_string().into())).unwrap();
                }
                true
            });
            let endpoint = locate(&binding).unwrap().unwrap();
            let handoff = Handoff {
                thread: "thread-1",
                client_id: "client-1",
                text: "hello",
                mode: Mode::Message,
                allow_resume: false,
                require_idle: true,
                cold_expected_turn: None,
                deadline_ms: current_unix_millis() + 3000,
                timeout: Duration::from_secs(3),
            };
            let outcome = deliver(&endpoint, &handoff, || panic!("must not resume"), || Ok(()));
            let started = worker.join().unwrap();
            let target_dir = std::env::temp_dir()
                .parent()
                .unwrap()
                .join(dir.file_name().unwrap());
            fs::remove_dir_all(dir).unwrap();
            fs::remove_dir_all(target_dir).unwrap();
            assert_eq!(started, matches!(case, "idle" | "lost"), "{case}");
            assert!(
                match case {
                    "idle" => matches!(outcome, Outcome::NativeAccepted { .. }),
                    "lost" => matches!(outcome, Outcome::OutcomeUnknown { .. }),
                    _ => matches!(outcome, Outcome::DeferredKnownUnsent { .. }),
                },
                "{case}: {outcome:?}"
            );
        }
    }

    /// A retired binding may use its one-shot idle proof for an already loaded
    /// idle thread, but never writes after a denied proof or a pending approval.
    #[test]
    fn retired_loaded_idle_requires_proof_and_current_native_idle() {
        for case in ["idle", "proof_denied", "waiting", "oversized", "deadline"] {
            let (dir, listener, binding) = fixture();
            let worker = thread::spawn(move || {
                drop(listener.accept().unwrap().0);
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let _ = ws.read().unwrap();
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let _ = ws.read().unwrap();
                let _ = ws.read().unwrap();
                ws.send(Message::Text(
                    json!({"id":2,"result":{"thread":{"id":"thread-1","status":{"type":"idle"}}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(read)) = ws.read() else {
                    return false;
                };
                let read: Value = serde_json::from_str(&read).unwrap();
                assert_eq!(read["method"], "thread/read");
                let status = if case == "waiting" {
                    json!({"type":"active","activeFlags":["waitingOnApproval"]})
                } else {
                    json!({"type":"idle"})
                };
                ws.send(Message::Text(
                    json!({"id":5,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let started =
                    matches!(ws.read(), Ok(Message::Text(text)) if text.contains("turn/start"));
                if started {
                    ws.send(Message::Text(json!({"id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}).to_string().into())).unwrap();
                }
                started
            });
            let endpoint = locate(&binding).unwrap().unwrap();
            let oversized = "x".repeat(LIMIT + 1);
            let deadline_ms = current_unix_millis() + if case == "deadline" { 1000 } else { 3000 };
            let handoff = Handoff {
                thread: "thread-1",
                client_id: "client-1",
                text: if case == "oversized" {
                    &oversized
                } else {
                    "hello"
                },
                mode: Mode::Message,
                allow_resume: true,
                require_idle: false,
                cold_expected_turn: None,
                deadline_ms,
                timeout: Duration::from_secs(3),
            };
            let proofs = AtomicU64::new(0);
            let outcome = deliver(
                &endpoint,
                &handoff,
                || {
                    proofs.fetch_add(1, Ordering::Relaxed);
                    if case == "deadline" {
                        let remaining = deadline_ms.saturating_sub(current_unix_millis());
                        thread::sleep(Duration::from_millis(remaining + 25));
                    }
                    if case == "proof_denied" {
                        Err("no idle proof".into())
                    } else {
                        Ok(())
                    }
                },
                || Ok(()),
            );
            let started = worker.join().unwrap();
            let target_dir = std::env::temp_dir()
                .parent()
                .unwrap()
                .join(dir.file_name().unwrap());
            fs::remove_dir_all(dir).unwrap();
            fs::remove_dir_all(target_dir).unwrap();
            assert_eq!(proofs.load(Ordering::Relaxed), 1, "{case}");
            assert_eq!(started, case == "idle", "{case}");
            assert!(
                if case == "idle" {
                    matches!(outcome, Outcome::NativeAccepted { .. })
                } else {
                    matches!(outcome, Outcome::DeferredKnownUnsent { .. })
                },
                "{case}: {outcome:?}"
            );
        }
    }

    /// Resume requires the same episode and binding; uncertain writes stay unknown.
    #[test]
    fn unloaded_thread_resumes_without_crossing_a_changed_binding() {
        for case in [
            "ready",
            "empty_ready",
            "empty_changed",
            "different",
            "in_progress",
            "pending_before",
            "pending_after",
            "probe_active",
            "probe_idle",
            "state_change",
            "invalid_id",
            "multiple",
            "initial_idle",
            "unqualified",
            "deadline",
            "fence_before",
            "renewed",
            "waiting",
            "lost",
            "message_lost",
            "wrong",
            "denied",
            "pre_busy",
        ] {
            let changed = case == "renewed";
            let (dir, listener, binding) = fixture();
            let fence = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let server_fence = std::sync::Arc::clone(&fence);
            let claims = std::sync::Arc::new(AtomicU64::new(0));
            let server_claims = std::sync::Arc::clone(&claims);
            let worker = thread::spawn(move || {
                drop(listener.accept().unwrap().0);
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut ws = tungstenite::accept(stream).unwrap();
                let _ = ws.read().unwrap();
                ws.send(Message::Text(
                    json!({"id":1,"result":{}}).to_string().into(),
                ))
                .unwrap();
                let _ = ws.read().unwrap();
                let _ = ws.read().unwrap();
                let initial = if case == "initial_idle" {
                    "idle"
                } else {
                    "notLoaded"
                };
                ws.send(Message::Text(
                    json!({"id":2,"result":{"thread":{"id":"thread-1","status":{"type":initial}}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                if !matches!(case, "initial_idle" | "unqualified" | "deadline" | "denied") {
                    listener.set_nonblocking(true).unwrap();
                    let limit = Instant::now() + Duration::from_secs(4);
                    let probe_stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                assert!(Instant::now() < limit, "{case}: no episode recheck");
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(err) => panic!("{case}: probe accept failed: {err}"),
                        }
                    };
                    assert_eq!(server_claims.load(Ordering::SeqCst), 1, "{case}");
                    probe_stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut probe = tungstenite::accept(probe_stream).unwrap();
                    let _ = probe.read().unwrap();
                    probe
                        .send(Message::Text(
                            json!({"id":1,"result":{}}).to_string().into(),
                        ))
                        .unwrap();
                    let _ = probe.read().unwrap();
                    let _ = probe.read().unwrap();
                    let status = match case {
                        "pending_before" => {
                            json!({"type":"active","activeFlags":["waitingOnApproval"]})
                        }
                        "probe_active" => json!({"type":"active","activeFlags":[]}),
                        "probe_idle" => json!({"type":"idle"}),
                        _ => json!({"type":"notLoaded"}),
                    };
                    probe
                        .send(Message::Text(
                            json!({"id":2,"result":{"thread":{"id":"thread-1","status":status}}})
                                .to_string()
                                .into(),
                        ))
                        .unwrap();
                    if let Ok(Message::Text(list)) = probe.read() {
                        let list: Value = serde_json::from_str(&list).unwrap();
                        assert_eq!(list["method"], "thread/turns/list", "{case}");
                        let data = match case {
                            "empty_ready" => json!([]),
                            "different" => json!([{"id":"other","status":"completed"}]),
                            "in_progress" => json!([{"id":"turn-1","status":"inProgress"}]),
                            "invalid_id" => json!([{"id":"","status":"completed"}]),
                            "multiple" => {
                                json!([{"id":"turn-1","status":"completed"},{"id":"turn-2","status":"completed"}])
                            }
                            _ => json!([{"id":"turn-1","status":"completed"}]),
                        };
                        probe
                            .send(Message::Text(
                                json!({"id":3,"result":{"data":data}}).to_string().into(),
                            ))
                            .unwrap();
                        if let Ok(Message::Text(read)) = probe.read() {
                            let read: Value = serde_json::from_str(&read).unwrap();
                            assert_eq!(read["method"], "thread/read", "{case}");
                            let status = match case {
                                "pending_after" => {
                                    json!({"type":"active","activeFlags":["waitingOnApproval"]})
                                }
                                "probe_idle" | "state_change" => json!({"type":"idle"}),
                                _ => json!({"type":"notLoaded"}),
                            };
                            probe.send(Message::Text(json!({"id":4,"result":{"thread":{"id":"thread-1","status":status}}}).to_string().into())).unwrap();
                        }
                    }
                }
                let Ok(Message::Text(recheck)) = ws.read() else {
                    return (false, false);
                };
                let recheck: Value = serde_json::from_str(&recheck).unwrap();
                assert_eq!(recheck["method"], "thread/read");
                let status = if case == "pre_busy" {
                    json!({"type":"active","activeFlags":["waitingOnApproval"]})
                } else {
                    json!({"type":"notLoaded"})
                };
                ws.send(Message::Text(
                    json!({"id":6,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(resume)) = ws.read() else {
                    return (false, false);
                };
                let resume: Value = serde_json::from_str(&resume).unwrap();
                if resume["method"] != "thread/resume" {
                    return (false, false);
                }
                assert_eq!(
                    resume["params"],
                    json!({"threadId":"thread-1","excludeTurns":true})
                );
                server_fence.store(changed, Ordering::SeqCst);
                if case == "lost" {
                    return (true, false);
                }
                let resumed_thread = if case == "wrong" {
                    "other-thread"
                } else {
                    "thread-1"
                };
                ws.send(Message::Text(
                    json!({"id":4,"result":{"thread":{"id":resumed_thread}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let Ok(Message::Text(read)) = ws.read() else {
                    return (true, false);
                };
                let read: Value = serde_json::from_str(&read).unwrap();
                assert_eq!(read["method"], "thread/read");
                let status = if case == "waiting" {
                    json!({"type":"active","activeFlags":["waitingOnApproval"]})
                } else {
                    json!({"type":"idle"})
                };
                ws.send(Message::Text(
                    json!({"id":5,"result":{"thread":{"id":"thread-1","status":status}}})
                        .to_string()
                        .into(),
                ))
                .unwrap();
                let started =
                    matches!(ws.read(), Ok(Message::Text(text)) if text.contains("turn/start"));
                if started && case != "message_lost" {
                    ws.send(Message::Text(json!({"id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}).to_string().into())).unwrap();
                }
                (true, started)
            });
            let endpoint = locate(&binding).unwrap().unwrap();
            let deadline_ms = current_unix_millis() + if case == "deadline" { 1000 } else { 3000 };
            let handoff = Handoff {
                thread: "thread-1",
                client_id: "client-1",
                text: "hello",
                mode: Mode::Message,
                allow_resume: true,
                require_idle: false,
                cold_expected_turn: match case {
                    "unqualified" => None,
                    "empty_ready" | "empty_changed" => Some(""),
                    _ => Some("turn-1"),
                },
                deadline_ms,
                timeout: Duration::from_secs(3),
            };
            let outcome = deliver(
                &endpoint,
                &handoff,
                || {
                    claims.fetch_add(1, Ordering::SeqCst);
                    if case == "deadline" {
                        let remaining = deadline_ms.saturating_sub(current_unix_millis());
                        thread::sleep(Duration::from_millis(remaining + 25));
                    }
                    if case == "denied" {
                        Err("no idle proof".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    if case == "fence_before" || fence.load(Ordering::SeqCst) {
                        Err("changed".into())
                    } else {
                        Ok(())
                    }
                },
            );
            let (resumed, started) = worker.join().unwrap();
            let target_dir = std::env::temp_dir()
                .parent()
                .unwrap()
                .join(dir.file_name().unwrap());
            fs::remove_dir_all(dir).unwrap();
            fs::remove_dir_all(target_dir).unwrap();
            assert_eq!(
                claims.load(Ordering::SeqCst),
                u64::from(!matches!(case, "initial_idle" | "unqualified")),
                "{case}"
            );
            assert_eq!(
                resumed,
                matches!(
                    case,
                    "ready"
                        | "empty_ready"
                        | "renewed"
                        | "waiting"
                        | "lost"
                        | "message_lost"
                        | "wrong"
                ),
                "{case}"
            );
            assert_eq!(
                started,
                matches!(case, "ready" | "empty_ready" | "message_lost"),
                "{case}"
            );
            assert!(
                match case {
                    "ready" | "empty_ready" => matches!(outcome, Outcome::NativeAccepted { .. }),
                    "lost" | "wrong" | "message_lost" =>
                        matches!(outcome, Outcome::OutcomeUnknown { .. }),
                    "renewed" | "waiting" =>
                        matches!(outcome, Outcome::ResumeAcceptedNoMessage { .. }),
                    _ => matches!(outcome, Outcome::DeferredKnownUnsent { .. }),
                },
                "{case}: {outcome:?}"
            );
        }
    }

    /// An incorrect frozen incarnation cannot select an otherwise owned socket.
    #[test]
    fn rejects_wrong_peer_incarnation() {
        let (dir, listener, mut binding) = fixture();
        binding.harness.1 += 1;
        assert!(locate(&binding).is_err());
        drop(listener);
        let target_dir = std::env::temp_dir()
            .parent()
            .unwrap()
            .join(dir.file_name().unwrap());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(target_dir).unwrap();
    }
    /// A live process with matching UID and incarnation cannot impersonate the socket peer.
    #[test]
    fn rejects_wrong_kernel_peer_pid() {
        let (dir, listener, mut binding) = fixture();
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let facts = os::process_facts(child.id()).unwrap();
        binding.harness = (facts.pid, facts.start_time);
        binding.executable = facts.exe.unwrap();
        let refused = locate(&binding).is_err();
        child.kill().unwrap();
        child.wait().unwrap();
        drop(listener);
        let target_dir = std::env::temp_dir()
            .parent()
            .unwrap()
            .join(dir.file_name().unwrap());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(target_dir).unwrap();
        assert!(refused);
    }
}
