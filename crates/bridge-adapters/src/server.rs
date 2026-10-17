//! The adapter channel: a private Unix socket in the Bridge daemon that
//! hook commands and root MCP servers connect to.
//!
//! Every connection's peer is identified by the kernel (PID, UID) before a
//! byte is read, and the registry resolves it to a marked harness incarnation
//! that the harness policy enables (see [`crate::registry`]). One JSON request
//! line per connection:
//!
//! - `{"op":"hook","harness":..,"payload":{native hook JSON}}` admits one
//!   hook event. At a natural context point of the addressed actor with
//!   inject granted by the harness policy, the server drains through core
//!   [`Storage::drain_inject`] — which commits the reserved, `invoking`,
//!   frozen manifest *before* any byte is returned — and replies with the
//!   exact stdout line the hook must print. The hook prints, flushes and
//!   answers `{"op":"flushed","digest":..}`; only that records
//!   `hook_submitted` (emission evidence, not model context). Silence,
//!   EOF, a wrong digest or a timeout after the reply records
//!   `outcome_unknown` (retained, never re-offered).
//! - `{"op":"attest","meta":{..}}` attests the presenting process as the
//!   caller of one MCP request (see [`crate::registry::Registry::attest_caller`]).
//!
//! Lock order: the registry lock and the storage lock are never held at the
//! same time, and neither is held across socket I/O.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod producer;

use bridge_core::dispatch::{DispatchTiming, Outcome, Selection, lock_storage};
use bridge_core::service::{current_unix_millis, log_event};
use bridge_core::{Harness, Storage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::os;
use crate::registry::{
    ActorRole, CallerChannel, CorrelationError, HookPayload, PresentedMeta, Registry,
};

/// Largest request line accepted on the channel, in bytes.
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// Largest number of connections served at once.
const MAX_CONNECTIONS: usize = 64;

/// Per-read/write timeout on a channel connection.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Access to the one authoritative custody store the core service owns.
///
/// Implemented for the running core service and for a bare
/// `Mutex<Storage>` (tests). Implementations run `action` with exclusive
/// access and must not hold the store across slow work.
pub trait Custody: Send + Sync {
    /// Runs `action` on the store, or does nothing when no store is
    /// attached yet (see [`LateCustody`]); returns whether it ran.
    fn run(&self, action: &mut dyn FnMut(&mut Storage)) -> bool;
}

impl Custody for bridge_core::Running {
    /// Runs under the service's own storage lock.
    fn run(&self, action: &mut dyn FnMut(&mut Storage)) -> bool {
        self.with_storage(|storage| action(storage));
        true
    }
}

impl Custody for Mutex<Storage> {
    /// Runs under this mutex (poison-tolerant, like core).
    fn run(&self, action: &mut dyn FnMut(&mut Storage)) -> bool {
        action(&mut lock_storage(self));
        true
    }
}

/// A custody handle attached after the service started.
///
/// Carriers are handed to the core service before it exists; their
/// background threads (late callbacks) reach custody through this handle,
/// which the daemon attaches once the service runs. Before attachment
/// nothing runs and callers treat it as unavailable. The handle is weak, so
/// it never keeps the service alive (the service owns the carriers that
/// own this handle).
#[derive(Default)]
pub struct LateCustody {
    /// The attached store.
    inner: OnceLock<Weak<dyn Custody>>,
}

impl LateCustody {
    /// Attaches the store; a second attachment is ignored.
    pub fn attach(&self, custody: &Arc<dyn Custody>) {
        let weak: Weak<dyn Custody> = Arc::downgrade(custody);
        let _ = self.inner.set(weak);
    }
}

impl Custody for LateCustody {
    /// Delegates to the attached store, or reports `false`.
    fn run(&self, action: &mut dyn FnMut(&mut Storage)) -> bool {
        match self.inner.get().and_then(Weak::upgrade) {
            Some(custody) => custody.run(action),
            None => false,
        }
    }
}

/// Runs `action` on custody and returns its value, or `None` when custody
/// is not attached.
pub fn with_custody<R>(custody: &dyn Custody, action: impl FnOnce(&mut Storage) -> R) -> Option<R> {
    let mut action = Some(action);
    let mut result = None;
    custody.run(&mut |storage| {
        if let Some(action) = action.take() {
            result = Some(action(storage));
        }
    });
    result
}

/// One request line on the channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum ChannelRequest {
    /// One native hook event.
    Hook {
        /// Harness that ran the hook.
        harness: Harness,
        /// The native hook payload as the harness wrote it.
        payload: serde_json::Value,
    },
    /// Caller attestation of the presenting process (native metadata from
    /// a harness-launched frontend, or a sealed proof from a relay).
    Attest {
        /// Protected MCP metadata or a sealed proof.
        meta: PresentedMeta,
        /// Also issue a sealed single-use proof of the result.
        #[serde(default)]
        seal: bool,
    },
    /// Hook confirmation that the reply was fully written and flushed.
    Flushed {
        /// SHA-256 of the exact stdout bytes printed.
        digest: String,
    },
}

/// One response line on the channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum ChannelResponse {
    /// Admitted; nothing to print.
    Ok,
    /// Print exactly `stdout`, flush, then confirm with its digest.
    Inject {
        /// The complete stdout line for the hook.
        stdout: String,
        /// SHA-256 of `stdout`'s bytes.
        digest: String,
    },
    /// The verified caller.
    Caller {
        /// Address the caller acts in.
        address: bridge_core::NativeAddress,
        /// Root or child.
        role: ActorRole,
        /// Native actor id.
        native_id: String,
        /// Binding epoch.
        epoch: u64,
        /// Hook record observation time.
        observed_at_ms: u64,
        /// Correlation channel.
        channel: CallerChannel,
        /// Obtained by redeeming a sealed proof.
        #[serde(default)]
        relayed: bool,
        /// Sealed proof of this result, when requested.
        #[serde(default)]
        proof: Option<crate::registry::SealedProof>,
    },
    /// Refused; nothing was admitted or disclosed.
    Refused {
        /// Correlation error class.
        class: String,
        /// Detail without secrets.
        detail: String,
    },
}

impl From<CorrelationError> for ChannelResponse {
    /// Wire form of a refusal.
    fn from(error: CorrelationError) -> Self {
        ChannelResponse::Refused {
            class: error.class().to_string(),
            detail: error.detail().to_string(),
        }
    }
}

/// Lowercase hex SHA-256 of bytes.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Shared state of a running channel.
struct ChannelState {
    /// The protected registry.
    registry: Arc<Mutex<Registry>>,
    /// The custody store.
    custody: Arc<dyn Custody>,
    /// Drain timing (lease and hand-off windows).
    timing: DispatchTiming,
    /// Cleared to stop.
    running: AtomicBool,
    /// Connections being served.
    active: AtomicUsize,
}

/// A running channel listener.
pub struct ChannelServer {
    /// Socket path.
    socket: PathBuf,
    /// Socket inode identity, so stop removes only our endpoint.
    identity: (u64, u64),
    /// Shared state.
    state: Arc<ChannelState>,
    /// Accept loop.
    accept: Option<JoinHandle<()>>,
    /// Exclusive endpoint lock (`<socket>.lock`), held for the server's whole
    /// life and released after the socket is removed on stop.
    _lock: std::fs::File,
}

/// Takes the exclusive advisory lock that serializes every channel server
/// contending for `socket`: `<socket>.lock`, created `0600` if absent and left
/// in place afterwards (removing it would reopen the race it closes). A
/// non-regular file (including a symlink) at that path is refused untouched.
///
/// # Errors
///
/// The lock path is not a regular file or cannot be opened, or another live
/// server holds the lock (`WouldBlock`).
fn lock_endpoint(socket: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    let path = PathBuf::from(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(std::io::Error::other(
                "channel endpoint lock path is not a regular file",
            ));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "another channel server owns this endpoint",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

/// Clears `socket` for binding only when it is positively stale; called with
/// the endpoint lock held, so no other channel server can bind in between.
///
/// Absent: nothing to do. A socket file owned by `owner_uid` that refuses a
/// connection (nothing listens: a crashed earlier server) is removed, and only
/// while it is still the inode that was inspected. Everything else is refused
/// and left untouched: a live listener (`AddrInUse`), a symlink, a regular
/// file or directory, a socket of another user, a replaced inode, and any
/// connect error that is not a refusal (no positive staleness proof).
///
/// # Errors
///
/// Any refusal above or an inspection/removal failure.
fn claim_stale_socket(socket: &Path, owner_uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match std::fs::symlink_metadata(socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    if !metadata.file_type().is_socket() || metadata.uid() != owner_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "channel path is not a socket of this user; left untouched",
        ));
    }
    match UnixStream::connect(socket) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "a live server already owns the channel socket",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let again = std::fs::symlink_metadata(socket)?;
            if (again.dev(), again.ino()) != (metadata.dev(), metadata.ino()) {
                return Err(std::io::Error::other(
                    "channel socket was replaced while it was inspected",
                ));
            }
            std::fs::remove_file(socket)
        }
        Err(error) => Err(std::io::Error::new(
            error.kind(),
            "cannot prove the channel socket is stale; left untouched",
        )),
    }
}

/// Locks the registry, tolerating poison (each admission is a whole
/// in-memory update).
pub(crate) fn lock_registry(registry: &Mutex<Registry>) -> MutexGuard<'_, Registry> {
    registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Creates or verifies the private channel directory: owned by this user
/// and not accessible by group or others. Returns the owner uid.
pub fn private_directory(path: &Path) -> std::io::Result<u32> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(std::io::Error::other(
                    "channel directory is not a directory",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let own = os::process_facts(std::process::id())
        .and_then(|facts| facts.uid)
        .ok_or_else(|| std::io::Error::other("own uid unreadable"))?;
    if metadata.uid() != own || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "channel directory must be owned by this user with mode 0700",
        ));
    }
    Ok(own)
}

impl ChannelServer {
    /// Binds `socket` (its directory must be private, see
    /// [`private_directory`]) and starts serving.
    ///
    /// Revalidates the private sibling route journal and records renewed core
    /// fences before accepting hooks. Call records are never recovered.
    ///
    /// Endpoint ownership: the exclusive `<socket>.lock` is taken first (a
    /// second live server refuses before inspecting anything) and held for
    /// the server's life. A stale socket left by a crashed server (this
    /// user's socket, connection refused, same inode) is removed so a restart
    /// binds again; a live listener, a symlink, a non-socket path or another
    /// user's socket is refused and never removed.
    pub fn start(
        socket: &Path,
        registry: Arc<Mutex<Registry>>,
        custody: Arc<dyn Custody>,
        timing: DispatchTiming,
    ) -> std::io::Result<ChannelServer> {
        let directory = socket
            .parent()
            .ok_or_else(|| std::io::Error::other("channel socket has no directory"))?;
        let owner = private_directory(directory)?;
        let lock = lock_endpoint(socket)?;
        claim_stale_socket(socket, owner)?;
        let restored = lock_registry(&registry)
            .attach_journal(
                &socket.with_extension("bindings.json"),
                current_unix_millis(),
            )
            .map_err(std::io::Error::other)?;
        for attestation in restored {
            let observed = with_custody(custody.as_ref(), |storage| {
                storage.observe_binding(&attestation, current_unix_millis())
            });
            match observed {
                Some(Ok(_)) => {}
                _ => {
                    return Err(std::io::Error::other(
                        "restored recipient fence could not be recorded",
                    ));
                }
            }
        }
        let listener = UnixListener::bind(socket)?;
        let metadata = std::fs::symlink_metadata(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let state = Arc::new(ChannelState {
            registry,
            custody,
            timing,
            running: AtomicBool::new(true),
            active: AtomicUsize::new(0),
        });
        let accept_state = Arc::clone(&state);
        let accept = std::thread::Builder::new()
            .name("bridge-adapter-channel".into())
            .spawn(move || accept_loop(listener, accept_state))?;
        Ok(ChannelServer {
            socket: socket.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
            state,
            accept: Some(accept),
            _lock: lock,
        })
    }

    /// The bound socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Stops accepting, waits for the accept loop and removes the socket
    /// only if it is still the inode this server bound. In-flight
    /// connections finish on their own threads; an unconfirmed drain still
    /// records `outcome_unknown`.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Shared stop logic for [`ChannelServer::stop`] and drop.
    fn shutdown(&mut self) {
        self.state.running.store(false, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if std::fs::symlink_metadata(&self.socket)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
        {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

impl Drop for ChannelServer {
    /// Stops like [`ChannelServer::stop`].
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Accepts connections until stopped, one bounded thread each.
fn accept_loop(listener: UnixListener, state: Arc<ChannelState>) {
    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if state.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    state.active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let connection_state = Arc::clone(&state);
                let spawned = std::thread::Builder::new()
                    .name("bridge-adapter-conn".into())
                    .spawn(move || {
                        serve(stream, &connection_state);
                        connection_state.active.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    state.active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Reads one bounded strict UTF-8 line under one absolute timeout. Partial
/// traffic never renews the caller-supplied budget. Initial ingress uses five
/// seconds; hook confirmation supplies its own configured handoff window.
/// EOF/oversize/timeout/errors return None.
fn read_line(reader: &mut BufReader<UnixStream>, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        reader.get_ref().set_read_timeout(Some(remaining)).ok()?;
        let chunk = reader.fill_buf().ok()?;
        if chunk.is_empty() {
            return None;
        }
        let take = chunk
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(chunk.len(), |index| index + 1);
        if bytes.len() + take > MAX_REQUEST_BYTES {
            return None;
        }
        let complete = chunk[take - 1] == b'\n';
        bytes.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if complete {
            return String::from_utf8(bytes).ok();
        }
    }
}

/// Writes one response line.
fn write_response(stream: &mut UnixStream, response: &ChannelResponse) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

/// Serves one protected connection. Native observation reads bypass executable
/// digest refresh so authorization precedes registry access and reads stay pure.
fn serve(stream: UnixStream, state: &ChannelState) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(peer) = os::peer_identity(&stream) else {
        return;
    };
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let Some(line) = read_line(&mut reader, IO_TIMEOUT) else {
        return;
    };
    if serde_json::from_str::<serde_json::Value>(&line)
        .ok()
        .is_some_and(|value| value.get("api_version").is_some())
    {
        producer::serve_v1(&line, peer, state, &mut writer);
        return;
    }
    // Refresh configured relay/audience builds before legacy attestation; v1
    // registration/assertion paths refresh after decoding their operation.
    crate::registry::refresh_stale(&state.registry);
    let request: ChannelRequest = match serde_json::from_str(&line) {
        Ok(request) => request,
        Err(_) => {
            let _ = write_response(
                &mut writer,
                &CorrelationError::NotEvidence("malformed channel request".into()).into(),
            );
            return;
        }
    };
    match request {
        ChannelRequest::Attest { meta, seal } => {
            let now = current_unix_millis();
            let result = if seal {
                lock_registry(&state.registry)
                    .attest_and_seal(peer, &meta, now)
                    .map(|(caller, proof)| (caller, Some(proof)))
            } else {
                lock_registry(&state.registry)
                    .attest_caller(peer, &meta, now)
                    .map(|caller| (caller, None))
            };
            let response = match result {
                Ok((caller, proof)) => ChannelResponse::Caller {
                    relayed: caller.relayed(),
                    proof,
                    address: caller.address().clone(),
                    role: caller.role(),
                    native_id: caller.native_id().to_string(),
                    epoch: caller.epoch(),
                    observed_at_ms: caller.observed_at_ms(),
                    channel: caller.channel(),
                },
                Err(error) => {
                    log_event("warn", "caller_refused", &[("class", error.class())]);
                    error.into()
                }
            };
            let _ = write_response(&mut writer, &response);
        }
        ChannelRequest::Hook { harness, payload } => {
            serve_hook(peer, harness, payload, state, &mut reader, &mut writer);
        }
        ChannelRequest::Flushed { .. } => {
            let _ = write_response(
                &mut writer,
                &CorrelationError::NotEvidence("flushed without a reply".into()).into(),
            );
        }
    }
}

/// Admits one hook event and, at a context point with inject granted, drains.
fn serve_hook(
    peer: os::PeerIdentity,
    harness: Harness,
    payload: serde_json::Value,
    state: &ChannelState,
    reader: &mut BufReader<UnixStream>,
    writer: &mut UnixStream,
) {
    let payload: HookPayload = match serde_json::from_value(payload) {
        Ok(payload) => payload,
        Err(_) => {
            let _ = write_response(
                writer,
                &CorrelationError::NotEvidence("malformed hook payload".into()).into(),
            );
            return;
        }
    };
    let now = current_unix_millis();
    let admitted = lock_registry(&state.registry).admit_hook(peer, harness, &payload, now);
    let admission = match admitted {
        Ok(admission) => admission,
        Err(error) => {
            log_event("warn", "hook_refused", &[("class", error.class())]);
            let _ = write_response(writer, &error.into());
            return;
        }
    };
    if let Some(attestation) = &admission.renewed {
        let observed = with_custody(state.custody.as_ref(), |storage| {
            storage.observe_binding(attestation, now)
        });
        if let Some(Err(error)) = observed {
            log_event(
                "warn",
                "binding_fence_refused",
                &[("error", &error.to_string())],
            );
        }
    }
    let Some(attestation) = admission.drain else {
        let _ = write_response(writer, &ChannelResponse::Ok);
        return;
    };
    // Reserve + invoking + frozen manifest commit in one core transaction,
    // before any payload byte can leave.
    let drained = with_custody(state.custody.as_ref(), |storage| {
        storage.drain_inject(&attestation, current_unix_millis(), &state.timing)
    });
    let record = match drained {
        Some(Ok(Selection::Attempt(record))) => record,
        Some(Ok(Selection::Idle | Selection::Held(_))) => {
            let _ = write_response(writer, &ChannelResponse::Ok);
            return;
        }
        Some(Err(error)) => {
            log_event("warn", "drain_refused", &[("error", &error.to_string())]);
            let _ = write_response(writer, &ChannelResponse::Ok);
            return;
        }
        None => {
            let _ = write_response(writer, &ChannelResponse::Ok);
            return;
        }
    };
    let stdout = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": admission.kind.as_str(),
            "additionalContext": record.manifest,
        }
    })
    .to_string();
    let digest = sha256_hex(stdout.as_bytes());
    let replied = write_response(
        writer,
        &ChannelResponse::Inject {
            stdout,
            digest: digest.clone(),
        },
    );
    // From here a hand-off may exist: only a matching flush confirmation is
    // positive evidence; everything else is a retained unknown outcome.
    let confirmation = match replied {
        Ok(()) => read_line(
            reader,
            Duration::from_millis(state.timing.handoff_ms.min(30_000)),
        )
        .and_then(|line| serde_json::from_str::<ChannelRequest>(&line).ok()),
        Err(_) => None,
    };
    let outcome = match confirmation {
        Some(ChannelRequest::Flushed { digest: echoed }) if echoed == digest => {
            Outcome::HookSubmitted {
                evidence: format!(
                    "hook {} pid {} flushed {} digest {}",
                    admission.kind.as_str(),
                    peer.pid,
                    harness.as_str(),
                    &digest[..16]
                ),
            }
        }
        Some(_) => Outcome::OutcomeUnknown {
            reason: "hook confirmation did not match the handed reply".into(),
        },
        None => Outcome::OutcomeUnknown {
            reason: "hook reply possibly handed without a flush confirmation".into(),
        },
    };
    let recorded = with_custody(state.custody.as_ref(), |storage| {
        storage.record_outcome(&record.fence, outcome, current_unix_millis())
    });
    if let Some(Err(error)) = recorded {
        log_event(
            "error",
            "hook_outcome_unrecorded",
            &[("error", &error.to_string())],
        );
    }
}

#[cfg(test)]
mod tests {
    //! Channel endpoint ownership: only a positively stale socket of this user
    //! is reclaimed, under an exclusive lock; nothing else is ever removed.
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh private scratch directory (mode 0700) under `TMPDIR`.
    fn scratch(tag: &str) -> PathBuf {
        let entropy = os::random_bytes().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "{tag}{:x}",
            u64::from_le_bytes(entropy[..8].try_into().unwrap())
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// A crashed server's socket (bound, listener gone) is removed; a live
    /// listener, a symlink to a stale socket, a regular file and a directory
    /// are refused and left exactly in place; an absent path is fine.
    #[test]
    fn only_a_positively_stale_own_socket_is_claimed() {
        let dir = scratch("cs");
        let uid = os::process_facts(std::process::id()).unwrap().uid.unwrap();
        let path = dir.join("c.sock");
        claim_stale_socket(&path, uid).unwrap();
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists(), "a dropped listener leaves its socket file");
        claim_stale_socket(&path, uid).unwrap();
        assert!(!path.exists(), "the stale socket is reclaimed");
        let live = UnixListener::bind(&path).unwrap();
        let error = claim_stale_socket(&path, uid).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            UnixStream::connect(&path).is_ok(),
            "the live endpoint survives"
        );
        drop(live);
        let error = claim_stale_socket(&path, uid + 1).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(path.exists(), "another user's socket is never removed");
        let link = dir.join("l.sock");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        claim_stale_socket(&link, uid).unwrap_err();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(path.exists(), "a symlink target is never touched");
        let file = dir.join("f.sock");
        std::fs::write(&file, b"foreign").unwrap();
        claim_stale_socket(&file, uid).unwrap_err();
        assert_eq!(std::fs::read(&file).unwrap(), b"foreign");
        let directory = dir.join("d.sock");
        std::fs::create_dir(&directory).unwrap();
        claim_stale_socket(&directory, uid).unwrap_err();
        assert!(directory.is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The endpoint lock admits one holder at a time and is released on drop;
    /// a symlink at the lock path is refused untouched.
    #[test]
    fn the_endpoint_lock_is_exclusive() {
        let dir = scratch("cl");
        let path = dir.join("c.sock");
        let held = lock_endpoint(&path).unwrap();
        let error = lock_endpoint(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        drop(held);
        drop(lock_endpoint(&path).unwrap());
        let other = dir.join("o.sock");
        std::os::unix::fs::symlink(dir.join("c.sock.lock"), dir.join("o.sock.lock")).unwrap();
        lock_endpoint(&other).unwrap_err();
        assert!(
            std::fs::symlink_metadata(dir.join("o.sock.lock"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
