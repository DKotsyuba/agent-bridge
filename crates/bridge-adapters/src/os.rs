//! Kernel-observed peer and process facts.
//!
//! Every identity decision of this crate starts here, from facts the
//! operating system reports rather than anything a peer writes: the PID and
//! effective UID of a connected Unix-socket peer, and the parent chain,
//! start time, executable and own environment of a process. None of these
//! facts alone identifies an actor — a PID can be reused and any same-user
//! process can connect — so callers combine them with a registered harness
//! incarnation (PID plus start time) and the harness's own hook channel
//! (see [`crate::registry`]).
//!
//! The crate forbids first-party `unsafe`; peer credentials come from
//! tokio's stable `peer_cred` (LOCAL_PEEREPID + getpeereid on macOS,
//! SO_PEERCRED on Linux) and process facts from `sysinfo`.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Deepest parent chain walked when looking for a harness ancestor.
///
/// Hooks run under at most a few shells below their harness; a deeper
/// chain is not a hook of a registered harness.
pub const MAX_ANCESTRY: usize = 8;

/// The kernel-reported identity of a connected Unix-socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Process id of the peer at connection time.
    pub pid: u32,
    /// Effective user id of the peer.
    pub uid: u32,
}

/// Reads the kernel-reported identity of a connected stream's peer.
///
/// The stream is temporarily registered with a private current-thread tokio
/// reactor only to call the stable `peer_cred` API and is returned to
/// blocking std form unchanged. Errors when the platform reports no PID or
/// the socket is not connected; callers must refuse the connection.
pub fn peer_identity(stream: &UnixStream) -> std::io::Result<PeerIdentity> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let clone = stream.try_clone()?;
    clone.set_nonblocking(true)?;
    let credentials = runtime.block_on(async move {
        let tokio_stream = tokio::net::UnixStream::from_std(clone)?;
        let credentials = tokio_stream.peer_cred();
        drop(tokio_stream.into_std()?);
        credentials
    })?;
    // The clone shares the open file description; restore blocking mode
    // for the caller's std stream.
    stream.set_nonblocking(false)?;
    let pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| std::io::Error::other("the kernel reported no peer pid"))?;
    Ok(PeerIdentity {
        pid,
        uid: credentials.uid(),
    })
}

/// OS facts about one process, read at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessFacts {
    /// Process id.
    pub pid: u32,
    /// Parent process id, when the OS reports one.
    pub parent: Option<u32>,
    /// Start time in seconds since the Unix epoch; with `pid` it names one
    /// process incarnation (a reused PID has a later start time).
    pub start_time: u64,
    /// Resolved executable path, when readable.
    pub exe: Option<PathBuf>,
    /// Real user id, when readable.
    pub uid: Option<u32>,
}

/// Reads the facts of one process, or `None` when it does not exist (or is
/// not visible to this user).
pub fn process_facts(pid: u32) -> Option<ProcessFacts> {
    let mut system = System::new();
    let target = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_user(UpdateKind::Always),
    );
    let process = system.process(target)?;
    Some(ProcessFacts {
        pid,
        parent: process.parent().map(Pid::as_u32),
        start_time: process.start_time(),
        exe: process.exe().map(PathBuf::from),
        uid: process.user_id().map(|uid| **uid),
    })
}

/// Reads the parent chain of `pid`, starting with `pid` itself, at most
/// [`MAX_ANCESTRY`] + 1 entries; stops at the first process that cannot be
/// read. Empty when `pid` itself is gone.
pub fn ancestry(pid: u32) -> Vec<ProcessFacts> {
    let mut chain = Vec::new();
    let mut next = Some(pid);
    while let Some(current) = next {
        if chain.len() > MAX_ANCESTRY {
            break;
        }
        let Some(facts) = process_facts(current) else {
            break;
        };
        next = facts
            .parent
            .filter(|parent| *parent != current && *parent > 1);
        chain.push(facts);
    }
    chain
}

/// Whether the exact process incarnation (`pid` started at `start_time`)
/// is still alive.
pub fn incarnation_alive(pid: u32, start_time: u64) -> bool {
    process_facts(pid).is_some_and(|facts| facts.start_time == start_time)
}

/// Reads 32 random bytes from the OS (`/dev/urandom`), for unguessable
/// proofs and message ids.
pub fn random_bytes() -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads one variable from a process's own environment as the OS reports
/// it (never from a peer's message).
///
/// Returns `None` when the variable is absent or the environment is not
/// readable. Used only for a harness process's own store selection
/// (`CODEX_HOME`, `CLAUDE_CONFIG_DIR`), never as caller identity.
pub fn process_env(pid: u32, name: &str) -> Option<OsString> {
    let mut system = System::new();
    let target = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_environ(UpdateKind::Always),
    );
    let process = system.process(target)?;
    let prefix = format!("{name}=");
    process.environ().iter().find_map(|entry| {
        let text = entry.to_str()?;
        text.strip_prefix(&prefix).map(OsString::from)
    })
}

#[cfg(test)]
mod tests {
    //! Facts about this very test process and a connected socket pair.

    use super::*;

    /// Peer credentials of a socket pair name this process and leave the stream usable.
    #[test]
    fn peer_identity_reports_this_process() {
        let (left, right) = UnixStream::pair().unwrap();
        let identity = peer_identity(&left).unwrap();
        assert_eq!(identity.pid, std::process::id());
        // The stream stays usable in blocking mode afterwards.
        use std::io::{Read, Write};
        (&right).write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        (&left).read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
    }

    /// Ancestry starts with this process and its exact incarnation is alive.
    #[test]
    fn ancestry_starts_with_self_and_incarnation_is_alive() {
        let chain = ancestry(std::process::id());
        assert_eq!(chain[0].pid, std::process::id());
        assert!(chain[0].exe.is_some());
        assert!(incarnation_alive(chain[0].pid, chain[0].start_time));
        assert!(!incarnation_alive(chain[0].pid, chain[0].start_time + 1));
    }
}
