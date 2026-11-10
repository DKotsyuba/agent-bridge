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

/// Linux-only attempt identity and direct launch-environment capture.
pub mod attempt;

use std::ffi::{OsStr, OsString};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Deepest parent chain walked when looking for a harness ancestor.
///
/// Hooks run under at most a few shells below their harness; a deeper
/// chain is not a hook of a registered harness.
pub const MAX_ANCESTRY: usize = 8;

/// Connects a Unix socket before an absolute monotonic deadline, returning a
/// blocking stream. An expired deadline, socket failure or reactor error refuses
/// without a retry; a full listen backlog cannot block the caller indefinitely.
pub fn connect_unix(
    path: &std::path::Path,
    deadline: std::time::Instant,
) -> std::io::Result<UnixStream> {
    if std::time::Instant::now() >= deadline {
        return Err(std::io::ErrorKind::TimedOut.into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let stream = runtime.block_on(async {
        tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            tokio::net::UnixStream::connect(path),
        )
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
    })?;
    if std::time::Instant::now() >= deadline {
        return Err(std::io::ErrorKind::TimedOut.into());
    }
    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

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
    /// Kernel start tick (since boot) read from `/proc/<pid>/stat` before and
    /// after the process-table read, when both reads agree. Only
    /// [`ProcessFacts::start_bound`] uses it, to place the start on the wall
    /// clock; the incarnation identity stays `(pid, start_time)`.
    #[cfg(target_os = "linux")]
    pub start_ticks: Option<u64>,
    /// Full Linux identity sampled around the process-table read, if available.
    #[cfg(target_os = "linux")]
    pub kernel_incarnation: Option<attempt::KernelIncarnation>,
    /// Resolved executable path, when readable.
    pub exe: Option<PathBuf>,
    /// Real user id, when readable.
    pub uid: Option<u32>,
}

/// Reads the facts of one process, or `None` when it does not exist (or is
/// not visible to this user).
pub fn process_facts(pid: u32) -> Option<ProcessFacts> {
    #[cfg(target_os = "linux")]
    let ticks_before = proc_start_ticks(pid);
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
        #[cfg(target_os = "linux")]
        start_ticks: ticks_before.filter(|ticks| proc_start_ticks(pid) == Some(*ticks)),
        #[cfg(target_os = "linux")]
        kernel_incarnation: None,
        parent: process.parent().map(Pid::as_u32),
        start_time: process.start_time(),
        exe: process.exe().map(PathBuf::from),
        uid: process.user_id().map(|uid| **uid),
    })
}

/// Kernel clock ticks per second of `/proc/<pid>/stat` times (`USER_HZ`, fixed
/// by the Linux userspace ABI on every architecture Bridge supports).
#[cfg(target_os = "linux")]
const USER_HZ: u128 = 100;

/// Resolution of `/proc/uptime`, which truncates to hundredths of a second.
#[cfg(target_os = "linux")]
const UPTIME_QUANTUM_NS: i128 = 10_000_000;

/// Start tick of `pid` from `/proc/<pid>/stat` (field 22), or `None`.
#[cfg(target_os = "linux")]
fn proc_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_ascii_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
        .filter(|ticks| *ticks > 0)
}

/// A lower bound of the wall-clock time the system booted, in nanoseconds
/// since the Unix epoch: `CLOCK_REALTIME` is sampled before the uptime
/// (`CLOCK_BOOTTIME`, truncated to hundredths by `/proc/uptime`, so one full
/// quantum is added back), so no step of the sampling can make the bound exceed
/// the true boot time. Derived from the same two kernel clocks the start tick
/// and file timestamps come from, not from `/proc/stat` `btime`.
#[cfg(target_os = "linux")]
fn boot_wall_lower_bound_ns() -> Option<i128> {
    let realtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let (seconds, hundredths) = uptime.split_ascii_whitespace().next()?.split_once('.')?;
    let hundredths = match hundredths.len() {
        2 => hundredths.parse::<u128>().ok()?,
        _ => return None,
    };
    let boot_ns = seconds
        .parse::<u128>()
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(hundredths * 10_000_000)?;
    Some(i128::try_from(realtime).ok()? - i128::try_from(boot_ns).ok()? - UPTIME_QUANTUM_NS)
}

/// The earliest wall-clock instant, in nanoseconds since the Unix epoch, at
/// which a process may have started, for comparison with full-resolution file
/// timestamps. Both sides are then read from the same kernel clocks.
///
/// A process whose start tick is known is placed exactly (`boot + ticks /
/// USER_HZ`, never later than its true start); otherwise only its whole start
/// second is known and the bound is the start of that second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartBound(i128);

impl StartBound {
    /// The start of whole Unix second `seconds`.
    #[must_use]
    pub fn from_secs(seconds: u64) -> Self {
        Self(i128::from(seconds) * 1_000_000_000)
    }

    /// Whether the Unix `(seconds, nanoseconds)` instant `time` is strictly
    /// before the process start bound.
    #[must_use]
    pub fn is_after(self, time: (i64, i64)) -> bool {
        i128::from(time.0) * 1_000_000_000 + i128::from(time.1) < self.0
    }

    /// Whether a file last written at `mtime` and last changed at `ctime`
    /// (each `(seconds, nanoseconds)`) was unchanged since before the process
    /// started: the later of the two must be strictly before the bound.
    #[must_use]
    pub fn is_after_change(self, mtime: (i64, i64), ctime: (i64, i64)) -> bool {
        self.is_after(mtime.max(ctime))
    }

    /// [`StartBound::is_after_change`] for the current metadata of a file.
    #[must_use]
    pub fn is_after_file(self, metadata: &std::fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.is_after_change(
            (metadata.mtime(), metadata.mtime_nsec()),
            (metadata.ctime(), metadata.ctime_nsec()),
        )
    }
}

impl From<u64> for StartBound {
    /// A start known only to whole second resolution.
    fn from(seconds: u64) -> Self {
        Self::from_secs(seconds)
    }
}

impl From<&ProcessFacts> for StartBound {
    fn from(facts: &ProcessFacts) -> Self {
        facts.start_bound()
    }
}

impl ProcessFacts {
    /// The wall-clock lower bound of this process's start; see [`StartBound`].
    /// Falls back to the whole start second when the kernel start tick or the
    /// boot clocks are unreadable.
    #[must_use]
    pub fn start_bound(&self) -> StartBound {
        #[cfg(target_os = "linux")]
        if let (Some(ticks), Some(boot)) = (self.start_ticks, boot_wall_lower_bound_ns()) {
            let since_boot = u128::from(ticks) * 1_000_000_000 / USER_HZ;
            if let Ok(since_boot) = i128::try_from(since_boot) {
                return StartBound(boot + since_boot);
            }
        }
        StartBound::from_secs(self.start_time)
    }
}

/// Samples a Linux process-table record between equal full identity reads.
/// Missing kernel evidence leaves the record unqualified for managed use.
#[cfg(target_os = "linux")]
pub(crate) fn process_facts_managed(pid: u32) -> Option<ProcessFacts> {
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .and_then(|metadata| attempt::kernel_incarnation(pid, metadata.uid()).ok());
    let mut facts = process_facts(pid)?;
    facts.kernel_incarnation = before.and_then(|before| {
        (facts.uid == Some(before.uid)
            && attempt::kernel_incarnation(pid, before.uid).ok().as_ref() == Some(&before))
        .then_some(before)
    });
    Some(facts)
}

/// Reads the bounded ancestry with complete identity around each process read.
#[cfg(target_os = "linux")]
pub(crate) fn ancestry_managed(pid: u32) -> Vec<ProcessFacts> {
    let mut chain = Vec::new();
    let mut next = Some(pid);
    while let Some(current) = next {
        if chain.len() > MAX_ANCESTRY {
            break;
        }
        let Some(facts) = process_facts_managed(current) else {
            break;
        };
        next = facts
            .parent
            .filter(|parent| *parent != current && *parent > 0);
        chain.push(facts);
    }
    chain
}

/// Reads the parent chain of `pid`, starting with `pid` itself, at most
/// [`MAX_ANCESTRY`] + 1 entries; stops at the first process that cannot be
/// read. PID 1 remains a real namespace parent, never implicit harness authority.
/// Empty when `pid` itself is gone.
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
            .filter(|parent| *parent != current && *parent > 0);
        chain.push(facts);
    }
    chain
}

/// Every process id the OS currently lists, from one process-table snapshot.
///
/// A cheap liveness prefilter for scans over many candidate PIDs (stale socket
/// names): it proves nothing about identity, so a listed PID must still pass
/// [`process_facts`]/[`ancestry`] and the incarnation checks before it counts.
pub fn live_pids() -> std::collections::HashSet<u32> {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    system.processes().keys().map(|pid| pid.as_u32()).collect()
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
/// readable; a value that is not valid UTF-8 is returned byte-exact, never
/// treated as absent. Used only for a harness process's own store selection
/// (`CODEX_HOME`, `CLAUDE_CONFIG_DIR`), never as caller identity.
pub fn process_env(pid: u32, name: &str) -> Option<OsString> {
    process_env_checked(pid, name).ok().flatten()
}

/// Like [`process_env`] but distinguishes positive absence from missing
/// knowledge: `Ok(None)` means the environment was read, held entries and none
/// is `name`; `Err` (kind `NotFound` for a gone process, `Unsupported` for an
/// environment that came back empty) means the answer is unknown. An empty
/// answer cannot be told apart from an unreadable one on this OS interface (a
/// process that genuinely has no environment may report exec metadata entries
/// instead, and then reads as positive absence). A present entry is matched on
/// its raw bytes, so a value that is not valid UTF-8 is still present and is
/// returned byte-exact, never reported as absent. A caller that must not treat
/// unknown metadata as absence (the native owner locator) holds on `Err`.
pub fn process_env_checked(pid: u32, name: &str) -> std::io::Result<Option<OsString>> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::ffi::OsStrExt;
    let mut system = System::new();
    let target = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_environ(UpdateKind::Always),
    );
    let process = system
        .process(target)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "process is gone"))?;
    if process.environ().is_empty() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "process environment is empty or unreadable",
        ));
    }
    let key = name.as_bytes();
    Ok(process.environ().iter().find_map(|entry| {
        let bytes = entry.as_bytes();
        match bytes.strip_prefix(key) {
            Some([b'=', value @ ..]) => Some(OsStr::from_bytes(value).to_os_string()),
            _ => None,
        }
    }))
}

/// Like [`process_env`], but also finds an entry that a process-title rewrite
/// shifted out of the environment block.
///
/// Node and Electron harnesses rename their processes (`process.title`) by
/// overwriting the original argument area; the kernel's argument count is
/// unchanged, so the first environment entries are then reported as arguments
/// and seem absent (ZCode's `zcode-cli` loses `HOME` this way). When `name` is
/// not in the environment, the reported arguments after the first are searched
/// for an exact `name=` entry. Used only for a profile-only harness's store
/// selection, whose result is still proven canonical, owned and private.
pub fn process_env_shifted(pid: u32, name: &str) -> Option<OsString> {
    use std::os::unix::ffi::OsStrExt;
    if let Some(value) = process_env(pid, name) {
        return Some(value);
    }
    let mut system = System::new();
    let target = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let key = name.as_bytes();
    system
        .process(target)?
        .cmd()
        .iter()
        .skip(1)
        .find_map(|entry| match entry.as_bytes().strip_prefix(key) {
            Some([b'=', value @ ..]) => Some(OsStr::from_bytes(value).to_os_string()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    //! Facts about this very test process and a connected socket pair.

    use super::*;

    /// An elapsed deadline refuses before connecting, even to a live listener.
    #[test]
    fn connect_refuses_an_expired_deadline() {
        let error = connect_unix(
            std::path::Path::new("/unused-socket"),
            std::time::Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    /// Linux's full Unix accept queue returns within the same bounded budget;
    /// all queued connections and the exclusively created socket are test-owned.
    #[cfg(target_os = "linux")]
    #[test]
    fn connect_to_a_full_listen_queue_is_bounded() {
        use std::time::{Duration, Instant};

        let name = format!(
            "bq-{}",
            random_bytes().unwrap()[0..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let directory = std::env::temp_dir().join(name);
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("s");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        let listener = {
            let _entered = runtime.enter();
            let listener = tokio::net::UnixSocket::new_stream().unwrap();
            listener.bind(&socket).unwrap();
            listener.listen(1).unwrap()
        };
        let mut queued = Vec::new();
        let mut full = false;
        for _ in 0..8192 {
            // Only kernel EAGAIN proves a full backlog. A short expired
            // deadline under parallel test load is not queue readiness.
            let connected = runtime.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(1),
                    tokio::net::UnixStream::connect(&socket),
                )
                .await
                .expect("fixture connection timed out before queue state was established")
            });
            match connected {
                Ok(stream) => queued.push(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    full = true;
                    break;
                }
                Err(error) => panic!("fixture connect failed before proving full queue: {error}"),
            }
        }
        let started = Instant::now();
        let result = connect_unix(&socket, started + Duration::from_millis(50));
        drop(queued);
        drop(listener);
        std::fs::remove_dir_all(directory).unwrap();
        assert!(full, "fixture did not fill the listen queue");
        assert!(
            result.is_err(),
            "an unaccepted full queue admitted a connection"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A Node process that renames itself (`process.title`, as ZCode's CLI
    /// does) shifts its first environment entries into the reported
    /// arguments: the plain environment read misses `HOME`, the shifted read
    /// finds the exact value, and an absent name stays absent. Needs an
    /// explicitly prepared `BRIDGE_TEST_NODE`; skipped without it.
    #[test]
    fn retitled_process_environment_is_still_found() {
        let Some(node) = std::env::var_os("BRIDGE_TEST_NODE") else {
            eprintln!("skipped: BRIDGE_TEST_NODE is not set");
            return;
        };
        let mut child = std::process::Command::new(node)
            .args([
                "-e",
                "process.title = 't'; console.log('ready'); setTimeout(() => {}, 20000)",
                "padding-one",
                "padding-two",
            ])
            .env_clear()
            .env("HOME", "/retitled/home")
            .env("SECOND", "2")
            .env("THIRD", "3")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let pid = child.id();
        let plain = process_env(pid, "HOME");
        let shifted = process_env_shifted(pid, "HOME");
        let absent = process_env_shifted(pid, "NOT_THERE");
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(line.trim(), "ready");
        #[cfg(target_os = "macos")]
        assert_eq!(
            plain, None,
            "the rewrite shifted HOME out of the environment"
        );
        #[cfg(not(target_os = "macos"))]
        assert!(plain.is_none() || plain.as_deref() == Some(OsStr::new("/retitled/home")));
        assert_eq!(shifted.as_deref(), Some(OsStr::new("/retitled/home")));
        assert_eq!(absent, None);
    }

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

    /// Checked lookup reads this process's own environment: a present variable
    /// is returned and an absent one is positive absence, not unknown.
    #[test]
    fn checked_env_reports_present_and_absent() {
        let pid = std::process::id();
        assert!(process_env_checked(pid, "PATH").unwrap().is_some());
        assert!(
            process_env_checked(pid, "BRIDGE_OS_TEST_UNSET")
                .unwrap()
                .is_none()
        );
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
