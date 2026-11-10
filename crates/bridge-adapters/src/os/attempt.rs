//! Linux kernel incarnation and original exec-environment capture.
//!
//! These observations are correlation facts, never authorization. A caller must
//! still prove ancestry, actor, audience, and the Run-owned attempt binding.

use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A same-namespace process identity as observed from Linux procfs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelIncarnation {
    /// Linux boot UUID.
    pub boot_id: String,
    /// Inode of the process's PID namespace.
    pub pid_namespace_inode: u64,
    /// Effective user ID from procfs.
    pub uid: u32,
    /// Process ID in the observer's PID namespace.
    pub pid: u32,
    /// Kernel start time in clock ticks since boot.
    pub start_ticks: u64,
}

/// Original launch identity and the kernel incarnation observed around the read.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchObservation {
    /// Full process identity, equal before and after the environment read.
    pub incarnation: KernelIncarnation,
    /// Canonical launch UUID from the process's own exec environment.
    pub launch_id: String,
}

/// Validates each captured ancestry edge and monotonic kernel birth ticks.
#[cfg(target_os = "linux")]
pub(crate) fn ordered_managed_ancestry(chain: &[super::ProcessFacts], owner: u32) -> bool {
    !chain.is_empty()
        && chain.windows(2).all(|pair| {
            let (Some(child), Some(parent)) =
                (&pair[0].kernel_incarnation, &pair[1].kernel_incarnation)
            else {
                return false;
            };
            pair[0].parent == Some(parent.pid)
                && child.uid == owner
                && parent.uid == owner
                && child.boot_id == parent.boot_id
                && child.pid_namespace_inode == parent.pid_namespace_inode
                && parent.start_ticks <= child.start_ticks
        })
}

impl std::fmt::Debug for LaunchObservation {
    /// Do not accidentally print environment-derived data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchObservation")
            .field("incarnation", &self.incarnation)
            .field("launch_id", &"<redacted>")
            .finish()
    }
}

/// Maximum procfs bytes inspected for a single environment; oversize refuses.
const MAX_ENV_BYTES: u64 = 1024 * 1024;
/// The only launch environment entry read by this module.
const LAUNCH_NAME: &[u8] = b"AGENT_RUN_LAUNCH_ID=";
/// Only the independent v2 owner locator is inspected for managed egress.
#[cfg(target_os = "linux")]
const OWNER_V2_NAME: &[u8] = b"BRIDGE_NATIVE_OWNER_SOCKET_V2=";

/// Maximum complete process ancestry accepted for a detached managed consumer.
/// Reaching the bound before namespace init is uncertainty, not absence.
#[cfg(target_os = "linux")]
const MAX_ROLE_ANCESTRY: usize = 128;

/// Kernel-reported parent edge and birth information, including foreign-UID
/// ancestors whose executable and PID namespace may not be readable.
#[cfg(target_os = "linux")]
#[derive(Clone, PartialEq, Eq)]
struct RoleLink {
    /// PID in Bridge's visible PID namespace.
    pid: u32,
    /// Kernel-reported parent PID, zero only at namespace init.
    parent: u32,
    /// Effective UID from the kernel status record.
    uid: u32,
    /// Birth tick from the kernel stat record.
    start_ticks: u64,
}

/// Reads one role ancestry edge without requiring access to a foreign UID's exe.
#[cfg(target_os = "linux")]
fn role_link_at(proc_root: &Path, pid: u32) -> io::Result<RoleLink> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "process ancestry unavailable");
    if pid == 0 {
        return Err(invalid());
    }
    let process = proc_root.join(pid.to_string());
    let status = bounded(&process.join("status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status).map_err(|_| invalid())?;
    let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let values = uid_lines
        .next()
        .ok_or_else(invalid)?
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if values.len() != 4 || uid_lines.next().is_some() {
        return Err(invalid());
    }
    let stat = bounded(&process.join("stat"), 64 * 1024)?;
    let end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(invalid)?;
    let open = stat[..end]
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or_else(invalid)?;
    if std::str::from_utf8(&stat[..open])
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
        != Some(pid)
    {
        return Err(invalid());
    }
    let fields: Vec<_> = stat[end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    let number = |index: usize| {
        fields
            .get(index)
            .and_then(|field| std::str::from_utf8(field).ok())
            .and_then(|field| field.parse::<u64>().ok())
            .ok_or_else(invalid)
    };
    let parent = u32::try_from(number(1)?).map_err(|_| invalid())?;
    let start_ticks = number(19)?;
    if parent == pid {
        return Err(invalid());
    }
    Ok(RoleLink {
        pid,
        parent,
        uid: values[1],
        start_ticks,
    })
}

/// Reads only whether the managed launch entry was present in the original
/// exec environment. An unreadable, truncated or empty environment is unknown.
#[cfg(target_os = "linux")]
fn launch_marker_at(proc_root: &Path, identity: &KernelIncarnation) -> io::Result<bool> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "process role unavailable");
    if incarnation_at(proc_root, identity.pid, identity.uid)? != *identity {
        return Err(invalid());
    }
    let bytes = bounded(
        &proc_root.join(identity.pid.to_string()).join("environ"),
        MAX_ENV_BYTES,
    )?;
    if bytes.is_empty() || bytes.last() != Some(&0) {
        return Err(invalid());
    }
    let present = bytes
        .split(|byte| *byte == 0)
        .any(|entry| entry.starts_with(LAUNCH_NAME));
    if incarnation_at(proc_root, identity.pid, identity.uid)? != *identity {
        return Err(invalid());
    }
    Ok(present)
}

/// Proves a same-UID consumer is outside every known managed harness/frontend
/// and has no managed-launch marker in any same-UID ancestor. Every parent edge
/// is re-read through namespace init; unreadable, changed, cyclic or overlong
/// chains refuse instead of being treated as detached.
#[cfg(target_os = "linux")]
pub(crate) fn detached_consumer(
    peer: &KernelIncarnation,
    excluded: &[KernelIncarnation],
) -> io::Result<bool> {
    detached_consumer_at(Path::new("/proc"), peer, excluded, || {})
}

/// Shared implementation with a synthetic reparent/identity-race seam.
#[cfg(target_os = "linux")]
fn detached_consumer_at(
    proc_root: &Path,
    peer: &KernelIncarnation,
    excluded: &[KernelIncarnation],
    between: impl FnOnce(),
) -> io::Result<bool> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "process ancestry unavailable");
    let mut chain = Vec::new();
    let mut next = peer.pid;
    while next != 0 {
        if chain.len() >= MAX_ROLE_ANCESTRY
            || chain
                .iter()
                .any(|(link, _): &(RoleLink, Option<KernelIncarnation>)| link.pid == next)
        {
            return Err(invalid());
        }
        let link = role_link_at(proc_root, next)?;
        let identity = if link.uid == peer.uid {
            let identity = incarnation_at(proc_root, link.pid, peer.uid)?;
            if identity.start_ticks != link.start_ticks
                || identity.boot_id != peer.boot_id
                || identity.pid_namespace_inode != peer.pid_namespace_inode
            {
                return Err(invalid());
            }
            if excluded.contains(&identity) || launch_marker_at(proc_root, &identity)? {
                return Ok(false);
            }
            Some(identity)
        } else {
            None
        };
        if let Some((child, _)) = chain.last()
            && link.start_ticks > child.start_ticks
        {
            return Err(invalid());
        }
        next = link.parent;
        chain.push((link, identity));
    }
    if chain.first().and_then(|(_, identity)| identity.as_ref()) != Some(peer)
        || chain.last().is_none_or(|(link, _)| link.pid != 1)
    {
        return Err(invalid());
    }
    between();
    for (link, identity) in &chain {
        if role_link_at(proc_root, link.pid)? != *link {
            return Err(invalid());
        }
        if let Some(identity) = identity
            && (incarnation_at(proc_root, identity.pid, identity.uid)? != *identity
                || launch_marker_at(proc_root, identity)?)
        {
            return Err(invalid());
        }
    }
    Ok(true)
}

/// Reads the exact live executable path and inode between equal process
/// incarnations, without trusting arguments or a configured label.
#[cfg(target_os = "linux")]
pub(crate) fn live_executable(
    identity: &KernelIncarnation,
) -> io::Result<(std::path::PathBuf, u64, u64)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "process executable unavailable");
    if kernel_incarnation(identity.pid, identity.uid)? != *identity {
        return Err(invalid());
    }
    let path = Path::new("/proc")
        .join(identity.pid.to_string())
        .join("exe");
    let executable = std::fs::read_link(&path)?;
    let metadata = std::fs::metadata(&path)?;
    if !metadata.is_file()
        || std::fs::read_link(&path)? != executable
        || kernel_incarnation(identity.pid, identity.uid)? != *identity
    {
        return Err(invalid());
    }
    Ok((executable, metadata.dev(), metadata.ino()))
}

/// Kernel start tick of a thread created before connecting to a managed peer.
/// Equal-tick PID reuse still requires the documented pidfd hardening.
#[cfg(target_os = "linux")]
pub(crate) fn sample_start_ticks() -> io::Result<u64> {
    std::thread::Builder::new()
        .spawn(|| {
            let stat = std::fs::read_to_string("/proc/thread-self/stat")?;
            stat.rsplit_once(')')
                .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| io::Error::other("kernel tick sample unavailable"))
        })?
        .join()
        .map_err(|_| io::Error::other("kernel tick sample unavailable"))?
}

/// Checks the inode column of a synthetic or kernel Unix-socket table.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unix_table_contains(bytes: &[u8], inode: u64) -> bool {
    std::str::from_utf8(bytes).ok().is_some_and(|table| {
        table.lines().skip(1).any(|line| {
            line.split_ascii_whitespace()
                .nth(6)
                .and_then(|value| value.parse::<u64>().ok())
                == Some(inode)
        })
    })
}

/// Verifies one stdio descriptor is a pipe or a socket in the kernel Unix table.
/// Missing or changed descriptors and unreadable socket tables refuse.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn managed_stdio(pid: u32, fd: u8) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let path = format!("/proc/{pid}/fd/{fd}");
    let Ok(before) = std::fs::metadata(&path) else {
        return false;
    };
    let qualified = if before.file_type().is_fifo() {
        true
    } else if before.file_type().is_socket() {
        bounded(Path::new("/proc/net/unix"), 16 * 1024 * 1024)
            .is_ok_and(|bytes| unix_table_contains(&bytes, before.ino()))
    } else {
        false
    };
    qualified
        && std::fs::metadata(&path).is_ok_and(|after| {
            (before.dev(), before.ino(), before.mode()) == (after.dev(), after.ino(), after.mode())
        })
}

/// Checks canonical lowercase UUID spelling without accepting aliases.
pub(crate) fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// Reads a bounded procfs file, refusing truncation and unreadable entries.
fn bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proc entry too large",
        ));
    }
    Ok(bytes)
}

/// Reads one kernel identity from a procfs tree, requiring the local namespace.
fn incarnation_at(proc_root: &Path, pid: u32, expected_uid: u32) -> io::Result<KernelIncarnation> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "kernel identity unavailable");
    if pid == 0 {
        return Err(invalid());
    }
    let boot_bytes = bounded(&proc_root.join("sys/kernel/random/boot_id"), 64)?;
    let boot = std::str::from_utf8(&boot_bytes)
        .map_err(|_| invalid())?
        .trim_end_matches('\n');
    if !canonical_uuid(boot) {
        return Err(invalid());
    }
    let process = proc_root.join(pid.to_string());
    let local_ns = std::fs::metadata(proc_root.join("self/ns/pid"))?.ino();
    let target_ns = std::fs::metadata(process.join("ns/pid"))?.ino();
    if target_ns == 0 || target_ns != local_ns {
        return Err(invalid());
    }
    let status_bytes = bounded(&process.join("status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status_bytes).map_err(|_| invalid())?;
    let mut uid_lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let uid_line = uid_lines.next().ok_or_else(invalid)?;
    if uid_lines.next().is_some() {
        return Err(invalid());
    }
    let uids: Vec<u32> = uid_line
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    if uids.len() != 4 || uids[1] != expected_uid {
        return Err(invalid());
    }
    let stat = bounded(&process.join("stat"), 64 * 1024)?;
    let end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(invalid)?;
    let open = stat[..end]
        .iter()
        .position(|byte| *byte == b'(')
        .ok_or_else(invalid)?;
    let stat_pid = std::str::from_utf8(&stat[..open])
        .map_err(|_| invalid())?
        .trim();
    if stat_pid.parse::<u32>().ok() != Some(pid) {
        return Err(invalid());
    }
    // Comm is arbitrary bytes; field 3 follows its final ')', field 22 is index 19.
    let ticks = stat[end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .nth(19)
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|field| field.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(invalid)?;
    Ok(KernelIncarnation {
        boot_id: boot.to_string(),
        pid_namespace_inode: target_ns,
        uid: uids[1],
        pid,
        start_ticks: ticks,
    })
}

/// Reads a same-namespace Linux process incarnation; errors mean unknown, not dead.
pub fn kernel_incarnation(pid: u32, expected_uid: u32) -> io::Result<KernelIncarnation> {
    incarnation_at(Path::new("/proc"), pid, expected_uid)
}

/// Extracts exactly one launch value from the exec environment, rejecting duplicates.
fn launch_from_environment(bytes: &[u8]) -> io::Result<String> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "launch environment unavailable");
    if bytes.is_empty() || bytes.last() != Some(&0) {
        return Err(invalid());
    }
    let mut values = bytes
        .split(|b| *b == 0)
        .filter_map(|entry| entry.strip_prefix(LAUNCH_NAME));
    let value = values.next().ok_or_else(invalid)?;
    if values.next().is_some() {
        return Err(invalid());
    }
    let value = std::str::from_utf8(value).map_err(|_| invalid())?;
    if !canonical_uuid(value) {
        return Err(invalid());
    }
    Ok(value.to_string())
}

/// Captures the launch directly from `/proc/<pid>/environ` between identity reads.
///
/// The observer must compare the returned incarnation with the one captured
/// while matching the original harness ancestor; callers must never substitute
/// arguments, a shifted environment, or a later capture for a failed hook read.
pub fn capture_launch(pid: u32, expected_uid: u32) -> io::Result<LaunchObservation> {
    capture_at(Path::new("/proc"), pid, expected_uid, || {})
}

/// Reads only the v2 owner locator directly from the exact process's exec
/// environment, bracketed by equal full kernel identities. Missing is `None`;
/// malformed, duplicated, unreadable or changed data is an error. This never
/// falls back to argv, the v1 locator, or a later process with a reused PID.
#[cfg(target_os = "linux")]
pub(crate) fn owner_v2_locator(expected: &KernelIncarnation) -> io::Result<Option<String>> {
    owner_v2_locator_at(Path::new("/proc"), expected, || {})
}

/// Implements the v2 locator read with a synthetic identity-race seam.
#[cfg(target_os = "linux")]
fn owner_v2_locator_at(
    proc_root: &Path,
    expected: &KernelIncarnation,
    between: impl FnOnce(),
) -> io::Result<Option<String>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "owner v2 locator unavailable");
    if incarnation_at(proc_root, expected.pid, expected.uid)? != *expected {
        return Err(invalid());
    }
    let environment = bounded(
        &proc_root.join(expected.pid.to_string()).join("environ"),
        MAX_ENV_BYTES,
    )?;
    if environment.is_empty() || environment.last() != Some(&0) {
        return Err(invalid());
    }
    let mut values = environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(OWNER_V2_NAME));
    let result = match (values.next(), values.next()) {
        (None, None) => None,
        (Some(value), None) => {
            let value = std::str::from_utf8(value).map_err(|_| invalid())?;
            if value.is_empty() {
                return Err(invalid());
            }
            Some(value.to_string())
        }
        _ => return Err(invalid()),
    };
    between();
    if incarnation_at(proc_root, expected.pid, expected.uid)? != *expected {
        return Err(invalid());
    }
    Ok(result)
}

/// Establishes that a PID is absent from a readable, non-hidepid procfs view.
/// Unreadable mount information or hidden PID policy is never proof of absence.
pub(crate) fn definitely_gone(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let proc_mounts: Vec<_> = mounts
        .lines()
        .filter(|line| {
            let Some((pre, post)) = line.split_once(" - ") else {
                return false;
            };
            pre.split_ascii_whitespace().nth(4) == Some("/proc")
                && post.split_ascii_whitespace().next() == Some("proc")
        })
        .collect();
    if proc_mounts.is_empty()
        || proc_mounts.iter().any(|line| {
            line.split([',', ' '])
                .any(|option| option.starts_with("hidepid=") && option != "hidepid=0")
        })
    {
        return false;
    }
    let missing = || {
        std::fs::metadata(format!("/proc/{pid}"))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
    };
    if !missing() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    let mut saw_self = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == std::process::id().to_string() {
            saw_self = true;
        }
        if name.parse::<u32>().ok() == Some(pid) {
            return false;
        }
    }
    saw_self && missing()
}

/// Capture implementation with an observation seam for synthetic race tests.
fn capture_at(
    proc_root: &Path,
    pid: u32,
    expected_uid: u32,
    between: impl FnOnce(),
) -> io::Result<LaunchObservation> {
    let before = incarnation_at(proc_root, pid, expected_uid)?;
    let environment = bounded(
        &proc_root.join(pid.to_string()).join("environ"),
        MAX_ENV_BYTES,
    )?;
    let launch_id = launch_from_environment(&environment)?;
    between();
    let after = incarnation_at(proc_root, pid, expected_uid)?;
    if before != after {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel incarnation changed",
        ));
    }
    Ok(LaunchObservation {
        incarnation: before,
        launch_id,
    })
}

#[cfg(test)]
mod tests {
    //! Pure synthetic procfs fixtures: no real sessions or provider processes.
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique test directory selector.
    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Only the Unix-table inode field qualifies a socket descriptor.
    #[test]
    fn unix_socket_table_requires_exact_inode() {
        let table = b"Num RefCount Protocol Flags Type St Inode Path\n0000: 00000002 00000000 00000000 0001 03 1234 /fixture\n";
        assert!(unix_table_contains(table, 1234));
        assert!(!unix_table_contains(table, 123));
        assert!(!unix_table_contains(b"invalid\xff", 1234));
    }

    /// A device descriptor cannot qualify as a stdio transport. A parallel test
    /// may hold thousands of sockets for a moment, so the descriptor is
    /// reopened (bounded) until its number fits the `u8` the check takes.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_stdio_device_is_refused() {
        use std::os::fd::AsRawFd;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let (file, fd) = loop {
            let file = std::fs::File::open("/dev/null").unwrap();
            if let Ok(fd) = u8::try_from(file.as_raw_fd()) {
                break (file, fd);
            }
            assert!(std::time::Instant::now() < deadline, "no small descriptor");
            drop(file);
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(!managed_stdio(std::process::id(), fd));
        drop(file);
    }

    /// A parent born after its claimed child cannot establish managed ancestry.
    #[cfg(target_os = "linux")]
    #[test]
    fn ancestry_parent_start_ticks_are_ordered() {
        let fact = |pid, parent, ticks| super::super::ProcessFacts {
            pid,
            parent,
            start_time: 1,
            start_ticks: Some(ticks),
            kernel_incarnation: Some(KernelIncarnation {
                boot_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
                pid_namespace_inode: 7,
                uid: 1000,
                pid,
                start_ticks: ticks,
            }),
            exe: None,
            uid: Some(1000),
        };
        assert!(ordered_managed_ancestry(
            &[fact(2, Some(1), 20), fact(1, None, 10)],
            1000
        ));
        assert!(!ordered_managed_ancestry(
            &[fact(2, Some(1), 10), fact(1, None, 20)],
            1000
        ));
    }

    /// V2 locator discovery never substitutes the v1 name, tolerates no
    /// duplicates, and refuses an identity change around the environment read.
    #[cfg(target_os = "linux")]
    #[test]
    fn v2_locator_is_exact_and_bracketed() {
        let fixture = ProcFixture::new();
        let identity = incarnation_at(&fixture.0, 42, 1000).unwrap();
        fixture.environment(b"BRIDGE_NATIVE_OWNER_SOCKET=/old.sock\0");
        assert_eq!(
            owner_v2_locator_at(&fixture.0, &identity, || {}).unwrap(),
            None
        );
        fixture.environment(b"BRIDGE_NATIVE_OWNER_SOCKET_V2=/v2.sock\0");
        assert_eq!(
            owner_v2_locator_at(&fixture.0, &identity, || {})
                .unwrap()
                .as_deref(),
            Some("/v2.sock")
        );
        fixture
            .environment(b"BRIDGE_NATIVE_OWNER_SOCKET_V2=/a\0BRIDGE_NATIVE_OWNER_SOCKET_V2=/b\0");
        assert!(owner_v2_locator_at(&fixture.0, &identity, || {}).is_err());
        fixture.environment(b"BRIDGE_NATIVE_OWNER_SOCKET_V2=/v2.sock\0");
        assert!(
            owner_v2_locator_at(&fixture.0, &identity, || ProcFixture::stat(&fixture.0, 124))
                .is_err()
        );
    }
    /// Fixture tree, removed on drop.
    struct ProcFixture(std::path::PathBuf);
    impl ProcFixture {
        /// Creates a synthetic process with a same-namespace identity.
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ab-proc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("sys/kernel/random")).unwrap();
            std::fs::create_dir_all(path.join("self/ns")).unwrap();
            std::fs::create_dir_all(path.join("42/ns")).unwrap();
            std::fs::write(
                path.join("sys/kernel/random/boot_id"),
                "01234567-89ab-cdef-0123-456789abcdef\n",
            )
            .unwrap();
            std::fs::write(path.join("self/ns/pid"), "namespace").unwrap();
            std::fs::hard_link(path.join("self/ns/pid"), path.join("42/ns/pid")).unwrap();
            std::fs::write(
                path.join("42/status"),
                "Name:\ttest\nUid:\t1000\t1000\t1000\t1000\n",
            )
            .unwrap();
            Self::stat(&path, 123);
            Self(path)
        }
        /// Writes a stat record with a possibly changing start tick.
        fn stat(root: &Path, ticks: u64) {
            std::fs::write(
                root.join("42/stat"),
                format!(
                    "42 (name with ) parentheses) S {} {ticks} 0\n",
                    vec!["1"; 18].join(" ")
                ),
            )
            .unwrap();
        }
        /// Replaces the environment with synthetic bytes.
        fn environment(&self, bytes: &[u8]) {
            std::fs::write(self.0.join("42/environ"), bytes).unwrap();
        }
        /// Runs capture against the synthetic proc tree.
        fn capture(&self) -> io::Result<LaunchObservation> {
            capture_at(&self.0, 42, 1000, || {})
        }
    }
    impl Drop for ProcFixture {
        /// Removes only the owned fixture tree.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Direct environment is mandatory; duplicates and shifted/argv-only values refuse.
    #[test]
    fn launch_env_direct_checked() {
        let p = ProcFixture::new();
        let launch = b"AGENT_RUN_LAUNCH_ID=01234567-89ab-cdef-0123-456789abcdef\0";
        p.environment(launch);
        let found = p.capture().unwrap();
        assert_eq!(found.incarnation.start_ticks, 123);
        assert_eq!(found.launch_id, "01234567-89ab-cdef-0123-456789abcdef");
        p.environment(b"OTHER=value\0");
        std::fs::write(p.0.join("42/cmdline"), launch).unwrap();
        assert!(p.capture().is_err());
        p.environment(&[launch.as_slice(), launch.as_slice()].concat());
        assert!(p.capture().is_err());
        p.environment(b"AGENT_RUN_LAUNCH_ID=bad\0");
        assert!(p.capture().is_err());
        std::fs::remove_file(p.0.join("42/environ")).unwrap();
        assert!(p.capture().is_err());
    }

    /// Detached role proof requires the complete stable chain and refuses a
    /// known frontend or a managed-launch marker, even with no live binding.
    #[cfg(target_os = "linux")]
    #[test]
    fn detached_role_requires_complete_stable_ancestry() {
        let p = ProcFixture::new();
        std::fs::create_dir_all(p.0.join("1")).unwrap();
        std::fs::write(p.0.join("1/status"), "Name:\tinit\nUid:\t0\t0\t0\t0\n").unwrap();
        std::fs::write(
            p.0.join("1/stat"),
            format!("1 (init) S 0 {} 10 0\n", vec!["0"; 17].join(" ")),
        )
        .unwrap();
        p.environment(b"OTHER=value\0");
        let peer = incarnation_at(&p.0, 42, 1000).unwrap();
        assert!(detached_consumer_at(&p.0, &peer, &[], || {}).unwrap());
        assert!(!detached_consumer_at(&p.0, &peer, std::slice::from_ref(&peer), || {}).unwrap());
        p.environment(b"AGENT_RUN_LAUNCH_ID=invalid-still-refuses\0");
        assert!(!detached_consumer_at(&p.0, &peer, &[], || {}).unwrap());
        p.environment(b"OTHER=value\0");
        assert!(detached_consumer_at(&p.0, &peer, &[], || ProcFixture::stat(&p.0, 124)).is_err());
        ProcFixture::stat(&p.0, 123);
        std::fs::remove_file(p.0.join("1/status")).unwrap();
        assert!(detached_consumer_at(&p.0, &peer, &[], || {}).is_err());
    }

    /// Namespace, UID and start-tick changes cannot preserve process identity.
    #[test]
    fn foreign_actor_process_uid_and_stale_incarnation() {
        let p = ProcFixture::new();
        p.environment(b"AGENT_RUN_LAUNCH_ID=01234567-89ab-cdef-0123-456789abcdef\0");
        assert!(capture_at(&p.0, 42, 999, || {}).is_err());
        assert!(capture_at(&p.0, 42, 1000, || ProcFixture::stat(&p.0, 124)).is_err());
        std::fs::remove_file(p.0.join("42/ns/pid")).unwrap();
        std::fs::write(p.0.join("42/ns/pid"), "other").unwrap();
        assert!(p.capture().is_err());
    }
}
