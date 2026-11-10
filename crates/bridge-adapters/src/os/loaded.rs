//! Loaded-build evidence of a running executable.
//!
//! Whether the file at a path is the build a process runs is not answered by
//! comparing file times with a wall-clock estimate of the process start: any step
//! of the wall clock between the start and the check moves such an estimate and
//! lets a later change look older than the process. Instead the kernel's own
//! objects are compared, all through one descriptor opened on `/proc/<pid>/exe`,
//! which is the very file the process mapped when it ran `exec`:
//!
//! * The descriptor's device, inode, length and nanosecond mtime and ctime must
//!   equal those the configured path resolves to, so a file replaced by rename
//!   (new inode) or deleted never matches.
//! * Everything else is judged on the descriptor, never by resolving the path a
//!   second time: its owner and mode, and the digest, which the caller looks up
//!   by the descriptor's exact identity (a digest hashed from another inode, or
//!   from this inode before a write moved its ctime, has another key). A swap of
//!   the path or of one of its parent directories between two resolutions
//!   therefore cannot pair the loaded file with the evidence of another file.
//! * On a filesystem where the kernel denies opening a running executable for
//!   writing (`ETXTBSY`: ext2/3/4, xfs, btrfs, tmpfs) the content of that inode
//!   cannot have changed since the process loaded it, so a digest of the inode
//!   is a digest of the loaded build whatever its timestamps say. The filesystem
//!   is that of the descriptor's own mount: its `mnt_id` (from
//!   `/proc/self/fdinfo/<fd>`) names exactly one record of Bridge's
//!   `/proc/self/mountinfo`. A device number is not enough: a non-directory on an
//!   overlay reports the device of its backing filesystem. Any other filesystem
//!   (overlay, network, FUSE, unknown), a missing `mnt_id`, and a mount without
//!   exactly one record (a mount of another mount namespace or a detached mount;
//!   mount IDs are unique system-wide) fail closed: there the kernel makes no
//!   such promise, or Bridge cannot see which filesystem it is.
//! * The process incarnation (`pid`, start tick) is read before and after the
//!   whole proof, the caller's digest and mode checks included, so a recycled
//!   PID is never judged by another process's executable.
//!
//! No `unsafe` and no `statfs` is needed. Linux is the only platform with this
//! evidence. Elsewhere the proof that managed attempt-binding routes require
//! (`Route::Managed`) fails closed; ordinary harness, owner, relay and audience
//! routes (`Route::Ordinary`) keep the earlier whole-second comparison of the
//! file times with the process start, a documented non-Linux residual.

use std::path::Path;

use super::ProcessFacts;

/// Which routes an executable proof serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// Ordinary native harness, owner v1, Desktop hop, relay and audience routes.
    Ordinary,
    /// Managed attempt-binding routes (managed frontends, harnesses, Run readers
    /// and the owner-v2 Run server). Linux only; refused elsewhere.
    Managed,
}

/// Filesystem type names (the field after the `-` separator of `mountinfo`, the
/// same filesystems the listed `statfs` magic numbers identify) on which the kernel denies opening a
/// running executable for writing.
#[cfg(target_os = "linux")]
const WRITE_DENYING: [(&str, u64); 6] = [
    ("ext2", 0xEF53),
    ("ext3", 0xEF53),
    ("ext4", 0xEF53),
    ("xfs", 0x5846_5342),
    ("btrfs", 0x9123_683E),
    ("tmpfs", 0x0102_1994),
];

/// Whether the filesystem type named `fstype` denies writes to a running
/// executable.
#[cfg(target_os = "linux")]
fn denies_running_writes(fstype: &str) -> bool {
    WRITE_DENYING.iter().any(|(name, _)| *name == fstype)
}

/// The mount ID of an open descriptor from its `fdinfo` text: exactly one
/// `mnt_id:` line with a decimal value, else `None`.
#[cfg(target_os = "linux")]
fn fdinfo_mount_id(fdinfo: &str) -> Option<u64> {
    let mut ids = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    let id = ids.next()?.trim().parse::<u64>().ok()?;
    ids.next().is_none().then_some(id)
}

/// The filesystem type of the mount `id` in `mountinfo`, when exactly one
/// well-formed record has that ID.
///
/// Fields before the `-` separator are `id parent major:minor root mountpoint
/// options [optional...]`; after it `fstype source superoptions`. Spaces inside
/// paths are escaped (`\040`) by the kernel, so fields split on single spaces.
#[cfg(target_os = "linux")]
fn mount_type(mountinfo: &str, id: u64) -> Option<&str> {
    let wanted = id.to_string();
    let mut records = mountinfo
        .lines()
        .filter(|line| line.split(' ').next() == Some(wanted.as_str()));
    let record = records.next()?;
    if records.next().is_some() {
        return None;
    }
    let fields: Vec<&str> = record.split(' ').collect();
    let dash = fields.iter().position(|field| *field == "-")?;
    (dash >= 6)
        .then(|| fields.get(dash + 1).copied())
        .flatten()
        .filter(|fstype| !fstype.is_empty())
}

/// Whether the descriptor with `fdinfo` lies on a write-denying filesystem
/// according to `mountinfo`: its single `mnt_id` has exactly one record whose
/// type is allowlisted.
#[cfg(target_os = "linux")]
fn mount_denies_running_writes(fdinfo: &str, mountinfo: &str) -> bool {
    fdinfo_mount_id(fdinfo)
        .and_then(|id| mount_type(mountinfo, id))
        .is_some_and(denies_running_writes)
}

/// The filesystem check of [`loaded_executable`] for the opened loaded file.
#[cfg(target_os = "linux")]
fn descriptor_denies_running_writes(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    #[cfg(test)]
    if let Some(fstype) = injected::get() {
        return denies_running_writes(&fstype);
    }
    let Ok(fdinfo) = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
    else {
        return false;
    };
    std::fs::read_to_string("/proc/self/mountinfo")
        .is_ok_and(|mountinfo| mount_denies_running_writes(&fdinfo, &mountinfo))
}

/// Test-only injection, per thread: the filesystem type of every executable, and
/// an action run at the boundary between the identity checks and the caller's
/// own checks (where a path could be swapped).
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod injected {
    use std::cell::RefCell;

    thread_local! {
        static FSTYPE: RefCell<Option<String>> = const { RefCell::new(None) };
        static BOUNDARY: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Makes this thread's executable proofs see filesystem type `fstype`.
    pub(crate) fn set(fstype: Option<&str>) {
        FSTYPE.with(|cell| *cell.borrow_mut() = fstype.map(str::to_owned));
    }

    pub(super) fn get() -> Option<String> {
        FSTYPE.with(|cell| cell.borrow().clone())
    }

    /// Runs `action` once, inside this thread's next executable proof, after the
    /// loaded file and the path were compared and before the caller's checks.
    pub(crate) fn at_boundary(action: impl FnOnce() + 'static) {
        BOUNDARY.with(|cell| *cell.borrow_mut() = Some(Box::new(action)));
    }

    pub(super) fn boundary() {
        if let Some(action) = BOUNDARY.with(|cell| cell.borrow_mut().take()) {
            action();
        }
    }
}

/// The exact identity of an opened or resolved file: device, inode, length,
/// and nanosecond mtime and ctime.
#[cfg(target_os = "linux")]
fn identity(meta: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    )
}

/// Proves that the file `exe` is the executable `facts` is running, and returns
/// the metadata of that loaded file, read from its descriptor, for the caller's
/// owner and mode checks. An ordinary-route proof (`Route::Ordinary`, see
/// `prove_loaded`): on Linux the descriptor-based proof of the module
/// documentation; elsewhere the earlier whole-second comparison of the file
/// times with the process start, a documented residual.
///
/// # Errors
///
/// The reason the loaded build is unproven (a static text, never the path).
pub fn loaded_executable(
    facts: &ProcessFacts,
    exe: &Path,
) -> Result<std::fs::Metadata, &'static str> {
    prove_loaded(Route::Ordinary, facts, exe, |_| Ok(())).map(|(loaded, ())| loaded)
}

/// Proves that the file `exe` is the executable `facts` is running and runs the
/// caller's own checks of that loaded file (`also`, given the metadata read from
/// the opened `/proc/<pid>/exe` descriptor, for example the digest lookup by its
/// exact identity) inside the proof, so the closing incarnation check covers
/// them as well.
///
/// On Linux, for either route: the process incarnation is unchanged before and
/// after; the descriptor opened on `/proc/<pid>/exe` has exactly the identity
/// (device, inode, length, mtime, ctime) `exe` resolves to; its own mount is a
/// filesystem on which the running image cannot be written (see the module
/// documentation); and after `also` the descriptor's identity and
/// `/proc/<pid>/exe` are unchanged. No wall clock is consulted.
///
/// Elsewhere [`Route::Managed`] is refused, and [`Route::Ordinary`] keeps the
/// earlier whole-second comparison of the file times at `exe` with the start
/// second (a documented non-Linux residual: a wall-clock step can move it).
///
/// # Errors
///
/// The reason the loaded build is unproven, or `also`'s refusal (a static text,
/// never the path).
#[cfg(target_os = "linux")]
pub(crate) fn prove_loaded<T>(
    route: Route,
    facts: &ProcessFacts,
    exe: &Path,
    also: impl FnOnce(&std::fs::Metadata) -> Result<T, &'static str>,
) -> Result<(std::fs::Metadata, T), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let _ = route;
    let ticks = facts
        .start_ticks
        .ok_or("process start tick unreadable; loaded executable unproven")?;
    let incarnation = || super::proc_start_ticks(facts.pid) == Some(ticks);
    if !incarnation() {
        return Err("process incarnation changed; loaded executable unproven");
    }
    let proc_exe = format!("/proc/{}/exe", facts.pid);
    let file = std::fs::File::open(&proc_exe).map_err(|_| "loaded executable is unreadable")?;
    let loaded = file
        .metadata()
        .map_err(|_| "loaded executable is unreadable")?;
    let named = std::fs::metadata(exe).map_err(|_| "executable is unreadable")?;
    if identity(&loaded) != identity(&named) {
        return Err("executable path is not the file the process loaded");
    }
    if !descriptor_denies_running_writes(&file) {
        return Err(
            "executable filesystem does not deny writes to a running executable; loaded build unproven",
        );
    }
    #[cfg(test)]
    injected::boundary();
    let proved = also(&loaded)?;
    let still = file
        .metadata()
        .map_err(|_| "loaded executable is unreadable")?;
    let mapped = std::fs::metadata(&proc_exe).map_err(|_| "loaded executable is unreadable")?;
    if identity(&still) != identity(&loaded)
        || (mapped.dev(), mapped.ino()) != (loaded.dev(), loaded.ino())
    {
        return Err("loaded executable changed during the proof");
    }
    if !incarnation() {
        return Err("process incarnation changed; loaded executable unproven");
    }
    Ok((loaded, proved))
}

/// See the Linux version: managed routes are refused here; ordinary routes keep
/// the whole-second comparison of the file times with the start second.
///
/// # Errors
///
/// The reason the loaded build is unproven, or `also`'s refusal (a static text,
/// never the path).
#[cfg(not(target_os = "linux"))]
pub(crate) fn prove_loaded<T>(
    route: Route,
    facts: &ProcessFacts,
    exe: &Path,
    also: impl FnOnce(&std::fs::Metadata) -> Result<T, &'static str>,
) -> Result<(std::fs::Metadata, T), &'static str> {
    use std::os::unix::fs::MetadataExt;
    if route == Route::Managed {
        return Err(
            "this platform has no immutable loaded-build evidence; managed executable proof refused",
        );
    }
    let meta = std::fs::metadata(exe).map_err(|_| "executable is unreadable")?;
    let changed = u64::try_from(meta.mtime().max(meta.ctime())).unwrap_or(u64::MAX);
    if changed >= facts.start_time {
        return Err("executable was written or changed at or after the process start");
    }
    let proved = also(&meta)?;
    Ok((meta, proved))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const MOUNTS: &str = "\
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
30 1 259:2 / / rw,relatime shared:1 - ext4 /dev/md2 rw
31 30 0:27 / /run rw,nosuid shared:2 - tmpfs tmpfs rw,mode=755
32 30 0:50 /sub /mnt\\040space rw - fuse.sshfs host:/ rw
33 30 0:51 / /ov rw - overlay overlay rw,lowerdir=/srv/lower,upperdir=/srv/up,workdir=/srv/w
34 30 259:2 /srv/lower/bin /bound rw,relatime shared:1 - ext4 /dev/md2 rw
35 30 259:2 /data /nfsish rw - nfs4 other rw
36 30 0:51 /bin/tool /tool rw - overlay overlay rw
37 30 259:2 / /short rw
38 30 259:2 / /empty rw -
";

    fn info(id: &str) -> String {
        format!("pos:\t0\nflags:\t0100000\nmnt_id:\t{id}\nino:\t42\n")
    }

    /// The allowlist names exactly the filesystems whose kernel denies writes to
    /// a running executable, and the mount is the descriptor's own record.
    #[test]
    fn mount_id_resolution_and_allowlist() {
        assert_eq!(fdinfo_mount_id(&info("30")), Some(30));
        assert_eq!(fdinfo_mount_id("pos:\t0\nflags:\t0\n"), None, "missing");
        assert_eq!(fdinfo_mount_id("mnt_id:\tx\n"), None, "malformed");
        assert_eq!(fdinfo_mount_id("mnt_id:\t30\nmnt_id:\t30\n"), None, "twice");
        assert_eq!(mount_type(MOUNTS, 30), Some("ext4"));
        assert_eq!(mount_type(MOUNTS, 32), Some("fuse.sshfs"));
        assert_eq!(mount_type(MOUNTS, 37), None, "no separator");
        assert_eq!(mount_type(MOUNTS, 38), None, "no type");
        assert_eq!(mount_type(MOUNTS, 99), None, "unlisted");
        let doubled = format!("{MOUNTS}30 1 259:2 / /again rw - ext4 /dev/md2 rw\n");
        assert_eq!(mount_type(&doubled, 30), None, "ambiguous record");

        let denies = |id: &str| mount_denies_running_writes(&info(id), MOUNTS);
        assert!(denies("30"), "ext4 root");
        assert!(denies("31"), "tmpfs");
        assert!(!denies("22"), "proc");
        assert!(!denies("32"), "fuse");
        assert!(!denies("33"), "overlay");
        // An overlay non-directory reports the backing device 259:2, which also
        // has the ext4 mounts 30 and 34; only the descriptor's own mount counts.
        assert!(!denies("36"), "bind of an overlay file");
        assert!(denies("34"), "bind mount of an ext4 subtree is that ext4");
        assert!(!denies("35"), "same device under another type");
        assert!(!denies("99"), "foreign namespace or detached: no record");
        assert!(
            !mount_denies_running_writes("flags:\t0\n", MOUNTS),
            "no mnt_id"
        );
        assert!(!mount_denies_running_writes(&info("30"), ""), "empty table");
        for name in ["ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"] {
            assert!(denies_running_writes(name), "{name}");
        }
        for name in ["overlay", "nfs", "fuse", "vfat", "9p", "ext", ""] {
            assert!(!denies_running_writes(name), "{name}");
        }
        let magic: Vec<u64> = WRITE_DENYING.iter().map(|(_, magic)| *magic).collect();
        assert!(magic.contains(&0x0102_1994) && magic.contains(&0x9123_683E));
    }

    /// The kernel really reports the mount of an opened scratch file, and that
    /// mount has exactly one record in this process's table.
    #[test]
    fn this_hosts_fdinfo_names_one_mount_record() {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let fdinfo =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).unwrap();
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let id = fdinfo_mount_id(&fdinfo).expect("mnt_id in fdinfo");
        assert!(mount_type(&mountinfo, id).is_some());
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod tests {
    use super::*;

    /// Without immutable loaded-build evidence a managed route never proves an
    /// executable, not even this test's own.
    #[test]
    fn managed_proof_fails_closed_off_linux() {
        let facts = super::super::process_facts(std::process::id()).unwrap();
        let exe = std::env::current_exe().unwrap();
        let refused = prove_loaded(Route::Managed, &facts, &exe, |_| Ok(())).unwrap_err();
        assert!(refused.contains("managed executable proof refused"));
    }
}
