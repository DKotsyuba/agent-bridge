//! Loaded-build evidence of a running executable.
//!
//! Whether the file at a path is the build a process runs is not answered by
//! comparing file times with a wall-clock estimate of the process start: any step
//! of the wall clock between the start and the check moves such an estimate and
//! lets a later change look older than the process. Instead the kernel's own
//! objects are compared:
//!
//! * `/proc/<pid>/exe` names the very inode the process mapped when it ran
//!   `exec`; its device and inode must equal those of the configured path, so a
//!   file replaced by rename (new inode) or deleted never matches.
//! * On a filesystem where the kernel denies opening a running executable for
//!   writing (`ETXTBSY`: ext2/3/4, xfs, btrfs, tmpfs) the content of that inode
//!   cannot have changed since the process loaded it, so a digest of the inode
//!   is a digest of the loaded build whatever its timestamps say. Any other
//!   filesystem (network, FUSE, overlay, unknown) fails closed: there the kernel
//!   makes no such promise and nothing else proves the content.
//! * The process incarnation (`pid`, start tick) is read before and after, so a
//!   recycled PID is never judged by another process's executable.
//!
//! The filesystem type is read from the kernel's `/proc/self/mountinfo` by the
//! device of the loaded inode (no `unsafe`, no `statfs`). Overlay filesystems are
//! not on the allowlist: a write through an overlay opens a file of another
//! filesystem, and the kernel's text-busy denial is not guaranteed for that
//! path across versions.

use std::path::Path;

use super::ProcessFacts;

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
pub(crate) fn denies_running_writes(fstype: &str) -> bool {
    WRITE_DENYING.iter().any(|(name, _)| *name == fstype)
}

/// The `(major, minor)` of a Linux `st_dev` (glibc `gnu_dev_major`/`minor`).
#[cfg(target_os = "linux")]
fn device_numbers(dev: u64) -> (u64, u64) {
    (
        ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff),
        (dev & 0xff) | ((dev >> 12) & !0xff),
    )
}

/// Every filesystem type `mountinfo` lists for the device `dev`.
///
/// Fields before the `-` separator are `id parent major:minor root mountpoint
/// options [optional...]`; after it `fstype source superoptions`. A line that
/// does not parse contributes nothing, so an unparsed mount can only make the
/// answer smaller (the caller refuses an empty answer).
#[cfg(target_os = "linux")]
pub(crate) fn mount_types(mountinfo: &str, dev: u64) -> Vec<&str> {
    let (major, minor) = device_numbers(dev);
    let wanted = format!("{major}:{minor}");
    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let dash = fields.iter().position(|field| *field == "-")?;
            (dash >= 6 && fields.get(2) == Some(&wanted.as_str()))
                .then(|| fields.get(dash + 1).copied())
                .flatten()
        })
        .collect()
}

/// Whether every mount of `dev` in `mountinfo` is a write-denying filesystem and
/// at least one mount is listed.
#[cfg(target_os = "linux")]
pub(crate) fn device_denies_running_writes(mountinfo: &str, dev: u64) -> bool {
    let types = mount_types(mountinfo, dev);
    !types.is_empty() && types.iter().all(|name| denies_running_writes(name))
}

/// The filesystem check of [`loaded_executable`] for the device of the loaded
/// inode.
#[cfg(target_os = "linux")]
fn filesystem_denies_running_writes(dev: u64) -> bool {
    #[cfg(test)]
    if let Some(fstype) = injected::get() {
        return denies_running_writes(&fstype);
    }
    std::fs::read_to_string("/proc/self/mountinfo")
        .is_ok_and(|mountinfo| device_denies_running_writes(&mountinfo, dev))
}

/// Test-only injection of the filesystem type of every executable, per thread.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod injected {
    use std::cell::RefCell;

    thread_local! {
        static FSTYPE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Makes this thread's executable proofs see filesystem type `fstype`.
    pub(crate) fn set(fstype: Option<&str>) {
        FSTYPE.with(|cell| *cell.borrow_mut() = fstype.map(str::to_owned));
    }

    pub(super) fn get() -> Option<String> {
        FSTYPE.with(|cell| cell.borrow().clone())
    }
}

/// Proves that the file `exe` is the executable `facts` is running, and returns
/// the metadata of that loaded inode for the caller's owner and mode checks.
///
/// On Linux: the process incarnation is unchanged around the read,
/// `/proc/<pid>/exe` and `exe` are the same device and inode, and that device is
/// a filesystem on which the running image cannot be written (see the module
/// documentation). No wall clock is consulted. Elsewhere only the previous
/// whole-second comparison of file times with the start second is available.
///
/// # Errors
///
/// The reason the loaded build is unproven (a static text, never the path).
#[cfg(target_os = "linux")]
pub fn loaded_executable(
    facts: &ProcessFacts,
    exe: &Path,
) -> Result<std::fs::Metadata, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let ticks = facts
        .start_ticks
        .ok_or("process start tick unreadable; loaded executable unproven")?;
    let incarnation = || super::proc_start_ticks(facts.pid) == Some(ticks);
    if !incarnation() {
        return Err("process incarnation changed; loaded executable unproven");
    }
    let loaded = std::fs::metadata(format!("/proc/{}/exe", facts.pid))
        .map_err(|_| "loaded executable is unreadable")?;
    let named = std::fs::metadata(exe).map_err(|_| "executable is unreadable")?;
    if (loaded.dev(), loaded.ino()) != (named.dev(), named.ino()) {
        return Err("executable path is not the file the process loaded");
    }
    if !filesystem_denies_running_writes(loaded.dev()) {
        return Err(
            "executable filesystem does not deny writes to a running executable; loaded build unproven",
        );
    }
    if !incarnation() {
        return Err("process incarnation changed; loaded executable unproven");
    }
    Ok(loaded)
}

/// See the Linux version; here only whole seconds are comparable.
///
/// # Errors
///
/// The reason the loaded build is unproven (a static text, never the path).
#[cfg(not(target_os = "linux"))]
pub fn loaded_executable(
    facts: &ProcessFacts,
    exe: &Path,
) -> Result<std::fs::Metadata, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(exe).map_err(|_| "executable is unreadable")?;
    let changed = u64::try_from(meta.mtime().max(meta.ctime())).unwrap_or(u64::MAX);
    if changed >= facts.start_time {
        return Err("executable was written or changed at or after the process start");
    }
    Ok(meta)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    const MOUNTS: &str = "\
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
30 1 259:2 / / rw,relatime shared:1 - ext4 /dev/md2 rw
31 30 0:27 / /run rw,nosuid shared:2 - tmpfs tmpfs rw,mode=755
32 30 0:50 /sub /mnt\\040space rw - fuse.sshfs host:/ rw
33 30 0:51 / /ov rw - overlay overlay rw,lowerdir=/a
34 30 8:1 / /a rw - ext4 /dev/sda1 rw
35 30 8:1 / /b rw - nfs4 other rw
";

    fn dev(major: u64, minor: u64) -> u64 {
        (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
    }

    /// The allowlist names exactly the filesystems whose kernel denies writes to
    /// a running executable, and the device lookup uses the mount's own device.
    #[test]
    fn mountinfo_device_lookup_and_allowlist() {
        assert_eq!(device_numbers(dev(259, 2)), (259, 2));
        assert_eq!(mount_types(MOUNTS, dev(259, 2)), ["ext4"]);
        assert!(device_denies_running_writes(MOUNTS, dev(259, 2)));
        assert!(device_denies_running_writes(MOUNTS, dev(0, 27)));
        assert!(!device_denies_running_writes(MOUNTS, dev(0, 50)), "fuse");
        assert!(!device_denies_running_writes(MOUNTS, dev(0, 51)), "overlay");
        assert!(
            !device_denies_running_writes(MOUNTS, dev(8, 1)),
            "one unsupported mount of the device refuses it"
        );
        assert!(!device_denies_running_writes(MOUNTS, dev(9, 9)), "unlisted");
        assert!(!device_denies_running_writes("", dev(259, 2)), "empty");
        for name in ["ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"] {
            assert!(denies_running_writes(name), "{name}");
        }
        for name in ["overlay", "nfs", "fuse", "vfat", "9p", "ext", ""] {
            assert!(!denies_running_writes(name), "{name}");
        }
        let magic: Vec<u64> = WRITE_DENYING.iter().map(|(_, magic)| *magic).collect();
        assert!(magic.contains(&0x0102_1994) && magic.contains(&0x9123_683E));
    }

    /// The kernel really reports the filesystem of this test's scratch space.
    #[test]
    fn this_hosts_mountinfo_names_the_current_directory_filesystem() {
        use std::os::unix::fs::MetadataExt;
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let meta = std::fs::metadata(std::env::temp_dir()).unwrap();
        assert!(!mount_types(&mountinfo, meta.dev()).is_empty());
    }
}
