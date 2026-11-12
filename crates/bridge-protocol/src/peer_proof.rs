//! Loaded-build evidence shared by every Linux peer-executable proof
//! (attempt-binding errata E13/E14).
//!
//! A pinned digest identifies the code a peer runs only while nothing else
//! decides that code. These checks refuse a genuine pinned executable whose
//! running code may not be the pinned build: a dynamic-loader override in the
//! peer's initial environment, a tracer attached to it, a global preload list,
//! a generic interpreter (whose digest says nothing about the program it runs)
//! and a loaded file on a filesystem where the kernel does not deny writes to a
//! running executable. Every unreadable, oversized or ambiguous fact fails
//! closed. No wall clock, file time or label grants authority, and no value read
//! here is ever returned or logged.
//!
//! The same rules are enforced by Agent Run and Agent Pool for their peers; the
//! Bridge SDK server proof and Bridge's managed attempt-binding peer proofs use
//! this module so the two sides cannot drift.

use std::path::Path;

/// Largest initial environment read from procfs.
#[cfg(target_os = "linux")]
const MAX_ENVIRON: u64 = 1024 * 1024;
/// Largest `status` or `fdinfo` record read from procfs.
#[cfg(target_os = "linux")]
const MAX_RECORD: u64 = 64 * 1024;
/// Largest mount table read from procfs.
#[cfg(target_os = "linux")]
const MAX_MOUNTINFO: u64 = 4 * 1024 * 1024;
/// Largest `/etc/ld.so.preload` that may still be accepted as blank.
#[cfg(target_os = "linux")]
const MAX_PRELOAD: u64 = 64 * 1024;

/// Filesystem types (the field after the `-` separator of `mountinfo`) on which
/// the kernel refuses to open a running executable for writing (`ETXTBSY`),
/// with the `statfs` magic number errata E13 names for each. Overlay is absent:
/// its type alone does not prove the write exclusion of its upper filesystem.
pub const WRITE_EXCLUDING_FILESYSTEMS: [(&str, u64); 6] = [
    ("ext2", 0xEF53),
    ("ext3", 0xEF53),
    ("ext4", 0xEF53),
    ("xfs", 0x5846_5342),
    ("btrfs", 0x9123_683E),
    ("tmpfs", 0x0102_1994),
];

/// Generic interpreters run whatever program they are given, so their
/// executable digest does not identify the peer's code. Matches the exact file
/// name, or the name followed by a digit, `.`, `-` or `_` (a version suffix),
/// case-insensitively; a path without a UTF-8 file name is refused too. The
/// list is the one Agent Run and Agent Pool use.
#[must_use]
pub fn forbidden_interpreter(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return true;
    };
    let name = name.to_ascii_lowercase();
    [
        "python",
        "pypy",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "expect",
        "rscript",
        "julia",
        "erl",
        "escript",
        "ld",
        "ld.so",
        "ld-linux",
        "ld-musl",
        "node",
        "nodejs",
        "deno",
        "bun",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "sh",
        "csh",
        "tcsh",
        "pwsh",
        "powershell",
        "perl",
        "ruby",
        "lua",
        "php",
        "tclsh",
        "wish",
        "gjs",
        "qjs",
        "jsc",
        "wasmtime",
        "wasmer",
        "env",
        "busybox",
        "java",
        "dotnet",
    ]
    .iter()
    .any(|prefix| {
        name == *prefix
            || (name.starts_with(prefix)
                && name
                    .as_bytes()
                    .get(prefix.len())
                    .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')))
    })
}

/// A complete NUL-terminated environment block (`/proc/PID/environ`) with no
/// dynamic-loader variable: no entry starts with `LD_`, with or without a value.
#[must_use]
pub fn clean_environment(environ: &[u8]) -> bool {
    (environ.is_empty() || environ.last() == Some(&0))
        && !environ
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"LD_"))
}

/// A `/proc/PID/status` record with exactly one `TracerPid` line naming no
/// tracer.
#[must_use]
pub fn untraced(status: &str) -> bool {
    let mut values = status
        .lines()
        .filter_map(|line| line.strip_prefix("TracerPid:"));
    matches!((values.next(), values.next()), (Some(value), None) if value.trim() == "0")
}

/// The mount ID of an open descriptor from its `fdinfo` text: exactly one
/// `mnt_id:` line with a decimal value, else `None`.
#[must_use]
pub fn fdinfo_mount_id(fdinfo: &str) -> Option<u64> {
    let mut ids = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:"));
    let id = ids.next()?.trim().parse::<u64>().ok()?;
    ids.next().is_none().then_some(id)
}

/// The filesystem type of mount `id` in `mountinfo`, when exactly one
/// well-formed record has that ID.
///
/// Fields before the `-` separator are `id parent major:minor root mountpoint
/// options [optional...]`; after it `fstype source superoptions`. Spaces inside
/// paths are escaped (`\040`) by the kernel, so fields split on single spaces.
#[must_use]
pub fn mount_type(mountinfo: &str, id: u64) -> Option<&str> {
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

/// Whether the filesystem type `fstype` is in [`WRITE_EXCLUDING_FILESYSTEMS`].
#[must_use]
pub fn write_excluding_type(fstype: &str) -> bool {
    WRITE_EXCLUDING_FILESYSTEMS
        .iter()
        .any(|(name, _)| *name == fstype)
}

/// Whether the descriptor described by `fdinfo` lies on a write-excluding
/// filesystem according to `mountinfo`: its single `mnt_id` names exactly one
/// record whose type is allowlisted (errata E14(a)). A device number is never
/// used: an overlay non-directory reports its backing device.
#[must_use]
pub fn mount_write_excluded(fdinfo: &str, mountinfo: &str) -> bool {
    fdinfo_mount_id(fdinfo)
        .and_then(|id| mount_type(mountinfo, id))
        .is_some_and(write_excluding_type)
}

/// Reads at most `limit` bytes; a longer file is an error, never a truncation.
#[cfg(target_os = "linux")]
fn bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("procfs fact oversized"));
    }
    Ok(bytes)
}

/// Whether process `pid` started without a dynamic-loader variable in its
/// initial environment ([`clean_environment`]) and has no tracer now
/// ([`untraced`]). Callers check it before and after the executable proof so a
/// tracer attached during the proof is seen. The initial environment is what
/// the loader consumed at `exec`; a peer that later rewrites that memory already
/// runs foreign code, which the other checks exclude. An unreadable environment
/// (another UID, or an exited process) fails closed.
#[cfg(target_os = "linux")]
#[must_use]
pub fn clean_process(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let process = Path::new("/proc").join(pid.to_string());
    let environment = bounded(&process.join("environ"), MAX_ENVIRON);
    let status = bounded(&process.join("status"), MAX_RECORD);
    environment.is_ok_and(|bytes| clean_environment(&bytes))
        && status.is_ok_and(|bytes| std::str::from_utf8(&bytes).is_ok_and(untraced))
}

/// Whether the global loader preload list would inject no code: only an absent
/// or blank `/etc/ld.so.preload` is accepted.
#[cfg(target_os = "linux")]
#[must_use]
pub fn loader_preload_safe() -> bool {
    blank_preload_list(Path::new("/etc/ld.so.preload"))
}

/// An absent, or present, bounded and whitespace-only, preload list; any other
/// read failure (a directory, a permission error) fails closed.
#[cfg(target_os = "linux")]
fn blank_preload_list(path: &Path) -> bool {
    match bounded(path, MAX_PRELOAD) {
        Ok(bytes) => bytes.iter().all(u8::is_ascii_whitespace),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Whether the opened file lies on a filesystem where the kernel denies writes
/// to a running executable: the descriptor's own `mnt_id` (from this process's
/// `/proc/self/fdinfo`) resolves to exactly one record of this process's
/// `/proc/self/mountinfo` with an allowlisted type ([`mount_write_excluded`]).
/// A mount of another namespace, a detached mount, an ambiguous record, overlay,
/// network, FUSE or an unknown type fails closed.
#[cfg(target_os = "linux")]
#[must_use]
pub fn write_excluded(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    let fdinfo = bounded(
        &Path::new("/proc/self/fdinfo").join(file.as_raw_fd().to_string()),
        MAX_RECORD,
    );
    let mountinfo = bounded(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO);
    match (fdinfo, mountinfo) {
        (Ok(fdinfo), Ok(mountinfo)) => {
            match (
                std::str::from_utf8(&fdinfo),
                std::str::from_utf8(&mountinfo),
            ) {
                (Ok(fdinfo), Ok(mountinfo)) => mount_write_excluded(fdinfo, mountinfo),
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic mount table covering allowed, refused and malformed records.
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

    /// A synthetic `fdinfo` record naming mount `id`.
    fn info(id: &str) -> String {
        format!("pos:\t0\nflags:\t0100000\nmnt_id:\t{id}\nino:\t42\n")
    }

    /// Generic interpreters are refused by exact name and by version suffix;
    /// ordinary product names that merely start with the same letters are not.
    #[test]
    fn interpreter_names_are_refused_by_name_and_version() {
        for name in [
            "python3",
            "Python3.12",
            "bash",
            "node",
            "env",
            "ld-linux-x86-64.so.2",
            "busybox",
        ] {
            assert!(forbidden_interpreter(&Path::new("/usr/bin").join(name)));
        }
        for name in [
            "bridge-native-daemon",
            "agent-pool",
            "environment",
            "nodeps",
            "shell-tool",
            "sleep",
        ] {
            assert!(!forbidden_interpreter(&Path::new("/opt/bin").join(name)));
        }
        assert!(forbidden_interpreter(Path::new("/")));
    }

    /// Any `LD_` entry, valued or not, and a truncated block are refused; only
    /// exactly one zero `TracerPid` is untraced.
    #[test]
    fn loader_and_tracer_evidence_is_refused() {
        assert!(clean_environment(b""));
        assert!(clean_environment(b"PATH=/usr/bin\0HOME=/h\0OLD_LD_X=1\0"));
        assert!(!clean_environment(b"LD_PRELOAD=/fixture.so\0"));
        assert!(!clean_environment(b"A=1\0LD_LIBRARY_PATH=\0"));
        assert!(!clean_environment(b"LD_AUDIT=/fixture.so\0"));
        assert!(!clean_environment(b"LD_AUDIT\0"));
        assert!(!clean_environment(b"PATH=/usr/bin"), "unterminated");
        assert!(untraced("Name:\tx\nTracerPid:\t0\n"));
        assert!(!untraced("TracerPid:\t42\n"));
        assert!(!untraced("TracerPid:\t0\nTracerPid:\t0\n"));
        assert!(!untraced("TracerPid:\t\n"));
        assert!(!untraced("Name:\tx\n"));
    }

    /// The allowlist names exactly the write-excluding filesystems, and the
    /// mount is the descriptor's own single record.
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

        let excluded = |id: &str| mount_write_excluded(&info(id), MOUNTS);
        assert!(excluded("30"), "ext4 root");
        assert!(excluded("31"), "tmpfs");
        assert!(!excluded("22"), "proc");
        assert!(!excluded("32"), "fuse");
        assert!(!excluded("33"), "overlay");
        // An overlay non-directory reports the backing device 259:2, which also
        // has the ext4 mounts 30 and 34; only the descriptor's own mount counts.
        assert!(!excluded("36"), "bind of an overlay file");
        assert!(excluded("34"), "bind mount of an ext4 subtree is that ext4");
        assert!(!excluded("35"), "same device under a network type");
        assert!(!excluded("99"), "foreign namespace or detached: no record");
        assert!(!mount_write_excluded("flags:\t0\n", MOUNTS), "no mnt_id");
        assert!(!mount_write_excluded(&info("30"), ""), "empty table");
        for name in ["ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"] {
            assert!(write_excluding_type(name), "{name}");
        }
        for name in ["overlay", "nfs", "nfs4", "fuse", "vfat", "9p", "ext", ""] {
            assert!(!write_excluding_type(name), "{name}");
        }
    }

    /// The kernel reports the mount of an opened file, and that mount has
    /// exactly one record in this process's table.
    #[cfg(target_os = "linux")]
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

    /// Only an absent or blank, bounded preload list is accepted.
    #[cfg(target_os = "linux")]
    #[test]
    fn preload_list_must_be_absent_or_blank() {
        let parent = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, Into::into);
        let directory = parent.join(format!("bridge-preload-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let list = directory.join("ld.so.preload");
        assert!(blank_preload_list(&list), "absent");
        std::fs::write(&list, b" \n\t\n").unwrap();
        assert!(blank_preload_list(&list), "blank");
        std::fs::write(&list, b"/fixture/synthetic-preload.so\n").unwrap();
        assert!(!blank_preload_list(&list), "entry");
        std::fs::write(&list, vec![b' '; 64 * 1024 + 1]).unwrap();
        assert!(!blank_preload_list(&list), "oversized");
        assert!(!blank_preload_list(&directory), "directory");
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
