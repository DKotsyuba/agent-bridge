//! Linux same-connection managed-server process and loaded-build verification
//! (attempt-binding errata E13/E14), to the level Agent Run and Agent Pool
//! prove their own peers.
//!
//! All procfs reads are bounded; any unavailable fact refuses before the SDK
//! writes credentials. This uses the kernel executable inode, never argv labels.
//! Besides the pinned digest, owner/mode and full kernel incarnation, the
//! connected server must have started without any `LD_*` loader variable, have
//! no tracer (both checked before and after the executable proof), and its
//! loaded file must lie on a write-excluding filesystem resolved through the
//! `/proc/PID/exe` descriptor's own `mnt_id`; the pin must not name a generic
//! interpreter and `/etc/ld.so.preload` must be absent or blank
//! ([`bridge_protocol::peer_proof`]).

use crate::AttemptServerPin;
use bridge_protocol::peer_proof;
use std::{
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};

/// Complete kernel identity, sampled around the connected executable proof.
#[derive(Debug, PartialEq, Eq)]
struct Incarnation {
    /// Linux boot UUID.
    boot_id: String,
    /// Local PID namespace inode.
    pid_namespace_inode: u64,
    /// Effective UID.
    uid: u32,
    /// Kernel-reported PID.
    pid: u32,
    /// Kernel process start ticks.
    start_ticks: u64,
}

/// Reads a bounded procfs value without including its contents in errors.
fn bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("process fact oversized"));
    }
    Ok(bytes)
}

/// Samples boot, namespace, effective UID, PID and start ticks from procfs.
fn incarnation(root: &Path, pid: u32, uid: u32) -> io::Result<Incarnation> {
    let invalid = || io::Error::other("kernel identity unavailable");
    if pid == 0 {
        return Err(invalid());
    }
    let boot = bounded(&root.join("sys/kernel/random/boot_id"), 64)?;
    let boot = std::str::from_utf8(&boot)
        .map_err(|_| invalid())?
        .trim_end_matches('\n');
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
    {
        return Err(invalid());
    }
    let process = root.join(pid.to_string());
    let namespace = std::fs::metadata(process.join("ns/pid"))?.ino();
    if namespace == 0 || namespace != std::fs::metadata(root.join("self/ns/pid"))?.ino() {
        return Err(invalid());
    }
    let status = bounded(&process.join("status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status).map_err(|_| invalid())?;
    let mut lines = status.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let effective: Vec<u32> = lines
        .next()
        .ok_or_else(invalid)?
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    if lines.next().is_some() || effective.len() != 4 || effective[1] != uid {
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
    let ticks = stat[end + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
        .nth(19)
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|part| part.parse::<u64>().ok())
        .filter(|ticks| *ticks > 0)
        .ok_or_else(invalid)?;
    Ok(Incarnation {
        boot_id: boot.into(),
        pid_namespace_inode: namespace,
        uid,
        pid,
        start_ticks: ticks,
    })
}

/// Stable executable identity including metadata changes during hashing.
fn file_key(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.mode(),
        metadata.uid(),
    )
}

/// Reader which refuses to start or continue hashing after the exchange deadline.
struct DeadlineReader<R> {
    /// Owned executable handle.
    inner: R,
    /// Absolute exchange deadline.
    deadline: Instant,
}
impl<R: Read> Read for DeadlineReader<R> {
    /// Reads at most one chunk while the original deadline remains.
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.inner.read(bytes)
    }
}

/// Identity of an executable file whose actual bytes have just been hashed.
type FileKey = (u64, u64, u64, i64, i64, i64, i64, u32, u32);

/// Samples a kernel birth tick before connect using a fresh local thread.
/// Its procfs birth tick cannot precede a process born later than the sample.
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

/// Hashes the pinned executable before connecting, and pins its exact inode and
/// nanosecond metadata for comparison to the connected peer's live executable.
pub(crate) fn prepare(uid: u32, pin: &AttemptServerPin, deadline: Instant) -> io::Result<FileKey> {
    use std::sync::{Mutex, OnceLock};
    /// Small process-local cache; every use still checks the full live FileKey.
    static CACHE: OnceLock<Mutex<std::collections::HashMap<FileKey, String>>> = OnceLock::new();
    let invalid = || io::Error::other("server identity not authorized");
    if pin.executable.canonicalize().ok().as_deref() != Some(pin.executable.as_path())
        || peer_proof::forbidden_interpreter(&pin.executable)
        || !peer_proof::loader_preload_safe()
    {
        return Err(invalid());
    }
    let expected = std::fs::metadata(&pin.executable)?;
    if !expected.is_file()
        || !(expected.uid() == uid || expected.uid() == 0)
        || expected.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    let file = std::fs::File::open(&pin.executable)?;
    let opened = file.metadata()?;
    if file_key(&opened) != file_key(&expected) || !peer_proof::write_excluded(&file) {
        return Err(invalid());
    }
    let key = file_key(&opened);
    let cached = CACHE
        .get_or_init(Default::default)
        .lock()
        .ok()
        .and_then(|cache| cache.get(&key).cloned());
    let mut reader = DeadlineReader {
        inner: file,
        deadline,
    };
    let digest = match cached {
        Some(digest) => digest,
        None => bridge_protocol::sha256_reader(&mut reader)?,
    };
    if digest != pin.sha256
        || Instant::now() >= deadline
        || file_key(&reader.inner.metadata()?) != file_key(&opened)
        || std::fs::metadata(&pin.executable)
            .ok()
            .is_none_or(|meta| file_key(&meta) != file_key(&opened))
        || pin.executable.canonicalize().ok().as_deref() != Some(pin.executable.as_path())
    {
        return Err(invalid());
    }
    if let Ok(mut cache) = CACHE.get_or_init(Default::default).lock() {
        if cache.len() >= 64 && !cache.contains_key(&key) {
            cache.clear();
        }
        cache.insert(key, digest);
    }
    Ok(file_key(&opened))
}

/// Proves the same connected peer's live executable is exactly the previously
/// hashed file; full kernel and file identities must remain equal around the
/// check. The PID and UID come from the very socket that receives the request.
///
/// The peer must also carry no `LD_*` variable in its initial environment and
/// have no tracer, both before and after the file checks; the descriptor opened
/// through `/proc/PID/exe` must have the hashed file's full identity (so its
/// owner and mode are the ones `prepare` accepted) and lie on a write-excluding
/// filesystem by its own `mnt_id`, so the hashed bytes are the bytes it runs;
/// and `/etc/ld.so.preload` must stay absent or blank throughout.
pub(crate) fn verify(
    pid: u32,
    uid: u32,
    pin: &AttemptServerPin,
    expected: FileKey,
    before_connect_ticks: u64,
    deadline: Instant,
) -> io::Result<()> {
    let invalid = || io::Error::other("server identity not authorized");
    let root = Path::new("/proc");
    if !peer_proof::loader_preload_safe() || peer_proof::forbidden_interpreter(&pin.executable) {
        return Err(invalid());
    }
    let before = incarnation(root, pid, uid)?;
    if before.start_ticks > before_connect_ticks || !peer_proof::clean_process(pid) {
        return Err(invalid());
    }
    let process_exe: PathBuf = root.join(pid.to_string()).join("exe");
    if std::fs::read_link(&process_exe).ok().as_deref() != Some(pin.executable.as_path()) {
        return Err(invalid());
    }
    let loaded = std::fs::File::open(&process_exe)?;
    if Instant::now() >= deadline
        || loaded
            .metadata()
            .ok()
            .is_none_or(|meta| file_key(&meta) != expected)
        || !peer_proof::write_excluded(&loaded)
        || std::fs::metadata(&pin.executable)
            .ok()
            .is_none_or(|meta| file_key(&meta) != expected)
        || pin.executable.canonicalize().ok().as_deref() != Some(pin.executable.as_path())
        || std::fs::read_link(&process_exe).ok().as_deref() != Some(pin.executable.as_path())
        || std::fs::metadata(&process_exe)
            .ok()
            .is_none_or(|meta| file_key(&meta) != expected)
        || loaded
            .metadata()
            .ok()
            .is_none_or(|meta| file_key(&meta) != expected)
        || !peer_proof::clean_process(pid)
        || !peer_proof::loader_preload_safe()
        || incarnation(root, pid, uid)? != before
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Reaps a synthetic peer even if an assertion fails.
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Spawns `program args` with exactly `env` (no inherited test-runner
    /// variables such as nextest's `LD_LIBRARY_PATH`).
    fn spawn(program: &Path, args: &[&str], env: &[(&str, &str)]) -> ChildGuard {
        ChildGuard(
            Command::new(program)
                .args(args)
                .env_clear()
                .envs(env.iter().copied())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    /// Waits until `pid` has run `exec` into `executable`.
    fn exec_into(pid: u32, executable: &Path) {
        let until = Instant::now() + std::time::Duration::from_secs(10);
        while std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .as_deref()
            != Some(executable)
        {
            assert!(Instant::now() < until, "fixture did not exec");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A pinned system executable, its digest pin and the current UID.
    fn sleep_pin() -> (u32, AttemptServerPin) {
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let executable = PathBuf::from("/usr/bin/sleep").canonicalize().unwrap();
        let digest =
            bridge_protocol::sha256_reader(&mut std::fs::File::open(&executable).unwrap()).unwrap();
        (uid, AttemptServerPin::new(executable, digest).unwrap())
    }

    /// Proves `pid` against `pin` with a fresh pre-connect sample.
    fn proves(pid: u32, uid: u32, pin: &AttemptServerPin) -> bool {
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        prepare(uid, pin, deadline)
            .and_then(|key| verify(pid, uid, pin, key, sample_start_ticks()?, deadline))
            .is_ok()
    }

    /// A peer born after the supplied pre-connect bound is refused, while the
    /// same executable and full incarnation pass a current kernel sample; a
    /// pin with another digest never prepares.
    #[test]
    fn peer_birth_must_not_follow_the_preconnect_sample() {
        let (uid, pin) = sleep_pin();
        let child = spawn(&pin.executable, &["20"], &[]);
        let pid = child.0.id();
        exec_into(pid, &pin.executable);
        let current = incarnation(Path::new("/proc"), pid, uid).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        let key = prepare(uid, &pin, deadline).unwrap();
        assert!(verify(pid, uid, &pin, key, current.start_ticks - 1, deadline).is_err());
        assert!(verify(pid, uid, &pin, key, sample_start_ticks().unwrap(), deadline).is_ok());
        assert_eq!(prepare(uid, &pin, deadline).unwrap(), key);
        let wrong = AttemptServerPin::new(pin.executable.clone(), "a".repeat(64)).unwrap();
        assert!(prepare(uid, &wrong, deadline).is_err());
        assert!(!proves(pid, uid, &wrong), "wrong digest");
    }

    /// A genuine pinned server started with any dynamic-loader variable is
    /// refused; the same build started cleanly is accepted.
    #[test]
    fn loader_environment_is_refused() {
        let (uid, pin) = sleep_pin();
        let clean = spawn(&pin.executable, &["20"], &[("PATH", "/usr/bin:/bin")]);
        exec_into(clean.0.id(), &pin.executable);
        assert!(proves(clean.0.id(), uid, &pin), "clean peer");
        for variable in [
            ("LD_PRELOAD", "/nonexistent/synthetic-preload.so"),
            ("LD_LIBRARY_PATH", "/nonexistent"),
            ("LD_AUDIT", "/nonexistent/synthetic-audit.so"),
        ] {
            let loaded = spawn(&pin.executable, &["20"], &[variable]);
            exec_into(loaded.0.id(), &pin.executable);
            assert!(!proves(loaded.0.id(), uid, &pin), "{}", variable.0);
        }
    }

    /// A genuine pinned server running under a tracer is refused. strace is
    /// optional host tooling; the `TracerPid` parser is covered by
    /// `bridge_protocol::peer_proof` unit tests either way.
    #[test]
    fn traced_peer_is_refused() {
        let strace = Path::new("/usr/bin/strace");
        if !strace.is_file() {
            eprintln!("traced-peer case not run: /usr/bin/strace is absent");
            return;
        }
        let (uid, pin) = sleep_pin();
        let program = pin.executable.to_str().unwrap();
        let tracer = spawn(
            strace,
            &["-qq", "-o", "/dev/null", "--", program, "20"],
            &[],
        );
        let children = format!("/proc/{0}/task/{0}/children", tracer.0.id());
        let until = Instant::now() + std::time::Duration::from_secs(10);
        let traced = loop {
            let pid = std::fs::read_to_string(&children)
                .ok()
                .and_then(|list| list.split_ascii_whitespace().next()?.parse::<u32>().ok());
            if let Some(pid) = pid.filter(|pid| {
                std::fs::read_link(format!("/proc/{pid}/exe"))
                    .ok()
                    .as_deref()
                    == Some(pin.executable.as_path())
            }) {
                break pid;
            }
            assert!(Instant::now() < until, "traced fixture did not start");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let status = std::fs::read_to_string(format!("/proc/{traced}/status")).unwrap();
        assert!(!status.contains("TracerPid:\t0\n"), "fixture is traced");
        assert!(!proves(traced, uid, &pin));
    }

    /// A pin naming a generic interpreter is refused even with the right
    /// digest of the very file the peer runs.
    #[test]
    fn interpreter_pin_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (uid, system) = sleep_pin();
        let parent = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let directory = parent
            .canonicalize()
            .unwrap()
            .join(format!("sdk-peer-interpreter-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let interpreter = directory.join("python3");
        std::fs::copy(&system.executable, &interpreter).unwrap();
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pin = AttemptServerPin::new(&interpreter, system.sha256.clone()).unwrap();
        let named = spawn(&interpreter, &["20"], &[]);
        exec_into(named.0.id(), &interpreter);
        assert!(!proves(named.0.id(), uid, &pin));
        drop(named);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
