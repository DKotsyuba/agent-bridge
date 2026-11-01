//! Process lifecycle of the installed daemons: start, stop and status.
//!
//! Two components run from the active release (`<home>/current/bin`):
//! `core` (`bridge-native-daemon <daemon-config>`: core service, native
//! carriers and the adapter channel) and `relay` (`bridge-root-relay
//! <interfaces-config>`). Each start resolves the real release path,
//! starts the process in its own process group with output appended to
//! `<state>/<component>.log`, records `<state>/<component>.pid` (pid,
//! kernel start time and executable) atomically and waits until every socket
//! it serves (for `core` the core socket *and* the adapter channel) is served
//! by that very process (kernel peer pid), each as a distinct OS socket
//! (device and inode). Starts and stops of a
//! component are serialized by `<state>/<component>.lock`; a failed start
//! kills and reaps only the child it spawned.
//!
//! Stop signals only a process whose record names this component's
//! executable inside a sealed release of the home and whose pid, start
//! time *and* executable still match (a forged or foreign record is
//! preserved and refused; a reused pid is never signalled), with
//! `SIGTERM` (both daemons drain and exit), and waits for it to end. No
//! process is ever restarted automatically and stopping never touches
//! custody, incidents or configuration.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// How long a start waits for the socket.
const START_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a stop waits for the process to end.
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

/// A managed daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    /// `bridge-native-daemon`.
    Core,
    /// `bridge-root-relay`.
    Relay,
}

impl Component {
    /// Parses `core` or `relay`.
    pub fn parse(name: &str) -> Option<Component> {
        match name {
            "core" => Some(Component::Core),
            "relay" => Some(Component::Relay),
            _ => None,
        }
    }

    /// Component name.
    pub fn name(self) -> &'static str {
        match self {
            Component::Core => "core",
            Component::Relay => "relay",
        }
    }

    /// Executable name in the release.
    pub fn executable(self) -> &'static str {
        match self {
            Component::Core => "bridge-native-daemon",
            Component::Relay => "bridge-root-relay",
        }
    }

    /// The socket the component serves, read from its configuration
    /// (`socket` of the daemon configuration; `[root].socket` of the
    /// interfaces configuration).
    pub fn socket(self, config: &Path) -> Result<PathBuf, String> {
        match self {
            Component::Core => {
                let text = std::fs::read_to_string(config).map_err(|error| error.to_string())?;
                // Only the socket key is read; parse errors are withheld
                // because the daemon configuration holds grant tokens.
                let value: toml::Value = toml::from_str(&text)
                    .map_err(|_| "daemon configuration is invalid".to_string())?;
                value
                    .get("socket")
                    .and_then(toml::Value::as_str)
                    .map(PathBuf::from)
                    .ok_or_else(|| "daemon configuration has no socket".to_string())
            }
            Component::Relay => crate::config::InterfacesConfig::load(config)?
                .root
                .map(|root| root.socket)
                .ok_or_else(|| "interfaces configuration has no [root]".to_string()),
        }
    }

    /// Every socket the component serves once it is fully started: its
    /// [`Component::socket`] and, for `core`, the adapter channel
    /// (`[adapters].channel` of the daemon configuration), which the daemon
    /// binds only after the core socket and without which it exits. A start
    /// is ready only when all of them are served by the started process.
    ///
    /// # Errors
    ///
    /// As [`Component::socket`]; for `core` also a configuration without a
    /// string `[adapters].channel` (parse errors are withheld), or one whose
    /// channel is the core socket's own endpoint (see [`same_endpoint`]): one
    /// listener would then answer both readiness probes while the real daemon
    /// dies on the colliding channel bind; or any of these socket paths whose
    /// final component is a symlink, dangling or not (see [`unlinked`]).
    fn ready_sockets(self, config: &Path) -> Result<Vec<PathBuf>, String> {
        let socket = self.socket(config)?;
        if self == Component::Relay {
            return unlinked(vec![socket]);
        }
        let text = std::fs::read_to_string(config).map_err(|error| error.to_string())?;
        let value: toml::Value =
            toml::from_str(&text).map_err(|_| "daemon configuration is invalid".to_string())?;
        let channel = value
            .get("adapters")
            .and_then(|adapters| adapters.get("channel"))
            .and_then(toml::Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| "daemon configuration has no [adapters].channel".to_string())?;
        if same_endpoint(&socket, &channel) {
            return Err(
                "daemon configuration names the same endpoint for socket and [adapters].channel"
                    .into(),
            );
        }
        unlinked(vec![socket, channel])
    }
}

/// Returns `sockets` unchanged when no path's final component is a symlink
/// (read with `lstat`, so a dangling link counts). A linked socket path would
/// let the readiness probe, which follows links, reach another endpoint (a
/// channel linked to the core socket is answered by the core listener alone),
/// while the daemon itself refuses the link only after it started. Nothing is
/// removed, resolved or rewritten; an absent path or another lstat failure is
/// left to the daemon.
///
/// # Errors
///
/// A configured socket path whose final component is a symlink.
fn unlinked(sockets: Vec<PathBuf>) -> Result<Vec<PathBuf>, String> {
    match sockets.iter().find(|socket| {
        std::fs::symlink_metadata(socket).is_ok_and(|meta| meta.file_type().is_symlink())
    }) {
        Some(socket) => Err(format!(
            "configured socket {} is a symlink; it was left unchanged and nothing was started",
            socket.display()
        )),
        None => Ok(sockets),
    }
}

/// Whether two configured socket paths name one filesystem endpoint: equal
/// file names in the same directory, the directories compared canonically
/// (symlinked or `.`/`..` aliases resolve) when they exist and by their
/// normalized components otherwise. Neither socket needs to exist yet.
fn same_endpoint(left: &Path, right: &Path) -> bool {
    let key = |path: &Path| {
        let directory = path.parent().map(|parent| {
            parent
                .canonicalize()
                .unwrap_or_else(|_| parent.components().collect())
        });
        (directory, path.file_name().map(std::ffi::OsStr::to_owned))
    };
    key(left) == key(right)
}

/// The pid record of a started component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PidRecord {
    /// Process id.
    pub pid: u32,
    /// Kernel start time of that process.
    pub start_time: u64,
    /// Real executable path it was started from.
    pub exe: PathBuf,
    /// Its socket.
    pub socket: PathBuf,
}

/// Pid file path of a component.
fn pid_path(state: &Path, component: Component) -> PathBuf {
    state.join(format!("{}.pid", component.name()))
}

/// Takes the component's state lock (`<state>/<component>.lock`, held
/// until the file is dropped), creating the state directory when absent.
/// Serializes every start and stop of one component.
fn lock_component(state: &Path, component: Component) -> Result<std::fs::File, String> {
    private_dir(state, true)?;
    let lock = crate::config::open_private(&state.join(format!("{}.lock", component.name())))?;
    lock.lock()
        .map_err(|error| format!("cannot lock {} state: {error}", component.name()))?;
    Ok(lock)
}

/// Reads a component's pid record.
///
/// `Ok(None)` only when no file exists. An existing record that is a link,
/// not a private regular file of this user, unreadable or not a valid
/// record is an error: its state is uncertain (it may describe a running
/// service), so callers preserve it and refuse rather than treat it as
/// "not running".
pub fn read_record(state: &Path, component: Component) -> Result<Option<PidRecord>, String> {
    let path = pid_path(state, component);
    let untrusted = |detail: String| {
        format!(
            "the {} pid record {} is untrusted ({detail}); it was preserved, nothing was started or signalled",
            component.name(),
            path.display()
        )
    };
    if !crate::config::private_file(&path).map_err(untrusted)? {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|error| untrusted(error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| untrusted("not a valid pid record".into()))
}

/// Whether the recorded process is still exactly that process (kernel
/// start time and executable path match).
pub fn alive(record: &PidRecord) -> bool {
    bridge_adapters::os::process_facts(record.pid).is_some_and(|facts| {
        facts.start_time == record.start_time && facts.exe.as_deref() == Some(record.exe.as_path())
    })
}

/// Whether `exe` is the component's executable inside a sealed release of
/// `home`: `<home>/releases/<id>/bin/<executable>` (both canonical), a
/// regular file.
fn managed_exe(home: &Path, component: Component, exe: &Path) -> bool {
    let Ok(releases) = home.join("releases").canonicalize() else {
        return false;
    };
    exe.file_name() == Some(std::ffi::OsStr::new(component.executable()))
        && exe
            .parent()
            .filter(|bin| bin.file_name() == Some(std::ffi::OsStr::new("bin")))
            .and_then(Path::parent)
            .and_then(Path::parent)
            == Some(releases.as_path())
        && std::fs::symlink_metadata(exe).is_ok_and(|metadata| metadata.is_file())
}

/// Whether `socket` is served by process `pid` right now: a connection
/// is accepted and the kernel names `pid` as the listening peer. A foreign
/// endpoint at the same path never counts.
fn served_by(socket: &Path, pid: u32) -> bool {
    UnixStream::connect(socket)
        .ok()
        .and_then(|stream| bridge_adapters::os::peer_identity(&stream).ok())
        .is_some_and(|peer| peer.pid == pid)
}

/// Whether every one of `sockets` is served by process `pid` ([`served_by`])
/// *and* they are pairwise distinct OS sockets: each path's file identity
/// (device, inode; links followed, as the probe connects through them) differs
/// from every other's. Two configured names of one socket (a case-variant name
/// on a case-insensitive volume, a hard link, or any other alias) are answered
/// by one listener and so never count as two ready endpoints. An unreadable
/// identity is not ready.
fn served_distinct(sockets: &[PathBuf], pid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut seen = Vec::with_capacity(sockets.len());
    sockets.iter().all(|socket| {
        let identity = std::fs::metadata(socket).map(|meta| (meta.dev(), meta.ino()));
        served_by(socket, pid)
            && identity.is_ok_and(|identity| {
                let fresh = !seen.contains(&identity);
                seen.push(identity);
                fresh
            })
    })
}

/// A spawned child that is killed and reaped on drop unless released.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    /// The child, while guarded.
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("guarded child")
    }

    /// Releases the child to run on (it is not reaped by this process).
    fn release(mut self) {
        self.0.take();
    }
}

impl Drop for ChildGuard {
    /// Kills and reaps the still-guarded child.
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Removes the pid record only if it is still exactly `record`.
fn remove_record_if(state: &Path, component: Component, record: &PidRecord) {
    if read_record(state, component).ok().flatten().as_ref() == Some(record) {
        let _ = std::fs::remove_file(pid_path(state, component));
    }
}

/// Starts a component from `<home>/current/bin` with `config`.
///
/// Under the component's state lock: refuses when a live recorded
/// instance exists, when an existing pid record is untrusted
/// ([`read_record`]) or names no managed executable of this home (such a
/// record is preserved byte for byte); replaces only a valid record of ours
/// whose process has ended; requires `home/current` to be the recorded active
/// release ([`crate::install::check_current`]: an interrupted activation is
/// reported, never started), the whole active release to verify against its
/// manifest (`install::verify_release`: every binary's size and
/// digest, and the home, `releases` and release directories owned by this user
/// with no group/other write — a planted or modified executable is never run)
/// and the active executable to be a sealed
/// release executable of `home`; spawns it in its own process group, records it
/// atomically and waits until every configured socket of the component
/// (`Component::ready_sockets`: for `core` the core socket and the adapter
/// channel, so a daemon that serves core but then fails its channel is never
/// reported started) is served by *that* process (kernel peer pid), each as a
/// distinct OS socket (`served_distinct`: two names of one socket never
/// count twice). On every
/// failure after the spawn the child
/// is killed and reaped and only its own record is removed; nothing else
/// is signalled or removed.
pub fn start(
    home: &Path,
    state: &Path,
    component: Component,
    config: &Path,
) -> Result<PidRecord, String> {
    let _lock = lock_component(state, component)?;
    // An untrusted record refuses here (`?`), before any spawn, signal or
    // record write; a valid record is replaced only when it is provably
    // ours (this component's executable in a sealed release of this home)
    // and its process has ended.
    if let Some(record) = read_record(state, component)? {
        if alive(&record) {
            return Err(format!(
                "{} is already running (pid {})",
                component.name(),
                record.pid
            ));
        }
        if !managed_exe(home, component, &record.exe) {
            return Err(format!(
                "the {} pid record does not name a managed executable of this home; it was preserved and nothing was started",
                component.name()
            ));
        }
    }
    let active = crate::install::check_current(home)?;
    crate::install::verify_release(home, &active)?;
    let exe = home
        .join("current")
        .join("bin")
        .join(component.executable())
        .canonicalize()
        .map_err(|error| format!("no active {}: {error}", component.executable()))?;
    if !managed_exe(home, component, &exe) {
        return Err(format!(
            "{} is not a sealed release executable of this home",
            exe.display()
        ));
    }
    let ready = component.ready_sockets(config)?;
    let socket = ready[0].clone();
    let log_path = state.join(format!("{}.log", component.name()));
    crate::config::private_file(&log_path)?;
    let log = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&log_path)
        .map_err(|error| error.to_string())?;
    let child = Command::new(&exe)
        .arg(config)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|error| error.to_string())?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", exe.display()))?;
    let mut guard = ChildGuard(Some(child));
    let pid = guard.child().id();
    let start_time = bridge_adapters::os::process_facts(pid)
        .map(|facts| facts.start_time)
        .ok_or_else(|| "started process vanished".to_string())?;
    let record = PidRecord {
        pid,
        start_time,
        exe,
        socket: socket.clone(),
    };
    write_record(state, component, &record)?;
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Ok(Some(status)) = guard.child().try_wait() {
            remove_record_if(state, component, &record);
            return Err(format!(
                "{} exited during start ({status}); see {}.log",
                component.name(),
                component.name()
            ));
        }
        if served_distinct(&ready, pid) {
            guard.release();
            return Ok(record);
        }
        if Instant::now() > deadline {
            remove_record_if(state, component, &record);
            return Err(format!(
                "{} did not serve all its sockets in time; it was stopped",
                component.name()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Requires `path` to be a real directory owned by this user that no group
/// or other user can write (otherwise another user could replace the files
/// inside it); with `create`, an absent directory is created (`0700`). Never
/// changes permissions of, clears or replaces anything that already exists.
pub(crate) fn private_dir(path: &Path, create: bool) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|error| error.to_string())?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
        Ok(metadata)
            if metadata.is_dir()
                && metadata.uid() == crate::config::own_uid()?
                && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(format!(
            "{} is not a directory owned by this user without group/other write; it was left unchanged",
            path.display()
        )),
    }
}

/// Atomically writes a pid record through an exclusively created,
/// unpredictable temporary file renamed over `<component>.pid`.
fn write_record(state: &Path, component: Component, record: &PidRecord) -> Result<(), String> {
    use std::io::Write;
    let temporary = state.join(format!(
        ".{}.pid.{}.tmp",
        component.name(),
        crate::config::random_hex(12)?
    ));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(&serde_json::to_vec(record).map_err(std::io::Error::other)?)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, pid_path(state, component)));
    written.map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot record pid: {error}")
    })
}

/// Signals exactly the recorded process with `SIGTERM` and waits until it
/// has ended, bounded by the stop timeout. Refuses pid 0, 1 and this
/// process.
fn stop_record(record: &PidRecord) -> Result<(), String> {
    if record.pid <= 1 || record.pid == std::process::id() {
        return Err(format!("refusing to signal pid {}", record.pid));
    }
    let signalled = Command::new("/bin/kill")
        .args(["-TERM", &record.pid.to_string()])
        .status()
        .map_err(|error| error.to_string())?;
    if !signalled.success() && alive(record) {
        return Err(format!("cannot signal pid {}", record.pid));
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    while alive(record) {
        if Instant::now() > deadline {
            return Err(format!("pid {} did not stop in time", record.pid));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Stops a recorded component of `home` with `SIGTERM` and waits for it.
///
/// Under the component's state lock. An untrusted record is an error
/// (state uncertain, preserved, nothing signalled), never "not running". A
/// record that does not name this
/// component's executable inside a sealed release of `home` is preserved
/// and refused (nothing is signalled): it cannot be verified as ours.
/// Returns `false` when the verified record's process is no longer running
/// (that stale record is removed); errors when the process did not end
/// within the timeout.
pub fn stop(home: &Path, state: &Path, component: Component) -> Result<bool, String> {
    let _lock = lock_component(state, component)?;
    let Some(record) = read_record(state, component)? else {
        return Ok(false);
    };
    if !managed_exe(home, component, &record.exe) {
        return Err(format!(
            "the {} pid record does not name a managed executable of this home; it was preserved and nothing was signalled",
            component.name()
        ));
    }
    if !alive(&record) {
        remove_record_if(state, component, &record);
        return Ok(false);
    }
    stop_record(&record)?;
    remove_record_if(state, component, &record);
    Ok(true)
}

#[cfg(test)]
mod tests {
    //! Readiness identity: one OS socket under two names is never two ready
    //! endpoints, on any volume (a hard link gives one inode two names).
    use super::*;
    use crate::testdir::TestDir;
    use std::os::unix::net::UnixListener;

    /// Distinct listeners of this process are ready; a second name of the same
    /// socket (hard link, same device and inode) is not, in either order, and
    /// another process's PID or an absent path is never ready.
    #[test]
    fn one_socket_under_two_names_is_not_ready() {
        let dir = TestDir::new("rd");
        let me = std::process::id();
        let (core, channel) = (dir.path().join("k.sock"), dir.path().join("c.sock"));
        let _core = UnixListener::bind(&core).unwrap();
        let _channel = UnixListener::bind(&channel).unwrap();
        let alias = dir.path().join("K2.sock");
        std::fs::hard_link(&core, &alias).unwrap();
        assert!(served_distinct(&[core.clone(), channel.clone()], me));
        assert!(!served_distinct(&[core.clone(), alias.clone()], me));
        assert!(!served_distinct(&[alias.clone(), core.clone()], me));
        assert!(!served_distinct(&[core.clone(), channel.clone()], me + 1));
        assert!(!served_distinct(
            &[core, dir.path().join("absent.sock")],
            me
        ));
    }
}
