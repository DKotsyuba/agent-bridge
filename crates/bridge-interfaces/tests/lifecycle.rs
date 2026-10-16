//! Lifecycle of a real managed daemon (`bridge-root-relay`, copied into an
//! owned sealed-release layout) under faults: parallel starts, a foreign
//! endpoint already bound at the socket, a pid record that cannot be
//! written, and a forged pid record. Everything lives in fresh exclusive
//! scratch directories under the configured temporary root; the only processes started or
//! signalled are the relay copies these tests spawn.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use bridge_interfaces::install::{
    BINARIES, MANIFEST, MANIFEST_SCHEMA, PRODUCT, ReleaseFile, ReleaseManifest, file_sha256, target,
};
use bridge_interfaces::lifecycle::{Component, PidRecord, read_record, start, stop};

/// An exclusively created scratch tree, removed (only it) on drop.
struct Scratch(PathBuf);

impl Scratch {
    /// Exclusively creates `bil<12 random hex>` under the configured temporary
    /// root with mode `0700`; never reuses an existing path. The root must leave
    /// room for descendant sockets within macOS's approximately 104-byte ceiling.
    /// Panics after 16 failed creation attempts; drop removes only this tree.
    /// Entropy, permission-setting or canonicalization failures panic immediately.
    fn new() -> Scratch {
        for _ in 0..16 {
            let random = bridge_adapters::os::random_bytes().unwrap();
            let suffix: String = random[..6].iter().map(|b| format!("{b:02x}")).collect();
            let dir = std::env::temp_dir().join(format!("bil{suffix}"));
            if std::fs::create_dir(&dir).is_ok() {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                return Scratch(dir.canonicalize().unwrap());
            }
        }
        panic!("no free scratch name");
    }
}

impl Drop for Scratch {
    /// Removes the scratch tree, first making a sealed fixture release (and its
    /// `bin/`) writable again so it can be deleted.
    fn drop(&mut self) {
        let release = self.0.join("home").join("releases").join("0.1.0+t");
        for dir in [release.join("bin"), release] {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A home with one sealed-layout release holding a copy of the relay (and
/// inert stand-ins for the other packaged binaries, all bound by a manifest),
/// its interfaces configuration and state directory. The `bridge-native-daemon`
/// stand-in execs the relay copy (same PID) serving only the daemon's core
/// socket, never its adapter channel: a daemon that is not fully started.
struct Fixture {
    /// Scratch owner.
    scratch: Scratch,
    /// Installation home.
    home: PathBuf,
    /// Lifecycle state directory.
    state: PathBuf,
    /// Relay configuration.
    config: PathBuf,
    /// Relay socket.
    socket: PathBuf,
    /// The copied relay executable (unique per fixture).
    exe: PathBuf,
    /// Daemon configuration naming the stand-in's core socket and a channel.
    daemon_config: PathBuf,
    /// The core socket the stand-in serves.
    core_socket: PathBuf,
}

/// Builds a fixture.
fn fixture() -> Fixture {
    let scratch = Scratch::new();
    let root = scratch.0.clone();
    let home = root.join("home");
    let bin = home.join("releases").join("0.1.0+t").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let exe = bin.join("bridge-root-relay");
    std::fs::copy(env!("CARGO_BIN_EXE_bridge-root-relay"), &exe).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The other packaged binaries are inert stand-ins; the manifest binds
    // every file, as in a sealed release.
    let mut files = Vec::new();
    for name in BINARIES {
        let path = bin.join(name);
        if name == "bridge-native-daemon" {
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nexec \"{}\" \"{}\"\n",
                    exe.display(),
                    root.join("core-standin.toml").display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        } else if name != "bridge-root-relay" {
            std::fs::write(&path, format!("#!/bin/sh\necho {name}\n")).unwrap();
        }
        files.push(ReleaseFile {
            name: name.into(),
            sha256: file_sha256(&path).unwrap(),
            bytes: std::fs::metadata(&path).unwrap().len(),
        });
    }
    let manifest = ReleaseManifest {
        schema: MANIFEST_SCHEMA,
        product: PRODUCT.into(),
        version: "0.1.0".into(),
        build_label: "t".into(),
        target: target(),
        core_schema: 4,
        files,
        plugin_files: Vec::new(),
    };
    std::fs::write(
        home.join("releases").join("0.1.0+t").join(MANIFEST),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    // Seal the finished release as the installer does: no write bit on the
    // release directory or its `bin/`.
    let release = home.join("releases").join("0.1.0+t");
    for dir in [bin.clone(), release] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    std::os::unix::fs::symlink("releases/0.1.0+t", home.join("current")).unwrap();
    let state_file = home.join("install-state.json");
    std::fs::write(
        &state_file,
        r#"{"current":"0.1.0+t","previous":null,"max_core_schema":4}"#,
    )
    .unwrap();
    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let relay_dir = root.join("rl");
    std::fs::create_dir(&relay_dir).unwrap();
    std::fs::set_permissions(&relay_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = relay_dir.join("token");
    std::fs::write(&token, "relay-token-for-lifecycle-test").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let socket = relay_dir.join("r.sock");
    let config = root.join("interfaces.toml");
    std::fs::write(
        &config,
        format!(
            "core_socket = \"{core}\"\n[root]\nsocket = \"{socket}\"\ntoken_file = \"{token}\"\n[[root.callers]]\nhost_id = \"h\"\nharness = \"claude-code\"\nnative_store_namespace = \"n\"\nrecipients = []\nmodes = []\nkinds = []\n",
            core = root.join("absent-core.sock").display(),
            socket = socket.display(),
            token = token.display(),
        ),
    )
    .unwrap();
    // The core stand-in is the relay serving the daemon's core socket only.
    let core_socket = relay_dir.join("k.sock");
    std::fs::write(
        root.join("core-standin.toml"),
        format!(
            "core_socket = \"{core}\"\n[root]\nsocket = \"{socket}\"\ntoken_file = \"{token}\"\n[[root.callers]]\nhost_id = \"h\"\nharness = \"claude-code\"\nnative_store_namespace = \"n\"\nrecipients = []\nmodes = []\nkinds = []\n",
            core = root.join("absent-core.sock").display(),
            socket = core_socket.display(),
            token = token.display(),
        ),
    )
    .unwrap();
    let daemon_config = root.join("daemon.toml");
    std::fs::write(
        &daemon_config,
        format!(
            "socket = \"{}\"\n[adapters]\nchannel = \"{}\"\n",
            core_socket.display(),
            relay_dir.join("c.sock").display()
        ),
    )
    .unwrap();
    Fixture {
        daemon_config,
        core_socket,
        state: root.join("state"),
        home,
        config,
        socket,
        exe: exe.canonicalize().unwrap(),
        scratch,
    }
}

/// Whether any process runs from `exe` (test-only check of this
/// fixture's unique executable path).
fn running(exe: &Path) -> bool {
    Command::new("/usr/bin/pgrep")
        .arg("-f")
        .arg(exe)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Concurrent starts are serialized to one daemon, and stop signals exactly that
/// daemon.
#[test]
fn parallel_starts_are_serialized_and_stop_is_exact() {
    let fixture = fixture();
    let results: Vec<Result<PidRecord, String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    start(
                        &fixture.home,
                        &fixture.state,
                        Component::Relay,
                        &fixture.config,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let started: Vec<_> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect();
    assert_eq!(started.len(), 1, "{results:?}");
    assert!(results.iter().any(|result| {
        result
            .as_ref()
            .is_err_and(|error| error.contains("already running"))
    }));
    assert_eq!(
        read_record(&fixture.state, Component::Relay)
            .unwrap()
            .as_ref(),
        Some(started[0])
    );
    assert!(stop(&fixture.home, &fixture.state, Component::Relay).unwrap());
    assert!(!running(&fixture.exe));
    assert!(!fixture.socket.exists(), "relay removed its own socket");
    assert!(!stop(&fixture.home, &fixture.state, Component::Relay).unwrap());
}

/// A socket held by another process refuses start, is left in place and no record
/// is written.
#[test]
fn a_foreign_endpoint_is_never_taken_for_ours() {
    let fixture = fixture();
    let foreign = UnixListener::bind(&fixture.socket).unwrap();
    let error = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    )
    .unwrap_err();
    assert!(!error.is_empty());
    assert!(fixture.socket.exists(), "foreign socket untouched");
    assert!(
        read_record(&fixture.state, Component::Relay)
            .unwrap()
            .is_none()
    );
    assert!(!running(&fixture.exe), "the spawned child was stopped");
    drop(foreign);
}

/// If the pid record cannot be written, start fails and the spawned daemon is
/// stopped.
#[test]
fn a_record_write_failure_stops_the_spawned_child() {
    let fixture = fixture();
    // Lock and log exist; the directory then becomes read-only, so the
    // daemon starts but its pid record cannot be written.
    state_dir(&fixture, 0o700);
    for name in ["relay.lock", "relay.log"] {
        pid_file_named(&fixture, name);
    }
    std::fs::set_permissions(&fixture.state, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    );
    std::fs::set_permissions(&fixture.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = result.unwrap_err();
    assert!(error.contains("cannot record pid"), "{error}");
    assert!(!running(&fixture.exe), "no orphan without a record");
    assert!(!fixture.state.join("relay.pid").exists());
}

/// A record naming a live process that is not the managed daemon is kept, and
/// stop signals nothing.
#[test]
fn a_forged_record_is_preserved_and_nothing_is_signalled() {
    let fixture = fixture();
    std::fs::create_dir(&fixture.state).unwrap();
    std::fs::set_permissions(&fixture.state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let own = bridge_adapters::os::process_facts(std::process::id()).unwrap();
    let forged = PidRecord {
        pid: own.pid,
        start_time: own.start_time,
        exe: own.exe.unwrap(),
        socket: fixture.socket.clone(),
    };
    let path = fixture.state.join("relay.pid");
    std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = stop(&fixture.home, &fixture.state, Component::Relay).unwrap_err();
    assert!(error.contains("preserved"), "{error}");
    assert_eq!(
        read_record(&fixture.state, Component::Relay),
        Ok(Some(forged))
    );
    let _ = &fixture.scratch;
}

/// Start is refused while the install state disagrees with the active release.
#[test]
fn an_interrupted_activation_is_never_started() {
    let fixture = fixture();
    // The state records another release than `current` points at.
    let state_file = fixture.home.join("install-state.json");
    std::fs::write(
        &state_file,
        r#"{"current":"0.1.0+other","previous":"0.1.0+t","max_core_schema":4}"#,
    )
    .unwrap();
    let started = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    );
    // Clean up first in every outcome, then judge.
    let _ = stop(&fixture.home, &fixture.state, Component::Relay);
    let error = started.unwrap_err();
    assert!(error.contains("interrupted activation"), "{error}");
    assert!(!running(&fixture.exe));
}

/// A release executable that no longer matches its manifest, or a release
/// directory other users can write, is never executed by `start`.
#[test]
fn a_planted_or_unsafe_release_is_never_executed() {
    let (fixture, intact) = (fixture(), self::fixture());
    let marker = fixture.scratch.0.join("planted-ran");
    std::fs::write(
        &fixture.exe,
        format!("#!/bin/sh\ntouch {}\nsleep 5\n", marker.display()),
    )
    .unwrap();
    let error = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    )
    .unwrap_err();
    assert!(error.contains("does not match the manifest"), "{error}");
    assert!(!marker.exists(), "the planted executable ran");
    assert!(!fixture.state.join("relay.pid").exists());

    // An unmodified release in a group-writable directory is refused too.
    let sealed = intact.exe.parent().unwrap().parent().unwrap().to_path_buf();
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o775)).unwrap();
    let error = start(
        &intact.home,
        &intact.state,
        Component::Relay,
        &intact.config,
    )
    .unwrap_err();
    assert!(error.contains("group/other write"), "{error}");
    assert!(!running(&intact.exe));
}

/// Creates the fixture's state directory with `mode` (not via lifecycle).
fn state_dir(fixture: &Fixture, mode: u32) {
    std::fs::create_dir(&fixture.state).unwrap();
    std::fs::set_permissions(&fixture.state, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Writes `bytes` as the relay pid record with `mode`.
fn pid_file(fixture: &Fixture, bytes: &[u8], mode: u32) -> PathBuf {
    let path = fixture.state.join("relay.pid");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// Record files that are group/other readable, malformed or foreign are never
/// overwritten, signalled or read as not running.
#[test]
fn untrusted_pid_records_are_preserved_and_refuse_start_and_stop() {
    let fixture = fixture();
    state_dir(&fixture, 0o700);
    // A real record of the managed daemon but readable by others, malformed
    // bytes, and a valid record of a foreign executable: none may be
    // overwritten, signalled or read as "not running".
    let dead = PidRecord {
        pid: 999_999,
        start_time: 1,
        exe: fixture.exe.clone(),
        socket: fixture.socket.clone(),
    };
    // A valid private record naming a foreign executable is preserved too.
    let foreign = PidRecord {
        exe: PathBuf::from("/usr/bin/true"),
        ..dead.clone()
    };
    let cases: [(Vec<u8>, u32, bool); 3] = [
        (serde_json::to_vec(&dead).unwrap(), 0o644, true),
        (b"{ not a pid record".to_vec(), 0o600, true),
        (serde_json::to_vec(&foreign).unwrap(), 0o600, false),
    ];
    for (bytes, mode, untrusted) in cases {
        let path = pid_file(&fixture, &bytes, mode);
        let started = start(
            &fixture.home,
            &fixture.state,
            Component::Relay,
            &fixture.config,
        );
        let stopped = stop(&fixture.home, &fixture.state, Component::Relay);
        let after = std::fs::read(&path).unwrap();
        assert!(!running(&fixture.exe), "nothing was spawned");
        assert!(started.unwrap_err().contains("preserved"));
        assert!(
            stopped.unwrap_err().contains("preserved"),
            "never 'not running'"
        );
        assert_eq!(
            read_record(&fixture.state, Component::Relay).is_err(),
            untrusted
        );
        assert_eq!(after, bytes, "record preserved byte for byte");
        std::fs::remove_file(&path).unwrap();
    }
}

/// A valid private record of a dead managed daemon is replaced by a fresh start.
#[test]
fn a_valid_dead_record_of_ours_is_replaced() {
    let fixture = fixture();
    state_dir(&fixture, 0o700);
    let mut gone = Command::new("/usr/bin/true").spawn().unwrap();
    let pid = gone.id();
    gone.wait().unwrap();
    let dead = PidRecord {
        pid,
        start_time: 1,
        exe: fixture.exe.clone(),
        socket: fixture.socket.clone(),
    };
    pid_file(&fixture, &serde_json::to_vec(&dead).unwrap(), 0o600);
    let started = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    );
    let stopped = stop(&fixture.home, &fixture.state, Component::Relay);
    let record = started.unwrap();
    assert_ne!(record.pid, pid);
    assert!(stopped.unwrap());
    assert!(!running(&fixture.exe));
}

/// A group/other-writable state directory refuses start and stop and keeps its
/// mode.
#[test]
fn a_group_or_world_writable_state_directory_is_refused_unchanged() {
    let fixture = fixture();
    state_dir(&fixture, 0o777);
    let started = start(
        &fixture.home,
        &fixture.state,
        Component::Relay,
        &fixture.config,
    );
    let stopped = stop(&fixture.home, &fixture.state, Component::Relay);
    assert!(!running(&fixture.exe));
    assert!(started.unwrap_err().contains("group/other write"));
    assert!(stopped.is_err());
    let mode = std::fs::metadata(&fixture.state)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o777, "permissions never changed");
    assert_eq!(
        std::fs::read_dir(&fixture.state).unwrap().count(),
        0,
        "nothing written"
    );
}

/// Creates an empty private file `name` in the fixture's state directory.
fn pid_file_named(fixture: &Fixture, name: &str) {
    let path = fixture.state.join(name);
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A core daemon that serves its core socket but never its adapter channel
/// (a daemon about to exit after its channel failed) is never reported
/// started: start fails, the spawned process is stopped and no pid record
/// remains. A daemon configuration without a channel refuses before spawning.
#[test]
fn core_is_started_only_when_its_channel_is_served_too() {
    let fixture = fixture();
    let error = start(
        &fixture.home,
        &fixture.state,
        Component::Core,
        &fixture.daemon_config,
    )
    .unwrap_err();
    assert!(error.contains("did not serve all its sockets"), "{error}");
    assert!(
        read_record(&fixture.state, Component::Core)
            .unwrap()
            .is_none()
    );
    assert!(!running(&fixture.exe), "the partial daemon was stopped");
    assert!(
        std::os::unix::net::UnixStream::connect(&fixture.core_socket).is_err(),
        "nothing serves the core socket afterwards"
    );
    let no_channel = fixture.scratch.0.join("no-channel.toml");
    std::fs::write(
        &no_channel,
        format!("socket = \"{}\"\n", fixture.core_socket.display()),
    )
    .unwrap();
    let error = start(&fixture.home, &fixture.state, Component::Core, &no_channel).unwrap_err();
    assert!(error.contains("[adapters].channel"), "{error}");
    assert!(!running(&fixture.exe));
}

/// A daemon configuration whose adapter channel names the core socket itself
/// (literally, or through a `.` component or a symlinked directory) would let
/// one endpoint answer both readiness probes while the real daemon then dies
/// on the colliding channel bind: start refuses it before spawning anything.
/// Distinct sockets (the ordinary case) are still waited for (see above).
#[test]
fn a_channel_coinciding_with_the_core_socket_is_refused_before_spawn() {
    let fixture = fixture();
    let rl = fixture.core_socket.parent().unwrap();
    let alias = fixture.scratch.0.join("rl-alias");
    std::os::unix::fs::symlink(rl, &alias).unwrap();
    for channel in [
        fixture.core_socket.clone(),
        rl.join(".").join("k.sock"),
        alias.join("k.sock"),
    ] {
        let config = fixture.scratch.0.join("coincident.toml");
        std::fs::write(
            &config,
            format!(
                "socket = \"{}\"\n[adapters]\nchannel = \"{}\"\n",
                fixture.core_socket.display(),
                channel.display()
            ),
        )
        .unwrap();
        let result = start(&fixture.home, &fixture.state, Component::Core, &config);
        // A wrongly started stand-in is stopped so a failed check leaves no process.
        if let Ok(record) = &result {
            let _ = Command::new("/bin/kill")
                .arg(record.pid.to_string())
                .status();
        }
        let error = result.unwrap_err();
        assert!(
            error.contains("same endpoint"),
            "{}: {error}",
            channel.display()
        );
        assert!(
            read_record(&fixture.state, Component::Core)
                .unwrap()
                .is_none()
        );
        assert!(!running(&fixture.exe), "nothing was spawned");
    }
}

/// A configured socket path whose final component is a symlink (here the
/// channel, dangling at the future core socket, so one core-only listener would
/// answer both readiness probes; and the core socket itself, linked to a
/// regular file) is refused before spawning. The link and its target are left
/// exactly as they were: never removed, resolved, created or rewritten.
#[test]
fn a_symlinked_socket_path_is_refused_before_spawn() {
    use std::os::unix::fs::MetadataExt;
    let fixture = fixture();
    let rl = fixture.core_socket.parent().unwrap().to_path_buf();
    let link = rl.join("c.sock");
    std::os::unix::fs::symlink("k.sock", &link).unwrap();
    let file = rl.join("plain");
    std::fs::write(&file, b"foreign").unwrap();
    let file_inode = std::fs::metadata(&file).unwrap().ino();
    let core_link = rl.join("j.sock");
    std::os::unix::fs::symlink(&file, &core_link).unwrap();
    for (socket, channel) in [
        (fixture.core_socket.clone(), link.clone()),
        (core_link.clone(), rl.join("d.sock")),
    ] {
        let config = fixture.scratch.0.join("linked.toml");
        std::fs::write(
            &config,
            format!(
                "socket = \"{}\"\n[adapters]\nchannel = \"{}\"\n",
                socket.display(),
                channel.display()
            ),
        )
        .unwrap();
        let result = start(&fixture.home, &fixture.state, Component::Core, &config);
        // A wrongly started stand-in is stopped so a failed check leaves no process.
        if let Ok(record) = &result {
            let _ = Command::new("/bin/kill")
                .arg(record.pid.to_string())
                .status();
        }
        let error = result.unwrap_err();
        assert!(error.contains("symlink"), "{}: {error}", socket.display());
        assert!(
            read_record(&fixture.state, Component::Core)
                .unwrap()
                .is_none()
        );
        assert!(!running(&fixture.exe), "nothing was spawned");
    }
    assert_eq!(std::fs::read_link(&link).unwrap(), PathBuf::from("k.sock"));
    assert!(
        !fixture.core_socket.exists(),
        "the link target was never created"
    );
    assert_eq!(std::fs::read_link(&core_link).unwrap(), file);
    assert_eq!(std::fs::metadata(&file).unwrap().ino(), file_inode);
    assert_eq!(std::fs::read(&file).unwrap(), b"foreign");
}

/// Two configured names that are one OS socket (here `k.sock` and `K.sock`,
/// one inode on a case-insensitive volume) must never count as two served
/// endpoints: the core-only stand-in answers both names, so start must fail
/// and stop it instead of reporting the daemon started. On a case-sensitive
/// volume the names are distinct files and this case does not apply; the
/// portable same-inode contract is the unit test `one_socket_under_two_names_is_not_ready`.
#[test]
fn case_variant_names_of_one_socket_are_never_ready() {
    let fixture = fixture();
    let rl = fixture.core_socket.parent().unwrap().to_path_buf();
    let probe = rl.join("case-probe");
    std::fs::write(&probe, b"").unwrap();
    let insensitive = rl.join("CASE-PROBE").exists();
    std::fs::remove_file(&probe).unwrap();
    if !insensitive {
        eprintln!("case-variant check not applicable: this volume is case-sensitive");
        return;
    }
    let config = fixture.scratch.0.join("case.toml");
    std::fs::write(
        &config,
        format!(
            "socket = \"{}\"\n[adapters]\nchannel = \"{}\"\n",
            fixture.core_socket.display(),
            rl.join("K.sock").display()
        ),
    )
    .unwrap();
    let result = start(&fixture.home, &fixture.state, Component::Core, &config);
    // A wrongly started stand-in is stopped so a failed check leaves no process.
    if let Ok(record) = &result {
        let _ = Command::new("/bin/kill")
            .arg(record.pid.to_string())
            .status();
    }
    let error = result.unwrap_err();
    assert!(error.contains("did not serve all its sockets"), "{error}");
    assert!(
        read_record(&fixture.state, Component::Core)
            .unwrap()
            .is_none()
    );
    assert!(!running(&fixture.exe), "the partial daemon was stopped");
}
