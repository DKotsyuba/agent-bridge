//! Agent Bridge workspace automation.
//!
//! ```text
//! cargo xtask package [--label LABEL] [--out ABS_DIR]
//! cargo xtask qualify --prefix ABS_DIR
//! cargo xtask check-public [--root DIR]
//! ```
//!
//! `check-public` runs the public-repository checker ([`public`]): required
//! files, Markdown links and coverage, private paths and identifiers, and
//! version/license/schema/CI consistency. It reads only the source tree.
//!
//! `package` builds every workspace binary in release mode (offline,
//! locked) with `BRIDGE_BUILD_LABEL` (default: the 12-digit Git commit,
//! `-dirty` when the worktree has changes) and writes a verified bundle
//! with the built `bridge package`, always passing the repository's
//! `crates/bridge-adapters/plugins/opencode` directory so the bundle carries
//! the OpenCode plugin. It prints the manifest and the
//! `SHA256SUMS` digest to pass to `install.sh`.
//!
//! `qualify` exercises the real packaged product inside one new isolated
//! prefix only (installation home, launcher directory, state, sockets,
//! database, tokens, configuration): attestation refusal before execution,
//! install, installed version/hash, daemon start, doctor, operator read,
//! upgrade, rollback, restart and stop. It never touches the user's
//! installation, harness stores or sessions, sends nothing over the
//! network and starts no model. The prefix is created exclusively (an
//! existing path is refused). Started daemons are stopped by a guard on
//! every exit path. Every command runs with closed stdin and a time budget
//! (build 30 min, product command 2 min, whole invocation 45 min); an
//! expired command is killed and reaped. Results go to
//! `<prefix>/qualification.json`; the exit status is 0 only when every
//! check passed. Guard cleanup receives an independent two-minute budget per
//! component even when the global qualification deadline has already expired.

mod public;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// Workspace root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

/// Entry point.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|index| args.get(index + 1))
            .cloned()
    };
    let result = match args.first().map(String::as_str) {
        Some("package") => {
            let label = flag("--label").unwrap_or_else(default_label);
            let out = flag("--out").map(PathBuf::from).unwrap_or_else(|| {
                root().join("dist").join(format!(
                    "agent-bridge-{}+{label}",
                    env!("CARGO_PKG_VERSION")
                ))
            });
            package(&label, &out).map(|value| println!("{value:#}"))
        }
        Some("qualify") => match flag("--prefix") {
            Some(prefix) => qualify(Path::new(&prefix)),
            None => Err("--prefix is required".into()),
        },
        Some("check-public") => {
            public::run(&flag("--root").map(PathBuf::from).unwrap_or_else(root))
        }
        _ => Err(
            "usage: cargo xtask package [--label L] [--out DIR] | qualify --prefix DIR | check-public [--root DIR]"
                .into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Total time budget of one xtask invocation.
const TOTAL_BUDGET: Duration = Duration::from_secs(45 * 60);

/// Budget of one product command (install, service, doctor, operator).
const COMMAND_BUDGET: Duration = Duration::from_secs(120);

/// Budget of one release build.
const BUILD_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Deadline of this invocation, fixed at first use.
static DEADLINE: OnceLock<Instant> = OnceLock::new();

/// Runs a command with stdin closed and output captured, bounded by
/// `budget` and the invocation's total budget; on expiry the child is
/// killed and reaped and an error returned.
fn run_within(command: &mut Command, budget: Duration) -> Result<Output, String> {
    let deadline =
        (Instant::now() + budget).min(*DEADLINE.get_or_init(|| Instant::now() + TOTAL_BUDGET));
    run_until(command, deadline)
}

/// Runs `command` with closed stdin and captured output until the explicit
/// monotonic `deadline`. Timeout kills and reaps its child and returns an
/// error; this helper does not inherit the invocation deadline, so owned
/// cleanup can still run after qualification has timed out.
fn run_until(command: &mut Command, deadline: Instant) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run {command:?}: {error}"))?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
    );
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{command:?} exceeded its time budget or failed: {other:?}"
                ));
            }
        }
    };
    Ok(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Runs a product command within [`COMMAND_BUDGET`].
fn run(command: &mut Command) -> Result<Output, String> {
    run_within(command, COMMAND_BUDGET)
}

/// The default build label: short commit, `-dirty` with local changes.
fn default_label() -> String {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(root())
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let commit = git(&["rev-parse", "--short=12", "HEAD"]);
    let commit = if commit.is_empty() {
        "unknown".into()
    } else {
        commit
    };
    if git(&["status", "--porcelain"]).is_empty() {
        commit
    } else {
        format!("{commit}-dirty")
    }
}

/// Builds release binaries with `label` and packages them at `out`.
///
/// The binaries are located from Cargo's own artifact messages (so a
/// `CARGO_TARGET_DIR` or configured target directory is honoured and a
/// stale binary elsewhere is never packaged); all packaged executables
/// must come from this build and one directory. The repository's OpenCode
/// plugin directory is always passed explicitly (never inferred by `bridge`
/// from the working directory). Returns the `bridge package` result
/// (`manifest`, `sums_sha256`).
fn package(label: &str, out: &Path) -> Result<Value, String> {
    let plugin = root().join("crates/bridge-adapters/plugins/opencode");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let build = run_within(
        Command::new(cargo)
            .args([
                "build",
                "--release",
                "--offline",
                "--locked",
                "--workspace",
                "--bins",
                "--message-format=json-render-diagnostics",
            ])
            .env("BRIDGE_BUILD_LABEL", label)
            .current_dir(root()),
        BUILD_BUDGET,
    )?;
    if !build.status.success() {
        return Err(format!(
            "release build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        ));
    }
    let mut built = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(&build.stdout).lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] == "compiler-artifact"
            && let Some(executable) = message["executable"].as_str()
        {
            let path = PathBuf::from(executable);
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                built.insert(name.to_string(), path.clone());
            }
        }
    }
    let mut directory = None;
    for name in PACKAGED {
        let path = built
            .get(name)
            .ok_or_else(|| format!("the build reported no {name} executable"))?;
        let parent = path.parent().map(Path::to_path_buf);
        if directory.get_or_insert_with(|| parent.clone()) != &parent {
            return Err("packaged executables come from different directories".into());
        }
    }
    let release = directory
        .flatten()
        .ok_or_else(|| "no build output directory".to_string())?;
    let packaged = run(Command::new(release.join("bridge"))
        .args(["package", "--from"])
        .arg(&release)
        .arg("--out")
        .arg(out)
        .arg("--plugin-dir")
        .arg(&plugin))?;
    if !packaged.status.success() {
        return Err(format!(
            "bridge package failed: {}",
            String::from_utf8_lossy(&packaged.stderr)
        ));
    }
    serde_json::from_slice(&packaged.stdout).map_err(|error| error.to_string())
}

/// The executables a bundle carries (`bridge package` re-checks the set).
const PACKAGED: [&str; 6] = [
    "bridge",
    "bridge-root-mcp",
    "bridge-root-relay",
    "bridge-native-daemon",
    "bridge-hook",
    "bridge-daemon",
];

/// One recorded qualification check.
struct Recorder {
    /// Checks in order: name, passed, observation.
    checks: Vec<Value>,
}

impl Recorder {
    /// Records one check.
    fn check(&mut self, name: &str, passed: bool, observed: Value) {
        eprintln!("{} {name}", if passed { "PASS" } else { "FAIL" });
        self.checks
            .push(json!({"check": name, "passed": passed, "observed": observed}));
    }
}

/// Output of a product command: exit code and JSON stdout (or text).
fn product(command: &mut Command) -> Result<(i32, Value), String> {
    let output = run(command)?;
    let stdout = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| json!(String::from_utf8_lossy(&output.stdout)));
    Ok((output.status.code().unwrap_or(-1), stdout))
}

/// Writes a file with mode 0600.
fn private_file(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).map_err(|error| error.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

/// 32 random bytes as hex, for test-only grant tokens.
fn random_token() -> Result<String, String> {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| error.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Writes the isolated daemon configuration naming `relay` as the
/// trusted relay build.
fn daemon_config(
    prefix: &Path,
    relay: &Value,
    root_token: &str,
    operator_token: &str,
) -> Result<PathBuf, String> {
    let path = prefix.join("etc").join("daemon.toml");
    private_file(
        &path,
        &format!(
            r#"database = "{run}/bridge.db"
socket = "{run}/core.sock"

[limits]
max_admitted_events = 1000

[[grant]]
token = "{root_token}"
publisher = "bridge-root"
recipients = ["qual-host/claude-code/qual-store/qual-session"]
kinds = ["root.note"]
modes = ["inject", "auto"]
policies = ["keep_all"]

[[grant]]
token = "{operator_token}"
publisher = "bridge-ops"
admin = true
recipients = []
kinds = []
modes = []
policies = []

[adapters]
channel = "{run}/ch/c.sock"
host_id = "qual-host"
profiles = []

[[adapters.relays]]
path = "{relay_path}"
sha256 = "{relay_sha}"
"#,
            run = prefix.join("run").display(),
            relay_path = relay["path"].as_str().unwrap_or_default(),
            relay_sha = relay["sha256"].as_str().unwrap_or_default(),
        ),
    )?;
    Ok(path)
}

/// Stops this run's managed daemons on drop (relay, then core), through
/// the product's own record-verified `bridge service stop`, each within the
/// independent command budget even after the invocation deadline has expired;
/// at most two command budgets in total. Outcomes go to stderr.
struct Services {
    /// The launcher of the installed `bridge`.
    bridge: PathBuf,
    /// Installation home of this run.
    home: PathBuf,
    /// Lifecycle state of this run.
    state: PathBuf,
}

impl Drop for Services {
    /// Stops both components; never panics.
    fn drop(&mut self) {
        for component in ["relay", "core"] {
            let outcome = run_until(
                Command::new(&self.bridge)
                    .args(["service", "stop", component, "--home"])
                    .arg(&self.home)
                    .arg("--state")
                    .arg(&self.state),
                Instant::now() + COMMAND_BUDGET,
            );
            match outcome {
                Ok(output) => eprintln!(
                    "cleanup stop {component}: exit {:?} {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).trim()
                ),
                Err(error) => eprintln!("cleanup stop {component}: {error}"),
            }
        }
    }
}

/// Runs the isolated install/lifecycle qualification.
fn qualify(prefix: &Path) -> Result<(), String> {
    if !prefix.is_absolute() {
        return Err("--prefix must be an absolute path".into());
    }
    // Exclusive creation: an existing path (file, directory or link) is
    // refused untouched; only this new tree is ever written.
    std::fs::create_dir(prefix).map_err(|error| {
        format!("--prefix must be a new path in an existing directory: {error}")
    })?;
    for dir in ["dist", "etc", "run", "state", "bin", "secrets"] {
        std::fs::create_dir(prefix.join(dir)).map_err(|error| error.to_string())?;
    }
    let prefix = prefix.canonicalize().map_err(|error| error.to_string())?;
    let home = prefix.join("home");
    let bin = prefix.join("bin");
    let state = prefix.join("state");
    let installer = root().join("install.sh");
    let mut recorder = Recorder { checks: Vec::new() };
    let base = default_label();
    let (label_a, label_b) = (format!("{base}.qa"), format!("{base}.qb"));
    let bundle_a = prefix.join("dist").join("a");
    let bundle_b = prefix.join("dist").join("b");
    let packaged_a = package(&label_a, &bundle_a)?;
    let sums_a = packaged_a["sums_sha256"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    // The storage schema the packaged binaries were built with (no fixed
    // number here: the bundle manifest is the authority).
    let packaged_schema = packaged_a["manifest"]["core_schema"].clone();
    let sums_b = package(&label_b, &bundle_b)?["sums_sha256"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let install = |bundle: &Path, sums: &str| {
        product(
            Command::new("/bin/bash")
                .arg(&installer)
                .args(["--bundle"])
                .arg(bundle)
                .args(["--sums-sha256", sums, "--home"])
                .arg(&home)
                .arg("--bin-dir")
                .arg(&bin),
        )
    };

    // Attestation before execution: a tampered bundle never runs.
    let tampered = prefix.join("dist").join("tampered");
    run(Command::new("/bin/cp")
        .args(["-R"])
        .arg(&bundle_a)
        .arg(&tampered))?;
    let marker = prefix.join("tampered-ran");
    std::fs::write(
        tampered.join("bin").join("bridge"),
        format!("#!/bin/sh\ntouch {}\n", marker.display()),
    )
    .map_err(|error| error.to_string())?;
    let (code, _) = install(&tampered, &sums_a)?;
    recorder.check(
        "tampered_bundle_refused_before_execution",
        code != 0 && !marker.exists() && std::fs::symlink_metadata(home.join("current")).is_err(),
        json!({"exit": code, "marker_created": marker.exists()}),
    );
    let (code, _) = install(&bundle_a, &"0".repeat(64))?;
    recorder.check(
        "unattested_digest_refused",
        code != 0,
        json!({"exit": code}),
    );

    // Install A and check the installed build itself.
    let (code, activation_a) = install(&bundle_a, &sums_a)?;
    recorder.check("install_a", code == 0, activation_a.clone());
    let plugin_entry = activation_a["plugin_binding"]["path"]
        .as_str()
        .map(PathBuf::from);
    recorder.check(
        "installed_plugin_binding_is_the_sealed_release_file",
        plugin_entry.as_deref().is_some_and(|entry| {
            entry.ends_with("plugins/opencode/index.js")
                && entry.starts_with(home.join("releases"))
                && entry
                    .parent()
                    .is_some_and(|dir| dir.join("package.json").is_file())
                && std::fs::metadata(entry).is_ok_and(|meta| meta.permissions().readonly())
                && activation_a["plugin_binding"]["sha256"]
                    == packaged_a["manifest"]["plugin_files"][0]["sha256"]
                && std::fs::read(entry)
                    .ok()
                    .zip(
                        std::fs::read(
                            root().join("crates/bridge-adapters/plugins/opencode/index.js"),
                        )
                        .ok(),
                    )
                    .is_some_and(|(installed, source)| installed == source)
        }),
        activation_a["plugin_binding"].clone(),
    );
    let (_, version) = product(Command::new(bin.join("bridge")).arg("version"))?;
    recorder.check(
        "installed_version_is_a",
        version["build_label"] == label_a.as_str()
            && packaged_schema.is_u64()
            && version["core_schema"] == packaged_schema,
        version,
    );

    let root_token = random_token()?;
    let operator_token = random_token()?;
    let mut daemon = daemon_config(
        &prefix,
        &activation_a["relay_binding"],
        &root_token,
        &operator_token,
    )?;
    private_file(&prefix.join("secrets").join("root"), &root_token)?;
    private_file(&prefix.join("secrets").join("operator"), &operator_token)?;
    let interfaces = prefix.join("etc").join("interfaces.toml");
    private_file(
        &interfaces,
        &format!(
            r#"core_socket = "{run}/core.sock"
[operator]
token_file = "{secrets}/operator"
[notify]
ledger = "{run}/notify-ledger.json"
[root]
socket = "{run}/rl/relay.sock"
token_file = "{secrets}/root"
channel = "{run}/ch/c.sock"
[[root.callers]]
host_id = "qual-host"
harness = "claude-code"
native_store_namespace = "qual-store"
recipients = ["qual-host/claude-code/qual-store/qual-session"]
modes = ["inject"]
kinds = ["root.note"]
"#,
            run = prefix.join("run").display(),
            secrets = prefix.join("secrets").display(),
        ),
    )?;
    // Whatever happens below (including an early error), the daemons this
    // run may have started are stopped when the guard drops.
    let _services = Services {
        bridge: bin.join("bridge"),
        home: home.clone(),
        state: state.clone(),
    };
    // `service stop` accepts no `--config` (the CLI refuses unknown options).
    let service = |verb: &str, component: &str, config: &Path| {
        let mut command = Command::new(bin.join("bridge"));
        command
            .args(["service", verb, component, "--home"])
            .arg(&home)
            .arg("--state")
            .arg(&state);
        if verb == "start" {
            command.arg("--config").arg(config);
        }
        product(&mut command)
    };
    let start_all = |recorder: &mut Recorder, daemon: &Path, tag: &str| -> Result<(), String> {
        let (core, observed) = service("start", "core", daemon)?;
        recorder.check(&format!("start_core_{tag}"), core == 0, observed);
        let (relay, observed) = service("start", "relay", &interfaces)?;
        recorder.check(&format!("start_relay_{tag}"), relay == 0, observed);
        Ok(())
    };
    let stop_all = |recorder: &mut Recorder, tag: &str| -> Result<(), String> {
        for component in ["relay", "core"] {
            let (code, observed) = service("stop", component, &interfaces)?;
            recorder.check(
                &format!("stop_{component}_{tag}"),
                code == 0 && observed["stopped"] == true,
                observed,
            );
        }
        Ok(())
    };
    let doctor = |daemon: &Path| {
        product(
            Command::new(bin.join("bridge"))
                .args(["doctor", "--home"])
                .arg(&home)
                .arg("--bin-dir")
                .arg(&bin)
                .arg("--state")
                .arg(&state)
                .arg("--config")
                .arg(&interfaces)
                .arg("--daemon-config")
                .arg(daemon),
        )
    };
    let status = |report: &Value, name: &str| -> String {
        report["checks"]
            .as_array()
            .and_then(|checks| checks.iter().find(|check| check["name"] == name))
            .and_then(|check| check["status"].as_str())
            .unwrap_or("absent")
            .to_string()
    };
    let healthy = |report: &Value| {
        [
            "install.release",
            "install.launchers",
            "process.core",
            "process.relay",
            "core.reachable",
            "relay.reachable",
            "adapters.relay_binding",
            "install.current_link",
            "recovery.pending",
        ]
        .iter()
        .all(|name| status(report, name) == "ok")
            && status(report, "telegram") == "not_configured"
            && status(report, "qualification") == "not_verified"
    };

    start_all(&mut recorder, &daemon, "a")?;
    let (code, report) = doctor(&daemon)?;
    let recovery_a = report["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["name"] == "recovery.pending")
        })
        .cloned()
        .unwrap_or(Value::Null);
    recorder.check("doctor_a_running", code == 0 && healthy(&report), report);
    let (code, incidents) = product(
        Command::new(bin.join("bridge"))
            .args(["operator"])
            .arg(&interfaces)
            .arg("incidents"),
    )?;
    recorder.check(
        "operator_reads_installed_core",
        code == 0 && incidents["incidents"].as_array().is_some_and(Vec::is_empty),
        incidents,
    );
    let (code, counts) = product(
        Command::new(bin.join("bridge"))
            .args(["operator"])
            .arg(&interfaces)
            .arg("counts"),
    )?;
    recorder.check(
        "operator_counts_complete_and_empty",
        code == 0
            && counts["counts"]
                .as_object()
                .is_some_and(|fields| fields.len() == 10 && fields.values().all(|v| v == 0)),
        counts,
    );
    recorder.check(
        "doctor_recovery_empty_from_counts",
        recovery_a["status"] == "ok"
            && recovery_a["detail"]["state"] == "empty"
            && recovery_a["detail"]["waiting_events"] == 0
            && recovery_a["detail"]["incident_sample"]["sampled"] == 0
            && recovery_a["detail"]["incident_sample"]["sample_complete"] == true
            && recovery_a["detail"]["counts"]
                .as_object()
                .is_some_and(|fields| fields.len() == 10 && fields.values().all(|v| v == 0)),
        recovery_a,
    );

    // Upgrade to B: activation does not restart; the relay binding and
    // daemons are switched explicitly.
    let (code, activation_b) = install(&bundle_b, &sums_b)?;
    recorder.check(
        "install_b",
        code == 0
            && activation_b["previous"] == activation_a["current"]
            && activation_b["plugin_binding"]["sha256"] == activation_a["plugin_binding"]["sha256"]
            && activation_b["plugin_binding"]["path"] != activation_a["plugin_binding"]["path"],
        activation_b.clone(),
    );
    let (_, report) = doctor(&daemon)?;
    recorder.check(
        "doctor_reports_stale_running_build_after_upgrade",
        status(&report, "process.core") == "warn",
        report,
    );
    stop_all(&mut recorder, "a")?;
    daemon = daemon_config(
        &prefix,
        &activation_b["relay_binding"],
        &root_token,
        &operator_token,
    )?;
    start_all(&mut recorder, &daemon, "b")?;
    let (code, report) = doctor(&daemon)?;
    recorder.check("doctor_b_running", code == 0 && healthy(&report), report);
    let (_, version) = product(Command::new(bin.join("bridge")).arg("version"))?;
    recorder.check(
        "installed_version_is_b",
        version["build_label"] == label_b.as_str(),
        version,
    );

    // Rollback to A: code only; custody database and state stay.
    let database = prefix.join("run").join("bridge.db");
    let (code, rolled) = product(
        Command::new(bin.join("bridge"))
            .args(["rollback", "--home"])
            .arg(&home),
    )?;
    recorder.check(
        "rollback_to_a",
        code == 0
            && rolled["current"] == activation_a["current"]
            && rolled["plugin_binding"] == activation_a["plugin_binding"],
        rolled,
    );
    let (_, version) = product(Command::new(bin.join("bridge")).arg("version"))?;
    recorder.check(
        "rolled_back_version_is_a",
        version["build_label"] == label_a.as_str(),
        version,
    );
    stop_all(&mut recorder, "b")?;
    daemon = daemon_config(
        &prefix,
        &activation_a["relay_binding"],
        &root_token,
        &operator_token,
    )?;
    start_all(&mut recorder, &daemon, "rollback")?;
    let (code, report) = doctor(&daemon)?;
    recorder.check(
        "doctor_after_rollback",
        code == 0 && healthy(&report),
        report,
    );
    recorder.check(
        "database_kept_across_rollback",
        database.is_file(),
        json!({"database": database}),
    );
    stop_all(&mut recorder, "final")?;
    let sockets_gone = !prefix.join("run").join("core.sock").exists()
        && !prefix.join("run").join("rl").join("relay.sock").exists();
    recorder.check("sockets_removed_on_stop", sockets_gone, json!({}));

    let passed = recorder.checks.iter().all(|check| check["passed"] == true);
    let evidence = json!({
        "prefix": prefix,
        "labels": [label_a, label_b],
        "sums_sha256": [sums_a, sums_b],
        "passed": passed,
        "checks": recorder.checks,
        "scope": "isolated package/install/lifecycle only; no native harness, model, network or user installation",
    });
    std::fs::write(prefix.join("qualification.json"), format!("{evidence:#}"))
        .map_err(|error| error.to_string())?;
    if passed {
        Ok(())
    } else {
        Err(format!(
            "qualification failed; see {}/qualification.json",
            prefix.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    //! Cleanup remains usable after the qualification deadline. The stop
    //! executable is a faithful local stand-in that terminates two owned
    //! process fixtures; this is not installed-product/native qualification.

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An expired invocation still lets the actual Services drop guard stop
    /// both owned fixtures, and an independently stalled command is bounded.
    #[test]
    fn cleanup_has_an_independent_finite_budget() {
        let dir = std::env::temp_dir().join(format!(
            "bridge-cleanup-{}-{}",
            std::process::id(),
            random_token().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut children = ["relay", "core"].map(|component| {
            let child = Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::fs::write(dir.join(component), child.id().to_string()).unwrap();
            child
        });
        let script = dir.join("bridge");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nsleep 0.1\nkill \"$(cat '{}/'$3)\"\necho \"$3\" >> '{}/stopped'\n",
                dir.display(),
                dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        DEADLINE
            .set(Instant::now() - Duration::from_secs(1))
            .unwrap();
        let guard = Services {
            bridge: script,
            home: dir.clone(),
            state: dir.clone(),
        };
        drop(guard);
        let stopped = std::fs::read_to_string(dir.join("stopped")).unwrap_or_default();
        let mut clean = true;
        for child in &mut children {
            for _ in 0..20 {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().unwrap().is_none() {
                clean = false;
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(stopped, "relay\ncore\n");
        assert!(clean, "cleanup left an owned daemon fixture alive");
        let started = Instant::now();
        assert!(
            run_until(
                Command::new("/bin/sleep").arg("5"),
                Instant::now() + Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
