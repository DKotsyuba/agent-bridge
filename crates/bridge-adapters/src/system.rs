//! One Linux system service coordinating native workers under their own UIDs.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use bridge_core::dispatch::{
    AttemptFence, AttemptRecord, AttemptState, Attestation, DispatchTiming, EffectiveMode,
};
use bridge_core::recovery::EvidenceTier;
use bridge_core::service::current_unix_millis;
use bridge_core::{Harness, NativeAddress};
use serde::{Deserialize, Serialize};

use crate::system_ipc::{BindingFacts, Event, Request, Response, WireOutcome};
use crate::system_link::{Incoming, Link};

/// One root-approved native namespace served by exactly one account.
#[derive(Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Scope {
    /// Host component of the native address.
    host: String,
    /// Canonical native harness name.
    harness: String,
    /// Native store namespace owned by this account.
    namespace: String,
}

/// One fixed non-root account and its existing private Bridge configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    /// System account name.
    name: String,
    /// Expected numeric user identity.
    uid: u32,
    /// Expected primary group identity.
    gid: u32,
    /// Expected home directory.
    home: PathBuf,
    /// Existing native daemon configuration, read only after dropping UID.
    daemon_config: PathBuf,
    /// Existing root relay configuration, read only after dropping UID.
    interfaces_config: PathBuf,
    /// Explicit fresh database path, only when the administrator approved one.
    #[serde(default)]
    new_database: Option<PathBuf>,
    /// Native namespaces this account may attest.
    scopes: Vec<Scope>,
}

/// Protected system configuration, never a source of native identity proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemConfig {
    /// Internal configuration format version.
    version: u32,
    /// Explicitly permitted Linux accounts.
    accounts: Vec<Account>,
}

/// Refuses writable, non-root or symlinked system configuration and ancestors.
fn trusted_root_file(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("system configuration path is not absolute".into());
    }
    for entry in std::iter::once(path).chain(path.ancestors().skip(1)) {
        let meta = fs::symlink_metadata(entry).map_err(|_| "system path unreadable")?;
        let correct_type = if entry == path {
            meta.file_type().is_file()
        } else {
            meta.file_type().is_dir()
        };
        if !correct_type || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("system path is not root-owned and protected".into());
        }
    }
    Ok(())
}

/// Checks the account against the host passwd database without a shell.
fn check_passwd(account: &Account) -> Result<(), String> {
    let output = Command::new("/usr/bin/getent")
        .args(["passwd", &account.name])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .map_err(|_| "account lookup failed")?;
    if !output.status.success() {
        return Err("configured account is unavailable".into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| "account record invalid")?;
    let fields: Vec<_> = text.trim_end().split(':').collect();
    if fields.len() != 7
        || fields[0] != account.name
        || fields[2].parse::<u32>().ok() != Some(account.uid)
        || fields[3].parse::<u32>().ok() != Some(account.gid)
        || Path::new(fields[5]) != account.home
    {
        return Err("configured account identity changed".into());
    }
    Ok(())
}

/// Validates fixed accounts and returns the unique native namespace map.
fn validate_config(config: &SystemConfig) -> Result<BTreeMap<Scope, u32>, String> {
    if config.version != 1 || config.accounts.is_empty() {
        return Err("unsupported or empty system configuration".into());
    }
    let mut names = HashSet::new();
    let mut uids = HashSet::new();
    let mut scopes = BTreeMap::new();
    for account in &config.accounts {
        if account.name.is_empty()
            || !account
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || account.uid == 0
            || account.gid == 0
            || !account.home.is_absolute()
            || !account.daemon_config.is_absolute()
            || !account.interfaces_config.is_absolute()
            || account.new_database.as_ref().is_some_and(|path| {
                !path.is_absolute()
                    || !path.starts_with(account.home.join(".agent-bridge"))
                    || path
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir))
            })
            || !names.insert(account.name.clone())
            || !uids.insert(account.uid)
            || account.scopes.is_empty()
        {
            return Err("invalid or duplicate system account".into());
        }
        for scope in &account.scopes {
            let harness = Harness::parse(&scope.harness).map_err(|_| "invalid harness")?;
            if harness.as_str() != scope.harness
                || NativeAddress::new(&scope.host, harness, &scope.namespace, "probe").is_err()
                || scopes.insert(scope.clone(), account.uid).is_some()
            {
                return Err("invalid or duplicate native namespace".into());
            }
        }
    }
    Ok(scopes)
}

/// Rejects remaining processes from an earlier generation of this system unit.
fn check_cgroup_empty() -> Result<(), String> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or("cgroup v2 unavailable")?;
    if relative.split('/').any(|part| part == "..") || !relative.ends_with("agent-bridge.service") {
        return Err("unexpected system service cgroup".into());
    }
    let path = Path::new("/sys/fs/cgroup").join(relative);
    let mut groups = vec![path];
    let own = std::process::id();
    while let Some(group) = groups.pop() {
        let processes = fs::read_to_string(group.join("cgroup.procs"))
            .map_err(|_| "service cgroup processes unavailable")?;
        for pid in processes.lines() {
            if pid.parse::<u32>().ok() != Some(own) {
                return Err("previous service processes still exist".into());
            }
        }
        for entry in fs::read_dir(group).map_err(|_| "service cgroup unavailable")? {
            let entry = entry.map_err(|_| "service cgroup unavailable")?;
            if entry
                .file_type()
                .map_err(|_| "service cgroup unavailable")?
                .is_dir()
            {
                groups.push(entry.path());
            }
        }
    }
    Ok(())
}

/// Runs the root-owned system service with one protected configuration path.
pub fn run_system(arguments: &[String]) -> ExitCode {
    match run_system_inner(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            bridge_core::service::log_event(
                "error",
                "system_service_failed",
                &[("detail", &error)],
            );
            ExitCode::FAILURE
        }
    }
}

/// Parses and starts the fixed system service.
fn run_system_inner(arguments: &[String]) -> Result<(), String> {
    let [path] = arguments else {
        return Err("expected one system configuration path".into());
    };
    let path = Path::new(path);
    trusted_root_file(path)?;
    let text = fs::read_to_string(path).map_err(|_| "system configuration unreadable")?;
    let config: SystemConfig = toml::from_str(&text).map_err(|_| "invalid system configuration")?;
    let scopes = validate_config(&config)?;
    for account in &config.accounts {
        check_passwd(account)?;
    }
    check_cgroup_empty()?;
    coordinate(config, scopes)
}

/// Bound ordinary calls independently from native hand-off and startup.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
/// The caller's hook deadline is three seconds; leave time for the response.
const HOOK_TIMEOUT: Duration = Duration::from_millis(2400);
/// A native hand-off can wait for its own receipt deadline.
const SEND_TIMEOUT: Duration = Duration::from_secs(65);
/// All coordinator request handlers and background jobs share this bound.
const MAX_JOBS: usize = 64;
/// Retain delayed evidence without allowing an unbounded in-memory index.
const MAX_TICKETS: usize = 4096;

/// A delayed observation waiting for the initial result or another observation.
enum TicketUpdate {
    Closed,
    Outcome(WireOutcome),
    Evidence {
        publisher: String,
        event_id: String,
        tier: EvidenceTier,
        detail: String,
    },
}

/// Source ownership and the entire immutable fence of a possible hand-off.
struct Ticket {
    source: u32,
    target: u32,
    fence: AttemptFence,
    initial: bool,
    processing: bool,
    callback_open: bool,
    updates: VecDeque<TicketUpdate>,
    hook: Option<(NativeAddress, u64)>,
}

/// Short-held coordinator state; no lock is retained during a worker RPC.
struct CoordinatorState {
    frozen: HashSet<NativeAddress>,
    busy: HashMap<NativeAddress, bool>,
    native_busy: HashSet<u32>,
    maintenance: HashSet<u32>,
    polling: HashSet<u32>,
    windows: BTreeMap<u32, VecDeque<NativeAddress>>,
    cursors: BTreeMap<u32, Option<NativeAddress>>,
    turns: HashMap<NativeAddress, u32>,
    tickets: HashMap<u64, Ticket>,
    next_ticket: u64,
}

/// Shared immutable peer mapping and bounded, separately locked state.
struct Coordinator {
    scopes: BTreeMap<Scope, u32>,
    links: BTreeMap<u32, Link>,
    state: Mutex<CoordinatorState>,
    changed: Condvar,
    fatal: AtomicBool,
    active: AtomicBool,
    starting: AtomicBool,
    stopping: Arc<AtomicBool>,
    jobs: AtomicUsize,
}

impl Coordinator {
    /// Closes admission after an IPC, protocol or coordinator failure.
    fn fail(&self) {
        self.fatal.store(true, Ordering::SeqCst);
        self.active.store(false, Ordering::SeqCst);
        self.changed.notify_all();
    }

    /// Looks up a validated native address using exact structured components.
    fn target(&self, address: &NativeAddress) -> Option<u32> {
        address.validate().ok()?;
        self.scopes
            .get(&Scope {
                host: address.host_id.clone(),
                harness: address.harness.as_str().to_owned(),
                namespace: address.native_store_namespace.clone(),
            })
            .copied()
    }

    /// Validates facts against the fixed worker identity before trusting them.
    fn valid_binding(&self, peer: u32, binding: &BindingFacts) -> bool {
        self.target(&binding.address) == Some(peer)
            && Attestation::verified(
                binding.address.clone(),
                binding.actor.clone(),
                binding.endpoint_epoch,
                binding.lifecycle,
                binding.capabilities,
                binding.proof_ref.clone(),
            )
            .is_ok()
    }

    /// Reserves one bounded task slot before spawning a thread.
    fn spawn(self: &Arc<Self>, task: impl FnOnce(Arc<Self>) + Send + 'static) -> bool {
        if self
            .jobs
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < MAX_JOBS).then_some(n + 1)
            })
            .is_err()
        {
            return false;
        }
        let shared = Arc::clone(self);
        let spawn = std::thread::Builder::new()
            .name("bridge-system-job".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    task(Arc::clone(&shared))
                }));
                if result.is_err() {
                    shared.fail();
                }
                shared.jobs.fetch_sub(1, Ordering::SeqCst);
                shared.changed.notify_all();
            });
        if spawn.is_err() {
            self.jobs.fetch_sub(1, Ordering::SeqCst);
            self.fail();
            return false;
        }
        true
    }

    /// Calls a fixed peer and converts transport uncertainty into service failure.
    fn call(&self, uid: u32, request: Request, timeout: Duration) -> Result<Response, ()> {
        let Some(link) = self.links.get(&uid) else {
            self.fail();
            return Err(());
        };
        match link.call(request, timeout) {
            Ok(response) => Ok(response),
            Err(_) => {
                self.fail();
                Err(())
            }
        }
    }

    /// Requires an explicit successful acknowledgement.
    fn ack(&self, uid: u32, request: Request, timeout: Duration) -> Result<(), ()> {
        match self.call(uid, request, timeout)? {
            Response::Ok {} => Ok(()),
            _ => {
                self.fail();
                Err(())
            }
        }
    }

    /// Releases a recipient and optional carrier slot after its immediate work.
    fn release(&self, address: &NativeAddress, target: Option<u32>) {
        if let Ok(mut state) = self.state.lock() {
            state.busy.remove(address);
            if let Some(uid) = target {
                state.native_busy.remove(&uid);
            }
            self.changed.notify_all();
        } else {
            self.fail();
        }
    }

    /// Checks whether an admitted job was invalidated by a binding change.
    fn current(&self, address: &NativeAddress) -> bool {
        match self.state.lock() {
            Ok(state) => {
                state.busy.get(address) == Some(&false)
                    && !state.frozen.contains(address)
                    && self.active.load(Ordering::SeqCst)
                    && !self.fatal.load(Ordering::SeqCst)
            }
            Err(_) => {
                self.fail();
                false
            }
        }
    }

    /// Allocates the correlation ticket before a payload can reach the target.
    fn ticket(
        &self,
        source: u32,
        target: u32,
        record: &AttemptRecord,
        initial: bool,
        hook: bool,
    ) -> Option<u64> {
        let mut state = self.state.lock().ok()?;
        let hook_target = if hook {
            let address = NativeAddress::parse(&record.fence.recipient).ok()?;
            if state.busy.get(&address) != Some(&false)
                || state.frozen.contains(&address)
                || !self.active.load(Ordering::SeqCst)
                || self.fatal.load(Ordering::SeqCst)
            {
                return None;
            }
            Some(address)
        } else {
            None
        };
        if state.tickets.len() >= MAX_TICKETS {
            return None;
        }
        let ticket = state.next_ticket;
        state.next_ticket = ticket.checked_add(1)?;
        state.tickets.insert(
            ticket,
            Ticket {
                source,
                target,
                fence: record.fence.clone(),
                initial,
                processing: false,
                callback_open: false,
                updates: VecDeque::new(),
                hook: hook_target.map(|address| (address, record.deadline_ms)),
            },
        );
        Some(ticket)
    }
}

/// A status account contains only process identities and nonsecret health.
#[derive(Serialize)]
struct AccountStatus {
    uid: u32,
    worker_pid: u32,
    relay_pid: u32,
    state: &'static str,
    version: &'static str,
}

/// Root-owned external status contract for the running systemd invocation.
#[derive(Serialize)]
struct ServiceStatus {
    version: u32,
    service_pid: u32,
    invocation_id: String,
    updated_unix_ms: u64,
    state: &'static str,
    accounts: BTreeMap<String, AccountStatus>,
}

/// Writes a mode-0600 snapshot through a protected directory and atomic rename.
fn write_status(status: &Mutex<ServiceStatus>) -> Result<(), String> {
    let directory = Path::new("/run/agent-bridge");
    let metadata = fs::symlink_metadata(directory).map_err(|_| "status directory unavailable")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("status directory is not root-owned and protected".into());
    }
    let mut status = status.lock().map_err(|_| "status state unavailable")?;
    status.updated_unix_ms = current_unix_millis();
    let temporary = directory.join(format!(".status-{}.tmp", status.invocation_id));
    let mut created = false;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "status snapshot creation failed")?;
        created = true;
        let meta = file.metadata().map_err(|_| "status metadata unavailable")?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 {
            return Err("status snapshot permissions are invalid");
        }
        serde_json::to_writer(&mut file, &*status).map_err(|_| "status serialization failed")?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_all())
            .map_err(|_| "status snapshot write failed")?;
        fs::rename(&temporary, directory.join("status.json"))
            .map_err(|_| "status snapshot replacement failed")?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(str::to_owned)
}

/// Owns the worker children and always kills and reaps them on early exit.
struct Children(Vec<Child>);

impl Children {
    /// Allows acknowledged workers a bounded interval to reap their own relays.
    fn wait(&mut self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut alive = false;
            for child in &mut self.0 {
                alive |= child
                    .try_wait()
                    .map_err(|_| "worker state unavailable")?
                    .is_none();
            }
            if !alive {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("worker shutdown timed out".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Children {
    /// Kills all remaining workers before waiting for any one of them.
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
        }
        for child in &mut self.0 {
            let _ = child.wait();
        }
    }
}

/// Launches exactly the configured account through the protected setpriv binary.
fn start_child(
    account: &Account,
    executable: &Path,
    generation: u64,
) -> Result<(Child, UnixStream), String> {
    let (parent, worker) = UnixStream::pair().map_err(|_| "worker channel unavailable")?;
    let worker_output = worker
        .try_clone()
        .map_err(|_| "worker channel unavailable")?;
    let tmp = account.home.join(".agent-bridge/tmp");
    let runtime = PathBuf::from(format!("/run/user/{}", account.uid));
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .args([
            "--reuid",
            &account.uid.to_string(),
            "--regid",
            &account.gid.to_string(),
            "--clear-groups",
            "--no-new-privs",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
        ])
        .arg(executable)
        .arg("--system-worker")
        .arg(&account.daemon_config)
        .arg(&account.interfaces_config)
        .arg(generation.to_string());
    if let Some(path) = &account.new_database {
        command.arg("--new-database").arg(path);
    }
    command
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", &tmp)
        .env("TMP", &tmp)
        .env("TEMP", &tmp)
        .env("XDG_RUNTIME_DIR", runtime)
        .stdin(Stdio::from(OwnedFd::from(worker)))
        .stdout(Stdio::from(OwnedFd::from(worker_output)))
        .process_group(0);
    let child = command
        .spawn()
        .map_err(|_| "worker process could not start")?;
    Ok((child, parent))
}

/// Confirms every kernel credential field after the worker has prepared.
fn verify_child(account: &Account, child: &mut Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|_| "worker state unavailable")?
        .is_some()
    {
        return Err("worker exited during startup".into());
    }
    let status = fs::read_to_string(format!("/proc/{}/status", child.id()))
        .map_err(|_| "worker kernel credentials unavailable")?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let ids_match = |name, expected: u32| {
        field(name).is_some_and(|value| {
            let ids: Vec<_> = value.split_whitespace().collect();
            ids.len() == 4
                && ids
                    .iter()
                    .all(|id| id.parse::<u32>().ok() == Some(expected))
        })
    };
    let no_caps = |name| field(name).is_some_and(|value| u64::from_str_radix(value, 16) == Ok(0));
    if !ids_match("Uid:", account.uid)
        || !ids_match("Gid:", account.gid)
        || !field("Groups:").is_some_and(str::is_empty)
        || !["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
            .into_iter()
            .all(no_caps)
        || field("NoNewPrivs:") != Some("1")
        || child
            .try_wait()
            .map_err(|_| "worker state unavailable")?
            .is_some()
    {
        return Err("worker credential check failed".into());
    }
    Ok(())
}

/// Runs each startup or shutdown phase concurrently without retaining state locks.
fn phase(
    shared: &Coordinator,
    request: impl Fn(u32) -> Request + Sync,
    timeout: Duration,
) -> Result<Vec<(u32, Response)>, String> {
    std::thread::scope(|scope| {
        let calls: Vec<_> = shared
            .links
            .keys()
            .map(|&uid| {
                let request = request(uid);
                scope.spawn(move || (uid, shared.call(uid, request, timeout)))
            })
            .collect();
        calls
            .into_iter()
            .map(|call| {
                let (uid, result) = call.join().map_err(|_| "worker phase panicked")?;
                result
                    .map(|response| (uid, response))
                    .map_err(|_| "worker phase failed".to_string())
            })
            .collect()
    })
}

/// Installs an update barrier, applies the verified binding everywhere and unfreezes only on full success.
fn apply_binding(shared: &Coordinator, peer: u32, binding: BindingFacts) -> Result<(), ()> {
    if !shared.valid_binding(peer, &binding) {
        shared.fail();
        return Err(());
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let target = binding.address.clone();
    {
        let mut state = shared.state.lock().map_err(|_| {
            shared.fail();
        })?;
        while state.frozen.contains(&target) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                shared.fail();
                return Err(());
            };
            let (next, wait) = shared.changed.wait_timeout(state, left).map_err(|_| {
                shared.fail();
            })?;
            state = next;
            if wait.timed_out() || shared.fatal.load(Ordering::SeqCst) {
                shared.fail();
                return Err(());
            }
        }
        state.frozen.insert(target.clone());
        if let Some(invalidated) = state.busy.get_mut(&target) {
            *invalidated = true;
        }
        while state.tickets.values().any(|ticket| {
            ticket
                .hook
                .as_ref()
                .is_some_and(|(address, _)| *address == target)
        }) {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                shared.fail();
                return Err(());
            };
            let (next, wait) = shared.changed.wait_timeout(state, left).map_err(|_| {
                shared.fail();
            })?;
            state = next;
            if wait.timed_out() || shared.fatal.load(Ordering::SeqCst) {
                shared.fail();
                return Err(());
            }
        }
    }
    let result: Result<(), ()> = (|| {
        for &uid in shared.links.keys() {
            let left = deadline.checked_duration_since(Instant::now()).ok_or(())?;
            shared.ack(
                uid,
                Request::Freeze {
                    target: target.clone(),
                },
                left,
            )?;
        }
        for &uid in shared.links.keys() {
            let left = deadline.checked_duration_since(Instant::now()).ok_or(())?;
            shared.ack(
                uid,
                Request::ApplyBinding {
                    binding: binding.clone(),
                    now_ms: current_unix_millis(),
                },
                left,
            )?;
        }
        for &uid in shared.links.keys() {
            let left = deadline.checked_duration_since(Instant::now()).ok_or(())?;
            shared.ack(
                uid,
                Request::Unfreeze {
                    target: target.clone(),
                },
                left,
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        shared.fail();
        return Err(());
    }
    let mut state = shared.state.lock().map_err(|_| {
        shared.fail();
    })?;
    state.frozen.remove(&target);
    shared.changed.notify_all();
    Ok(())
}

/// Checks the full source-produced fence and path before a payload is routed.
fn valid_attempt(
    record: &AttemptRecord,
    target: &NativeAddress,
    binding: &BindingFacts,
    state: AttemptState,
    mode: EffectiveMode,
) -> bool {
    record.state == state
        && record.effective_mode == mode
        && record.fence.recipient == target.to_canonical_string()
        && record.fence.endpoint_epoch == binding.endpoint_epoch
}

/// Records a stream of ticket observations in order without holding the index lock.
fn process_ticket(shared: &Coordinator, ticket: u64) {
    loop {
        let (source, update) = {
            let Ok(mut state) = shared.state.lock() else {
                shared.fail();
                return;
            };
            let Some(entry) = state.tickets.get_mut(&ticket) else {
                shared.fail();
                return;
            };
            let Some(update) = entry.updates.pop_front() else {
                entry.processing = false;
                return;
            };
            (entry.source, update)
        };
        if matches!(update, TicketUpdate::Closed) {
            let Ok(mut state) = shared.state.lock() else {
                shared.fail();
                return;
            };
            let Some(entry) = state.tickets.get(&ticket) else {
                shared.fail();
                return;
            };
            if entry.initial
                || !entry.callback_open
                || entry.hook.is_some()
                || !entry.updates.is_empty()
            {
                shared.fail();
                return;
            }
            state.tickets.remove(&ticket);
            return;
        }
        let (request, terminal, callback_open) =
            match update {
                TicketUpdate::Closed => unreachable!(),
                TicketUpdate::Outcome(outcome) => {
                    let terminal = !matches!(
                        outcome,
                        WireOutcome::NativeHeld { .. } | WireOutcome::WrittenNoReceipt { .. }
                    );
                    let fence = match shared.state.lock().ok().and_then(|state| {
                        state.tickets.get(&ticket).map(|entry| entry.fence.clone())
                    }) {
                        Some(fence) => fence,
                        None => {
                            shared.fail();
                            return;
                        }
                    };
                    (
                        Request::RecordOutcome {
                            fence,
                            outcome,
                            now_ms: current_unix_millis(),
                        },
                        terminal,
                        !terminal,
                    )
                }
                TicketUpdate::Evidence {
                    publisher,
                    event_id,
                    tier,
                    detail,
                } => {
                    let terminal = tier != EvidenceTier::ReceiptTokenPossession;
                    let fence = match shared.state.lock().ok().and_then(|state| {
                        state.tickets.get(&ticket).map(|entry| entry.fence.clone())
                    }) {
                        Some(fence) => fence,
                        None => {
                            shared.fail();
                            return;
                        }
                    };
                    (
                        Request::RecordEvidence {
                            publisher,
                            event_id,
                            fence,
                            tier,
                            detail,
                            now_ms: current_unix_millis(),
                        },
                        terminal,
                        false,
                    )
                }
            };
        if shared.ack(source, request, RPC_TIMEOUT).is_err() {
            return;
        }
        if callback_open {
            let Ok(mut state) = shared.state.lock() else {
                shared.fail();
                return;
            };
            let Some(entry) = state.tickets.get_mut(&ticket) else {
                shared.fail();
                return;
            };
            entry.callback_open = true;
        }
        if terminal {
            let Ok(mut state) = shared.state.lock() else {
                shared.fail();
                return;
            };
            let Some(entry) = state.tickets.remove(&ticket) else {
                shared.fail();
                return;
            };
            if !entry.updates.is_empty() {
                shared.fail();
            }
            if let Some((address, _)) = entry.hook {
                state.busy.remove(&address);
            }
            shared.changed.notify_all();
            return;
        }
    }
}

/// Authenticates a callback using the fixed peer, source and every fence field.
fn observe_ticket(
    shared: &Arc<Coordinator>,
    peer: u32,
    source: u32,
    ticket: u64,
    fence: AttemptFence,
    update: TicketUpdate,
) {
    let run = {
        let Ok(mut state) = shared.state.lock() else {
            shared.fail();
            return;
        };
        let Some(entry) = state.tickets.get_mut(&ticket) else {
            shared.fail();
            return;
        };
        if entry.target != peer
            || entry.source != source
            || entry.fence != fence
            || entry.updates.len() >= 16
        {
            shared.fail();
            return;
        }
        entry.updates.push_back(update);
        if entry.initial || entry.processing {
            false
        } else {
            entry.processing = true;
            true
        }
    };
    if run && !shared.spawn(move |shared| process_ticket(&shared, ticket)) {
        shared.fail();
    }
}

/// Places the immediate native outcome before callbacks that raced its response.
fn initial_outcome(shared: &Coordinator, ticket: u64, outcome: WireOutcome) {
    let run = {
        let Ok(mut state) = shared.state.lock() else {
            shared.fail();
            return;
        };
        let Some(entry) = state.tickets.get_mut(&ticket) else {
            shared.fail();
            return;
        };
        if !entry.initial {
            shared.fail();
            return;
        }
        entry.initial = false;
        entry.updates.push_front(TicketUpdate::Outcome(outcome));
        if entry.processing {
            false
        } else {
            entry.processing = true;
            true
        }
    };
    if run {
        process_ticket(shared, ticket);
    }
}

/// Selects at most one source for a genuine hook, never continuing after an uncertain RPC.
fn drain_hook(shared: &Coordinator, peer: u32, binding: BindingFacts) -> Result<Response, ()> {
    if !shared.valid_binding(peer, &binding) {
        shared.fail();
        return Err(());
    }
    let target = binding.address.clone();
    let idle = || Response::HookAttempt {
        source_uid: 0,
        ticket: 0,
        attempt: None,
    };
    let sources = {
        let mut state = shared.state.lock().map_err(|_| {
            shared.fail();
        })?;
        if !shared.active.load(Ordering::SeqCst)
            || state.frozen.contains(&target)
            || state.busy.contains_key(&target)
            || state.tickets.len() >= MAX_TICKETS
        {
            return Ok(idle());
        }
        state.busy.insert(target.clone(), false);
        let previous = state.turns.get(&target).copied().unwrap_or(0);
        let mut sources: Vec<_> = shared.links.keys().copied().collect();
        let pivot = sources.iter().position(|uid| *uid > previous).unwrap_or(0);
        sources.rotate_left(pivot);
        sources
    };
    let deadline = Instant::now() + HOOK_TIMEOUT;
    let timing = DispatchTiming::default();
    for source in sources {
        if !shared.current(&target) {
            break;
        }
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            break;
        };
        match shared.call(
            source,
            Request::DrainInject {
                binding: binding.clone(),
                now_ms: current_unix_millis(),
                lease_ms: timing.lease_ms,
                handoff_ms: timing.handoff_ms,
            },
            left,
        )? {
            Response::Attempt {
                attempt: Some(record),
            } => {
                if !valid_attempt(
                    &record,
                    &target,
                    &binding,
                    AttemptState::Invoking,
                    EffectiveMode::Inject,
                ) {
                    shared.fail();
                    return Err(());
                }
                let ticket = shared.ticket(source, peer, &record, false, true);
                let Some(ticket) = ticket else {
                    if shared.current(&target) {
                        shared.fail();
                        return Err(());
                    }
                    shared.ack(
                        source,
                        Request::RecordOutcome {
                            fence: record.fence.clone(),
                            outcome: WireOutcome::DeferredKnownUnsent {
                                evidence: "binding changed before hook handoff".into(),
                            },
                            now_ms: current_unix_millis(),
                        },
                        RPC_TIMEOUT,
                    )?;
                    shared.release(&target, None);
                    return Ok(idle());
                };
                if let Ok(mut state) = shared.state.lock() {
                    if state.turns.len() >= MAX_TICKETS && !state.turns.contains_key(&target) {
                        state.turns.clear();
                    }
                    state.turns.insert(target.clone(), source);
                } else {
                    shared.fail();
                    return Err(());
                }
                return Ok(Response::HookAttempt {
                    source_uid: source,
                    ticket,
                    attempt: Some(record),
                });
            }
            Response::Attempt { attempt: None } | Response::Held { .. } => {}
            _ => {
                shared.fail();
                return Err(());
            }
        }
    }
    shared.release(&target, None);
    Ok(idle())
}

/// Dispatches one selected message through attest, reserve, re-attest, invoke and one send.
fn dispatch_message(shared: &Coordinator, source: u32, target_uid: u32, target: NativeAddress) {
    let result = (|| -> Result<(), ()> {
        let first = match shared.call(
            target_uid,
            Request::AttestMessage {
                target: target.clone(),
            },
            RPC_TIMEOUT,
        )? {
            Response::Binding { binding } => binding,
            Response::Held { .. } | Response::Failed {} => {
                shared.ack(
                    source,
                    Request::RecordHold {
                        target: target.clone(),
                        reason: "target unavailable".into(),
                        now_ms: current_unix_millis(),
                    },
                    RPC_TIMEOUT,
                )?;
                return Ok(());
            }
            _ => {
                shared.fail();
                return Err(());
            }
        };
        if first.address != target || !shared.valid_binding(target_uid, &first) {
            shared.fail();
            return Err(());
        }
        if !shared.current(&target) {
            return Ok(());
        }
        let timing = DispatchTiming::default();
        let reserved = match shared.call(
            source,
            Request::ReserveMessage {
                binding: first.clone(),
                now_ms: current_unix_millis(),
                lease_ms: timing.lease_ms,
                handoff_ms: timing.handoff_ms,
            },
            RPC_TIMEOUT,
        )? {
            Response::Attempt {
                attempt: Some(record),
            } => record,
            Response::Attempt { attempt: None } | Response::Held { .. } => return Ok(()),
            _ => {
                shared.fail();
                return Err(());
            }
        };
        if !valid_attempt(
            &reserved,
            &target,
            &first,
            AttemptState::Reserved,
            EffectiveMode::Message,
        ) {
            shared.fail();
            return Err(());
        }
        let fresh = if shared.current(&target) {
            match shared.call(
                target_uid,
                Request::AttestMessage {
                    target: target.clone(),
                },
                RPC_TIMEOUT,
            ) {
                Ok(Response::Binding { binding })
                    if binding.address == target && shared.valid_binding(target_uid, &binding) =>
                {
                    Some(binding)
                }
                Ok(Response::Held { .. } | Response::Failed {}) | Err(()) => None,
                _ => {
                    shared.fail();
                    None
                }
            }
        } else {
            None
        };
        let Some(fresh) = fresh.filter(|_| shared.current(&target)) else {
            shared.ack(
                source,
                Request::ReleaseAttempt {
                    fence: reserved.fence.clone(),
                },
                RPC_TIMEOUT,
            )?;
            return Ok(());
        };
        let invoking = match shared.call(
            source,
            Request::MarkInvoking {
                fence: reserved.fence.clone(),
                binding: fresh.clone(),
                now_ms: current_unix_millis(),
            },
            RPC_TIMEOUT,
        )? {
            Response::Attempt {
                attempt: Some(record),
            } => record,
            Response::Released { .. } => return Ok(()),
            _ => {
                shared.fail();
                return Err(());
            }
        };
        if invoking.fence != reserved.fence
            || !valid_attempt(
                &invoking,
                &target,
                &fresh,
                AttemptState::Invoking,
                EffectiveMode::Message,
            )
        {
            shared.fail();
            return Err(());
        }
        if !shared.current(&target) {
            shared.ack(
                source,
                Request::RecordOutcome {
                    fence: invoking.fence.clone(),
                    outcome: WireOutcome::DeferredKnownUnsent {
                        evidence: "binding changed before native handoff".into(),
                    },
                    now_ms: current_unix_millis(),
                },
                RPC_TIMEOUT,
            )?;
            return Ok(());
        }
        let Some(ticket) = shared.ticket(source, target_uid, &invoking, true, false) else {
            shared.fail();
            return Err(());
        };
        match shared.call(
            target_uid,
            Request::SendMessage {
                source_uid: source,
                ticket,
                binding: fresh,
                attempt: invoking,
            },
            SEND_TIMEOUT,
        )? {
            Response::Outcome { outcome } => initial_outcome(shared, ticket, outcome),
            _ => {
                shared.fail();
                return Err(());
            }
        }
        Ok(())
    })();
    if result.is_err() {
        shared.fail();
    }
    shared.release(&target, Some(target_uid));
}

/// Processes bounded inbound callbacks while startup and normal calls remain reentrant.
fn dispatch_incoming(shared: Arc<Coordinator>, incoming: mpsc::Receiver<Incoming>) {
    loop {
        if shared.stopping.load(Ordering::SeqCst) && shared.starting.load(Ordering::SeqCst) {
            for link in shared.links.values() {
                link.close();
            }
            break;
        }
        if shared.fatal.load(Ordering::SeqCst) {
            break;
        }
        let input = match incoming.recv_timeout(Duration::from_millis(100)) {
            Ok(input) => input,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => {
                shared.fail();
                break;
            }
        };
        match input {
            Incoming::Closed { peer_uid } => {
                if !shared.links.contains_key(&peer_uid) || !shared.stopping.load(Ordering::SeqCst)
                {
                    shared.fail();
                }
                break;
            }
            Incoming::Request {
                peer_uid,
                request_id,
                request,
            } => {
                if !shared.spawn(move |shared| {
                    let response = match request {
                        Request::ApplyBinding { binding, .. } => {
                            apply_binding(&shared, peer_uid, binding).map(|()| Response::Ok {})
                        }
                        Request::HookDrain { binding } => drain_hook(&shared, peer_uid, binding),
                        _ => {
                            shared.fail();
                            Err(())
                        }
                    };
                    if let Some(link) = shared.links.get(&peer_uid) {
                        if link
                            .respond(request_id, response.unwrap_or(Response::Failed {}))
                            .is_err()
                        {
                            shared.fail();
                        }
                    } else {
                        shared.fail();
                    }
                }) {
                    shared.fail();
                    break;
                }
            }
            Incoming::Event { peer_uid, event } => match event {
                Event::Hello {} | Event::Ready {} => {}
                Event::HookFinished {
                    source_uid,
                    ticket,
                    fence,
                    outcome,
                }
                | Event::LateOutcome {
                    source_uid,
                    ticket,
                    fence,
                    outcome,
                } => observe_ticket(
                    &shared,
                    peer_uid,
                    source_uid,
                    ticket,
                    fence,
                    TicketUpdate::Outcome(outcome),
                ),
                Event::LateEvidence {
                    source_uid,
                    ticket,
                    publisher,
                    event_id,
                    fence,
                    tier,
                    detail,
                } => observe_ticket(
                    &shared,
                    peer_uid,
                    source_uid,
                    ticket,
                    fence,
                    TicketUpdate::Evidence {
                        publisher,
                        event_id,
                        tier,
                        detail,
                    },
                ),
                Event::CallbackClosed {
                    source_uid,
                    ticket,
                    fence,
                } => observe_ticket(
                    &shared,
                    peer_uid,
                    source_uid,
                    ticket,
                    fence,
                    TicketUpdate::Closed,
                ),
                _ => shared.fail(),
            },
        }
    }
}

/// Refreshes one source's bounded work window and rotating cursor.
fn poll_source(shared: &Coordinator, source: u32, after: Option<NativeAddress>) {
    let response = shared.call(
        source,
        Request::ListWork {
            now_ms: current_unix_millis(),
            limit: 16,
            after,
        },
        RPC_TIMEOUT,
    );
    let Ok(mut state) = shared.state.lock() else {
        shared.fail();
        return;
    };
    state.polling.remove(&source);
    match response {
        Ok(Response::Work { recipients }) if recipients.len() <= 16 => {
            let next = recipients.last().cloned();
            state.cursors.insert(source, next);
            state
                .windows
                .insert(source, recipients.into_iter().collect());
        }
        _ => shared.fail(),
    }
}

/// Schedules independent maintenance and fair source windows without waiting for carriers.
fn schedule(shared: &Arc<Coordinator>) {
    let mut maintenance_due = Instant::now();
    let mut poll_due = Instant::now();
    while !shared.fatal.load(Ordering::SeqCst) && !shared.stopping.load(Ordering::SeqCst) {
        if shared.links.values().any(Link::is_closed) {
            shared.fail();
            break;
        }
        let now = Instant::now();
        if now >= maintenance_due {
            maintenance_due = now + Duration::from_secs(1);
            for &uid in shared.links.keys() {
                let admitted = shared
                    .state
                    .lock()
                    .map(|mut state| state.maintenance.insert(uid))
                    .unwrap_or(false);
                if admitted
                    && !shared.spawn(move |shared| {
                        let _ = shared.ack(
                            uid,
                            Request::Maintenance {
                                now_ms: current_unix_millis(),
                            },
                            RPC_TIMEOUT,
                        );
                        if let Ok(mut state) = shared.state.lock() {
                            state.maintenance.remove(&uid);
                        } else {
                            shared.fail();
                        }
                    })
                {
                    if let Ok(mut state) = shared.state.lock() {
                        state.maintenance.remove(&uid);
                    } else {
                        shared.fail();
                    }
                }
            }
        }
        if now >= poll_due {
            poll_due = now + Duration::from_millis(300);
            for &uid in shared.links.keys() {
                let cursor = match shared.state.lock() {
                    Ok(mut state) => {
                        if state.windows.get(&uid).is_none_or(VecDeque::is_empty)
                            && state.polling.insert(uid)
                        {
                            Some(state.cursors.get(&uid).cloned().unwrap_or(None))
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        shared.fail();
                        None
                    }
                };
                if let Some(cursor) = cursor
                    && !shared.spawn(move |shared| poll_source(&shared, uid, cursor))
                {
                    if let Ok(mut state) = shared.state.lock() {
                        state.polling.remove(&uid);
                    } else {
                        shared.fail();
                    }
                }
            }
        }
        let selected = {
            let Ok(mut state) = shared.state.lock() else {
                shared.fail();
                break;
            };
            if state.tickets.values().any(|ticket| {
                ticket
                    .hook
                    .as_ref()
                    .is_some_and(|(_, deadline)| *deadline <= current_unix_millis())
            }) {
                // The hook may still be flushing; only stopping its worker makes another handoff safe.
                shared.fail();
                break;
            }
            let mut candidates: HashMap<NativeAddress, Vec<u32>> = HashMap::new();
            for (&source, window) in &state.windows {
                for target in window {
                    if shared.target(target).is_some() {
                        candidates.entry(target.clone()).or_default().push(source);
                    }
                }
            }
            let mut selected = Vec::new();
            if state.tickets.len() < MAX_TICKETS {
                for (target, mut sources) in candidates {
                    let Some(uid) = shared.target(&target) else {
                        continue;
                    };
                    if state.frozen.contains(&target)
                        || state.busy.contains_key(&target)
                        || state.native_busy.contains(&uid)
                    {
                        continue;
                    }
                    sources.sort_unstable();
                    sources.dedup();
                    let previous = state.turns.get(&target).copied().unwrap_or(0);
                    let source = sources
                        .iter()
                        .copied()
                        .find(|source| *source > previous)
                        .unwrap_or(sources[0]);
                    if let Some(window) = state.windows.get_mut(&source)
                        && let Some(index) = window.iter().position(|address| *address == target)
                    {
                        window.remove(index);
                    }
                    if state.turns.len() >= MAX_TICKETS && !state.turns.contains_key(&target) {
                        state.turns.clear();
                    }
                    state.turns.insert(target.clone(), source);
                    state.busy.insert(target.clone(), false);
                    state.native_busy.insert(uid);
                    selected.push((source, uid, target));
                }
            }
            // Advance past unavailable recipients so one slow carrier cannot pin a whole window.
            let busy: HashSet<_> = state
                .busy
                .keys()
                .chain(state.frozen.iter())
                .cloned()
                .collect();
            let native_busy = state.native_busy.clone();
            for window in state.windows.values_mut() {
                window.retain(|target| {
                    !busy.contains(target)
                        && shared
                            .target(target)
                            .is_some_and(|uid| !native_busy.contains(&uid))
                });
            }
            selected
        };
        for (source, uid, target) in selected {
            let cleanup = target.clone();
            if !shared.spawn(move |shared| dispatch_message(&shared, source, uid, target)) {
                shared.release(&cleanup, Some(uid));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Runs one generation, stops the whole unit on any worker failure, and reaps every child.
fn coordinate(config: SystemConfig, scopes: BTreeMap<Scope, u32>) -> Result<(), String> {
    let invocation =
        std::env::var("INVOCATION_ID").map_err(|_| "systemd invocation unavailable")?;
    if invocation.len() != 32
        || !invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
        || invocation.bytes().all(|byte| byte == b'0')
    {
        return Err("invalid systemd invocation".into());
    }
    let generation = u64::from_str_radix(&invocation[..16], 16)
        .map_err(|_| "invalid invocation")?
        ^ u64::from_str_radix(&invocation[16..], 16).map_err(|_| "invalid invocation")?;
    let generation = generation.max(1);
    let executable = std::env::current_exe().map_err(|_| "worker executable unavailable")?;
    trusted_root_file(&executable)?;
    trusted_root_file(Path::new("/usr/bin/setpriv"))?;
    let stopped = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stopped))
        .map_err(|_| "signal handler unavailable")?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stopped))
        .map_err(|_| "signal handler unavailable")?;
    let status = Arc::new(Mutex::new(ServiceStatus {
        version: 1,
        service_pid: std::process::id(),
        invocation_id: invocation,
        updated_unix_ms: 0,
        state: "starting",
        accounts: config
            .accounts
            .iter()
            .map(|account| {
                (
                    account.name.clone(),
                    AccountStatus {
                        uid: account.uid,
                        worker_pid: 0,
                        relay_pid: 0,
                        state: "starting",
                        version: env!("CARGO_PKG_VERSION"),
                    },
                )
            })
            .collect(),
    }));
    write_status(&status)?;
    let (sender, receiver) = mpsc::sync_channel(64);
    let mut children = Children(Vec::new());
    let mut links = BTreeMap::new();
    let launched = (|| -> Result<(), String> {
        for account in &config.accounts {
            if stopped.load(Ordering::SeqCst) {
                return Err("startup interrupted".into());
            }
            let (child, stream) = start_child(account, &executable, generation)?;
            if let Ok(mut status) = status.lock() {
                if let Some(entry) = status.accounts.get_mut(&account.name) {
                    entry.worker_pid = child.id();
                }
            } else {
                return Err("status state unavailable".into());
            }
            children.0.push(child);
            links.insert(
                account.uid,
                Link::new(stream, generation, account.uid, sender.clone())
                    .map_err(str::to_owned)?,
            );
        }
        Ok(())
    })();
    if let Err(error) = launched {
        if let Ok(mut status) = status.lock() {
            status.state = "failed";
            for account in status.accounts.values_mut() {
                account.state = "failed";
            }
        }
        let _ = write_status(&status);
        return Err(error);
    }
    drop(sender);
    let shared = Arc::new(Coordinator {
        scopes,
        links,
        state: Mutex::new(CoordinatorState {
            frozen: HashSet::new(),
            busy: HashMap::new(),
            native_busy: HashSet::new(),
            maintenance: HashSet::new(),
            polling: HashSet::new(),
            windows: BTreeMap::new(),
            cursors: BTreeMap::new(),
            turns: HashMap::new(),
            tickets: HashMap::new(),
            next_ticket: 1,
        }),
        changed: Condvar::new(),
        fatal: AtomicBool::new(false),
        active: AtomicBool::new(false),
        starting: AtomicBool::new(true),
        stopping: Arc::clone(&stopped),
        jobs: AtomicUsize::new(0),
    });
    let dispatcher = {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || dispatch_incoming(shared, receiver))
    };
    let status_done = Arc::new(AtomicBool::new(false));
    let status_thread = {
        let shared = Arc::clone(&shared);
        let status = Arc::clone(&status);
        let done = Arc::clone(&status_done);
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                if write_status(&status).is_err() {
                    shared.fail();
                    break;
                }
                for _ in 0..20 {
                    if done.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        })
    };
    let run = (|| -> Result<(), String> {
        let prepared = phase(
            &shared,
            |_| Request::Prepare { epoch: generation },
            Duration::from_secs(60),
        )?;
        let mut max_epoch = 0;
        for (uid, response) in prepared {
            let Some(account) = config.accounts.iter().find(|account| account.uid == uid) else {
                return Err("unknown prepared worker".into());
            };
            let Response::Prepared {
                uid: actual,
                max_epoch: epoch,
                scopes: actual_scopes,
            } = response
            else {
                return Err("worker preparation refused".into());
            };
            let expected: HashSet<_> = account
                .scopes
                .iter()
                .map(|scope| {
                    (
                        scope.host.clone(),
                        scope.harness.clone(),
                        scope.namespace.clone(),
                    )
                })
                .collect();
            let actual_set: HashSet<_> = actual_scopes.iter().cloned().collect();
            if actual != uid || actual_set != expected || actual_set.len() != actual_scopes.len() {
                return Err("worker scopes differ from configured scopes".into());
            }
            max_epoch = max_epoch.max(epoch);
        }
        for (account, child) in config.accounts.iter().zip(&mut children.0) {
            verify_child(account, child)?;
        }
        let ready = phase(
            &shared,
            |_| Request::SetEpochFloor { epoch: max_epoch },
            Duration::from_secs(60),
        )?;
        {
            let mut status = status.lock().map_err(|_| "status state unavailable")?;
            for (uid, response) in ready {
                let Response::Ready { relay_pid } = response else {
                    return Err("worker initialization refused".into());
                };
                if relay_pid == 0 {
                    return Err("worker relay is unavailable".into());
                }
                let account = config
                    .accounts
                    .iter()
                    .find(|account| account.uid == uid)
                    .ok_or("unknown ready worker")?;
                let entry = status
                    .accounts
                    .get_mut(&account.name)
                    .ok_or("missing account status")?;
                entry.relay_pid = relay_pid;
            }
        }
        for (_, response) in phase(&shared, |_| Request::Activate {}, Duration::from_secs(60))? {
            if !matches!(response, Response::Ok {}) {
                return Err("worker activation refused".into());
            }
        }
        if shared.fatal.load(Ordering::SeqCst) || stopped.load(Ordering::SeqCst) {
            return Err("startup interrupted".into());
        }
        {
            let mut status = status.lock().map_err(|_| "status state unavailable")?;
            status.state = "ready";
            for account in status.accounts.values_mut() {
                account.state = "ready";
            }
        }
        write_status(&status)?;
        shared.active.store(true, Ordering::SeqCst);
        shared.starting.store(false, Ordering::SeqCst);
        schedule(&shared);
        if shared.fatal.load(Ordering::SeqCst) {
            return Err("worker or coordinator failed".into());
        }
        shared.active.store(false, Ordering::SeqCst);
        // The workers fence new ingress before the bounded drain of admitted jobs.
        for (_, response) in phase(&shared, |_| Request::Quiesce {}, RPC_TIMEOUT)? {
            if !matches!(response, Response::Ok {}) {
                return Err("worker quiesce refused".into());
            }
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline && !shared.fatal.load(Ordering::SeqCst) {
            let hooks = match shared.state.lock() {
                Ok(state) => state.tickets.values().any(|ticket| ticket.hook.is_some()),
                Err(_) => {
                    shared.fail();
                    break;
                }
            };
            if shared.jobs.load(Ordering::SeqCst) == 0 && !hooks {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if shared.fatal.load(Ordering::SeqCst) {
            return Err("worker failed during shutdown".into());
        }
        for (_, response) in phase(&shared, |_| Request::Stop {}, RPC_TIMEOUT)? {
            if !matches!(response, Response::Ok {}) {
                return Err("worker stop refused".into());
            }
        }
        children.wait(Duration::from_secs(5))?;
        Ok(())
    })();
    shared.active.store(false, Ordering::SeqCst);
    for link in shared.links.values() {
        link.close();
    }
    shared.fatal.store(true, Ordering::SeqCst);
    let _ = dispatcher.join();
    status_done.store(true, Ordering::SeqCst);
    let _ = status_thread.join();
    if let Ok(mut status) = status.lock() {
        status.state = if run.is_ok() { "stopped" } else { "failed" };
        let final_state = status.state;
        for account in status.accounts.values_mut() {
            account.state = final_state;
        }
    }
    let final_status = write_status(&status);
    drop(children);
    run.and(final_status)
}

/// Starts a same-user worker with its inherited private coordinator connection.
pub fn run_worker(arguments: &[String]) -> ExitCode {
    let (daemon, interfaces, generation, new_database) = match arguments {
        [daemon, interfaces, generation] => (daemon, interfaces, generation, None),
        [daemon, interfaces, generation, flag, path] if flag == "--new-database" => {
            (daemon, interfaces, generation, Some(Path::new(path)))
        }
        _ => {
            eprintln!("bridge-native-daemon: invalid system worker arguments");
            return ExitCode::FAILURE;
        }
    };
    let Ok(generation) = generation.parse::<u64>() else {
        eprintln!("bridge-native-daemon: invalid system worker generation");
        return ExitCode::FAILURE;
    };
    let result = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(UnixStream::from)
        .map_err(|_| "worker channel unavailable".to_string())
        .and_then(|stream| {
            let peer = crate::os::peer_identity(&stream)
                .map_err(|_| "worker parent identity unavailable".to_string())?;
            let parent = crate::os::process_facts(std::process::id())
                .and_then(|facts| facts.parent)
                .ok_or_else(|| "worker parent unavailable".to_string())?;
            if peer.uid != 0 || peer.pid != parent {
                return Err("worker channel is not owned by its root parent".into());
            }
            crate::system_worker::run(
                Path::new(daemon),
                Path::new(interfaces),
                generation,
                stream,
                new_database,
            )
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            bridge_core::service::log_event("error", "system_worker_failed", &[("detail", &error)]);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic socketpairs exercise routing and callback ownership only.
    use super::*;
    use bridge_core::dispatch::{Capabilities, Lifecycle, MemberRef};

    /// Fresh stores are explicit and must remain within the account's Bridge home.
    #[test]
    fn fresh_database_is_limited_to_its_account() {
        let mut config = SystemConfig {
            version: 1,
            accounts: vec![Account {
                name: "agent".into(),
                uid: 1001,
                gid: 1001,
                home: "/home/agent".into(),
                daemon_config: "/home/agent/.agent-bridge/daemon.toml".into(),
                interfaces_config: "/home/agent/.agent-bridge/interfaces.toml".into(),
                new_database: Some("/home/agent/.agent-bridge/system.db".into()),
                scopes: vec![Scope {
                    host: "host".into(),
                    harness: "codex".into(),
                    namespace: "store".into(),
                }],
            }],
        };
        assert!(validate_config(&config).is_ok());
        config.accounts[0].new_database = Some("/home/agent/.agent-bridge/../outside.db".into());
        assert!(validate_config(&config).is_err());
        config.accounts[0].new_database = Some("/home/other/.agent-bridge/system.db".into());
        assert!(validate_config(&config).is_err());
    }

    /// Builds one fixed-address binding without a live native process.
    fn binding() -> BindingFacts {
        BindingFacts {
            address: NativeAddress::new("host", Harness::CLAUDE_CODE, "store/one", "session")
                .unwrap(),
            actor: "session".into(),
            endpoint_epoch: 1,
            lifecycle: Lifecycle::Inactive,
            capabilities: Capabilities {
                inject: false,
                message: true,
            },
            proof_ref: "proof".into(),
        }
    }

    /// Builds the same source attempt in either reservation state.
    fn attempt(binding: &BindingFacts, state: AttemptState) -> Box<AttemptRecord> {
        Box::new(AttemptRecord {
            fence: AttemptFence {
                attempt_seq: 1,
                recipient: binding.address.to_canonical_string(),
                endpoint_epoch: 1,
                manifest_hash: "hash".into(),
            },
            state,
            requested_mode: bridge_core::Mode::Message,
            effective_mode: EffectiveMode::Message,
            actor: "session".into(),
            proof_ref: "proof".into(),
            granted: "message".into(),
            members: vec![MemberRef {
                publisher: "source".into(),
                event_id: "event".into(),
                envelope_hash: "hash".into(),
            }],
            manifest: "payload".into(),
            deadline_ms: current_unix_millis() + 60_000,
            lease_expires_ms: None,
            recheck_ms: None,
            duplicate_risk: false,
            created_ms: 0,
            updated_ms: 0,
            note: None,
        })
    }

    /// Creates an isolated coordinator with a fixed namespace and no OS processes.
    fn coordinator(links: BTreeMap<u32, Link>) -> Arc<Coordinator> {
        let mut scopes = BTreeMap::new();
        scopes.insert(
            Scope {
                host: "host".into(),
                harness: Harness::CLAUDE_CODE.as_str().into(),
                namespace: "store/one".into(),
            },
            2000,
        );
        Arc::new(Coordinator {
            scopes,
            links,
            state: Mutex::new(CoordinatorState {
                frozen: HashSet::new(),
                busy: HashMap::new(),
                native_busy: HashSet::new(),
                maintenance: HashSet::new(),
                polling: HashSet::new(),
                windows: BTreeMap::new(),
                cursors: BTreeMap::new(),
                turns: HashMap::new(),
                tickets: HashMap::new(),
                next_ticket: 1,
            }),
            changed: Condvar::new(),
            fatal: AtomicBool::new(false),
            active: AtomicBool::new(true),
            starting: AtomicBool::new(false),
            stopping: Arc::new(AtomicBool::new(false)),
            jobs: AtomicUsize::new(0),
        })
    }

    /// Scope lookup and callbacks are fenced by the actual fixed peer and every fence field.
    #[test]
    fn exact_scope_and_forged_ticket_are_refused() {
        let shared = coordinator(BTreeMap::new());
        let binding = binding();
        assert_eq!(shared.target(&binding.address), Some(2000));
        let mut wrong = binding.address.clone();
        wrong.native_store_namespace = "store".into();
        assert_eq!(shared.target(&wrong), None);
        assert!(shared.valid_binding(2000, &binding));
        assert!(!shared.valid_binding(1000, &binding));
        let record = attempt(&binding, AttemptState::Invoking);
        shared
            .state
            .lock()
            .unwrap()
            .busy
            .insert(binding.address.clone(), false);
        let ticket = shared.ticket(1000, 2000, &record, false, true).unwrap();
        observe_ticket(
            &shared,
            1000,
            1000,
            ticket,
            record.fence.clone(),
            TicketUpdate::Outcome(WireOutcome::NativeAccepted {
                evidence: "forged".into(),
            }),
        );
        assert!(shared.fatal.load(Ordering::SeqCst));
        assert!(shared.state.lock().unwrap().tickets.contains_key(&ticket));
    }

    /// Exercises a callback racing the response while routing through two fake workers.
    fn check_racing_callback(close_callback: bool) {
        let (incoming_tx, incoming_rx) = mpsc::sync_channel(64);
        let (source_coord, source_worker) = UnixStream::pair().unwrap();
        let (target_coord, target_worker) = UnixStream::pair().unwrap();
        let mut links = BTreeMap::new();
        links.insert(
            1000,
            Link::new(source_coord, 7, 1000, incoming_tx.clone()).unwrap(),
        );
        links.insert(2000, Link::new(target_coord, 7, 2000, incoming_tx).unwrap());
        let (source_tx, source_rx) = mpsc::sync_channel(8);
        let (target_tx, target_rx) = mpsc::sync_channel(8);
        let source = Link::new(source_worker, 7, 0, source_tx).unwrap();
        let target = Link::new(target_worker, 7, 0, target_tx).unwrap();
        let shared = coordinator(links);
        let binding = binding();
        {
            let mut state = shared.state.lock().unwrap();
            state.busy.insert(binding.address.clone(), false);
            state.native_busy.insert(2000);
        }
        let (observed_tx, observed_rx) = mpsc::sync_channel(4);
        let (finish_source_tx, finish_source_rx) = mpsc::channel();
        let (finish_target_tx, finish_target_rx) = mpsc::channel();
        let source_binding = binding.clone();
        let source_thread = std::thread::spawn(move || {
            loop {
                let Incoming::Request {
                    request_id,
                    request,
                    ..
                } = source_rx.recv_timeout(Duration::from_secs(3)).unwrap()
                else {
                    panic!("source request")
                };
                let response = match request {
                    Request::ReserveMessage { .. } => Response::Attempt {
                        attempt: Some(attempt(&source_binding, AttemptState::Reserved)),
                    },
                    Request::MarkInvoking { .. } => Response::Attempt {
                        attempt: Some(attempt(&source_binding, AttemptState::Invoking)),
                    },
                    Request::RecordOutcome { outcome, .. } => {
                        let terminal = matches!(outcome, WireOutcome::NativeAccepted { .. });
                        observed_tx.send(terminal).unwrap();
                        if terminal || close_callback {
                            source.respond(request_id, Response::Ok {}).unwrap();
                            break;
                        }
                        Response::Ok {}
                    }
                    _ => panic!("unexpected source operation"),
                };
                source.respond(request_id, response).unwrap();
            }
            finish_source_rx
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        });
        let target_binding = binding.clone();
        let target_thread = std::thread::spawn(move || {
            loop {
                let Incoming::Request {
                    request_id,
                    request,
                    ..
                } = target_rx.recv_timeout(Duration::from_secs(3)).unwrap()
                else {
                    panic!("target request")
                };
                match request {
                    Request::AttestMessage { .. } => target
                        .respond(
                            request_id,
                            Response::Binding {
                                binding: target_binding.clone(),
                            },
                        )
                        .unwrap(),
                    Request::SendMessage {
                        source_uid,
                        ticket,
                        attempt,
                        ..
                    } => {
                        assert_eq!(source_uid, 1000);
                        let event = if close_callback {
                            Event::CallbackClosed {
                                source_uid,
                                ticket,
                                fence: attempt.fence.clone(),
                            }
                        } else {
                            Event::LateOutcome {
                                source_uid,
                                ticket,
                                fence: attempt.fence.clone(),
                                outcome: WireOutcome::NativeAccepted {
                                    evidence: "accepted".into(),
                                },
                            }
                        };
                        target.event(event).unwrap();
                        target
                            .respond(
                                request_id,
                                Response::Outcome {
                                    outcome: WireOutcome::NativeHeld {
                                        recheck_ms: current_unix_millis() + 5_000,
                                    },
                                },
                            )
                            .unwrap();
                        break;
                    }
                    _ => panic!("unexpected target operation"),
                }
            }
            finish_target_rx
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
        });
        let dispatcher_shared = Arc::clone(&shared);
        let dispatcher =
            std::thread::spawn(move || dispatch_incoming(dispatcher_shared, incoming_rx));
        dispatch_message(&shared, 1000, 2000, binding.address.clone());
        assert!(!observed_rx.recv_timeout(Duration::from_secs(3)).unwrap());
        if !close_callback {
            assert!(observed_rx.recv_timeout(Duration::from_secs(3)).unwrap());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !shared.state.lock().unwrap().tickets.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(shared.state.lock().unwrap().tickets.is_empty());
        assert!(!shared.fatal.load(Ordering::SeqCst));
        shared.stopping.store(true, Ordering::SeqCst);
        shared.fatal.store(true, Ordering::SeqCst);
        for link in shared.links.values() {
            link.close();
        }
        finish_source_tx.send(()).unwrap();
        finish_target_tx.send(()).unwrap();
        source_thread.join().unwrap();
        target_thread.join().unwrap();
        dispatcher.join().unwrap();
    }

    /// Native acceptance cannot overtake the original held outcome.
    #[test]
    fn message_routes_once_and_orders_racing_callback() {
        check_racing_callback(false);
    }

    /// Callback expiry before the first response removes only the original ticket.
    #[test]
    fn racing_callback_close_follows_initial_outcome() {
        check_racing_callback(true);
    }

    /// A binding update fences admission until an already-issued hook finishes.
    #[test]
    fn binding_update_waits_for_issued_hook() {
        let shared = coordinator(BTreeMap::new());
        let binding = binding();
        let record = attempt(&binding, AttemptState::Invoking);
        shared
            .state
            .lock()
            .unwrap()
            .busy
            .insert(binding.address.clone(), false);
        let ticket = shared.ticket(1000, 2000, &record, false, true).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let task_shared = Arc::clone(&shared);
        let task_binding = binding.clone();
        let task = std::thread::spawn(move || {
            done_tx
                .send(apply_binding(&task_shared, 2000, task_binding))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !shared
            .state
            .lock()
            .unwrap()
            .frozen
            .contains(&binding.address)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            shared
                .state
                .lock()
                .unwrap()
                .frozen
                .contains(&binding.address)
        );
        assert!(done_rx.try_recv().is_err());
        assert!(shared.ticket(1000, 2000, &record, false, true).is_none());
        {
            let mut state = shared.state.lock().unwrap();
            state.tickets.remove(&ticket);
            state.busy.remove(&binding.address);
            shared.changed.notify_all();
        }
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_ok()
        );
        task.join().unwrap();
        assert!(
            !shared
                .state
                .lock()
                .unwrap()
                .frozen
                .contains(&binding.address)
        );
    }

    /// An overdue hook fences the service rather than releasing its recipient.
    #[test]
    fn expired_hook_stops_service_without_releasing_permit() {
        let shared = coordinator(BTreeMap::new());
        let binding = binding();
        let mut record = attempt(&binding, AttemptState::Invoking);
        record.deadline_ms = 1;
        {
            let mut state = shared.state.lock().unwrap();
            state.busy.insert(binding.address.clone(), false);
        }
        let ticket = shared.ticket(1000, 2000, &record, false, true).unwrap();
        schedule(&shared);
        assert!(shared.fatal.load(Ordering::SeqCst));
        let state = shared.state.lock().unwrap();
        assert!(state.busy.contains_key(&binding.address));
        assert!(state.tickets.contains_key(&ticket));
    }
}
