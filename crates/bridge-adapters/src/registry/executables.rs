//! Digest evidence of Bridge's own privileged components: the digest cache of the
//! configured relay and backend audience executables, refreshed
//! outside the registry lock.
//!
//! The registry never reads an executable while serving. A file's *identity*
//! ([`FileKey`]: path, device and inode, length, nanosecond mtime and ctime) is
//! the key of everything cached about it: its real SHA-256. [`refresh_stale`]
//! fills the cache in a background pass after an application update; until it
//! finishes, the new identity simply has no evidence and every route that needs
//! it refuses before changing any state.
//!
//! Only privileged Bridge components are covered (`relays` and `audiences`
//! of the configuration; the native owner route has none), never the Codex or Claude Code binary of a
//! recipient: native recipients are identified by their process facts and
//! harness-level policy, not by a predeclared build. Trust never comes from this
//! module's work alone: an exact digest still has to equal a configured one and
//! [`Registry::verify_loaded`] additionally requires the file's mtime and ctime
//! to precede the process start second.

use super::*;

/// Operator-recorded signing identity of a vendor build, kept ONLY so that a
/// configuration written for the removed executable trust still parses.
///
/// It is migration input: no signature checker exists any more and the value
/// never authorizes, qualifies or restricts anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorSignature {
    /// Legacy code-signing identifier; ignored.
    pub identifier: String,
    /// Legacy Apple Developer Team identifier; ignored.
    pub team_id: String,
}

/// One configured file whose current identity still lacks a digest.
#[derive(Debug)]
pub(super) struct Stale {
    /// Configured path.
    path: PathBuf,
    /// Identity at staging time; every later step must still see exactly this.
    key: FileKey,
    /// Set when the daemon is stopping: the pass abandons its work.
    stop: Arc<AtomicBool>,
}

/// Evidence computed for one [`Stale`] file, committed only if still current.
#[derive(Debug)]
pub(super) struct Checked {
    /// The identity the evidence belongs to.
    key: FileKey,
    /// Real digest of exactly that identity.
    digest: String,
}

impl Registry {
    /// Every distinct configured relay and backend audience executable path,
    /// sorted. The only set the digest cache ever covers.
    pub(super) fn configured_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<&Path> = self
            .config
            .relays
            .iter()
            .map(|relay| relay.path.as_path())
            .chain(
                self.config
                    .audiences
                    .iter()
                    .map(|audience| audience.executable.path.as_path()),
            )
            .collect();
        paths.sort();
        paths.dedup();
        paths.into_iter().map(Path::to_path_buf).collect()
    }

    /// Stat-only list of the configured files whose *current* identity lacks a
    /// digest. No file is read, so this is safe under the registry lock. A missing
    /// or unreadable file has no identity and is not listed; a hashed identity,
    /// whatever its digest, is never listed again (a changed build is not
    /// re-hashed per request).
    pub(super) fn stale_files(&self) -> Vec<Stale> {
        self.configured_paths()
            .into_iter()
            .filter_map(|path| {
                let key = file_key(&path)?;
                (!self.digests.contains_key(&key)).then(|| Stale {
                    path,
                    key,
                    stop: Arc::clone(&self.stopping),
                })
            })
            .collect()
    }

    /// Commits one staged result, but only if the file at its path *still* has
    /// the identity the evidence was computed for (checked here, under the lock
    /// the caller holds): a file that changed between the hash and this commit is
    /// skipped with nothing pruned or inserted, so it stays unqualified and is
    /// staged again. Otherwise caches `digest` for exactly that identity and drops
    /// every superseded identity of the same path, so repeated updates cannot grow
    /// the cache. Trust is not granted here: [`Registry::verify_loaded`] still
    /// compares digests with configured ones, for the current file identity only.
    pub(super) fn commit_checked(&mut self, item: Checked) {
        if file_key(&item.key.path).as_ref() != Some(&item.key) {
            return;
        }
        let key = item.key;
        self.digests.retain(|old, _| old.path != key.path);
        self.digests.insert(key, item.digest);
    }

    /// Hashes every configured file whose identity lacks a digest, on the caller's
    /// thread and under the caller's exclusive access. Startup warm-up only
    /// ([`Registry::warm_digests`]).
    pub(super) fn refresh_blocking(&mut self) {
        for item in self.stale_files().into_iter().filter_map(check_file) {
            self.commit_checked(item);
        }
    }
}

/// A reader that fails once `stop` is set, so a daemon shutdown interrupts a
/// whole-file hash within one chunk.
struct Interruptible<'a, R> {
    /// The wrapped reader.
    inner: R,
    /// Shutdown flag.
    stop: &'a AtomicBool,
}

impl<R: Read> Read for Interruptible<'_, R> {
    /// Reads from the wrapped reader unless the shutdown flag is set, which is
    /// an `Interrupted`-kind failure the hash treats as an abandoned read.
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.stop.load(Ordering::SeqCst) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.inner.read(buffer)
    }
}

/// Hashes the opened file and returns the digest only if the *opened file's own*
/// identity (read from the descriptor, not the path) is `key` before and after
/// the read and the path still resolves to `key` afterwards. A rename or an
/// in-place write between open and close, including one that swaps a file in and
/// back, changes the descriptor's or the path's ctime/inode and drops the read.
/// Unreadable, changing or (on `stop`) abandoned files return `None` and stay
/// unqualified.
pub(super) fn hash_stable(path: &Path, key: &FileKey, stop: &AtomicBool) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    if &key_of(path, &file.metadata().ok()?) != key {
        return None;
    }
    let mut reader = Interruptible { inner: &file, stop };
    let digest = sha256_reader(&mut reader).ok()?;
    (&key_of(path, &file.metadata().ok()?) == key && file_key(path).as_ref() == Some(key))
        .then_some(digest)
}

/// Computes the digest of one staged file under its staged identity. `None` when
/// the read was unstable; nothing is then cached and the identity stays refused.
pub(super) fn check_file(stale: Stale) -> Option<Checked> {
    let digest = hash_stable(&stale.path, &stale.key, &stale.stop)?;
    Some(Checked {
        key: stale.key,
        digest,
    })
}

/// Clears the single-flight flag of a refresh pass on every exit, panics included.
struct Flight(Arc<AtomicBool>);

impl Drop for Flight {
    /// Releases the flag so a later request may start the next pass.
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Starts a background pass that refreshes the digests of a serving registry for
/// every configured relay or backend audience executable whose current file
/// identity has none: an application update, a restored or touched file, a
/// rename-replacement with identical bytes. Returns whether a pass was started
/// (`false`: nothing stale, a pass already running, or the daemon stopping).
///
/// The caller never waits and never hashes: under the registry lock the call only
/// stats the configured paths; the pass runs on its own thread, so no request or
/// hook blocks on a whole-file read, and every route refuses an identity without
/// evidence before it changes any state. The pass stages the unhashed identities
/// under the lock, hashes them with the lock released, and commits under the lock
/// only the results whose file still has the identity they were computed for,
/// dropping superseded identities of the same path. Nothing is trusted by this
/// call: a digest only becomes evidence through [`Registry::verify_loaded`], and a
/// process started before the file's last change stays unproven. [`stop_refresh`]
/// ends the pass at shutdown.
// ponytail: a file rewritten continuously is re-hashed once per pass; add a per-path cooldown if that is ever observed.
pub(crate) fn refresh_stale(registry: &Arc<Mutex<Registry>>) -> bool {
    let (flag, slot, stopping) = {
        let registry = lock_registry(registry);
        if registry.stopping.load(Ordering::SeqCst) || registry.stale_files().is_empty() {
            return false;
        }
        (
            Arc::clone(&registry.refreshing),
            Arc::clone(&registry.pass),
            Arc::clone(&registry.stopping),
        )
    };
    // The slot lock is held from the last stop check through publishing the join
    // handle (lock order: never taken under the registry lock, and nothing here
    // takes the registry lock while holding it except the spawned thread, which
    // does not touch the slot): a concurrent `stop_refresh` either runs before
    // this check and prevents the pass, or waits here and then joins the handle.
    let mut published = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if stopping.load(Ordering::SeqCst) || flag.swap(true, Ordering::SeqCst) {
        return false;
    }
    let pass = Arc::clone(registry);
    let started = std::thread::Builder::new()
        .name("bridge-digest-refresh".into())
        .spawn({
            let flight = Flight(Arc::clone(&flag));
            move || {
                let _flight = flight;
                let staged = lock_registry(&pass).stale_files();
                let checked: Vec<Checked> = staged.into_iter().filter_map(check_file).collect();
                let mut registry = lock_registry(&pass);
                if !registry.stopping.load(Ordering::SeqCst) {
                    for item in checked {
                        registry.commit_checked(item);
                    }
                }
            }
        });
    match started {
        Ok(handle) => {
            *published = Some(handle);
            true
        }
        Err(_) => {
            flag.store(false, Ordering::SeqCst);
            false
        }
    }
}

/// Waits for the running refresh pass, if any, to finish. The registry lock is
/// not held while waiting.
pub(super) fn wait_refresh(registry: &Arc<Mutex<Registry>>) {
    let slot = Arc::clone(&lock_registry(registry).pass);
    let handle = slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

/// Ends the background refresh for good (daemon shutdown): later calls start
/// nothing, a running pass abandons its hash, nothing more is committed, and this
/// call returns only after the pass thread has been joined.
pub(crate) fn stop_refresh(registry: &Arc<Mutex<Registry>>) {
    lock_registry(registry)
        .stopping
        .store(true, Ordering::SeqCst);
    wait_refresh(registry);
}
