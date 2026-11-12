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
//!   such promise, or Bridge cannot see which filesystem it is. The parser and
//!   allowlist are [`bridge_protocol::peer_proof`]'s, shared with the SDK's
//!   server proof.
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

/// The filesystem check of [`loaded_executable`] for the opened loaded file.
#[cfg(target_os = "linux")]
fn descriptor_denies_running_writes(file: &std::fs::File) -> bool {
    #[cfg(test)]
    if let Some(fstype) = injected::get() {
        return bridge_protocol::peer_proof::write_excluding_type(&fstype);
    }
    bridge_protocol::peer_proof::write_excluded(file)
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
