//! Agent Bridge interfaces: the restricted root MCP, operator recovery,
//! the outbound owner channel and product packaging.
//!
//! Everything here consumes the core and adapter crates through their
//! public APIs; nothing opens the core database, keeps a second incident
//! or attempt store, or dispatches natively.
//!
//! - [`mcp`] + [`root`]: the root tool surface. A harness-launched stdio
//!   MCP frontend (`bridge-root-mcp`, no credentials) attests every call
//!   through the adapter registry and forwards a sealed single-use proof to
//!   the root relay (`bridge-root-relay`), the configured relay executable
//!   that redeems it and alone holds a core publisher grant restricted to
//!   `keep_all` and exact recipients. Tools: `bridge_me`, `bridge_send`,
//!   `bridge_status`. No receipt acknowledgement tool exists (no producer
//!   declared a receipt tier and core issues no receipt token).
//! - [`operator`]: incident reading and explicit audited decisions over
//!   the core operator grant (`bridge operator …`).
//! - [`telegram`] + [`notify`]: outbound-only plain-text reports of open
//!   incidents to one fixed chat, with a durable send ledger that never
//!   repeats a possible send.
//! - [`install`], [`lifecycle`], [`doctor`]: verified bundles, sealed
//!   releases, activation/rollback without schema downgrade, daemon
//!   start/stop and local diagnostics (`bridge package|self-install|
//!   rollback|service|doctor`).
//! - [`config`]: the closed interfaces configuration and protected
//!   secret files.

pub mod config;
pub mod doctor;
pub mod install;
pub mod lifecycle;
pub mod mcp;
pub mod notify;
pub mod operator;
pub mod root;
pub mod telegram;

#[cfg(test)]
pub(crate) mod testdir {
    //! Exclusive, unpredictable scratch directories for unit tests.
    //!
    //! Each directory is created with `create_dir` (never reusing or
    //! clearing an existing path) under a random name, mode `0700`, and only
    //! that directory is removed on drop. Nothing outside it is touched.

    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// A scratch directory owned by one test.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        /// Creates `$TMPDIR/bi-<tag>-<16 random hex>` exclusively.
        ///
        /// Retries on a name collision; panics on any other failure.
        pub(crate) fn new(tag: &str) -> TestDir {
            for _ in 0..16 {
                let random = bridge_adapters::os::random_bytes().expect("random bytes");
                let suffix: String = random[..8].iter().map(|b| format!("{b:02x}")).collect();
                let path = std::env::temp_dir().join(format!("bi-{tag}-{suffix}"));
                match std::fs::create_dir(&path) {
                    Ok(()) => {
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .expect("private scratch");
                        return TestDir(path.canonicalize().expect("canonical scratch"));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create scratch directory: {error}"),
                }
            }
            panic!("no free scratch directory name");
        }

        /// The directory.
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    /// Restores owner write on every real directory below `path` (sealed
    /// test releases are read-only); links are never followed.
    fn writable(path: &Path) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if metadata.is_dir() {
            let _ = std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(metadata.permissions().mode() | 0o700),
            );
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    writable(&entry.path());
                }
            }
        }
    }

    impl Drop for TestDir {
        /// Removes exactly the directory this guard created.
        fn drop(&mut self) {
            writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
