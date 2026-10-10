//! Shared test helpers: isolated temporary directories.

/// Guard that removes its directory when dropped.
///
/// Every test owns a fresh directory under the system temp dir; no shared
/// or installed state is touched. Allowed dead code: shared by test
/// binaries that may not need every helper.
#[allow(dead_code)]
pub struct TempDir(std::path::PathBuf);

#[allow(dead_code)]
impl TempDir {
    /// Creates a unique directory for one test.
    pub fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "bridge-core-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    /// A path inside the directory.
    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    /// Removes the directory tree; test-isolated state only.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
