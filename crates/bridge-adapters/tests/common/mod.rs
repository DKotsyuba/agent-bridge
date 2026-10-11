//! Shared test helpers: isolated temporary directories and a digest stand-in.

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
            "bridge-adapters-{}-{}-{}",
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

/// Deterministic digest stand-in for test assertions.
///
/// Not cryptography: tests only need stable, distinct digests per distinct
/// payload. Product code never uses this.
#[allow(dead_code)]
pub fn digest(text: &str) -> String {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        acc = (acc ^ u64::from(byte)).wrapping_mul(0x1000_0000_01b3);
    }
    format!("{acc:016x}")
}
