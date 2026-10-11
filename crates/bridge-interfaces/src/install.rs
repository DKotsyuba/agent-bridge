//! Local package, install, rollback and doctor capability.
//!
//! Family-convention productization for the standalone Bridge: package a
//! built release into a sealed directory with a content manifest, install
//! it into a versioned prefix with digest verification, roll the prefix
//! back to the previous sealed version, and report the truthful state of
//! every capability through `doctor`.
//!
/// Scope limits, deliberately: this is fixture-grade, isolated-root
//! capability for local qualification. Release publication, attested
//! network downloads, working-application installation and any database
//! rollback are out of scope. Rollback swaps the installed program tree
//! only and explicitly refuses to touch data: after new events have been
//! accepted, data rollback belongs to the core's fenced handback, never to
//! a snapshot restore.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Manifest schema version written into packages.
const PACKAGE_MANIFEST_VERSION: u32 = 1;

/// One entry of a package manifest: a file with its SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageFile {
    /// Path of the file inside the package, relative to its root.
    pub path: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// The sealed package manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Manifest schema version ([`PACKAGE_MANIFEST_VERSION`]).
    pub schema: u32,
    /// Product name (`agent-bridge`).
    pub product: String,
    /// Package version string.
    pub version: String,
    /// Wall clock when the package was created, epoch milliseconds.
    pub created_at_ms: u64,
    /// Every file in the package with its digest.
    pub files: Vec<PackageFile>,
}

/// The installed-state record kept in a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallState {
    /// Prefix-relative path of the currently active version directory.
    pub current: String,
    /// Previous version directory retained for rollback, if any.
    pub previous: Option<String>,
    /// The manifest of the currently active version.
    pub manifest: PackageManifest,
}

/// Errors produced by the packaging operations.
///
/// One structured error class per failure; all messages are safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// A needed path does not exist; names it.
    Missing(PathBuf),
    /// A package failed verification (no manifest or a digest mismatch).
    Unverified(String),
    /// The filesystem refused an operation; names path and reason.
    Io(String),
    /// The request is structurally invalid (empty file list, bad state).
    Invalid(String),
}

impl std::fmt::Display for InstallError {
    /// Renders class and detail on one line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::Missing(path) => write!(f, "missing: {}", path.display()),
            InstallError::Unverified(detail) => write!(f, "unverified package: {detail}"),
            InstallError::Io(detail) => write!(f, "io failure: {detail}"),
            InstallError::Invalid(detail) => write!(f, "invalid request: {detail}"),
        }
    }
}

impl std::error::Error for InstallError {}

/// Computes the lowercase hex SHA-256 of a file's bytes.
///
/// Reads the whole file; package payloads are small binaries and configs.
fn file_digest(path: &Path) -> Result<String, InstallError> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)
        .map_err(|error| InstallError::Io(format!("{}: {error}", path.display())))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// Lowercase-hex encodes a digest.
fn hex(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte| [(byte >> 4) as usize, (byte & 0x0f) as usize])
        .map(|nibble| HEX[nibble] as char)
        .collect()
}

/// Packages the given files into a fresh sealed directory.
///
/// `sources` maps package-relative destinations to existing files. The
/// output directory must not exist. On success it contains every file plus
/// `manifest.json` covering exactly those files. Refuses an empty file
/// list (an empty package cannot be verified or installed).
pub fn package(
    out: &Path,
    version: &str,
    sources: &[(String, PathBuf)],
    now_ms: u64,
) -> Result<PackageManifest, InstallError> {
    if sources.is_empty() {
        return Err(InstallError::Invalid("package needs at least one file".into()));
    }
    if out.exists() {
        return Err(InstallError::Invalid(format!(
            "output directory {} already exists",
            out.display()
        )));
    }
    let mut files = Vec::new();
    for (relative, source) in sources {
        if !source.is_file() {
            return Err(InstallError::Missing(source.clone()));
        }
        let bytes = std::fs::metadata(source)
            .map_err(|error| InstallError::Io(format!("{}: {error}", source.display())))?
            .len();
        files.push(PackageFile {
            path: relative.clone(),
            sha256: file_digest(source)?,
            bytes,
        });
        let destination = out.join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| InstallError::Io(format!("{}: {error}", parent.display())))?;
        }
        std::fs::copy(source, &destination).map_err(|error| {
            InstallError::Io(format!("{}: {error}", destination.display()))
        })?;
    }
    let manifest = PackageManifest {
        schema: PACKAGE_MANIFEST_VERSION,
        product: "agent-bridge".to_string(),
        version: version.to_string(),
        created_at_ms: now_ms,
        files,
    };
    let manifest_path = out.join("manifest.json");
    let text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| InstallError::Io(format!("serialize manifest: {error}")))?;
    std::fs::write(&manifest_path, text)
        .map_err(|error| InstallError::Io(format!("{}: {error}", manifest_path.display())))?;
    Ok(manifest)
}

/// Loads and verifies a package manifest from a directory.
///
/// Verification is the install gate: a missing manifest, a wrong schema,
/// a missing file or any digest mismatch makes the package unverified and
/// refused ("attestation before executable use", applied to local
/// packages through content digests).
pub fn verify_package(package_dir: &Path) -> Result<PackageManifest, InstallError> {
    let manifest_path = package_dir.join("manifest.json");
    if !manifest_path.is_file() {
        return Err(InstallError::Unverified(format!(
            "no manifest.json in {}",
            package_dir.display()
        )));
    }
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|error| InstallError::Io(format!("{}: {error}", manifest_path.display())))?;
    let manifest: PackageManifest = serde_json::from_str(&text).map_err(|error| {
        InstallError::Unverified(format!("manifest is not readable: {error}"))
    })?;
    if manifest.schema != PACKAGE_MANIFEST_VERSION {
        return Err(InstallError::Unverified(format!(
            "manifest schema {} != {PACKAGE_MANIFEST_VERSION}",
            manifest.schema
        )));
    }
    if manifest.files.is_empty() {
        return Err(InstallError::Unverified("manifest covers no files".into()));
    }
    for file in &manifest.files {
        let path = package_dir.join(&file.path);
        if !path.is_file() {
            return Err(InstallError::Unverified(format!(
                "manifest file {} is absent",
                file.path
            )));
        }
        let digest = file_digest(&path)?;
        if digest != file.sha256 {
            return Err(InstallError::Unverified(format!(
                "digest mismatch for {}: manifest {} != actual {}",
                file.path, file.sha256, digest
            )));
        }
    }
    Ok(manifest)
}

/// Installs a verified package into a versioned prefix.
///
/// The prefix layout is `versions/<version>-<shortdigest>/` per install;
/// `state.json` records the active and previous version directories.
/// Installing never deletes the previously active version (rollback needs
/// it) and never touches anything outside the prefix. Refuses unverified
/// packages before any file is copied.
pub fn install(package_dir: &Path, prefix: &Path) -> Result<InstallState, InstallError> {
    let manifest = verify_package(package_dir)?;
    let version_dir_name = format!(
        "v{}-{}",
        manifest.version,
        &manifest.files[0].sha256[..8.min(manifest.files[0].sha256.len())]
    );
    let version_dir = prefix.join("versions").join(&version_dir_name);
    if version_dir.exists() {
        return Err(InstallError::Invalid(format!(
            "version directory {} already exists",
            version_dir.display()
        )));
    }
    std::fs::create_dir_all(&version_dir)
        .map_err(|error| InstallError::Io(format!("{}: {error}", version_dir.display())))?;
    for file in &manifest.files {
        let source = package_dir.join(&file.path);
        let destination = version_dir.join(&file.path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| InstallError::Io(format!("{}: {error}", parent.display())))?;
        }
        std::fs::copy(&source, &destination).map_err(|error| {
            InstallError::Io(format!("{}: {error}", destination.display()))
        })?;
    }
    let state_path = prefix.join("state.json");
    let previous = if state_path.is_file() {
        let text = std::fs::read_to_string(&state_path)
            .map_err(|error| InstallError::Io(format!("{}: {error}", state_path.display())))?;
        let state: InstallState = serde_json::from_str(&text)
            .map_err(|error| InstallError::Io(format!("state.json unreadable: {error}")))?;
        Some(state.current)
    } else {
        None
    };
    let state = InstallState {
        current: format!("versions/{version_dir_name}"),
        previous,
        manifest: manifest.clone(),
    };
    let text = serde_json::to_string_pretty(&state)
        .map_err(|error| InstallError::Io(format!("serialize state: {error}")))?;
    std::fs::create_dir_all(prefix)
        .map_err(|error| InstallError::Io(format!("{}: {error}", prefix.display())))?;
    std::fs::write(&state_path, text)
        .map_err(|error| InstallError::Io(format!("{}: {error}", state_path.display())))?;
    Ok(state)
}

/// Rolls the prefix back to its previous sealed version.
///
/// Only the active-version pointer in `state.json` changes; no file is
/// deleted or restored by this operation, so the rollback is exactly
/// "point at the previously verified program tree again". Refuses when
/// there is no previous version. Never touches databases or any data
/// outside the prefix: after new events were accepted, data rollback is
/// the core's fenced handback, not a package operation.
pub fn rollback(prefix: &Path) -> Result<InstallState, InstallError> {
    let state_path = prefix.join("state.json");
    if !state_path.is_file() {
        return Err(InstallError::Invalid(format!(
            "no installation state in {}",
            prefix.display()
        )));
    }
    let text = std::fs::read_to_string(&state_path)
        .map_err(|error| InstallError::Io(format!("{}: {error}", state_path.display())))?;
    let state: InstallState = serde_json::from_str(&text)
        .map_err(|error| InstallError::Io(format!("state.json unreadable: {error}")))?;
    let Some(previous) = state.previous.clone() else {
        return Err(InstallError::Invalid(
            "no previous version retained; nothing to roll back to".into(),
        ));
    };
    let previous_dir = prefix.join(&previous);
    let previous_manifest = previous_dir.join("manifest.json");
    if !previous_manifest.is_file() {
        return Err(InstallError::Missing(previous_manifest));
    }
    // The previously installed tree was verified at install time and is
    // immutable within the prefix; re-verify to catch accidental damage.
    let manifest_text = std::fs::read_to_string(&previous_manifest)
        .map_err(|error| InstallError::Io(format!("{}: {error}", previous_manifest.display())))?;
    let mut manifest: PackageManifest = serde_json::from_str(&manifest_text)
        .map_err(|error| InstallError::Io(format!("previous manifest unreadable: {error}")))?;
    for file in &manifest.files {
        let path = previous_dir.join(&file.path);
        if !path.is_file() || file_digest(&path)? != file.sha256 {
            return Err(InstallError::Unverified(format!(
                "previous version file {} is damaged",
                file.path
            )));
        }
    }
    manifest.version = format!("{} (rolled back)", manifest.version);
    let rolled = InstallState {
        current: previous,
        previous: Some(state.current),
        manifest,
    };
    let text = serde_json::to_string_pretty(&rolled)
        .map_err(|error| InstallError::Io(format!("serialize state: {error}")))?;
    std::fs::write(&state_path, text)
        .map_err(|error| InstallError::Io(format!("{}: {error}", state_path.display())))?;
    Ok(rolled)
}

/// Inputs for a doctor report.
///
/// Paths are checked for existence/readability only; doctor never starts,
/// stops or mutates anything.
#[derive(Debug, Clone, Default)]
pub struct DoctorInput {
    /// Core custody database path, if configured.
    pub database: Option<PathBuf>,
    /// Core publisher socket path, if configured.
    pub publisher_socket: Option<PathBuf>,
    /// Root ingress socket path, if configured.
    pub root_socket: Option<PathBuf>,
    /// Operator interface socket path, if configured.
    pub operator_socket: Option<PathBuf>,
    /// Operator incident database path, if configured.
    pub incident_database: Option<PathBuf>,
    /// Telegram channel configuration, if any.
    pub telegram: Option<crate::telegram::TelegramConfig>,
    /// Install prefix to report on, if any.
    pub prefix: Option<PathBuf>,
}

/// One doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check name, stable for tooling.
    pub name: String,
    /// `ok`, `warn` or `unavailable`; only `ok` means verified present.
    pub status: String,
    /// Human-readable detail without secrets.
    pub detail: String,
}

/// The complete doctor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Product version of this build.
    pub product_version: String,
    /// Every check, in report order.
    pub checks: Vec<DoctorCheck>,
    /// Whether every check is `ok` or an explicitly tolerated state.
    pub healthy: bool,
    /// Standing truth: nothing here claims runtime qualification.
    pub qualification: String,
}

/// Builds the doctor report for the given inputs.
///
/// Truthful by construction: capabilities report `unavailable` when their
/// configuration is absent, Telegram reports its real configured state,
/// and the qualification field stays `not_verified` — doctor checks
/// configuration and file presence, never live behavior.
pub fn doctor(input: &DoctorInput) -> DoctorReport {
    let mut checks = Vec::new();
    let mut healthy = true;
    let mut check = |name: &str, ok: bool, warn: bool, detail: String| {
        let status = if ok {
            "ok"
        } else if warn {
            healthy = false;
            "warn"
        } else {
            "unavailable"
        };
        checks.push(DoctorCheck {
            name: name.to_string(),
            status: status.to_string(),
            detail,
        });
    };
    match &input.database {
        Some(path) if path.is_file() => check("core_database", true, false, path.display().to_string()),
        Some(path) => check(
            "core_database",
            false,
            true,
            format!("configured but absent: {}", path.display()),
        ),
        None => check("core_database", false, false, "not configured".into()),
    }
    for (name, path) in [
        ("publisher_socket", &input.publisher_socket),
        ("root_socket", &input.root_socket),
        ("operator_socket", &input.operator_socket),
    ] {
        match path {
            Some(path) if path.exists() => {
                check(name, true, false, path.display().to_string())
            }
            Some(path) => check(
                name,
                false,
                true,
                format!("configured but not listening: {}", path.display()),
            ),
            None => check(name, false, false, "not configured".into()),
        }
    }
    match &input.incident_database {
        Some(path) if path.is_file() => {
            check("incident_database", true, false, path.display().to_string())
        }
        Some(path) => check(
            "incident_database",
            false,
            true,
            format!("configured but absent: {}", path.display()),
        ),
        None => check("incident_database", false, false, "not configured".into()),
    }
    match &input.telegram {
        Some(config) => {
            let token_readable = config.enabled && config.bot_token_file.is_file();
            let detail = if !config.enabled {
                "channel disabled; owner notifications will report unconfigured".to_string()
            } else if token_readable {
                format!("enabled, fixed destination {}", config.chat_id)
            } else {
                format!(
                    "enabled but token file missing: {}",
                    config.bot_token_file.display()
                )
            };
            check(
                "telegram_channel",
                config.enabled && token_readable,
                config.enabled && !token_readable,
                detail,
            );
        }
        None => check(
            "telegram_channel",
            false,
            false,
            "not configured; incidents stay local and are never reported as notified".into(),
        ),
    }
    match &input.prefix {
        Some(prefix) if prefix.join("state.json").is_file() => {
            match std::fs::read_to_string(prefix.join("state.json")) {
                Ok(text) => match serde_json::from_str::<InstallState>(&text) {
                    Ok(state) => check(
                        "installed_version",
                        true,
                        false,
                        format!("{} at {}", state.manifest.version, state.current),
                    ),
                    Err(_) => check(
                        "installed_version",
                        false,
                        true,
                        "state.json is unreadable".into(),
                    ),
                },
                Err(_) => check(
                    "installed_version",
                    false,
                    true,
                    "state.json cannot be read".into(),
                ),
            }
        }
        Some(prefix) => check(
            "installed_version",
            false,
            false,
            format!("no installation state in {}", prefix.display()),
        ),
        None => check("installed_version", false, false, "not installed".into()),
    }
    check(
        "native_adapters",
        false,
        false,
        "no adapter qualification recorded by this build; loaded-host capability is not_verified"
            .into(),
    );
    check(
        "data_rollback",
        false,
        false,
        "package rollback swaps the program tree only; data rollback requires the core fenced handback"
            .into(),
    );
    DoctorReport {
        product_version: env!("CARGO_PKG_VERSION").to_string(),
        checks,
        healthy,
        qualification: "not_verified".to_string(),
    }
}
