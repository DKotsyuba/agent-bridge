//! Release bundles, verified installation, activation and rollback.
//!
//! A bundle is a directory with exactly `release-manifest.json`,
//! `SHA256SUMS` and `bin/` holding exactly [`BINARIES`] as regular files, plus
//! (from 0.3.0) `plugins/opencode/` holding exactly [`PLUGIN_FILES`], the
//! first-party OpenCode lifecycle plugin. The manifest binds product, version,
//! build label, target, the core storage schema and each file's size and
//! SHA-256; `SHA256SUMS` must be exactly the rendering of those digests plus
//! the manifest's own. A bundle without a `plugins` directory and without
//! `plugin_files` in its manifest is a legacy (0.2) bundle: it still verifies,
//! installs, rolls back and reports no plugin binding. The
//! digest of `SHA256SUMS`, printed by [`package`], is the out-of-band
//! attestation value: `install.sh` and [`self_install`] refuse a bundle
//! whose `SHA256SUMS` differs from it *before* any bundle executable runs
//! (`install.sh` copies the bundle to a private directory, checks the copy with
//! `shasum` and runs the verified copy of `bridge`; the sealed bytes must hash
//! to the same attested digest).
//! A hash is not a signature: trust is the operator's own local build.
//!
//! Layout under the installation home (nothing outside it and the launcher
//! directory is written):
//!
//! - `releases/<version>+<label>/` — immutable sealed copies (executables `0555`,
//!   manifest and plugin files `0444`, directories `0555`); staged
//!   owner-writable, verified, renamed, and only then sealed `0555` before
//!   activation. The installed plugin entrypoint is
//!   `<home>/current/plugins/opencode/index.js` with `package.json` beside it;
//!   a supervisor must be given the resolved release path and SHA-256 of
//!   [`Activation::plugin_binding`], never a source-tree or `current` path;
//! - `current` — symlink to the active release, replaced atomically;
//! - `install-state.json` — active and previous release and the highest
//!   core storage schema ever activated;
//! - `.lock` — serializes cooperating installers.
//!
//! Launchers are symlinks `<bin-dir>/<name>` → `<home>/current/bin/<name>`;
//! an existing foreign file at a launcher path refuses the install before
//! anything is activated. Activation and rollback refuse a release whose
//! core storage schema is older than one already activated: a live schema
//! is never downgraded and no database snapshot is ever restored (rollback
//! changes program code only; accepted events, incidents and audit stay).
//! Live processes are not restarted ([`crate::lifecycle`] does that).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Product name in manifests.
pub const PRODUCT: &str = "agent-bridge";

/// Manifest file name.
pub const MANIFEST: &str = "release-manifest.json";

/// Checksum file name.
pub const SUMS: &str = "SHA256SUMS";

/// The packaged executables, in manifest order.
pub const BINARIES: [&str; 6] = [
    "bridge",
    "bridge-root-mcp",
    "bridge-root-relay",
    "bridge-native-daemon",
    "bridge-hook",
    "bridge-daemon",
];

/// Files of the first-party OpenCode plugin, in manifest order; the first is
/// its entrypoint. Packaged under [`PLUGIN_DIR`] and never anything else.
pub const PLUGIN_FILES: [&str; 2] = ["index.js", "package.json"];

/// Release-relative directory of the OpenCode plugin.
pub const PLUGIN_DIR: &str = "plugins/opencode";

/// Manifest schema version.
pub const MANIFEST_SCHEMA: u32 = 1;

/// State file name under the home.
const STATE: &str = "install-state.json";

/// The build label compiled into this binary (`BRIDGE_BUILD_LABEL` at
/// build time, `dev` otherwise).
pub const BUILD_LABEL: &str = match option_env!("BRIDGE_BUILD_LABEL") {
    Some(label) => label,
    None => "dev",
};

/// One packaged file: a binary under `bin/` or a plugin file under
/// [`PLUGIN_DIR`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFile {
    /// File name under `bin/` (or [`PLUGIN_DIR`] for a plugin file).
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// The release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// [`MANIFEST_SCHEMA`].
    pub schema: u32,
    /// [`PRODUCT`].
    pub product: String,
    /// Cargo package version of the build.
    pub version: String,
    /// Build label (`[A-Za-z0-9._-]`, at most 64 bytes).
    pub build_label: String,
    /// `<arch>-<os>` of the build.
    pub target: String,
    /// Core storage schema version the binaries create or migrate to.
    pub core_schema: u32,
    /// Exactly [`BINARIES`], in order.
    pub files: Vec<ReleaseFile>,
    /// Empty for a legacy release (absent in its manifest); otherwise exactly
    /// [`PLUGIN_FILES`], in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugin_files: Vec<ReleaseFile>,
}

impl ReleaseManifest {
    /// Release directory name: `<version>+<label>`.
    pub fn release_id(&self) -> String {
        format!("{}+{}", self.version, self.build_label)
    }

    /// The `SHA256SUMS` text this manifest implies, given the manifest
    /// file's own digest.
    fn sums(&self, manifest_sha: &str) -> String {
        let mut text = format!("{manifest_sha}  {MANIFEST}\n");
        for file in &self.files {
            text.push_str(&format!("{}  bin/{}\n", file.sha256, file.name));
        }
        for file in &self.plugin_files {
            text.push_str(&format!("{}  {PLUGIN_DIR}/{}\n", file.sha256, file.name));
        }
        text
    }

    /// Structural rules: schema, product, label/version charset, target of
    /// this build, exactly the expected binary list and either no plugin files
    /// (legacy) or exactly [`PLUGIN_FILES`].
    fn check(&self) -> Result<(), String> {
        if self.schema != MANIFEST_SCHEMA || self.product != PRODUCT {
            return Err("manifest schema or product mismatch".into());
        }
        for (field, value) in [
            ("version", &self.version),
            ("build_label", &self.build_label),
        ] {
            if value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(format!("manifest {field} has an invalid form"));
            }
        }
        if self.target != target() {
            return Err(format!("bundle target {} is not {}", self.target, target()));
        }
        let names: Vec<&str> = self.files.iter().map(|file| file.name.as_str()).collect();
        if names != BINARIES {
            return Err("manifest does not list exactly the product binaries".into());
        }
        let plugins: Vec<&str> = self
            .plugin_files
            .iter()
            .map(|file| file.name.as_str())
            .collect();
        if !plugins.is_empty() && plugins != PLUGIN_FILES {
            return Err("manifest does not list exactly the plugin files".into());
        }
        Ok(())
    }
}

/// Persistent installation state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallState {
    /// Active release id.
    pub current: Option<String>,
    /// Release id a rollback returns to.
    pub previous: Option<String>,
    /// Highest core storage schema ever activated.
    pub max_core_schema: u32,
}

/// `<arch>-<os>` of this build.
pub fn target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// Lowercase hex SHA-256 of a file.
pub fn file_sha256(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(hex(&hasher.finalize()))
}

/// Lowercase hex of bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Builds a bundle at `out` from built binaries in `from`.
///
/// `from/bridge` must be this very executable (so the manifest's version
/// and label are the packaged `bridge`'s own). `out` must not exist.
/// With `plugin`, the explicit source directory of the OpenCode plugin, exactly
/// [`PLUGIN_FILES`] are copied from it as regular files (a missing file or a
/// link refuses; other entries of that directory, such as its test, are not
/// packaged); the path is never inferred from the working directory or
/// recorded. Without it the bundle is a legacy one.
/// Returns the manifest and the `SHA256SUMS` digest to hand to installers.
pub fn package(
    from: &Path,
    out: &Path,
    plugin: Option<&Path>,
) -> Result<(ReleaseManifest, String), String> {
    let own = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .map_err(|error| format!("own executable unreadable: {error}"))?;
    if file_sha256(&from.join("bridge"))? != file_sha256(&own)? {
        return Err("from/bridge is not the running bridge build".into());
    }
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(format!("{} already exists", out.display()));
    }
    std::fs::create_dir(out).map_err(|error| format!("{}: {error}", out.display()))?;
    std::fs::create_dir(out.join("bin")).map_err(|error| error.to_string())?;
    let mut files = Vec::new();
    let mut plugin_files = Vec::new();
    if let Some(plugin) = plugin {
        if !std::fs::symlink_metadata(plugin).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(format!("{} is not a plugin directory", plugin.display()));
        }
        std::fs::create_dir_all(out.join(PLUGIN_DIR)).map_err(|error| error.to_string())?;
        for name in PLUGIN_FILES {
            let source = plugin.join(name);
            let bytes = regular(&source)?;
            let destination = out.join(PLUGIN_DIR).join(name);
            std::fs::copy(&source, &destination).map_err(|error| error.to_string())?;
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o644))
                .map_err(|error| error.to_string())?;
            plugin_files.push(ReleaseFile {
                name: name.into(),
                sha256: file_sha256(&destination)?,
                bytes,
            });
        }
    }
    for name in BINARIES {
        let source = from.join(name);
        let metadata = std::fs::symlink_metadata(&source)
            .map_err(|error| format!("{}: {error}", source.display()))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", source.display()));
        }
        let destination = out.join("bin").join(name);
        std::fs::copy(&source, &destination).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        files.push(ReleaseFile {
            name: name.into(),
            sha256: file_sha256(&destination)?,
            bytes: metadata.len(),
        });
    }
    let manifest = ReleaseManifest {
        schema: MANIFEST_SCHEMA,
        product: PRODUCT.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        build_label: BUILD_LABEL.into(),
        target: target(),
        core_schema: bridge_core::schema::SCHEMA_VERSION,
        files,
        plugin_files,
    };
    manifest.check()?;
    let manifest_path = out.join(MANIFEST);
    write_file(
        &manifest_path,
        &serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
        0o644,
    )?;
    let sums = manifest.sums(&file_sha256(&manifest_path)?);
    write_file(&out.join(SUMS), sums.as_bytes(), 0o644)?;
    Ok((manifest, hex(&Sha256::digest(sums.as_bytes()))))
}

/// Verifies a bundle completely; see the module docs.
///
/// With `expected_sums`, the `SHA256SUMS` digest must equal it. Refuses
/// extra or missing entries, links, special files, size or digest
/// mismatches and a `SHA256SUMS` that is not exactly the manifest's.
pub fn verify_bundle(
    bundle: &Path,
    expected_sums: Option<&str>,
) -> Result<ReleaseManifest, String> {
    let sums = std::fs::read(bundle.join(SUMS)).map_err(|error| error.to_string())?;
    if let Some(expected) = expected_sums
        && hex(&Sha256::digest(&sums)) != expected
    {
        return Err("SHA256SUMS does not match the attested digest".into());
    }
    let manifest = verify_layout(bundle, &[SUMS])?;
    let expected = manifest.sums(&file_sha256(&bundle.join(MANIFEST))?);
    if sums != expected.as_bytes() {
        return Err("SHA256SUMS is not exactly the manifest's digests".into());
    }
    Ok(manifest)
}

/// Verifies a release directory: `release-manifest.json`, `bin/*` and, when
/// the manifest lists plugin files, `plugins/opencode/*` (exact entry sets,
/// regular files, sizes and digests).
pub fn verify_tree(dir: &Path) -> Result<ReleaseManifest, String> {
    verify_layout(dir, &[])
}

/// [`verify_tree`] where `dir` may also hold the `extra` top-level entries
/// (`SHA256SUMS` in a bundle) and nothing else.
fn verify_layout(dir: &Path, extra: &[&str]) -> Result<ReleaseManifest, String> {
    let manifest_path = dir.join(MANIFEST);
    regular(&manifest_path)?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("manifest unreadable: {error}"))?;
    manifest.check()?;
    let mut top = vec![MANIFEST, "bin"];
    top.extend(extra);
    let plugins = !manifest.plugin_files.is_empty();
    if plugins {
        top.push("plugins");
        exact_entries(&dir.join("plugins"), &["opencode"])?;
        exact_entries(&dir.join(PLUGIN_DIR), &PLUGIN_FILES)?;
    }
    exact_entries(dir, &top)?;
    exact_entries(&dir.join("bin"), &BINARIES)?;
    for (files, parent) in [
        (&manifest.files, dir.join("bin")),
        (&manifest.plugin_files, dir.join(PLUGIN_DIR)),
    ] {
        for file in files {
            let path = parent.join(&file.name);
            let size = regular(&path)?;
            if size != file.bytes || file_sha256(&path)? != file.sha256 {
                return Err(format!("{} does not match the manifest", file.name));
            }
        }
    }
    Ok(manifest)
}

/// Requires a regular file (not a link); returns its size.
fn regular(path: &Path) -> Result<u64, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(metadata.len())
}

/// Requires `dir` to be a real directory holding exactly `names`.
fn exact_entries(dir: &Path, names: &[&str]) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .map_err(|error| error.to_string())?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?;
    found.sort();
    let mut expected: Vec<String> = names.iter().map(ToString::to_string).collect();
    expected.sort();
    if found != expected {
        return Err(format!(
            "{} must hold exactly {expected:?}, found {found:?}",
            dir.display()
        ));
    }
    Ok(())
}

/// Writes a new file with `mode`, synced.
fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// The result of an install or rollback.
#[derive(Debug, Clone, Serialize)]
pub struct Activation {
    /// Active release id.
    pub current: String,
    /// Previous release id.
    pub previous: Option<String>,
    /// Whether the release directory already existed with identical bytes.
    pub reused: bool,
    /// Path and digest to configure as the adapters' trusted root relay
    /// (`[[adapters.relays]]`): the real release path, not the launcher.
    pub relay_binding: RelayBinding,
    /// Real release path and SHA-256 of the OpenCode plugin entrypoint to hand
    /// to its supervisor; `null` when the active release is a legacy one
    /// without the plugin (so a rollback to it reports none).
    pub plugin_binding: Option<RelayBinding>,
}

/// The identity of an executable or file by real release path and digest: the
/// root relay for the adapter registry, or the OpenCode plugin entrypoint.
#[derive(Debug, Clone, Serialize)]
pub struct RelayBinding {
    /// Absolute canonical release path (`bridge-root-relay`, or the plugin's
    /// `index.js`).
    pub path: PathBuf,
    /// Its SHA-256.
    pub sha256: String,
}

/// Takes the home's installer lock (held until the file is dropped).
///
/// The home must be absolute. An absent home is created with mode `0700`.
/// An existing one must be a real directory owned by this user that no
/// group or other user can write ([`crate::lifecycle::private_dir`]; its
/// mode is never changed) and that is either empty or already an Agent
/// Bridge home (holds `.lock` or the state file); anything else is refused
/// untouched, so user files are never mixed with or replaced by releases
/// and nobody else can swap a release the daemons will run.
fn lock_home(home: &Path) -> Result<File, String> {
    if !home.is_absolute() {
        return Err("the installation home must be an absolute path".into());
    }
    let existed = std::fs::symlink_metadata(home).is_ok();
    crate::lifecycle::private_dir(home, true)?;
    if existed {
        let ours = home.join(".lock").exists() || home.join(STATE).exists();
        let empty = std::fs::read_dir(home)
            .map_err(|error| error.to_string())?
            .next()
            .is_none();
        if !ours && !empty {
            return Err(format!(
                "{} is not empty and not an Agent Bridge home; refusing",
                home.display()
            ));
        }
    }
    let lock = crate::config::open_private(&home.join(".lock"))?;
    lock.lock()
        .map_err(|error| format!("cannot lock home: {error}"))?;
    Ok(lock)
}

/// Whether `id` has the release id form `<version>+<label>`, each part
/// 1–64 bytes of `[A-Za-z0-9._-]` (one path component, never `.`/`..`).
fn valid_release_id(id: &str) -> bool {
    let part = |text: &str| {
        (1..=64).contains(&text.len())
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    };
    id.split_once('+')
        .is_some_and(|(version, label)| part(version) && part(label))
}

/// Verifies the sealed release `id` of `home`: a valid id naming a real
/// directory (not a link), sealed read-only (no write bit, owner can read and
/// enter it; the installer sets `0555`, so a release that was
/// renamed into place but never sealed fails closed), whose verified manifest
/// has exactly that id. The home, its `releases` directory and the release directory must be owned by
/// this user with no group/other write ([`crate::lifecycle::private_dir`]),
/// so nobody else could have swapped what is about to be executed.
pub(crate) fn verify_release(home: &Path, id: &str) -> Result<ReleaseManifest, String> {
    if !valid_release_id(id) {
        return Err("installation state names an invalid release id".into());
    }
    let dir = home.join("releases").join(id);
    for owned in [home, &home.join("releases"), &dir] {
        crate::lifecycle::private_dir(owned, false)?;
    }
    let metadata =
        std::fs::symlink_metadata(&dir).map_err(|error| format!("release {id}: {error}"))?;
    if !metadata.is_dir() {
        return Err(format!("release {id} is not a directory"));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o222 != 0 || mode & 0o500 != 0o500 {
        return Err(format!(
            "release {id} is not sealed read-only (an interrupted install?); \
             remove that release directory and install again"
        ));
    }
    let manifest = verify_tree(&dir)?;
    if manifest.release_id() != id {
        return Err(format!("release {id} holds a manifest of another release"));
    }
    Ok(manifest)
}

/// Loads the installation state (absent: empty). The state file must be
/// a private regular file of this user (never a link) and name only valid
/// release ids.
pub fn load_state(home: &Path) -> Result<InstallState, String> {
    crate::config::private_file(&home.join(STATE))?;
    let state: InstallState = match std::fs::read(home.join(STATE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("installation state is corrupt: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => InstallState::default(),
        Err(error) => return Err(error.to_string()),
    };
    if [&state.current, &state.previous]
        .into_iter()
        .flatten()
        .any(|id| !valid_release_id(id))
    {
        return Err("installation state names an invalid release id".into());
    }
    Ok(state)
}

/// Atomically replaces the installation state through an exclusively
/// created, unpredictable temporary file (removed only by this call, on
/// failure), then syncs the home directory.
fn save_state(home: &Path, state: &InstallState) -> Result<(), String> {
    let temporary = home.join(format!(".{STATE}.{}.tmp", crate::config::random_hex(12)?));
    write_file(
        &temporary,
        &serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?,
        0o600,
    )?;
    std::fs::rename(&temporary, home.join(STATE)).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        error.to_string()
    })?;
    File::open(home)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| error.to_string())
}

/// Test-only callback run once with the staging directory just before [`seal`]
/// renames it.
#[cfg(test)]
type StagingHook = Box<dyn FnOnce(&Path)>;

/// Test-only callback run once right after the bundle was verified.
#[cfg(test)]
type RaceHook = Box<dyn FnOnce()>;

#[cfg(test)]
thread_local! {
    /// Test-only fault point: the next `current` switch fails before it
    /// changes anything (an interruption after the state was recorded).
    static FAIL_NEXT_SWITCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only fault point: the next [`seal`] fails right after the release
    /// directory was renamed into place, before it is sealed `0555`.
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only inspection point: runs once with the staging directory just
    /// before [`seal`] renames it, to observe its permissions at that moment.
    static BEFORE_RENAME: std::cell::RefCell<Option<StagingHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Test-only race point: runs once right after the bundle was verified,
    /// standing in for a writer that changes a writable bundle before it is
    /// copied.
    static AFTER_BUNDLE_VERIFIED: std::cell::RefCell<Option<RaceHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Points `home/current` at `releases/<id>` atomically through an
/// unpredictable temporary link (creating it fails on any existing path;
/// removed only by this call, on failure), then syncs the home directory.
fn switch_current(home: &Path, id: &str) -> Result<(), String> {
    #[cfg(test)]
    if FAIL_NEXT_SWITCH.with(|fail| fail.replace(false)) {
        return Err("injected interruption before the current link switch".into());
    }
    let temporary = home.join(format!(".current.{}.tmp", crate::config::random_hex(12)?));
    std::os::unix::fs::symlink(Path::new("releases").join(id), &temporary)
        .map_err(|error| error.to_string())?;
    std::fs::rename(&temporary, home.join("current")).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        error.to_string()
    })?;
    File::open(home)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| error.to_string())
}

/// The release id `home/current` points at (`None` when there is no link).
fn current_link(home: &Path) -> Result<Option<String>, String> {
    match std::fs::read_link(home.join("current")) {
        Ok(target) => target
            .strip_prefix("releases")
            .ok()
            .and_then(|id| id.to_str())
            .filter(|id| valid_release_id(id))
            .map(|id| Some(id.to_string()))
            .ok_or_else(|| "home/current points outside the sealed releases".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("home/current: {error}")),
    }
}

/// Read-only check that `home/current` is exactly the recorded active
/// release. A mismatch means an interrupted activation (the state, with
/// its schema floor, is always recorded before the link changes); it is
/// reported, never guessed around: run install or rollback to complete it.
pub fn check_current(home: &Path) -> Result<String, String> {
    let state = load_state(home)?;
    let link = current_link(home)?;
    match (&state.current, &link) {
        (Some(recorded), Some(linked)) if recorded == linked => Ok(recorded.clone()),
        (None, None) => Err("nothing is installed".into()),
        _ => Err(format!(
            "interrupted activation: state records {:?} but current points at {:?}; run install or rollback to complete it",
            state.current, link
        )),
    }
}

/// Completes an interrupted activation under the home lock: when the
/// link differs from the recorded active release, re-verifies that release
/// and points the link at it. Returns the state.
fn reconcile(home: &Path) -> Result<InstallState, String> {
    let state = load_state(home)?;
    let link = current_link(home)?;
    match &state.current {
        Some(recorded) if link.as_ref() != Some(recorded) => {
            verify_release(home, recorded)?;
            switch_current(home, recorded)?;
        }
        None if link.is_some() => {
            return Err("home/current exists without installation state; refusing".into());
        }
        _ => {}
    }
    Ok(state)
}

/// Records `next` as the active state, then switches the link to its
/// current release. The state (and its schema floor) is durable before
/// the link changes, so an interruption leaves a recorded intent that
/// [`check_current`] reports and [`reconcile`] completes.
fn activate(home: &Path, next: &InstallState) -> Result<(), String> {
    let id = next
        .current
        .as_deref()
        .ok_or_else(|| "no release to activate".to_string())?;
    save_state(home, next)?;
    switch_current(home, id)
}

/// Installs a verified bundle into `home`, activates it and links
/// launchers into `bin_dir`.
///
/// `expected_sums` is the out-of-band `SHA256SUMS` digest and is
/// mandatory: a bundle is installed only when it matches. Order: verify
/// the bundle, lock and reconcile the home (an existing home or `releases`
/// directory writable by group or others refuses untouched), check launcher
/// paths, seal the release (its staged bytes must hash to `expected_sums`,
/// so a bundle changed after verification refuses; or reuse an identical
/// one; same id with other bytes refuses),
/// refuse a schema downgrade, record the new state and floor, switch
/// `current`, create missing launchers.
pub fn self_install(
    bundle: &Path,
    home: &Path,
    bin_dir: &Path,
    expected_sums: &str,
) -> Result<Activation, String> {
    let manifest = verify_bundle(bundle, Some(expected_sums))?;
    #[cfg(test)]
    if let Some(race) = AFTER_BUNDLE_VERIFIED.with(|slot| slot.borrow_mut().take()) {
        race();
    }
    if !bin_dir.is_absolute() {
        return Err("the launcher directory must be an absolute path".into());
    }
    let _lock = lock_home(home)?;
    let mut state = reconcile(home)?;
    let launchers = launcher_plan(home, bin_dir)?;
    let id = manifest.release_id();
    let releases = home.join("releases");
    crate::lifecycle::private_dir(&releases, true)?;
    let reused = if std::fs::symlink_metadata(releases.join(&id)).is_ok() {
        if verify_release(home, &id)? != manifest {
            return Err(format!("release {id} exists with different bytes"));
        }
        true
    } else {
        seal(bundle, &releases, &id, expected_sums)?;
        false
    };
    if manifest.core_schema < state.max_core_schema {
        return Err(format!(
            "release {id} has core schema {} older than the activated schema {}; refusing a downgrade",
            manifest.core_schema, state.max_core_schema
        ));
    }
    if state.current.as_deref() != Some(id.as_str()) {
        state.previous = state.current.take();
    }
    state.current = Some(id.clone());
    state.max_core_schema = state.max_core_schema.max(manifest.core_schema);
    activate(home, &state)?;
    for (link, target) in launchers {
        std::os::unix::fs::symlink(&target, &link)
            .map_err(|error| format!("{}: {error}", link.display()))?;
    }
    activation(home, &state, &manifest, reused)
}

/// Launchers still to create; refuses a foreign file at any launcher path.
fn launcher_plan(home: &Path, bin_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    std::fs::create_dir_all(bin_dir).map_err(|error| error.to_string())?;
    let mut missing = Vec::new();
    for name in BINARIES {
        let link = bin_dir.join(name);
        let target = home.join("current").join("bin").join(name);
        match std::fs::read_link(&link) {
            Ok(existing) if existing == target => {}
            Ok(_) => return Err(format!("{} is a foreign link; refusing", link.display())),
            Err(_) if std::fs::symlink_metadata(&link).is_ok() => {
                return Err(format!(
                    "{} exists and is not ours; refusing",
                    link.display()
                ));
            }
            Err(_) => missing.push((link, target)),
        }
    }
    Ok(missing)
}

/// Copies a verified bundle into an exclusively created, unpredictable
/// staging directory, re-verifies it, seals permissions and renames it to
/// `releases/<id>`. The copy is read again from the bundle, so the staged
/// files must hash — manifest and every binary — to the original attested
/// `expected_sums` digest (the digest of the `SHA256SUMS` those hashes imply);
/// a bundle changed after [`verify_bundle`], even consistently, is refused.
///
/// Sequencing: the staging directory is owner-private (`0700`) and writable
/// until it has been renamed, because some platforms refuse to rename a
/// directory the owner cannot write (macOS 15 answers `EACCES` for a `0555`
/// source). The files are created read-only and `bin/` is sealed `0555`
/// before the rename; only after the rename is the final release directory
/// itself sealed `0555`, and the function returns only then. Nothing can
/// activate the release earlier, because activation follows this call, and
/// [`verify_release`] refuses a release directory that is still writable.
///
/// On failure only what this call created is removed: the staging directory,
/// or, once renamed, the final release directory it just made (the caller
/// has checked under the home lock that `releases/<id>` did not exist).
/// Leftovers of other runs and foreign releases are never touched.
fn seal(bundle: &Path, releases: &Path, id: &str, expected_sums: &str) -> Result<(), String> {
    let staging = releases.join(format!(".staging-{id}-{}", crate::config::random_hex(12)?));
    let target = releases.join(id);
    std::fs::create_dir(&staging).map_err(|error| format!("cannot create staging: {error}"))?;
    let mut renamed = false;
    let result = (|| {
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        std::fs::create_dir(staging.join("bin")).map_err(|error| error.to_string())?;
        if bundle.join("plugins").exists() {
            std::fs::create_dir_all(staging.join(PLUGIN_DIR)).map_err(|error| error.to_string())?;
        }
        let executables = BINARIES.iter().map(|name| {
            (
                bundle.join("bin").join(name),
                staging.join("bin").join(name),
                0o555,
            )
        });
        let plugin_files = PLUGIN_FILES
            .iter()
            .filter(|_| bundle.join("plugins").exists())
            .map(|name| {
                (
                    bundle.join(PLUGIN_DIR).join(name),
                    staging.join(PLUGIN_DIR).join(name),
                    0o444,
                )
            });
        for (from, to, mode) in
            std::iter::once((bundle.join(MANIFEST), staging.join(MANIFEST), 0o444))
                .chain(executables)
                .chain(plugin_files)
        {
            let bytes = std::fs::read(&from).map_err(|error| error.to_string())?;
            write_file(&to, &bytes, mode)?;
        }
        let staged = verify_tree(&staging)?;
        let implied = staged.sums(&file_sha256(&staging.join(MANIFEST))?);
        if hex(&Sha256::digest(implied.as_bytes())) != expected_sums {
            return Err("the sealed bytes do not match the attested digest".into());
        }
        for sealed in [
            staging.join("bin"),
            staging.join(PLUGIN_DIR),
            staging.join("plugins"),
        ] {
            if sealed.exists() {
                std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555))
                    .map_err(|error| error.to_string())?;
            }
        }
        #[cfg(test)]
        if let Some(inspect) = BEFORE_RENAME.with(|slot| slot.borrow_mut().take()) {
            inspect(&staging);
        }
        std::fs::rename(&staging, &target).map_err(|error| error.to_string())?;
        renamed = true;
        #[cfg(test)]
        if FAIL_AFTER_RENAME.with(|fail| fail.replace(false)) {
            return Err("injected failure after the release rename".into());
        }
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o555))
            .map_err(|error| error.to_string())?;
        File::open(releases)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let ours = if renamed { &target } else { &staging };
        let _ = std::fs::set_permissions(ours, std::fs::Permissions::from_mode(0o755));
        for sealed in ["bin", "plugins", PLUGIN_DIR] {
            let _ =
                std::fs::set_permissions(ours.join(sealed), std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_dir_all(ours);
    }
    result
}

/// Re-activates the previous release.
///
/// Under the home lock, first completes any interrupted activation. Then
/// requires a recorded previous release that still verifies and whose core
/// schema is not older than the highest activated one (the floor never
/// moves down). Only the state and the `current` link change, state
/// first.
pub fn rollback(home: &Path) -> Result<Activation, String> {
    let _lock = lock_home(home)?;
    let mut state = reconcile(home)?;
    let previous = state
        .previous
        .clone()
        .ok_or_else(|| "no previous release recorded".to_string())?;
    let manifest = verify_release(home, &previous)?;
    if manifest.core_schema < state.max_core_schema {
        return Err(format!(
            "previous release {previous} has core schema {} older than the activated schema {}; a live schema is never downgraded",
            manifest.core_schema, state.max_core_schema
        ));
    }
    state.previous = state.current.replace(previous);
    activate(home, &state)?;
    activation(home, &state, &manifest, true)
}

/// Builds the activation report for the current state; `manifest` is the
/// verified manifest of the active release and decides whether a plugin
/// binding exists.
fn activation(
    home: &Path,
    state: &InstallState,
    manifest: &ReleaseManifest,
    reused: bool,
) -> Result<Activation, String> {
    let current = state
        .current
        .clone()
        .ok_or_else(|| "no active release".to_string())?;
    let path = home
        .join("releases")
        .join(&current)
        .join("bin")
        .join("bridge-root-relay")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let plugin_binding = if manifest.plugin_files.is_empty() {
        None
    } else {
        let entry = home
            .join("releases")
            .join(&current)
            .join(PLUGIN_DIR)
            .join(PLUGIN_FILES[0])
            .canonicalize()
            .map_err(|error| error.to_string())?;
        Some(RelayBinding {
            sha256: file_sha256(&entry)?,
            path: entry,
        })
    };
    Ok(Activation {
        relay_binding: RelayBinding {
            sha256: file_sha256(&path)?,
            path,
        },
        plugin_binding,
        current,
        previous: state.previous.clone(),
        reused,
    })
}

#[cfg(test)]
mod tests {
    //! Bundle, seal, activation and rollback rules on small synthetic
    //! files (the real built binaries are exercised by `cargo xtask
    //! qualify`). The bundle is assembled directly because [`package`]
    //! requires the running executable.

    use super::*;

    use crate::testdir::TestDir;

    /// Writes a synthetic legacy (no plugin) bundle whose binaries hold `content`.
    fn bundle(dir: &Path, label: &str, content: &str, core_schema: u32) -> (PathBuf, String) {
        assemble(dir, label, content, core_schema, false)
    }

    /// Writes a synthetic bundle; with `plugin` it also carries the two
    /// plugin files, whose text holds `content`.
    fn assemble(
        dir: &Path,
        label: &str,
        content: &str,
        core_schema: u32,
        plugin: bool,
    ) -> (PathBuf, String) {
        let out = dir.join(format!("bundle-{label}"));
        std::fs::create_dir_all(out.join("bin")).unwrap();
        let describe = |path: &Path, name: &str| ReleaseFile {
            name: name.into(),
            sha256: file_sha256(path).unwrap(),
            bytes: std::fs::metadata(path).unwrap().len(),
        };
        let mut files = Vec::new();
        for name in BINARIES {
            let path = out.join("bin").join(name);
            std::fs::write(&path, format!("#!/bin/sh\necho {name} {content}\n")).unwrap();
            files.push(describe(&path, name));
        }
        let mut plugin_files = Vec::new();
        if plugin {
            std::fs::create_dir_all(out.join(PLUGIN_DIR)).unwrap();
            for name in PLUGIN_FILES {
                let path = out.join(PLUGIN_DIR).join(name);
                std::fs::write(&path, format!("// {name} {content}\n")).unwrap();
                plugin_files.push(describe(&path, name));
            }
        }
        let manifest = ReleaseManifest {
            schema: MANIFEST_SCHEMA,
            product: PRODUCT.into(),
            version: "0.1.0".into(),
            build_label: label.into(),
            target: target(),
            core_schema,
            files,
            plugin_files,
        };
        std::fs::write(
            out.join(MANIFEST),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let sums = manifest.sums(&file_sha256(&out.join(MANIFEST)).unwrap());
        std::fs::write(out.join(SUMS), &sums).unwrap();
        (out, hex(&Sha256::digest(sums.as_bytes())))
    }

    /// A bundle verifies only against its attested digest; changed bytes and
    /// extra files are refused.
    #[test]
    fn tampered_or_unattested_bundles_are_refused() {
        let scratch = TestDir::new("itamper");
        let dir = scratch.path();
        let (out, sums) = bundle(dir, "a", "one", 4);
        verify_bundle(&out, Some(&sums)).unwrap();
        assert!(verify_bundle(&out, Some(&"0".repeat(64))).is_err());
        std::fs::write(out.join("bin").join("bridge"), "evil").unwrap();
        assert!(verify_bundle(&out, None).is_err(), "changed bytes refused");
        let (extra, _) = bundle(dir, "b", "two", 4);
        std::fs::write(extra.join("bin").join("payload"), "x").unwrap();
        assert!(verify_bundle(&extra, None).is_err(), "extra file refused");
    }

    /// Plugin bytes are attested, sealed and reused; legacy rollback reports no
    /// binding, and rolling forward again restores the exact canonical binding.
    #[test]
    fn plugin_install_reuse_and_legacy_rollback() {
        let scratch = TestDir::new("iplugin");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (legacy, _) = bundle(dir, "legacy", "old", 4);
        let mut legacy_manifest = verify_bundle(&legacy, None).unwrap();
        legacy_manifest.version = "0.2.0".into();
        std::fs::write(
            legacy.join(MANIFEST),
            serde_json::to_vec_pretty(&legacy_manifest).unwrap(),
        )
        .unwrap();
        let legacy_text = legacy_manifest.sums(&file_sha256(&legacy.join(MANIFEST)).unwrap());
        std::fs::write(legacy.join(SUMS), &legacy_text).unwrap();
        let legacy_sums = hex(&Sha256::digest(legacy_text.as_bytes()));
        let legacy_manifest = std::fs::read_to_string(legacy.join(MANIFEST)).unwrap();
        assert!(!legacy_manifest.contains("plugin_files"));
        assert!(
            self_install(&legacy, &home, &bin, &legacy_sums)
                .unwrap()
                .plugin_binding
                .is_none()
        );
        let (plugin, sums) = assemble(dir, "plugin", "new", 4, true);
        let manifest = verify_bundle(&plugin, Some(&sums)).unwrap();
        let installed = self_install(&plugin, &home, &bin, &sums).unwrap();
        let binding = installed.plugin_binding.unwrap();
        assert_eq!(
            binding.path,
            home.join("releases/0.1.0+plugin/plugins/opencode/index.js")
                .canonicalize()
                .unwrap()
        );
        assert_eq!(binding.sha256, manifest.plugin_files[0].sha256);
        assert_eq!(
            std::fs::read(&binding.path).unwrap(),
            std::fs::read(plugin.join(PLUGIN_DIR).join("index.js")).unwrap()
        );
        for name in PLUGIN_FILES {
            assert_eq!(
                std::fs::metadata(binding.path.parent().unwrap().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o444
            );
        }
        for path in [
            binding.path.parent().unwrap().to_path_buf(),
            home.join("releases/0.1.0+plugin/plugins"),
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o555
            );
        }
        assert_eq!(std::fs::read_dir(&bin).unwrap().count(), BINARIES.len());
        assert!(self_install(&plugin, &home, &bin, &sums).unwrap().reused);
        assert!(rollback(&home).unwrap().plugin_binding.is_none());
        let restored = rollback(&home).unwrap().plugin_binding.unwrap();
        assert_eq!(restored.path, binding.path);
        assert_eq!(restored.sha256, binding.sha256);
        std::fs::set_permissions(&binding.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&binding.path, "tampered").unwrap();
        assert!(
            self_install(&plugin, &home, &bin, &sums).is_err(),
            "tampered reuse refused"
        );
    }

    /// Missing, additional, linked and changed plugin entries never verify or
    /// activate. Nested directory links cannot escape exact-tree verification.
    #[test]
    fn plugin_layout_and_attestation_refusals() {
        let scratch = TestDir::new("iplugbad");
        let dir = scratch.path();
        for kind in ["missing", "extra", "link", "tamper", "directory", "top"] {
            let (out, sums) = assemble(dir, kind, "synthetic", 4, true);
            let entry = out.join(PLUGIN_DIR).join("index.js");
            match kind {
                "missing" => std::fs::remove_file(&entry).unwrap(),
                "extra" => std::fs::write(out.join(PLUGIN_DIR).join("extra.js"), "x").unwrap(),
                "link" => {
                    std::fs::remove_file(&entry).unwrap();
                    std::os::unix::fs::symlink(out.join(MANIFEST), &entry).unwrap();
                }
                "tamper" => std::fs::write(&entry, "changed").unwrap(),
                "directory" => {
                    std::fs::rename(out.join(PLUGIN_DIR), out.join("external")).unwrap();
                    std::os::unix::fs::symlink(out.join("external"), out.join(PLUGIN_DIR)).unwrap();
                }
                "top" => std::fs::write(out.join("plugins/extra"), "x").unwrap(),
                _ => unreachable!(),
            }
            assert!(verify_bundle(&out, Some(&sums)).is_err(), "{kind}");
            let home = dir.join(format!("home-{kind}"));
            assert!(
                self_install(&out, &home, &dir.join("bin"), &sums).is_err(),
                "{kind}"
            );
            assert!(!home.exists());
        }
    }

    /// A plugin changed after bundle verification cannot pass the sealed-byte
    /// attestation fence or leave an activated release behind.
    #[test]
    fn plugin_tamper_during_seal_is_refused() {
        let scratch = TestDir::new("iplugrace");
        let dir = scratch.path();
        let (out, sums) = assemble(dir, "a", "good", 4, true);
        let entry = out.join(PLUGIN_DIR).join("index.js");
        AFTER_BUNDLE_VERIFIED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || std::fs::write(entry, "changed").unwrap()));
        });
        assert!(self_install(&out, &dir.join("home"), &dir.join("bin"), &sums).is_err());
        assert!(std::fs::symlink_metadata(dir.join("home/current")).is_err());
    }

    /// Install, no-op reinstall, upgrade and rollback work; an unattested digest,
    /// a same-id different-content bundle and a core-schema downgrade are
    /// refused.
    #[test]
    fn install_activate_rollback_and_refusals() {
        let scratch = TestDir::new("icycle");
        let dir = scratch.path();
        let home = dir.join("home");
        let bin = dir.join("bin");
        let (one, sums_one) = bundle(dir, "a", "one", 4);
        let (two, sums_two) = bundle(dir, "b", "two", 4);
        let unattested = self_install(&one, &home, &bin, &"0".repeat(64));
        assert!(
            unattested.is_err(),
            "a bundle is installed only against its attested digest"
        );
        assert!(std::fs::symlink_metadata(home.join("current")).is_err());
        let first = self_install(&one, &home, &bin, &sums_one).unwrap();
        assert_eq!(first.current, "0.1.0+a");
        assert!(!first.reused);
        let again = self_install(&one, &home, &bin, &sums_one).unwrap();
        assert!(again.reused, "identical reinstall is a no-op");
        let second = self_install(&two, &home, &bin, &sums_two).unwrap();
        assert_eq!(second.previous.as_deref(), Some("0.1.0+a"));
        assert!(
            std::fs::read_to_string(bin.join("bridge"))
                .unwrap()
                .contains("two")
        );
        let back = rollback(&home).unwrap();
        assert_eq!(back.current, "0.1.0+a");
        assert!(
            std::fs::read_to_string(bin.join("bridge"))
                .unwrap()
                .contains("one")
        );

        let (same_id, sums_same) = bundle(&dir.join("other"), "a", "different", 4);
        assert!(self_install(&same_id, &home, &bin, &sums_same).is_err());

        let (old, sums_old) = bundle(dir, "c", "old", 3);
        let error = self_install(&old, &home, &bin, &sums_old).unwrap_err();
        assert!(error.contains("downgrade"), "{error}");
    }

    /// A pre-existing foreign launcher file refuses the install and is left
    /// unchanged with no release activated.
    #[test]
    fn foreign_launcher_files_are_preserved() {
        let scratch = TestDir::new("iforeign");
        let dir = scratch.path();
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("bridge-hook"), "user file").unwrap();
        let (one, sums) = bundle(dir, "a", "one", 4);
        assert!(self_install(&one, &dir.join("home"), &bin, &sums).is_err());
        assert_eq!(
            std::fs::read_to_string(bin.join("bridge-hook")).unwrap(),
            "user file"
        );
        assert!(std::fs::symlink_metadata(dir.join("home/current")).is_err());
    }

    /// A non-empty home the installer does not own refuses install and rollback
    /// and gains no entries.
    #[test]
    fn a_foreign_nonempty_home_is_refused_untouched() {
        let scratch = TestDir::new("ihome");
        let dir = scratch.path();
        let home = dir.join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("notes.txt"), "user data").unwrap();
        let (one, sums) = bundle(dir, "a", "one", 4);
        assert!(self_install(&one, &home, &dir.join("bin"), &sums).is_err());
        assert!(rollback(&home).is_err());
        let entries: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("notes.txt")],
            "nothing added"
        );
    }

    /// A bundle rewritten consistently (manifest, sums and binaries) after it
    /// was verified is refused at seal time: the sealed bytes must hash to the
    /// attested digest, not merely agree with their own manifest.
    #[test]
    fn a_bundle_swapped_after_verification_is_not_sealed() {
        let scratch = TestDir::new("iswap");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (good, sums) = bundle(dir, "a", "good", 4);
        let (evil, _) = bundle(&dir.join("evil"), "a", "evil", 4);
        let target = good.clone();
        AFTER_BUNDLE_VERIFIED.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::copy(evil.join(MANIFEST), target.join(MANIFEST)).unwrap();
                std::fs::copy(evil.join(SUMS), target.join(SUMS)).unwrap();
                for name in BINARIES {
                    std::fs::copy(evil.join("bin").join(name), target.join("bin").join(name))
                        .unwrap();
                }
            }));
        });
        let error = self_install(&good, &home, &bin, &sums).unwrap_err();
        assert!(error.contains("attested digest"), "{error}");
        assert!(std::fs::symlink_metadata(home.join("current")).is_err());
        assert!(
            std::fs::read_dir(home.join("releases"))
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(true),
            "nothing sealed or left behind"
        );
    }

    /// An existing home or `releases` directory that group/other users can
    /// write is refused untouched (no silent mode change, nothing added).
    #[test]
    fn unsafe_owned_homes_and_release_directories_are_refused_untouched() {
        let scratch = TestDir::new("iprivacy");
        let dir = scratch.path();
        let (one, sums) = bundle(dir, "a", "one", 4);
        let home = dir.join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o775)).unwrap();
        let error = self_install(&one, &home, &dir.join("bin"), &sums).unwrap_err();
        assert!(error.contains("without group/other write"), "{error}");
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o775,
            "mode left unchanged"
        );
        assert!(rollback(&home).is_err());
        assert_eq!(
            std::fs::read_dir(&home).unwrap().count(),
            0,
            "nothing added"
        );

        let other = dir.join("home2");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join(".lock"), "").unwrap();
        std::fs::set_permissions(other.join(".lock"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::create_dir(other.join("releases")).unwrap();
        std::fs::set_permissions(
            other.join("releases"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let error = self_install(&one, &other, &dir.join("bin"), &sums).unwrap_err();
        assert!(error.contains("without group/other write"), "{error}");
        assert_eq!(
            std::fs::metadata(other.join("releases"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o777,
            "mode left unchanged"
        );
        assert_eq!(
            std::fs::read_dir(other.join("releases")).unwrap().count(),
            0
        );
    }

    /// The release id the `current` link names.
    fn linked(home: &Path) -> Option<String> {
        current_link(home).unwrap()
    }

    /// After an interrupted switch the schema floor is already recorded; rollback
    /// completes the recorded activation and then refuses to go below the floor.
    #[test]
    fn an_interrupted_activation_keeps_the_floor_and_is_completed_not_downgraded() {
        let scratch = TestDir::new("iint");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (a, sums_a) = bundle(dir, "a", "one", 4);
        let (c, sums_c) = bundle(dir, "c", "newer", 5);
        self_install(&a, &home, &bin, &sums_a).unwrap();
        FAIL_NEXT_SWITCH.with(|fail| fail.set(true));
        let error = self_install(&c, &home, &bin, &sums_c).unwrap_err();
        assert!(error.contains("injected"), "{error}");
        let state = load_state(&home).unwrap();
        assert_eq!(state.current.as_deref(), Some("0.1.0+c"));
        assert_eq!(state.max_core_schema, 5, "floor recorded before the link");
        assert_eq!(linked(&home).as_deref(), Some("0.1.0+a"));
        assert!(check_current(&home).unwrap_err().contains("interrupted"));
        // Rollback first completes the recorded activation, then refuses
        // to go below the floor.
        let refused = rollback(&home).unwrap_err();
        assert!(refused.contains("never downgraded"), "{refused}");
        assert_eq!(linked(&home).as_deref(), Some("0.1.0+c"));
        assert_eq!(check_current(&home).unwrap(), "0.1.0+c");
        assert_eq!(load_state(&home).unwrap().max_core_schema, 5);
    }

    /// Repeating an interrupted install completes it as a reuse and keeps the
    /// previous release for rollback.
    #[test]
    fn retrying_an_interrupted_install_completes_it() {
        let scratch = TestDir::new("iretry");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (a, sums_a) = bundle(dir, "a", "one", 4);
        let (b, sums_b) = bundle(dir, "b", "two", 4);
        self_install(&a, &home, &bin, &sums_a).unwrap();
        FAIL_NEXT_SWITCH.with(|fail| fail.set(true));
        assert!(self_install(&b, &home, &bin, &sums_b).is_err());
        let done = self_install(&b, &home, &bin, &sums_b).unwrap();
        assert!(done.reused);
        assert_eq!(done.previous.as_deref(), Some("0.1.0+a"));
        assert_eq!(check_current(&home).unwrap(), "0.1.0+b");
        assert_eq!(rollback(&home).unwrap().current, "0.1.0+a");
    }

    /// State naming a path outside the home, or a release link that is not a
    /// directory, is refused without changing the active release.
    #[test]
    fn escaping_or_mismatched_state_is_refused() {
        let scratch = TestDir::new("istate");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (a, sums_a) = bundle(dir, "a", "one", 4);
        self_install(&a, &home, &bin, &sums_a).unwrap();
        let state_file = home.join(STATE);
        let original = std::fs::read(&state_file).unwrap();
        std::fs::write(
            &state_file,
            r#"{"current":"0.1.0+a","previous":"../../outside","max_core_schema":4}"#,
        )
        .unwrap();
        assert!(load_state(&home).is_err());
        assert!(rollback(&home).is_err());
        // A release directory that is a link to another release is refused.
        std::os::unix::fs::symlink("0.1.0+a", home.join("releases").join("0.1.0+z")).unwrap();
        std::fs::write(
            &state_file,
            r#"{"current":"0.1.0+a","previous":"0.1.0+z","max_core_schema":4}"#,
        )
        .unwrap();
        assert!(rollback(&home).unwrap_err().contains("not a directory"));
        assert_eq!(linked(&home).as_deref(), Some("0.1.0+a"));
        std::fs::write(&state_file, original).unwrap();
        check_current(&home).unwrap();
    }

    /// The staging directory is still owner-writable (`0700`) when it is
    /// renamed, because macOS 15 refuses to rename a directory its owner cannot
    /// write; afterwards the release, its `bin/` and its files are sealed
    /// read-only, and a release directory that is not `0555` fails closed.
    #[test]
    fn staging_is_writable_at_rename_and_the_release_is_sealed_afterwards() {
        use std::cell::Cell;
        use std::rc::Rc;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let scratch = TestDir::new("iseal");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (a, sums) = bundle(dir, "a", "one", 4);
        let seen = Rc::new(Cell::new((0, 0)));
        let slot = Rc::clone(&seen);
        BEFORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |staging| {
                slot.set((mode(staging), mode(&staging.join("bin"))));
            }));
        });
        self_install(&a, &home, &bin, &sums).unwrap();
        assert_eq!(seen.get(), (0o700, 0o555), "owner-writable top, sealed bin");
        let release = home.join("releases/0.1.0+a");
        assert_eq!(mode(&release), 0o555);
        assert_eq!(mode(&release.join("bin")), 0o555);
        // Files keep the creation mask (a 077 umask yields 0400/0500), so the
        // invariant is read-only for the owner: no write bit, owner can read.
        for file in [
            release.join(MANIFEST),
            release.join("bin").join(BINARIES[0]),
        ] {
            assert_eq!(mode(&file) & 0o222, 0, "{}", file.display());
            assert_eq!(mode(&file) & 0o400, 0o400, "{}", file.display());
        }
        std::fs::set_permissions(&release, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = verify_release(&home, "0.1.0+a").unwrap_err();
        assert!(error.contains("not sealed"), "{error}");
        std::fs::set_permissions(&release, std::fs::Permissions::from_mode(0o555)).unwrap();
        verify_release(&home, "0.1.0+a").unwrap();
    }

    /// A failure right after the rename removes only the release this call
    /// created and activates nothing; a sibling release stays intact and a
    /// retry completes.
    #[test]
    fn a_failure_after_the_rename_removes_only_the_new_release() {
        let scratch = TestDir::new("ifault");
        let dir = scratch.path();
        let (home, bin) = (dir.join("home"), dir.join("bin"));
        let (a, sums_a) = bundle(dir, "a", "one", 4);
        let (b, sums_b) = bundle(dir, "b", "two", 4);
        self_install(&a, &home, &bin, &sums_a).unwrap();
        FAIL_AFTER_RENAME.with(|fail| fail.set(true));
        let error = self_install(&b, &home, &bin, &sums_b).unwrap_err();
        assert!(error.contains("injected"), "{error}");
        let names: Vec<_> = std::fs::read_dir(home.join("releases"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("0.1.0+a")]);
        assert_eq!(check_current(&home).unwrap(), "0.1.0+a");
        verify_release(&home, "0.1.0+a").unwrap();
        assert_eq!(
            self_install(&b, &home, &bin, &sums_b).unwrap().current,
            "0.1.0+b"
        );
    }
}
