//! `install.sh` runs only a private, hash-verified copy of the bundle: a
//! bundle that changes after the check cannot change what is executed.
//!
//! The bundle is synthetic (inert shell scripts with a consistent
//! `SHA256SUMS`); the stand-in `bridge` records how it was invoked. Every
//! path is a fresh exclusively created scratch tree under the configured
//! temporary root.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use bridge_interfaces::install::{BINARIES, file_sha256};
use sha2::{Digest, Sha256};

/// Writes a synthetic bundle in `root/bundle` whose `bridge` appends its own
/// path and arguments to `root/ran`; returns the `SHA256SUMS` digest.
fn bundle(root: &std::path::Path) -> String {
    let dir = root.join("bundle");
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    let mut sums = String::new();
    std::fs::write(dir.join("release-manifest.json"), "{}").unwrap();
    sums.push_str(&format!(
        "{}  release-manifest.json\n",
        file_sha256(&dir.join("release-manifest.json")).unwrap()
    ));
    for name in BINARIES {
        let path = dir.join("bin").join(name);
        let body = if name == "bridge" {
            format!(
                "#!/bin/sh\necho \"$0 $*\" >> {}\n",
                root.join("ran").display()
            )
        } else {
            format!("#!/bin/sh\necho {name}\n")
        };
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        sums.push_str(&format!("{}  bin/{name}\n", file_sha256(&path).unwrap()));
    }
    std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
    Sha256::digest(sums.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether this host is one `install.sh` supports (it refuses others).
fn supported() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

/// Exclusively creates `bii<12 random hex>` under the configured temporary root
/// with mode `0700` and returns its canonical path. Panics on collision or I/O
/// failure; the calling test owns cleanup. Socket fixtures require a root short
/// enough for macOS's approximately 104-byte Unix socket path ceiling.
fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "bii{}",
        bridge_adapters::os::random_bytes().unwrap()[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root.canonicalize().unwrap()
}

/// Runs `install.sh` on `root/bundle` with the attested digest `sums`.
fn install(root: &std::path::Path, sums: &str) -> std::process::Output {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
    Command::new("/bin/bash")
        .arg(&script)
        .args(["--bundle"])
        .arg(root.join("bundle"))
        .args(["--sums-sha256", sums, "--home"])
        .arg(root.join("home"))
        .arg("--bin-dir")
        .arg(root.join("bin"))
        .output()
        .unwrap()
}

/// The installer executes a verified private copy of `bridge`, never the
/// file inside the (possibly writable) bundle, and passes that same private
/// copy directory (not the original bundle path) to `self-install`.
#[test]
fn the_installer_runs_a_private_verified_copy_not_the_bundle_file() {
    if !supported() {
        return;
    }
    let root = scratch();
    let sums = bundle(&root);
    let output = install(&root, &sums);
    let ran = std::fs::read_to_string(root.join("ran")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    assert!(output.status.success(), "{output:?}");
    let invoked = ran.split_whitespace().next().unwrap_or_default();
    assert!(
        !invoked.starts_with(root.join("bundle").to_str().unwrap()),
        "ran the bundle's own file: {ran}"
    );
    assert!(ran.contains("self-install --bundle"), "{ran}");
    let words: Vec<&str> = ran.split_whitespace().collect();
    let passed = words
        .iter()
        .position(|word| *word == "--bundle")
        .and_then(|index| words.get(index + 1))
        .copied()
        .unwrap_or_default();
    assert_ne!(passed, root.join("bundle").to_str().unwrap(), "{ran}");
    assert_eq!(invoked, format!("{passed}/bin/bridge"), "{ran}");
}

/// A bundle whose `bin` directory or `SHA256SUMS` file is a link to an
/// external mutable location is refused before any bundle executable runs,
/// even though every leaf file is regular and attested; the original is left
/// untouched.
#[test]
fn a_linked_bin_directory_or_sums_file_is_refused_before_anything_runs() {
    if !supported() {
        return;
    }
    for linked in ["bin", "SHA256SUMS"] {
        let root = scratch();
        let sums = bundle(&root);
        let external = root.join("external");
        std::fs::rename(root.join("bundle").join(linked), &external).unwrap();
        std::os::unix::fs::symlink(&external, root.join("bundle").join(linked)).unwrap();
        let output = install(&root, &sums);
        let ran = root.join("ran").exists();
        let still_linked = std::fs::symlink_metadata(root.join("bundle").join(linked))
            .unwrap()
            .file_type()
            .is_symlink();
        let untouched = external.exists() && !root.join("home").exists();
        let _ = std::fs::remove_dir_all(&root);
        assert!(!output.status.success(), "{linked}: {output:?}");
        assert!(!ran, "{linked}: a bundle executable ran");
        assert!(
            still_linked && untouched,
            "{linked}: the original was modified"
        );
    }
}

/// Plugin files join pre-execution attestation. Missing, linked, tampered or
/// extra entries (including hidden files) refuse before the synthetic bridge runs.
#[test]
fn plugin_pre_execution_attestation_and_exact_entries() {
    if !supported() {
        return;
    }
    for kind in [
        "valid",
        "missing",
        "link",
        "directory",
        "tamper",
        "extra",
        "hidden",
        "root",
    ] {
        let root = scratch();
        bundle(&root);
        let dir = root.join("bundle");
        std::fs::create_dir_all(dir.join("plugins/opencode")).unwrap();
        let mut sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
        for name in ["index.js", "package.json"] {
            let path = dir.join("plugins/opencode").join(name);
            std::fs::write(&path, "synthetic").unwrap();
            sums.push_str(&format!(
                "{}  plugins/opencode/{name}\n",
                file_sha256(&path).unwrap()
            ));
        }
        std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
        let digest = file_sha256(&dir.join("SHA256SUMS")).unwrap();
        let entry = dir.join("plugins/opencode/index.js");
        match kind {
            "missing" => std::fs::remove_file(&entry).unwrap(),
            "link" => {
                std::fs::remove_file(&entry).unwrap();
                std::os::unix::fs::symlink(dir.join("release-manifest.json"), &entry).unwrap();
            }
            "directory" => {
                std::fs::rename(dir.join("plugins"), root.join("external")).unwrap();
                std::os::unix::fs::symlink(root.join("external"), dir.join("plugins")).unwrap();
            }
            "tamper" => std::fs::write(&entry, "changed").unwrap(),
            "extra" => std::fs::write(dir.join("plugins/opencode/extra.js"), "x").unwrap(),
            "hidden" => std::fs::write(dir.join("plugins/opencode/.hidden"), "x").unwrap(),
            "root" => std::fs::write(dir.join("extra"), "x").unwrap(),
            "valid" => {}
            _ => unreachable!(),
        }
        let output = install(&root, &digest);
        assert_eq!(
            output.status.success(),
            kind == "valid",
            "{kind}: {output:?}"
        );
        assert_eq!(root.join("ran").exists(), kind == "valid", "{kind}");
        std::fs::remove_dir_all(root).unwrap();
    }
}
