//! Boundary control for the public repository itself: the real source tree
//! must satisfy `cargo xtask check-public`. Removing a linked document or
//! adding an owner-specific path anywhere in the tree makes this test fail;
//! restoring it makes it pass again.

use std::process::Command;

/// Runs the built checker against the workspace this crate belongs to.
#[test]
fn repository_is_publishable() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("check-public")
        .arg("--root")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root"),
        )
        .output()
        .expect("xtask check-public starts");
    assert!(
        output.status.success(),
        "public-repository findings:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The attempt-binding codec requires a pinned JSON version and binary64
/// roundtrip parsing, with arbitrary precision absent from feature unification.
#[test]
fn attempt_binding_json_feature_unification() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let output = Command::new(env!("CARGO"))
        .current_dir(root)
        .args([
            "tree",
            "--offline",
            "--locked",
            "--workspace",
            "-e",
            "features",
            "-i",
            "serde_json",
        ])
        .output()
        .expect("offline cargo feature tree starts");
    assert!(output.status.success(), "offline feature inspection failed");
    let tree = String::from_utf8(output.stdout).expect("feature tree is UTF-8");
    assert!(tree.contains("serde_json v1.0.154\n"));
    assert!(tree.contains("serde_json feature \"float_roundtrip\""));
    assert!(!tree.contains("serde_json feature \"arbitrary_precision\""));
}
