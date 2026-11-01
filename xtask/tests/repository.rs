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
        .output()
        .expect("xtask check-public starts");
    assert!(
        output.status.success(),
        "public-repository findings:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
