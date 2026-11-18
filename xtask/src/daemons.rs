//! `cargo xtask check-daemons`: the gate's leak check for test daemons.
//!
//! A test that starts `bridge-native-daemon` must not leave it running. After
//! the tests, this check lists every running process whose executable is named
//! `bridge-native-daemon` and whose command line points into one of the
//! temporary roots (`TMPDIR`, `TMP`, `TEMP`, or each `--dir`) and fails if any
//! exists. It only reports: it never signals a process, so a daemon of an
//! installed Bridge (whose configuration lives outside those roots) is never
//! affected and nothing is killed on a guess.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Executable basename of the daemon the tests start.
const DAEMON: &str = "bridge-native-daemon";

/// One surviving daemon.
#[derive(Debug, PartialEq, Eq)]
pub struct Survivor {
    /// Process id.
    pub pid: u32,
    /// Full command line as `ps` reports it.
    pub command: String,
}

/// The temporary roots named by the environment (`TMPDIR`, `TMP`, `TEMP`),
/// de-duplicated and without a trailing separator; the platform temporary
/// directory when none is set.
pub fn environment_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for name in ["TMPDIR", "TMP", "TEMP"] {
        if let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            let root = PathBuf::from(value);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    if roots.is_empty() {
        roots.push(std::env::temp_dir());
    }
    roots
}

/// Whether `command` mentions `root` as a path prefix (the root itself or a
/// descendant), so `/t/a` matches `/t/a/b.toml` but not `/t/ab/b.toml`.
fn mentions(command: &str, root: &Path) -> bool {
    let root = root.to_string_lossy();
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    command.match_indices(root).any(|(start, _)| {
        let before_ok = start == 0
            || command[..start].ends_with(|c: char| c.is_whitespace() || c == '=' || c == '"');
        let after = &command[start + root.len()..];
        before_ok
            && (after.is_empty()
                || after.starts_with(|c: char| c == '/' || c.is_whitespace() || c == '"'))
    })
}

/// Parses `ps -o pid= -o args=` output into the daemons that point into one of
/// `roots`, ignoring `own_pid`. A line counts only when the first word of its
/// command line has the basename `bridge-native-daemon`.
pub fn survivors(listing: &str, roots: &[PathBuf], own_pid: u32) -> Vec<Survivor> {
    listing
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            let pid: u32 = pid.parse().ok()?;
            let command = command.trim();
            let (program, arguments) = command
                .split_once(char::is_whitespace)
                .unwrap_or((command, ""));
            let named = Path::new(program)
                .file_name()
                .is_some_and(|name| name == DAEMON);
            (pid != own_pid && named && roots.iter().any(|root| mentions(arguments, root))).then(
                || Survivor {
                    pid,
                    command: command.to_string(),
                },
            )
        })
        .collect()
}

/// Lists running processes and fails when a test daemon survives in one of
/// `roots` (the environment's when empty).
pub fn run(roots: &[PathBuf]) -> Result<(), String> {
    let roots = if roots.is_empty() {
        environment_roots()
    } else {
        roots.to_vec()
    };
    let output = Command::new("ps")
        .args(["-axww", "-o", "pid=", "-o", "args="])
        .output()
        .map_err(|error| format!("cannot run ps: {error}"))?;
    if !output.status.success() {
        return Err(format!("ps failed with {}", output.status));
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let found = survivors(&listing, &roots, std::process::id());
    if found.is_empty() {
        println!("no {DAEMON} survives in the test temporary directories");
        return Ok(());
    }
    let mut message = format!(
        "{} {DAEMON} process(es) from the test temporary directories survived the tests; a test leaked its daemon:",
        found.len()
    );
    for survivor in &found {
        message.push_str(&format!("\n  pid {}: {}", survivor.pid, survivor.command));
    }
    Err(message)
}

#[cfg(test)]
mod tests {
    //! The survivor parser accepts only daemons that point into the roots.
    use super::*;

    /// Only a daemon-named process whose arguments live under a root counts.
    #[test]
    fn only_daemons_inside_the_roots_are_survivors() {
        let roots = [PathBuf::from("/work/t")];
        let listing = "\
  101 /work/t/x/bridge-native-daemon /work/t/abc/bridge.toml
  102 /opt/bridge/bin/bridge-native-daemon /home/u/.config/bridge/daemon.toml
  103 /work/t/x/bridge-native-daemon /work/tx/bridge.toml
  106 /work/t/bridge-native-daemon
  104 /usr/bin/sleep /work/t/abc/bridge.toml
  105 /work/t/x/bridge-native-daemon /work/t/abc/bridge.toml
 1060 cargo xtask check-daemons /work/t/bridge-native-daemon
";
        let found = survivors(listing, &roots, 105);
        assert_eq!(
            found.iter().map(|s| s.pid).collect::<Vec<_>>(),
            vec![101],
            "{found:?}"
        );
    }
}
