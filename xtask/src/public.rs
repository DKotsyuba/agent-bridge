//! Public-repository checker (`cargo xtask check-public`).
//!
//! A small regression guard, standard library only, for what a public reader
//! relies on:
//!
//! - the required public files exist;
//! - every relative Markdown link and `#fragment` resolves, and every Markdown
//!   file is reachable from `README.md`;
//! - no text file names an owner-specific path, a private documentation
//!   directory or a private tracker identifier;
//! - the changelog covers the workspace version, and the CI workflow runs on
//!   macOS, installs the pinned toolchain, runs this checker, pins every action
//!   to a full commit SHA and runs no native probe.
//!
//! It is not a secret scanner; use a dedicated tool for credentials.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// Directory names never walked, at any depth.
const SKIPPED_DIRS: [&str; 3] = ["target", ".git", "dist"];

/// Files that must exist in a public tree.
const REQUIRED: [&str; 8] = [
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "agent.md",
    "AGENTS.md",
    ".github/workflows/ci.yml",
];

/// The one file not scanned for private content: it defines the patterns.
const SELF_EXEMPT: &str = "xtask/src/public.rs";

/// Substrings no public text file may contain.
const FORBIDDEN_TEXT: [&str; 6] = [
    "/Users/",
    "/private/var",
    "/var/folders",
    "agent-docs",
    "AgentTasks",
    "Agent Tasks",
];

/// Substrings that would make CI run a native, paid or privacy-sensitive probe.
const FORBIDDEN_CI: [&str; 4] = [
    "-probe",
    "BRIDGE_Q4_PAID",
    "BRIDGE_UNIVERSAL_PAID",
    "--ignored",
];

/// One violated rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Path relative to the checked root, `/`-separated.
    pub path: String,
    /// One-based line, or zero when the finding concerns the whole file.
    pub line: usize,
    /// What is wrong, without echoing private content.
    pub message: String,
}

impl fmt::Display for Finding {
    /// Formats as `path[:line]: message`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            0 => write!(f, "{}: {}", self.path, self.message),
            line => write!(f, "{}:{line}: {}", self.path, self.message),
        }
    }
}

/// Builds a finding for `path` at `line` (zero: whole file).
fn found(path: &str, line: usize, message: &str) -> Finding {
    Finding {
        path: path.into(),
        line,
        message: message.into(),
    }
}

/// Runs every rule against `root`, prints each finding to standard error and
/// fails when there is at least one.
///
/// # Errors
/// The findings count, or the I/O error that prevented a complete check.
pub fn run(root: &Path) -> Result<(), String> {
    let findings = check(root)?;
    for finding in &findings {
        eprintln!("{finding}");
    }
    if findings.is_empty() {
        println!("check-public: ok");
        Ok(())
    } else {
        Err(format!("{} public-repository finding(s)", findings.len()))
    }
}

/// Applies all rules to the tree at `root` and returns the violations in a
/// stable order (empty when the tree is publishable).
///
/// # Errors
/// An unreadable directory or file; the tree is then unverified, never ok.
pub fn check(root: &Path) -> Result<Vec<Finding>, String> {
    let files = walk(root)?;
    let mut findings = Vec::new();
    for required in REQUIRED {
        if !root.join(required).is_file() {
            findings.push(found(required, 0, "required public file is missing"));
        }
    }
    let mut documents = BTreeSet::new();
    let mut edges = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue; // binary content is not scanned
        };
        if path.ends_with(".md") {
            links(root, path, &text, &mut edges, &mut findings);
            documents.insert(path.clone());
        }
        if path != SELF_EXEMPT && !path.ends_with("Cargo.lock") {
            private_content(path, &text, &mut findings);
        }
    }
    let mut reached = BTreeSet::from(["README.md".to_string()]);
    loop {
        let next = edges
            .iter()
            .find(|(from, to)| reached.contains(from) && !reached.contains(to))
            .map(|(_, to)| to.clone());
        match next {
            Some(to) => reached.insert(to),
            None => break,
        };
    }
    for path in documents.difference(&reached) {
        findings.push(found(
            path,
            0,
            "Markdown file is not reachable from README.md",
        ));
    }
    release_rules(root, &mut findings);
    findings.sort_by(|a, b| (&a.path, a.line, &a.message).cmp(&(&b.path, b.line, &b.message)));
    findings.dedup();
    Ok(findings)
}

/// Lists every regular file below `root` as sorted `/`-separated relative
/// paths, skipping [`SKIPPED_DIRS`] and never following symbolic links.
fn walk(root: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(root.join(&dir))
            .map_err(|error| format!("cannot read {}: {error}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if SKIPPED_DIRS.contains(&&*name.to_string_lossy()) {
                continue;
            }
            let relative = dir.join(&name);
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                pending.push(relative);
            } else if kind.is_file() {
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Lexically resolves `target` against the directory of `from`; `None` when
/// it escapes the root.
fn resolve(from: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            name => parts.push(name),
        }
    }
    Some(parts.join("/"))
}

/// GitHub-style heading anchors of a Markdown text: lowercase, spaces to
/// hyphens, anything but alphanumerics, `-` and `_` dropped.
fn anchors(text: &str) -> BTreeSet<String> {
    let mut fenced = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced && line.starts_with('#') {
            out.insert(
                line.trim_start_matches('#')
                    .trim()
                    .to_lowercase()
                    .chars()
                    .filter_map(|c| match c {
                        ' ' => Some('-'),
                        c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
                        _ => None,
                    })
                    .collect(),
            );
        }
    }
    out
}

/// Checks every inline `[text](target)` link outside code of one Markdown file
/// and records `(from, to)` edges for links to other Markdown files.
/// Reference-style links are not interpreted; the public documents use inline
/// links only.
fn links(
    root: &Path,
    path: &str,
    text: &str,
    edges: &mut Vec<(String, String)>,
    findings: &mut Vec<Finding>,
) {
    let mut fenced = false;
    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut inside = false;
        let prose: String = line
            .chars()
            .filter(|&c| {
                inside ^= c == '`';
                !inside && c != '`'
            })
            .collect();
        for piece in prose.split("](").skip(1) {
            let Some(target) = piece.split(')').next() else {
                continue;
            };
            if ["http://", "https://", "mailto:"]
                .iter()
                .any(|scheme| target.starts_with(scheme))
            {
                continue;
            }
            let bad = |message: &str| found(path, index + 1, message);
            let (file, fragment) = target.split_once('#').unwrap_or((target, ""));
            let Some(resolved) = (if file.is_empty() {
                Some(path.to_string())
            } else {
                resolve(path, file)
            }) else {
                findings.push(bad("link leaves the repository"));
                continue;
            };
            if !root.join(&resolved).exists() {
                findings.push(bad("link target does not exist"));
                continue;
            }
            if resolved.ends_with(".md") {
                if resolved != path {
                    edges.push((path.to_string(), resolved.clone()));
                }
                let known = std::fs::read_to_string(root.join(&resolved))
                    .map(|doc| fragment.is_empty() || anchors(&doc).contains(fragment))
                    .unwrap_or(false);
                if !known {
                    findings.push(bad("link fragment matches no heading"));
                }
            }
        }
    }
}

/// Whether `line` has a private work-tracking reference: a one-letter or
/// `DOC` prefix, a hyphen and exactly three digits, not inside a longer word.
fn has_private_id(line: &str) -> bool {
    let b = line.as_bytes();
    (0..b.len()).any(|i| {
        if i > 0 && b[i - 1].is_ascii_alphanumeric() {
            return false;
        }
        let rest = &b[i..];
        let digits = if rest.starts_with(b"DOC-") {
            4
        } else if rest.len() > 1 && b"MEDAT".contains(&rest[0]) && rest[1] == b'-' {
            2
        } else {
            return false;
        };
        rest.len() >= digits + 3
            && rest[digits..digits + 3].iter().all(u8::is_ascii_digit)
            && rest.get(digits + 3).is_none_or(|c| !c.is_ascii_digit())
    })
}

/// Flags private paths and tracker identifiers in one text file.
fn private_content(path: &str, text: &str, findings: &mut Vec<Finding>) {
    for (index, line) in text.lines().enumerate() {
        if FORBIDDEN_TEXT.iter().any(|needle| line.contains(needle)) {
            findings.push(found(path, index + 1, "private path or project reference"));
        }
        if has_private_id(line) {
            findings.push(found(path, index + 1, "private work-tracking identifier"));
        }
    }
}

/// Value of the first `key = "value"` line inside `[section]` of a TOML text.
fn toml_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == format!("[{section}]");
        } else if inside
            && let Some(rest) = line.strip_prefix(key).map(str::trim_start)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Changelog and CI constraints; a missing file is already a finding.
fn release_rules(root: &Path, findings: &mut Vec<Finding>) {
    let read = |path: &str| std::fs::read_to_string(root.join(path)).ok();
    let manifest = read("Cargo.toml").unwrap_or_default();
    let version = toml_value(&manifest, "workspace.package", "version");
    if let (Some(version), Some(changelog)) = (&version, read("CHANGELOG.md"))
        && !changelog
            .lines()
            .any(|l| l.starts_with(&format!("## [{version}]")))
    {
        findings.push(found(
            "CHANGELOG.md",
            0,
            "no `## [version]` heading for the workspace version",
        ));
    }
    let channel = read("rust-toolchain.toml").and_then(|t| toml_value(&t, "toolchain", "channel"));
    let ci = ".github/workflows/ci.yml";
    let Some(workflow) = read(ci) else { return };
    for (index, line) in workflow.lines().enumerate() {
        let line = line.trim().trim_start_matches("- ");
        if let Some(reference) = line.strip_prefix("uses:") {
            let pinned = reference
                .split('#')
                .next()
                .and_then(|r| r.trim().split_once('@'))
                .is_some_and(|(_, sha)| {
                    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
                });
            if !pinned {
                findings.push(found(
                    ci,
                    index + 1,
                    "action is not pinned to a full commit SHA",
                ));
            }
        }
        if FORBIDDEN_CI.iter().any(|needle| line.contains(needle)) {
            findings.push(found(
                ci,
                index + 1,
                "CI must not run native or paid probes",
            ));
        }
    }
    let channel_ok = channel
        .as_ref()
        .is_some_and(|c| workflow.contains(c.as_str()));
    for (ok, message) in [
        (
            workflow.contains("runs-on: macos-"),
            "CI must run on a macOS runner",
        ),
        (
            workflow.contains("xtask check-public"),
            "CI does not run `cargo xtask check-public`",
        ),
        (
            channel_ok,
            "CI does not install the toolchain pinned by rust-toolchain.toml",
        ),
    ] {
        if !ok {
            findings.push(found(ci, 0, message));
        }
    }
}

#[cfg(test)]
mod tests {
    //! Boundary controls: a minimal valid tree passes and each rule fails on one
    //! deliberate, realistic violation (removed document, private path, private
    //! identifier, unreachable file, unpinned action, version drift).

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A 40-hex commit SHA for the pinned action of the valid tree.
    const SHA: &str = "11d5960a326750d5838078e36cf38b85af677262";

    /// Distinguishes the temporary trees of concurrently running tests.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// The smallest tree that satisfies every rule, as `(path, content)`.
    fn good() -> Vec<(String, String)> {
        let ci = format!(
            "runs-on: macos-15\n- uses: actions/checkout@{SHA} # v4\n- run: cargo +1.98.1 xtask check-public\n"
        );
        [
            ("README.md", "# Bridge\n[g](docs/guide.md#start) [c](CONTRIBUTING.md) [s](SECURITY.md) [l](CHANGELOG.md) [a](agent.md) [b](AGENTS.md)\n"),
            ("docs/guide.md", "# Start\n[readme](../README.md)\n"),
            ("CONTRIBUTING.md", "# Contributing\n"),
            ("SECURITY.md", "# Security\n"),
            ("CHANGELOG.md", "# Changelog\n## [0.2.0]\n"),
            ("agent.md", "# Agent\n"),
            ("AGENTS.md", "# Agents\n"),
            ("LICENSE", "MIT License\n"),
            ("Cargo.toml", "[workspace.package]\nversion = \"0.2.0\"\n"),
            ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.98.1\"\n"),
            (".github/workflows/ci.yml", ci.as_str()),
        ]
        .map(|(path, text)| (path.to_string(), text.to_string()))
        .to_vec()
    }

    /// Applies `mutate` to the valid tree, checks it under a fresh directory
    /// below the process temporary directory (honoring `TMPDIR`) and returns
    /// the findings as text.
    fn mutated(mutate: impl FnOnce(&mut Vec<(String, String)>)) -> Vec<String> {
        let mut files = good();
        mutate(&mut files);
        let root = std::env::temp_dir().join(format!(
            "bridge-public-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        for (path, content) in &files {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        let found = check(&root).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        found.iter().map(ToString::to_string).collect()
    }

    /// Replaces the content of an existing file of the valid tree.
    fn replace(files: &mut [(String, String)], path: &str, content: &str) {
        files.iter_mut().find(|(p, _)| p == path).unwrap().1 = content.into();
    }

    /// Asserts that some finding mentions `needle`.
    fn expect(found: &[String], needle: &str) {
        assert!(
            found.iter().any(|f| f.contains(needle)),
            "expected `{needle}` in {found:?}"
        );
    }

    /// The valid tree has no finding.
    #[test]
    fn valid_tree_passes() {
        assert_eq!(mutated(|_| {}), Vec::<String>::new());
    }

    /// Removing a linked document breaks the link that named it.
    #[test]
    fn removed_document_fails() {
        let found = mutated(|files| files.retain(|(p, _)| p != "docs/guide.md"));
        expect(&found, "README.md:2: link target does not exist");
    }

    /// A fragment without a heading and a document nothing links to both fail.
    #[test]
    fn broken_anchor_and_unlinked_document_fail() {
        let found = mutated(|files| replace(files, "docs/guide.md", "# Other\n"));
        expect(&found, "link fragment matches no heading");
        let found = mutated(|files| files.push(("docs/orphan.md".into(), "# Orphan\n".into())));
        expect(&found, "docs/orphan.md: Markdown file is not reachable");
    }

    /// An owner-specific path and a tracker identifier fail; look-alikes pass.
    #[test]
    fn private_content_fails_but_lookalikes_pass() {
        let path = format!("{}example/tmp", FORBIDDEN_TEXT[0]);
        let found = mutated(|files| {
            files.push((
                "tools/probe.cjs".into(),
                format!("const root = '{path}';\n"),
            ))
        });
        expect(&found, "tools/probe.cjs:1: private path");
        let id = format!("{}-{}", "E", "002");
        let found = mutated(|files| {
            replace(
                files,
                "SECURITY.md",
                &format!("# Security\nOwned by {id}.\n"),
            )
        });
        expect(&found, "SECURITY.md:2: private work-tracking identifier");
        assert!(!has_private_id("SHA-256, UTF-8, ABC-123, M-0100, xM-010"));
    }

    /// An unpinned action, a native probe in CI, a stale changelog and a
    /// missing required file each fail.
    #[test]
    fn release_rules_fail() {
        let ci = ".github/workflows/ci.yml";
        let found = mutated(|files| {
            replace(
                files,
                ci,
                "runs-on: macos-15\n- uses: actions/checkout@v4\n- run: cargo +1.98.1 xtask check-public\n",
            )
        });
        expect(&found, "action is not pinned");
        let found = mutated(|files| {
            replace(
                files,
                ci,
                &format!(
                    "runs-on: macos-15\n- uses: a/b@{SHA}\n- run: node codex-native-probe.cjs; cargo +1.98.1 xtask check-public\n"
                ),
            )
        });
        expect(&found, "CI must not run native or paid probes");
        let found = mutated(|files| replace(files, "CHANGELOG.md", "# Changelog\n## [0.1.0]\n"));
        expect(&found, "no `## [version]` heading");
        let found = mutated(|files| files.retain(|(p, _)| p != "CONTRIBUTING.md"));
        expect(&found, "CONTRIBUTING.md: required public file is missing");
    }
}
