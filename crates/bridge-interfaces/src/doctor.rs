//! Local diagnostics: what is installed, what is running, what is
//! configured and what is merely declared.
//!
//! `doctor` reads and connects; it never starts, stops, sends or repairs
//! anything and never prints a secret (secret files are checked for
//! protection and presence only). Each check is one of `ok`, `fail`,
//! `warn`, `not_configured` or `not_verified`. Declared adapter
//! capabilities and the Telegram channel are always `not_verified`: only
//! separately recorded host qualification evidence can establish them.
//! The overall qualification is `not_verified`.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};

use crate::config::{InterfacesConfig, read_secret};
use crate::install::{BINARIES, file_sha256, load_state, verify_tree};
use crate::lifecycle::{Component, alive, read_record};

/// Inputs; every part is optional.
#[derive(Debug, Clone, Default)]
pub struct DoctorInput {
    /// Installation home.
    pub home: Option<PathBuf>,
    /// Launcher directory.
    pub bin_dir: Option<PathBuf>,
    /// Lifecycle state directory (pid records).
    pub state: Option<PathBuf>,
    /// Interfaces configuration.
    pub config: Option<PathBuf>,
    /// Native daemon configuration (only `[adapters]` is read).
    pub daemon_config: Option<PathBuf>,
}

/// One check result.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Check name.
    pub name: String,
    /// `ok`, `fail`, `warn`, `not_configured` or `not_verified`.
    pub status: &'static str,
    /// Safe detail.
    pub detail: Value,
}

/// Runs every applicable check.
pub fn run(input: &DoctorInput) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut push = |name: &str, status: &'static str, detail: Value| {
        checks.push(Check {
            name: name.into(),
            status,
            detail,
        });
    };
    let mut release_dir = None;
    if let Some(home) = &input.home {
        let state = load_state(home);
        match state {
            Ok(state) => match &state.current {
                Some(current) => {
                    let dir = home.join("releases").join(current);
                    match verify_tree(&dir) {
                        Ok(manifest) => {
                            push(
                                "install.release",
                                "ok",
                                json!({"current": current, "previous": state.previous,
                                       "core_schema": manifest.core_schema,
                                       "max_core_schema": state.max_core_schema,
                                       "files": manifest.files}),
                            );
                            release_dir = Some(dir);
                        }
                        Err(error) => push("install.release", "fail", json!(error)),
                    }
                }
                None => push(
                    "install.release",
                    "not_configured",
                    json!("nothing installed"),
                ),
            },
            Err(error) => push("install.release", "fail", json!(error)),
        }
        match crate::install::check_current(home) {
            Ok(current) => push("install.current_link", "ok", json!(current)),
            Err(error) => push("install.current_link", "fail", json!(error)),
        }
    }
    if let (Some(home), Some(bin_dir)) = (&input.home, &input.bin_dir) {
        let wrong: Vec<&str> = BINARIES
            .iter()
            .copied()
            .filter(|name| {
                std::fs::read_link(bin_dir.join(name)).ok()
                    != Some(home.join("current").join("bin").join(name))
            })
            .collect();
        if wrong.is_empty() {
            push("install.launchers", "ok", json!(bin_dir));
        } else {
            push("install.launchers", "fail", json!({"not_linked": wrong}));
        }
    }
    if let Some(state) = &input.state {
        for component in [Component::Core, Component::Relay] {
            let name = format!("process.{}", component.name());
            match read_record(state, component) {
                Ok(Some(record)) if alive(&record) => {
                    let loaded = file_sha256(&record.exe).unwrap_or_default();
                    let active = release_dir.as_ref().and_then(|dir| {
                        dir.join("bin")
                            .join(component.executable())
                            .canonicalize()
                            .ok()
                    });
                    let expected = active.as_deref().and_then(|path| file_sha256(path).ok());
                    let matches = expected.as_deref() == Some(loaded.as_str());
                    let from_active = active.as_deref() == Some(record.exe.as_path());
                    push(
                        &name,
                        if matches && from_active { "ok" } else { "warn" },
                        json!({"pid": record.pid, "exe": record.exe, "sha256": loaded,
                               "matches_active_release": matches,
                               "runs_from_active_release": from_active,
                               "note": if from_active { "" } else { "started from another release; restart to load the active one" }}),
                    );
                }
                Ok(Some(_)) => push(&name, "warn", json!("stale pid record; not running")),
                Err(error) => push(&name, "fail", json!({"uncertain": true, "detail": error})),
                Ok(None) => push(
                    &name,
                    "not_configured",
                    json!("not started by bridge service"),
                ),
            }
        }
    }
    if let Some(path) = &input.config {
        match InterfacesConfig::load(path) {
            Ok(config) => interfaces(&config, &mut push),
            Err(error) => push("config.interfaces", "fail", json!(error)),
        }
    }
    if let Some(path) = &input.daemon_config {
        adapters(path, release_dir.as_deref(), &mut push);
    }
    push(
        "qualification",
        "not_verified",
        json!(
            "local diagnostics only; native host, installed-host and Telegram qualification require separate recorded evidence"
        ),
    );
    checks
}

/// Checks of the interfaces configuration.
fn interfaces(config: &InterfacesConfig, push: &mut dyn FnMut(&str, &'static str, Value)) {
    push("config.interfaces", "ok", json!("valid"));
    push(
        "core.reachable",
        if std::os::unix::net::UnixStream::connect(&config.core_socket).is_ok() {
            "ok"
        } else {
            "fail"
        },
        json!(config.core_socket),
    );
    let mut secret = |name: &str, path: &Path| match read_secret(path) {
        Ok(_) => push(name, "ok", json!("present and protected")),
        Err(error) => push(name, "fail", json!(error)),
    };
    if let Some(operator) = &config.operator {
        secret("secret.operator", &operator.token_file);
    }
    if let Some(root) = &config.root {
        secret("secret.root", &root.token_file);
    }
    if let Some(telegram) = &config.telegram {
        secret("secret.telegram", &telegram.token_file);
    }
    if let Some(operator) = &config.operator {
        let incidents = read_secret(&operator.token_file).and_then(|token| {
            bridge_client::BridgeClient::connect(&config.core_socket)
                .map_err(|error| error.to_string())?
                .incidents(&token, false, Some(200))
                .map_err(|error| error.to_string())
        });
        match incidents {
            Ok(incidents) => {
                let mut categories = std::collections::BTreeMap::new();
                for incident in &incidents {
                    *categories
                        .entry(crate::operator::classify(&incident.kind).0)
                        .or_insert(0) += 1;
                }
                push(
                    "recovery.pending",
                    if incidents.is_empty() { "ok" } else { "warn" },
                    json!({"open_incidents": incidents.len(), "by_category": categories}),
                );
            }
            Err(error) => push("recovery.pending", "fail", json!(error)),
        }
    }
    match &config.root {
        Some(root) => {
            push(
                "relay.reachable",
                if std::os::unix::net::UnixStream::connect(&root.socket).is_ok() {
                    "ok"
                } else {
                    "fail"
                },
                json!(root.socket),
            );
            if root.channel.is_none() {
                push(
                    "relay.attestation",
                    "warn",
                    json!("no adapter channel: every root request refuses (caller_unattested)"),
                );
            }
        }
        None => push("relay", "not_configured", json!("no [root] section")),
    }
    match &config.telegram {
        Some(telegram) => push(
            "telegram",
            "not_verified",
            json!({"chat_id": telegram.chat_id, "api_base": telegram.api_base,
                   "note": "configured; no live send has been authorized or observed"}),
        ),
        None => push(
            "telegram",
            "not_configured",
            json!("owner notifications cannot be delivered; incidents stay visible locally"),
        ),
    }
}

/// Checks of the native daemon's `[adapters]` declarations.
fn adapters(path: &Path, release: Option<&Path>, push: &mut dyn FnMut(&str, &'static str, Value)) {
    // Parse errors are withheld: the daemon configuration holds tokens.
    let parsed = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|value| value.get("adapters").cloned())
        .and_then(|adapters| adapters.try_into::<bridge_adapters::RegistryConfig>().ok());
    let Some(registry) = parsed else {
        push(
            "adapters",
            "fail",
            json!("daemon configuration or [adapters] unreadable"),
        );
        return;
    };
    for profile in &registry.profiles {
        for executable in &profile.executables {
            let on_disk = file_sha256(&executable.path).ok();
            push(
                &format!(
                    "adapters.{}.{}",
                    profile.harness.as_str(),
                    profile.namespace
                ),
                if on_disk.as_deref() == Some(executable.sha256.as_str()) {
                    "not_verified"
                } else {
                    "fail"
                },
                json!({"executable": executable.path, "version": executable.version,
                       "declared_inject": executable.inject, "declared_message": executable.message,
                       "file_matches_declared_sha256": on_disk.as_deref() == Some(executable.sha256.as_str()),
                       "note": "declared capability; host qualification evidence is separate"}),
            );
        }
    }
    let relay = release
        .map(|dir| dir.join("bin").join("bridge-root-relay"))
        .and_then(|path| path.canonicalize().ok());
    let relay_sha = relay.as_deref().and_then(|path| file_sha256(path).ok());
    let bound = registry.relays.iter().any(|entry| {
        Some(&entry.path) == relay.as_ref() && Some(&entry.sha256) == relay_sha.as_ref()
    });
    push(
        "adapters.relay_binding",
        if bound { "ok" } else { "warn" },
        json!({"active_relay": relay, "active_relay_sha256": relay_sha,
               "configured": registry.relays.iter().map(|entry| json!({"path": entry.path, "sha256": entry.sha256})).collect::<Vec<_>>(),
               "note": if bound { "the active relay may redeem caller proofs" } else { "the active relay is not configured: root tools refuse until [[adapters.relays]] names it and the daemon restarts" }}),
    );
}

/// Exit status for a report: 2 when any check failed, else 0.
pub fn exit_code(checks: &[Check]) -> u8 {
    if checks.iter().any(|check| check.status == "fail") {
        2
    } else {
        0
    }
}
