//! Bridge daemon with native adapters: the core service, the Codex and
//! Claude message carriers, and the adapter channel for hooks and root
//! caller attestation.
//!
//! Usage: `bridge-native-daemon <config.toml>`. The file is the core
//! configuration (database, socket, limits, grants) plus an `[adapters]`
//! table: `channel` (socket path inside a private 0700 directory),
//! `sandbox` (confinement launcher, default `/usr/bin/sandbox-exec`) and
//! the registry fields (`host_id`, `harnesses`, optional `intermediates`,
//! `max_call_age_ms`). The `harnesses` policies name the harness products served,
//! their address namespace and capabilities; no store path or harness
//! executable is declared. Legacy `profiles` still load as migration input, one
//! `legacy_profile_migrated` log line per entry, and authorize nothing; a legacy
//! `owner_relays` table is ignored with one `legacy_owner_relays_ignored` log line.
//! When the
//! launcher is missing, the Codex message
//! capability is never granted, so such publications refuse before
//! acceptance. `Registry::new` hashes every configured relay and
//! audience executable once before returning (the daemon then reports the counts via
//! the idempotent `Registry::warm_digests`), so no hook request
//! reads a whole executable under the registry lock; startup takes about
//! one streamed read of those files (about 1.6 s per 246 MB optimized, far
//! longer unoptimized) and logs `executable_digests_warmed` with the cached,
//! skipped and unqualified counts (a warning when either of the last two is
//! non-zero: a file is missing, unreadable or changing, or its real hash is
//! not the configured digest; counts only, no paths or contents). Serving never
//! hashes: while running, the
//! main loop notices about twice a second that a configured file's identity
//! changed (an application update) and hashes it on a background thread
//! outside the registry lock, so an update that leaves the approved bytes
//! unchanged qualifies again with no restart; until then the new identity is
//! refused before any state changes. A different digest is cached once and stays
//! refused (update its configured digest and restart). SIGTERM/SIGINT stop the
//! channel, end the background refresh and drain the service.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
use bridge_adapters::codex::{CodexQueueCarrier, DEFAULT_HELPER_TIMEOUT};
use bridge_adapters::registry::LEGACY_OWNER_RELAYS_PREFIX;
use bridge_adapters::server::{ChannelServer, Custody, LateCustody, private_directory};
use bridge_adapters::{Registry, RegistryConfig, refresh_executables, stop_executable_refresh};
use bridge_core::Harness;
use bridge_core::dispatch::DispatchTiming;
use bridge_core::service::{self, Config};
use serde::Deserialize;
use signal_hook::consts::{SIGINT, SIGTERM};

/// The `[adapters]` table.
#[derive(Deserialize)]
struct AdapterConfig {
    /// Channel socket path.
    channel: PathBuf,
    /// Confinement launcher for the Codex helper.
    #[serde(default = "default_sandbox")]
    sandbox: PathBuf,
    /// Registry configuration.
    #[serde(flatten)]
    registry: RegistryConfig,
}

/// Default macOS confinement launcher.
fn default_sandbox() -> PathBuf {
    PathBuf::from("/usr/bin/sandbox-exec")
}

/// Whole daemon configuration.
#[derive(Deserialize)]
struct NativeConfig {
    /// Core service configuration.
    #[serde(flatten)]
    core: Config,
    /// Adapter configuration.
    adapters: AdapterConfig,
}

/// Logs a startup failure and returns the failure code.
fn fail(event: &str, detail: &str) -> ExitCode {
    service::log_event("error", event, &[("detail", detail)]);
    ExitCode::FAILURE
}

/// Loads the configuration, starts everything and waits for a signal.
fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: bridge-native-daemon <config.toml>");
        return ExitCode::FAILURE;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return fail("config_read_failed", "configuration unreadable");
    };
    // The parse error can quote a grant token; it is withheld.
    let Ok(config) = toml::from_str::<NativeConfig>(&text) else {
        return fail(
            "config_parse_failed",
            "configuration is invalid; the message is withheld",
        );
    };
    let Some(directory) = config.adapters.channel.parent() else {
        return fail("channel_invalid", "channel socket has no directory");
    };
    let owner = match private_directory(directory) {
        Ok(owner) => owner,
        Err(error) => return fail("channel_directory_refused", &error.to_string()),
    };
    let mut registry = match Registry::new(config.adapters.registry, owner) {
        Ok(registry) => registry,
        Err(error) => return fail("registry_invalid", &error),
    };
    // A legacy profile note keeps its established `legacy_profile_migrated` event;
    // the ignored legacy owner_relays table has its own distinct event.
    for note in registry.migration_notes() {
        match note.strip_prefix(LEGACY_OWNER_RELAYS_PREFIX) {
            Some(text) => {
                service::log_event("warn", "legacy_owner_relays_ignored", &[("note", text)])
            }
            None => service::log_event("warn", "legacy_profile_migrated", &[("note", note)]),
        }
    }
    if !config.adapters.sandbox.is_file() {
        registry.disable_message(Harness::Codex);
        service::log_event(
            "warn",
            "codex_message_unsupported",
            &[("reason", "no confinement launcher")],
        );
    }
    // `Registry::new` already hashed the configured executables before
    // anything is served; this idempotent call re-reads nothing and only
    // reports the counts.
    let (cached, skipped) = registry.warm_digests();
    let unqualified = registry.unqualified_executables();
    // Counts only, never paths, digests or file contents. A warning means
    // some configured route cannot attest until the files or the
    // configured digests are fixed and the daemon is restarted.
    service::log_event(
        if skipped > 0 || unqualified > 0 {
            "warn"
        } else {
            "info"
        },
        "executable_digests_warmed",
        &[
            ("cached", &cached.to_string()),
            ("skipped", &skipped.to_string()),
            ("unqualified", &unqualified.to_string()),
        ],
    );
    let registry = Arc::new(Mutex::new(registry));
    let late = Arc::new(LateCustody::default());
    let claude = match ClaudeLaterCarrier::new(
        Arc::clone(&registry),
        Arc::clone(&late) as Arc<dyn Custody>,
        ClaudeTiming::default(),
    ) {
        Ok(carrier) => carrier,
        Err(error) => return fail("carrier_start_failed", &error.to_string()),
    };
    let codex = CodexQueueCarrier::new(
        Arc::clone(&registry),
        config.adapters.sandbox.clone(),
        DEFAULT_HELPER_TIMEOUT,
    )
    .with_desktop_directory(config.adapters.channel.parent().unwrap().to_path_buf());
    let terminate = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        let registered =
            signal_hook::flag::register_conditional_shutdown(signal, 1, Arc::clone(&terminate))
                .and_then(|_| signal_hook::flag::register(signal, Arc::clone(&terminate)));
        if registered.is_err() {
            return fail("signal_registration_failed", "signal handlers unavailable");
        }
    }
    let running =
        match service::start_with_carriers(config.core, vec![Box::new(codex), Box::new(claude)]) {
            Ok(running) => Arc::new(running),
            Err(error) => return fail("service_start_failed", &error.to_string()),
        };
    let custody: Arc<dyn Custody> = Arc::clone(&running) as Arc<dyn Custody>;
    late.attach(&custody);
    drop(custody);
    let channel = match ChannelServer::start(
        &config.adapters.channel,
        Arc::clone(&registry),
        Arc::clone(&running) as Arc<dyn Custody>,
        DispatchTiming::default(),
    ) {
        Ok(channel) => channel,
        Err(error) => {
            running.shutdown();
            return fail("channel_start_failed", &error.to_string());
        }
    };
    service::log_event("info", "native_daemon_started", &[]);
    let mut ticks = 0u32;
    while running.is_running() && !terminate.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
        // Roughly twice a second: a stat per configured executable; a changed
        // file identity (an application update) is hashed on a background
        // thread, never under the registry lock and never on a request.
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(5) {
            refresh_executables(&registry);
        }
    }
    running.shutdown();
    channel.stop();
    stop_executable_refresh(&registry);
    match Arc::try_unwrap(running) {
        Ok(running) => running.join(),
        Err(_) => service::log_event(
            "warn",
            "drain_skipped",
            &[("reason", "service still shared")],
        ),
    }
    ExitCode::SUCCESS
}
