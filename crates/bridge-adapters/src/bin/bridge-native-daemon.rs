//! Bridge daemon with native adapters: the core service, the Codex and
//! Claude message carriers, and the adapter channel for hooks and root
//! caller attestation.
//!
//! Usage: `bridge-native-daemon <config.toml>`. The file is the core
//! configuration (database, socket, limits, grants) plus an `[adapters]`
//! table: `channel` (socket path inside a private 0700 directory),
//! `sandbox` (confinement launcher, default `/usr/bin/sandbox-exec`) and
//! the registry fields (`host_id`, `profiles`, optional `intermediates`,
//! `max_call_age_ms`). When the launcher is missing, the Codex message
//! capability is never granted, so such publications refuse before
//! acceptance. `Registry::new` hashes every configured harness and relay
//! executable once before returning (the daemon then reports the counts via
//! the idempotent `Registry::warm_digests`), so no hook request
//! reads a whole executable under the registry lock; startup takes about
//! one streamed read of those files (about 1.6 s per 246 MB optimized, far
//! longer unoptimized) and logs `executable_digests_warmed` with the cached,
//! skipped and unqualified counts (a warning when either of the last two is
//! non-zero: a file is missing, unreadable or changing, or its real hash is
//! not the configured digest; counts only, no paths or contents). Serving
//! never hashes: a configured file that was
//! missing or unreadable at startup, or is installed, replaced or modified
//! later, is refused as unqualified until the daemon is restarted (other
//! warmed executables keep attesting); after updating a harness build,
//! update its configured digest and restart. SIGTERM/SIGINT stop the channel,
//! then drain the service.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_adapters::claude::{ClaudeLaterCarrier, ClaudeTiming};
use bridge_adapters::codex::{CodexQueueCarrier, DEFAULT_HELPER_TIMEOUT};
use bridge_adapters::server::{ChannelServer, Custody, LateCustody, private_directory};
use bridge_adapters::{Registry, RegistryConfig};
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
    while running.is_running() && !terminate.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    running.shutdown();
    channel.stop();
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
