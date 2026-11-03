//! Shared native daemon configuration for standalone and system workers.

use std::path::PathBuf;

use bridge_core::service::Config;
use serde::Deserialize;

use crate::RegistryConfig;

/// The daemon's native adapter configuration.
#[derive(Deserialize)]
pub struct AdapterConfig {
    /// Private native channel socket.
    pub channel: PathBuf,
    /// Confinement launcher for the legacy Codex helper.
    #[serde(default = "default_sandbox")]
    pub sandbox: PathBuf,
    /// Native registry and harness policies.
    #[serde(flatten)]
    pub registry: RegistryConfig,
}

/// Returns the historical macOS confinement launcher path.
fn default_sandbox() -> PathBuf {
    PathBuf::from("/usr/bin/sandbox-exec")
}

/// Core and native adapter settings read by either daemon mode.
#[derive(Deserialize)]
pub struct NativeConfig {
    /// Core storage, socket and grant settings.
    #[serde(flatten)]
    pub core: Config,
    /// Native adapter settings.
    pub adapters: AdapterConfig,
}
