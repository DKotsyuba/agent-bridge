//! Manual single-publication example. Reads a protected credential reference and
//! typed PublishParams from a JSON specification; never accepts a token in argv
//! or retries an uncertain publication. Native qualification is outside CI.
use bridge_sdk::{
    Client, Config,
    bridge_protocol::{PublishParams, Secret},
};
use serde::Deserialize;
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};

/// macOS O_NOFOLLOW; this manual native example executes only on the supported platform.
const NO_FOLLOW: i32 = 0x0100;

/// Explicit deployment and immutable publish intention supplied by the operator.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    /// Protected adapter channel path.
    registration_socket: PathBuf,
    /// Protected core socket path.
    core_socket: PathBuf,
    /// Absolute owner-only regular credential file; value never appears in output.
    token_file: PathBuf,
    /// Stable request identity, retained for any manual reconciliation.
    request_id: String,
    /// Exact typed publication, including stable event id and native destination.
    publish: PublishParams,
}

/// Submit once through the public SDK; print only its correlated custody receipt.
/// Invalid local input or transport failure returns a static secret-safe error.
fn run() -> Result<(), &'static str> {
    if !cfg!(target_os = "macos") {
        return Err("native example is supported on macOS only");
    }
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: publish <specification.json>")?;
    let mut spec = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "specification unreadable")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut spec)
        .map_err(|_| "specification unreadable")?;
    if spec.len() > 1024 * 1024 {
        return Err("specification too large");
    }
    let input: Input = serde_json::from_slice(&spec).map_err(|_| "specification invalid")?;
    if !input.token_file.is_absolute()
        || input.token_file.canonicalize().ok().as_ref() != Some(&input.token_file)
    {
        return Err("credential reference must be canonical");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW)
        .open(&input.token_file)
        .map_err(|_| "credential unavailable")?;
    let metadata = file.metadata().map_err(|_| "credential unavailable")?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > 16384 {
        return Err("credential protection invalid");
    }
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "credential unreadable")?;
    if bytes.len() > 16384 {
        return Err("credential too large");
    }
    let token = String::from_utf8(bytes).map_err(|_| "credential encoding invalid")?;
    let mut config = Config::new(
        input.registration_socket,
        input.core_socket,
        Secret::new(token.trim_end()),
        Duration::from_secs(30),
    )
    .map_err(|_| "deployment invalid")?;
    config.reconnect_once = false;
    let client = Client::new(config).map_err(|_| "deployment invalid")?;
    let receipt = client.publish(&input.request_id, input.publish).map_err(
        |_| "publication failed; reconcile the original request id, do not create a new id",
    )?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|_| "receipt encoding failed")?
    );
    Ok(())
}

/// Return a finite failing exit without exposing credentials or message bytes.
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}
