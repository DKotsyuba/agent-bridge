//! One-shot bounded diagnostics helper. Explicit observer configuration is the
//! only credential source. This module never opens a database or starts a daemon.

use std::io::Read;
use std::path::Path;

use bridge_client::BridgeClient;
use bridge_core::observation::{MAX_OBSERVATION_BYTES, ObservationQuery};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::{InterfacesConfig, read_secret};

/// Maximum entire stdin frame, including its single terminating newline.
pub const MAX_INPUT_BYTES: usize = 16 * 1024;

/// Closed helper input; typed operation/params are validated separately so the
/// schema version is never silently defaulted or interpreted as another protocol.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    /// Exactly version one.
    schema_version: u32,
    /// One of the four fixed operation names.
    operation: String,
    /// Required closed parameters object for that operation.
    params: Value,
}

/// Builds a secret-safe structured failure with no success data branch.
fn failure(kind: &str, code: &str, outcome: &str, detail: &str) -> Value {
    json!({"schema_version":1,"kind":kind,"error":{"code":code,"outcome":outcome,"detail":detail}})
}

/// Reads exactly one bounded UTF-8 JSON line followed by EOF, validates closed
/// argv/config/schema, and performs only a typed observer API call. All errors
/// are fixed generic text; raw parser, socket, credential and stderr text never
/// escape. Missing config or observer sections never use admin/root credentials.
/// The embedding caller owns the stdin/process deadline; socket I/O uses the
/// existing bounded BridgeClient deadlines and safe read-only reconnect policy.
/// Returns exactly one success data branch or one structured error branch.
pub fn run(args: &[String], input: &mut dyn Read) -> Value {
    let mut bytes = Vec::new();
    if input
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_INPUT_BYTES
        || !bytes.ends_with(b"\n")
        || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n')
    {
        return failure(
            "observation_error",
            "invalid_input",
            "blocked",
            "one bounded JSON line required",
        );
    }
    let parsed: Input = match serde_json::from_slice(&bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            return failure(
                "observation_error",
                "invalid_input",
                "blocked",
                "invalid observation input",
            );
        }
    };
    if parsed.schema_version != 1 {
        return failure(
            "observation_error",
            "unsupported_schema",
            "blocked",
            "unsupported observation schema",
        );
    }
    let query: ObservationQuery = match serde_json::from_value(
        json!({"operation":parsed.operation,"params":parsed.params}),
    ) {
        Ok(query) => query,
        Err(_) => {
            return failure(
                "observation_error",
                "invalid_operation",
                "blocked",
                "invalid observation operation or parameters",
            );
        }
    };
    let kind = query.kind();
    let path = match args {
        [flag, path] if flag == "--config" && Path::new(path).is_absolute() => Path::new(path),
        [] => {
            return failure(
                kind,
                "observer_unconfigured",
                "blocked",
                "explicit observer configuration required",
            );
        }
        _ => {
            return failure(
                kind,
                "invalid_arguments",
                "blocked",
                "invalid observe arguments",
            );
        }
    };
    let config = match InterfacesConfig::load(path) {
        Ok(config) => config,
        Err(_) => {
            return failure(
                kind,
                "invalid_config",
                "blocked",
                "observer configuration unavailable or invalid",
            );
        }
    };
    let Some(observer) = config.observer else {
        return failure(
            kind,
            "observer_unconfigured",
            "blocked",
            "diagnostics observer is not configured",
        );
    };
    let token = match read_secret(&observer.token_file) {
        Ok(token) => token,
        Err(_) => {
            return failure(
                kind,
                "invalid_credential",
                "blocked",
                "observer credential unavailable or invalid",
            );
        }
    };
    let mut client = match BridgeClient::connect(&config.core_socket) {
        Ok(client) => client,
        Err(_) => {
            return failure(
                kind,
                "bridge_unavailable",
                "unavailable",
                "Bridge service unavailable",
            );
        }
    };
    let observation = match client.observe(&token, &query) {
        Ok(observation) => observation,
        Err(error) => {
            let (code, outcome) = match error.class.as_str() {
                "auth" | "forbidden" => ("observer_denied", "blocked"),
                "invalid" => ("observation_rejected", "blocked"),
                _ => ("bridge_unavailable", "unavailable"),
            };
            return failure(kind, code, outcome, "Bridge observation could not be read");
        }
    };
    let mut value = match serde_json::to_value(observation) {
        Ok(value) => value,
        Err(_) => {
            return failure(
                kind,
                "invalid_response",
                "unavailable",
                "invalid Bridge observation",
            );
        }
    };
    value["schema_version"] = json!(1);
    if serde_json::to_vec(&value).map_or(true, |bytes| bytes.len() + 1 > MAX_OBSERVATION_BYTES) {
        return failure(
            kind,
            "response_too_large",
            "unavailable",
            "Bridge observation exceeds frame budget",
        );
    }
    value
}
