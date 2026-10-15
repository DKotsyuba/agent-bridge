//! Independent SDK qualification frontend; root copies this into the pinned
//! portable consumer before building. No core, adapter or framework dependency.
//! Run `producer <private-config.json>` for MCP or add `--recover` to recover
//! the original registration/custody without asserting fresh native authority.
//! `--close` closes the recovered route using the public SDK's stable identity.
//! Configuration and payload stay in private files; MCP arguments are empty,
//! and stdout/journal contain receipts only. This is an owned test fixture,
//! not producer business admission or a persistent outbox.

use bridge_sdk::bridge_protocol::*;
use bridge_sdk::{Client, Config, extract_native_evidence};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::process::ExitCode;
use std::time::Duration;

/// Reads at most `limit` bytes from a private regular, nonsymlink fixture file.
/// Group/other access, inode replacement, excess bytes, invalid UTF-8 and I/O
/// failures return static errors; file contents are never put into errors.
fn private_text(path: &str, limit: usize) -> Result<String, &'static str> {
    let before = std::fs::symlink_metadata(path).map_err(|_| "private file unavailable")?;
    if !before.is_file() || before.mode() & 0o077 != 0 || before.len() > limit as u64 {
        return Err("private file refused");
    }
    let file = File::open(path).map_err(|_| "private file unavailable")?;
    let after = file.metadata().map_err(|_| "private file unavailable")?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err("private file changed");
    }
    let mut value = String::new();
    file.take((limit + 1) as u64)
        .read_to_string(&mut value)
        .map_err(|_| "private file unreadable")?;
    if value.len() > limit {
        return Err("private file too large");
    }
    Ok(value)
}

/// Returns a required nonempty string in the root-provisioned configuration;
/// missing/wrong fields refuse without displaying the configuration or value.
fn setting<'a>(config: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    config
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or("configuration field unavailable")
}

/// Constructs immutable registration intent from private runtime configuration.
/// `evidence` is an unverified framework candidate for a new call, or absent
/// for exact historical recovery. It never derives identity from arguments.
fn registration(
    config: &Value,
    evidence: Option<CallEvidence>,
) -> Result<RegisterCallParams, &'static str> {
    let mode = serde_json::from_value(config["mode"].clone()).map_err(|_| "mode refused")?;
    Ok(RegisterCallParams {
        operation_key: setting(config, "operation_key")?.into(),
        evidence,
        reply_policy: ReplyPolicy::SelfActor,
        allowed_modes: Some(vec![mode]),
        allowed_kinds: Some(vec![setting(config, "kind")?.into()]),
        max_payload_bytes: None,
        route_expires_at_ms: None,
        assertion_audience: None,
        invocation_key: None,
    })
}

/// Registers or recovers one persisted identity, then submits the original
/// private publication intent via its returned route and observes status.
/// `metadata` must be the framework's original separated `_meta`, never tool
/// arguments; absence requests historical recovery. SDK errors stay typed
/// internally and become static fixture failure categories. Success proves
/// custody/observation only, never native delivery or business admission.
fn submit(client: &Client, config: &Value, metadata: Option<&Value>) -> Result<Value, &'static str> {
    let evidence = metadata
        .map(|metadata| {
            let host = serde_json::from_value(config["host"].clone())
                .map_err(|_| "native host refused")?;
            extract_native_evidence(host, metadata).map_err(|_| "native candidate refused")
        })
        .transpose()?;
    let registered = client
        .register_call(setting(config, "request_id")?, registration(config, evidence)?)
        .map_err(|_| "registration unresolved; preserve original identity")?;
    let payload = private_text(setting(config, "payload_file")?, MAX_PAYLOAD_BYTES)?;
    let published = client
        .publish(
            format!("publish-{}", setting(config, "request_id")?),
            PublishParams {
                destination: Destination::Route {
                    route_key: registered.receipt.route_key.clone(),
                },
                event_id: setting(config, "event_id")?.into(),
                kind: setting(config, "kind")?.into(),
                payload: Payload::new(payload).map_err(|_| "payload refused")?,
                mode: serde_json::from_value(config["mode"].clone()).map_err(|_| "mode refused")?,
                policy: Policy::KeepAll,
                metadata: Metadata::new(),
                expires_at_ms: None,
                delivery_scope_key: None,
            },
        )
        .map_err(|_| "publication unresolved; preserve original identity")?;
    let status = client
        .status(
            format!("status-{}", setting(config, "request_id")?),
            StatusSelector::Event {
                event_id: setting(config, "event_id")?.into(),
            },
        )
        .map_err(|_| "status unavailable")?;
    Ok(json!({"registration": registered.receipt, "evidence_state": registered.evidence_state,
        "assertion_present": registered.assertion.is_some(), "publication": published.receipt,
        "replayed": published.replayed, "status": status}))
}

/// Appends receipt-only JSON to a private fixture journal and flushes it before
/// returning it to MCP. Root provisions the parent directory. Existing symlink
/// or group/other-readable files refuse; journal errors never imply noncommit.
fn journal(config: &Value, result: &Value) -> Result<(), &'static str> {
    let path = setting(config, "receipt_file")?;
    let before = match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.mode() & 0o077 != 0 => {
            return Err("receipt journal refused");
        }
        Ok(meta) => Some(meta),
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err("receipt journal unavailable");
        }
        Err(_) => None,
    };
    let mut file = OpenOptions::new()
        .create_new(before.is_none())
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "receipt journal unavailable")?;
    let opened = file.metadata().map_err(|_| "receipt journal unavailable")?;
    if !opened.is_file() || opened.mode() & 0o077 != 0
        || before.is_some_and(|meta| (meta.dev(), meta.ino()) != (opened.dev(), opened.ino())) {
        return Err("receipt journal changed");
    }
    serde_json::to_writer(&mut file, result).map_err(|_| "receipt journal unavailable")?;
    file.write_all(b"\n").map_err(|_| "receipt journal unavailable")?;
    file.sync_data().map_err(|_| "receipt journal unavailable")
}

/// Reads a private fixture configuration and serves bounded MCP frames with
/// one configured tool and empty arguments, or performs explicit `--recover`
/// or idempotent `--close` after historical registration recovery.
/// Unknown tool/method, metadata or input failures return static errors. Each
/// successful submission journals receipts before exposing them on stdout.
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if !(args.len() == 2 || (args.len() == 3 && ["--recover", "--close"].contains(&args[2].as_str()))) {
        return Err("expected private configuration and optional --recover/--close");
    }
    let config: Value = serde_json::from_str(&private_text(&args[1], MAX_REGISTRATION_BYTES)?)
        .map_err(|_| "configuration refused")?;
    let credential = private_text(setting(&config, "credential_file")?, 4096)?;
    let client = Client::new(
        Config::new(
            setting(&config, "registration_socket")?,
            setting(&config, "core_socket")?,
            Secret::new(credential.trim_end()),
            Duration::from_secs(5),
        )
        .map_err(|_| "client configuration refused")?,
    )
    .map_err(|_| "client configuration refused")?;
    if args.len() == 3 {
        let result = if args[2] == "--close" {
            let recovered = client.register_call(setting(&config, "request_id")?, registration(&config, None)?)
                .map_err(|_| "registration unresolved; preserve original identity")?;
            let closed = client.close_route(format!("close-{}", setting(&config, "request_id")?), CloseRouteParams {
                route_key: recovered.receipt.route_key,
                reason: None,
            }).map_err(|_| "close unresolved; preserve original identity")?;
            json!({"close": closed})
        } else {
            submit(&client, &config, None)?
        };
        journal(&config, &result)?;
        println!("{result}");
        return Ok(());
    }
    let mut input = io::stdin().lock();
    loop {
        let mut line = String::new();
        if input.by_ref().take((MAX_REGISTRATION_BYTES + 1) as u64)
            .read_line(&mut line).map_err(|_| "MCP input unavailable")? == 0 {
            break;
        }
        if line.len() > MAX_REGISTRATION_BYTES || !line.ends_with('\n') {
            return Err("MCP frame refused");
        }
        let rpc: Value = serde_json::from_str(&line).map_err(|_| "MCP frame refused")?;
        let Some(id) = rpc.get("id") else { continue; };
        let result = match rpc.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({"protocolVersion":"2025-03-26", "capabilities":{"tools":{}},
                "serverInfo":{"name":"independent-sdk-producer","version":"0.3.0"}}),
            Some("ping") => json!({}),
            Some("tools/list") => json!({"tools":[{"name":setting(&config,"tool_name")?,
                "description":"Register this native call and publish private fixture data; return receipts only",
                "inputSchema":{"type":"object","properties":{},"additionalProperties":false}}]}),
            Some("tools/call") => {
                let params = &rpc["params"];
                if params["name"].as_str() != Some(setting(&config, "tool_name")?)
                    || !params["arguments"].as_object().is_some_and(|a| a.is_empty()) {
                    return Err("MCP invocation refused");
                }
                match params.get("_meta").ok_or("original metadata missing")
                    .and_then(|metadata| submit(&client, &config, Some(metadata))) {
                    Ok(value) => {
                        journal(&config, &value)?;
                        json!({"content":[{"type":"text","text":value.to_string()}]})
                    }
                    Err(reason) => json!({"isError":true,"content":[{"type":"text","text":reason}]}),
                }
            }
            _ => return Err("MCP method unsupported"),
        };
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &json!({"jsonrpc":"2.0","id":id,"result":result}))
            .map_err(|_| "MCP output unavailable")?;
        output.write_all(b"\n").and_then(|_| output.flush()).map_err(|_| "MCP output unavailable")?;
    }
    Ok(())
}

/// Exits zero after successful MCP/recovery execution; failures print only a
/// static category to stderr and exit one. No panic/error body dumps are used.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => { eprintln!("{reason}"); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    //! Minimal independent fixture check for immutable registration intent.
    use super::*;

    /// Recovery preserves the original semantic fingerprint while dropping
    /// ephemeral evidence; random runtime operation/kind values remain opaque.
    #[test]
    fn recovery_preserves_registration_identity() {
        let config = json!({"operation_key":"unknown-op", "kind":"unknown.kind", "mode":"inject"});
        let evidence = CallEvidence::Native { host: Host::Codex, metadata: Default::default() };
        let fresh = registration(&config, Some(evidence)).unwrap();
        let recovered = registration(&config, None).unwrap();
        assert!(fresh.evidence.is_some());
        assert!(recovered.evidence.is_none());
        assert_eq!(registration_request_fingerprint(&fresh).unwrap(),
            registration_request_fingerprint(&recovered).unwrap());
        assert!(registration(&json!({"operation_key":"op","mode":"inject"}), None).is_err());
    }
}
