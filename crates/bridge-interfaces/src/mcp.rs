//! Root MCP frontend: a stdio MCP server the harness launches, exposing
//! exactly `bridge_me`, `bridge_send` and `bridge_status`.
//!
//! The frontend holds no Bridge credential. For each `tools/call` it reads
//! only the harness-owned request `_meta` (Claude `claudecode/toolUseId`,
//! Codex `threadId` + `callId` + `x-codex-turn-metadata`), asks the adapter
//! registry to attest *this process's* caller and seal a single-use proof
//! ([`bridge_adapters::RegistryAttestor::attest_sealed`]: the registry
//! identifies the frontend by kernel peer credentials and requires it to
//! descend from a marked harness the policy enables), and forwards `{proof, tool,
//! arguments}` to the root relay ([`crate::root`]), which redeems the proof
//! and enforces policy. Missing `_meta`, a model-supplied identity, or any
//! attestation failure refuses the call before the relay is contacted.
//!
//! Protocol subset: `initialize`, `notifications/*` (ignored), `ping`,
//! `tools/list` and `tools/call`; anything else is JSON-RPC
//! `-32601`. Lines are bounded before allocation. Tool results carry the
//! relay answer as text and `structuredContent`, with `isError` set on
//! refusal; the sealed proof is never echoed.

use std::io::{BufRead, Write};
use std::path::Path;

use bridge_adapters::registry::{CorrelationError, PresentedMeta, SealedProof};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::root::{RelayRequest, RelayResponse, TOOLS, call_relay};

/// Largest accepted JSON-RPC line, in bytes.
pub const MAX_LINE_BYTES: usize = 512 * 1024;

/// MCP protocol revisions this frontend answers with; the newest is the
/// default when the client asks for an unknown one.
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];

/// Server name reported in `initialize`.
pub const SERVER_NAME: &str = "agent-bridge-root";

/// The sealing step: attest the caller of one request's `_meta` and return
/// a single-use proof for the relay (production:
/// `RegistryAttestor::attest_sealed`, ignoring the frontend-side caller).
pub type Sealer<'a> = &'a dyn Fn(&PresentedMeta, u64) -> Result<SealedProof, CorrelationError>;

/// Serves JSON-RPC lines from `input` until EOF, answering on `output`.
///
/// A line over [`MAX_LINE_BYTES`] or unparseable JSON answers a JSON-RPC
/// error with a null id and the loop continues; an output write failure
/// ends the loop (the harness went away).
pub fn serve(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    seal: Sealer<'_>,
    relay_socket: &Path,
) -> std::io::Result<()> {
    loop {
        let line = match read_line(input)? {
            None => return Ok(()),
            Some(Ok(line)) => line,
            Some(Err(message)) => {
                write_message(output, &error(Value::Null, -32700, message))?;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(answer) = handle_line(&line, seal, relay_socket) {
            write_message(output, &answer)?;
        }
    }
}

/// Reads one line bounded by [`MAX_LINE_BYTES`].
///
/// `None` at EOF; `Some(Err)` for an oversize (the rest of that line is
/// discarded) or non-UTF-8 line. A final line without a newline is
/// accepted.
fn read_line(input: &mut dyn BufRead) -> std::io::Result<Option<Result<String, &'static str>>> {
    let mut line = Vec::new();
    let mut oversize = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() && !oversize {
                return Ok(None);
            }
            break;
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let take = end.unwrap_or(available.len());
        if line.len() + take > MAX_LINE_BYTES {
            oversize = true;
            line.clear();
        } else if !oversize {
            line.extend_from_slice(&available[..take]);
        }
        input.consume(take + usize::from(end.is_some()));
        if end.is_some() {
            break;
        }
    }
    if oversize {
        return Ok(Some(Err("request line too large")));
    }
    Ok(Some(
        String::from_utf8(line).map_err(|_| "request is not UTF-8"),
    ))
}

/// Handles one JSON-RPC message; `None` for notifications.
pub fn handle_line(line: &str, seal: Sealer<'_>, relay_socket: &Path) -> Option<Value> {
    let Ok(Value::Object(message)) = serde_json::from_str::<Value>(line) else {
        return Some(error(Value::Null, -32700, "invalid JSON-RPC message"));
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let id = id?;
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_list()})),
        "tools/call" => call_tool(&params, seal, relay_socket),
        _ => Err((-32601, "method not found")),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => error(id, code, message),
    })
}

/// The `initialize` result: the requested revision when supported.
fn initialize(params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|version| **version == requested)
        .unwrap_or(&PROTOCOL_VERSIONS[PROTOCOL_VERSIONS.len() - 1]);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
        "instructions": "Agent Bridge root tools. Your identity comes from the harness, never from arguments. Sends are keep_all to valid native addresses within the configured policy (star allows new sessions without manual admission); status shows only your own requests. Uncertain delivery is never resent automatically.",
    })
}

/// The closed tool definitions.
pub fn tool_list() -> Value {
    let address = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["host_id", "harness", "native_store_namespace", "native_session_id"],
        "properties": {
            "host_id": {"type": "string"},
            "harness": {"type": "string", "enum": ["codex", "claude-code"]},
            "native_store_namespace": {"type": "string"},
            "native_session_id": {"type": "string"},
        },
    });
    json!([
        {
            "name": TOOLS[0],
            "description": "Your attested native address and what you may send.",
            "inputSchema": {"type": "object", "additionalProperties": false, "properties": {}},
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        },
        {
            "name": TOOLS[1],
            "description": "Send with address and message. Native message delivery is the default. New sessions need no manual admission when policy is *. An omitted request_id is generated from this authenticated host call and returned. Reuse that id to reconcile uncertain delivery; never resend an uncertain message with a new id. Legacy recipient/body/kind/mode fields remain supported.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "anyOf": [{"required": ["address", "message"]}, {"required": ["recipient", "body"]}],
                "properties": {
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"},
                    "address": {"type": "string", "description": "Canonical native address from bridge_me"},
                    "message": {"type": "string"},
                    "recipient": {"oneOf": [{"type": "string"}, address]},
                    "kind": {"type": "string"},
                    "mode": {"type": "string", "enum": ["inject", "message", "auto"]},
                    "body": {"type": "string"},
                    "expires_at_ms": {"type": "integer", "minimum": 1},
                },
            },
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false},
        },
        {
            "name": TOOLS[2],
            "description": "Custody, native, context and uncertainty status of one of your own requests.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["request_id"],
                "properties": {"request_id": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"}},
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        },
    ])
}

/// `tools/call`: closed params, attestation, and relay. For sends without
/// `request_id`, derive a stable id from the authenticated native call id
/// before any relay write. Kind/mode defaults and target validation remain
/// relay-owned; unknown outcomes disclose the id for reconciliation.
fn call_tool(
    params: &Value,
    seal: Sealer<'_>,
    relay_socket: &Path,
) -> Result<Value, (i64, &'static str)> {
    let Some(params) = params.as_object() else {
        return Err((-32602, "params must be an object"));
    };
    if params
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
    {
        return Err((-32602, "unknown tools/call parameter"));
    }
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !TOOLS.contains(&name) {
        return Err((-32602, "unknown tool"));
    }
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !arguments.is_object() {
        return Err((-32602, "arguments must be an object"));
    }
    let answer = match params.get("_meta").and_then(Value::as_object) {
        None => RelayResponse::error(
            "caller_not_evidence",
            "the request carries no harness _meta; arguments never identify a caller",
        ),
        Some(meta) => match PresentedMeta::from_mcp_meta(meta).and_then(|meta| {
            seal(&meta, bridge_core::service::current_unix_millis()).map(|proof| (proof, meta))
        }) {
            Err(refusal) => RelayResponse::error(
                format!("caller_{}", refusal.class().trim_start_matches("caller_")),
                refusal.detail().to_string(),
            ),
            Ok((proof, native_meta)) => {
                if name == TOOLS[1] && arguments.get("request_id").is_none() {
                    let call_id = match &native_meta {
                        PresentedMeta::Claude { tool_use_id } => tool_use_id,
                        PresentedMeta::Codex { call_id, .. } => call_id,
                        PresentedMeta::Sealed { .. } => {
                            return Err((-32602, "native call identity missing"));
                        }
                    };
                    arguments["request_id"] =
                        Value::String(format!("call-{:x}", Sha256::digest(call_id.as_bytes())));
                }
                let request_id = arguments
                    .get("request_id")
                    .and_then(Value::as_str)
                    .filter(|id| {
                        id.len() <= 128
                            && id
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                    })
                    .map(str::to_owned);
                let mut answer = call_relay(
                    relay_socket,
                    &RelayRequest {
                        proof,
                        tool: name.to_string(),
                        arguments,
                    },
                );
                if let RelayResponse::Error { class, detail } = &mut answer
                    && matches!(class.as_str(), "relay_outcome_unknown" | "custody_unknown")
                    && let Some(id) = request_id
                {
                    detail.push_str(&format!(
                        "; reconcile request_id={id}; never create a new id for this message"
                    ));
                }
                answer
            }
        },
    };
    Ok(tool_result(&answer))
}

/// Renders a relay answer as an MCP tool result.
fn tool_result(answer: &RelayResponse) -> Value {
    let (structured, is_error) = match answer {
        RelayResponse::Ok { value } => (value.clone(), false),
        RelayResponse::Error { class, detail } => (json!({"error": class, "detail": detail}), true),
    };
    json!({
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
        "isError": is_error,
    })
}

/// A JSON-RPC error object.
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Writes one message line and flushes.
fn write_message(output: &mut dyn Write, message: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    line.push(b'\n');
    output.write_all(&line)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    //! Protocol framing and refusal before any relay contact.

    use super::*;

    /// A sealer that must never be reached.
    fn unreachable_sealer(_: &PresentedMeta, _: u64) -> Result<SealedProof, CorrelationError> {
        panic!("sealing must not run");
    }

    /// A sealer that refuses as a duplicate.
    fn duplicate_sealer(_: &PresentedMeta, _: u64) -> Result<SealedProof, CorrelationError> {
        Err(CorrelationError::Duplicate("call-1".into()))
    }

    /// Runs one line through the handler with a dead relay path.
    fn run(line: &str, seal: Sealer<'_>) -> Value {
        handle_line(line, seal, Path::new("/nonexistent/relay.sock")).unwrap()
    }

    /// Pins the independently specified three-tool root surface and refuses operator or acknowledgement tools before attestation.
    #[test]
    fn lists_exactly_three_closed_tools() {
        let tools = tool_list();
        let names: Vec<_> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect();
        // Pinned to literals, independent of `TOOLS`, so widening the root
        // surface (any new tool, in the list or the accepted set) fails here.
        let pinned = ["bridge_me", "bridge_send", "bridge_status"];
        assert_eq!(names, pinned);
        assert_eq!(names.len(), 3);
        assert_eq!(TOOLS.as_slice(), pinned.as_slice());
        for tool in tools.as_array().unwrap() {
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
    }

    /// A tool call without host call metadata is refused as `caller_not_evidence`
    /// before any sealing.
    #[test]
    fn missing_meta_refuses_without_sealing() {
        let answer = run(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bridge_me","arguments":{"caller":"root"}}}"#,
            &unreachable_sealer,
        );
        assert_eq!(answer["result"]["isError"], true);
        assert_eq!(
            answer["result"]["structuredContent"]["error"],
            "caller_not_evidence"
        );
    }

    /// A sealer refusal is returned as a tool error carrying its class
    /// (`caller_duplicate`).
    #[test]
    fn attestation_refusal_is_reported_with_its_class() {
        let answer = run(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bridge_status","arguments":{"request_id":"a"},"_meta":{"claudecode/toolUseId":"call-1"}}}"#,
            &duplicate_sealer,
        );
        assert_eq!(
            answer["result"]["structuredContent"]["error"],
            "caller_duplicate"
        );
    }

    /// Tools outside the fixed list (acknowledge, retry, admin, counts, transfer,
    /// incident listing), unknown parameters and unknown methods are refused
    /// before attestation.
    #[test]
    fn unknown_tools_params_and_methods_are_refused() {
        // No acknowledgement, retry, reset, enumeration or admin tool
        // exists; asking for one never reaches attestation.
        for tool in [
            "bridge_ack",
            "bridge.ack",
            "bridge_retry",
            "bridge_list",
            "bridge_admin",
            "bridge_counts",
            "bridge_transfer_lineage",
            "bridge_incidents",
        ] {
            let unknown_tool = run(
                &json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": tool, "arguments": {"receipt_handle": "x"},
                                   "_meta": {"claudecode/toolUseId": "call-1"}}})
                .to_string(),
                &unreachable_sealer,
            );
            assert_eq!(unknown_tool["error"]["code"], -32602, "{tool}");
        }
        let listed = tool_list().to_string();
        for operator_only in ["ack", "receipt", "count", "lineage", "incident"] {
            assert!(!listed.contains(operator_only), "{operator_only}");
        }
        let extra = run(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bridge_me","caller":"x"}}"#,
            &unreachable_sealer,
        );
        assert_eq!(extra["error"]["code"], -32602);
        let method = run(
            r#"{"jsonrpc":"2.0","id":5,"method":"resources/list"}"#,
            &unreachable_sealer,
        );
        assert_eq!(method["error"]["code"], -32601);
        assert!(
            handle_line(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                &unreachable_sealer,
                Path::new("/x")
            )
            .is_none()
        );
    }

    /// An over-long input line is refused and skipped, and the next request is
    /// still served.
    #[test]
    fn oversize_lines_are_refused_and_skipped() {
        let mut input = Vec::new();
        input.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 10));
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}");
        let mut output = Vec::new();
        serve(
            &mut std::io::BufReader::new(&input[..]),
            &mut output,
            &unreachable_sealer,
            Path::new("/x"),
        )
        .unwrap();
        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines[0]["error"]["code"], -32700);
        assert_eq!(lines[1]["id"], 9);
    }
}
