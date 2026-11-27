//! Root MCP frontend: a stdio MCP server the harness launches, exposing
//! exactly `bridge_me`, `bridge_send` and `bridge_status`.
//!
//! The frontend holds no Bridge credential. For each `tools/call` it reads
//! only the harness-owned request `_meta` (Claude `claudecode/toolUseId`,
//! Codex `threadId` + `callId` + `x-codex-turn-metadata`), or, for a harness
//! whose profile accepts hook tokens, the single-use `bridge_call_token` its
//! protected `PreToolUse` hook wrote into the arguments (removed before anything
//! else reads them, and preferred over `_meta` when present), asks the adapter
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
//! a short text summary and the relay answer in `structuredContent`, with `isError` set on
//! refusal; the sealed proof is never echoed.

use std::io::{BufRead, Write};
use std::path::Path;

use bridge_adapters::registry::{
    CALL_TOKEN_ARGUMENT, CallToken, CorrelationError, PresentedMeta, SealedProof,
};
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
    // Written by the harness's own Bridge hook, never by the model; a value the
    // hook did not issue joins no record and refuses.
    let token = json!({
        "type": "string",
        "description": "Set by the Bridge hook. Never set or invent it.",
    });
    let address = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["host_id", "harness", "native_store_namespace", "native_session_id"],
        "properties": {
            "host_id": {"type": "string"},
            "harness": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,31}$"},
            "native_store_namespace": {"type": "string"},
            "native_session_id": {"type": "string"},
        },
    });
    json!([
        {
            "name": TOOLS[0],
            "description": "Your attested native address, permitted sends and retained delivery failure reports. Use reports_after from next_after_seq to read another page; reading preserves all reports.",
            "inputSchema": {"type": "object", "additionalProperties": false, "properties": {
                CALL_TOKEN_ARGUMENT: token.clone(),
                "reports_after": {"type":"integer","minimum":0,"maximum":bridge_core::MAX_SQLITE_INT,"description":"Exclusive completed-report cursor; omit or use 0 to begin."}
            }},
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
                    CALL_TOKEN_ARGUMENT: token.clone(),
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"},
                    "address": {"type": "string", "description": "Canonical native address from bridge_me"},
                    "message": {"type": "string"},
                    "as": {"type": "string", "pattern": "^[A-Za-z0-9 _.-]{1,32}$", "description": "Your role for recipients, e.g. `executor`. Required on your first message to register it; afterwards optional — the last declared role is reused automatically. Send a new value to change it."},
                    "reply_to": {"type": "string", "pattern": "^#[A-Fa-f0-9]{6,40}$", "description": "Short reply label shown as supplied."},
                    "priority": {"type": "string", "enum": ["urgent", "normal", "fyi"], "description": "Display label only. Defaults to normal."},
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
                "properties": {
                    CALL_TOKEN_ARGUMENT: token,
                    "request_id": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"},
                },
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
    let Some(object) = arguments.as_object_mut() else {
        return Err((-32602, "arguments must be an object"));
    };
    let token = match object.remove(CALL_TOKEN_ARGUMENT) {
        None => None,
        Some(Value::String(token)) => Some(CallToken::from_wire(token)),
        Some(_) => return Err((-32602, "bridge_call_token must be a string")),
    };
    let presented = match (token, params.get("_meta").and_then(Value::as_object)) {
        (Some(token), _) => Ok(PresentedMeta::HookToken { token }),
        (None, Some(meta)) => PresentedMeta::from_mcp_meta(meta),
        (None, None) => Err(CorrelationError::NotEvidence(
            "the request carries no harness _meta or hook token; arguments never identify a caller"
                .into(),
        )),
    };
    let mut reconciliation_id = None;
    let answer = match presented.and_then(|meta| {
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
                    PresentedMeta::OpenCode { call_id, .. } => call_id,
                    PresentedMeta::HookToken { token } => token.as_str(),
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
                && let Some(id) = request_id.as_deref()
            {
                detail.push_str(&format!(
                    "; reconcile request_id={id}; never create a new id for this message"
                ));
            }
            reconciliation_id = request_id;
            answer
        }
    };
    Ok(tool_result(name, &answer, reconciliation_id.as_deref()))
}

/// Renders a text summary while preserving the complete structured relay answer.
fn tool_result(tool: &str, answer: &RelayResponse, request_id: Option<&str>) -> Value {
    let (text, structured, is_error) = match answer {
        RelayResponse::Ok { value } => (success_summary(tool, value), value.clone(), false),
        RelayResponse::Error { class, detail } => (
            error_summary(tool, class, request_id),
            json!({"error": class, "detail": detail}),
            true,
        ),
    };
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": is_error,
    })
}

/// Summarizes successful calls using only the fields needed to act.
fn success_summary(tool: &str, value: &Value) -> String {
    use bridge_core::framing::format_utc_timestamp;

    match tool {
        "bridge_me" => {
            let caller = value["caller"]["canonical"].as_str().unwrap_or("unknown");
            let time = value["caller"]["observed_at_ms"]
                .as_u64()
                .map(|ms| format!(" at {}", format_utc_timestamp(ms)))
                .unwrap_or_default();
            format!("Bridge verified your address as {caller}{time}.")
        }
        "bridge_send" => {
            let request_id = value["request_id"].as_str().unwrap_or("unknown");
            let time = value["custody"]["accepted_at_ms"]
                .as_u64()
                .map(|ms| format!(" at {}", format_utc_timestamp(ms)))
                .unwrap_or_default();
            format!(
                "Bridge accepted {request_id} into custody{time} — check bridge_status before taking any further action."
            )
        }
        "bridge_status" => status_summary(value),
        _ => "Bridge completed the request.".into(),
    }
}

/// Describes the recorded handoff and the safest next step without inferring delivery.
fn status_summary(value: &Value) -> String {
    if value["custody"]["state"] == "not_found" {
        return "Bridge found no custody record for this request — verify the request ID before taking further action.".into();
    }
    if value["uncertainty"]["manual_resolution_required"] == true {
        return "Bridge has custody and delivery requires operator review — do not resend.".into();
    }
    if value["delivery"]["state"] == "disposed" {
        return match value["report"]["outcome"].as_str() {
            Some("failed") => "Bridge stopped delivery after confirming no handoff — review the delivery report before taking further action.",
            _ if value["uncertainty"]["disposed"] == true => "Bridge closed delivery without confirming the outcome — do not resend.",
            _ => "Bridge closed this delivery — review the status before taking further action.",
        }.into();
    }
    let native = value["native"].as_str();
    let time = || {
        value["tiers"]
            .as_array()
            .and_then(|tiers| {
                tiers
                    .iter()
                    .rev()
                    .find(|tier| tier["tier"].as_str() == native)
            })
            .and_then(|tier| tier["at_ms"].as_u64())
            .map(|ms| format!(" at {}", bridge_core::framing::format_utc_timestamp(ms)))
            .unwrap_or_default()
    };
    let hold_reason = value["delivery"]["hold_reason"]
        .as_str()
        .and_then(bridge_core::recovery::public_native_hold_reason)
        .map(|reason| format!(" ({reason})"))
        .unwrap_or_default();
    match native {
        Some("native_accepted") => format!("The recipient’s native queue accepted the message{} — wait for the recipient’s response.", time()),
        Some("hook_emitted") => format!("Bridge handed the message to the recipient’s hook{} — wait for the recipient’s response.", time()),
        Some("in_flight") => "Bridge has custody and the handoff is in progress — check again with bridge_status and do not resend.".into(),
        Some("native_held") => format!("The native route is holding the message{hold_reason} — check again with bridge_status and do not resend."),
        Some("written_no_receipt") => "The message was written without a receipt — check again with bridge_status and do not resend.".into(),
        Some("not_handed") => format!("Bridge has custody and is waiting to hand off the message{hold_reason} — check again with bridge_status and do not resend."),
        Some("refused") => "The native route refused the handoff — review the status before taking further action.".into(),
        _ => "Bridge has custody and the handoff outcome is unknown — check again with bridge_status and do not resend.".into(),
    }
}

/// Describes refusals without copying free-form details or credential fields into text.
fn error_summary(tool: &str, class: &str, request_id: Option<&str>) -> String {
    match class {
        "relay_outcome_unknown" | "custody_unknown" if tool == "bridge_me" => {
            "Bridge did not confirm the result — check again with bridge_me.".into()
        }
        "relay_outcome_unknown" | "custody_unknown" => {
            let request = request_id.map_or_else(
                || "the original request ID".into(),
                |id| format!("request ID {id}"),
            );
            format!("Bridge could not confirm the outcome — reconcile using bridge_status with {request} and do not resend.")
        }
        "relay_unavailable" | "core_unavailable" => "Bridge is unavailable — check the service before trying again.".into(),
        "invalid" | "oversize" => "Bridge rejected the input — check the arguments and the structured error detail.".into(),
        "forbidden" => "Bridge denied the request — check the caller’s permitted actions with bridge_me.".into(),
        class if class.starts_with("caller_") => "Bridge could not verify this call — check the harness’s Bridge setup.".into(),
        _ => "Bridge could not complete the request — check the structured error detail before taking further action.".into(),
    }
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

    /// Text snapshots describe custody and evidence separately and preserve the structured wire view.
    #[test]
    fn tool_result_summaries_preserve_structured_content() {
        let cases = [
            (
                "bridge_me",
                json!({"caller": {
                    "canonical": "host/codex/default/thread",
                    "observed_at_ms": 90_123_999, "endpoint_epoch": 9,
                }}),
                "Bridge verified your address as host/codex/default/thread at 1970-01-02T01:02:03Z.",
            ),
            (
                "bridge_send",
                json!({"request_id": "send-1", "custody": {
                    "state": "accepted", "accepted_at_ms": 90_123_999,
                    "envelope_hash": "fixture-hash", "replayed": false,
                }}),
                "Bridge accepted send-1 into custody at 1970-01-02T01:02:03Z — check bridge_status before taking any further action.",
            ),
            (
                "bridge_status",
                json!({
                    "custody": {"state": "accepted"}, "native": "in_flight"
                }),
                "Bridge has custody and the handoff is in progress — check again with bridge_status and do not resend.",
            ),
            (
                "bridge_status",
                json!({
                    "native": "native_accepted", "tiers": [
                        {"tier": "native_accepted", "at_ms": 90_123_999},
                        {"tier": "context_observed", "at_ms": 91_000_000}
                    ],
                }),
                "The recipient’s native queue accepted the message at 1970-01-02T01:02:03Z — wait for the recipient’s response.",
            ),
            (
                "bridge_status",
                json!({"custody": {"state": "not_found"}}),
                "Bridge found no custody record for this request — verify the request ID before taking further action.",
            ),
            (
                "bridge_status",
                json!({
                    "native": "not_handed",
                    "delivery": {"state": "unhanded", "hold_reason": "native owner session is closing or finished"}
                }),
                "Bridge has custody and is waiting to hand off the message (native owner session is closing or finished) — check again with bridge_status and do not resend.",
            ),
            (
                "bridge_status",
                json!({
                    "native": "not_handed",
                    "delivery": {"state": "unhanded", "hold_reason": "native owner socket unavailable: /private/path"}
                }),
                "Bridge has custody and is waiting to hand off the message — check again with bridge_status and do not resend.",
            ),
        ];
        for (tool, value, expected) in cases {
            let result = tool_result(
                tool,
                &RelayResponse::Ok {
                    value: value.clone(),
                },
                None,
            );
            assert_eq!(
                result["content"],
                json!([{"type": "text", "text": expected}])
            );
            assert_eq!(result["structuredContent"], value);
            assert_eq!(result["isError"], false);
        }
    }

    /// An uncertain result exposes reconciliation instructions without repeating raw details in text.
    #[test]
    fn tool_result_uncertainty_directs_reconciliation() {
        let result = tool_result(
            "bridge_send",
            &RelayResponse::error("custody_unknown", "internal fixture detail"),
            Some("send-1"),
        );
        assert_eq!(
            result["content"],
            json!([{"type": "text", "text":
                "Bridge could not confirm the outcome — reconcile using bridge_status with request ID send-1 and do not resend."
            }])
        );
        assert_eq!(
            result["structuredContent"],
            json!({
                "error": "custody_unknown", "detail": "internal fixture detail"
            })
        );
        assert_eq!(result["isError"], true);

        let read = tool_result(
            "bridge_me",
            &RelayResponse::error("relay_outcome_unknown", "internal fixture detail"),
            None,
        );
        assert_eq!(
            read["content"],
            json!([{"type": "text", "text":
                "Bridge did not confirm the result — check again with bridge_me."
            }])
        );
    }

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
            assert_eq!(
                tool["inputSchema"]["properties"][CALL_TOKEN_ARGUMENT]["type"],
                "string"
            );
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

    /// A hook token in the arguments is removed before anything else reads
    /// them and presented instead of `_meta` (a host `_meta` that is not a
    /// contract, like ZCode's request context, is ignored); the relay receives
    /// the arguments without it and a derived request id; a non-string token
    /// refuses before sealing.
    #[test]
    fn hook_token_is_presented_and_never_relayed() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("mt{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("r.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let relay = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            (&stream)
                .write_all(b"{\"result\":\"ok\",\"value\":{}}\n")
                .unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        });
        let presented = std::cell::RefCell::new(None);
        let sealer = |meta: &PresentedMeta, _: u64| {
            *presented.borrow_mut() = Some(meta.clone());
            Ok(SealedProof::from_wire("p"))
        };
        let answer = handle_line(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bridge_send","arguments":{"address":"a","message":"m","bridge_call_token":"t0"},"_meta":{"com.zcode/request-context":{"session_id":"s"}}}}"#,
            &sealer,
            &socket,
        )
        .unwrap();
        assert_eq!(answer["result"]["isError"], false, "{answer}");
        assert_eq!(
            presented.into_inner(),
            Some(PresentedMeta::HookToken {
                token: CallToken::from_wire("t0")
            })
        );
        let relayed = relay.join().unwrap();
        assert!(relayed["arguments"].get("bridge_call_token").is_none());
        assert_eq!(relayed["arguments"]["message"], "m");
        assert!(
            relayed["arguments"]["request_id"]
                .as_str()
                .unwrap()
                .starts_with("call-")
        );
        let _ = std::fs::remove_dir_all(&directory);

        let refused = run(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bridge_me","arguments":{"bridge_call_token":7}}}"#,
            &unreachable_sealer,
        );
        assert_eq!(refused["error"]["code"], -32602, "{refused}");
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
