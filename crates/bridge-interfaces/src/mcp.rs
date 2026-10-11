//! stdio MCP server wrapper for the restricted root tool set.
//!
//! Exposes `bridge.me`, `bridge.send` and `bridge.status` as MCP tools over
//! JSON-RPC 2.0 on stdin/stdout, reusing the root ingress request logic
//! in-process. The MCP server never serves more tools and never accepts an
//! identity from tool arguments: the root token comes from the server
//! process's protected environment (`BRIDGE_ROOT_TOKEN`), and tool
//! arguments go through the same closed-key validation as the socket
//! surface.
//!
//! Protocol surface: `initialize`, `tools/list`, `tools/call`; requests
//! with any other method are refused with `-32601`, and notifications
//! (messages without an `id`) are ignored. One JSON message per line.

use std::io::{BufRead, Write};

use crate::root::{
    self, RootConfig, RootResponse, SendArgs, serve_in_process,
};

/// Environment variable holding the root grant token for this MCP server.
pub const ROOT_TOKEN_ENV: &str = "BRIDGE_ROOT_TOKEN";

/// MCP protocol version advertised by this server.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server name advertised in `initialize` results.
pub const SERVER_NAME: &str = "agent-bridge-root";

/// Runs the stdio MCP server loop over the given reader/writer pair.
///
/// Reads one JSON message per line until EOF. Every response is written as
/// a single line and flushed. Returns the number of requests answered;
/// write failures end the loop. The token is resolved once from the
/// environment; a missing token makes every tool call answer with an
/// `auth` refusal instead of guessing an identity.
pub fn run_stdio(
    config: &RootConfig,
    token: Option<&str>,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> u64 {
    let mut answered = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => return answered,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let message: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(message) => message,
            Err(error) => {
                let _ = write_line(
                    output,
                    &jsonrpc_error(
                        serde_json::Value::Null,
                        -32700,
                        &format!("parse error: {error}"),
                    ),
                );
                answered += 1;
                continue;
            }
        };
        // Notifications carry no id and never get a response.
        let id = message.get("id").cloned();
        let Some(id) = id else {
            continue;
        };
        let method = message
            .get("method")
            .and_then(|method| method.as_str())
            .unwrap_or("");
        let result = match method {
            "initialize" => Ok(serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
            })),
            "tools/list" => Ok(serde_json::json!({"tools": tools()})),
            "tools/call" => {
                let name = message
                    .pointer("/params/name")
                    .and_then(|name| name.as_str())
                    .unwrap_or("");
                let arguments = message
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(serde_json::Value::Object(Default::default()));
                match call_tool(config, token, name, &arguments) {
                    Ok(text) => Ok(serde_json::json!({
                        "content": [{"type": "text", "text": text}]
                    })),
                    Err(detail) => Ok(serde_json::json!({
                        "content": [{"type": "text", "text": detail}],
                        "isError": true,
                    })),
                }
            }
            other => Err(jsonrpc_error(
                id.clone(),
                -32601,
                &format!("method not found: {other}"),
            )),
        };
        let response = match result {
            Ok(value) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": value}),
            Err(error) => error,
        };
        if write_line(output, &response).is_err() {
            return answered;
        }
        answered += 1;
    }
}

/// The closed tool list served by this MCP server.
fn tools() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "bridge.me",
            "description": "The caller's attested native address and its permitted delivery capabilities.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        },
        {
            "name": "bridge.send",
            "description": "Publish one bounded keep_all notification to an explicitly authorized exact recipient.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string"},
                    "recipient": {"type": "string"},
                    "kind": {"type": "string"},
                    "mode": {"type": "string", "enum": ["inject", "message", "auto"]},
                    "body": {"type": "string"}
                },
                "required": ["request_id", "recipient", "kind", "mode", "body"],
                "additionalProperties": false,
            },
        },
        {
            "name": "bridge.status",
            "description": "Only this caller's own publication and delivery evidence.",
            "inputSchema": {
                "type": "object",
                "properties": {"request_id": {"type": "string"}},
                "required": ["request_id"],
                "additionalProperties": false,
            },
        },
    ])
}

/// Calls one tool with closed-key-validated arguments.
///
/// `Ok` carries the JSON text of the root response for the tool result;
/// `Err` carries a tool-level error string (unknown tool, malformed
/// arguments, missing token environment). Tool arguments never include a
/// token or any identity field.
fn call_tool(
    config: &RootConfig,
    token: Option<&str>,
    name: &str,
    arguments: &serde_json::Value,
) -> Result<String, String> {
    let Some(token) = token else {
        return Err(format!("{ROOT_TOKEN_ENV} is not set; refusing to guess a caller"));
    };
    let response = match name {
        "bridge.me" => {
            closed_keys(arguments, &[])?;
            serve_in_process(config, root_request_me(token))
        }
        "bridge.send" => {
            closed_keys(
                arguments,
                &["request_id", "recipient", "kind", "mode", "body"],
            )?;
            let args = SendArgs {
                request_id: string_argument(arguments, "request_id")?,
                recipient: string_argument(arguments, "recipient")?,
                kind: string_argument(arguments, "kind")?,
                mode: string_argument(arguments, "mode")?,
                body: string_argument(arguments, "body")?,
            };
            serve_in_process(config, root_request_send(token, args))
        }
        "bridge.status" => {
            closed_keys(arguments, &["request_id"])?;
            let request_id = string_argument(arguments, "request_id")?;
            serve_in_process(config, root_request_status(token, request_id))
        }
        other => return Err(format!("unknown tool {other:?}")),
    };
    let response = response.unwrap_or_else(|response| response);
    Ok(serde_json::to_string(&response).unwrap_or_else(|error| {
        serde_json::to_string(&RootResponse::Error {
            class: "internal".into(),
            detail: format!("serialize response: {error}"),
        })
        .unwrap_or_default()
    }))
}

/// Builds the in-process `me` request.
fn root_request_me(token: &str) -> crate::root::RootRequest {
    crate::root::RootRequest::Me {
        token: token.to_string(),
    }
}

/// Builds the in-process `send` request.
fn root_request_send(token: &str, args: SendArgs) -> crate::root::RootRequest {
    crate::root::RootRequest::Send {
        token: token.to_string(),
        args,
    }
}

/// Builds the in-process `status` request.
fn root_request_status(token: &str, request_id: String) -> crate::root::RootRequest {
    crate::root::RootRequest::Status {
        token: token.to_string(),
        request_id,
    }
}

/// Enforces the closed argument key set for one tool call.
///
/// Exactly the given fields may appear; anything else (including token or
/// identity fields) is a tool error before any request is built.
fn closed_keys(
    arguments: &serde_json::Value,
    fields: &[&str],
) -> Result<(), String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "tool arguments must be a JSON object".to_string())?;
    let unexpected: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !fields.contains(key))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!("closed schema: unknown argument keys {unexpected:?}"));
    }
    let missing: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return Err(format!("closed schema: missing argument keys {missing:?}"));
    }
    Ok(())
}

/// Reads one required string tool argument.
fn string_argument(
    arguments: &serde_json::Value,
    field: &str,
) -> Result<String, String> {
    arguments
        .get(field)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("argument {field:?} must be a string"))
}

/// Builds a JSON-RPC error response value.
fn jsonrpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

/// Writes one JSON message followed by a newline and flushes.
fn write_line(output: &mut dyn Write, value: &serde_json::Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    line.push(b'\n');
    output.write_all(&line)?;
    output.flush()
}
