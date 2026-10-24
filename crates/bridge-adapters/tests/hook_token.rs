//! Hook-token caller proof over real processes: the real channel, the real
//! `bridge-hook` and the registry, with a profile-only stand-in harness.

mod common;

use bridge_core::Harness;
use common::*;
use serde_json::{Value, json};

/// A `PreToolUse` payload of `tool` with its own input.
fn pre_tool_use(session: &str, call: &str, tool: &str) -> Value {
    json!({
        "hook_event_name": "PreToolUse", "session_id": session,
        "tool_use_id": call, "tool_name": tool,
        "tool_input": {"address": "x", "message": "hello"}
    })
}

/// The token a hook reply carries in `updatedInput`, with the reply's input.
fn issued(reply: &Value) -> Option<(String, Value)> {
    let stdout = reply["stdout"].as_str()?.trim();
    let output: Value = serde_json::from_str(stdout).ok()?;
    assert_eq!(output["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let input = output["hookSpecificOutput"]["updatedInput"].clone();
    Some((input["bridge_call_token"].as_str()?.to_string(), input))
}

/// A profile-only harness gets a single-use token only at the `PreToolUse` of
/// a Bridge root tool; the original input is preserved; a descendant frontend
/// attests the root caller once with it; a replay is a duplicate and an
/// unissued token joins nothing; another MCP tool gets no token.
#[test]
fn hook_token_attests_a_profile_only_caller_once() {
    let lab = Lab::new("ht1");
    let mut harness = Harnessed::start(GENERIC, &lab.generic_store);
    let started = harness.hook(&lab.socket, GENERIC, hook("SessionStart", "zs-1"));
    assert_eq!(started["status"], 0, "{started}");

    let other = harness.hook(
        &lab.socket,
        GENERIC,
        pre_tool_use("zs-1", "call-0", "mcp__agent-ide__prepare"),
    );
    assert_eq!(other["stdout"], "", "no token for another server: {other}");

    let reply = harness.hook(
        &lab.socket,
        GENERIC,
        pre_tool_use("zs-1", "call-1", "mcp__agent-bridge-root__bridge_me"),
    );
    let (token, input) = issued(&reply).expect("a token reply");
    assert_eq!(token.len(), 64);
    assert_eq!(input["address"], "x");
    assert_eq!(input["message"], "hello");

    assert_eq!(
        harness.mcp(&lab.socket, json!({"bridge_call_token": "0".repeat(64)}))["err"],
        "missing"
    );
    let accepted = harness.mcp(&lab.socket, json!({"bridge_call_token": token}));
    assert_eq!(accepted["ok"]["role"], "root", "{accepted}");
    assert_eq!(accepted["ok"]["native_id"], "zs-1");
    assert_eq!(
        accepted["ok"]["address"],
        lab.generic_address("zs-1").to_canonical_string()
    );
    assert_eq!(accepted["ok"]["may_act_as_address"], true);
    assert_eq!(
        harness.mcp(&lab.socket, json!({"bridge_call_token": token}))["err"],
        "duplicate"
    );
    harness.stop();
}

/// A built-in harness keeps its `_meta` proof by default: no token is issued
/// for its Bridge root tool calls, so its hooks print nothing new.
#[test]
fn built_in_harness_gets_no_token_by_default() {
    let lab = Lab::new("ht2");
    let mut harness = Harnessed::start(Harness::CLAUDE_CODE, &lab.claude_store);
    harness.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        hook("SessionStart", "cs-1"),
    );
    let reply = harness.hook(
        &lab.socket,
        Harness::CLAUDE_CODE,
        pre_tool_use("cs-1", "call-1", "mcp__agent-bridge-root__bridge_me"),
    );
    assert_eq!(reply["stdout"], "", "{reply}");
    harness.stop();
}
