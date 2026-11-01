//! Exact process/IPC tests of the native MCP context transport; synthetic data only.
mod common;
use common::{TempDir, fixture_exe, hook_exe};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Own one proxy child and always reap it, including a failed assertion.
struct Owned(Child);
impl Drop for Owned {
    /// Cleanup targets the actual Child handle, never a persisted numeric PID.
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
/// Exchange one bounded parent control message over the test-owned endpoint.
fn control(path: &std::path::Path, value: Value) -> Value {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(stream, "{value}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
/// The actual direct parent can correlate one native call; a sibling process cannot.
/// Session-only and reused contexts refuse before the persistent backend sees them.
#[test]
fn proxy_preserves_backend_and_verifies_native_parent() {
    let dir = TempDir::new("mc");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    bridge_adapters::server::private_directory(&dir.0).unwrap();
    let mut child = Owned(
        Command::new(hook_exe())
            .arg("mcp-proxy")
            .arg(&dir.0)
            .arg("pool")
            .arg(fixture_exe())
            .arg("mcp-meta-echo")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = bridge_adapters::native_mcp::socket_path(&dir.0, std::process::id(), "pool");
    let end = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < end, "context listener readiness");
        assert!(child.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(5));
    }
    let begin = json!({"op":"begin","server":"pool","context":{"session_id":"ses-native","call_id":"call-native","tool":"probe","arguments":{"value":7}}});
    let mut sibling = Command::new(fixture_exe())
        .arg("mcp-context")
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(sibling.stdin.take().unwrap(), "{begin}").unwrap();
    let refused = sibling.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&refused.stdout).contains("false"));
    let mut input = child.0.stdin.take().unwrap();
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe","arguments":{"value":7},"_meta":{"ai.opencode/sessionID":"ses-native"}}});
    writeln!(input, "{request}").unwrap();
    input.flush().unwrap();
    output.read_line(&mut line).unwrap();
    let missing: Value = serde_json::from_str(&line).unwrap();
    assert!(missing.get("error").is_some());
    assert_eq!(missing["error"]["data"]["effect"], "not_forwarded");
    line.clear();
    assert_eq!(control(&socket, begin.clone())["ok"], true);
    assert_eq!(control(&socket, begin)["ok"], false);
    writeln!(input, "{request}").unwrap();
    input.flush().unwrap();
    output.read_line(&mut line).unwrap();
    let accepted: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        accepted["result"]["params"]["_meta"]["ai.agent_bridge/toolCallID"],
        "call-native"
    );
    assert_eq!(
        accepted["result"]["params"]["arguments"],
        json!({"value":7})
    );
    // The registered frontend must remain the native harness direct child.
    let frontend = bridge_adapters::os::process_facts(child.0.id()).unwrap();
    assert_eq!(frontend.parent, Some(std::process::id()));
    assert_eq!(
        frontend.exe.unwrap().canonicalize().unwrap(),
        fixture_exe().canonicalize().unwrap()
    );
    line.clear();
    writeln!(input, "{request}").unwrap();
    input.flush().unwrap();
    output.read_line(&mut line).unwrap();
    let repeated: Value = serde_json::from_str(&line).unwrap();
    assert!(repeated.get("error").is_some());
    assert_eq!(repeated["error"]["data"]["effect"], "outcome_unknown");
    assert_eq!(
        control(
            &socket,
            json!({"op":"end","server":"pool","call_id":"other"})
        )["ok"],
        false
    );
    assert_eq!(
        control(
            &socket,
            json!({"op":"end","server":"pool","call_id":"call-native"})
        )["ok"],
        true
    );
    drop(input);
    let end = Instant::now() + Duration::from_secs(8);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < end, "owned backend/transport EOF");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!socket.exists());
}
