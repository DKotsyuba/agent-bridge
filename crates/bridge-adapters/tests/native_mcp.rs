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

/// Exclusively creates a private context directory with a six-hex basename so
/// the production native endpoint fits the Unix socket limit under task TMPDIR.
/// Collisions retry without reusing or changing the existing path.
fn context_dir() -> TempDir {
    use std::os::unix::fs::DirBuilderExt;

    for _ in 0..16 {
        let nonce: String = bridge_adapters::os::random_bytes().unwrap()[..3]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = std::env::temp_dir().join(nonce);
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return TempDir(path.canonicalize().unwrap()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("cannot create context fixture directory: {error}"),
        }
    }
    panic!("no exclusive context fixture directory after 16 attempts");
}

/// Linux rejects redirected/count-mismatched inherited descriptors, non-sockets
/// and sockets owned by a peer other than the exact Node parent before readiness.
#[cfg(target_os = "linux")]
#[test]
fn frontend_rejects_invalid_inherited_descriptor_and_foreign_peer() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    let node = std::env::var_os("BRIDGE_TEST_NODE").expect("BRIDGE_TEST_NODE required");
    let dir = context_dir();
    let channel = dir.0.join("c.sock");
    let peer_path = dir.0.join("p.sock");
    let _foreign_peer = UnixListener::bind(&peer_path).unwrap();
    let script = r#"
const {spawn}=require('node:child_process');
const net=require('node:net');
const [executable,channel,mode,peerPath]=process.argv.slice(1);
function run(descriptor) {
  const closeDescriptor=()=>{if(typeof descriptor==='number')require('node:fs').closeSync(descriptor);else if(typeof descriptor!=='string')descriptor.destroy();};
  const env={...process.env,BRIDGE_DESKTOP_PARENT_PID:String(process.pid),LISTEN_FDS:'1'};
  delete env.LISTEN_PID;delete env.LISTEN_FDS_FIRST_FD;delete env.LISTEN_FDNAMES;
  delete env.CODEX_APP_TOOLS_PIPE_PATH;delete env.CODEX_MCP_NODE_PATH;
  if(mode==='count')env.LISTEN_FDS='2';
  if(mode==='redirect')env.LISTEN_FDS_FIRST_FD='0';
  const child=spawn(executable,['desktop-child',channel],{env,stdio:['ignore','pipe','pipe',descriptor]});
  let stdout='',stderr='';
  child.stdout.on('data',bytes=>{stdout=(stdout+bytes).slice(0,2048);});
  child.stderr.on('data',bytes=>{stderr=(stderr+bytes).slice(0,2048);});
  const timer=setTimeout(()=>child.kill('SIGKILL'),2000);
  child.on('error',()=>{clearTimeout(timer);closeDescriptor();process.exit(2);});
  child.on('close',(code,signal)=>{
    clearTimeout(timer);closeDescriptor();
    process.stdout.write(JSON.stringify({code,signal,stdout,stderr})+'\n');
  });
}
if(mode==='foreign') {
  const peer=net.createConnection(peerPath);
  peer.once('connect',()=>run(peer));
  peer.on('error',()=>process.exit(3));
} else run(mode==='type'?require('node:fs').openSync('/dev/null','r'):'pipe');
"#;
    for mode in ["count", "redirect", "type", "foreign"] {
        let mut parent = Owned(
            Command::new(&node)
                .arg("-e")
                .arg(script)
                .arg("--")
                .arg(fixture_exe())
                .arg(&channel)
                .arg(mode)
                .arg(&peer_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = parent.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "{mode}: Node parent did not exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "{mode}: Node parent failed ({status})");
        let mut output = String::new();
        parent
            .0
            .stdout
            .take()
            .unwrap()
            .take(8192)
            .read_to_string(&mut output)
            .unwrap();
        let result: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(result["code"], 101, "{mode}: {result}");
        assert_eq!(result["signal"], Value::Null, "{mode}: {result}");
        assert_eq!(
            result["stdout"], "",
            "{mode}: a rejected frontend became ready"
        );
        let reason = if mode == "type" {
            "not a socket"
        } else {
            "PermissionDenied"
        };
        assert!(
            result["stderr"].as_str().unwrap().contains(reason),
            "{mode}: rejection did not come from the expected guard: {result}"
        );
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
    let dir = context_dir();
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
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let socket = bridge_adapters::native_mcp::socket_path(&dir.0, std::process::id(), "pool");
    let end = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < end, "context listener readiness");
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("native context proxy exited before readiness ({status}); see inherited stderr");
        }
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
