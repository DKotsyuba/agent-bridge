//! Harness hook command: forwards one native hook event to the Bridge
//! adapter channel and prints Bridge context only when handed one.
//!
//! Usage (as the hook command of every relevant event):
//! `bridge-hook <channel-socket> <harness>` (`claude-code`, `codex`, `opencode` or
//! a profile-only harness identifier) with the native hook JSON on stdin. Hook mode always exits 0 and prints nothing unless the
//! channel handed a context reply, so a missing or failing Bridge never
//! blocks or breaks the harness; Bridge keeps undelivered events.
//! `bridge-hook mcp-proxy <private-directory> <server> <absolute-backend> [args]`
//! instead runs the protected persistent MCP transport and exits nonzero on failure.

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use bridge_adapters::client::{ChannelClient, HookRun, MAX_HOOK_INPUT_BYTES};
use bridge_core::Harness;

/// Dispatches the protected MCP transport or the bounded fail-open lifecycle hook.
fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    if matches!(
        args.peek().map(String::as_str),
        Some("mcp-proxy" | "mcp-proxy-sidecar")
    ) {
        let sidecar = args.next().as_deref() == Some("mcp-proxy-sidecar");
        let arguments: Vec<_> = args.collect();
        let result = if sidecar {
            bridge_adapters::native_mcp::run_sidecar(&arguments)
        } else {
            bridge_adapters::native_mcp::run(&arguments)
        };
        return if result.is_ok() {
            ExitCode::SUCCESS
        } else {
            if !sidecar {
                eprintln!("bridge-hook: native MCP transport refused");
            }
            ExitCode::FAILURE
        };
    }
    let (Some(socket), Some(harness)) = (args.next(), args.next()) else {
        eprintln!("usage: bridge-hook <channel-socket> <harness>");
        return ExitCode::SUCCESS;
    };
    let Ok(harness) = Harness::parse(&harness) else {
        eprintln!("bridge-hook: unknown harness");
        return ExitCode::SUCCESS;
    };
    let mut input = Vec::new();
    if std::io::stdin()
        .take(MAX_HOOK_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .is_err()
    {
        return ExitCode::SUCCESS;
    }
    let client = ChannelClient::new(socket, Duration::from_secs(5));
    let mut stdout = std::io::stdout().lock();
    match client.run_hook(harness, &input, &mut stdout) {
        HookRun::Admitted | HookRun::Injected | HookRun::Tokened => {}
        HookRun::Refused(class, _) => eprintln!("bridge-hook: refused ({class})"),
        HookRun::Failed(reason) => eprintln!("bridge-hook: {reason}"),
    }
    ExitCode::SUCCESS
}
