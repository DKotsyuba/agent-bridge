//! Harness hook command: forwards one native hook event to the Bridge
//! adapter channel and prints Bridge context only when handed one.
//!
//! Usage (as the hook command of every relevant event):
//! `bridge-hook <channel-socket> <harness>` (`claude-code`, `codex`, `opencode` or
//! a profile-only harness identifier) with the native hook JSON on stdin. Hook mode
//! always exits 0. Before any reply is written, Claude Code and Codex failures
//! can surface a warning through the host’s JSON output contract. All failures
//! also report to stderr.
//! `bridge-hook mcp-proxy <private-directory> <server> <absolute-backend> [args]`
//! instead runs the protected persistent MCP transport and exits nonzero on failure.

use std::io::{Read, Write};
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
        hook_notice("expected a channel socket and harness argument");
        return ExitCode::SUCCESS;
    };
    let Ok(harness) = Harness::parse(&harness) else {
        hook_notice("unknown harness");
        return ExitCode::SUCCESS;
    };
    let mut stdout = HookOutput {
        writer: std::io::stdout().lock(),
        attempted: false,
    };
    let mut input = Vec::new();
    if std::io::stdin()
        .take(MAX_HOOK_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .is_err()
    {
        hook_notice("could not read the hook input");
        stdout.warning(harness, "could not read the hook input");
        return ExitCode::SUCCESS;
    }
    let client = ChannelClient::new(socket, Duration::from_secs(5));
    match client.run_hook(harness, &input, &mut stdout) {
        HookRun::Admitted | HookRun::Injected | HookRun::Tokened => {}
        HookRun::Refused(class, _) => {
            let class = match class.as_str() {
                class @ ("caller_unattested" | "missing" | "duplicate" | "stale"
                | "conflicting" | "not_evidence" | "unavailable") => class,
                _ => "unknown",
            };
            let _ = writeln!(std::io::stderr().lock(), "bridge-hook: refused ({class})");
            stdout.warning(harness, "Bridge refused the hook event");
        }
        HookRun::Failed(_) => {
            let message = "could not complete the Bridge hook event";
            hook_notice(message);
            stdout.warning(harness, message);
        }
    }
    ExitCode::SUCCESS
}

/// Writes a best-effort diagnostic from static text without changing the exit status.
fn hook_notice(message: &'static str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "bridge-hook: {message} — the host can continue."
    );
}

/// Tracks attempted stdout writes so a failed or uncertain reply never gets a second frame.
struct HookOutput<W> {
    /// Native hook stdout.
    writer: W,
    /// Set before attempting to write any reply bytes.
    attempted: bool,
}

impl<W: Write> HookOutput<W> {
    /// Emits a host warning if stdout is still unused.
    fn warning(&mut self, harness: Harness, message: &'static str) {
        if !self.attempted && matches!(harness, Harness::CLAUDE_CODE | Harness::CODEX) {
            let output = serde_json::json!({
                "systemMessage": format!("bridge-hook: {message} — the host can continue.")
            });
            let _ = writeln!(self, "{output}").and_then(|()| self.flush());
        }
    }
}

impl<W: Write> Write for HookOutput<W> {
    /// Marks stdout as potentially written even when the underlying write fails.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.attempted = true;
        self.writer.write(bytes)
    }

    /// Flushes the native hook output before the client acknowledges it.
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
