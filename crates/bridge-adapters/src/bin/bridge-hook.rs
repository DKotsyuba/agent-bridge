//! Harness hook command: forwards one native hook event to the Bridge
//! adapter channel and prints Bridge context only when handed one.
//!
//! Usage (as the hook command of every relevant event):
//! `bridge-hook <channel-socket> <claude-code|codex>` with the native hook
//! JSON on stdin. The command always exits 0 and prints nothing unless the
//! channel handed a context reply, so a missing or failing Bridge never
//! blocks or breaks the harness; Bridge keeps undelivered events.

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use bridge_adapters::client::{ChannelClient, HookRun, MAX_HOOK_INPUT_BYTES};
use bridge_core::Harness;

/// Reads the bounded hook input and runs it through the channel.
fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(socket), Some(harness)) = (args.next(), args.next()) else {
        eprintln!("usage: bridge-hook <channel-socket> <claude-code|codex>");
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
        HookRun::Admitted | HookRun::Injected => {}
        HookRun::Refused(class, _) => eprintln!("bridge-hook: refused ({class})"),
        HookRun::Failed(reason) => eprintln!("bridge-hook: {reason}"),
    }
    ExitCode::SUCCESS
}
