# bridge-adapters

Native Codex / Claude Code adapters for Agent Bridge: the protected caller
registry, quiet root hooks and qualified message carriers. They consume core's
single custody and attempt state (`DispatchCarrier`, `observe_binding`,
`drain_inject`, `record_outcome`); there is no second attempt or hook store.

Status: implemented and tested against owned fixture processes. Real loaded
Codex / Claude qualification is **not** established (see the end).

## Components

| Piece | Role |
|---|---|
| `bridge-native-daemon` | core service + Codex and Claude carriers + adapter channel |
| `bridge-hook` | the harness hook command; forwards one hook event, prints Bridge context only when handed one, always exits 0 |
| `registry` | harness incarnations, endpoint epochs, owner lifecycle, single-use call records, root-caller ABI |
| `server` / `client` | the private adapter channel and its clients (`RegistryAttestor`) |
| `codex` | `message` via one `thread/queue/add` in an OS-confined queue-only App Server helper |
| `claude` | `message` via the authenticated native peer send with `priority = "later"` |

## Trust model

- **Channel peer.** Every channel connection is identified by kernel peer
  credentials (PID, UID). A peer is a *hook of a harness* only if it runs as
  the daemon's user and its nearest ancestor that is not an allowlisted shell
  (`intermediates`) is a configured harness executable whose resolved path and
  SHA-256 match a profile, whose file was not modified after that process
  started (loaded build = disk build), and whose own store (`CODEX_HOME` /
  `CLAUDE_CONFIG_DIR`, else `$HOME/.codex` / `$HOME/.claude`, read from that
  process's own environment) is that profile's store. PID, UID, cwd, argv or
  a process name alone never qualify.
- **Binding and epoch.** The harness process incarnation (PID + start time)
  owns its session addresses. The first hook, a `SessionStart`, or a new
  incarnation (after the old one died) renews the binding with a strictly
  larger epoch; older records become stale. A second *live* incarnation
  claiming a bound address is refused as conflicting.
- **Lifecycle.** From the owner session's own hooks: prompt/tool events are
  active; `Stop` or an idle-prompt notification is inactive; permission
  requests, permission notifications and `AskUserQuestion` await input;
  `SessionEnd`, a dead incarnation, or no binding (e.g. after a daemon
  restart) is unknown. Unknown is never inactive. Bridge never answers a
  permission request.
- **Root caller.** `PreToolUse` records the per-call id with the actual actor
  (`agent_id` or the session's root). A caller is attested by joining the MCP
  request's `_meta` call id to exactly one fresh, unconsumed record of the
  current epoch from the same harness incarnation; the join consumes it
  (replay = duplicate). `VerifiedCaller` scope is (address, role, native id):
  Claude subagents share the address but never `may_act_as_address`; a Codex
  child thread has its own address.
- **Relay.** A process that is not a harness descendant (the restricted MCP's
  root daemon) gets caller facts only by redeeming a sealed proof issued to
  its harness-launched frontend (`RegistryAttestor::attest_sealed`) — once,
  within 30 s, from a configured relay build, while the binding is unchanged.
- **Boundary.** Same-user code running inside a harness's own tool sandbox
  (e.g. a model shell command) shares the harness's ancestry and can replay
  the hook client with forged native JSON; deny the channel directory to the
  harness tool sandbox. Hostile same-user code is outside the claimed
  isolation.

## Delivery paths

- **inject**: at a root (`PostToolUse` / `UserPromptSubmit`) hook of the
  addressed actor with qualified inject, the channel calls `drain_inject`
  (manifest frozen and `invoking` committed first), replies with the exact
  hook stdout line, and records `hook_submitted` only after the hook confirms
  the flushed digest. Anything else after the reply is `outcome_unknown`
  (retained incident, never re-offered). A child never drains root data.
- **Codex message**: `sandbox-exec -p '(version 1)(allow default)(deny
  network*)(deny process-fork)' <qualified codex> app-server --listen
  stdio://` with a scrubbed environment and `CODEX_HOME` = the attested store;
  only `initialize`, `initialized` and `thread/queue/add` are sent. One total
  budget bounds the exchange: a watchdog kills the helper at the deadline
  (unblocking a stalled write), notifications never extend it, and the helper
  is always killed and reaped. Failure
  before the add is written is known-unsent; a native error is a positive
  refusal; silence after the write is unknown. Queue acceptance is storage,
  not delivery; `clientUserMessageId` never deduplicates. Without the launcher
  the Codex message capability is never granted (publication refuses before
  acceptance).
- **Claude message**: the descriptor in `<store>/sessions` must name the
  session *and* the attested harness PID, and the inbox socket's kernel peer
  must be that PID before the session's own peer token is sent. Only
  `priority = "later"` is sent; peer inject is prohibited. Receipts go to a
  stable daemon callback in the inbox directory. A receipt counts only when
  it names the attempt's unguessable message id *and* its sender's kernel
  identity, read first thing after accept, is the attested recipient PID as
  this user; a sender that already closed (its PID is no longer readable) is
  ignored and logged `claude_receipt_unverifiable` — fail closed, the
  attempt stays held/unreceipted until core's overdue incident. `held` is non-terminal, `delivered` is acceptance, a refusal
  before any hold is known-unsent, any negative after a hold is unknown, and
  silence is `written_no_receipt`, closed positively only when the session's
  own transcript holds the exact manifest as a user message. A daemon restart
  forgets callbacks; core's recheck deadlines then raise incidents, never
  replays (a stopped carrier removes its own callback sockets). Manifests
  over 4096 bytes are refused before any write.

## Configuration

`bridge-native-daemon <config.toml>` takes the core configuration plus:

```toml
[adapters]
channel = "/abs/private-0700-dir/channel.sock"
sandbox = "/usr/bin/sandbox-exec"          # default
host_id = "this-host"
# intermediates = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/usr/bin/env"]
# max_call_age_ms = 600000

[[adapters.profiles]]
namespace = "claude-main"                   # native_store_namespace of addresses
harness = "ClaudeCode"                      # or "Codex"
store = "/Users/me/.claude"
[[adapters.profiles.executables]]
path = "/abs/resolved/claude/binary"
sha256 = "<64 hex of the qualified build>"
version = "2.1.294"
inject = true
message = true

[[adapters.relays]]                          # optional: root MCP daemon build
path = "/abs/root-mcp-daemon"
sha256 = "<64 hex>"
```

Install `bridge-hook <channel> claude-code` (or `codex`) as the command of the
`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
`PermissionRequest`, `Notification`, `Stop`, `SubagentStop` and `SessionEnd`
hooks. Installation into working applications is a separate, explicitly
authorized step; nothing here installs anything.

## Tests

```sh
TMPDIR=<short owned dir> cargo +1.98.1 test --offline -p bridge-adapters
BRIDGE_QUALIFY_CODEX_EXE=<codex> cargo +1.98.1 test --offline -p bridge-adapters --test qualify_codex -- --ignored
```

`tests/native.rs` runs the real channel, the real `bridge-hook` and core
custody with `bridge-fixture` processes as harnesses, Claude inboxes and a
Codex App Server (inside the real confinement, with a positive control).
`tests/qualify_codex.rs` is the gated real-Codex queue-only qualification.

## Root-run native qualification probes

Each probe needs explicit root provisioning; none runs in `cargo test`.
Build first: `cargo +1.98.1 build --offline -p bridge-adapters --bins`.

| Probe | Model | Command | Passing evidence |
|---|---|---|---|
| Codex queue helper | no | `BRIDGE_QUALIFY_CODEX_EXE=<codex> cargo +1.98.1 test --offline -p bridge-adapters --test qualify_codex -- --ignored --nocapture` | `NativeAccepted` for an unloaded owned thread, queue/list shows the item and text, missing thread `KnownUnsent` |
| Claude hooks, caller, inject, `later`, pause | yes (haiku, 0.5 USD cap) | `node qualification/claude-native-probe.cjs` | `checks.json`: root/child attested from real `toolUseId`, the hook-injected marker quoted by the model, a message marker answered in a distinct unprompted turn, no turn while paused and one after resume; `daemon_events` shows whether real receipts were verifiable |
| Codex hooks, caller (callId = tool_use_id), inject, child thread | yes | `node qualification/codex-native-probe.cjs` | `checks.json`: root join succeeded (proves the callId/tool_use_id equality for that build), marker in the reply, child attested on its own thread address |

All probes use fresh owned Bridge state, a new session/thread, a daemon grant
naming only it, the probe MCP server (`bridge-fixture mcp-server`, which
attests from `_meta` only and never returns the marker in the tool result),
and terminate their children. They show what the named build did once; they
are not release qualification.

## Not yet established

- No real Claude Code or Codex session has run these hooks or carriers:
  hook installation, timeouts, output visibility (Codex `additionalContext`
  in particular) and coexistence with other hooks are unqualified.
- Codex caller join assumes `_meta.callId` equals the same call's
  `PreToolUse` `tool_use_id`; the `_meta` keys themselves (`threadId`,
  `callId`, `x-codex-turn-metadata`) were captured from Codex
  0.162.0-alpha.17.2, the equality was not.
- The real Claude inbox's receipt behaviour for `later` (held/release/drop
  timing, and whether it stays connected long enough for its PID to be read)
  is not re-qualified. If it closes first, every receipt is ignored by
  design and those hand-offs rely on transcript closure or the overdue
  incident; that would make held-release unsupported, never silently
  accepted.
- The Codex helper has not been run against the real App Server here (see
  the gated test); Linux has no confinement launcher, so Codex message is
  unsupported there.
