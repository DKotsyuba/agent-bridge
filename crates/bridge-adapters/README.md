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
  before the add is written is known-unsent. After the write, only a success
  whose `queuedSubmission` echoes the same `clientUserMessageId` is
  acceptance; every native error (including validation-like and generic
  internal errors, which can follow a queue effect), a malformed success and
  silence are unknown. No error of the loaded build is qualified as proof of
  no queue effect. Queue acceptance is storage,
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
  silence is `written_no_receipt`. That hand-off is reconciled against the
  addressed session's own native transcript (shapes observed on 2.1.296): an
  `enqueue` of the exact manifest records `native_accepted`, a peer-origin user
  entry naming this hand-off's callback and containing the exact manifest
  records `context_observed`; no message id is assumed and absence never
  retries. A session descriptor without an inbox (restricted session) is
  positive disablement: the message capability is withdrawn and recorded in
  core, so later message publications refuse before acceptance; a missing
  descriptor is only a transient hold. A daemon restart
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
| Q1 Codex helper classification | no | `BRIDGE_QUALIFY_CODEX_EXE=<codex> cargo +1.98.1 test --offline -p bridge-adapters --test qualify_codex -- --ignored --nocapture` | conservative classification only: native errors after the write (model-less unpersisted thread, missing thread) are never known-unsent; any acceptance has a native readback. Not positive queue qualification |
| Q2 Claude hooks, caller, inject, `later`, pause | haiku, low, 0.5 USD cap | `node qualification/claude-native-probe.cjs` | `checks.json` with no failures: closed native tool inventory and manual/default permissions, root/child attested from the real `toolUseId`, the hook-injected marker quoted while the planted project-memory canary is absent, the background child's native completion (and any follow-up turn) before the idle steps, a message answered in a distinct unprompted turn with actor-bound transcript evidence (`context_observed` or `native_accepted`), pause applied with the paused event held (no attempt, no-wake hold reason) and no turn start or result in the paused window while the receiver was alive with budget, then a distinct turn after resume |
| Q3 Codex gate only | no | `CODEX_PROBE_GATE_ONLY=1 node qualification/codex-native-probe.cjs` | `hooks_isolated` and `approval_config_effective` true (ends with `gate_only_run` by design) |
| Q3 Codex hooks, caller, inject, child, queue | gpt-6-luna, low | `node qualification/codex-native-probe.cjs` | `checks.json` with no failures: model in the build catalog, hooks isolated, exact-tool approval effective, the read-only `bridge_me` root join succeeded (shows callId = tool_use_id for that build), the externally published marker in the reply, the unapproved `bridge_unlisted` refused by the host and never executed, child attested on its own thread, the helper's correlated `native_accepted` with native readback on the persisted thread, and the probe's own queue item removed and verified gone |

Shared lifecycle (`qualification/probe-lib.cjs`): one absolute total budget
(a local command is refused once it is spent); a lifecycle fence refuses any
new process once cleanup starts, except a registered cleanup action's own
marked process; every child in its own process
group, its stderr descriptor closed in the parent; cleanup runs registered
cleanup actions (own fixed allowance), then SIGTERM, bounded grace, SIGKILL,
and waits for each child to exit *and* its stdout to end before ending its
log (`unreaped:` / `unclosed:` failures otherwise); an orphan sweep by
private-directory/session markers; synthetic grant tokens only in 0600 files
(never argv), redacted from any evidence file and from the written result,
which records `secret_in_*` failures. A required check that is missing or
not exactly `true` is a failure. `node qualification/probe-lib.cjs
--self-test` exercises all of this without any model and passes only on its
exact expected failure set.

Isolation: Q2 uses `--setting-sources ''`, only the Agent tool (native `Task`)
plus the fixture MCP tool checked against the native inventory, an explicit
private `--messaging-socket-path` (not `--restricted`: the 2.1.296 bundle
ignores the messaging socket in a restricted session), `--no-chrome`,
`--permission-prompts none`, `--strict-mcp-config`, its own settings/agent,
and the installed build's memory switches (`CLAUDE_CODE_DISABLE_CLAUDE_MDS`,
`CLAUDE_CODE_DISABLE_AUTO_MEMORY`, `CLAUDE_CODE_DISABLE_ORG_MEMORY`), checked
by the canary; `--bare` is not used because it disables OAuth. Q3 runs its
isolation gate before the first model call: a confined App Server lists the
hooks Codex would load, every foreign enabled hook is disabled and the
probe's own hooks are trusted by their listed hash, all in one per-launch
whole-map override `-c hooks.state={"<key>"={...},...}` (hook keys contain
dots, so per-leaf dotted `-c` paths are split and ignored by 0.162.0-alpha.17.2,
as the root's gate run on the previous candidate showed). A second listing
must confirm it and the build must report no ignored setting; otherwise the
probe stops with `isolation_unavailable`. No trust bypass, no coexistence
override, nothing persisted. Gate-only runs on this candidate (no model,
no network, no child processes) showed all 7 user hooks disabled and the 5
probe hooks enabled and trusted, with `~/.codex` files unmodified; the
model phases themselves have not run. All probes use fresh owned Bridge state, a new
session/thread, a daemon grant naming only it, and the probe MCP server
(`bridge-fixture mcp-server`, which attests from `_meta` only and never
returns the marker in the tool result). The probes show what the named build
did once; they are not release qualification.

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
- Codex queue acceptance on a real build is not established. The root's Q1
  run on Codex 0.162.0-alpha.17.2 (source 0210a732) got native -32603 "no
  rollout found" for a model-less owned thread: a thread needs a persisted
  rollout, so positive acceptance is checked in Q3 phase 3. That error is
  a plausible pre-effect failure but is not qualified as no-acceptance, so
  it is classified unknown. Linux has no confinement launcher, so Codex
  message is unsupported there.
