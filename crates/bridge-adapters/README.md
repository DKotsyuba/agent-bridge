# bridge-adapters

Native Codex / Claude Code adapters for Agent Bridge: the protected caller
registry, quiet root hooks and qualified message carriers. They consume core's
single custody and attempt state (`DispatchCarrier`, `observe_binding`,
`drain_inject`, `record_outcome`); there is no second attempt or hook store.

Status: implemented and tested against owned fixture processes. The Root has
recorded native Q2 / Q3 / Auto passes of owned frontends on the builds named in
this document (source/binary gate `root-native-core5-r10-binaries.json`); that
qualifies those owned builds and that observed scope only. Working GUI, apps,
chats and global hooks were not touched and are not qualified, the Q4 lifecycle
results below are history scoped to the sealed f2 production (no native run
exists yet on the assembled production), and what is not established is listed
at the end.

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
  SHA-256 match a profile, whose file was last modified *and* last changed
  (kernel ctime, which `cp -p` / `install -p` / `touch` cannot restore)
  strictly before the whole second that process started, so the bytes
  hashed at daemon startup are the bytes it started from (a replacement or
  in-place rewrite after the start, even with a preserved mtime, and a change
  in the start second itself are unproven: restart the harness a second or
  more after installing a build; a benign chmod or link change after the
  daemon warmed also moves the nanosecond ctime, which is part of the
  daemon-start digest cache identity as well, so it needs BOTH a daemon
  restart (re-hash, never under the serving lock) and a harness restart; a
  native run should record the stock binary's inode, mtime and ctime before
  and after to show it was not touched, which proves that run only, not that
  the OS can never write it; the OS keeps
  reporting the same executable path for the live process after a
  replacement, so the path proves nothing, and none of this defends against
  code that can move the clock backwards), and whose own store (`CODEX_HOME` /
  `CLAUDE_CONFIG_DIR`, else `$HOME/.codex` / `$HOME/.claude`, read from that
  process's own environment) is that profile's store. PID, UID, cwd, argv or
  a process name alone never qualify. `Registry::new` (so every consumer that
  constructs and then serves a registry, the daemon included) hashes every
  configured harness and relay executable once before it returns
  (`executable_digests_warmed` logs the daemon's cached/skipped/unqualified
  counts, as a warning when a file is missing, unreadable or changing or its
  real hash differs from the configured digest, never paths or contents; about
  one streamed read of those files, roughly 1.6 s per 246 MB optimized and
  several times longer unoptimized), and keeps
  the real digest per exact file identity (path, device and inode, length,
  nanosecond mtime and ctime). Serving never hashes: a hook or relay request never reads
  an executable under the registry lock. A file that was missing or unreadable
  at startup, or is installed, replaced or modified afterwards (even a
  same-size rewrite in the same second), has no digest for its identity and is
  refused as unqualified (`NotEvidence`) until the daemon is restarted, which
  re-hashes the then-current files; other warmed executables keep attesting.
  After installing or updating a harness build, update its configured digest
  and restart the daemon.
- **Binding and epoch.** The harness process incarnation (PID + start time)
  owns its session addresses. The first hook, the owner's own non-`compact`
  `SessionStart` (not a Claude child's, whose events share the root's address,
  and not a `compact` restart, which keep binding, epoch and state), or a new
  incarnation (after the old one died) renews the binding with a strictly
  larger epoch; older records become stale. A second *live* incarnation
  claiming a bound address is refused as conflicting.
- **Lifecycle.** From the owner session's own hooks: prompt/tool events are
  active; the owner's `Stop`, idle-prompt notification or a non-`compact`
  `SessionStart` is inactive; permission requests, permission notifications
  and `AskUserQuestion` await input; `SessionEnd`, a dead incarnation, or no
  binding (e.g. after a daemon restart) is unknown. A new or renewed binding
  starts unknown and only those positive owner events leave it: a first
  `SubagentStop`, a child's `Stop` / `SessionStart` / `SessionEnd` / idle
  notification, another notification type or a `compact` restart never make
  it inactive, and none of them changes an established state. Unknown is
  never inactive. Bridge never answers a permission request.
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
- **Codex application message**: when the attested recipient harness exposes
  `CODEX_APP_TOOLS_PIPE_PATH`, Bridge uses the application's native
  `send_message_to_thread` tool with `callerSource = "codex"`, the same
  host contract as agent-run. This preserves the application's cross-task source
  label; XML inside the message is not used to manufacture a UI badge. The pipe
  is inherited by the app-authorized MCP frontend, never from sender arguments.
  The resident daemon uses a message-only private relay: kernel ancestry ties
  its frontend to the attested recipient harness, and the frontend accepts only
  the actual adapter daemon identified through the protected channel socket.
  This keeps native host calls in the registered frontend context, as agent-run
  does; the daemon cannot invoke arbitrary host tools. The Codex MCP entry
  forwards `CODEX_APP_TOOLS_PIPE_PATH` and `CODEX_MCP_NODE_PATH` for this integration.
  The latter names the host-supplied signed Node runtime: on macOS the native
  pipe closes unsigned-client connections before discovery. The typed Bridge
  frontend executes one embedded fixed-call client through that runtime with
  the existing bounded child watchdog, never a caller-supplied script or tool.
  The signed client preserves its inherited MCP host environment; clearing it
  closes native discovery even with the supplied signed executable. The separate
  confined CLI queue helper retains its cleared environment and OS restrictions.
  Local native-client tests require an explicitly prepared `BRIDGE_TEST_NODE`;
  omission is reported as a skipped host-transport check, without downloading Node.
  Only read-only tool discovery and that one exact message operation are sent,
  under one eight-second connect/read/write deadline. A positive native success
  is acceptance only. Any failure after the message request starts is unknown,
  retained and never followed by a second ordinary-queue send.
- **Codex CLI message**: `sandbox-exec -p '(version 1)(allow default)(deny
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
  session *and* the attested harness PID (the per-process
  `sessions/<pid>.json` that 2.1.296 writes is read directly; only when it
  is missing or names another session does a bounded scan of at most 512
  other descriptors run; the session's own `<pid>.*.key` peer token is
  selected by name before the same 512 bound, so a wide store cannot hide it,
  and must be an owned regular non-symlink file), and the inbox socket's kernel peer
  must be that PID before the session's own peer token is sent. Only
  `priority = "later"` is sent; peer inject is prohibited. Receipts go to a
  callback socket bound in the inbox directory for that one attempt (named
  from its message id, unlinked when the attempt settles or expires, at most
  64 at once by default; while all are held by unsettled hand-offs the
  recipient's attestation holds visibly, so core reserves no attempt and the
  payload stays pending until a slot frees; that check releases only held
  hand-offs past their recheck horizon, in memory, and reads no transcript;
  written-without-receipt slots are freed by the background pass, which
  checks the transcript first; passes are 2 s apart by default, plus
  transcript scan time); earlier candidates shared one callback per daemon and inbox
  directory, which let a historical peer entry settle a later same-manifest
  attempt after a manual retry. A receipt counts only on the attempt's own
  callback, when it names that attempt's unguessable message id *and* its sender's kernel
  identity, read first thing after accept, is the attested recipient PID as
  this user; a sender that already closed (its PID is no longer readable) is
  ignored and logged `claude_receipt_unverifiable` — fail closed, the
  attempt stays held/unreceipted until core's overdue incident. `held` is non-terminal, `delivered` is acceptance, any other
  native status after the write (a refusal included, with or without a hold)
  is an unknown outcome, never known-unsent, since its no-effect meaning is
  not qualified for the supported build and a delivery on another connection
  could still follow; only local failures before any byte is written are
  known-unsent; silence is `written_no_receipt`. A `held` followed by a terminal receipt
  inside the same first-receipt window settles on the terminal one in order
  (`delivered` accepted, a negative unknown); contradictory receipts in one
  window (a different status after the first terminal one) are unknown too;
  a delivery that arrives later on another connection after a negative was
  settled is ignored, leaving the unknown outcome (no automatic repeat); the
  hold horizon of both the
  first-window and the late `held` path is `held_recheck_ms`. That hand-off is
  reconciled against the
  addressed session's own native transcript (shapes observed on 2.1.296; at
  most the last 8 MiB is read, its first partial line skipped, and each whole
  line is parsed as strict UTF-8 JSON, so a large non-ASCII transcript still
  closes while malformed bytes are never repaired into manifest text):
  only a peer-origin user entry of that session whose `origin.from` names
  this attempt's own callback and that contains the exact manifest records
  `context_observed`. The `queue-operation` `enqueue` is not evidence: it
  carries no attempt identity and a retry re-sends the same manifest. No
  message id is assumed and absence never retries. A session descriptor
  without an inbox (restricted session) is positive disablement: the
  message capability is withdrawn and recorded in core, so later message
  publications refuse before acceptance; a missing descriptor is only a
  transient hold. An inbox that appears later in the same incarnation
  restores the capability only if the loaded profile qualified `message`
  (a profile with `message = false` stays refused). Every such change is
  recorded in core first and applied to the registry only after that
  succeeded (a failed core write is retried, never left half-applied), and
  only to the exact binding observed: a renewed epoch or incarnation since
  the observation makes it a hold and a re-attestation. Withdrawn but
  qualified bindings are re-checked every 2 s even with nothing pending
  (publications refuse while message is withdrawn, so no dispatch would
  otherwise look). A daemon restart
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
| Q2 Claude hooks, caller, inject, `later`, pause | haiku, low, 0.5 USD cap | `node qualification/claude-native-probe.cjs` | `checks.json` with no failures: closed native tool inventory and manual/default permissions, root/child attested from the real `toolUseId`, the hook-injected marker quoted while the planted project-memory canary is absent, the background child's native completion (and any follow-up turn) before the idle steps, a message answered in a distinct unprompted turn with actor-bound evidence (a verified receipt's `native_accepted` or this attempt's transcript `context_observed`), pause applied with the paused event held (no attempt, no-wake hold reason) and no turn start or result in the paused window while the receiver was alive with budget, then a distinct turn after resume |
| Q3 config control | no (fake App Server) | `node qualification/codex-native-probe.cjs --self-test-config` | `config_control: PASS`: the own `bridge_probe` subtree survives the pre-write projection, the own hook is recognized and the state override trusts it and disables the foreign one, the stderr override warning is detected, kept `hooks/list` entries carry only the minimal fields, and fake credentials planted in a foreign hook command, the config tree, a notification, an unparsable line and stderr are in no retained file or console output of a completed gate, a gate interrupted by SIGTERM, or a gate whose server ignores SIGTERM and keeps writing without any override warning (which must still be rejected, by the non-exit check alone), with no surviving process |
| Q3 Codex gate only | no | `CODEX_PROBE_GATE_ONLY=1 node qualification/codex-native-probe.cjs` | `hooks_isolated` and `approval_config_effective` true (ends with `gate_only_run` by design) |
| Q3 Codex hooks, caller, inject, child, queue | gpt-6-luna, low | `node qualification/codex-native-probe.cjs` | `checks.json` with no failures: model in the build catalog, hooks isolated, exact-tool approval effective, the read-only `bridge_me` root join succeeded (shows callId = tool_use_id for that build), the externally published marker in the reply, the unapproved `bridge_unlisted` refused by the host and never executed (this proves the caller, the host approval boundary and the parsed config, not that the `approve` value itself caused `bridge_me` to run), child attested on its own thread, the helper's correlated `native_accepted` with native readback on the persisted thread, and the probe's own queue item removed and verified gone |
| Q4 Codex owned-frontend mechanism | no model (network-denied; native turns recorded) | `BRIDGE_Q4_ROLLOUT=<probe-owned rollout> BRIDGE_Q4_THREAD=<its thread id> [CODEX_EXE=<codex>] node qualification/frontend-lifecycle-probe.cjs` (`--self-test` for the pure validators) | `checks.json` with no failures, **loaded-frontend mechanism evidence only — it launches no Bridge component**. The operator supplies one probe-owned rollout explicitly (no default, nothing enumerated; the path must be absolute, normalized, `rollout-*.jsonl` naming the id; it is validated, then copied into a fresh private `CODEX_HOME` under a confined `sessions/...` path; its `meta.id == session_id == expected id` is an identity-consistency check, not ownership). Every native session runs under `sandbox-exec` with network denied, witnessed by a PAIRED loopback control (`lifecycle-lib.cjs`: an own listener accepts an unconfined connect and the same connect under the policy is denied with `EPERM`/`EACCES`; no external address is contacted). Recorded for the loaded build: path/sha256/version, its own exported schema (lifecycle methods present, no clear RPC), a real `thread/start` producing a distinct idle thread (empty preview, no fork lineage) whose turn list and queue are asked in the SAME owner process: the queue must list no row, and the turn list must be empty, refused with `no rollout found for thread id <id>`, or refused with the build's explicit before-first-user-message state (error -32600, exactly `thread <id> is not materialized yet; thread/turns/list is unavailable before first user message`, accepted only with the verified fresh idle constructor and that empty queue; a later process's `notLoaded` and any other error are not accepted as empty), resume/fork creating no turn (complete bounded turn-id pagination), a fork while an own queue item is pending (item stays on the original, absent on the fork), the archive round-trip with the native archive refusal of a queue add (error -32600, message `... is archived`, no result) PLUS the exact marker absent from the own queue and the complete turn list, and the item's disposition by exact marker, an own-item readback through a LIVE owner process (PID alive at add and readback, explicit disconnect with exit and liveness recorded; if the build consumes the item in that owner the check fails and the outcome is kept), and a client restart where the item is still pending with no new turn **or** consumed as exactly the one new turn carrying its marker (any other new turn fails). Native turns this build creates are real (they exist as `interrupted`/non-completed turns with no model output) and are listed with id, status and marker; this is native turn creation, not external model inference. All own queue items are deleted at cleanup and verified gone. `case_map` keeps `bridge_composition_codex` and the working-GUI cases `pending_model`/`unsupported_in_scope`. **Current source v5 (signed `5439c194`, tree `35ba70e3`), Root-run: `root-q4-v5-codex-mechanism.log` (rc 0), frozen checks `root-q4-v5-codex-mechanism-checks.json`, owned fixture `m2q4-JZdMzd`, `failures: []`: the live owner PID (12077) alive at add, readback and disconnect, the own marker one row pending before the disconnect, owner exit 0 and not alive afterwards, a new process restart with exactly one marked `interrupted` native turn, the archived queue add refused with the exact -32600 and no result, the marker absent from the own queue and the full turn set, no paid model effect and `orphans: []`. This proves the updated frontend mechanism only: it launches no Bridge component (the sealed old binaries only pass an identity gate), so the assembled Bridge production and its native scope remain pending.** History: the same driver at sealed f2 on source v4 (`root-q4-v4-codex-mechanism.log`, rc 0, fixture `m2q4-jTnRtq`, `failures: []`) ran stock CLI 0.162.0-alpha.17.2 (sha256 `0d5ac7aae20c4eda...b9d28`) with 37 confined sessions, no model effect, paired loopback witness EPERM, one exactly-marked `interrupted` native turn on restart and `orphans: []`; the archive-refusal and live-owner checks were then only exercised against a local App Server double |
| Q4 Claude lifecycle, unpaid | no (zero inference: remote-IP network denied) | `node qualification/claude-lifecycle-probe.cjs` (`--self-test` for the pure validators) | **Bridge-composition evidence, root-run at sealed f2 on source v2 (pre-dating this file's later edits): `root-q4-v2-claude-unpaid.log`, rc 0, fixture `m2q4c-MAMpyw`, `failures: []`, Claude Code 2.1.296, paired loopback witness `{open: connected, fenced: EPERM, ok: true}`, `paid_gate_unmet: []`, correlated reset with hook-bound native identity (the SDK reset ids differ from the hook-bound new session; identity is taken from hooks and bindings, never from the reset), epochs, fail-closed dead-incarnation holds after pause release, zero turns/tokens, `orphans: []`. Owned receiver only; no working application. A rerun is needed for any later source edit.** One stock 2.1.296 stream-json receiver, closed before launch (`--setting-sources ''`, own settings with the product hook beside a no-op hook, `--strict-mcp-config` with no server, `--tools ''`, manual permissions, no prompts, private cwd, parent-harness `CLAUDE_CODE_*`/`CLAUDECODE` variables removed and store/auth variables untouched) and confined by `sandbox-exec`, witnessed before launch by the paired loopback control (own listener: unconfined connect succeeds, the same connect under the policy is denied with `EPERM`/`EACCES`). Required: init inventory closed and `clear` among the loaded slash commands; a Core `bindings` row (read-only `sqlite3` of the probe's OWN fresh database — the daemon logs only refusals and the row holds recipient, epoch and capabilities only) for the exact session address with an epoch not older than the launch, plus the receiver's own `SessionStart` hook frame and zero `hook_refused`/`binding_fence_refused`/`caller_refused`/`drain_refused`; a paused `later` message held with zero attempts; a streamed `/clear` with a client uuid answered by a `conversation_reset` (`trigger: clear`, `user_message_uuid` equal to it); the old/new identity decided by the post-clear SessionStart hook frames and binding rows (never assumed equal or different); the held event staying on its old recipient with no attempt anywhere; after the receiver exits and the pause is released, a fresh message and the older one held by the dead-incarnation reason (session ended / harness process gone, never the no-wake text) with no hand-off; and no model effect (confined, every result frame zero turns/cost/nested usage). With `BRIDGE_Q4_PAID=1` the paid phase refuses to start unless EVERY unpaid required check is exactly `true` |
| Q4 Claude lifecycle, paid fork | haiku, low, TOTAL 0.50 USD (caps 0.30 original + 0.10 fork, shared running sum) | `BRIDGE_Q4_PAID=1 node qualification/claude-lifecycle-probe.cjs` (root only; includes the unpaid phase) | **Root-reported at sealed f2 on source v1 (guarded-paid phase; reported cost 0.000695 USD, exact old/fork routing, epochs, exits and cleanup verified); not rerun on later sources.** One prompted turn on an unconfined closed original receiver (own messaging socket), then a `later` message held by a Core pause while `claude --resume <original> --fork-session --session-id <fresh uuid>` starts under the SAME closed launch: the fork must bind its own new address (original binding epoch unchanged), the event must stay on the original recipient with no attempt for either, and after unpause the original must answer it in a distinct turn quoting its marker (positive `context_observed`/`native_accepted`, attempt actor and proof reference naming the original process id) while the fork never sees the marker; the shared cost must stay within 0.50 USD (15 minute budget plus bounded cleanup) |
| Q4 Codex Bridge composition | gpt-6-luna, low, at most 3 short turns, tokens measured (no dollar claim) | `BRIDGE_Q4_PAID=1 [CODEX_EXE=<codex>] BRIDGE_BIN_DIR=<target>/debug node qualification/codex-lifecycle-probe.cjs` (root only; refuses without the flag; `--self-test` for the pure validators) | **Not a pass. The root's native run of source v2 (`m2q4x-hh6Pkj`) passed the isolation gates, first root binding, host refusal, archive/dead holds with audited disposal, restart/resume, the real fork on its own address and the pending inject staying on T1, but failed before turn 3: the cumulative token counters were summed wrongly (fixed here by per-turn increments) and the first SessionStart/UserPromptSubmit hooks timed out at 5 s with one `hook_refused: not_evidence` (a measured f2 first-hook digest cost, see below). The later edits are validated only against a local double of the App Server subset with the real daemon, hook and fixture; the final native run on the assembled production is pending.** The Q3 isolation gate is reused unchanged (own hooks trusted by hash, every other hook disabled per launch, exact-tool approval parsed back) plus every foreign MCP server of the user configuration disabled per launch and read back as disabled. One unconfined `codex app-server` backend A creates thread T1 before the daemon starts (its grant names T1); turn 1 must give the exact binding row equal to the `bridge_me` root caller's epoch, the frontend's own `hook/completed` records and the host-refused, never-executed `bridge_unlisted`. T1 is archived with an `inject` event pending (no attempt, no tier, same recipient/envelope hash, no pause policy anywhere). A is killed: a `message` event published meanwhile must be held fail-closed with no attempt and no pause (the real daemon reports the generic carrier-chain text `no carrier attests this endpoint: ...` for a dead Codex harness, so the reason is recorded exactly and the causal link rests on ordering, verified exit and the frozen old epoch), then it is closed by an audited operator disposition so it can never become a native queue turn. A NEW backend B resumes T1; T1 is forked to T2 while the inject event is pending and turn 2 runs on T2: its caller is T2 on its own address, the inject event stays on T1 (no attempt for either recipient, T1's epoch unchanged, marker absent from the fork's reply). Turn 3 on T1 (B) must renew the epoch strictly (E2 > E1), join the caller at E2 and hand the inject event out through T1's own natural hook (attempt actor T1, epoch E2, proof reference naming B's process id, delivery `hook_submitted`) with the marker in T1's reply. Before the first paid turn the driver observes the own MCP server on the own thread with `mcpServerStatus/list` (exact server and thread, `toolsAndAuthOnly`, complete pagination (at most five pages), `runtimeStatus: connected`, empty `toolsError`, both own tools advertised, within 60 s total elapsed across inventory polls and page requests, with every request bounded by the remaining readiness and run budgets and 60 s reserved for cleanup) and aborts before any model turn otherwise (`mcp_inventory_ready`; cleanup attempts to archive every owned thread, including a thread with no logged turn); the observation is possible only after `thread/start`, so it follows the thread constructor and the daemon start. The root's native run of the assembled production (`m2q4x-TfpqOV`) FAILED (rc 1) on exactly this seam: all three turns completed within the token bound with no hook failures or daemon warnings, and every archive, dead-incarnation, fork-custody, restart, epoch-renewal, natural-hook and marker check passed, but the first turn made no MCP call (the model reported the tool unavailable), so the first-turn root attestation, binding, Pre/PostToolUse and host-refusal checks were false. That is a recorded failed observation; whether the new gate cures first-turn availability is unproven until the root reruns natively, and the later resumed/fork turns' successful calls are not first-turn evidence. Native `sessionId` equality or difference is recorded, never used as a role signal. The dead-incarnation hold qualifies absence only with an actual dead-incarnation reason (`harness process is gone`, `the recipient session ended`, `no attested binding`); the generic carrier-chain fallback (`no carrier attests this endpoint: ...`, which at f2 carries another carrier's refusal) does NOT qualify, so this check fails against a core that overwrites the reason. App-server launches pass `--ignore-user-config`/`--ignore-rules` only if its `--help` lists them (they are not listed on 0.162.0-alpha.17.2, which leaves user configuration, global instructions, AGENTS files, profiles, `notify` and rules in force except for the per-launch neutralising overrides; `config/read` reads back the two instruction fields only). Every owned hook failure fails the run, the host refusal of `bridge_unlisted` must be an explicit approval refusal (no other MCP error counts), and any turn without native completion is interrupted, its backend stopped and the run aborted with the turn log kept. Own threads are archived at cleanup. Usage is counted per turn as the increment of that turn's own correlated token snapshots (final cumulative total minus `first.total - first.last`; inherited fork history is not counted, unavailable or invalid usage forbids a further paid turn); the 150000-token ceiling is checked before each turn. **Historical f2 daemon finding (the warm-digest production change first signed at `b7ec832a` is present in this source assembly; its current native run is still pending):** at f2 the registry hashes the harness executable on the first admitted hook, under its lock; an unoptimized `sha2` needs 27-35 s for the 246 MB Codex build as measured with the registry's own `file_sha256` (about 12 s elapsed between the first hook and the refusal in the root's native run; 1.6 s with `--config 'profile.dev.package.sha2.opt-level=3'`), longer than the 5 s hook timeout, which is consistent with (not proven by) the root's native timeline of two timed-out first hooks and one `hook_refused: not_evidence`; an f2-era daemon must be built with that flag or in release; a daemon with the warm-digest production change needs neither. A timed-out hook is never waived (`t1_hooks_observed`, `t1_resumed_user_prompt_hook_positive`; failures kept in `t1_hook_failures`, daemon warnings in `daemon_warnings`) |

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

`Probe.spawn` takes an optional `keep` that rewrites or drops each stdout
line before it is logged or handed on; without it lines are logged as is.

Isolation: Q2 uses `--setting-sources ''`, only the Agent tool (native `Task`)
plus the fixture MCP tool checked against the native inventory (the fixture
server is started with only `bridge_probe`: the root's 2.1.296 run listed
every tool the server offered; Q3 starts it with `bridge_me,bridge_unlisted`),
an open first-turn scope or a gone receiver stops Q2 before any later step
(their checks stay missing), an explicit
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
probe stops with `isolation_unavailable`. Every gate App Server stdout line is projected before
it is logged or parsed (the root's r6 gate logs held the user config and
foreign hook commands raw): `hooks/list` entries keep only `key`, `source`,
`eventName`, `enabled`, `trustStatus`, `currentHash` and an `own` flag
computed from the exact own command; `config/read` keeps only
`result.config.mcp_servers.bridge_probe`; other answers keep their id or
error code, notifications their method; unparsable lines are dropped. The
gate's stderr never reaches a file: it is piped and reduced in memory to
its size and whether it reported an ignored setting, and only that summary
is written once the gate ends, so a signal, a thrown error or a gate
process that keeps writing leaves no raw stderr behind. The `config/read` path is the shape this probe expects, not one
proven against the build, and an absent subtree fails the gate. The model
phases, queue App Server sessions and the queue helper still log stdout and
stderr unfiltered; those channels are not claimed free of configuration
diagnostics. No trust bypass, no coexistence
override, nothing persisted. Gate-only runs on this candidate (no model,
no network, no child processes) showed all 7 user hooks disabled and the 5
probe hooks enabled and trusted, with `~/.codex` files unmodified; the
model phases themselves have not run. All probes use fresh owned Bridge state, a new
session/thread, a daemon grant naming only it, and the probe MCP server
(`bridge-fixture mcp-server`, which attests from `_meta` only and never
returns the marker in the tool result). The probes show what the named build
did once; they are not release qualification.

## Not yet established

Verified since the R10 root runs (evidence: `m2cp-XRv61Z`, `m2cp-AM6xUY`,
`m2xp-9hkYAB`, all `failures: []`): real *owned* Claude 2.1.296 and Codex
0.162.0-alpha.17.2 sessions ran these hooks and carriers end to end —
root/child caller joins (`_meta.callId` = the same call's `PreToolUse`
`tool_use_id` on the Codex build), the hook-injected marker quoted in the
model reply, a `later` message answered in a distinct unprompted turn with
actor-bound `native_accepted`/`context_observed` evidence (the per-attempt
callback name and its `origin.from` accepted by the real inbox), the paused
window with zero attempts and turns, and the confined queue helper's
correlated native acceptance with readback on the persisted thread. Scope: these
are the sealed-f2 Q2/Q3 results (Codex queue acceptance on a real build is
established by Q3 `m2xp-9hkYAB`: a correlated `native_accepted` with native
readback on the persisted thread, and the probe's own item removed and verified
gone); they are not claims about any later production assembly.

Still not established, retained honestly:

- No *working* Claude Code or Codex application, chat or global
  configuration has been touched (D-003): hook installation into working
  apps, coexistence with their existing hooks there, Codex
  `additionalContext` visibility in the real frontend, the GUI's own
  /clear, and full working-app restart are unqualified (A-003 scope).
- A22/T008 lifecycle (clear, resume, fork, restart) is NOT established by
  source preparation. The Q4 drivers above are supported *owned-frontend*
  qualification, separate from any working-GUI deployment, and until the
  root reruns them on the assembled sources the native cases below are scoped to the pins that were actually run (see the table rows): the Claude `/clear`
  seam and dead-incarnation negative (unpaid, v2), the Claude
  fork-while-`later`-pending custody (guarded-paid, v1) and the Codex mechanism (v5 on the current signed source, no Bridge component; v4 at sealed f2). The Codex
  Bridge-composition seam (protected hook binding, a new incarnation's epoch
  after a restart, stale-binding fail-closed, fork custody) needs turns, hence a
  model: `codex-lifecycle-probe.cjs` is its driver; its v2 native run FAILED before turn 3 (not a pass) and no later native result exists, so the mechanism probe keeps it `pending_model`. A stream-json `/clear` that
  the build does not dispatch (or after which the receiver ends before a
  post-clear SessionStart) fails the unpaid driver; it is never promoted to a
  pass, and a PTY frontend would be the next step.
- The network-denial control is PAIRED (`lifecycle-lib.cjs`): an own loopback
  listener accepts an unconfined connect and the same connect under the
  policy must be denied with `EPERM`/`EACCES`; no external address is
  contacted. It shows the policy denies network connects for the processes it
  wraps and says nothing about what the CLI itself reads with its own
  protected authentication (the probes never extract, copy or write
  credentials).
- Historical scope: the f2 qualification (Q2/Q3 native probes and the Q4 runs
  above) was run against the pinned f2 production. The signed production
  candidates that change the registry digest path and the core hold-reason
  presentation are separate branches that the root assembles with this one;
  no native result on that assembly exists yet, so the final native production
  qualification is still pending. This document does not turn any f2 result
  into a claim about the assembled production: Codex queue acceptance on a
  real build was established natively at sealed f2 only (Q3 `m2xp-9hkYAB`,
  correlated `native_accepted` with native readback and verified cleanup),
  not on the assembled current production.
- Source-proven only on the assembled production, with no native run on it
  yet: `Registry::new` hashes every configured executable once, and an
  executable that is new, replaced or changed afterwards is unqualified until
  the daemon restarts (identity: inode, length, nanosecond mtime and ctime;
  mtime and ctime must be strictly before the process start second, so a
  same-second change, a backdated replacement or a chmod after start is
  unproven, and a change after the daemon warmed needs both a daemon restart
  and a harness restart); the daemon logs `executable_digests_warmed` with cached,
  skipped and unqualified counts; native negative receipt statuses after the
  write are unknown outcomes, never known-unsent; contradictory receipts in
  one window are unknown; an owner lifecycle starts unknown and only the
  owner's own non-`compact` `SessionStart` renews or idles it. The fixture
  inbox proves these; native semantics of negatives and of an early `held`
  followed by a terminal receipt are not established.
- The Codex `_meta.callId` = `tool_use_id` equality was observed on the named
  Codex build only; on any other build a mismatch finds no record and refuses.
- Codex `approval_mode = "approve"` semantics: Q3 shows the parsed value and
  the host boundary, not that this value is what allows `bridge_me`.
- The full held/release/drop timing window against the real Claude inbox
  beyond the verified receipt and transcript closure remains model-gated;
  if a sender closes before its PID is readable, receipts are ignored by
  design and those hand-offs rely on transcript closure or the overdue
  incident — held-release would become unsupported, never silently
  accepted.
- Q1's model-less `-32603 "no rollout found"` is classified unknown, not
  no-acceptance (a thread needs a persisted rollout). Linux has no
  confinement launcher, so Codex message is unsupported there.
