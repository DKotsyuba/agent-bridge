# bridge-adapters

Native Codex / Claude Code adapters for Agent Bridge: the protected caller
registry, quiet root hooks and qualified message carriers. They consume core's
single custody and attempt state (`DispatchCarrier`, `observe_binding`,
`drain_inject`, `record_outcome`); there is no second attempt or hook store.

Status: implemented and covered by tests that run real channel, hook, relay and core
processes against labeled stand-in harnesses (`bridge-fixture`) and scripted carriers.
Native results were observed by manual probes on named owned builds and scopes; they are
listed with their limits in the [qualification matrix](../../docs/qualification.md), which
is the authority on what is qualified. Working applications, chats and global hooks are not
touched by anything here, and nothing in this crate installs a hook for you.

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
  host contract the application uses itself. This preserves the application's cross-task source
  label; XML inside the message is not used to manufacture a UI badge. The pipe
  is inherited by the app-authorized MCP frontend, never from sender arguments.
  The resident daemon uses a message-only private relay: kernel ancestry ties
  its frontend to the attested recipient harness, and the frontend accepts only
  the actual adapter daemon identified through the protected channel socket.
  This keeps native host calls in the registered frontend context, as the application's own tooling
  does; the daemon cannot invoke arbitrary host tools. The Codex MCP entry
  forwards `CODEX_APP_TOOLS_PIPE_PATH` and `CODEX_MCP_NODE_PATH` for this integration.
  The latter names the host-supplied signed Node runtime: on macOS the native
  pipe closes unsigned-client connections before discovery. The typed Bridge
  launcher replaces itself with that signed frontend, preserving the registered
  MCP PID and inherited host context. Node starts the Rust MCP
  child with both native capability variables removed. Authenticated daemon
  requests reach Node only over the child's inherited private descriptor; Rust
  checks the kernel parent PID/UID and exact call correlation, and closes an
  uncertain channel rather than replaying it. Only the supplied Node executable
  is an allowed intermediate between the Rust child and qualified Codex harness.
  Old frontend builds cannot mask the active build during rolling updates.
  The confined CLI queue helper retains its cleared environment and restrictions.
  The native-client and Desktop regression tests require an explicitly prepared absolute
  `BRIDGE_TEST_NODE`; some skip and the deterministic Desktop regressions fail without it. Node is never downloaded.
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
  transcript scan time); a shared callback per daemon and inbox
  directory would let a historical peer entry settle a later same-manifest
  attempt after a manual retry, so each attempt has its own. A receipt counts only on the attempt's own
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
store = "/abs/home/.claude"
[[adapters.profiles.executables]]
path = "/abs/resolved/claude/binary"
sha256 = "<64 hex of the qualified build>"
version = "<exact build version>"
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

## Manual native qualification probes

Each probe needs explicit operator provisioning, an exact harness build and, for most,
a paid model. **None runs in `cargo test` or CI.** Build first with
`cargo +1.98.1 build --offline -p bridge-adapters --bins`, run the `node
qualification/...` commands below from the `crates/bridge-adapters` directory (the
`cargo` commands work from anywhere in the workspace), and set `TMPDIR` (and, for
the universal probe, `TMP` and `TEMP`) to one short absolute directory you own: probes
refuse to use any other temporary location. A probe reads host state such as the harness
store, so run it deliberately and keep its logs and session identifiers private.

| Probe | Model | Command | What a pass demonstrates |
|---|---|---|---|
| Q1 Codex helper classification | no | `BRIDGE_QUALIFY_CODEX_EXE=<codex> cargo +1.98.1 test --offline -p bridge-adapters --test qualify_codex -- --ignored --nocapture` | Conservative classification only: native errors after the write are never known-unsent, and any acceptance has a native readback. Not a positive queue qualification. |
| Q2 Claude hooks, caller, inject, `later`, pause | small, low effort, budget-capped | `node qualification/claude-native-probe.cjs` | `checks.json` with no failures: closed native tool inventory and manual permissions; root and child attested from the real tool-use id; the hook-injected marker quoted while a planted project-memory canary is absent; a message answered in a distinct unprompted turn with actor-bound evidence; pause applied with the event held and no turn in the paused window; a distinct turn after resume. |
| Q3 config control | no (fake App Server) | `node qualification/codex-native-probe.cjs --self-test-config` | The probe's own config subtree survives projection, its own hook is trusted and the foreign one disabled, the override warning is detected, and planted fake credentials appear in no retained file or console output, including after an interrupt. |
| Q3 Codex gate only | no | `CODEX_PROBE_GATE_ONLY=1 node qualification/codex-native-probe.cjs` | Hooks isolated and exact-tool approval effective. Ends with `gate_only_run` by design. |
| Q3 Codex hooks, caller, inject, child, queue | small, low effort | `node qualification/codex-native-probe.cjs` | `checks.json` with no failures: model in the build catalog, hooks isolated, the read-only `bridge_me` root join, the externally published marker in the reply, an unlisted tool refused by the host and never executed, a child attested on its own thread, the helper's correlated `native_accepted` with native readback, and the probe's own queue item removed. |
| Q4 Codex owned-frontend mechanism | no (network denied) | `BRIDGE_Q4_ROLLOUT=<probe-owned rollout> BRIDGE_Q4_THREAD=<its thread id> [CODEX_EXE=<codex>] node qualification/frontend-lifecycle-probe.cjs` (`--self-test` for the pure validators) | Loaded-frontend mechanism evidence only; it launches no Bridge component. Thread start, resume, fork, archive and queue behavior of the exact build, in a confined sandbox with a paired loopback network-denial control, ending with all own queue items removed. |
| Q4 Claude lifecycle, unpaid | no (zero inference) | `node qualification/claude-lifecycle-probe.cjs` (`--self-test` for the pure validators) | Bridge-composition evidence on an owned, confined receiver: hook-bound binding with a renewed epoch, a held `later` message with zero attempts, `/clear` identity decided by the post-clear hooks and bindings, and fail-closed holds after the receiver exits. |
| Q4 Claude lifecycle, paid fork | small, low effort, budget-capped | `BRIDGE_Q4_PAID=1 node qualification/claude-lifecycle-probe.cjs` | A held message stays on the original recipient while a fork binds its own address; the original answers it after unpause and the fork never sees it. Refuses to start unless every unpaid check is exactly `true`. |
| Q4 Codex Bridge composition | small, low effort, token-bounded | `BRIDGE_Q4_PAID=1 [CODEX_EXE=<codex>] BRIDGE_BIN_DIR=<target>/debug node qualification/codex-lifecycle-probe.cjs` (`--self-test` for the pure validators) | Protected hook binding, renewed epoch after restart, fail-closed dead-incarnation holds, fork custody and a pending inject handed out through the thread's own natural hook. Any owned hook failure fails the run. |
| Universal producer (raw and SDK) | small, low effort, token-bounded | `BRIDGE_UNIVERSAL_PAID=1 node qualification/universal-native-probe.cjs <settings.json>` | Two concurrent unknown producers register and publish through the public v1 protocol on an exact Codex build; each caller receives only its own hidden marker; restart recovers the historical registration; close and replay add no attempts; owned threads are archived. `--cleanup-existing` finishes cleanup of an earlier owned run without any model request. |

Shared lifecycle (`qualification/probe-lib.cjs`): one absolute total budget (a local
command is refused once it is spent); a lifecycle fence that refuses any new process once
cleanup starts, except a registered cleanup action's own marked process; every child in its
own process group; cleanup that runs registered actions, then SIGTERM, a bounded grace and
SIGKILL, waiting for each child to exit *and* its stdout to end (`unreaped:` or
`unclosed:` failures otherwise); an orphan sweep by private-directory and session markers;
synthetic grant tokens only in `0600` files (never argv), redacted from every evidence file
and from the written result, which records `secret_in_*` failures. A required check that is
missing or not exactly `true` is a failure. `node qualification/probe-lib.cjs --self-test`
exercises all of this without a model and passes only on its exact expected failure set.
`Probe.spawn` takes an optional `keep` that rewrites or drops each stdout line before it is
logged or handed on.

Isolation: probes use their own settings, strict MCP configuration, a private messaging
socket and the installed build's memory switches (`CLAUDE_CODE_DISABLE_CLAUDE_MDS`,
`CLAUDE_CODE_DISABLE_AUTO_MEMORY`, `CLAUDE_CODE_DISABLE_ORG_MEMORY`), checked by a canary;
`--bare` is not used because it disables OAuth. The Codex gate lists the hooks Codex would
load, disables every foreign enabled hook and trusts the probe's own hooks by their listed
hash in one per-launch whole-map `hooks.state` override (hook keys contain dots, so per-leaf
dotted `-c` paths are ignored by 0.162.0-alpha.17.2), confirms it with a second listing and
stops with `isolation_unavailable` otherwise. Gate output is projected before it is logged
(only hook key, source, event, enabled, trust status, hash and an `own` flag; the
`config/read` subtree of the probe's own server) and gate stderr never reaches a file. The
model phases and queue helpers still log stdout and stderr unfiltered and are not claimed
free of configuration diagnostics. No trust bypass, no coexistence override and nothing is
persisted. The probes use the probe MCP server (`bridge-fixture mcp-server`), which attests
from `_meta` only and never returns the marker in a tool result. They show what the named
build did once; they are not release qualification. What has been observed, on which builds,
is in the [qualification matrix](../../docs/qualification.md).

The network-denial control is paired (`lifecycle-lib.cjs`): an own loopback listener accepts
an unconfined connect and the same connect under the policy must be denied with
`EPERM`/`EACCES`; no external address is contacted. It shows the policy denies connects for
the processes it wraps and says nothing about what a harness reads with its own protected
authentication; probes never extract, copy or write credentials.

## Known limits

- Hook installation into working applications, coexistence with their existing hooks,
  Codex `additionalContext` visibility in a real frontend, a GUI's own `/clear` and a full
  working-application restart are not qualified; the lifecycle probes use owned frontends.
- A stream-json `/clear` that the build does not dispatch fails the unpaid Claude driver; it
  is never promoted to a pass.
- The Codex `_meta.callId` = `tool_use_id` equality was observed on the named Codex build
  only; on any other build a mismatch finds no record and refuses.
- Codex `approval_mode = "approve"`: the probes show the parsed value and the host
  boundary, not that this value is what allows `bridge_me`.
- Native negative receipt statuses after a write are unknown outcomes, and so are
  contradictory receipts in one window; the native semantics of a negative or of an early
  `held` followed by a terminal receipt are not established.
- If a sender closes before its PID is readable, receipts are ignored by design and the
  hand-off relies on transcript closure or the overdue incident; held-release would become
  unsupported, never silently accepted.
- A model-less `-32603 "no rollout found"` from the Codex queue helper is classified unknown,
  not no-acceptance (a thread needs a persisted rollout). Linux has no confinement launcher,
  so Codex message is unsupported there.

## Recipient recovery after daemon restart

The adapter channel atomically persists only verified recipient bindings in its
owner-only directory, with a bounded versioned mode-0600 snapshot. At restart it
revalidates the same PID/start time, UID, executable bytes, native store and
current profile, then renews the endpoint epoch and records the fence in core
before serving. Lifecycle remains the last verified owner state: unknown and
approval/input waits are never converted to idle. Retired, dead/reused-process,
changed-store or unqualified-build routes cannot be restored. Caller records,
sealed proofs, native inbox secrets and message payloads are never in the cache.

An already observed live recipient can therefore receive an addressed message
without any post-restart bridge_me or hook from the recipient. Recipient native
endpoint/receipt checks still run before actual delivery. Earlier uncertain
hand-offs remain retained and are never replayed by route recovery. The native
boundary test covers delivery without recipient activity, larger renewed epochs,
input-wait preservation, retired/dead routes, changed qualification and private
file protection. Successful native hooks initialize this snapshot. A missing
interactive Claude recipient, including a session opened before this format,
can also be discovered from its bounded owner-owned native session descriptor.
Discovery rechecks the live process UID/start time, descriptor age, exact native
store and qualified executable before persisting the route. Only native status
supplies lifecycle; unknown/input waits stay held. Known and retired bindings
are never overwritten, and discovery grants no MCP caller identity or proof.

Codex application frontends use a versioned private protocol, independently of
release build labels. A daemon update prefers its current build but can retain
an older labelled frontend under a primary Node process; kernel PID/incarnation,
protected channel and native signed-client checks still apply. An unavailable
frontend holds before reservation, so reconnection consumes no delivery retries.

## Universal producer ingress

The adapter socket additionally serves authenticated v1 `capabilities`,
`register_call` and `consume_assertion`; core publication/status/lifetime
operations retain the separately configured core endpoint. The authority is
shared with core, while native observation claims and audience assertions remain
ephemeral. Historical route recovery is not invocation permission.

See [the native provider contract](docs/producer-native-v1.md) for opaque
producer onboarding, declaration of generic backend audiences, exact
reserve/commit/finalize and retry rules, supported host grammar and the
runtime-configured owned MCP qualification probe. No consumer migration or
installed-service change is performed by this source feature.
