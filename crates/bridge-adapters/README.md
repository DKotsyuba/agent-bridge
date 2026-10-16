# bridge-adapters

Native Codex, Claude Code and managed OpenCode adapters for Agent Bridge: the protected caller
registry, quiet root hooks, lifecycle plugin and message carriers. They consume core's
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
| `bridge-native-daemon` | core service + Codex, Claude and OpenCode owner carriers + adapter channel |
| `bridge-hook` | the harness hook command; forwards one hook event, prints Bridge context only when handed one, always exits 0 |
| `registry` | harness incarnations, endpoint epochs, owner lifecycle, single-use call records, root-caller ABI |
| `server` / `client` | the private adapter channel and its clients (`RegistryAttestor`) |
| `codex` | `message` via one `thread/queue/add` in an OS-confined queue-only App Server helper |
| `claude` | `message` via the authenticated native peer send with `priority = "later"` |
| `opencode` / `plugins/opencode` | message-only `opencode_input` via the exact native owner; plugin lifecycle observations, no inject/context path |

## Trust model

- **Channel peer.** Every channel connection is identified by kernel peer
  credentials (PID, UID). A peer is a *hook of a harness* only if it runs as
  the daemon's user, a harness-level policy serves that harness product, and its
  nearest ancestor that is not an allowlisted shell (`intermediates`) is a
  process of that product: it runs as the same user, its resolved executable
  path carries the product marker (the product name `codex` / `claude` / `opencode` or a
  configured `executable_markers` entry; an environment variable never counts,
  because every descendant of a harness inherits its store variables), the file
  is a regular file owned by that user or root that no group or other user can
  write and was last modified *and* last changed (kernel ctime, which `cp -p` /
  `install -p` / `touch` cannot restore) strictly before the whole second the
  process started, and its own store (`CODEX_HOME` / `CLAUDE_CONFIG_DIR`, else
  `$HOME/.codex` / `$HOME/.claude`; OpenCode uses the parent of its explicit
  `OPENCODE_DB`, read from that process's own environment) is
  an absolute, already canonical directory owned by that user that no group or
  other user can write (symlinks and non-canonical spellings are refused). The
  message-candidate validation (owner-routed sends) and journal restore check the store again at use;
  the legacy Claude inbox route instead rechecks the incarnation and validates each
  descriptor and token file it reads (owned, regular, bounded, not a symlink),
  without a separate store check at the write. No store
  path and no harness executable is predeclared and nothing is enrolled: a fresh
  session in any such store registers from its own lifecycle hook. PID, UID, cwd,
  argv or a process name alone never identify a harness, and the marker is best-effort
  identification, not authentication (see the boundary below). Addresses use the
  harness policy's single namespace, so an equal session id held by another live
  incarnation conflicts. `Registry::new` hashes only the configured relay, owner
  relay and audience executables once before it returns
  (`executable_digests_warmed` logs the daemon's cached/skipped/unqualified
  counts, as a warning when a file is missing, unreadable or changing or its
  real hash differs from the configured digest, never paths or contents), and
  keeps the real digest per exact file identity (path, device and inode, length,
  nanosecond mtime and ctime), the newest identity per path only. Serving never
  hashes: a request never reads an executable and no registry lock is held
  across a read. When a configured file's identity changes (an application update,
  a touch, a rename-replacement with identical bytes) the daemon notices within
  about half a second and hashes it on a background thread (single-flight; the
  opened descriptor's identity and the path's must be unchanged across the read,
  otherwise nothing is cached); until that finishes the new identity has no
  evidence and every route that needs it refuses *before changing any state*.
  Nothing is trusted by hashing: the real digest must still equal the configured
  one, and a process that started before the file's last change is never proven
  loaded.
- **Legacy configuration.** `[[adapters.profiles]]` (stores, executable paths,
  digests and vendor `signature`) still parses as migration input only: the daemon
  derives one harness policy per harness from it (its single namespace and the
  union of the capability flags), logs one `legacy_profile_migrated` line per
  profile, refuses two namespaces for one harness and refuses a configuration that
  carries both forms, and nothing in a legacy entry authorizes a store or an
  executable. The vendor signature checker is removed. A legacy `[[adapters.owner_relays]]`
  table is parsed and discarded (it authorizes nothing, joins no digest cache and takes no
  part in owner admission) and logged as `legacy_owner_relays_ignored`, also shown by
  `bridge doctor`.
- **Journal compatibility and rollback.** The route journal rows gained optional
  fields: `wake` (the idle proof, written on every Desktop idle owner hook),
  `pending` (read for compatibility only; never written, and such rows are dropped on restore)
  and, for OpenCode rows only, `role` (root or child, taken from the session's own hook).
  Rows deny unknown fields, so a daemon of an earlier
  build refuses to start on a journal that contains them: rolling back needs a journal
  written by that build or a fresh one. No migration rewrites rows and no schema changes. Absent
  fields read as before, except that an OpenCode row without `role` (written by an earlier
  build) is restored with message withheld until the address's own next hook.
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
  addressed actor with inject granted by the harness policy, the channel calls `drain_inject`
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
  uncertain channel rather than replaying it. The chain is Rust peer, then its direct
  signed Node parent, then the Codex harness. That single Node hop is skipped when
  identifying the Codex harness only if the Rust peer's actual direct kernel parent is
  the owner Node process, that process's current canonical kernel executable equals
  `CODEX_MCP_NODE_PATH` from its own preserved exec-time environment, that environment
  carries the application tools pipe, and the Rust peer's `BRIDGE_DESKTOP_PARENT_PID`
  equals the Node process's PID. No hook or non-Codex process is exempt, and there is no
  other automatic Node exemption; explicitly configured `intermediates` keep their
  existing validation.
  Old frontend builds cannot mask the active build during rolling updates.
  The confined CLI queue helper retains its cleared environment and restrictions.
  The native-client and Desktop regression tests require an explicitly prepared absolute
  `BRIDGE_TEST_NODE`; some skip and the deterministic Desktop regressions fail without it. Node is never downloaded.
  Only read-only tool discovery and that one exact message operation are sent,
  under one eight-second connect/read/write deadline. The rendered message text is
  at most 98304 bytes and the private frame between daemon and frontend at most
  197696 bytes (one bound shared by the Rust and JavaScript sides); text may
  contain only tab, newline and carriage-return control characters, and thread
  and call ids are nonempty, at most 256 bytes and control-free. Anything larger
  or malformed is refused before any write. A positive native success
  is acceptance only. Any failure after the message request starts is unknown,
  retained and never followed by a second ordinary-queue send.
- **Codex CLI message**: `sandbox-exec -p '(version 1)(allow default)(deny
  network*)(deny process-fork)' <the binding's Codex executable> app-server --listen
  stdio://` with a scrubbed environment and `CODEX_HOME` = the attested store;
  only `initialize`, `initialized` and `thread/queue/add` are sent. One total
  budget bounds the exchange: a watchdog kills the helper at the deadline
  (unblocking a stalled write), notifications never extend it, and the helper
  is always killed and reaped. Failure
  before the add is written is known-unsent. After the write, only a success
  whose `queuedSubmission` echoes the same `clientUserMessageId` is
  acceptance; every native error (including validation-like and generic
  internal errors, which can follow a queue effect), a malformed success and
  silence are unknown. No error of the Codex build counts as proof of
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
  message id is assumed and absence never retries. One manifest is one inbox
  message of at most 98304 bytes (the core framing bound; larger refuses before
  any write, never chunked or truncated), so a core-admitted body, including a
  full 16 KiB body whose escaping and wrapper fit that bound, is sent. A session descriptor
  without an inbox (restricted session) is positive disablement: the
  message capability is withdrawn and recorded in core, so later message
  publications refuse before acceptance; a missing descriptor is only a
  transient hold. An inbox that appears later in the same incarnation
  restores the capability only if the harness policy supports `message`
  (a policy with `message = false` stays refused). Every such change is
  recorded in core first and applied to the registry only after that
  succeeded (a failed core write is retried, never left half-applied), and
  only to the exact binding observed: a renewed epoch or incarnation since
  the observation makes it a hold and a re-attestation. Withdrawn
  bindings the harness policy grants message to are re-checked every 2 s even with nothing pending
  (publications refuse while message is withdrawn, so no dispatch would
  otherwise look). A daemon restart
  forgets callbacks; core's recheck deadlines then raise incidents, never
  replays (a stopped carrier removes its own callback sockets). A manifest
  over 98304 bytes is refused before any write; native acceptance of larger
  payloads is not qualified (see `docs/qualification.md`).

## Configuration

`bridge-native-daemon <config.toml>` takes the core configuration plus:

```toml
[adapters]
channel = "/abs/private-0700-dir/channel.sock"
sandbox = "/usr/bin/sandbox-exec"          # default
host_id = "this-host"
# intermediates = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/usr/bin/env"]
# max_call_age_ms = 600000

[[adapters.harnesses]]                      # one policy per harness product
harness = "ClaudeCode"                      # or "Codex"; OpenCode example below
namespace = "claude-main"                   # native_store_namespace of addresses
inject = true
message = true

[[adapters.harnesses]]
harness = "OpenCode"
namespace = "opencode-main"
inject = false                              # no OpenCode context injection
message = true                              # owner + lifecycle plugin required
# executable_markers = ["opencode"]         # optional; default is the product name

[[adapters.relays]]                          # optional: root MCP daemon build
path = "/abs/root-mcp-daemon"
sha256 = "<64 hex>"
```

**Native owner route (`owner` module).** When the attested harness's own environment
names `BRIDGE_NATIVE_OWNER_SOCKET`, the carriers select that route before the Codex
helper, the application frontend and the Claude inbox, and never fall back after
selecting it. The route needs a positively idle recipient (a Claude recipient needs no
inbox descriptor), a canonical private socket, a connected peer that is the exact direct
parent (PID, start, user) of the harness running a trusted executable (a regular file owned
by that user or root, not writable by group or other, unchanged since the owner started; no
path or digest is configured and a legacy `owner_relays` entry is ignored). An
absent locator preserves Codex/Claude legacy routes; OpenCode requires the owner
and has no legacy fallback. A present malformed, non-UTF-8,
untrusted or unavailable one, or an unreadable environment, holds. One six-key request
and one five-key receipt cross the socket under one absolute 35-second budget, which the
core attempt must still cover before connecting and immediately before the first byte.
Only a correlated accepted receipt of the harness's own protocol is native acceptance
(not context or processing); a known-unsent receipt needs a finite reason; everything
after the write is an unknown outcome that is retained and never resent. The route is
tested with a scripted stand-in owner and bounded real supervisor canaries; see
the exact candidate scopes in the [qualification matrix](../../docs/qualification.md).

Install `bridge-hook <channel> claude-code` (or `codex`) as the command of the
`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
`PermissionRequest`, `Notification`, `Stop`, `SubagentStop` and `SessionEnd`
hooks. Installation into working applications is a separate, explicitly
authorized step; nothing here installs anything.

For managed OpenCode 2.0.28, use the first-party lifecycle plugin instead of
installing Codex/Claude hook settings. The installed entrypoint is
`<home>/current/plugins/opencode/index.js`; its supervisor must consume the exact
canonical release path and SHA-256 from activation's `plugin_binding`, with
absolute `channel` and `hookCommand` options and its native owner socket. The
plugin observes prompt, tool and execution events without rewriting prompts.
OpenCode delivery is message-only through that owner; standalone root MCP,
child wake and context injection are unqualified. See the [configuration
reference](../../docs/configuration.md#native-owner-route).

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
| Q2 Claude hooks, caller, inject, `later`, pause | small, low effort, budget-capped | `node qualification/claude-native-probe.cjs` | `checks.json` with no failures: closed native tool inventory and manual permissions; root and child attested from the real tool-use id; the hook-injected marker quoted while a planted project-memory canary is absent; a message of exactly 16384 UTF-8 payload bytes (`message_payload_exact_16384_utf8_bytes`) answered in a distinct unprompted turn with actor-bound evidence; pause applied with the event held and no turn in the paused window; a distinct turn after resume. |
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
revalidates the same PID/start time, UID, recorded executable (a trusted,
non-writable file unchanged since the process started) and canonical owner-only native
store and the current harness policy, then renews the endpoint epoch and records the fence in core
before serving. Lifecycle remains the last verified owner state: unknown and
approval/input waits are never converted to idle. Retired, dead/reused-process,
changed-store or policy-less routes cannot be restored. Caller records,
sealed proofs, native inbox secrets and message payloads are never in the cache.
An OpenCode root recorded as such keeps its message capability across a restart without
a new hook. An OpenCode child, or an OpenCode row written by an earlier build (which does
not say whether it is a root or a child), is restored with message withheld, so core
refuses a message to it before acceptance. The address's own next hook renews it: a root
regains message and a child stays withdrawn. For an idle OpenCode root restored from an
earlier build's journal this is a one-time wait for its own hook; later restarts restore it
automatically.

An already observed live recipient can therefore receive an addressed message
without any post-restart bridge_me or hook from the recipient. Recipient native
endpoint/receipt checks still run before actual delivery. Earlier uncertain
hand-offs remain retained and are never replayed by route recovery. The native
boundary test covers delivery without recipient activity, larger renewed epochs,
input-wait preservation, retired/dead routes, changed executable or policy and private
file protection. Successful native hooks initialize this snapshot. A missing
interactive Claude recipient, including a session opened before this format,
is not created from a native session descriptor: an address is registered only by the
harness's own hook. A known live route stuck at `Unknown` is re-observed from its bounded
owner-owned native session descriptor after rechecking the live process UID/start time,
descriptor age and exact canonical native store. Only native status supplies lifecycle;
unknown/input waits stay held. Retired bindings are never overwritten, and discovery
grants no MCP caller identity or proof.

A saved *live* route is restored with a strictly larger epoch and capabilities narrowed to
the harness policy. A row written by the removed vendor verification (`pending`) was never
proven and is dropped. Identity and lifecycle stay distinct: for a Codex Desktop route that
carries an unspent idle proof, the route is `Unknown` and held until the harness's own next
hook or its unspent idle proof (the exact transcript stamp from the earlier
positive idle), re-read unchanged at attest and again at the last write before the native
byte (message only, no inject, one-shot, spent before the write); a transcript that grew
or was replaced meanwhile, a turn, a permission wait or a hook that moved the lifecycle
holds.

A known Claude route stuck at `Unknown` is likewise not trusted from its saved state:
the next attest re-observes the owned native session descriptor and sets the lifecycle
only from a descriptor that positively reports `idle` or `busy` for exactly the recorded
session, PID and start time, executable and store, written at or after the process start;
an unknown-status, stale, other-store, other-PID or reused-PID descriptor, a retired,
held, input-waiting or already observed route change nothing. No hook,
caller or inject is manufactured and the epoch is unchanged. This keeps the address and its
history instead of dropping and rediscovering it. A recorded PID counts as
the same incarnation only with its exact recorded start time: a reused PID is a different
process, never authority, and its route survives only as an unspent idle-proof gateway
candidate of the same configured thread and store.

### Idle Codex Desktop recipient after an application restart

After an application update or restart the Desktop harness is a new process and an
idle thread fires no hook, so the recorded incarnation is gone and nothing renews
the binding. A queued message to such an address is delivered through a MESSAGE-only
**physical gateway** instead, with no caller, call or inject authority and no rebinding
of the recorded harness (the thread's own next hook renews the binding the ordinary
way). The route needs all of:

1. The owner's own hook last left the lifecycle positively `Inactive` on a Desktop
   harness (the application's native pipe in its environment). That stamps a private
   *wake proof* binding the retained transcript's device and inode, length, nanosecond
   modification and status-change times, a SHA-256 of its last 64 KiB and the thread id
   read from its own `session_meta` header, all from one opened descriptor whose
   metadata is unchanged across the read and whose path still resolves to the same owned
   regular file. Every other lifecycle and a renewal clear it; a `SessionEnd` keeps the
   proof stamped before it only under the existing narrow retired-Desktop idle exception
   (positive pre-end idle and the same transcript inode), and any other retired binding
   is never eligible.
2. The recorded incarnation is dead.
3. The transcript reads back with exactly the stamped identity, length, times, tail and
   thread id. No time window is ever substituted for this proof; a write anywhere in the
   file moves its status-change time, which a program cannot set back, so even a
   same-length rewrite of the middle holds.
4. Exactly one distinct live Desktop harness that started after the recorded one, from the
   recorded executable (unchanged since it started) and store, owns a probe-verified frontend; zero or
   several hold.

The gateway is committed with a fresh, strictly larger endpoint epoch, journaled before core
fences it and before any send, and every fact is proven again on attest and on send; a
failed journal write restores the previous binding. The proof is one-shot and is spent in
the journal *before* the first native write: a spend that cannot be recorded sends nothing
(known-unsent; the next attempt must record the removal again before any write). After
that durable reservation, and again at the last pre-write boundary (after the frontend
connection, the peer-ancestry proof and the request frame are prepared, with no registry
lock held), a fresh fence re-proves the binding at exactly its epoch, the dead recorded
incarnation, the live gateway and the exact transcript stamp: a hook that
renewed the binding, a new turn or permission wait, or any transcript change makes the
hand-off known-unsent with zero native bytes written. Only such a refusal, and only while
the same fence still holds and the journal accepts it, gives the proof back; an accepted or
possibly delivered hand-off never does, so neither a crash nor a restart nor a
different queued message can revive it. An unspent proof survives a daemon restart that
happens while the application is down (the journal restore keeps a gone Codex incarnation
only while it carries one); a spent one is gone. Active, awaiting-input, unknown, ended,
changed-transcript, duplicate-gateway, other-store and live-old-incarnation cases hold, and
an uncertain event is retained and never resent or re-homed. Pre-change journal rows carry
no proof and are not eligible until the next owner idle hook. Known limits: a real resumed
turn that has not yet appended to the transcript cannot be seen from the filesystem, and
the host's flush order after `Stop` is unobserved (a late append only invalidates the stamp
and holds), so a fixed read-only native thread-state query remains the required
qualification step before claiming native idle proof. This route is tested with synthetic
native-owner input only and is not native-qualified.

Codex application frontends use a versioned private protocol, independently of
release build labels. A daemon update prefers its current build but can retain
an older labelled frontend under a primary Node process; kernel PID/incarnation,
protected channel and native signed-client checks still apply. An unavailable
frontend holds before reservation, so reconnection consumes no delivery retries.
Discovery reads the whole protected directory, examines only frontend-shaped names
whose PID the OS lists (so thousands of stale entries or one non-UTF-8 name neither
hide a current frontend nor cost a connection each) and probes the socket peer's
kernel PID. A frontend whose signed parent channel closed, whose parent exited or whose
hand-off outcome became unknown retires its own advertisement by unlinking only its
own socket inode within about half a second; a foreign or newer file at the name is
never removed, a live listener on the name blocks binding, and the leftover of a dead
one (connection refused) is replaced.

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
