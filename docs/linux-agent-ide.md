# Linux ARM64 Agent IDE integration candidate

This is a development handoff, not a native wake qualification. Linux process
fixtures prove the protected MCP transport and owner boundary; a real Codex
0.164.0 or OpenCode 2.2.5 session must still produce the receipts below. No
provider credential, previous session store or model response belongs in this
bundle. The [configuration reference](configuration.md) defines all TOML fields.

## Executables and private paths

The release build produces `bridge`, `bridge-hook`, `bridge-native-daemon`,
`bridge-root-mcp`, `bridge-root-relay` and `bridge-daemon`. Use
`bridge-native-daemon` for IDE delivery: it contains core custody plus the native
adapter channel/carriers. Plain `bridge-daemon` has no native adapter; do not run
both against one database/socket. Root MCP/relay are optional for IDE's direct
producer path and do not substitute for a native owner.

Build from the pinned dirty candidate and committed lockfile:

```sh
cargo +1.98.1 build --offline --locked --release \
  -p bridge-core -p bridge-adapters -p bridge-interfaces \
  --bin bridge --bin bridge-hook --bin bridge-native-daemon \
  --bin bridge-root-mcp --bin bridge-root-relay --bin bridge-daemon
```

Choose an immutable bundle directory as `BRIDGE` and a short, canonical,
operator-owned directory as `STATE`. The examples use `/ABS/bridge` and
`/ABS/state`; replace them consistently. Prepare directories before launch:

```sh
BRIDGE=/ABS/bridge
STATE=/ABS/state
umask 077
mkdir -p "$STATE/native" "$STATE/secrets" "$STATE/tmp" "$STATE/home" \
  "$STATE/codex" "$STATE/opencode" "$STATE/mcp-context" "$STATE/owners"
chmod 700 "$STATE" "$STATE/native" "$STATE/secrets" "$STATE/tmp" \
  "$STATE/home" "$STATE/codex" "$STATE/opencode" "$STATE/mcp-context" "$STATE/owners"
export TMPDIR="$STATE/tmp" TMP="$STATE/tmp" TEMP="$STATE/tmp"
```

Private provisioning creates `secrets/ide-producer.token`,
`secrets/operator.token` and, only if root tools are enabled,
`secrets/root-relay.token`. Each is a real owner-only `0600` file. The daemon's
`0600` TOML holds the corresponding grant values; it does not expand environment
variables or read a grant `token_file`. Materialize that private file at runtime
from the operator's secret provisioning, never inside an image/public artifact.
IDE receives only the producer credential file path, never a model argument.

## Daemon and IDE configuration

The following is a template, not a file containing usable credentials:

```toml
database = "/ABS/state/bridge.db"
socket = "/ABS/state/core.sock"
[limits]
max_admitted_events = 10000

[[grant]]
token = "<runtime value from private ide-producer.token>"
publisher = "agent-ide"
recipients = ["*"]
kinds = ["ide.test.finished", "ide.edit.checked", "ide.job.finished", "ide.job.lost"]
modes = ["message"]
policies = ["keep_all"]
[grant.producer_v1]
direct_address = true
delivery_scopes = true
native_scopes = ["linux-arm64/codex/codex-linux", "linux-arm64/opencode/opencode-linux"]

[[grant]]
token = "<runtime value from private operator.token>"
publisher = "bridge-ops"
admin = true
recipients = []
kinds = []
modes = []
policies = []

[adapters]
channel = "/ABS/state/native/c.sock"
host_id = "linux-arm64"
[[adapters.harnesses]]
harness = "Codex"
namespace = "codex-linux"
inject = false
message = true
[[adapters.harnesses]]
harness = "OpenCode"
namespace = "opencode-linux"
inject = false
message = true
```

The example permits dynamic session addresses only within the two exact
`native_scopes`; narrow `recipients` to exact native session addresses when they
are known. Recipient grants support exact addresses or `"*"`, not glob prefixes.
The namespace is a logical policy label;
`CODEX_HOME` and the parent of `OPENCODE_DB` must independently be real canonical
private native stores. Never derive either store or actor from the worktree.

Add this object to the trusted Agent IDE launcher template:

```json
{
  "bridge": {
    "registration_socket": "/ABS/state/native/c.sock",
    "core_socket": "/ABS/state/core.sock",
    "credential_file": "/ABS/state/secrets/ide-producer.token",
    "native_stores": [
      {"harness":"codex","host":"linux-arm64","store":"codex-linux"},
      {"harness":"opencode","host":"linux-arm64","store":"opencode-linux"}
    ]
  }
}
```

The actual actor comes only from a validated native IDE binding. These literal
host/store values must match the daemon policy and grant scopes. Direct address
delivery requires no fabricated `DirectMcp` capability or caller registration.
It grants no workspace, source-read, edit or execution authority.

Run and stop the actual foreground daemon with an owned PID:

```sh
"$BRIDGE/bin/bridge" version
"$BRIDGE/bin/bridge-native-daemon" "$STATE/daemon.toml" &
bridge_pid=$!
# Native channel: $STATE/native/c.sock; producer custody: $STATE/core.sock.
# Run the authorized native canaries, then drain and reap this exact child.
kill -TERM "$bridge_pid"
wait "$bridge_pid"
```

For optional root tools, provision a separate root publisher grant, its relay
build digest and the [interfaces configuration](configuration.md#interfaces-configuration).
Then run `bridge-root-relay /ABS/state/interfaces.toml` and configure the native
stdio command `bridge-root-mcp /ABS/state/native/c.sock /ABS/state/relay.sock`.
These tools require actual protected caller metadata/hooks. Standalone OpenCode
root-tool qualification remains separate from IDE's producer path.

## Native hosts, plugin and protected MCP proxy

Tool Test owns the real harness adapter/supervisor. It must be the native
process's actual direct parent, retain the live native input channel and create
a canonical private owner socket before launching that process. There is no
`owner-supervisor` executable or invented owner CLI in this Bridge bundle.
A shell setting a locator does not implement the owner protocol.

For Codex, the adapter sets `CODEX_HOME=/ABS/state/codex` and
`BRIDGE_NATIVE_OWNER_SOCKET=/ABS/state/owners/codex.sock` in the actual Codex
0.164.0 process, retains its `app-server --listen stdio://` connection and
executes only real native input operations. Install genuine Bridge hook commands
`bridge-hook /ABS/state/native/c.sock codex` for the supported SessionStart,
PreToolUse, PostToolUse, Stop and SessionEnd events. Compose them with Agent IDE's
own hooks generated by `agent-ide codex-hooks print`; do not fabricate hook
payloads, call IDs or idle events. IDE's managed command is
`agent-ide mcp --launcher-template /ABS/state/ide-launcher.json`.

For OpenCode, the adapter sets `OPENCODE_DB=/ABS/state/opencode/opencode.db` and
`BRIDGE_NATIVE_OWNER_SOCKET=/ABS/state/owners/opencode.sock` on the actual native
2.2.5 server process and retains its real session input API. Configure the plugin
with the directory containing the verified immutable `index.js` and
`package.json`, using the actual 2.2.5 `plugins` form:

```json
{
  "plugins": [{
    "package": "/ABS/bridge/plugins/opencode",
    "options": {
      "channel": "/ABS/state/native/c.sock",
      "hookCommand": "/ABS/bridge/bin/bridge-hook",
      "contextDirectory": "/ABS/state/mcp-context",
      "mcpServers": ["agent_ide"]
    }
  }]
}
```

An individual configured JavaScript file is ignored by the 2.2.5 loader. Native
plugins initialize lazily: on the same live server/location initialize the agent
catalog, then inspect `plugin.list`; require `agent-bridge` with
`features.server=true` and `state.status=active`. This proves setup, not a model
call or wake. The plugin supports the exact inspected 2.0.28 and 2.2.5 contracts;
unknown versions refuse.

Set the `agent_ide` native stdio server's command/arguments to:

```text
/ABS/bridge/bin/bridge-hook mcp-proxy /ABS/state/mcp-context agent_ide /ABS/agent-ide/bin/agent-ide mcp --opencode-launcher-template /ABS/state/ide-launcher.json
```

The proxy preserves the MCP backend's direct native parent. Only that native
PID/UID/birth can submit protected ToolContext. Exact native session, tool name
and arguments must match; then the proxy supplies one
`ai.agent_bridge/toolCallID` alongside native `ai.opencode/sessionID`. Session-only,
mixed-host, conflicting, missing or reused context refuses without forwarding.
The plugin leaves original permission checks, arguments, output and errors intact.
IDE uses distinct OpenCode host/replay/generation state and reconciles registered
sources at managed read boundaries. OpenCode problem feedback rides IDE replies;
Bridge's lifecycle observations are not an IDE post-hook delivery claim.

## Owner wire contract and required receipts

The socket is `0600` inside a canonical same-user `0700` directory. A read-only
probe must accept connection/EOF without starting native input. A delivery has
one four-byte little-endian length plus one strict JSON object, at most 1 MiB.
The six request keys are `thread_id`, `call_id`, `text`, `native_pid`,
`native_start_time`, `wake_only:true`; text is the immutable manifest, at most
98304 bytes. Verify the exact native actor/incarnation and positive idleness
before one native effect. Do not answer permission requests for the agent.

The five required receipt keys are `call_id`, `state`, `protocol`, `native_id`,
`reason`. `accepted` requires the same call ID, protocol `codex_turn` or
`opencode_input`, a genuine native turn/input ID and `reason:null`.
`known_unsent` requires null protocol/native ID and an agreed bounded reason;
`unknown` retains possible effects and must never trigger an automatic replay.
See [the native owner contract](../crates/bridge-adapters/src/owner.rs) for exact
reason sets. One absolute 35-second exchange budget is not renewed by partial I/O.

The current owner peer must be the native process's exact direct parent with
matching UID, birth and trusted unchanged executable. Actual executable mtime and
ctime must predate process birth; start a freshly provisioned owner only after that
condition can hold. Never backdate a file or rewrite process facts to pass it. A socket bound by the
OpenCode plugin itself has the same PID as the native process and fails that
parent check. Although the actual SDK has `ctx.session.prompt`, this bundle does
not treat a same-process socket as a parent or claim a built-in OpenCode owner.
Without a real Tool Test owner, automatic wake is unavailable.

On Linux a missing confinement launcher disables only Codex's legacy queue helper;
a positively verified owner remains eligible. No owner plus no confinement holds
before any native attempt. Missing/malformed/stale owner evidence never falls back.
Do not create a fake `sandbox-exec` or substitute an unconfining executable.

Tool Test must retain, for each real host, the exact bundle/source/config hashes,
genuine MCP metadata and corresponding lifecycle identity, one accepted IDE job,
Bridge custody/attempt/owner receipt with its real native ID, and evidence that
the same native session made a new step and consumed the job marker. Collect a
missing-context/foreign-owner denial, replay denial and cleanup confirmation.
`native_accepted`, an active plugin, fixture receipt or successful build alone is
not context observation, model processing or an end-to-end PASS.
