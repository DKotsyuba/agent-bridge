# Getting started

This guide takes a clean macOS machine from source to a running Bridge with one
native session able to send and receive. It builds and installs from your own
checkout. The installer downloads nothing and extracts no archive; it trusts only
the `SHA256SUMS` digest you pass it. A hash is not a signature: the digest of your
own build is the strongest trust available. If the project's release page offers a
prebuilt bundle, unpack it into a new directory yourself, take its digest from the
release notes through a channel you trust, and use it in step 3 in place of a local
build.

## 1. Prerequisites

| Need | Why |
|---|---|
| macOS on Apple silicon | the only supported platform (`install.sh` refuses others) |
| Xcode command line tools (`xcode-select --install`) | linker, `/usr/bin/curl`, `/usr/bin/shasum`, `/usr/bin/sandbox-exec` |
| [rustup](https://rustup.rs) with Rust 1.98.1 | pinned in `rust-toolchain.toml` |
| A short directory you own for `TMPDIR` | Unix socket paths are limited to about 100 bytes |
| An exact Codex, Claude Code or managed OpenCode build, run as the same user | the native session you want to reach; OpenCode 2.0.28 requires a supervisor/owner and lifecycle plugin; see the [qualification matrix](qualification.md) |
| Node.js (to run the full tests) | the full workspace tests need an absolute `BRIDGE_TEST_NODE` for the deterministic Desktop regressions, and native probes use Node; building, installing and running Bridge or the SDK does not |

The daemon, hook and relay are ordinary user processes. Nothing needs `sudo`,
and Bridge never edits your harness configuration for you.

## 2. Build and test

```sh
rustup toolchain install 1.98.1 --profile minimal -c rustfmt -c clippy
cargo +1.98.1 fetch --locked                     # the only step that uses the network
export TMPDIR="$HOME/.agent-bridge-tmp" TMP="$HOME/.agent-bridge-tmp" TEMP="$HOME/.agent-bridge-tmp" && mkdir -p -m 700 "$TMPDIR"
BRIDGE_TEST_NODE="$(command -v node)" cargo +1.98.1 test --offline --workspace
```

The tests use synthetic state only (temporary databases, private sockets, fixture
processes); they do not touch your sessions, hooks or any model. Full checks are
listed in the [README](../README.md#checks).

## 3. Package and install

```sh
cargo +1.98.1 xtask package
```

This builds every binary in release mode (offline, locked) and writes a verified
bundle, including exactly the OpenCode plugin's `index.js` and `package.json`,
to `dist/agent-bridge-0.3.0+<label>`, where the label is the 12-digit Git
commit (`-dirty` when the tree has changes; pass `--label NAME` outside a Git
checkout). It prints the manifest and `sums_sha256`. Install with that digest,
passed exactly as printed:

```sh
./install.sh --bundle "$PWD/dist/agent-bridge-0.3.0+<label>" --sums-sha256 <sums_sha256> \
  --home "$HOME/.agent-bridge" --bin-dir "$HOME/.local/bin"
```

`install.sh` copies the bundle to a private temporary directory, checks
`SHA256SUMS` against your digest and every file against `SHA256SUMS` before running
anything from the copy, then seals the release under `<home>/releases/` and switches
`<home>/current` atomically. It prints a `relay_binding` (the real release path and
SHA-256 of `bridge-root-relay`) that you need in step 5. The home must be new, empty
or an existing Bridge home owned by you and not writable by anyone else.

The stable user-facing OpenCode entrypoint is
`<home>/current/plugins/opencode/index.js`, with `package.json` beside it.
Activation also reports `plugin_binding`: supervisors must consume its exact
canonical release path and SHA-256, not the moving `current` path. Legacy
plugin-less releases still install and roll back; their binding is `null`.

To rehearse the whole install/upgrade/rollback cycle in a throwaway prefix without
touching your installation, a harness or the network:

```sh
cargo +1.98.1 xtask qualify --prefix "$TMPDIR/bridge-qualify"   # the prefix must not exist
```

## 4. Private state and credentials

Choose one state root and keep it private. Sockets live in directories that must
be mode `0700`; secret files must be regular files owned by you with no group or
other access.

```sh
STATE="$HOME/.agent-bridge-state"
mkdir -p -m 700 "$STATE" "$STATE/ch" "$STATE/rl" "$STATE/secrets"
( umask 077; openssl rand -hex 32 > "$STATE/secrets/relay-token"
              openssl rand -hex 32 > "$STATE/secrets/operator-token" )
```

Grant tokens are bearer secrets of at least 16 bytes. The same value must appear in
the daemon configuration (as the grant `token`) and in the matching token file read
by the relay or the operator CLI. Keep short socket paths: `$STATE/core.sock`,
`$STATE/ch/c.sock` and `$STATE/rl/relay.sock` all fit.

## 5. Configure

Write two files (full field reference: [Configuration](configuration.md)).

`$STATE/daemon.toml` configures the core, its grants and the native adapters:

```toml
database = "/ABS/state/bridge.db"
socket   = "/ABS/state/core.sock"

[limits]
max_admitted_events = 10000

[[grant]]                        # restricted root MCP backend (publisher realm)
token = "<contents of secrets/relay-token>"
publisher = "bridge-root"
recipients = ["*"]               # or exact canonical addresses
kinds = ["bridge.message"]
modes = ["message", "inject", "auto"]
policies = ["keep_all"]

[[grant]]                        # operator (never publishes)
token = "<contents of secrets/operator-token>"
publisher = "bridge-ops"
admin = true
recipients = []
kinds = []
modes = []
policies = []

[adapters]
channel = "/ABS/state/ch/c.sock"
host_id = "this-host"

[[adapters.harnesses]]           # one policy per harness product; no store or executable
harness = "ClaudeCode"           # or "Codex"; OpenCode example below
namespace = "claude-main"
inject = true                    # hook injection is supported for this harness
message = true                   # and its message carrier

[[adapters.harnesses]]
harness = "OpenCode"
namespace = "opencode-main"
inject = false                   # OpenCode is message-only
message = true                   # requires owner + lifecycle plugin

[[adapters.relays]]              # the relay_binding printed by the installer
path = "/ABS/home/releases/<version>+<label>/bin/bridge-root-relay"
sha256 = "<64 hex>"
```

`$STATE/interfaces.toml` configures the relay and operator CLI:

```toml
core_socket = "/ABS/state/core.sock"

[operator]
token_file = "/ABS/state/secrets/operator-token"

[root]
socket = "/ABS/state/rl/relay.sock"
token_file = "/ABS/state/secrets/relay-token"
channel = "/ABS/state/ch/c.sock"

[[root.callers]]
host_id = "this-host"
harness = "claude-code"
native_store_namespace = "claude-main"
recipients = ["*"]
modes = ["message", "inject", "auto"]
kinds = ["bridge.message"]
```

No store path or harness executable is configured: a fresh session in any canonical store
you own (not writable by group or other) registers from its own lifecycle hook, and updating
the harness needs no configuration change. A configuration written for the earlier
per-store `[[adapters.profiles]]` still loads as migration input; see the [configuration
reference](configuration.md#migrating-a-configuration-written-for-store-and-build-allowlists).

## 6. Start

```sh
bridge service start core  --home "$HOME/.agent-bridge" --state "$STATE" --config "$STATE/daemon.toml"
bridge service start relay --home "$HOME/.agent-bridge" --state "$STATE" --config "$STATE/interfaces.toml"
bridge doctor --home "$HOME/.agent-bridge" --bin-dir "$HOME/.local/bin" --state "$STATE" \
  --config "$STATE/interfaces.toml" --daemon-config "$STATE/daemon.toml"
```

(`bridge` is in `~/.local/bin`; add it to `PATH` or use the full path.) `doctor` exits
0 when no check failed, 2 when one did. Its declared adapter capabilities and
Telegram are always reported `not_verified`: they are configuration, not proof.
Stop with `bridge service stop relay|core ...`; stopping never touches custody or
configuration.

## 7. Connect a native session

Codex and Claude use their own hooks and a restricted MCP server for sending.
Managed OpenCode 2.0.28 requires its first-party lifecycle plugin and an exact
direct-parent native owner exposing `BRIDGE_NATIVE_OWNER_SOCKET`; the supervisor
must load the installed `plugin_binding` path/hash from step 3, with absolute
`channel` and `hookCommand` options. Its native store is a private canonical
parent of `OPENCODE_DB`. OpenCode has no inject/context path or qualified standalone
root MCP path; use the v1 producer API for publication. These integrations are
deliberate manual steps; packaging does not activate them in working applications.

1. **Hooks.** Set `bridge-hook <channel> claude-code` (or `codex`) as the command of
   the `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
   `PermissionRequest`, `Notification`, `Stop`, `SubagentStop` and `SessionEnd`
   hooks. For Claude Code, in the settings file you choose:

   ```json
   { "hooks": { "SessionStart": [ { "hooks": [
     { "type": "command", "command": "/ABS/bin/bridge-hook /ABS/state/ch/c.sock claude-code" }
   ] } ] } }
   ```

   Repeat the entry for each event. The hook always exits 0 and prints nothing unless
   Bridge hands it a message, so a missing Bridge never blocks the harness. Codex uses
   the same command with the `codex` argument in its own hook configuration; Codex
   requires hook trust, see the [adapter guide](../crates/bridge-adapters/README.md).
2. **Root MCP (to let the session send).** Register
   `bridge-root-mcp /ABS/state/ch/c.sock /ABS/state/rl/relay.sock` as an MCP server of
   the harness; for Codex also pre-approve exactly its three tools. Details and the
   refusal classes are in the [interfaces guide](../crates/bridge-interfaces/README.md).
   The session gets exactly `bridge_me`, `bridge_send` and `bridge_status`.
3. **Receiving does not need enrollment.** A recipient needs no `bridge_me` call and no
   manual session registration: a session that has a verified native route (a
   hook binding of a marked harness process under the harness policy) can be addressed. An unknown,
   dead, permission-waiting or unattested recipient is a visible hold, and an
   uncertain delivery is never resent for you.

## 8. Send and observe

From an attested session, ask it to call `bridge_send` with the recipient's canonical
address and a message, then `bridge_status` with the returned `request_id`. Repeat the
**same** `request_id` after a lost answer; never invent a new one for the same message.
Operators observe with the CLI:

```sh
bridge operator "$STATE/interfaces.toml" counts
bridge operator "$STATE/interfaces.toml" incidents
bridge operator "$STATE/interfaces.toml" holds
```

For what each status and incident means and how to resolve an uncertain delivery,
read the [operator recovery guide](../crates/bridge-interfaces/README.md#operator-recovery-guide).

## 9. Integrate your own producer

New tools publish through the v1 protocol or SDK with a dedicated grant and
explicit permissions; see [Producer integration](producer-integration.md).

## 10. Upgrade and roll back

Run step 3 again with the new bundle, update the relay binding in `daemon.toml` and
the OpenCode supervisor's plugin binding from activation, then
restart both services (activation never restarts daemons). `bridge rollback --home H`
switches program code back; the custody database, incidents and configuration stay, and
a release with an older core schema than one already activated is refused.
