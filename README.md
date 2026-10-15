# Agent Bridge

Agent Bridge is a local, durable message service for coding-agent sessions. A
producer (an agent tool, a CLI, a background worker) publishes an event addressed
to one exact native session of Codex, Claude Code or managed OpenCode; Bridge keeps it in a
SQLite custody store, delivers it through the host's own native path, and
reports honestly what is known. A delivery whose outcome is uncertain is
retained and surfaced for a manual decision; it is never repeated
automatically.

| | |
|---|---|
| Version | 0.3.0 (not published to crates.io; build from source) |
| Producer API | v1 (`bridge-protocol` / `bridge-sdk`), plus the legacy publisher and operator socket API |
| Database | storage schema 6, forward migration only |
| Platform | **macOS on Apple silicon (`aarch64-apple-darwin`) only** |
| Toolchain | Rust 1.98.1, pinned by `rust-toolchain.toml` |
| License | [MIT](LICENSE) |

## What it does

- **Exact routing.** An address names one host, harness, native store and
  session; nothing is routed by working directory, "latest chat" or process name.
- **Three delivery modes.** `inject` hands the message to the recipient's own
  hook while it is active, `message` queues it through a native message path
  while it is idle, and `auto` chooses per delivery. Both requested and
  effective modes are recorded.
  OpenCode supports only `message` through its native owner and lifecycle plugin;
  it has no `inject` or context-injection path.
- **Durable custody and honest evidence.** A receipt proves custody only.
  Native acceptance, hook emission, context observation and application
  processing are separate, never inferred from each other.
- **Visible holds.** A dead, unknown, permission-waiting or unqualified
  recipient is a visible hold with a reason, not a silent drop or a guess.
- **Operator recovery.** Incidents, audited retry/dispose/waive decisions,
  pause/resume and stream-lineage transfer, plus an outbound-only Telegram
  notifier.
- **Producer SDK.** A dependency-light Rust protocol crate and synchronous
  client for new producers, with no producer-specific code in Bridge.

## Support and limits

Bridge supports macOS on Apple silicon only. The core and library crates use
Unix sockets and Unix file semantics, but other operating systems are not
supported and nothing here claims Linux or Windows operation. Native-host
support is per exact build and is explicit in the [qualification
matrix](docs/qualification.md): configuring a harness policy enables a harness, it
is not a qualification result. Nested inner-call MCP paths, host observations and
generic detached Claude consumers are not supported; live Telegram delivery has
not been qualified.

## Quick start

Prerequisites: macOS on Apple silicon, Xcode command line tools, and
[rustup](https://rustup.rs). The pinned toolchain installs from
`rust-toolchain.toml`.

```sh
rustup toolchain install 1.98.1 --profile minimal -c rustfmt -c clippy
cargo +1.98.1 fetch --locked
BRIDGE_TEST_NODE="$(command -v node)" cargo +1.98.1 test --offline --workspace
cargo +1.98.1 xtask package          # prints the bundle manifest and sums_sha256
```

Then follow [Getting started](docs/getting-started.md) to install the bundle,
write private configuration, install the hooks and send a first message.

## Documentation

- [Getting started](docs/getting-started.md): prerequisites, build, test, package, install, first run.
- [Configuration](docs/configuration.md): daemon, adapter, producer-permission and interfaces files.
- [Architecture](docs/architecture.md): custody, dispatch contract, service and lifecycle rules.
- [Producer integration](docs/producer-integration.md): onboarding a new producer with the protocol or SDK.
- [Qualification and support matrix](docs/qualification.md): what was observed, on which builds.
- [Native adapters](crates/bridge-adapters/README.md): trust model, delivery paths, qualification probes.
- [Interfaces](crates/bridge-interfaces/README.md): root MCP, operator recovery, Telegram, install and rollback.
- [Producer SDK](crates/bridge-sdk/README.md): synchronous client and packaging notes.
- Contracts: [wire v1](crates/bridge-protocol/docs/wire-v1.md), [core v1](crates/bridge-core/docs/producer-core-v1.md), [native ingress v1](crates/bridge-adapters/docs/producer-native-v1.md).
- Project: [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), [Changelog](CHANGELOG.md), [agent.md](agent.md), [AGENTS.md](AGENTS.md).

## Repository layout

| Path | Contents |
|---|---|
| `crates/bridge-core` | service library and `bridge-daemon`: types, SQLite storage, framing, dispatch, recovery, wire service |
| `crates/bridge-client` | typed legacy publisher and operator client |
| `crates/bridge-protocol` | dependency-light v1 wire DTOs, validation and fingerprints |
| `crates/bridge-sdk` | synchronous v1 producer client |
| `crates/bridge-adapters` | Codex, Claude Code and managed OpenCode adapters, lifecycle plugin, `bridge-hook`, `bridge-native-daemon`, qualification probes |
| `crates/bridge-interfaces` | restricted root MCP and relay, `bridge` operator and install CLI |
| `xtask` | `cargo xtask package`, `qualify` and `check-public` |
| `install.sh` | installer for a locally built bundle |

## Checks

```sh
cargo +1.98.1 fmt --all --check
cargo +1.98.1 clippy --offline --workspace --all-targets -- -D warnings
BRIDGE_TEST_NODE="$(command -v node)" cargo +1.98.1 test --offline --workspace
RUSTDOCFLAGS="-D warnings" cargo +1.98.1 doc --offline --workspace --no-deps --document-private-items
cargo +1.98.1 xtask check-public
```

Tests use isolated synthetic state: fresh temporary databases, private
short-lived sockets and scripted carriers. They touch no installed application,
no session store and no network. Set `TMPDIR` to a short directory you own
(Unix socket paths are limited to about 100 bytes) and `BRIDGE_TEST_NODE` to an
absolute Node.js executable: the full workspace tests need Node for the deterministic
Desktop regressions (CI uses the runner's preinstalled Node). Node is not needed to
build, run or integrate Bridge or the SDK. Native qualification probes
need real harness builds and paid models, never run in `cargo test` or CI, and
are described in the [adapter guide](crates/bridge-adapters/README.md).
