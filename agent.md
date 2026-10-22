# Agent guide

Orientation for AI coding agents and new contributors working in this
repository. [AGENTS.md](AGENTS.md) is the short form; [README.md](README.md) is
the user-facing entry point and [CONTRIBUTING.md](CONTRIBUTING.md) the human
process.

## What this is

Agent Bridge is a local durable message service for Codex, Claude Code and managed OpenCode
sessions: producers publish events to an exact native address, Bridge keeps them
in SQLite custody and delivers them through native hooks or queues, and every
uncertain outcome is retained for a manual decision. Source version 0.3.2,
producer API v1, storage schema 6, macOS on Apple silicon only.

## Map

| Area | Where | Notes |
|---|---|---|
| Custody, dispatch, recovery, service | `crates/bridge-core/src` | `types`, `schema`, `storage`, `dispatch`, `recovery`, `universal`, `service`, `wire`, `framing` |
| v1 wire contract | `crates/bridge-protocol` | std + serde + sha2 only; fixtures in `tests/wire-v1.json` |
| Producer SDK | `crates/bridge-sdk` | synchronous Unix-socket client; no core or native dependency |
| Native adapters | `crates/bridge-adapters/src` | `registry`, `server`, `codex`, `claude`, `desktop`, hook binary, fixture harness |
| OpenCode lifecycle plugin | `crates/bridge-adapters/plugins/opencode` | Pinned lifecycle plugin and protected MCP transport; managed owner MESSAGE route; no context injection |
| Root MCP, operator CLI, install | `crates/bridge-interfaces/src` | `mcp`, `root`, `operator`, `notify`, `telegram`, `install`, `lifecycle`, `doctor` |
| Packaging and repo checks | `xtask`, `install.sh` | `cargo xtask package`, `qualify`, `check-public` |
| Contracts | `crates/*/docs` | wire v1, core v1, native ingress v1 |

## Commands

```sh
cargo +1.98.1 fetch --locked
cargo +1.98.1 fmt --all --check
cargo +1.98.1 clippy --offline --workspace --all-targets -- -D warnings
BRIDGE_TEST_NODE="$(command -v node)" cargo +1.98.1 test --offline --workspace   # + short owned TMPDIR, see below
RUSTDOCFLAGS="-D warnings" cargo +1.98.1 doc --offline --workspace --no-deps --document-private-items
cargo +1.98.1 xtask check-public
```

Run the narrowest test for what you changed first (`cargo test -p bridge-core
--test dispatch`, for example), then the affected crate, then the gates above.

## Invariants not to break

- **Fail closed.** Unknown, disconnected, permission-waiting, stale or
  unqualified states are visible holds, never idle and never a fallback route.
- **Uncertain means retained.** An attempt that may have reached a recipient
  becomes `outcome_unknown` with an incident. Nothing retries it automatically;
  only an audited operator decision does.
- **No inferred evidence.** Custody, native acceptance, hook emission, context
  observation and processing are separate facts.
- **No authority from labels.** Addresses, PIDs, working directories, names and
  model-written fields are never proof of identity; native proof comes from the
  protected hook, kernel peer credentials, a marked harness process and its
  executable state. Executable digests are checked only for Bridge's own relay,
  and audience builds.
- **Secrets stay out.** No token, credential, payload or parser text that can
  quote one appears in logs, errors, `Debug` output or documentation.
- **Bridge never answers a permission request** for a recipient.
- **Migrations preserve** accepted bytes, hashes, identifiers and uncertain
  attempt history; unknown or newer databases are refused before any Bridge schema or journal-mode change.

## Rules for changes

- Document every declaration (public, private and tests) with a Rustdoc comment
  that states its contract, and keep it current in the same change.
- No new dependencies; the lockfile is the supported set. `unsafe` is forbidden.
- Tests use isolated synthetic state only: temporary databases and sockets,
  scripted carriers, fixture processes. Never touch a real session store,
  hooks, models or the network. Native probes under
  `crates/bridge-adapters/qualification` are manual, paid and out of CI.
- Do not weaken a refusal or widen a trust boundary to make a test pass. When
  a boundary changes, update its document in `crates/*/docs` and its tests.
- Keep documentation public and self-contained: relative links, no personal
  paths, session identifiers, logs or tracker references. `cargo xtask
  check-public` enforces this.
- Do not claim support or qualification you did not observe; see the
  [qualification matrix](docs/qualification.md) for the current honest scope.
