# Agent Bridge

Shared communication service for the Agent MCP family, Codex and Claude Code.

Implementation has started on the core module (M-001). The authoritative
requirements, decisions, work decomposition and acceptance records are
maintained through Agent Tasks with project alias `agent-bridge`; the family
documentation repository is `../agent-docs/agent-bridge`.

The agreed delivery modes are `inject`, `message` and `auto`:
`auto` selects `inject` for an active recipient and `message` for an inactive one.
An uncertain delivery is retained and reported for manual resolution; it is not
automatically repeated after a possible handoff.

## Workspace layout

- `crates/bridge-core` — the service library and daemon:
  - `types`: canonical event identity — exact native logical address
    (host / harness / native store namespace / native session id),
    envelope with keep_all / latest / batch policy, bounded payload and
    metadata, once-normalized absolute expiry, deterministic canonical
    serialization and the frozen SHA-256 identity-content hash. All
    components are revalidated at every trust boundary (construction,
    canonical decode, raw deserialization, storage admission).
  - `storage`: SQLite durable custody (WAL, synchronous FULL, schema fence)
    with idempotent publication — identical replay returns the original
    receipt, changed identity-content conflicts, monotonic acceptance
    order, latest-stream watermarks scoped by the full coalescing group
    (publisher, recipient, kind, mode, project/task, stream), an admission
    hard cap that never evicts dedup history, and pending-only expiry.
  - `service`: the authenticated local publisher protocol — ndjson over a
    Unix stream socket. Every ingress is authenticated by an integration
    grant before validation, dedup or status disclosure; grants bind the
    publisher identity (stamped by the service, never asserted by the
    caller) and the allowed recipients, kinds, modes and policies.
  - `src/bin/bridge-daemon.rs`: the daemon binary with TOML configuration
    and JSON-lines structured logging on stderr. Protocol-driven drained
    shutdown via an admin grant; OS-signal handling is a documented
    followup of the lifecycle task.
- `crates/bridge-client` — the shared typed client family producers depend
  on: `PublishRequest` (validating builder), `BridgeClient` (publish /
  status over the socket), and re-exports of the canonical types.

A lost publish response is retried by resending the identical event: custody
deduplication returns the original receipt; business work is never restarted
and a producer domain transaction never spans the IPC boundary.

## Building and testing

Pinned toolchain `1.98.1` (see `rust-toolchain.toml`).

```sh
cargo +1.98.1 build --offline --workspace
cargo +1.98.1 test --offline --workspace
cargo +1.98.1 clippy --offline --workspace --all-targets -- -D warnings
cargo +1.98.1 fmt --all --check
```

Tests use only isolated synthetic state (fresh temporary databases, private
short-lived sockets); no working sessions or installed applications are
touched.

## Running the daemon

```sh
cargo +1.98.1 run --offline --bin bridge-daemon -- path/to/bridge.toml
```

Minimal configuration:

```toml
database = "/path/to/bridge.db"
socket = "/path/to/bridge.sock"

[limits]
max_admitted_events = 10000

[[grant]]
token = "<unguessable secret issued to the producer>"
publisher = "agent-run"
recipients = ["host-id/codex/native-store-namespace/thread-id"]
kinds = ["worker.completed"]
modes = ["message", "auto"]
policies = ["keep_all", "latest"]
```

Address components in `recipients` are percent-encoded when they contain
`/` or `%`; the encoding is lossless and injective. An admin grant adds
`admin = true` and may request shutdown over the socket.

Delivery (dispatch, adapters, coalescing execution, recovery reporting,
restricted root MCP and Telegram) is planned in the tracked task breakdown
and not yet implemented.
