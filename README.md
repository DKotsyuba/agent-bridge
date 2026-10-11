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
    (host / harness / native store namespace / native session id,
    percent-encoded losslessly in the canonical text form), envelope with
    keep_all / latest / batch policy, bounded payload and metadata,
    once-normalized absolute expiry, deterministic canonical serialization
    and the frozen SHA-256 identity-content hash. All components are
    revalidated at every trust boundary (construction, canonical decode,
    raw deserialization, storage admission), and u64 revisions/expiry are
    bounded explicitly before any signed cast.
  - `storage`: SQLite durable custody (WAL, synchronous FULL, schema fence)
    with idempotent publication — identical replay returns the original
    receipt, changed identity-content conflicts, monotonic acceptance
    order, latest-stream watermarks scoped by the full coalescing group
    (publisher, recipient, kind, mode, project/task, stream), admission
    fairness quotas (global hard cap, per-publisher item quota,
    per-recipient replaceable-snapshot cap with keep_all exempt),
    pending-only expiry, and payload compaction that keeps dedup identity.
  - `dispatch`: fenced dispatch attempts with distinct evidence tiers
    (reserved, invoking persisted before any hand-off, native accepted,
    held with recheck, hook submitted, known-unsent, outcome-unknown,
    permanent refusal), lease expiry that reclaims only never-invoked
    reservations, durable no-wake recipient policies covering auto AND
    message, auto resolution from lifecycle observation (unknown/disconnected
    holds visibly), dependency ordering on declared predecessors, retained
    incidents with reason/age/deadlines/blocked dependents, and audited
    manual authorization with recorded duplicate risk — never automatic
    replay after a possible hand-off. `DispatchCarrier` is the
    contract-faithful substitute trait for the native adapter interface.
  - `framing`: allowlisted source-tag wrappers with escaped, bounded
    rendering, forbidden-control rejection, per-member blocks for batches,
    and the fixed external-data/no-authority statement.
  - `service`: the authenticated local publisher protocol — ndjson over a
    Unix stream socket with bounded framing (incremental line cap),
    bounded connection admission, socket ownership that refuses live
    endpoints and preserves foreign paths, and a shutdown fence that
    refuses post-stop work without custody. Every ingress is authenticated
    by an integration grant before validation, dedup or status disclosure;
    grants bind the publisher identity (stamped by the service, never
    asserted by the caller) and the allowed recipients, kinds, modes and
    policies. Status exposes custody plus the newest delivery-evidence
    tier (absent tiers are not_available, never delivered).
  - `src/bin/bridge-daemon.rs`: the daemon binary with TOML configuration
    and JSON-lines structured logging on stderr. Protocol-driven drained
    shutdown via an admin grant; OS-signal handling is a documented
    followup of the lifecycle task.
- `crates/bridge-client` — the shared typed client family consumers depend
  on: `PublishRequest` (validating builder), `BridgeClient` (publish /
  status over the socket, including delivery evidence), and re-exports of
  the canonical types. The restricted root orchestrator surface (M-006)
  consumes this same protocol through its own dedicated backend grant
  whose allowlist forces keep_all and its exact authorized recipients;
  external root credentials are never core credentials.

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

## Scope and baseline alignment

This repository implements the standalone Bridge core only (decision
D-003): durable authenticated publication, custody, dispatch state,
coalescing/admission fairness, recovery incidents and the local publisher
protocol. Native adapters and the restricted orchestrator/Telegram
surfaces are separate Modules that consume the interfaces above; dispatch
in this crate runs against contract-faithful synthetic carriers until
those adapters land, and missing peer proof is tracked as an explicit gap
— never as a pass.

The pinned family checkouts recorded by the implementation audit
(Agent Run `9d004b7217b91…`, Agent IDE `004afb7b4cb7…`, Agent Worktree
`15f752183a29…`, each with hashed overlays) are historical baselines for
future integration; nothing here claims any installed runtime matches
them. Re-verification against live adapters happens in their own Modules
before any integration claim.

Remaining gaps (tracked in the Agent Tasks project): real native carrier
qualification, OS-signal shutdown handling, written_no_receipt tracking,
receipt-token tier for the root surface, and end-to-end integration —
see Module M-001's current result for the authoritative list.
