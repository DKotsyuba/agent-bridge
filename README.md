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
    and the frozen SHA-256 identity-content hash. Every component is
    revalidated at every trust boundary, **including `Deserialize`**
    (envelope, address, ids, expiry, hashes, receipts, delivery evidence),
    and every u64 that reaches SQLite (revisions, expiries, counters,
    timestamps, epochs) is range-checked before any signed conversion.
  - `schema` / `storage`: SQLite durable custody (WAL, synchronous FULL, busy
    timeout) with idempotent publication — identical replay returns the
    original receipt, changed identity-content conflicts, monotonic
    acceptance order, latest-stream watermarks scoped by the full coalescing
    group, supersession of older *pending* snapshots only, admission quotas
    (non-terminal cap, per-publisher, per-recipient snapshot reserve with
    keep_all exempt, and a hard cap on retained dedup history that is never
    evicted), pending-only expiry, payload compaction that keeps dedup
    identity. The schema is versioned (current: 4); versions 2 and 3 migrate
    forward in one transaction without touching accepted bytes, hashes or
    identifiers, a version-3 attempt that may have reached a carrier becomes
    a `review` event with an incident, and unknown/newer/foreign databases
    are refused untouched.
  - `framing`: allowlisted source-tag wrappers with escaped, bounded
    manifests, a separate source block per member, forbidden-control
    rejection and the fixed external-data/no-authority statement. An event
    that could never be rendered is refused at publication.
  - `dispatch`: fenced attempts over an ordered frozen manifest (see
    below).
  - `recovery`: evidence tiers, retained incidents (reason, age, deadlines,
    responsible source, blocked dependents computed from live state),
    audited operator recovery, reconciliation.
  - `wire` / `service`: the authenticated local socket service and its
    lifecycle (see below). `src/bin/bridge-daemon.rs` is the daemon.
- `crates/bridge-client` — the shared typed client: `PublishRequest`
  (validating builder), `BridgeClient` (publish / status plus the operator
  operations, bounded reads and writes, one safe reconnect after an idle
  close, every response revalidated) and re-exports of the canonical types.
- `crates/bridge-adapters` — native Codex / Claude Code adapters: protected
  caller registry and root-caller ABI, quiet root hooks (`bridge-hook`),
  OS-confined Codex queue and Claude `later` message carriers, and the
  `bridge-native-daemon`. See `crates/bridge-adapters/README.md` for its
  trust model, configuration and unqualified native gaps.

## Dispatch contract (what an adapter implements and calls)

An **attempt** owns an ordered list of pending events of one recipient and
freezes, before anything leaves the process: the exact recipient, the actual
acting actor's native id, the endpoint epoch, the granted capabilities, the
requested and effective path, the rendered manifest bytes with their SHA-256,
the hand-off deadline and the proof reference of the attestation. A carrier or
hook can only send exactly `AttemptRecord::manifest`.

- `Attestation::verified(address, actor_id, epoch, lifecycle, capabilities,
  proof_ref)` — built **only by the protected adapter binding**, after it
  validated the actor, address, epoch and lifecycle against native evidence
  (no public fields, no `Deserialize`: a request body or a config file cannot
  mint one). Core fails closed on a stale epoch, a different address, an actor
  that is not the addressed actor (a child sharing the root session never
  consumes root data; a child with its own attested address receives its own),
  a missing capability, and any lifecycle other than `Active` / `Inactive`.
  Core cannot itself verify the adapter's proof; labels, PIDs and
  configuration are never accepted as native proof.
- `Storage::reserve_next(att, path, now, timing)` →
  `Selection::{Attempt, Idle, Held(reason)}`; `Storage::mark_invoking(fence,
  fresh_att, now)` → `Invoked::{Invoking, Released(reason)}` re-checks epoch,
  pause, capability, lifecycle and expiry and persists `invoking` before the
  hand-off; `Storage::drain_inject(att, now, timing)` does both in one
  transaction for a qualified hook (write `manifest` to the hook reply only
  after it returns).
- `Storage::record_outcome(fence, Outcome, now)`: `NativeAccepted`,
  `NativeHeld{recheck_ms}`, `WrittenNoReceipt{evidence, receipt_deadline_ms}`,
  `HookSubmitted`, `KnownUnsent{non-empty proof}`, `OutcomeUnknown`,
  `PermanentRefusal`. Late positive evidence for an older or uncertain attempt:
  `Storage::record_evidence(publisher, event, attempt, EvidenceTier, detail,
  now)` (native accepted, hook emitted, context observed, application
  processed, known-unsent proof; `ReceiptTokenPossession` is an annotation
  only). `Storage::observe_binding(att, now)` tells core which paths a
  recipient has loaded so unsupported modes are refused **before** acceptance.
- `DispatchCarrier { attest, send }` plus `dispatch::dispatch_message` /
  `service::start_with_carriers` drive the message path; inject has no carrier
  (a hook drains it).

Rules enforced by core: one possibly-handed-off attempt per event; `auto`
resolves per dispatch (active → inject at the hook, positively inactive →
message), requested and effective modes both recorded, never both paths;
pause blocks the message path at reservation *and* again before invocation (a
natural hook never wakes anyone and is not blocked); unknown, disconnected,
awaiting-input and failed attestation are visible holds, never idle; an
`invoking` attempt past its deadline, a lost carrier result or a panic becomes
`outcome_unknown` with a retained incident and is **never retried
automatically**; a positively known-unsent attempt is closed before a bounded
retry with doubling delay (exhaustion refuses the event with an incident);
held and written-without-receipt hand-offs are non-terminal with recheck
deadlines and overdue incidents; only an audited operator decision
(`authorize_manual_retry` on the *same* event with the duplicate risk recorded
forever, `dispose_event`, `waive_predecessor`) or positive evidence resolves an
incident. Dependents declared with `predecessor` metadata are accepted even if
the predecessor has not arrived, and wait for positive predecessor evidence, a
superseding snapshot or an audited disposition/waiver — never for time;
cycles are refused. Selection is keep_all first with age-based anti-starvation
of snapshots, independent traffic is never blocked behind a dependent, batch
siblings are frozen together in acceptance order only inside one scope
(publisher, recipient, kind, mode, project, task, group), and an in-flight
manifest is immutable.

## Service and protocol

ndjson over a Unix stream socket. Every ingress is authenticated by a grant
token (constant-time over all grants, tokens at least 16 bytes, unique, never
printed — request and grant `Debug` redact them) before validation, dedup or
status disclosure. Two disjoint realms:

- **publisher grants** (the identity is also the source tag): `publish`,
  `status` of their own events; allowlists for recipients, kinds, modes and
  policies. The restricted root orchestrator backend uses a *publisher* grant
  forcing `keep_all` and its exact recipients; an external root token is never
  a core credential.
- **operator grants** (`admin = true`, empty allowlists, cannot publish):
  `incidents`, `holds`, `authorize_retry`, `dispose`, `waive_predecessor`,
  `evidence`, `pause`, `resume`, `shutdown`; every decision is audited with the
  grant's identity.

Lifecycle: socket ownership refuses a live endpoint, preserves every foreign
path (regular file, symlink, directory, unprovable socket) and removes a stale
socket only after a connection attempt was positively refused and the inode is
unchanged; the socket is created `0600`; only the service's own inode is
removed at stop. Frames are limited incrementally *before* allocation;
connections are capped, idle/stalled readers and non-reading writers time out;
stopping fences new work under the custody lock (nothing is accepted after the
stop returned), wakes and drains in-flight connections, and is bounded even
with a hung carrier. SIGTERM/SIGINT stop the daemon cleanly (a second signal
exits immediately); the maintenance loop survives panics.

Logging is JSON lines on stderr without tokens, payloads or config text.

## Building and testing

Pinned toolchain `1.98.1` (see `rust-toolchain.toml`).

```sh
cargo +1.98.1 build --offline --workspace
cargo +1.98.1 test --offline --workspace
cargo +1.98.1 clippy --offline --workspace --all-targets -- -D warnings
cargo +1.98.1 fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo +1.98.1 doc --offline --workspace --no-deps --document-private-items
```

Tests use only isolated synthetic state (fresh temporary databases, private
short-lived sockets, scripted synthetic carriers); no working sessions or
installed applications are touched.

## Running the daemon

```sh
cargo +1.98.1 run --offline --bin bridge-daemon -- path/to/bridge.toml
```

```toml
database = "/path/to/bridge.db"
socket = "/path/to/bridge.sock"

[limits]
max_admitted_events = 10000
# optional, defaults shown:
# max_pending_per_publisher = 10000
# max_pending_latest_per_recipient = 128
# max_retained_events = 5000000
# max_connections = 64
# idle_timeout_ms = 60000
# request_timeout_ms = 10000
# write_timeout_ms = 10000

[[grant]]            # `[[grants]]` is accepted as well
token = "<unguessable secret, at least 16 bytes>"
publisher = "agent-run"          # also the source tag
recipients = ["host-id/codex/native-store-namespace/thread-id"]
kinds = ["worker.completed"]
modes = ["message", "auto"]
policies = ["keep_all", "latest"]

[[grant]]
token = "<a different unguessable secret>"
publisher = "bridge-ops"
admin = true                     # operator realm: no allowlists
recipients = []
kinds = []
modes = []
policies = []
```

Address components in `recipients` are percent-encoded when they contain
`/` or `%`; the encoding is lossless and injective. The daemon starts without
native carriers: events stay pending, visibly, until a qualified adapter drives
them.

## Scope and open gaps

This repository implements the standalone Bridge core only (decision D-003).
Native adapters (actual-actor / address / epoch / lifecycle attestation, the
Codex queue helper, the Claude peer and hook paths, held-callback handling),
the restricted orchestrator MCP and the outbound Telegram channel are separate
Modules that consume the interfaces above. Missing peer proof is an explicit
gap — never a pass:

- no real native carrier or hook has been exercised; every dispatch check runs
  against scripted synthetic carriers, and core trusts the adapter's
  `Attestation`;
- the optional receipt-token tier is recorded as an annotation only (no
  per-producer predeclared release/GC contract);
- operator notification channels (Telegram) are not part of core: incidents are
  durable and listed, but nothing tells the owner by itself;
- wall-clock regressions are not modeled (leases and deadlines use the service
  clock as given).
