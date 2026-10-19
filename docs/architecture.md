# Architecture

This document describes how Agent Bridge keeps and delivers events: the
custody store, the dispatch contract adapters implement, the local socket
service and its lifecycle rules. Native adapters and operator tooling are
documented in their [adapter](../crates/bridge-adapters/README.md) and
[interfaces](../crates/bridge-interfaces/README.md) guides; the producer-facing
protocol is in [Producer integration](producer-integration.md).

## Components

```text
producer ──► bridge-core service (SQLite custody, dispatch, recovery)
                  ▲   │ attempts
 operator CLI ────┘   ▼
                bridge-adapters (registry, hooks, lifecycle plugin, carriers)
                          │ native hook output, queue, message or owner call
                          ▼
                 Codex / Claude Code / managed OpenCode session
```

- `bridge-core`: the service library and `bridge-daemon`.
  - `types`: canonical event identity: the exact native logical address
    (host / harness / native store namespace / native session id, percent-encoded
    losslessly in the canonical text form), the envelope with its `keep_all`,
    `latest` or `batch` policy, bounded payload and metadata, a once-normalized
    absolute expiry, deterministic canonical serialization and the frozen SHA-256
    identity-content hash. Every component is revalidated at every trust boundary,
    including `Deserialize`, and every `u64` that reaches SQLite is range-checked
    before any signed conversion.
  - `schema` / `storage`: SQLite durable custody (WAL, `synchronous = FULL`, busy
    timeout). Validation and any supported migration hold an exclusive lock through enabling WAL.
  A foreign, unknown or newer database is refused before Bridge makes any schema or
  journal-mode change and without a close-time WAL checkpoint; SQLite's own recovery of
  an interrupted rollback journal may restore committed content first, and ordinary WAL
  reads or recovery may rewrite advisory `-shm` WAL-index metadata (the main and WAL
  bytes of a refused WAL database are preserved). See [Custody](#custody).
  - `framing`: allowlisted source-tag wrappers with escaped, bounded manifests, a
    separate source block per member, forbidden-control rejection and a fixed
    external-data, no-authority statement. An event that could never be rendered is
    refused at publication.
  - `dispatch`: fenced attempts over an ordered frozen manifest. See
    [Dispatch contract](#dispatch-contract).
  - `recovery`: evidence tiers, retained incidents (reason, age, deadlines,
    responsible source, blocked dependents computed from live state), audited
    operator recovery and reconciliation.
  - `wire` / `service`: the authenticated local socket service. See
    [Service and protocol](#service-and-protocol).
- `bridge-client`: the typed legacy publisher and operator client: a validating
  `PublishRequest` builder and `BridgeClient` (publish, status and the operator
  operations, bounded reads and writes, one safe reconnect after an idle close,
  every response revalidated), with re-exports of the canonical types.
- `bridge-protocol` and `bridge-sdk`: the independent v1 producer contract and
  client.
- `bridge-adapters` and `bridge-interfaces`: native carriers and hooks, and the
  restricted root MCP, operator CLI and packaging.
  OpenCode uses its lifecycle plugin and a message-only direct-parent owner route;
  it never drains injected context. Codex and Claude retain their hook paths.

## Custody

Publication is idempotent: an identical replay returns the original receipt, and
changed identity-content conflicts. Acceptance order is monotonic.

- `latest` streams keep a watermark scoped by the full coalescing group; only older
  pending snapshots are superseded. A lifetime-scoped stream is retained and read by its
  full scoped key; an unscoped legacy key uses the legacy watermark, and a malformed or
  mismatched lifetime key refuses.
- Admission quotas: a non-terminal cap with at least one slot, a quarter of larger
  caps reserved for `keep_all`, a per-publisher cap, a per-recipient snapshot
  reserve (with `keep_all` exempt) and a hard cap on retained dedup history that is
  never evicted.
- Expiry applies only to pending events; payload compaction keeps dedup identity.
- **Producer lineage authority.** One authenticated producer owns each `latest`
  lineage (the coalescing scope without the publisher). Any other producer is
  declined before acceptance. Authority passes only through an audited operator
  transfer that never rewrites event ids, watermarks, attempts or evidence. A
  transfer validates every scope field with the publication rules, holds the
  previous owner's unhanded or reserved `latest` events visibly (a retained
  `lineage_authority_lost` incident) so they are never selected or invoked
  afterwards, and is refused while another producer's event in the lineage is
  invoking, in review or held by the native side: a possible native effect cannot
  be recalled, so the operator must first resolve it with the audited disposition.
- Identity is the Bridge-stamped publisher only. Two processes sharing one grant are
  one producer, so a same-publisher restart that reuses lower revisions is
  indistinguishable from stale input and stays superseded; the supported declared
  signals are a new stream id or an audited transfer to a different publisher
  identity.
- **Schema.** The database is versioned (current: 6). The additive 5-to-6 migration
  preserves accepted bytes, hashes, identifiers and uncertain attempt history.
  Versions 2, 3 and 4 migrate forward in one transaction without touching accepted
  bytes, hashes or identifiers: lineage owners are backfilled from retained events
  and watermarks, and a lineage with several historical producers migrates as
  *ambiguous* and fences publication and dispatch until an operator resolves it. A
  version-3 attempt that may have reached a carrier, or that has an open version-3
  `unknown_handoff` incident, becomes a `review` event; every version-3 incident is
  carried into the live table with its number, kind, reason and dates; open ones stay
  open whatever their kind, and the old rows stay in `incidents_v3`. Unknown, newer
  and foreign databases are refused before any Bridge schema or journal-mode change.

## Dispatch contract

An **attempt** owns an ordered list of pending events of one recipient and freezes,
before anything leaves the process: the exact recipient, the actual acting actor's
native id, the endpoint epoch, the granted capabilities, the requested and effective
path, the rendered manifest bytes with their SHA-256, the hand-off deadline and the
proof reference of the attestation. A carrier or hook can only send exactly
`AttemptRecord::manifest`.

- `Attestation::verified(address, actor_id, epoch, lifecycle, capabilities,
  proof_ref)` is built **only by the protected adapter binding**, after it validated
  the actor, address, epoch and lifecycle against native evidence. It has no public
  fields and no `Deserialize`: a request body or a config file cannot mint one. Core
  fails closed on a stale epoch, a different address, an actor that is not the
  addressed actor (a child sharing the root session never consumes root data; a
  child with its own attested address receives its own), a missing capability and
  any lifecycle other than `Active` or `Inactive`. Core cannot itself verify the
  adapter's proof; labels, PIDs and configuration are never accepted as native proof.
- `Storage::reserve_next(att, path, now, timing)` returns
  `Selection::{Attempt, Idle, Held(reason)}`. `Storage::mark_invoking(fence,
  fresh_att, now)` returns `Invoked::{Invoking, Released(reason)}`; it re-checks
  epoch, pause, capability, lifecycle and expiry and persists `invoking` before the
  hand-off. `Storage::drain_inject(att, now, timing)` does both in one transaction
  for a qualified hook, which writes `manifest` to its reply only after it returns.
- `Storage::record_outcome(fence, Outcome, now)` takes `NativeAccepted`,
  `NativeHeld{recheck_ms}`, `WrittenNoReceipt{evidence, receipt_deadline_ms}`,
  `HookSubmitted`, `KnownUnsent{non-empty proof}`, `OutcomeUnknown` or
  `PermanentRefusal`. Late positive evidence for an older or uncertain attempt uses
  `Storage::record_evidence(publisher, event, attempt, EvidenceTier, detail, now)`
  (native accepted, hook emitted, context observed, application processed,
  known-unsent proof; `ReceiptTokenPossession` is an annotation only).
  `Storage::observe_binding(att, now)` tells core which paths a recipient has loaded
  so unsupported modes are refused **before** acceptance.
- `DispatchCarrier { attest, send }` with `dispatch::dispatch_message` and
  `service::start_with_carriers` drive the message path; inject has no carrier (a hook
  drains it).

Rules enforced by core:

- One possibly-handed-off attempt per event.
- `auto` resolves per dispatch (active to inject at the hook, positively inactive to
  message). Requested and effective modes are both recorded, and never both paths.
- Pause blocks the message path at reservation *and* again before invocation; a
  natural hook never wakes anyone and is not blocked.
- Unknown, disconnected, awaiting-input and failed attestation are visible holds, never
  idle.
- An `invoking` attempt past its deadline, a lost carrier result or a panic becomes
  `outcome_unknown` with a retained incident and is **never retried automatically**.
- An ordinary positively known-unsent transport failure is closed before a bounded
  retry with doubling delay; exhaustion refuses the event with an incident.
- A positively busy native owner is held before reservation. A verified owner
  epoch/lifecycle race, or its correlated closed zero-effect `not_idle`,
  `awaiting_input` or `capacity` refusal, closes as known-unsent and refunds only
  that attempt's budget charge. The original event waits for a fresh attestation
  under the existing delay, expiry, coalescing and retirement fences. Immutable
  attempt history is retained; no lost, malformed or uncorrelated receipt can
  obtain this deferral.
- Held and written-without-receipt hand-offs are non-terminal with recheck deadlines
  and overdue incidents.
- Only an audited operator decision (`authorize_manual_retry` on the *same* event with
  the duplicate risk recorded forever, `dispose_event`, `waive_predecessor`) or
  positive evidence resolves an incident.
- Dependents declared with `predecessor` metadata are accepted even if the predecessor
  has not arrived, and wait for positive predecessor evidence, a superseding snapshot
  or an audited disposition or waiver, never for time. A predecessor that expired
  raises a `predecessor_expired` incident on the dependent, which stays blocked until a
  waiver or disposition; cycles are refused.
- Selection is `keep_all` first with age-based anti-starvation of snapshots. Independent
  traffic is never blocked behind a dependent. Batch siblings are frozen together in
  acceptance order only inside one scope (publisher, recipient, kind, mode, project,
  task, group), and an in-flight manifest is immutable. A late outcome of a batch keeps
  its evidence for every frozen member but changes state and incidents only for members
  still owned by that exact attempt; disposed or newer siblings are unchanged.

## Service and protocol

The service speaks newline-delimited JSON over a Unix stream socket. Every ingress is
authenticated by a grant token (constant-time over all grants, tokens at least 16
bytes, unique, never printed; request and grant `Debug` redact them) before
validation, dedup or status disclosure. There are two disjoint realms:

- **Publisher grants.** The identity is also the source tag. They permit `publish` and
  `status` of their own events within allowlists for recipients, kinds, modes and
  policies. The restricted root orchestrator backend uses a publisher grant forcing
  `keep_all` and its exact recipients; an external root token is never a core
  credential.
- **Operator grants** (`admin = true`, empty allowlists, cannot publish):
  `incidents`, `incidents_page`, `retention`, `holds`, `counts`, `authorize_retry`,
  `dispose`, `waive_predecessor`, `evidence`, `pause`, `resume`, `transfer_lineage` and
  `shutdown`. Every decision is audited with the grant's identity.

Operator reads keep stable shapes. `BridgeClient::incidents_page(token,
include_closed, limit, after_seq, through_seq)` starts with `after_seq = 0` and
`through_seq = None`, then carries the returned fixed high-water mark and
`next_after_seq`. A page holds at most 200 incidents in stable sequence order and a
final page has no next cursor. Row states are live, so restart the finite scan to
include newly inserted or reopened incidents. Invalid, reversed or out-of-range
cursors are refused. Reading a page neither closes an incident nor reports it to an
owner.

`BridgeClient::retention(token, publisher, event_id)` returns an exact nullable
storage view: retained custody identity, bounded delivery evidence, original expiry,
envelope byte count, compacted or tombstone flag, logical payload GC eligibility and
the event's exact-scoped latest watermark. It loads no payload bytes. An absent key
returns `None`; publisher and ordinary root grants cannot read it. Expiry and
collection describe storage dispositions, never recall of a possible or accepted
native effect. Reads do not trigger expiry or collection, and dedup rows, hashes and
watermarks remain retained after payload compaction.

The v1 producer operations are served by the same core on separate typed methods; see
[Producer integration](producer-integration.md) and the [core v1
contract](../crates/bridge-core/docs/producer-core-v1.md).

## Lifecycle

Socket ownership refuses a live endpoint, preserves every foreign path (regular file,
symlink, directory, unprovable socket) and removes a stale socket only after a
connection attempt was positively refused and the inode is unchanged. The socket is
created `0600` under a lifetime `.lock` file; a stale socket is removed only when it
belongs to the same user, a connection was refused and its inode is unchanged. Readiness
for lifecycle supervision requires both the core and the adapter-channel sockets from the
spawned process, by its exact PID, each as a distinct OS socket (device and inode), so two
names of one socket never count twice and an unreadable identity is not ready; a configuration whose adapter channel is the core
socket's own endpoint (same directory and file name, including `.` and symlinked directory
aliases) is refused before the process is spawned; other aliases (for example a case variant
or a hard link) are not all recognized before spawning and fail readiness instead. A start whose required socket
paths (the core and adapter-channel sockets for the core, the relay socket for the relay)
include a final-component symlink, dangling or not, is also refused before spawning and the link is left unchanged. Only the service's own inode is removed at stop. Frames are limited
incrementally *before* allocation; connections are capped; an idle connection and a
request in progress have separate absolute deadlines, the request deadline starting at the
first nonempty byte buffer (an interrupted read renews neither); stalled readers and
non-reading writers time out. Stopping fences new work under the custody lock (nothing
is accepted after the stop returned), wakes and drains in-flight connections, and is
bounded even with a hung carrier. SIGTERM and SIGINT stop the daemon cleanly (a second
signal exits immediately). The maintenance loop survives panics, a carrier whose
attestation panics holds only its own recipient, and each dispatch pass takes a
rotating window of recipients so idle or blocked recipients with unchanging work cannot
pin the window (no exact coverage bound is promised while the workload keeps changing).

Logging is JSON lines on stderr without tokens, payloads or config text.

## Known limits

- Core dispatch tests use scripted synthetic carriers and trust the adapter's
  `Attestation`. Native evidence belongs to the exact builds and scopes in the
  [qualification matrix](qualification.md).
- The optional receipt-token tier is recorded as an annotation only; no producer has a
  predeclared release or GC contract, the root MCP has no `bridge.ack`, and core issues
  no recipient receipt token.
- Notification channels are not part of core: incidents are durable and listed,
  `bridge notify` reports them to a configured owner chat, and an unconfigured channel
  reports the owner as not notified.
- Wall-clock regressions are not modeled; leases and deadlines use the service clock as
  given.
