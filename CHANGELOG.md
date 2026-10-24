# Changelog

All notable changes to Agent Bridge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions describe the
source, and the crates are not published to crates.io.

## [Unreleased]

## [0.4.0] - 2026-10-24

### Added

- Harness profiles: a harness Bridge ships no code for is connected by
  configuration alone. An `[[adapters.harnesses]]` entry with a canonical
  identifier, a store rule (`store_env` / `store_home`), child addressing and
  accepted caller proofs serves its identity, Claude-compatible lifecycle hooks,
  inject, and message through its native owner. See
  [Harness profiles](docs/harness-profiles.md).
- Hook-token caller proof: at the `PreToolUse` of a Bridge root tool call the
  daemon issues a single-use token that `bridge-hook` writes into the call input
  (`updatedInput`); the root frontend presents it instead of host `_meta`, and
  the registry joins it to exactly that record under the existing ancestry,
  epoch and single-use rules. It is the default for a profile-only harness and
  makes caller attestation independent of host metadata keys.
- `bridge doctor` reports each harness profile with its resolved defaults;
  attestation refusals name the harness and the missing profile element.

### Changed

- The native harness of an address is an open canonical identifier
  (`[a-z][a-z0-9-]{0,31}`). Built-in harnesses keep their canonical names and
  historical serialized spellings, so stored envelopes, hashes, route journals
  and configuration are unchanged. Wire contract revision 4 accepts any canonical
  harness name in an address.
- `bridge-protocol`: `NativeAddress::harness` is now `HarnessName` (open);
  `HarnessName::host()` maps a built-in harness to its metadata `Host`. Rust
  consumers that matched `address.harness` against `Host` values must compare
  `address.harness.host()` instead.
- The OpenCode owner carrier is now the owner-only carrier
  (`bridge_adapters::owner_only::OwnerOnlyCarrier`) and also serves profile-only
  harnesses; a profile-only harness's owner answers with `<harness>_input`.

## [0.3.2] - 2026-10-22

### Fixed

- The SDK no longer mistakes a received answer for a lost one when the service
  answers and closes its connection before the client sets its read timeout
  (macOS refuses `SO_RCVTIMEO` on a closed socket). The read falls back to a
  nonblocking read, so the absolute deadline still holds; the request is no
  longer replayed on a second connection. No wire, API or error-reason change.

- Preserve the MCP frontend's direct native parent while projecting OpenCode
  ToolContext: exec the original backend after a private worker readiness
  handshake. The transport worker validates its kernel peer and native origin;
  registry ancestry and evidence checks remain unchanged.

- Managed OpenCode MCP calls preserve the original permission-checked executor
  and persistent backend while forwarding genuine ToolContext metadata over a
  kernel-authenticated parent-only channel. Component ABI 2 refuses absent,
  mismatched or reused contexts without inventing identity or replaying effects.
  Native MCP classification comes from the exact registered MCP definition;
  OpenCode's unprefixed registry IDs no longer appear to be ordinary local tools.

- Owner-routed native delivery holds busy recipients before dispatch and keeps
  positively unsent busy/endpoint-change events queued without exhausting the
  ordinary five-attempt transport budget. Fresh attestation, immutable attempt
  history, retirement fences and unknown-outcome non-retry rules are preserved;
  no producer wire or database migration is required.

### Added

- Explicitly granted adapter-only `observe_recipient` and `resolve_recipient`
  reads with typed SDK methods. Exact protected bindings, live process/store
  checks and final snapshot fences return content-free observations or unavailable;
  they create no caller authority and perform no delivery or custody mutation.
- The producer SDK checks the connected Unix peer's kernel user identity before
  transmitting a credential, using the already locked safe Tokio API. Missing or
  foreign user credentials refuse without sending request bytes.

## [0.3.1] - 2026-10-16

### Fixed

- The Claude native inbox carrier no longer refuses a manifest over 4096 bytes as a
  permanent refusal. Its bound is now core's 98304-byte framing bound (the one the owner
  and Desktop routes already use), so a core-admitted body (including a full 16 KiB body
  whose escaping and source-wrapper overhead fits that bound; 16 KiB of `"` does not) is
  written as one unchunked inbox message. A larger manifest
  still refuses before any byte is written. The former 4096-byte value had no recorded native basis.
  Native acceptance is qualified only for the tested 16384-byte payload on Claude Code 2.1.295 and
  2.1.296; larger payloads and other builds remain unqualified.
- OpenCode plugin: sustained native-feed overload now invalidates readiness once per separated
  overload episode, including after an intervening `Stop`, and accepts nothing behind a queued
  invalidation. The pending bound, FIFO order and cleanup are unchanged.
- OpenCode child sessions never receive the `message` capability (also withdrawn from older
  bindings at renewal); a child `SessionEnd` retires to `Unknown` and a child `Stop` never
  makes it `Inactive`. The route journal now records an OpenCode address's role: a recorded
  root keeps its message capability across a restart without a new hook; a child, or a row from an
  earlier build, is restored with message withheld until the address's own next hook (a one-time
  wait for such a root). An earlier build refuses a journal holding the new field, so rolling back
  needs an earlier or fresh journal. Child wake remains unqualified.
- Codex Desktop: rendered text is bounded at 98304 bytes and the private frame at 197696 bytes,
  shared by the Rust and JavaScript sides; only tab, newline and carriage-return controls are
  accepted and ids are bounded and control-free. Oversize is refused before any write. The
  supplied signed Node hop is skipped only when the Rust peer's direct parent is the owner Node
  process whose executable matches its own preserved `CODEX_MCP_NODE_PATH`, with the tools pipe
  in its environment and the peer's `BRIDGE_DESKTOP_PARENT_PID` equal to its PID; no hook or
  non-Codex exemption.
- Adapter sockets are claimed under a lifetime lock and a stale socket is reclaimed only after a
  refused connection with an unchanged inode, same user; readiness requires both the core and
  adapter-channel sockets from the spawned process, each a distinct OS socket (so other aliases
  of one socket, such as a case variant or hard link, are never ready), and a configuration naming the same endpoint
  for both (literal, `.` or symlinked-directory alias) is refused before spawning, as is a required
  socket path (core and channel for the core, relay socket for the relay) whose final component is a
  symlink, dangling or not; the link is left unchanged.
- Documentation: inbox size wording is the 98304-byte bound everywhere, and the store
  revalidation statement distinguishes the routes that recheck the store from the legacy Claude
  inbox route, which checks incarnation and each descriptor/token file.
- Batch outcomes: a late batch outcome keeps evidence for every frozen member but changes
  state and incidents only for members still owned by that exact attempt.
- `retire_unhanded` permanently rejects manual retry. A late known-unsent outcome closes a
  retired member only when no historical possible-effect risk exists, otherwise the review and a
  visible incident remain. Retired orphan rows from older builds are excluded from selection and
  work listings and show a scope-fence diagnostic.
- Lifetime `latest` retention uses the full scoped key and `scoped_watermarks`; unscoped legacy
  keys use `watermarks`; a malformed or mismatched lifetime refuses.
- Rollback schema validation or migration holds an exclusive lock through enabling WAL, and a
  foreign, unknown or newer database is refused before Bridge makes any schema or journal-mode
  change and without a close-time WAL checkpoint. SQLite's own recovery of an interrupted rollback
  journal may restore committed content first, and ordinary WAL reads or recovery may rewrite advisory
  `-shm` WAL-index metadata (the main and WAL bytes of a refused WAL database are preserved).
- Request reads use a separate absolute idle deadline and a request deadline that starts at the
  first nonempty byte buffer; an interrupted read renews neither.

## [0.3.0] - 2026-10-15

### Added

- Generic managed OpenCode 2.0.28 lifecycle support: an observation-only first-party
  plugin (`crates/bridge-adapters/plugins/opencode`) that reports the actual native
  session and execution lifecycle, the `Host`/`Harness` value `opencode` in the wire
  contract and core, and a message-only `opencode_input` route through the exact
  direct-parent native owner (no context injection, no resend or fallback; owner admission
  is native acceptance, not processing). The producer SDK gains the `ai.opencode/sessionID`
  plus `ai.agent_bridge/toolCallID` native metadata candidate and a manual single-publication
  example (`publish`) for publication support. One isolated live-session candidate is
  recorded in the qualification matrix; standalone OpenCode root MCP, child wake and
  context injection stay unqualified.
- Attested OpenCode plugin packaging and canonical activation binding, with
  plugin-less legacy install/rollback compatibility. Plugin disposal awaits
  every cleanup stage and reports the first failure after completion.
- Automatic recovery after an application update or restart (source-tested; not natively
  qualified): a Bridge relay or audience executable whose file identity changed but whose
  real SHA-256 is still a configured one qualifies again by itself (background single-flight
  hashing from the opened file with identity checks, outside the registry lock; requests never
  hash and refuse before changing state; a different digest is cached once and stays refused;
  this now covers Bridge's own relay and audience builds only); and a MESSAGE-only physical
  gateway that delivers a queued message once to a positively idle Desktop Codex thread after the application
  restarted, from a protected idle stamp of its exact transcript and a unique
  live frontend, with a fresh journaled endpoint epoch, no caller or inject authority and
  a one-shot proof journaled as spent before the first native write, a fresh binding,
  incarnation, gateway and transcript fence at the last pre-write boundary (zero native
  bytes on any change), and restoration of the proof only after a refusal that proves
  nothing was written while the same fence still holds.
- Owner-routed idle wake for a live managed Codex or Claude Code session: a harness
  whose environment names `BRIDGE_NATIVE_OWNER_SOCKET` is woken through its exact
  direct-parent owner (which must run a trusted, unchanged executable; no owner path or digest is configured), only while
  positively idle, with one request, a conservative receipt mapping, one absolute
  35-second budget guarded before connecting and before the write, and no fallback
  or resend. Absent locators keep Codex/Claude legacy routes. Source-tested with a scripted
  stand-in owner and observed on the bounded `c00e6fc`/candidate5 IDE/Agent Run
  Codex and Claude canaries in the qualification matrix; other builds and the
  v0.3 release artifact remain natively unqualified.
- Public repository documentation: getting started, configuration,
  architecture, producer integration and a qualification and support matrix.
- `cargo xtask check-public`: verifies required files, Markdown links and
  reachability from the README, absence of private paths and identifiers, the
  changelog heading for the workspace version, and the CI workflow rules.
- Minimal GitHub Actions workflow for macOS on Apple silicon: format, strict
  Clippy, tests, private Rustdoc and the public checker. It runs no native or
  paid probe.

### Changed

- The native owner route no longer needs an owner path and SHA-256 allowlist (`owner_relays`),
  which held a freshly registered session with "native owner build is not a qualified owner relay".
  The owner must still be the exact same-user direct parent of the attested harness behind a
  private canonical 0700 directory and 0600 socket, and must run from a trusted executable (a
  regular file owned by the user or root, not writable by group or other, unchanged since the
  owner started). `owner_relays` is removed from the configuration; a table from an earlier
  release is parsed and discarded, authorizes nothing and is reported as
  `legacy_owner_relays_ignored` in the daemon log and `bridge doctor`. Relay and audience
  path and SHA-256 qualification are unchanged.
- Native recipients are no longer trusted by predeclared exact store paths and harness
  executable path and SHA-256. A fresh Codex, Claude Code or managed OpenCode session in any canonical store
  you own that no group or other user can write registers from its genuine lifecycle hook
  with no pre-enrollment: the store comes from the verified harness process, the harness must
  carry a product marker and run from a trusted file unchanged since it started, and
  namespace and capabilities come from one `[[adapters.harnesses]]` policy per harness.
  Existing `[[adapters.profiles]]` still load as migration input (one note per profile, one
  namespace per harness, otherwise refused) and authorize nothing; the vendor signature
  policy, its checker, pending routes and `Registry::new_with_checker` are removed. Equal
  session ids in two stores now conflict because the address namespace is per harness.
  Digest qualification stays for relays and audiences, and no runtime profile
  enrollment operation exists.
- A known live interactive Claude route stuck at `Unknown` is re-observed from a fresh
  owned native descriptor that positively reports `idle` or `busy` for the exact session,
  PID and start, executable and store, instead of staying held;
  the one-shot gateway proof is restored after a known-unsent refusal only over the exact
  binding that stood after the spend; the background refresh join handle is published under
  the stop slot lock. Route journal rows gained `wake` (a `pending` field of the removed
  vendor verification is still read, never written, and such rows are dropped); an earlier
  daemon refuses a journal that carries `wake` (rollback needs a compatible one).
- The advertised `native_contracts` list is empty: there is no configured host build to
  disclose, and nothing fake is advertised. A reused PID is treated as a gone incarnation.
- Codex application frontend discovery reads the whole protected directory (it scanned
  only the first 512 entries and gave up at one non-UTF-8 name), skips dead PIDs before
  probing, and a frontend whose parent channel closed retires its own socket instead of
  staying advertised; a dead leftover socket of the same name is replaced.
- The producer SDK boundary test and the universal qualification probe take
  their temporary directory from `TMPDIR` instead of a fixed location.
- CI provisions the runner's preinstalled Node (`BRIDGE_TEST_NODE`) and one short
  `TMPDIR`/`TMP`/`TEMP` for the full workspace tests, and the documentation lists
  Node as a prerequisite of those tests.
- Installer: the release staging directory stays owner-writable until it is
  renamed and the final release directory is sealed read-only afterwards, which
  fixes `EACCES` when installing on macOS 15; an unsealed release now fails closed.

### Fixed

- Publication admission no longer refuses `auto` for a recipient that loaded only the
  message path. `auto` is admitted when at least one effective path is loaded (it resolves
  to message while positively inactive and holds without effect while active); with no
  loaded path it is still refused before custody, and explicit `message` or `inject`
  stay outside an `auto`-only grant.

## [0.2.0] - 2026-10-13

### Added

- Universal producer API v1: `bridge-protocol` (strict bounded wire types,
  canonical request and publication fingerprints) and `bridge-sdk` (a
  synchronous client with one absolute exchange deadline and explicit
  uncertain-outcome reporting). Operations: capabilities, register_call,
  publish, status, close_route, and the optional consume_assertion and
  retire_delivery_scope.
- Native producer ingress in the adapter channel: registration against one
  protected native MCP invocation, exclusive evidence claims, optional
  short-lived audience-bound assertions for detached backends.
- Core producer authority (`producer_v1` grant policy), durable routes,
  direct-address publication, producer delivery lifetimes and the
  pre-invoking retirement fence.
- Restricted operator reads: paged incidents and exact retention views.
- Address-based personal messaging with `recipients = ["*"]`, still gated by
  sender attestation and a qualified native endpoint.
- Recipient route recovery after a daemon restart from verified, privately
  persisted bindings.

### Changed

- Storage schema 6: an additive transactional migration from schema 5 that
  preserves accepted bytes, hashes, identifiers and uncertain attempt history.
  Older, newer and foreign databases are refused untouched.

## 0.1.x

Earlier internal versions: the durable event core, native Codex and Claude Code
adapters, the restricted root MCP, the operator CLI, outbound Telegram
notification and local packaging. They were not published.
