# Changelog

All notable changes to Agent Bridge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions describe the
source, and the crates are not published to crates.io.

## [Unreleased]

### Added

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
  or resend. Absent locators keep every legacy route. Source-tested with a scripted
  stand-in owner; not native-qualified.
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
  executable path and SHA-256. A fresh Codex or Claude Code session in any canonical store
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
