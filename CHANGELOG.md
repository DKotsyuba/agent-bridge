# Changelog

All notable changes to Agent Bridge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions describe the
source, and the crates are not published to crates.io.

## [Unreleased]

### Added

- Public repository documentation: getting started, configuration,
  architecture, producer integration and a qualification and support matrix.
- `cargo xtask check-public`: verifies required files, Markdown links and
  reachability from the README, absence of private paths and identifiers, the
  changelog heading for the workspace version, and the CI workflow rules.
- Minimal GitHub Actions workflow for macOS on Apple silicon: format, strict
  Clippy, tests, private Rustdoc and the public checker. It runs no native or
  paid probe.

### Changed

- The producer SDK boundary test and the universal qualification probe take
  their temporary directory from `TMPDIR` instead of a fixed location.
- CI provisions the runner's preinstalled Node (`BRIDGE_TEST_NODE`) and one short
  `TMPDIR`/`TMP`/`TEMP` for the full workspace tests, and the documentation lists
  Node as a prerequisite of those tests.
- Installer: the release staging directory stays owner-writable until it is
  renamed and the final release directory is sealed read-only afterwards, which
  fixes `EACCES` when installing on macOS 15; an unsealed release now fails closed.

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
