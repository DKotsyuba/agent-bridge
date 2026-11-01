# Contributing

Thank you for helping. Agent Bridge handles message custody and delivery
evidence, so changes are judged first on whether they keep its guarantees:
fail closed, never infer evidence, never repeat an uncertain delivery.

## Before you start

- Open an issue to discuss anything that changes delivery semantics, the
  producer API, the database schema, or what a hook, adapter or credential is
  trusted to do. Bug fixes and documentation corrections can go straight to a
  pull request.
- Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md),
  not in an issue or pull request.
- The supported platform is macOS on Apple silicon. Portable code is welcome,
  but a change must not claim support for another platform without a way to
  verify it.

## Build and check

Use the pinned toolchain (`rust-toolchain.toml`, Rust 1.98.1) and fetch
dependencies once; later commands run offline against `Cargo.lock`.

```sh
cargo +1.98.1 fetch --locked
cargo +1.98.1 fmt --all --check
cargo +1.98.1 clippy --offline --workspace --all-targets -- -D warnings
BRIDGE_TEST_NODE="$(command -v node)" cargo +1.98.1 test --offline --workspace
RUSTDOCFLAGS="-D warnings" cargo +1.98.1 doc --offline --workspace --no-deps --document-private-items
cargo +1.98.1 xtask check-public
```

These are the checks CI runs. Set `TMPDIR` to a short directory you own; tests
create Unix sockets beneath it. Set `BRIDGE_TEST_NODE` to an absolute Node.js
executable (`command -v node`): the full workspace tests, including the deterministic
Desktop regressions, require it and fail without it. Node is not needed to build or use
Bridge or the SDK. Tests must use only isolated synthetic state:
fresh temporary databases, private sockets, scripted carriers and fixture
processes. A test must never touch your real Codex, Claude Code or OpenCode stores,
sessions or hooks, call a model, or use the network.

The native probes in `crates/bridge-adapters/qualification/` need real harness
builds, may spend model budget and read host state. They are run deliberately by
a maintainer, never from `cargo test` or CI, and a contributor does not need
them for an ordinary change.

## Code conventions

- Every declaration, including private ones and tests, has a Rustdoc comment
  that states its contract: meaning of inputs, result, failure modes, side
  effects and invariants. Update the comment in the same change as the code.
- Keep dependencies at the locked set. Adding a crate needs a prior discussion
  and a reason the standard library or an existing dependency cannot serve.
- `unsafe` is forbidden workspace-wide.
- Never print or log credentials, tokens, payloads or parser text that can
  quote a value; keep errors secret-safe.
- A change to a documented boundary (wire v1, core v1, native ingress v1)
  updates the matching document under `crates/*/docs/` and its tests together.
- Add a test that fails without your change. For a safety rule, prove the test
  detects a real violation: break the behavior on purpose, see it fail, restore it.

## Documentation

Documents are plain Markdown reachable from [README.md](README.md). Use inline
relative links; `cargo xtask check-public` fails on a broken link or fragment,
an unreachable document, an owner-specific path or a private tracker identifier.
Describe what the code does and what was actually observed; do not claim a
qualification that was not run, and keep personal paths, session identifiers and
logs out of the repository.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/) such as
`fix(storage): preserve the current file on stale writes`. Keep a pull request
to one concern, describe the behavior change and the checks you ran, and update
[CHANGELOG.md](CHANGELOG.md) for user-visible changes.

By contributing you agree that your work is licensed under the [MIT
license](LICENSE).
