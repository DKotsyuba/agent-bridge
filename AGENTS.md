# AGENTS.md

Agent Bridge: local durable message service for Codex, Claude Code and managed OpenCode sessions.
Full guide: [agent.md](agent.md). Process: [CONTRIBUTING.md](CONTRIBUTING.md).

- Rust 1.98.1 (`rust-toolchain.toml`); macOS Apple silicon and Linux x86_64/ARM64 source candidates. Native qualification is route-specific; see `docs/qualification.md`. Use `cargo +1.98.1 ... --offline` after one `cargo fetch --locked`.
- Before finishing: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (short owned `TMPDIR`; absolute `BRIDGE_TEST_NODE`, Node is required for the full suite), strict private `cargo doc`, `cargo xtask check-public`.
- Fail closed; never retry an uncertain delivery; never infer evidence or identity from labels; never log secrets or payloads.
- Document every declaration; add no dependencies; tests use synthetic state only (no real sessions, models or network); native probes are manual and out of CI.
- The owner approved Linux-only `listenfd =1.0.2` for safe inherited socket ownership; keep its use at single-threaded frontend startup and retain kernel parent/UID checks. Other new dependencies still require review.
- Keep docs public: relative links, no personal paths or private identifiers.

- The owner approved Linux-only `tungstenite =0.30.0` with handshake only for the protected live Codex App Server route; no TLS features or new network listeners. Keep exact peer/incarnation and registry fences. Other new dependencies still require review.
