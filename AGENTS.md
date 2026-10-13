# AGENTS.md

Agent Bridge: local durable message service for Codex and Claude Code sessions.
Full guide: [agent.md](agent.md). Process: [CONTRIBUTING.md](CONTRIBUTING.md).

- Rust 1.98.1 (`rust-toolchain.toml`), macOS Apple silicon only. Use `cargo +1.98.1 ... --offline` after one `cargo fetch --locked`.
- Before finishing: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (short owned `TMPDIR`; absolute `BRIDGE_TEST_NODE`, Node is required for the full suite), strict private `cargo doc`, `cargo xtask check-public`.
- Fail closed; never retry an uncertain delivery; never infer evidence or identity from labels; never log secrets or payloads.
- Document every declaration; add no dependencies; tests use synthetic state only (no real sessions, models or network); native probes are manual and out of CI.
- Keep docs public: relative links, no personal paths or private identifiers.
