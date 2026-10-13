# Qualification and support matrix

What is supported, what was actually observed, and on which exact builds. Read
this before relying on Bridge with a native host.

**How to read it.** *Qualified* means the behavior was observed by running an
owned test fixture or probe against the exact build named in the row, on macOS with
Apple silicon, with the evidence checked by its own required checks. It is a result
about that build and that scope at the time it was run, not a property of "Codex" or
"Claude Code" in general and not a release guarantee. A harness build you configure
(`[[adapters.profiles.executables]]` with a path and SHA-256) enables a profile; that
digest is *configuration*, not qualification, and `bridge doctor` reports adapter
capabilities and Telegram as `not_verified` for exactly this reason. A different
harness build, a changed source revision or a different configuration is unqualified
until its probes are run again.

| | |
|---|---|
| Source | Bridge 0.2.0, producer API v1 (wire, core and native contracts revision 3), storage schema 6 |
| Platform | macOS, Apple silicon (`aarch64-apple-darwin`) |
| Toolchain | Rust 1.98.1 |

## Platform

| Platform | Status |
|---|---|
| macOS Apple silicon | Supported target. Source checks and the isolated package lifecycle run here. |
| macOS Intel | Not a target and not exercised. |
| Linux | Not supported. Library crates use Unix sockets and files, but nothing is claimed; the Codex message carrier needs a confinement launcher that is absent, so it is unsupported. |
| Windows | Not supported. |

## Source checks (no host, no model)

These need no native harness and are what CI runs on macOS Apple silicon (see
[Contributing](../CONTRIBUTING.md#build-and-check)): formatting, strict Clippy over all
targets, the workspace tests, private-item Rustdoc and `cargo xtask check-public`. The
tests exercise real service, adapter-channel, hook, relay and CLI executables with
labeled stand-in harnesses (`bridge-fixture`) and scripted carriers. A stand-in harness is
**not** native Claude Code or Codex evidence.

`cargo xtask qualify --prefix DIR` additionally runs the packaged release in one new
isolated prefix: tamper refusal, install, version and hash, start, doctor, operator read,
upgrade, rollback, restart and stop. It touches no installation, harness store or session
and uses no network or model. It is package and lifecycle evidence only.

## Native host matrix

| Capability | Codex 0.162.0-alpha.17.2 (SHA-256 `0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28`) | Claude Code |
|---|---|---|
| Protected hook caller binding, root and child attestation | Observed on owned sessions | Observed on owned sessions of the older builds below |
| `inject` through the recipient's own hook | Observed on owned sessions | Observed on the older builds below |
| `message` carrier | Queue acceptance with native readback observed on owned sessions. **Application native message delivery observed once in an owner-operated session on the installed 0.2.0 service:** the signed Codex application frontend accepted a v1 direct-address message exactly once and the recipient chat returned a hidden acknowledgement, with no receiver `bridge_me` or manual enrollment; the root caller attestation worked after a final service restart and all earlier events and attempts stayed immutable. This is not consumer cutover, GUI clear, unload or restart qualification | Peer `later` message answered in a distinct turn observed on the older builds below |
| Producer v1 direct-MCP registration and publication | Qualified: an unknown raw producer and a portable-SDK producer registered and published through the public protocol; two concurrent callers each received only their own message; restart recovered identical historical registration and custody; close and exact replay added no delivery attempts | **Not qualified** |
| Nested inner-call MCP | Unsupported | Unsupported |
| Host observations (`host_observations`) | Absent: no operation and no capability | Absent |
| Detached backend assertions (`consume_assertion`) and delivery-scope retirement | Implemented and fixture-tested; the native runs used a profile with these features off, so they are **not** qualified in a native deployment | Not qualified |
| Generic detached consumer | Not claimed | Not claimed |
| Working applications, chats and global hooks | Only the single owner-operated delivery above; hook coexistence, GUI clear, unload and full application restart are not qualified | Not touched, not qualified |

Claude Code builds 2.1.294 and 2.1.296 are legacy-version qualifiers. The Claude hook,
caller, inject, `later` message, pause and lifecycle probes were run against 2.1.296
(and a profile example references 2.1.294) at earlier source revisions. Those results
are separate from the Codex qualification and from this source revision: re-run the
probes against your exact Claude Code build and Bridge revision before relying on them.

## What is explicitly not established

- Any native result for a harness build other than the ones named above.
- Native semantics of negative receipt statuses and of an early `held` followed by a
  terminal receipt on the Claude inbox: negatives and contradictions are treated as
  unknown outcomes, never as known-unsent.
- `approval_mode = "approve"` semantics for the Codex MCP frontend: the probes show the
  parsed value and the host refusing an unlisted tool, not that this value is what permits
  the listed tools. The `_meta.callId` equals `tool_use_id` observation holds on the named
  Codex build only; on another build a mismatch finds no record and refuses.
- Linux or Windows operation, and any installation into a working application without a
  deliberate local test.
- Live Telegram delivery. The notifier is exercised against a local HTTP stub only.
- Wall-clock regressions, which are not modeled (leases and deadlines use the service clock as given).
- Receiver-side manual enrollment is **not** required for any of this: a recipient needs
  no `bridge_me` call. Permission-waiting, unknown and dead recipients are visible holds
  and an uncertain delivery is never resent automatically.

## Reproduce or extend qualification

The probes live in `crates/bridge-adapters/qualification/` and are described in the
[adapter guide](../crates/bridge-adapters/README.md#manual-native-qualification-probes).
They are manual, need the exact harness build and explicit operator provisioning, can
spend model budget and read host state, and never run in CI or `cargo test`. Each uses a
fresh owned Bridge state, a new session and a daemon grant naming only it, writes a
`checks.json` where every required check must be exactly `true`, redacts synthetic
credentials, and confines its processes with a paired network-denial control where
no network is intended. Keep the resulting logs and session identifiers private; publish
only the build identity, the scope and the pass or fail result, as this page does.
