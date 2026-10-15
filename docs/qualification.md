# Qualification and support matrix

What is supported, what was actually observed, and on which exact builds. Read
this before relying on Bridge with a native host.

**How to read it.** *Qualified* means the behavior was observed by running an
owned test fixture or probe against the exact build named in the row, on macOS with
Apple silicon, with the evidence checked by its own required checks. It is a result
about that build and that scope at the time it was run, not a property of "Codex" or
"Claude Code" in general and not a release guarantee. A harness policy you configure
(`[[adapters.harnesses]]` with a namespace and the capabilities you assert; no store path or
executable is declared) enables a harness; that policy is *configuration*, not
qualification, and `bridge doctor` reports adapter capabilities and Telegram as
`not_verified` for exactly this reason. Any build of the harness product can register, so
the build named in a row records what was observed; Bridge does not enforce it, and no
harness executable digest is checked. A different harness build, a changed source revision
or a different configuration is unqualified until its probes are run again.

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

### Managed OpenCode owner wake

A private local candidate was exercised with OpenCode 2.0.28 and Agent Run on
2026-10-15. The first-party lifecycle plugin registered the actual native
session from its private store and observed its first completed idle turn.
One SDK publication then carried a newly generated marker, absent from the
initial task, through Bridge's `opencode_input` owner route. The same session,
PID and full process-birth identity executed turn two and called its real
private `finish` tool once with that marker. The native transcript contains one
matching input whose native message ID equals Bridge's acceptance receipt.
There was one delivery attempt and no uncertain result. The completion notice
arrived automatically in the bound Codex chat; supervisor process-group and
descendant cleanup, private broker shutdown and socket retirement were verified.

Exact executed SHA-256 values: Bridge daemon
`41acb1c2e1c249686223596ee81eab1888460029e65c75d5ec83a0c593086433`,
hook `eab945eae5ede7bb3da1ddc0214c4dbf1dedf83755b42d4df5d65fdec6655a08`,
Agent Run `dc02e15291bdd36726777fc0d4dd5047f05e515c599a4820be3ba56cae7395d9`.
This qualifies that managed live-session route on those local candidates.
It does not qualify standalone OpenCode root MCP return delivery, child wake,
context injection, an idle IDE application, installation or publication.

| Capability | Codex 0.162.0-alpha.17.2 (SHA-256 `0d5ac7aae20c4eda6242428d5e218c55ba96d8763fda2a271088ff37104b9d28`) | Claude Code |
|---|---|---|
| Protected hook caller binding, root and child attestation | Observed on owned sessions | Observed on owned sessions of the older builds below |
| `inject` through the recipient's own hook | Observed on owned sessions | Observed on the older builds below |
| `message` carrier | Queue acceptance with native readback observed on owned sessions. **Application native message delivery observed once in an owner-operated session on the installed 0.2.0 service:** the signed Codex application frontend accepted a v1 direct-address message exactly once and the recipient chat returned a hidden acknowledgement, with no receiver `bridge_me` or manual enrollment; the root caller attestation worked after a final service restart and all earlier events and attempts stayed immutable. This is not consumer cutover, GUI clear, unload or restart qualification | Peer `later` message answered in a distinct turn observed on the older builds below |
| Producer v1 direct-MCP registration and publication | Qualified: an unknown raw producer and a portable-SDK producer registered and published through the public protocol; two concurrent callers each received only their own message; restart recovered identical historical registration and custody; close and exact replay added no delivery attempts | **Not qualified** |
| Owner-routed idle wake of a supervisor-owned live session (`BRIDGE_NATIVE_OWNER_SOCKET`) | Source-tested with a scripted stand-in owner only: exact direct-parent and owner-executable fences, one request frame, conservative receipt mapping, no resend or fallback. **Not qualified:** no native Codex turn or owner implementation was observed | Source-tested with a scripted stand-in owner only. **Not qualified:** no native Claude replay acknowledgement or owner implementation was observed |
| Automatic recovery after an application update or restart: digest refresh for Bridge's own relay and audience builds, MESSAGE-only gateway to an idle Desktop thread, frontend discovery among thousands of stale entries | Source-tested with synthetic native-owner input only. **Not natively qualified:** no real Codex update, restart or model wake was observed through Bridge, and no real harness registered from an arbitrary runtime store; whether a resumed turn can exist before its transcript append, and the exact transcript flush order after `Stop`, are unobserved and need a manual native check (a fixed read-only native thread-state query if they differ). Registration no longer distinguishes a downgrade or a different build of the harness from the build you tested | Not applicable (no gateway); registration from an arbitrary canonical owner-only store is source-tested only |
| Nested inner-call MCP | Unsupported | Unsupported |
| Host observations (`host_observations`) | Absent: no operation and no capability | Absent |
| Detached backend assertions (`consume_assertion`) and delivery-scope retirement | Implemented and fixture-tested; the native runs used a harness policy with these features off, so they are **not** qualified in a native deployment | Not qualified |
| Generic detached consumer | Not claimed | Not claimed |
| Working applications, chats and global hooks | Only the single owner-operated delivery above; hook coexistence, GUI clear, unload and full application restart are not qualified | Not touched, not qualified |

Claude Code builds 2.1.294 and 2.1.296 are legacy-version qualifiers. The Claude hook,
caller, inject, `later` message, pause and lifecycle probes were run against 2.1.296
(and an earlier `[[adapters.profiles]]` example referenced 2.1.294) at earlier source revisions. Those results
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
- Owner-routed wake against a real supervisor, Codex build or Claude Code build: the
  stand-in tests do not establish a native turn, a replayed user frame, a context
  observation or a consumer result.
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
