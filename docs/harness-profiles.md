# Harness profiles

Status: owner-agreed direction (2026-10-24). Stages 1 and 2 below are
implemented; each stage keeps the existing trust model and the behavior of the
already supported harnesses unchanged.

## Goal

A new agent harness can be connected, and an update of a connected harness can
be absorbed, without changing Agent Bridge code. Bridge implements one
harness contract once; each harness is described by a *profile* (operator-owned
configuration data) and, only where the harness cannot satisfy the contract by
itself, by a *connector* (a small plugin or process next to the harness that
speaks a Bridge-owned protocol, like the existing OpenCode plugin).

Profiles say where to look, never whom to trust. Every existing kernel check
stays in Bridge: peer UID and ancestry, the marked harness process, an
executable unchanged since its process started, a private canonical store, the
single-use join of a protected `PreToolUse` record, endpoint epochs and the
dispatch fences. A wrong profile can only make Bridge refuse.

## The contract

| Part | What Bridge needs | Generic mechanisms |
|---|---|---|
| Identity | which process is the harness and which store it owns | executable markers; store from an environment variable or a home-relative default |
| Lifecycle | session start, activity, idle, input waits, end; root or child | Claude-compatible hook JSON through `bridge-hook`; or a connector that emits the same JSON (OpenCode) |
| Caller proof | the MCP call that reached Bridge is the one a protected hook observed | host `_meta` call id (Claude, Codex); connector-stamped context (OpenCode); one-time hook token (new) |
| Inject | context at a natural hook point of an active session | Claude-compatible `hookSpecificOutput.additionalContext` |
| Message | delivery into an idle session | native owner route; built-in carriers of the built-in harnesses; connector delivery (later stage) |

The Claude Code hook format has become the de facto standard: Codex hooks and
ZCode hooks emit the same `hook_event_name` / `session_id` / `tool_use_id`
payload and accept the same `hookSpecificOutput` reply. Bridge therefore treats
that format as the native lifecycle and inject contract for every harness that
does not declare otherwise.

## Harness identifier

`Harness` becomes an open identifier: 1 to 32 bytes of `[a-z0-9-]`, starting with
a letter. The canonical names of the built-in harnesses are unchanged
(`codex`, `claude-code`, `opencode`), so canonical addresses, stored events,
hashes, grants (`native_scopes`) and consumer configuration are unchanged.
Legacy spellings (`Codex`, `ClaudeCode`, `OpenCode`) are still accepted where
they were accepted before (configuration, route journal), and the route journal
keeps writing them for the built-in harnesses so that a rollback to an earlier
build still reads it. Any other harness is written by its canonical name.

An address of a harness that no profile serves is still a valid address: core
custody and the protocol accept it, and the adapter refuses to attest or deliver
for it (no policy, no binding), exactly as for a built-in harness that the
operator did not enable.

## Profile fields

A profile is one `[[adapters.harnesses]]` entry. The fields that exist today keep
their meaning; the new fields are optional for the built-in harnesses, whose
defaults reproduce the current behavior exactly.

```toml
[[adapters.harnesses]]
harness = "zcode"                 # canonical id (legacy spellings accepted)
namespace = "zcode-main"          # native_store_namespace of its addresses
inject = true
message = false
executable_markers = ["zcode"]    # default: the built-in product name, else the id
store_env = "ZCODE_HOME"          # optional; read from the harness process's own environment
store_home = ".zcode"             # optional; $HOME-relative fallback
child_address = "shared"          # "shared": a child acts inside the root's address; "own": its own address
caller_proof = ["hook-token"]     # accepted proofs, see below
```

| Field | `codex` | `claude-code` | `opencode` | other harnesses |
|---|---|---|---|---|
| `executable_markers` | `codex` | `claude` | `opencode` | the id |
| store | `CODEX_HOME`, `~/.codex` | `CLAUDE_CONFIG_DIR`, `~/.claude` | parent of `OPENCODE_DB` | `store_env`, then `store_home`; one of them is required |
| `child_address` | `own` | `shared` | `own` (plugin lifecycle) | `shared` |
| lifecycle feed | hooks | hooks | connector | hooks |
| `caller_proof` | `codex-meta` | `claude-meta` | `opencode-meta` | `hook-token` |
| message carriers | owner route, Codex application, queue helper | owner route, Claude inbox | owner route (required) | owner route |

The built-in carriers and the Codex Desktop idle gateway remain code owned by
the built-in harnesses. They are optional enhancements: if a harness update
breaks one, only that carrier holds or refuses; identity, caller proof, inject
and the owner route keep working.

## Caller proof strategies

- `claude-meta`, `codex-meta`, `opencode-meta`: the existing `_meta` contracts,
  unchanged.
- `hook-token` (new): when the protected `PreToolUse` hook of a Bridge root tool
  call is admitted, the daemon issues a single-use, unguessable token bound to
  that call record and returns it in the hook reply as
  `hookSpecificOutput.updatedInput` (the original input plus
  `bridge_call_token`). The harness executes the tool with the updated input; the
  restricted MCP frontend strips the token from the arguments before any other
  processing and presents it instead of `_meta`. The daemon joins the token to
  exactly one fresh, unconsumed record, checks that the frontend is a descendant
  of the same live harness incarnation, consumes the record and attests the
  caller exactly as for a native call id. The token never authorizes by itself
  (ancestry and epoch checks still apply), is never logged, and expires with the
  record. It does not depend on host `_meta`, so a harness update that renames
  its metadata keys does not affect it.

A profile may accept several strategies (for example `["claude-meta",
"hook-token"]`), which lets an operator switch a built-in harness to the
host-independent proof by configuration if a host update breaks its `_meta`.

## Diagnostics

A refusal names the profile and the missing contract element instead of a
generic `caller_not_evidence`, for example `zcode: no protected PreToolUse
record for this call (is bridge-hook installed for PreToolUse?)` or `zcode:
store_env ZCODE_HOME and store_home both unresolvable`. `bridge doctor` lists
every profile with its resolved defaults.

## Stages

1. Open identifier and profile-driven registry; the three built-in harnesses
   become built-in profiles with unchanged behavior. All existing tests pass.
2. `hook-token` caller proof and profile diagnostics.
3. ZCode connected by a profile only; live acceptance of `bridge_me`,
   `bridge_send` and `bridge_status` from a ZCode session.
4. Generic connector delivery protocol (generalized native owner route) and the
   ZCode idle-session delivery mechanism.

Out of scope here: other repositories that parse native addresses with their own
closed harness lists (Agent Run, Agent Pool) need their protocol dependency
updated before they can address a new harness's sessions.
