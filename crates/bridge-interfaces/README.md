# bridge-interfaces

Restricted root MCP, operator recovery, outbound owner notification and
product packaging for Agent Bridge. Everything here consumes `bridge-core`,
`bridge-client` and `bridge-adapters` through their public APIs: no second
incident, attempt or hook store, no direct database access, no native
dispatch.

Qualification status: **not_verified**. See [Evidence levels](#evidence-levels).

## Executables

| Binary | Runs as | Holds |
|---|---|---|
| `bridge-root-mcp <channel> <relay>` | stdio MCP server launched by the harness | nothing secret |
| `bridge-root-relay <interfaces.toml>` | resident daemon started by the operator | core *publisher* grant token (keep_all, exact recipients) |
| `bridge` | operator CLI | reads the core *operator* grant token from its protected file |

`bridge-native-daemon`, `bridge-hook` and `bridge-daemon` come from the core
and adapter crates and are packaged unchanged.

## Root tools

Exactly three tools: `bridge_me`, `bridge_send`, `bridge_status`. Closed
JSON schemas (`additionalProperties: false`); unknown tools, parameters and
methods are refused.

Caller identity is never an argument. For each `tools/call` the frontend
reads only the harness-owned `_meta` (Claude `claudecode/toolUseId`; Codex
`threadId` + `callId` + `x-codex-turn-metadata`), asks the adapter registry
to attest the call (it joins exactly one fresh, unconsumed `PreToolUse`
record from the same harness incarnation and epoch) and to seal a
single-use proof, and forwards `{proof, tool, arguments}` to the relay.
The relay redeems the proof itself; the registry admits redemption only
from a configured relay executable (path + SHA-256), once, within 30 s,
while the caller's binding epoch is unchanged. Then the relay requires:

1. a **root** actor acting as its own session (`may_act_as_address`): a
   Claude subagent sharing its root session, or any child, is refused —
   never redirected to the parent;
2. a configured `[[root.callers]]` scope;
3. valid closed arguments.

Refusal classes: `caller_unattested` (no provider configured — the default
without `[root].channel`), `caller_missing`, `caller_duplicate`,
`caller_stale`, `caller_conflicting`, `caller_not_evidence`,
`caller_unavailable`, `forbidden`, `invalid`, `oversize`, `expired`,
`unknown_tool`, `core_unavailable` (nothing sent), `custody_unknown`
(repeat the same `request_id`; idempotent) and the core's own classes.

- `bridge_me` → the attested address, endpoint epoch, channel and the
  permitted recipients, modes, kinds, `keep_all` and body bound.
- `bridge_send(request_id, recipient, kind, mode, body, expires_at_ms?)` →
  publishes `keep_all` to an exact allowlisted recipient. The core event id
  is derived from the caller address, actor and `request_id`: repeating a
  `request_id` replays (same receipt), a changed body under it conflicts,
  and callers never share events (equal native ids in different stores
  stay distinct; the address is part of the id). Sender harness/session
  metadata is audit-only, never rendered or provenance. Oversize bodies and past expiries are
  refused explicitly; nothing is truncated.
- `bridge_status(request_id)` → only the caller's own events: `custody`,
  `native` (`not_handed`, `in_flight`, `native_accepted`, `native_held`,
  `written_no_receipt`, `hook_emitted`, `unknown`, `refused`,
  `disposed_not_delivered`), `context` and `processed` (`observed` only for
  that exact recorded tier) and `uncertainty` (manual resolution, never an
  automatic resend). Tier details are withheld.

There is no enumeration, retry, reset, drain, admin, raw passthrough or
acknowledgement tool. **`bridge.ack` is not implemented**: core records
`receipt_token_possession` only as an annotation, issues no recipient
receipt token and has no predeclared release/GC tier, and no producer has
declared one (peer gap for the core module).

### Host installation of the frontend

Launch `bridge-root-mcp <adapter-channel-socket> <relay-socket>` as an MCP
server of the harness. The relay socket's directory must be `0700`.

- **Claude Code**: an `mcpServers` entry with that command and arguments.
- **Codex 0.162 (observed binary, not qualified)**: MCP tool calls under
  `approval_policy = "never"` fail with "requires approval". The loaded
  build carries per-server `enabled_tools`, `default_tools_approval_mode`
  and per-tool `tools.<name>.approval_mode`. The scoped choice is:

  ```toml
  [mcp_servers.agent-bridge-root]
  command = "/ABS/bin/bridge-root-mcp"
  args = ["/ABS/run/ch/c.sock", "/ABS/run/rl/relay.sock"]
  enabled_tools = ["bridge_me", "bridge_send", "bridge_status"]
  [mcp_servers.agent-bridge-root.tools.bridge_me]
  approval_mode = "approve"
  # same for bridge_send and bridge_status
  ```

  The variant semantics are inferred from strings in the binary and are
  **not qualified**; do not change the global approval policy. A host
  qualification must show that only the named tools are pre-approved (an
  unlisted tool still requires approval). Until then native root-caller
  acceptance remains blocked.

## Operator recovery guide

```sh
bridge operator interfaces.toml incidents [--all] [--limit N]
bridge operator interfaces.toml holds
bridge operator interfaces.toml evidence PUBLISHER EVENT ATTEMPT TIER --detail TEXT
bridge operator interfaces.toml dispose  PUBLISHER EVENT --note TEXT
bridge operator interfaces.toml waive    PUBLISHER EVENT --note TEXT
bridge operator interfaces.toml retry    PUBLISHER EVENT --note TEXT --accept-duplicate-risk
bridge operator interfaces.toml pause RECIPIENT --reason TEXT | resume RECIPIENT | shutdown
```

Each incident shows the core's reason, age, deadlines, responsible source,
blocked dependents and resolution, plus a `category` and `next_action`:
`unknown` (possible hand-off, outcome unknown), `overdue` (native hold or
written-without-receipt past its deadline), `held` (recipient
unknown/disconnected/paused), `refused`, `integrity`. Routine
written-without-receipt hand-offs within their deadline are not incidents.

Procedure for an `unknown` incident:

1. Look for positive exact-session evidence (receipt, marker in the
   recipient's context). If found, record it with `evidence`: the incident
   resolves at that tier without another send.
2. Absence of evidence is not proof of non-delivery. Decide explicitly:
   `dispose` (closes it, never claims delivery) or `retry
   --accept-duplicate-risk` (another attempt of the **same** event; the
   core records the duplicate risk permanently). The CLI refuses a retry
   without that flag.
3. Dependents of a disposed or lost predecessor wait until `waive`.

Every decision is applied and audited by the core under the operator grant
identity. A lost answer to a decision is never resent; re-read the
incidents. Nothing — timer, missing ack, hook, notification — repeats an
uncertain event automatically. The root MCP has none of these powers.

## Owner notification (Telegram)

```toml
[telegram]
token_file = "/ABS/secrets/telegram-bot-token"   # 0600, owned by you
chat_id = "123456789"                            # numeric id or @username
# api_base = "https://api.telegram.org"          # the only accepted value
# timeout_ms = 15000                             # 1..=120000 (total deadline)
[notify]
ledger = "/ABS/state/notify-ledger.json"         # 0600 file, one per core
# max_attempts = 3                               # 1..=10
```

`bridge notify interfaces.toml` reports each open incident once as plain
text to the fixed chat (`sendMessage` with `chat_id` and `text` only). There
is no `getUpdates`, webhook, command, reply or approval path. The origin is
fixed: any other `api_base` (host, scheme, user info, port, path, trailing
slash, controls) is refused at load and again by `send` before the token is
read. The token is read from the protected file and given to
`/usr/bin/curl` through stdin as a config file (never argv); `~/.curlrc` is
ignored, the environment is cleared, `--noproxy *`, only https, no
redirects, bounded total time and reply. Every provider answer and
transport diagnostic is redacted against the token (verbatim, `%3A`-encoded
and its secret part) before anything is classified, cut or stored.
Configuration parse errors report only a line number, never parser text.

Classification: HTTP 2xx with `ok: true` → `provider_accepted` (not proof
of reading; output always says `owner_read: unknown`); 4xx → known refusal
(429 honours `retry_after`). `known_unsent` only when no request can have
left this host: no or invalid configuration, unprotected token, curl not
started, or — after the whole request config reached curl — curl exits 1,
2, 3, 6, 7, 35 or 60 (protocol, init, URL, DNS, TCP connect, TLS handshake,
certificate; single request, no proxy, no redirect). Everything else is
`possible_send`: a partially delivered request config, timeouts, lost or
ambiguous answers, 5xx.

The ledger is bound to one core (its socket path) and records each
incident's identity (publisher, event, kind, creation time), so a reused
incident number is reported again instead of being suppressed. It records
a `sending` intent before each request; a crash during a send becomes
`possible_send`, which is never resent automatically. Only known-unsent
reports are retried, at most `max_attempts`, then `gave_up`. Ledger and lock
must be private regular files (links refused); the ledger is replaced
through an exclusively created temporary file. Without `[telegram]` every
report is `known_unsent: owner not notified`; incidents stay open and
visible. A live send requires owner-provided configuration and a separately
authorized test delivery; none has happened.

## Install, doctor, rollback

```sh
cargo xtask package                     # prints manifest + sums_sha256
./install.sh --bundle /ABS/dist/agent-bridge-0.1.0+LABEL --sums-sha256 HEX \
  --home /ABS/home --bin-dir /ABS/bin
bridge service start core  --home H --state S --config daemon.toml
bridge service start relay --home H --state S --config interfaces.toml
bridge doctor --home H --bin-dir B --state S --config interfaces.toml --daemon-config daemon.toml
bridge rollback --home H
bridge service stop relay|core --home H --state S
```

- `install.sh` checks `SHA256SUMS` against the digest you pass and every
  expected file against `SHA256SUMS` before running anything from the
  bundle; then the verified `bridge self-install` re-verifies, seals the
  release under `releases/<version>+<label>` (read-only), switches
  `current` atomically and links launchers. Same release id with other
  bytes, foreign launcher files and core-schema downgrades are refused.
- The home must be new, empty or an existing Agent Bridge home (owned by
  you); a non-empty foreign directory is refused untouched. Staging,
  state and `current` updates use exclusively created, unpredictable
  temporary names; an interrupted install may leave a `.staging-*`
  directory, which is never reused or deleted automatically. The service
  state directory must be yours; pid and log files that are links or
  foreign are refused. `cargo xtask qualify --prefix` requires a new path.
- `self-install` always requires the attested `--sums-sha256`; `bridge
  verify` without it reports `attested: false` (internal consistency only).
- Activation records the new state, including the core-schema floor,
  durably *before* switching `current`. An interruption in between leaves
  a recorded intent: `doctor` (`install.current_link`) and `service start`
  refuse and report it; re-running the install or `rollback` completes it
  first (rollback still refuses to go below the floor). State naming an
  invalid release id, a linked release directory or a manifest of another
  release is refused.
- Activation does not restart daemons. After install or rollback, set
  `[[adapters.relays]]` in the daemon configuration to the printed
  `relay_binding` (the real release path and SHA-256 of
  `bridge-root-relay`) and restart both components; `doctor` reports a
  running build that differs from the active release and an unbound relay.
- Rollback switches program code only. The custody database, incidents,
  audit and configuration stay; a release with an older core schema than
  one already activated is refused (no live-schema downgrade, no snapshot
  restore).
- `doctor` exit codes: 0 no failed check, 2 a check failed, 3 invalid
  invocation. Declared adapter capabilities and Telegram are always
  `not_verified`; the overall qualification is `not_verified`.

## Evidence levels

- Unit tests: classification, ledger, closed schemas, secret files,
  bundle/seal/rollback rules, Telegram over a real `curl` process against a
  local HTTP stub.
- `tests/root_composition.rs`: real core service, adapter registry and
  channel, real `bridge-root-mcp`, `bridge-root-relay` and `bridge`
  executables with kernel peer identities. The harness is a labeled
  stand-in (the test executable qualified in an owned profile); it is **not**
  native Claude or Codex evidence.
- `cargo xtask qualify --prefix ABS`: the packaged release in one isolated
  prefix (tamper refusal, install, version/hash, start, doctor, upgrade,
  rollback, restart, stop).
- Not established: native caller attestation on a real loaded harness,
  Codex per-tool approval behaviour, real Telegram delivery, installed-host
  operation.
