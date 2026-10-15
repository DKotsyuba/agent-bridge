# bridge-interfaces

Restricted root MCP, operator recovery, outbound owner notification and
product packaging for Agent Bridge. Everything here consumes `bridge-core`,
`bridge-client` and `bridge-adapters` through their public APIs: no second
incident, attempt or hook store, no direct database access, no native
dispatch.

Qualification status: **not_verified**. See [Evidence levels](#evidence-levels) and the
[qualification matrix](../../docs/qualification.md).

## Executables

| Binary | Runs as | Holds |
|---|---|---|
| `bridge-root-mcp <channel> <relay>` | stdio MCP server launched by the harness | nothing secret |
| `bridge-root-relay <interfaces.toml>` | resident daemon started by the operator | core *publisher* grant token (keep_all, configured recipient scope) |
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

For address-based personal messaging, set `recipients = ["*"]` in the root
publisher grant and its root caller policies. This permits every well-formed
native address without per-session edits or service restarts; exact lists
remain supported. Sender attestation, root-only access, kinds, modes and
body limits are unchanged. Delivery still requires a qualified native endpoint;
an unknown address waits visibly rather than being rerouted or fabricated.

Refusal classes: `caller_unattested` (no provider configured — the default
without `[root].channel`), `caller_missing`, `caller_duplicate`,
`caller_stale`, `caller_conflicting`, `caller_not_evidence`,
`caller_unavailable`, `forbidden`, `invalid`, `oversize`, `expired`,
`unknown_tool`, `core_unavailable` (nothing sent), `custody_unknown`
(repeat the same `request_id`; idempotent) and the core's own classes.
The frontend adds two of its own: `relay_unavailable` (the relay could not
be reached before the request was written: nothing was sent, call the tool
again) and `relay_outcome_unknown` (the request was written but no answer
arrived within the frontend's finite wait of about 115 s (the relay's expected
budget, not a hard bound: queueing, attestation trickle and an expired replay's
additional custody lookup are not counted): a `bridge_send` may
have been published, so repeat the **same** `request_id` or ask
`bridge_status` with it; never use a new `request_id` for the same
message).

- `bridge_me` → the attested address, endpoint epoch, channel and the
  permitted recipients, modes, kinds, `keep_all` and body bound.
- `bridge_send(address, message, request_id?, kind?, mode?, expires_at_ms?)` →
  publishes `keep_all` within the configured address scope. Kind defaults to
  `bridge.message`, mode to `message`. The canonical address string is sufficient;
  legacy structured `recipient` and `body` spellings remain supported. If the
  request id is omitted, the frontend derives it from the authenticated native
  tool-call identity before writing to the relay and returns it in the receipt.
  Already connected older frontends are compatible: the relay derives a
  fallback id from their redeemed one-use proof if normalization is absent.
  Use the returned id for status/reconciliation or an explicit idempotent retry;
  after a lost/uncertain answer never create a fresh id for the same message. The core event id
  is derived from the caller address, actor and `request_id`: repeating a
  `request_id` replays (same receipt), a changed body under it conflicts,
  and callers never share events (equal native ids in different stores
  stay distinct; the address is part of the id). Sender harness/session
  metadata is audit-only, never rendered or provenance. Oversize bodies and past expiries are
  refused explicitly; nothing is truncated. An identical accepted request
  still replays its original custody identity after expiry; changed content
  conflicts and a new expired identity refuses without admission.
- `bridge_status(request_id)` → only the caller's own events: `custody`,
  `native` (`not_handed`, `in_flight`, `native_accepted`, `native_held`,
  `written_no_receipt`, `hook_emitted`, `unknown`, `refused`),
  `context` and `processed` (`observed` only for
  that exact recorded tier) and `uncertainty` (manual resolution, never an
  automatic resend). A disposition closes the workflow and future dispatch
  but never claims non-delivery: `delivery.state` is `disposed`, `native`
  keeps what the surviving evidence shows and `uncertainty` stays set with
  `disposed: true`. An earlier unknown attempt is never erased by a later
  known-unsent one (nor by a duplicate-risk retry: an `unhanded` event whose
  earlier attempt may have reached the recipient is `unknown`, not
  `not_handed`, and a `refused` one — retries exhausted or a permanent
  refusal after such a retry — is `unknown` too, its open incident's reason
  also naming the earlier hand-off); when the record cannot rule the earlier
  hand-off out (a full evidence window, a duplicate-risk mark, or a disposed
  event with no record at all, which cannot be told from a closed legacy
  hand-off), `native` is `unknown`. Tier details are withheld.

There is no enumeration, retry, reset, drain, admin, raw passthrough or
acknowledgement tool, and no counts, incident or lineage tool (those are
operator-only CLI commands). **`bridge.ack` is conditional and inactive**:
core records `receipt_token_possession` only as an operator annotation that
never settles, releases, renders or retries anything, and no producer in
this delivery declares that evidence tier. The guard that refuses it is a
required passing check, not a waived one.

### Host installation of the frontend

Launch `bridge-root-mcp <adapter-channel-socket> <relay-socket>` as an MCP
server of the harness. The relay socket's directory must be `0700`.

- **Claude Code**: an `mcpServers` entry with that command and arguments.
- **Codex 0.162**: MCP tool calls under `approval_policy = "never"` fail with
  "requires approval". The loaded build carries per-server `enabled_tools`,
  `default_tools_approval_mode` and per-tool `tools.<name>.approval_mode`. The
  scoped choice is:

  ```toml
  [mcp_servers.agent-bridge-root]
  command = "/ABS/bin/bridge-root-mcp"
  args = ["/ABS/run/ch/c.sock", "/ABS/run/rl/relay.sock"]
  enabled_tools = ["bridge_me", "bridge_send", "bridge_status"]
  [mcp_servers.agent-bridge-root.tools.bridge_me]
  approval_mode = "approve"
  # same for bridge_send and bridge_status
  ```

  Root-caller attestation and direct v1 delivery were observed on the Codex
  build named in the [qualification matrix](../../docs/qualification.md). What is
  not fully qualified is the specific `approval_mode` semantics: the probes show the
  parsed value and the host refusing an unlisted tool, not that this value alone
  is what permits the listed ones. Do not change the global approval policy, and
  confirm on your own build that only the named tools are pre-approved (an unlisted
  tool must still require approval).

## Operator recovery guide

```sh
bridge operator interfaces.toml counts
bridge operator interfaces.toml retention PUBLISHER EVENT
bridge operator interfaces.toml incidents [--all] [--limit N]
bridge operator interfaces.toml holds [--limit N]
bridge operator interfaces.toml evidence PUBLISHER EVENT ATTEMPT TIER --detail TEXT
bridge operator interfaces.toml dispose  PUBLISHER EVENT --note TEXT
bridge operator interfaces.toml waive    PUBLISHER EVENT --note TEXT
bridge operator interfaces.toml retry    PUBLISHER EVENT --note TEXT --accept-duplicate-risk
bridge operator interfaces.toml pause RECIPIENT --reason TEXT | resume RECIPIENT | shutdown
bridge operator interfaces.toml transfer-lineage --recipient ADDR --kind KIND --mode MODE \
  --project PROJECT --task TASK --stream STREAM --new-publisher ID --note TEXT
```

All operator commands need the core *operator* grant; a publisher or root
credential is refused by the core (`forbidden`) and the refusal is printed
unchanged. Before the connection is opened the CLI refuses blank notes
and reasons, a retry without `--accept-duplicate-risk`, and a lineage
scope or new producer that fails the core's public validators (address,
kind, mode, stream, publisher id, project/task metadata) — such a decision
never contacts the core. Unknown flags, a misspelled option and surplus or
missing positional arguments exit 3 the same way, before any connection
(each action accepts only its own flags). The core itself validates the final operator
text (for example its length and control characters) before any
mutation and its refusal is printed unchanged. Each decision is sent once;
a lost answer prints `outcome unknown … it was not resent`: re-read
`counts` and `incidents` before deciding again. A failed read-only query
(`counts`, `incidents`, `holds`) prints `read failed: the current data is
unknown`; it changed nothing.

- `counts` prints the core's ten complete totals at one instant
  (`unhanded`, `reserved`, `invoking`, `held` — including written without
  receipt — `review`, `accepted`, `hook_submitted`, `refused`, `disposed`,
  `open_incidents`). They are totals, not a sample.
- `retention PUBLISHER EVENT` is an operator-only exact nullable read of
  custody identity/disposition, bounded delivery evidence, original expiry,
  stored envelope byte count, compacted tombstone flag, current GC guard and
  the event's full-scope latest watermark. Null means the identity is absent;
  no payload or credential is disclosed. Eligibility does not promise actual
  compaction (keep-newest may keep bytes). Expiry or compaction never recalls
  an earlier possible effect; the read changes neither storage nor delivery.
- `incidents` and `holds` are listings bounded by `--limit` (default 100,
  at most 200); use `counts` for totals.
- `transfer-lineage` hands a `latest` stream lineage to another producer.
  The scope is the full coalescing scope without the publisher: canonical
  recipient, kind, mode, declared project and task (pass `""` when
  undeclared) and stream. The core decides everything: it refuses while
  another producer's event in the lineage has a possible or unknown native
  effect (resolve it first), holds the previous producer's still pending
  snapshots with a `lineage_authority_lost` incident and declines its
  further `latest` publications. Event ids, watermarks, attempts and
  evidence are never rewritten. The handover is audited with the note.

Each incident shows the core's reason, age, deadlines, responsible source,
blocked dependents and resolution, plus a `category` and `next_action`:
`unknown` (possible hand-off, outcome unknown), `overdue` (native hold or
written-without-receipt past its deadline), `held` (recipient
unknown/disconnected/paused), `refused`, `integrity`, `lineage` (the
producer lost authority by an audited transfer: its held event is not
dispatched while another producer owns the lineage and is never replayed
automatically; confirm the current owner and usually `dispose` it. Only if
the original producer must be authoritative again, transfer the lineage
back explicitly and then decide an audited `retry` with its recorded
duplicate risk). Routine
written-without-receipt hand-offs within their deadline are not incidents;
they are counted in `held`.

A `refused` event supports an audited `dispose`, which closes its workflow
without recalling or settling an earlier possible effect. The core refuses
`retry` for this state; the duplicate-risk retry control applies only to
`review` and `held`. Inspect all retained evidence before deciding. A new
notification is a separate explicit decision, not recovery of the old event.

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
and its secret part) before anything is classified, cut or stored, and
again on every decoded string of a JSON answer (a JSON escape cannot hide
the token).
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
incident number is reported again instead of being suppressed. The
ledger drops an entry only on the core's own closed row of the same
incident (same number and identity, state other than open); absence from a
capped or racing page, or a failed page read, prunes nothing, so a
`possible_send` or `provider_accepted` entry is never forgotten while its
incident may still be open. Each CLI pass fetches one include-closed sequence
page of at most 200 rows under the ledger lock. The durable
`after_seq`/`through_seq` cursor scans a captured finite high-water range;
final-page completion resets it for new or reopened rows. Page state is live,
not an immutable snapshot. Outcomes are saved before advancing the cursor,
so an interrupted pass repeats its page safely without re-sending ambiguous
or accepted reports. With 201 open incidents behind 200 terminal report
entries, the second pass reaches 201. Output states partial page coverage.
Old ledgers start a fresh scan while keeping every send record.
Operating ceiling: no entry-count or byte bound; a large/open backlog needs
multiple passes and the whole ledger is read and rewritten (pretty JSON,
file and directory sync) before every send and at each pass. Closure is reached
by paging, never unsafe absence pruning. It records
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
./install.sh --bundle /ABS/dist/agent-bridge-0.2.0+LABEL --sums-sha256 HEX \
  --home /ABS/home --bin-dir /ABS/bin
bridge service start core  --home H --state S --config daemon.toml
bridge service start relay --home H --state S --config interfaces.toml
bridge doctor --home H --bin-dir B --state S --config interfaces.toml --daemon-config daemon.toml
bridge rollback --home H
bridge service stop relay|core --home H --state S
```

- `install.sh` copies the bundle into a private temporary
  directory, checks `SHA256SUMS` against the digest you pass and every
  expected file against `SHA256SUMS` on that copy before running anything
  from it (a bundle changed afterwards cannot change what runs; a linked
  bundle root, `bin` or `SHA256SUMS` is refused before anything runs); then the
  verified `bridge self-install` re-verifies and seals the release under
  `releases/<version>+<label>` (read-only; the sealed bytes must hash to the
  attested digest, so a bundle rewritten even consistently after
  verification is refused), switches `current` atomically and links
  launchers. Same release id with other
  bytes, foreign launcher files and core-schema downgrades are refused.
- The home must be new, empty or an existing Agent Bridge home (owned by
  you, writable by no group or other user, never chmod-ed by the installer);
  a non-empty foreign directory, or a home or `releases` directory others
  can write, is refused untouched. `service start` verifies the whole
  active release against its manifest first, so a planted or modified
  executable is never run. Staging,
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
  restore). This composition's core writes storage schema 6 (producer v1 routes,
  lifetimes and stream lineage authority); once a schema-6 release has been activated, the
  floor is 6 and any older-schema release is refused for install and rollback.
- `doctor` exit codes: 0 no failed check, 2 a check failed, 3 invalid
  invocation. Declared adapter capabilities and Telegram are always
  `not_verified`; the overall qualification is `not_verified`.
- `doctor` `relay.tools` lists the configured closed three-tool set and each
  caller's exact scope, recipients, kinds and modes plus the body limit and
  `keep_all` policy. Exact-session scopes take precedence over whole-store
  scopes; these are configured permissions, reported `not_verified` until
  loaded host/tool qualification is separately established. No credential
  file contents are displayed.
- `doctor` `recovery.pending` is `not_configured` with `state: unknown`
  when the configuration has no `[operator]` section (pending work cannot
  be read), and otherwise reads the core's complete `counts` and then,
  separately, a bounded sample of at most 200 open incidents; the two
  reads are not one snapshot. `ok`/`empty` only when the counts show
  nothing waiting, nothing in review and no open incident *and* the
  sample is empty; `warn`/`routine_waiting` when events wait (for example
  a paused recipient) with no incident or review in either read;
  otherwise `warn`/`attention` (open incidents, hand-offs in review, or a
  sample that disagrees with the counts). Totals come from `counts`; the
  category breakdown covers only the sample. `observations_consistent`
  is false when the sample holds more incidents than the counted total,
  and `sample_complete` is true only for a consistent sample of exactly
  the counted number that is smaller than the 200-incident cap. A refused counts call, authentication error or unreadable
  token is `fail` with `state: unknown`, never zero. No native delivery
  is asserted.

## Evidence levels

- Unit tests: classification, ledger, closed schemas, secret files,
  bundle/seal/rollback rules, Telegram over a real `curl` process against a
  local HTTP stub.
- `tests/root_composition.rs`: real core service, adapter registry and
  channel, real `bridge-root-mcp`, `bridge-root-relay` and `bridge`
  executables with kernel peer identities. The harness is a labeled
  stand-in (the test executable, recognized under an owned harness policy and store); it is **not**
  native Claude or Codex evidence.
- `tests/operator_counts.rs`: real current-schema core service and the real
  `bridge` CLI: complete counts, CLI lineage transfer with the incident it
  creates, more than 200 open incidents against the bounded doctor sample,
  publisher-credential refusal, pre-request validation and a silent core
  that receives each decision exactly once (outcome unknown, not resent).
- The conditional `bridge.ack` guard is a required passing check: the
  root tool list and calls refuse acknowledgement, counts, lineage and
  incident tools (`mcp` unit tests).
- `cargo xtask qualify --prefix ABS`: the packaged release in one isolated
  prefix (tamper refusal, install, version/hash, start, doctor, upgrade,
  rollback, restart, stop).
- Not established by these tests: native caller attestation on other builds,
  the exact Codex per-tool `approval_mode` semantics, real Telegram delivery
  and installed-host operation on your machine. See the
  [qualification matrix](../../docs/qualification.md) for what was observed.
