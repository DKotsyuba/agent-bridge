/**
 * Root-run Codex Bridge-composition lifecycle qualification (Q4, Codex
 * side): the A22 lifecycle seam — protected-hook binding and caller join,
 * archive and disconnect holds, backend restart with the same native
 * thread id, and fork while an own event is pending — observed through a
 * live `bridge-native-daemon`, the product `bridge-hook` as the loaded
 * frontend's own hooks, the fixture MCP server and the daemon's own Core
 * database. MODEL-BEARING: it refuses to run unless `BRIDGE_Q4_PAID=1`
 * (root only); `--self-test` runs the pure validators without any native
 * process.
 *
 * Bounds: model `gpt-6-luna` at low effort (checked against the loaded
 * build's own catalog; the catalog is not an entitlement), at most 3 short
 * prompted native turns, an absolute 15 minute budget plus the bounded
 * cleanup allowance. Token usage is measured from the build's own
 * `thread/tokenUsage/updated` notifications and reported as tokens; no
 * dollar cost is claimed. Each turn's usage is the INCREMENT of its own
 * correlated snapshots (`usageIncrement`: final cumulative total minus the
 * baseline `first.total - first.last`), so a fork's or resumed thread's
 * inherited history and an earlier turn's replayed counters are never
 * counted, and every model call of an MCP turn is; the raw cumulative
 * counters stay in `turn_log`. Unavailable or invalid usage fails the run and
 * forbids any further paid turn. The 150000-token ceiling is checked before
 * each turn starts (a started turn may overrun it). Normal protected Codex authentication and the
 * normal store are used as-is: nothing reads or copies credentials, edits
 * any configuration file or installs anything, and the probe's own threads
 * are archived (reversible) at cleanup.
 *
 * Isolation, all before the first model call. The Q3 gate machinery from
 * `codex-native-probe.cjs` is reused unchanged: a paired loopback fence
 * witness for the confined gate policy; a confined hooks/config gate that
 * trusts only this probe's own hooks by hash and disables every other hook
 * per launch (`hooks.state`); the exact-tool MCP approval parsed back; every
 * foreign MCP server of the user configuration disabled per launch and read
 * back as disabled; plugins, apps, memories, browser and goals disabled.
 * The Q3 MODEL launches (`codex exec`) also pass `--ignore-user-config` and
 * `--ignore-rules`; `codex app-server` has no such flags in the installed
 * 0.162.0-alpha.17.2 (its `--help` is read at run time and each flag is
 * passed if and only if that help lists it, `isolation_flags_supported`).
 * Where unsupported, user configuration is NOT ignored: the launch neutralises
 * what it can by explicit per-launch overrides (`notify=[]`,
 * `project_doc_max_bytes=0`, empty `instructions` and `developer_instructions`)
 * and `config/read` is read back under the SAME flags: both instruction
 * fields must be empty (`config_residual_closed`) and the names of the
 * remaining non-session setting origins are recorded. `notify`, config
 * profiles, global AGENTS files and execution-policy rules are not exposed by
 * `config/read`; their neutralisation is NOT read back and stays a residual
 * surface, as do the built-in Codex tools under a read-only sandbox with
 * approval `never`.
 * Only the read-only fixture tools `bridge_me` (approved) and
 * `bridge_unlisted` (the host negative boundary: the host must refuse it with
 * an approval refusal and the fixture must never see it) are added.
 * The config gate reads configuration, not the thread runtime. Before the FIRST
 * paid turn (after `thread/start` and the daemon start, because the thread id
 * must exist and the daemon's grant names it) the driver therefore observes the
 * exact own server on the exact own thread with the build's
 * `mcpServerStatus/list` (`serverName: bridge_probe`, `threadId`, `detail:
 * toolsAndAuthOnly`, complete pagination, up to 60 s): `runtimeStatus` must be
 * `connected`, `toolsError` empty and both `bridge_me` and `bridge_unlisted`
 * advertised (`mcpInventoryVerdict`); anything unavailable, failed, malformed,
 * incomplete or timed out aborts BEFORE any model turn (`mcp_inventory_ready`).
 * Only the own fields are kept in `mcp_inventory`. This observes readiness; it
 * does not prove the model will call the tool.
 *
 * One backend process "A" (an unconfined `codex app-server` over stdio, the
 * supported frontend) starts a thread T1 BEFORE the daemon so the daemon's
 * publisher grant can name T1; then in order:
 *  1. turn 1 on T1 (A): `bridge_me` root caller join, the exact binding row
 *     (epoch E1) equal to the caller's epoch, the host-refused
 *     `bridge_unlisted`, and the frontend's own `hook/completed` records;
 *  2. T1 archived: an `inject` event published meanwhile must stay pending
 *     (no attempt, no tier, same recipient and envelope hash) with NO pause
 *     policy anywhere; T1 unarchived;
 *  3. disconnect: A is killed; a `message` event published meanwhile must
 *     be held by the dead-incarnation reason (never the no-wake text) with
 *     no hand-off, the older binding epoch stays E1, and the message is
 *     closed by an audited operator disposition so a later live binding can
 *     never turn it into a native queue turn;
 *  4. restart: a NEW backend process "B" resumes T1; then T1 is forked to a
 *     NEW thread T2 while the inject event is still pending, and turn 2 runs
 *     on T2: its caller must be T2 on its own address, the inject event must
 *     stay on T1 (no attempt for either recipient, T1's binding epoch
 *     unchanged, the marker absent from the fork's reply);
 *  5. turn 3 on T1 (B): the binding must renew with a strictly larger epoch
 *     E2, the caller join must carry E2, the inject event must be handed out
 *     by T1's own natural hook (attempt actor T1, epoch E2, proof reference
 *     naming B's process id, delivery `hook_submitted`) and its marker must
 *     appear in T1's reply.
 * Native `sessionId` equality or difference between a thread and its fork is
 * recorded as an observed fact only, never as a role signal.
 *
 * Daemon build requirement, HISTORICAL f2 finding (observed, read-only trace;
 * the warm-digest production fix is present in this source assembly, whose
 * current native run remains pending): the f2 registry hashes
 * the harness executable on the FIRST hook it admits, inside the hook request
 * and under the registry lock (`verify_loaded`). An unoptimized `sha2` takes
 * 27-35 s on the 246 MB Codex build (measured here with the registry's own
 * `file_sha256`; about 12 s elapsed between the first hook and the refusal in
 * the root's native run), beyond the 5 s hook timeout. That is consistent with
 * (not proven by) the root's native timeline: the first SessionStart and the
 * queued UserPromptSubmit time out, the binding already carries the first
 * hook's arrival time, and the single `hook_refused: not_evidence` follows
 * when the dead UserPromptSubmit peer is finally looked up. Build the daemon with
 * `--config 'profile.dev.package.sha2.opt-level=3'` (1.6 s measured) or in
 * release. The probe does not waive such a timeout: a non-completed hook run
 * fails `t1_hooks_observed` and is kept in `t1_hook_failures`, and every
 * daemon warning is ordered in `daemon_warnings`.
 *
 * Usage: `cargo +1.98.1 build --offline -p bridge-adapters --bins`, then
 * `BRIDGE_Q4_PAID=1 node qualification/codex-lifecycle-probe.cjs` (env:
 * `BRIDGE_BIN_DIR`, `CODEX_EXE`, default `codex` on PATH). Writes
 * `checks.json` in a fresh private directory; exits 0 only when every
 * required check is exactly true and nothing failed.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { run } = require('./probe-lib.cjs');
const { networkFenceWitness, coreCall, dbRows, usageTotal } = require('./lifecycle-lib.cjs');
const { MODEL, EFFORT, POLICY, DISABLED, EVENTS, ME_APPROVAL, gateRead, stateOverride, ownApprovalParsed, appServer } = require('./codex-native-probe.cjs');

/** A JSON value (see `lifecycle-lib.cjs`).
 * @typedef {import('./lifecycle-lib.cjs').JsonValue} JsonValue */
/** A row of the probe's own Core database (see `lifecycle-lib.cjs`).
 * @typedef {import('./lifecycle-lib.cjs').DbRow} DbRow */
/** Parameters of one App Server request: string-keyed JSON, shaped per method by the loaded build's schema.
 * @typedef {{[param: string]: JsonValue}} RpcParams */
/** One App Server JSON-RPC response: the request id and EITHER a method-specific result object OR an error.
 * @typedef {{id: number, result?: {[field: string]: JsonValue}, error?: {code: number, message: string}}} RpcResponse */
/** The native per-turn and per-thread token breakdowns of a `thread/tokenUsage/updated` notification (only `totalTokens` is read).
 * @typedef {{last: {totalTokens: number}, total: {totalTokens: number}}} TokenUsage */
/** One retained App Server notification (no request id); only the parameter fields this probe reads are named, every other field is ignored.
 * @typedef {{method: string, params?: {threadId?: string, turnId?: string, turn?: {id?: string, status?: string}, run?: {eventName?: string, status?: string, source?: string}, item?: {type?: string, text?: string, tool?: string, status?: string, error?: JsonValue}, tokenUsage?: TokenUsage}}} Notification */
/** One `mcpServerStatus/list` request and the response it got (null when none arrived in time), kept together so the exact parameters sent can be checked.
 * @typedef {{params: RpcParams, response: RpcResponse|null}} McpExchange */
/** Verdict of one MCP inventory read: whether the own server is connected on the own thread with all expected tools, why not, whether the state is terminal (no waiting can fix it), and ONLY the own fields observed.
 * @typedef {{ready: boolean, terminal: boolean, reason: string, runtime_status: string|null, tools: string[], pages: number}} McpVerdict */
/** A hook run the frontend reported (`hook/completed`): camelCase event name, run status and hook source (`sessionFlags` is this probe's own per-launch hook).
 * @typedef {{event: string, status: string, source: string}} HookRun */
/** One row of the Core `events` table as this probe selects it.
 * @typedef {{event_id: string, recipient: string, delivery: string, attempts_made: number, attempt_seq: number|null, envelope_hash: string}} EventRow */
/** One row of the Core `attempts` table as this probe selects it (`proof_ref` names the harness process as `<label>:<pid>@<start>:...`).
 * @typedef {{attempt_seq: number, state: string, actor: string, endpoint_epoch: number, proof_ref: string}} AttemptRow */
/** The delivery block of a publisher status as the fixture prints it.
 * @typedef {{attempts_made: number, attempt_state: string, delivery?: string, hold_reason?: string|null, tiers?: {tier: string}[]}} Delivery */
/** One evidence record the fixture MCP server appends per tool call (only the read fields are named).
 * @typedef {{tool: string, unlisted_called?: boolean, refused?: string, caller?: {role: string, native_id: string, address: string, epoch: number, may_act_as_address: boolean}}} McpRecord */
/** A gate-projected hook: scalar fields only plus `own` (see `gateRead` in `codex-native-probe.cjs`).
 * @typedef {{key: string|null, source: string|null, eventName: string|null, enabled: boolean|null, trustStatus: string|null, currentHash: string|null, own: boolean}} GateHook */
/** A live stock `codex app-server` backend: label, process, retained notifications (appended live), server-request methods the probe refused, launch time (epoch ms), a request sender (null when no response arrived within `ms`, default 30000) and the initialize handshake (true when answered).
 * @typedef {{label: string, child: import('node:child_process').ChildProcess, events: Notification[], serverRequests: string[], startedAt: number, request: (method: string, params: RpcParams, ms?: number) => Promise<RpcResponse|null>, init: () => Promise<boolean>}} Backend */

/**
 * Built Bridge binaries.
 * @type {string}
 */
const bin = process.env.BRIDGE_BIN_DIR || path.resolve(__dirname, '../../../target/debug');
/**
 * Whether the model-bearing run is authorised (root only).
 * @type {boolean}
 */
const PAID = process.env.BRIDGE_Q4_PAID === '1';
/**
 * Most prompted native turns.
 * @type {number}
 */
const MAX_TURNS = 3;
/**
 * Cumulative-token ceiling above which no further turn starts.
 * @type {number}
 */
const TOKEN_STOP = 150_000;
/**
 * Total elapsed readiness budget, in milliseconds, shared by inventory requests before the first paid turn.
 * @type {number}
 */
const MCP_READY_MS = 60_000;
/**
 * Most `mcpServerStatus/list` pages one inventory read follows; a longer listing counts as incomplete.
 * @type {number}
 */
const MAX_MCP_PAGES = 5;
/**
 * Longest wait for a turn's native `turn/completed`, in milliseconds; a turn without it is interrupted and the run aborts.
 * @type {number}
 */
const TURN_TIMEOUT_MS = 240_000;
/**
 * Largest tolerated retained response line, in characters.
 * @type {number}
 */
const MAX_LINE = 60_000;
/**
 * Notification methods dropped before logging (high-volume deltas).
 * @type {RegExp}
 */
const NOISY = /\/(delta|outputDelta|progress)$|^account\/|^mcpServer\/startupStatus|^thread\/status\/changed$/;
/** Actionable hold reasons of a recipient whose harness is dead (the Codex carrier's own attestation refusals, `registry.rs` attest_recipient). The
 * generic Core carrier-chain fallback ("no carrier attests this endpoint: ...", which at f2 carries the LAST carrier's unrelated refusal) is deliberately
 * NOT accepted: absence of a hand-off qualifies only when the actual dead-incarnation reason is present, so the check fails against a core that
 * overwrites it. Case-sensitive on purpose.
 * @type {RegExp}
 */
const DEAD_REASON = /(harness process is gone|the recipient session ended|no attested binding)/;
/**
 * Canonical lowercase/uppercase UUID (the only form interpolated into SQL).
 * @type {RegExp}
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * Checks that must all be exactly true.
 * @type {string[]}
 */
const REQUIRED = [
  'versions_recorded', 'model_in_catalog', 'network_fence_witnessed', 'hooks_isolated', 'approval_config_effective', 'foreign_mcp_disabled',
  'config_residual_closed', 'daemon_started', 't1_thread_started', 'mcp_inventory_ready', 'turn1_completed', 't1_root_attested', 't1_binding_matches_caller', 't1_hooks_observed', 't1_hooks_clean',
  'unlisted_refused_by_host', 'unlisted_not_executed', 'loaded_process_identified',
  'archive_ok', 'archived_inject_pending_without_pause', 'unarchive_ok',
  'backend_a_dead', 'dead_message_held_fail_closed', 'dead_message_disposed_unsent', 'inject_pending_through_disconnect', 'old_epoch_retained_while_dead',
  'restart_new_process', 'restart_resumed_same_thread', 'fork_new_thread_id', 'turn2_completed', 'fork_caller_is_fork_thread', 'fork_binding_distinct',
  'fork_event_stays_on_original', 'fork_reply_lacks_marker',
  'turn3_completed', 't1_resumed_user_prompt_hook_positive', 'epoch_renewed_on_restart', 't1_caller_after_restart', 'inject_handed_by_original_hook', 'marker_in_original_reply',
  'only_own_hooks_ran', 'no_owned_hook_failures', 'turns_within_budget', 'tokens_measured', 'no_daemon_refusals', 'threads_archived_cleanup',
];

/** Hook runs the frontend reported for one thread, from its
 * `hook/completed` notifications.
 * @param {Notification[]} events Retained notifications.
 * @param {string} thread Native thread id.
 * @returns {HookRun[]} One entry per completed hook run, in order.
 */
function hookRuns(events, thread) {
  return events.filter(e => e.method === 'hook/completed' && e.params && e.params.threadId === thread && e.params.run)
    .map(e => ({ event: String(e.params.run.eventName), status: String(e.params.run.status), source: String(e.params.run.source) }));
}

/** Hook runs of one thread that did NOT complete (failed, blocked, stopped,
 * still running), with the native timing and error entries, so a timeout is
 * kept as evidence instead of being counted or dropped silently.
 * @param {Notification[]} events Retained notifications.
 * @param {string} thread Native thread id.
 * @returns {{event: string, status: string, started_at: number|null, completed_at: number|null, duration_ms: number|null, entries: string[]}[]} One entry per non-completed run (entry texts bounded to 200 characters).
 */
function hookFailures(events, thread) {
  return events.filter(e => e.method === 'hook/completed' && e.params && e.params.threadId === thread && e.params.run && e.params.run.status !== 'completed')
    .map(e => ({
      event: String(e.params.run.eventName), status: String(e.params.run.status),
      started_at: Number.isFinite(e.params.run.startedAt) ? e.params.run.startedAt : null,
      completed_at: Number.isFinite(e.params.run.completedAt) ? e.params.run.completedAt : null,
      duration_ms: Number.isFinite(e.params.run.durationMs) ? e.params.run.durationMs : null,
      entries: (e.params.run.entries || []).map(entry => String(entry && entry.text).slice(0, 200)),
    }));
}

/** Every warning or error line of the daemon's structured stderr with its
 * event name, class and timestamp, so refusals can be ordered against hook
 * runs and publications. Unparsable lines are skipped.
 * @param {string} stderr The daemon's stderr text (one JSON object per line).
 * @returns {{event: string, level: string, class: string|null, ts_ms: number|null}[]} In log order.
 */
function daemonWarnings(stderr) {
  const found = [];
  for (const line of stderr.split('\n')) {
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    if (entry && (entry.level === 'warn' || entry.level === 'error')) {
      found.push({ event: String(entry.event), level: String(entry.level), class: typeof entry.class === 'string' ? entry.class : null, ts_ms: Number.isFinite(entry.ts_ms) ? entry.ts_ms : null });
    }
  }
  return found;
}

/** Whether a hook sequence is positive: no run of the thread failed (or was blocked, stopped or still running) AND every required event has at
 * least one completed run. One completed run of an event never excuses another failed one.
 * @param {HookRun[]} runs Hook runs from `hookRuns`.
 * @param {{event: string}[]} failures Non-completed runs from `hookFailures`.
 * @param {string[]} required Required camelCase event names.
 * @returns {boolean}
 */
function hooksPositive(runs, failures, required) {
  return failures.length === 0 && required.every(event => runs.some(run => run.event === event && run.status === 'completed'));
}

/** Whether a completed MCP tool-call item is the HOST's explicit approval refusal: it failed AND its error message names an approval. A
 * connection, parser, transport or tool-runtime error, a missing error, or a successful call is not the host boundary (the Q3 classification:
 * failed with an approval error).
 * @param {{status: string, error: JsonValue}} call One item from `toolCalls`.
 * @returns {boolean}
 */
function approvalRefusal(call) {
  const text = call.error && typeof call.error === 'object' && !Array.isArray(call.error) ? call.error.message : call.error;
  return call.status === 'failed' && typeof text === 'string' && /approval/i.test(text);
}

/** Judges one complete inventory read of the own MCP server on the own thread.
 *
 * The read is a chain of `mcpServerStatus/list` exchanges. Every request must
 * carry EXACTLY `serverName: bridge_probe`, `threadId: <thread>` and
 * `detail: toolsAndAuthOnly` (a read for another server or thread proves
 * nothing about this one); the first has no cursor and each later one the
 * previous response's `nextCursor`; every response is a success whose `data`
 * is an array; the last page has no `nextCursor` (a listing cut short or
 * longer than the page bound is incomplete). Across the pages exactly one row
 * named `bridge_probe` must exist (rows of other servers are ignored and
 * never retained), whose `runtimeStatus` is `connected` (the thread-runtime
 * connection state; `starting`/`notStarted`/explicit null are waited for,
 * while missing, malformed, unsupported or unusable values are terminal), whose
 * `toolsError` is null or absent, and whose `tools` catalog holds all
 * expected owned tools (default `bridge_me` and `bridge_unlisted`, by
 * catalog key or tool name). Every
 * catalog value must be a non-null, non-array object; null, scalar and array
 * definitions make the inventory malformed and terminal.
 * @param {string} thread The own native thread id.
 * @param {McpExchange[]} exchanges The exchanges of one read, in order.
 * @param {string[]} [tools] Nonempty unique owned tool names; defaults preserve
 * the legacy probe. Names come from the frozen run's private configuration.
 * @returns {McpVerdict} The verdict; `tools` lists only expected own names found.
 */
function mcpInventoryVerdict(thread, exchanges, tools = ['bridge_me', 'bridge_unlisted']) {
  /** Builds a verdict with the page count of this read.
   * @param {boolean} ready Whether the gate may open.
   * @param {boolean} terminal Whether waiting cannot fix the state.
   * @param {string} reason Short cause.
   * @param {string|null} [status] Observed runtime status.
   * @param {string[]} [tools] Own tool names found.
   * @returns {McpVerdict}
   */
  const verdict = (ready, terminal, reason, status = null, tools = []) => ({ ready, terminal, reason, runtime_status: status, tools, pages: exchanges.length });
  if (tools.length === 0 || new Set(tools).size !== tools.length) return verdict(false, true, 'invalid owned tool set');
  if (exchanges.length === 0 || exchanges.length > MAX_MCP_PAGES) return verdict(false, true, 'no or too many pages');
  const rows = [];
  let cursor = null;
  for (const [index, { params, response }] of exchanges.entries()) {
    if (!params || params.serverName !== 'bridge_probe' || params.threadId !== thread || params.detail !== 'toolsAndAuthOnly') return verdict(false, true, 'request is not for the own server on the own thread');
    if ((params.cursor || null) !== cursor) return verdict(false, true, 'pagination chain broken');
    if (!response || response.error || !response.result || !Array.isArray(response.result.data)) return verdict(false, true, 'inventory unavailable or malformed');
    rows.push(...response.result.data);
    const next = response.result.nextCursor;
    const last = index === exchanges.length - 1;
    if (last ? (next !== null && next !== undefined) : typeof next !== 'string' || next === '') return verdict(false, true, 'pagination incomplete');
    cursor = typeof next === 'string' ? next : null;
  }
  const own = rows.filter(row => row && row.name === 'bridge_probe');
  if (own.length !== 1) return verdict(false, true, own.length === 0 ? 'own server not listed' : 'own server listed more than once');
  const [row] = own;
  const status = typeof row.runtimeStatus === 'string' ? row.runtimeStatus : null;
  if (row.toolsError !== null && row.toolsError !== undefined) return verdict(false, true, 'tool discovery failed', status);
  if (row.runtimeStatus === null) return verdict(false, false, 'server runtime status not available yet', null);
  if (status === null) return verdict(false, true, 'malformed server runtime status', null);
  if (status === 'starting' || status === 'notStarted') return verdict(false, false, 'server runtime not connected yet', status);
  if (status !== 'connected') return verdict(false, true, 'unsupported or unusable server runtime status', status);
  const catalog = row.tools && typeof row.tools === 'object' && !Array.isArray(row.tools) ? row.tools : null;
  if (!catalog) return verdict(false, true, 'tool catalog missing', status);
  const entries = Object.entries(catalog);
  if (entries.some(([, tool]) => !tool || typeof tool !== 'object' || Array.isArray(tool))) return verdict(false, true, 'malformed tool catalog entry', status);
  const names = new Set(entries.flatMap(([key, tool]) => [key, tool && tool.name]));
  const found = tools.filter(name => names.has(name));
  if (found.length !== tools.length) return verdict(false, true, 'own tools not all advertised', status, found);
  return verdict(true, false, 'connected with all own tools', status, found);
}

/** Remaining time available for one inventory request or for accepting its result.
 * @param {number} deadline Monotonic readiness deadline in milliseconds.
 * @param {number} runRemaining Total probe budget left in milliseconds.
 * @param {number} now Current monotonic time in milliseconds.
 * @returns {number} The request bound, at most 15 seconds and preserving 60 seconds for cleanup; non-positive means expired.
 */
function mcpRequestBudget(deadline, runRemaining, now) {
  return Math.min(15_000, deadline - now, runRemaining - 60_000);
}

/** Refuses an otherwise-ready MCP listing if its bounded read finished too late.
 * @param {string} thread Own native thread id.
 * @param {McpExchange[]} exchanges One complete inventory read.
 * @param {number} remainingBudgetMs Positive time left before both readiness and cleanup limits, or zero/negative if expired.
 * @returns {McpVerdict} The normal inventory verdict while in budget, otherwise a closed readiness verdict.
 */
function mcpInventoryWithinBudget(thread, exchanges, remainingBudgetMs) {
  return mcpInventoryVerdict(thread, remainingBudgetMs > 0 ? exchanges : []);
}

/** Whether a help text lists a command-line flag as an option (an exact whitespace- or comma-delimited token, so `--ignore-user-config` is not found
 * inside a longer flag).
 * @param {string} help The `--help` output.
 * @param {string} flag The flag, for example `--ignore-rules`.
 * @returns {boolean}
 */
function supportsFlag(help, flag) {
  return help.split(/[\s,]+/).includes(flag);
}

/** Whether the read-back effective configuration shows both instruction
 * fields empty (absent, null or empty string): the one place `config/read`
 * can confirm the per-launch neutralisation of global instructions.
 * @param {{instructions: boolean|null, developer_instructions: boolean|null}|null} read Presence flags of the read-back (true = non-empty text), null when not answered.
 * @returns {boolean}
 */
function instructionsClosed(read) {
  return Boolean(read) && read.instructions === false && read.developer_instructions === false;
}

/** Whether EVERY observed hook run came from the probe's own per-launch
 * hooks (`sessionFlags`); an empty list proves nothing.
 * @param {HookRun[]} runs Hook runs from `hookRuns`.
 * @returns {boolean}
 */
function ownHooksOnly(runs) {
  return runs.length > 0 && runs.every(run => run.source === 'sessionFlags');
}

/** The agent's reply text of one turn: its completed `agentMessage` items.
 * @param {Notification[]} events Retained notifications.
 * @param {string} thread Native thread id.
 * @param {string} turnId Native turn id.
 * @returns {string} The joined texts (empty when none).
 */
function agentText(events, thread, turnId) {
  return events.filter(e => e.method === 'item/completed' && e.params && e.params.threadId === thread && e.params.turnId === turnId
    && e.params.item && e.params.item.type === 'agentMessage').map(e => String(e.params.item.text || '')).join('\n');
}

/** Completed MCP tool-call items of one tool on one thread.
 * @param {Notification[]} events Retained notifications.
 * @param {string} thread Native thread id.
 * @param {string} tool Tool name.
 * @returns {{tool: string, status: string, error: JsonValue}[]} Their native status and error.
 */
function toolCalls(events, thread, tool) {
  return events.filter(e => e.method === 'item/completed' && e.params && e.params.threadId === thread && e.params.item
    && e.params.item.type === 'mcpToolCall' && e.params.item.tool === tool)
    .map(e => ({ tool, status: String(e.params.item.status), error: e.params.item.error || null }));
}

/** One turn's usage from its own correlated token snapshots.
 *
 * Every `thread/tokenUsage/updated` of the EXACT thread and turn is one
 * snapshot: `total` is the thread's cumulative counter (it includes the
 * history a resumed or forked thread inherited) and `last` the most recent
 * model call. The baseline is `first.total - first.last` (what the thread had
 * used before this turn's first call) and the increment is
 * `final.total - baseline`: all model calls of the turn (MCP tool rounds
 * included), none of the inherited history. Snapshots must be consistent:
 * counters are finite non-negative safe integers, `last <= total`, and
 * every later snapshot's total exceeds the previous by exactly its `last`.
 * Missing, invalid, decreasing or inconsistent snapshots yield `null` (never
 * a zero default); snapshots of other turns, including an earlier turn of the
 * same thread, are ignored.
 * @param {Notification[]} events Retained notifications.
 * @param {string} thread Native thread id.
 * @param {string} turnId Native turn id.
 * @returns {{baseline: number, increment: number, raw_total: number, snapshots: number}|null} Baseline, this turn's increment, the raw final cumulative counter and the snapshot count; null when unavailable or invalid.
 */
function usageIncrement(events, thread, turnId) {
  const snapshots = events.filter(e => e.method === 'thread/tokenUsage/updated' && e.params && e.params.threadId === thread
    && e.params.turnId === turnId && e.params.tokenUsage).map(e => e.params.tokenUsage);
  if (snapshots.length === 0) return null;
  /** Whether a native counter is usable: a finite non-negative safe integer.
   * @param {JsonValue|undefined} value Candidate counter.
   * @returns {boolean}
   */
  const counter = value => Number.isSafeInteger(value) && value >= 0;
  let baseline = null, previous = null;
  for (const snapshot of snapshots) {
    const total = snapshot.total && snapshot.total.totalTokens, last = snapshot.last && snapshot.last.totalTokens;
    if (!counter(total) || !counter(last) || last > total) return null;
    if (previous === null) baseline = total - last;
    else if (total < previous || total - previous !== last) return null;
    previous = total;
  }
  return { baseline, increment: previous - baseline, raw_total: previous, snapshots: snapshots.length };
}

/** Whether an event row is still untouched and pending: never handed out,
 * no attempt, and its recipient and envelope hash exactly as first read.
 * @param {EventRow|null} row Current `events` row (null when unreadable, which proves nothing).
 * @param {EventRow|null} first The same row as first read.
 * @returns {boolean}
 */
function pendingUntouched(row, first) {
  return Boolean(row && first && row.delivery === 'unhanded' && row.attempts_made === 0 && row.attempt_seq === null
    && row.recipient === first.recipient && row.envelope_hash === first.envelope_hash);
}

/** Whether a publisher status shows an event held fail-closed for a dead
 * incarnation:
 * zero attempts, no attempt state, a dead-incarnation reason and NOT the
 * no-wake pause text.
 * @param {Delivery|null} delivery Delivery block of the status.
 * @returns {boolean}
 */
function heldByDeadIncarnation(delivery) {
  return Boolean(delivery && delivery.attempts_made === 0 && delivery.attempt_state === 'none'
    && DEAD_REASON.test(delivery.hold_reason || '') && !/no-wake/.test(delivery.hold_reason || ''));
}

/** Whether the attempts of one recipient show exactly one hook hand-off by
 * the expected actor, at the expected epoch, by the expected loaded
 * process (the proof reference names `<pid>@`).
 * @param {AttemptRow[]} attempts Attempt rows of the recipient.
 * @param {string} thread Expected actor (the addressed thread).
 * @param {number} epoch Expected endpoint epoch.
 * @param {number} pid Expected harness process id.
 * @returns {boolean}
 */
function handedByHook(attempts, thread, epoch, pid) {
  return attempts.length === 1 && attempts[0].actor === thread && attempts[0].endpoint_epoch === epoch
    && new RegExp(`:${pid}@`).test(attempts[0].proof_ref) && /hook/.test(attempts[0].state);
}

/** Drops high-volume notifications and bounds oversized lines before a
 * line is logged or parsed (`Probe.spawn` `keep` contract).
 * @param {string} line One raw stdout line.
 * @returns {string|null} The line to keep, or null to drop it.
 */
function keepLive(line) {
  let message;
  try { message = JSON.parse(line); } catch { return null; }
  if (!message || typeof message !== 'object') return null;
  if (message.method !== undefined && message.id === undefined && NOISY.test(String(message.method)) && message.method !== 'thread/tokenUsage/updated') return null;
  return line.length > MAX_LINE ? JSON.stringify({ id: message.id, method: message.method, truncated_chars: line.length }) : line;
}

/** Pure-logic assertion check (`--self-test`): no native process. */
function selfTest() {
  const assert = require('node:assert/strict');
  /** Builds a `hook/completed` notification for thread `T`.
   * @param {string} event Hook event name.
   * @param {string} status Run status.
   * @param {string} source Hook source.
   * @returns {Notification}
   */
  const hook = (event, status, source) => ({ method: 'hook/completed', params: { threadId: 'T', run: { eventName: event, status, source } } });
  const runs = hookRuns([hook('userPromptSubmit', 'completed', 'sessionFlags'), hook('stop', 'completed', 'sessionFlags'), { method: 'hook/completed', params: { threadId: 'U', run: { eventName: 'stop', status: 'completed', source: 'user' } } }], 'T');
  assert.equal(runs.length, 2);
  assert.equal(ownHooksOnly(runs), true);
  const ok4 = ['sessionStart', 'userPromptSubmit', 'preToolUse', 'postToolUse'].map(event => ({ event, status: 'completed', source: 'sessionFlags' }));
  assert.equal(hooksPositive(ok4, [], ['sessionStart', 'userPromptSubmit', 'preToolUse', 'postToolUse']), true);
  assert.equal(hooksPositive([...ok4, { event: 'userPromptSubmit', status: 'failed', source: 'sessionFlags' }], [{ event: 'userPromptSubmit' }], ['userPromptSubmit']), false); // one completed run never excuses a failed one
  assert.equal(hooksPositive(ok4.slice(1), [], ['sessionStart', 'userPromptSubmit']), false); // a required event never observed
  assert.equal(hooksPositive([], [], []), true);
  const refusal = { status: 'failed', error: { message: 'tool call requires approval and none is available' } };
  assert.equal(approvalRefusal(refusal), true);
  assert.equal(approvalRefusal({ status: 'failed', error: 'approval denied' }), true);
  assert.equal(approvalRefusal({ status: 'failed', error: { message: 'MCP transport closed' } }), false); // connection error
  assert.equal(approvalRefusal({ status: 'failed', error: { message: 'failed to parse tool result' } }), false); // parser error
  assert.equal(approvalRefusal({ status: 'failed', error: { message: 'tool runtime error: exit 1' } }), false);
  assert.equal(approvalRefusal({ status: 'failed', error: null }), false);
  assert.equal(approvalRefusal({ status: 'completed', error: { message: 'approval' } }), false); // not a failed call
  assert.equal(approvalRefusal({ status: 'failed', error: { message: 42 } }), false);
  const help = '  -c, --config <key=value>\n      --enable <FEATURE>\n      --ignore-user-config\n      --ignore-rules  Skip rules\n';
  /** A synthetic own thread id for the inventory assertions.
   * @type {string} */
  const T = '00000000-0000-4000-8000-000000000b01';
  /** The exact request a read of thread `thread` must send.
   * @param {string|null} cursor Continuation cursor, or null for the first page.
   * @param {string} [thread] Thread id asked about (default: the own thread).
   * @returns {RpcParams}
   */
  const askFor = (cursor, thread = T) => ({ serverName: 'bridge_probe', threadId: thread, detail: 'toolsAndAuthOnly', ...(cursor ? { cursor } : {}) });
  /** A minimal advertised tool.
   * @param {string} name Tool name.
   * @returns {{name: string, inputSchema: {}}}
   */
  const tool = name => ({ name, inputSchema: {} });
  const goodRow = { name: 'bridge_probe', runtimeStatus: 'connected', toolsError: null, tools: { bridge_me: tool('bridge_me'), bridge_unlisted: tool('bridge_unlisted') } };
  /** A successful listing page.
   * @param {JsonValue[]} data Server rows.
   * @param {string|null} [next] Continuation cursor, or null for the last page.
   * @returns {RpcResponse}
   */
  const page = (data, next = null) => ({ id: 1, result: { data, nextCursor: next } });
  /** A single-page read of one row.
   * @param {JsonValue} row The server row.
   * @returns {McpExchange[]}
   */
  const one = row => [{ params: askFor(), response: page([row]) }];
  assert.deepEqual(mcpInventoryVerdict(T, one(goodRow)), { ready: true, terminal: false, reason: 'connected with all own tools', runtime_status: 'connected', tools: ['bridge_me', 'bridge_unlisted'], pages: 1 });
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: page([{ name: 'other', runtimeStatus: 'connected' }], 'c1') }, { params: askFor('c1'), response: page([goodRow]) }]).ready, true); // follows a complete chain, ignores other servers
  const keyed = { ...goodRow, tools: { bridge_me: tool('bridge_me'), x: tool('bridge_unlisted') } };
  assert.equal(mcpInventoryVerdict(T, one(keyed)).ready, true); // advertised by tool name as well as by catalog key
  for (const invalid of [null, 'not a tool definition', []]) {
    const malformed = mcpInventoryVerdict(T, one({ ...goodRow, tools: { bridge_me: invalid, bridge_unlisted: invalid } }));
    assert.deepEqual([malformed.ready, malformed.terminal], [false, true]);
  }
  const starting = mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: 'starting' }));
  assert.deepEqual([starting.ready, starting.terminal], [false, false]); // tools present but runtime not ready: wait, never open the gate
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: null })).ready, false);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: 'notStarted' })).terminal, false);
  for (const status of ['failed', 'cancelled', 'disabled', 'authenticationRequired']) assert.deepEqual([status, mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: status })).terminal], [status, true]);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: 'unexpected' })).terminal, true);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: 7 })).terminal, true);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, runtimeStatus: undefined })).terminal, true);
  assert.equal(mcpRequestBudget(6000, 120000, 1000), 5000);
  assert.equal(mcpRequestBudget(120000, 60001, 0), 1); // retain the fixed cleanup allowance
  assert.equal(mcpRequestBudget(1000, 120000, 1000), 0); // do not start after expiry
  assert.equal(mcpInventoryWithinBudget(T, one(goodRow), 1).ready, true);
  assert.equal(mcpInventoryWithinBudget(T, one(goodRow), 0).ready, false); // late connected result cannot open the gate
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, toolsError: 'discovery failed' })).ready, false); // discovery error
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, tools: { bridge_me: tool('bridge_me') } })).ready, false); // a tool missing
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, tools: {} })).ready, false);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, tools: undefined })).ready, false);
  assert.equal(mcpInventoryVerdict(T, one({ ...goodRow, name: 'other' })).ready, false); // wrong server row
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: page([goodRow, goodRow]) }]).ready, false); // listed twice
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(null, 'another-thread'), response: page([goodRow]) }]).ready, false); // read for another thread
  assert.equal(mcpInventoryVerdict(T, [{ params: { ...askFor(), serverName: 'other' }, response: page([goodRow]) }]).ready, false); // read for another server
  assert.equal(mcpInventoryVerdict(T, [{ params: { ...askFor(), detail: 'full' }, response: page([goodRow]) }]).ready, false);
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: page([goodRow], 'c1') }]).ready, false); // listing cut short
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: page([], 'c1') }, { params: askFor('wrong'), response: page([goodRow]) }]).ready, false); // broken chain
  assert.equal(mcpInventoryVerdict(T, Array.from({ length: MAX_MCP_PAGES + 1 }, () => ({ params: askFor(), response: page([]) }))).ready, false); // longer than the bound
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: { id: 1, error: { code: -32603, message: 'x' } } }]).ready, false);
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: null }]).terminal, true); // timed out
  assert.equal(mcpInventoryVerdict(T, [{ params: askFor(), response: { id: 1, result: {} } }]).ready, false); // malformed
  assert.equal(mcpInventoryVerdict(T, []).ready, false);
  assert.equal(supportsFlag(help, '--ignore-user-config'), true);
  assert.equal(supportsFlag(help, '--ignore-rules'), true);
  assert.equal(supportsFlag('      --ignore-user-config-extra\n', '--ignore-user-config'), false); // longer flag is not the flag
  assert.equal(supportsFlag('  --enable <FEATURE>\n  --strict-config\n', '--ignore-rules'), false);
  assert.equal(instructionsClosed({ instructions: false, developer_instructions: false }), true);
  assert.equal(instructionsClosed({ instructions: true, developer_instructions: false }), false);
  assert.equal(instructionsClosed({ instructions: false, developer_instructions: null }), false); // not answered is unproven
  assert.equal(instructionsClosed(null), false);
  assert.deepEqual(hookFailures([hook('userPromptSubmit', 'completed', 'sessionFlags'), { method: 'hook/completed', params: { threadId: 'T', run: { eventName: 'sessionStart', status: 'failed', source: 'sessionFlags', startedAt: 10, completedAt: 15, durationMs: 5004, entries: [{ kind: 'error', text: 'hook timed out after 5s' }] } } }], 'T'),
    [{ event: 'sessionStart', status: 'failed', started_at: 10, completed_at: 15, duration_ms: 5004, entries: ['hook timed out after 5s'] }]); // a timeout is kept, with its timing
  assert.deepEqual(hookFailures(runs.map(() => hook('stop', 'completed', 'sessionFlags')), 'T'), []);
  assert.deepEqual(daemonWarnings('{"event":"service_starting","level":"info","ts_ms":1}\nnot json\n{"class":"not_evidence","event":"hook_refused","level":"warn","ts_ms":7}\n{"event":"publish","level":"info"}'),
    [{ event: 'hook_refused', level: 'warn', class: 'not_evidence', ts_ms: 7 }]);
  assert.equal(ownHooksOnly([...runs, { event: 'stop', status: 'completed', source: 'user' }]), false); // a foreign hook ran
  assert.equal(ownHooksOnly([]), false); // nothing observed proves nothing
  /** Builds an `item/completed` notification for thread `T`, turn `u1`.
   * @param {string} type Thread item type.
   * @param {{[field: string]: JsonValue}} extra Further item fields.
   * @returns {Notification}
   */
  const item = (type, extra) => ({ method: 'item/completed', params: { threadId: 'T', turnId: 'u1', item: { type, ...extra } } });
  assert.equal(agentText([item('agentMessage', { text: 'A' }), item('agentMessage', { text: 'B' }), item('userMessage', { text: 'X' })], 'T', 'u1'), 'A\nB');
  assert.equal(agentText([item('agentMessage', { text: 'A' })], 'T', 'other'), '');
  const calls = toolCalls([item('mcpToolCall', { tool: 'bridge_unlisted', status: 'failed', error: { message: 'approval' } }), item('mcpToolCall', { tool: 'bridge_me', status: 'completed' })], 'T', 'bridge_unlisted');
  assert.deepEqual(calls, [{ tool: 'bridge_unlisted', status: 'failed', error: { message: 'approval' } }]);
  /** Builds a `thread/tokenUsage/updated` notification for thread `T`.
   * @param {string} turnId Turn id.
   * @param {number} total Cumulative total tokens (last is fixed at 1).
   * @returns {Notification}
   */
  const usage = (turnId, total) => ({ method: 'thread/tokenUsage/updated', params: { threadId: 'T', turnId, tokenUsage: { last: { totalTokens: 1 }, total: { totalTokens: total } } } });
  // Real snapshots of the root's native run: a multi-call first turn, then an inheriting fork turn.
  /** Builds a `thread/tokenUsage/updated` snapshot notification.
   * @param {string} thread Thread id.
   * @param {string} turnId Turn id.
   * @param {JsonValue} total Cumulative `total.totalTokens` (deliberately untyped for the invalid-counter cases).
   * @param {JsonValue} last `last.totalTokens`.
   * @returns {Notification}
   */
  const snap = (thread, turnId, total, last) => ({ method: 'thread/tokenUsage/updated', params: { threadId: thread, turnId, tokenUsage: { last: { totalTokens: last }, total: { totalTokens: total } } } });
  const firstTurn = [[17346, 17346], [34892, 17546], [52509, 17617], [70183, 17674]].map(([t, l]) => snap('T', 'u1', t, l));
  assert.deepEqual(usageIncrement(firstTurn, 'T', 'u1'), { baseline: 0, increment: 70183, raw_total: 70183, snapshots: 4 }); // all model calls of an MCP turn, not just the last
  const forkTurn = [[86441, 16258], [102747, 16306]].map(([t, l]) => snap('F', 'f1', t, l));
  assert.deepEqual(usageIncrement(forkTurn, 'F', 'f1'), { baseline: 70183, increment: 32564, raw_total: 102747, snapshots: 2 }); // inherited history excluded
  assert.equal(70183 + 32564 <= 150000 && 70183 + 102747 > 150000, true); // the old cumulative sum would have tripped the cap
  const resumed = [...firstTurn, snap('T', 'u3', 70183 + 9000, 9000)];
  assert.deepEqual(usageIncrement(resumed, 'T', 'u3'), { baseline: 70183, increment: 9000, raw_total: 79183, snapshots: 1 }); // old turn's snapshots are not counted
  assert.equal(usageIncrement([...firstTurn, ...firstTurn], 'T', 'u1'), null); // a replayed snapshot is inconsistent
  assert.equal(usageIncrement(firstTurn, 'T', 'other-turn'), null); // no snapshot for that turn: never zero
  assert.equal(usageIncrement(firstTurn, 'U', 'u1'), null); // another thread
  assert.equal(usageIncrement([], 'T', 'u1'), null);
  assert.equal(usageIncrement([snap('T', 'u1', 100, 100), snap('T', 'u1', 90, 90)], 'T', 'u1'), null); // decreasing total
  assert.equal(usageIncrement([snap('T', 'u1', 100, 100), snap('T', 'u1', 250, 100)], 'T', 'u1'), null); // jump != last
  assert.equal(usageIncrement([snap('T', 'u1', 100, 150)], 'T', 'u1'), null); // last > total
  assert.equal(usageIncrement([snap('T', 'u1', -1, 0)], 'T', 'u1'), null); // negative
  assert.equal(usageIncrement([snap('T', 'u1', 10.5, 5)], 'T', 'u1'), null); // not an integer
  assert.equal(usageIncrement([snap('T', 'u1', '100', 50)], 'T', 'u1'), null); // not a number
  assert.equal(usageIncrement([snap('T', 'u1', NaN, 1)], 'T', 'u1'), null);
  assert.equal(usageIncrement([{ method: 'thread/tokenUsage/updated', params: { threadId: 'T', turnId: 'u1', tokenUsage: { total: { totalTokens: 5 } } } }], 'T', 'u1'), null); // missing last
  const first = { recipient: 'r', envelope_hash: 'h' };
  const row = { recipient: 'r', envelope_hash: 'h', delivery: 'unhanded', attempts_made: 0, attempt_seq: null };
  assert.equal(pendingUntouched(row, first), true);
  assert.equal(pendingUntouched({ ...row, recipient: 'other' }, first), false); // redirected
  assert.equal(pendingUntouched({ ...row, attempts_made: 1 }, first), false);
  assert.equal(pendingUntouched({ ...row, delivery: 'hook_submitted' }, first), false); // drained
  assert.equal(pendingUntouched({ ...row, attempt_seq: 3 }, first), false);
  assert.equal(pendingUntouched(null, first), false); // unreadable is unproven
  const dead = { attempts_made: 0, attempt_state: 'none', hold_reason: "the recipient's harness process is gone (disconnected, not inactive)" };
  assert.equal(heldByDeadIncarnation(dead), true);
  assert.equal(heldByDeadIncarnation({ ...dead, hold_reason: 'no carrier attests this endpoint: not a Claude recipient' }), false); // the generic fallback (another carrier's refusal) never qualifies absence
  assert.equal(heldByDeadIncarnation({ ...dead, hold_reason: 'no-wake policy active: paused' }), false); // pause masking
  assert.equal(heldByDeadIncarnation({ ...dead, hold_reason: 'capability message is not loaded for this recipient' }), false); // some other hold
  assert.equal(heldByDeadIncarnation({ ...dead, attempts_made: 1 }), false);
  assert.equal(heldByDeadIncarnation(null), false);
  const attempt = { state: 'hook_submitted', actor: 'T', endpoint_epoch: 7, proof_ref: 'UserPromptSubmit:4242@1790000000:probe:epoch7' };
  assert.equal(handedByHook([attempt], 'T', 7, 4242), true);
  assert.equal(handedByHook([attempt], 'T', 7, 4243), false); // another process
  assert.equal(handedByHook([attempt], 'T', 6, 4242), false); // stale epoch
  assert.equal(handedByHook([attempt], 'U', 7, 4242), false); // another actor (the fork)
  assert.equal(handedByHook([attempt, attempt], 'T', 7, 4242), false); // a second hand-off
  assert.equal(handedByHook([], 'T', 7, 4242), false);
  assert.equal(keepLive('{"method":"item/agentMessage/delta","params":{}}'), null);
  assert.notEqual(keepLive('{"method":"thread/tokenUsage/updated","params":{}}'), null);
  assert.notEqual(keepLive('{"id":1,"result":{}}'), null);
  assert.equal(keepLive('not json'), null);
  assert.equal(usageTotal({ a: { b: 2 } }), 2);
  assert.equal(UUID.test('00000000-0000-4000-8000-00000000000a'), true);
  assert.equal(UUID.test("x' OR 1=1 --"), false);
  console.log(JSON.stringify({ self_test: 'PASS' }));
}

/** Runs the probe body.
 * @param {import('./probe-lib.cjs').Probe} probe The lifecycle-managed probe.
 * @returns {Promise<void>}
 */
async function main(probe) {
  const codex = fs.realpathSync(process.env.CODEX_EXE || execFileSync('/usr/bin/which', ['codex'], { encoding: 'utf8' }).trim());
  const fixture = path.join(bin, 'bridge-fixture');
  const store = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
  probe.checks.codex_exe = codex;
  probe.checks.codex_version = probe.local(codex, ['--version']);
  probe.checks.codex_sha256 = probe.sha256(codex);
  probe.checks.profile_store = store;
  probe.checks.bridge_sha256 = Object.fromEntries(['bridge-native-daemon', 'bridge-hook', 'bridge-fixture'].map(b => [b, probe.sha256(path.join(bin, b))]));
  probe.checks.versions_recorded = !probe.checks.codex_version.startsWith('error:');

  // Offline catalog check (no network): the model and effort must exist.
  const catalog = probe.local('/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'debug', 'models']);
  let entry = null;
  try { entry = JSON.parse(catalog.split('\n')[0]).models.find(m => m.slug === MODEL); } catch {}
  probe.checks.model_in_catalog = Boolean(entry && entry.supported_reasoning_levels.some(l => l.effort === EFFORT));
  if (!probe.checks.model_in_catalog) throw new Error('model not in the build catalog');

  // Paired loopback witness of the confined gate policy (own listener only).
  const fence = await networkFenceWitness(probe, POLICY);
  probe.checks.network_fence_witness = fence;
  probe.checks.network_fence_witnessed = fence.ok === true;

  const host = 'q4x-host', namespace = 'codex-q4';
  /** Canonical Bridge address of one native Codex thread.
   * @param {string} thread Native thread id (canonical UUID).
   * @returns {string} `host/codex/namespace/thread`.
   */
  const address = thread => `${host}/codex/${namespace}/${thread}`;
  const publisher = probe.credential('publisher.token'), admin = probe.credential('admin.token');
  const channelDir = path.join(probe.dir, 'ch'); fs.mkdirSync(channelDir, { mode: 0o700 });
  const channel = path.join(channelDir, 'c.sock'), core = path.join(probe.dir, 'core.sock');
  const database = path.join(probe.dir, 'bridge.db');
  const evidence = path.join(probe.dir, 'probe.jsonl');
  const hookCommand = `'${path.join(bin, 'bridge-hook')}' '${channel}' codex`;
  const hook = `[{matcher="",hooks=[{type="command",command="${hookCommand}",timeout=5}]}]`;
  const own = [
    '-c', `mcp_servers.bridge_probe.command=${JSON.stringify(fixture)}`,
    '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(['mcp-server', channel, core, publisher.file, evidence, 'bridge_me,bridge_unlisted'])}`,
    '-c', 'mcp_servers.bridge_probe.enabled_tools=["bridge_me","bridge_unlisted"]',
    '-c', `mcp_servers.bridge_probe.tools.bridge_me.approval_mode="${ME_APPROVAL}"`,
    ...EVENTS.flatMap(e => ['-c', `hooks.${e}=${hook}`]),
  ];

  // Per-launch configuration hygiene. The Q3 model launches pass
  // --ignore-user-config and --ignore-rules; the app-server takes them only if
  // its own --help lists them (decided at run time, never assumed). Otherwise
  // the launch neutralises what it can by explicit overrides and the gate
  // reads the instruction fields back (the only ones config/read exposes).
  const serverHelp = probe.local(codex, ['app-server', '--help']);
  const flagsSupported = { ignore_user_config: supportsFlag(serverHelp, '--ignore-user-config'), ignore_rules: supportsFlag(serverHelp, '--ignore-rules') };
  probe.checks.isolation_flags_supported = flagsSupported;
  const hygiene = [
    ...(flagsSupported.ignore_user_config ? ['--ignore-user-config'] : []), ...(flagsSupported.ignore_rules ? ['--ignore-rules'] : []),
    '-c', 'notify=[]', '-c', 'project_doc_max_bytes=0', '-c', 'instructions=""', '-c', 'developer_instructions=""',
  ];

  // Isolation gate (before any model call): the Q3 sequence plus the hygiene flags.
  let effective = null, rejected = true;
  /** One confined gate listing with the probe's own overrides plus `extra`.
   * @param {string} label Log label of the gate session.
   * @param {string[]} extra Extra App Server flags.
   * @returns {Promise<GateHook[]|null>} Projected hooks, or null when not answered.
   */
  const list = async (label, extra) => {
    const read = await gateRead(probe, codex, store, label, [...DISABLED, '--enable', 'hooks', ...hygiene, ...own, ...extra], hookCommand);
    effective = read.effective;
    rejected = read.overrideRejected;
    return read.hooks;
  };
  const first = await list('hooks-gate-1', []);
  const state = stateOverride(first || []);

  /** Reads which MCP servers the effective configuration holds and whether
   * each is enabled, keeping only server NAMES and a boolean (never a
   * command, argument, environment or URL), in one confined session.
   * @param {string} label Log label.
   * @param {string[]} flags App Server flags.
   * @returns {Promise<{servers: Record<string, boolean|null>|null, instructions: boolean|null, developer_instructions: boolean|null, foreign_origins: string[]|null, rejected: boolean}>} Name to enabled flag (null when not answered), whether each instruction field holds text (true) or not (false; null when not answered), the first 50 setting keys whose origin is not this launch's session flags (key names only, never values), and the stderr verdict.
   */
  const mcpRead = async (label, flags) => {
    /** Projects one stdout line to names and booleans only.
     * @param {string} line Raw stdout line of the gate session.
     * @returns {string|null} The projected JSON line (names and booleans only), or null to drop it.
     */
    const keep = line => {
      let message;
      try { message = JSON.parse(line); } catch { return null; }
      if (!message || typeof message !== 'object') return null;
      if (message.method !== undefined) return JSON.stringify({ method: String(message.method).slice(0, 64) });
      if (message.id === 1 && message.result && message.result.config) {
        const servers = message.result.config.mcp_servers || {};
        const origins = message.result.origins && typeof message.result.origins === 'object' ? message.result.origins : {};
        return JSON.stringify({ id: 1, result: {
          servers: Object.fromEntries(Object.entries(servers).map(([name, value]) => [name, value && typeof value.enabled === 'boolean' ? value.enabled : null])),
          instructions: typeof message.result.config.instructions === 'string' && message.result.config.instructions.length > 0,
          developer_instructions: typeof message.result.config.developer_instructions === 'string' && message.result.config.developer_instructions.length > 0,
          foreign_origins: Object.entries(origins).filter(([, origin]) => !(origin && origin.name && origin.name.type === 'sessionFlags')).map(([key]) => String(key).slice(0, 80)).slice(0, 50),
        } });
      }
      return JSON.stringify({ id: typeof message.id === 'number' ? message.id : null, result: {} });
    };
    const [config] = await appServer(probe, codex, store, label, flags, [['config/read', { cwd: probe.dir }]], false, keep, /is ignored|unrecognized configuration/);
    const child = probe.children.find(c => c.name === label);
    let timer;
    const settled = await Promise.race([child.closed, new Promise(r => { timer = setTimeout(() => r(false), 2000); })]);
    clearTimeout(timer);
    const reduced = child.child.stderrSummary;
    const answered = config && config.result && config.result.servers ? config.result : null;
    return { servers: answered ? answered.servers : null, instructions: answered ? answered.instructions : null, developer_instructions: answered ? answered.developer_instructions : null, foreign_origins: answered ? answered.foreign_origins : null, rejected: !probe.checks[`${label}_exit`] || settled !== true || !reduced || reduced.matched };
  };
  const base = [...DISABLED, '--enable', 'hooks', ...hygiene, ...own, ...state];
  const names = await mcpRead('mcp-read-1', base);
  const foreign = Object.keys(names.servers || {}).filter(name => name !== 'bridge_probe');
  const safeNames = foreign.every(name => /^[A-Za-z0-9_-]+$/.test(name));
  const mcpOff = foreign.flatMap(name => ['-c', `mcp_servers.${name}.enabled=false`]);
  const liveFlags = [...base, ...mcpOff, '-c', 'analytics.enabled=false'];
  const second = first ? await list('hooks-gate-2', [...state, ...mcpOff]) : null;
  const afterMcp = await mcpRead('mcp-read-2', liveFlags);
  probe.checks.config_foreign_origins = afterMcp.foreign_origins;
  probe.checks.config_residual_closed = Boolean(!afterMcp.rejected && instructionsClosed(afterMcp));
  const ownAfter = (second || []).filter(h => h.own);
  probe.checks.hooks_before = (first || []).map(h => ({ source: h.source, event: h.eventName, enabled: h.enabled, trust: h.trustStatus, own: h.own }));
  probe.checks.hooks_after = (second || []).map(h => ({ source: h.source, event: h.eventName, enabled: h.enabled, trust: h.trustStatus, own: h.own }));
  probe.checks.foreign_mcp_servers = foreign.length;
  probe.checks.hooks_isolated = Boolean(second && !rejected && second.filter(h => !h.own).every(h => !h.enabled)
    && ownAfter.length === EVENTS.length && ownAfter.every(h => h.enabled && h.trustStatus === 'trusted'));
  probe.checks.approval_config_effective = Boolean(!rejected && ownApprovalParsed(effective));
  probe.checks.foreign_mcp_disabled = Boolean(names.servers && !names.rejected && safeNames && afterMcp.servers && !afterMcp.rejected
    && foreign.every(name => afterMcp.servers[name] === false) && 'bridge_probe' in afterMcp.servers);
  if (!probe.checks.hooks_isolated) { probe.fail('isolation_unavailable'); return; }
  if (!probe.checks.approval_config_effective) { probe.fail('approval_config_unavailable'); return; }
  if (!probe.checks.foreign_mcp_disabled || !probe.checks.network_fence_witnessed) { probe.fail('tool_isolation_unavailable'); return; }
  if (!probe.checks.config_residual_closed) { probe.fail('config_isolation_unavailable'); return; }

  // ------------------------------------------------------------------
  // Live backends (unconfined stock `codex app-server` over stdio).
  // ------------------------------------------------------------------
  const spawned = [];
  /** Starts one live backend and its JSON-RPC client.
   * @param {string} label Process label.
   * @returns {Backend} The backend: process, retained notifications (appended live), refused server-request methods, launch time (epoch ms), a request sender (null on timeout) and the initialize handshake.
   */
  const live = label => {
    const events = [], responses = new Map(), serverRequests = [];
    let nextId = 1;
    const child = probe.spawn(label, codex, ['app-server', '--listen', 'stdio://', ...liveFlags],
      { stdin: true, keep: keepLive, env: { ...process.env, CODEX_HOME: store } }, line => {
        let message;
        try { message = JSON.parse(line); } catch { return; }
        if (message.id !== undefined && message.method === undefined) responses.set(message.id, message);
        else if (message.id !== undefined) {
          // The probe supports no server request (approvals, elicitations): fail closed.
          serverRequests.push(String(message.method));
          child.stdin.write(JSON.stringify({ id: message.id, error: { code: -32601, message: 'the probe supports no server requests' } }) + '\n');
        } else events.push(message);
      });
    child.stdin.on('error', () => {});
    const backend = {
      label, child, events, serverRequests, startedAt: Date.now(),
      request: async (method, params, ms = 30000) => {
        const id = nextId; nextId += 1;
        child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
        await probe.until(() => responses.has(id), ms);
        return responses.get(id) || null;
      },
      init: async () => {
        const reply = await backend.request('initialize', { clientInfo: { name: 'agent_bridge_q4x', version: '0' }, capabilities: { experimentalApi: true } });
        if (reply && reply.result) child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
        return Boolean(reply && reply.result);
      },
    };
    spawned.push(backend);
    return backend;
  };
  /** Whether a backend process is still running.
   * @param {Backend} backend The backend.
   * @returns {boolean}
   */
  const alive = backend => backend.child.exitCode === null && backend.child.signalCode === null;
  /** OS view of a live process (start time and command, bounded).
   * @param {number} pid Process id.
   * @returns {string}
   */
  const processFacts = pid => probe.local('/bin/ps', ['-o', 'pid=,lstart=,command=', '-p', String(pid)]).slice(0, 300);
  /** Rows of the owned Core database.
   * @param {string} sql One SELECT with only validated identifiers interpolated.
   * @returns {DbRow[]}
   */
  const rows = sql => dbRows(probe, database, sql);
  /** Validates a native id before it is interpolated into SQL.
   * @param {string} id Candidate canonical UUID.
   * @returns {string} The id.
   * @throws {Error} It is not a canonical UUID.
   */
  const uuid = id => { if (!UUID.test(String(id))) throw new Error('native id is not a canonical uuid'); return id; };
  /** Current binding epoch of one thread's address.
   * @param {string} thread Native thread id.
   * @returns {number|null} Epoch, or null when no row.
   */
  const epochOf = thread => { const found = rows(`SELECT endpoint_epoch FROM bindings WHERE recipient = '${address(uuid(thread))}'`)[0]; return found ? found.endpoint_epoch : null; };
  /** Attempt rows of one thread's address.
   * @param {string} thread Native thread id.
   * @returns {AttemptRow[]}
   */
  const attemptsOf = thread => rows(`SELECT attempt_seq, state, actor, endpoint_epoch, proof_ref FROM attempts WHERE recipient = '${address(uuid(thread))}'`);
  /** One event row (recipient and envelope hash included).
   * @param {string} id Constant event id of this probe.
   * @returns {EventRow|null}
   */
  const eventRow = id => rows(`SELECT event_id, recipient, delivery, attempts_made, attempt_seq, envelope_hash FROM events WHERE event_id = '${id}'`)[0] || null;
  /** Number of no-wake pause policies in force anywhere (must stay 0: a hold must never be a pause).
   * @returns {number|undefined} Count, undefined when unreadable.
   */
  const pauses = () => (rows('SELECT COUNT(*) AS n FROM recipient_policies WHERE no_wake = 1')[0] || {}).n;
  /** Number of attempts anywhere in the database.
   * @returns {number|undefined}
   */
  const attemptCount = () => (rows('SELECT COUNT(*) AS n FROM attempts')[0] || {}).n;
  /** Publisher status delivery block of an event.
   * @param {string} id Event id.
   * @returns {Delivery|null}
   */
  const delivery = id => {
    const out = probe.local(fixture, ['status', core, publisher.file, id]);
    try { return (JSON.parse(out).Status || {}).delivery || null; } catch { return null; }
  };
  /** Publishes one event through the fixture.
   * @param {string} recipient Canonical address.
   * @param {'inject'|'message'} mode Event mode.
   * @param {string} id Event id.
   * @param {string} text Payload text.
   * @returns {string} The fixture's bounded output line.
   */
  const publish = (recipient, mode, id, text) => probe.local(fixture, ['publish', core, publisher.file, recipient, mode, id, text]).slice(0, 300);
  /** The fixture MCP server's evidence records.
   * @returns {McpRecord[]}
   */
  const records = () => fs.existsSync(evidence) ? fs.readFileSync(evidence, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
  /** Ends a backend's process group and awaits its exit.
   * @param {Backend} backend The backend.
   * @returns {Promise<void>}
   */
  const stop = async backend => {
    if (alive(backend)) { try { process.kill(-backend.child.pid, 'SIGTERM'); } catch {} }
    await probe.exited(backend.child, 15000);
  };

  /** Turns run so far: native ids and status, plus each turn's correlated usage (`usageIncrement`, null when unavailable or invalid). Published on the probe's checks at once so a fail-closed exit still leaves it.
   * @type {{label: string, thread: string, turn_id: string, status: string, usage: {baseline: number, increment: number, raw_total: number, snapshots: number}|null, partial_usage?: {baseline: number, increment: number, raw_total: number, snapshots: number}|null, interrupt?: {accepted: boolean, ended: boolean}}[]} */
  const turnLog = [];
  /** Whether a turn ended in anything but a native `completed`; no further paid turn may start once set.
   * @type {boolean} */
  let halted = false;
  probe.checks.turn_log = turnLog;
  /** Runs one prompted native turn and waits for its native completion.
   * @param {Backend} backend The backend that owns the thread.
   * @param {string} thread Native thread id.
   * @param {string} label Step label.
   * @param {string} text Short prompt.
   * @returns {Promise<{turnId: string, status: string, text: string}>} The native turn status and reply text.
   * @throws {Error} The turn budget or token ceiling is exhausted, an earlier turn did not complete natively or its usage was unavailable or invalid (no further paid turn), no turn started, or this turn produced no native `turn/completed` within 240 s (the exact own thread+turn is interrupted, the owned backend is stopped, the turn is logged with `status: timeout` and no usable usage, and the run aborts).
   */
  const turn = async (backend, thread, label, text) => {
    const spent = turnLog.reduce((sum, t) => sum + (t.usage ? t.usage.increment : 0), 0);
    if (halted) { probe.fail(`turn_not_completed_before:${label}`); throw new Error(`an earlier turn did not complete; no further paid turn before ${label}`); }
    if (turnLog.some(t => t.usage === null)) { probe.fail(`usage_unavailable_before:${label}`); throw new Error(`an earlier turn's usage is unavailable; no further paid turn before ${label}`); }
    if (turnLog.length >= MAX_TURNS || spent > TOKEN_STOP) { probe.fail(`turn_budget:${label}`); throw new Error(`turn budget exhausted before ${label}`); }
    const started = await backend.request('turn/start', {
      threadId: thread, input: [{ type: 'text', text, text_elements: [] }], model: MODEL, effort: EFFORT,
      approvalPolicy: 'never', sandboxPolicy: { type: 'readOnly' }, cwd: probe.dir,
    });
    const turnId = started && started.result && started.result.turn && started.result.turn.id;
    if (!turnId) { probe.fail(`turn_start_failed:${label}`); throw new Error(`turn/start failed for ${label}`); }
    /** The native completion of this exact turn.
     * @returns {Notification|undefined}
     */
    const completion = () => backend.events.find(e => e.method === 'turn/completed' && e.params && e.params.turn && e.params.turn.id === turnId);
    await probe.until(() => completion() !== undefined, TURN_TIMEOUT_MS);
    const done = completion();
    if (!done) {
      // No native completion: fail closed. Interrupt exactly this thread+turn,
      // stop the owned backend, keep the turn (with partial usage kept apart,
      // never usable) and abort so no later paid turn can start.
      probe.fail(`turn_timeout:${label}`);
      const interrupt = await backend.request('turn/interrupt', { threadId: thread, turnId }, 15000);
      const ended = await probe.until(() => completion() !== undefined, 15000);
      turnLog.push({ label, thread, turn_id: turnId, status: 'timeout', usage: null, partial_usage: usageIncrement(backend.events, thread, turnId), interrupt: { accepted: Boolean(interrupt && interrupt.result), ended } });
      halted = true;
      await stop(backend);
      throw new Error(`no turn/completed for ${label} within ${TURN_TIMEOUT_MS / 1000} s; backend stopped`);
    }
    await new Promise(r => setTimeout(r, 1500)); // late token-usage notifications
    const usage = usageIncrement(backend.events, thread, turnId);
    const status = String(done.params.turn.status);
    turnLog.push({ label, thread, turn_id: turnId, status, usage });
    if (!usage) probe.fail(`usage_unavailable:${label}`);
    if (status !== 'completed') { halted = true; probe.fail(`turn_not_completed:${label}:${status}`); }
    return { turnId, status, text: agentText(backend.events, thread, turnId) };
  };

  /** Native ids of the probe's own threads (set once created) for the cleanup archive. */
  let t1 = null, t2 = null;
  probe.onCleanup('archive-own-threads', async () => {
    for (const backend of spawned) await stop(backend);
    const ids = [t1, t2].filter(Boolean);
    if (ids.length === 0) { probe.checks.threads_archived_cleanup = true; return; }
    let ok = true;
    for (const id of ids) {
      const [reply] = await appServer(probe, codex, store, `cleanup-archive-${id.slice(0, 8)}`, [], [['thread/archive', { threadId: id }]], true);
      ok = ok && Boolean(reply && reply.result);
    }
    probe.checks.threads_archived_cleanup = ok;
  });

  // ------------------------------------------------------------------
  // 1. Backend A: thread T1, daemon, turn 1.
  // ------------------------------------------------------------------
  const backendA = live('backend-a');
  if (!await backendA.init()) throw new Error('backend A did not initialize');
  const started = await backendA.request('thread/start', { cwd: probe.dir, model: MODEL, approvalPolicy: 'never', sandbox: 'read-only' });
  const thread1 = started && started.result && started.result.thread;
  if (!thread1 || !UUID.test(String(thread1.id))) throw new Error('thread/start did not return a thread');
  t1 = thread1.id;
  probe.markers.push(t1);
  probe.checks.t1_thread_started = Boolean(thread1.status && thread1.status.type === 'idle' && !thread1.forkedFromId);
  probe.checks.t1_start_facts = { id: t1, sessionId: thread1.sessionId, status: thread1.status, forkedFromId: thread1.forkedFromId || null };

  const config = path.join(probe.creds, 'bridge.toml');
  fs.writeFileSync(config, [
    `database = "${database}"`, `socket = "${core}"`, '[limits]', 'max_admitted_events = 100',
    '[[grant]]', `token = "${publisher.token}"`, 'publisher = "bridge-probe"', `recipients = ["${address(t1)}"]`,
    'kinds = ["bridge.probe"]', 'modes = ["inject", "message"]', 'policies = ["keep_all"]',
    '[[grant]]', `token = "${admin.token}"`, 'publisher = "bridge-probe-ops"', 'admin = true',
    'recipients = []', 'kinds = []', 'modes = []', 'policies = []',
    '[adapters]', `channel = "${channel}"`, `host_id = "${host}"`,
    '[[adapters.profiles]]', `namespace = "${namespace}"`, 'harness = "Codex"', `store = "${store}"`,
    '[[adapters.profiles.executables]]', `path = "${codex}"`, `sha256 = "${probe.checks.codex_sha256}"`,
    'version = "probe"', 'inject = true', 'message = true', ''].join('\n'), { mode: 0o600 });
  const daemon = probe.spawn('daemon', path.join(bin, 'bridge-native-daemon'), [config]);
  probe.checks.daemon_started = await probe.until(() => fs.existsSync(channel) && fs.existsSync(core), 10000);
  if (!probe.checks.daemon_started) throw new Error('daemon did not start');

  // Paid gate: the OWN MCP server must be connected on the OWN thread with
  // both own tools before any model turn. The thread exists since thread/start
  // (before the daemon, so its grant can name it); the runtime connection of
  // its MCP servers is observed only AFTER that, with the build's own
  // `mcpServerStatus/list` (thread-scoped, own server only, complete
  // pagination), polled within MCP_READY_MS and the remaining run budget
  // (preserving 60 s for cleanup); only the own fields are kept.
  /** Reads the own MCP server's inventory within the shared readiness and cleanup budgets, following at most five pages.
   * @param {number} deadline Monotonic `performance.now()` deadline in milliseconds.
   * @returns {Promise<McpExchange[]>} The exchanges, in order (a null response ends the chain).
   */
  const readMcpInventory = async deadline => {
    const exchanges = [];
    let cursor = null;
    for (let page = 0; page < MAX_MCP_PAGES; page += 1) {
      const remaining = mcpRequestBudget(deadline, probe.remaining(), performance.now());
      if (remaining <= 0) break;
      const params = { serverName: 'bridge_probe', threadId: t1, detail: 'toolsAndAuthOnly', ...(cursor ? { cursor } : {}) };
      let timer;
      const response = await Promise.race([
        backendA.request('mcpServerStatus/list', params, remaining),
        new Promise(resolve => { timer = setTimeout(() => resolve(null), remaining); }),
      ]);
      clearTimeout(timer);
      exchanges.push({ params, response });
      if (performance.now() >= deadline || probe.remaining() <= 60_000) break;
      const next = response && response.result ? response.result.nextCursor : null;
      if (typeof next !== 'string' || next === '') break;
      cursor = next;
    }
    return exchanges;
  };
  const mcpStarted = performance.now();
  const mcpDeadline = mcpStarted + MCP_READY_MS;
  let mcpVerdict = mcpInventoryVerdict(t1, []);
  let mcpPolls = 0;
  while (performance.now() < mcpDeadline && probe.remaining() > 60_000) {
    mcpPolls += 1;
    const exchanges = await readMcpInventory(mcpDeadline);
    const remainingBudgetMs = mcpRequestBudget(mcpDeadline, probe.remaining(), performance.now());
    mcpVerdict = mcpInventoryWithinBudget(t1, exchanges, remainingBudgetMs);
    if (remainingBudgetMs <= 0) break;
    if (mcpVerdict.ready || mcpVerdict.terminal) break;
    const pollDelayMs = Math.min(1000, mcpDeadline - performance.now(), probe.remaining() - 60_000);
    if (pollDelayMs > 0) await new Promise(r => setTimeout(r, pollDelayMs));
  }
  probe.checks.mcp_inventory = { server: 'bridge_probe', thread: t1, ...mcpVerdict, polls: mcpPolls, waited_ms: Math.round(performance.now() - mcpStarted) };
  probe.checks.mcp_inventory_ready = mcpVerdict.ready === true;
  if (!probe.checks.mcp_inventory_ready) { probe.fail('mcp_inventory_unavailable'); throw new Error(`own MCP server not ready on the own thread (${mcpVerdict.reason}); no paid turn started`); }

  const turn1 = await turn(backendA, t1, 'turn1', 'This is an isolated Agent Bridge qualification run. First call the bridge_me MCP tool exactly once with {}. Then call the bridge_unlisted MCP tool exactly once with {}; it is expected to be refused, do not retry it. Finally reply READY. Do not read files or run commands.');
  probe.checks.turn1_completed = turn1.status === 'completed';
  await probe.until(() => epochOf(t1) !== null, 15000);
  const epoch1 = epochOf(t1);
  const root1 = records().find(r => r.tool === 'bridge_me' && r.caller && r.caller.role === 'root' && r.caller.native_id === t1);
  probe.checks.t1_root_attested = Boolean(root1 && root1.caller.may_act_as_address && root1.caller.address === address(t1));
  probe.checks.t1_binding_matches_caller = Boolean(root1 && Number.isInteger(epoch1) && root1.caller.epoch === epoch1 && epoch1 >= backendA.startedAt);
  const runs1 = hookRuns(backendA.events, t1);
  probe.checks.t1_hook_runs = runs1;
  probe.checks.t1_hook_failures = hookFailures(backendA.events, t1);
  // Every owned hook of A's first turn is positive: SessionStart, UserPromptSubmit, PreToolUse and PostToolUse each completed, and NO run
  // of the thread failed (a timeout is never waived, nor excused by another completed run of the same event).
  probe.checks.t1_hooks_observed = hooksPositive(runs1, probe.checks.t1_hook_failures, ['sessionStart', 'userPromptSubmit', 'preToolUse', 'postToolUse']);
  probe.checks.t1_hooks_clean = probe.checks.t1_hook_failures.length === 0;
  const unlisted = toolCalls(backendA.events, t1, 'bridge_unlisted');
  probe.checks.unlisted_calls = unlisted;
  // The host boundary is the host's explicit approval refusal (Q3 classification), never any MCP failure.
  probe.checks.unlisted_refused_by_host = unlisted.length > 0 && unlisted.every(approvalRefusal);
  probe.checks.unlisted_not_executed = !records().some(r => r.unlisted_called);
  probe.checks.loaded_process_identified = Number.isInteger(backendA.child.pid) && alive(backendA);
  probe.checks.backend_a_facts = { pid: backendA.child.pid, os: processFacts(backendA.child.pid), epoch: epoch1 };

  // ------------------------------------------------------------------
  // 2. Archive: an inject event must stay pending, with no pause anywhere.
  // ------------------------------------------------------------------
  const archived = await backendA.request('thread/archive', { threadId: t1 });
  probe.checks.archive_ok = Boolean(archived && archived.result);
  const marker = 'BRIDGE_CTX_' + crypto.randomBytes(6).toString('hex');
  probe.checks.inject_publish = publish(address(t1), 'inject', 'q4x-inject-1', `Synthetic Bridge qualification context marker ${marker}.`);
  const injectFirst = eventRow('q4x-inject-1');
  await new Promise(r => setTimeout(r, 8000));
  probe.checks.archived_inject_pending_without_pause = pendingUntouched(eventRow('q4x-inject-1'), injectFirst) && pauses() === 0 && attemptCount() === 0 && epochOf(t1) === epoch1;
  const unarchived = await backendA.request('thread/unarchive', { threadId: t1 });
  probe.checks.unarchive_ok = Boolean(unarchived && unarchived.result);

  // ------------------------------------------------------------------
  // 3. Disconnect: A is killed; a message must be held by the dead
  //    incarnation (not by a pause), then closed unsent.
  // ------------------------------------------------------------------
  await stop(backendA);
  probe.checks.backend_a_dead = !alive(backendA) && probe.local('/bin/ps', ['-p', String(backendA.child.pid)]).split('\n').length < 2;
  probe.checks.dead_publish = publish(address(t1), 'message', 'q4x-msg-dead', 'Synthetic message while the backend is gone.');
  await probe.until(() => heldByDeadIncarnation(delivery('q4x-msg-dead')), 30000);
  probe.checks.dead_status = delivery('q4x-msg-dead');
  probe.checks.dead_message_held_fail_closed = heldByDeadIncarnation(delivery('q4x-msg-dead')) && pauses() === 0;
  const disposed = await coreCall(core, { op: 'dispose', token: admin.token, publisher: 'bridge-probe', event_id: 'q4x-msg-dead', note: 'q4 probe: close the dead-incarnation message unsent before a new binding exists' });
  const deadRow = eventRow('q4x-msg-dead');
  probe.checks.dead_dispose_response = typeof disposed === 'string' ? disposed : Object.keys(disposed || {}).slice(0, 3);
  probe.checks.dead_message_disposed_unsent = Boolean(deadRow && deadRow.delivery === 'disposed' && deadRow.attempts_made === 0 && deadRow.attempt_seq === null) && attemptCount() === 0;
  probe.checks.inject_pending_through_disconnect = pendingUntouched(eventRow('q4x-inject-1'), injectFirst) && pauses() === 0;
  probe.checks.old_epoch_retained_while_dead = epochOf(t1) === epoch1;

  // ------------------------------------------------------------------
  // 4. Restart (B resumes T1), then fork T1 -> T2 with the inject pending.
  // ------------------------------------------------------------------
  const backendB = live('backend-b');
  if (!await backendB.init()) throw new Error('backend B did not initialize');
  probe.checks.restart_new_process = backendB.child.pid !== backendA.child.pid && alive(backendB);
  const resumed = await backendB.request('thread/resume', { threadId: t1, excludeTurns: true });
  probe.checks.restart_resumed_same_thread = Boolean(resumed && resumed.result && resumed.result.thread && resumed.result.thread.id === t1);
  await new Promise(r => setTimeout(r, 3000));
  const epochAfterResume = epochOf(t1);
  probe.checks.resume_renewed_epoch = epochAfterResume !== epoch1; // observed fact: whether resume itself fires a binding hook
  const forked = await backendB.request('thread/fork', { threadId: t1, excludeTurns: true });
  const thread2 = forked && forked.result && forked.result.thread;
  t2 = thread2 && UUID.test(String(thread2.id)) ? thread2.id : null;
  if (t2) probe.markers.push(t2);
  probe.checks.fork_new_thread_id = Boolean(t2 && t2 !== t1 && thread2.forkedFromId === t1);
  probe.checks.fork_facts = thread2 && { id: thread2.id, sessionId: thread2.sessionId, forkedFromId: thread2.forkedFromId || null, original_sessionId: thread1.sessionId };
  if (!t2) throw new Error('thread/fork did not return a thread');
  const epochBeforeForkTurn = epochOf(t1);
  const turn2 = await turn(backendB, t2, 'turn2', 'This is an isolated Agent Bridge qualification run. Call the bridge_me MCP tool exactly once with {}. Then reply with every BRIDGE_CTX_ marker you can see in your context, or NONE. Do not read files or run commands.');
  probe.checks.turn2_completed = turn2.status === 'completed';
  await probe.until(() => epochOf(t2) !== null, 15000);
  const fork2 = records().find(r => r.tool === 'bridge_me' && r.caller && r.caller.native_id === t2);
  probe.checks.fork_caller_is_fork_thread = Boolean(fork2 && fork2.caller.role === 'root' && fork2.caller.may_act_as_address && fork2.caller.address === address(t2));
  probe.checks.fork_binding_distinct = Boolean(fork2 && Number.isInteger(epochOf(t2)) && fork2.caller.epoch === epochOf(t2) && address(t2) !== address(t1));
  probe.checks.fork_event_stays_on_original = pendingUntouched(eventRow('q4x-inject-1'), injectFirst) && attemptsOf(t1).length === 0 && attemptsOf(t2).length === 0
    && epochOf(t1) === epochBeforeForkTurn && pauses() === 0;
  probe.checks.fork_reply_lacks_marker = turn2.status === 'completed' && !turn2.text.includes(marker) && !JSON.stringify(backendB.events.filter(e => e.params && e.params.threadId === t2)).includes(marker);

  // ------------------------------------------------------------------
  // 5. Turn 3 on T1 (B): renewed epoch, natural-hook hand-off, marker.
  // ------------------------------------------------------------------
  const turn3 = await turn(backendB, t1, 'turn3', 'This is an isolated Agent Bridge qualification run. First call the bridge_me MCP tool exactly once with {}. Then reply with every BRIDGE_CTX_ marker you can see in your context, or NONE. Do not read files or run commands.');
  probe.checks.turn3_completed = turn3.status === 'completed';
  // The resumed original's own UserPromptSubmit hook (backend B) must be a positive completed run, never a timeout.
  probe.checks.t1_resumed_hook_runs = hookRuns(backendB.events, t1);
  probe.checks.t1_resumed_hook_failures = hookFailures(backendB.events, t1);
  probe.checks.t1_resumed_user_prompt_hook_positive = probe.checks.t1_resumed_hook_runs.some(r => r.event === 'userPromptSubmit' && r.status === 'completed')
    && probe.checks.t1_resumed_hook_failures.length === 0;
  await probe.until(() => attemptsOf(t1).length > 0, 15000);
  const epoch2 = epochOf(t1);
  probe.checks.epoch_renewed_on_restart = Number.isInteger(epoch2) && epoch2 > epoch1;
  const root3 = records().filter(r => r.tool === 'bridge_me' && r.caller && r.caller.native_id === t1).pop();
  probe.checks.t1_caller_after_restart = Boolean(root3 && root3.caller.epoch === epoch2 && root3.caller.epoch !== epoch1 && root3.caller.may_act_as_address);
  const handed = attemptsOf(t1);
  probe.checks.inject_attempts = handed;
  probe.checks.inject_handed_by_original_hook = handedByHook(handed, t1, epoch2, backendB.child.pid) && attemptsOf(t2).length === 0
    && (eventRow('q4x-inject-1') || {}).delivery === 'hook_submitted';
  probe.checks.marker_in_original_reply = turn3.status === 'completed' && turn3.text.includes(marker);
  probe.checks.backend_b_facts = { pid: backendB.child.pid, os: processFacts(backendB.child.pid), epoch: epoch2 };

  // ------------------------------------------------------------------
  // Closing facts.
  // ------------------------------------------------------------------
  const everyEvent = spawned.flatMap(b => b.events);
  const allRuns = [...hookRuns(everyEvent, t1), ...hookRuns(everyEvent, t2)];
  probe.checks.hook_runs_total = allRuns.length;
  probe.checks.only_own_hooks_ran = ownHooksOnly(allRuns);
  probe.checks.no_owned_hook_failures = hookFailures(everyEvent, t1).length === 0 && hookFailures(everyEvent, t2).length === 0;
  probe.checks.turn_started_notifications = everyEvent.filter(e => e.method === 'turn/started').length;
  probe.checks.turns_within_budget = turnLog.length <= MAX_TURNS && probe.checks.turn_started_notifications === turnLog.length;
  probe.checks.tokens_measured = turnLog.length === MAX_TURNS && turnLog.every(t => t.usage !== null && t.usage.increment > 0);
  // New model tokens only (each turn's increment); the raw cumulative counters stay in turn_log.
  probe.checks.tokens_total = turnLog.reduce((sum, t) => sum + (t.usage ? t.usage.increment : 0), 0);
  probe.checks.server_requests_refused = spawned.map(b => ({ backend: b.label, methods: b.serverRequests }));
  process.kill(-daemon.pid, 'SIGTERM');
  probe.checks.daemon_exit = await probe.exited(daemon, 15000);
  const stderr = fs.existsSync(path.join(probe.dir, 'daemon.stderr')) ? fs.readFileSync(path.join(probe.dir, 'daemon.stderr'), 'utf8') : '';
  const daemonEvents = [...stderr.matchAll(/"event":"([a-z_]+)"/g)].reduce((counts, m) => ({ ...counts, [m[1]]: (counts[m[1]] || 0) + 1 }), {});
  probe.checks.daemon_events = daemonEvents;
  probe.checks.daemon_warnings = daemonWarnings(stderr);
  probe.checks.no_daemon_refusals = ['hook_refused', 'binding_fence_refused', 'caller_refused', 'drain_refused'].every(name => !daemonEvents[name]);
}

if (require.main === module) {
  if (process.argv[2] === '--self-test') selfTest();
  else if (!PAID) {
    console.log(JSON.stringify({ refused: 'model-bearing driver: set BRIDGE_Q4_PAID=1 (root only); --self-test runs the pure validators' }));
    process.exitCode = 2;
  } else run('m2q4x', 15 * 60_000, REQUIRED, main);
}
module.exports = { hookRuns, ownHooksOnly, agentText, toolCalls, mcpInventoryVerdict, usageIncrement, hookFailures, daemonWarnings, hooksPositive, approvalRefusal, supportsFlag, instructionsClosed, pendingUntouched, heldByDeadIncarnation, handedByHook, keepLive };
