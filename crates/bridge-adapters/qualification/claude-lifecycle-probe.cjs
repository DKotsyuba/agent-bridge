/**
 * Owned Claude frontend lifecycle qualification (Q4, Claude side): the real
 * `/clear` dispatch and the paid fork-while-`later`-pending custody case,
 * both observed THROUGH the Bridge composition — a live `bridge-native-daemon`
 * profile, the product `bridge-hook` as the receiver's own hooks and the
 * daemon's own Core database — never through a text reply.
 *
 * Unpaid phase (default, zero inference): one stock Claude Code 2.1.296
 * stream-json receiver under `sandbox-exec` with remote-IP network DENIED,
 * so no model exchange can complete. Its launch is closed before it starts:
 * `--setting-sources ''`, only this probe's settings file (the product hook
 * beside one coexisting no-op hook), `--strict-mcp-config` with no server,
 * `--tools ''`, manual permissions with `--permission-prompts none`, no
 * chrome, a private cwd, a scrubbed environment (the foreign parent
 * harness's `CLAUDE_CODE_*`/`CLAUDECODE` routing variables are removed, the
 * store/auth variables are passed through unchanged) and the installed
 * build's own memory switches. `/clear` is sent as a streamed user message
 * with a client-chosen uuid (the 2.1.296 SDK default leaves slash dispatch
 * on); the positive reset evidence is the SDK's `conversation_reset` frame
 * with `trigger: "clear"` whose `user_message_uuid` is that uuid. Which
 * native id the Bridge sees afterwards is NOT assumed: the receiver's own
 * hook frames (`session_id` of SessionStart/SessionEnd) and the fresh
 * Core `bindings` rows decide the old/new mapping.
 *
 * Positive Bridge evidence: the daemon logs only refusals, so a binding is
 * proven by reading the probe's OWN fresh Core database read-only
 * (`sqlite3 -readonly`): a `bindings` row for the exact native address of
 * the receiver's session, with an endpoint epoch not older than the
 * receiver's launch. `bindings` carries only recipient, epoch and loaded
 * capabilities (no attestation JSON), so the row is read together with the
 * receiver's own hook frames and process id; zero `hook_refused`,
 * `binding_fence_refused` and `caller_refused` daemon events are required
 * too. This database is owned verification data (never a user store).
 *
 * Paid phase (`BRIDGE_Q4_PAID=1`, root only; its checks are absent
 * otherwise): ONE unconfined original receiver and ONE resumed fork
 * (`--resume <original> --fork-session --session-id <fresh uuid>`), both
 * haiku at low effort with the same closed launch, under a TOTAL ceiling of
 * USD 0.50 (per-receiver Claude caps 0.30 + 0.10 and a shared running sum
 * that refuses the next prompted step near the ceiling), an absolute
 * 15 minute budget plus bounded cleanup. One prompted turn runs on the
 * original; a `later` message is then held by a Core pause while the fork
 * starts under a NEW session id; the held event must stay on the ORIGINAL
 * recipient (no attempt for either recipient, no redirect or drain), and
 * after unpause the original receiver must answer it in its own distinct
 * turn while the fork never sees its marker.
 *
 * The probe never extracts, copies or writes any credential; no claim is
 * made about what the CLI itself reads with its own protected
 * authentication. No working Claude application, chat or global
 * configuration is touched.
 *
 * Usage: `cargo +1.98.1 build --offline -p bridge-adapters --bins`, then
 * `node qualification/claude-lifecycle-probe.cjs` (env: `BRIDGE_BIN_DIR`,
 * `CLAUDE_EXE`, `BRIDGE_Q4_PAID=1`); `--self-test` runs the pure validators
 * without any native process. Writes `checks.json` in a fresh private
 * directory; exits 0 only when every required check is exactly true.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { run, TurnTracker } = require('./probe-lib.cjs');
const { networkFenceWitness, usageTotal } = require('./lifecycle-lib.cjs');

/** A JSON value (see `lifecycle-lib.cjs`).
 * @typedef {import('./lifecycle-lib.cjs').JsonValue} JsonValue */
/** A database row of the probe's own Core database (see `lifecycle-lib.cjs`).
 * @typedef {import('./lifecycle-lib.cjs').DbRow} DbRow */
/** One parsed stream-json line of a receiver; only the fields this probe reads are named, every other field is ignored.
 * @typedef {{type: string, subtype?: string, session_id?: string, hook_event?: string, uuid?: string, trigger?: string, user_message_uuid?: string, new_conversation_id?: string, tools?: string[], mcp_servers?: JsonValue[], permissionMode?: string, slash_commands?: string[], claude_code_version?: string, num_turns?: number, total_cost_usd?: number, usage?: JsonValue, is_error?: boolean, result?: string}} StreamFrame */
/** The delivery block of a publisher status as the fixture prints it (absent fields are `undefined`).
 * @typedef {{attempts_made: number, attempt_state: string, delivery?: string, hold_reason?: string|null, tiers?: {tier: string}[]}} Delivery */
/** A fixture reply: the parsed JSON line, or the raw bounded error text when it is not JSON.
 * @typedef {JsonValue|string} FixtureReply */
/** A process exit as `Probe.exited` reports it.
 * @typedef {{code: number|null, signal: string|null}|{error: string}} ExitStatus */
/** A running stream-json receiver: its process, every parsed stdout frame so far (appended live), launch time (epoch ms), whether it runs under the network-denying sandbox, and a sender of one streamed user message (optional client uuid).
 * @typedef {{child: import('node:child_process').ChildProcess, frames: StreamFrame[], startedAt: number, confined: boolean, send: (text: string, uuid?: string) => void}} Receiver */

/**
 * Built Bridge binaries.
 * @type {string}
 */
const bin = process.env.BRIDGE_BIN_DIR || path.resolve(__dirname, '../../../target/debug');
/** Unpaid receiver confinement: remote IP network denied (no model exchange
 * is possible) while unix-domain sockets stay reachable, so the CLI can
 * spawn its hooks and `bridge-hook` can reach the channel.
 * @type {string}
 */
const POLICY = '(version 1)(allow default)(deny network-outbound (remote ip))';
/**
 * TOTAL USD ceiling of the whole paid phase (both receivers).
 * @type {number}
 */
const TOTAL_USD = 0.5;
/**
 * Claude's own per-receiver caps; their sum stays below TOTAL_USD.
 * @type {{original: number, fork: number}}
 */
const CAP_USD = { original: 0.3, fork: 0.1 };
/**
 * Whether the paid phase runs (root only).
 * @type {boolean}
 */
const PAID = process.env.BRIDGE_Q4_PAID === '1';
/** Foreign parent-harness routing variables removed from every receiver's
 * environment (names only; store and auth variables are never touched).
 * @type {RegExp}
 */
const FOREIGN_ENV = /^(CLAUDECODE|CLAUDE_PID|CLAUDE_EFFORT|CLAUDE_MEMORY_STORES|CLAUDE_CODE_(ENTRYPOINT|EXECPATH|SESSION_ID|CHILD_SESSION|SESSION_ATTENDED|MESSAGING_[A-Z_]+))$/;
/**
 * Hook events the product hook is registered for.
 * @type {string[]}
 */
const HOOK_EVENTS = ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest', 'Notification', 'Stop', 'SubagentStop', 'SessionEnd'];
/** Hold reasons the product gives a recipient whose session ended, whose
 * harness process is gone or that has no binding: the carrier's own
 * attestation refusals (`registry.rs` attest_recipient) or the Core
 * lifecycle-unknown gate (`dispatch.rs` gate). Never the no-wake text.
 * @type {RegExp}
 */
const DEAD_REASON = /(the recipient session ended|harness process is gone|no attested binding|lifecycle is unknown, disconnected or not loaded)/;
/**
 * Checks that must all be exactly true (unpaid phase).
 * @type {string[]}
 */
const REQUIRED = [
  'versions_recorded', 'receiver_isolated', 'receiver_inventory_closed', 'loaded_clear_command_present',
  'bridge_session_binding_observed', 'no_daemon_refusals', 'paused_event_held_before_reset',
  'reset_frame_correlated', 'reset_identity_decided_by_hooks', 'reset_new_identity_bound_or_kept_renewed',
  'paused_event_kept_on_old_recipient', 'reset_nothing_dispatched_to_any_session',
  'receiver_ended_cleanly', 'dead_incarnation_holds_fail_closed', 'network_confinement_effective', 'no_model_effect',
];
/**
 * The unpaid required checks (the paid ones are appended below).
 * @type {string[]}
 */
const UNPAID_REQUIRED = [...REQUIRED];
if (PAID) REQUIRED.push('paid_original_turn_ok', 'paid_original_bound', 'paid_fork_launched_new_session', 'paid_fork_new_session_bound',
  'paid_fork_keeps_event_on_original', 'paid_unpause_delivers_to_original_turn', 'paid_fork_never_saw_marker',
  'paid_delivery_attempt_bound_to_original_process', 'paid_total_cost_within_ceiling', 'paid_fork_isolated');

/** Names of the required checks that are not exactly `true`: the fail-closed
 * gate that must be empty before ANY paid receiver may start.
 * @param {Record<string, JsonValue|undefined>} checks The recorded checks.
 * @param {string[]} required Required check names.
 * @returns {string[]} The missing or non-true names (empty when all hold).
 */
function unmet(checks, required) {
  return required.filter(name => checks[name] !== true);
}

/** Whether the result frames show no model effect at all: every frame has
 * zero turns, zero cost and a zero-sum (nested) usage block. An empty list
 * is vacuously true; the caller pairs this with the network confinement.
 * @param {{num_turns?: number, total_cost_usd?: number, usage?: JsonValue}[]} frames Stream `result` frames.
 * @returns {boolean}
 */
function noModelEffect(frames) {
  return frames.every(frame => (frame.num_turns || 0) === 0 && !(frame.total_cost_usd > 0) && usageTotal(frame.usage) === 0);
}

/** Total cost across receivers: each receiver's `total_cost_usd` is
 * cumulative for its process, so only its largest observed value counts.
 * @param {Record<string, number[]>} byReceiver Observed cumulative costs per receiver label.
 * @returns {number} Shared sum in USD.
 */
function sharedSpend(byReceiver) {
  return Object.values(byReceiver).reduce((sum, costs) => sum + costs.reduce((max, cost) => Math.max(max, Number.isFinite(cost) ? cost : 0), 0), 0);
}

/** Classifies one `conversation_reset` frame against the `/clear` the probe
 * sent and the session the receiver was launched with. Nothing about the
 * identity relation is assumed; the frame only has to be the correlated
 * clear and name a canonical new conversation id.
 * @param {StreamFrame|null} frame The reset frame, or null.
 * @param {string} sentUuid The uuid of the streamed `/clear` user message.
 * @returns {{correlated: boolean, newId: string|null, sessionId: string|null}} The decision inputs.
 */
function classifyReset(frame, sentUuid) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const ok = Boolean(frame && frame.type === 'conversation_reset' && frame.trigger === 'clear'
    && frame.user_message_uuid === sentUuid && uuid.test(String(frame.new_conversation_id)));
  return { correlated: ok, newId: ok ? frame.new_conversation_id : null, sessionId: frame && typeof frame.session_id === 'string' ? frame.session_id : null };
}

/** Decides, from the receiver's OWN hook frames and the Core binding rows,
 * which native id the Bridge bound after a reset: the SessionStart hook
 * frames AFTER the reset name the session id the hook saw, and the Bridge
 * must hold a binding row for that exact address whose epoch is strictly
 * newer than `priorEpoch` when it is the old session (a renewal) and exists
 * when it is another id (a new incarnation of the conversation).
 * @param {string[]} startIds `session_id` of every post-reset SessionStart hook frame, in order.
 * @param {string} oldId The pre-reset session id.
 * @param {Record<string, number>} epochs Binding epoch per native session id (rows of the owned database).
 * @param {number} priorEpoch Epoch of the old session's binding before the reset.
 * @returns {{identity: 'kept'|'new'|'none'|'ambiguous', boundId: string|null, ok: boolean}} Verdict.
 */
function decideIdentity(startIds, oldId, epochs, priorEpoch) {
  const distinct = [...new Set(startIds)];
  if (distinct.length === 0) return { identity: 'none', boundId: null, ok: false };
  if (distinct.length > 1) return { identity: 'ambiguous', boundId: null, ok: false };
  const [id] = distinct;
  const kept = id === oldId;
  const ok = kept ? (epochs[id] || 0) > priorEpoch : (epochs[id] || 0) > 0;
  return { identity: kept ? 'kept' : 'new', boundId: id, ok };
}

/** Builds a receiver environment: a copy of the caller's with the foreign
 * parent-harness routing variables removed (nothing else is touched, so the
 * store and authentication selection stay the caller's own) and the
 * installed build's memory switches set.
 * @param {NodeJS.ProcessEnv} source The environment to copy.
 * @returns {{env: NodeJS.ProcessEnv, removed: string[]}} The environment and the sorted names removed.
 */
function receiverEnv(source) {
  const env = { ...source };
  const removed = Object.keys(env).filter(name => FOREIGN_ENV.test(name)).sort();
  for (const name of removed) delete env[name];
  return { env: { ...env, CLAUDE_CODE_DISABLE_CLAUDE_MDS: '1', CLAUDE_CODE_DISABLE_AUTO_MEMORY: '1', CLAUDE_CODE_DISABLE_ORG_MEMORY: '1' }, removed };
}

/** The closed launch argument list shared by every receiver of this probe.
 * @param {string} dir Private evidence directory (holds `settings.json`).
 * @param {string[]} extra Launch-specific arguments (session selection, caps, inbox).
 * @returns {string[]} Arguments after the executable.
 */
function launchArgs(dir, extra) {
  return ['--print', '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose', '--include-hook-events',
    '--model', 'haiku', '--effort', 'low', ...extra, '--setting-sources', '', '--settings', path.join(dir, 'settings.json'),
    '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}', '--tools', '', '--permission-mode', 'manual', '--permission-prompts', 'none', '--no-chrome'];
}

/** Whether a stream `system/init` frame shows the closed inventory: no
 * tool, no MCP server, manual or default permissions.
 * @param {StreamFrame|null} init The init frame.
 * @returns {boolean}
 */
function inventoryClosed(init) {
  return Boolean(init && Array.isArray(init.tools) && init.tools.length === 0
    && (!init.mcp_servers || init.mcp_servers.length === 0) && ['default', 'manual'].includes(init.permissionMode));
}

/** Pure validators' assertion check (`--self-test`): no native process. */
function selfTest() {
  const assert = require('node:assert/strict');
  assert.equal(usageTotal({ input_tokens: 0, cache_creation: { a: 0, b: 0 }, iterations: [{ output_tokens: 0 }], service_tier: 'standard' }), 0);
  assert.equal(usageTotal({ input_tokens: 0, cache_creation: { a: 0, b: 3 } }), 3); // nested effect must not short-circuit
  assert.equal(noModelEffect([{ num_turns: 0, total_cost_usd: 0, usage: { input_tokens: 0 } }]), true);
  assert.equal(noModelEffect([{ num_turns: 0, usage: { x: { y: 1 } } }]), false);
  assert.equal(noModelEffect([{ num_turns: 1 }]), false);
  assert.equal(noModelEffect([{ num_turns: 0, total_cost_usd: 0.01 }]), false);
  assert.equal(sharedSpend({ a: [0.1, 0.2], b: [0.15] }), 0.35); // per-receiver max, summed
  const id = '11111111-2222-4333-8444-555555555555', sent = '99999999-2222-4333-8444-555555555555';
  const frame = { type: 'conversation_reset', trigger: 'clear', user_message_uuid: sent, new_conversation_id: id, session_id: 'x' };
  assert.equal(classifyReset(frame, sent).correlated, true);
  assert.equal(classifyReset({ ...frame, user_message_uuid: id }, sent).correlated, false);
  assert.equal(classifyReset({ ...frame, trigger: 'fresh_session' }, sent).correlated, false);
  assert.equal(classifyReset({ ...frame, new_conversation_id: 'nope' }, sent).correlated, false);
  assert.equal(classifyReset(null, sent).correlated, false);
  assert.deepEqual(decideIdentity([], 'old', {}, 5), { identity: 'none', boundId: null, ok: false });
  assert.equal(decideIdentity(['new1'], 'old', { new1: 7 }, 5).ok, true);
  assert.equal(decideIdentity(['new1'], 'old', { old: 9 }, 5).ok, false); // hook named an id with no binding row
  assert.equal(decideIdentity(['old'], 'old', { old: 9 }, 5).ok, true);
  assert.equal(decideIdentity(['old'], 'old', { old: 5 }, 5).ok, false); // same id must be a strictly newer epoch
  assert.equal(decideIdentity(['old', 'new1'], 'old', { old: 9, new1: 9 }, 5).identity, 'ambiguous');
  const scrubbed = receiverEnv({ HOME: '/h', CLAUDECODE: '1', CLAUDE_CODE_SESSION_ID: 's', CLAUDE_CODE_MESSAGING_TOKEN: 't', CLAUDE_CODE_OAUTH_TOKEN: 'keep', CLAUDE_CONFIG_DIR: '/c' });
  assert.deepEqual(scrubbed.removed, ['CLAUDECODE', 'CLAUDE_CODE_MESSAGING_TOKEN', 'CLAUDE_CODE_SESSION_ID']);
  assert.equal(scrubbed.env.CLAUDE_CODE_OAUTH_TOKEN, 'keep'); // auth selection untouched
  assert.equal(scrubbed.env.CLAUDE_CONFIG_DIR, '/c');
  assert.equal(inventoryClosed({ tools: [], mcp_servers: [], permissionMode: 'manual' }), true);
  assert.equal(inventoryClosed({ tools: ['Bash'], permissionMode: 'manual' }), false);
  assert.equal(inventoryClosed({ tools: [], permissionMode: 'bypassPermissions' }), false);
  assert.equal(DEAD_REASON.test('the recipient session ended (unknown, not inactive)'), true);
  assert.equal(DEAD_REASON.test("the recipient's harness process is gone (disconnected, not inactive)"), true);
  assert.equal(DEAD_REASON.test('no-wake policy active: paused'), false); // the pause text is not a dead-incarnation reason
  assert.deepEqual(unmet({ a: true, b: false, c: 'true' }, ['a', 'b', 'c', 'd']), ['b', 'c', 'd']); // missing, false and truthy-but-not-true all block the paid phase
  assert.deepEqual(unmet({ a: true }, ['a']), []);
  assert.equal(CAP_USD.original + CAP_USD.fork < TOTAL_USD, true);
  console.log(JSON.stringify({ self_test: 'PASS' }));
}

/** Runs the probe body.
 * @param {import('./probe-lib.cjs').Probe} probe The lifecycle-managed probe.
 * @returns {Promise<void>}
 */
async function main(probe) {
  const claude = fs.realpathSync(process.env.CLAUDE_EXE || execFileSync('/usr/bin/which', ['claude'], { encoding: 'utf8' }).trim());
  const fixture = path.join(bin, 'bridge-fixture');
  probe.checks.claude_exe = claude;
  probe.checks.claude_version = probe.local(claude, ['--version']);
  probe.checks.claude_sha256 = probe.sha256(claude);
  probe.checks.bridge_sha256 = Object.fromEntries(['bridge-native-daemon', 'bridge-hook', 'bridge-fixture'].map(b => [b, probe.sha256(path.join(bin, b))]));
  probe.checks.versions_recorded = !probe.checks.claude_version.startsWith('error:');
  probe.checks.paid_phase_enabled = PAID;

  const host = 'q4-host', namespace = 'claude-q4';
  // The profile store is the receiver's OWN store selection: its inherited
  // CLAUDE_CONFIG_DIR when set, else $HOME/.claude — exactly what the
  // registry resolves from the harness process environment. Read-only.
  const store = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
  probe.checks.profile_store = store;
  probe.checks.profile_store_source = process.env.CLAUDE_CONFIG_DIR ? 'CLAUDE_CONFIG_DIR' : 'HOME/.claude';
  const { env, removed } = receiverEnv(process.env);
  probe.checks.receiver_env_removed = removed;
  /** Canonical Bridge address of one native Claude session.
   * @param {string} session Native session id (empty for the prefix).
   * @returns {string} `host/claude-code/namespace/session`.
   */
  const address = session => `${host}/claude-code/${namespace}/${session}`;
  const unpaidId = crypto.randomUUID(), originalId = crypto.randomUUID(), forkId = crypto.randomUUID();
  for (const id of [unpaidId, originalId, forkId]) probe.markers.push(id);
  const publisher = probe.credential('publisher.token'), admin = probe.credential('admin.token');
  const channelDir = path.join(probe.dir, 'ch'); fs.mkdirSync(channelDir, { mode: 0o700 });
  const channel = path.join(channelDir, 'c.sock'), core = path.join(probe.dir, 'core.sock');
  const database = path.join(probe.dir, 'bridge.db');
  const config = path.join(probe.creds, 'bridge.toml');
  // Grants: the unpaid session, the paid original and (so the fork's own
  // address could be published to, and is shown to stay empty) the fork.
  const recipients = [unpaidId, ...(PAID ? [originalId, forkId] : [])].map(address);
  fs.writeFileSync(config, [
    `database = "${database}"`, `socket = "${core}"`, '[limits]', 'max_admitted_events = 100',
    '[[grant]]', `token = "${publisher.token}"`, 'publisher = "bridge-probe"', `recipients = [${recipients.map(r => `"${r}"`).join(', ')}]`,
    'kinds = ["bridge.probe"]', 'modes = ["inject", "message"]', 'policies = ["keep_all"]',
    '[[grant]]', `token = "${admin.token}"`, 'publisher = "bridge-probe-ops"', 'admin = true',
    'recipients = []', 'kinds = []', 'modes = []', 'policies = []',
    '[adapters]', `channel = "${channel}"`, `host_id = "${host}"`,
    '[[adapters.profiles]]', `namespace = "${namespace}"`, 'harness = "ClaudeCode"', `store = "${store}"`,
    '[[adapters.profiles.executables]]', `path = "${claude}"`, `sha256 = "${probe.checks.claude_sha256}"`,
    'version = "probe"', 'inject = true', 'message = true', ''].join('\n'), { mode: 0o600 });
  const daemon = probe.spawn('daemon', path.join(bin, 'bridge-native-daemon'), [config]);
  if (!await probe.until(() => fs.existsSync(channel) && fs.existsSync(core), 10000)) throw new Error('daemon did not start');

  const hook = { type: 'command', command: `'${path.join(bin, 'bridge-hook')}' '${channel}' claude-code`, timeout: 5 };
  const coexisting = { type: 'command', command: '/usr/bin/true', timeout: 5 };
  fs.writeFileSync(path.join(probe.dir, 'settings.json'), JSON.stringify({ hooks: Object.fromEntries(HOOK_EVENTS.map(e => [e, [{ hooks: [hook, coexisting] }]])) }));

  /** Runs one fixture request mode and parses its JSON line.
   * @param {string[]} args Fixture arguments (secrets only as 0600 file paths).
   * @returns {FixtureReply} Parsed JSON, or the raw error text (bounded).
   */
  const request = args => {
    const out = probe.local(fixture, args);
    try { return JSON.parse(out); } catch { return out.slice(0, 200); }
  };
  /** Reads the Core database read-only (the probe's own fresh file).
   * @param {string} sql One SELECT statement.
   * @returns {DbRow[]} Rows (empty when the database is not readable yet).
   */
  const rows = sql => {
    if (!fs.existsSync(database)) return [];
    const out = probe.local('/usr/bin/sqlite3', ['-readonly', '-json', database, sql]);
    try { return out ? JSON.parse(out) : []; } catch { return []; }
  };
  /** Binding epoch per native session id of this host/namespace.
   * @returns {Record<string, number>} Epoch by session id.
   */
  const epochs = () => Object.fromEntries(rows('SELECT recipient, endpoint_epoch FROM bindings').filter(r => r.recipient.startsWith(address(''))).map(r => [r.recipient.slice(address('').length), r.endpoint_epoch]));
  /** Attempt rows of one recipient.
   * @param {string} session Native session id.
   * @returns {DbRow[]} Attempt rows (attempt_seq, state, recipient, actor, endpoint_epoch, proof_ref).
   */
  const attempts = session => rows(`SELECT attempt_seq, state, recipient, actor, endpoint_epoch, proof_ref FROM attempts WHERE recipient = '${address(session)}'`);
  /** Daemon event-name counts from its structured stderr log.
   * @returns {Record<string, number>}
   */
  const daemonEvents = () => {
    const file = path.join(probe.dir, 'daemon.stderr');
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    return [...text.matchAll(/"event":"([a-z_]+)"/g)].reduce((counts, m) => ({ ...counts, [m[1]]: (counts[m[1]] || 0) + 1 }), {});
  };
  /** Delivery block of an event's publisher status.
   * @param {string} id Event id.
   * @returns {Delivery|null} The block, or null when the status has none.
   */
  const delivery = id => { const status = request(['status', core, publisher.file, id]); return (status && status.Status && status.Status.delivery) || null; };
  /** Spawns one stream-json receiver and collects its parsed frames.
   * @param {string} label Process label.
   * @param {string[]} args Launch arguments after the executable.
   * @param {boolean} confined Whether to run under the network-denying sandbox.
   * @returns {Receiver} The receiver (see the typedef).
   * @throws {Error} The probe is closing (lifecycle fence) or a secret would appear in argv.
   */
  const launch = (label, args, confined) => {
    const frames = [];
    const child = confined
      ? probe.spawn(label, '/usr/bin/sandbox-exec', ['-p', POLICY, claude, ...args], { stdin: true, env }, line => { try { frames.push(JSON.parse(line)); } catch {} })
      : probe.spawn(label, claude, args, { stdin: true, env }, line => { try { frames.push(JSON.parse(line)); } catch {} });
    // A receiver that exits on its own (print mode may end after a bare
    // built-in) must not crash the probe on a later write or end.
    child.stdin.on('error', () => {});
    return {
      child, frames, startedAt: Date.now(), confined,
      send: (text, uuid) => child.stdin.write(JSON.stringify({ type: 'user', ...(uuid ? { uuid } : {}), parent_tool_use_id: null, message: { role: 'user', content: text } }) + '\n'),
    };
  };
  /** Session ids of the receiver's own hook frames for one hook event.
   * @param {StreamFrame[]} frames Receiver frames.
   * @param {string} event Hook event name.
   * @returns {string[]} `session_id` per `hook_started` frame, in order.
   */
  const hookSessions = (frames, event) => frames.filter(f => f.type === 'system' && f.subtype === 'hook_started' && f.hook_event === event).map(f => f.session_id);
  /** Whether a live process was launched with the closed flag set, read
   * from the OS's own command line of that pid (not from the builder).
   * @param {number} pid Receiver process id.
   * @returns {boolean}
   */
  const launchClosed = pid => {
    const line = probe.local('/bin/ps', ['-o', 'command=', '-p', String(pid)]);
    return ['--strict-mcp-config', '--tools', '--setting-sources', '--permission-mode manual', '--permission-prompts none', '--no-chrome'].every(flag => line.includes(flag)) && !line.startsWith('error:');
  };
  /** Waits for a frame matching `predicate`.
   * @param {StreamFrame[]} frames Receiver frames.
   * @param {(frame: StreamFrame) => boolean} predicate Matcher.
   * @param {number} ms Local bound.
   * @returns {Promise<StreamFrame|null>} The frame, or null.
   */
  const waitFrame = async (frames, predicate, ms) => { await probe.until(() => frames.some(predicate), ms); return frames.find(predicate) || null; };
  /** Ends a receiver cleanly (stdin closed) and awaits its exit.
   * @param {Receiver} receiver The receiver.
   * @returns {Promise<ExitStatus|null>} Exit status, or null on timeout.
   */
  const end = async receiver => { receiver.child.stdin.end(); return probe.exited(receiver.child, 30000); };

  // ------------------------------------------------------------------
  // Unpaid phase: confined receiver, real /clear, Bridge composition.
  // ------------------------------------------------------------------
  // Paired fence witness BEFORE any native launch: an OWN loopback listener
  // accepts an unconfined connect and the same connect under the policy
  // must be denied with a permission error (no external connection).
  const fence = await networkFenceWitness(probe, POLICY);
  probe.checks.network_fence_witness = fence;
  const receiver = launch('receiver', launchArgs(probe.dir, ['--session-id', unpaidId]), true);
  probe.checks.receiver_isolated = removed.every(name => !(name in env)) && launchClosed(receiver.child.pid);
  // In print/stream-json mode `system/init` is emitted when the first input
  // is processed; the SessionStart hook frames arrive first.
  await waitFrame(receiver.frames, f => f.type === 'system' && f.subtype === 'hook_started' && f.hook_event === 'SessionStart', 30000);
  probe.checks.session_start_frames = hookSessions(receiver.frames, 'SessionStart');
  await probe.until(() => epochs()[unpaidId] !== undefined, 20000);
  const priorEpoch = epochs()[unpaidId] || 0;
  probe.checks.bridge_session_binding = { session: unpaidId, epoch: priorEpoch, receiver_pid: receiver.child.pid, launched_ms: receiver.startedAt };
  probe.checks.bridge_session_binding_observed = priorEpoch >= receiver.startedAt - 1000 && probe.checks.session_start_frames.includes(unpaidId);

  const held = 'BRIDGE_Q4_HELD_' + crypto.randomBytes(6).toString('hex');
  probe.checks.pause_on = request(['pause', core, admin.file, address(unpaidId), 'on']);
  probe.checks.held_publish = request(['publish', core, publisher.file, address(unpaidId), 'message', 'q4-held-1', `Synthetic held lifecycle message ${held}.`]);
  await probe.until(() => { const d = delivery('q4-held-1'); return d && d.attempts_made === 0 && /no-wake/.test(d.hold_reason || ''); }, 15000);
  const beforeReset = delivery('q4-held-1');
  probe.checks.held_before_reset = beforeReset;
  probe.checks.paused_event_held_before_reset = Boolean(beforeReset && beforeReset.attempts_made === 0 && beforeReset.attempt_state === 'none' && /no-wake/.test(beforeReset.hold_reason || ''));

  // The real clear: a streamed built-in command with a client-chosen uuid.
  const clearUuid = crypto.randomUUID();
  const sentAt = receiver.frames.length; // frames before this index predate the clear
  receiver.send('/clear', clearUuid);
  const resetFrame = await waitFrame(receiver.frames, f => f.type === 'conversation_reset', 30000);
  const reset = classifyReset(resetFrame, clearUuid);
  probe.checks.reset_frame = resetFrame;
  probe.checks.reset_frame_correlated = reset.correlated;
  if (reset.newId) probe.markers.push(reset.newId);
  const init = await waitFrame(receiver.frames, f => f.type === 'system' && f.subtype === 'init', 30000);
  probe.checks.init_facts = init && { claude_code_version: init.claude_code_version, session_id: init.session_id, tools: init.tools, mcp_servers: init.mcp_servers, permissionMode: init.permissionMode, slash_commands_has_clear: (init.slash_commands || []).includes('clear') };
  // Observed fact only (never a role heuristic): the init frame's session id after the clear.
  probe.checks.init_session_after_clear = init && init.session_id;
  probe.checks.loaded_clear_command_present = Boolean(init && (init.slash_commands || []).includes('clear'));
  probe.checks.receiver_inventory_closed = inventoryClosed(init);
  if (!probe.checks.receiver_inventory_closed) { probe.fail('native_inventory_or_permission_scope'); try { process.kill(-receiver.child.pid, 'SIGTERM'); } catch {} }

  // Which native id the Bridge bound after the reset is decided by the
  // receiver's own post-reset SessionStart hook frames and the Core rows.
  /** Session ids named by SessionStart hook frames received after `/clear` was sent.
   * @returns {string[]} In arrival order (the frames before `sentAt` predate the clear).
   */
  const postStarts = () => receiver.frames.slice(sentAt).filter(f => f.type === 'system' && f.subtype === 'hook_started' && f.hook_event === 'SessionStart').map(f => f.session_id);
  await probe.until(() => postStarts().length > 0 && Object.keys(epochs()).some(id => postStarts().includes(id) && (id !== unpaidId || epochs()[id] > priorEpoch)), 20000);
  const decision = decideIdentity(postStarts(), unpaidId, epochs(), priorEpoch);
  probe.checks.reset_hook_frames = receiver.frames.filter(f => f.type === 'system' && /^hook_/.test(String(f.subtype))).map(f => ({ subtype: f.subtype, hook_event: f.hook_event, session_id: f.session_id }));
  probe.checks.reset_sdk_ids = { session_id: reset.sessionId, new_conversation_id: reset.newId, hook_bound: decision.boundId, identity: decision.identity };
  probe.checks.reset_identity_decided_by_hooks = decision.identity === 'kept' || decision.identity === 'new';
  probe.checks.reset_new_identity_bound_or_kept_renewed = decision.ok;
  probe.checks.bindings_after_reset = epochs();

  // The receiver ends; the held event must still sit on its frozen old
  // recipient with no attempt anywhere (never redirected or drained).
  const receiverExit = await end(receiver);
  probe.checks.receiver_exit = receiverExit;
  probe.checks.receiver_ended_cleanly = Boolean(receiverExit && receiverExit.code === 0);
  await new Promise(r => setTimeout(r, 2500));
  const afterReset = delivery('q4-held-1');
  probe.checks.held_after_reset = afterReset;
  probe.checks.paused_event_kept_on_old_recipient = Boolean(afterReset && afterReset.attempts_made === 0 && afterReset.attempt_state === 'none' && afterReset.delivery === 'unhanded'
    && attempts(unpaidId).length === 0);
  probe.checks.reset_nothing_dispatched_to_any_session = rows('SELECT COUNT(*) AS n FROM attempts')[0]?.n === 0;

  // Dead incarnation, separated from the pause: release the own pause
  // AFTER the receiver exited, publish a fresh message and require the
  // actual unknown/disconnected hold reason (not the no-wake text) with
  // zero hand-off, while the older event stays unhanded with its recipient.
  probe.checks.pause_off = request(['pause', core, admin.file, address(unpaidId), 'off']);
  probe.checks.post_death_publish = request(['publish', core, publisher.file, address(unpaidId), 'message', 'q4-after-death', 'Synthetic post-exit message.']);
  /** Whether an event is held by the dead-incarnation reason (never the no-wake text) with no hand-off.
   * @param {string} id Event id.
   * @returns {boolean}
   */
  const deadHold = id => { const d = delivery(id); return Boolean(d && d.attempts_made === 0 && d.attempt_state === 'none' && DEAD_REASON.test(d.hold_reason || '') && !/no-wake/.test(d.hold_reason || '')); };
  await probe.until(() => deadHold('q4-after-death') && deadHold('q4-held-1'), 20000);
  probe.checks.dead_status = { new: delivery('q4-after-death'), old: delivery('q4-held-1') };
  probe.checks.dead_incarnation_holds_fail_closed = deadHold('q4-after-death') && deadHold('q4-held-1') && rows('SELECT COUNT(*) AS n FROM attempts')[0]?.n === 0;

  // No model effect: derived from the confinement and the observed result
  // frames — every one must carry zero turns, cost and (nested) usage.
  const resultFrames = receiver.frames.filter(f => f.type === 'result');
  probe.checks.unpaid_result_frames = resultFrames.map(r => ({ num_turns: r.num_turns, cost_usd: r.total_cost_usd, usage_total: usageTotal(r.usage) }));
  probe.checks.network_confinement_effective = receiver.confined === true && fence.ok === true;
  probe.checks.no_model_effect = receiver.confined === true && noModelEffect(resultFrames);

  const events = daemonEvents();
  probe.checks.daemon_events = events;
  probe.checks.no_daemon_refusals = ['hook_refused', 'binding_fence_refused', 'caller_refused', 'drain_refused'].every(name => !events[name]);

  // ------------------------------------------------------------------
  // Paid phase (root only): original + resumed fork, total ceiling 0.50.
  // ------------------------------------------------------------------
  // Fail closed: no paid receiver starts unless every unpaid check is true.
  const unpaidUnmet = unmet(probe.checks, UNPAID_REQUIRED);
  probe.checks.paid_gate_unmet = unpaidUnmet;
  if (PAID && unpaidUnmet.length > 0) probe.fail('paid_phase_refused:unpaid_checks_unmet');
  if (PAID && unpaidUnmet.length === 0) {
    const costs = { original: [], fork: [] };
    /** Shared running spend of both paid receivers.
     * @returns {number} USD.
     */
    const spent = () => sharedSpend(costs);
    /** Records the cumulative cost of every result frame of one receiver.
     * @param {'original'|'fork'} label Receiver label.
     * @param {StreamFrame[]} frames That receiver's frames.
     * @returns {void}
     */
    const track = (label, frames) => { for (const f of frames) if (f.type === 'result' && typeof f.total_cost_usd === 'number') costs[label].push(f.total_cost_usd); };
    /** Private messaging-socket path inside the evidence directory.
     * @param {string} name Socket file name.
     * @returns {string} Absolute path.
     */
    const inbox = name => path.join(probe.dir, name);
    const original = launch('paid-original', launchArgs(probe.dir, ['--session-id', originalId, '--messaging-socket-path', inbox('inbox-o.sock'), '--max-budget-usd', String(CAP_USD.original)]), false);
    const tracker = new TurnTracker();
    /** Count of original frames already fed to the tracker. */
    let fed = 0;
    /** Feeds new original frames into the turn tracker and the cost sum.
     * @returns {void}
     */
    const pump = () => { for (; fed < original.frames.length; fed += 1) tracker.observe(original.frames[fed]); track('original', original.frames); };
    original.send('Use no tools. Reply with the single word READY.');
    const firstResult = await waitFrame(original.frames, f => f.type === 'result', 180000);
    pump();
    probe.checks.paid_original_turn_ok = Boolean(firstResult && !firstResult.is_error && /READY/i.test(String(firstResult.result || '')) && inventoryClosed(original.frames.find(f => f.type === 'system' && f.subtype === 'init')));
    await probe.until(() => { pump(); return tracker.idle(10000); }, 60000);
    const originalEpoch = epochs()[originalId];
    probe.checks.paid_original_bound = Boolean(originalEpoch) && hookSessions(original.frames, 'SessionStart').includes(originalId);
    if (!probe.checks.paid_original_turn_ok || spent() >= TOTAL_USD * 0.5) throw new Error('paid original turn not ok or spend too high; fork not started');

    // A `later` message is held by the Core pause, then the fork starts.
    const marker = 'BRIDGE_Q4_FORK_' + crypto.randomBytes(6).toString('hex');
    probe.checks.paid_pause_on = request(['pause', core, admin.file, address(originalId), 'on']);
    probe.checks.paid_publish = request(['publish', core, publisher.file, address(originalId), 'message', 'q4-fork-1', `Synthetic fork-custody message ${marker}. Quote it.`]);
    await probe.until(() => { const d = delivery('q4-fork-1'); return d && d.attempts_made === 0 && /no-wake/.test(d.hold_reason || ''); }, 15000);
    const fork = launch('paid-fork', launchArgs(probe.dir, ['--resume', originalId, '--fork-session', '--session-id', forkId, '--messaging-socket-path', inbox('inbox-f.sock'), '--max-budget-usd', String(CAP_USD.fork)]), false);
    await waitFrame(fork.frames, f => f.type === 'system' && f.subtype === 'hook_started' && f.hook_event === 'SessionStart', 60000);
    probe.checks.paid_fork_start_frames = hookSessions(fork.frames, 'SessionStart');
    await probe.until(() => epochs()[forkId] !== undefined, 30000);
    probe.checks.paid_fork_launched_new_session = fork.child.pid > 0 && forkId !== originalId && probe.checks.paid_fork_start_frames.length > 0 && probe.checks.paid_fork_start_frames.every(id => id === forkId);
    probe.checks.paid_fork_new_session_bound = epochs()[forkId] >= fork.startedAt - 1000 && epochs()[originalId] === originalEpoch;
    await new Promise(r => setTimeout(r, 5000));
    const during = delivery('q4-fork-1');
    probe.checks.paid_during_fork = during;
    probe.checks.paid_fork_keeps_event_on_original = Boolean(during && during.attempts_made === 0 && during.attempt_state === 'none' && /no-wake/.test(during.hold_reason || ''))
      && attempts(originalId).length === 0 && attempts(forkId).length === 0;
    probe.checks.paid_fork_isolated = removed.every(name => !(name in env)) && launchClosed(fork.child.pid) && launchClosed(original.child.pid);
    probe.checks.paid_fork_exit = await end(fork);
    track('fork', fork.frames);

    if (spent() >= TOTAL_USD * 0.8) throw new Error('shared spend near the ceiling before unpause');
    probe.checks.paid_pause_off = request(['pause', core, admin.file, address(originalId), 'off']);
    const turnsBefore = original.frames.filter(f => f.type === 'result').length;
    await probe.until(() => original.frames.filter(f => f.type === 'result').length > turnsBefore, 120000);
    pump();
    const delivered = original.frames.filter(f => f.type === 'result').slice(turnsBefore).find(f => !f.is_error && String(f.result || '').includes(marker)) || null;
    let tiers = [];
    await probe.until(() => { tiers = ((delivery('q4-fork-1') || {}).tiers || []).map(entry => entry.tier); return tiers.includes('context_observed') || tiers.includes('native_accepted'); }, 30000);
    probe.checks.paid_delivered_tiers = tiers;
    probe.checks.paid_unpause_delivers_to_original_turn = Boolean(delivered) && (tiers.includes('context_observed') || tiers.includes('native_accepted')) && attempts(forkId).length === 0;
    probe.checks.paid_fork_never_saw_marker = !JSON.stringify(fork.frames).includes(marker);
    const origAttempts = attempts(originalId);
    probe.checks.paid_original_attempts = origAttempts;
    // The attempt's proof reference names the harness incarnation (pid@start) the Bridge bound.
    probe.checks.paid_delivery_attempt_bound_to_original_process = origAttempts.length > 0 && origAttempts.every(a => a.actor === originalId && new RegExp(`:${original.child.pid}@`).test(a.proof_ref));
    probe.checks.paid_original_exit = await end(original);
    pump();
    probe.checks.paid_cost_by_receiver = costs;
    probe.checks.paid_total_cost_usd = spent();
    probe.checks.paid_total_cost_within_ceiling = spent() <= TOTAL_USD;
  }

  process.kill(-daemon.pid, 'SIGTERM');
  probe.checks.daemon_exit = await probe.exited(daemon, 15000);
}

if (require.main === module) {
  if (process.argv[2] === '--self-test') selfTest();
  else run('m2q4c', PAID ? 15 * 60_000 : 8 * 60_000, REQUIRED, main);
}
module.exports = { DEAD_REASON, unmet, usageTotal, noModelEffect, sharedSpend, classifyReset, decideIdentity, receiverEnv, inventoryClosed };
