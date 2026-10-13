/**
 * Owned frontend lifecycle qualification (Q4, Codex side): the
 * clear-equivalent, resume, fork-while-queue-pending, archive/unarchive,
 * disconnect and full-restart cases of A22, against isolated stock
 * app-server frontend processes and one operator-selected probe-owned
 * native session.
 *
 * Paid-model boundary: every long-running native frontend process this
 * probe starts (every app-server session) runs under `sandbox-exec` with
 * network denied, so no paid model effect is possible. Native TURN
 * creation is not model inference: this build submits a pending queue
 * item as a native turn in some lifecycle transitions, and those turns
 * are recorded exactly — id, observed status and marker — and must show no
 * model output (`modelFree`), instead of being denied. The no-model-effect
 * check is derived from the confinement (every native process under the
 * policy, plus a paired OWNED-loopback control: an own listener accepts an
 * unconfined connect and the same connect under the policy is denied with
 * EPERM/EACCES; no external address is contacted) and
 * those observed turns, never set by a comment. Short `--version`/`--help`/schema-export
 * local commands cannot create turns. The probe never extracts, copies or
 * writes any credential, and makes no claim about what the CLI itself
 * reads with its own protected authentication.
 *
 * The native session fixture is supplied EXPLICITLY by the operator
 * (`BRIDGE_Q4_ROLLOUT`, `BRIDGE_Q4_THREAD`): one probe-owned rollout file
 * (for example the root's verified R10 Q3 artifact in a private wrapper).
 * Nothing is enumerated; the file is validated before copying (its
 * `session_meta` must carry exactly the expected thread id, and its id
 * must equal its own session id — an identity-consistency check, not a
 * proof of ownership, which only the operator's selection provides) and
 * is then copied into a fresh private `CODEX_HOME` under a normalized
 * `sessions/...` relative path that cannot escape the private store. The
 * real store is read for exactly this one file and never mutated.
 *
 * Scope truth: this probe does NOT launch Bridge components (registry,
 * channel, daemon, helper); the `bridge_*` digests it records are disk
 * digests only. Its results are PREPARATORY loaded-frontend mechanism
 * evidence. The Bridge-composition lifecycle seam is the subject of
 * `claude-lifecycle-probe.cjs` for Claude (its result exists only when the
 * root runs it) and remains `pending_model` for Codex (app-server hooks
 * need turns, hence a model, to fire).
 *
 * Case map retained in `checks.case_map`, each entry `qualified`,
 * `pending_model` or `unsupported_in_scope` — nothing is erased or waived.
 *
 * Usage: `cargo +1.98.1 build --offline -p bridge-adapters --bins`, then
 * `BRIDGE_Q4_ROLLOUT=<probe-owned rollout> BRIDGE_Q4_THREAD=<thread id> \
 *    node qualification/frontend-lifecycle-probe.cjs`
 * (`CODEX_EXE` optional, default: `codex` resolved on PATH). `--self-test`
 * runs the pure validators (rollout confinement, marker dispositions,
 * model-free turns, empty-thread proof) without any native process. Writes
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
const { networkFenceWitness } = require('./lifecycle-lib.cjs');

/** A JSON value (see `lifecycle-lib.cjs`).
 * @typedef {import('./lifecycle-lib.cjs').JsonValue} JsonValue */
/** Parameters of one App Server request: string-keyed JSON, shaped per method by the loaded build's schema.
 * @typedef {{[param: string]: JsonValue}} RpcParams */
/** One App Server JSON-RPC response: the request id and EITHER a method-specific result object OR an error.
 * @typedef {{id: number, result?: {[field: string]: JsonValue}, error?: {code?: number, message?: string}}} RpcResponse */
/** One item of a native turn; only the fields read here are named (`clientId` is the queue item's client id, `content` the user input blocks).
 * @typedef {{type?: string, clientId?: string|null, content?: JsonValue}} TurnItem */
/** One native turn as `thread/turns/list` returns it.
 * @typedef {{id: string, status: string, items?: TurnItem[]}} Turn */

/**
 * Built Bridge binaries (disk digests only; never launched here).
 * @type {string}
 */
const bin = process.env.BRIDGE_BIN_DIR || path.resolve(__dirname, '../../../target/debug');
/**
 * The confinement policy of every app-server session (network denied).
 * @type {string}
 */
const POLICY = '(version 1)(allow default)(deny network*)(deny process-fork)';
/**
 * Upper bound of `thread/turns/list` pages one collection may read.
 * @type {number}
 */
const MAX_TURN_PAGES = 10;
/**
 * Largest accepted fixture rollout, in bytes.
 * @type {number}
 */
const MAX_ROLLOUT_BYTES = 64 << 20;
/**
 * Checks that must all be exactly true.
 * @type {string[]}
 */
const REQUIRED = [
  'versions_recorded', 'schema_exported_from_loaded_build', 'schema_lifecycle_methods', 'schema_no_clear_rpc',
  'fixture_supplied_and_consistent', 'network_confinement_effective', 'clear_equivalent_thread_started',
  'session_resumed', 'resume_and_fork_create_no_turn',
  'queue_item_pending', 'fork_new_thread_id', 'fork_item_stays_on_original', 'fork_item_absent_on_fork', 'fork_session_id_recorded',
  'archive_roundtrip', 'archived_queue_add_refused', 'archive_pending_disposition_recorded', 'restart_item_pending_before_disconnect',
  'disconnect_sessions_ended', 'restart_session_resumed', 'restart_state_readback', 'restart_no_unexpected_turns',
  'queue_item_cleanup', 'no_paid_model_effect', 'native_turns_recorded', 'case_map_retained',
];

/** Resolves the confined destination of an operator-selected rollout inside
 * the private store, without touching the filesystem.
 *
 * The path must be absolute and already normalized (`path.normalize` leaves
 * it unchanged, so it holds no `..`, `.` or empty segment: that single guard
 * keeps the destination inside the private store), name a `rollout-*.jsonl` file whose name contains the expected
 * thread id, and the id must be a canonical UUID. The destination is the
 * `sessions/...` tail after the LAST `sessions` segment, or
 * `sessions/imported/<basename>` when there is none.
 * @param {string} rollout Operator-selected source path.
 * @param {string} threadId Expected native thread id (canonical UUID).
 * @returns {string} Relative destination under the private store.
 * @throws {Error} The path or id is not acceptable.
 */
function confinedRollout(rollout, threadId) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(threadId))) throw new Error('thread id is not a canonical uuid');
  if (!path.isAbsolute(rollout) || path.normalize(rollout) !== rollout) throw new Error('rollout path must be absolute and normalized');
  const name = path.basename(rollout);
  if (!/^rollout-.+\.jsonl$/.test(name) || !name.includes(threadId)) throw new Error('rollout file name must be rollout-*.jsonl naming the thread id');
  const parts = rollout.split(path.sep).slice(1);
  const last = parts.lastIndexOf('sessions');
  const relative = last >= 0 && last < parts.length - 1 ? parts.slice(last) : ['sessions', 'imported', name];
  return relative.join(path.sep);
}

/** Whether a turn carries a queue-item marker exactly: an item whose
 * `clientId` is the marker, or whose text content contains it.
 * @param {Turn} turn A native turn.
 * @param {string} marker Exact client id of an own queue item.
 * @returns {boolean}
 */
function hasMarker(turn, marker) {
  return (turn.items || []).some(item => item.clientId === marker || JSON.stringify(item.content || []).includes(marker));
}

/** Classifies the disposition of one own queue item after a lifecycle step
 * against the exact pre-step turn-id set: it is still pending (no new turn),
 * or consumed as exactly one new turn carrying its marker; anything else
 * (both, neither, a second marker turn, or ANY new turn without the marker)
 * is not an accepted outcome.
 * @param {boolean} pending Whether the item is still listed in the queue.
 * @param {Turn[]} turns The complete current turn list.
 * @param {Set<string>} baselineIds Turn ids that existed before the step.
 * @param {string} marker Exact client id of the item.
 * @returns {{disposition: 'still_pending'|'consumed_as_turn'|'unreadable', ok: boolean, consumed: Turn[], others: Turn[]}} Verdict.
 */
function disposition(pending, turns, baselineIds, marker) {
  const fresh = turns.filter(turn => !baselineIds.has(turn.id));
  const consumed = fresh.filter(turn => hasMarker(turn, marker));
  const others = fresh.filter(turn => !hasMarker(turn, marker));
  const kind = pending && consumed.length === 0 ? 'still_pending' : !pending && consumed.length === 1 ? 'consumed_as_turn' : 'unreadable';
  return { disposition: kind, ok: kind !== 'unreadable' && others.length === 0, consumed, others };
}

/** Whether a native turn shows no model output: it did not complete and
 * holds no assistant message item (a turn created under network denial is
 * observed `interrupted`; this does not assert it).
 * @param {Turn} turn A native turn.
 * @returns {boolean}
 */
function modelFree(turn) {
  return turn.status !== 'completed' && !(turn.items || []).some(item => item.type === 'agentMessage');
}

/** Whether a response proves a thread is EMPTY: a successful listing with no
 * rows and no further page, or the build's own "no rollout found for thread
 * id <id>" refusal (nothing persisted for it yet).
 * @param {RpcResponse|undefined} answer One JSON-RPC response (listing results carry `data` and `nextCursor`).
 * @param {string} id The thread id asked about.
 * @returns {boolean}
 */
function emptyAnswer(answer, id) {
  if (!answer) return false;
  if (answer.result) return Array.isArray(answer.result.data) && answer.result.data.length === 0 && !answer.result.nextCursor;
  return Boolean(answer.error && /no rollout found/.test(String(answer.error.message)) && String(answer.error.message).includes(id));
}

/** Whether a fresh `thread/start` thread is provably empty although the loaded
 * build refuses its turn list: the build answers `thread/turns/list` of a
 * thread that has had no user message with error code -32600 and EXACTLY
 * "thread <id> is not materialized yet; thread/turns/list is unavailable
 * before first user message" (an explicit before-first-message state, NOT
 * `notLoaded`). It is accepted only together with the verified constructor
 * facts of the same response (the id asked about, status `idle`, empty
 * preview, no fork lineage) and a SUCCESSFUL empty `thread/queue/list` from
 * the same owner process; any other error, code, message, suffix or id, a
 * missing or failed queue listing, or a non-fresh constructor is not empty.
 * @param {RpcResponse|undefined} turnsReply Response to `thread/turns/list` of the new thread.
 * @param {RpcResponse|undefined} queueReply Response to `thread/queue/list` of the new thread, from the same owner process.
 * @param {{id?: string, status?: {type?: string}, preview?: string, forkedFromId?: string|null}|null} start The `thread` of the `thread/start` response.
 * @param {string} id The id asked about (the new thread's id).
 * @returns {boolean}
 */
function unmaterializedEmpty(turnsReply, queueReply, start, id) {
  const fresh = Boolean(start && start.id === id && start.status && start.status.type === 'idle' && start.preview === '' && !start.forkedFromId);
  const queueEmpty = Boolean(queueReply && queueReply.result && Array.isArray(queueReply.result.data) && queueReply.result.data.length === 0);
  const refused = Boolean(turnsReply && turnsReply.error && turnsReply.error.code === -32600
    && turnsReply.error.message === `thread ${id} is not materialized yet; thread/turns/list is unavailable before first user message`);
  return fresh && queueEmpty && refused;
}

/** Whether a `thread/queue/add` response to an ARCHIVED thread is the build's
 * native archive refusal: a JSON-RPC error with code -32600 whose message
 * says the thread "is archived" (observed on 0.162.0-alpha.17.2), and NO
 * result. Any other error (including an internal error after which a queue
 * effect is possible), a success, or a missing response is not the refusal.
 * @param {RpcResponse|undefined} reply The response to the add.
 * @returns {boolean}
 */
function archiveRefusal(reply) {
  return Boolean(reply && reply.result === undefined && reply.error && reply.error.code === -32600 && /is archived/.test(String(reply.error.message)));
}

/** Pure-logic assertion check (`--self-test`): no native process. */
function selfTest() {
  const assert = require('node:assert/strict');
  const id = '00000000-0000-4000-8000-00000000000a';
  const file = `/x/sessions/2026/10/11/rollout-2026-10-11T11-03-03-${id}.jsonl`;
  assert.equal(confinedRollout(file, id), `sessions/2026/10/11/rollout-2026-10-11T11-03-03-${id}.jsonl`);
  assert.equal(confinedRollout(`/x/y/rollout-a-${id}.jsonl`, id), `sessions/imported/rollout-a-${id}.jsonl`);
  assert.throws(() => confinedRollout(`/x/sessions/../../etc/rollout-a-${id}.jsonl`, id)); // traversal refused
  assert.throws(() => confinedRollout(`sessions/rollout-a-${id}.jsonl`, id)); // relative refused
  assert.throws(() => confinedRollout(file, 'not-a-uuid'));
  assert.throws(() => confinedRollout(file.replace(id, '11111111-2222-4333-8444-555555555555'), id)); // name must carry the id
  assert.throws(() => confinedRollout(`/x/sessions/note-${id}.txt`, id));
  /** Builds a minimal native turn for the assertions.
   * @param {string} tid Turn id.
   * @param {string|null} marker Queue-item client id carried by its user message, or null.
   * @param {string} [status] Turn status.
   * @returns {Turn}
   */
  const turn = (tid, marker, status = 'interrupted') => ({ id: tid, status, items: marker ? [{ type: 'userMessage', clientId: marker, content: [{ type: 'text', text: 'm ' + marker }] }] : [] });
  const base = new Set(['t1']);
  assert.equal(disposition(true, [turn('t1')], base, 'M').disposition, 'still_pending');
  assert.equal(disposition(true, [turn('t1')], base, 'M').ok, true);
  assert.equal(disposition(false, [turn('t1'), turn('t2', 'M')], base, 'M').disposition, 'consumed_as_turn');
  assert.equal(disposition(false, [turn('t1'), turn('t2', 'M')], base, 'M').ok, true);
  assert.equal(disposition(true, [turn('t1'), turn('t2', 'M')], base, 'M').ok, false); // both pending and consumed
  assert.equal(disposition(false, [turn('t1')], base, 'M').ok, false); // item lost
  assert.equal(disposition(false, [turn('t1'), turn('t2', 'M'), turn('t3', 'M')], base, 'M').ok, false); // two marker turns
  assert.equal(disposition(false, [turn('t1'), turn('t2', 'M'), turn('t3')], base, 'M').ok, false); // an unrelated new turn
  assert.equal(disposition(true, [turn('t1'), turn('t9', 'M-longer')], base, 'M').consumed.length, 1); // a marker that merely extends M still contains it: ids must not be prefixes
  assert.equal(modelFree(turn('t', 'M', 'interrupted')), true);
  assert.equal(modelFree(turn('t', 'M', 'completed')), false);
  assert.equal(modelFree({ id: 't', status: 'failed', items: [{ type: 'agentMessage' }] }), false);
  assert.equal(emptyAnswer({ result: { data: [] } }, id), true);
  assert.equal(emptyAnswer({ result: { data: [], nextCursor: 'c' } }, id), false);
  assert.equal(emptyAnswer({ result: { data: [{}] } }, id), false);
  assert.equal(emptyAnswer({ error: { message: `no rollout found for thread id ${id}` } }, id), true);
  assert.equal(emptyAnswer({ error: { message: 'no rollout found for thread id other' } }, id), false);
  assert.equal(emptyAnswer(undefined, id), false);
  assert.equal(archiveRefusal({ id: 1, error: { code: -32600, message: `thread ${id} is archived` } }), true);
  assert.equal(archiveRefusal({ id: 1, error: { code: -32603, message: `thread ${id} is archived` } }), false); // internal error: a queue effect is possible
  assert.equal(archiveRefusal({ id: 1, error: { code: -32600, message: 'invalid request' } }), false); // another validation error
  assert.equal(archiveRefusal({ id: 1, error: { code: -32600, message: 'thread is archived' }, result: {} }), false);
  assert.equal(archiveRefusal({ id: 1, result: { queuedSubmission: {} } }), false); // accepted
  assert.equal(archiveRefusal(undefined), false);
  const fresh = { id, status: { type: 'idle' }, preview: '', forkedFromId: null };
  const emptyQueue = { id: 3, result: { data: [] } };
  const unmaterialized = { id: 2, error: { code: -32600, message: `thread ${id} is not materialized yet; thread/turns/list is unavailable before first user message` } };
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, fresh, id), true);
  assert.equal(unmaterializedEmpty({ id: 2, error: { code: -32600, message: `thread ${id} is not loaded` } }, emptyQueue, fresh, id), false); // notLoaded / other message
  assert.equal(unmaterializedEmpty({ id: 2, error: { code: -32603, message: unmaterialized.error.message } }, emptyQueue, fresh, id), false); // other code
  assert.equal(unmaterializedEmpty({ id: 2, error: { code: -32600, message: unmaterialized.error.message + ' (retry)' } }, emptyQueue, fresh, id), false); // not the exact suffix
  assert.equal(unmaterializedEmpty({ id: 2, error: { code: -32600, message: unmaterialized.error.message.replace(id, 'other') } }, emptyQueue, fresh, id), false); // another thread
  assert.equal(unmaterializedEmpty(unmaterialized, { id: 3, result: { data: [{}] } }, fresh, id), false); // inherited queue item
  assert.equal(unmaterializedEmpty(unmaterialized, { id: 3, error: { code: -32603, message: 'no rollout found' } }, fresh, id), false); // queue not listed successfully
  assert.equal(unmaterializedEmpty(unmaterialized, undefined, fresh, id), false);
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, { ...fresh, forkedFromId: 'p' }, id), false); // a fork is not an empty reset
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, { ...fresh, preview: 'hello' }, id), false);
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, { ...fresh, status: { type: 'notLoaded' } }, id), false);
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, { ...fresh, id: 'other' }, id), false);
  assert.equal(unmaterializedEmpty(unmaterialized, emptyQueue, null, id), false);
  console.log(JSON.stringify({ self_test: 'PASS' }));
}

if (require.main === module && process.argv[2] === '--self-test') selfTest();
else if (require.main === module) run('m2q4', 15 * 60_000, REQUIRED, async probe => {
  const codex = fs.realpathSync(process.env.CODEX_EXE || execFileSync('/usr/bin/which', ['codex'], { encoding: 'utf8' }).trim());

  // Identity of the loaded frontend and the adapter/helper build on disk
  // (A22: hash/path/version of what is actually loaded; the disk digests
  // here only tie the build artifacts to this run).
  probe.checks.codex_exe = codex;
  probe.checks.codex_version = probe.local(codex, ['--version']);
  probe.checks.codex_sha256 = probe.sha256(codex);
  probe.checks.bridge_disk_sha256 = Object.fromEntries(['bridge-native-daemon', 'bridge-hook', 'bridge-fixture'].map(b => [b, probe.sha256(path.join(bin, b))]));
  probe.checks.bridge_bins_not_launched = true; // this probe spawns no Bridge binary
  probe.checks.versions_recorded = !probe.checks.codex_version.startsWith('error:');

  // The loaded build's OWN protocol schema, exported now, confined (read-only
  // use of the normal config; no credential is extracted or logged).
  // `--experimental` matches the surface the product speaks: every runtime
  // session initializes with `experimentalApi: true`, and without the flag
  // the exporter omits the queue methods entirely.
  const schemaDir = path.join(probe.dir, 'schema-bundle');
  fs.mkdirSync(schemaDir, { mode: 0o700 });
  probe.local('/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'app-server', 'generate-json-schema', '--experimental', '--out', schemaDir]);
  const bundle = fs.readdirSync(schemaDir).filter(f => f.endsWith('.json'));
  const methods = new Set();
  let revertDescription = null;
  /** Collects every `thread/...` method name string anywhere in a schema.
   * @param {JsonValue} value A parsed JSON schema fragment (any JSON value).
   * @returns {void} Names are added to the enclosing `methods` set.
   */
  const walkSchema = value => {
    if (typeof value === 'string') {
      if (/^thread\//.test(value)) methods.add(value);
      return;
    }
    if (Array.isArray(value)) return value.forEach(walkSchema);
    if (value && typeof value === 'object') {
      for (const child of Object.values(value)) walkSchema(child);
    }
  };
  for (const file of bundle) {
    let parsed = null;
    try { parsed = JSON.parse(fs.readFileSync(path.join(schemaDir, file), 'utf8')); } catch {}
    if (!parsed) continue;
    walkSchema(parsed);
    if (parsed.definitions && parsed.definitions.ThreadRevertParams && parsed.definitions.ThreadRevertParams.description) {
      revertDescription = parsed.definitions.ThreadRevertParams.description;
    }
  }
  probe.checks.schema_bundle_files = bundle.length;
  probe.checks.schema_methods = [...methods].sort();
  const need = ['thread/start', 'thread/resume', 'thread/fork', 'thread/archive', 'thread/unarchive', 'thread/revert', 'thread/queue/add', 'thread/queue/list', 'thread/queue/delete'];
  probe.checks.schema_lifecycle_methods = need.every(m => methods.has(m));
  probe.checks.schema_no_clear_rpc = !methods.has('thread/clear') && !methods.has('thread/reset');
  probe.checks.schema_exported_from_loaded_build = probe.checks.schema_lifecycle_methods === true && probe.checks.schema_no_clear_rpc === true;
  probe.checks.revert_schema_description = revertDescription;
  if (!probe.checks.schema_exported_from_loaded_build) throw new Error('loaded build schema export did not show the lifecycle surface');

  // The operator-selected probe-owned fixture: explicit rollout path and
  // expected thread id, validated before anything is copied.
  const rollout = process.env.BRIDGE_Q4_ROLLOUT;
  const threadId = process.env.BRIDGE_Q4_THREAD;
  if (!rollout || !threadId) throw new Error('BRIDGE_Q4_ROLLOUT and BRIDGE_Q4_THREAD (one probe-owned rollout and its thread id) are required');
  const relative = confinedRollout(rollout, threadId);
  const status = fs.lstatSync(rollout);
  if (!status.isFile() || status.size > MAX_ROLLOUT_BYTES) throw new Error('rollout must be a regular file within the size bound');
  const meta = JSON.parse(fs.readFileSync(rollout, 'utf8').split('\n')[0]).payload;
  // Identity consistency of the fixture's own metadata: the file's thread id
  // equals its session id and the operator's expected id. This proves
  // internal consistency, NOT ownership — ownership comes only from the
  // operator's explicit selection of a probe-owned artifact.
  probe.checks.fixture_facts = {
    source_basename: path.basename(rollout), sha256: probe.sha256(rollout), bytes: status.size,
    meta_id: meta.id, meta_session_id: meta.session_id, expected_thread_id: threadId,
    identity_consistent: meta.id === meta.session_id && meta.id === threadId,
  };
  probe.checks.fixture_supplied_and_consistent = probe.checks.fixture_facts.identity_consistent === true;
  if (!probe.checks.fixture_supplied_and_consistent) throw new Error('fixture metadata is not identity-consistent with BRIDGE_Q4_THREAD');
  const store = path.join(probe.dir, 'codex-home');
  fs.mkdirSync(path.join(store, path.dirname(relative)), { recursive: true, mode: 0o700 });
  fs.copyFileSync(rollout, path.join(store, relative), fs.constants.COPYFILE_EXCL);
  probe.checks.fixture_copied_to = relative;

  // Own queue-item client ids: distinct, none a prefix of another (the
  // marker match is a substring match over turn content).
  const tag = crypto.randomBytes(6).toString('hex');
  const clientA = `q4fe-a-${tag}`, clientB = `q4fe-b-${tag}`, clientX = `q4fe-x-${tag}`;
  /** The queue-item client ids this probe may own in the fixture thread.
   * @returns {string[]} Client ids whose queue items cleanup must remove. */
  const ownClients = () => [clientA, clientB, clientX];
  let confinedNatives = 0; // native frontend processes started under POLICY
  let threadReady = false; // whether the fixture thread exists in the private store (cleanup guard)

  /**
   * Opens one confined, network-denied app-server owner process against the
   * isolated store and performs the initialize handshake; the process stays
   * alive (and its loaded state with it) until `close`. Logs only bounded
   * projected lines.
   * @param {string} label Log label.
   * @param {boolean} [cleanup] Registered-cleanup invocation (allowed past the lifecycle fence).
   * @returns {Promise<{child: import('node:child_process').ChildProcess, ready: boolean, request: (method: string, params: RpcParams) => Promise<RpcResponse|undefined>, close: () => Promise<{code: number|null, signal: string|null}|{error: string}|null>}>}
   *   The owner: its process, whether the handshake was answered, a sequential request sender (undefined when the owner is not ready or no response arrived in 20 s) and a closer that ends stdin, terminates the process group and returns its exit.
   */
  async function openOwner(label, cleanup = false) {
    const lines = [];
    /** Pre-write projection of one stdout line: notifications keep their
     * method (and thread id), responses pass through unless huge (then
     * only their byte count is retained); unparsable lines are dropped.
     * @param {string} line One raw stdout line.
     * @returns {string|null} The line to log and parse, or null to drop.
     */
    const keep = line => {
      let message;
      try { message = JSON.parse(line); } catch { return null; }
      if (!message || typeof message !== 'object') return null;
      if (message.method !== undefined) return JSON.stringify({ method: String(message.method).slice(0, 64), threadId: message.params && message.params.threadId ? String(message.params.threadId) : null });
      const body = JSON.stringify(message.result !== undefined ? message.result : message.error);
      return body && body.length > 16000 ? JSON.stringify({ id: message.id, result_bytes: body.length }) : line;
    };
    confinedNatives += 1;
    const child = probe.spawn(label, '/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'app-server', '--listen', 'stdio://'],
      { stdin: true, cleanup, keep, env: { PATH: '/usr/bin:/bin', HOME: os.homedir(), CODEX_HOME: store } },
      line => { try { lines.push(JSON.parse(line)); } catch {} });
    child.stdin.on('error', () => {});
    /** Sends one JSON-RPC request.
     * @param {number} id Request id.
     * @param {string} method Method name.
     * @param {RpcParams} params Parameters.
     * @returns {void}
     */
    const send = (id, method, params) => child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    /** Resolves when the response to `id` arrived.
     * @param {number} id Request id.
     * @returns {Promise<RpcResponse|undefined>} The response, or undefined on timeout.
     */
    const answer = async id => { await probe.until(() => lines.some(l => l.id === id && l.method === undefined), 20000); return lines.find(l => l.id === id && l.method === undefined); };
    send(0, 'initialize', { clientInfo: { name: 'agent_bridge_q4', version: '0' }, capabilities: { experimentalApi: true } });
    const ready = Boolean(await answer(0));
    if (ready) child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
    let nextId = 1;
    return {
      child, ready,
      request: async (method, params) => {
        if (!ready) return undefined;
        const id = nextId; nextId += 1;
        send(id, method, params);
        return answer(id);
      },
      close: async () => {
        child.stdin.end();
        try { process.kill(-child.pid, 'SIGTERM'); } catch {}
        const exit = await probe.exited(child, 5000);
        probe.checks[`${label}_exit`] = exit;
        return exit;
      },
    };
  }

  /**
   * Runs one confined, network-denied app-server session against the
   * isolated store: opens an owner, sends the requests in order and closes it.
   * @param {string} label Log label.
   * @param {[string, RpcParams|((responses: (RpcResponse|undefined)[]) => RpcParams)][]} requests Requests after
   *   `initialize`; a params value may be a function of the responses so far
   *   (all requests of one call share ONE owner process, so a thread the
   *   first request created is still loaded for the later ones).
   * @param {boolean} [cleanup] Registered-cleanup invocation (allowed past
   *   the lifecycle fence).
   * @returns {Promise<(RpcResponse|undefined)[]>} Responses in order (undefined where none arrived in 20 s).
   */
  async function q4session(label, requests, cleanup = false) {
    const owner = await openOwner(label, cleanup);
    const responses = [];
    if (owner.ready) {
      for (const [method, params] of requests) responses.push(await owner.request(method, typeof params === 'function' ? params(responses) : params));
    }
    await owner.close();
    return responses;
  }

  /**
   * Collects one thread's complete turn list with bounded pagination.
   * @param {string} label Log label.
   * @param {string} [thread] Thread id (default: the fixture thread).
   * @returns {Promise<{turns: Turn[]|null, complete: boolean}>}
   *   Turns (null when a page failed) and whether pagination finished within
   *   MAX_TURN_PAGES pages; an incomplete collection never proves absence.
   */
  async function collectTurns(label, thread = threadId) {
    const turns = [];
    let cursor = null;
    for (let page = 0; page < MAX_TURN_PAGES; page += 1) {
      const [reply] = await q4session(`${label}-${page}`, [['thread/turns/list', cursor ? { threadId: thread, limit: 50, cursor } : { threadId: thread, limit: 50 }]]);
      const result = ((reply || {}).result) || null;
      if (!result || !Array.isArray(result.data)) return { turns: null, complete: false };
      turns.push(...result.data);
      cursor = result.nextCursor || null;
      if (!cursor) return { turns, complete: true };
    }
    return { turns, complete: false };
  }

  /** Lists the own queue items still present on the fixture thread.
   * @param {string} label Log label.
   * @param {boolean} [cleanup] Registered-cleanup invocation.
   * @returns {Promise<{id: string, clientUserMessageId: string}[]|null>} Own items, or null when the listing failed.
   */
  async function ownItems(label, cleanup = false) {
    const [reply] = await q4session(label, [['thread/queue/list', { threadId }]], cleanup);
    const data = ((reply || {}).result || {}).data;
    return Array.isArray(data) ? data.filter(i => ownClients().includes(i.clientUserMessageId)) : null;
  }

  // Deterministic cleanup of ALL own queued items on every path: unarchive
  // first (an interrupted archive step would otherwise refuse the listing),
  // then delete each own item, then verify none remains.
  probe.onCleanup('q4-queue-items', async () => {
    if (!threadReady) { probe.checks.queue_item_cleanup = true; probe.checks.queue_cleanup_removed = 0; return; }
    await q4session('cleanup-unarchive', [['thread/unarchive', { threadId }]], true);
    const mine = await ownItems('cleanup-list', true);
    for (const entry of mine || []) await q4session('cleanup-delete', [['thread/queue/delete', { threadId, queuedSubmissionId: entry.id }]], true);
    const remaining = await ownItems('cleanup-verify', true);
    probe.checks.queue_cleanup_removed = (mine || []).length;
    probe.checks.queue_item_cleanup = Array.isArray(remaining) && remaining.length === 0;
  });

  // Confinement truth, paired: an OWN loopback listener accepts an
  // unconfined connect and the same connect under the policy must be denied
  // with a permission error. Every native session below runs under that
  // policy, so a turn the build creates cannot complete a model exchange.
  const fence = await networkFenceWitness(probe, POLICY);
  probe.checks.network_fence_witness = fence;
  probe.checks.network_confinement_effective = fence.ok === true;

  // Clear-equivalent, executed for real: a confined `thread/start` on the
  // isolated store must produce a DISTINCT, empty thread — new id, no turns,
  // no inherited queue item — which is what a frontend clear maps to on this
  // protocol (there is no clear RPC; `thread/revert` only truncates durable
  // history, and `thread/fork` copies history).
  // The turn list and the queue are asked IN THE SAME owner process that
  // created the thread (it is still loaded there): a later process would
  // answer "thread not loaded", which is NOT accepted as empty.
  /** Thread id created by the first response, or a placeholder that no list can match.
   * @param {(RpcResponse|undefined)[]} responses Responses so far.
   * @returns {string}
   */
  const createdId = responses => ((((responses[0] || {}).result || {}).thread) || {}).id || 'no-thread-created';
  const cleared = await q4session('clear-start', [
    ['thread/start', { cwd: probe.dir }],
    ['thread/turns/list', responses => ({ threadId: createdId(responses), limit: 50 })],
    ['thread/queue/list', responses => ({ threadId: createdId(responses) })],
  ]);
  const startThread = (((cleared[0] || {}).result || {}).thread) || null;
  probe.checks.clear_start_facts = startThread && { id: startThread.id, sessionId: startThread.sessionId, status: startThread.status, preview: startThread.preview, forkedFromId: startThread.forkedFromId || null, response_turns: Array.isArray(startThread.turns) ? startThread.turns.length : null };
  let clearThreadChecks = { distinct: false, positiveStart: false, noTurns: false, noInheritedQueue: false };
  if (startThread && startThread.id && startThread.id !== threadId) {
    probe.markers.push(startThread.id);
    // Empty-thread proof: an empty list, "no rollout found", or the explicit
    // before-first-message refusal (see `unmaterializedEmpty`, which also
    // re-verifies the constructor and the same-owner empty queue).
    // Positive constructor facts of the response (the schema populates
    // `turns` only on resume/fork/read, so its emptiness here is recorded,
    // not relied on) plus an empty list or the build's own "no rollout found
    // for thread id <id>" refusal, from the owner that still has it loaded.
    clearThreadChecks = {
      distinct: true,
      positiveStart: startThread.status && startThread.status.type === 'idle' && startThread.preview === '' && !startThread.forkedFromId,
      noTurns: emptyAnswer(cleared[1], startThread.id) || unmaterializedEmpty(cleared[1], cleared[2], startThread, startThread.id),
      noInheritedQueue: emptyAnswer(cleared[2], startThread.id),
    };
    probe.checks.clear_start_answers = { turns: cleared[1] && (cleared[1].error || { rows: ((cleared[1].result || {}).data || []).length }), queue: cleared[2] && (cleared[2].error || { rows: ((cleared[2].result || {}).data || []).length }) };
  }
  probe.checks.clear_thread_checks = clearThreadChecks;
  probe.checks.clear_equivalent_thread_started = clearThreadChecks.distinct && clearThreadChecks.positiveStart === true && clearThreadChecks.noTurns && clearThreadChecks.noInheritedQueue;

  // Session A: resume the fixture, queue one item, fork while pending, then
  // the archive/unarchive round-trip.
  threadReady = true;
  const resumed = await q4session('resume-a', [['thread/resume', { threadId, excludeTurns: true }]]);
  const resumeThread = (((resumed[0] || {}).result || {}).thread) || null;
  probe.checks.session_resumed = Boolean(resumeThread && resumeThread.id === threadId);
  probe.checks.resume_thread_facts = resumeThread && { id: resumeThread.id, sessionId: resumeThread.sessionId, forkedFromId: resumeThread.forkedFromId || null };
  const baseline = await collectTurns('turns-baseline');
  if (!baseline.complete) throw new Error('turn collection did not complete before the queue case');
  const baselineIds = new Set(baseline.turns.map(t => t.id));
  probe.checks.turn_baseline_ids = [...baselineIds];

  const queued = await q4session('queue-add', [['thread/queue/add', { threadId, clientUserMessageId: clientA, input: [{ type: 'text', text: `Q4 frontend lifecycle pending item ${clientA}` }] }]]);
  const addItem = (queued[0] || {}).result || (queued[0] || {}).error || null;
  probe.checks.queue_add_result = addItem;
  const itemsA = await ownItems('queue-list-a');
  probe.checks.queue_item_pending = Boolean(addItem && !addItem.code && Array.isArray(itemsA) && itemsA.some(i => i.clientUserMessageId === clientA));

  const forked = await q4session('fork', [['thread/fork', { threadId }]]);
  const forkThread = (((forked[0] || {}).result || {}).thread) || null;
  probe.checks.fork_thread_facts = forkThread && { id: forkThread.id, sessionId: forkThread.sessionId, forkedFromId: forkThread.forkedFromId || null };
  probe.checks.fork_new_thread_id = Boolean(forkThread && forkThread.id && forkThread.id !== threadId);
  probe.checks.fork_shares_session_id = Boolean(forkThread && resumeThread && forkThread.sessionId === resumeThread.sessionId);
  probe.checks.fork_session_id_recorded = Boolean(forkThread && typeof forkThread.sessionId === 'string'
    && resumeThread && typeof resumeThread.sessionId === 'string');
  if (forkThread) probe.markers.push(forkThread.id);
  const origItems = await ownItems('queue-list-orig');
  const [forkListed] = forkThread ? await q4session('queue-list-fork', [['thread/queue/list', { threadId: forkThread.id }]]) : [undefined];
  const forkItems = (((forkListed || {}).result || {}).data) || null;
  probe.checks.fork_item_stays_on_original = Array.isArray(origItems) && origItems.some(i => i.clientUserMessageId === clientA);
  probe.checks.fork_item_absent_on_fork = Array.isArray(forkItems) && !forkItems.some(i => i.clientUserMessageId === clientA);
  // A fork copies history into a new thread but must create no turn on the
  // original: compare the complete turn-id set with the pre-fork baseline.
  const afterFork = await collectTurns('turns-after-fork');
  probe.checks.resume_and_fork_create_no_turn = afterFork.complete && afterFork.turns.every(t => baselineIds.has(t.id)) && afterFork.turns.length === baseline.turns.length;

  const archived = await q4session('archive', [['thread/archive', { threadId }]]);
  probe.checks.archive_result = (archived[0] || {}).error || 'ok';
  const archivedAdd = await q4session('queue-add-archived', [['thread/queue/add', { threadId, clientUserMessageId: clientX, input: [{ type: 'text', text: 'must be refused on an archived thread' }] }]]);
  const archivedAddError = (archivedAdd[0] || {}).error || null;
  probe.checks.archived_queue_add_result = archivedAddError || (archivedAdd[0] || {}).result || null;
  probe.checks.archived_queue_add_refusal_class = archiveRefusal(archivedAdd[0]); // the exact native class; absence is read back below
  const unarchived = await q4session('unarchive', [['thread/unarchive', { threadId }]]);
  probe.checks.unarchive_result = (unarchived[0] || {}).error || 'ok';
  probe.checks.archive_roundtrip = probe.checks.archive_result === 'ok' && probe.checks.unarchive_result === 'ok';
  // Observed disposition of the pending item across the archive round-trip:
  // this build may settle it into a native turn (interrupted under network
  // denial) or keep it pending, racily in time, so it is polled up to 20 s
  // and the verdict is computed against the COMPLETE turn list afterwards,
  // by exact marker (see `disposition`). A still-pending item is deleted so
  // the restart case has a deterministic turn set.
  const settleEnd = Date.now() + 20_000;
  while (Date.now() < settleEnd && probe.remaining() > 30_000) {
    const left = await ownItems('settle-poll');
    if (Array.isArray(left) && !left.some(i => i.clientUserMessageId === clientA)) break;
    await new Promise(r => setTimeout(r, 1000));
  }
  const archiveTurns = await collectTurns('turns-after-archive');
  if (!archiveTurns.complete) throw new Error('turn collection did not complete after the archive case');
  // The refused add must have left NO trace: the exact marker is absent from
  // the own queue and from the complete native turn list (an error after a
  // possible write is never accepted as a refusal on its own).
  const queueAfterArchive = await ownItems('queue-list-clientx');
  probe.checks.archived_queue_add_absent = Array.isArray(queueAfterArchive) && !queueAfterArchive.some(i => i.clientUserMessageId === clientX)
    && !archiveTurns.turns.some(t => hasMarker(t, clientX));
  probe.checks.archived_queue_add_refused = probe.checks.archived_queue_add_refusal_class === true && probe.checks.archived_queue_add_absent === true;
  const stillPendingA = ((await ownItems('queue-list-after-archive')) || []).some(i => i.clientUserMessageId === clientA);
  const archiveVerdict = disposition(stillPendingA, archiveTurns.turns, baselineIds, clientA);
  probe.checks.archive_pending_disposition = { disposition: archiveVerdict.disposition, turns: archiveVerdict.consumed.map(t => ({ id: t.id, status: t.status })), unrelated_new_turns: archiveVerdict.others.length };
  probe.checks.archive_pending_disposition_recorded = archiveVerdict.ok;
  if (stillPendingA) {
    for (const entry of (await ownItems('queue-list-pre-delete')) || []) {
      if (entry.clientUserMessageId === clientA) await q4session('queue-delete-a', [['thread/queue/delete', { threadId, queuedSubmissionId: entry.id }]]);
    }
  }

  // Turn-id baseline AFTER settlement/deletion and BEFORE the restart item,
  // so the restart comparison is against the actual pre-restart turn set,
  // whatever the archive disposition did.
  const baseline2 = await collectTurns('turns-baseline-2');
  if (!baseline2.complete) throw new Error('turn collection did not complete before the restart case');
  const baseline2Ids = new Set(baseline2.turns.map(t => t.id));

  // A fresh pending item carries the disconnect/restart case. It is added
  // and read back through a LIVE owner process that stays up (its PID alive)
  // until the explicit disconnect below; if the build consumes the item in
  // that live owner the readback is not pending, the check fails and the
  // outcome stays recorded (nothing is passed on a process that was never live).
  const liveOwner = await openOwner('live-owner');
  const livePid = liveOwner.child.pid;
  /** Whether a process id is alive.
   * @param {number} pid Process id.
   * @returns {boolean}
   */
  const pidAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
  const aliveBeforeAdd = liveOwner.ready && pidAlive(livePid);
  const queued2 = await liveOwner.request('thread/queue/add', { threadId, clientUserMessageId: clientB, input: [{ type: 'text', text: `Q4 restart persistence item ${clientB}` }] });
  const addItem2 = (queued2 || {}).result || (queued2 || {}).error || null;
  probe.checks.queue_add_b_result = addItem2 && addItem2.queuedSubmission ? 'ok' : addItem2;
  const readbackReply = await liveOwner.request('thread/queue/list', { threadId });
  const readbackB = (((readbackReply || {}).result || {}).data || []).filter(i => i.clientUserMessageId === clientB);
  const aliveAtReadback = pidAlive(livePid);
  probe.checks.live_owner_readback = { pid: livePid, alive_before_add: aliveBeforeAdd, alive_at_readback: aliveAtReadback, rows: readbackB.length };
  probe.checks.restart_item_pending_before_disconnect = aliveBeforeAdd && aliveAtReadback && readbackB.length === 1
    && JSON.stringify(readbackB[0].input || []).includes(clientB);

  // Explicit disconnect of that live owner: its exit and liveness are
  // recorded. The pending state's persistence is proven after restart by
  // own-item readback in a NEW process, not by a file listing.
  const aliveAtDisconnect = pidAlive(livePid);
  const liveExit = await liveOwner.close();
  probe.checks.live_owner_disconnect = { pid: livePid, alive_at_disconnect: aliveAtDisconnect, exit: liveExit, alive_after: pidAlive(livePid) };
  probe.checks.disconnect_sessions_ended = aliveAtDisconnect && liveExit !== null && !pidAlive(livePid)
    && probe.children.every(c => c.child.exitCode !== null || c.child.signalCode !== null);

  // Full restart of the owned client: a fresh app-server resumes the same
  // thread id. Exactly two outcomes are accepted: the item still pending
  // with no new turn, or consumed as the ONE new turn carrying its marker.
  // Any other new turn, a lost item, or both fail (see `disposition`).
  const restartResumed = await q4session('resume-b', [['thread/resume', { threadId, excludeTurns: true }]]);
  const restartThread = (((restartResumed[0] || {}).result || {}).thread) || null;
  probe.checks.restart_session_resumed = Boolean(restartThread && restartThread.id === threadId);
  await new Promise(r => setTimeout(r, 2000));
  const stillPendingB = ((await ownItems('queue-list-after-restart')) || []).some(i => i.clientUserMessageId === clientB);
  const restartTurns = await collectTurns('turns-after-restart');
  if (!restartTurns.complete) throw new Error('turn collection did not complete after the restart case');
  const restartVerdict = disposition(stillPendingB, restartTurns.turns, baseline2Ids, clientB);
  probe.checks.restart_item_disposition = restartVerdict.disposition;
  probe.checks.restart_new_turns = restartTurns.turns.filter(t => !baseline2Ids.has(t.id)).map(t => ({ id: t.id, status: t.status, marker: hasMarker(t, clientB) ? clientB : null }));
  probe.checks.restart_state_readback = probe.checks.restart_session_resumed === true && restartVerdict.ok && probe.checks.restart_item_pending_before_disconnect === true;
  probe.checks.restart_no_unexpected_turns = restartVerdict.ok && restartVerdict.others.length === 0;
  probe.checks.turn_counts = { baseline: baseline.turns.length, after_fork: afterFork.turns.length, after_archive: archiveTurns.turns.length, baseline_2: baseline2.turns.length, after_restart: restartTurns.turns.length };

  // Native turn truth: every turn this run created is recorded exactly (id,
  // status, correlation marker). Native turn creation is NOT model
  // inference: the no-model-effect check is derived from the confinement
  // (every native process ran under POLICY, and the paired loopback control
  // showed an own listener accepting an unconfined connect while the same
  // connect under POLICY was denied) AND from each created turn showing no
  // model output.
  const createdHere = [...archiveVerdict.consumed, ...restartVerdict.consumed];
  probe.checks.native_turns = createdHere.map(t => ({ id: t.id, status: t.status, marker: hasMarker(t, clientA) ? clientA : clientB, model_free: modelFree(t) }));
  probe.checks.native_turns_recorded = createdHere.every(t => (t.items || []).length > 0 && modelFree(t));
  probe.checks.confined_native_sessions = confinedNatives;
  probe.checks.no_paid_model_effect = confinedNatives > 0 && probe.checks.network_confinement_effective === true && probe.checks.native_turns_recorded === true;

  // The retained case map: qualified here, pending a bounded model-bearing
  // root run, or unsupported on this frontend — nothing erased or waived.
  probe.checks.case_map = {
    codex_clear_equivalent: { state: probe.checks.clear_equivalent_thread_started ? 'qualified' : 'failed', evidence: 'a real confined thread/start produced a distinct thread (new id, idle) whose queue (asked of the same owner process) lists no row and whose turn list is empty, refused with "no rollout found for thread id <id>", or refused with the build\'s explicit before-first-user-message state (-32600 "thread <id> is not materialized yet; thread/turns/list is unavailable before first user message", accepted only for a verified fresh idle constructor with an empty same-owner queue; notLoaded and any other error are not empty); the loaded schema has no clear RPC and thread/revert only truncates durable history; a frontend clear therefore maps to a new empty thread id' },
    codex_fork_is_not_clear: { state: probe.checks.fork_new_thread_id ? 'qualified' : 'failed', evidence: 'fork copies history into a new thread id (forkedFromId lineage) — a branch, not an empty reset' },
    codex_working_gui_clear_button: { state: 'unsupported_in_scope', reason: 'working-GUI feature; working applications are outside the scope of this probe' },
    codex_resume_no_turn: { state: probe.checks.resume_and_fork_create_no_turn ? 'qualified' : 'failed', evidence: 'complete turn-id set unchanged across resume and fork' },
    codex_fork_while_queue_pending: { state: probe.checks.fork_new_thread_id && probe.checks.fork_item_stays_on_original && probe.checks.fork_item_absent_on_fork ? 'qualified' : 'failed', evidence: 'fork returns a new thread id; the pending item stays on the original thread and is absent on the fork (mechanism evidence only, no Bridge component involved)' },
    codex_fork_session_id_not_role: { state: probe.checks.fork_session_id_recorded ? 'qualified' : 'failed', evidence: `fork sessionId ${probe.checks.fork_shares_session_id ? 'equals' : 'differs from'} the original's — recorded, never a role signal; role comes only from the protected agent_id hook join` },
    codex_archive_unarchive: { state: probe.checks.archive_roundtrip && probe.checks.archived_queue_add_refused && probe.checks.archive_pending_disposition_recorded ? 'qualified' : 'failed', evidence: `round-trip on the loaded build; queue add to the archived thread refused; pending-item disposition by exact marker over the complete turn list: ${JSON.stringify(probe.checks.archive_pending_disposition)}` },
    codex_disconnect: { state: probe.checks.disconnect_sessions_ended && probe.checks.restart_state_readback ? 'qualified' : 'failed', evidence: 'a LIVE confined owner process (pid recorded, alive at the queue add and readback) held the own item pending with its exact marker, was explicitly disconnected (exit and liveness recorded), and the item\'s disposition and the complete new-turn set were read back in a NEW process after restart' },
    codex_full_client_restart: { state: probe.checks.restart_state_readback && probe.checks.restart_no_unexpected_turns ? 'qualified' : 'failed', evidence: `fresh process resumed the same thread id; disposition: ${probe.checks.restart_item_disposition}; every new turn correlated to the probe marker` },
    bridge_composition_codex: { state: 'pending_model', reason: 'Codex hooks fire only on turns, which need a model; the Bridge-composition lifecycle seam (protected hook binding, new incarnation epoch after restart, stale-binding fail-closed) is NOT proven by this probe and awaits the root-run model-bearing driver' },
    scope_note: { state: 'unsupported_in_scope', reason: 'this probe launches no Bridge component; results are loaded-frontend MECHANISM evidence for an owned session, not Bridge-composition proof and not working-GUI qualification; bridge digests recorded are disk digests only' },
  };
  probe.checks.case_map_retained = Object.values(probe.checks.case_map).every(entry => entry.state && ['qualified', 'pending_model', 'unsupported_in_scope', 'failed'].includes(entry.state));
});
