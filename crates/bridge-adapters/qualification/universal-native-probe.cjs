/** Root-run public-producer qualification on two owned stock Codex threads.
 * Run only after root builds the independent SDK frontend and freezes every
 * common binary/source/package hash. `BRIDGE_UNIVERSAL_PAID=1 node ... <config>`
 * admits two concurrent registration turns and at most two later natural
 * observation turns, 150000 measured tokens across ALL observed model turns,
 * a 15-minute total deadline and bounded cleanup. Config chooses `sdk`/`raw`
 * and `inject`/`message`; unknown identities/tool/kind/payload are generated
 * only after verifying the supplied freeze. No current Desktop pipe is used.
 * Arrival requires the independently hidden marker in actual native agent
 * text; queue/custody acceptance alone fails this gate. Message observations
 * that the stock build cannot positively expose remain failures, never passes.
 * `--self-test` checks pure gates without processes, files or model effects.
 * `--cleanup-existing <settings.json> <old-checks.json>` is a root-only,
 * model-free queue/archive supplement; it never rewrites the failed run.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { pathToFileURL } = require('node:url');
const { isDeepStrictEqual } = require('node:util');
const { run } = require('./probe-lib.cjs');
const { networkFenceWitness, dbRows } = require('./lifecycle-lib.cjs');
const { MODEL, EFFORT, POLICY, DISABLED, EVENTS, ME_APPROVAL, gateRead, stateOverride, ownApprovalParsed, appServer } = require('./codex-native-probe.cjs');
const { agentText, toolCalls, usageIncrement, hookRuns, hookFailures, ownHooksOnly, mcpInventoryVerdict, supportsFlag, instructionsClosed, keepLive } = require('./codex-lifecycle-probe.cjs');
const { exchange, privateText, registrationParams, receiptsBound } = require('./raw-producer.cjs');

/** Safe JSON data used by owned RPC/configuration fixtures.
 * @typedef {null|boolean|number|string|Json[]|{[key:string]:Json}} Json */
/** Root-provisioned run settings; SHA map contains absolute common production,
 * qualification, SDK artifact/consumer and native executable paths. Root owns
 * all manifests/builds, store/auth selection and actual execution.
 * @typedef {{producer:'sdk'|'raw',mode:'inject'|'message',bin_dir:string,sdk_executable:string,
 * node_executable:string,codex_executable:string,codex_store:string,
 * frozen:{candidate:string,sha256:Record<string,string>}} Settings */
/** Actual stock backend and its bounded, fail-closed RPC client.
 * @typedef {{child:import('node:child_process').ChildProcess,events:{method:string,params:object}[],
 * request:(method:string,params:object,ms?:number)=>Promise<object|null>}} Backend */
/** Required checks are positive facts; missing/substitute observations fail. */
const REQUIRED = ['frozen_before_producer', 'frozen_after_probe', 'network_fence_witnessed', 'model_in_catalog',
  'isolation_verified', 'inventories_ready', 'unsupported_capabilities_honest', 'native_calls_registered', 'actor_scopes_distinct',
  'custody_bound', 'native_arrival', 'no_cross_talk', 'no_unexpected_tools', 'native_hooks_clean',
  'usage_measured', 'restart_recovery_historical', 'route_close_replay', 'accepted_replay_after_close', 'own_queue_removed', 'threads_archived_cleanup'];
/** Project temporary root: the absolute directory named by `TMPDIR`, which must
 * be short enough for Unix sockets and owned by the operator. `TMP` and `TEMP`
 * must name the same directory so no child falls back to a system temporary
 * directory. Empty when `TMPDIR` is unset or relative.
 */
const TEMP_ROOT = path.isAbsolute(process.env.TMPDIR || '') ? path.resolve(process.env.TMPDIR) : '';

/** Whether `TMPDIR`, `TMP` and `TEMP` all name the one configured project root.
 * @returns {boolean} False when any is unset, relative or different.
 */
function tempRootConfigured() {
  return TEMP_ROOT !== '' && [process.env.TMPDIR, process.env.TMP, process.env.TEMP]
    .every(value => path.isAbsolute(value || '') && path.resolve(value) === TEMP_ROOT);
}

/** Copies a native child environment while dropping Desktop-only capabilities.
 * @param {NodeJS.ProcessEnv} environment Inherited root execution environment.
 * @returns {NodeJS.ProcessEnv} New object; original is never mutated or logged.
 */
function stockEnvironment(environment) {
  const child = { ...environment };
  delete child.CODEX_APP_TOOLS_PIPE_PATH; delete child.CODEX_MCP_NODE_PATH;
  return child;
}

/** Validates complete required executable/qualification pins and every supplied
 * common hash. No IDs or fixture payloads are chosen until it returns true.
 * @param {import('./probe-lib.cjs').Probe} probe Root-run bounded lifecycle.
 * @param {Settings} settings Root freeze/paths; no credentials are included.
 * @returns {boolean} All required paths have correct SHA-256 observations.
 */
function frozenMatches(probe, settings) {
  const hashes = settings.frozen && settings.frozen.sha256;
  if (!hashes || !/^[a-f0-9]{40}$/.test(settings.frozen.candidate)) return false;
  const required = ['bridge-native-daemon', 'bridge-hook', 'bridge-fixture'].map(name => path.join(settings.bin_dir, name));
  required.push(settings.codex_executable, settings.node_executable,
    ...(settings.producer === 'sdk' ? [settings.sdk_executable] : []), __filename,
    ...['raw-producer.cjs', 'sdk-producer.rs', 'probe-lib.cjs', 'lifecycle-lib.cjs', 'codex-native-probe.cjs', 'codex-lifecycle-probe.cjs'].map(name => path.join(__dirname, name)));
  if (required.some(file => !hashes[file])) return false;
  return Object.entries(hashes).every(([file, hash]) => path.isAbsolute(file) && /^[a-f0-9]{64}$/.test(hash) && probe.sha256(file) === hash);
}

/** Starts one stock App Server with native Desktop capabilities removed, using
 * root-provisioned store and per-launch isolation flags. Unknown server RPCs
 * refuse; requests stop at lifecycle/deadline fences. Raw host config is never
 * requested on this logged connection.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle/log owner.
 * @param {Settings} settings Explicit native executable/store paths.
 * @param {string} label Owned backend log label.
 * @param {string[]} flags Verified per-launch configuration.
 * @param {() => void} observed Updates already-observed usage/evidence only;
 * cannot start a model or native request, including during failure cleanup.
 * @returns {Backend} Process, native notifications and bounded RPC sender.
 */
function backend(probe, settings, label, flags, observed) {
  const events = [], responses = new Map();
  let nextId = 0;
  const child = probe.spawn(label, settings.codex_executable, ['app-server', '--listen', 'stdio://', ...flags],
    { stdin: true, keep: keepLive, env: { ...stockEnvironment(process.env), CODEX_HOME: settings.codex_store } }, line => {
      let message;
      try { message = JSON.parse(line); } catch { return; }
      if (message.id !== undefined && message.method === undefined) responses.set(message.id, message);
      else if (message.id !== undefined) {
        probe.fail('unexpected_native_server_request');
        child.stdin.write(JSON.stringify({ id: message.id, error: { code: -32601, message: 'unsupported by owned probe' } }) + '\n');
      } else { events.push(message); observed(); }
    });
  child.stdin.on('error', () => {});
  return { child, events, request: async (method, params, ms = 30000) => {
    probe.fence(method);
    const budget = Math.min(ms, probe.remaining() - 60000);
    if (budget <= 0) throw new Error('native request budget exhausted');
    const id = nextId++;
    child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
    await probe.until(() => responses.has(id), budget);
    return responses.get(id) || null;
  } };
}

/** Reads a complete thread-scoped own-tool inventory using existing validators;
 * at most five pages and 60 seconds total, reserving cleanup time. Unusable or
 * partial inventories forbid the first model turn.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle.
 * @param {Backend} owner Backend owning the thread.
 * @param {string} thread Actual native thread ID.
 * @param {string} tool Runtime-generated owned tool name.
 * @returns {Promise<import('./codex-lifecycle-probe.cjs').McpVerdict>} Existing positive inventory verdict or refusal.
 */
async function inventory(probe, owner, thread, tool) {
  const deadline = performance.now() + 60000;
  let verdict = mcpInventoryVerdict(thread, [], [tool]);
  while (performance.now() < deadline && probe.remaining() > 60000) {
    const exchanges = [];
    let cursor = null;
    for (let page = 0; page < 5; page++) {
      const budget = Math.min(deadline - performance.now(), probe.remaining() - 60000);
      if (budget <= 0) break;
      const params = { serverName: 'bridge_probe', threadId: thread, detail: 'toolsAndAuthOnly', ...(cursor ? { cursor } : {}) };
      const response = await owner.request('mcpServerStatus/list', params, budget);
      exchanges.push({ params, response });
      cursor = response && response.result && response.result.nextCursor;
      if (typeof cursor !== 'string' || !cursor) break;
    }
    verdict = mcpInventoryVerdict(thread, exchanges, [tool]);
    if (performance.now() >= deadline || probe.remaining() <= 60000) return { ...verdict, ready: false };
    if (verdict.ready || verdict.terminal) break;
    await new Promise(resolve => setTimeout(resolve, Math.min(1000, deadline - performance.now())));
  }
  return verdict;
}

/** Runs one explicitly bounded short native turn; two callers are allocated
 * by main. Native completion/usage are correlated by actual thread+turn IDs.
 * Timeout interrupts that exact turn and fails; no additional turn is started.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle.
 * @param {Backend} owner Thread owner.
 * @param {string} thread Native thread ID.
 * @param {string|null} tool Unknown configured tool, or null for a natural
 * observation with no tool calls. Payload marker is never included in input.
 * @returns {Promise<{thread:string,turn_id:string,status:string,usage:object|null,text:string}>} Actual completed turn observations.
 */
async function turn(probe, owner, thread, tool) {
  const instruction = tool ? `Call the MCP tool ${tool} on server bridge_probe (qualified name mcp__bridge_probe__${tool}) exactly once with {}. Then` : 'Do not call any tools. Only';
  const reply = await owner.request('turn/start', { threadId: thread,
    input: [{ type: 'text', text: `Owned Bridge qualification. ${instruction} quote every U_CTX_ marker actually visible in your context, or NONE. Do not read files, execute commands, browse, call other tools or delegate. Keep the reply short.`, text_elements: [] }],
    model: MODEL, effort: EFFORT, approvalPolicy: 'never', sandboxPolicy: { type: 'readOnly' } });
  const id = reply && reply.result && reply.result.turn && reply.result.turn.id;
  if (!id) throw new Error('native turn did not start');
  /** Finds native completion of this exact owner thread and turn.
   * @returns {{method:string,params:object}|undefined} Correlated notification.
   */
  const completion = () => owner.events.find(event => event.method === 'turn/completed'
    && event.params && event.params.threadId === thread && event.params.turn && event.params.turn.id === id);
  const ended = await probe.until(() => Boolean(completion()), Math.min(240000, probe.remaining() - 60000));
  if (!ended) {
    await owner.request('turn/interrupt', { threadId: thread, turnId: id }, 15000);
    probe.fail('native_turn_timeout'); throw new Error('native turn incomplete');
  }
  await probe.until(() => usageIncrement(owner.events, thread, id) !== null, 3000);
  return { thread, turn_id: id, status: completion().params.turn.status,
    usage: usageIncrement(owner.events, thread, id), text: agentText(owner.events, thread, id) };
}

/** Accounts for every observed owned native turn, including unsolicited turns,
 * rather than only turn/start replies. Missing completion or usage is unknown
 * and forbids a further model turn; no zero usage is fabricated.
 * @param {Backend[]} owners All backend observation streams.
 * @param {string[]} threads Owned native thread IDs.
 * @returns {{turns:{thread:string,turn_id:string,status:string|null,usage:object|null}[],tokens:number,complete:boolean}} All observed model turn facts and their measured sum.
 */
function usageLedger(owners, threads) {
  const events = owners.flatMap(owner => owner.events), keys = new Map();
  for (const event of events) {
    const params = event.params;
    if (!params || !threads.includes(params.threadId)) continue;
    const id = params.turnId || (params.turn && params.turn.id);
    if (id && ['turn/started', 'turn/completed', 'thread/tokenUsage/updated'].includes(event.method)) keys.set(`${params.threadId}/${id}`, [params.threadId, id]);
  }
  const turns = [...keys.values()].map(([thread, id]) => {
    const done = events.find(event => event.method === 'turn/completed' && event.params && event.params.threadId === thread && event.params.turn && event.params.turn.id === id);
    return { thread, turn_id: id, status: done ? done.params.turn.status : null, usage: usageIncrement(events, thread, id) };
  });
  return { turns, tokens: turns.reduce((sum, item) => sum + (item.usage ? item.usage.increment : 0), 0),
    complete: turns.length > 0 && turns.every(item => item.status === 'completed' && item.usage && item.usage.increment > 0) };
}

/** Classifies actual native invocation/receipt evidence before delivery waits.
 * Inventory alone is never an executed call. A missing receipt after execution
 * is unresolved, not proof that no mutation committed; original IDs stay fixed.
 * @param {{status:string,error:Json}[]} calls Completed native items of this tool.
 * @param {{[key:string]:Json}|null} receipt Parsed safe journal, null when unavailable.
 * @param {import('./raw-producer.cjs').Fixture} config Original actor intent.
 * @returns {string|null} Static failure category, or null for qualified custody.
 */
function registrationProblem(calls, receipt, config) {
  if (calls.length === 0) return 'fail_missing_native_call';
  if (calls.length !== 1 || calls[0].status !== 'completed' || calls[0].error) return 'fail_native_call_not_completed_once';
  if (!receipt) return 'fail_native_receipt_missing_unresolved';
  if (receipt.evidence_state !== 'verified_at_registration' || receipt.assertion_present !== false
      || !receiptsBound(config, receipt.registration, receipt.publication)) return 'fail_native_receipt_binding';
  return null;
}

/** Allows immutable SQLite only for a closed owned Bridge database: all tracked
 * Bridge children positively exited zero and no WAL/SHM exists. Absence of an
 * observed daemon is not exit proof. Live evidence queries never use this URI.
 * @param {string} database Absolute owned database path.
 * @param {{exitCode:number|null,signalCode:string|null}[]} daemons Actual tracked children.
 * @param {boolean} wal Whether the database has a WAL sibling.
 * @param {boolean} shm Whether the database has an SHM sibling.
 * @returns {string} Properly escaped immutable SQLite URI.
 * @throws {Error} Live/unverified processes, journal siblings or relative path.
 */
function immutableCleanupURI(database, daemons, wal, shm) {
  if (!path.isAbsolute(database) || daemons.length === 0 || daemons.some(child => child.exitCode !== 0 || child.signalCode !== null) || wal || shm) {
    throw new Error('immutable cleanup requires positively closed Bridge without WAL/SHM');
  }
  return `file:${pathToFileURL(database).pathname}?immutable=1`;
}

/** Reads only attempt IDs/hashes/actors from the positively closed own database
 * during registered cleanup. Apple SQLite needs immutable mode after shutdown;
 * the guard forbids applying it to live queries or ignoring uncheckpointed WAL.
 * Reuses Probe.spawn's cleanup flag and bounded exit/stdio collection; SQL
 * failure is unproven, never an invented empty attempt set.
 * @param {import('./probe-lib.cjs').Probe} probe Active registered cleanup owner.
 * @param {string} database Exact owned database path.
 * @returns {Promise<import('./lifecycle-lib.cjs').DbRow[]>} Actual readonly rows.
 * @throws {Error} Readonly process/output could not be verified.
 */
async function cleanupAttempts(probe, database) {
  const uri = immutableCleanupURI(database, probe.children.filter(entry => entry.name.startsWith('daemon-')).map(entry => entry.child),
    fs.existsSync(`${database}-wal`), fs.existsSync(`${database}-shm`));
  const lines = [];
  const child = probe.spawn('cleanup-attempts', '/usr/bin/sqlite3', ['-readonly', '-json', uri,
    'SELECT attempt_seq,manifest_hash,actor FROM attempts'], { cleanup: true }, line => lines.push(line));
  const exit = await probe.exited(child, 10000);
  const entry = probe.children.find(entry => entry.child === child);
  let timer;
  const closed = await Promise.race([entry.closed, new Promise(resolve => { timer = setTimeout(() => resolve(false), 2000); })]);
  clearTimeout(timer);
  if (!exit || exit.code !== 0 || closed !== true) throw new Error('cleanup readonly attempts unavailable');
  const rows = lines.length ? JSON.parse(lines.join('\n')) : [];
  if (!Array.isArray(rows)) throw new Error('cleanup readonly attempts malformed');
  return rows;
}

/** Recognizes an already-consumed native queue message on the exact owner:
 * one user item binds actual client ID, thread, turn and hidden input marker;
 * that same completed, measured turn must independently quote the marker.
 * @param {{method:string,params:object}[]} events Actual owner notifications.
 * @param {string} thread Frozen recipient thread.
 * @param {string} clientId Actual attempt-derived native queue client ID.
 * @param {string} marker Hidden fixture marker, never supplied in a prompt.
 * @returns {{turn_id:string,text:string}|null} Positive context observation;
 * null means incomplete/unmatched/duplicate evidence, never no-effect certainty.
 */
function messageContext(events, thread, clientId, marker) {
  const users = events.filter(event => event.method === 'item/completed' && event.params && event.params.threadId === thread
    && event.params.item && event.params.item.type === 'userMessage' && event.params.item.clientId === clientId
    && JSON.stringify(event.params.item.content || []).includes(marker));
  if (users.length !== 1 || !users[0].params.turnId) return null;
  const id = users[0].params.turnId;
  const done = events.find(event => event.method === 'turn/completed' && event.params && event.params.threadId === thread
    && event.params.turn && event.params.turn.id === id && event.params.turn.status === 'completed');
  const text = agentText(events, thread, id), usage = usageIncrement(events, thread, id);
  return done && usage && usage.increment > 0 && text.includes(marker) ? { turn_id: id, text } : null;
}

/** Reads the native queue of an exact owned recipient through the existing
 * network/fork-denied App Server reader. The pre-write projection retains only
 * submission/client IDs and a hidden-marker match boolean, never queue payload.
 * Native queue storage is explicitly separate from model context arrival.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle.
 * @param {Settings} settings Native executable/store.
 * @param {string[]} flags Already verified isolation flags.
 * @param {string} thread Exact owned recipient thread.
 * @param {string|null} marker Private expected marker, never logged as a request;
 * null selects metadata-only cleanup using exact previously observed client IDs.
 * @param {boolean} [cleanup] Whether called inside registered cleanup.
 * @returns {Promise<{id:string,clientUserMessageId:string,marker_present:boolean}[]|null>} Safe native readback or null when unproven.
 */
async function queueReadback(probe, settings, flags, thread, marker, cleanup = false) {
  /** Projects native response before any file/retained stream sees payload.
   * @param {string} line One raw native line.
   * @returns {string|null} Safe IDs/booleans or handshake status only.
   */
  const keep = line => {
    let value;
    try { value = JSON.parse(line); } catch { return null; }
    if (value.id === 1 && value.result && Array.isArray(value.result.data)) return JSON.stringify({ id: 1, result: { data: value.result.data.map(item => ({
      id: item.id, clientUserMessageId: item.clientUserMessageId, marker_present: marker !== null && JSON.stringify(item.input || []).includes(marker),
    })) } });
    return JSON.stringify({ id: value.id, result: value.result ? {} : null, error: value.error ? { code: value.error.code } : null });
  };
  const [reply] = await appServer(probe, settings.codex_executable, settings.codex_store,
    `queue-${cleanup ? 'cleanup' : 'observe'}-${thread}-${probe.children.length}`, flags, [['thread/queue/list', { threadId: thread }]], cleanup, keep);
  return reply && reply.result && Array.isArray(reply.result.data) ? reply.result.data : null;
}

/** Supplements cleanup of an already-completed owned run without replaying any
 * producer operation or model turn. Root supplies its original settings and
 * exact proof JSON. Only the old proof's actor/client pairs may be deleted or
 * archived. Every helper is network/fork denied; configuration readback disables
 * all MCP servers/hooks and clears per-launch instructions before cleanup RPCs.
 * Original failures/proof are never rewritten; a fresh Probe writes its own
 * cleanup supplement, scope and exits. No credentials are read/copied or sent.
 * @param {Settings} settings Original root-native executable/store selection.
 * @param {{dir:string,checks:object}} previous Explicit old owned proof.
 * @returns {Promise<import('./probe-lib.cjs').Probe>} Supplement lifecycle result.
 * @throws {Error} The temporary root is unconfigured, or proof scope/identity or original Bridge exit facts are invalid.
 */
function cleanupExisting(settings, previous) {
  if (!tempRootConfigured()) throw new Error('one absolute project temporary root required');
  const facts = previous.checks, pairs = facts && facts.message_native_readback;
  if (!previous.dir || !previous.dir.startsWith(`${TEMP_ROOT}/`) || path.resolve(previous.dir) !== previous.dir
      || !facts || !facts.freeze || facts.freeze.candidate !== settings.frozen.candidate
      || !Array.isArray(pairs) || pairs.length !== 2 || new Set(pairs.map(item => item.thread)).size !== 2
      || pairs.some(item => !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.thread)
        || !/^agent-bridge-[1-9][0-9]*-[a-f0-9]{16}$/.test(item.client_id)
        || !(facts.receipts || []).some(receipt => receipt && receipt.publication.destination.address.endsWith(`/${item.thread}`)))) {
    throw new Error('existing cleanup proof scope refused');
  }
  for (const name of ['daemon-before', 'daemon-after']) {
    if (!facts.exits || !facts.exits[name] || facts.exits[name].code !== 0 || facts.exits[name].signal !== null) throw new Error('existing Bridge shutdown unverified');
  }
  return run('m2uc', 5 * 60000, ['cleanup_only_isolated', 'own_queue_removed', 'threads_archived_cleanup', 'original_proof_unchanged'], async probe => {
    if (probe.sha256(settings.codex_executable) !== settings.frozen.sha256[settings.codex_executable]) throw new Error('existing native build changed');
    const proofPath = path.join(previous.dir, 'checks.json'), proofHash = probe.sha256(proofPath);
    probe.checks.original_scope = { dir: previous.dir, proof_path: proofPath, proof_sha256: proofHash, candidate: facts.freeze.candidate, pairs };
    const base = [...DISABLED, '--enable', 'hooks', '-c', 'notify=[]', '-c', 'project_doc_max_bytes=0',
      '-c', 'instructions=""', '-c', 'developer_instructions=""'];
    const first = await gateRead(probe, settings.codex_executable, settings.codex_store, 'cleanup-isolation-first', base, '');
    const servers = first.configFacts && first.configFacts.servers;
    if (!first.hooks || first.overrideRejected || !servers || !Object.keys(servers).every(name => /^[A-Za-z0-9_-]+$/.test(name))
        || first.hooks.some(hook => hook.own)) throw new Error('cleanup configuration unavailable');
    const flags = [...base, ...stateOverride(first.hooks), ...Object.keys(servers).flatMap(name => ['-c', `mcp_servers.${name}.enabled=false`])];
    const second = await gateRead(probe, settings.codex_executable, settings.codex_store, 'cleanup-isolation-confirm', flags, '');
    probe.checks.cleanup_only_isolated = Boolean(!second.overrideRejected && second.hooks && second.hooks.every(hook => hook.enabled === false)
      && second.configFacts && instructionsClosed(second.configFacts) && Object.keys(servers).every(name => second.configFacts.servers[name] === false));
    if (!probe.checks.cleanup_only_isolated) throw new Error('cleanup isolation refused');
    let queueRemoved = true, archived = true;
    for (const item of pairs) {
      const before = await queueReadback(probe, settings, flags, item.thread, null);
      if (!before) queueRemoved = false;
      for (const entry of (before || []).filter(entry => entry.clientUserMessageId === item.client_id)) {
        const [deleted] = await appServer(probe, settings.codex_executable, settings.codex_store,
          `cleanup-delete-${item.thread}-${entry.id}`, flags, [['thread/queue/delete', { threadId: item.thread, queuedSubmissionId: entry.id }]]);
        queueRemoved = queueRemoved && Boolean(deleted && deleted.result);
      }
      const after = await queueReadback(probe, settings, flags, item.thread, null);
      queueRemoved = queueRemoved && Boolean(after && after.every(entry => entry.clientUserMessageId !== item.client_id));
      const [reply] = await appServer(probe, settings.codex_executable, settings.codex_store,
        `cleanup-archive-${item.thread}`, flags, [['thread/archive', { threadId: item.thread }]]);
      archived = archived && Boolean(reply && reply.result);
    }
    probe.checks.own_queue_removed = queueRemoved;
    probe.checks.threads_archived_cleanup = archived;
    probe.checks.model_requests = 0;
    probe.checks.original_proof_unchanged = probe.sha256(proofPath) === proofHash;
  });
}

/** Observes a message after registration turns: accepts an already-consumed
 * exact native user/client/turn/context join, or requires pending queue/client/
 * hidden-input readback before resuming the same owned thread and observing
 * an unsolicited reply or one short natural context-only turn. Before
 * any additional paid request, ALL prior observed turns must have completed,
 * measured usage below the shared ceiling; missing usage fails closed.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle.
 * @param {Settings} settings Explicit owned native settings.
 * @param {Backend[]} owners All owned notification streams.
 * @param {string[]} threads Exact owned recipients.
 * @param {{marker:string,value:import('./raw-producer.cjs').Fixture}[]} cases Private fixture cases.
 * @param {string[]} flags Verified isolated reader flags.
 * @param {string} core Owned public endpoint.
 * @param {string} credential Synthetic token, never logged.
 * @param {string} database Owned database for bounded attempt correlation.
 * @returns {Promise<string[]>} Actual native agent texts, never queue text.
 */
async function messageObservation(probe, settings, owners, threads, cases, flags, core, credential, database) {
  const texts = [];
  probe.checks.message_native_readback = [];
  for (const [index, item] of cases.entries()) {
    const deadline = Date.now() + 60000;
    let status;
    while (Date.now() < deadline && probe.remaining() > 120000) {
      status = await exchange(core, credential, `message-status-${index}`, 'status', { selector: { type: 'event', event_id: item.value.event_id } });
      if (status.event && status.event.delivery.delivery === 'accepted') break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    const seq = status && status.event && status.event.delivery.attempt;
    if (!Number.isSafeInteger(seq) || seq <= 0) throw new Error('message attempt not observed');
    const attempt = dbRows(probe, database, `SELECT manifest_hash, actor FROM attempts WHERE attempt_seq=${seq}`)[0];
    if (!attempt || !/^[a-f0-9]{64}$/.test(attempt.manifest_hash) || attempt.actor !== threads[index]) throw new Error('message recipient attempt mismatch');
    const client = `agent-bridge-${seq}-${attempt.manifest_hash.slice(0, 16)}`;
    await probe.until(() => messageContext(owners[index].events, threads[index], client, item.marker) !== null, 5000);
    const consumed = messageContext(owners[index].events, threads[index], client, item.marker);
    if (consumed) {
      probe.checks.message_native_readback.push({ thread: threads[index], client_id: client, turn_id: consumed.turn_id, consumed_context: true });
      texts.push(consumed.text); continue;
    }
    const queue = await queueReadback(probe, settings, flags, threads[index], item.marker);
    const matching = queue && queue.filter(entry => entry.clientUserMessageId === client && entry.marker_present);
    probe.checks.message_native_readback.push({ thread: threads[index], client_id: client, matched: Boolean(matching && matching.length === 1) });
    const raced = messageContext(owners[index].events, threads[index], client, item.marker);
    if (raced) {
      Object.assign(probe.checks.message_native_readback.at(-1), { turn_id: raced.turn_id, consumed_context: true });
      texts.push(raced.text); continue;
    }
    if (!matching || matching.length !== 1) throw new Error('message pending/consumed evidence unavailable; custody is not context');
    const prior = usageLedger(owners, threads);
    probe.checks.model_usage = prior;
    if (!prior.complete || prior.tokens >= 150000 || prior.turns.length >= 4) throw new Error('prior model usage unavailable or exhausted');
    const resumed = await owners[index].request('thread/resume', { threadId: threads[index], excludeTurns: true });
    if (!resumed || !resumed.result || !resumed.result.thread || resumed.result.thread.id !== threads[index]) throw new Error('message recipient resume unavailable');
    await probe.until(() => owners[index].events.some(event => event.method === 'item/completed' && event.params && event.params.threadId === threads[index]
      && event.params.item && event.params.item.type === 'agentMessage' && String(event.params.item.text || '').includes(item.marker)), 3000);
    const observed = owners[index].events.filter(event => event.method === 'item/completed' && event.params && event.params.threadId === threads[index]
      && event.params.item && event.params.item.type === 'agentMessage').map(event => String(event.params.item.text || '')).join('\n');
    if (observed.includes(item.marker)) { texts.push(observed); continue; }
    const beforeNatural = usageLedger(owners, threads);
    if (!beforeNatural.complete || beforeNatural.tokens >= 150000 || beforeNatural.turns.length >= 4) throw new Error('unsolicited model turn unmeasured; no extra paid request');
    const natural = await turn(probe, owners[index], threads[index], null);
    texts.push(natural.text);
    const measured = usageLedger(owners, threads);
    if (!measured.complete || measured.tokens > 150000 || measured.turns.length > 4) throw new Error('all-turn model budget failed');
  }
  return texts;
}

/** Root-only full probe: verifies freezes before creating unknown fixtures,
 * reuses safe native isolation/configuration gates, registers two actual callers
 * through SDK/raw frontends, observes hidden arrival and distinct scopes, then
 * restarts Bridge and reconciles original receipts without fresh authority.
 * Payload and credential files are removed by shared cleanup; owned threads
 * are archived and every process reaped on all paths. No consumer is edited.
 * @param {import('./probe-lib.cjs').Probe} probe Root lifecycle/state owner.
 * @param {Settings} settings Private root configuration.
 * @returns {Promise<void>} Required checks/facts populate the lifecycle report.
 */
async function main(probe, settings) {
  if (!['sdk', 'raw'].includes(settings.producer) || !['inject', 'message'].includes(settings.mode)) throw new Error('probe mode refused');
  probe.checks.frozen_before_producer = frozenMatches(probe, settings);
  if (!probe.checks.frozen_before_producer) throw new Error('common freeze mismatch');
  probe.checks.freeze = settings.frozen;
  probe.checks.producer_transport = settings.producer;
  probe.checks.node_runtime = { path: settings.node_executable, sha256: probe.sha256(settings.node_executable) };
  const catalog = probe.local('/usr/bin/sandbox-exec', ['-p', POLICY, settings.codex_executable, 'debug', 'models']);
  const entry = JSON.parse(catalog.split('\n')[0]).models.find(model => model.slug === MODEL);
  probe.checks.model_in_catalog = Boolean(entry && entry.supported_reasoning_levels.some(level => level.effort === EFFORT));
  if (!probe.checks.model_in_catalog) throw new Error('model catalog refused');
  probe.checks.network_fence_witnessed = (await networkFenceWitness(probe, POLICY)).ok;
  const nonce = crypto.randomBytes(12).toString('hex'), tool = `u_${nonce}`, producer = `u-${nonce}`, kind = `u.${nonce}`;
  const token = probe.credential('producer.token');
  const host = 'u-host', namespace = 'u-codex', channelDir = path.join(probe.dir, 'ch');
  fs.mkdirSync(channelDir, { mode: 0o700 });
  const channel = path.join(channelDir, 'c.sock'), core = path.join(probe.dir, 'core.sock'), database = path.join(probe.dir, 'bridge.db');
  const cases = [0, 1].map(index => {
    const marker = `U_CTX_${crypto.randomBytes(16).toString('hex')}`, config = path.join(probe.creds, `producer-${index}.json`);
    const value = { registration_socket: channel, core_socket: core, credential_file: token.file,
      payload_file: path.join(probe.creds, `payload-${index}`), receipt_file: path.join(probe.dir, `receipts-${index}.jsonl`),
      host: 'codex', tool_name: tool, request_id: `req-${nonce}-${index}`, operation_key: `op-${nonce}-${index}`,
      event_id: `event-${nonce}-${index}`, kind, mode: settings.mode };
    fs.writeFileSync(value.payload_file, JSON.stringify({ arbitrary_domain: crypto.randomBytes(8).toString('hex'), marker }), { mode: 0o600 });
    fs.writeFileSync(config, JSON.stringify(value), { mode: 0o600 });
    return { marker, config, value };
  });
  const frontend = settings.producer === 'sdk' ? settings.sdk_executable : settings.node_executable;
  /** Selects root-built SDK or independent raw frontend arguments.
   * @param {string} config Owned private runtime configuration path.
   * @returns {string[]} Explicit arguments; no secrets or payloads.
   */
  const args = config => settings.producer === 'sdk' ? [config] : [path.join(__dirname, 'raw-producer.cjs'), config];
  const hookCommand = `'${path.join(settings.bin_dir, 'bridge-hook')}' '${channel}' codex`;
  const hook = `[{matcher="",hooks=[{type="command",command="${hookCommand}",timeout=5}]}]`;
  const own = ['-c', `mcp_servers.bridge_probe.command=${JSON.stringify(frontend)}`,
    '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(args(cases[0].config))}`,
    '-c', `mcp_servers.bridge_probe.enabled_tools=${JSON.stringify([tool])}`,
    '-c', `mcp_servers.bridge_probe.tools.${tool}.approval_mode=${JSON.stringify(ME_APPROVAL)}`,
    ...EVENTS.flatMap(event => ['-c', `hooks.${event}=${hook}`])];
  const help = probe.local(settings.codex_executable, ['app-server', '--help']);
  const hygiene = [...['--ignore-user-config', '--ignore-rules'].filter(flag => supportsFlag(help, flag)),
    '-c', 'notify=[]', '-c', 'project_doc_max_bytes=0', '-c', 'instructions=""', '-c', 'developer_instructions=""'];
  const base = [...DISABLED, '--enable', 'hooks', ...hygiene, ...own];
  const first = await gateRead(probe, settings.codex_executable, settings.codex_store, 'isolation-first', base, hookCommand);
  const servers = first.configFacts && first.configFacts.servers;
  const foreign = Object.keys(servers || {}).filter(name => name !== 'bridge_probe');
  if (!servers || !foreign.every(name => /^[A-Za-z0-9_-]+$/.test(name))) throw new Error('MCP isolation unavailable');
  const flags = [...base, ...stateOverride(first.hooks || []), ...foreign.flatMap(name => ['-c', `mcp_servers.${name}.enabled=false`]), '-c', 'analytics.enabled=false'];
  const second = await gateRead(probe, settings.codex_executable, settings.codex_store, 'isolation-confirm', flags, hookCommand);
  const hooks = second.hooks || [], ownedHooks = hooks.filter(hook => hook.own);
  probe.checks.isolation_verified = Boolean(!first.overrideRejected && !second.overrideRejected && second.configFacts
    && instructionsClosed(second.configFacts) && foreign.every(name => second.configFacts.servers[name] === false)
    && ownApprovalParsed(second.effective, [tool]) && ownedHooks.length === EVENTS.length
    && ownedHooks.every(hook => hook.enabled && hook.trustStatus === 'trusted') && hooks.filter(hook => !hook.own).every(hook => !hook.enabled));
  if (!probe.checks.isolation_verified || !probe.checks.network_fence_witnessed) throw new Error('native isolation refused');
  const owners = [], threads = [];
  /** Snapshots all already-observed native model effects and context arrival.
   * Called on every notification and cleanup; never submits a native/model call.
   * @returns {void}
   */
  const observed = () => {
    const measured = usageLedger(owners, threads);
    probe.checks.model_usage = measured;
    probe.checks.usage_measured = measured.complete && measured.tokens <= 150000 && measured.turns.length <= (settings.mode === 'message' ? 4 : 2);
    probe.checks.native_arrival_by_actor = cases.map((item, index) => Boolean(owners[index] && owners[index].events.some(event =>
      event.method === 'item/completed' && event.params && event.params.threadId === threads[index]
      && event.params.item && event.params.item.type === 'agentMessage' && String(event.params.item.text || '').includes(item.marker))));
    if (measured.tokens > 150000 || measured.turns.length > (settings.mode === 'message' ? 4 : 2)) probe.fail('observed_all_turn_budget_exhausted');
  };
  let nativeStarted = false;
  probe.onCleanup('owned-native-threads', async () => {
    for (const entry of probe.children.filter(entry => entry.name.startsWith('daemon-'))) {
      try { process.kill(-entry.child.pid, 'SIGTERM'); } catch {}
      await probe.exited(entry.child, 10000);
    }
    for (const owner of owners) { try { process.kill(-owner.child.pid, 'SIGTERM'); } catch {} await probe.exited(owner.child, 10000); }
    observed();
    probe.checks.frozen_after_probe = frozenMatches(probe, settings);
    let queueRemoved = true;
    if (settings.mode === 'message' && nativeStarted) {
      const attempts = await cleanupAttempts(probe, database);
      const clients = attempts.filter(item => Number.isSafeInteger(item.attempt_seq) && /^[a-f0-9]{64}$/.test(item.manifest_hash)
        && threads.includes(item.actor)).map(item => `agent-bridge-${item.attempt_seq}-${item.manifest_hash.slice(0, 16)}`);
      for (const [index, thread] of threads.entries()) {
        const before = await queueReadback(probe, settings, flags, thread, cases[index].marker, true);
        if (!before) { queueRemoved = false; continue; }
        for (const item of before.filter(item => clients.includes(item.clientUserMessageId))) {
          const [deleted] = await appServer(probe, settings.codex_executable, settings.codex_store,
            `delete-own-${thread}-${item.id}`, flags, [['thread/queue/delete', { threadId: thread, queuedSubmissionId: item.id }]], true);
          queueRemoved = queueRemoved && Boolean(deleted && deleted.result);
        }
        const after = await queueReadback(probe, settings, flags, thread, cases[index].marker, true);
        queueRemoved = queueRemoved && Boolean(after && after.every(item => !clients.includes(item.clientUserMessageId) && !item.marker_present));
      }
    }
    probe.checks.own_queue_removed = queueRemoved;
    let archived = true;
    for (const thread of threads) {
      const [reply] = await appServer(probe, settings.codex_executable, settings.codex_store, `archive-${thread}`, flags, [['thread/archive', { threadId: thread }]], true);
      archived = archived && Boolean(reply && reply.result);
    }
    probe.checks.threads_archived_cleanup = archived;
  });
  for (const [index, item] of cases.entries()) {
    const owner = backend(probe, settings, `backend-${index}`, [...flags, '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(args(item.config))}`], observed);
    owners.push(owner);
    const init = await owner.request('initialize', { clientInfo: { name: 'bridge_universal_qualification', version: '1' }, capabilities: { experimentalApi: true } });
    if (!init || !init.result) throw new Error('native initialization refused');
    owner.child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
    const started = await owner.request('thread/start', { cwd: probe.dir, model: MODEL, approvalPolicy: 'never', sandbox: 'read-only' });
    const thread = started && started.result && started.result.thread;
    if (!thread || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(thread.id) || thread.forkedFromId || !thread.status || thread.status.type !== 'idle') throw new Error('owned thread constructor refused');
    threads.push(thread.id); probe.markers.push(thread.id);
  }
  const daemonConfig = path.join(probe.creds, 'bridge.toml');
  fs.writeFileSync(daemonConfig, [`database=${JSON.stringify(database)}`, `socket=${JSON.stringify(core)}`, '[limits]', 'max_admitted_events=100',
    '[[grant]]', `token=${JSON.stringify(token.token)}`, `publisher=${JSON.stringify(producer)}`,
    `recipients=${JSON.stringify(threads.map(thread => `${host}/codex/${namespace}/${thread}`))}`, `kinds=${JSON.stringify([kind])}`,
    'modes=["inject","message"]', 'policies=["keep_all"]', '[grant.producer_v1]', 'registration=true', 'reply_policies=["self"]',
    `native_scopes=${JSON.stringify([`${host}/codex/${namespace}`])}`, '[adapters]', `channel=${JSON.stringify(channel)}`, `host_id=${JSON.stringify(host)}`,
    '[[adapters.harnesses]]', `namespace=${JSON.stringify(namespace)}`, 'harness="Codex"',
    'inject=true', 'message=true', ''].join('\n'), { mode: 0o600 });
  /** Starts one root-owned Bridge incarnation with the same private config.
   * @param {string} label New process/log identity.
   * @returns {import('node:child_process').ChildProcess} Owned daemon process.
   */
  const startDaemon = label => probe.spawn(label, path.join(settings.bin_dir, 'bridge-native-daemon'), [daemonConfig]);
  let daemon = startDaemon('daemon-before');
  if (!await probe.until(() => fs.existsSync(channel) && fs.existsSync(core), 15000)) throw new Error('daemon unavailable');
  const capabilities = await exchange(channel, token.token, `capabilities-${nonce}`, 'capabilities', {});
  probe.checks.capabilities = capabilities;
  probe.checks.unsupported_capabilities_honest = capabilities.features && capabilities.features.host_observations === false
    && Array.isArray(capabilities.native_contracts) && capabilities.native_contracts.length === 0;
  if (!probe.checks.unsupported_capabilities_honest) throw new Error('unsupported native capability projection mismatch');
  const inventories = await Promise.all(owners.map((owner, index) => inventory(probe, owner, threads[index], tool)));
  probe.checks.inventories = inventories; probe.checks.inventories_ready = inventories.every(item => item.ready === true);
  if (!probe.checks.inventories_ready) throw new Error('own native tools unavailable; no model turn started');
  nativeStarted = true;
  const turns = await Promise.all(owners.map((owner, index) => turn(probe, owner, threads[index], tool)));
  probe.checks.turns = turns.map(({ text, ...facts }) => facts);
  observed();
  const receipts = cases.map(item => {
    try {
      const lines = privateText(item.value.receipt_file, 1024 * 1024).trim().split('\n').map(line => JSON.parse(line));
      return lines.length === 1 ? lines[0] : null;
    } catch { return null; }
  });
  probe.checks.receipts = receipts;
  const problems = cases.map((item, index) => registrationProblem(toolCalls(owners[index].events, threads[index], tool), receipts[index], item.value));
  probe.checks.registration_phase = problems.map((failure, index) => ({ actor: threads[index], failure }));
  probe.checks.native_calls_registered = problems.every(failure => failure === null);
  for (const [index, problem] of problems.entries()) if (problem) probe.fail(`${problem}:actor-${index}`);
  if (!probe.checks.native_calls_registered) throw new Error('native registration phase failed before delivery observation');
  probe.checks.actor_scopes_distinct = receipts[0].registration.caller_scope !== receipts[1].registration.caller_scope
    && receipts[0].registration.destination_scope !== receipts[1].registration.destination_scope;
  probe.checks.custody_bound = receipts.every((item, index) => receiptsBound(cases[index].value, item.registration, item.publication)
    && item.publication.destination.address === `${host}/codex/${namespace}/${threads[index]}`);
  if (!probe.checks.actor_scopes_distinct || !probe.checks.custody_bound) throw new Error('native receipt scope phase failed before delivery observation');
  const arrivalTexts = settings.mode === 'message'
    ? await messageObservation(probe, settings, owners, threads, cases, flags, core, token.token, database)
    : turns.map(item => item.text);
  const measured = usageLedger(owners, threads);
  probe.checks.model_usage = measured;
  probe.checks.usage_measured = measured.complete && measured.tokens <= 150000 && measured.turns.length <= (settings.mode === 'message' ? 4 : 2);
  probe.checks.native_hooks_clean = owners.every((owner, index) => hookFailures(owner.events, threads[index]).length === 0 && ownHooksOnly(hookRuns(owner.events, threads[index])));
  probe.checks.no_unexpected_tools = owners.every(owner => !owner.events.some(event => event.method === 'item/completed'
    && event.params && event.params.item && (['commandExecution', 'fileChange', 'webSearch', 'collabAgentSpawn', 'imageView'].includes(event.params.item.type)
      || (event.params.item.type === 'mcpToolCall' && event.params.item.tool !== tool))));
  probe.checks.native_arrival = arrivalTexts.every((text, index) => text.includes(cases[index].marker));
  probe.checks.no_cross_talk = arrivalTexts.every((text, index) => !text.includes(cases[1 - index].marker));
  const beforeRestart = await Promise.all(cases.map((item, index) => exchange(core, token.token, `before-restart-${index}`, 'status',
    { selector: { type: 'event', event_id: item.value.event_id } })));
  process.kill(-daemon.pid, 'SIGTERM');
  const stopped = await probe.exited(daemon, 15000);
  if (!stopped || stopped.code !== 0) throw new Error('Bridge restart stop not verified');
  daemon = startDaemon('daemon-after');
  if (!await probe.until(() => fs.existsSync(channel) && fs.existsSync(core), 15000)) throw new Error('restarted Bridge unavailable');
  const recovered = await Promise.all(cases.map(async (item, index) => {
    const reg = await exchange(channel, token.token, item.value.request_id, 'register_call', registrationParams(item.value, null));
    const status = await exchange(core, token.token, `reconcile-${index}`, 'status', { selector: { type: 'event', event_id: item.value.event_id } });
    return { reg, status };
  }));
  probe.checks.restart_recovery_historical = recovered.every((item, index) => item.reg.evidence_state === 'historical'
    && !item.reg.assertion && isDeepStrictEqual(item.reg.receipt, receipts[index].registration)
    && item.status.event && isDeepStrictEqual(item.status.event.receipt, receipts[index].publication)
    && beforeRestart[index].event && item.status.event.delivery.attempts_made === beforeRestart[index].event.delivery.attempts_made);
  /** Closes the original route through the actual independent SDK for SDK
   * qualification, or through public NDJSON for raw qualification.
   * @param {number} index Fixture actor index.
   * @returns {Promise<object>} Actual correlated close result.
   */
  const close = async index => settings.producer === 'sdk'
    ? JSON.parse(probe.local(settings.sdk_executable, [cases[index].config, '--close'])).close
    : exchange(core, token.token, `close-${index}`, 'close_route', { route_key: receipts[index].registration.route_key, reason: null });
  const closed = await Promise.all(cases.map((_, index) => close(index)));
  const reclosed = await Promise.all(cases.map((_, index) => close(index)));
  probe.checks.route_close_replay = closed.every((item, index) => item.receipt.state === 'closed'
    && reclosed[index].replayed === true && isDeepStrictEqual(item.receipt, reclosed[index].receipt));
  const replayed = cases.map((item, index) => JSON.parse(settings.producer === 'sdk'
    ? probe.local(settings.sdk_executable, [item.config, '--recover'])
    : probe.local(settings.node_executable, [path.join(__dirname, 'raw-producer.cjs'), item.config, '--recover'])));
  probe.checks.accepted_replay_after_close = replayed.every((item, index) => item.replayed === true
    && item.evidence_state === 'historical' && !item.assertion_present && isDeepStrictEqual(item.publication, receipts[index].publication)
    && item.status.event && item.status.event.delivery.attempts_made === beforeRestart[index].event.delivery.attempts_made);
  probe.checks.frozen_after_probe = frozenMatches(probe, settings);
}

/** Pure dynamic-tool isolation/inventory controls and Desktop-env confinement.
 * @returns {void} Assertion failure throws; PASS is printed only after success.
 */
function selfTest() {
  const assert = require('node:assert/strict'), tool = 'unseen_tool';
  const environment = { CODEX_APP_TOOLS_PIPE_PATH: 'private', CODEX_MCP_NODE_PATH: 'signed', CODEX_HOME: 'store' };
  assert.deepEqual(stockEnvironment(environment), { CODEX_HOME: 'store' });
  assert.equal(environment.CODEX_APP_TOOLS_PIPE_PATH, 'private');
  assert.equal(ownApprovalParsed({ enabled_tools: [tool], tools: { [tool]: { approval_mode: ME_APPROVAL } } }, [tool]), true);
  assert.equal(ownApprovalParsed({ enabled_tools: [tool, 'foreign'], tools: { [tool]: { approval_mode: ME_APPROVAL } } }, [tool]), false);
  const exchange = [{ params: { serverName: 'bridge_probe', threadId: 'thread', detail: 'toolsAndAuthOnly' },
    response: { result: { data: [{ name: 'bridge_probe', runtimeStatus: 'connected', tools: { [tool]: { name: tool } } }] } } }];
  assert.equal(mcpInventoryVerdict('thread', exchange, [tool]).ready, true);
  assert.equal(mcpInventoryVerdict('foreign', exchange, [tool]).ready, false);
  assert.equal(mcpInventoryVerdict('thread', exchange, ['different']).ready, false);
  const events = [{ method: 'turn/completed', params: { threadId: 'thread', turn: { id: 'one', status: 'completed' } } },
    { method: 'thread/tokenUsage/updated', params: { threadId: 'thread', turnId: 'one', tokenUsage: { total: { totalTokens: 20 }, last: { totalTokens: 20 } } } }];
  assert.equal(usageLedger([{ events }], ['thread']).tokens, 20);
  assert.equal(usageLedger([{ events: [...events, { method: 'turn/started', params: { threadId: 'thread', turn: { id: 'unsolicited' } } }] }], ['thread']).complete, false);
  const unsolicited = [{ method: 'turn/completed', params: { threadId: 'thread', turn: { id: 'two', status: 'completed' } } },
    { method: 'thread/tokenUsage/updated', params: { threadId: 'thread', turnId: 'two', tokenUsage: { total: { totalTokens: 35 }, last: { totalTokens: 15 } } } }];
  assert.equal(usageLedger([{ events: [...events, ...unsolicited] }], ['thread']).tokens, 35);
  assert.equal(usageLedger([{ events: [...events, ...unsolicited] }], ['thread']).turns.length, 2);
  const config = { request_id: 'req', operation_key: 'op', event_id: 'event' };
  const registration = { producer: 'opaque', request_id: 'req', operation_key: 'op', route_key: 'route', caller_scope: 'actor', destination_scope: 'target' };
  const publication = { producer: 'opaque', event_id: 'event', intent_hash: 'a'.repeat(64), envelope_hash: 'b'.repeat(64),
    destination: { route_key: 'route', caller_scope: 'actor', destination_scope: 'target' } };
  const receipt = { registration, publication, evidence_state: 'verified_at_registration', assertion_present: false };
  assert.equal(registrationProblem([], receipt, config), 'fail_missing_native_call');
  assert.equal(registrationProblem([{ status: 'completed', error: null }], null, config), 'fail_native_receipt_missing_unresolved');
  assert.equal(registrationProblem([{ status: 'completed', error: null }], receipt, config), null);
  const consumed = [...events, { method: 'item/completed', params: { threadId: 'thread', turnId: 'one',
    item: { type: 'userMessage', clientId: 'client', content: [{ type: 'text', text: 'hidden' }] } } },
    { method: 'item/completed', params: { threadId: 'thread', turnId: 'one', item: { type: 'agentMessage', text: 'hidden' } } }];
  assert.equal(messageContext(consumed, 'thread', 'client', 'hidden').turn_id, 'one');
  assert.equal(messageContext(consumed, 'foreign', 'client', 'hidden'), null);
  assert.equal(messageContext(consumed, 'thread', 'other-client', 'hidden'), null);
  assert.equal(messageContext(consumed.slice(0, -1), 'thread', 'client', 'hidden'), null);
  const closed = [{ exitCode: 0, signalCode: null }, { exitCode: 0, signalCode: null }];
  assert.equal(immutableCleanupURI('/owned/db with space', closed, false, false), 'file:/owned/db%20with%20space?immutable=1');
  assert.throws(() => immutableCleanupURI('/owned/db', [], false, false));
  assert.throws(() => immutableCleanupURI('/owned/db', [{ exitCode: null, signalCode: null }], false, false));
  assert.throws(() => immutableCleanupURI('/owned/db', [{ exitCode: 1, signalCode: null }], false, false));
  assert.throws(() => immutableCleanupURI('/owned/db', [{ exitCode: 0, signalCode: 'SIGTERM' }], false, false));
  assert.throws(() => immutableCleanupURI('/owned/db', closed, true, false));
  assert.throws(() => immutableCleanupURI('/owned/db', closed, false, true));
  console.log(JSON.stringify({ self_test: 'PASS' }));
}

if (require.main === module) {
  if (process.argv[2] === '--self-test') selfTest();
  else if (process.argv[2] === '--cleanup-existing') {
    if (!tempRootConfigured()) {
      console.error('one absolute project temporary root required: set TMPDIR, TMP and TEMP to it'); process.exitCode = 2;
    } else {
      const settings = JSON.parse(privateText(process.argv[3], 1024 * 1024));
      const previous = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
      cleanupExisting(settings, previous).catch(() => { console.error('existing cleanup supplement failed'); process.exitCode = 1; });
    }
  }
  else if (process.env.BRIDGE_UNIVERSAL_PAID !== '1') { console.error('root model authorization required'); process.exitCode = 2; }
  else if (!tempRootConfigured()) {
    console.error('one absolute project temporary root required: set TMPDIR, TMP and TEMP to it'); process.exitCode = 2;
  } else {
    const settings = JSON.parse(privateText(process.argv[2], 1024 * 1024));
    run('m2u', 15 * 60000, REQUIRED, probe => main(probe, settings));
  }
}

/** Root-only cleanup entry and pure immutable guard; importing has no effects.
 * @type {{cleanupExisting:typeof cleanupExisting,immutableCleanupURI:typeof immutableCleanupURI}}
 */
module.exports = { cleanupExisting, immutableCleanupURI };
