/**
 * Root-run native qualification probe: real Codex + Bridge hooks and the
 * probe MCP server, then the product queue helper on the persisted probe
 * thread.
 *
 * Questions answered for the exact loaded build: does the real MCP
 * `_meta.callId` equal the same call's `PreToolUse` `tool_use_id` (the
 * registry join succeeds only if it does), does root `PostToolUse` context
 * reach the model, is a native child attested on its own thread address,
 * and does the confined queue-only helper get a correlated native
 * acceptance (with native readback) on an unloaded persisted thread.
 *
 * Bounded model use, justified only because these native hook/MCP fields
 * cannot be configured through the broker: model `gpt-6-luna` at low
 * effort (checked offline against the build's own catalog), two
 * single-turn `codex exec` runs, 20 minute total budget, token usage
 * captured. Normal protected Codex authentication and store are used
 * as-is; nothing reads or copies credentials or edits any configuration
 * file.
 *
 * Isolation, in this order, all before the first model call:
 * 1. Every model phase runs with `--ignore-user-config`, `--ignore-rules`,
 *    plugins/apps/memories/browser/computer use/goals disabled, a
 *    read-only sandbox and a private cwd.
 * 2. Gate: a confined (no network, no child processes, so no hook or
 *    service can start) App Server with the same feature flags and the
 *    probe's own hook/MCP overrides lists the hooks Codex would load
 *    (`hooks/list`). The App Server cannot take `--ignore-user-config` or
 *    `--ignore-rules`, so it may list user hooks (and user trust) that the
 *    model phases would not load; the same `hooks.state` override is passed
 *    to every model phase, so each listed foreign hook is disabled there
 *    too. A hook loaded only under the model phases' profile and absent
 *    from this listing is not expected (those flags only remove sources)
 *    but is not proven here. Every enabled hook not set by the
 *    probe gets `enabled=false` and the probe's own hooks get
 *    `trusted_hash`, all in ONE per-launch whole-map override
 *    `-c hooks.state={"<key>"={...},...}` (keys contain dots, so per-leaf
 *    dotted paths are split and ignored by 0.162.0-alpha.17.2: root gate run
 *    on 0d623cd8 showed "is ignored" for each), with its own hooks' trust
 *    equal to their listed `currentHash` (no trust bypass, nothing
 *    persisted). A second listing with those overrides must show every
 *    foreign hook disabled and only the probe's hooks enabled and trusted;
 *    the build must not report any override as ignored
 *    (`gate_overrides_accepted`); otherwise the probe stops with
 *    `isolation_unavailable` before phase 1.
 *    The `HookStateToml { enabled, trusted_hash }` keys were read from the
 *    0.162.0-alpha.17.2 binary; the second listing is the proof.
 * 3. The same gate reads the effective config (`config/read`) and keeps
 *    only this probe's own server subtree: `enabled_tools` must be exactly
 *    `["bridge_me","bridge_unlisted"]`, only `bridge_me` may carry a
 *    per-launch `approval_mode` (ME_APPROVAL) and no server-wide default may
 *    be set (`approval_config_effective`), else `approval_config_unavailable`
 *    before any model call. Exec keeps its approval policy `never`; no global
 *    approval setting is changed.
 * 4. Phase 1 (thread creation) additionally disables hooks entirely;
 *    phase 2 uses the verified overrides.
 *
 * Caller attestation uses the read-only `bridge_me` tool (attests, never
 * publishes). The inject marker is published by the probe itself to the
 * root thread before phase 2 and must come back through the root's own
 * `PostToolUse` context. Negative control: the model is asked to call the
 * unapproved `bridge_unlisted`; the host must refuse it with an approval
 * error (`unlisted_refused_by_host`) and the fixture server must never see
 * it (`unlisted_not_executed`). A missing attempt is a failure, not a pass.
 *
 * Phase 3 queues one item with the product helper, then reads the queue
 * back natively. A registered cleanup removes exactly this probe's item
 * (matched by its unique `clientUserMessageId`) on every path, including
 * errors after a possible queue effect, and verifies its removal; an item
 * that may exist but cannot be read back or removed is a failure
 * (`queue_cleanup`), never green. The original event is never replayed.
 *
 * Usage: `cargo +1.98.1 build --offline -p bridge-adapters --bins`, then
 * `node qualification/codex-native-probe.cjs`. Environment:
 * `BRIDGE_BIN_DIR`, `CODEX_EXE` (default: the Desktop-bundled build),
 * `CODEX_PROBE_GATE_ONLY=1` to stop right after the isolation gate (no
 * model call; the run then ends with `gate_only_run` and missing model
 * checks, and `hooks_isolated` / `hooks_after` are the gate's evidence).
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { run } = require('./probe-lib.cjs');

/** Built Bridge binaries. */
const bin = process.env.BRIDGE_BIN_DIR || path.resolve(__dirname, '../../../target/debug');
/** The model and effort this probe is qualified to use. */
const MODEL = 'gpt-6-luna', EFFORT = 'low';
/** The helper's (and every confined App Server's) confinement policy. */
const POLICY = '(version 1)(allow default)(deny network*)(deny process-fork)';
/** Feature flags disabled in every launch (model phases and the gate). */
const DISABLED = ['plugins', 'apps', 'memories', 'browser_use', 'computer_use', 'in_app_browser', 'goals'].flatMap(f => ['--disable', f]);
/** Per-launch isolation flags shared by both model phases. */
const ISOLATION = ['--ignore-user-config', '--ignore-rules', '--skip-git-repo-check', '--sandbox', 'read-only',
  '-m', MODEL, '-c', `model_reasoning_effort="${EFFORT}"`, ...DISABLED];
/** Checks that must all be exactly true. */
const REQUIRED = ['versions_recorded', 'model_in_catalog', 'hooks_isolated', 'approval_config_effective', 'phase1_completed', 'phase2_completed',
  'root_attested', 'inject_published', 'inject_marker_in_reply', 'unlisted_refused_by_host', 'unlisted_not_executed',
  'child_attested_own_thread', 'queue_native_accepted', 'queue_readback', 'queue_cleanup'];
/** Per-launch approval of exactly the read-only `bridge_me` tool. The value
 * is a member of the loaded build's `AppToolApproval` schema enum
 * (`auto`, `prompt`, `writes`, `approve`); the enum string alone is not
 * its semantics: phase 2 must show `bridge_me` executed while the unlisted
 * `bridge_unlisted` is refused by the host and never reaches the server. */
const ME_APPROVAL = 'approve';
/** Hook events the probe installs. */
const EVENTS = ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'];

run('m2xp', 20 * 60_000, REQUIRED, async probe => {
  const codex = fs.realpathSync(process.env.CODEX_EXE || '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex');
  const fixture = path.join(bin, 'bridge-fixture');
  const store = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
  probe.checks.codex_exe = codex;
  probe.checks.codex_version = probe.local(codex, ['--version']);
  probe.checks.codex_sha256 = probe.sha256(codex);
  probe.checks.bridge_sha256 = Object.fromEntries(['bridge-native-daemon', 'bridge-hook', 'bridge-fixture'].map(b => [b, probe.sha256(path.join(bin, b))]));
  probe.checks.versions_recorded = !probe.checks.codex_version.startsWith('error:');

  // Offline catalog check (no network): the model and effort must exist.
  const catalog = probe.local('/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'debug', 'models']);
  let entry = null;
  try { entry = JSON.parse(catalog.split('\n')[0]).models.find(m => m.slug === MODEL); } catch {}
  probe.checks.model_in_catalog = Boolean(entry && entry.supported_reasoning_levels.some(l => l.effort === EFFORT));
  if (!probe.checks.model_in_catalog) throw new Error('model not in the build catalog');

  // Bridge-side paths the hooks and MCP server name (no thread needed yet).
  const publisher = probe.credential('publisher.token');
  const channelDir = path.join(probe.dir, 'ch'); fs.mkdirSync(channelDir, { mode: 0o700 });
  const channel = path.join(channelDir, 'c.sock'), core = path.join(probe.dir, 'core.sock');
  const evidence = path.join(probe.dir, 'probe.jsonl');
  const hookCommand = `'${path.join(bin, 'bridge-hook')}' '${channel}' codex`;
  const hook = `[{matcher="",hooks=[{type="command",command="${hookCommand}",timeout=5}]}]`;
  const own = [
    '-c', `mcp_servers.bridge_probe.command=${JSON.stringify(fixture)}`,
    '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(['mcp-server', channel, core, publisher.file, evidence])}`,
    '-c', 'mcp_servers.bridge_probe.enabled_tools=["bridge_me","bridge_unlisted"]',
    '-c', `mcp_servers.bridge_probe.tools.bridge_me.approval_mode="${ME_APPROVAL}"`,
    ...EVENTS.flatMap(e => ['-c', `hooks.${e}=${hook}`]),
  ];

  // Isolation gate (before any model call): list, derive per-launch state
  // overrides, re-list and verify.
  let effective = null;
  const list = async (label, extra) => {
    const [answer, config] = await appServer(probe, codex, store, label, [...DISABLED, '--enable', 'hooks', ...own, ...extra],
      [['hooks/list', { cwds: [probe.dir] }], ['config/read', { cwd: probe.dir }]]);
    // Only this probe's own server subtree is kept (the user config may hold secrets).
    effective = config && config.result && config.result.config && config.result.config.mcp_servers
      ? config.result.config.mcp_servers.bridge_probe || null : null;
    return answer && answer.result ? answer.result.data.flatMap(e => e.hooks || []) : null;
  };
  const isOwn = h => h.source === 'sessionFlags' && String(h.command || '') === hookCommand;
  const first = await list('hooks-gate-1', []);
  // One whole-map value: hook keys contain dots (".codex/hooks.json",
  // "config.toml"), so per-leaf dotted -c paths are split and ignored by
  // the loaded build. Inside one TOML inline table every key stays quoted.
  const entries = (first || []).map(h => isOwn(h)
    ? `${JSON.stringify(h.key)}={trusted_hash=${JSON.stringify(h.currentHash)}}`
    : `${JSON.stringify(h.key)}={enabled=false}`);
  const state = entries.length ? ['-c', `hooks.state={${entries.join(',')}}`] : [];
  const second = first ? await list('hooks-gate-2', state) : null;
  const summary = hooks => (hooks || []).map(h => ({ source: h.source, event: h.eventName, enabled: h.enabled, trust: h.trustStatus, own: isOwn(h) }));
  probe.checks.hooks_before = summary(first);
  probe.checks.hooks_after = summary(second);
  const ownAfter = (second || []).filter(isOwn);
  // The loaded build must not report the override as ignored.
  const gateStderr = fs.readFileSync(path.join(probe.dir, 'hooks-gate-2.stderr'), 'utf8');
  probe.checks.gate_overrides_accepted = Boolean(second) && !/is ignored|unrecognized configuration/.test(gateStderr);
  probe.checks.hooks_isolated = Boolean(probe.checks.gate_overrides_accepted && second
    && second.filter(h => !isOwn(h)).every(h => !h.enabled)
    && ownAfter.length === EVENTS.length
    && ownAfter.every(h => h.enabled && h.trustStatus === 'trusted'));
  // The loaded build must parse the exact-tool approval as given.
  probe.checks.approval_config = effective ? {
    enabled_tools: effective.enabled_tools || null,
    tools: effective.tools || null,
    default_tools_approval_mode: effective.default_tools_approval_mode || null,
  } : null;
  probe.checks.approval_config_effective = Boolean(effective && probe.checks.gate_overrides_accepted
    && JSON.stringify(effective.enabled_tools) === JSON.stringify(['bridge_me', 'bridge_unlisted'])
    && effective.tools && effective.tools.bridge_me && effective.tools.bridge_me.approval_mode === ME_APPROVAL
    && !(effective.tools.bridge_unlisted && effective.tools.bridge_unlisted.approval_mode)
    && !effective.default_tools_approval_mode);
  if (!probe.checks.hooks_isolated) { probe.fail('isolation_unavailable'); return; }
  if (!probe.checks.approval_config_effective) { probe.fail('approval_config_unavailable'); return; }
  if (process.env.CODEX_PROBE_GATE_ONLY === '1') { probe.fail('gate_only_run'); return; }

  /** Runs one bounded `codex exec --json` phase; records events and usage. */
  const exec = async (label, args) => {
    const events = [];
    const child = probe.spawn(label, codex, ['exec', '--json', ...args], {}, line => { try { events.push(JSON.parse(line)); } catch {} });
    const exit = await probe.exited(child, Math.min(probe.remaining(), 8 * 60_000));
    probe.checks[`${label}_exit`] = exit;
    probe.checks[`${label}_usage`] = events.filter(e => e.type === 'turn.completed').map(e => e.usage || null);
    probe.checks[`${label}_errors`] = events.filter(e => e.type === 'error' || e.type === 'turn.failed').map(e => String(e.message || (e.error && e.error.message) || '').slice(0, 200));
    if (!exit) probe.fail(`timeout:${label}`);
    return { events, completed: Boolean(exit && exit.code === 0 && events.some(e => e.type === 'turn.completed')) };
  };

  const phase1 = await exec('phase1', [...ISOLATION, ...state, '--disable', 'hooks', 'Reply READY and nothing else. Use no tools.']);
  probe.checks.phase1_completed = phase1.completed;
  const thread = (phase1.events.find(e => e.type === 'thread.started') || {}).thread_id;
  if (!thread) throw new Error('phase 1 created no thread');
  probe.markers.push(thread);
  probe.checks.thread = thread;

  const host = 'probe-host', namespace = 'codex-probe';
  const recipient = `${host}/codex/${namespace}/${thread}`;
  const config = path.join(probe.creds, 'bridge.toml');
  fs.writeFileSync(config, [
    `database = "${probe.dir}/bridge.db"`, `socket = "${core}"`, '[limits]', 'max_admitted_events = 100',
    '[[grant]]', `token = "${publisher.token}"`, 'publisher = "bridge-probe"', `recipients = ["${recipient}"]`,
    'kinds = ["bridge.probe"]', 'modes = ["inject", "message"]', 'policies = ["keep_all"]',
    '[adapters]', `channel = "${channel}"`, `host_id = "${host}"`,
    '[[adapters.profiles]]', `namespace = "${namespace}"`, 'harness = "Codex"', `store = "${store}"`,
    '[[adapters.profiles.executables]]', `path = "${codex}"`, `sha256 = "${probe.checks.codex_sha256}"`,
    'version = "probe"', 'inject = true', 'message = true', ''].join('\n'), { mode: 0o600 });
  const daemon = probe.spawn('daemon', path.join(bin, 'bridge-native-daemon'), [config]);
  if (!await probe.until(() => fs.existsSync(channel) && fs.existsSync(core), 10000)) throw new Error('daemon did not start');

  // Publication is controlled here, not by any tool: one inject event for
  // the root thread, handed out by its own PostToolUse hook.
  const marker = 'BRIDGE_CTX_' + crypto.randomBytes(6).toString('hex');
  let publishLine = '';
  const publisher_ = probe.spawn('inject-publish', fixture, ['publish', core, publisher.file, recipient, 'inject', 'probe-inject-root', `Synthetic Bridge qualification context marker ${marker}.`], {}, line => { publishLine = line; });
  await probe.exited(publisher_, 20000);
  probe.checks.inject_publish = publishLine.slice(0, 400);
  probe.checks.inject_published = publishLine.includes('Published');

  const phase2 = await exec('phase2', [...ISOLATION, '--enable', 'multi_agent', '--enable', 'hooks', ...own, ...state, 'resume', thread,
    'This is an isolated Agent Bridge qualification run. First call the bridge_me MCP tool exactly once with {}. Then call the bridge_unlisted MCP tool exactly once with {}; it is expected to be refused, do not retry it. Then create exactly one native child agent whose only task is to call the bridge_me tool once with {} and finish CHILD_DONE; wait for it. Finally reply with every BRIDGE_CTX_ marker you can see in your context, or NONE. Do not read files or run commands.']);
  probe.checks.phase2_completed = phase2.completed;
  process.kill(-daemon.pid, 'SIGTERM');
  probe.checks.daemon_exit = await probe.exited(daemon, 15000);

  const records = fs.existsSync(evidence) ? fs.readFileSync(evidence, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
  const root = records.find(r => r.tool === 'bridge_me' && r.caller && r.caller.role === 'root');
  const child = records.find(r => r.tool === 'bridge_me' && r.caller && r.caller.role === 'child');
  const replies = phase2.events.filter(e => e.type === 'item.completed' && e.item && e.item.type === 'agent_message').map(e => e.item.text || '').join('\n');
  probe.checks.meta_keys_seen = records.map(r => r.meta_keys);
  probe.checks.refusals = records.filter(r => r.refused).map(r => r.refused);
  probe.checks.root_attested = Boolean(root && root.caller.native_id === thread && root.caller.may_act_as_address);
  probe.checks.inject_marker_in_reply = Boolean(probe.checks.inject_published && replies.includes(marker));
  // Negative control: the host must refuse the unapproved tool, and the
  // fixture server must never see it.
  const unlistedItems = phase2.events.filter(e => JSON.stringify(e).includes('bridge_unlisted') && e.item && e.item.type !== 'agent_message');
  probe.checks.unlisted_items = unlistedItems.map(e => JSON.stringify(e).slice(0, 400));
  probe.checks.unlisted_refused_by_host = unlistedItems.some(e => e.type === 'item.completed'
    && (e.item.status === 'failed' || Boolean(e.item.error)) && /approval/i.test(JSON.stringify(e.item)));
  probe.checks.unlisted_not_executed = !records.some(r => r.unlisted_called);
  probe.checks.child_attested_own_thread = Boolean(child && child.caller.native_id !== thread && child.caller.address.endsWith('/' + child.caller.native_id));
  const stderr = fs.readFileSync(path.join(probe.dir, 'daemon.stderr'), 'utf8');
  probe.checks.daemon_events = Object.fromEntries([...stderr.matchAll(/"event":"([a-z_]+)"/g)].map(m => m[1]).reduce((map, e) => map.set(e, (map.get(e) || 0) + 1), new Map()));

  // Phase 3: one product hand-off on the now unloaded, persisted thread.
  // The cleanup is registered before the hand-off can have any effect.
  const client = 'agent-bridge-probe-' + crypto.randomBytes(8).toString('hex');
  let cleaned = false;
  probe.checks.queue_cleanup = false;
  probe.onCleanup('codex-queue-item', async () => {
    if (cleaned) return;
    cleaned = true;
    const items = await queueItems(probe, codex, store, 'queue-cleanup-list', thread, true);
    if (items === null) { probe.checks.queue_cleanup_detail = 'queue unreadable; own item may remain'; return; }
    const mine = items.filter(i => i.clientUserMessageId === client);
    for (const item of mine) {
      await appServer(probe, codex, store, 'queue-cleanup-delete', [], [['thread/queue/delete', { threadId: thread, queuedSubmissionId: item.id }]], true);
    }
    const after = await queueItems(probe, codex, store, 'queue-cleanup-verify', thread, true);
    probe.checks.queue_cleanup_removed = mine.length;
    probe.checks.queue_cleanup = Array.isArray(after) && !after.some(i => i.clientUserMessageId === client);
  });
  const text = path.join(probe.dir, 'queue-text.txt');
  fs.writeFileSync(text, `Synthetic Bridge queue qualification item ${client}.`);
  // A tracked process group (not a bare local command): a timeout kills
  // the fixture *and* its confined App Server helper together.
  const addLines = [];
  const adder = probe.spawn('queue-add', fixture, ['queue-add', '/usr/bin/sandbox-exec', codex, store, thread, client, text], {}, line => addLines.push(line));
  probe.checks.queue_add_exit = await probe.exited(adder, 60000);
  let added = {};
  try { added = JSON.parse(addLines[addLines.length - 1]); } catch {}
  probe.checks.queue_add = added;
  probe.checks.queue_native_accepted = added.outcome === 'native_accepted';
  const items = await queueItems(probe, codex, store, 'queue-readback', thread);
  const item = (items || []).find(i => i.clientUserMessageId === client);
  probe.checks.queue_readback = Boolean(probe.checks.queue_native_accepted && item && JSON.stringify(item.input).includes(client));
});

/** Lists one thread's native queue through a confined App Server.
 * @param {import('./probe-lib.cjs').Probe} probe The probe.
 * @param {string} codex Codex executable.
 * @param {string} store `CODEX_HOME`.
 * @param {string} label Log label.
 * @param {string} thread Thread id.
 * @param {boolean} [cleanup] Whether called from the registered cleanup action.
 * @returns {Promise<{id: string, clientUserMessageId: string, input: object[]}[]|null>} Items, or null when unreadable.
 */
async function queueItems(probe, codex, store, label, thread, cleanup = false) {
  const [answer] = await appServer(probe, codex, store, label, [], [['thread/queue/list', { threadId: thread }]], cleanup);
  return answer && answer.result && Array.isArray(answer.result.data) ? answer.result.data : null;
}

/** Runs one confined, network-denied, fork-denied App Server session
 * against `store` (so no hook, MCP server or other service can start).
 * @param {import('./probe-lib.cjs').Probe} probe The probe.
 * @param {string} codex Codex executable.
 * @param {string} store `CODEX_HOME`.
 * @param {string} label Log label.
 * @param {string[]} flags Extra App Server flags (`-c`, `--enable`, `--disable`).
 * @param {[string, object][]} requests Requests after `initialize`.
 * @param {boolean} [cleanup] Whether called from the registered cleanup action (allowed past the lifecycle fence).
 * @returns {Promise<(object|undefined)[]>} Responses of `requests` in order (undefined when missing).
 */
async function appServer(probe, codex, store, label, flags, requests, cleanup = false) {
  const lines = [];
  const child = probe.spawn(label, '/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'app-server', ...flags, '--listen', 'stdio://'],
    { stdin: true, cleanup, env: { PATH: '/usr/bin:/bin', HOME: os.homedir(), CODEX_HOME: store } }, line => { try { lines.push(JSON.parse(line)); } catch {} });
  const send = (id, method, params) => child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
  const answer = async id => { await probe.until(() => lines.some(l => l.id === id && !l.method), 20000); return lines.find(l => l.id === id && !l.method); };
  send(0, 'initialize', { clientInfo: { name: 'agent_bridge_probe', version: '0' }, capabilities: { experimentalApi: true } });
  const responses = [];
  if (await answer(0)) {
    child.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
    for (const [index, [method, params]] of requests.entries()) { send(index + 1, method, params); responses.push(await answer(index + 1)); }
  }
  child.stdin.end();
  try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  probe.checks[`${label}_exit`] = await probe.exited(child, 5000);
  return responses;
}
