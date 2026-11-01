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
 * 3. The same gate reads the effective config (`config/read`). Every gate
 *    App Server stdout line is projected *before* it is logged or parsed
 *    (`gateRead`; the user config and hook commands may hold credentials,
 *    and the root r6 run logged both raw): `hooks/list` keeps per hook only
 *    `key`, `source`, `eventName`, `enabled`, `trustStatus`,
 *    `currentHash` and an `own` flag computed from the exact own command
 *    (no command, arguments or other field); `config/read` keeps only this
 *    probe's own server subtree; other responses keep only their id (or
 *    error code), notifications only their method, and unparsable lines
 *    are dropped. The gate's stderr never reaches a file: it is piped and
 *    reduced in memory to its size and whether it reported an override as
 *    ignored (`Probe.spawn` `stderrMatch`), so a signal, a thrown error or
 *    a gate process that keeps writing leaves no raw stderr behind. Model phases, queue sessions and the
 *    queue helper log their stdout/stderr unfiltered; those channels are not
 *    claimed free of configuration diagnostics. The response
 *    shape (`result.config.mcp_servers.bridge_probe`) is the one this
 *    probe expects, not one proven against the build: an absent subtree
 *    fails the gate. `--self-test-config` checks the projection against a
 *    fake App Server that plants fake credentials in a foreign hook
 *    command, the config tree, a notification, an unparsable line and
 *    stderr, in a completed gate, a gate interrupted by SIGTERM and a gate
 *    whose server ignores SIGTERM and keeps writing.
 *    `enabled_tools` must be exactly
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
 * Together these prove the caller, the host approval boundary and the
 * parsed config, NOT that the `approve` value itself caused the
 * behavior (no control runs `bridge_me` without it). The fixture server
 * exposes only `bridge_me` and `bridge_unlisted`.
 *
 * Phase 3 queues one item with the product helper, then reads the queue
 * back natively. A registered cleanup removes exactly this probe's item
 * (matched by its unique `clientUserMessageId`) on every path, including
 * errors after a possible queue effect, and verifies its removal; an item
 * that may exist but cannot be read back or removed is a failure
 * (`queue_cleanup`), never green. The original event is never replayed.
 *
 * Usage: `cargo +1.98.1 build --offline -p bridge-adapters --bins`, then
 * `node qualification/codex-native-probe.cjs` (or `--self-test-config`:
 * the synthetic config control, no Codex and no model). Environment:
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
/** The own hook command the config control's fake App Server lists. */
const CONTROL_OWN_COMMAND = 'control-own-hook';

/** Source of the config control's fake App Server. `$CODEX_HOME/mode`
 * selects its behavior: `normal` answers as below; `hang` writes its
 * stderr and never answers; `late` answers as below but ignores SIGTERM
 * and keeps writing the planted values to stderr every 200 ms until
 * killed, and never writes the ignored-override warning (so only the
 * gate's fail-closed non-exit check can reject it). It reads two planted
 * fake credentials from `$CODEX_HOME/planted-hook` and
 * `$CODEX_HOME/planted-config` (inside the deleted credentials directory,
 * so only its output can carry them into evidence) and puts them where a
 * real App Server could: a foreign hook's command and extra fields in the
 * `hooks/list` answer (beside one own hook whose command is
 * `CONTROL_OWN_COMMAND`), foreign entries of the `config/read` answer
 * (beside the probe's own subtree), a notification, an unparsable stdout
 * line and stderr (with an "is ignored" override warning). */
const FAKE_APP_SERVER = `'use strict';
const fs = require('node:fs');
const hookSecret = fs.readFileSync(process.env.CODEX_HOME + '/planted-hook', 'utf8');
const configSecret = fs.readFileSync(process.env.CODEX_HOME + '/planted-config', 'utf8');
const mode = fs.readFileSync(process.env.CODEX_HOME + '/mode', 'utf8');
if (mode === 'late') {
  process.on('SIGTERM', () => {});
  setInterval(() => process.stderr.write('late diagnostic ' + hookSecret + ' ' + configSecret + '\\n'), 200);
}
const out = value => process.stdout.write((typeof value === 'string' ? value : JSON.stringify(value)) + '\\n');
if (mode !== 'late') process.stderr.write('warning: hooks.state.' + hookSecret + ' is ignored; config ' + configSecret + '\\n');
require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
  const message = JSON.parse(line);
  if (message.id === undefined || mode === 'hang') return;
  out({ method: 'config/warning', params: { detail: configSecret } });
  out('not json ' + hookSecret);
  const result = message.method === 'hooks/list'
    ? { data: [{ cwd: '/private', hooks: [
        { key: 'own-key', source: 'sessionFlags', eventName: 'Stop', command: '${CONTROL_OWN_COMMAND}', enabled: true, trustStatus: 'untrusted', currentHash: 'own-hash' },
        { key: 'foreign-key', source: 'user', eventName: 'Stop', command: 'curl -H "Authorization: Bearer ' + hookSecret + '"', enabled: true, trustStatus: 'trusted', currentHash: 'foreign-hash', env: { TOKEN: hookSecret } }] }] }
    : message.method === 'config/read'
      ? { config: { model_providers: { foreign: { experimental_bearer_token: configSecret } },
          mcp_servers: { foreign: { env: { TOKEN: configSecret } },
            bridge_probe: { enabled_tools: ['bridge_me', 'bridge_unlisted'], tools: { bridge_me: { approval_mode: '${ME_APPROVAL}' } } } } },
        origins: { 'mcp_servers.foreign.env.TOKEN': { name: { type: 'user', file: configSecret } } } }
      : { userAgent: configSecret };
  out({ id: message.id, result });
});
`;

if (require.main !== module) {
  // Loaded as a library by `codex-lifecycle-probe.cjs`: nothing runs.
} else if (process.argv[2] === '--self-test-config') configControls();
else if (process.argv[2] === '--config-control-case') configControl(process.argv[3]);
else run('m2xp', 20 * 60_000, REQUIRED, async probe => {
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
    '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(['mcp-server', channel, core, publisher.file, evidence, 'bridge_me,bridge_unlisted'])}`,
    '-c', 'mcp_servers.bridge_probe.enabled_tools=["bridge_me","bridge_unlisted"]',
    '-c', `mcp_servers.bridge_probe.tools.bridge_me.approval_mode="${ME_APPROVAL}"`,
    ...EVENTS.flatMap(e => ['-c', `hooks.${e}=${hook}`]),
  ];

  // Isolation gate (before any model call): list, derive per-launch state
  // overrides, re-list and verify.
  let effective = null, rejected = true;
  /** Runs one gate listing (`gateRead`) with the probe's own hook/MCP
   * overrides plus `extra`, keeping its own server subtree in `effective`
   * and its stderr verdict in `rejected`.
   * @param {string} label Log label of the gate session.
   * @param {string[]} extra Extra App Server flags (the state override for the second listing).
   * @returns {Promise<{key: string|null, source: string|null, eventName: string|null, enabled: boolean|null, trustStatus: string|null, currentHash: string|null, own: boolean}[]|null>} Projected hooks, or null when not answered.
   */
  const list = async (label, extra) => {
    const read = await gateRead(probe, codex, store, label, [...DISABLED, '--enable', 'hooks', ...own, ...extra], hookCommand);
    effective = read.effective;
    rejected = read.overrideRejected;
    return read.hooks;
  };
  const first = await list('hooks-gate-1', []);
  const state = stateOverride(first || []);
  const second = first ? await list('hooks-gate-2', state) : null;
  /** Result-safe view of projected hooks (no key or hash).
   * @param {{source: string|null, eventName: string|null, enabled: boolean|null, trustStatus: string|null, own: boolean}[]|null} hooks Projected hooks, or null.
   * @returns {{source: string|null, event: string|null, enabled: boolean|null, trust: string|null, own: boolean}[]} One entry per hook; empty for null.
   */
  const summary = hooks => (hooks || []).map(h => ({ source: h.source, event: h.eventName, enabled: h.enabled, trust: h.trustStatus, own: h.own }));
  probe.checks.hooks_before = summary(first);
  probe.checks.hooks_after = summary(second);
  const ownAfter = (second || []).filter(h => h.own);
  // The loaded build must not report the override as ignored.
  probe.checks.gate_overrides_accepted = Boolean(second) && !rejected;
  probe.checks.hooks_isolated = Boolean(probe.checks.gate_overrides_accepted && second
    && second.filter(h => !h.own).every(h => !h.enabled)
    && ownAfter.length === EVENTS.length
    && ownAfter.every(h => h.enabled && h.trustStatus === 'trusted'));
  // The loaded build must parse the exact-tool approval as given.
  probe.checks.approval_config = effective ? {
    enabled_tools: effective.enabled_tools || null,
    tools: effective.tools || null,
    default_tools_approval_mode: effective.default_tools_approval_mode || null,
  } : null;
  probe.checks.approval_config_effective = Boolean(probe.checks.gate_overrides_accepted && ownApprovalParsed(effective));
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
    '[[adapters.harnesses]]', `namespace = "${namespace}"`, 'harness = "Codex"',
    'inject = true', 'message = true', ''].join('\n'), { mode: 0o600 });
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

/** Whether the kept own server subtree is exactly the per-launch approval
 * config: exactly the supplied tools enabled, only the first with
 * `ME_APPROVAL`, no server-wide default. Defaults preserve the legacy probe.
 * @param {object|null} effective The kept `bridge_probe` subtree.
 * @param {string[]} [tools] Nonempty owned tool names; first is approved.
 * @returns {boolean}
 */
function ownApprovalParsed(effective, tools = ['bridge_me', 'bridge_unlisted']) {
  return Boolean(effective
    && tools.length > 0 && new Set(tools).size === tools.length
    && JSON.stringify(effective.enabled_tools) === JSON.stringify(tools)
    && effective.tools && effective.tools[tools[0]] && effective.tools[tools[0]].approval_mode === ME_APPROVAL
    && tools.slice(1).every(name => !(effective.tools[name] && effective.tools[name].approval_mode))
    && !effective.default_tools_approval_mode);
}

/** The per-launch `hooks.state` override for a gate listing: every own
 * hook trusted by its listed `currentHash`, every other hook disabled, in
 * ONE whole-map value (hook keys contain dots, such as ".codex/hooks.json"
 * or "config.toml", so per-leaf dotted `-c` paths are split and ignored by
 * the loaded build; inside one TOML inline table every key stays quoted).
 * @param {{key: string, own: boolean, currentHash: string|null}[]} hooks Projected hooks from `gateRead`.
 * @returns {string[]} `['-c', 'hooks.state={...}']`, or `[]` for no hooks.
 */
function stateOverride(hooks) {
  const entries = hooks.map(h => h.own
    ? `${JSON.stringify(h.key)}={trusted_hash=${JSON.stringify(h.currentHash)}}`
    : `${JSON.stringify(h.key)}={enabled=false}`);
  return entries.length ? ['-c', `hooks.state={${entries.join(',')}}`] : [];
}

/** Lists hooks and reads the effective config in one confined App Server
 * session, keeping only what the gate needs.
 *
 * Every stdout line is projected by `keep` before it is logged or parsed,
 * so no other part of it is written or retained: the `hooks/list` answer
 * (request id 1) to the minimal hook fields plus `own`, the `config/read`
 * answer (id 2) to `result.config.mcp_servers.bridge_probe` plus server-name
 * enablement and instruction-presence booleans (no foreign values), any other
 * answer to its id (or error code), a notification or server request to
 * its method name; an unparsable line is dropped. Stderr is never written:
 * it is reduced in memory while it streams (`Probe.spawn` `stderrMatch`),
 * and after the session only `{stderr_bytes, override_rejected}` is written
 * to `<label>.stderr-summary.json`, where `override_rejected` means it
 * reported a setting as ignored or unrecognized, or the session did not
 * exit or close its output within its bounds (fails closed).
 * @param {import('./probe-lib.cjs').Probe} probe The probe.
 * @param {string} codex Codex executable.
 * @param {string} store `CODEX_HOME`.
 * @param {string} label Log label.
 * @param {string[]} flags App Server flags.
 * @param {string} ownCommand The exact command of this probe's own hooks; a `sessionFlags` hook with exactly this command is `own`.
 * @returns {Promise<{hooks: {key: string|null, source: string|null, eventName: string|null, enabled: boolean|null, trustStatus: string|null, currentHash: string|null, own: boolean}[]|null, effective: object|null, configFacts: {servers: Record<string,boolean|null>, instructions: boolean, developer_instructions: boolean}|null, overrideRejected: boolean}>}
 *   Projected hooks, own server subtree, safe configuration facts (null when
 *   unanswered), and stderr verdict. Foreign credentials/commands are omitted.
 */
async function gateRead(probe, codex, store, label, flags, ownCommand) {
  /** A JSON scalar or null (no object or array survives).
   * @param {unknown} value Field value.
   * @returns {string|number|boolean|null}
   */
  const scalar = value => ['string', 'number', 'boolean'].includes(typeof value) ? value : null;
  /** Projects one raw stdout line before it is logged or parsed (the
   * `Probe.spawn` `keep` contract); the raw line is never retained.
   * @param {string} line One raw stdout line of the App Server.
   * @returns {string|null} The projected JSON line, or null to drop it.
   */
  const keep = line => {
    let message;
    try { message = JSON.parse(line); } catch { return null; }
    if (!message || typeof message !== 'object') return null;
    if (message.method !== undefined) return JSON.stringify({ method: String(scalar(message.method)).slice(0, 64) });
    const id = scalar(message.id);
    if (message.error) return JSON.stringify({ id, error: { code: scalar(message.error.code) } });
    const result = message.result || {};
    if (id === 1) {
      const listed = Array.isArray(result.data) ? result.data.flatMap(e => e && Array.isArray(e.hooks) ? e.hooks : []) : [];
      const hooks = listed.filter(h => h && typeof h === 'object').map(h => ({
        key: scalar(h.key), source: scalar(h.source), eventName: scalar(h.eventName), enabled: scalar(h.enabled),
        trustStatus: scalar(h.trustStatus), currentHash: scalar(h.currentHash),
        own: h.source === 'sessionFlags' && h.command === ownCommand,
      }));
      return JSON.stringify({ id, result: { data: [{ hooks }] } });
    }
    if (id === 2) {
      const servers = result.config && result.config.mcp_servers;
      const config = result.config;
      return JSON.stringify({ id, result: { config: { mcp_servers: { bridge_probe: (servers && servers.bridge_probe) || null } },
        facts: config && servers && typeof servers === 'object' && !Array.isArray(servers) ? {
          servers: Object.fromEntries(Object.entries(servers).map(([name, value]) => [name, value && typeof value.enabled === 'boolean' ? value.enabled : null])),
          instructions: typeof config.instructions === 'string' && config.instructions.length > 0,
          developer_instructions: typeof config.developer_instructions === 'string' && config.developer_instructions.length > 0,
        } : null } });
    }
    return JSON.stringify({ id, result: {} });
  };
  const [answer, config] = await appServer(probe, codex, store, label, flags,
    [['hooks/list', { cwds: [probe.dir] }], ['config/read', { cwd: probe.dir }]], false, keep, /is ignored|unrecognized configuration/);
  const entry = probe.children.find(c => c.name === label);
  let timer;
  const settled = await Promise.race([entry.closed, new Promise(r => { timer = setTimeout(() => r(false), 2000); })]);
  clearTimeout(timer);
  const reduced = entry.child.stderrSummary;
  const overrideRejected = !probe.checks[`${label}_exit`] || settled !== true || !reduced || reduced.matched;
  fs.writeFileSync(path.join(probe.dir, `${label}.stderr-summary.json`),
    JSON.stringify({ stderr_bytes: reduced ? reduced.stderr_bytes : null, override_rejected: overrideRejected }) + '\n');
  return {
    hooks: answer && answer.result ? answer.result.data[0].hooks : null,
    effective: config && config.result ? config.result.config.mcp_servers.bridge_probe : null,
    configFacts: config && config.result ? config.result.facts : null,
    overrideRejected,
  };
}

/** One case of the synthetic `gateRead` control (no Codex, no model, no
 * real configuration), run as its own process by `configControls` against
 * `FAKE_APP_SERVER`. The planted fake credentials come from the 0600 files
 * in `$CONFIG_CONTROL_PLANTED` and are deliberately NOT registered as probe
 * secrets, so `finish` cannot redact a leak: the parent finds it.
 *
 * - `normal`: requires the own config subtree, own-hook recognition (and
 *   only it), the state override and the detected stderr override warning;
 *   after `finish` also checks that the kept `hooks/list` entries carry only
 *   the minimal fields, the kept `config/read` line is the own subtree plus
 *   exact server-name enablement/instruction-presence booleans, and notifications
 *   keep only their method. No foreign configuration values survive.
 * - `signal`: the server writes its stderr and never answers; the probe
 *   sends itself SIGTERM mid-gate, so cleanup runs before any gate result.
 * - `late`: the server answers, ignores SIGTERM and keeps writing stderr
 *   without any ignored-override warning; the gate must still reject
 *   (`config_late_rejected`) because the session neither exited nor
 *   closed within its bounds.
 * @param {string} mode `normal`, `signal` or `late`.
 * @returns {void}
 */
function configControl(mode) {
  const required = { normal: ['config_own_survives', 'config_facts_minimal', 'config_hooks_classified', 'config_state_override', 'config_override_rejection_detected'],
    signal: ['config_gate_completed'], late: ['config_late_rejected'] }[mode];
  if (!required) throw new Error(`unknown control case ${mode}`);
  run('m2xc', 60_000, required, async probe => {
    const store = path.join(probe.creds, 'store');
    fs.mkdirSync(store, { mode: 0o700 });
    for (const name of ['planted-hook', 'planted-config']) {
      fs.copyFileSync(path.join(process.env.CONFIG_CONTROL_PLANTED, name), path.join(store, name));
    }
    fs.writeFileSync(path.join(store, 'mode'), mode === 'signal' ? 'hang' : mode, { mode: 0o600 });
    const fake = path.join(probe.dir, 'fake-app-server');
    fs.writeFileSync(fake, `#!${process.execPath}\n${FAKE_APP_SERVER}`, { mode: 0o700 });
    if (mode === 'signal') {
      gateRead(probe, fake, store, 'hooks-gate-c', [], CONTROL_OWN_COMMAND).then(() => { probe.checks.config_gate_completed = true; });
      await new Promise(r => setTimeout(r, 1500));
      process.kill(process.pid, 'SIGTERM');
      await new Promise(r => setTimeout(r, 30_000));
      return;
    }
    const { hooks, effective, configFacts, overrideRejected } = await gateRead(probe, fake, store, 'hooks-gate-c', [], CONTROL_OWN_COMMAND);
    if (mode === 'late') { probe.checks.config_late_rejected = overrideRejected === true; return; }
    probe.checks.config_own_survives = ownApprovalParsed(effective);
    probe.checks.config_facts_minimal = JSON.stringify(configFacts) === JSON.stringify({
      servers: { foreign: null, bridge_probe: null }, instructions: false, developer_instructions: false,
    });
    probe.checks.config_hooks_classified = Boolean(hooks && hooks.length === 2
      && hooks.some(h => h.key === 'own-key' && h.own === true && h.currentHash === 'own-hash')
      && hooks.some(h => h.key === 'foreign-key' && h.own === false)
      && hooks.every(h => !('command' in h) && !('env' in h)));
    probe.checks.config_state_override = JSON.stringify(stateOverride(hooks || []))
      === JSON.stringify(['-c', 'hooks.state={"own-key"={trusted_hash="own-hash"},"foreign-key"={enabled=false}}']);
    probe.checks.config_override_rejection_detected = overrideRejected === true;
  }).then(probe => {
    if (mode !== 'normal') return;
    const log = fs.readFileSync(path.join(probe.dir, 'hooks-gate-c.stdout'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    const hooksLine = log.find(l => l.id === 1);
    const hooksMinimal = Boolean(hooksLine) && hooksLine.result.data[0].hooks.every(h => JSON.stringify(Object.keys(h))
      === JSON.stringify(['key', 'source', 'eventName', 'enabled', 'trustStatus', 'currentHash', 'own']));
    const configKept = log.filter(l => l.id === 2).map(l => JSON.stringify(l));
    const configOwnOnly = configKept.length === 1
      && configKept[0] === JSON.stringify({ id: 2, result: {
        config: { mcp_servers: { bridge_probe: { enabled_tools: ['bridge_me', 'bridge_unlisted'], tools: { bridge_me: { approval_mode: ME_APPROVAL } } } } },
        facts: { servers: { foreign: null, bridge_probe: null }, instructions: false, developer_instructions: false },
      } });
    const notificationsMethodOnly = log.filter(l => l.method !== undefined).every(l => JSON.stringify(Object.keys(l)) === '["method"]');
    const pass = probe.failures.length === 0 && hooksMinimal && configOwnOnly && notificationsMethodOnly;
    console.log(JSON.stringify({ config_case: 'normal', pass, hooksMinimal, configOwnOnly, notificationsMethodOnly }));
    if (!pass) process.exitCode = 1;
  });
}

/** Runs the three `configControl` cases as separate processes and judges
 * what they retained, from outside (no model, no Codex).
 *
 * It plants two fresh fake credentials in a private 0700 directory (0600
 * files, deleted afterwards), runs each case with a 90 s bound and checks,
 * in this order: no file under the case's evidence directory and none of
 * its console output contains either planted value (a leak fails the case
 * before anything else is judged); no surviving process names the case's
 * directory; then the case verdict (`normal`: exit 0 and its own checks
 * passed; `signal`: `signal:SIGTERM` recorded and the gate never
 * completed; `late`: exit 0 with the late gate rejected). Prints one JSON
 * line `{config_control: PASS|FAIL, cases}` and sets the exit code.
 * @returns {void}
 */
function configControls() {
  const { spawnSync, execFileSync } = require('node:child_process');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'm2xcp-'));
  fs.chmodSync(work, 0o700);
  const planted = ['planted-hook', 'planted-config'].map(name => {
    const value = `FAKE_FOREIGN_CREDENTIAL_${name.toUpperCase().replace('-', '_')}_${crypto.randomBytes(12).toString('hex')}`;
    fs.writeFileSync(path.join(work, name), value, { mode: 0o600 });
    return value;
  });
  /** Every regular file under `dir`, recursively.
   * @param {string} dir Directory.
   * @returns {string[]} Absolute file paths.
   */
  const files = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory()
    ? files(path.join(dir, e.name)) : e.isFile() ? [path.join(dir, e.name)] : []);
  const cases = {};
  for (const mode of ['normal', 'signal', 'late']) {
    const ran = spawnSync(process.execPath, [__filename, '--config-control-case', mode],
      { env: { ...process.env, CONFIG_CONTROL_PLANTED: work }, encoding: 'utf8', timeout: 90_000 });
    const output = `${ran.stdout || ''}${ran.stderr || ''}`;
    let result = null;
    try { result = JSON.parse(output.split('\n').find(l => l.startsWith('{"dir"'))); } catch {}
    const dir = result && result.dir;
    const leaked = planted.some(value => output.includes(value))
      || (dir ? files(dir).some(f => planted.some(value => fs.readFileSync(f, 'latin1').includes(value))) : false);
    const survivors = dir ? execFileSync('/bin/ps', ['-A', '-o', 'command='], { encoding: 'utf8' }).split('\n').filter(l => l.includes(dir)).length : -1;
    const checks = dir && fs.existsSync(path.join(dir, 'checks.json')) ? JSON.parse(fs.readFileSync(path.join(dir, 'checks.json'), 'utf8')) : null;
    const failures = result ? result.failures : null;
    const verdict = !dir ? false
      : mode === 'normal' ? ran.status === 0
      : mode === 'signal' ? failures.includes('signal:SIGTERM') && !(checks && checks.checks.config_gate_completed)
      : ran.status === 0 && Boolean(checks && checks.checks.config_late_rejected === true);
    cases[mode] = { pass: Boolean(dir) && !leaked && survivors === 0 && verdict, leaked, survivors, status: ran.status, signal: ran.signal, failures };
  }
  fs.rmSync(work, { recursive: true, force: true });
  const pass = Object.values(cases).every(c => c.pass);
  console.log(JSON.stringify({ config_control: pass ? 'PASS' : 'FAIL', cases }));
  process.exitCode = pass ? 0 : 1;
}

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
 * @param {(line: string) => string|null} [keep] Pre-write rewrite of each output line (see `Probe.spawn`).
 * @param {RegExp} [stderrMatch] Reduce stderr in memory instead of logging it (see `Probe.spawn`).
 * @returns {Promise<(object|undefined)[]>} Responses of `requests` in order (undefined when missing).
 */
async function appServer(probe, codex, store, label, flags, requests, cleanup = false, keep = undefined, stderrMatch = undefined) {
  const lines = [];
  const child = probe.spawn(label, '/usr/bin/sandbox-exec', ['-p', POLICY, codex, 'app-server', ...flags, '--listen', 'stdio://'],
    { stdin: true, cleanup, keep, stderrMatch, env: { PATH: '/usr/bin:/bin', HOME: os.homedir(), CODEX_HOME: store } }, line => { try { lines.push(JSON.parse(line)); } catch {} });
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

/** Shared Q3 isolation/config building blocks; importing runs nothing.
 * Legacy tool defaults remain; universal qualification supplies its own tool.
 * @type {{MODEL:string,EFFORT:string,POLICY:string,DISABLED:string[],EVENTS:string[],ME_APPROVAL:string,
 * gateRead:typeof gateRead,stateOverride:typeof stateOverride,ownApprovalParsed:typeof ownApprovalParsed,appServer:typeof appServer}} */
module.exports = { MODEL, EFFORT, POLICY, DISABLED, EVENTS, ME_APPROVAL, gateRead, stateOverride, ownApprovalParsed, appServer };
