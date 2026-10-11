/**
 * Root-run native qualification probe: real Codex + Bridge hooks and the
 * probe MCP server. It answers the open question whether the real
 * `_meta.callId` of an MCP call equals that call's `PreToolUse`
 * `tool_use_id` (the registry join succeeds only if it does), and whether
 * root `PostToolUse` context reaches the model, for a root and one native
 * child thread.
 *
 * Needs a model and the user's normal Codex login; run only when the root
 * explicitly provisions it. Phase 1 creates one fresh owned thread with a
 * minimal turn; phase 2 resumes exactly that thread with session-only
 * overrides: the user's configured MCP servers are disabled by name, the
 * probe MCP server and Bridge hooks are added, sandbox read-only. All
 * Bridge state is in a fresh mkdtemp directory; the daemon grant names only
 * the probe thread; children are terminated on exit. Codex may require the
 * hook definitions to be trusted; if hooks do not run, the root join fails
 * closed and `root_attested` is false (that is a finding, not a pass).
 *
 * Usage: `node codex-native-probe.cjs` after `cargo build --offline -p
 * bridge-adapters --bins`. Environment: `BRIDGE_BIN_DIR` (default
 * `<repo>/target/debug`), `CODEX_EXE` (default: the Desktop-bundled
 * build), optional `CODEX_PROBE_MODEL`. Exits 0 only when every expected
 * check holds; evidence: `phase1.jsonl`, `events.jsonl`, `probe.jsonl`,
 * `daemon.stderr`, `checks.json` in the printed directory.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const readline = require('node:readline');

/** Built Bridge binaries. */
const bin = process.env.BRIDGE_BIN_DIR || path.resolve(__dirname, '../../../target/debug');
/** The loaded Codex build. */
const codex = fs.realpathSync(process.env.CODEX_EXE || '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex');
/** Fresh owned evidence and state directory. */
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'm2xp-'));
/** Children to terminate on any exit. */
const children = [];
process.on('exit', () => { for (const child of children) { try { child.kill('SIGTERM'); } catch {} } });

/** Lowercase hex SHA-256 of a file.
 * @param {string} file Absolute path.
 * @returns {string} Digest.
 */
function sha256(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

/** Waits until `check()` is true or `ms` passes.
 * @param {() => boolean} check Condition.
 * @param {number} ms Budget in milliseconds.
 * @returns {Promise<boolean>} Whether it became true.
 */
async function until(check, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (check()) return true; await new Promise(r => setTimeout(r, 200)); }
  return check();
}

/** Runs one bounded `codex exec --json` and records its events.
 * @param {string[]} args Arguments after `exec`.
 * @param {string} file Event log name inside the evidence directory.
 * @returns {Promise<object[]>} Parsed events.
 */
function exec(args, file) {
  return new Promise(resolve => {
    const events = [];
    const child = spawn(codex, ['exec', '--json', '--skip-git-repo-check', '--sandbox', 'read-only', ...args],
      { cwd: dir, stdio: ['ignore', 'pipe', fs.openSync(path.join(dir, file + '.stderr'), 'w')] });
    children.push(child);
    const log = fs.createWriteStream(path.join(dir, file));
    readline.createInterface({ input: child.stdout }).on('line', line => { log.write(line + '\n'); try { events.push(JSON.parse(line)); } catch {} });
    const timer = setTimeout(() => child.kill('SIGTERM'), 300000);
    child.on('exit', () => { clearTimeout(timer); resolve(events); });
  });
}

/** Runs the probe and writes `checks.json`. */
async function main() {
  const model = process.env.CODEX_PROBE_MODEL ? ['-m', process.env.CODEX_PROBE_MODEL] : [];
  const phase1 = await exec([...model, '-c', 'model_reasoning_effort="low"', 'Reply READY and nothing else. Use no tools.'], 'phase1.jsonl');
  const thread = (phase1.find(e => e.type === 'thread.started') || {}).thread_id;
  if (!thread) throw new Error('phase 1 created no thread');
  const host = 'probe-host', namespace = 'codex-probe';
  const store = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
  const recipient = `${host}/codex/${namespace}/${thread}`;
  const token = crypto.randomBytes(24).toString('hex');
  const channelDir = path.join(dir, 'ch'); fs.mkdirSync(channelDir, { mode: 0o700 });
  const channel = path.join(channelDir, 'c.sock'), core = path.join(dir, 'core.sock');
  const evidence = path.join(dir, 'probe.jsonl');
  fs.writeFileSync(path.join(dir, 'bridge.toml'), [
    `database = "${dir}/bridge.db"`, `socket = "${core}"`, '[limits]', 'max_admitted_events = 100',
    '[[grant]]', `token = "${token}"`, 'publisher = "bridge-probe"', `recipients = ["${recipient}"]`,
    'kinds = ["bridge.probe"]', 'modes = ["inject", "message"]', 'policies = ["keep_all"]',
    '[adapters]', `channel = "${channel}"`, `host_id = "${host}"`,
    '[[adapters.profiles]]', `namespace = "${namespace}"`, 'harness = "Codex"', `store = "${store}"`,
    '[[adapters.profiles.executables]]', `path = "${codex}"`, `sha256 = "${sha256(codex)}"`,
    'version = "probe"', 'inject = true', 'message = true', ''].join('\n'));
  const daemon = spawn(path.join(bin, 'bridge-native-daemon'), [path.join(dir, 'bridge.toml')], { stdio: ['ignore', 'ignore', fs.openSync(path.join(dir, 'daemon.stderr'), 'w')] });
  children.push(daemon);
  if (!await until(() => fs.existsSync(channel), 5000)) throw new Error('daemon channel did not start');

  // Only configured server *names* are read, to disable them for this run.
  let names = [];
  try { names = [...fs.readFileSync(path.join(store, 'config.toml'), 'utf8').matchAll(/^\[mcp_servers\.([A-Za-z0-9_-]+)\]/gm)].map(m => m[1]); } catch {}
  const hook = `[{matcher="",hooks=[{type="command",command="'${path.join(bin, 'bridge-hook')}' '${channel}' codex",timeout=5}]}]`;
  const overrides = [
    ...names.filter(n => n !== 'bridge_probe').flatMap(n => ['-c', `mcp_servers.${n}.enabled=false`]),
    '-c', `mcp_servers.bridge_probe.command=${JSON.stringify(path.join(bin, 'bridge-fixture'))}`,
    '-c', `mcp_servers.bridge_probe.args=${JSON.stringify(['mcp-server', channel, core, token, evidence])}`,
    '-c', 'features.multi_agent=true', '-c', 'model_reasoning_effort="low"',
    ...['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'].flatMap(e => ['-c', `hooks.${e}=${hook}`]),
  ];
  const events = await exec([...model, ...overrides, 'resume', thread,
    'This is an isolated Agent Bridge qualification run. First call the bridge_probe MCP tool exactly once with {}. Then create exactly one native child agent whose only task is to call the same bridge_probe tool once with {} and finish CHILD_DONE; wait for it. Finally reply with every BRIDGE_CTX_ marker you can see in your context, or NONE. Do not read files or run commands.'], 'events.jsonl');
  daemon.kill('SIGTERM');
  await until(() => daemon.exitCode !== null, 10000);

  const records = fs.existsSync(evidence) ? fs.readFileSync(evidence, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
  const root = records.find(r => r.caller && r.caller.role === 'root');
  const child = records.find(r => r.caller && r.caller.role === 'child');
  const replies = events.filter(e => e.type === 'item.completed' && e.item && e.item.type === 'agent_message').map(e => e.item.text || '').join('\n');
  const stderr = fs.readFileSync(path.join(dir, 'daemon.stderr'), 'utf8');
  const checks = {
    codex, thread, dir,
    meta_keys_seen: records.map(r => r.meta_keys),
    refusals: records.filter(r => r.refused).map(r => r.refused),
    root_attested: Boolean(root && root.caller.native_id === thread && root.caller.may_act_as_address),
    root_call_id_joined_pre_tool_use: Boolean(root),
    inject_marker_in_reply: Boolean(root && root.marker && replies.includes(root.marker)),
    child_attested_own_thread: Boolean(child && child.caller.native_id !== thread && child.caller.address.endsWith('/' + child.caller.native_id)),
    daemon_events: Object.fromEntries([...stderr.matchAll(/"event":"([a-z_]+)"/g)].map(m => m[1]).reduce((map, e) => map.set(e, (map.get(e) || 0) + 1), new Map())),
    token_in_daemon_log: stderr.includes(token),
  };
  fs.writeFileSync(path.join(dir, 'checks.json'), JSON.stringify(checks, null, 2));
  const required = ['root_attested', 'inject_marker_in_reply', 'child_attested_own_thread'];
  console.log(JSON.stringify({ dir, passed: required.filter(k => checks[k]), failed: required.filter(k => !checks[k]), refusals: checks.refusals }));
  process.exitCode = required.every(k => checks[k]) && !checks.token_in_daemon_log ? 0 : 1;
}

main().catch(error => { console.error(`probe failed: ${error.message}; evidence ${dir}`); process.exitCode = 2; });
