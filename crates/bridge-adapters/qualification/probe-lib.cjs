/**
 * Shared lifecycle for the root-run native qualification probes.
 *
 * One absolute total budget bounds every wait. Every child runs as its own
 * process group (`detached`), and cleanup on every path (success, error,
 * timeout, signal) sends SIGTERM to each group, waits a bounded grace,
 * sends SIGKILL, awaits each exit, then sweeps for any surviving process
 * whose command line names this probe's private directory or session and
 * records it as an orphan (a failure). Logs are flushed before the result
 * is written. Synthetic grant tokens live only in 0600 files inside a 0700
 * credentials directory that cleanup deletes; they never appear in argv,
 * logs, model input or the result. Nothing here reads native credentials or
 * edits any existing configuration.
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const readline = require('node:readline');

/** Time granted to registered cleanup actions beyond an exhausted budget. */
const CLEANUP_ALLOWANCE_MS = 60_000;

/** A probe run: private directory, budget, children, checks, failures. */
class Probe {
  /**
   * @param {string} name Short probe name (directory prefix).
   * @param {number} budgetMs Absolute total budget in milliseconds.
   */
  constructor(name, budgetMs) {
    /** @type {string} Private evidence directory (0700, fresh). */
    this.dir = fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
    fs.chmodSync(this.dir, 0o700);
    /** @type {string} Credentials directory (0700), deleted by cleanup. */
    this.creds = path.join(this.dir, 'creds');
    fs.mkdirSync(this.creds, { mode: 0o700 });
    /** @type {number} Absolute deadline (epoch ms). */
    this.deadline = Date.now() + budgetMs;
    /** @type {{name:string, child:import('node:child_process').ChildProcess, exit:Promise<object>, log:fs.WriteStream|null}[]} */
    this.children = [];
    /** @type {Record<string, unknown>} Recorded checks and facts. */
    this.checks = {};
    /** @type {string[]} Failure categories (any one fails the probe). */
    this.failures = [];
    /** @type {string[]} Strings that must never appear in evidence. */
    this.secrets = [];
    /** @type {string[]} Extra markers identifying this probe's processes. */
    this.markers = [this.dir];
    /** @type {{name: string, action: () => Promise<void>}[]} Registered cleanup actions. */
    this.cleanups = [];
    /** @type {'running'|'cleanup'|'closed'} Lifecycle fence: once cleanup starts only
     * registered cleanup actions may start processes; once closed none may. */
    this.phase = 'running';
  }

  /** Refuses a new process when the lifecycle fence forbids it (a body
   * resumed after a timeout or signal started cleanup), recording
   * `late_spawn:<name>`. During cleanup only a start that both happens
   * inside a registered cleanup action and is marked `cleanup` passes, so a
   * body resuming concurrently with a cleanup action is still refused.
   * @param {string} name Label of the refused process.
   * @param {boolean} [cleanup] Whether the caller is a registered cleanup action.
   */
  fence(name, cleanup = false) {
    if (this.phase === 'closed' || (this.phase === 'cleanup' && !(cleanup && this.inCleanupAction))) {
      this.fail(`late_spawn:${name}`);
      throw new Error(`probe is closing; ${name} not started`);
    }
  }

  /** Registers a cleanup action that `finish` runs on every path (success,
   * error, timeout, signal) before terminating children, with its own
   * fixed allowance (CLEANUP_ALLOWANCE_MS) even when the budget is spent.
   * An action that throws records `cleanup_failed:<name>`; actions must
   * record their own outcome as checks.
   * @param {string} name Label.
   * @param {() => Promise<void>} action Idempotent async action.
   */
  onCleanup(name, action) { this.cleanups.push({ name, action }); }

  /** Milliseconds left in the total budget (never negative). */
  remaining() { return Math.max(0, this.deadline - Date.now()); }

  /** Records a failure category once.
   * @param {string} category Failure category.
   */
  fail(category) { if (!this.failures.includes(category)) this.failures.push(category); }

  /** Writes a fresh synthetic token to an owned 0600 file.
   * @param {string} name File name inside the credentials directory.
   * @returns {{token: string, file: string}} The token (kept in memory) and its file.
   */
  credential(name) {
    const token = crypto.randomBytes(24).toString('hex');
    const file = path.join(this.creds, name);
    fs.writeFileSync(file, token, { mode: 0o600 });
    this.secrets.push(token);
    return { token, file };
  }

  /** Lowercase hex SHA-256 of a file (streamed).
   * @param {string} file Absolute path.
   * @returns {string} Digest.
   */
  sha256(file) {
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(file, 'r');
    const buffer = Buffer.alloc(1 << 20);
    try { for (let n; (n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0;) hash.update(buffer.subarray(0, n)); }
    finally { fs.closeSync(fd); }
    return hash.digest('hex');
  }

  /** Spawns a child in its own process group, logging stdout lines and
   * stderr to files in the evidence directory.
   *
   * The stderr file descriptor is closed in this process right after the
   * spawn (the child keeps its own copy). With `stderrMatch`, stderr is
   * never written anywhere instead: it is read through a pipe and reduced
   * in memory to `child.stderrSummary` = `{stderr_bytes, matched}`
   * (`matched`: `stderrMatch` matched the stream, checked across chunk
   * boundaries over a 256-character carry), so no file holds raw stderr on
   * any path, including a signal, a thrown error or a child that keeps
   * writing after it should have exited. `closed` resolves only when the
   * child exited *and* all its stdio ended (or the spawn failed), so every
   * stdout line, including a final line without newline, is logged before
   * the log is ended. A spawn failure records `spawn_error:<name>`.
   * @param {string} name Label (log file prefix).
   * @param {string} file Executable.
   * @param {string[]} args Arguments (never secrets).
   * @param {{cwd?: string, env?: NodeJS.ProcessEnv, stdin?: boolean, cleanup?: boolean, keep?: (line: string) => string|null, stderrMatch?: RegExp}} [options] Extra spawn options; `cleanup` marks a registered cleanup action's own process; `keep` maps each stdout line *before* it is logged or handed to `onLine` (null drops it), so a line it rewrites is never written or retained anywhere; `stderrMatch` (a non-global RegExp) replaces the stderr file by the in-memory summary above.
   * @param {(line: string) => void} [onLine] Called for each kept stdout line.
   * @returns {import('node:child_process').ChildProcess} The child.
   */
  spawn(name, file, args, options = {}, onLine) {
    this.fence(name, options.cleanup === true);
    if (args.some(arg => this.secrets.some(secret => arg.includes(secret)))) throw new Error('secret in argv');
    const reduce = options.stderrMatch instanceof RegExp;
    const fd = reduce ? null : fs.openSync(path.join(this.dir, `${name}.stderr`), 'w');
    let child;
    try {
      child = spawn(file, args, {
        cwd: options.cwd || this.dir,
        env: options.env || process.env,
        detached: true,
        stdio: [options.stdin ? 'pipe' : 'ignore', 'pipe', reduce ? 'pipe' : fd],
      });
    } finally { if (fd !== null) fs.closeSync(fd); }
    if (reduce) {
      const summary = { stderr_bytes: 0, matched: false };
      let carry = '';
      child.stderr.on('data', chunk => {
        summary.stderr_bytes += chunk.length;
        const text = carry + chunk.toString('latin1');
        if (options.stderrMatch.test(text)) summary.matched = true;
        carry = text.slice(-256);
      });
      child.stderrSummary = summary;
    }
    const log = fs.createWriteStream(path.join(this.dir, `${name}.stdout`));
    const lines = readline.createInterface({ input: child.stdout });
    lines.on('line', raw => {
      const line = options.keep ? options.keep(raw) : raw;
      if (line === null) return;
      log.write(line + '\n');
      if (onLine) onLine(line);
    });
    const exit = new Promise(resolve => {
      child.once('error', error => { this.fail(`spawn_error:${name}`); resolve({ error: error.code || String(error) }); });
      child.once('exit', (code, signal) => resolve({ code, signal }));
    });
    const ended = new Promise(resolve => lines.once('close', resolve));
    const closed = Promise.all([
      new Promise(resolve => { child.once('close', resolve); child.once('error', resolve); }),
      ended,
    ]).then(() => true);
    this.children.push({ name, child, exit, closed, log, lines });
    return child;
  }

  /** Waits for `check()` within `ms` and the total budget.
   * @param {() => boolean} check Condition.
   * @param {number} ms Local bound.
   * @returns {Promise<boolean>} Whether it became true (false on budget).
   */
  async until(check, ms) {
    const end = Math.min(Date.now() + ms, this.deadline);
    while (Date.now() < end) { if (check()) return true; await new Promise(r => setTimeout(r, 200)); }
    if (!check() && Date.now() >= this.deadline) this.fail('budget_exhausted');
    return check();
  }

  /** Waits for one child's exit within `ms` and the budget.
   * @param {import('node:child_process').ChildProcess} child Child.
   * @param {number} ms Bound.
   * @returns {Promise<{code: number|null, signal: string|null}|{error: string}|null>} Exit, or null on timeout or exhausted budget.
   */
  async exited(child, ms) {
    const entry = this.children.find(c => c.child === child);
    const bound = Math.min(ms, this.remaining());
    if (bound <= 0) { this.fail('budget_exhausted'); return null; }
    // Dispose the losing timer so a completed child does not keep the probe
    // alive until the bound expires (root-observed 8-minute wrapper hang).
    let timeout;
    try {
      const timer = new Promise(r => { timeout = setTimeout(() => r(null), bound); });
      return await Promise.race([entry.exit, timer]);
    } finally { clearTimeout(timeout); }
  }

  /** Runs a short local command (no model) and returns trimmed stdout.
   *
   * Refused without running when the total budget is exhausted (a zero
   * timeout would mean no bound at all); otherwise bounded by
   * min(30 s, remaining budget).
   * @param {string} file Executable.
   * @param {string[]} args Arguments (never secrets).
   * @returns {string} Output, or `error:<message>`.
   */
  local(file, args) {
    try { this.fence(path.basename(file)); } catch { return 'error:probe_closing'; }
    if (args.some(arg => this.secrets.some(secret => arg.includes(secret)))) throw new Error('secret in argv');
    const bound = Math.min(30000, this.remaining());
    if (bound <= 0) { this.fail('budget_exhausted'); return 'error:budget_exhausted'; }
    try { return execFileSync(file, args, { encoding: 'utf8', maxBuffer: 64 << 20, timeout: bound }).trim(); }
    catch (error) { return `error:${String(error.message).split('\n')[0].slice(0, 200)}`; }
  }

  /** Replaces every synthetic secret in `text` with `<redacted>`.
   * @param {string} text Text to clean.
   * @returns {{text: string, found: boolean}} Cleaned text and whether a secret was present.
   */
  redact(text) {
    let found = false;
    for (const secret of this.secrets) if (text.includes(secret)) { found = true; text = text.split(secret).join('<redacted>'); }
    return { text, found };
  }

  /** Terminates every process group (TERM, bounded grace, KILL), waits for
   * each child to exit and its stdio to end, flushes logs, sweeps for
   * orphans, deletes credentials, redacts and writes `checks.json`.
   *
   * Registered cleanup actions run first (see `onCleanup`).
   *
   * Failures recorded here: `cleanup_failed:<name>`, `unreaped:<name>` (no exit after KILL),
   * `unclosed:<name>` (stdio still open after KILL, e.g. an escaped
   * descendant holds it; the stream is then destroyed so the log can end),
   * `orphan_processes`, `secret_in_evidence:<file>` (the file is redacted in
   * place), `secret_in_result`, `check_failed:<name>`, `check_missing:<name>`.
   * @param {string[]} required Check names that must be exactly `true`.
   * @returns {Promise<number>} Process exit code (0 only when everything passed).
   */
  async finish(required) {
    this.phase = 'cleanup';
    if (this.cleanups.length) {
      this.deadline = Math.max(this.deadline, Date.now() + CLEANUP_ALLOWANCE_MS);
      for (const { name, action } of this.cleanups.splice(0)) {
        this.inCleanupAction = true;
        try { await action(); } catch (error) { this.fail(`cleanup_failed:${name}`); }
        finally { this.inCleanupAction = false; }
      }
    }
    this.phase = 'closed';
    for (const { child } of this.children) { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }
    const grace = new Promise(r => setTimeout(r, 5000));
    await Promise.race([Promise.all(this.children.map(c => c.closed)), grace]);
    for (const { child } of this.children) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
    const exits = {};
    for (const entry of this.children) {
      const closed = await Promise.race([entry.closed, new Promise(r => setTimeout(() => r(false), 3000))]);
      const exit = await Promise.race([entry.exit, new Promise(r => setTimeout(() => r(null), 100))]);
      if (!closed) {
        this.fail(`unclosed:${entry.name}`);
        if (entry.child.stdout) entry.child.stdout.destroy();
        if (entry.child.stderr) entry.child.stderr.destroy();
        entry.lines.close();
      }
      if (!exit) this.fail(`unreaped:${entry.name}`);
      exits[entry.name] = exit || { unreaped: true };
      await new Promise(r => entry.log.end(r));
    }
    this.checks.exits = exits;
    const orphans = this.sweep();
    this.checks.orphans = orphans;
    if (orphans.length) this.fail('orphan_processes');
    fs.rmSync(this.creds, { recursive: true, force: true });
    for (const file of fs.readdirSync(this.dir)) {
      const full = path.join(this.dir, file);
      if (!fs.statSync(full).isFile()) continue;
      const cleaned = this.redact(fs.readFileSync(full, 'utf8'));
      if (cleaned.found) { this.fail(`secret_in_evidence:${file}`); fs.writeFileSync(full, cleaned.text); }
    }
    for (const name of required) {
      if (!(name in this.checks)) this.fail(`check_missing:${name}`);
      else if (this.checks[name] !== true) this.fail(`check_failed:${name}`);
    }
    if (this.redact(JSON.stringify(this.checks)).found) this.fail('secret_in_result');
    const { text } = this.redact(JSON.stringify({ dir: this.dir, failures: this.failures, checks: this.checks }, null, 2));
    fs.writeFileSync(path.join(this.dir, 'checks.json'), text);
    console.log(this.redact(JSON.stringify({ dir: this.dir, failures: this.failures })).text);
    return this.failures.length === 0 ? 0 : 1;
  }

  /** Kills and reports any surviving process naming a probe marker.
   * @returns {{pid: number, command: string}[]} Survivors found.
   */
  sweep() {
    let table = '';
    try { table = execFileSync('/bin/ps', ['-A', '-o', 'pid=,command='], { encoding: 'utf8' }); } catch { return [{ pid: 0, command: 'ps unavailable' }]; }
    const found = [];
    for (const line of table.split('\n')) {
      const match = line.trim().match(/^(\d+)\s+(.*)$/);
      if (!match || Number(match[1]) === process.pid) continue;
      if (this.markers.some(marker => match[2].includes(marker))) {
        found.push({ pid: Number(match[1]), command: this.redact(match[2].slice(0, 160)).text });
        try { process.kill(Number(match[1]), 'SIGKILL'); } catch {}
      }
    }
    return found;
  }
}

/** Runs `main(probe)` with cleanup on every path, including signals.
 * @param {string} name Probe name.
 * @param {number} budgetMs Total budget.
 * @param {string[]} required Required checks.
 * @param {(probe: Probe) => Promise<void>} main Probe body.
 * @returns {Promise<Probe>} Resolves with the probe after `finish` wrote its result.
 */
function run(name, budgetMs, required, main) {
  const probe = new Probe(name, budgetMs);
  let finishing = null;
  const done = () => {
    if (!finishing) finishing = probe.finish(required).then(code => { process.exitCode = code; return probe; });
    return finishing;
  };
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { probe.fail(`signal:${signal}`); done().then(() => process.exit()); });
  const timer = setTimeout(() => { probe.fail('budget_exhausted'); done().then(() => process.exit()); }, budgetMs + 15000);
  return main(probe)
    .catch(error => { probe.fail(`error:${String(error.message).slice(0, 120)}`); })
    .then(() => { clearTimeout(timer); return done(); });
}

/** Tracks native turn and background-task state from a Claude stream-json
 * receiver, so a probe can wait for an *authoritative* idle state instead
 * of trusting model text.
 *
 * A turn starts with `system/init` and ends with `result`; a background
 * child starts with `system/task_started` and ends with
 * `system/task_notification` (its `status`), both carrying the same
 * `task_id`. The receiver is idle when every started turn has a result,
 * no task is still running, and no event arrived for `quietMs` (a
 * completion notification can start a follow-up turn shortly after).
 */
class TurnTracker {
  /** @param {() => number} [clock] Millisecond clock (injectable for the control). */
  constructor(clock = Date.now) {
    /** @type {() => number} Clock. */
    this.clock = clock;
    /** @type {number} Turns started (`system/init`). */
    this.started = 0;
    /** @type {number} Turns finished (`result`). */
    this.finished = 0;
    /** @type {Map<string, string>} Background task id -> `running` or its final status. */
    this.tasks = new Map();
    /** @type {number} Time of the latest turn/task event. */
    this.lastEventAt = clock();
  }

  /** Feeds one parsed stream-json event.
   * @param {{type?: string, subtype?: string, task_id?: string, status?: string}} event Event.
   */
  observe(event) {
    if (event.type === 'system' && event.subtype === 'init') this.started++;
    else if (event.type === 'result') this.finished++;
    else if (event.type === 'system' && event.subtype === 'task_started' && event.task_id) this.tasks.set(event.task_id, 'running');
    else if (event.type === 'system' && event.subtype === 'task_notification' && event.task_id) this.tasks.set(event.task_id, String(event.status || 'unknown'));
    else return;
    this.lastEventAt = this.clock();
  }

  /** Task ids still running. @returns {string[]} */
  running() { return [...this.tasks].filter(([, state]) => state === 'running').map(([id]) => id); }

  /** Whether the receiver is authoritatively idle for at least `quietMs`.
   * @param {number} quietMs Required quiet interval in milliseconds.
   * @returns {boolean}
   */
  idle(quietMs) {
    return this.started === this.finished && this.running().length === 0 && this.clock() - this.lastEventAt >= quietMs;
  }
}

module.exports = { Probe, run, TurnTracker };

/** The exact failure set the lifecycle self-test must produce. */
const SELF_TEST_EXPECTED = ['cleanup_failed:boom', 'late_spawn:unmarked', 'spawn_error:missing', 'unclosed:escaper', 'orphan_processes',
  'secret_in_evidence:leak.txt', 'secret_in_result', 'check_missing:never_set'].sort();

// Self-test of the lifecycle itself (no model, no native harness). It
// passes only when cleanup produces exactly SELF_TEST_EXPECTED: a missing
// executable is a spawn error; a group with marked grandchildren leaves no
// survivor; a line printed while handling SIGTERM reaches the log; a
// detached descendant holding stdout is reported unclosed and swept as an
// orphan; a leaked synthetic token is redacted in the evidence file and in
// the written result; a missing required check fails; an exhausted budget
// refuses a local command before running it; registered cleanups run and a
// throwing one is reported; after cleanup no process or command starts.
/** Child-completion sequencing control, modelled on the native Q2 stream
 * (task started in the child turn, completion notification arriving
 * during a later turn, then a follow-up turn): idle must not be reported
 * before the follow-up turn ended and the quiet interval passed.
 * @returns {boolean} Whether the tracker sequenced the stream correctly.
 */
function turnTrackerControl() {
  let now = 0;
  const tracker = new TurnTracker(() => now);
  const feed = (event, at) => { now = at; tracker.observe(event); };
  feed({ type: 'system', subtype: 'init' }, 1); feed({ type: 'result' }, 2);
  feed({ type: 'system', subtype: 'init' }, 3);
  feed({ type: 'system', subtype: 'task_started', task_id: 't1' }, 4);
  feed({ type: 'result' }, 5); // the model says the child is in the background
  now = 30; const whileChildRuns = tracker.idle(10);
  feed({ type: 'system', subtype: 'init' }, 31);
  feed({ type: 'system', subtype: 'task_notification', task_id: 't1', status: 'completed' }, 32);
  feed({ type: 'result' }, 33);
  feed({ type: 'system', subtype: 'init' }, 36); // follow-up turn reporting the child
  now = 40; const duringFollowUp = tracker.idle(1);
  feed({ type: 'result' }, 41);
  now = 45; const tooSoon = tracker.idle(10);
  now = 52; const quiet = tracker.idle(10);
  return !whileChildRuns && !duringFollowUp && !tooSoon && quiet;
}

if (require.main === module && process.argv[2] === '--self-test') {
  const keep = 'setInterval(() => {}, 1000)';
  run('m2st', 30000, ['spawned', 'never_set'], async probe => {
    const { token } = probe.credential('selftest.token');
    probe.onCleanup('ran', async () => {
      const child = probe.spawn('cleanup-child', process.execPath, ['-e', '0', probe.dir], { cleanup: true });
      probe.checks.cleanup_ran = Boolean(await probe.exited(child, 5000));
    });
    probe.onCleanup('boom', async () => { throw new Error('boom'); });
    // A start during cleanup that is not marked as the cleanup's own (as a
    // body resuming concurrently would do) is refused.
    probe.onCleanup('unmarked', async () => {
      try { probe.spawn('unmarked', process.execPath, ['-e', '0', probe.dir]); } catch { probe.checks.unmarked_refused = true; }
    });
    probe.spawn('missing', path.join(probe.dir, 'no-such-executable'), []);
    probe.spawn('sleeper', '/bin/sh', ['-c', `"$0" -e '${keep}' "$1" & "$0" -e '${keep}' "$1"`, process.execPath, probe.dir]);
    probe.spawn('trailing', process.execPath, ['-e', `process.on('SIGTERM', () => { process.stdout.write('TRAILING_AFTER_TERM'); setTimeout(() => process.exit(0), 100); }); ${keep}`, probe.dir]);
    probe.spawn('escaper', process.execPath, ['-e',
      `require('child_process').spawn(process.execPath, ['-e', '${keep}', process.argv[1]], { detached: true, stdio: ['ignore', 'inherit', 'ignore'] }).unref()`, probe.dir]);
    fs.writeFileSync(path.join(probe.dir, 'leak.txt'), `leaked ${token}`);
    probe.checks.leaked = token;
    await new Promise(r => setTimeout(r, 800));
    const marked = execFileSync('/bin/ps', ['-A', '-o', 'command='], { encoding: 'utf8' }).split('\n').filter(l => l.includes(probe.dir) && l.includes('-e')).length;
    probe.checks.marked_processes = marked;
    probe.checks.spawned = marked >= 4;
  }).then(probe => {
    const written = fs.readFileSync(path.join(probe.dir, 'checks.json'), 'utf8');
    const trailing = fs.readFileSync(path.join(probe.dir, 'trailing.stdout'), 'utf8').includes('TRAILING_AFTER_TERM');
    const leakRedacted = !fs.readFileSync(path.join(probe.dir, 'leak.txt'), 'utf8').includes(probe.secrets[0]);
    const resultRedacted = !written.includes(probe.secrets[0]) && written.includes('<redacted>');
    const failures = [...probe.failures].sort();
    // An exhausted budget refuses a local command without running it.
    const spent = new Probe('m2sb', 0);
    const started = Date.now();
    const refused = spent.local('/bin/sleep', ['5']) === 'error:budget_exhausted' && Date.now() - started < 1000 && spent.failures.includes('budget_exhausted');
    fs.rmSync(spent.dir, { recursive: true, force: true });
    const cleanupRan = probe.checks.cleanup_ran === true;
    // After cleanup started, a resumed body cannot start anything.
    let lateRefused = false;
    try { probe.spawn('late', process.execPath, ['-e', '0', probe.dir]); } catch { lateRefused = probe.failures.includes('late_spawn:late'); }
    const localRefused = probe.local('/bin/echo', ['x']) === 'error:probe_closing';
    const sequencing = turnTrackerControl();
    const pass = JSON.stringify(failures) === JSON.stringify(SELF_TEST_EXPECTED) && trailing && leakRedacted && resultRedacted && refused && cleanupRan && lateRefused && localRefused && probe.checks.unmarked_refused === true && sequencing;
    console.log(JSON.stringify({ self_test: pass ? 'PASS' : 'FAIL', failures, expected: SELF_TEST_EXPECTED, trailing, leakRedacted, resultRedacted, refused, cleanupRan, lateRefused, localRefused, sequencing }));
    process.exitCode = pass ? 0 : 1;
  });
}
