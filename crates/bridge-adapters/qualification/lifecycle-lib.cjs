/**
 * Shared helpers of the Q4 lifecycle drivers (`claude-lifecycle-probe.cjs`,
 * `frontend-lifecycle-probe.cjs`, `codex-lifecycle-probe.cjs`): the paired
 * network-fence witness, the nested-usage arithmetic, a one-shot Core socket
 * client and a read-only reader of an OWN Core database — logic the drivers
 * must not each re-implement. Pure Node, no native frontend, no
 * external connection: the witness only talks to an OWN loopback listener.
 *
 * `node qualification/lifecycle-lib.cjs --self-test` runs the assertions.
 */
'use strict';
const net = require('node:net');

/** A JSON value: null, boolean, number, string, array of JSON values, or string-keyed object of JSON values.
 * @typedef {null|boolean|number|string|JsonValue[]|{[key: string]: JsonValue}} JsonValue */
/** One Core request line: the snake_case operation name `op` plus that operation's JSON fields.
 * @typedef {{op: string, [field: string]: JsonValue}} CoreRequest */
/** One database row: column name to SQLite scalar (SQL NULL is `null`).
 * @typedef {{[column: string]: string|number|null}} DbRow */
/** Outcome of the paired network witness: the bounded child outputs (`connected` or a socket error code) and the verdict.
 * @typedef {{open: string, fenced: string, ok: boolean}} FenceWitness */

/** Child program of the witness: connects to the loopback port in `argv[1]`
 * and prints `connected` or the socket error code (`EPERM`, `ECONNREFUSED`,
 * ...), then exits (bounded by its own 3 s timer).
 * @type {string}
 */
const CONNECT_PROGRAM = "const c=require('net').connect({host:'127.0.0.1',port:Number(process.argv[1])});"
  + "c.on('connect',()=>{console.log('connected');c.destroy();process.exit(0)});"
  + "c.on('error',e=>{console.log(e.code||'ERROR');process.exit(0)});setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},3000)";

/** Decides the paired witness: the unconfined connect to the owned loopback
 * listener must succeed and the SAME connect under the policy must fail
 * with a permission denial (`EPERM`/`EACCES`) — a refused, unreachable or
 * timed-out connect is not a positive fence witness.
 * @param {string} open Child output of the unconfined connect.
 * @param {string} fenced Child output of the connect under the policy.
 * @returns {boolean} Whether the fence is positively witnessed.
 */
function fenceVerdict(open, fenced) {
  return open.trim() === 'connected' && /^(EPERM|EACCES)$/.test(fenced.trim());
}

/** Runs the paired witness against an OWN loopback listener: starts a
 * bounded listener on `127.0.0.1` (ephemeral port, closed before return),
 * connects once without confinement (must succeed) and once under
 * `sandbox-exec -p policy` (must be denied). No external address is
 * contacted.
 * @param {import('./probe-lib.cjs').Probe} probe The probe (its bounded `local` runs the children).
 * @param {string} policy The Seatbelt policy under test.
 * @returns {Promise<FenceWitness>} Raw child outputs (bounded) and the verdict.
 * @throws {Error} The loopback listener could not start (the promise rejects).
 */
async function networkFenceWitness(probe, policy) {
  const server = net.createServer(socket => socket.destroy());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  try {
    const { port } = server.address();
    const open = probe.local(process.execPath, ['-e', CONNECT_PROGRAM, String(port)]);
    const fenced = probe.local('/usr/bin/sandbox-exec', ['-p', policy, process.execPath, '-e', CONNECT_PROGRAM, String(port)]);
    return { open: open.slice(0, 60), fenced: fenced.slice(0, 60), ok: fenceVerdict(open, fenced) };
  } finally { await new Promise(resolve => server.close(resolve)); }
}

/** Sums every finite number in a usage-like value, recursing into nested
 * objects and arrays; strings, booleans and null add nothing.
 * @param {JsonValue} value A usage block or any JSON value.
 * @returns {number} The sum of all finite numbers found (0 for none).
 */
function usageTotal(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
  if (Array.isArray(value)) return value.reduce((sum, item) => sum + usageTotal(item), 0);
  if (value && typeof value === 'object') return Object.values(value).reduce((sum, item) => sum + usageTotal(item), 0);
  return 0;
}

/** Sends one request line to the Core service socket of an OWN daemon and
 * returns its one response line, parsed. Used for the operator `dispose`
 * the bundled fixture has no mode for; the request carries a synthetic
 * grant token held only in memory (never argv, never logged).
 * @param {string} socket Absolute path of the Core socket.
 * @param {CoreRequest} request One `Request` (internally tagged by `op`, snake_case).
 * @param {number} [ms] Bound for the whole exchange (default 10000).
 * @returns {Promise<JsonValue|string>} The parsed response, or an `error:...` string (unreachable, timeout, unparsable).
 */
function coreCall(socket, request, ms = 10000) {
  return new Promise(resolve => {
    const client = net.connect(socket);
    let buffer = '';
    const timer = setTimeout(() => { client.destroy(); resolve('error:timeout'); }, ms);
    client.on('connect', () => client.write(JSON.stringify(request) + '\n'));
    client.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const end = buffer.indexOf('\n');
      if (end < 0) return;
      clearTimeout(timer); client.destroy();
      try { resolve(JSON.parse(buffer.slice(0, end))); } catch { resolve('error:unparsable'); }
    });
    client.on('error', error => { clearTimeout(timer); resolve(`error:${error.code || 'socket'}`); });
  });
}

/** Reads rows of an OWN Core database read-only (`sqlite3 -readonly -json`).
 * @param {import('./probe-lib.cjs').Probe} probe The probe (bounded `local`).
 * @param {string} database Absolute database path.
 * @param {string} sql One SELECT statement (no external input interpolated by callers).
 * @returns {DbRow[]} Rows; empty when the file or output is unreadable (callers must treat empty as unproven, never as absence).
 */
function dbRows(probe, database, sql) {
  if (!require('node:fs').existsSync(database)) return [];
  const out = probe.local('/usr/bin/sqlite3', ['-readonly', '-json', database, sql]);
  try { return out ? JSON.parse(out) : []; } catch { return []; }
}

/** The helpers shared by the Q4 lifecycle drivers.
 * @type {{fenceVerdict: (open: string, fenced: string) => boolean, networkFenceWitness: (probe: import('./probe-lib.cjs').Probe, policy: string) => Promise<FenceWitness>, usageTotal: (value: JsonValue) => number, coreCall: (socket: string, request: CoreRequest, ms?: number) => Promise<JsonValue|string>, dbRows: (probe: import('./probe-lib.cjs').Probe, database: string, sql: string) => DbRow[]}} */
module.exports = { fenceVerdict, networkFenceWitness, usageTotal, coreCall, dbRows };

if (require.main === module && process.argv[2] === '--self-test') {
  const assert = require('node:assert/strict');
  const { Probe } = require('./probe-lib.cjs');
  const fs = require('node:fs');
  assert.equal(fenceVerdict('connected', 'EPERM'), true);
  assert.equal(fenceVerdict('connected', 'EACCES'), true);
  assert.equal(fenceVerdict('connected', 'ECONNREFUSED'), false); // an unreachable port is not a fence
  assert.equal(fenceVerdict('connected', 'TIMEOUT'), false);
  assert.equal(fenceVerdict('connected', 'connected'), false); // the policy let it through
  assert.equal(fenceVerdict('ECONNREFUSED', 'EPERM'), false); // no unconfined success: the pair is void
  assert.equal(usageTotal({ a: 0, b: { c: [0, 2] }, d: 'x' }), 2);
  // Actual local witness: the owned-loopback pair under a real policy, then
  // the same pair under a policy that allows the network (must NOT pass).
  (async () => {
    const probe = new Probe('q4lib', 60_000);
    try {
      const fenced = await networkFenceWitness(probe, '(version 1)(allow default)(deny network-outbound (remote ip))');
      const unfenced = await networkFenceWitness(probe, '(version 1)(allow default)');
      assert.equal(fenced.ok, true, JSON.stringify(fenced));
      assert.equal(unfenced.ok, false, JSON.stringify(unfenced)); // negative control: a policy that denies nothing is not witnessed
      console.log(JSON.stringify({ self_test: 'PASS', fenced, unfenced }));
    } finally { fs.rmSync(probe.dir, { recursive: true, force: true }); }
  })().catch(error => { console.log(JSON.stringify({ self_test: 'FAIL', error: String(error.message).slice(0, 300) })); process.exitCode = 1; });
}
