/** Synthetic lifecycle contract check; no native sessions, sockets or models. */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { Writable } from 'node:stream';

test('native facts preserve prompt data, correlate children and invalidate a lost feed', { timeout: 5000 }, async () => {
  /** @type {Array<Record<string,string>>} Metadata sent to the existing hook client. */
  const calls = [];
  /** @type {Array<()=>void>} Checkpoints resolved by actual hook writes. */
  const checkpoints = [];
  mock.method(childProcess, 'execFile', (command, args, options, callback) => {
    assert.equal(command, '/owned/hook');
    assert.deepEqual(args, ['/owned/channel', 'opencode']);
    assert.equal(options.timeout, 5000);
    return { stdin: new Writable({ write(bytes, encoding, done) {
      calls.push(JSON.parse(bytes.toString()));
      for (const checkpoint of checkpoints.splice(0)) checkpoint();
      done(); callback(null, '', '');
    } }) };
  });
  syncBuiltinESMExports();
  const { default: plugin } = await import('./index.js');
  /** @type {Map<string,(event:object)=>Promise<void>>} Native registered callbacks. */
  const hooks = new Map();
  /** @type {(value:{done:boolean,value?:object})=>void} Active native event consumer. */
  let next;
  /** @type {number} Disposed hook registrations. */
  let disposed = 0;
  const context = {
    app: { version: '2.0.28' }, options: { channel: '/owned/channel', hookCommand: '/owned/hook' },
    session: { get: async ({ sessionID }) => ({ id: sessionID, ...(sessionID === 'child' ? { parentID: 'root' } : {}) }),
      hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => { disposed++; } }; } },
    tool: { hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => { disposed++; } }; } },
    event: { subscribe: async () => ({ [Symbol.asyncIterator]: () => ({
      next: () => new Promise(resolve => { next = resolve; }),
      return: async () => { next({ done: true }); return { done: true }; },
    }) }) },
  };
  /** Wait for actual completed hook writes; no timing-based readiness claim.
   * @param {number} count Required emitted metadata records. @returns {Promise<void>} Checkpoint. */
  async function until(count) {
    while (calls.length < count) await new Promise(resolve => checkpoints.push(resolve));
  }
  try {
    const dispose = await plugin.setup(context);
    const prompt = Object.freeze({ sessionID: 'root', messageID: 'message', prompt: Object.freeze({ text: 'PRIVATE_PROMPT' }) });
    await hooks.get('prompt')(prompt);
    assert.deepEqual(calls.map(value => value.hook_event_name), ['SessionStart', 'OpenCodeActivity']);
    next({ done: false, value: { type: 'session.execution.succeeded', data: { sessionID: 'root' } } });
    await until(3);
    assert.equal(calls[2].hook_event_name, 'Stop');
    await hooks.get('execute.before')({ sessionID: 'child', id: 'native-call', tool: 'finish', input: { secret: 'PRIVATE_ARGUMENT' } });
    assert.deepEqual(calls.slice(3).map(value => [value.hook_event_name, value.agent_id]), [['SessionStart', 'child'], ['PreToolUse', 'child']]);
    assert.equal(calls[4].tool_use_id, 'native-call');
    next({ done: true });
    await until(7);
    assert.deepEqual(calls.slice(5).map(value => value.hook_event_name), ['OpenCodeUnknown', 'OpenCodeUnknown']);
    await hooks.get('prompt')({ sessionID: 'root' });
    assert.equal(calls.length, 7);
    await dispose();
    assert.equal(disposed, 2);
    assert.equal(JSON.stringify(calls).includes('PRIVATE_'), false);
    await assert.rejects(plugin.setup({ ...context, app: { version: 'other' } }));
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});
