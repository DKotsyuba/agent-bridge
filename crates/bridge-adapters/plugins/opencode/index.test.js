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
    assert.equal(calls.length, 7, 'feed loss and later disposal share one final invalidation');
    assert.equal(JSON.stringify(calls).includes('PRIVATE_'), false);
    await assert.rejects(plugin.setup({ ...context, app: { version: 'other' } }));
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});

for (const failedStage of ['prompt', 'return', 'both']) test(`cleanup awaits feed, return and drain after ${failedStage} rejection`, { timeout: 5000 }, async () => {
  /** @type {Array<Record<string,string>>} Metadata sent to the existing hook client. */
  const calls = [];
  /** @type {Array<()=>void>} Checkpoints resolved by actual hook writes. */
  const checkpoints = [];
  /** @type {(()=>void)|undefined} Completion of the withheld in-flight `PreToolUse` hook. */
  let release;
  /** @type {()=>void} Completion of the independently withheld iterator return. */
  let returnRelease;
  /** @type {Promise<void>} Controlled native iterator-return completion. */
  const returning = new Promise(resolve => { returnRelease = resolve; });
  /** @type {()=>void} Completion of the independently withheld feed read. */
  let feedRelease;
  mock.method(childProcess, 'execFile', (command, args, options, callback) => ({ stdin: new Writable({ write(bytes, encoding, done) {
    const payload = JSON.parse(bytes.toString());
    calls.push(payload);
    for (const checkpoint of checkpoints.splice(0)) checkpoint();
    done();
    if (payload.hook_event_name === 'PreToolUse') release = () => callback(null, '', ''); else callback(null, '', '');
  } }) }));
  syncBuiltinESMExports();
  const { default: plugin } = await import('./index.js');
  /** @type {Map<string,(event:object)=>Promise<void>>} Native registered callbacks. */
  const hooks = new Map();
  /** @type {{prompt:number,tool:number,returned:number}} Disposal stage counters. */
  const stages = { prompt: 0, tool: 0, returned: 0 };
  const failure = new Error('prompt dispose failed');
  const returnFailure = new Error('iterator return failed');
  const context = {
    app: { version: '2.0.28' }, options: { channel: '/owned/channel', hookCommand: '/owned/hook' },
    session: { get: async ({ sessionID }) => ({ id: sessionID }),
      hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => { stages.prompt++; if (failedStage !== 'return') throw failure; } }; } },
    tool: { hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => { stages.tool++; } }; } },
    event: { subscribe: async () => ({ [Symbol.asyncIterator]: () => ({
      next: () => new Promise(resolve => { feedRelease = () => resolve({ done: true }); }),
      return: async () => { stages.returned++; await returning; if (failedStage !== 'prompt') throw returnFailure; return { done: true }; },
    }) }) },
  };
  try {
    const dispose = await plugin.setup(context);
    await hooks.get('prompt')({ sessionID: 'root' });
    assert.deepEqual(calls.map(value => value.hook_event_name), ['SessionStart', 'OpenCodeActivity']);
    const inFlight = hooks.get('execute.before')({ sessionID: 'root', id: 'native-call', tool: 'finish' });
    while (calls.length < 3) await new Promise(resolve => checkpoints.push(resolve));
    let settled = false;
    const completion = dispose();
    const disposal = completion.finally(() => { settled = true; });
    assert.equal(dispose(), completion, 'repeated disposal shares completion');
    const rejected = assert.rejects(disposal, failedStage === 'return' ? returnFailure : failure);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false, 'disposal waits for in-flight serialized work');
    release();
    await inFlight;
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(settled, false, 'disposal awaits native iterator return');
    feedRelease();
    returnRelease();
    await rejected;
    assert.deepEqual(stages, { prompt: 1, tool: 1, returned: 1 });
    assert.deepEqual(calls.slice(2).map(value => value.hook_event_name), ['PreToolUse', 'OpenCodeUnknown']);
    assert.equal(calls.length, 4, 'one invalidation per retained session');
    await hooks.get('prompt')({ sessionID: 'root' });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls.length, 4, 'no background cleanup or observations after disposal');
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});

test('feed cancellation retains no handler per completed native event', { timeout: 10000 }, async () => {
  assert.equal(typeof global.gc, 'function', 'run with --expose-gc');
  mock.method(childProcess, 'execFile', (command, args, options, callback) => ({ stdin: new Writable({ write(bytes, encoding, done) { done(); callback(null, '', ''); } }) }));
  syncBuiltinESMExports();
  const { default: plugin } = await import('./index.js');
  const total = 100_001;
  let reads = 0;
  /** @type {()=>void} Signals that every synthetic completed read was consumed. */
  let reached;
  const consumed = new Promise(resolve => { reached = resolve; });
  /** @type {((value:{done:boolean})=>void)|undefined} Completes the final pending native read. */
  let pending;
  const iterator = {
    next: () => {
      reads++;
      if (reads <= total) {
        if (reads === total) reached();
        return Promise.resolve({ done: false, value: { type: 'ignored', data: {} } });
      }
      return new Promise(resolve => { pending = resolve; });
    },
    return: async () => { pending?.({ done: true }); return { done: true }; },
  };
  const disposable = { dispose: async () => {} };
  const context = {
    app: { version: '2.0.28' }, options: { channel: '/owned/channel', hookCommand: '/owned/hook' },
    session: { hook: async () => disposable }, tool: { hook: async () => disposable },
    event: { subscribe: async () => ({ [Symbol.asyncIterator]: () => iterator }) },
  };
  try {
    global.gc();
    const before = process.memoryUsage().heapUsed;
    const dispose = await plugin.setup(context);
    await consumed;
    await new Promise(resolve => setImmediate(resolve));
    global.gc();
    const retained = process.memoryUsage().heapUsed - before;
    assert.ok(retained < 8 * 1024 * 1024, `completed reads retained ${retained} bytes`);
    await dispose();
    global.gc();
    assert.ok(process.memoryUsage().heapUsed - before < 8 * 1024 * 1024, 'cleanup releases the pending read');
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});

test('separated overflow episodes each invalidate, with a Stop between them', { timeout: 10000 }, async () => {
  /** @type {Array<Record<string,string>>} Metadata sent to the existing hook client. */
  const calls = [];
  /** @type {Array<()=>void>} Hook completions withheld while the native consumer is slow. */
  const held = [];
  /** @type {boolean} Whether new hook writes are withheld instead of completed. */
  let slow = true;
  mock.method(childProcess, 'execFile', (command, args, options, callback) => ({ stdin: new Writable({
    /** Record one hook payload and complete the fake hook process, immediately or on release.
     * @param {Buffer} bytes UTF-8 JSON metadata written to the hook's stdin.
     * @param {string} encoding Stream encoding, unused for buffers.
     * @param {(error?:Error|null)=>void} done Acknowledges the stdin write, always without error.
     * @returns {void} Appends the parsed payload to `calls`; while `slow`, the exec callback is
     *   withheld in `held` until the test releases it, otherwise it fires at once. */
    write(bytes, encoding, done) {
      calls.push(JSON.parse(bytes.toString()));
      done();
      if (slow) held.push(() => callback(null, '', '')); else callback(null, '', '');
    },
  }) }));
  syncBuiltinESMExports();
  const { default: plugin } = await import('./index.js');
  /** @type {Map<string,(event:object)=>Promise<void>>} Native registered callbacks. */
  const hooks = new Map();
  /** @type {(value:{done:boolean,value?:object})=>void} Active native event consumer. */
  let next;
  const context = {
    app: { version: '2.0.28' }, options: { channel: '/owned/channel', hookCommand: '/owned/hook' },
    session: { get: async ({ sessionID }) => ({ id: sessionID }),
      hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => {} }; } },
    tool: { hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => {} }; } },
    event: { subscribe: async () => ({ [Symbol.asyncIterator]: () => ({
      next: () => new Promise(resolve => { next = resolve; }),
      return: async () => { next({ done: true }); return { done: true }; },
    }) }) },
  };
  /** Release every withheld hook until all accepted work and the queued invalidation settled.
   * @returns {Promise<void>} Quiescence after a bounded number of event-loop turns. */
  async function drain() {
    slow = false;
    for (let turn = 0; turn < 50; turn++) {
      for (const release of held.splice(0)) release();
      await new Promise(resolve => setImmediate(resolve));
    }
  }
  /** Overload the bounded queue while its first hook is withheld.
   * @returns {Promise<void>} Settled after the burst and a full drain. */
  async function burst() {
    slow = true;
    for (let index = 0; index < 70; index++) hooks.get('prompt')({ sessionID: 'root' });
    await drain();
  }
  /** @returns {string[]} Hook event names recorded so far. */
  const names = () => calls.map(value => value.hook_event_name);
  try {
    const dispose = await plugin.setup(context);
    await burst();
    assert.equal(names().filter(name => name === 'OpenCodeActivity').length, 64, 'excess activity is dropped, not buffered');
    assert.equal(names().at(-1), 'OpenCodeUnknown', 'first episode invalidates after accepted work');
    next({ done: false, value: { type: 'session.execution.succeeded', data: { sessionID: 'root' } } });
    await drain();
    assert.equal(names().at(-1), 'Stop', 'a Stop between episodes is still delivered');
    await burst();
    assert.equal(names().filter(name => name === 'OpenCodeActivity').length, 128);
    assert.equal(names().at(-1), 'OpenCodeUnknown', 'second separated episode invalidates the stale Stop');
    assert.equal(names().filter(name => name === 'OpenCodeUnknown').length, 2);
    await dispose();
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});

test('no observation is accepted behind a queued overload invalidation', { timeout: 10000 }, async () => {
  /** @type {Array<Record<string,string>>} Metadata sent to the existing hook client. */
  const calls = [];
  /** @type {Array<()=>void>} Hook completions released one at a time by the test. */
  const held = [];
  /** @type {boolean} Whether new hook writes are withheld instead of completed. */
  let slow = true;
  mock.method(childProcess, 'execFile', (command, args, options, callback) => ({ stdin: new Writable({
    /** Record one hook payload and complete the fake hook process, immediately or on release.
     * @param {Buffer} bytes UTF-8 JSON metadata written to the hook's stdin.
     * @param {string} encoding Stream encoding, unused for buffers.
     * @param {(error?:Error|null)=>void} done Acknowledges the stdin write, always without error.
     * @returns {void} Appends the parsed payload to `calls`; while `slow`, the exec callback is
     *   withheld in `held` until the test releases it, otherwise it fires at once. */
    write(bytes, encoding, done) {
      calls.push(JSON.parse(bytes.toString()));
      done();
      if (slow) held.push(() => callback(null, '', '')); else callback(null, '', '');
    },
  }) }));
  syncBuiltinESMExports();
  const { default: plugin } = await import('./index.js');
  /** @type {Map<string,(event:object)=>Promise<void>>} Native registered callbacks. */
  const hooks = new Map();
  /** @type {(value:{done:boolean,value?:object})=>void} Active native event consumer. */
  let next;
  const context = {
    app: { version: '2.0.28' }, options: { channel: '/owned/channel', hookCommand: '/owned/hook' },
    session: { get: async ({ sessionID }) => ({ id: sessionID }),
      hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => {} }; } },
    tool: { hook: async (name, callback) => { hooks.set(name, callback); return { dispose: async () => {} }; } },
    event: { subscribe: async () => ({ [Symbol.asyncIterator]: () => ({
      next: () => new Promise(resolve => { next = resolve; }),
      return: async () => { next({ done: true }); return { done: true }; },
    }) }) },
  };
  /** @returns {Promise<void>} One event-loop turn, letting released hooks settle. */
  const turn = () => new Promise(resolve => setImmediate(resolve));
  try {
    const dispose = await plugin.setup(context);
    for (let index = 0; index < 70; index++) hooks.get('prompt')({ sessionID: 'root' });
    await turn();
    // Complete two withheld hooks so one accepted slot frees while the invalidation is still queued.
    for (let index = 0; index < 2; index++) { held.shift()(); await turn(); }
    next({ done: false, value: { type: 'session.execution.succeeded', data: { sessionID: 'root' } } });
    hooks.get('prompt')({ sessionID: 'root' });
    slow = false;
    for (let index = 0; index < 50; index++) { for (const release of held.splice(0)) release(); await turn(); }
    const names = calls.map(value => value.hook_event_name);
    assert.equal(names.at(-1), 'OpenCodeUnknown', 'the invalidation is the last word after the overload');
    assert.equal(names.includes('Stop'), false, 'a restoring Stop is not queued behind the invalidation');
    await dispose();
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});
