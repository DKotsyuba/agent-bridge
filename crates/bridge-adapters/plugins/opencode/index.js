/** First-party OpenCode 2.0.28 lifecycle and protected native MCP projection.
 * Native input remains owned by the launcher. No prompt rewriting, inference,
 * credentials or model-progress polling occurs here. */
import { execFile } from 'node:child_process';
import { createConnection } from 'node:net';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

/** @type {number} Maximum retained lifecycle operations before invalidation. */
const MAX_PENDING = 64;
/** @type {number} Maximum native parent associations retained per process. */
const MAX_SESSIONS = 4096;

/** Check a native identifier, never a display label.
 * @param {unknown} value Native session/call id. @returns {boolean} Bounded and control-free. */
function identifier(value) {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}

/** @type {{id:string,setup:(ctx:object)=>Promise<()=>Promise<void>>}} Native plugin entrypoint. */
export default {
  id: 'agent-bridge',
  /** Observe genuine native prompt/tool/execution events, preserving their order.
   * @param {import('@opencode/plugin').Context} ctx Pinned native context with operator-owned options.
   * @returns {Promise<() => Promise<void>>} Disposer that makes readiness unknown.
   * @throws {Error} Before attaching for unsupported versions or component paths. */
  async setup(ctx) {
    const { channel, hookCommand, contextDirectory, mcpServers = [] } = ctx.options;
    if (!Array.isArray(mcpServers) || mcpServers.some(name => !identifier(name)) || (mcpServers.length && (typeof contextDirectory !== 'string' || !contextDirectory.startsWith('/')))) throw new Error('Invalid managed native MCP projection');
    if (ctx.app.version !== '2.0.28' || typeof channel !== 'string' || !channel.startsWith('/') || typeof hookCommand !== 'string' || !hookCommand.startsWith('/')) {
      throw new Error('Agent Bridge requires the pinned lifecycle contract and absolute component paths');
    }
    /** @type {Map<string,{child:boolean}>} Actual immutable native parent associations. */
    const sessions = new Map();
    /** @type {Promise<void>} Ordered hook work, never a model-input scheduler. */
    let serial = Promise.resolve();
    /** @type {number} Retained operations. */
    let pending = 0;
    /** @type {boolean} No new work after disposal or a native feed gap. */
    let active = true;
    /** @type {boolean} One queued invalidation replaces unbounded buffering; re-armed once it settles. */
    let overflow = false;

    /** Invoke the existing bounded hook client without a shell or credentials.
     * @param {object} payload Lifecycle/native call metadata, never tool arguments or prompt text.
     * @returns {Promise<void>} Fail-open observation; never retries message effects. */
    function hook(payload) {
      return new Promise(resolve => {
        const child = execFile(hookCommand, [channel, 'opencode'], { timeout: 5000, maxBuffer: 65536 }, () => resolve());
        child.stdin.on('error', () => {});
        child.stdin.end(JSON.stringify(payload));
      });
    }

    /** Read immutable native parent facts. A timeout only discards metadata;
     * it is never used as cancellation of an input operation.
     * @param {string} sessionID Actual native id. @returns {Promise<{child:boolean}>} Parent association. */
    async function identity(sessionID) {
      const retained = sessions.get(sessionID);
      if (retained) return retained;
      if (sessions.size >= MAX_SESSIONS) throw new Error('Agent Bridge session capacity');
      let timer;
      try {
        const reply = await Promise.race([ctx.session.get({ sessionID }), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('native metadata unavailable')), 1000); })]);
        const info = reply?.data ?? reply;
        if (info?.id !== sessionID || (info.parentID != null && !identifier(info.parentID))) throw new Error('native identity mismatch');
        const found = { child: info.parentID != null };
        sessions.set(sessionID, found);
        await hook({ hook_event_name: 'SessionStart', session_id: sessionID, ...(found.child ? { agent_id: sessionID } : {}), source: 'opencode' });
        return found;
      } finally { clearTimeout(timer); }
    }

    /** Invalidate retained actors on a local feed gap, never claiming idle.
     * @returns {Promise<void>} Bounded hook children without native model work. */
    async function invalidate() {
      for (const [sessionID, actor] of sessions) await hook({ hook_event_name: 'OpenCodeUnknown', session_id: sessionID, ...(actor.child ? { agent_id: sessionID } : {}) });
    }

    /** Queue one genuine observation; reject invalid ids and bound pending work. A
     * rejected excess observation queues one invalidation; every arrival is
     * rejected until it settles, so nothing queues behind it and restores
     * readiness it has just made unknown. A later separated overload may queue another.
     * @param {string} kind Normalized event. @param {string} sessionID Native actor id.
     * @param {{tool_use_id?:string,tool_name?:string}} [call={}] Native call metadata only.
     * @returns {Promise<void>} Fail-open observation, without an input effect. */
    function observe(kind, sessionID, call = {}) {
      if (!active || !identifier(sessionID)) return Promise.resolve();
      if (overflow || pending >= MAX_PENDING) {
        if (!overflow) { overflow = true; serial = serial.then(invalidate).catch(() => {}).finally(() => { overflow = false; }); }
        return Promise.resolve();
      }
      pending++;
      const next = serial.then(async () => {
        if (!active) return;
        const actor = await identity(sessionID);
        await hook({ hook_event_name: kind, session_id: sessionID, ...(actor.child ? { agent_id: sessionID } : {}), ...call });
        if (kind === 'SessionEnd') sessions.delete(sessionID);
      }).catch(() => {}).finally(() => { pending--; });
      serial = next;
      return next;
    }

    /** @type {Map<string,Promise<void>>} Per-server lanes preserve native executor permission checks. */
    const lanes = new Map();
    /** @type {Map<string,number>} Native calls admitted per server, including queued calls. */
    const depth = new Map();
    /** @type {Set<string>} An unresolved context cleanup fails later calls closed. */
    const blocked = new Set();
    /** Submit actual protected ToolContext from this native process; the proxy checks
     * our kernel PID, UID and birth. Nothing comes from model identity arguments.
     * @param {string} server Original namespace. @param {{op:'begin',context:{session_id:string,call_id:string,tool:string,arguments:Record<string,unknown>}}|{op:'end',call_id:string}} request Control payload.
     * @returns {Promise<void>} Exact acknowledgement; refusal/timeout never starts a tool. */
    function nativeContext(server, request) {
      const digest = createHash('sha256').update(server).digest('hex').slice(0, 20);
      const path = join(contextDirectory, 'mcp-' + process.pid + '-' + digest + '.sock');
      const payload = JSON.stringify({ server, ...request }) + '\n';
      if (Buffer.byteLength(payload) > 16 * 1024 * 1024) return Promise.reject(new Error('Native MCP frame exceeds the host limit'));
      return new Promise((resolve, reject) => {
        const socket = createConnection(path); let bytes = '';
        socket.setTimeout(5000, () => socket.destroy(new Error('Native MCP control deadline')));
        socket.on('error', () => reject(new Error('Native MCP control unavailable')));
        socket.on('connect', () => socket.write(payload));
        socket.on('data', chunk => {
          bytes += chunk;
          if (bytes.length > 1024) return socket.destroy(new Error('Native MCP control response exceeds bound'));
          const end = bytes.indexOf('\n'); if (end < 0) return;
          socket.destroy();
          try { if (JSON.parse(bytes.slice(0, end)).ok !== true) throw new Error('Native MCP context refused'); resolve(); }
          catch { reject(new Error('Native MCP context refused')); }
        });
        socket.on('end', () => { if (!bytes.includes('\n')) reject(new Error('Native MCP control closed without acknowledgement')); });
      });
    }
    /** @type {Map<string,string>} Frozen configured namespaces indexed by native normalization. */
    const nativeServers = new Map(mcpServers.map(server => [server.replace(/[^a-zA-Z0-9_-]/g, '_'), server]));
    /** @type {Map<string,string>} Actual native MCP registry IDs mapped to Bridge hook classification.
     * The mapping uses protected definitions, never parses a model-supplied name. */
    const nativeCalls = new Map();
    /** @type {WeakSet<Function>} Executor wrappers already projected by this plugin. */
    const wrapped = new WeakSet();
    /** @type {{dispose:()=>Promise<void>}|undefined} Owned native tool transformation subscription. */
    const transport = mcpServers.length ? await ctx.tool.transform(editor => {
      nativeCalls.clear();
      for (const tool of editor.list()) {
        const server = nativeServers.get(tool.options?.namespace);
        if (!server) continue;
        nativeCalls.set(tool.id, 'mcp__' + tool.options.namespace + '__' + tool.name.replace(/[^a-zA-Z0-9_-]/g, '_'));
        if (wrapped.has(tool.execute)) continue;
        const original = tool.execute;
        /** Preserve original permission checks, schema, output and errors. Only the
         * actual executor's matching MCP wire request receives native metadata.
         * @param {Record<string,unknown>} input Original decoded arguments. @param {{sessionID:string,id:string}} context Protected ToolContext; all other native fields pass unchanged.
         * @returns {Promise<object>} Unchanged original result; never re-executes a tool. */
        const execute = async (input, context) => {
          const pending = depth.get(server) ?? 0;
          if (pending >= MAX_PENDING) throw new Error('Native MCP capacity unavailable');
          depth.set(server, pending + 1);
          const previous = lanes.get(server) ?? Promise.resolve(); let release;
          const completed = new Promise(resolve => { release = resolve; });
          const tail = previous.then(() => completed); lanes.set(server, tail);
          await previous;
          try {
            if (!active || blocked.has(server) || !identifier(context.sessionID) || !identifier(context.id)) throw new Error('Native MCP context unavailable');
            try {
              await nativeContext(server, { op: 'begin', context: { session_id: context.sessionID, call_id: context.id, tool: tool.name, arguments: input ?? {} } });
              return await original(input, context);
            }
            finally {
              try { await nativeContext(server, { op: 'end', call_id: context.id }); }
              catch { blocked.add(server); }
            }
          } finally { release(); const remaining = depth.get(server) - 1; if (remaining) depth.set(server, remaining); else depth.delete(server); if (lanes.get(server) === tail) lanes.delete(server); }
        };
        wrapped.add(execute); editor.update(tool.id, entry => { entry.execute = execute; });
      }
    }) : undefined;
    const prompt = await ctx.session.hook('prompt', event => observe('OpenCodeActivity', event.sessionID));
    const tool = await ctx.tool.hook('execute.before', event => identifier(event.id) && identifier(event.tool)
      ? observe('PreToolUse', event.sessionID, { tool_use_id: event.id, tool_name: nativeCalls.get(event.tool) ?? event.tool }) : observe('OpenCodeUnknown', event.sessionID));
    const events = await ctx.event.subscribe();
    const iterator = events[Symbol.asyncIterator]();
    /** @type {()=>void} Ends the one currently pending read, or a no-op between reads. */
    let stopFeed = () => {};
    /** @type {Promise<void>|undefined} Shared final drain and invalidation. */
    let finalization;
    /** Drain accepted work and invalidate retained actors exactly once.
     * @returns {Promise<void>} Completion shared by feed loss and disposal. */
    function finalize() {
      active = false;
      return finalization ??= serial.then(invalidate);
    }
    /** @type {Promise<void>} Owned local native subscription; no progress polling. */
    const feed = (async () => {
      while (active) {
        /** @type {()=>void} Cancellation owned only by this pending read. */
        let cancel;
        /** @type {Promise<{done:boolean}>} Per-read cancellation; settled races can be collected. */
        const stopped = new Promise(resolve => { cancel = () => resolve({ done: true }); });
        stopFeed = cancel;
        let value;
        try { value = await Promise.race([iterator.next(), stopped]); }
        finally { if (stopFeed === cancel) stopFeed = () => {}; }
        if (value.done) break;
        const event = value.value;
        const sessionID = event.data?.sessionID ?? event.data?.info?.id;
        if (!identifier(sessionID)) continue;
        if (event.type === 'session.created') await observe('OpenCodeUnknown', sessionID);
        else if (event.type === 'session.execution.started' || (event.type === 'session.status' && ['busy', 'retry'].includes(event.data?.status?.type))) await observe('OpenCodeActivity', sessionID);
        else if (['session.execution.succeeded', 'session.execution.failed', 'session.execution.interrupted'].includes(event.type)) await observe('Stop', sessionID);
        else if (event.type === 'session.deleted') await observe('SessionEnd', sessionID);
      }
    })().catch(() => {}).finally(async () => { if (active) await finalize(); });
    /** @type {Promise<void>|undefined} One disposal shared by repeated callers. */
    let cleanup;
    /** Attempt every cleanup stage, awaiting native return, feed completion,
     * serialized work and exactly one final invalidation before settling.
     * @returns {Promise<void>} Shared completion; no cleanup continues afterwards.
     * @throws {unknown} First stage failure, only after every stage settles. */
    return () => cleanup ??= (async () => {
      active = false;
      stopFeed();
      /** @type {{error:unknown}|undefined} First cleanup failure, surfaced after all stages. */
      let failure;
      for (const stage of [() => transport?.dispose(), () => prompt.dispose(), () => tool.dispose(), () => iterator.return?.(), () => feed, finalize]) {
        try { await stage(); } catch (error) { failure ??= { error }; }
      }
      if (failure) throw failure.error;
    })();
  },
};
