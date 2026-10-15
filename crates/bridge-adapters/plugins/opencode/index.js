/** First-party, observation-only OpenCode 2.0.28 lifecycle projection.
 * Native input remains owned by the launcher. No prompt rewriting, inference,
 * credentials or model-progress polling occurs here. */
import { execFile } from 'node:child_process';

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
    const { channel, hookCommand } = ctx.options;
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
    /** @type {boolean} One overflow invalidation replaces unbounded buffering. */
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

    /** Queue one genuine observation; reject invalid ids and bound pending work.
     * @param {string} kind Normalized event. @param {string} sessionID Native actor id.
     * @param {{tool_use_id?:string,tool_name?:string}} [call={}] Native call metadata only.
     * @returns {Promise<void>} Fail-open observation, without an input effect. */
    function observe(kind, sessionID, call = {}) {
      if (!active || !identifier(sessionID)) return Promise.resolve();
      if (pending >= MAX_PENDING) {
        if (!overflow) { overflow = true; serial = serial.then(invalidate).catch(() => {}); }
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

    const prompt = await ctx.session.hook('prompt', event => observe('OpenCodeActivity', event.sessionID));
    const tool = await ctx.tool.hook('execute.before', event => identifier(event.id) && identifier(event.tool)
      ? observe('PreToolUse', event.sessionID, { tool_use_id: event.id, tool_name: event.tool }) : observe('OpenCodeUnknown', event.sessionID));
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
      for (const stage of [() => prompt.dispose(), () => tool.dispose(), () => iterator.return?.(), () => feed, finalize]) {
        try { await stage(); } catch (error) { failure ??= { error }; }
      }
      if (failure) throw failure.error;
    })();
  },
};
