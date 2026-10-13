/** Independent public-NDJSON producer, using Node stdlib only. Root runs
 * `node raw-producer.cjs <private-config.json>` as an MCP frontend or adds
 * `--recover` for exact historical recovery. Config, credential and hidden
 * payload are private files; model arguments are empty. Receipts are journaled
 * and returned without payload, proof or metadata. No automatic retry/native
 * fallback: an unresolved write keeps the original request/event identity.
 * `--self-test` checks correlation and immutable receipt binding without I/O.
 */
'use strict';
const fs = require('node:fs');
const net = require('node:net');

/** JSON data; opaque payload/proof/credential values never enter diagnostics.
 * @typedef {null|boolean|number|string|Json[]|{[key:string]:Json}} Json */
/** Root-owned private fixture settings; paths are explicit and never inferred
 * from native arguments/cwd. Identity/kind/tool values are fixed after freeze.
 * @typedef {{registration_socket:string,core_socket:string,credential_file:string,
 * payload_file:string,receipt_file:string,host:'codex'|'claude_code',tool_name:string,
 * request_id:string,operation_key:string,event_id:string,kind:string,mode:'message'|'inject'|'auto'}} Fixture */
/** Maximum inbound public response/MCP frame sizes in bytes. */
const RESPONSE_BYTES = 4 * 1024 * 1024, MCP_BYTES = 128 * 1024;

/** Reads one bounded private regular nonsymlink file owned by this UID.
 * @param {string} file Explicit root-provisioned path.
 * @param {number} limit Maximum byte length.
 * @returns {string} UTF-8 file contents; no contents are displayed on failure.
 * @throws {Error} File identity, ownership, permissions, size or I/O refused.
 */
function privateText(file, limit) {
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) || before.size > limit) throw new Error('private file refused');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const after = fs.fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino) throw new Error('private file changed');
    const buffer = Buffer.alloc(limit + 1);
    const bytes = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (bytes > limit) throw new Error('private file too large');
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytes));
  } finally { fs.closeSync(fd); }
}

/** Checks public envelope version/correlation/exclusive shape and result op.
 * Service failures become static class/reason categories; raw detail is never
 * propagated. This independent fixture does not use the SDK codec.
 * @param {Json} response One decoded response.
 * @param {string} requestId Original request identity.
 * @param {string} op Requested public operation.
 * @returns {{[key:string]:Json}} Operation-specific successful value.
 * @throws {Error} Invalid response, correlation, result or service refusal.
 */
function responseValue(response, requestId, op) {
  if (!response || Array.isArray(response) || typeof response !== 'object') throw new Error('response refused');
  const keys = Object.keys(response).sort().join(',');
  if (response.api_version !== 1 || response.request_id !== requestId || typeof response.success !== 'boolean'
      || keys !== (response.success ? 'api_version,request_id,result,success' : 'api_version,error,request_id,success')) throw new Error('response correlation refused');
  if (!response.success) throw new Error('service refused; preserve original identity');
  const result = response.result;
  if (!result || typeof result !== 'object' || Array.isArray(result) || Object.keys(result).sort().join(',') !== 'op,value'
      || result.op !== op || !result.value || typeof result.value !== 'object' || Array.isArray(result.value)) throw new Error('response operation refused');
  return result.value;
}

/** Exchanges one public v1 line on an explicit owned Unix endpoint. A fixed
 * five-second deadline bounds connect/write/read; partial traffic never renews
 * it. Request/response bytes are bounded; all socket resources close on every
 * path. No reconnect or native send occurs here.
 * @param {string} socket Explicit registration/core endpoint.
 * @param {string} credential In-memory synthetic producer credential.
 * @param {string} requestId Persisted original exchange identity.
 * @param {string} op Public operation name.
 * @param {{[key:string]:Json}} params Public operation parameters.
 * @returns {Promise<{[key:string]:Json}>} Validated operation result.
 * @throws {Error} Static not-sent/unknown/read failure or response refusal.
 */
function exchange(socket, credential, requestId, op, params) {
  const bytes = Buffer.from(JSON.stringify({ api_version: 1, request_id: requestId, credential, op, params }) + '\n');
  if (bytes.length > (op === 'register_call' ? MCP_BYTES : 512 * 1024)) return Promise.reject(new Error('request too large'));
  return new Promise((resolve, reject) => {
    const client = net.connect(socket);
    let chunks = [], length = 0, wrote = false, settled = false;
    /** Settles exactly once and releases the fixed deadline/socket.
     * @param {Error|null} error Static failure category, null for success.
     * @param {{[key:string]:Json}} [value] Successful operation value.
     * @returns {void}
     */
    const finish = (error, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer); client.destroy();
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error(wrote ? 'outcome unknown; preserve original identity' : 'request not sent')), 5000);
    client.on('connect', () => { wrote = true; client.write(bytes); });
    client.on('data', chunk => {
      length += chunk.length;
      if (length > RESPONSE_BYTES) return finish(new Error('response too large; preserve original identity'));
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks, length), end = buffer.indexOf(10);
      if (end < 0) return;
      try {
        if (buffer.subarray(end + 1).some(byte => ![9, 10, 13, 32].includes(byte))) throw new Error('trailing response refused');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end));
        finish(null, responseValue(JSON.parse(text), requestId, op));
      } catch { finish(new Error('response unresolved; preserve original identity')); }
    });
    client.on('error', () => finish(new Error(wrote ? 'outcome unknown; preserve original identity' : 'request not sent')));
    client.on('end', () => finish(new Error(wrote ? 'outcome unknown; preserve original identity' : 'read failed')));
  });
}

/** Creates the same immutable registration parameters for fresh and recovery.
 * @param {Fixture} config Private runtime identities/constraints.
 * @param {{[key:string]:Json}|null} metadata Original framework metadata, or
 * null to omit evidence during explicit committed-request recovery.
 * @returns {{[key:string]:Json}} Public register_call parameters.
 */
function registrationParams(config, metadata) {
  return { operation_key: config.operation_key, reply_policy: 'self', allowed_modes: [config.mode],
    allowed_kinds: [config.kind], max_payload_bytes: null, route_expires_at_ms: null,
    assertion_audience: null, invocation_key: null,
    ...(metadata ? { evidence: { type: 'native', host: config.host, metadata } } : {}) };
}

/** Checks original registration and publication receipt bindings before
 * releasing the private intent. Scope/route keys remain opaque references.
 * @param {Fixture} config Original runtime identities.
 * @param {{[key:string]:Json}} registration Public registration receipt.
 * @param {{[key:string]:Json}} custody Public event receipt.
 * @returns {boolean} Exact public identity/destination binding holds.
 */
function receiptsBound(config, registration, custody) {
  const destination = custody && custody.destination;
  return Boolean(registration && custody && typeof registration.producer === 'string'
    && registration.request_id === config.request_id && registration.operation_key === config.operation_key
    && typeof registration.route_key === 'string' && registration.route_key.length > 0
    && typeof registration.caller_scope === 'string' && typeof registration.destination_scope === 'string'
    && custody.producer === registration.producer && custody.event_id === config.event_id
    && /^[a-f0-9]{64}$/.test(custody.intent_hash) && /^[a-f0-9]{64}$/.test(custody.envelope_hash)
    && destination && destination.route_key === registration.route_key
    && destination.caller_scope === registration.caller_scope && destination.destination_scope === registration.destination_scope);
}

/** Registers from actual separated metadata or recovers the original request,
 * publishes the private original payload, then reads scoped public status.
 * @param {Fixture} config Root-owned fixture configuration.
 * @param {{[key:string]:Json}|null} metadata Framework-protected candidate;
 * null requests historical recovery only. Bridge performs native verification.
 * @returns {Promise<{[key:string]:Json}>} Receipt-only observation.
 * @throws {Error} Admission, I/O, receipt binding or public status refused.
 */
async function submit(config, metadata) {
  const credential = privateText(config.credential_file, 4096).trimEnd();
  const registered = await exchange(config.registration_socket, credential, config.request_id, 'register_call', registrationParams(config, metadata));
  const publication = await exchange(config.core_socket, credential, `publish-${config.request_id}`, 'publish', {
    destination: { type: 'route', route_key: registered.receipt.route_key }, event_id: config.event_id,
    kind: config.kind, payload: privateText(config.payload_file, 65536), mode: config.mode,
    policy: { type: 'keep_all' }, metadata: {}, expires_at_ms: null, delivery_scope_key: null,
  });
  if (!receiptsBound(config, registered.receipt, publication.receipt)) throw new Error('receipt binding refused');
  const status = await exchange(config.core_socket, credential, `status-${config.request_id}`, 'status', {
    selector: { type: 'event', event_id: config.event_id },
  });
  return { registration: registered.receipt, evidence_state: registered.evidence_state,
    assertion_present: registered.assertion !== null && registered.assertion !== undefined,
    publication: publication.receipt, replayed: publication.replayed, status };
}

/** Appends receipt-only JSON and fsyncs an owned private journal. Existing
 * symlinks, foreign UID or group/other permissions refuse before writing.
 * @param {string} file Root-provisioned journal path under its owned fixture.
 * @param {{[key:string]:Json}} value Safe receipts/status only.
 * @returns {void}
 * @throws {Error} Journal cannot be safely written; no noncommit inference.
 */
function journal(file, value) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const meta = fs.fstatSync(fd);
    if (!meta.isFile() || meta.uid !== process.getuid() || (meta.mode & 0o077)) throw new Error('receipt file refused');
    fs.writeSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}

/** Handles one public MCP frame; metadata stays separated from empty model
 * arguments. Notifications produce no response. Unsupported input throws a
 * static refusal; tool execution failures become receipt-free static errors.
 * @param {Fixture} config Root-owned private configuration.
 * @param {{[key:string]:Json}} rpc Parsed MCP request.
 * @returns {Promise<{[key:string]:Json}|null>} MCP response or null.
 */
async function mcp(config, rpc) {
  if (rpc.id === undefined) return null;
  let result;
  switch (rpc.method) {
    case 'initialize': result = { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'independent-raw-producer', version: '1' } }; break;
    case 'ping': result = {}; break;
    case 'tools/list': result = { tools: [{ name: config.tool_name,
      description: 'Register this native call and publish private fixture data; return receipts only',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false } }] }; break;
    case 'tools/call': {
      const params = rpc.params;
      if (!params || params.name !== config.tool_name || !params.arguments || Array.isArray(params.arguments)
          || typeof params.arguments !== 'object' || Object.keys(params.arguments).length
          || !params._meta || typeof params._meta !== 'object' || Array.isArray(params._meta)) throw new Error('MCP invocation refused');
      try {
        const value = await submit(config, params._meta);
        journal(config.receipt_file, value);
        result = { content: [{ type: 'text', text: JSON.stringify(value) }] };
      } catch { result = { isError: true, content: [{ type: 'text', text: 'submission unresolved; preserve original identities' }] }; }
      break;
    }
    default: throw new Error('MCP method unsupported');
  }
  return { jsonrpc: '2.0', id: rpc.id, result };
}

/** Serves bounded sequential stdin MCP lines or explicit --recover. No process
 * spawning, model call or implicit retry occurs. Root owns execution/state.
 * @returns {Promise<void>}
 * @throws {Error} Configuration, framing, input or output refused.
 */
async function main() {
  const args = process.argv.slice(2);
  if (!(args.length === 1 || (args.length === 2 && args[1] === '--recover'))) throw new Error('configuration arguments refused');
  const config = JSON.parse(privateText(args[0], MCP_BYTES));
  if (args.length === 2) {
    const result = await submit(config, null); journal(config.receipt_file, result);
    process.stdout.write(JSON.stringify(result) + '\n'); return;
  }
  let buffer = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    buffer = Buffer.concat([buffer, chunk]);
    let end;
    while ((end = buffer.indexOf(10)) >= 0) {
      if (end + 1 > MCP_BYTES) throw new Error('MCP frame too large');
      const line = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end));
      buffer = buffer.subarray(end + 1);
      const response = await mcp(config, JSON.parse(line));
      if (response) process.stdout.write(JSON.stringify(response) + '\n');
    }
    if (buffer.length > MCP_BYTES) throw new Error('MCP frame too large');
  }
  if (buffer.length) throw new Error('incomplete MCP frame');
}

/** Pure identity/correlation controls, including malformed exclusive response
 * shape and equal-address/different-route adoption. No files/sockets/processes.
 * @returns {void} Throws on failure; prints PASS only after all controls pass.
 */
function selfTest() {
  const assert = require('node:assert/strict');
  const response = { api_version: 1, request_id: 'req', success: true, result: { op: 'status', value: { type: 'event', event: null } } };
  assert.deepEqual(responseValue(response, 'req', 'status'), response.result.value);
  assert.throws(() => responseValue(response, 'other', 'status'));
  assert.throws(() => responseValue({ ...response, error: null }, 'req', 'status'));
  assert.throws(() => responseValue(response, 'req', 'publish'));
  const config = { request_id: 'req', operation_key: 'op', event_id: 'event', kind: 'kind', mode: 'inject', host: 'codex' };
  const receipt = { producer: 'unknown', request_id: 'req', operation_key: 'op', route_key: 'route', caller_scope: 'actor', destination_scope: 'target' };
  const custody = { producer: 'unknown', event_id: 'event', intent_hash: 'a'.repeat(64), envelope_hash: 'b'.repeat(64), destination: { route_key: 'route', caller_scope: 'actor', destination_scope: 'target' } };
  assert.equal(receiptsBound(config, receipt, custody), true);
  assert.equal(receiptsBound(config, receipt, { ...custody, destination: { ...custody.destination, route_key: 'other' } }), false);
  assert.equal(receiptsBound(config, receipt, { ...custody, producer: 'foreign' }), false);
  const fresh = registrationParams(config, { threadId: 'thread' }), recovery = registrationParams(config, null);
  delete fresh.evidence; assert.deepEqual(fresh, recovery);
  console.log(JSON.stringify({ self_test: 'PASS' }));
}

if (require.main === module) {
  if (process.argv[2] === '--self-test') selfTest();
  else main().catch(() => { console.error('raw producer failed; preserve original identities'); process.exitCode = 1; });
}
/** Root-run qualification helpers; importing this module has no I/O effects.
 * @type {{exchange:typeof exchange,privateText:typeof privateText,registrationParams:typeof registrationParams,
 * receiptsBound:typeof receiptsBound,submit:typeof submit,journal:typeof journal,mcp:typeof mcp}}
 */
module.exports = { exchange, privateText, registrationParams, receiptsBound, submit, journal, mcp };
