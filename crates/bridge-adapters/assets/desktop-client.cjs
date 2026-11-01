/** Signed MCP frontend: Rust owns authorization and stdio; only its private channel selects one fixed native message call. */
'use strict';
/** @typedef {{tools?:Array<{name:string,namespace?:string}>,success?:boolean}} NativeResult Fields consumed from native replies. */
/** @typedef {{threadStartKind:'all'}|{arguments:{threadId:string,prompt:string},callerSource:'codex',callId:string,namespace:string,threadId:string,tool:'send_message_to_thread',turnId:string}} NativeParams Closed native request variants. */
/** Native IPC, with no external network or file access. @type {typeof import('node:net')} */
const net = require('node:net');
/** Largest message text in UTF-8 bytes: core's framing bound (Rust `MAX_FRAMED_BYTES`). @type {number} */
const TEXT_LIMIT=98304;
/** Largest thread/call id in UTF-8 bytes: core's field bound (Rust `MAX_ID_BYTES`). @type {number} */
const ID_LIMIT=256;
/** Largest private request frame body: doubled text and ids plus the JSON skeleton allowance (Rust `MAX_PRIVATE_FRAME_BYTES`). @type {number} */
const FRAME_LIMIT=197696;
/** Execute one closed native message request in this signed process. @param {{thread_id:string,call_id:string,text:string}} request Frozen fields. @returns {Promise<{state:'accepted'|'known_unsent'|'unknown'}>} One conservative receipt. */
function nativeMessage(request) {
  return new Promise(resolve => {
/** Shared absolute deadline and maximum native frame bytes. @type {number} */
const deadline = Date.now() + 7500, limit = 8 * 1024 * 1024;
/** Owned native connection, destroyed by finish on every classified path. @type {import('node:net').Socket|null} */
let socket = null;
/** True only after the fixed message call starts writing. @type {boolean} */
let sent = false;
/** Ensures only one receipt is emitted even when timeout and socket failure race. @type {boolean} */
let finished = false;
/** Emit one fixed classified receipt and close the owned process. @param {'accepted'|'known_unsent'|'unknown'} state Delivery tier. @returns {void} */
function finish(state) {
  if (finished) return;
  finished = true; clearTimeout(timer); socket?.destroy();
  resolve({state});
}
/** One total timer, independent of partial frames. @type {NodeJS.Timeout} */
const timer = setTimeout(() => finish(sent ? 'unknown' : 'known_unsent'), Math.max(1,deadline-Date.now()));
/** Read one correlated bounded native reply before any request write. @param {number} id Expected request id. @returns {Promise<NativeResult>} Result object. */
function receive(id) {
  return new Promise((resolve,reject) => {
    /** Bounded native reply bytes across partial reads. @type {Buffer} */
    let data = Buffer.alloc(0);
    /** Release only this exchange's socket listeners. @returns {void} */
    const clean = () => {socket.off('data',onData);socket.off('error',onError);socket.off('close',onClose);};
    /** Reject this exchange without printing host diagnostics. @param {Error} e Failure. @returns {void} */
    const onError = e => {clean();reject(e);};
    /** Treat incomplete closure as failure; classified at the effect boundary. @returns {void} */
    const onClose = () => onError(new Error('closed'));
    /** Decode one bounded correlated response. @param {Buffer} b Next native bytes. @returns {void} */
    const onData = b => {
      if(data.length+b.length>limit+4) return onError(new Error('frame limit'));
      data=Buffer.concat([data,b]); if(data.length<4) return;
      const n=data.readUInt32LE(0); if(!n||n>limit) return onError(new Error('frame limit'));
      if(data.length<4+n) return;
      clean();try {const v=JSON.parse(data.subarray(4,4+n).toString('utf8')); if(v.jsonrpc!=='2.0'||v.id!==id||v.error||!v.result||typeof v.result!=='object') throw new Error('invalid reply');resolve(v.result);} catch(e){reject(e);}
    };
    socket.on('data',onData);socket.once('error',onError);socket.once('close',onClose);
  });
}
/** Exchange a fixed parent-selected native request. @param {number} id Request identity. @param {string} method Fixed method. @param {NativeParams} params Owned parameters. @returns {Promise<NativeResult>} Correlated native result. */
function rpc(id,method,params) {
  const response=receive(id), body=Buffer.from(JSON.stringify({jsonrpc:'2.0',id,method,params})), head=Buffer.alloc(4);
  if(body.length>limit) throw new Error('frame limit'); head.writeUInt32LE(body.length);socket.write(Buffer.concat([head,body]));return response;
}
/** Perform only discovery then one exact send, never retry/fallback. @param {{thread_id:string,call_id:string,text:string}} request Frozen parent fields. @returns {Promise<void>} One typed stdout receipt. */
async function perform(request) {
  try {
    if(JSON.stringify(Object.keys(request).sort())!==JSON.stringify(['call_id','text','thread_id'])||!['thread_id','call_id','text'].every(k=>typeof request[k]==='string'&&request[k])||Buffer.byteLength(request.text)>TEXT_LIMIT||Buffer.byteLength(request.thread_id)>ID_LIMIT||Buffer.byteLength(request.call_id)>ID_LIMIT) throw new Error('invalid request');
    socket=net.createConnection(process.env.CODEX_APP_TOOLS_PIPE_PATH);
    await new Promise((resolve,reject)=>{socket.once('connect',resolve);socket.once('error',reject);});
    const listed=await rpc(1,'tools/list',{threadStartKind:'all'});
    const tool=Array.isArray(listed.tools)&&listed.tools.find(t=>t.name==='send_message_to_thread'&&typeof t.namespace==='string'&&t.namespace&&t.namespace.length<=256);
    if(!tool) return finish('known_unsent');
    sent=true;
    const result=await rpc(2,'tools/call',{arguments:{threadId:request.thread_id,prompt:request.text},callerSource:'codex',callId:request.call_id,namespace:tool.namespace,threadId:request.thread_id,tool:'send_message_to_thread',turnId:request.call_id});
    finish(result.success===true?'accepted':'unknown');
  } catch {finish(sent?'unknown':'known_unsent');}
}
    void perform(request);
  });
}

/** Standalone protocol entry for owned socket tests; production uses the private parent channel below. @returns {void} */
function singleClient() {
  /** Bounded standalone test request bytes. @type {Buffer} */
  let input=Buffer.alloc(0);
  /** Emit a pre-call refusal for malformed standalone input. @returns {void} */
  const fail=()=>process.stdout.write(JSON.stringify({id:1,result:{state:'known_unsent'}})+'\n',()=>process.exit(0));
  process.stdin.on('data',b=>{if(input.length+b.length>FRAME_LIMIT+1)return fail();input=Buffer.concat([input,b]);const end=input.indexOf(10);if(end>=0){process.stdin.pause();try{void nativeMessage(JSON.parse(input.subarray(0,end).toString('utf8'))).then(result=>process.stdout.write(JSON.stringify({id:1,result})+'\n',()=>process.exit(0)));}catch{fail();}}});
  process.stdin.on('error',fail);
  process.stdin.on('end',()=>{if(!input.includes(10))fail();});
}

/** Run the Rust MCP child with private descriptor 3; only that child can submit authenticated delivery fields. @returns {void} */
function mcpFrontend() {
  /** Trusted child launcher; executable and arguments originate in Rust main. @type {typeof import('node:child_process')} */
  const {spawn}=require('node:child_process');
  /** Exact Rust executable and MCP arguments, without shell parsing. @type {[string,...string[]]} */
  const [executable,...args]=process.argv.slice(1);
  /** Child context with native capabilities confined to this signed parent. @type {NodeJS.ProcessEnv} */
  const env={...process.env};
  delete env.CODEX_APP_TOOLS_PIPE_PATH;delete env.CODEX_MCP_NODE_PATH;
  env.BRIDGE_DESKTOP_PARENT_PID=String(process.pid);
  /** Owned Rust MCP child and its private socket-backed descriptor 3. @type {import('node:child_process').ChildProcess} */
  const child=spawn(executable,args,{env,stdio:['inherit','inherit','inherit','pipe']});
  /** Bounded private frame bytes across partial reads. @type {Buffer} */
  let bytes=Buffer.alloc(0);
  /** One in-flight delivery; concurrent frames close only this owned child. @type {boolean} */
  let active=false;
  child.stdio[3].on('data',b=>{
    if(bytes.length+b.length>FRAME_LIMIT+4)return child.kill();
    bytes=Buffer.concat([bytes,b]);if(bytes.length<4)return;
    const n=bytes.readUInt32LE(0);if(!n||n>FRAME_LIMIT)return child.kill();if(bytes.length<n+4)return;
    if(active||bytes.length!==n+4)return child.kill();
    active=true;let request;try{request=JSON.parse(bytes.subarray(4).toString('utf8'));}catch{return child.kill();}bytes=Buffer.alloc(0);
    void nativeMessage(request).then(result=>{const body=Buffer.from(JSON.stringify({...result,call_id:request.call_id})),head=Buffer.alloc(4);head.writeUInt32LE(body.length);child.stdio[3].write(Buffer.concat([head,body]));active=false;});
  });
  child.stdio[3].on('error',()=>child.kill());
  child.on('error',()=>process.exit(1));
  child.on('exit',(code,signal)=>{if(signal)process.kill(process.pid,signal);else process.exit(code??1);});
  for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>{child.kill(signal);setTimeout(()=>{child.kill('SIGKILL');process.exit(1);},1000).unref();});
}
if(process.argv.length>1)mcpFrontend();else singleClient();
