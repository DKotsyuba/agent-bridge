/** Fixed native message client executed only by the host-supplied signed Node. No arbitrary RPC or child process. */
'use strict';
/** @typedef {{tools?:Array<{name:string,namespace?:string}>,success?:boolean}} NativeResult Fields consumed from native replies. */
/** @typedef {{threadStartKind:'all'}|{arguments:{threadId:string,prompt:string},callerSource:'codex',callId:string,namespace:string,threadId:string,tool:'send_message_to_thread',turnId:string}} NativeParams Closed native request variants. */
/** Native IPC, with no external network or file access. @type {typeof import('node:net')} */
const net = require('node:net');
/** Shared absolute deadline and maximum native frame bytes. @type {number} */
const deadline = Date.now() + 7500, limit = 8 * 1024 * 1024;
/** Owned native connection, destroyed by finish on every classified path. @type {import('node:net').Socket|null} */
let socket = null;
/** True only after the fixed message call starts writing. @type {boolean} */
let sent = false;
/** Ensures only one receipt is emitted even when timeout and socket failure race. @type {boolean} */
let finished = false;
/** Trusted parent request bytes, bounded before JSON parsing. @type {Buffer} */
let input = Buffer.alloc(0);
/** Emit one fixed classified receipt and close the owned process. @param {'accepted'|'known_unsent'|'unknown'} state Delivery tier. @returns {void} */
function finish(state) {
  if (finished) return;
  finished = true; clearTimeout(timer); socket?.destroy();
  process.stdout.write(JSON.stringify({id:1,result:{state}})+'\n', () => process.exit(0));
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
async function deliver(request) {
  try {
    if(JSON.stringify(Object.keys(request).sort())!==JSON.stringify(['call_id','text','thread_id'])||!['thread_id','call_id','text'].every(k=>typeof request[k]==='string'&&request[k])||Buffer.byteLength(request.text)>65536) throw new Error('invalid request');
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
process.stdin.on('data',b=>{if(input.length+b.length>131072)return finish('known_unsent');input=Buffer.concat([input,b]);const end=input.indexOf(10);if(end>=0){process.stdin.pause();try{void deliver(JSON.parse(input.subarray(0,end).toString('utf8')));}catch{finish('known_unsent');}}});
process.stdin.on('error',()=>finish(sent?'unknown':'known_unsent'));
process.stdin.on('end',()=>{if(!input.includes(10))finish('known_unsent');});
