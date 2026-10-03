// 비밀번호로 받은 키로 같은 출처 파일을 복호화해 돌려준다 (scripts/publish_pages.mjs)
const PLAIN=new Set(['','index.html','sw.js','check.bin']);
const TYPES={html:'text/html; charset=utf-8',js:'text/javascript',css:'text/css',json:'application/json',glb:'model/gltf-binary',
 png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',webp:'image/webp',svg:'image/svg+xml',woff2:'font/woff2',wasm:'application/wasm',ktx2:'image/ktx2',bin:'application/octet-stream'};
let key=null;
const DB='argong-poc-gate';
function idb(mode,fn){return new Promise((res,rej)=>{const o=indexedDB.open(DB,1);o.onupgradeneeded=()=>o.result.createObjectStore('k');
 o.onsuccess=()=>{const t=o.result.transaction('k',mode);const s=t.objectStore('k');const r=fn(s);t.oncomplete=()=>res(r&&r.result);t.onerror=()=>rej(t.error);};o.onerror=()=>rej(o.error);});}
async function getKey(){if(key)return key;const raw=await idb('readonly',s=>s.get('raw'));
 if(raw)key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);return key;}
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('message',e=>{if(e.data&&e.data.type==='key'){e.waitUntil((async()=>{
 key=await crypto.subtle.importKey('raw',e.data.raw,'AES-GCM',false,['decrypt']);await idb('readwrite',s=>s.put(e.data.raw,'raw'));
 e.ports[0]&&e.ports[0].postMessage('ok');})());}});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);const scope=new URL(self.registration.scope);
 if(u.origin!==location.origin||!u.pathname.startsWith(scope.pathname))return;
 const rel=decodeURIComponent(u.pathname.slice(scope.pathname.length));
 if(PLAIN.has(rel))return;
 e.respondWith((async()=>{const k=await getKey();
  if(!k)return e.request.mode==='navigate'?Response.redirect(scope.href+u.search,302):new Response('locked',{status:401});
  const r=await fetch(u.href,{cache:'default'});if(!r.ok)return r;
  const b=new Uint8Array(await r.arrayBuffer());
  try{const p=await crypto.subtle.decrypt({name:'AES-GCM',iv:b.slice(0,12)},k,b.slice(12));
   const ext=(rel.split('.').pop()||'').toLowerCase();
   return new Response(p,{status:200,headers:{'Content-Type':TYPES[ext]||'application/octet-stream'}});}
  catch{return e.request.mode==='navigate'?Response.redirect(scope.href,302):new Response('bad key',{status:403});}})());});
