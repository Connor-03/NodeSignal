// fixture-ws.js: a fake daemon WebSocket for screenshots of nodesignal.html.
// Injected before the page's own script (Playwright addInitScript). Pick a
// scene with ?mode= : ok (default) | locked (history passphrase not yet typed)
// | norpc | slow (connecting) | down (never
// connects) | drop (connects, then loses the daemon; set window.__allow=true
// to let it reconnect) | hostile (every string a peer, a node or a release
// note could choose ends in quotes and markup that would count a hit in
// window.__xss if it ever ran; tests/console-hostile.e2e.js uses it). Add &calm=1 to leave out osprey's pending key change
// (and so the red security banner) in scenes that are about something else.
// All addresses are documentation ranges and all fingerprints are made up,
// so the images are safe to publish.
(()=>{
const Q=new URLSearchParams(location.search),MODE=Q.get('mode')||'ok',CALM=Q.get('calm')==='1';
const now=Date.now(), m=(min)=>now-min*60000;
const UAS=['/Satoshi:29.0.0/','/Satoshi:28.1.0/Knots:20250601/','/Satoshi:29.0.0/','/Satoshi:29.1.0/Knots:20250903/','/Satoshi:28.1.0/','/btcd:0.24.2/','/Satoshi:27.2.0/','/Satoshi:29.1.0/Knots:20250903/','/libbitcoin:4.0/','/Satoshi:29.0.0/','/bcoin:2.2.0/'];
const impl=u=>/knots/i.test(u)?'Bitcoin Knots':/satoshi/i.test(u)?'Bitcoin Core':/btcd/i.test(u)?'btcd':/libbitcoin/i.test(u)?'libbitcoin':/bcoin/i.test(u)?'Bcoin':'Unknown';
const ver=u=>{const k=u.match(/knots[:\s]*(\d+)/i),mm=u.match(/:([0-9][0-9.]*)/);const b=mm?'v'+mm[1].replace(/\.0$/,''):u;return k?b+'.knots'+k[1]:b;};
const LAT=[12,30,45,70,90,120,160,210,280,340,450,600,850];
const peers=Array.from({length:22},(_,i)=>{const ua=i===3?UAS[3].replace(/\/$/,'(nodesignal)/'):UAS[i%UAS.length];return {nodesignal:/\bnodesignal\b/i.test(ua)?{port:8788}:null,addr:(i%5===4?`[2001:db8::${(i+1).toString(16)}]:8333`:`${i%2?'203.0.113':'198.51.100'}.${10+i*7}:8333`),ua,impl:impl(ua),version:ver(ua),declared:[],latency:LAT[i%13]+(i%3)*4,inbound:i%3===0,height:950000};});
const self={ua:'/Satoshi:29.1.0/Knots:20250903/',impl:'Bitcoin Knots',version:'v29.1.knots20250903',declared:[],height:950012,network:'main',connections:22,pruned:false,pruneHeight:null};
const kiwi={host:'203.0.113.42',port:8788,nick:'kiwi-relay',hasPin:false,unread:1,lastSeen:m(1),established:true,online:true,
  peerFp:'9c1e44b07a2f3d58e6b1c0a49f7d2e31',
  peerInfo:{ua:'/Satoshi:29.1.0/Knots:20250903/',impl:'Bitcoin Knots',version:'v29.1.knots20250903',height:950012,latency:48,declared:[],supports:['BIP-141 segwit','BIP-159','BIP-130','BIP-152','BIP-339'],services:['NODE_NETWORK','NODE_WITNESS','NODE_NETWORK_LIMITED'],network:'mainnet'},
  msgs:[{id:'a1',from:'them',ts:m(42),text:'gm. just finished IBD on the new box, peer count climbing.'},
        {id:'a2',from:'me',ts:m(40),text:'nice. what are you running now, Knots or Core?',status:'delivered'},
        {id:'a3',from:'them',ts:m(38),text:'Knots 29.1 for now. watching how the relay policy discussion goes before I settle.'},
        {id:'a4',from:'me',ts:m(12),text:'same. my mempool has been quiet all morning.',status:'delivered'},
        {id:'a5',from:'them',ts:m(1),text:'quiet here too. ping me if you see anything odd at the next difficulty adjustment.'}]};
const ember={host:'198.51.100.77',port:8788,nick:'ember-node',hasPin:false,unread:0,lastSeen:0,established:false,online:false,peerFp:null,
  peerInfo:{ua:'/Satoshi:29.0.0/',impl:'Bitcoin Core',version:'v29.0',height:950011,latency:132,declared:[],supports:['BIP-141 segwit'],services:[],network:'mainnet'},
  msgs:[{id:'b1',from:'me',ts:m(5),text:'hey, saw you on my peer list. running nodesignald?',status:'pending',
    error:'refused: nothing listening on 198.51.100.77:8788',nextTry:now+4*60000,attempts:3}]};
const osprey={host:'203.0.113.88',port:8788,nick:'osprey',unread:0,lastSeen:m(600),established:true,online:false,
  peerFp:'3fa0c2d19b7e4410a6c5e2f87d0b1c93',pendingFp:{got:'e81b56f04c2a9d377a10fe5c3b8d6e21',at:m(3)},proto:3,
  peerInfo:{ua:'/Satoshi:29.0.0/',impl:'Bitcoin Core',version:'v29.0',height:950010,latency:96,declared:[],supports:['BIP-141 segwit'],services:[],network:'mainnet',source:'p2p:8333'},
  msgs:[{id:'c1',from:'them',ts:m(1500),text:'see you at the meetup next week'},{id:'c2',from:'me',ts:m(1490),text:'see you there',status:'delivered'}]};
if(CALM)delete osprey.pendingFp;
const quiet={host:'2001:db8::5a',port:8788,nick:'',hasPin:false,unread:0,lastSeen:0,established:false,online:false,peerFp:null,peerInfo:null,msgs:[]};
const locked=MODE==='locked';
if(locked)for(const c of [kiwi,ember])c.msgs=c.msgs.map(x=>({...x,text:null,locked:true,lockKind:'vault'}));
// 1.4: signing keys, onion addresses (made up, not real onions), posts,
// rooms, introductions, an available update
const KIWI_SK='a2l3aS1yZWxheS1zaWduaW5nLWtleS1leGFtcGxlMDA=',FAN_SK='c2F0b3NoaS1mYW4tc2lnbmluZy1rZXktZXhhbXBsZTA=',ME_SK='YWxwaGEtc2lnbmluZy1rZXktZXhhbXBsZS0wMDAwMDA=';
const ONION='alphaexampleonionaddressforscreenshotsxxxxxxxxxxxxxxxxxx.onion';
Object.assign(kiwi,{signPub:KIWI_SK,signId:'5c1d0a27e9b44f81',following:true,caps:['social1','rooms1','mbox1','who1'],servesMailbox:true,discoverable:true,
  onion:'kiwiexampleonionaddressforscreenshotsxxxxxxxxxxxxxxxxxxx.onion',
  nodeProof:{onion:'kiwiexampleonionaddressforscreenshotsxxxxxxxxxxxxxxxxxxx.onion',at:m(30),how:'a peer of your node'},pinnedBy:'link'});
const FEED=[
  {id:'p1',a:KIWI_SK,keyId:'5c1d0a27e9b44f81',nick:'kiwi-relay',ts:m(18),text:'Upgraded to Knots 29.1 last night. Mempool policy notes in the relay policy room if anyone wants to compare.',mine:false,hops:1,via:'kiwi-relay',contact:{host:'203.0.113.42',nick:'kiwi-relay'}},
  {id:'p2',a:FAN_SK,keyId:'9e3b77c4a1d0f262',nick:'satoshi-fan',ts:m(55),text:'Three weeks of uptime on a Pi 5 with a pruned node. Ask me anything about the setup.',mine:false,hops:2,via:'kiwi-relay',contact:null},
  {id:'p3',a:ME_SK,keyId:'7f5f561b8faca2a7',nick:'Alpha',ts:m(140),text:'Hello from Alpha. Testing posts between node operators: signed, no server.',mine:true,hops:0,via:null,contact:null}];
const ROOMS=[{room:'4f1c2a9e7b3d5a60c8e2f1a9b7d3c5e1',name:'relay policy',creator:KIWI_SK,joined:true,
  members:[{a:KIWI_SK,nick:'kiwi-relay',fp:kiwi.peerFp,host:kiwi.onion,left:false,me:false},{a:ME_SK,nick:'Alpha',fp:'54f42d4a9a31820cb0e17f3a62d9c855',host:ONION,left:false,me:true},
    {a:FAN_SK,nick:'satoshi-fan',fp:'e7d1b09c4a2f3e58b6c1a0d9f2e4b7c3',host:null,left:false,me:false}],
  msgs:[{id:'r1',a:KIWI_SK,nick:'kiwi-relay',ts:m(40),text:'Started this room to compare mempool policy settings across implementations.',mine:false},
    {id:'r2',a:FAN_SK,nick:'satoshi-fan',ts:m(33),text:'Pruned node here, default policy. Happy to share numbers.',mine:false},
    {id:'r3',a:ME_SK,nick:'Alpha',ts:m(25),text:'Same, Knots 29.1. I will post my settings tonight.',mine:true}]}];
const INTROS=[{fp:'b3a9c1e7d2f04a6895c3e1b7a2d9f0c4',nick:'mempool-watcher',host:'watcherexampleonionaddressforscreenshotsxxxxxxxxxxxxxx.onion',port:8788,via:['kiwi-relay'],at:m(12)},
  {fp:'0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e1f',nick:'node-in-a-closet',host:'198.51.100.140',port:8788,via:['kiwi-relay','osprey'],at:m(90)}];
let STATE=()=>({type:'state',daemon:{nick:'Alpha',ua:'/NodeSignal:1.4/',peerPort:8788,webPort:8789,proto:3,fingerprint:'54f42d4a9a31820cb0e17f3a62d9c855',secure:true,
    vault:{set:true,unlocked:!locked},portMapping:null,
    onion:ONION,onionMode:'auto',tor:{state:'up',onion:ONION,via:'/run/tor/control'},reach:{host:ONION,port:8788},
    share:'nodesignal:'+ONION+'?port=8788&fp=54f42d4a9a31820cb0e17f3a62d9c855&nick=Alpha',
    signKey:ME_SK,signId:'7f5f561b8faca2a7',discoverable:true,mailbox:true,mailboxStats:{recipients:1,items:2,bytes:9000},
    myMailboxes:[],sameOnion:false,nodeOnions:[],
    update:{state:'available',current:'1.4.0',version:'1.4.1',verified:true,installable:true,checkedAt:m(60),
      notes:'Fixes from operators running 1.4.0.\n- Rooms keep their order after a restart.\n- Clearer mailbox status in the console.'}},
  node:MODE==='norpc'?{self:null,peers:[],error:'connect ECONNREFUSED 127.0.0.1:8332'}:{self,peers},
  contacts:MODE==='norpc'?[]:[kiwi,ember,quiet,osprey],
  feed:FEED,follows:[KIWI_SK,FAN_SK],rooms:ROOMS,introductions:INTROS});
// mode=hostile: append quotes and markup to everything someone else chose.
// Identity keys (host of a contact, ids, fingerprints) are left alone so the
// page can still find things; the daemon validates those to a fixed charset.
const EVIL=`'"><img src=x onerror="window.__xss=(window.__xss||0)+1"><b x='`;
const PEER_TEXT=new Set(['nick','text','error','heldAt','via','name','notes','ua','version','impl','declared','supports','services','how','title']);
function taint(o,inside){
  if(Array.isArray(o))return o.map((x)=>typeof x==='string'?(inside?x+EVIL:x):taint(x,inside));
  if(!o||typeof o!=='object')return o;
  const out={};
  for(const [k,v] of Object.entries(o)){
    const hit=PEER_TEXT.has(k)||(k==='host'&&inside==='member');
    if(typeof v==='string')out[k]=hit?v+EVIL:v;
    else if(Array.isArray(v)&&hit)out[k]=taint(v,true);
    else out[k]=taint(v,k==='members'||k==='introductions'?'member':inside==='member'?'member':undefined);
  }
  return out;
}
if(MODE==='hostile'){
  ember.msgs.push({id:'b2',from:'me',ts:m(2),text:'waiting at a mailbox',status:'held',heldAt:'mailbox-operator'},
    {id:'b3',from:'me',ts:m(1),text:'gave up',status:'failed',error:'refused'});
  const base=STATE;
  STATE=()=>{const st=taint(base());st.type='state';st.daemon.tor.error='tor said no';st.daemon.tor=taint(st.daemon.tor,true);return st;};
}
class FakeWS{
  constructor(){this.readyState=0;window.__ws=this;
    if(MODE==='drop'){window.__n=(window.__n||0)+1;
      if(window.__n===1){setTimeout(()=>{this.readyState=1;this.onopen&&this.onopen();this._emit(STATE());},30);
        setTimeout(()=>{this.readyState=3;this.onclose&&this.onclose();},700);return;}
      if(!window.__allow){setTimeout(()=>{this.readyState=3;this.onclose&&this.onclose();},30);return;}
      setTimeout(()=>{this.readyState=1;this.onopen&&this.onopen();this._emit(STATE());},30);return;}
    if(MODE==='down'){setTimeout(()=>{this.readyState=3;this.onclose&&this.onclose();},30);return;}
    setTimeout(()=>{this.readyState=1;this.onopen&&this.onopen();this._emit(STATE());},MODE==='slow'?4000:30);}
  _emit(o){this.onmessage&&this.onmessage({data:JSON.stringify(o)});}
  send(s){const o=JSON.parse(s);window.__sent=(window.__sent||[]).concat(o);
    if(o.type==='hello')this._emit(STATE());
    if(o.type==='share.get')this._emit({type:'share',link:STATE().daemon.share,svg:window.__QR_SVG||null,fp:'54f42d4a9a31820cb0e17f3a62d9c855'});
    if(o.type==='room.invite')this._emit({type:'room.invite',room:o.room,link:'nodesignal-room:'+o.room+'?name=relay+policy&host='+ONION+'&port=8788&fp=54f42d4a9a31820cb0e17f3a62d9c855'});
    if(o.type==='chat.send'){const id='x'+Math.random().toString(36).slice(2);
      this._emit({type:'chat.recv',host:o.host,msg:{id,from:'me',ts:Date.now(),text:o.text,status:'sending'}});
      setTimeout(()=>this._emit({type:'chat.status',host:o.host,id,status:'delivered'}),400);}
  }
  close(){this.readyState=3;}
}
window.WebSocket=FakeWS;
})();
