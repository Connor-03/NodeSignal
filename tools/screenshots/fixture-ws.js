// fixture-ws.js: a fake daemon WebSocket for screenshots of nodesignal.html.
// Injected before the page's own script (Playwright addInitScript). Pick a
// scene with ?mode= : ok (default) | norpc | slow (connecting) | down (never
// connects) | drop (connects, then loses the daemon; set window.__allow=true
// to let it reconnect). All addresses are documentation ranges and all
// fingerprints are made up, so the images are safe to publish.
(()=>{
const MODE=(new URLSearchParams(location.search)).get('mode')||'ok';
const now=Date.now(), m=(min)=>now-min*60000;
const UAS=['/Satoshi:29.0.0/','/Satoshi:28.1.0/Knots:20250601/','/Satoshi:29.0.0/','/Satoshi:29.1.0/Knots:20250903/','/Satoshi:28.1.0/','/btcd:0.24.2/','/Satoshi:27.2.0/','/Satoshi:29.1.0/Knots:20250903/','/libbitcoin:4.0/','/Satoshi:29.0.0/','/bcoin:2.2.0/'];
const impl=u=>/knots/i.test(u)?'Bitcoin Knots':/satoshi/i.test(u)?'Bitcoin Core':/btcd/i.test(u)?'btcd':/libbitcoin/i.test(u)?'libbitcoin':/bcoin/i.test(u)?'Bcoin':'Unknown';
const ver=u=>{const k=u.match(/knots[:\s]*(\d+)/i),mm=u.match(/:([0-9][0-9.]*)/);const b=mm?'v'+mm[1].replace(/\.0$/,''):u;return k?b+'.knots'+k[1]:b;};
const LAT=[12,30,45,70,90,120,160,210,280,340,450,600,850];
const peers=Array.from({length:22},(_,i)=>{const ua=UAS[i%UAS.length];return {addr:(i%5===4?`[2001:db8::${(i+1).toString(16)}]:8333`:`${i%2?'203.0.113':'198.51.100'}.${10+i*7}:8333`),ua,impl:impl(ua),version:ver(ua),declared:[],latency:LAT[i%13]+(i%3)*4,inbound:i%3===0,height:950000};});
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
  msgs:[{id:'b1',from:'me',ts:m(5),text:'hey, saw you on my peer list. running nodesignald?',status:'failed',error:'timeout'}]};
const quiet={host:'2001:db8::5a',port:8788,nick:'',hasPin:false,unread:0,lastSeen:0,established:false,online:false,peerFp:null,peerInfo:null,msgs:[]};
const STATE=()=>({type:'state',daemon:{nick:'Alpha',ua:'/NodeSignal:1.2/',peerPort:8788,webPort:8789,fingerprint:'54f42d4a9a31820cb0e17f3a62d9c855',secure:true},
  node:MODE==='norpc'?{self:null,peers:[],error:'connect ECONNREFUSED 127.0.0.1:8332'}:{self,peers},
  contacts:MODE==='norpc'?[]:[kiwi,ember,quiet]});
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
    if(o.type==='chat.send'){const id='x'+Math.random().toString(36).slice(2);
      this._emit({type:'chat.recv',host:o.host,msg:{id,from:'me',ts:Date.now(),text:o.text,status:'sending'}});
      setTimeout(()=>this._emit({type:'chat.status',host:o.host,id,status:'delivered'}),400);}
  }
  close(){this.readyState=3;}
}
window.WebSocket=FakeWS;
})();
