// mock-node.js: a fake Bitcoin node for tests, Node standard library only.
//   · JSON-RPC on 127.0.0.1:<rpcPort> answering the three methods the daemon
//     uses (getnetworkinfo, getblockchaininfo, getpeerinfo), Basic auth u:p.
//     With conf: <bitcoin.conf> it also reads rpcauth=, rpcwhitelist= and
//     rpcwhitelistdefault= from that file the way bitcoind does: once, at
//     start (reload() plays a node restart), 401 for an unknown login, 403
//     for a method outside the user's whitelist.
//   · a :8333-style listener that answers the identify handshake with a real
//     `version` message plus a `sendheaders`
// Peer addresses use documentation ranges only (RFC 5737 / RFC 3849).
'use strict';
const http = require('http'), net = require('net'), crypto = require('crypto');

const UAS = ['/Satoshi:29.0.0/', '/Satoshi:28.1.0/Knots:20250601/', '/Satoshi:29.1.0/Knots:20250903/',
  '/btcd:0.24.2/', '/Satoshi:27.2.0/', '/libbitcoin:4.0/', '/bcoin:2.2.0/'];
function peers(n) {
  return Array.from({ length: n }, (_, i) => ({
    addr: i % 5 === 4 ? `[2001:db8::${(i + 1).toString(16)}]:8333` : `${i % 2 ? '203.0.113' : '198.51.100'}.${10 + i * 7}:8333`,
    subver: UAS[i % UAS.length], pingtime: 0.012 + (i % 13) * 0.05, inbound: i % 3 === 0, synced_headers: 950000,
  }));
}
// rpcauth/rpcwhitelist as bitcoind applies them (src/httprpc.cpp)
function readAuthConf(file) {
  const out = { rpcauth: [], whitelist: new Map(), whitelistDefault: null };
  if (!file) return out;
  for (const raw of require('fs').readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    if (/^\[/.test(line)) break;                            // top level only, enough here
    const m = /^-?(rpcauth|rpcwhitelist|rpcwhitelistdefault)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === 'rpcauth') { const a = /^([^:]+):([0-9a-f]+)\$([0-9a-f]{64})$/.exec(m[2]); if (a) out.rpcauth.push({ user: a[1], salt: a[2], hash: a[3] }); }
    else if (m[1] === 'rpcwhitelist') {
      const [user, methods = ''] = m[2].split(':');
      const set = new Set(methods.split(',').map((x) => x.trim()).filter(Boolean));
      out.whitelist.set(user, out.whitelist.has(user) ? new Set([...out.whitelist.get(user)].filter((x) => set.has(x))) : set);
    } else out.whitelistDefault = m[2] !== '0';
  }
  return out;
}
function rpcServer({ port = 18332, host = '127.0.0.1', npeers = 22, nodesignalPeers = 0, conf = null } = {}) {
  let ac = readAuthConf(conf);
  const loginOf = (header) => {
    const m = /^Basic (.+)$/.exec(header || '');
    if (!m) return null;
    const s = Buffer.from(m[1], 'base64').toString('utf8'), i = s.indexOf(':');
    const user = s.slice(0, i), pass = s.slice(i + 1);
    if (user === 'u' && pass === 'p') return user;
    for (const a of ac.rpcauth) if (a.user === user && crypto.createHmac('sha256', a.salt).update(pass).digest('hex') === a.hash) return user;
    return null;
  };
  const allowed = (user, method) => {
    if (ac.whitelist.has(user)) return ac.whitelist.get(user).has(method);
    const dflt = ac.whitelistDefault === null ? ac.whitelist.size > 0 : ac.whitelistDefault;
    return !dflt;                                           // whitelisting on by default: an empty list
  };
  const list = peers(npeers);
  // peers that advertise NodeSignal via `uacomment=nodesignal` in bitcoin.conf
  for (let i = 0; i < nodesignalPeers; i++)
    list.push({ addr: `192.0.2.${20 + i}:8333`, subver: '/Satoshi:29.0.0(nodesignal)/', pingtime: 0.04, inbound: false, synced_headers: 950000 });
  const srv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => (b += c));
    req.on('end', () => {
      const user = loginOf(req.headers.authorization);
      if (!user) { res.writeHead(401); return res.end(); }
      let j; try { j = JSON.parse(b); } catch { res.writeHead(400); return res.end(); }
      if (!allowed(user, j.method)) { res.writeHead(403); return res.end(); }
      const result = {
        getnetworkinfo: { subversion: '/Satoshi:29.0.0/', connections: list.length },
        getblockchaininfo: { blocks: 950000, chain: 'main', pruned: false },
        getpeerinfo: list,
      }[j.method];
      res.end(JSON.stringify(result === undefined
        ? { result: null, error: { code: -32601, message: 'Method not found' }, id: j.id }
        : { result, error: null, id: j.id }));
    });
  });
  srv.reload = () => { ac = readAuthConf(conf); };          // a node restart, as far as RPC logins go
  srv.peers = list;                                         // what getpeerinfo answers: tests may change it
  return new Promise((r) => srv.listen(port, host, () => r(srv)));
}
const MAGIC = Buffer.from('f9beb4d9', 'hex');
const dsha = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
function frame(cmd, p) {
  const c = Buffer.alloc(12); c.write(cmd);
  const l = Buffer.alloc(4); l.writeUInt32LE(p.length);
  return Buffer.concat([MAGIC, c, l, dsha(p).slice(0, 4), p]);
}
function p2pServer({ port = 8333, host = '127.0.0.2', ua = '/Satoshi:29.2.0/Knots:20251110/', height = 950032 } = {}) {
  const srv = net.createServer((s) => {
    s.on('error', () => { });
    s.once('data', () => {
      const u = Buffer.from(ua), h = Buffer.alloc(4); h.writeInt32LE(height);
      const payload = Buffer.concat([Buffer.from([0x80, 0x11, 0x01, 0]), Buffer.from([9, 4, 0, 0, 0, 0, 0, 0]),
        Buffer.alloc(8), Buffer.alloc(52), Buffer.alloc(8), Buffer.from([u.length]), u, h, Buffer.from([1])]);
      s.write(frame('version', payload)); s.write(frame('sendheaders', Buffer.alloc(0)));
    });
  });
  return new Promise((r) => srv.listen(port, host, () => r(srv)));
}
module.exports = { rpcServer, p2pServer, peers };

if (require.main === module) {
  // node tests/mock-node.js [--conf <bitcoin.conf>] [--no-p2p]
  const i = process.argv.indexOf('--conf');
  const conf = i > 0 ? process.argv[i + 1] : null;
  Promise.all([rpcServer({ conf }), process.argv.includes('--no-p2p') ? null : p2pServer()]).then(() =>
    console.log(`mock node: RPC 127.0.0.1:18332 (u:p${conf ? ' plus rpcauth from ' + conf : ''})` +
      (process.argv.includes('--no-p2p') ? '' : ', identify 127.0.0.2:8333')));
}
