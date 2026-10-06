// mock-node.js: a fake Bitcoin node for tests, Node standard library only.
//   · JSON-RPC on 127.0.0.1:<rpcPort> answering the three methods the daemon
//     uses (getnetworkinfo, getblockchaininfo, getpeerinfo), Basic auth u:p
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
function rpcServer({ port = 18332, host = '127.0.0.1', npeers = 22, nodesignalPeers = 0 } = {}) {
  const list = peers(npeers);
  // peers that advertise NodeSignal via `uacomment=nodesignal` in bitcoin.conf
  for (let i = 0; i < nodesignalPeers; i++)
    list.push({ addr: `192.0.2.${20 + i}:8333`, subver: '/Satoshi:29.0.0(nodesignal)/', pingtime: 0.04, inbound: false, synced_headers: 950000 });
  const srv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => (b += c));
    req.on('end', () => {
      if (req.headers.authorization !== 'Basic ' + Buffer.from('u:p').toString('base64')) { res.writeHead(401); return res.end(); }
      let j; try { j = JSON.parse(b); } catch { res.writeHead(400); return res.end(); }
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
  Promise.all([rpcServer(), p2pServer()]).then(() =>
    console.log('mock node: RPC 127.0.0.1:18332 (u:p), identify 127.0.0.2:8333'));
}
