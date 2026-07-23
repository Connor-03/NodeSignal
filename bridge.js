// bridge.js — NodeSignal local TCP <-> WebSocket bridge
// ============================================================================
// >> DO NOT DOUBLE-CLICK THIS FILE ON WINDOWS. <<
// Double-clicking hands it to Windows Script Host (Microsoft JScript), which
// does not understand `require` or `const` and will throw:
//     "Syntax error, Code: 800A03EA, Microsoft JScript compilation error"
// That is the wrong interpreter, not a bug in this file.
//
// Run it with Node.js instead:
//     - double-click start-bridge.bat  (does everything for you), or
//     - open a terminal in this folder and run:  node bridge.js
// ============================================================================
// Browsers can't open raw TCP sockets, so this relay runs on YOUR machine,
// opens the real TCP connection to a clearnet host, and forwards it to
// nodesignal.html over a WebSocket.
//
// Two protocol modes:
//   p2p      — real Bitcoin peer-to-peer. Performs the version/verack
//              handshake, so you get the peer's ACTUAL user agent
//              (/Satoshi:29.0.0/, /Satoshi:28.1.0(knots...)/ ...), protocol
//              version, service flags and chain height. Then relays inv /
//              headers / addr / ping traffic and answers pings.
//   stratum  — mining pool. Sends mining.subscribe and relays job traffic.
//
// Mode is auto-detected from the port (8333/18333/38333/48333 -> p2p),
// or you can force it with {mode:"p2p"|"stratum"}.
//
//   Setup (once):   npm install ws
//   Run:            node bridge.js
//   Then:           open nodesignal.html LOCALLY (file:// or http://localhost).
//                   An https page cannot reach ws://localhost.
//
// Read-only by design: it never sends a transaction, never submits a mining
// share, and never authorizes a worker.
// ============================================================================

const net = require('net');
const crypto = require('crypto');
let WebSocketServer;
try { ({ WebSocketServer } = require('ws')); }
catch (e) { console.error('\n  Missing dependency. Run:  npm install ws\n'); process.exit(1); }

const PORT = 8787;

/* ---------------------------------------------------------------- helpers */
const sha256 = b => crypto.createHash('sha256').update(b).digest();
const dsha   = b => sha256(sha256(b));

const NETWORKS = {
  8333:  { name: 'mainnet', magic: Buffer.from('f9beb4d9', 'hex') },
  18333: { name: 'testnet', magic: Buffer.from('0b110907', 'hex') },
  38333: { name: 'signet',  magic: Buffer.from('0a03cf40', 'hex') },
  48333: { name: 'regtest', magic: Buffer.from('fabfb5da', 'hex') },
};
const P2P_PORTS = Object.keys(NETWORKS).map(Number);

function encVarInt(n) {
  if (n < 0xfd) { const b = Buffer.alloc(1); b[0] = n; return b; }
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
  if (n <= 0xffffffff) { const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = 0xff; b.writeBigUInt64LE(BigInt(n), 1); return b;
}
function readVarInt(buf, off) {
  const f = buf[off];
  if (f < 0xfd) return [f, off + 1];
  if (f === 0xfd) return [buf.readUInt16LE(off + 1), off + 3];
  if (f === 0xfe) return [buf.readUInt32LE(off + 1), off + 5];
  return [Number(buf.readBigUInt64LE(off + 1)), off + 9];
}
function encVarStr(s) { const b = Buffer.from(s, 'ascii'); return Buffer.concat([encVarInt(b.length), b]); }

function netAddr(services, ip, port) {
  const b = Buffer.alloc(26);
  b.writeBigUInt64LE(BigInt(services), 0);
  b[18] = 0xff; b[19] = 0xff;                       // IPv4-mapped IPv6
  const parts = String(ip).split('.').map(Number);
  if (parts.length === 4 && parts.every(x => x >= 0 && x <= 255)) {
    b[20] = parts[0]; b[21] = parts[1]; b[22] = parts[2]; b[23] = parts[3];
  }
  b.writeUInt16BE(port & 0xffff, 24);
  return b;
}
function frame(magic, command, payload) {
  const cmd = Buffer.alloc(12); cmd.write(command, 'ascii');
  const len = Buffer.alloc(4); len.writeUInt32LE(payload.length, 0);
  return Buffer.concat([magic, cmd, len, dsha(payload).slice(0, 4), payload]);
}

const CONNECT_TIMEOUT = 8000;   // ms before we give up on a silent host

function explain(err, host, port) {
  const c = (err && err.code) || '';
  if (c === 'ETIMEDOUT') return `No response from ${host}:${port} (ETIMEDOUT). Nothing answered at all, which means: the port isn't open/forwarded, a firewall is dropping it, or you're on the SAME network as the node and your router can't loop back to its own public IP — in that case use the node's local IP (192.168.x.x) or 127.0.0.1.`;
  if (c === 'ECONNREFUSED') return `${host}:${port} actively refused the connection (ECONNREFUSED). The host is reachable but nothing is listening on that port — check the port number and that the node has listen=1.`;
  if (c === 'EHOSTUNREACH') return `${host} is unreachable (EHOSTUNREACH). Check the address and your network route.`;
  if (c === 'ENETUNREACH') return `Network unreachable for ${host} (ENETUNREACH).`;
  if (c === 'ENOTFOUND') return `${host} could not be resolved (ENOTFOUND). Check the hostname.`;
  if (c === 'ECONNRESET') return `${host}:${port} reset the connection (ECONNRESET). It may have dropped or banned us mid-handshake.`;
  return (err && err.message) || String(err);
}

/* ---- What a peer tells us about itself, mapped to BIPs -------------------
   Two honest sources, no guessing:
     DECLARED   — tokens the operator put in their own user agent string.
                  This is the established convention for a non-mining node to
                  advertise a position (cf. /Satoshi:0.14.0(UASF-SegWit-BIP148)/).
     SUPPORTS   — capabilities proven by service bits and by the protocol
                  messages the peer actually sends during the handshake.
   Block version-bit signalling (BIP-9) is deliberately NOT used here: those
   bits come from whoever mined the block, not from the peer we're talking to. */
const SERVICE_BIPS = {
  NODE_BLOOM: 'BIP-37',
  NODE_GETUTXO: 'BIP-64',
  NODE_WITNESS: 'BIP-141 segwit',
  NODE_COMPACT_FILTERS: 'BIP-157/158',
  NODE_NETWORK_LIMITED: 'BIP-159',
  NODE_P2P_V2: 'BIP-324 v2 transport',
};
const MSG_BIPS = {
  sendheaders: 'BIP-130',
  sendcmpct: 'BIP-152',
  feefilter: 'BIP-133',
  sendaddrv2: 'BIP-155',
  wtxidrelay: 'BIP-339',
};
// Pull any BIP tokens the operator wrote into their user agent.
function declaredFromUA(ua) {
  const out = [];
  const re = /BIP[\s_-]?(\d{1,4})/gi;
  let m;
  while ((m = re.exec(ua)) !== null) out.push('BIP-' + m[1]);
  if (/UASF/i.test(ua)) out.push('UASF');
  if (/NO2X|noseg2x/i.test(ua)) out.push('NO2X');
  return [...new Set(out)];
}

const SERVICE_BITS = [
  [1n, 'NODE_NETWORK'], [2n, 'NODE_GETUTXO'], [4n, 'NODE_BLOOM'], [8n, 'NODE_WITNESS'],
  [64n, 'NODE_COMPACT_FILTERS'], [1024n, 'NODE_NETWORK_LIMITED'], [2048n, 'NODE_P2P_V2'],
];
function decodeServices(s) {
  const out = [];
  for (const [bit, name] of SERVICE_BITS) if ((s & bit) === bit) out.push(name);
  return out;
}
function implFromUA(ua) {
  if (/knots/i.test(ua)) return 'Bitcoin Knots';
  if (/satoshi/i.test(ua)) return 'Bitcoin Core';
  if (/btcd/i.test(ua)) return 'btcd';
  if (/libbitcoin/i.test(ua)) return 'libbitcoin';
  if (/bcoin/i.test(ua)) return 'Bcoin';
  if (/bitcoinj/i.test(ua)) return 'bitcoinj';
  return 'Unknown';
}
function verFromUA(ua) {
  const knots = ua.match(/knots(\d+)/i);
  const m = ua.match(/:([0-9][0-9.]*)/);
  const base = m ? 'v' + m[1].replace(/\.0$/, '') : ua;
  return knots ? `${base}.knots${knots[1]}` : base;
}
function parseVersion(p) {
  let o = 0;
  const version = p.readInt32LE(o); o += 4;
  const services = p.readBigUInt64LE(o); o += 8;
  const timestamp = Number(p.readBigInt64LE(o)); o += 8;
  o += 26; o += 26; o += 8;                          // addr_recv, addr_from, nonce
  const [ualen, o2] = readVarInt(p, o); o = o2;
  const userAgent = p.slice(o, o + ualen).toString('ascii'); o += ualen;
  const startHeight = p.readInt32LE(o); o += 4;
  const relay = o < p.length ? !!p[o] : true;
  return { version, services, timestamp, userAgent, startHeight, relay };
}
const INV_TYPE = { 1: 'tx', 2: 'block', 3: 'filtered-block', 4: 'cmpct-block',
                   0x40000001: 'tx', 0x40000002: 'block' };
function summarizeInv(p) {
  try {
    let [count, o] = readVarInt(p, 0);
    const tally = {};
    for (let i = 0; i < count && o + 36 <= p.length; i++) {
      const t = INV_TYPE[p.readUInt32LE(o)] || 'other';
      tally[t] = (tally[t] || 0) + 1; o += 36;
    }
    return Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(', ') || `${count} items`;
  } catch { return 'unparsed'; }
}
function parseAddr(p, v2) {
  const out = [];
  try {
    let [count, o] = readVarInt(p, 0);
    for (let i = 0; i < count && i < 1000; i++) {
      if (v2) {
        o += 4;                                       // time
        const [, o1] = readVarInt(p, o); o = o1;      // services (varint)
        const netId = p[o]; o += 1;
        const [alen, o2] = readVarInt(p, o); o = o2;
        const addr = p.slice(o, o + alen); o += alen;
        const port = p.readUInt16BE(o); o += 2;
        if (netId === 1 && alen === 4) out.push({ ip: Array.from(addr).join('.'), port });
      } else {
        o += 4;                                       // time
        o += 8;                                       // services
        const ip = p.slice(o, o + 16); o += 16;
        const port = p.readUInt16BE(o); o += 2;
        if (ip[10] === 0xff && ip[11] === 0xff) out.push({ ip: Array.from(ip.slice(12)).join('.'), port });
      }
    }
  } catch { /* partial parse is fine */ }
  return out;
}

/* ------------------------------------------------------------ server */
const wss = new WebSocketServer({ port: PORT });
console.log(`NodeSignal bridge up -> ws://localhost:${PORT}`);
console.log('Modes: p2p (ports 8333/18333/38333/48333) · stratum (everything else)');
console.log('Open nodesignal.html locally, then use "Live connect" on a node.\n');

wss.on('connection', (ws) => {
  let tcp = null;
  const send = (o) => { try { ws.send(JSON.stringify(o)); } catch (_) {} };
  const log = (l) => { console.log('  <- ' + String(l).slice(0, 130)); send({ type: 'data', line: l }); };

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch (_) { return; }

    /* ---- connect ---- */
    if (msg.type === 'connect') {
      const host = String(msg.host);
      const port = Number(msg.port);
      const mode = msg.mode || (P2P_PORTS.includes(port) ? 'p2p' : 'stratum');
      const net_ = NETWORKS[port] || NETWORKS[8333];
      const t0 = Date.now();
      console.log(`-> ${mode.toUpperCase()} connect ${host}:${port}`);

      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        const msg = explain({ code: 'ETIMEDOUT' }, host, port);
        console.log('  !! ' + msg);
        send({ type: 'status', state: 'error', error: msg });
        if (tcp) tcp.destroy();
      }, CONNECT_TIMEOUT);

      tcp = net.connect({ host, port }, () => {
        settled = true; clearTimeout(timer);
        const latency = Date.now() - t0;
        send({ type: 'status', state: 'connected', latency, host, port, mode, network: net_.name });

        if (mode === 'stratum') {
          tcp.write(JSON.stringify({ id: 1, method: 'mining.subscribe', params: ['NodeSignal/0.1'] }) + '\n');
        } else {
          const payload = Buffer.concat([
            (() => { const b = Buffer.alloc(4); b.writeInt32LE(70016, 0); return b; })(),   // protocol version
            (() => { const b = Buffer.alloc(8); b.writeBigUInt64LE(0n, 0); return b; })(),  // our services: none
            (() => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(Math.floor(Date.now() / 1000)), 0); return b; })(),
            netAddr(0, host, port),                                                        // addr_recv
            netAddr(0, '0.0.0.0', 0),                                                      // addr_from
            crypto.randomBytes(8),                                                         // nonce
            encVarStr('/NodeSignal:0.1/'),
            (() => { const b = Buffer.alloc(4); b.writeInt32LE(0, 0); return b; })(),       // start_height
            Buffer.from([0]),                                                              // relay = false
          ]);
          tcp.write(frame(net_.magic, 'version', payload));
          log('-> sent version handshake');
        }
      });

      /* ---- stratum stream: line-delimited JSON ---- */
      let sbuf = '';
      /* ---- p2p stream: framed messages ---- */
      let pbuf = Buffer.alloc(0);
      /* ---- what this peer has told us about itself ---- */
      let declared = [];
      const supports = new Set();
      const noteSupport = (bip) => {
        if (!bip || supports.has(bip)) return;
        supports.add(bip);
        send({ type: 'signals', declared, supports: [...supports] });
      };

      tcp.on('data', (chunk) => {
        if (mode === 'stratum') {
          sbuf += chunk.toString('utf8');
          let i;
          while ((i = sbuf.indexOf('\n')) >= 0) {
            const line = sbuf.slice(0, i).trim(); sbuf = sbuf.slice(i + 1);
            if (line) log(line);
          }
          return;
        }

        pbuf = Buffer.concat([pbuf, chunk]);
        while (pbuf.length >= 24) {
          if (!pbuf.slice(0, 4).equals(net_.magic)) {          // resync on magic
            const idx = pbuf.indexOf(net_.magic, 1);
            if (idx < 0) { pbuf = Buffer.alloc(0); return; }
            pbuf = pbuf.slice(idx); continue;
          }
          const len = pbuf.readUInt32LE(16);
          if (len > 32 * 1024 * 1024) { pbuf = Buffer.alloc(0); return; }
          if (pbuf.length < 24 + len) return;                  // wait for the rest
          const command = pbuf.slice(4, 16).toString('ascii').replace(/\0+$/, '');
          const payload = pbuf.slice(24, 24 + len);
          pbuf = pbuf.slice(24 + len);

          if (command === 'version') {
            const v = parseVersion(payload);
            const services = decodeServices(v.services);
            declared = declaredFromUA(v.userAgent);
            for (const s of services) if (SERVICE_BIPS[s]) supports.add(SERVICE_BIPS[s]);
            send({
              type: 'peerinfo',
              userAgent: v.userAgent,
              impl: implFromUA(v.userAgent),
              version: verFromUA(v.userAgent),
              protocol: v.version,
              height: v.startHeight,
              services,
              declared,
              supports: [...supports],
              network: net_.name,
            });
            log(`version · ${v.userAgent} · protocol ${v.version} · height ${v.startHeight}`);
            if (services.length) log('services · ' + services.join(', '));
            if (declared.length) log('declared in user agent · ' + declared.join(', '));
            tcp.write(frame(net_.magic, 'verack', Buffer.alloc(0)));
          } else if (command === 'verack') {
            log('verack · handshake complete');
            send({ type: 'status', state: 'handshaked' });
            tcp.write(frame(net_.magic, 'getaddr', Buffer.alloc(0)));   // ask for its peers
          } else if (command === 'ping') {
            tcp.write(frame(net_.magic, 'pong', payload));
            log('ping -> pong');
          } else if (command === 'inv') {
            log('inv · ' + summarizeInv(payload));
          } else if (command === 'addr' || command === 'addrv2') {
            const list = parseAddr(payload, command === 'addrv2');
            log(`${command} · ${list.length} peer addresses`);
            if (list.length) send({ type: 'peers', list: list.slice(0, 40) });
          } else if (command === 'headers') {
            const [c] = readVarInt(payload, 0);
            log(`headers · ${c}`);
          } else if (command === 'feefilter') {
            noteSupport(MSG_BIPS.feefilter);
            log(`feefilter · ${Number(payload.readBigUInt64LE(0)) / 1000} sat/vB minimum`);
          } else if (command === 'sendcmpct' || command === 'sendheaders' || command === 'wtxidrelay' || command === 'sendaddrv2') {
            noteSupport(MSG_BIPS[command]);
            log(`${command}${MSG_BIPS[command] ? ' · ' + MSG_BIPS[command] : ''}`);
          } else if (command === 'reject') {
            log('reject · ' + payload.toString('ascii').replace(/[^\x20-\x7e]/g, ' ').trim());
          } else {
            log(`${command} · ${len} bytes`);
          }
        }
      });

      tcp.on('error', (err) => {
        if (settled && err.code === 'ETIMEDOUT') return;   // already reported by the guard
        settled = true; clearTimeout(timer);
        const msg = explain(err, host, port);
        console.log('  !! ' + msg);
        send({ type: 'status', state: 'error', error: msg });
      });
      tcp.on('close', () => send({ type: 'status', state: 'closed' }));

    /* ---- raw send from the composer ---- */
    } else if (msg.type === 'send' && tcp && !tcp.destroyed) {
      tcp.write(msg.line.endsWith('\n') ? msg.line : msg.line + '\n');

    } else if (msg.type === 'disconnect' && tcp) {
      tcp.destroy();
    }
  });

  ws.on('close', () => { if (tcp) tcp.destroy(); });
});
