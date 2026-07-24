#!/usr/bin/env node
// nodesignald.js — the NodeSignal daemon + self-hosted web app
// ============================================================================
// Operator-to-operator chat for Bitcoin nodes. Runs beside bitcoind/Knots and
// serves its own web interface, so you use it from any browser on your tailnet.
//
//   :8789  HTTP   web app (GET /) + WebSocket API (/ws) + GET /health
//   :8788  TCP    daemon <-> daemon encrypted messaging
//   :8333  TCP    outbound only — Bitcoin P2P handshake used to identify peers
//
//   discovery : getpeerinfo / getnetworkinfo / getblockchaininfo over RPC, so
//               the map shows the peers your node actually has
//   identify  : dials a peer's :8333 and reads its version message — user agent
//               (=> implementation, version, declared BIPs), height, service
//               bits, capability messages. Read-only.
//   transport : the Bitcoin protocol cannot carry chat, so messages travel
//               daemon-to-daemon on :8788, PBKDF2 -> AES-256-GCM under a
//               shared PIN.
//
// USAGE
//   node nodesignald.js [options]
//     --nick <name>        display name sent to peers      (default: hostname)
//     --web-port <n>       web app + WebSocket API         (default: 8789)
//     --peer-port <n>      daemon-to-daemon messaging      (default: 8788)
//     --web-token <secret> require login for the web UI    (default: open)
//     --bind <addr>        listen address                  (default: 0.0.0.0)
//     --web-root <dir>     where nodesignal.html lives     (default: this dir)
//     --data <dir>         state directory                 (default: ~/.nodesignal)
//     --rpc-url <url>      bitcoind/knots RPC              (default: http://127.0.0.1:8332)
//     --rpc-user <u> --rpc-pass <p>    RPC credentials, or:
//     --rpc-cookie <path>  cookie file (auto-tried: ~/.bitcoin/.cookie)
//     --no-rpc             standalone: no Bitcoin node on this machine
//
// Intended for a private tailnet. No router port forwarding is required or
// recommended; don't expose :8789 publicly without --web-token behind TLS.
//
// Dependencies: npm install express ws
// ============================================================================

'use strict';
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { subtle } = crypto.webcrypto;

let express, WebSocketServer;
try {
  express = require('express');
  ({ WebSocketServer } = require('ws'));
} catch {
  console.error('\n  Missing dependencies. Run:  npm install express ws\n');
  process.exit(1);
}

/* ------------------------------------------------------------ config */
const argv = process.argv.slice(2);
const arg = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : d; };
const flag = (n) => argv.includes('--' + n);

const CFG = {
  nick: arg('nick', os.hostname()),
  webPort: Number(arg('web-port', 8789)),
  peerPort: Number(arg('peer-port', 8788)),
  webToken: arg('web-token', ''),
  bind: arg('bind', '0.0.0.0'),
  webRoot: arg('web-root', __dirname),
  dataDir: arg('data', path.join(os.homedir(), '.nodesignal')),
  rpcUrl: arg('rpc-url', 'http://127.0.0.1:8332'),
  rpcUser: arg('rpc-user', ''),
  rpcPass: arg('rpc-pass', ''),
  rpcCookie: arg('rpc-cookie', ''),
  rpcConf: arg('rpc-conf', ''),
  noRpc: flag('no-rpc'),
  // Demo only: advertise a synthetic node identity to peers. Used by the
  // Windows demo machine, which has no Bitcoin node of its own, so it still
  // appears on other operators' maps as a classified node.
  impersonate: arg('impersonate', ''),
  impersonateHeight: Number(arg('impersonate-height', 0)) || 0,
};
const PROTO = 1;
const UA = '/NodeSignal:1.1/';
const log = (m) => console.log(new Date().toISOString().slice(11, 19) + '  ' + m);

/* ------------------------------------------------------------ storage */
fs.mkdirSync(CFG.dataDir, { recursive: true });
const STATE_FILE = path.join(CFG.dataDir, 'state.json');
let state = { contacts: {} };
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { /* fresh install */ }
if (!state.contacts) state.contacts = {};

let saveTimer = null, dirty = false;
function saveNow() {
  dirty = false;
  try {
    const tmp = STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, STATE_FILE);          // atomic: a crash can't truncate state
  } catch (e) { log('!! could not save state: ' + e.message); }
}
function save() { dirty = true; clearTimeout(saveTimer); saveTimer = setTimeout(saveNow, 100); }
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (dirty) saveNow(); process.exit(0); });
process.on('exit', () => { if (dirty) saveNow(); });

/* ------------------------------------------------------------ crypto */
const te = new TextEncoder(), td = new TextDecoder();
const SALT = te.encode('NodeSignal/1');
const keyCache = new Map();
async function pinKey(pin) {
  if (keyCache.has(pin)) return keyCache.get(pin);
  const base = await subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
  const key = await subtle.deriveKey({ name: 'PBKDF2', salt: SALT, iterations: 120000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  keyCache.set(pin, key);
  return key;
}
async function encMsg(pin, text) {
  const iv = crypto.randomBytes(12);
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv }, await pinKey(pin), te.encode(text)));
  return { iv: [...iv], ct: [...ct] };
}
async function decMsg(pin, m) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(m.iv) }, await pinKey(pin), new Uint8Array(m.ct));
  return td.decode(pt);
}

/* ------------------------------------------------------------ helpers */
const normIp = (a) => (a || '').replace(/^::ffff:/, '');
function implFromUA(ua) {
  if (/knots/i.test(ua)) return 'Bitcoin Knots';
  if (/satoshi/i.test(ua)) return 'Bitcoin Core';
  if (/btcd/i.test(ua)) return 'btcd';
  if (/libbitcoin/i.test(ua)) return 'libbitcoin';
  if (/bcoin/i.test(ua)) return 'Bcoin';
  return 'Unknown';
}
function verFromUA(ua) {
  const knots = ua.match(/knots[:\s]*(\d+)/i);
  const m = ua.match(/:([0-9][0-9.]*)/);
  const base = m ? 'v' + m[1].replace(/\.0$/, '') : ua;
  return knots ? `${base}.knots${knots[1]}` : base;
}
function declaredFromUA(ua) {
  const out = []; let m;
  const re = /BIP[\s_-]?(\d{1,4})/gi;
  while ((m = re.exec(ua)) !== null) out.push('BIP-' + m[1]);
  if (/UASF/i.test(ua)) out.push('UASF');
  if (/NO2X/i.test(ua)) out.push('NO2X');
  return [...new Set(out)];
}

/* ---- synthetic identity (demo machines with no Bitcoin node) ---- */
let IMPERSONATED = null;
function buildImpersonation() {
  if (!CFG.impersonate) return null;
  const ua = CFG.impersonate;
  return {
    ua, impl: implFromUA(ua), version: verFromUA(ua), declared: declaredFromUA(ua),
    height: CFG.impersonateHeight || 0,
    network: 'mainnet', connections: 0, simulated: true,
  };
}

/* ------------------------------------------------------------ node RPC */
const rpc = { ok: false, self: null, peers: [], error: 'not configured' };
/* Credential discovery. bitcoind/Knots can be configured half a dozen ways and
   the daemon may run as a different user than the node, so we try each source
   in turn and REMEMBER what we tried — a silent "not connected" is useless to
   an operator. Re-run on every call because the cookie rotates on restart. */
function parseBitcoinConf(file) {
  try {
    const txt = fs.readFileSync(file, 'utf8');
    const out = {}; let section = '';
    for (let line of txt.split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      const sec = line.match(/^\[(\w+)\]$/);
      if (sec) { section = sec[1].toLowerCase(); continue; }
      if (section && section !== 'main') continue;        // ignore testnet/signet blocks
      const i = line.indexOf('=');
      if (i < 0) continue;
      const k = line.slice(0, i).trim().toLowerCase();
      if (!(k in out)) out[k] = line.slice(i + 1).trim();
    }
    return out;
  } catch { return null; }
}
function readCookie(file, tried) {
  try {
    const s = fs.readFileSync(file, 'utf8').trim();
    tried.push({ path: file, result: 'ok' });
    return s;
  } catch (e) {
    tried.push({ path: file, result:
      e.code === 'EACCES' ? 'permission denied — the daemon user cannot read it'
      : e.code === 'ENOENT' ? 'not found' : (e.code || 'error') });
    return null;
  }
}
const COOKIE_PATHS = [
  path.join(os.homedir(), '.bitcoin', '.cookie'),
  '/var/lib/bitcoind/.cookie',
  '/var/lib/bitcoin/.cookie',
  '/home/bitcoin/.bitcoin/.cookie',
  path.join(os.homedir(), 'snap', 'bitcoin-core', 'common', '.bitcoin', '.cookie'),
];
const CONF_PATHS = [
  path.join(os.homedir(), '.bitcoin', 'bitcoin.conf'),
  '/etc/bitcoin/bitcoin.conf',
  '/var/lib/bitcoind/bitcoin.conf',
];
const rpcDiag = { source: null, tried: [], port: null };
function rpcAuth() {
  const tried = [];
  if (CFG.rpcUser) { rpcDiag.source = '--rpc-user / --rpc-pass'; rpcDiag.tried = tried; return CFG.rpcUser + ':' + CFG.rpcPass; }
  if (CFG.rpcCookie) {
    const c = readCookie(CFG.rpcCookie, tried);
    if (c) { rpcDiag.source = 'cookie ' + CFG.rpcCookie; rpcDiag.tried = tried; return c; }
  }
  for (const cp of [CFG.rpcConf, ...CONF_PATHS].filter(Boolean)) {
    const conf = parseBitcoinConf(cp);
    if (!conf) { tried.push({ path: cp, result: 'no bitcoin.conf here' }); continue; }
    tried.push({ path: cp, result: 'read ok' });
    if (conf.rpcport) rpcDiag.port = conf.rpcport;
    if (conf.rpcuser && conf.rpcpassword) {
      rpcDiag.source = 'rpcuser/rpcpassword in ' + cp; rpcDiag.tried = tried;
      return conf.rpcuser + ':' + conf.rpcpassword;
    }
    // rpcauth= stores a salted hash, so the password is NOT recoverable from
    // the file. Say so plainly instead of reporting a vague failure.
    if (conf.rpcauth && !conf.rpcpassword) {
      tried.push({ path: cp, result:
        'uses rpcauth= (hashed) — the password cannot be read from this file; ' +
        'pass --rpc-user/--rpc-pass in the systemd unit, or add plain ' +
        'rpcuser=/rpcpassword= lines and restart bitcoind' });
    }
    if (conf.rpccookiefile) {
      const c = readCookie(conf.rpccookiefile, tried);
      if (c) { rpcDiag.source = 'cookie ' + conf.rpccookiefile + ' (from ' + cp + ')'; rpcDiag.tried = tried; return c; }
    }
    if (conf.datadir) {
      const c = readCookie(path.join(conf.datadir, '.cookie'), tried);
      if (c) { rpcDiag.source = 'cookie in datadir ' + conf.datadir; rpcDiag.tried = tried; return c; }
    }
  }
  for (const cpath of COOKIE_PATHS) {
    const c = readCookie(cpath, tried);
    if (c) { rpcDiag.source = 'cookie ' + cpath; rpcDiag.tried = tried; return c; }
  }
  rpcDiag.source = null; rpcDiag.tried = tried;
  return null;
}
function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    const auth = rpcAuth();
    if (!auth) return reject(new Error('no RPC credentials (--rpc-user/--rpc-pass or --rpc-cookie)'));
    const u = new URL(CFG.rpcUrl);
    if (rpcDiag.port && u.port === '8332' && !argv.includes('--rpc-url')) u.port = rpcDiag.port;
    const body = JSON.stringify({ jsonrpc: '1.0', id: 'ns', method, params });
    const req = http.request({
      hostname: u.hostname, port: u.port || 8332, path: '/', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'Authorization': 'Basic ' + Buffer.from(auth).toString('base64') }, timeout: 5000,
    }, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        try { const j = JSON.parse(d); j.error ? reject(new Error(j.error.message)) : resolve(j.result); }
        catch { reject(new Error('bad RPC response (' + res.statusCode + ')')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('RPC timeout')));
    req.end(body);
  });
}
async function pollRpc() {
  if (CFG.noRpc) { rpc.error = 'disabled (--no-rpc)'; return; }
  try {
    const [ni, ch, pr] = await Promise.all([rpcCall('getnetworkinfo'), rpcCall('getblockchaininfo'), rpcCall('getpeerinfo')]);
    const wasDown = !rpc.ok;
    rpc.ok = true; rpc.error = null;
    rpc.self = { ua: ni.subversion, impl: implFromUA(ni.subversion), version: verFromUA(ni.subversion),
      declared: declaredFromUA(ni.subversion), height: ch.blocks, network: ch.chain, connections: ni.connections };
    rpc.peers = pr.map(p => ({
      addr: p.addr, ua: p.subver, impl: implFromUA(p.subver || ''), version: verFromUA(p.subver || ''),
      declared: declaredFromUA(p.subver || ''),
      latency: p.pingtime != null ? Math.round(p.pingtime * 1000) : null,
      inbound: !!p.inbound, height: p.synced_headers ?? null }));
    rpc._loggedFail = false;
    if (wasDown) log(`node RPC ok via ${rpcDiag.source || 'credentials'} — ${rpc.self.ua} · height ${rpc.self.height} · ${rpc.peers.length} peers`);
    broadcastUi({ type: 'node', self: rpc.self, peers: rpc.peers });
  } catch (e) {
    const was = rpc.ok;
    rpc.ok = false; rpc.error = e.message;
    if (was || !rpc._loggedFail) {
      rpc._loggedFail = true;
      log('!! Bitcoin RPC not connected: ' + e.message);
      if (!rpcDiag.source && rpcDiag.tried.length) {
        log('   looked for credentials in:');
        for (const t of rpcDiag.tried) log(`     ${t.path}  ->  ${t.result}`);
        log('   fix: add rpcuser=/rpcpassword= to bitcoin.conf and restart, or');
        log('        run this service as the user that owns the .cookie file, or');
        log('        pass --rpc-cookie /path/to/.cookie in the systemd unit');
      }
      broadcastUi({ type: 'node', self: null, peers: [], error: rpc.error, diag: rpcDiag });
    }
  }
}

/* ------------------------------------------------------------ P2P identify (:8333) */
const NETWORKS = {
  8333: { name: 'mainnet', magic: Buffer.from('f9beb4d9', 'hex') },
  18333: { name: 'testnet', magic: Buffer.from('0b110907', 'hex') },
  38333: { name: 'signet', magic: Buffer.from('0a03cf40', 'hex') },
  48333: { name: 'regtest', magic: Buffer.from('fabfb5da', 'hex') },
};
const dsha = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
const encVarInt = (n) => { if (n < 0xfd) return Buffer.from([n]); const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; };
const encVarStr = (s) => { const b = Buffer.from(s, 'ascii'); return Buffer.concat([encVarInt(b.length), b]); };
function readVarInt(buf, off) {
  const f = buf[off];
  if (f < 0xfd) return [f, off + 1];
  if (f === 0xfd) return [buf.readUInt16LE(off + 1), off + 3];
  if (f === 0xfe) return [buf.readUInt32LE(off + 1), off + 5];
  return [Number(buf.readBigUInt64LE(off + 1)), off + 9];
}
const netAddr = () => { const b = Buffer.alloc(26); b[18] = 0xff; b[19] = 0xff; return b; };
function p2pFrame(magic, command, payload) {
  const cmd = Buffer.alloc(12); cmd.write(command, 'ascii');
  const len = Buffer.alloc(4); len.writeUInt32LE(payload.length, 0);
  return Buffer.concat([magic, cmd, len, dsha(payload).slice(0, 4), payload]);
}
const SERVICE_BITS = [[1n, 'NODE_NETWORK'], [2n, 'NODE_GETUTXO'], [4n, 'NODE_BLOOM'], [8n, 'NODE_WITNESS'],
  [64n, 'NODE_COMPACT_FILTERS'], [1024n, 'NODE_NETWORK_LIMITED'], [2048n, 'NODE_P2P_V2']];
const SERVICE_BIPS = { NODE_BLOOM: 'BIP-37', NODE_GETUTXO: 'BIP-64', NODE_WITNESS: 'BIP-141 segwit',
  NODE_COMPACT_FILTERS: 'BIP-157/158', NODE_NETWORK_LIMITED: 'BIP-159', NODE_P2P_V2: 'BIP-324 v2 transport' };
const MSG_BIPS = { sendheaders: 'BIP-130', sendcmpct: 'BIP-152', feefilter: 'BIP-133',
  sendaddrv2: 'BIP-155', wtxidrelay: 'BIP-339' };
const decodeServices = (s) => { const o = []; for (const [b, n] of SERVICE_BITS) if ((s & b) === b) o.push(n); return o; };
function parseVersionMsg(p) {
  let o = 0;
  const version = p.readInt32LE(o); o += 4;
  const services = p.readBigUInt64LE(o); o += 8;
  o += 8 + 26 + 26 + 8;
  const [ualen, o2] = readVarInt(p, o); o = o2;
  const userAgent = p.slice(o, o + ualen).toString('ascii'); o += ualen;
  return { version, services, userAgent, startHeight: p.readInt32LE(o) };
}
function identifyP2P(host, port) {
  port = Number(port) || 8333;
  const net_ = NETWORKS[port] || NETWORKS[8333];
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const sock = net.connect({ host, port });
    let info = null, done = false, pbuf = Buffer.alloc(0), linger = null;
    const supports = new Set();
    const finish = (err) => {
      if (done) return; done = true;
      clearTimeout(hard); clearTimeout(linger); sock.destroy();
      if (err) return reject(err);
      if (!info) return reject(new Error('no version message from ' + host + ':' + port));
      info.supports = [...supports];
      resolve(info);
    };
    const hard = setTimeout(() => finish(new Error('timeout — nothing answered on ' + host + ':' + port)), 9000);
    sock.on('connect', () => {
      sock._latency = Date.now() - t0;
      sock.write(p2pFrame(net_.magic, 'version', Buffer.concat([
        (() => { const b = Buffer.alloc(4); b.writeInt32LE(70016, 0); return b; })(),
        Buffer.alloc(8),
        (() => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(Math.floor(Date.now() / 1000)), 0); return b; })(),
        netAddr(), netAddr(), crypto.randomBytes(8), encVarStr(UA), Buffer.alloc(4), Buffer.from([0]),
      ])));
    });
    sock.on('data', (chunk) => {
      pbuf = Buffer.concat([pbuf, chunk]);
      while (pbuf.length >= 24) {
        if (!pbuf.slice(0, 4).equals(net_.magic)) {
          const i = pbuf.indexOf(net_.magic, 1);
          if (i < 0) { pbuf = Buffer.alloc(0); return; }
          pbuf = pbuf.slice(i); continue;
        }
        const len = pbuf.readUInt32LE(16);
        if (len > 4 * 1024 * 1024) return finish(new Error('oversized frame'));
        if (pbuf.length < 24 + len) return;
        const command = pbuf.slice(4, 16).toString('ascii').replace(/\0+$/, '');
        const payload = pbuf.slice(24, 24 + len);
        pbuf = pbuf.slice(24 + len);
        if (command === 'version') {
          const v = parseVersionMsg(payload);
          const services = decodeServices(v.services);
          for (const s of services) if (SERVICE_BIPS[s]) supports.add(SERVICE_BIPS[s]);
          info = { ua: v.userAgent, impl: implFromUA(v.userAgent), version: verFromUA(v.userAgent),
            protocol: v.version, height: v.startHeight, services, declared: declaredFromUA(v.userAgent),
            network: net_.name, latency: sock._latency ?? null, source: 'p2p:' + port, at: Date.now() };
          sock.write(p2pFrame(net_.magic, 'verack', Buffer.alloc(0)));
          linger = setTimeout(() => finish(), 2200);      // catch capability messages
        } else if (MSG_BIPS[command]) supports.add(MSG_BIPS[command]);
      }
    });
    sock.on('error', (e) => finish(new Error(
      e.code === 'ECONNREFUSED' ? 'refused — nothing listening on ' + host + ':' + port
        : e.code === 'ETIMEDOUT' ? 'timeout — port closed, firewalled, or unreachable' : e.message)));
  });
}
async function identifyContact(host, port) {
  const info = await identifyP2P(host, port);
  const c = contact(host, true);
  c.peerInfo = info; c.lastSeen = c.lastSeen || 0; delete c._idRetry; save();
  broadcastUi({ type: 'contact', contact: uiContact(c) });
  log(`identified ${host}: ${info.ua} · height ${info.height}`);
  return info;
}
// Contacts added before their node is reachable retry on a backoff
// (5s,10s,20s,40s,60s cap) so they self-identify with no manual action.
// After MAX_ID_TRIES we stop: some peers legitimately have no Bitcoin node
// on :8333 (a laptop running only NodeSignal), and endlessly retrying would
// just spam the log. The "identify" button re-runs it on demand.
const MAX_ID_TRIES = 6;
const idTimers = new Map();
function scheduleIdentify(host, delay) {
  host = normIp(host);
  if (idTimers.has(host)) return;
  const c = state.contacts[host];
  if (!c || c.peerInfo) return;
  if ((c._idRetry || 0) >= MAX_ID_TRIES) return;
  const wait = delay ?? Math.min(60000, 5000 * Math.pow(2, c._idRetry || 0));
  idTimers.set(host, setTimeout(async () => {
    idTimers.delete(host);
    const cc = state.contacts[host];
    if (!cc || cc.peerInfo) return;
    try { await identifyContact(host, 8333); }
    catch {
      cc._idRetry = (cc._idRetry || 0) + 1;
      if (cc._idRetry >= MAX_ID_TRIES)
        log(`identify ${host}: giving up after ${MAX_ID_TRIES} tries (no Bitcoin node there?) — messaging still works`);
      else scheduleIdentify(host);
    }
  }, wait));
}

/* ------------------------------------------------------------ contacts */
function contact(host, create) {
  host = normIp(host);
  if (!state.contacts[host] && create)
    state.contacts[host] = { host, port: CFG.peerPort, nick: '', pin: '', msgs: [], unread: 0, lastSeen: 0, peerInfo: null };
  return state.contacts[host];
}
function pushMsg(c, m) { c.msgs.push(m); if (c.msgs.length > 500) c.msgs.splice(0, c.msgs.length - 500); save(); }
async function tryDecryptStored(c) {
  if (!c.pin) return;
  for (const m of c.msgs) if (m.enc && m.text == null) {
    try { m.text = await decMsg(c.pin, m.enc); delete m.locked; } catch { m.locked = true; }
  }
  save();
}

/* ------------------------------------------------------------ peer wire (:8788) */
const helloPayload = () => ({ t: 'hello', proto: PROTO, nick: CFG.nick, ua: UA,
  peerPort: CFG.peerPort, node: rpc.ok ? rpc.self : (IMPERSONATED || null) });
function lineStream(sock, onLine) {
  let buf = '';
  sock.on('data', d => {
    buf += d.toString('utf8');
    if (buf.length > 1e6) { sock.destroy(); return; }
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      let j; try { j = JSON.parse(line); } catch { continue; }
      onLine(j);
    }
  });
}
const sendLine = (s, o) => { try { s.write(JSON.stringify(o) + '\n'); } catch { } };

const peerServer = net.createServer((sock) => {
  const host = normIp(sock.remoteAddress);
  sock.setTimeout(120000, () => sock.destroy());
  lineStream(sock, async (m) => {
    if (m.t === 'hello') {
      const c = contact(host, true);
      if (m.nick && !c.nick) c.nick = m.nick;
      if (m.peerPort) c.port = Number(m.peerPort) || c.port;
      if (m.node) c.peerInfo = Object.assign({}, c.peerInfo, m.node);
      c.lastSeen = Date.now(); save();
      sendLine(sock, helloPayload());
      broadcastUi({ type: 'contact', contact: uiContact(c) });
      scheduleIdentify(host, 1000);
    } else if (m.t === 'msg') {
      const c = contact(host, true);
      c.lastSeen = Date.now();
      const rec = { id: m.id || crypto.randomUUID(), from: 'them', ts: m.ts || Date.now() };
      if (m.iv && m.ct) {
        rec.enc = { iv: m.iv, ct: m.ct };
        if (c.pin) { try { rec.text = await decMsg(c.pin, rec.enc); } catch { rec.locked = true; } }
        else rec.locked = true;
      } else if (typeof m.text === 'string') rec.text = String(m.text).slice(0, 4000);
      else return;
      c.unread++; pushMsg(c, rec);
      sendLine(sock, { t: 'ack', id: rec.id });
      log(`msg from ${c.nick || host}${rec.locked ? ' (locked — PIN not set)' : ''}`);
      broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec), unread: c.unread });
    } else if (m.t === 'ping') sendLine(sock, { t: 'pong' });
  });
  sock.on('error', () => { });
});

function sendToPeer(c, text) {
  return new Promise(async (resolve) => {
    const id = crypto.randomUUID();
    const rec = { id, from: 'me', ts: Date.now(), text, status: 'sending' };
    pushMsg(c, rec);
    broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec) });
    const fail = (why) => {
      rec.status = 'failed'; rec.error = why; save();
      broadcastUi({ type: 'chat.status', host: c.host, id, status: 'failed', error: why });
      resolve({ ok: false, error: why });
    };
    const payload = c.pin ? { t: 'msg', id, ts: rec.ts, ...(await encMsg(c.pin, text)) } : { t: 'msg', id, ts: rec.ts, text };
    const sock = net.connect({ host: c.host, port: c.port || CFG.peerPort });
    let done = false;
    const finish = (fn) => { if (!done) { done = true; clearTimeout(timer); sock.destroy(); fn(); } };
    const timer = setTimeout(() => finish(() => fail(
      'timeout — is nodesignald running and reachable on ' + c.host + ':' + (c.port || CFG.peerPort) + '?')), 8000);
    sock.on('connect', () => { sendLine(sock, helloPayload()); sendLine(sock, payload); });
    lineStream(sock, (m) => {
      if (m.t === 'hello') {
        if (m.nick && !c.nick) c.nick = m.nick;
        if (m.node) { c.peerInfo = Object.assign({}, c.peerInfo, m.node); broadcastUi({ type: 'contact', contact: uiContact(c) }); }
        c.lastSeen = Date.now(); save();
      } else if (m.t === 'ack' && m.id === id) {
        finish(() => {
          rec.status = 'delivered'; save();
          broadcastUi({ type: 'chat.status', host: c.host, id, status: 'delivered' });
          resolve({ ok: true });
        });
      }
    });
    sock.on('error', (e) => finish(() => fail(e.code === 'ECONNREFUSED'
      ? 'refused — host reachable but nodesignald is not listening on ' + (c.port || CFG.peerPort) : e.message)));
  });
}

/* ------------------------------------------------------------ UI payloads */
const uiClients = new Set();
function broadcastUi(o) { const s = JSON.stringify(o); for (const ws of uiClients) { try { ws.send(s); } catch { } } }
const publicMsg = (m) => ({ id: m.id, from: m.from, ts: m.ts, text: m.text ?? null,
  locked: !!m.locked && m.text == null, status: m.status || null });
const uiContact = (c) => ({ host: c.host, port: c.port || CFG.peerPort, nick: c.nick, hasPin: !!c.pin,
  unread: c.unread, lastSeen: c.lastSeen, peerInfo: c.peerInfo, msgs: c.msgs.slice(-200).map(publicMsg) });
const fullState = () => ({
  type: 'state',
  daemon: { nick: CFG.nick, ua: UA, peerPort: CFG.peerPort, webPort: CFG.webPort },
  node: rpc.ok ? { self: rpc.self, peers: rpc.peers } : { self: null, peers: [], error: rpc.error, diag: rpcDiag },
  contacts: Object.values(state.contacts).map(uiContact),
});

/* ------------------------------------------------------------ auth (optional)
   With --web-token the browser logs in once and gets an HttpOnly session
   cookie, which also authenticates the /ws upgrade. The token is never put in
   a query string. Programmatic clients may use Authorization: Bearer instead. */
const sessions = new Map();
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const AUTH_ON = !!CFG.webToken;
function newSession() { const sid = crypto.randomBytes(32).toString('hex'); sessions.set(sid, Date.now() + SESSION_MS); return sid; }
function validSession(sid) {
  if (!sid) return false;
  const exp = sessions.get(sid);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(sid); return false; }
  return true;
}
function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
const timingSafeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};
function reqAuthed(req) {
  if (!AUTH_ON) return true;
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ') && timingSafeEq(h.slice(7), CFG.webToken)) return true;
  return validSession(cookies(req).ns_session);
}
const LOGIN_PAGE = `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NodeSignal — sign in</title><style>
body{margin:0;height:100vh;display:grid;place-items:center;background:#070a0f;color:#dde7e2;
font-family:"IBM Plex Mono",ui-monospace,Menlo,monospace}
form{background:#0e131c;border:1px solid rgba(140,210,180,.2);border-radius:14px;padding:28px 30px;width:320px}
h1{margin:0 0 4px;font-size:17px}h1 span{color:#f7931a}
p{margin:0 0 18px;font-size:12px;color:#5d7069;line-height:1.5}
input{width:100%;box-sizing:border-box;background:#070a0f;border:1px solid rgba(140,210,180,.2);border-radius:9px;
color:#dde7e2;padding:11px 13px;font:inherit;font-size:13px;outline:none}
input:focus{border-color:#f7931a}
button{width:100%;margin-top:12px;background:#f7931a;border:0;border-radius:9px;color:#150d02;padding:11px 0;
font:inherit;font-weight:600;font-size:13px;cursor:pointer}
.err{color:#ff453a;font-size:12px;min-height:16px;margin-top:10px}
</style></head><body><form method="POST" action="/login">
<h1><span>◈</span> NodeSignal</h1><p>This daemon requires an access token.</p>
<input type="password" name="token" placeholder="access token" autofocus autocomplete="current-password">
<button type="submit">sign in</button><div class="err">__ERR__</div>
</form></body></html>`;

/* ------------------------------------------------------------ web app (:8789) */
const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// public health check — open http://<host>:8789/health in a browser,
// or point any uptime monitor at it
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    nick: CFG.nick,
    version: UA,
    rpcConnected: rpc.ok,
    peerCount: rpc.ok ? rpc.peers.length : 0,
    contacts: Object.keys(state.contacts).length,
    webPort: CFG.webPort,
    peerPort: CFG.peerPort,
    authRequired: AUTH_ON,
    rpcSource: rpcDiag.source,
    uptime: Math.round(process.uptime()),
  });
});
app.get('/login', (_req, res) => AUTH_ON ? res.type('html').send(LOGIN_PAGE.replace('__ERR__', '')) : res.redirect('/'));
app.post('/login', (req, res) => {
  if (!AUTH_ON) return res.redirect('/');
  if (timingSafeEq((req.body && req.body.token) || '', CFG.webToken)) {
    res.setHeader('Set-Cookie',
      `ns_session=${newSession()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}`);
    return res.redirect('/');
  }
  res.status(401).type('html').send(LOGIN_PAGE.replace('__ERR__', 'wrong token'));
});
app.post('/logout', (req, res) => {
  const sid = cookies(req).ns_session;
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'ns_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.redirect('/login');
});

// everything below requires auth when a token is configured
app.use((req, res, next) => {
  if (reqAuthed(req)) return next();
  if (req.accepts('html')) return res.redirect('/login');
  res.status(401).json({ error: 'unauthorized' });
});

app.get('/', (_req, res) => {
  // Prefer the operator console; fall back to the demo build if that is what
  // this machine has (the Windows demo folder ships nodesignal-demo.html).
  for (const name of ['nodesignal.html', 'nodesignal-demo.html']) {
    const f = path.join(CFG.webRoot, name);
    if (fs.existsSync(f)) return res.sendFile(f);
  }
  res.status(500).type('text').send('No interface file found in ' + CFG.webRoot +
    '\nExpected nodesignal.html (or nodesignal-demo.html) next to nodesignald.js.');
});
// express.static sets correct MIME types and rejects path traversal
app.use(express.static(CFG.webRoot, { index: false, dotfiles: 'deny', maxAge: '1h' }));
app.use((_req, res) => res.status(404).type('text').send('not found'));

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req, socket, head) => {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { }
  if (pathname !== '/ws') { socket.destroy(); return; }
  if (!reqAuthed(req)) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (ws) => {
  uiClients.add(ws);
  ws.send(JSON.stringify(fullState()));
  ws.on('message', async (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (m.type === 'hello') { ws.send(JSON.stringify(fullState())); return; }
    if (m.type === 'contact.add') {
      const c = contact(m.host, true);
      if (m.port) c.port = Number(m.port) || CFG.peerPort;
      if (m.nick != null) c.nick = String(m.nick).slice(0, 60);
      if (m.pin != null) { c.pin = String(m.pin).slice(0, 32); await tryDecryptStored(c); }
      save(); ws.send(JSON.stringify({ type: 'contact', contact: uiContact(c) }));
      identifyContact(c.host, m.p2pPort || 8333)
        .catch(e => {
          log('identify ' + c.host + ' pending: ' + e.message);
          broadcastUi({ type: 'identified', host: c.host, error: e.message });
          scheduleIdentify(c.host, 5000);
        });
    } else if (m.type === 'identify') {
      const host = normIp(m.host);
      identifyContact(host, m.port || 8333)
        .then(info => ws.send(JSON.stringify({ type: 'identified', host, info })))
        .catch(e => ws.send(JSON.stringify({ type: 'identified', host, error: e.message })));
    } else if (m.type === 'contact.remove') {
      const host = normIp(m.host);
      if (state.contacts[host]) { delete state.contacts[host]; save(); log('contact removed: ' + host); }
      broadcastUi({ type: 'contact.removed', host });
    } else if (m.type === 'contact.pin') {
      const c = contact(m.host, false); if (!c) return;
      c.pin = String(m.pin || '').slice(0, 32);
      await tryDecryptStored(c);
      broadcastUi({ type: 'contact', contact: uiContact(c) });
    } else if (m.type === 'chat.send') {
      const c = contact(m.host, true);
      if (m.port) c.port = Number(m.port) || c.port;
      const text = String(m.text || '').slice(0, 4000);
      if (text) sendToPeer(c, text);
    } else if (m.type === 'chat.read') {
      const c = contact(m.host, false);
      if (c) { c.unread = 0; save(); broadcastUi({ type: 'chat.readack', host: c.host }); }
    } else if (m.type === 'peers.refresh') {
      await pollRpc(); ws.send(JSON.stringify(fullState()));
    } else if (m.type === 'ping') ws.send(JSON.stringify({ type: 'pong' }));
  });
  ws.on('close', () => uiClients.delete(ws));
});

/* ------------------------------------------------------------ boot */
peerServer.on('error', (e) => { console.error('peer port ' + CFG.peerPort + ': ' + e.message); process.exit(1); });
server.on('error', (e) => { console.error('web port ' + CFG.webPort + ': ' + e.message); process.exit(1); });

peerServer.listen(CFG.peerPort, CFG.bind, () => {
  server.listen(CFG.webPort, CFG.bind, () => {
    console.log('');
    console.log('  NodeSignal daemon ' + UA);
    console.log('  ----------------------------------------------------------');
    log(`nick           : ${CFG.nick}`);
    log(`Web app        : http://${CFG.bind}:${CFG.webPort}`);
    log(`WebSocket      : ws://${CFG.bind}:${CFG.webPort}/ws`);
    log(`Peer messaging : tcp://${CFG.bind}:${CFG.peerPort}`);
    log(`Health         : http://${CFG.bind}:${CFG.webPort}/health`);
    log(`web auth       : ${AUTH_ON ? 'token required (login page)' : 'open — intended for a private tailnet'}`);
    log(`web root       : ${CFG.webRoot}`);
    log(`state          : ${STATE_FILE}  (${Object.keys(state.contacts).length} contacts)`);
    log(CFG.noRpc ? 'node RPC       : disabled — standalone mode' : `node RPC       : ${CFG.rpcUrl}`);
    IMPERSONATED = buildImpersonation();
    if (IMPERSONATED) {
      log(`impersonating  : ${IMPERSONATED.ua}`);
      log(`                 (SIMULATED identity — this machine has no Bitcoin node)`);
    }
    console.log('');
    pollRpc();
    setInterval(pollRpc, 30000);
    // identify anything we don't know yet, then refresh hourly
    setTimeout(() => { for (const c of Object.values(state.contacts)) if (!c.peerInfo) scheduleIdentify(c.host, 2000); }, 2500);
    setInterval(() => {
      for (const c of Object.values(state.contacts)) {
        const age = c.peerInfo ? Date.now() - (c.peerInfo.at || 0) : Infinity;
        if (age > 60 * 60 * 1000) identifyContact(c.host, 8333).catch(() => { });
      }
    }, 15 * 60 * 1000);
  });
});
