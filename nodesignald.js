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
// Dependencies: NONE. Requires only Node.js and the two files shipped
// beside it: noise.js (encryption) and nodeps.js (http/websocket).
// ============================================================================

'use strict';
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { subtle } = crypto.webcrypto;

// Zero external dependencies: the HTTP/static/WebSocket layer lives in
// nodeps.js, built on Node's standard library. Nothing to npm install.
let W;
try { W = require('./nodeps.js'); }
catch (e) {
  console.error('\n  nodeps.js not found next to nodesignald.js.');
  console.error('  Keep nodesignald.js, noise.js and nodeps.js in the same folder.\n');
  process.exit(1);
}

/* ------------------------------------------------------------ config */
const argv = process.argv.slice(2);
const rawArg = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : d; };
const flag = (n) => argv.includes('--' + n);

/* Optional JSON config file. Written by the Windows installer so credentials
   live in one permission-restricted file rather than on a command line, where
   they would be visible to any process listing (Windows) or `systemctl cat`
   (Linux). Command-line flags always override the file. Keys use the same
   names as the flags, without the leading dashes. */
let FILE_CFG = {};
const configPath = rawArg('config', '');
if (configPath) {
  try { FILE_CFG = JSON.parse(fs.readFileSync(configPath, 'utf8')); }
  catch (e) {
    console.error('\n  Could not read config file: ' + configPath);
    console.error('  ' + e.message + '\n');
    process.exit(1);
  }
}
// flag > config file > default
const arg = (n, d) => {
  const i = argv.indexOf('--' + n);
  if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1];
  if (Object.prototype.hasOwnProperty.call(FILE_CFG, n)) return FILE_CFG[n];
  return d;
};
const boolOpt = (n) => flag(n) || FILE_CFG[n] === true;

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
  noRpc: boolOpt('no-rpc'),
  // Demo only: advertise a synthetic node identity to peers. Used by the
  // Windows demo machine, which has no Bitcoin node of its own, so it still
  // appears on other operators' maps as a classified node.
  impersonate: arg('impersonate', ''),
  impersonateHeight: Number(arg('impersonate-height', 0)) || 0,
};
const PROTO = 2;   // 2 = Noise handshake; falls back to 1 (PIN) for old peers
const UA = '/NodeSignal:1.2/';
const log = (m) => console.log(new Date().toISOString().slice(11, 19) + '  ' + m);

let noise = null;
try { noise = require('./noise.js'); }
catch { log('!! noise.js not found — encrypted handshake disabled, falling back to PIN only'); }

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

// Static Noise identity — generated once, persisted, this daemon's cryptographic
// identity. Fingerprint is what a peer pins on first contact (TOFU). Created
// here, after the save machinery exists, so it can be flushed immediately.
let myIdentity = null;
if (noise) {
  if (!state.identity) { state.identity = noise.newIdentity(); saveNow(); }
  myIdentity = noise.loadIdentity(state.identity);
}

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
/* Bitcoin's default data directory is platform-specific. Getting this wrong is
   the #1 reason the peer map stays empty, so search all of them:
     Linux    ~/.bitcoin
     Windows  %APPDATA%\Bitcoin      (C:\Users\<you>\AppData\Roaming\Bitcoin)
     macOS    ~/Library/Application Support/Bitcoin                            */
function defaultDataDirs() {
  const dirs = [];
  const home = os.homedir();
  if (process.platform === 'win32') {
    const appdata = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    dirs.push(path.join(appdata, 'Bitcoin'));
    dirs.push(path.join(home, 'AppData', 'Roaming', 'Bitcoin'));
  } else if (process.platform === 'darwin') {
    dirs.push(path.join(home, 'Library', 'Application Support', 'Bitcoin'));
  }
  dirs.push(path.join(home, '.bitcoin'));                       // Linux, and common everywhere
  dirs.push(path.join(home, 'snap', 'bitcoin-core', 'common', '.bitcoin'));
  return [...new Set(dirs)];
}
const COOKIE_PATHS = [
  ...defaultDataDirs().map(d => path.join(d, '.cookie')),
  '/var/lib/bitcoind/.cookie',
  '/var/lib/bitcoin/.cookie',
  '/home/bitcoin/.bitcoin/.cookie',
];
const CONF_PATHS = [
  ...defaultDataDirs().map(d => path.join(d, 'bitcoin.conf')),
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
    if (rpcDiag.port && u.port === '8332' && !argv.includes('--rpc-url') && !FILE_CFG['rpc-url']) u.port = rpcDiag.port;
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
      declared: declaredFromUA(ni.subversion), height: ch.blocks, network: ch.chain, connections: ni.connections,
      pruned: !!ch.pruned, pruneHeight: ch.pruneheight ?? null };
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
    // dial() transparently uses the Tor SOCKS proxy for .onion hosts.
    const sock = dial(host, port,
      (s) => { s._latency = Date.now() - t0; onConnected(s); },
      (e) => finish(e));
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
    function onConnected(s) {
      attachReader(s);
      s.write(p2pFrame(net_.magic, 'version', Buffer.concat([
        (() => { const b = Buffer.alloc(4); b.writeInt32LE(70016, 0); return b; })(),
        Buffer.alloc(8),
        (() => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(Math.floor(Date.now() / 1000)), 0); return b; })(),
        netAddr(), netAddr(), crypto.randomBytes(8), encVarStr(UA), Buffer.alloc(4), Buffer.from([0]),
      ])));
    }
    function attachReader(s) {
    s.on('data', (chunk) => {
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
    }
    sock.on('error', (e) => finish(new Error(
      e.code === 'ECONNREFUSED' ? 'refused — nothing listening on ' + host + ':' + port
        : e.code === 'ETIMEDOUT' ? 'timeout — port closed, firewalled, or unreachable'
          : (e.message || e.code))));
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
  peerPort: CFG.peerPort, node: rpc.ok ? rpc.self : (IMPERSONATED || null),
  fp: myIdentity ? myIdentity.fp : null });

/* Length-prefixed binary frames: [4-byte BE length][payload]. Used for the
   Noise handshake and then for AEAD-sealed application frames. A cap keeps a
   peer from making us buffer unbounded data before the handshake completes. */
const MAX_FRAME = 128 * 1024;
function frameStream(sock, onFrame) {
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > MAX_FRAME) { sock.destroy(); return; }
      if (buf.length < 4 + len) break;
      const payload = buf.slice(4, 4 + len);
      buf = buf.slice(4 + len);
      onFrame(payload);
    }
  });
}
const sendFrame = (sock, buf) => {
  try { const h = Buffer.alloc(4); h.writeUInt32BE(buf.length, 0); sock.write(Buffer.concat([h, buf])); } catch { }
};

/* A secured peer link. Once the Noise handshake completes, JSON control
   messages (hello/msg/ack/ping) are serialized, AEAD-sealed, and framed. TOFU:
   the first time we see a host we pin its static-key fingerprint; a later
   mismatch is surfaced, not silently trusted. */
function tofuCheck(host, fp) {
  const c = contact(host, false);
  if (!c) return { ok: true, first: true };
  if (!c.peerFp) return { ok: true, first: true };
  if (c.peerFp === fp) return { ok: true, first: false };
  return { ok: false, expected: c.peerFp, got: fp };
}
function tofuRecord(host, fp) {
  const c = contact(host, true);
  if (!c.peerFp) { c.peerFp = fp; save(); log(`pinned identity for ${host}: ${fp.slice(0, 16)}…`); }
}

// Responder side: handle an inbound connection.
function serveSecure(sock, host, onJson) {
  let hs = null, session = null;
  frameStream(sock, (frame) => {
    if (!session) {
      if (!hs) {
        // frame is msg1 (initiator ephemeral). If Noise is unavailable or the
        // frame is not a valid handshake, drop — old PIN peers use the legacy
        // path below, negotiated by port/first-byte is not possible here, so
        // v2 daemons speak only v2 to each other.
        try { hs = noise.respond(myIdentity, frame); sendFrame(sock, hs.msg2); }
        catch { sock.destroy(); }
      } else {
        try {
          const res = hs._finish(frame);
          const tof = tofuCheck(host, res.peerFp);
          if (!tof.ok) {
            log(`!! identity MISMATCH for ${host}: pinned ${tof.expected.slice(0,16)}… got ${tof.got.slice(0,16)}… — rejecting`);
            broadcastUi({ type: 'security', host, kind: 'fp-mismatch', expected: tof.expected, got: tof.got });
            sock.destroy(); return;
          }
          tofuRecord(host, res.peerFp);
          session = noise.makeSession(res.tx, res.rx);
          sock._peerFp = res.peerFp;
        } catch { sock.destroy(); }
      }
      return;
    }
    // secured application frame
    let m; try { m = JSON.parse(session.decrypt(frame)); } catch { sock.destroy(); return; }
    onJson(m, (obj) => sendFrame(sock, session.encrypt(JSON.stringify(obj))));
  });
}

// Initiator side: dial out and run the handshake, then hand back a sealed send.
function dialSecure(host, port, onReady, onJson, onErr) {
  let hs = null, session = null;
  // Frame handling is attached inside onConnected, NOT before: when the
  // connection goes through a SOCKS proxy the handshake bytes arrive on the
  // same socket first, and feeding those to the frame parser corrupts it.
  const sock = dial(host, port, (s) => onConnected(s), onErr);
  function onConnected(s) {
  frameStream(s, (frame) => {
    if (!session) {
      try {
        const res = noise.initFinish(hs, frame);
        const tof = tofuCheck(host, res.peerFp);
        if (!tof.ok) {
          onErr(new Error('identity mismatch — pinned ' + tof.expected.slice(0,16) + '… but got ' + tof.got.slice(0,16) + '…'));
          sock.destroy(); return;
        }
        tofuRecord(host, res.peerFp);
        sendFrame(sock, res.msg3);
        session = noise.makeSession(res.tx, res.rx);
        onReady(sock, (obj) => sendFrame(sock, session.encrypt(JSON.stringify(obj))), res.peerFp);
      } catch (e) { onErr(e); sock.destroy(); }
      return;
    }
    let m; try { m = JSON.parse(session.decrypt(frame)); } catch { return; }
    onJson(m);
  });
  hs = noise.initStart(myIdentity);
  sendFrame(s, hs.msg1);
  }
  return sock;
}

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

/* ---- outbound dialling, with optional SOCKS5 (Tor) --------------------
   A .onion address cannot be resolved by DNS, so a direct net.connect()
   fails with ENOTFOUND. Reaching another operator's hidden service requires
   handing the hostname to a SOCKS5 proxy — Tor's, normally 127.0.0.1:9050 —
   and letting Tor do the resolution inside the network.

   Rules:
     · any host ending in .onion always goes through the proxy
     · --tor-all routes every outbound connection through it
     · everything else dials directly                                      */
const TOR_PROXY = arg('tor-proxy', '');
const TOR_ALL = boolOpt('tor-all');
function proxyParts() {
  const raw = TOR_PROXY || '127.0.0.1:9050';
  const i = raw.lastIndexOf(':');
  return i > 0
    ? { host: raw.slice(0, i), port: Number(raw.slice(i + 1)) || 9050 }
    : { host: raw, port: 9050 };
}
const isOnion = (h) => /\.onion$/i.test(String(h || ''));
const useProxy = (h) => isOnion(h) || (TOR_ALL && (TOR_PROXY || true));

// SOCKS5 CONNECT (RFC 1928), no authentication.
function socks5Connect(target, targetPort, onReady, onError) {
  const px = proxyParts();
  const sock = net.connect({ host: px.host, port: px.port });
  let stage = 0;
  const fail = (msg) => { sock.destroy(); onError(new Error(msg)); };
  sock.on('error', (e) => onError(new Error(
    e.code === 'ECONNREFUSED'
      ? `no SOCKS proxy at ${px.host}:${px.port} — is Tor running? (set --tor-proxy if it listens elsewhere)`
      : (e.code || e.message))));
  sock.on('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));  // greet: no-auth
  const onData = (chunk) => {
    if (stage === 0) {
      if (chunk.length < 2 || chunk[0] !== 0x05) return fail('bad SOCKS5 greeting reply');
      if (chunk[1] !== 0x00) return fail('SOCKS proxy demands authentication');
      const host = Buffer.from(String(target), 'utf8');
      if (host.length > 255) return fail('hostname too long for SOCKS5');
      const req = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, host.length]), host,
        (() => { const b = Buffer.alloc(2); b.writeUInt16BE(targetPort, 0); return b; })(),
      ]);
      stage = 1; sock.write(req);
      return;
    }
    if (stage === 1) {
      if (chunk.length < 2 || chunk[0] !== 0x05) return fail('bad SOCKS5 reply');
      if (chunk[1] !== 0x00) {
        const why = { 1: 'general failure', 2: 'not allowed', 3: 'network unreachable',
          4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
          7: 'command not supported', 8: 'address type not supported' }[chunk[1]] || ('code ' + chunk[1]);
        return fail(`Tor could not reach ${target}:${targetPort} (${why})`);
      }
      stage = 2;
      sock.removeListener('data', onData);
      onReady(sock);
      return;
    }
  };
  sock.on('data', onData);
  return sock;
}
// Uniform dialler used by every outbound path in the daemon.
function dial(host, port, onReady, onError) {
  if (useProxy(host)) return socks5Connect(host, port, onReady, onError);
  const sock = net.connect({ host, port });
  sock.on('error', onError);
  sock.on('connect', () => onReady(sock));
  return sock;
}

/* ---- DDoS defenses: caps + per-source-block rate limiting ---------------
   A source "block" is the unit an ISP hands to one customer: a /32 for IPv4,
   a /64 for IPv6. Rate-limiting per block (not per address) is what defeats
   the IPv6 spray attack, where one customer has 1.8e19 addresses but only one
   /64. Token bucket: BURST connections instantly, then 1 per REFILL_MS. */
const MAX_CONNS = Number(arg('max-conns', 128));
const RL_BURST = Number(arg('rl-burst', 12));
const RL_REFILL_MS = Number(arg('rl-refill-ms', 1500));
const RL_MAX_BLOCKS = 4096;                    // cap the limiter's own memory
const rlBuckets = new Map();                   // sourceBlock -> { tokens, ts }
function sourceBlock(host) {
  if (host.includes(':')) {                    // IPv6 -> /64 = first 4 hextets
    const h = host.split('%')[0].split(':');
    return 'v6:' + h.slice(0, 4).join(':');
  }
  const p = host.split('.');                   // IPv4 -> /24 is generous; use full /32
  return 'v4:' + p.join('.');
}
function rateOk(host) {
  const key = sourceBlock(host);
  const now = Date.now();
  let b = rlBuckets.get(key);
  if (!b) {
    if (rlBuckets.size >= RL_MAX_BLOCKS) {     // evict oldest to bound memory
      const oldest = [...rlBuckets.entries()].sort((a, c) => a[1].ts - c[1].ts)[0];
      if (oldest) rlBuckets.delete(oldest[0]);
    }
    b = { tokens: RL_BURST, ts: now }; rlBuckets.set(key, b);
  }
  const refill = Math.floor((now - b.ts) / RL_REFILL_MS);
  if (refill > 0) { b.tokens = Math.min(RL_BURST, b.tokens + refill); b.ts = now; }
  if (b.tokens <= 0) return false;
  b.tokens--; return true;
}

/* ---- privacy: choose a safe default bind ------------------------------
   The old default (0.0.0.0) exposed both ports on every interface, including
   clearnet. Now:
     · if a Tailscale interface exists, bind to its address by default — the
       intended deployment, reachable by peers on the tailnet and nobody else
     · otherwise bind the WEB UI to localhost (operate via SSH tunnel), and
       the PEER port to 0.0.0.0 only if the operator opts in
   --bind still overrides everything for advanced setups (e.g. an onion HS). */
function tailscaleAddr() {
  try {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      if (!/tailscale|^ts\d/i.test(name)) continue;
      for (const a of ifaces[name]) if (a.family === 'IPv4' && !a.internal) return a.address;
    }
    // Tailscale IPs live in 100.64.0.0/10 even if the iface name is unusual
    for (const name of Object.keys(ifaces)) {
      for (const a of ifaces[name]) {
        if (a.family === 'IPv4' && !a.internal) {
          const o = a.address.split('.').map(Number);
          if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return a.address;
        }
      }
    }
  } catch { }
  return null;
}
const TS_ADDR = tailscaleAddr();
const explicitBind = argv.includes('--bind') || Object.prototype.hasOwnProperty.call(FILE_CFG, 'bind');
// web UI: explicit > tailscale > localhost.  peer port: explicit > tailscale > all.
const WEB_BIND = explicitBind ? CFG.bind : (TS_ADDR || '127.0.0.1');
const PEER_BIND = explicitBind ? CFG.bind : (TS_ADDR || '0.0.0.0');

const peerServer = net.createServer((sock) => {
  const host = normIp(sock.remoteAddress);

  // --- DDoS / disk-exhaustion defenses -----------------------------------
  // The critique's worst case: an IPv6 attacker opens endless connections from
  // fresh addresses, each creating a persisted contact record, filling the
  // disk and taking bitcoind down with it. Defenses, in order of cheapness:
  //   1. hard cap on concurrent inbound connections
  //   2. per-source-block (IPv4 /32, IPv6 /64) rate limit on new connections
  //   3. NO persisted state until a handshake proves a real peer (below)
  if (peerServer._active >= MAX_CONNS) { sock.destroy(); return; }
  if (!rateOk(host)) { sock.destroy(); return; }
  peerServer._active = (peerServer._active || 0) + 1;
  sock.once('close', () => { peerServer._active--; });
  // Unfinished handshakes must not tie up a slot forever.
  sock.setTimeout(30000, () => sock.destroy());

  // v2: Noise handshake, then plaintext JSON inside the encrypted session.
  if (noise && myIdentity) {
    serveSecure(sock, host, async (m, reply) => {
      if (m.t === 'hello') {
        const c = contact(host, true);
        if (m.nick && !c.nick) c.nick = m.nick;
        if (m.peerPort) c.port = Number(m.peerPort) || c.port;
        if (m.node) c.peerInfo = Object.assign({}, c.peerInfo, m.node);
        if (sock._peerFp) c.peerFp = c.peerFp || sock._peerFp;
        c.lastSeen = Date.now(); save();
        reply(helloPayload());
        broadcastUi({ type: 'contact', contact: uiContact(c) });
        scheduleIdentify(host, 1000);
      } else if (m.t === 'msg') {
        const c = contact(host, true);
        c.lastSeen = Date.now();
        c.established = true;                 // authenticated peer delivered a message
        // The transport is already end-to-end encrypted and authenticated, so
        // the message text arrives in the clear inside the session. No PIN.
        const rec = { id: m.id || crypto.randomUUID(), from: 'them', ts: m.ts || Date.now(),
          text: typeof m.text === 'string' ? String(m.text).slice(0, 4000) : '' };
        if (!rec.text) return;
        c.unread++; pushMsg(c, rec);
        reply({ t: 'ack', id: rec.id });
        log(`msg from ${c.nick || host} [${(sock._peerFp || '').slice(0, 12)}…]`);
        broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec), unread: c.unread });
      } else if (m.t === 'ping') reply({ t: 'pong' });
    });
    sock.on('error', () => { });
    return;
  }

  // legacy v1 path (no noise module): PIN-encrypted line protocol
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
      c.lastSeen = Date.now(); c.established = true;
      const rec = { id: m.id || crypto.randomUUID(), from: 'them', ts: m.ts || Date.now() };
      if (m.iv && m.ct) {
        rec.enc = { iv: m.iv, ct: m.ct };
        if (c.pin) { try { rec.text = await decMsg(c.pin, rec.enc); } catch { rec.locked = true; } }
        else rec.locked = true;
      } else if (typeof m.text === 'string') rec.text = String(m.text).slice(0, 4000);
      else return;
      c.unread++; pushMsg(c, rec);
      sendLine(sock, { t: 'ack', id: rec.id });
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
    const port = c.port || CFG.peerPort;

    // v2: Noise-secured. The message rides inside the encrypted session.
    if (noise && myIdentity) {
      let done = false;
      const finish = (fn) => { if (!done) { done = true; clearTimeout(timer); try { sock.destroy(); } catch {} fn(); } };
      const timer = setTimeout(() => finish(() => fail(
        'timeout — is nodesignald running and reachable on ' + c.host + ':' + port + '?')), 9000);
      const sock = dialSecure(c.host, port,
        (s, sealSend, peerFp) => {
          if (peerFp) { c.peerFp = c.peerFp || peerFp; }
          sealSend(helloPayload());
          sealSend({ t: 'msg', id, ts: rec.ts, text });
        },
        (m) => {
          if (m.t === 'hello') {
            if (m.nick && !c.nick) c.nick = m.nick;
            if (m.node) { c.peerInfo = Object.assign({}, c.peerInfo, m.node); broadcastUi({ type: 'contact', contact: uiContact(c) }); }
            c.lastSeen = Date.now(); save();
          } else if (m.t === 'ack' && m.id === id) {
            finish(() => {
              rec.status = 'delivered'; c.established = true; save();
              broadcastUi({ type: 'chat.status', host: c.host, id, status: 'delivered' });
              broadcastUi({ type: 'contact', contact: uiContact(c) });
              resolve({ ok: true });
            });
          }
        },
        (e) => finish(() => fail(e.code === 'ECONNREFUSED'
          ? 'refused — host reachable but nodesignald is not listening on ' + port
          : (e.message || 'connection error'))));
      return;
    }

    // legacy v1 path
    const payload = c.pin ? { t: 'msg', id, ts: rec.ts, ...(await encMsg(c.pin, text)) } : { t: 'msg', id, ts: rec.ts, text };
    const sock = dial(c.host, port,
      (s) => {
        lineStream(s, onLine);
        sendLine(s, helloPayload());
        sendLine(s, payload);
      },
      (e) => finish(() => fail(e.code === 'ECONNREFUSED'
        ? 'refused — host reachable but nodesignald is not listening on ' + port : (e.message || e.code))));
    let done = false;
    const finish = (fn) => { if (!done) { done = true; clearTimeout(timer); sock.destroy(); fn(); } };
    const timer = setTimeout(() => finish(() => fail(
      'timeout — is nodesignald running and reachable on ' + c.host + ':' + port + '?')), 8000);
    function onLine(m) {
      if (m.t === 'hello') {
        if (m.nick && !c.nick) c.nick = m.nick;
        if (m.node) { c.peerInfo = Object.assign({}, c.peerInfo, m.node); broadcastUi({ type: 'contact', contact: uiContact(c) }); }
        c.lastSeen = Date.now(); save();
      } else if (m.t === 'ack' && m.id === id) {
        finish(() => {
          rec.status = 'delivered'; c.established = true; save();
          broadcastUi({ type: 'chat.status', host: c.host, id, status: 'delivered' });
          broadcastUi({ type: 'contact', contact: uiContact(c) });
          resolve({ ok: true });
        });
      }
    }
  });
}

/* ------------------------------------------------------------ UI payloads */
const uiClients = new Set();
function broadcastUi(o) { const s = JSON.stringify(o); for (const ws of uiClients) { try { ws.send(s); } catch { } } }
const publicMsg = (m) => ({ id: m.id, from: m.from, ts: m.ts, text: m.text ?? null,
  locked: !!m.locked && m.text == null, status: m.status || null });
const uiContact = (c) => ({ host: c.host, port: c.port || CFG.peerPort, nick: c.nick, hasPin: !!c.pin,
  unread: c.unread, lastSeen: c.lastSeen, peerInfo: c.peerInfo,
  established: !!c.established,
  peerFp: c.peerFp || null,
  online: !!(c.established && c.lastSeen && (Date.now() - c.lastSeen < 5 * 60 * 1000)),
  msgs: c.msgs.slice(-200).map(publicMsg) });
const fullState = () => ({
  type: 'state',
  daemon: { nick: CFG.nick, ua: UA, peerPort: CFG.peerPort, webPort: CFG.webPort,
    fingerprint: myIdentity ? myIdentity.fp : null, secure: !!(noise && myIdentity) },
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

/* ------------------------------------------------------------ web app (:8789)
   Plain Node http + the WebSocket server from nodeps.js. No express, no ws,
   no npm install — which removes 66 packages from a machine running a Bitcoin
   node (a finding in the threat model) and makes Windows setup dependency-free. */
function healthPayload() {
  return {
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
    secure: !!(noise && myIdentity),
    fingerprint: myIdentity ? myIdentity.fp : null,
    uptime: Math.round(process.uptime()),
  };
}
const wantsHtml = (req) => String(req.headers.accept || '').includes('text/html');
function redirect(res, to) { res.writeHead(302, { Location: to, 'Content-Length': 0 }); res.end(); }

async function handleRequest(req, res) {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { }
  const method = req.method || 'GET';

  // --- public routes (no auth) ---
  if (pathname === '/health') return W.sendJson(res, healthPayload());

  if (pathname === '/login') {
    if (!AUTH_ON) return redirect(res, '/');
    if (method === 'GET') return W.sendHtml(res, LOGIN_PAGE.replace('__ERR__', ''));
    if (method === 'POST') {
      const body = await W.readForm(req);
      if (timingSafeEq(body.token || '', CFG.webToken)) {
        return redirect2(res, '/',
          `ns_session=${newSession()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}`);
      }
      return W.sendHtml(res, LOGIN_PAGE.replace('__ERR__', 'wrong token'), 401);
    }
  }
  if (pathname === '/logout' && method === 'POST') {
    const sid = cookies(req).ns_session;
    if (sid) sessions.delete(sid);
    return redirect2(res, '/login', 'ns_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  }

  // --- everything below requires auth when a token is configured ---
  if (!reqAuthed(req)) {
    if (wantsHtml(req)) return redirect(res, '/login');
    return W.sendJson(res, { error: 'unauthorized' }, 401);
  }

  if (pathname === '/') {
    // Prefer the operator console; fall back to the demo build if that is what
    // this machine has (the Windows demo folder ships nodesignal-demo.html).
    for (const name of ['nodesignal.html', 'nodesignal-demo.html']) {
      const f = path.join(CFG.webRoot, name);
      if (fs.existsSync(f)) return W.sendFile(res, f);
    }
    return W.sendText(res, 'No interface file found in ' + CFG.webRoot +
      '\nExpected nodesignal.html (or nodesignal-demo.html) next to nodesignald.js.', 500);
  }

  // static assets: correct MIME types, path traversal and dotfiles rejected
  if (method === 'GET' && W.serveStatic(CFG.webRoot, pathname, res)) return;
  return W.sendText(res, 'not found', 404);
}
function redirect2(res, to, setCookie) {
  res.writeHead(302, { Location: to, 'Set-Cookie': setCookie, 'Content-Length': 0 });
  res.end();
}
const requestListener = (req, res) => {
  handleRequest(req, res).catch(() => { try { W.sendText(res, 'server error', 500); } catch { } });
};

const server = http.createServer(requestListener);
// Second listener on loopback. When the primary bind is a Tailscale address,
// the machine's own browser would otherwise get ECONNREFUSED on localhost —
// confusing when you are sitting at the very machine running the daemon.
// This adds localhost WITHOUT exposing anything to clearnet.
const localServer = http.createServer(requestListener);
const wss = new W.WSServer();
const onUpgrade = (req, socket, head) => {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { }
  if (pathname !== '/ws') { socket.destroy(); return; }
  if (!reqAuthed(req)) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
};
server.on('upgrade', onUpgrade);
localServer.on('upgrade', onUpgrade);

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

peerServer.listen(CFG.peerPort, PEER_BIND, () => {
  server.listen(CFG.webPort, WEB_BIND, () => {
    console.log('');
    console.log('  NodeSignal daemon ' + UA);
    console.log('  ----------------------------------------------------------');
    log(`nick           : ${CFG.nick}`);
    log(`Web app        : http://${WEB_BIND}:${CFG.webPort}`);
    if (WEB_BIND !== '127.0.0.1' && WEB_BIND !== '0.0.0.0') {
      localServer.on('error', () => { });          // port busy on loopback is non-fatal
      localServer.listen(CFG.webPort, '127.0.0.1',
        () => log(`                 http://localhost:${CFG.webPort}  (same app, from this machine)`));
    }
    log(`WebSocket      : ws://${WEB_BIND}:${CFG.webPort}/ws`);
    log(`Peer messaging : tcp://${PEER_BIND}:${CFG.peerPort}`);
    log(`Health         : http://${WEB_BIND}:${CFG.webPort}/health`);
    if (TS_ADDR && !explicitBind) log(`bind           : Tailscale (${TS_ADDR}) — private tailnet only, not clearnet`);
    else if (!explicitBind && WEB_BIND === '127.0.0.1') log('bind           : localhost — no Tailscale found; reach the UI via SSH tunnel, peer port is 0.0.0.0');
    else log(`bind           : ${CFG.bind} (explicit)`);
    if (myIdentity) log(`identity fp    : ${myIdentity.fp}  (peers pin this on first contact)`);
    else log('identity       : PIN fallback (noise.js missing)');
    log(`web auth       : ${AUTH_ON ? 'token required (login page)' : 'open — safe only on a private tailnet'}`);
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
