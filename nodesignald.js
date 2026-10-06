#!/usr/bin/env node
// nodesignald.js: the NodeSignal daemon + self-hosted web app
// ============================================================================
// Operator-to-operator chat for Bitcoin nodes. Runs beside bitcoind/Knots and
// serves its own web interface, so you use it from any browser on your tailnet.
//
//   :8789  HTTP   web app (GET /) + WebSocket API (/ws) + GET /health
//   :8788  TCP    daemon <-> daemon encrypted messaging
//   :8333  TCP    outbound only: Bitcoin P2P handshake used to identify peers
//
//   discovery : getpeerinfo / getnetworkinfo / getblockchaininfo over RPC, so
//               the map shows the peers your node actually has. Peers whose
//               user agent carries the `nodesignal` comment are marked.
//   identify  : dials a peer's :8333 and reads its version message: user agent
//               (=> implementation, version, declared BIPs), height, service
//               bits, capability messages. Read-only.
//   transport : the Bitcoin protocol cannot carry chat, so messages travel
//               daemon-to-daemon on :8788 inside a Noise_XX_25519_ChaChaPoly_
//               SHA256 session (noise.js). Either side's connection can carry
//               messages both ways, so only one operator needs to be reachable.
//               Undelivered messages are retried with backoff.
//   storage   : with a passphrase set, message text is sealed at rest
//               (store.js); the daemon still receives while locked.
//
// USAGE
//   node nodesignald.js [options]
//     --config <file>      JSON file whose keys are these option names
//     --nick <name>        display name sent to peers      (default: hostname)
//     --web-port <n>       web app + WebSocket API         (default: 8789)
//     --peer-port <n>      daemon-to-daemon messaging      (default: 8788)
//     --web-token <secret> require login for the web UI    (default: open)
//     --bind <addr>        listen address                  (default: Tailscale, else localhost)
//     --web-root <dir>     where nodesignal.html lives     (default: this dir)
//     --data <dir>         state directory                 (default: ~/.nodesignal)
//     --rpc-url <url>      bitcoind/knots RPC              (default: http://127.0.0.1:8332)
//     --rpc-user <u> --rpc-pass <p>    RPC credentials, or:
//     --rpc-cookie <path>  cookie file (auto-tried: ~/.bitcoin/.cookie)
//     --port-mapping       ask the router to forward the peer port (UPnP/NAT-PMP).
//                          Opt-in: it publishes your IP on clearnet.
//     --checkin-ms <n>     how often to check in with established contacts
//                          (default 180000; 0 disables)
//     --no-rpc             standalone: no Bitcoin node on this machine (testing)
//
// Intended for a private tailnet. No router port forwarding is required or
// recommended; don't expose :8789 publicly without --web-token behind TLS.
//
// Dependencies: NONE. Requires only Node.js and the files shipped beside it:
// noise.js (handshake), nodeps.js (http/websocket), store.js (at-rest
// encryption) and portmap.js (opt-in router port mapping).
// ============================================================================

'use strict';
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

// Zero external dependencies: every module below ships next to this file.
let W, noise, store;
try { W = require('./nodeps.js'); noise = require('./noise.js'); store = require('./store.js'); }
catch (e) {
  console.error('\n  ' + e.message);
  console.error('  Keep nodesignald.js, noise.js, nodeps.js, store.js and portmap.js in the same folder.\n');
  process.exit(1);
}

/* ------------------------------------------------------------ config */
const argv = process.argv.slice(2);
const rawArg = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : d; };
const flag = (n) => argv.includes('--' + n);

/* Optional JSON config file. Written by the installers so credentials
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
  nick: cleanStr(arg('nick', os.hostname()), 60) || 'node',
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
  portMapping: boolOpt('port-mapping'),
  checkinMs: Number(arg('checkin-ms', 180000)),
  // Testing only: shrink every retry delay and the retry tick by this factor.
  retryScale: Math.min(1, Math.max(0.0001, Number(arg('retry-scale', 1)) || 1)),
  // Testing only: advertise a synthetic node identity to peers. Flagged
  // `simulated: true` in the protocol so nobody mistakes it for a real node.
  impersonate: arg('impersonate', ''),
  impersonateHeight: Number(arg('impersonate-height', 0)) || 0,
};
const PROTO = 3;   // 3 = standard Noise XX; still answers v2 peers for one release
const UA = '/NodeSignal:1.3/';
const log = (m) => console.log(new Date().toISOString().slice(11, 19) + '  ' + m);
// Strip control characters and cap length: used on every peer-supplied string.
function cleanStr(v, max) {
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, max) : '';
}

/* ------------------------------------------------------------ storage */
fs.mkdirSync(CFG.dataDir, { recursive: true, mode: 0o700 });
const STATE_FILE = path.join(CFG.dataDir, 'state.json');
let state = { contacts: {} };
try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { /* fresh install */ }
if (!state.contacts) state.contacts = {};
try { fs.chmodSync(STATE_FILE, 0o600); } catch { }
// v1.3 retired the shared-PIN scheme: drop stored PINs.
for (const c of Object.values(state.contacts)) { delete c.pin; if (!Array.isArray(c.msgs)) c.msgs = []; }

let saveTimer = null, dirty = false;
function saveNow() {
  dirty = false;
  try {
    const tmp = STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    fs.renameSync(tmp, STATE_FILE);          // atomic: a crash can't truncate state
  } catch (e) { log('!! could not save state: ' + e.message); }
}
function save() { dirty = true; clearTimeout(saveTimer); saveTimer = setTimeout(saveNow, 100); }
let shuttingDown = false;
let portmapCtl = null;              // set by startPortMapping() when --port-mapping is on
async function shutdown() {
  if (shuttingDown) return; shuttingDown = true;
  if (dirty) saveNow();
  if (portmapCtl) await Promise.race([portmapCtl.stop().catch(() => { }), new Promise((r) => setTimeout(r, 3000))]);
  process.exit(0);
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, shutdown);
process.on('exit', () => { if (dirty) saveNow(); });

// Static Noise identity: generated once, persisted, this daemon's cryptographic
// identity. Fingerprint is what a peer pins on first contact (TOFU). It stays
// readable to the daemon's user (the daemon needs it unattended); state.json
// is written 0600.
if (!state.identity) { state.identity = noise.newIdentity(); saveNow(); }
const myIdentity = noise.loadIdentity(state.identity);

/* ------------------------------------------------------------ at-rest vault
   With a passphrase set, message text is never written in the clear: it is
   sealed to the vault's public key as it arrives, so a locked daemon keeps
   receiving. Unlocking (from the web UI) loads the private key into memory
   only. Messages typed this session are kept in memory so they can still be
   retried while locked. See store.js for what this does and doesn't cover. */
const vault = { key: null, cache: new Map(), fails: 0, nextTry: 0 };
const outText = new Map();                 // message id -> plaintext, this process only
const vaultOn = () => !!(state.vault && state.vault.pub);
const unlocked = () => !!vault.key;
function storeText(rec, text) {
  if (vaultOn()) { rec.sealed = store.seal(state.vault.pub, text); delete rec.text; if (unlocked()) vault.cache.set(rec.id, text); }
  else rec.text = text;
}
function textOf(m) {
  if (outText.has(m.id)) return outText.get(m.id);
  if (typeof m.text === 'string') return m.text;
  if (m.sealed && unlocked()) {
    if (vault.cache.has(m.id)) return vault.cache.get(m.id);
    try { const t = store.open(vault.key, m.sealed); vault.cache.set(m.id, t); return t; } catch { return null; }
  }
  return null;
}
function lockKind(m) {
  if (textOf(m) != null) return null;
  if (m.sealed) return 'vault';
  if (m.enc) return 'legacy';            // v1 PIN-encrypted, unreadable since the PIN path was retired
  return null;
}
async function vaultSet(passphrase) {
  if (vaultOn()) throw new Error('a passphrase is already set');
  const { vault: v, priv } = await store.createVault(passphrase);
  state.vault = v; vault.key = priv; vault.cache.clear();
  // Seal everything stored in the clear so far.
  let n = 0;
  for (const c of Object.values(state.contacts)) for (const m of c.msgs) {
    if (typeof m.text === 'string') { storeText(m, m.text); n++; }
    delete m.enc;
  }
  saveNow();
  log(`history passphrase set; ${n} stored messages sealed`);
}
async function vaultUnlock(passphrase) {
  if (!vaultOn()) throw new Error('no passphrase is set');
  if (Date.now() < vault.nextTry) throw new Error('too many attempts, wait ' + Math.ceil((vault.nextTry - Date.now()) / 1000) + 's');
  try { vault.key = await store.unlock(state.vault, passphrase); vault.fails = 0; vault.cache.clear(); log('history unlocked'); }
  catch (e) {
    vault.fails++; vault.nextTry = Date.now() + Math.min(60000, 1000 * 2 ** (vault.fails - 1));
    throw e;
  }
}
function vaultLock() { vault.key = null; vault.cache.clear(); log('history locked'); }
async function vaultChange(oldPass, newPass) {
  if (!vaultOn()) throw new Error('no passphrase is set');
  const key = await store.unlock(state.vault, oldPass);
  state.vault = await store.changePassphrase(state.vault, key, newPass);
  vault.key = key; saveNow(); log('history passphrase changed');
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
// `uacomment=nodesignal` in bitcoin.conf puts "(nodesignal)" in a node's user
// agent. Optional ":port" if the operator's daemon listens elsewhere.
function nodesignalFromUA(ua) {
  const m = /\bnodesignal(?:[:=](\d{1,5}))?\b/i.exec(ua || '');
  if (!m) return null;
  const port = Number(m[1]) || 8788;
  return { port: port >= 1 && port <= 65535 ? port : 8788 };
}

/* ---- synthetic identity (testing only; flagged simulated to peers) ---- */
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
      pruned: !!ch.pruned, pruneHeight: ch.pruneheight ?? null, advertising: !!nodesignalFromUA(ni.subversion) };
    rpc.peers = pr.map(p => ({
      addr: p.addr, ua: p.subver, impl: implFromUA(p.subver || ''), version: verFromUA(p.subver || ''),
      declared: declaredFromUA(p.subver || ''),
      latency: p.pingtime != null ? Math.round(p.pingtime * 1000) : null,
      inbound: !!p.inbound, height: p.synced_headers ?? null,
      // runs NodeSignal, by its own user agent comment (self-declared, public)
      nodesignal: nodesignalFromUA(p.subver) }));
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
          let v;
          try { v = parseVersionMsg(payload); }               // a short payload must not crash the daemon
          catch { return finish(new Error('malformed version message from ' + host + ':' + port)); }
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
  if (!c || (c.peerInfo && c.peerInfo.source !== 'claimed')) return;
  if ((c._idRetry || 0) >= MAX_ID_TRIES) return;
  const wait = delay ?? Math.min(60000, 5000 * Math.pow(2, c._idRetry || 0));
  idTimers.set(host, setTimeout(async () => {
    idTimers.delete(host);
    const cc = state.contacts[host];
    if (!cc || (cc.peerInfo && cc.peerInfo.source !== 'claimed')) return;
    try { await identifyContact(host, 8333); }
    catch {
      cc._idRetry = (cc._idRetry || 0) + 1;
      if (cc._idRetry >= MAX_ID_TRIES)
        log(`identify ${host}: giving up after ${MAX_ID_TRIES} tries (no Bitcoin node there?) — messaging still works`);
      else scheduleIdentify(host);
    }
  }, wait));
}


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
// Router port mapping forwards to this machine's LAN address, so the peer
// port must listen there too.
const PEER_BIND = explicitBind ? CFG.bind : (CFG.portMapping ? '0.0.0.0' : (TS_ADDR || '0.0.0.0'));


/* ------------------------------------------------------------ contacts */
function contact(host, create) {
  host = normIp(host);
  if (!state.contacts[host] && create)
    state.contacts[host] = { host, port: CFG.peerPort, nick: '', msgs: [], unread: 0, lastSeen: 0, peerInfo: null };
  return state.contacts[host];
}
function pushMsg(c, m) { c.msgs.push(m); if (c.msgs.length > 500) c.msgs.splice(0, c.msgs.length - 500); save(); }
const MSG_ID = /^[A-Za-z0-9_-]{1,64}$/;
const findMsg = (c, id) => c.msgs.find((m) => m.id === id);

/* ---- validation of everything a peer says ----------------------------
   Peers are authenticated by the handshake but not trusted: every field is
   type-checked, length-capped and stripped of control characters before it
   is stored or shown. Unknown fields are dropped. */
function cleanNode(n) {
  if (!n || typeof n !== 'object' || Array.isArray(n)) return null;
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    ua: cleanStr(n.ua, 256), impl: cleanStr(n.impl, 40) || 'Unknown', version: cleanStr(n.version, 80),
    declared: Array.isArray(n.declared) ? n.declared.filter((x) => typeof x === 'string').slice(0, 20).map((x) => cleanStr(x, 40)) : [],
    height: num(n.height), network: cleanStr(n.network, 16), connections: num(n.connections),
    pruned: n.pruned === true, simulated: n.simulated === true, source: 'claimed',
  };
}
function applyHello(c, m) {
  const nick = cleanStr(m.nick, 60);
  if (nick && !c.nick) c.nick = nick;
  const pp = Number(m.peerPort);
  if (Number.isInteger(pp) && pp > 0 && pp < 65536) c.port = pp;
  // A node identity the peer CLAIMS. It never overwrites what we measured
  // ourselves over :8333 (source p2p), only fills in when we have nothing.
  const node = cleanNode(m.node);
  if (node && (!c.peerInfo || c.peerInfo.source === 'claimed')) c.peerInfo = Object.assign({}, c.peerInfo, node);
  c.peerProto = Number(m.proto) || 2;
  c.lastSeen = Date.now();
}

/* ------------------------------------------------------------ peer wire (:8788) */
const helloPayload = () => ({ t: 'hello', proto: PROTO, nick: CFG.nick, ua: UA,
  peerPort: CFG.peerPort, node: rpc.ok ? rpc.self : (IMPERSONATED || null), fp: myIdentity.fp });

/* Length-prefixed binary frames: [4-byte BE length][payload]. Used for the
   handshake and then for AEAD-sealed application frames. The cap keeps a
   peer from making us buffer unbounded data; Noise frames are <= 65535. */
const MAX_FRAME = 70 * 1024;
function frameStream(sock, onFrame) {
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > MAX_FRAME || len === 0) { sock.destroy(); return; }
      if (buf.length < 4 + len) break;
      const payload = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);
      try { onFrame(payload); } catch { sock.destroy(); return; }
      if (sock.destroyed) return;
    }
  });
}
const sendFrame = (sock, buf) => {
  try { const h = Buffer.alloc(4); h.writeUInt32BE(buf.length, 0); sock.write(Buffer.concat([h, buf])); } catch { }
};

/* TOFU: the first time we see a host we pin its static-key fingerprint; a
   later mismatch is REJECTED and held as pendingFp until the operator
   deliberately accepts or dismisses it in the console. */
function tofuCheck(c, fp) {
  if (!c || !c.peerFp || c.peerFp === fp) return true;
  if (!c.pendingFp || c.pendingFp.got !== fp) {
    c.pendingFp = { got: fp, at: Date.now() }; save();
    log(`!! identity MISMATCH for ${c.host}: pinned ${c.peerFp.slice(0, 16)}... got ${fp.slice(0, 16)}... (rejected)`);
  }
  broadcastUi({ type: 'security', host: c.host, kind: 'fp-mismatch', expected: c.peerFp, got: fp });
  broadcastUi({ type: 'contact', contact: uiContact(c) });
  return false;
}
function tofuRecord(c, fp) {
  if (!c.peerFp) { c.peerFp = fp; save(); log(`pinned identity for ${c.host}: ${fp.slice(0, 16)}...`); }
}
// An authenticated key we already pinned identifies the contact even if its
// address changed (dynamic IP, NAT): the key is the identity, not the IP.
function contactFor(addr, fp) {
  const c = state.contacts[addr];
  if (c) return c;
  const byKey = Object.values(state.contacts).find((x) => x.peerFp === fp);
  if (byKey) { byKey.lastAddr = addr; return byKey; }
  return null;
}

/* ---- links: one authenticated session, either direction ---------------
   Whoever dialled, the session carries messages BOTH ways. When a peer we
   cannot reach (NAT, no port forward) connects to us, everything we have
   queued for it goes back over its own connection. So only one of two
   operators needs to be reachable. */
const links = new Map();                     // contact host -> live link
const LINK_IDLE_MS = 2500, LINK_MAX_MS = 30000;
function openLink(sock, { initiator, addr, peerFp, proto, session }) {
  const link = { sock, initiator, addr, peerFp, proto, contact: null, unacked: new Set(), closed: false, helloSent: false, peerHello: false };
  link.send = (obj) => { if (!link.closed) sendFrame(sock, session.encrypt(JSON.stringify(obj))); };
  link.close = () => { if (link.closed) return; link.closed = true; try { sock.end(); } catch { } setTimeout(() => sock.destroy(), 1000).unref(); };
  // The dialling side hangs up once nothing is in flight and the line is quiet.
  link.touch = () => {
    if (!initiator) return;
    clearTimeout(link.idle);
    link.idle = setTimeout(() => (link.unacked.size ? link.touch() : link.close()), LINK_IDLE_MS);
  };
  const hard = setTimeout(() => link.close(), LINK_MAX_MS); hard.unref();
  sock.once('close', () => {
    link.closed = true; clearTimeout(link.idle); clearTimeout(hard);
    const c = link.contact;
    if (c && links.get(c.host) === link) links.delete(c.host);
    // Anything sent on this link but never acked goes back to the retry queue.
    if (c) for (const id of link.unacked) { const m = findMsg(c, id); if (m && m.status === 'sending') deferMsg(c, m, 'connection closed before the peer confirmed delivery'); }
  });
  link.onFrame = (frame) => {
    let m;
    try { m = JSON.parse(session.decrypt(frame)); } catch { sock.destroy(); return; }
    if (m && typeof m === 'object') onPeerMessage(link, m);
  };
  return link;
}
function bindLink(link, c) {
  link.contact = c;
  if (!links.has(c.host) || links.get(c.host).closed) links.set(c.host, link);
}

function onPeerMessage(link, m) {
  link.touch();
  if (m.t === 'hello') {
    let c = link.contact;
    if (!c) {
      // First authenticated hello from a stranger: only now is state created.
      c = contact(link.addr, true);
      if (!tofuCheck(c, link.peerFp)) { link.sock.destroy(); return; }
      tofuRecord(c, link.peerFp);
      bindLink(link, c);
      scheduleIdentify(c.host, 1000);
    }
    applyHello(c, m); link.peerHello = true; save();
    if (!link.helloSent) { link.send(helloPayload()); link.helloSent = true; }
    // Answer a v3 peer's call with whatever we have queued for it.
    if (!link.initiator && c.peerProto >= 3) flushPending(c, link);
    broadcastUi({ type: 'contact', contact: uiContact(c) });
    return;
  }
  if (m.t === 'msg') {
    let c = link.contact;
    if (!c) {                                 // v2 peers may skip hello
      c = contact(link.addr, true);
      if (!tofuCheck(c, link.peerFp)) { link.sock.destroy(); return; }
      tofuRecord(c, link.peerFp); bindLink(link, c);
    }
    // Keep newlines and tabs; drop every other control character.
    const text = typeof m.text === 'string'
      ? m.text.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, 4000) : '';
    if (!text) return;
    const id = typeof m.id === 'string' && MSG_ID.test(m.id) ? m.id : null;
    c.lastSeen = Date.now(); c.established = true;   // an authenticated peer delivered a message
    // Retries can deliver the same message twice: acknowledge, don't store again.
    if (id && findMsg(c, id)) { link.send({ t: 'ack', id }); return; }
    const now = Date.now();
    const ts = Number.isFinite(m.ts) && m.ts > now - 30 * 864e5 && m.ts < now + 5 * 60000 ? m.ts : now;
    const rec = { id: id || crypto.randomUUID(), from: 'them', ts };
    storeText(rec, text);
    c.unread++; pushMsg(c, rec);
    link.send({ t: 'ack', id: rec.id });
    log(`msg from ${c.nick || c.host} [${link.peerFp.slice(0, 12)}...] via ${link.initiator ? 'our' : 'their'} connection`);
    broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec), unread: c.unread });
    broadcastUi({ type: 'contact', contact: uiContact(c) });
    return;
  }
  if (m.t === 'ack') {
    const c = link.contact; if (!c || typeof m.id !== 'string') return;
    link.unacked.delete(m.id);
    const rec = findMsg(c, m.id);
    if (rec && rec.from === 'me' && rec.status !== 'delivered') {
      rec.status = 'delivered'; delete rec.error; delete rec.nextTry; outText.delete(rec.id);
      c.established = true; c.lastSeen = Date.now(); save();
      broadcastUi({ type: 'chat.status', host: c.host, id: rec.id, status: 'delivered' });
      broadcastUi({ type: 'contact', contact: uiContact(c) });
    }
    return;
  }
  if (m.t === 'ping') link.send({ t: 'pong' });
}

/* ---- delivery: send now, or hold and retry ------------------------------ */
const RETRY_MS = [30e3, 60e3, 120e3, 300e3, 600e3, 1800e3, 3600e3];
const GIVE_UP_MS = { established: 7 * 864e5, unknown: 864e5 };
const deliverable = (m) => m.from === 'me' && (m.status === 'sending' || m.status === 'pending');
function flushPending(c, link) {
  for (const m of c.msgs) {
    if (!deliverable(m) || link.unacked.has(m.id)) continue;
    const text = textOf(m);
    if (text == null) continue;              // sealed and locked: waits for unlock
    link.send({ t: 'msg', id: m.id, ts: m.ts, text });
    link.unacked.add(m.id);
    if (m.status !== 'sending') { m.status = 'sending'; broadcastUi({ type: 'chat.status', host: c.host, id: m.id, status: 'sending' }); }
  }
}
function deferMsg(c, m, why) {
  m.attempts = (m.attempts || 0) + 1;
  const limit = c.established ? GIVE_UP_MS.established : GIVE_UP_MS.unknown;
  if (Date.now() - m.ts > limit) return failMsg(c, m, `gave up after ${Math.round(limit / 864e5)} day(s): ${why}`);
  m.status = 'pending'; m.error = why;
  m.nextTry = Date.now() + RETRY_MS[Math.min(RETRY_MS.length - 1, m.attempts - 1)] * CFG.retryScale;
  save();
  broadcastUi({ type: 'chat.status', host: c.host, id: m.id, status: 'pending', error: why, nextTry: m.nextTry });
}
function failMsg(c, m, why) {
  m.status = 'failed'; m.error = why; delete m.nextTry; outText.delete(m.id); save();
  broadcastUi({ type: 'chat.status', host: c.host, id: m.id, status: 'failed', error: why });
}
function sendToPeer(c, text) {
  const rec = { id: crypto.randomUUID(), from: 'me', ts: Date.now(), status: 'sending' };
  outText.set(rec.id, text);
  storeText(rec, text);
  pushMsg(c, rec);
  broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec) });
  const l = links.get(c.host);
  if (l && !l.closed) { flushPending(c, l); l.touch(); }
  else connectTo(c, 'send');
}

/* ---- dialling ------------------------------------------------------------
   Standard Noise first. A v1.2 daemon answers our 32-byte msg1 by hanging up,
   so if the line drops before msg2 and we have never spoken v3 to this
   contact, try the old handshake once. Remembered per contact. */
const dialing = new Set();
const lastDial = new Map();
function connectTo(c, why) {
  if (links.has(c.host) || dialing.has(c.host)) return;
  dialing.add(c.host); lastDial.set(c.host, Date.now());
  const port = c.port || CFG.peerPort;
  const first = c.proto === 2 ? 2 : 3;
  attemptDial(c, port, first, (err, link) => {
    if (err && err.beforeMsg2 && first === 3 && c.proto !== 3)
      return attemptDial(c, port, 2, (err2, link2) => done(err2 ? err : null, link2));
    done(err, link);
  });
  function done(err, link) {
    dialing.delete(c.host);
    if (link) return;
    const reason = err.code === 'ECONNREFUSED' ? `refused: nothing listening on ${c.host}:${port}` : (err.message || String(err));
    // A check-in that finds nobody home is not news; a send is.
    const now = Date.now();
    for (const m of c.msgs) if (deliverable(m) && (m.status === 'sending' || (m.nextTry || 0) <= now)) deferMsg(c, m, reason);
    if (why !== 'checkin') log(`deliver to ${c.host}: ${reason}`);
    // A failed dial is fresher news than the last hello: stop calling it online.
    c.lastFailAt = Date.now();
    broadcastUi({ type: 'contact', contact: uiContact(c) });
  }
}
function attemptDial(c, port, proto, cb) {
  let hs = null, link = null, settled = false;
  const settle = (err, l) => { if (settled) return; settled = true; clearTimeout(timer); cb(err, l); };
  const timer = setTimeout(() => { sock && sock.destroy(); settle(new Error(`timeout: is nodesignald running and reachable on ${c.host}:${port}?`)); }, 9000);
  const sock = dial(c.host, port, (s) => {
    s.setNoDelay(true);
    frameStream(s, (frame) => {
      if (link) return link.onFrame(frame);
      let res, session;
      if (proto === 3) { res = noise.v3.initFinish(hs, frame); session = res.session; }
      else { res = noise.legacy.initFinish(hs, frame); session = noise.legacy.makeSession(res.tx, res.rx); }
      if (!tofuCheck(c, res.peerFp)) {
        s.destroy();
        const e = new Error('identity mismatch: this address presented a different key than the one pinned. Review it in the console.');
        e.mismatch = true; return settle(e);
      }
      sendFrame(s, res.msg3);
      tofuRecord(c, res.peerFp);
      c.proto = proto;
      link = openLink(s, { initiator: true, addr: c.host, peerFp: res.peerFp, proto, session });
      bindLink(link, c);
      link.send(helloPayload()); link.helloSent = true;
      flushPending(c, link); link.touch();
      settle(null, link);
    });
    s.once('close', () => { if (!link) { const e = new Error(`connection closed during the handshake with ${c.host}:${port}`); e.beforeMsg2 = true; settle(e); } });
    hs = proto === 3 ? noise.v3.initStart(myIdentity) : noise.legacy.initStart(myIdentity);
    sendFrame(s, hs.msg1);
  }, (e) => settle(e));
}

/* ---- inbound (responder) -------------------------------------------------- */
function serveSecure(sock, addr) {
  let hs = null, proto = 0, link = null;
  frameStream(sock, (frame) => {
    if (link) return link.onFrame(frame);
    if (!hs) {
      // The first frame tells the version: 32 bytes = standard Noise (v3),
      // 44 bytes = the v1.2 handshake (kept for one release).
      if (frame.length === 32) { proto = 3; hs = noise.v3.respond(myIdentity, frame); }
      else if (frame.length === 44) { proto = 2; hs = noise.legacy.respond(myIdentity, frame); }
      else { sock.destroy(); return; }
      sendFrame(sock, hs.msg2);
      return;
    }
    const res = proto === 3 ? hs.finish(frame) : hs._finish(frame);
    const session = proto === 3 ? res.session : noise.legacy.makeSession(res.tx, res.rx);
    const c = contactFor(addr, res.peerFp);
    if (c && !tofuCheck(c, res.peerFp)) { sock.destroy(); return; }
    link = openLink(sock, { initiator: false, addr, peerFp: res.peerFp, proto, session });
    if (c) { tofuRecord(c, res.peerFp); if (proto === 3) c.proto = 3; bindLink(link, c); }
  });
}

const peerServer = net.createServer((sock) => {
  const host = normIp(sock.remoteAddress);
  // --- DDoS / disk-exhaustion defenses -----------------------------------
  //   1. hard cap on concurrent inbound connections
  //   2. per-source-block (IPv4 /32, IPv6 /64) rate limit on new connections
  //   3. NO persisted state until a handshake AND a hello prove a real peer
  if (peerServer._active >= MAX_CONNS) { sock.destroy(); return; }
  if (!rateOk(host)) { sock.destroy(); return; }
  peerServer._active = (peerServer._active || 0) + 1;
  sock.once('close', () => { peerServer._active--; });
  // Unfinished handshakes and idle sessions must not tie up a slot forever.
  sock.setTimeout(30000, () => sock.destroy());
  sock.on('error', () => { });
  serveSecure(sock, host);
});

/* ---- retry queue and check-ins --------------------------------------------
   Every 10s: dial contacts that have a message due for retry. Every
   checkin-ms (with jitter): dial each established contact we haven't spoken
   to recently. A check-in is just a hello; it lets a peer behind NAT collect
   what we hold for it, and keeps "online" honest. */
function retryTick() {
  const now = Date.now();
  for (const c of Object.values(state.contacts)) {
    if (links.has(c.host) || dialing.has(c.host)) continue;
    let due = false;
    for (const m of c.msgs) {
      if (!deliverable(m)) continue;
      const limit = c.established ? GIVE_UP_MS.established : GIVE_UP_MS.unknown;
      if (now - m.ts > limit) { failMsg(c, m, `gave up after ${Math.round(limit / 864e5)} day(s): ${m.error || 'never reached'}`); continue; }
      if ((m.nextTry || 0) <= now && textOf(m) != null) due = true;
    }
    if (due) connectTo(c, 'retry');
  }
}
function checkinTick() {
  if (!(CFG.checkinMs > 0)) return;
  const now = Date.now();
  for (const c of Object.values(state.contacts)) {
    if (!c.established || links.has(c.host) || dialing.has(c.host)) continue;
    if (now - Math.max(c.lastSeen || 0, lastDial.get(c.host) || 0) < CFG.checkinMs * (0.8 + Math.random() * 0.4)) continue;
    connectTo(c, 'checkin');
  }
}

/* ------------------------------------------------------------ UI payloads */
const uiClients = new Set();
function broadcastUi(o) { const s = JSON.stringify(o); for (const ws of uiClients) { try { ws.send(s); } catch { } } }
function broadcastState() { for (const ws of uiClients) { try { ws.send(JSON.stringify(fullState())); } catch { } } }
function publicMsg(m) {
  const text = textOf(m), lk = text == null ? lockKind(m) : null;
  return { id: m.id, from: m.from, ts: m.ts, text, locked: !!lk, lockKind: lk, status: m.status || null,
    error: m.error || null, nextTry: m.nextTry || null, attempts: m.attempts || 0 };
}
const uiContact = (c) => ({ host: c.host, port: c.port || CFG.peerPort, nick: c.nick,
  unread: c.unread, lastSeen: c.lastSeen, peerInfo: c.peerInfo,
  established: !!c.established,
  peerFp: c.peerFp || null,
  pendingFp: c.pendingFp || null,
  proto: c.proto || null,
  lastAddr: c.lastAddr || null,
  online: !!(c.established && c.lastSeen && (Date.now() - c.lastSeen < 5 * 60 * 1000) && !((c.lastFailAt || 0) > c.lastSeen)),
  msgs: c.msgs.slice(-200).map(publicMsg) });
const fullState = () => ({
  type: 'state',
  daemon: { nick: CFG.nick, ua: UA, peerPort: CFG.peerPort, webPort: CFG.webPort, proto: PROTO,
    fingerprint: myIdentity.fp, secure: true,
    vault: { set: vaultOn(), unlocked: unlocked() },
    portMapping: CFG.portMapping ? (portmapStatus || { state: 'mapping' }) : null },
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
    secure: true,
    fingerprint: myIdentity.fp,
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
  const reply = (o) => { try { ws.send(JSON.stringify(o)); } catch { } };
  ws.on('message', async (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || typeof m !== 'object') return;
    try { await handleUi(m, reply); }
    catch (e) { reply({ type: 'error', op: String(m.type || ''), error: e.message }); }
  });
  ws.on('close', () => uiClients.delete(ws));
});
// An address the operator typed: IPv4, IPv6 (brackets stripped), hostname or .onion.
function uiHost(v) {
  const h = normIp(cleanStr(v, 255).replace(/^\[|\]$/g, ''));
  if (!h || !/^[A-Za-z0-9.:%_-]+$/.test(h)) throw new Error('not a valid address');
  return h;
}
const uiPort = (v, d) => { const n = Number(v); return Number.isInteger(n) && n > 0 && n < 65536 ? n : d; };
function identifyNew(c) {
  identifyContact(c.host, 8333).catch((e) => {
    log('identify ' + c.host + ' pending: ' + e.message);
    broadcastUi({ type: 'identified', host: c.host, error: e.message });
    scheduleIdentify(c.host, 5000);
  });
}
async function handleUi(m, reply) {
  switch (m.type) {
    case 'hello': reply(fullState()); return;
    case 'ping': reply({ type: 'pong' }); return;
    case 'contact.add': {
      const host = uiHost(m.host);
      const c = contact(host, true);
      c.port = uiPort(m.port, c.port || CFG.peerPort);
      if (m.nick != null) c.nick = cleanStr(String(m.nick), 60);
      save(); broadcastUi({ type: 'contact', contact: uiContact(c) });
      identifyNew(c);                         // P2P identification fires on every add
      return;
    }
    case 'identify': {
      const host = uiHost(m.host);
      identifyContact(host, uiPort(m.port, 8333))
        .then((info) => reply({ type: 'identified', host, info }))
        .catch((e) => reply({ type: 'identified', host, error: e.message }));
      return;
    }
    case 'contact.remove': {
      const host = uiHost(m.host);
      if (state.contacts[host]) { delete state.contacts[host]; save(); log('contact removed: ' + host); }
      broadcastUi({ type: 'contact.removed', host });
      return;
    }
    case 'contact.acceptKey': {
      // Deliberate re-pinning after a key change. The UI must send back the
      // exact new fingerprint it showed the operator, so a third key that
      // turns up in between is never accepted by accident.
      const c = contact(uiHost(m.host), false);
      if (!c || !c.pendingFp || c.pendingFp.got !== m.fp) throw new Error('no matching key change to accept');
      c.prevFps = (c.prevFps || []).concat({ fp: c.peerFp, replacedAt: Date.now() }).slice(-5);
      c.peerFp = c.pendingFp.got; delete c.pendingFp; save();
      log(`new identity accepted for ${c.host}: ${c.peerFp.slice(0, 16)}...`);
      broadcastUi({ type: 'contact', contact: uiContact(c) });
      for (const x of c.msgs) if (deliverable(x)) x.nextTry = 0;
      retryTick();
      return;
    }
    case 'contact.dismissKey': {
      const c = contact(uiHost(m.host), false);
      if (c && c.pendingFp) { delete c.pendingFp; save(); broadcastUi({ type: 'contact', contact: uiContact(c) }); }
      return;
    }
    case 'chat.send': {
      const host = uiHost(m.host);
      const isNew = !state.contacts[host];
      const c = contact(host, true);
      c.port = uiPort(m.port, c.port || CFG.peerPort);
      const text = typeof m.text === 'string' ? m.text.replace(/\r\n?/g, '\n').trim().slice(0, 4000) : '';
      if (!text) return;
      sendToPeer(c, text);
      if (isNew) identifyNew(c);              // messaging a node peer makes it a contact
      return;
    }
    case 'chat.retry': {
      const c = contact(uiHost(m.host), false); if (!c) return;
      for (const x of c.msgs) if (deliverable(x)) x.nextTry = 0;
      connectTo(c, 'send');
      return;
    }
    case 'chat.cancel': {
      const c = contact(uiHost(m.host), false); if (!c) return;
      const x = findMsg(c, String(m.id || ''));
      if (x && deliverable(x)) failMsg(c, x, 'cancelled');
      return;
    }
    case 'chat.read': {
      const c = contact(uiHost(m.host), false);
      if (c) { c.unread = 0; save(); broadcastUi({ type: 'chat.readack', host: c.host }); }
      return;
    }
    case 'peers.refresh': await pollRpc(); reply(fullState()); return;
    case 'vault.set': await vaultSet(String(m.passphrase || '')); reply({ type: 'vault', ok: true, op: 'set' }); broadcastState(); retryTick(); return;
    case 'vault.unlock': await vaultUnlock(String(m.passphrase || '')); reply({ type: 'vault', ok: true, op: 'unlock' }); broadcastState(); retryTick(); return;
    case 'vault.lock': vaultLock(); broadcastState(); return;
    case 'vault.change': await vaultChange(String(m.old || ''), String(m.passphrase || '')); reply({ type: 'vault', ok: true, op: 'change' }); return;
  }
}

/* ------------------------------------------------------------ router port mapping (opt-in) */
let portmapStatus = null;
function startPortMapping() {
  if (!CFG.portMapping) return;
  let pm;
  try { pm = require('./portmap.js'); }
  catch { log('!! port-mapping is on but portmap.js is missing next to nodesignald.js'); return; }
  if (explicitBind && !['0.0.0.0', '::'].includes(CFG.bind))
    log(`!! port-mapping is on but --bind ${CFG.bind} is not the LAN address: forwarded connections will not arrive`);
  portmapCtl = pm.start({
    internalPort: CFG.peerPort, description: 'NodeSignal',
    log: (s) => log(s),                       // already prefixed upnp: / natpmp: / portmap:
    onChange: (st) => {
      portmapStatus = st;
      if (st.state === 'mapped') log(`port mapping: ${st.method} ${st.externalIp}:${st.externalPort} -> :${CFG.peerPort} (your IP is now public to anyone you contact)`);
      if (st.warning) log('port mapping warning: ' + st.warning);
      broadcastUi({ type: 'portmap', status: st });
    },
  });
}

/* ------------------------------------------------------------ boot */
peerServer.on('error', (e) => { console.error('peer port ' + CFG.peerPort + ': ' + e.message); process.exit(1); });
server.on('error', (e) => { console.error('web port ' + CFG.webPort + ': ' + e.message); process.exit(1); });

// Messages that were mid-delivery when the daemon stopped go back in the queue.
for (const c of Object.values(state.contacts)) for (const m of c.msgs) if (m.from === 'me' && m.status === 'sending') { m.status = 'pending'; m.nextTry = 0; }

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
    if (TS_ADDR && !explicitBind && !CFG.portMapping) log(`bind           : Tailscale (${TS_ADDR}): private tailnet only, not clearnet`);
    else if (!explicitBind && CFG.portMapping) log('bind           : peer port on all interfaces for router port mapping (clearnet)');
    else if (!explicitBind && WEB_BIND === '127.0.0.1') log('bind           : localhost: no Tailscale found; reach the UI via SSH tunnel, peer port is 0.0.0.0');
    else log(`bind           : ${CFG.bind} (explicit)`);
    log(`identity fp    : ${myIdentity.fp}  (peers pin this on first contact)`);
    log(`handshake      : ${noise.PROTOCOL_NAME} (also answers v1.2 peers)`);
    log(`history        : ${vaultOn() ? 'sealed at rest, locked until you unlock it in the console' : 'stored unencrypted; set a passphrase in the console'}`);
    log(`web auth       : ${AUTH_ON ? 'token required (login page)' : 'open: safe only on a private tailnet'}`);
    log(`web root       : ${CFG.webRoot}`);
    log(`state          : ${STATE_FILE}  (${Object.keys(state.contacts).length} contacts)`);
    log(CFG.noRpc ? 'node RPC       : disabled (--no-rpc)' : `node RPC       : ${CFG.rpcUrl}`);
    IMPERSONATED = buildImpersonation();
    if (IMPERSONATED) {
      log(`impersonating  : ${IMPERSONATED.ua}`);
      log(`                 (SIMULATED identity, flagged as such to peers)`);
    }
    console.log('');
    startPortMapping();
    pollRpc();
    setInterval(pollRpc, 30000);
    setInterval(retryTick, Math.max(200, 10000 * CFG.retryScale));
    setInterval(checkinTick, Math.max(5000, Math.min(30000, (CFG.checkinMs || 30000) / 4)));
    setTimeout(retryTick, 1500);
    // identify anything we don't know yet, then refresh hourly
    setTimeout(() => { for (const c of Object.values(state.contacts)) if (!c.peerInfo || c.peerInfo.source === 'claimed') scheduleIdentify(c.host, 2000); }, 2500);
    setInterval(() => {
      for (const c of Object.values(state.contacts)) {
        const age = c.peerInfo && c.peerInfo.source !== 'claimed' ? Date.now() - (c.peerInfo.at || 0) : Infinity;
        if (age > 60 * 60 * 1000) identifyContact(c.host, 8333).catch(() => { });
      }
    }, 15 * 60 * 1000);
  });
});
