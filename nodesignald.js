#!/usr/bin/env node
// nodesignald.js: the NodeSignal daemon + self-hosted web app
// ============================================================================
// Operator-to-operator chat for Bitcoin nodes. Runs beside bitcoind/Knots and
// serves its own web interface on 127.0.0.1 (from elsewhere: an SSH tunnel).
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
//     --bind <addr>        peer port address    (default: Tailscale + 127.0.0.1, else all)
//     --web-root <dir>     where nodesignal.html lives     (default: this dir)
//     --data <dir>         state directory                 (default: ~/.nodesignal)
//     --rpc-url <url>      bitcoind/knots RPC              (default: http://127.0.0.1:8332)
//     --rpc-user <u> --rpc-pass <p>    NodeSignal's own RPC login (normally in
//                          the config file; setup creates a "nodesignal"
//                          rpcauth user limited by rpcwhitelist). The node's
//                          cookie file is never read.
//     --port-mapping       ask the router to forward the peer port (UPnP/NAT-PMP).
//                          Opt-in: it publishes your IP on clearnet.
//     --checkin-ms <n>     how often to check in with established contacts
//                          (default 180000; 0 disables)
//     --no-rpc             standalone: no Bitcoin node on this machine (testing)
//
// The web console never leaves 127.0.0.1. Inbound peers need TCP 8788
// reachable (clearnet), a tailnet, or a Tor hidden service.
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
let W, noise, store, social, mailbox, backup, qr, torcontrol, updater;
try {
  W = require('./nodeps.js'); noise = require('./noise.js'); store = require('./store.js');
  social = require('./social.js'); mailbox = require('./mailbox.js'); backup = require('./backup.js');
  qr = require('./qr.js'); torcontrol = require('./torcontrol.js'); updater = require('./updater.js');
} catch (e) {
  console.error('\n  ' + e.message);
  console.error('  Keep nodesignald.js and the modules listed in packaging/files.json in the same folder.\n');
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
  // Tor: "auto" asks Tor's control port for NodeSignal's own onion service
  // (no torrc editing, no port forwarding); "off" never does; "external"
  // uses an onion the operator set up in torrc, named by onion-address
  // (the "same onion as the node" setup).
  onion: ['auto', 'off', 'external'].includes(arg('onion', 'auto')) ? arg('onion', 'auto') : 'auto',
  onionAddress: arg('onion-address', ''),
  torControl: arg('tor-control', ''),          // host:port or a unix socket path
  torControlPass: arg('tor-control-pass', ''), // HASHEDPASSWORD auth; config file only
  // The address to put in a contact link when there is no onion (a public
  // IP or name the operator knows reaches this machine's peer port).
  publicHost: arg('public-host', ''),
  // Once a day, ask GitHub Releases whether a newer NodeSignal exists.
  updateCheck: !(flag('no-update-check') || FILE_CFG['update-check'] === false),
  updateRepo: arg('update-repo', 'Connor-03/NodeSignal'),
};
const PROTO = 3;   // 3 = standard Noise XX; still answers v2 peers for one release
const UA = '/NodeSignal:1.4/';
const log = (m) => console.log(new Date().toISOString().slice(11, 19) + '  ' + m);
// Strip control characters and cap length: used on every peer-supplied string.
function cleanStr(v, max) {
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, max) : '';
}

/* ------------------------------------------------------------ storage */
fs.mkdirSync(CFG.dataDir, { recursive: true, mode: 0o700 });
const STATE_FILE = path.join(CFG.dataDir, 'state.json');
let state = { contacts: {} };
/* Only a MISSING state.json means a fresh install. Anything else (bad JSON
   after a disk fault, a permission problem) stops the daemon instead of
   starting fresh: a fresh start would write a new identity over the old
   file and lose the identity key, every pin and all history. */
{
  let raw = null;
  try { raw = fs.readFileSync(STATE_FILE, 'utf8'); }
  catch (e) { if (e.code !== 'ENOENT') refuseState(`cannot read it (${e.code || e.message})`); }
  if (raw !== null) {
    try { state = JSON.parse(raw); } catch (e) { refuseState(`it is not valid JSON (${e.message})`); }
    if (!state || typeof state !== 'object' || Array.isArray(state)) refuseState('it does not hold a NodeSignal state object');
  }
}
function refuseState(why) {
  console.error(`\n  NodeSignal will not start: ${STATE_FILE}: ${why}.`);
  console.error('  It holds your identity key and history, so it is left exactly as it is.');
  if (fs.existsSync(STATE_FILE + '.tmp')) console.error(`  ${STATE_FILE}.tmp is a newer save that may be incomplete; check it before using it.`);
  console.error('  Restore it from a backup, or move it aside to start with a new identity.\n');
  process.exit(1);
}
/* Maps keyed by something a peer can choose (an address, a fingerprint) have
   no prototype: on a plain object, contacts["__proto__"] IS Object.prototype,
   and a field written to that "contact" would show up on every other one
   (a pinned key, for one). Names like these are refused as keys anyway. */
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
function dict(from, keep = () => true) {
  const d = Object.create(null);
  if (from && typeof from === 'object' && !Array.isArray(from)) {
    for (const [k, v] of Object.entries(from)) if (!RESERVED_KEYS.has(k) && v && typeof v === 'object' && !Array.isArray(v) && keep(k, v)) d[k] = v;
  }
  return d;
}
state.contacts = dict(state.contacts, (k, c) => { c.host = k; return true; });
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
  try { SOCIAL_FILE.flush(() => feedStore.toJSON()); if (mbStore) MAILBOX_FILE.flush(() => mbStore.toJSON()); } catch { }
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
// A contact that "replied" with our own key was this daemon talking to
// itself (see SELF_ERROR): it never established anything.
for (const c of Object.values(state.contacts || {})) {
  if (c.peerFp === myIdentity.fp) { delete c.peerFp; c.established = false; saveNow(); }
}
// Signing identity (Ed25519) for posts and rooms: the Noise key (X25519)
// cannot sign. Kept beside it in state.json, generated once.
if (!state.signKey) { state.signKey = social.newSigningKey(); saveNow(); }
const mySign = social.loadSigningKey(state.signKey);
// Our signing key, signed for our Noise identity: it goes in every hello.
const MY_SKP = social.bindKey(mySign, myIdentity.fp);
// A contact's signing key counts only with its holder's proof for that
// contact's Noise key (see social.bindKey). Records without one are dropped.
for (const c of Object.values(state.contacts)) {
  if (c.signPub && !(c.peerFp && social.checkBinding(c.signPub, c.skp, c.peerFp))) { delete c.signPub; delete c.skp; }
}
// Settings the console can change at run time. The config file gives the
// defaults; these win once set.
if (!state.settings || typeof state.settings !== 'object') state.settings = {};
const setting = (k, dflt) => (k in state.settings ? state.settings[k] : dflt);
if (!Array.isArray(state.follows)) state.follows = [];         // signing keys (base64) we follow
if (!Array.isArray(state.unfollows)) state.unfollows = [];     // contacts we chose not to follow
if (!Array.isArray(state.myMailboxes)) state.myMailboxes = []; // [{ host, port, fp }] holding mail for us
state.introductions = dict(state.introductions, (k, it) => social.FP_RE.test(k) && it.fp === k);

/* Posts and rooms live in social.json, mail held for others in
   mailbox.json: both can grow to megabytes (mailbox.json to some 43 MB of
   base64), and state.json is rewritten on every message. Same atomic write,
   same 0600. Written at most once per interval, however often something
   changes: a debounce would rewrite the whole file after every quiet second,
   which a peer can arrange. Shutdown flushes. */
function jsonFile(name, everyMs) {
  const file = path.join(CFG.dataDir, name);
  let timer = null, pending = null;
  const writeNow = (obj) => { fs.writeFileSync(file + '.tmp', JSON.stringify(obj()), { mode: 0o600 }); fs.renameSync(file + '.tmp', file); };
  return {
    read() { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } },
    write(obj) {
      pending = obj;
      if (timer) return;
      timer = setTimeout(() => {
        timer = null; const o = pending; pending = null;
        try { writeNow(o); } catch (e) { log('!! could not save ' + name + ': ' + e.message); }
      }, everyMs);
    },
    flush(obj) { clearTimeout(timer); timer = null; pending = null; try { writeNow(obj); } catch { } },
  };
}
const SOCIAL_FILE = jsonFile('social.json', 5000), MAILBOX_FILE = jsonFile('mailbox.json', 30000);
const feedStore = social.createStore();
feedStore.load(SOCIAL_FILE.read());
const saveSocial = () => SOCIAL_FILE.write(() => feedStore.toJSON());
let mbStore = null;                           // mail we hold for others (only when serving)
const mailboxServing = () => setting('mailbox', boolOpt('mailbox'));
function openMailboxStore() {
  if (mbStore) return mbStore;
  mbStore = mailbox.fromJSON(MAILBOX_FILE.read() || {});
  return mbStore;
}
const saveMailbox = () => { if (mbStore) MAILBOX_FILE.write(() => mbStore.toJSON()); };

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
// Every passphrase check (unlock AND change) shares one backoff, so the
// change form cannot be used to guess faster than the unlock form.
async function checkPassphrase(passphrase) {
  if (Date.now() < vault.nextTry) throw new Error('too many attempts, wait ' + Math.ceil((vault.nextTry - Date.now()) / 1000) + 's');
  try { const key = await store.unlock(state.vault, passphrase); vault.fails = 0; return key; }
  catch (e) {
    vault.fails++; vault.nextTry = Date.now() + Math.min(60000, 1000 * 2 ** (vault.fails - 1));
    throw e;
  }
}
async function vaultUnlock(passphrase) {
  if (!vaultOn()) throw new Error('no passphrase is set');
  vault.key = await checkPassphrase(passphrase); vault.cache.clear(); log('history unlocked');
}
function vaultLock() { vault.key = null; vault.cache.clear(); log('history locked'); }
async function vaultChange(oldPass, newPass) {
  if (!vaultOn()) throw new Error('no passphrase is set');
  const key = await checkPassphrase(oldPass);
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
// "nodesignal", "nodesignal:<port>" or (1.4) "nodesignal:<56-char onion id>"
// in a user agent comment: this operator runs NodeSignal, and where.
function nodesignalFromUA(ua) {
  const m = /\bnodesignal(?::([a-z2-7]{56})|[:=](\d{1,5}))?(?![A-Za-z0-9])/i.exec(ua || '');
  if (!m) return null;
  const port = Number(m[2]) || 8788;
  return { port: port >= 1 && port <= 65535 ? port : 8788, onion: m[1] ? m[1].toLowerCase() + '.onion' : null };
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
/* Credentials. NodeSignal logs in to the node as its OWN RPC user: setup
   adds "rpcauth=nodesignal:<salt>$<hash>" plus "rpcwhitelist=nodesignal:
   getblockchaininfo,getnetworkinfo,getpeerinfo" to bitcoin.conf and keeps the
   password in NodeSignal's 0600 config (rpc-user / rpc-pass). The node's
   cookie file is never read, so the daemon needs no access to the node's
   data directory and can run as its own unprivileged user.
   For a daemon started by hand, rpcuser=/rpcpassword= in a bitcoin.conf it
   can read (--rpc-conf, or the default locations) still work. */
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
/* Bitcoin's default data directory is platform-specific:
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
const CONF_PATHS = [
  ...defaultDataDirs().map(d => path.join(d, 'bitcoin.conf')),
  '/etc/bitcoin/bitcoin.conf',
  '/var/lib/bitcoind/bitcoin.conf',
];
const rpcDiag = { source: null, tried: [], port: null };
function rpcAuth() {
  const tried = [];
  if (CFG.rpcUser) { rpcDiag.source = `RPC user "${CFG.rpcUser}"`; rpcDiag.tried = tried; return CFG.rpcUser + ':' + CFG.rpcPass; }
  for (const cp of [CFG.rpcConf, ...CONF_PATHS].filter(Boolean)) {
    const conf = parseBitcoinConf(cp);
    if (!conf) { tried.push({ path: cp, result: 'not readable here' }); continue; }
    tried.push({ path: cp, result: 'read ok, no rpcuser/rpcpassword' });
    if (conf.rpcport) rpcDiag.port = conf.rpcport;
    if (conf.rpcuser && conf.rpcpassword) {
      tried[tried.length - 1].result = 'rpcuser/rpcpassword';
      rpcDiag.source = 'rpcuser/rpcpassword from --rpc-conf'; rpcDiag.tried = tried;
      return conf.rpcuser + ':' + conf.rpcpassword;
    }
  }
  rpcDiag.source = null; rpcDiag.tried = tried;
  return null;
}
function rpcCall(method, params = []) {
  return new Promise((resolve, reject) => {
    const auth = rpcAuth();
    if (!auth) return reject(new Error('NodeSignal has no RPC login yet: run "sudo nodesignal setup" (Linux) or the installer'));
    const u = new URL(CFG.rpcUrl);
    if (rpcDiag.port && u.port === '8332' && !argv.includes('--rpc-url') && !FILE_CFG['rpc-url']) u.port = rpcDiag.port;
    const body = JSON.stringify({ jsonrpc: '1.0', id: 'ns', method, params });
    const req = http.request({
      hostname: u.hostname, port: u.port || 8332, path: '/', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        'Authorization': 'Basic ' + Buffer.from(auth).toString('base64') }, timeout: RPC_TIMEOUT_MS,
    }, (res) => {
      let d = ''; res.on('data', c => { if (d.length < 16 * 1024 * 1024) d += c; });
      res.on('end', () => {
        if (res.statusCode === 401) return reject(new Error(CFG.rpcUser
          ? `the node rejected the "${CFG.rpcUser}" login (401). If NodeSignal was just installed, restart bitcoind so it reads the new rpcauth line`
          : 'the node rejected the login (401)'));
        if (res.statusCode === 403) return reject(new Error(`the node refused "${method}" for this user (403): check the rpcwhitelist line in bitcoin.conf`));
        try { const j = JSON.parse(d); j.error ? reject(new Error(j.error.message)) : resolve(j.result); }
        catch { reject(new Error('bad RPC response (' + res.statusCode + ')')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('RPC timeout')));
    req.end(body);
  });
}
// bitcoind holds its main lock while it connects a block; on a slow disk
// (a USB drive, a Raspberry Pi SD card) getpeerinfo can wait that long.
const RPC_TIMEOUT_MS = 30000;
let pollInFlight = null;
function pollRpc() {
  // a slow node must not pile polls up behind each other
  if (!pollInFlight) pollInFlight = pollRpcOnce().finally(() => { pollInFlight = null; });
  return pollInFlight;
}
async function pollRpcOnce() {
  if (CFG.noRpc) { rpc.error = 'disabled (--no-rpc)'; return; }
  try {
    const [ni, ch, pr] = await Promise.all([rpcCall('getnetworkinfo'), rpcCall('getblockchaininfo'), rpcCall('getpeerinfo')]);
    const wasDown = !rpc.ok;
    rpc.ok = true; rpc.error = null;
    rpc.self = { ua: ni.subversion, impl: implFromUA(ni.subversion), version: verFromUA(ni.subversion),
      declared: declaredFromUA(ni.subversion), height: ch.blocks, network: ch.chain, connections: ni.connections,
      pruned: !!ch.pruned, pruneHeight: ch.pruneheight ?? null, advertising: !!nodesignalFromUA(ni.subversion),
      // the node's own onion address(es), for the "same onion" check
      onions: Array.isArray(ni.localaddresses) ? ni.localaddresses.map((a) => a && a.address).filter(validOnion).slice(0, 4) : [] };
    rpc.peers = pr.map(p => ({
      addr: p.addr, ua: p.subver, impl: implFromUA(p.subver || ''), version: verFromUA(p.subver || ''),
      declared: declaredFromUA(p.subver || ''),
      latency: p.pingtime != null ? Math.round(p.pingtime * 1000) : null,
      // synced_headers is -1 until the peer has sent headers (a light client, an indexer)
      inbound: !!p.inbound, height: p.synced_headers >= 0 ? p.synced_headers : null,
      // ipv4, ipv6, onion, i2p, cjdns or not_publicly_routable (Core 22+, Knots)
      net: typeof p.network === 'string' ? cleanStr(p.network, 24) : null,
      // runs NodeSignal, by its own user agent comment (self-declared, public)
      nodesignal: nodesignalFromUA(p.subver) }));
    rpc._loggedFail = false;
    if (wasDown) log(`node RPC ok via ${rpcDiag.source || 'credentials'}: ${rpc.self.ua} · height ${rpc.self.height} · ${rpc.peers.length} peers`);
    broadcastUi({ type: 'node', self: rpc.self, peers: rpc.peers });
  } catch (e) {
    const was = rpc.ok;
    rpc.ok = false; rpc.error = e.message;
    if (was || !rpc._loggedFail) {
      rpc._loggedFail = true;
      log('!! Bitcoin RPC not connected: ' + e.message);
      if (!rpcDiag.source && rpcDiag.tried.length) {
        log('   looked for rpcuser/rpcpassword in:');
        for (const t of rpcDiag.tried) log(`     ${t.path}  ->  ${t.result}`);
        log('   fix (Linux, on the node): sudo nodesignal setup   then restart bitcoind');
        log('   it adds NodeSignal\'s own rpcauth user to bitcoin.conf; the cookie is never used');
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
    const hard = setTimeout(() => finish(new Error('timeout: nothing answered on ' + host + ':' + port)), 9000);
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
          // Whatever answers on :8333 chooses this string: strip control
          // characters and cap it like Bitcoin Core does (256), before it
          // reaches state.json, the log or the console.
          v.userAgent = cleanStr(v.userAgent, 256);
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
      e.code === 'ECONNREFUSED' ? 'refused: nothing listening on ' + host + ':' + port
        : e.code === 'ETIMEDOUT' ? 'timeout: port closed, firewalled, or unreachable'
          : (e.message || e.code))));
  });
}
// The "same onion" proof is not set here: answering on :8333 says nothing
// about who holds the NodeSignal key. attemptDial() sets it, once we have
// dialled the onion ourselves and the pinned key answered.
async function identifyContact(host, port) {
  if (isPlaceholder(host)) throw new Error('it reached you through Tor or a mailbox: there is no address of its own to identify');
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
  if (!c || !identifiable(c) || (c.peerInfo && c.peerInfo.source !== 'claimed')) return;
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
        log(`identify ${host}: giving up after ${MAX_ID_TRIES} tries (no Bitcoin node there?); messaging still works`);
      else scheduleIdentify(host);
    }
  }, wait));
}


/* ---- outbound dialling, with optional SOCKS5 (Tor) --------------------
   A .onion address cannot be resolved by DNS, so a direct net.connect()
   fails with ENOTFOUND. Reaching another operator's hidden service requires
   handing the hostname to a SOCKS5 proxy (Tor's, normally 127.0.0.1:9050)
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
      ? `no SOCKS proxy at ${px.host}:${px.port}: is Tor running? (set --tor-proxy if it listens elsewhere)`
      : (e.code || e.message))));
  sock.on('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));  // greet: no-auth
  // TCP is a byte stream: a reply may arrive in pieces, so buffer until it is whole.
  let buf = Buffer.alloc(0);
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    if (buf.length > 512) return fail('bad SOCKS5 reply');
    if (stage === 0) {
      if (buf.length < 2) return;
      const chunk = buf; buf = buf.subarray(2);
      if (chunk[0] !== 0x05) return fail('bad SOCKS5 greeting reply');
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
      if (buf.length < 2) return;
      const chunk = buf;
      if (chunk[0] !== 0x05) return fail('bad SOCKS5 reply');
      if (chunk[1] !== 0x00) {
        const why = { 1: 'general failure', 2: 'not allowed', 3: 'network unreachable',
          4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
          7: 'command not supported', 8: 'address type not supported' }[chunk[1]] || ('code ' + chunk[1]);
        return fail(`Tor could not reach ${target}:${targetPort} (${why})`);
      }
      // VER REP RSV ATYP BND.ADDR BND.PORT: the whole reply, before any relayed byte
      if (chunk.length < 5) return;
      const alen = { 1: 4, 3: 1 + chunk[4], 4: 16 }[chunk[3]];
      if (!alen) return fail('bad SOCKS5 reply');
      if (chunk.length < 4 + alen + 2) return;
      const rest = chunk.subarray(4 + alen + 2);
      stage = 2;
      sock.pause();
      sock.removeListener('data', onData);
      if (rest.length) sock.unshift(rest);    // already the peer's first bytes
      onReady(sock);
      sock.resume();
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
  host = String(host).split('%')[0];
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(host);
  if (mapped) host = mapped[1];
  // IPv6 -> /64: the first four groups, written out. Node hands us the
  // compressed form (2001:db8::1:2:3:4), so splitting on ':' alone put every
  // address of a /64 with a zero group in its own block.
  if (host.includes(':')) return 'v6:' + v6Groups(host).slice(0, 4).join(':');
  return 'v4:' + host;                         // IPv4 -> /24 is generous; use full /32
}
function v6Groups(h) {
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);   // a dotted IPv4 tail is two groups
  if (v4) h = h.slice(0, v4.index) + ((v4[1] << 8) | v4[2]).toString(16) + ':' + ((v4[3] << 8) | v4[4]).toString(16);
  const cut = h.indexOf('::');
  const head = (cut < 0 ? h : h.slice(0, cut)).split(':').filter(Boolean);
  const tail = cut < 0 ? [] : h.slice(cut + 2).split(':').filter(Boolean);
  const zeros = cut < 0 ? [] : Array(Math.max(0, 8 - head.length - tail.length)).fill('0');
  return [...head, ...zeros, ...tail].map((g) => (parseInt(g, 16) || 0).toString(16));
}
function rateOk(host) {
  const key = sourceBlock(host);
  const now = Date.now();
  // Every onion peer reaches us from 127.0.0.1 through Tor, so that one
  // source gets eight times the burst and refill. MAX_CONNS still caps it.
  const tor = host === '127.0.0.1' || host === '::1';
  const burst = tor ? RL_BURST * 8 : RL_BURST, every = tor ? RL_REFILL_MS / 8 : RL_REFILL_MS;
  // The Map's insertion order is the eviction order: a bucket in use moves to
  // the end, so the first one is the least recently used. Sorting all 4096
  // on every new source block let a spray of addresses burn CPU instead.
  let b = rlBuckets.get(key);
  if (b) { rlBuckets.delete(key); rlBuckets.set(key, b); }
  else {
    if (rlBuckets.size >= RL_MAX_BLOCKS) rlBuckets.delete(rlBuckets.keys().next().value);
    b = { tokens: burst, ts: now }; rlBuckets.set(key, b);
  }
  const refill = Math.floor((now - b.ts) / every);
  if (refill > 0) { b.tokens = Math.min(burst, b.tokens + refill); b.ts = now; }
  if (b.tokens <= 0) return false;
  b.tokens--; return true;
}

/* ---- where the ports listen ---------------------------------------------
     · the WEB console: always 127.0.0.1 (reach it from elsewhere through an
       SSH tunnel)
     · the PEER port: the Tailscale address when there is one (plus
       127.0.0.1, where Tor hands onion peers over); otherwise every
       interface (0.0.0.0), so a peer can reach it on a public address or
       through a forwarded router port. Behind a home router nothing forwards
       it unless the operator turns on port mapping or forwards it by hand.
       --bind 127.0.0.1 keeps it to Tor (and this machine) only. */
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
// The web console is for THIS machine only: always loopback, whatever --bind
// says (that option now applies to the peer port only). Reach it from another
// machine through an SSH tunnel that keeps the same port number.
const WEB_BIND = '127.0.0.1';
// Router port mapping forwards to this machine's LAN address, so the peer
// port must listen there too.
const PEER_BIND = explicitBind ? CFG.bind : (CFG.portMapping ? '0.0.0.0' : (TS_ADDR || '0.0.0.0'));


/* ------------------------------------------------------------ contacts */
function contact(host, create) {
  host = normIp(host);
  if (RESERVED_KEYS.has(host)) { if (create) throw new Error('not a valid address'); return undefined; }
  if (!state.contacts[host] && create)
    state.contacts[host] = { host, port: CFG.peerPort, nick: '', msgs: [], unread: 0, lastSeen: 0, peerInfo: null };
  return state.contacts[host];
}
/* Placeholder keys for peers whose address says nothing: "tor:<fp>" for one
   that reached us through Tor (from 127.0.0.1), "mbox:<fp>" for one we only
   know from sealed mail, "peer:<fp>" for one someone else told us about (a
   room member entry, a contact's mailbox). Nobody can claim them: they are
   the peer's own key. */
function isPlaceholder(h) { return /^(tor|mbox|peer):/.test(String(h || '')); }
// A contact the operator added or wrote to: not one that only called us
// (inbound), and not one NodeSignal made itself for a room member, a mailbox
// or a pinned introduction (auto).
function chosen(c) { return !!c && !c.inbound && !c.auto; }
// ...and a real two-way exchange happened. Introductions, auto-follow, other
// people's posts, mailbox registration and check-ins are for these only: one
// unsolicited message makes a stranger "established", nothing more.
function trusted(c) { return chosen(c) && !!c.established; }
// Its node is worth a :8333 handshake: an address it really connected from,
// or one the operator gave. Never a host a peer merely claimed.
function identifiable(c) { return !!c && !isPlaceholder(c.host) && !c.auto; }
// The contact a proven key belongs to. A record at a real address (the
// operator's) wins over a placeholder for the same key.
function contactByKey(fp) {
  let alt = null;
  for (const x of Object.values(state.contacts)) {
    if (x.peerFp !== fp) continue;
    if (!isPlaceholder(x.host)) return x;
    alt = alt || x;
  }
  return alt;
}
// Move a record to another key (a placeholder the operator now gives an
// address for), with the link and queued work that go with it.
function rekeyContact(c, host) {
  const old = c.host;
  if (old === host || state.contacts[host] || dialing.has(old)) return false;
  delete state.contacts[old];
  c.host = host; state.contacts[host] = c;
  delete c.addr;                             // the address it now lives at is the one to call
  const l = links.get(old);
  if (l) { links.delete(old); if (!links.has(host)) links.set(host, l); }
  const tasks = linkTasks.get(old);
  if (tasks) { linkTasks.delete(old); linkTasks.set(host, tasks); }
  broadcastUi({ type: 'contact.removed', host: old });
  return true;
}
/* Strangers: anyone can make a key and complete a handshake, so a contact
   created by an inbound peer (not one the operator added or wrote to) is
   marked inbound and kept on a budget. Without it, one IPv6 /64 could
   create a new contact per address, within the rate limit, until the disk
   that bitcoind shares is full. Adding or messaging the contact lifts it. */
const MAX_STRANGERS = 256;                   // inbound-only contacts kept at once
const STRANGER_MSGS = 50;                    // messages kept per inbound-only contact
const LINK_MAX_FRAMES = 1000, LINK_MAX_MSGS = 200;   // per connection
const LINK_MAX_POSTS = 200;                  // posts looked at per connection (each is a signature check)
let strangerFullLogged = 0;
// A new record for a peer that called us. Never an existing one: whatever is
// filed under that key (a contact the operator wrote to, a message waiting)
// belongs to someone else, and the caller has already matched by key.
function newStranger(addr) {
  if (Object.values(state.contacts).filter((x) => x.inbound).length >= MAX_STRANGERS) {
    if (Date.now() - strangerFullLogged > 60000) {
      strangerFullLogged = Date.now();
      log(`!! refused a new contact from ${addr}: ${MAX_STRANGERS} contacts you never added or wrote to are already stored. Remove some in the console.`);
    }
    return null;
  }
  if (contact(addr, false)) { log(`!! refused a peer as ${addr}: that name already belongs to another contact`); return null; }
  const c = contact(addr, true); c.inbound = true; return c;
}
function pushMsg(c, m) {
  const cap = c.inbound ? STRANGER_MSGS : 500;
  c.msgs.push(m); if (c.msgs.length > cap) c.msgs.splice(0, c.msgs.length - cap); save();
}
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
// What a hello can change that is worth writing state.json for. Not the
// claimed node's peer count or height (they move with every block), and
// lastSeen only now and then (see onPeerMessage).
function helloSnapshot(c) {
  const pi = c.peerInfo ? Object.assign({}, c.peerInfo, { connections: null, height: null }) : null;
  return JSON.stringify([c.nick, c.port, pi, c.peerProto, c.caps, c.signPub, c.skp, c.onion, c.servesMailbox, c.mailboxes, c.discoverable, c.peerPub]);
}
// peerFp: the key this hello arrived under (proven by the handshake).
function applyHello(c, m, peerFp) {
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
  // 1.4 fields. The hello arrives over the authenticated link, so what it
  // says about the peer's own keys and addresses is the peer's word for it.
  c.caps = Array.isArray(m.caps) ? m.caps.filter((x) => typeof x === 'string' && /^[a-z0-9]{1,16}$/.test(x)).slice(0, 16) : [];
  // A signing key counts only with its holder's signature for this link's
  // Noise key (skp): anyone can copy someone else's sk from a hello.
  if (social.isPub(m.sk) && social.checkBinding(m.sk, m.skp, peerFp)) {
    if (c.signPub && c.signPub !== m.sk) log(`${c.nick || c.host} now signs with a different key`);
    c.signPub = m.sk; c.skp = m.skp;
  }
  // The onion it names is only a way to call it back, through Tor, where the
  // pinned key must answer (attemptDial). Never the key it is filed under.
  if (validOnion(m.onion)) c.onion = m.onion;
  c.servesMailbox = m.mbox === true;
  c.mailboxes = cleanMailboxes(m.mbx);
  c.discoverable = m.disc === true;
}

/* ------------------------------------------------------------ peer wire (:8788) */
const helloPayload = () => ({ t: 'hello', proto: PROTO, nick: CFG.nick, ua: UA,
  peerPort: CFG.peerPort, node: rpc.ok ? rpc.self : (IMPERSONATED || null), fp: myIdentity.fp,
  // 1.4: what this daemon understands, its signing key, how to reach it
  caps: CAPS, sk: mySign.pub, skp: MY_SKP, onion: myOnion || undefined, pub: CFG.publicHost || undefined,
  mbox: mailboxServing() || undefined, mbx: state.myMailboxes.length ? state.myMailboxes.map(mbPublic) : undefined,
  disc: discoverable() || undefined });

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
// A peer that reached the node through Tor shows in getpeerinfo as
// 127.0.0.1 (Tor hands it over locally), and dialling that address reaches
// this daemon. Until this check, the message then counted as delivered.
const SELF_ERROR = 'this address leads back to your own NodeSignal. A peer that connected to your node through Tor shows as 127.0.0.1, which hides its real address, so it cannot be messaged from the map';
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
// The peer's raw X25519 public key, base64, from the handshake's DER.
const pubRawB64 = (der) => { const b = Buffer.from(String(der || ''), 'base64'); return b.length === 44 ? b.subarray(12).toString('base64') : null; };
function tofuRecord(c, fp) {
  if (!c.peerFp) { c.peerFp = fp; save(); log(`pinned identity for ${c.host}: ${fp.slice(0, 16)}...`); }
}
// An authenticated key we already pinned identifies the contact even if its
// address changed (dynamic IP, NAT): the key is the identity, not the IP.
function contactFor(addr, fp) {
  // From loopback (Tor), the address belongs to nobody: only the key counts.
  if (!isLoopback(addr)) { const c = state.contacts[addr]; if (c) return c; }
  const byKey = contactByKey(fp);
  if (byKey) { if (!isLoopback(addr)) byKey.lastAddr = addr; return byKey; }
  return null;
}

/* ---- links: one authenticated session, either direction ---------------
   Whoever dialled, the session carries messages BOTH ways. When a peer we
   cannot reach (NAT, no port forward) connects to us, everything we have
   queued for it goes back over its own connection. So only one of two
   operators needs to be reachable. */
const links = new Map();                     // contact host -> live link
const LINK_IDLE_MS = 2500, LINK_MAX_MS = 30000;
/* Sizes. A Noise frame carries at most 65535 bytes, tag included, so one
   JSON frame may be 65519 bytes; anything batched (posts, room items, mail,
   introductions) is cut to FRAME_BUDGET bytes per frame. A peer that stops
   reading must not make us buffer without end: past LINK_MAX_BUFFER bytes
   waiting to be written, the link is dropped. */
const FRAME_MAX = 65519, FRAME_BUDGET = 60000, LINK_MAX_BUFFER = 1024 * 1024;
// items -> arrays of items, each at most `max` long and FRAME_BUDGET - reserve
// bytes as JSON. An item too big for any frame is left out.
function batches(items, max, reserve = 512) {
  const budget = FRAME_BUDGET - reserve, out = [];
  let cur = [], bytes = 0;
  for (const it of items) {
    const n = Buffer.byteLength(JSON.stringify(it)) + 1;
    if (n > budget) continue;
    if (cur.length && (cur.length >= max || bytes + n > budget)) { out.push(cur); cur = []; bytes = 0; }
    cur.push(it); bytes += n;
  }
  if (cur.length) out.push(cur);
  return out;
}
function openLink(sock, { initiator, addr, peerFp, proto, session }) {
  const link = { sock, initiator, addr, peerFp, proto, contact: null, unacked: new Set(), closed: false, helloSent: false, peerHello: false };
  link.send = (obj) => {
    if (link.closed) return;
    const json = JSON.stringify(obj);
    if (Buffer.byteLength(json) > FRAME_MAX) { log(`!! not sent to ${addr}: a "${obj.t}" frame over ${FRAME_MAX} bytes`); return; }
    sendFrame(sock, session.encrypt(json));
    if (sock.writableLength > LINK_MAX_BUFFER) {
      log(`!! dropped the link with ${link.contact ? link.contact.nick || link.contact.host : addr}: over ${LINK_MAX_BUFFER >> 20} MB waiting, it is not reading`);
      link.closed = true; sock.destroy();
    }
  };
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
  link.frames = 0; link.msgs = 0;
  link.onFrame = (frame) => {
    // One connection may not flood us: a real peer's queue fits easily, and
    // anything cut off is retried by the sender and deduplicated by id.
    if (++link.frames > LINK_MAX_FRAMES) { sock.destroy(); return; }
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
/* Requests whose answer can be large are answered one at a time per link,
   the next only once the last answer has left our write buffer, and at most
   one of each kind waits (one per room for room-req). A peer that asks
   again and again and never reads gets one answer, not one per request. */
const REQ_FRAMES = new Set(['feed-req', 'room-req', 'mb-get', 'who-req']);
function serveReq(link, key, fn) {
  const q = link.reqs || (link.reqs = { waiting: new Map(), busy: false });
  if (q.waiting.has(key) || q.waiting.size >= 24) return;
  q.waiting.set(key, fn);
  pumpReqs(link);
}
function pumpReqs(link) {
  const q = link.reqs;
  if (!q || q.busy || link.closed || !q.waiting.size) return;
  const [key, fn] = q.waiting.entries().next().value;
  q.waiting.delete(key);
  q.busy = true;
  try { fn(); } catch { link.sock.destroy(); return; }   // as for any bad frame: this link, never the daemon
  const next = () => { q.busy = false; pumpReqs(link); };
  if (link.sock.writableNeedDrain) link.sock.once('drain', next); else setImmediate(next);
}

function onPeerMessage(link, m) {
  link.touch();
  if (m.t === 'hello') {
    let c = link.contact;
    if (!c) {
      // First authenticated hello from a stranger: only now is state created.
      c = newStranger(strangerHost(link, m));
      if (!c) { link.sock.destroy(); return; }
      if (!tofuCheck(c, link.peerFp)) { link.sock.destroy(); return; }
      tofuRecord(c, link.peerFp);
      bindLink(link, c);
      if (!isPlaceholder(c.host) && !isLoopback(c.host)) scheduleIdentify(c.host, 1000);
    }
    // Write state.json only when the hello changed something: every check-in
    // is a hello, and the file holds the whole history.
    const before = helloSnapshot(c);
    if (link.peerPub) c.peerPub = link.peerPub;
    applyHello(c, m, link.peerFp); link.peerHello = true;
    if (helloSnapshot(c) !== before || Date.now() - (seenSaved.get(c) || 0) > 10 * 60e3) { seenSaved.set(c, Date.now()); save(); }
    if (!link.helloSent) { link.send(helloPayload()); link.helloSent = true; }
    // Answer a v3 peer's call with whatever we have queued for it.
    if (!link.initiator && c.peerProto >= 3) flushPending(c, link);
    broadcastUi({ type: 'contact', contact: uiContact(c) });
    afterHello(link, c);
    return;
  }
  if (m.t === 'msg') {
    if (++link.msgs > LINK_MAX_MSGS) { link.sock.destroy(); return; }
    let c = link.contact;
    if (!c) {                                 // v2 peers may skip hello
      c = newStranger(strangerHost(link, {}));
      if (!c) { link.sock.destroy(); return; }
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
  if (m.t === 'ping') { link.send({ t: 'pong' }); return; }
  const handler = typeof m.t === 'string' && Object.prototype.hasOwnProperty.call(SOCIAL_FRAMES, m.t) ? SOCIAL_FRAMES[m.t] : null;
  if (handler && link.contact && link.peerHello) {
    if ((link.social = (link.social || 0) + 1) > 400) { link.sock.destroy(); return; }
    if (REQ_FRAMES.has(m.t)) serveReq(link, m.t === 'room-req' ? 'room-req:' + String(m.room).slice(0, 40) : m.t, () => handler(link, link.contact, m));
    else handler(link, link.contact, m);
  }
}
const seenSaved = new WeakMap();             // contact -> when a hello last saved it
/* The contact key for a peer that called us: the address it called from.
   Tor hands every onion peer over from 127.0.0.1, where the address says
   nothing, so there it is "tor:<its fingerprint>". Whatever the hello names
   (an onion, a public address) is the peer's word only: filing the peer
   under it would let anyone take over a contact the operator wrote to, with
   its waiting messages, or make us dial and identify a host of their
   choosing. The onion stays a way to call back through Tor (applyHello). */
function strangerHost(link) {
  return isLoopback(link.addr) ? 'tor:' + link.peerFp : link.addr;
}

/* ==========================================================================
   1.4: reachability, posts, rooms, mailboxes, introductions
   --------------------------------------------------------------------------
   Every frame below goes only to peers whose hello listed the matching
   capability, and older daemons ignore frames they do not know. When a link
   is up and both hellos are exchanged, afterHello() syncs whatever both
   sides support, so the regular check-ins also keep feeds, rooms and
   mailboxes current. Everything a peer sends is checked and capped. */
const CAPS = ['social1', 'rooms1', 'mbox1', 'who1'];
const hasCap = (c, cap) => !!(c && Array.isArray(c.caps) && c.caps.includes(cap));
const isLoopback = (h) => h === '127.0.0.1' || h === '::1';
const validOnion = (h) => typeof h === 'string' && social.ONION_RE.test(h);
const FP_RE = /^[0-9a-f]{32}$/;
let myOnion = CFG.onion === 'external' && validOnion(CFG.onionAddress) ? CFG.onionAddress : null;
const discoverable = () => setting('discoverable', boolOpt('discoverable'));
// How other operators reach this daemon: for contact links, room member
// entries and the reply address inside mailbox mail.
function myReach() {
  if (myOnion) return { host: myOnion, port: CFG.peerPort };
  if (CFG.publicHost) return { host: CFG.publicHost, port: CFG.peerPort };
  return null;
}
const mbPublic = (mb) => ({ host: mb.host, port: mb.port, fp: mb.fp });
// A host from a peer that may become a contact key or be dialled: an IP,
// a name or an onion; never a placeholder, loopback or a reserved name.
const peerHostOk = (h) => typeof h === 'string' && /^[A-Za-z0-9.:\-[\]]{1,255}$/.test(h) && !RESERVED_KEYS.has(h) && !isLoopback(h) && !isPlaceholder(h);
function cleanMailboxes(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const x of v.slice(0, 2)) {
    if (!x || typeof x !== 'object') continue;
    const host = cleanStr(x.host, 255), port = Number(x.port);
    if (!peerHostOk(host) || !FP_RE.test(x.fp) || !(Number.isInteger(port) && port > 0 && port < 65536)) continue;
    out.push({ host, port, fp: x.fp });
  }
  return out;
}
/* A contact NodeSignal itself needs (a room member, a mailbox), with its key
   pinned up front, from what someone else said: a member entry, a mailbox
   a contact named. That is their word, so it is filed under the key
   ("peer:<fp>", an "auto" record) and never under the address it names: a
   record there, or one made there later, would let the holder of that key
   take what the operator writes to that address (over its own link, or
   sealed to its key at its mailbox), and lock out whoever really answers
   there. The address is kept only as a place to call it (c.addr), where
   the pinned key must answer (attemptDial). Auto records are hidden until a
   message is exchanged and capped like strangers.
   operator: the operator asked (a room link, an introduction they
   accepted): the record goes under the address they gave, their key may go
   on a record there that has none yet, and a placeholder for the same key
   moves there. */
const MAX_AUTO = 256;
let autoFullLogged = 0;
function ensureContact({ host, port, fp, nick, hidden = true }, { operator = false } = {}) {
  if (!FP_RE.test(fp) || fp === myIdentity.fp) return null;
  const okPort = Number.isInteger(port) && port > 0 && port < 65536;
  const byKey = contactByKey(fp);
  if (byKey) {
    if (operator && isPlaceholder(byKey.host) && peerHostOk(host) && !contact(host, false) && rekeyContact(byKey, host)) {
      delete byKey.auto; delete byKey.addr;
      if (validOnion(host)) byKey.onion = host;
      if (okPort) byKey.port = port;
      save();
    }
    return byKey;
  }
  if (!peerHostOk(host)) return null;
  if (!operator) {
    if (contact('peer:' + fp, false)) return null;
    if (Object.values(state.contacts).filter((x) => x.auto).length >= MAX_AUTO) {
      if (Date.now() - autoFullLogged > 60000) { autoFullLogged = Date.now(); log(`!! not adding ${host} for a room or mailbox: ${MAX_AUTO} such contacts are stored already`); }
      return null;
    }
    const c = contact('peer:' + fp, true);
    c.auto = true; c.hidden = true; c.peerFp = fp; c.pinnedBy = 'introduced';
    if (validOnion(host)) c.onion = host; else c.addr = host;
    if (okPort) c.port = port;
    if (nick) c.nick = cleanStr(nick, 60);
    save();
    return c;
  }
  const have = contact(host, false);
  if (have && have.peerFp) return null;                 // someone else answers there
  const c = contact(host, true);
  delete c.inbound;
  c.peerFp = fp; c.pinnedBy = 'introduced';
  if (okPort) c.port = port;
  if (nick && !c.nick) c.nick = cleanStr(nick, 60);
  if (hidden && !c.msgs.length && !have) c.hidden = true;
  if (validOnion(host)) c.onion = host;
  save();
  return c;
}

/* ---- work that waits for a link --------------------------------------- */
// Something peers learn from our hello changed (a setting, our onion, our
// mailbox): tell the links that are open now; others hear it next time.
function rehello() { for (const l of links.values()) if (!l.closed && l.helloSent) l.send(helloPayload()); }
// Register with our mailbox and collect what it holds, now if a link is up.
function pokeMailbox(c) {
  const l = links.get(c.host);
  if (l && !l.closed && l.peerHello) { l.send({ t: 'mb-reg' }); l.send({ t: 'mb-get' }); l.touch(); return; }
  withLink(c, () => { });                    // afterHello registers and fetches
}
const linkTasks = new Map();                 // contact host -> [fn(link)]
function withLink(c, task) {
  const l = links.get(c.host);
  if (l && !l.closed && l.peerHello) { try { task(l); } catch (e) { log('link task: ' + e.message); } l.touch(); return; }
  const list = linkTasks.get(c.host) || [];
  if (list.length < 50) list.push(task);
  linkTasks.set(c.host, list);
  connectTo(c, 'task');
}
function runLinkTasks(link, c) {
  const list = linkTasks.get(c.host);
  if (!list) return;
  linkTasks.delete(c.host);
  for (const f of list) { try { f(link); } catch (e) { log('link task: ' + e.message); } }
}
function afterHello(link, c) {
  if (link.synced) return;
  link.synced = true;
  syncWith(link, c, false);
  runLinkTasks(link, c);
}
// Ask the peer for what it has that we may have missed. force: also ask for
// introductions even if we did today (the console's refresh).
function syncWith(link, c, force) {
  const now = Date.now();
  if (hasCap(c, 'social1') && (!c.inbound || c.established)) link.send({ t: 'feed-req', since: c.feedAt ? c.feedAt - 3600e3 : now - 7 * 864e5 });
  if (hasCap(c, 'rooms1') && c.signPub) {
    for (const r of feedStore.roomList()) {
      if (!r.joined || !r.members.has(c.signPub) || r.members.get(c.signPub).left) continue;
      const since = (c.roomAt && c.roomAt[r.def.room]) || 0;
      link.send({ t: 'room-req', room: r.def.room, since: since ? since - 3600e3 : 0 });
    }
  }
  if (hasCap(c, 'who1') && discoverable() && c.discoverable && trusted(c) && (force || now - (c.whoAt || 0) > 864e5)) {
    link.whoAsked = true; link.whoTaken = 0;  // the only answer we take is to this, 100 entries at most
    link.send({ t: 'who-req' });
  }
  if (hasCap(c, 'mbox1') && state.myMailboxes.some((mb) => mb.fp === c.peerFp)) { link.send({ t: 'mb-reg' }); link.send({ t: 'mb-get' }); }
}

/* ---- posts ------------------------------------------------------------- */
// Followed signing keys: the ones followed by hand, plus every trusted
// contact's (one the operator added or wrote to, with a two-way exchange),
// unless unfollowed. A stranger who sent one message is not followed.
function followSet() {
  const s = new Set(state.follows);
  for (const c of Object.values(state.contacts)) if (trusted(c) && c.signPub && !state.unfollows.includes(c.signPub)) s.add(c.signPub);
  return s;
}
const nameForFp = (fp) => { const c = contactByKey(fp); return c ? (c.nick || c.host) : null; };
function uiPost(p) {
  const author = Object.values(state.contacts).find((x) => x.signPub === p.o.a);
  return { id: p.id || social.idOf(p.o), a: p.o.a, keyId: social.keyId(Buffer.from(p.o.a, 'base64')), nick: p.o.nick, fp: p.o.fp,
    ts: p.o.ts, text: p.o.text, mine: p.via === null, hops: p.hops, via: p.via ? nameForFp(p.via) || p.via.slice(0, 12) : null,
    // the signing key matches the one this contact announced over its own authenticated link
    contact: author ? { host: author.host, nick: author.nick || null } : null };
}
function sendPosts(link, entries) {
  for (const items of batches(entries.map((p) => ({ o: p.o, h: p.via === null ? 0 : p.hops })), 25)) link.send({ t: 'posts', items });
}
function createPost(text) {
  const o = social.makePost(mySign, { fp: myIdentity.fp, nick: CFG.nick, text });
  if (!o.text) throw new Error('a post needs some text');
  const r = feedStore.addPost(o, { via: null, hops: 0, mine: true });
  if (r.status !== 'new') throw new Error('could not store the post: ' + (r.error || r.status));
  saveSocial();
  const entry = { id: r.id, o, via: null, hops: 0 };
  broadcastUi({ type: 'post', post: uiPost(entry) });
  let n = 0;
  for (const c of Object.values(state.contacts)) {
    if (n >= 100 || !trusted(c) || !hasCap(c, 'social1')) continue;
    n++; withLink(c, (l) => sendPosts(l, [entry]));
  }
  log(`posted ${r.id.slice(0, 12)}..., pushed to ${n} contact(s)`);
  return entry;
}

/* ---- rooms ------------------------------------------------------------- */
const pendingJoins = new Map();              // room id -> { at, name } while a join is in flight
function uiRoom(r) {
  return { room: r.def.room, name: r.def.name, creator: r.def.a, joined: r.joined,
    members: [...r.members.values()].map((m) => ({ a: m.a, nick: m.nick, fp: m.fp, host: m.host || null, left: !!m.left, me: m.a === mySign.pub })),
    msgs: feedStore.roomMsgs(r.def.room, { limit: 100 }).map((m) => ({ id: m.id, a: m.o.a, nick: m.o.nick, ts: m.o.ts, text: m.o.text, mine: m.o.a === mySign.pub })) };
}
function myMember(room, left = false) {
  const reach = myReach() || {};
  return social.makeMember(mySign, { room, fp: myIdentity.fp, nick: CFG.nick, host: reach.host, port: reach.port, left });
}
// Send items to every other member we can address. Members with no address
// (no onion, no public host) get them through the sync on their next link.
// A member entry is the member's word for its key and address: ensureContact
// never lets it take over a record that exists, and a contact we know signs
// with another key is not that member. Dialling goes through dial(), so an
// onion, or every host under --tor-all, is reached through Tor.
function fanOutRoom(r, items) {
  let n = 0;
  for (const m of r.members.values()) {
    if (m.a === mySign.pub || m.left || !m.host || n >= 100) continue;
    const c = ensureContact({ host: m.host, port: m.port, fp: m.fp, nick: m.nick });
    if (!c || (c.signPub && c.signPub !== m.a)) continue;
    n++;
    withLink(c, (l) => sendRoomItems(l, r.def.room, items));
  }
  return n;
}
function sendRoomItems(link, room, items) {
  for (const b of batches(items, 20)) link.send({ t: 'room-items', room, items: b });
}
function roomLink(room) {
  const r = feedStore.room(room), reach = myReach();
  if (!r || !r.joined) throw new Error('not in that room');
  if (!reach) throw new Error('no address to invite people to: NodeSignal needs Tor (an onion) or a public-host setting');
  const q = new URLSearchParams({ name: r.def.name, host: reach.host, port: String(reach.port), fp: myIdentity.fp });
  return `nodesignal-room:${room}?${q}`;
}
function parseRoomLink(s) {
  const m = /^nodesignal-room:([0-9a-f]{32})\?(.*)$/.exec(String(s || '').trim());
  if (!m) throw new Error('not a NodeSignal room link');
  const q = new URLSearchParams(m[2]);
  const host = (q.get('host') || '').replace(/^\[|\]$/g, ''), port = Number(q.get('port') || CFG.peerPort), fp = (q.get('fp') || '').toLowerCase();
  if (!host || !FP_RE.test(fp) || !(Number.isInteger(port) && port > 0 && port < 65536)) throw new Error('the room link is incomplete');
  // the same rule as a contact link: the host becomes a contact key
  if (!/^[A-Za-z0-9.:-]{1,255}$/.test(host) || RESERVED_KEYS.has(host)) throw new Error('the room link has no usable address');
  return { room: m[1], name: cleanStr(q.get('name') || '', 60), host, port, fp };
}

/* ---- mailboxes ---------------------------------------------------------
   A reachable operator who opted in holds sealed mail for operators it
   cannot otherwise reach. The sealed box (mailbox.js) hides the text from
   the mailbox. The sender deposits over its own authenticated link, so
   the mailbox does learn who writes to whom, when, and how much: say so
   wherever the feature is offered. */
const MB_MAX_BLOB = 16 * 1024;
const MB_REPLY_BYTES = 512 * 1024;           // base64 per mb-get answer
function mailboxContact(mb) { return ensureContact({ host: mb.host, port: mb.port, fp: mb.fp }); }
// Sealed only to the public key that answered for the pinned fingerprint
// (learned in a handshake or from mail it sealed itself), never to a key
// someone named for it.
function sealFor(c, payload) {
  if (!c.peerPub || !c.peerFp) throw new Error('no public key for ' + (c.nick || c.host) + ' yet');
  const pub = Buffer.from(c.peerPub, 'base64');
  if (pub.length !== 32 || noise.fingerprintRaw(pub) !== c.peerFp) throw new Error('the stored public key for ' + (c.nick || c.host) + ' is not the pinned one');
  const blob = mailbox.seal({ senderPrivRaw: myIdentity.privRaw, senderPubRaw: myIdentity.pubRaw,
    recipientPubRaw: pub, plaintext: Buffer.from(JSON.stringify(payload)) });
  if (blob.length > MB_MAX_BLOB) throw new Error('too large for a mailbox');
  return blob.toString('base64');
}
const myReturnAddress = () => ({ reply: myReach() || undefined, mbx: state.myMailboxes.length ? state.myMailboxes.map(mbPublic) : undefined, sk: mySign.pub, skp: MY_SKP, nick: CFG.nick });
// Leave a message at the recipient's mailbox when it cannot be reached directly.
function depositMessage(c, m) {
  // not while its key is in doubt: a different key answered at its address
  if (!c.mailboxes || !c.mailboxes.length || !c.peerPub || m.heldAt || c.pendingFp) return;
  if (Date.now() - (m.mbTriedAt || 0) < 10 * 60e3) return;
  const text = textOf(m);
  if (text == null) return;
  m.mbTriedAt = Date.now();
  const mb = c.mailboxes[0], mc = mailboxContact(mb);
  if (!mc || mc === c) return;
  let blob;
  try { blob = sealFor(c, Object.assign({ k: 'msg', id: m.id, ts: m.ts, text }, myReturnAddress())); }
  catch (e) { log(`mailbox for ${c.nick || c.host}: ${e.message}`); return; }
  // a fresh deposit id, so the mailbox cannot match it to the message id
  const did = mailbox.newDepositId();
  withLink(mc, (l) => {
    (l.deposits || (l.deposits = new Map())).set(did, { c, m });
    l.send({ t: 'mb-put', to: c.peerFp, id: did, blob });
  });
}
function depositReceipt(c, ids) {
  if (!c.mailboxes || !c.mailboxes.length || !c.peerPub) return;
  const mc = mailboxContact(c.mailboxes[0]);
  if (!mc || mc === c) return;
  let blob;
  try { blob = sealFor(c, Object.assign({ k: 'receipt', ids: ids.slice(0, 50) }, myReturnAddress())); } catch { return; }
  withLink(mc, (l) => l.send({ t: 'mb-put', to: c.peerFp, id: mailbox.newDepositId(), blob }));
}
// One sealed item fetched from our mailbox. Returns true when it can be
// acknowledged (handled, or never readable).
function onMailboxItem(item) {
  let opened, p;
  try {
    opened = mailbox.open({ recipientPrivRaw: myIdentity.privRaw, recipientPubRaw: myIdentity.pubRaw, blob: Buffer.from(String(item.blob || ''), 'base64') });
    p = JSON.parse(opened.plaintext.toString('utf8'));
  } catch { return true; }
  if (!p || typeof p !== 'object') return true;
  const fp = noise.fingerprintRaw(opened.senderPubRaw);
  if (fp === myIdentity.fp) return true;
  const reply = p.reply && typeof p.reply === 'object' ? p.reply : null;
  // The sender is its key (the seal proves it). The address it names is its
  // word only: a new key is filed as "mbox:<fp>", never under that address,
  // which may be a contact the operator wrote to.
  let c = contactByKey(fp);
  if (!c) {
    c = newStranger('mbox:' + fp);
    if (!c) return false;
    c.peerFp = fp;
  }
  c.peerPub = opened.senderPubRaw.toString('base64');
  if (reply && Number.isInteger(reply.port) && reply.port > 0 && reply.port < 65536) c.port = reply.port;
  // its onion: a way back through Tor, where the pinned key must answer
  if (reply && validOnion(reply.host)) c.onion = reply.host;
  const mbx = cleanMailboxes(p.mbx); if (mbx.length) c.mailboxes = mbx;
  if (social.isPub(p.sk) && !c.signPub && social.checkBinding(p.sk, p.skp, fp)) { c.signPub = p.sk; c.skp = p.skp; }
  if (!c.nick && typeof p.nick === 'string') c.nick = cleanStr(p.nick, 60);
  if (p.k === 'msg') {
    const id = typeof p.id === 'string' && MSG_ID.test(p.id) ? p.id : null;
    const text = typeof p.text === 'string' ? p.text.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, 4000) : '';
    if (!id || !text) return true;
    c.established = true; c.lastSeen = Date.now();
    if (!findMsg(c, id)) {
      const now = Date.now();
      const ts = Number.isFinite(p.ts) && p.ts > now - 30 * 864e5 && p.ts < now + 5 * 60000 ? p.ts : now;
      const rec = { id, from: 'them', ts, viaMailbox: true };
      storeText(rec, text); c.unread++; pushMsg(c, rec);
      log(`msg from ${c.nick || c.host} [${fp.slice(0, 12)}...] via a mailbox`);
      broadcastUi({ type: 'chat.recv', host: c.host, msg: publicMsg(rec), unread: c.unread });
    }
    // tell the sender: through their mailbox if they have one, and directly if they answer
    depositReceipt(c, [id]);
    if (dialTargets(c).length) withLink(c, (l) => l.send({ t: 'ack', id }));
  } else if (p.k === 'receipt' && Array.isArray(p.ids)) {
    for (const id of p.ids.slice(0, 50)) {
      const rec = typeof id === 'string' ? findMsg(c, id) : null;
      if (rec && rec.from === 'me' && rec.status !== 'delivered') {
        rec.status = 'delivered'; delete rec.error; delete rec.nextTry; outText.delete(rec.id);
        broadcastUi({ type: 'chat.status', host: c.host, id: rec.id, status: 'delivered' });
      }
    }
    c.established = true; c.lastSeen = Date.now();
  }
  save();
  broadcastUi({ type: 'contact', contact: uiContact(c) });
  return true;
}
function mailboxTick() {
  for (const mb of state.myMailboxes) { const c = mailboxContact(mb); if (c) pokeMailbox(c); }
  if (mbStore) { const r = mbStore.prune(Date.now()); if (r.items || r.recipients) saveMailbox(); }
  for (const [room, j] of pendingJoins) {
    if (Date.now() - j.at < 120000) continue;
    pendingJoins.delete(room);
    broadcastUi({ type: 'room.error', room, error: 'the person who invited you did not answer; try again when they are online' });
  }
}

/* ---- the frames ---------------------------------------------------------- */
const SOCIAL_FRAMES = {
  'feed-req'(link, c, m) {
    const since = Number.isFinite(m.since) ? m.since : 0;
    const follows = followSet();
    const out = feedStore.postsSince(since, (p) => p.via === null || (p.hops <= 1 && follows.has(p.o.a)), 100);
    sendPosts(link, out);
  },
  'posts'(link, c, m) {
    if (!Array.isArray(m.items)) return;
    // Each post costs a signature check: one link gets LINK_MAX_POSTS looked at.
    if (link.postsIn >= LINK_MAX_POSTS) return;
    const follows = followSet();              // once per frame, not once per post
    const fromTrusted = trusted(c);
    let added = 0;
    for (const it of m.items.slice(0, 100)) {
      if ((link.postsIn = (link.postsIn || 0) + 1) > LINK_MAX_POSTS) break;
      if (!it || typeof it !== 'object') continue;
      const h = Number.isInteger(it.h) && it.h >= 0 ? it.h : 9;
      if (h + 1 > 2) continue;
      // only someone the operator added or wrote to, with a two-way exchange,
      // may pass on other people's posts; anyone else only its own
      if (!fromTrusted && (!it.o || !c.signPub || it.o.a !== c.signPub)) continue;
      // the people we follow are the last to go when the store is full
      const r = feedStore.addPost(it.o, { via: link.peerFp, hops: h + 1, keepAuthors: follows });
      if (r.status === 'new') { added++; broadcastUi({ type: 'post', post: uiPost({ id: r.id, o: it.o, via: link.peerFp, hops: h + 1 }) }); }
    }
    c.feedAt = Date.now();
    if (added) { saveSocial(); save(); }
    // pass new posts by people we follow straight on over links that are
    // open now (no dialling); everyone else pulls them on their next link
    const fresh = added ? feedStore.postsSince(Date.now() - 60e3, (p) => p.via === link.peerFp && p.hops <= 1 && follows.has(p.o.a), 25) : [];
    if (fresh.length) for (const l of links.values()) {
      if (l === link || l.closed || !l.peerHello || !l.contact || !hasCap(l.contact, 'social1') || !trusted(l.contact)) continue;
      sendPosts(l, fresh);
    }
  },
  'room-req'(link, c, m) {
    const r = typeof m.room === 'string' ? feedStore.room(m.room) : null;
    if (!r || !r.joined) { link.send({ t: 'room-err', room: typeof m.room === 'string' ? m.room.slice(0, 40) : null, error: 'unknown room' }); return; }
    if (m.join && typeof m.join === 'object') {
      // c.signPub is proven (applyHello): the join must be signed by this link's own signing key
      if (!c.signPub || m.join.a !== c.signPub || m.join.room !== r.def.room) { link.send({ t: 'room-err', room: r.def.room, error: 'that join is not signed by you' }); return; }
      const res = feedStore.addMember(m.join);
      if (res.status === 'rejected') { link.send({ t: 'room-err', room: r.def.room, error: res.error }); return; }
      if (res.status !== 'dup') { saveSocial(); fanOutRoom(r, [m.join]); broadcastUi({ type: 'room', room: uiRoom(r) }); }
    }
    const me = c.signPub && r.members.get(c.signPub);
    if (!me || me.left) { link.send({ t: 'room-err', room: r.def.room, error: 'not a member' }); return; }
    // room-state with as many members as fit beside the definition, the rest
    // (and the history) as room-items, which take member entries too
    const parts = batches([...r.members.values()].slice(0, 100), 100, 512 + Buffer.byteLength(JSON.stringify(r.def)));
    link.send({ t: 'room-state', def: r.def, members: parts[0] || [] });
    const since = Number.isFinite(m.since) ? m.since : 0;
    const msgs = feedStore.roomMsgs(r.def.room, { since, limit: 200 }).map((x) => x.o);
    sendRoomItems(link, r.def.room, parts.slice(1).flat().concat(msgs));
  },
  'room-state'(link, c, m) {
    const def = m.def;
    if (!def || typeof def !== 'object' || typeof def.room !== 'string') return;
    const joining = pendingJoins.has(def.room), have = feedStore.room(def.room);
    if (!joining && !(have && have.joined)) return;              // nobody asked for this room
    const res = feedStore.addRoom(def, { joined: true });
    if (res.status === 'rejected') { broadcastUi({ type: 'room.error', room: def.room, error: res.error }); return; }
    if (Array.isArray(m.members)) for (const x of m.members.slice(0, 100)) if (x && x.room === def.room) feedStore.addMember(x);
    if (joining) {
      pendingJoins.delete(def.room);
      const mine = myMember(def.room);
      feedStore.addMember(mine);
      fanOutRoom(feedStore.room(def.room), [mine]);
      log(`joined room "${def.name}"`);
    }
    saveSocial();
    broadcastUi({ type: 'room', room: uiRoom(feedStore.room(def.room)) });
  },
  'room-items'(link, c, m) {
    const r = typeof m.room === 'string' ? feedStore.room(m.room) : null;
    if (!r || !r.joined || !Array.isArray(m.items)) return;
    let changed = false;
    for (const it of m.items.slice(0, 50)) {
      if (!it || typeof it !== 'object' || it.room !== r.def.room) continue;
      const res = it.k === 'member' ? feedStore.addMember(it) : it.k === 'roommsg' ? feedStore.addRoomMsg(it, { via: link.peerFp }) : { status: 'rejected' };
      if (res.status === 'new' || res.status === 'updated') changed = true;
    }
    (c.roomAt || (c.roomAt = {}))[r.def.room] = Date.now();
    if (changed) { saveSocial(); save(); broadcastUi({ type: 'room', room: uiRoom(r) }); }
  },
  'room-err'(link, c, m) {
    if (typeof m.room === 'string' && pendingJoins.has(m.room)) {
      pendingJoins.delete(m.room);
      broadcastUi({ type: 'room.error', room: m.room, error: cleanStr(m.error, 120) || 'refused' });
    }
  },
  // Introductions go only to a contact the operator added or wrote to, with
  // a two-way exchange, and name only such contacts: one unsolicited message
  // must not let a stranger list the addresses and keys of everyone we know.
  'who-req'(link, c) {
    if (!discoverable() || !c.discoverable || !trusted(c)) { link.send({ t: 'who', items: [] }); return; }
    const items = [];
    for (const x of Object.values(state.contacts)) {
      if (x === c || !trusted(x) || !x.discoverable || !x.peerFp || items.length >= 100) continue;
      const host = x.onion || (!isPlaceholder(x.host) && !isLoopback(x.host) ? x.host : null);
      if (!host) continue;
      items.push({ nick: x.nick || '', host, port: x.port || 8788, fp: x.peerFp, sk: x.signPub || undefined, skp: x.signPub ? x.skp : undefined });
    }
    const parts = batches(items, 100);
    if (!parts.length) parts.push([]);
    parts.forEach((b, i) => link.send({ t: 'who', items: b, more: i < parts.length - 1 || undefined }));
  },
  // Taken only as the answer to our who-req on this link (syncWith asks
  // trusted contacts only), 100 entries per answer. An entry another
  // introducer gave is never rewritten: a second introducer that agrees is
  // added to "via", one that names another address or key is ignored.
  'who'(link, c, m) {
    if (!link.whoAsked || !trusted(c)) return;
    if (m.more !== true) link.whoAsked = false;
    c.whoAt = Date.now();
    if (!Array.isArray(m.items)) return;
    const via = c.nick || c.host;
    for (const it of m.items.slice(0, 100)) {
      if (++link.whoTaken > 100) { link.whoAsked = false; break; }
      if (!it || typeof it !== 'object' || !FP_RE.test(it.fp) || it.fp === myIdentity.fp || it.fp === link.peerFp) continue;
      if (Object.values(state.contacts).some((x) => x.peerFp === it.fp && !x.hidden && !x.inbound)) continue;
      const host = cleanStr(it.host, 255), port = Number(it.port);
      if (!peerHostOk(host) || !(Number.isInteger(port) && port > 0 && port < 65536)) continue;
      // its signing key, only with the holder's proof for that fingerprint
      const sk = social.isPub(it.sk) && social.checkBinding(it.sk, it.skp, it.fp) ? it.sk : null;
      const have = state.introductions[it.fp];
      const owners = have ? (Array.isArray(have.viaFp) ? have.viaFp : ['']) : [];
      if (owners.some((x) => x !== link.peerFp)) {
        if (have.host === host && have.port === port && (have.sk || null) === sk && !owners.includes(link.peerFp)) {
          have.via = [...(have.via || []), via].slice(0, 5); have.viaFp = [...owners, link.peerFp].slice(0, 5);
        }
        continue;
      }
      state.introductions[it.fp] = { fp: it.fp, nick: cleanStr(it.nick, 60), host, port, sk, skp: sk ? it.skp : null,
        via: [via], viaFp: [link.peerFp], at: Date.now() };
    }
    const all = Object.values(state.introductions).sort((a, b) => b.at - a.at);
    for (const old of all.slice(300)) delete state.introductions[old.fp];
    save();
    broadcastUi({ type: 'introductions', items: Object.values(state.introductions) });
  },
  // Only for a contact the operator added or wrote to, with a two-way
  // exchange: otherwise 256 throwaway keys would take every slot.
  'mb-reg'(link, c) {
    if (!mailboxServing()) { link.send({ t: 'mb-reg-err', error: 'this daemon does not run a mailbox' }); return; }
    if (!trusted(c)) { link.send({ t: 'mb-reg-err', error: 'this mailbox holds mail only for contacts its operator added or wrote to' }); return; }
    if (openMailboxStore().register(link.peerFp, Date.now())) { saveMailbox(); link.send({ t: 'mb-reg-ok' }); }
    else link.send({ t: 'mb-reg-err', error: 'this mailbox is full' });
  },
  'mb-reg-ok'(link) { const mb = state.myMailboxes.find((x) => x.fp === link.peerFp); if (mb && !mb.ok) { mb.ok = true; delete mb.error; save(); broadcastState(); } },
  'mb-reg-err'(link, c, m) { const mb = state.myMailboxes.find((x) => x.fp === link.peerFp); if (mb) { mb.ok = false; mb.error = cleanStr(m.error, 120) || 'refused'; save(); broadcastState(); } },
  'mb-put'(link, c, m) {
    const id = typeof m.id === 'string' ? m.id : '';
    if (!mailboxServing()) { link.send({ t: 'mb-put-err', id, error: 'this daemon does not run a mailbox' }); return; }
    if ((link.puts = (link.puts || 0) + 1) > 50) { link.send({ t: 'mb-put-err', id, error: 'too many at once' }); return; }
    const blob = Buffer.from(typeof m.blob === 'string' ? m.blob : '', 'base64');
    const r = !FP_RE.test(m.to) ? { ok: false, error: 'bad recipient' } : blob.length > MB_MAX_BLOB ? { ok: false, error: 'too large' }
      : openMailboxStore().deposit(m.to, { id, blob }, Date.now());
    if (r.ok) { saveMailbox(); link.send({ t: 'mb-put-ok', id }); } else link.send({ t: 'mb-put-err', id, error: r.error });
  },
  'mb-put-ok'(link, c, m) {
    const d = link.deposits && link.deposits.get(m.id);
    if (!d) return;
    link.deposits.delete(m.id);
    if (d.m.status === 'delivered') return;
    d.m.status = 'held'; d.m.heldAt = c.nick || c.host; d.m.error = null; save();
    broadcastUi({ type: 'chat.status', host: d.c.host, id: d.m.id, status: 'held', error: null, heldAt: d.m.heldAt });
  },
  'mb-put-err'(link, c, m) {
    const d = link.deposits && link.deposits.get(m.id);
    if (d) { link.deposits.delete(m.id); log(`mailbox ${c.nick || c.host} refused mail for ${d.c.nick || d.c.host}: ${cleanStr(m.error, 120)}`); }
  },
  // Oldest first, up to MB_REPLY_BYTES per answer, in frames that fit
  // (a 16 KiB item is some 22 KB of base64, so four of them overflowed one
  // Noise frame and jammed the mailbox for good). "more" on the last frame:
  // the recipient acknowledges and asks again.
  'mb-get'(link, c) {
    if (!mailboxServing() || !openMailboxStore().isRegistered(link.peerFp)) { link.send({ t: 'mb-items', items: [] }); return; }
    openMailboxStore().register(link.peerFp, Date.now());       // a fetch keeps the registration alive
    const held = mbStore.fetch(link.peerFp, 51), items = [];
    let bytes = 0;
    for (const x of held.slice(0, 50)) {
      const it = { id: x.id, blob: Buffer.from(x.blob).toString('base64') };
      if (items.length && bytes + it.blob.length > MB_REPLY_BYTES) break;
      items.push(it); bytes += it.blob.length;
    }
    const parts = batches(items, 10);
    if (!parts.length) parts.push([]);
    const more = held.length > items.length;
    parts.forEach((b, i) => link.send({ t: 'mb-items', items: b, more: more && i === parts.length - 1 ? true : undefined }));
  },
  'mb-items'(link, c, m) {
    if (!state.myMailboxes.some((mb) => mb.fp === link.peerFp) || !Array.isArray(m.items)) return;
    const done = [];
    for (const it of m.items.slice(0, 10)) if (it && typeof it.id === 'string' && onMailboxItem(it)) done.push(it.id);
    if (done.length) link.send({ t: 'mb-ack', ids: done });
    // more waiting, and this batch moved: fetch the next (the mailbox answers once the last has gone out)
    if (m.more === true && done.length) link.send({ t: 'mb-get' });
  },
  'mb-ack'(link, c, m) {
    if (!mbStore || !Array.isArray(m.ids)) return;
    if (mbStore.ack(link.peerFp, m.ids.filter((x) => typeof x === 'string').slice(0, 100))) saveMailbox();
  },
};

/* ---- how to reach a contact -------------------------------------------- */
// Its address, then its onion. A loopback address is Tor handing a peer
// over locally, so with an onion known the onion is the way back; tor:,
// mbox: and peer: hosts are placeholders for peers we only know a key for.
// An address that is not the contact's own key is someone's claim (the
// peer's hello or mail, a member entry): it is dialled only for a pinned
// key, which must answer there.
function dialTargets(c) {
  const out = [];
  if (!isPlaceholder(c.host) && !(isLoopback(c.host) && c.onion)) out.push(c.host);
  if (c.peerFp && c.addr && !out.includes(c.addr)) out.push(c.addr);
  if (c.onion && !out.includes(c.onion) && (c.onion === c.host || c.peerFp)) out.push(c.onion);
  return out;
}

/* ---- "same onion": proof that an operator runs the node ------------------
   We dialled this onion's NodeSignal port and it answered with the key we
   pinned, and the same onion is a Bitcoin node: it is in our node's peer
   list, or it answered the :8333 handshake. Only whoever holds that onion's
   key can run both, so this operator demonstrably runs that node. */
const hostOfAddr = (a) => { const s2 = String(a || ''); if (s2.startsWith('[')) return s2.slice(1, s2.indexOf(']')); const i = s2.lastIndexOf(':'); return i > 0 && s2.indexOf(':') === i ? s2.slice(0, i) : s2; };
function noteSameOnion(c, onion) {
  const asPeer = rpc.ok && rpc.peers.some((p) => hostOfAddr(p.addr) === onion);
  const identified = !!(c.peerInfo && typeof c.peerInfo.source === 'string' && c.peerInfo.source.startsWith('p2p') && c.host === onion);
  if (!asPeer && !identified) return;
  const had = !!c.nodeProof;
  c.nodeProof = { onion, at: Date.now(), how: asPeer ? 'a peer of your node' : 'answered as a Bitcoin node on :8333' };
  save();
  if (!had) log(`same onion: ${c.nick || c.host} runs the Bitcoin node at ${onion}`);
}

/* ---- share links -------------------------------------------------------- */
// nodesignal:<host>?port=<p>&fp=<32 hex>&nick=<name>
function parseContactLink(s) {
  const m = /^nodesignal:(?:\/\/)?([^?#\s]+)\?([^#\s]*)$/.exec(String(s || '').trim());
  if (!m) throw new Error('not a NodeSignal contact link');
  const q = new URLSearchParams(m[2]);
  const host = m[1].replace(/^\[|\]$/g, ''), port = Number(q.get('port') || 8788), fp = (q.get('fp') || '').toLowerCase();
  if (!/^[A-Za-z0-9.:-]{1,255}$/.test(host)) throw new Error('the link has no usable address');
  if (!FP_RE.test(fp)) throw new Error('the link has no valid fingerprint');
  if (!(Number.isInteger(port) && port > 0 && port < 65536)) throw new Error('the link has a bad port');
  return { host, port, fp, nick: cleanStr(q.get('nick') || '', 60) };
}
// What an identity backup holds: backup.buildPayload (the CLI uses it too).
const backupPayload = () => backup.buildPayload(state, feedStore.toJSON(), { nick: CFG.nick });
function shareLink() {
  const reach = myReach();
  if (!reach) return null;
  const q = new URLSearchParams({ port: String(reach.port), fp: myIdentity.fp, nick: CFG.nick });
  return `nodesignal:${reach.host}?${q}`;
}

/* ---- delivery: send now, or hold and retry ------------------------------ */
const RETRY_MS = [30e3, 60e3, 120e3, 300e3, 600e3, 1800e3, 3600e3];
const GIVE_UP_MS = { established: 7 * 864e5, unknown: 864e5 };
// "held" = waiting at the recipient's mailbox; direct delivery is still tried.
const deliverable = (m) => m.from === 'me' && (m.status === 'sending' || m.status === 'pending' || m.status === 'held');
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
  if (m.heldAt) {
    // Waiting at a mailbox: keep trying directly for a while, never "fail".
    if (Date.now() - m.ts > limit) m.directGaveUp = true;
    m.status = 'held'; m.error = null;
    m.nextTry = Date.now() + RETRY_MS[Math.min(RETRY_MS.length - 1, m.attempts - 1)] * CFG.retryScale;
    save();
    broadcastUi({ type: 'chat.status', host: c.host, id: m.id, status: 'held', heldAt: m.heldAt, nextTry: m.nextTry });
    return;
  }
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
  const port = c.port || CFG.peerPort;
  // its address first, then its onion (see dialTargets)
  const targets = dialTargets(c);
  dialing.add(c.host); lastDial.set(c.host, Date.now());
  let i = 0;
  const next = (lastErr) => {
    if (i >= targets.length) return done(lastErr || new Error('no address to call: it reached us through Tor or a mailbox, and answers go back that way'));
    const host = targets[i++];
    const first = c.proto === 2 ? 2 : 3;
    attemptDial(c, host, port, first, (err, link) => {
      if (err && err.beforeMsg2 && first === 3 && c.proto !== 3)
        return attemptDial(c, host, port, 2, (err2, link2) => after(err2 ? err : null, link2));
      after(err, link);
    });
    function after(err, link) { if (link || err.self || err.mismatch) return done(err, link); next(err); }
  };
  next(null);
  function done(err, link) {
    dialing.delete(c.host);
    if (link) return;
    linkTasks.delete(c.host);
    const reason = err.code === 'ECONNREFUSED' ? `refused: nothing listening on ${c.host}:${port}` : (err.message || String(err));
    // Retrying cannot help: the address leads back to this daemon.
    if (err.self) {
      for (const m of c.msgs) if (deliverable(m)) failMsg(c, m, reason);
      log(`deliver to ${c.host}: ${reason}`);
      c.lastFailAt = Date.now();
      broadcastUi({ type: 'contact', contact: uiContact(c) });
      return;
    }
    // A check-in that finds nobody home is not news; a send is.
    const now = Date.now();
    for (const m of c.msgs) if (deliverable(m) && (m.status === 'sending' || (m.nextTry || 0) <= now)) deferMsg(c, m, reason);
    // Still unreachable: leave it at the contact's mailbox, if it has one.
    // Not after a key mismatch: the key the mail would be sealed to is the one in question.
    if (!err.mismatch) for (const m of c.msgs) if (deliverable(m) && !m.heldAt) depositMessage(c, m);
    if (why !== 'checkin' && why !== 'task') log(`deliver to ${c.host}: ${reason}`);
    // A failed dial is fresher news than the last hello: stop calling it online.
    c.lastFailAt = Date.now();
    broadcastUi({ type: 'contact', contact: uiContact(c) });
  }
}
function attemptDial(c, host, port, proto, cb) {
  let hs = null, link = null, settled = false;
  const settle = (err, l) => { if (settled) return; settled = true; clearTimeout(timer); cb(err, l); };
  // an onion circuit can take half a minute to build
  const timer = setTimeout(() => { sock && sock.destroy(); settle(new Error(`timeout: is nodesignald running and reachable on ${host}:${port}?`)); }, validOnion(host) ? 45000 : 9000);
  const sock = dial(host, port, (s) => {
    s.setNoDelay(true);
    frameStream(s, (frame) => {
      if (link) return link.onFrame(frame);
      let res, session;
      if (proto === 3) { res = noise.v3.initFinish(hs, frame); session = res.session; }
      else { res = noise.legacy.initFinish(hs, frame); session = noise.legacy.makeSession(res.tx, res.rx); }
      if (res.peerFp === myIdentity.fp) {
        s.destroy();
        const e = new Error(SELF_ERROR); e.self = true; return settle(e);
      }
      // A second address (an onion or address someone named for it) that
      // answers with another key was never its address: forget it, and
      // raise no key-change alarm.
      if (host !== c.host && c.peerFp && res.peerFp !== c.peerFp) {
        s.destroy();
        if (c.onion === host || c.addr === host) {
          if (c.onion === host) delete c.onion; else delete c.addr;
          save(); log(`${c.nick || c.host}: ${host}, named for it, answered with another key; forgotten`);
        }
        return settle(new Error(`${host} answered with a different key than ${c.nick || c.host} has`));
      }
      if (!tofuCheck(c, res.peerFp)) {
        s.destroy();
        const e = new Error('identity mismatch: this address presented a different key than the one pinned. Review it in the console.');
        e.mismatch = true; return settle(e);
      }
      sendFrame(s, res.msg3);
      tofuRecord(c, res.peerFp);
      c.proto = proto;
      const pub = pubRawB64(res.peerPub);
      if (pub) c.peerPub = pub;
      if (validOnion(host)) noteSameOnion(c, host);
      link = openLink(s, { initiator: true, addr: c.host, peerFp: res.peerFp, proto, session });
      link.peerPub = pub;
      bindLink(link, c);
      link.send(helloPayload()); link.helloSent = true;
      flushPending(c, link); link.touch();
      settle(null, link);
    });
    s.once('close', () => { if (!link) { const e = new Error(`connection closed during the handshake with ${host}:${port}`); e.beforeMsg2 = true; settle(e); } });
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
    if (res.peerFp === myIdentity.fp) { sock.destroy(); return; }   // ourselves
    const c = contactFor(addr, res.peerFp);
    if (c && !tofuCheck(c, res.peerFp)) { sock.destroy(); return; }
    link = openLink(sock, { initiator: false, addr, peerFp: res.peerFp, proto, session });
    link.peerPub = pubRawB64(res.peerPub);
    if (c) {
      tofuRecord(c, res.peerFp);
      if ((proto === 3 && c.proto !== 3) || (link.peerPub && c.peerPub !== link.peerPub)) { if (proto === 3) c.proto = 3; if (link.peerPub) c.peerPub = link.peerPub; save(); }
      bindLink(link, c);
    }
  });
}

let peerActive = 0;
function onPeerSocket(sock) {
  const host = normIp(sock.remoteAddress);
  // --- DDoS / disk-exhaustion defenses -----------------------------------
  //   1. hard cap on concurrent inbound connections
  //   2. per-source-block (IPv4 /32, IPv6 /64) rate limit on new connections
  //   3. NO persisted state until a handshake AND a hello prove a real peer
  if (peerActive >= MAX_CONNS) { sock.destroy(); return; }
  if (!rateOk(host)) { sock.destroy(); return; }
  peerActive++;
  sock.once('close', () => { peerActive--; });
  // Unfinished handshakes and idle sessions must not tie up a slot forever.
  sock.setTimeout(30000, () => sock.destroy());
  sock.on('error', () => { });
  serveSecure(sock, host);
}
const peerServer = net.createServer(onPeerSocket);
// Bound to the Tailscale address, the peer port would not answer on
// 127.0.0.1, which is where a Tor hidden service forwards
// (HiddenServicePort 8788 127.0.0.1:8788). Loopback exposes nothing more.
// The same holds for NodeSignal's own onion service (ADD_ONION forwards to
// 127.0.0.1) whenever the peer port is bound to one specific address.
const peerLoopback = !['0.0.0.0', '::', '127.0.0.1'].includes(PEER_BIND) && (PEER_BIND === TS_ADDR || CFG.onion !== 'off') ? net.createServer(onPeerSocket) : null;

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
      if (!deliverable(m) || m.directGaveUp) continue;
      const limit = c.established ? GIVE_UP_MS.established : GIVE_UP_MS.unknown;
      if (now - m.ts > limit && !m.heldAt) { failMsg(c, m, `gave up after ${Math.round(limit / 864e5)} day(s): ${m.error || 'never reached'}`); continue; }
      if ((m.nextTry || 0) <= now && textOf(m) != null) due = true;
    }
    if (due) connectTo(c, 'retry');
  }
}
function checkinTick() {
  if (!(CFG.checkinMs > 0)) return;
  const now = Date.now();
  for (const c of Object.values(state.contacts)) {
    // only contacts the operator added or wrote to: a stranger's one message
    // does not earn it a call from us every few minutes
    if (!trusted(c) || links.has(c.host) || dialing.has(c.host)) continue;
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
    error: m.error || null, nextTry: m.nextTry || null, attempts: m.attempts || 0, heldAt: m.heldAt || null, viaMailbox: !!m.viaMailbox };
}
const uiContact = (c) => ({ host: c.host, port: c.port || CFG.peerPort, nick: c.nick,
  unread: c.unread, lastSeen: c.lastSeen, peerInfo: c.peerInfo,
  established: !!c.established,
  peerFp: c.peerFp || null,
  pendingFp: c.pendingFp || null,
  proto: c.proto || null,
  lastAddr: c.lastAddr || null,
  online: !!(c.established && c.lastSeen && (Date.now() - c.lastSeen < 5 * 60 * 1000) && !((c.lastFailAt || 0) > c.lastSeen)),
  // 1.4
  onion: c.onion || null, caps: c.caps || [], signPub: c.signPub || null,
  signId: c.signPub ? social.keyId(Buffer.from(c.signPub, 'base64')) : null,
  hidden: !!(c.hidden && !c.msgs.length), pinnedBy: c.pinnedBy || null, nodeProof: c.nodeProof || null,
  servesMailbox: !!c.servesMailbox, hasMailbox: !!(c.mailboxes && c.mailboxes.length), discoverable: !!c.discoverable,
  following: !!(c.signPub && followSet().has(c.signPub)),
  msgs: c.msgs.slice(-200).map(publicMsg) });
const fullState = () => ({
  type: 'state',
  daemon: { nick: CFG.nick, ua: UA, peerPort: CFG.peerPort, webPort: CFG.webPort, proto: PROTO, instance: INSTANCE,
    fingerprint: myIdentity.fp, secure: true,
    vault: { set: vaultOn(), unlocked: unlocked() },
    portMapping: CFG.portMapping ? (portmapStatus || { state: 'mapping' }) : null,
    // 1.4
    onion: myOnion, onionMode: CFG.onion, tor: torStatus, reach: myReach(), share: shareLink(),
    signKey: mySign.pub, signId: mySign.id, discoverable: discoverable(), mailbox: mailboxServing(),
    mailboxStats: mbStore ? mbStore.stats() : null,
    myMailboxes: state.myMailboxes.map((mb) => ({ host: mb.host, port: mb.port, fp: mb.fp, ok: !!mb.ok, error: mb.error || null, nick: nameForFp(mb.fp) })),
    sameOnion: !!(myOnion && rpc.ok && rpc.self && Array.isArray(rpc.self.onions) && rpc.self.onions.includes(myOnion)),
    nodeOnions: rpc.ok && rpc.self ? rpc.self.onions || [] : [],
    update: updateInfo },
  node: rpc.ok ? { self: rpc.self, peers: rpc.peers } : { self: null, peers: [], error: rpc.error, diag: rpcDiag },
  contacts: Object.values(state.contacts).map(uiContact),
  feed: feedStore.feed({ limit: 200 }).map(uiPost),
  follows: [...followSet()],
  rooms: feedStore.roomList().filter((r) => r.joined).map(uiRoom),
  introductions: Object.values(state.introductions),
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
    if (i <= 0) continue;
    // decodeURIComponent throws on a malformed escape; on the WebSocket
    // upgrade path that exception was uncaught and stopped the daemon.
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { }
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
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NodeSignal: sign in</title><style>
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
   no npm install, which removes 66 packages from a machine running a Bitcoin
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
    onion: myOnion,
    sameOnion: !!(myOnion && rpc.ok && rpc.self && Array.isArray(rpc.self.onions) && rpc.self.onions.includes(myOnion)),
    update: updateInfo && updateInfo.state === 'available' ? { version: updateInfo.version, verified: !!updateInfo.verified } : null,
    uptime: Math.round(process.uptime()),
  };
}
const wantsHtml = (req) => String(req.headers.accept || '').includes('text/html');

/* ---- web front door ------------------------------------------------------
   Three checks on every HTTP request and WebSocket upgrade, plus a token on
   every state-changing action:
     · Host must be localhost:<web-port> or 127.0.0.1:<web-port>. A web page
       that points its own DNS name at 127.0.0.1 (DNS rebinding) still sends
       its own name as Host, so it is refused.
     · Origin, when present, must be http://localhost:<port> or
       http://127.0.0.1:<port>. Browsers always send it on WebSocket upgrades
       and cross-site requests, so another site cannot drive the console.
     · ACTION_TOKEN is random per launch and only ever written into the page
       this daemon serves. Every WebSocket message that changes something
       must carry it; a page from anywhere else cannot read it. */
const ACTION_TOKEN = crypto.randomBytes(32).toString('base64url');
const INSTANCE = crypto.randomBytes(8).toString('hex');      // not secret: lets a stale page notice a restart
const ALLOWED_HOSTS = new Set([`localhost:${CFG.webPort}`, `127.0.0.1:${CFG.webPort}`]);
const ALLOWED_ORIGINS = new Set([`http://localhost:${CFG.webPort}`, `http://127.0.0.1:${CFG.webPort}`]);
const hostOk = (req) => ALLOWED_HOSTS.has(String(req.headers.host || '').toLowerCase());
const originOk = (req) => req.headers.origin === undefined || ALLOWED_ORIGINS.has(String(req.headers.origin).toLowerCase());
// The console is one self-contained page (its fonts included), so the policy
// lets it fetch from nothing but this daemon: if a peer's text ever slipped
// past esc(), the injected code could not load more code or fetch from or
// post to another server. It could still navigate the page away or use the
// action token through /ws, so escaping stays the real defence. Inline script
// stays allowed because the page is one file with onclick handlers.
const CSP = ["default-src 'none'", "script-src 'unsafe-inline'", "style-src 'unsafe-inline'", 'font-src data:', 'img-src data:',
  `connect-src 'self' ws://localhost:${CFG.webPort} ws://127.0.0.1:${CFG.webPort}`, "base-uri 'none'", "form-action 'self'",
  "frame-ancestors 'none'"].join('; ');
const SECURITY_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY', 'Content-Security-Policy': CSP };
function sendConsole(res, file) {
  // The token goes into the served page only: never a URL, a cookie or a log.
  const meta = `<meta name="ns-action-token" content="${ACTION_TOKEN}">\n<meta name="ns-instance" content="${INSTANCE}">\n`;
  let html = fs.readFileSync(file, 'utf8');
  html = /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (h) => h + '\n' + meta) : meta + html;
  W.sendHtml(res, html, 200, SECURITY_HEADERS);
}
function redirect(res, to) { res.writeHead(302, { Location: to, 'Content-Length': 0 }); res.end(); }

async function handleRequest(req, res) {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { }
  const method = req.method || 'GET';

  if (!hostOk(req)) {
    W.sendText(res, `NodeSignal only answers as localhost:${CFG.webPort} or 127.0.0.1:${CFG.webPort}.`, 421);
    return;
  }
  if (!originOk(req)) { W.sendText(res, 'cross-origin request refused', 403); return; }

  // --- public routes (no auth) ---
  if (pathname === '/health') return W.sendJson(res, healthPayload());

  if (pathname === '/login') {
    if (!AUTH_ON) return redirect(res, '/');
    if (method === 'GET') return W.sendHtml(res, LOGIN_PAGE.replace('__ERR__', ''), 200, SECURITY_HEADERS);
    if (method === 'POST') {
      const body = await W.readForm(req);
      if (timingSafeEq(body.token || '', CFG.webToken)) {
        return redirect2(res, '/',
          `ns_session=${newSession()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_MS / 1000)}`);
      }
      return W.sendHtml(res, LOGIN_PAGE.replace('__ERR__', 'wrong token'), 401, SECURITY_HEADERS);
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
      if (fs.existsSync(f)) return sendConsole(res, f);
    }
    return W.sendText(res, 'No interface file found in ' + CFG.webRoot +
      '\nExpected nodesignal.html (or nodesignal-demo.html) next to nodesignald.js.', 500);
  }

  // Nothing else is served from the web root. The console is one
  // self-contained page, and its folder is the program folder: a from-source
  // install keeps nodesignal-config.json (the RPC password, the web token)
  // there, and --data may point there too (state.json holds the private
  // identity key). So there is no static file fallback at all.
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
const wss = new W.WSServer();
const refuse = (socket, status) => { try { socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); } catch { } socket.destroy(); };
const onUpgrade = (req, socket, head) => {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://x').pathname; } catch { }
  if (pathname !== '/ws') { socket.destroy(); return; }
  if (!hostOk(req)) return refuse(socket, '421 Misdirected Request');
  if (!originOk(req)) return refuse(socket, '403 Forbidden');
  if (!reqAuthed(req)) return refuse(socket, '401 Unauthorized');
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
};
server.on('upgrade', onUpgrade);

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
  // A tab closed mid-write raises EPIPE/ECONNRESET on the socket. Without a
  // listener that 'error' event would be unhandled and stop the whole daemon.
  ws.on('error', () => uiClients.delete(ws));
});
// An address the operator typed: IPv4, IPv6 (brackets stripped, % for a
// zone), hostname or .onion; or a contact's tor:/mbox: key from the console.
function uiHost(v) {
  const h = normIp(cleanStr(v, 255).replace(/^\[|\]$/g, ''));
  if (!h || !/^[A-Za-z0-9.:%-]+$/.test(h) || RESERVED_KEYS.has(h)) throw new Error('not a valid address');
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
const READ_ONLY_OPS = new Set(['hello', 'ping']);
let badTokenLogged = 0;
async function handleUi(m, reply) {
  if (!READ_ONLY_OPS.has(m.type) && !(typeof m.token === 'string' && timingSafeEq(m.token, ACTION_TOKEN))) {
    if (Date.now() - badTokenLogged > 60000) { badTokenLogged = Date.now(); log(`!! refused a "${cleanStr(String(m.type || ''), 40)}" request without this launch's action token`); }
    reply({ type: 'error', op: String(m.type || ''), code: 'bad-token', error: 'refused: missing or stale action token (reload the console)' });
    return;
  }
  switch (m.type) {
    case 'hello': reply(fullState()); return;
    case 'ping': reply({ type: 'pong' }); return;
    case 'contact.add': {
      // From a contact link, the address, port, key and nick all come from it.
      const lk = typeof m.link === 'string' && m.link.trim() ? parseContactLink(m.link) : null;
      const host = uiHost(lk ? lk.host : m.host);
      const fp = lk ? lk.fp : (typeof m.fp === 'string' && m.fp ? m.fp.toLowerCase() : null);
      if (fp && !FP_RE.test(fp)) throw new Error('that fingerprint is not 32 hex characters');
      const existing = state.contacts[host];
      if (fp && existing && existing.peerFp && existing.peerFp !== fp) throw new Error(`${host} is already pinned to a different key; remove it first if this is a new install`);
      // Someone who reached us through Tor (or by mail) under this key: its
      // conversation moves to the address the operator now gives for it.
      const ph = fp && !existing ? Object.values(state.contacts).find((x) => x.peerFp === fp && isPlaceholder(x.host)) : null;
      if (ph) rekeyContact(ph, host);
      const c = contact(host, true);
      delete c.inbound; delete c.hidden; delete c.auto;      // the operator added it
      c.port = uiPort(lk ? lk.port : m.port, c.port || CFG.peerPort);
      const nick = lk ? lk.nick : m.nick;
      if (nick != null && nick !== '') c.nick = cleanStr(String(nick), 60);
      // pinned before the first connection: the key came from the operator,
      // not from whoever answers first
      if (fp && !c.peerFp) { c.peerFp = fp; c.pinnedBy = lk ? 'link' : 'typed'; }
      if (validOnion(host)) c.onion = host;
      save(); broadcastUi({ type: 'contact', contact: uiContact(c) });
      identifyNew(c);                         // P2P identification fires on every add
      return;
    }
    case 'share.get': {
      const link = shareLink();
      let svg = null;
      if (link) { try { svg = qr.toSvg(qr.encode(link, { ecc: 'M' }), { margin: 4 }); } catch (e) { log('qr: ' + e.message); } }
      reply({ type: 'share', link, svg, fp: myIdentity.fp,
        why: link ? null : 'No address to share yet. With Tor installed NodeSignal makes its own onion address; or set public-host in the config to an address that reaches this machine.' });
      return;
    }
    case 'post.create': { const e = createPost(typeof m.text === 'string' ? m.text : ''); reply({ type: 'posted', id: e.id }); return; }
    case 'follow.set': {
      const sk = String(m.sk || '');
      if (!social.isPub(sk) || sk === mySign.pub) throw new Error('not a signing key');
      state.follows = state.follows.filter((x) => x !== sk); state.unfollows = state.unfollows.filter((x) => x !== sk);
      if (m.on) state.follows.push(sk); else state.unfollows.push(sk);
      state.follows = state.follows.slice(-1000); state.unfollows = state.unfollows.slice(-1000);
      save(); broadcastState();
      return;
    }
    case 'room.create': {
      const name = cleanStr(String(m.name || ''), 60);
      if (!name) throw new Error('a room needs a name');
      const def = social.makeRoom(mySign, { name });
      const r = feedStore.addRoom(def, { joined: true });
      if (r.status !== 'new') throw new Error(r.error || 'could not create the room');
      feedStore.addMember(myMember(def.room));
      saveSocial(); log(`room "${name}" created`);
      broadcastUi({ type: 'room', room: uiRoom(feedStore.room(def.room)) });
      reply({ type: 'room.created', room: def.room });
      return;
    }
    case 'room.invite': reply({ type: 'room.invite', room: m.room, link: roomLink(String(m.room || '')) }); return;
    case 'room.join': {
      const lk = parseRoomLink(m.link);
      const have = feedStore.room(lk.room);
      if (have && have.joined) { reply({ type: 'room.joined', room: lk.room }); return; }
      if (lk.fp === myIdentity.fp) throw new Error('that is your own room link');
      const ic = ensureContact({ host: lk.host, port: lk.port, fp: lk.fp }, { operator: true });
      if (!ic) throw new Error(`${lk.host} is pinned to a different key than the link says`);
      pendingJoins.set(lk.room, { at: Date.now(), name: lk.name });
      // the member entry is signed for this room; the inviter checks it is ours
      const join = myMember(lk.room);
      withLink(ic, (l) => l.send({ t: 'room-req', room: lk.room, since: 0, join }));
      reply({ type: 'room.joining', room: lk.room, name: lk.name });
      return;
    }
    case 'room.send': {
      const r = feedStore.room(String(m.room || ''));
      if (!r || !r.joined) throw new Error('not in that room');
      const o = social.makeRoomMsg(mySign, { room: r.def.room, fp: myIdentity.fp, nick: CFG.nick, text: typeof m.text === 'string' ? m.text : '' });
      if (!o.text) return;
      const res = feedStore.addRoomMsg(o);
      if (res.status !== 'new') throw new Error(res.error || 'could not post to the room');
      saveSocial(); fanOutRoom(r, [o]);
      broadcastUi({ type: 'room', room: uiRoom(r) });
      return;
    }
    case 'room.leave': {
      const r = feedStore.room(String(m.room || ''));
      if (!r) return;
      const bye = myMember(r.def.room, true);
      feedStore.addMember(bye); fanOutRoom(r, [bye]);
      feedStore.leaveRoom(r.def.room); saveSocial();
      broadcastState();
      return;
    }
    case 'intro.add': {
      const it = state.introductions[String(m.fp || '')];
      if (!it) throw new Error('no such introduction');
      const c = ensureContact({ host: it.host, port: it.port, fp: it.fp, nick: it.nick, hidden: false }, { operator: true });
      if (!c) throw new Error(`${it.host} is already pinned to a different key`);
      delete c.hidden; delete c.inbound; delete c.auto; c.pinnedBy = 'introduced'; c.introducedBy = it.via;
      if (it.sk && !c.signPub && c.peerFp === it.fp && social.checkBinding(it.sk, it.skp, it.fp)) { c.signPub = it.sk; c.skp = it.skp; }
      delete state.introductions[it.fp]; save();
      identifyNew(c); broadcastState();
      return;
    }
    case 'sync.now': {
      // the console's refresh: sync with every established contact that speaks 1.4
      let n = 0;
      for (const c of Object.values(state.contacts)) {
        if (n >= 50 || !trusted(c) || !hasCap(c, 'social1')) continue;
        n++; withLink(c, (l) => syncWith(l, c, true));
      }
      reply({ type: 'synced', contacts: n });
      return;
    }
    case 'update.check': await checkForUpdate(true); return;
    case 'update.install': await installUpdate(); return;
    case 'intro.dismiss': { delete state.introductions[String(m.fp || '')]; save(); broadcastState(); return; }
    case 'settings.set': {
      const key = String(m.key || ''), val = m.value === true;
      if (!['discoverable', 'mailbox'].includes(key)) throw new Error('unknown setting');
      state.settings[key] = val; save();
      log(`setting ${key}: ${val ? 'on' : 'off'}`);
      if (key === 'mailbox' && val) openMailboxStore();
      rehello(); broadcastState();
      return;
    }
    case 'mailbox.use': {
      const c = Object.values(state.contacts).find((x) => x.peerFp === m.fp);
      if (!c || !c.servesMailbox) throw new Error('that contact does not run a mailbox');
      if (!state.myMailboxes.some((x) => x.fp === c.peerFp)) {
        const host = c.onion || (isPlaceholder(c.host) ? c.addr : null) || c.host;   // an address others can use
        state.myMailboxes = [{ host, port: c.port || 8788, fp: c.peerFp }].concat(state.myMailboxes).slice(0, 2);
      }
      save(); pokeMailbox(c); rehello(); broadcastState();
      return;
    }
    case 'mailbox.stop': { state.myMailboxes = state.myMailboxes.filter((x) => x.fp !== m.fp); save(); rehello(); broadcastState(); return; }
    case 'backup.export': {
      const pass = String(m.passphrase || '');
      const text = await backup.exportBackupAsync(backupPayload(), pass);
      const day = new Date().toISOString().slice(0, 10);
      reply({ type: 'backup', text, filename: `nodesignal-identity-${CFG.nick.replace(/[^A-Za-z0-9_-]/g, '') || 'node'}-${day}.nsbackup` });
      log('identity backup exported');
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
      c.peerFp = c.pendingFp.got; delete c.pendingFp;
      // what belonged to the old key (its public key for sealed mail, its
      // signing key) is learned again from the new one's hello
      delete c.peerPub; delete c.signPub; delete c.skp;
      save();
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
      delete c.inbound; delete c.auto;        // the operator wrote to it
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

/* ------------------------------------------------------------ Tor onion service
   With onion "auto" (the default) NodeSignal asks Tor's control port for
   its own onion service, the way bitcoind's -listenonion does: no torrc
   editing and no port forwarding, behind any NAT. The service's key is kept
   in state.json so the address stays the same. Without a reachable control
   port it simply runs without one and tries again later. */
let torStatus = { state: CFG.onion === 'off' ? 'off' : CFG.onion === 'external' ? (myOnion ? 'external' : 'external, but onion-address is not set') : 'starting' };
let torCtl = null;
function torCandidates() {
  const t = CFG.torControl;
  if (t) {
    if (t.startsWith('/') || /^[A-Za-z]:[\\/]/.test(t)) return [{ path: t }];
    const i = t.lastIndexOf(':');
    return [{ host: (i > 0 ? t.slice(0, i) : '127.0.0.1').replace(/^\[|\]$/g, ''), port: Number(i >= 0 ? t.slice(i + 1) : t) || 9051 }];
  }
  // Linux: only Tor's control socket. /run/tor belongs to root and Tor's own
  // account, so nobody else can stand in for Tor there. A TCP control port can
  // be opened by any local account while Tor is down, and an impostor would be
  // handed the onion key (its cookie "proof" names a file it wrote itself), so
  // TCP is used only when the operator names it with --tor-control. Windows
  // has no control socket, so it keeps the Tor Expert Bundle's TCP ports.
  if (process.platform !== 'win32') return [{ path: '/run/tor/control' }];
  return [{ host: '127.0.0.1', port: 9051 }, { host: '127.0.0.1', port: 9151 }];
}
function startOnion() {
  if (CFG.onion !== 'auto') return;
  let lastDown = '';
  torCtl = torcontrol.startOnionService({
    candidates: torCandidates(), password: CFG.torControlPass || undefined, key: state.onionKey || null,
    virtPort: CFG.peerPort, target: `127.0.0.1:${CFG.peerPort}`,
    log: (line) => log('tor: ' + line),
    onUp: ({ onion, key, endpoint }) => {
      if (key && key !== state.onionKey) { state.onionKey = key; saveNow(); }
      const changed = myOnion !== onion;
      myOnion = onion; lastDown = '';
      torStatus = { state: 'up', onion, via: endpoint ? (endpoint.path || `${endpoint.host}:${endpoint.port}`) : null };
      if (changed) { log(`onion service : ${onion} (peers reach this daemon through Tor; no port forwarding)`); rehello(); }
      broadcastState();
    },
    onDown: (err) => {
      torStatus = { state: myOnion ? 'reconnecting' : 'unavailable', error: String(err || '').slice(0, 200) };
      if (torStatus.error !== lastDown) { lastDown = torStatus.error; log('tor: ' + torStatus.error); }
      broadcastState();
    },
  });
}

/* ------------------------------------------------------------ updates
   Once a day (the first check two minutes after start) NodeSignal asks
   GitHub Releases for the newest version, through Tor when it has an onion.
   It installs nothing by itself. A release can be installed from the
   console only when its manifest is signed with a release key shipped in
   release-keys.json (updater.js checks signature, version, size, SHA-256):
     - .deb install: the daemon (user nodesignal, no root) downloads and
       checks the package into its state directory and writes a request;
       the root unit nodesignal-update.path runs "nodesignal update-apply",
       which copies everything somewhere only root can write and checks it
       all again before installing;
     - Windows .exe: the daemon downloads and checks the new .exe and runs it
       as "upgrade", which replaces the program and restarts NodeSignal.
   A copy installed from source is told about new versions only. */
const APP_VERSION = (() => {
  if (/^\d+\.\d+\.\d+/.test(process.env.NODESIGNAL_VERSION || '')) return process.env.NODESIGNAL_VERSION;
  for (const f of [path.join(__dirname, 'VERSION'), path.join(__dirname, 'package.json')]) {
    try { const t = fs.readFileSync(f, 'utf8'); const v = f.endsWith('.json') ? JSON.parse(t).version : t.trim(); if (/^\d+\.\d+\.\d+/.test(v)) return v; } catch { }
  }
  return '0.0.0';
})();
const INSTALL_KIND = process.env.NODESIGNAL_EXE ? 'windows' : (__dirname === '/opt/nodesignal' && fs.existsSync('/opt/nodesignal/VERSION') ? 'deb' : 'source');
const TRUSTED_KEYS = (() => { try { return updater.loadTrustedKeys(path.join(__dirname, 'release-keys.json')); } catch (e) { log('!! release-keys.json: ' + e.message); return []; } })();
let updateInfo = { state: CFG.updateCheck ? 'idle' : 'off', current: APP_VERSION };
let lastRelease = null;
function installAsset() {
  if (INSTALL_KIND === 'source') return null;
  return updater.platformAsset();
}
// Through Tor's SOCKS port when Tor runs here, so GitHub sees a Tor exit, not
// this machine.
function updateConnect() {
  if (!myOnion) return undefined;
  return (host, port) => new Promise((resolve, reject) => socks5Connect(host, port, resolve, reject));
}
async function checkForUpdate(manual) {
  if (['checking', 'installing'].includes(updateInfo.state)) return;
  updateInfo = Object.assign({}, updateInfo, { state: 'checking' });
  const connect = updateConnect();
  const get = (url, o) => updater.httpsGet(url, Object.assign({}, o, { connect, timeoutMs: connect ? 90000 : 30000 }));
  try {
    const r = await updater.checkLatest({ repo: CFG.updateRepo, currentVersion: APP_VERSION, trustedKeys: TRUSTED_KEYS, get });
    lastRelease = r;
    const asset = installAsset();
    const installable = !!(r.available && r.verified && asset && r.manifest && r.manifest.files[asset] && r.assets[asset]);
    const why = !r.available || installable ? null
      : INSTALL_KIND === 'source' ? 'This copy was installed from source: update it with git pull and its installer.'
        : !r.verified ? null : 'This release has no installer for this machine.';
    updateInfo = { state: r.available ? 'available' : (r.error ? 'error' : 'current'), current: APP_VERSION, version: r.version || null,
      notes: r.notes || '', published: r.published || null, page: r.page || null, signed: !!r.signed, verified: !!r.verified,
      installable, why, error: r.error || null, checkedAt: Date.now(), viaTor: !!connect };
    if (r.available) log(`update available: ${r.version}${r.verified ? ' (signed with a NodeSignal release key)' : ' (not signed with a key this copy trusts: install it by hand)'}`);
    else if (manual) log('update check: ' + (r.error || 'up to date'));
  } catch (e) {
    updateInfo = { state: 'error', current: APP_VERSION, error: e.message, checkedAt: Date.now() };
  }
  broadcastState();
}
function startUpdateChecks() {
  if (!CFG.updateCheck) return;
  // a little jitter, so daemons do not all ask at the same minute
  const next = (ms) => setTimeout(() => { checkForUpdate(false).finally(() => next(24 * 3600e3 + Math.random() * 3600e3)); }, ms).unref();
  next(120e3 + Math.random() * 60e3);
}
async function installUpdate() {
  const r = lastRelease, asset = installAsset();
  if (!r || !r.available || !r.verified || !r.manifest) throw new Error('there is no signed update to install; check again first');
  if (!asset || !r.assets[asset] || !r.manifest.files[asset]) throw new Error(updateInfo.why || 'this copy cannot be updated from the console');
  const dir = path.join(CFG.dataDir, 'updates');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  updateInfo = Object.assign({}, updateInfo, { state: 'installing', error: null, step: 'downloading' });
  broadcastState();
  const connect = updateConnect();
  try {
    const file = path.join(dir, asset);
    await updater.downloadVerified({ url: r.assets[asset], sha256: r.manifest.files[asset].sha256, size: r.manifest.files[asset].size,
      dest: file, connect, timeoutMs: connect ? 180000 : 60000 });
    log(`update ${r.version}: ${asset} downloaded, size and SHA-256 match the signed manifest`);
    if (INSTALL_KIND === 'deb') {
      fs.writeFileSync(path.join(dir, updater.MANIFEST_NAME), r.manifestBytes, { mode: 0o600 });
      fs.writeFileSync(path.join(dir, updater.SIG_NAME), r.sigBytes, { mode: 0o600 });
      try { fs.unlinkSync(path.join(dir, 'result.json')); } catch { }
      // the root unit (nodesignal-update.path) picks this up and checks it all again
      fs.writeFileSync(path.join(dir, 'request.json'), JSON.stringify({ version: r.version, asset, at: Date.now() }), { mode: 0o600 });
      updateInfo = Object.assign({}, updateInfo, { step: 'handed to the system installer; NodeSignal restarts when it is done' });
      broadcastState();
      setTimeout(() => {
        let res = null; try { res = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8')); } catch { }
        if (!res && updateInfo.state === 'installing') {
          updateInfo = Object.assign({}, updateInfo, { state: 'error', error: 'the system installer did not answer. On the node, run: sudo nodesignal update install' });
          broadcastState();
        } else if (res && !res.ok) { updateInfo = Object.assign({}, updateInfo, { state: 'error', error: res.error || 'the install failed' }); broadcastState(); }
      }, 120e3).unref();
    } else if (INSTALL_KIND === 'windows') {
      // the new .exe replaces the program and restarts NodeSignal (this process ends)
      const args = ['upgrade'];
      if (process.env.NODESIGNAL_ROOT) args.push('--root', process.env.NODESIGNAL_ROOT);
      require('child_process').spawn(file, args, { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      updateInfo = Object.assign({}, updateInfo, { step: 'installing; NodeSignal restarts in a moment' });
      broadcastState();
    }
  } catch (e) {
    updateInfo = Object.assign({}, updateInfo, { state: 'error', error: 'update not installed: ' + e.message });
    broadcastState();
    throw e;
  }
}
// After an install, the root side leaves result.json: say how it went once.
function reportUpdateResult() {
  const f = path.join(CFG.dataDir, 'updates', 'result.json');
  let res = null; try { res = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return; }
  try { fs.unlinkSync(f); } catch { }
  log(res.ok ? `updated to ${res.version}` : `!! update to ${res.version || '?'} failed: ${res.error || 'no reason given'}`);
  if (!res.ok) updateInfo = Object.assign({}, updateInfo, { state: 'error', error: 'the last update failed: ' + (res.error || 'no reason given') });
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

if (peerLoopback) {
  peerLoopback.on('error', (e) => log(`!! peer port on 127.0.0.1:${CFG.peerPort}: ${e.message} (a Tor hidden service cannot reach NodeSignal)`));
  peerLoopback.listen(CFG.peerPort, '127.0.0.1');
}
peerServer.listen(CFG.peerPort, PEER_BIND, () => {
  server.listen(CFG.webPort, WEB_BIND, () => {
    console.log('');
    console.log('  NodeSignal daemon ' + UA);
    console.log('  ----------------------------------------------------------');
    log(`nick           : ${CFG.nick}`);
    log(`Web app        : http://${WEB_BIND}:${CFG.webPort}`);
    log(`                 (this machine only; from elsewhere: ssh -L ${CFG.webPort}:127.0.0.1:${CFG.webPort} <this machine>)`);
    log(`WebSocket      : ws://${WEB_BIND}:${CFG.webPort}/ws`);
    log(`Peer messaging : tcp://${PEER_BIND}:${CFG.peerPort}${peerLoopback ? ` and tcp://127.0.0.1:${CFG.peerPort} (for Tor)` : ''}`);
    log(`Health         : http://${WEB_BIND}:${CFG.webPort}/health`);
    if (TS_ADDR && !explicitBind && !CFG.portMapping) {
      log(`peer bind      : Tailscale (${TS_ADDR}): your tailnet and Tor only, not clearnet`);
      log('                 (operators found on clearnet cannot dial in; you can still message them, and they reply over your link.');
      log('                 To accept clearnet peers: "bind": "0.0.0.0" in the config, then open TCP ' + CFG.peerPort + ')');
    }
    else if (!explicitBind && CFG.portMapping) log('peer bind      : all interfaces, for router port mapping (clearnet)');
    else if (!explicitBind) log('peer bind      : all interfaces (no Tailscale found)');
    else log(`peer bind      : ${CFG.bind} (explicit)`);
    log(`web front door : loopback only, Host + Origin checked, per-launch action token`);
    log(`identity fp    : ${myIdentity.fp}  (peers pin this on first contact)`);
    log(`handshake      : ${noise.PROTOCOL_NAME} (also answers v1.2 peers)`);
    log(`history        : ${vaultOn() ? 'sealed at rest, locked until you unlock it in the console' : 'stored unencrypted; set a passphrase in the console'}`);
    log(`web auth       : ${AUTH_ON ? 'token required (login page)' : 'open: every account on this machine can use the console'}`);
    log(`onion          : ${CFG.onion === 'auto' ? 'automatic (asks Tor for an onion service when Tor runs here)' : CFG.onion === 'external' ? (myOnion || 'external, onion-address not set') : 'off'}`);
    log(`signing key    : ${mySign.id}  (posts and rooms)`);
    log(`mailbox        : ${mailboxServing() ? 'holding sealed mail for contacts who ask' : 'not offered'}${state.myMailboxes.length ? `; ours: ${state.myMailboxes.map((x) => x.host).join(', ')}` : ''}`);
    log(`introductions  : ${discoverable() ? 'on (contacts who are also on may introduce you)' : 'off'}`);
    log(`update check   : ${CFG.updateCheck ? 'daily, GitHub Releases' : 'off'}`);
    log(`web root       : ${CFG.webRoot}`);
    log(`state          : ${STATE_FILE}  (${Object.keys(state.contacts).length} contacts)`);
    log(CFG.noRpc ? 'node RPC       : disabled (--no-rpc)' : `node RPC       : ${CFG.rpcUrl}${CFG.rpcUser ? ` as "${CFG.rpcUser}"` : ''}`);
    if (FILE_CFG['rpc-cookie'] || argv.includes('--rpc-cookie'))
      log('!! rpc-cookie is no longer used (v1.3 never reads the cookie): run "sudo nodesignal setup" to create NodeSignal\'s own RPC login');
    IMPERSONATED = buildImpersonation();
    if (IMPERSONATED) {
      log(`impersonating  : ${IMPERSONATED.ua}`);
      log(`                 (SIMULATED identity, flagged as such to peers)`);
    }
    console.log('');
    startPortMapping();
    startOnion();
    setTimeout(mailboxTick, 8000); setInterval(mailboxTick, 120000);
    setInterval(() => { feedStore.prune(Date.now()); saveSocial(); }, 6 * 3600e3);
    reportUpdateResult();
    startUpdateChecks();
    pollRpc();
    setInterval(pollRpc, 30000);
    setInterval(retryTick, Math.max(200, 10000 * CFG.retryScale));
    setInterval(checkinTick, Math.max(5000, Math.min(30000, (CFG.checkinMs || 30000) / 4)));
    setTimeout(retryTick, 1500);
    // identify anything we don't know yet, then refresh hourly
    // (only addresses a peer connected from or the operator gave: identifiable())
    setTimeout(() => { for (const c of Object.values(state.contacts)) if (!c.peerInfo || c.peerInfo.source === 'claimed') scheduleIdentify(c.host, 2000); }, 2500);
    setInterval(() => {
      for (const c of Object.values(state.contacts)) {
        if (!identifiable(c)) continue;
        const age = c.peerInfo && c.peerInfo.source !== 'claimed' ? Date.now() - (c.peerInfo.at || 0) : Infinity;
        if (age > 60 * 60 * 1000) identifyContact(c.host, 8333).catch(() => { });
      }
    }, 15 * 60 * 1000);
  });
});
