#!/usr/bin/env node
// setup-core.js: logic shared by every NodeSignal installer and the CLI.
// ============================================================================
// Used by install.js (from source), install-node.sh (from source, Linux),
// cli.js (the `nodesignal` command), the Debian package scripts and the
// Windows single executable (packaging/windows/sea-main.js).
//
// Node.js standard library only. Requiring this file has no side effects:
// nothing is read, written or started until a function is called. Run it
// directly for two small helpers used by shell installers:
//
//   node setup-core.js --check-files [dir]   list missing program files, exit 1 if any
//   node setup-core.js --detect              print what Bitcoin node was found, as JSON
//
// Nothing here ever restarts bitcoind or calls an RPC method other than the
// read-only getblockchaininfo / getnetworkinfo. NodeSignal never reads the
// node's cookie file: it logs in as its own RPC user (rpcauth, below).
// ============================================================================
'use strict';
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const { execFile, execFileSync } = require('child_process');

const IS_WIN = process.platform === 'win32';
const UA_COMMENT = 'nodesignal';
const UA_MARKER = '# Added by NodeSignal: advertise NodeSignal in the user agent (undo: nodesignal advertise off)';
const BACKUP_SUFFIX = '.nodesignal-backup';
// NodeSignal's own RPC login. The password lives only in NodeSignal's 0600
// config; bitcoin.conf gets the salted hash (rpcauth) and a whitelist of
// exactly the methods the daemon calls. Keep RPC_METHODS in step with every
// rpcCall in nodesignald.js (tests/setup-core.test.js checks it).
const RPC_USER = 'nodesignal';
const RPC_METHODS = ['getblockchaininfo', 'getnetworkinfo', 'getpeerinfo'];
const RPC_BEGIN = '# NodeSignal RPC access: begin. Managed by NodeSignal (removed on purge or by "nodesignal rpc-access remove").';
const RPC_END = '# NodeSignal RPC access: end';
const CONF_MAX_BYTES = 1024 * 1024;

/* ------------------------------------------------------------ file list
   packaging/files.json is the single list of program files. Builds and
   from-source installers read it; a listed file that is missing is an error. */
function readFileList(repoRoot = __dirname) {
  const j = JSON.parse(fs.readFileSync(path.join(repoRoot, 'packaging', 'files.json'), 'utf8'));
  if (!Array.isArray(j.daemon) || !Array.isArray(j.tools)) throw new Error('packaging/files.json: daemon and tools must be arrays');
  return { daemon: j.daemon.slice(), tools: j.tools.slice(), all: [...j.daemon, ...j.tools] };
}
function missingFiles(dir, names) {
  return names.filter((f) => { try { return !fs.statSync(path.join(dir, f)).isFile(); } catch { return true; } });
}

/* ------------------------------------------------------------ bitcoin.conf
   parseConf mirrors how bitcoind reads the file closely enough for discovery:
   top-level keys plus the [main] section, first value wins, `#` starts a
   comment. analyzeConf is the strict version used before we ever write. */
const SECTION_RE = /^\s*\[([A-Za-z0-9_.-]+)\]\s*$/;
const KV_RE = /^\s*-?([A-Za-z0-9_.]+)\s*=(.*)$/;

function parseConf(text) {
  const out = {}; let section = '';
  for (let line of String(text).split(/\r?\n/)) {
    const hash = line.indexOf('#');
    if (hash >= 0) line = line.slice(0, hash);
    line = line.trim();
    if (!line) continue;
    const sec = line.match(SECTION_RE);
    if (sec) { section = sec[1].toLowerCase(); continue; }
    if (section && section !== 'main') continue;
    const i = line.indexOf('=');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().replace(/^-/, '').toLowerCase();
    if (!(k in out)) out[k] = line.slice(i + 1).trim();
  }
  return out;
}
function readConf(file) {
  try { return parseConf(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
// Split into lines that keep their own line ending, so a rewrite can preserve
// every byte it does not mean to change.
function splitKeepEol(text) {
  const parts = text.match(/[^\n]*\n|[^\n]+$/g);
  return parts || [];
}
function analyzeConf(buf) {
  if (buf.length > CONF_MAX_BYTES) return { ok: false, error: 'it is larger than 1 MB' };
  if (buf.includes(0)) return { ok: false, error: 'it contains binary data' };
  const text = buf.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buf)) return { ok: false, error: 'it is not valid UTF-8 text' };
  const lines = splitKeepEol(text).map((raw, idx) => {
    const body = raw.replace(/\r?\n$/, '');
    const t = body.trim();
    let kind = 'other';
    if (!t) kind = 'blank';
    else if (t.startsWith('#')) kind = 'comment';
    else if (SECTION_RE.test(body)) kind = 'section';
    else if (KV_RE.test(body)) kind = 'kv';
    return { raw, body, kind, idx };
  });
  const bad = lines.find((l) => l.kind === 'other');
  if (bad) return { ok: false, error: `line ${bad.idx + 1} is not "key=value", a [section] or a comment` };
  return { ok: true, text, lines, eol: text.includes('\r\n') ? '\r\n' : '\n' };
}
const isOurUaLine = (l) => l.kind === 'kv' && /^\s*uacomment\s*=\s*nodesignal\s*(#.*)?$/i.test(l.body);
function uaCommentState(confPath) {
  let buf;
  try { buf = fs.readFileSync(confPath); }
  catch (e) { return e.code === 'ENOENT' ? { exists: false, on: false } : { exists: true, on: false, unreadable: e.code || e.message }; }
  const a = analyzeConf(buf);
  if (!a.ok) return { exists: true, on: false, unreadable: a.error };
  let topLevel = true, on = false, inSection = false;
  for (const l of a.lines) {
    if (l.kind === 'section') topLevel = false;
    if (isOurUaLine(l)) { if (topLevel) on = true; else inSection = true; }
  }
  return { exists: true, on, inSection };
}

/* setUaComment: add or remove a top-level `uacomment=nodesignal` line.
   - idempotent; everything else in the file is preserved byte for byte
   - the first change keeps a one-time copy as bitcoin.conf.nodesignal-backup
   - a file we cannot parse with confidence is left alone (throws)
   - never restarts bitcoind; the caller tells the operator to do it
   opts.owner = { uid, gid } sets ownership of a newly created file (Linux, root). */
function setUaComment(confPath, on, opts = {}) {
  let buf = null;
  try { buf = fs.readFileSync(confPath); }
  catch (e) { if (e.code !== 'ENOENT') throw new Error(`cannot read ${confPath} (${e.code || e.message})`); }

  if (buf === null) {
    if (!on) return { changed: false, created: false, path: confPath, on: false };
    const eol = IS_WIN ? '\r\n' : '\n';
    fs.mkdirSync(path.dirname(confPath), { recursive: true });
    fs.writeFileSync(confPath, UA_MARKER + eol + 'uacomment=' + UA_COMMENT + eol, { mode: 0o600, flag: 'wx' });
    chownIfRoot(confPath, opts.owner);
    return { changed: true, created: true, path: confPath, on: true };
  }

  const a = analyzeConf(buf);
  if (!a.ok) throw new Error(`refusing to edit ${confPath}: ${a.error}. Add or remove the line "uacomment=${UA_COMMENT}" by hand.`);
  const firstSection = a.lines.findIndex((l) => l.kind === 'section');
  const topEnd = firstSection < 0 ? a.lines.length : firstSection;
  const top = a.lines.slice(0, topEnd);
  const present = top.some(isOurUaLine);
  const inSection = a.lines.slice(topEnd).some(isOurUaLine);

  let out;
  if (on) {
    if (present) return { changed: false, path: confPath, on: true, inSection };
    const block = UA_MARKER + a.eol + 'uacomment=' + UA_COMMENT + a.eol;
    const raws = a.lines.map((l) => l.raw);
    if (firstSection < 0) {
      let tail = raws.join('');
      if (tail.length && !tail.endsWith('\n')) tail += a.eol;
      out = tail + block;
    } else {
      raws.splice(firstSection, 0, block + a.eol);
      out = raws.join('');
    }
  } else {
    if (!present) return { changed: false, path: confPath, on: false, inSection };
    const drop = new Set();
    top.forEach((l, i) => {
      if (!isOurUaLine(l)) return;
      drop.add(i);
      if (i > 0 && top[i - 1].body.trim() === UA_MARKER) drop.add(i - 1);
      // the blank separator we added before a [section]
      if (i + 1 === topEnd - 1 && firstSection >= 0 && top[i + 1].kind === 'blank' && top[i - 1] && top[i - 1].body.trim() === UA_MARKER) drop.add(i + 1);
    });
    out = a.lines.filter((l, i) => !(i < topEnd && drop.has(i))).map((l) => l.raw).join('');
  }

  const backup = confPath + BACKUP_SUFFIX;
  let madeBackup = false;
  if (!fs.existsSync(backup)) {
    fs.writeFileSync(backup, buf, { mode: 0o600 });
    try { const st = fs.statSync(confPath); chownIfRoot(backup, { uid: st.uid, gid: st.gid }); } catch { }
    madeBackup = true;
  }
  // Written in place (not tmp + rename) so the file keeps its inode, owner,
  // mode, ACLs, and a symlinked bitcoin.conf stays a symlink.
  fs.writeFileSync(confPath, out);
  return { changed: true, path: confPath, on, backup: madeBackup ? backup : null, inSection };
}

/* ------------------------------------------------------------ RPC access
   rpcauth=<user>:<salt>$<hmac> with hmac = HMAC-SHA256(key = salt as text,
   message = password), as Bitcoin Core's share/rpcauth/rpcauth.py writes it.

   rpcwhitelist subtlety: with rpcwhitelistdefault unset, the FIRST
   rpcwhitelist line makes bitcoind give every other RPC user (the cookie
   user bitcoin-cli relies on, Electrs, mempool...) an empty whitelist,
   locking them out. So when bitcoin.conf has no whitelist settings of its
   own we also write rpcwhitelistdefault=0, which keeps every other user
   exactly as before. If the operator already uses whitelists, their
   rpcwhitelistdefault choice is left alone. */
const crypto = require('crypto');
function generateRpcPassword() { return crypto.randomBytes(32).toString('base64url'); }
function makeRpcAuth(user, password, salt = crypto.randomBytes(16).toString('hex')) {
  if (!/^[A-Za-z0-9_.-]+$/.test(user)) throw new Error('bad RPC user name');
  const hmac = crypto.createHmac('sha256', salt).update(String(password)).digest('hex');
  return `rpcauth=${user}:${salt}$${hmac}`;
}
function rpcAuthMatches(line, user, password) {
  const m = /^\s*rpcauth\s*=\s*([^:\s]+):([0-9a-fA-F]+)\$([0-9a-fA-F]{64})\s*$/.exec(line || '');
  if (!m || m[1] !== user) return false;
  const want = crypto.createHmac('sha256', m[2]).update(String(password)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(want), Buffer.from(m[3].toLowerCase()));
}
// Where our block sits (indexes into analyzeConf lines), or null.
function findRpcBlock(lines) {
  const b = lines.findIndex((l) => l.body.trim() === RPC_BEGIN);
  if (b < 0) return null;
  const e = lines.findIndex((l, i) => i > b && l.body.trim() === RPC_END);
  return e < 0 ? { begin: b, end: null } : { begin: b, end: e };
}
function rpcAccessState(confPath) {
  let buf;
  try { buf = fs.readFileSync(confPath); }
  catch (e) { return e.code === 'ENOENT' ? { exists: false, on: false } : { exists: true, on: false, unreadable: e.code || e.message }; }
  const a = analyzeConf(buf);
  if (!a.ok) return { exists: true, on: false, unreadable: a.error };
  const blk = findRpcBlock(a.lines);
  if (!blk) return { exists: true, on: false };
  if (blk.end === null) return { exists: true, on: false, unreadable: 'the NodeSignal block has no end marker' };
  const inner = a.lines.slice(blk.begin + 1, blk.end).map((l) => l.body);
  return { exists: true, on: true, rpcauth: inner.find((x) => /^\s*rpcauth\s*=/.test(x)) || null, lines: inner };
}
/* setRpcAccess(confPath, password): add (or refresh) the managed block at the
   top level of bitcoin.conf, so it applies to every chain. password null
   removes the block. Idempotent: an existing block whose rpcauth already
   matches the password is left untouched, so upgrades do not force a
   bitcoind restart. Everything outside the block is preserved byte for byte;
   the first change keeps a one-time backup. A file we cannot parse with
   confidence is refused (throws), as is a whitelist we would weaken.
   Returns { changed, created, path, on, backup, lines }. */
function setRpcAccess(confPath, password, opts = {}) {
  let buf = null;
  try { buf = fs.readFileSync(confPath); }
  catch (e) { if (e.code !== 'ENOENT') throw new Error(`cannot read ${confPath} (${e.code || e.message})`); }
  const on = password != null;
  const a = buf === null ? { ok: true, text: '', lines: [], eol: IS_WIN ? '\r\n' : '\n' } : analyzeConf(buf);
  if (!a.ok) throw new Error(`refusing to edit ${confPath}: ${a.error}. Add the NodeSignal lines by hand (nodesignal rpc-access show).`);
  const blk = findRpcBlock(a.lines);
  if (blk && blk.end === null) throw new Error(`refusing to edit ${confPath}: it has a "${RPC_BEGIN.slice(0, 30)}..." line with no end marker. Fix it by hand.`);
  const outside = a.lines.filter((l, i) => !blk || i < blk.begin || i > blk.end);

  if (on) {
    const cur = blk ? a.lines.slice(blk.begin + 1, blk.end).map((l) => l.body) : [];
    const auth = cur.find((x) => /^\s*rpcauth\s*=/.test(x));
    if (blk && rpcAuthMatches(auth, RPC_USER, password)) return { changed: false, path: confPath, on: true, lines: cur };
  } else if (!blk) return { changed: false, path: confPath, on: false };

  let block = '';
  let inner = [];
  if (on) {
    const theirWhitelist = outside.some((l) => l.kind === 'kv' && /^\s*-?rpcwhitelist(default)?\s*=/i.test(l.body));
    inner = [makeRpcAuth(RPC_USER, password), `rpcwhitelist=${RPC_USER}:${RPC_METHODS.join(',')}`];
    if (!theirWhitelist) inner.push('rpcwhitelistdefault=0');
    block = [RPC_BEGIN, ...inner, RPC_END].join(a.eol) + a.eol;
  }
  let raws = a.lines.map((l) => l.raw);
  if (blk) {
    const before = raws.slice(0, blk.begin);
    let after = raws.slice(blk.end + 1);
    // When removing, also drop the blank line we put between the block and a
    // following [section]. When refreshing, everything after stays as it is.
    const next = a.lines[blk.end + 1], next2 = a.lines[blk.end + 2];
    if (!on && next && next.kind === 'blank' && next2 && next2.kind === 'section') after = after.slice(1);
    raws = [...before, ...(on ? [block] : []), ...after];
  } else {
    const firstSection = a.lines.findIndex((l) => l.kind === 'section');
    if (firstSection < 0) {
      let tail = raws.join('');
      if (tail.length && !tail.endsWith('\n')) tail += a.eol;
      raws = [tail + block];
    } else raws.splice(firstSection, 0, block + a.eol);
  }
  const out = raws.join('');
  if (buf === null) {
    fs.mkdirSync(path.dirname(confPath), { recursive: true });
    fs.writeFileSync(confPath, out, { mode: 0o600, flag: 'wx' });
    chownIfRoot(confPath, opts.owner);
    return { changed: true, created: true, path: confPath, on, lines: inner };
  }
  const backup = confPath + BACKUP_SUFFIX;
  let madeBackup = false;
  if (!fs.existsSync(backup)) {
    fs.writeFileSync(backup, buf, { mode: 0o600 });
    try { const st = fs.statSync(confPath); chownIfRoot(backup, { uid: st.uid, gid: st.gid }); } catch { }
    madeBackup = true;
  }
  fs.writeFileSync(confPath, out);                       // in place: keeps inode, owner, mode
  return { changed: true, created: false, path: confPath, on, backup: madeBackup ? backup : null, lines: inner };
}
/* NodeSignal's own login lives in its config (rpc-user / rpc-pass). An
   existing password is kept, so reinstalling does not force a bitcoind
   restart. Any cookie or bitcoin.conf pointer from an older install goes.
   Returns true when the config changed. */
function ensureRpcLogin(cfg) {
  let changed = false;
  if (cfg['rpc-user'] !== RPC_USER || !cfg['rpc-pass']) {
    cfg['rpc-user'] = RPC_USER;
    cfg['rpc-pass'] = generateRpcPassword();
    changed = true;
  }
  for (const k of ['rpc-cookie', 'rpc-conf']) if (k in cfg) { delete cfg[k]; changed = true; }
  return changed;
}
/* Which bitcoin.conf holds our block is recorded beside NodeSignal's config
   (/etc/nodesignal/bitcoin-conf on Linux), so uninstall and purge can remove
   the block without detecting the node again. */
function rpcRecordPath(cfgPath) { return path.join(path.dirname(cfgPath), 'bitcoin-conf'); }
function readRpcRecord(cfgPath) {
  try { return fs.readFileSync(rpcRecordPath(cfgPath), 'utf8').trim() || null; } catch { return null; }
}
function writeRpcRecord(cfgPath, confPath) {
  fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
  fs.writeFileSync(rpcRecordPath(cfgPath), confPath + '\n', { mode: 0o644 });
}
/* installRpcAccess: the whole job, shared by Linux setup, "nodesignal
   rpc-access add" and the Windows installer. Ensures NodeSignal's login in
   cfg (the caller writes cfg when cfgChanged), writes the matching block into
   confPath and records which file holds it. P maps a real path to a test
   root. Returns { cfgChanged, result } (result from setRpcAccess). */
function installRpcAccess({ cfg, cfgPath, confPath, owner = null, P = (x) => x }) {
  const cfgChanged = ensureRpcLogin(cfg);
  const result = setRpcAccess(P(confPath), cfg['rpc-pass'], { owner });
  writeRpcRecord(P(cfgPath), confPath);
  return { cfgChanged, result };
}
const RPC_RESTART_TEXT = {
  linux: ['Restart your Bitcoin node so it reads the new rpcauth line. NodeSignal does not do it for you.',
    'For example: sudo systemctl restart bitcoind',
    'Until then NodeSignal shows "not connected" and keeps retrying every 30 seconds.'],
  win32: ['Close Bitcoin Core or Knots and start it again so it reads the new rpcauth line.',
    'NodeSignal does not do it for you. Until then it shows "not connected" and keeps retrying.'],
};
// The bitcoin.conf NodeSignal should manage: the one the node reads.
function nodeConfPath(det) {
  return det ? (det.confPath || (det.datadir ? path.join(det.datadir, 'bitcoin.conf') : null)) : null;
}

/* ------------------------------------------------------------ files */
function chownIfRoot(file, owner) {
  if (IS_WIN || !owner || typeof process.getuid !== 'function' || process.getuid() !== 0) return;
  try { fs.chownSync(file, owner.uid, owner.gid); } catch { }
}
// Same approach as install.js always used: icacls on Windows, 0600 elsewhere.
function lockDownFile(file) {
  try {
    if (IS_WIN) {
      const user = process.env.USERNAME || '';
      if (!user) return false;
      execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${user}:F`], { stdio: 'ignore', timeout: 15000, windowsHide: true });
    } else fs.chmodSync(file, 0o600);
    return true;
  } catch { return false; }
}
/* writeConfig: the daemon's JSON config (keys equal flag names). Atomic write,
   readable by its owner only. An existing file keeps its owner (so `sudo
   nodesignal port-mapping on` does not lock the service user out); a new file
   gets opts.owner when running as root. */
function writeConfig(file, obj, opts = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let owner = opts.owner || null;
  try { const st = fs.statSync(file); owner = owner || { uid: st.uid, gid: st.gid }; } catch { }
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
  chownIfRoot(file, owner);
  return lockDownFile(file);
}
function readConfig(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/* ------------------------------------------------------------ users (Linux) */
function readPasswd(root = '') {
  const users = [];
  try {
    for (const line of fs.readFileSync(path.join(root || '/', 'etc', 'passwd'), 'utf8').split('\n')) {
      const p = line.split(':');
      if (p.length < 7) continue;
      users.push({ name: p[0], uid: Number(p[2]), gid: Number(p[3]), home: p[5], shell: p[6] });
    }
  } catch { }
  return users;
}
function userByUid(uid, root = '') {
  return readPasswd(root).find((u) => u.uid === uid) || null;
}

/* ------------------------------------------------------------ node detection */
const DATADIR_MARKERS = ['blocks', 'chainstate', 'bitcoin.conf', '.cookie', 'settings.json', 'peers.dat', 'debug.log', 'wallets'];
const PROC_NAMES = new Set(['bitcoind', 'bitcoin-qt', 'bitcoin-node', 'bitcoin-gui']);
const WIN_IMAGES = new Set(['bitcoind.exe', 'bitcoin-qt.exe', 'bitcoin-node.exe', 'bitcoin-gui.exe']);
const CHAIN_SUBDIR = { main: '', test: 'testnet3', testnet4: 'testnet4', signet: 'signet', regtest: 'regtest' };
const CHAIN_PORT = { main: 8332, test: 18332, testnet4: 48332, signet: 38332, regtest: 18443 };

function isDir(p) { try { return fs.statSync(p).isDirectory(); } catch { return false; } }
function isFile(p) { try { return fs.statSync(p).isFile(); } catch { return false; } }
function looksLikeDatadir(d) { return isDir(d) && DATADIR_MARKERS.some((m) => fs.existsSync(path.join(d, m))); }

function chainOf(conf) {
  if (!conf) return 'main';
  if (conf.chain && CHAIN_SUBDIR[conf.chain] !== undefined) return conf.chain;
  if (conf.testnet4 === '1') return 'testnet4';
  if (conf.testnet === '1') return 'test';
  if (conf.signet === '1') return 'signet';
  if (conf.regtest === '1') return 'regtest';
  return 'main';
}

// The data directories the daemon itself knows (nodesignald.js
// defaultDataDirs); detection starts from them too.
function daemonDataDirs(home, platform = process.platform, env = process.env) {
  const dirs = [];
  if (platform === 'win32') {
    const appdata = env.APPDATA || path.join(home, 'AppData', 'Roaming');
    dirs.push(path.join(appdata, 'Bitcoin'), path.join(home, 'AppData', 'Roaming', 'Bitcoin'));
  } else if (platform === 'darwin') {
    dirs.push(path.join(home, 'Library', 'Application Support', 'Bitcoin'));
  }
  dirs.push(path.join(home, '.bitcoin'), path.join(home, 'snap', 'bitcoin-core', 'common', '.bitcoin'));
  return [...new Set(dirs)];
}
function samePath(a, b, platform = process.platform) {
  if (!a || !b) return false;
  const na = path.resolve(a), nb = path.resolve(b);
  return platform === 'win32' ? na.toLowerCase() === nb.toLowerCase() : na === nb;
}

function execText(cmd, args, timeout = 8000) {
  return new Promise((resolve) => {
    try {
      execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
        (err, stdout) => resolve(err ? '' : String(stdout)));
    } catch { resolve(''); }
  });
}
function argValue(args, name) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const p of ['-' + name + '=', '--' + name + '=']) if (a.startsWith(p)) return a.slice(p.length);
    if ((a === '-' + name || a === '--' + name) && args[i + 1]) return args[i + 1];
  }
  return '';
}
function linuxProcesses(root = '') {
  const procDir = path.join(root || '/', 'proc');
  const out = [];
  let ents = [];
  try { ents = fs.readdirSync(procDir); } catch { return out; }
  for (const pid of ents) {
    if (!/^\d+$/.test(pid)) continue;
    let comm = '';
    try { comm = fs.readFileSync(path.join(procDir, pid, 'comm'), 'utf8').trim(); } catch { continue; }
    if (!PROC_NAMES.has(comm)) continue;
    let args = [], uid = null;
    try { args = fs.readFileSync(path.join(procDir, pid, 'cmdline'), 'utf8').split('\0').filter(Boolean); } catch { }
    try {
      const m = fs.readFileSync(path.join(procDir, pid, 'status'), 'utf8').match(/^Uid:\s+(\d+)/m);
      if (m) uid = Number(m[1]);
    } catch { }
    out.push({ pid: Number(pid), name: comm, uid, datadir: argValue(args, 'datadir'), conf: argValue(args, 'conf') });
  }
  return out;
}
async function windowsProcesses() {
  const text = await execText('tasklist', ['/fo', 'csv', '/nh']);
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^"([^"]+)","(\d+)"/);
    if (m && WIN_IMAGES.has(m[1].toLowerCase())) out.push({ pid: Number(m[2]), name: m[1], uid: null, datadir: '', conf: '' });
  }
  return out;
}
// Bitcoin Core / Knots GUI remembers a custom data directory (often a second
// drive on Windows) in the registry.
async function windowsRegistryDatadirs() {
  const out = [];
  for (const key of ['HKCU\\Software\\Bitcoin\\Bitcoin-Qt', 'HKCU\\Software\\Bitcoin\\Bitcoin-Qt-testnet']) {
    const text = await execText('reg', ['query', key, '/v', 'strDataDir']);
    const m = text.match(/strDataDir\s+REG_\w+\s+(.+)/);
    if (m) out.push(m[1].trim());
  }
  return out;
}
function linuxHomes(root = '') {
  const homes = new Set();
  for (const u of readPasswd(root)) if ((u.uid === 0 || u.uid >= 1000) && u.home && u.home !== '/') homes.add(u.home);
  try { for (const d of fs.readdirSync(path.join(root || '/', 'home'))) homes.add('/home/' + d); } catch { }
  if (!root) homes.add(os.homedir());
  return [...homes];
}
function linuxBinaries(root = '') {
  const found = [];
  const dirs = new Set((root ? [] : String(process.env.PATH || '').split(':')).concat(
    ['/usr/bin', '/usr/local/bin', '/usr/sbin', '/snap/bin', '/opt/bitcoin/bin']));
  try { for (const d of fs.readdirSync(path.join(root || '/', 'opt'))) if (/bitcoin|knots/i.test(d)) dirs.add('/opt/' + d + '/bin'); } catch { }
  for (const d of dirs) {
    if (!d) continue;
    for (const b of ['bitcoind', 'bitcoin-qt', 'bitcoin-core.daemon']) {
      const p = path.join(d, b);
      if (isFile(path.join(root || '/', p))) found.push(p);
    }
  }
  return [...new Set(found)];
}
function windowsBinaries(env = process.env) {
  const found = [];
  for (const base of [env.ProgramFiles, env['ProgramFiles(x86)'], env.ProgramW6432].filter(Boolean)) {
    for (const rel of ['Bitcoin\\bitcoin-qt.exe', 'Bitcoin\\daemon\\bitcoind.exe', 'Bitcoin\\bitcoind.exe', 'Bitcoin Knots\\bitcoin-qt.exe']) {
      const p = path.join(base, rel);
      if (isFile(p)) found.push(p);
    }
  }
  return [...new Set(found)];
}

/* detectBitcoinNode: is a Bitcoin node (Core or Knots) installed here, and
   where does it keep its data? Never throws.
   Returns { installed, datadirs, datadir, confPath, cookiePath, chain,
             rpcUrl, owner, running, processes, binaries, how }.
   opts.root lets tests point the Linux scan at a fake filesystem. */
async function detectBitcoinNode(opts = {}) {
  const platform = opts.platform || process.platform;
  const root = opts.root || '';
  const R = (p) => (root ? path.join(root, p) : p);
  const env = opts.env || process.env;
  const how = [];

  let processes = [];
  try { processes = platform === 'win32' ? await windowsProcesses() : (platform === 'linux' ? linuxProcesses(root) : []); }
  catch { processes = []; }

  const candidates = [];
  const confCandidates = [];
  for (const p of processes) {
    how.push(`${p.name} is running (pid ${p.pid})`);
    if (p.conf) confCandidates.push(p.conf);
    if (p.datadir) candidates.push(p.datadir);
    else if (platform === 'linux' && p.uid !== null) {
      const u = userByUid(p.uid, root);
      if (u) candidates.push(path.join(u.home, '.bitcoin'));
    }
  }
  if (platform === 'win32') {
    try { candidates.push(...await windowsRegistryDatadirs()); } catch { }
    candidates.push(...daemonDataDirs(os.homedir(), platform, env));
    const local = env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    candidates.push(path.join(local, 'Bitcoin'));
  } else if (platform === 'darwin') {
    candidates.push(...daemonDataDirs(os.homedir(), platform, env));
  } else {
    for (const h of linuxHomes(root)) candidates.push(path.join(h, '.bitcoin'), path.join(h, 'snap', 'bitcoin-core', 'common', '.bitcoin'));
    candidates.push('/var/lib/bitcoind', '/var/lib/bitcoin', '/home/bitcoin/.bitcoin');
    confCandidates.push('/etc/bitcoin/bitcoin.conf');
  }
  // a datadir= line in a system-wide conf counts too
  for (const c of confCandidates) {
    const conf = readConf(R(c));
    if (conf && conf.datadir) candidates.push(conf.datadir);
  }

  const seen = new Set();
  const datadirs = [];
  for (const d of candidates) {
    if (!d) continue;
    const key = platform === 'win32' ? path.resolve(d).toLowerCase() : path.resolve(d);
    if (seen.has(key)) continue;
    seen.add(key);
    if (looksLikeDatadir(R(d))) datadirs.push(d);
  }
  // Prefer the datadir a running node uses, then one holding a chain.
  datadirs.sort((a, b) => score(b) - score(a));
  function score(d) {
    let s = 0;
    if (processes.some((p) => p.datadir && samePath(p.datadir, d, platform))) s += 4;
    if (isDir(R(path.join(d, 'blocks')))) s += 2;
    if (isFile(R(path.join(d, '.cookie')))) s += 1;
    return s;
  }
  const datadir = datadirs[0] || null;

  let confPath = null;
  for (const c of [...confCandidates.filter((x) => processes.some((p) => p.conf === x)),
    ...(datadir ? [path.join(datadir, 'bitcoin.conf')] : []), ...confCandidates]) {
    if (c && isFile(R(c))) { confPath = c; break; }
  }
  const conf = confPath ? readConf(R(confPath)) : null;
  const effectiveDatadir = (conf && conf.datadir) || datadir;
  const chain = chainOf(conf);
  let cookiePath = null;
  if (conf && conf.rpccookiefile) {
    cookiePath = path.isAbsolute(conf.rpccookiefile) ? conf.rpccookiefile
      : path.join(effectiveDatadir || '', CHAIN_SUBDIR[chain], conf.rpccookiefile);
  } else if (effectiveDatadir) {
    cookiePath = path.join(effectiveDatadir, CHAIN_SUBDIR[chain], '.cookie');
  }
  const port = (conf && Number(conf.rpcport)) || CHAIN_PORT[chain];
  let host = '127.0.0.1';
  if (conf && conf.rpcconnect) host = conf.rpcconnect;
  const rpcUrl = `http://${host.includes(':') && !host.startsWith('[') ? '[' + host + ']' : host}:${port}`;
  // The daemon applies rpcport= from bitcoin.conf by itself, but knows nothing
  // of test chains or rpcconnect=, so only then must installers write rpc-url.
  const rpcUrlNeeded = host !== '127.0.0.1' || !!(chain !== 'main' && !(conf && conf.rpcport));

  const binaries = platform === 'win32' ? windowsBinaries(env) : (platform === 'linux' ? linuxBinaries(root) : []);
  for (const d of datadirs) how.push(`data directory ${d}`);
  if (confPath) how.push(`config ${confPath}`);
  for (const b of binaries) how.push(`program ${b}`);

  let owner = null;
  if (platform === 'linux') {
    let uid = null, gid = null;
    for (const p of [cookiePath, effectiveDatadir, datadir]) {
      if (!p) continue;
      try { const st = fs.statSync(R(p)); uid = st.uid; gid = st.gid; break; } catch { }
    }
    if (uid === null) { const pr = processes.find((p) => p.uid !== null); if (pr) uid = pr.uid; }
    if (uid !== null) {
      const u = userByUid(uid, root);
      owner = { uid, gid: gid !== null ? gid : (u ? u.gid : uid), username: u ? u.name : null, home: u ? u.home : null };
    }
  }

  return {
    installed: !!(datadirs.length || confPath || binaries.length || processes.length),
    datadirs, datadir, confPath, cookiePath, chain, rpcUrl, rpcUrlNeeded, owner,
    running: processes.length > 0, processes, binaries, how,
  };
}

/* ------------------------------------------------------------ RPC */
/* findRpcAuth: the same order the daemon uses (rpcAuth in nodesignald.js):
   NodeSignal's own login from its config, then rpcuser/rpcpassword in an
   explicitly given rpc-conf. The node's cookie file is never read.
   Returns { auth, source, notes } with auth null when nothing usable. */
function findRpcAuth(det, cfg = {}, opts = {}) {
  const R = (p) => (opts.root ? path.join(opts.root, p) : p);
  const notes = [];
  if (cfg['rpc-user']) return { auth: cfg['rpc-user'] + ':' + (cfg['rpc-pass'] || ''), source: `RPC user "${cfg['rpc-user']}" from the NodeSignal config`, notes };
  if (cfg['rpc-conf']) {
    const conf = readConf(R(cfg['rpc-conf']));
    if (conf && conf.rpcuser && conf.rpcpassword) return { auth: conf.rpcuser + ':' + conf.rpcpassword, source: 'rpcuser/rpcpassword in ' + cfg['rpc-conf'], notes };
  }
  notes.push('NodeSignal has no RPC login yet: run setup (it adds a "nodesignal" rpcauth user to bitcoin.conf).');
  return { auth: null, source: null, notes };
}

function rpcCall({ url, auth, method = 'getblockchaininfo', params = [], timeout = 5000 }) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, code: 'bad-url', error: 'bad RPC URL ' + url }); }
    const body = JSON.stringify({ jsonrpc: '1.0', id: 'nodesignal-setup', method, params });
    let done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    const req = http.request({
      hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || 8332, path: '/', method: 'POST', timeout,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        Authorization: 'Basic ' + Buffer.from(auth || '').toString('base64') },
    }, (res) => {
      let d = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (d.length < 4 * 1024 * 1024) d += c; });
      res.on('end', () => {
        if (res.statusCode === 401) return finish({ ok: false, code: 'auth', error: 'the node rejected the login (HTTP 401)' });
        if (res.statusCode === 403) return finish({ ok: false, code: 'forbidden', error: 'the node refused the method for this user (HTTP 403, rpcwhitelist)' });
        try {
          const j = JSON.parse(d);
          if (j.error) {
            const warming = j.error.code === -28;
            return finish({ ok: false, code: warming ? 'warmup' : 'rpc', error: warming ? 'the node is still starting up (' + j.error.message + ')' : j.error.message });
          }
          finish({ ok: true, result: j.result });
        } catch { finish({ ok: false, code: 'bad-reply', error: `unexpected reply (HTTP ${res.statusCode})` }); }
      });
    });
    req.on('error', (e) => finish({ ok: false, code: e.code === 'ECONNREFUSED' ? 'refused' : 'net',
      error: e.code === 'ECONNREFUSED' ? 'nothing is listening on the RPC port' : (e.code || e.message) }));
    req.on('timeout', () => { req.destroy(); finish({ ok: false, code: 'timeout', error: 'the node did not answer in time' }); });
    req.end(body);
  });
}
// rpcCheck: one read-only getblockchaininfo call with a timeout.
function rpcCheck({ url, auth, timeout = 5000 }) {
  if (!auth) return Promise.resolve({ ok: false, code: 'no-auth', error: 'no RPC credentials were found' });
  return rpcCall({ url, auth, method: 'getblockchaininfo', timeout });
}
/* checkNode: detection + credential discovery + rpcCheck, with a plain
   explanation and a hint when it fails. */
async function checkNode(det, cfg = {}, opts = {}) {
  const url = cfg['rpc-url'] || (det && det.rpcUrl) || 'http://127.0.0.1:8332';
  const found = findRpcAuth(det, cfg, opts);
  const r = await rpcCheck({ url, auth: found.auth, timeout: opts.timeout || 5000 });
  const out = { ok: r.ok, url, source: found.source, notes: found.notes, code: r.code, error: r.error };
  if (r.ok) {
    out.chain = r.result.chain; out.blocks = r.result.blocks; out.pruned = !!r.result.pruned;
    const ni = await rpcCall({ url, auth: found.auth, method: 'getnetworkinfo', timeout: opts.timeout || 5000 });
    if (ni.ok) { out.subversion = ni.result.subversion; out.connections = ni.result.connections; }
    return out;
  }
  out.hint = rpcHint(det, r.code, opts.platform || process.platform);
  return out;
}
function rpcHint(det, code, platform = process.platform) {
  const gui = platform === 'win32';
  if (code === 'no-auth') {
    return platform === 'win32' ? 'Run the installer again: it adds NodeSignal\'s own RPC login to bitcoin.conf.'
      : 'Run: sudo nodesignal setup   (it adds NodeSignal\'s own RPC login to bitcoin.conf)';
  }
  if (code === 'refused' || code === 'net') {
    if (det && det.running) {
      return gui
        ? 'Bitcoin is running but its RPC server is off. In Bitcoin Core or Knots open Settings > Options, tick "Enable RPC server" (or add server=1 to bitcoin.conf), then restart it.'
        : 'bitcoind is running but RPC is not answering. Check server=1 and rpcport in bitcoin.conf, or wait if it is still starting.';
    }
    return gui
      ? 'Bitcoin Core or Knots is installed but not running. Start it (with "Enable RPC server" ticked, or server=1 in bitcoin.conf).'
      : 'bitcoind is installed but not running. Start it, for example: sudo systemctl start bitcoind';
  }
  if (code === 'warmup') return 'The node is still loading. NodeSignal will connect by itself once it is ready.';
  if (code === 'auth') return gui
    ? 'The node does not know NodeSignal\'s RPC login yet. Close Bitcoin Core or Knots and start it again so it reads the new lines in bitcoin.conf.'
    : 'The node does not know NodeSignal\'s RPC login yet. Restart bitcoind so it reads the new lines in bitcoin.conf (for example: sudo systemctl restart bitcoind).';
  if (code === 'forbidden') return 'The node refused a method. Check the rpcwhitelist line for the nodesignal user in bitcoin.conf.';
  if (code === 'timeout') return 'The node is busy (often during initial sync). NodeSignal keeps retrying.';
  return '';
}

/* ------------------------------------------------------------ network */
function portFree(port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, host);
  });
}
function tailscaleAddr() {
  try {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const a of ifaces[name]) {
        if (a.family !== 'IPv4' || a.internal) continue;
        if (/tailscale|^ts\d/i.test(name)) return a.address;
        const o = a.address.split('.').map(Number);
        if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return a.address;
      }
    }
  } catch { }
  return null;
}
function httpGetJson(url, timeout = 3000) {
  return new Promise((resolve) => {
    let req;
    try {
      req = http.get(url, { timeout }, (res) => {
        let d = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { if (d.length < 1024 * 1024) d += c; });
        res.on('end', () => { try { resolve({ ok: res.statusCode === 200, status: res.statusCode, json: JSON.parse(d) }); } catch { resolve({ ok: false, status: res.statusCode, error: 'not JSON' }); } });
      });
    } catch (e) { return resolve({ ok: false, error: e.message }); }
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
  });
}
// Poll /health until it answers (and, with wantRpc, until RPC is connected).
async function waitForHealth(port, { timeoutMs = 20000, wantRpc = false, rpcGraceMs = 8000 } = {}) {
  const start = Date.now();
  let last = null, firstOk = 0;
  while (Date.now() - start < timeoutMs + (firstOk ? rpcGraceMs : 0)) {
    const r = await httpGetJson(`http://127.0.0.1:${port}/health`, 2000);
    if (r.ok && r.json && r.json.status === 'ok') {
      last = r.json;
      if (!firstOk) firstOk = Date.now();
      if (!wantRpc || last.rpcConnected || Date.now() - firstOk > rpcGraceMs) return last;
    }
    await new Promise((res) => setTimeout(res, 500));
  }
  return last;
}
// The address the web UI is reachable on, matching the daemon's bind rules.
// The console listens on loopback only and refuses any other Host header, so
// this is the one address that works (from another machine: an SSH tunnel
// that keeps the same port, ssh -L 8789:127.0.0.1:8789 <node>).
function webUrl(cfg = {}) {
  const port = Number(cfg['web-port']) || 8789;
  return `http://localhost:${port}/`;
}

/* ------------------------------------------------------------ paths */
function defaultConfigPath(platform = process.platform, env = process.env) {
  if (platform === 'win32') return path.join(env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'NodeSignal', 'config.json');
  if (platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'NodeSignal', 'config.json');
  return '/etc/nodesignal/config.json';
}

/* ------------------------------------------------------------ prompts
   Works on a terminal and with piped input (one answer per line), so every
   installer can be scripted:  node install.js < answers.txt               */
function createPrompter({ input = process.stdin, output = process.stdout } = {}) {
  const tty = !!input.isTTY;
  let rl = null, queued = null, loading = null;
  const loadPiped = () => loading || (loading = new Promise((resolve) => {
    let data = '';
    input.setEncoding('utf8');
    input.on('data', (d) => (data += d));
    input.on('end', () => resolve((queued = data.split(/\r?\n/))));
    input.on('error', () => resolve((queued = [])));
  }));
  async function ask(q) {
    if (tty) {
      if (!rl) rl = require('readline').createInterface({ input, output });
      return new Promise((res) => rl.question(q, (a) => res(a.trim())));
    }
    if (!queued) await loadPiped();
    output.write(q);
    const line = queued.length ? queued.shift() : '';
    output.write(line + '\n');
    return String(line).trim();
  }
  async function askDefault(q, dflt) {
    const a = await ask(`  ${q} [${dflt}]: `);
    return a === '' ? dflt : a;
  }
  async function askYesNo(q, dfltYes = false) {
    for (let i = 0; i < 20; i++) {
      const a = (await ask(`  ${q} [${dfltYes ? 'Y/n' : 'y/N'}]: `)).toLowerCase();
      if (a === '') return dfltYes;
      if (a === 'y' || a === 'yes') return true;
      if (a === 'n' || a === 'no') return false;
      output.write('  Please answer y or n.\n');
    }
    return dfltYes;
  }
  async function pause(msg = '  Press Enter to close this window.') {
    if (!tty) return;
    await ask(msg);
  }
  function close() { if (rl) { rl.close(); rl = null; } }
  return { ask, askDefault, askYesNo, pause, close, tty };
}

/* Text shared by every installer so the two opt-ins read the same everywhere. */
const OPT_IN_TEXT = {
  advertise: [
    'Advertise NodeSignal in your node\'s user agent?',
    'This adds "uacomment=nodesignal" to bitcoin.conf, so your node announces',
    'itself as /Satoshi:.../nodesignal/ (or the Knots equivalent). Other operators',
    'can then see that you run NodeSignal. It is PUBLIC: every peer your node',
    'connects to sees it. It takes effect after you restart your node yourself;',
    'NodeSignal never restarts it. Undo any time with: nodesignal advertise off',
  ],
  portMapping: [
    'Ask your router to open the NodeSignal peer port (UPnP / NAT-PMP)?',
    'Operators outside your network can then reach you directly. It also means',
    'your node\'s public IP is visible to anyone you message, on clearnet.',
    'Tor or Tailscale avoid that and need no port mapping.',
    'Undo any time with: nodesignal port-mapping off',
  ],
};

module.exports = {
  VERSION_FALLBACK: '1.3.0',
  IS_WIN, UA_COMMENT, UA_MARKER, BACKUP_SUFFIX, OPT_IN_TEXT,
  RPC_USER, RPC_METHODS, RPC_BEGIN, RPC_END,
  generateRpcPassword, makeRpcAuth, rpcAuthMatches, rpcAccessState, setRpcAccess, nodeConfPath,
  ensureRpcLogin, rpcRecordPath, readRpcRecord, writeRpcRecord, installRpcAccess, RPC_RESTART_TEXT,
  readFileList, missingFiles,
  parseConf, readConf, analyzeConf, setUaComment, uaCommentState,
  lockDownFile, writeConfig, readConfig, chownIfRoot,
  readPasswd, userByUid,
  detectBitcoinNode, daemonDataDirs, samePath, chainOf,
  findRpcAuth, rpcCall, rpcCheck, checkNode, rpcHint,
  portFree, tailscaleAddr, httpGetJson, waitForHealth, webUrl,
  defaultConfigPath, createPrompter,
};

/* ------------------------------------------------------------ direct use */
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args[0] === '--check-files') {
    const dir = path.resolve(args[1] || __dirname);
    let list;
    try { list = readFileList(__dirname); } catch (e) { console.error('Cannot read packaging/files.json: ' + e.message); process.exit(2); }
    const miss = missingFiles(dir, list.all);
    if (miss.length) { console.log(miss.join(' ')); process.exit(1); }
    process.exit(0);
  } else if (args[0] === '--list-files') {
    const list = readFileList(__dirname);
    console.log((args[1] === 'daemon' ? list.daemon : args[1] === 'tools' ? list.tools : list.all).join(' '));
  } else if (args[0] === '--detect') {
    detectBitcoinNode().then((d) => console.log(JSON.stringify(d, null, 2)));
  } else {
    console.log('usage: node setup-core.js --check-files [dir] | --list-files [daemon|tools] | --detect');
    process.exit(args.length ? 2 : 0);
  }
}
