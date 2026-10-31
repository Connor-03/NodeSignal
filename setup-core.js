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
// uacomment=nodesignal, or uacomment=nodesignal:<onion> (1.4: where to reach
// this operator's NodeSignal over Tor, readable by every peer)
const OUR_UA_RE = /^\s*uacomment\s*=\s*(nodesignal(?::[a-z2-7]{56})?)\s*(#.*)?$/i;
const isOurUaLine = (l) => l.kind === 'kv' && OUR_UA_RE.test(l.body);
const uaValueOf = (l) => (OUR_UA_RE.exec(l.body) || [])[1] || null;
// The comment value for an onion address (with or without ".onion").
function uaCommentFor(onion) {
  const id = String(onion || '').replace(/\.onion$/, '');
  return /^[a-z2-7]{56}$/.test(id) ? `${UA_COMMENT}:${id}` : UA_COMMENT;
}
function uaCommentState(confPath) {
  let buf;
  try { buf = fs.readFileSync(confPath); }
  catch (e) { return e.code === 'ENOENT' ? { exists: false, on: false } : { exists: true, on: false, unreadable: e.code || e.message }; }
  const a = analyzeConf(buf);
  if (!a.ok) return { exists: true, on: false, unreadable: a.error };
  let topLevel = true, on = false, inSection = false, value = null;
  for (const l of a.lines) {
    if (l.kind === 'section') topLevel = false;
    if (isOurUaLine(l)) { if (topLevel) { on = true; value = uaValueOf(l); } else inSection = true; }
  }
  return { exists: true, on, inSection, value };
}

/* ------------------------------------------------------------ editing as the file's owner
   bitcoin.conf, NodeSignal's state folder and its update folder belong to
   other accounts (the node's user, the nodesignal user), and those accounts
   can put links in them or swap them while root works there. So root never
   follows a path through them as root: it takes the owner's identity for the
   file work (asOwner) and goes back to root afterwards. A root-owned file is
   only worked on as root when no other account can change a folder above it
   (unsafeFolder). Linux; elsewhere, and when not root, nothing switches. */
const canSwitchIds = () => !IS_WIN && typeof process.geteuid === 'function' && process.geteuid() === 0
  && typeof process.seteuid === 'function';
// The identity for a file owned by uid (group gid): the user's own primary
// group when /etc/passwd knows the user, else the file's group. Root's group
// is never lent to another account.
function ownerIdentity(uid, gid) {
  const u = userByUid(uid);
  const g = u ? u.gid : gid;
  if (uid !== 0 && g === 0) throw new Error(`refusing to act for uid ${uid} with root's group`);
  return { uid, gid: g, name: u ? u.name : null };
}
// Run fn, synchronous file work only, with the effective uid and gid of id and
// no other groups; always back to root afterwards (the saved uid stays 0, so
// this can be undone). id null, or root, or not running as root: just fn().
function asOwner(id, fn) {
  if (!id || id.uid === 0 || !canSwitchIds()) return fn();
  const groups = process.getgroups(), egid = process.getegid();
  process.setgroups([id.gid]);
  try {
    process.setegid(id.gid);
    try {
      process.seteuid(id.uid);
      try {
        const r = fn();
        if (r && typeof r.then === 'function') throw new Error('asOwner: synchronous work only');
        return r;
      } finally { process.seteuid(0); }
    } finally { process.setegid(egid); }
  } finally { process.setgroups(groups); }
}
// null when dir and every folder above it belong to root and no other
// account can write to them (a sticky folder such as /tmp is fine); else the
// first folder that fails, and why. A root-owned link on the way (such as
// /bin -> usr/bin) is fine when what it points at passes too.
function unsafeFolder(dir) {
  let d = path.resolve(dir);
  for (;;) {
    let st;
    try { st = fs.lstatSync(d); } catch (e) { return { dir: d, why: e.code || e.message }; }
    if (st.isSymbolicLink()) {
      if (st.uid !== 0) return { dir: d, why: 'it is a link another account owns' };
      let target;
      try { target = fs.realpathSync(d); } catch (e) { return { dir: d, why: e.code || e.message }; }
      const bad = unsafeFolder(target);
      if (bad) return bad;
    } else if (st.uid !== 0) { const u = userByUid(st.uid); return { dir: d, why: `it belongs to ${u ? u.name : 'uid ' + st.uid}` }; }
    else if ((st.mode & 0o022) && !(st.mode & 0o1000)) return { dir: d, why: 'accounts other than root can write to it' };
    const up = path.dirname(d);
    if (up === d) return null;
    d = up;
  }
}
// A file read without following a link at its name, without waiting on a
// FIFO, and only if it is a regular file of at most max bytes.
function readPlainFileSync(file, max) {
  const C = fs.constants;
  const fd = fs.openSync(file, C.O_RDONLY | (C.O_NOFOLLOW || 0) | (C.O_NONBLOCK || 0));
  try { return readFd(fd, path.basename(file), max); } finally { fs.closeSync(fd); }
}
function readFd(fd, name, max) {
  const st = fs.fstatSync(fd);
  if (!st.isFile()) throw Object.assign(new Error(`${name} is not a plain file`), { code: 'ENOTPLAIN' });
  if (st.size > max) throw Object.assign(new Error(`${name} is larger than ${max} bytes`), { code: 'ETOOBIG' });
  const buf = Buffer.alloc(st.size);
  let off = 0;
  while (off < st.size) { const n = fs.readSync(fd, buf, off, st.size - off, off); if (!n) break; off += n; }
  return buf.subarray(0, off);
}
// Replace file with new content without following a link at its name: a new
// file (O_EXCL never follows a link) renamed over it (rename replaces the
// name, never what a link points at).
function replaceFileSync(file, data, mode = 0o600) {
  const tmp = `${file}.${process.pid}-${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, data, { mode, flag: 'wx' });
  try { fs.renameSync(tmp, file); } catch (e) { try { fs.unlinkSync(tmp); } catch { } throw e; }
}

/* copyStateTree(src, dst): an older install's state folder into the new
   one (setup, as root). Both belong to other accounts, which can put links in
   them or swap entries while root works, and the old folder's path comes
   from a config the nodesignal account can write. So root never copies as
   root: src is read as its owner, dst written as its owner (asOwner); only
   real folders and plain files are copied (no links, FIFOs or devices),
   COPY_MAX_BYTES in all; new files are made with O_EXCL (never through a
   link) and anything already in dst is kept. Everything is read before
   anything is written, so a refused source writes nothing. A root-owned src
   is read as root only when no other account can change it or a folder
   above it. Throws when src is not a real folder, when one folder holds the
   other, when src is too big, or when its state.json cannot be read or
   written. Returns { files, dirs, skipped }. */
const COPY_MAX_BYTES = 64 * 1024 * 1024, COPY_MAX_ENTRIES = 10000, COPY_MAX_DEPTH = 16;
function copyStateTree(src, dst, { maxBytes = COPY_MAX_BYTES } = {}) {
  const C = fs.constants;
  src = path.resolve(src); dst = path.resolve(dst);
  const within = (a, b) => { const r = path.relative(b, a); return r === '' || (r !== '..' && !r.startsWith('..' + path.sep) && !path.isAbsolute(r)); };
  const real = (p) => { try { return fs.realpathSync(p); } catch { return p; } };
  for (const [a, b] of [[src, dst], [real(src), real(dst)]]) {
    if (within(a, b)) throw new Error(`${src} is inside ${dst}`);
    if (within(b, a)) throw new Error(`${dst} is inside ${src}`);
  }
  const root = canSwitchIds();
  const owned = (p, what) => {
    const st = fs.lstatSync(p);
    if (!st.isDirectory()) throw new Error(`${p} is not a plain folder (a symbolic link?)`);
    if (!root) return null;
    if (st.uid !== 0) return ownerIdentity(st.uid, st.gid);
    const bad = unsafeFolder(p);
    if (bad) throw new Error(`${what} ${p} belongs to root, but ${bad.dir} can be changed by an account other than root (${bad.why})`);
    return null;
  };
  const srcId = owned(src, 'the old state folder');
  const dstId = owned(dst, 'the state folder');
  const items = [], skipped = [];
  let total = 0, count = 0;
  // read, as src's owner (as root: folders another account controls are skipped)
  asOwner(srcId, () => {
    const walk = (rel, depth) => {
      let names;
      try { names = fs.readdirSync(rel ? path.join(src, rel) : src).sort(); }
      catch (e) { if (!rel) throw e; skipped.push(`${rel} (${e.code || e.message})`); return; }
      for (const name of names) {
        const r = rel ? path.join(rel, name) : name, p = path.join(src, r);
        if (++count > COPY_MAX_ENTRIES) throw new Error(`${src} holds more than ${COPY_MAX_ENTRIES} entries`);
        let st;
        try { st = fs.lstatSync(p); } catch (e) { skipped.push(`${r} (${e.code || e.message})`); continue; }
        if (st.isDirectory()) {
          if (depth >= COPY_MAX_DEPTH) { skipped.push(`${r} (too deep)`); continue; }
          if (root && !srcId && (st.uid !== 0 || ((st.mode & 0o022) && !(st.mode & 0o1000)))) { skipped.push(`${r} (another account can change it)`); continue; }
          items.push({ rel: r, dir: true });
          walk(r, depth + 1);
        } else if (st.isFile()) {
          let buf;
          try { buf = readPlainFileSync(p, maxBytes - total); }
          catch (e) {
            if (e.code === 'ETOOBIG') throw new Error(`${src} holds more than ${maxBytes >= 1048576 ? Math.round(maxBytes / 1048576) + ' MiB' : maxBytes + ' bytes'}`);
            skipped.push(`${r} (${e.code === 'ELOOP' ? 'a symbolic link' : e.code === 'ENOTPLAIN' ? 'not a plain file' : e.code || e.message})`);
            continue;
          }
          total += buf.length;
          items.push({ rel: r, data: buf });
        } else skipped.push(`${r} (${st.isSymbolicLink() ? 'a symbolic link' : 'not a plain file'})`);
      }
    };
    walk('', 0);
  });
  if (!items.some((it) => it.rel === 'state.json' && it.data)) throw new Error(`${path.join(src, 'state.json')} could not be read as a plain file`);
  // write, as dst's owner
  let files = 0, dirs = 0, wroteState = false;
  const blocked = [];
  asOwner(dstId, () => {
    for (const it of items) {
      if (blocked.some((b) => it.rel.startsWith(b + path.sep))) continue;
      const p = path.join(dst, it.rel);
      if (it.dir) {
        try { fs.mkdirSync(p, { mode: 0o700 }); dirs++; continue; }
        catch (e) {
          let st = null;
          if (e.code === 'EEXIST') { try { st = fs.lstatSync(p); } catch { } }
          if (st && st.isDirectory()) continue;   // already there: fill it in
          blocked.push(it.rel);
          skipped.push(`${it.rel} (${st ? 'something that is not a folder is already there' : e.code || e.message})`);
        }
        continue;
      }
      let fd;
      try { fd = fs.openSync(p, C.O_WRONLY | C.O_CREAT | C.O_EXCL | (C.O_NOFOLLOW || 0), 0o600); }
      catch (e) { skipped.push(`${it.rel} (${e.code === 'EEXIST' ? 'already there, kept' : e.code || e.message})`); continue; }
      try {
        let off = 0;
        while (off < it.data.length) off += fs.writeSync(fd, it.data, off, it.data.length - off);
      } finally { fs.closeSync(fd); }
      files++;
      if (it.rel === 'state.json') wroteState = true;
    }
  });
  if (!wroteState) throw new Error(`state.json could not be written in ${dst} (${(skipped.find((s) => s.startsWith('state.json (')) || '').slice(12, -1) || 'unknown'})`);
  return { files, dirs, skipped };
}

/* Where an edit of bitcoin.conf really lands. A symlinked bitcoin.conf is
   followed to the real file (operators do that on purpose); the edit then
   runs as that file's owner (a new file: as the owner of the folder it goes
   in), so a link planted by another account cannot aim root at a file of its
   choosing. A root-owned file is edited as root only when no other account
   can change a folder above it. */
function confTarget(confPath) {
  const abs = path.resolve(confPath);
  let real = null, st = null;
  try { real = fs.realpathSync(abs); st = fs.statSync(real); }
  catch (e) {
    if (e.code !== 'ENOENT') throw new Error(`cannot read ${confPath} (${e.code || e.message})`);
    let link = false;
    try { link = fs.lstatSync(abs).isSymbolicLink(); } catch { }
    if (link) throw new Error(`refusing to edit ${confPath}: it is a link to a file that does not exist`);
  }
  if (st) {
    if (!st.isFile()) throw new Error(`refusing to edit ${confPath}: it is not a regular file`);
    return { real, exists: true, uid: st.uid, gid: st.gid, folder: path.dirname(real) };
  }
  // a new file: the nearest folder that exists decides
  const rest = [path.basename(abs)];
  let dir = path.dirname(abs);
  for (;;) {
    let rd = null, ds = null;
    try { rd = fs.realpathSync(dir); ds = fs.statSync(rd); }
    catch (e) { if (e.code !== 'ENOENT') throw new Error(`cannot create ${confPath} (${e.code || e.message})`); }
    if (ds) {
      if (!ds.isDirectory()) throw new Error(`cannot create ${confPath}: ${dir} is not a folder`);
      return { real: path.join(rd, ...rest), exists: false, uid: ds.uid, gid: ds.gid, folder: rd };
    }
    rest.unshift(path.basename(dir));
    const up = path.dirname(dir);
    if (up === dir) throw new Error(`cannot create ${confPath}: no folder above it exists`);
    dir = up;
  }
}
/* editConf(confPath, compute, opts): the read-modify-write behind
   setUaComment and setRpcAccess. compute(buf) gets the file's bytes (null
   when there is no file) and returns { result } when nothing changes, or
   { out, result } with the new text. The file is read and rewritten through
   one descriptor, in place (it keeps its inode, owner, mode and ACLs), as its
   owner. The first change keeps a one-time copy beside the real file
   (created with O_EXCL, so never through a link). A new file is created 0600
   (O_EXCL); when root creates it, it is handed to opts.owner. */
function editConf(confPath, compute, opts = {}) {
  const C = fs.constants;
  const tgt = confTarget(confPath);
  let fresh = null;
  if (!tgt.exists) {
    fresh = compute(null);
    if (fresh.out == null) return fresh.result;
  }
  const root = canSwitchIds();
  if (root && tgt.uid === 0) {
    const bad = unsafeFolder(tgt.folder);
    if (bad) throw new Error(`refusing to edit ${confPath} as root: ${bad.dir} can be changed by an account other than root (${bad.why}). Add the lines by hand.`);
  }
  const id = root && tgt.uid !== 0 ? ownerIdentity(tgt.uid, tgt.gid) : null;
  return asOwner(id, () => {
    if (!tgt.exists) {
      const r = fresh;
      fs.mkdirSync(path.dirname(tgt.real), { recursive: true });
      let fd;
      try { fd = fs.openSync(tgt.real, C.O_WRONLY | C.O_CREAT | C.O_EXCL | (C.O_NOFOLLOW || 0), 0o600); }
      catch (e) { throw new Error(`cannot create ${confPath} (${e.code || e.message})`); }
      try {
        fs.writeSync(fd, r.out);
        if (root && !id && opts.owner) { try { fs.fchownSync(fd, opts.owner.uid, opts.owner.gid); } catch { } }
      } finally { fs.closeSync(fd); }
      return r.result;
    }
    let fd, writeErr = null;
    try { fd = fs.openSync(tgt.real, C.O_RDWR | (C.O_NOFOLLOW || 0) | (C.O_NONBLOCK || 0)); }
    catch (e) {
      if (!['EACCES', 'EPERM', 'EROFS', 'EBUSY'].includes(e.code)) throw new Error(`cannot read ${confPath} (${e.code || e.message})`);
      writeErr = e;   // readable but not writable: fine while nothing changes
      try { fd = fs.openSync(tgt.real, C.O_RDONLY | (C.O_NOFOLLOW || 0) | (C.O_NONBLOCK || 0)); }
      catch (e2) { throw new Error(`cannot read ${confPath} (${e2.code || e2.message})`); }
    }
    try {
      let buf;
      try { buf = readFd(fd, path.basename(confPath), CONF_MAX_BYTES + 1); }
      catch (e) {
        if (e.code === 'ENOTPLAIN') throw new Error(`refusing to edit ${confPath}: it is not a regular file`);
        if (e.code === 'ETOOBIG') throw new Error(`refusing to edit ${confPath}: it is larger than 1 MB. Add the lines by hand.`);
        throw new Error(`cannot read ${confPath} (${e.code || e.message})`);
      }
      const r = compute(buf);
      if (r.out == null) return r.result;
      if (writeErr) throw new Error(`cannot write ${confPath} (${writeErr.code})`);
      const backup = tgt.real + BACKUP_SUFFIX;
      let madeBackup = false;
      try { fs.writeFileSync(backup, buf, { mode: 0o600, flag: 'wx' }); madeBackup = true; }
      catch (e) { if (e.code !== 'EEXIST') r.result.backupError = e.code || e.message; }   // EEXIST: kept once already
      const out = Buffer.from(r.out, 'utf8');
      fs.ftruncateSync(fd, 0);
      let off = 0;
      while (off < out.length) off += fs.writeSync(fd, out, off, out.length - off, off);
      r.result.backup = madeBackup ? backup : null;
      return r.result;
    } finally { fs.closeSync(fd); }
  });
}

/* setUaComment: add or remove a top-level `uacomment=nodesignal` line.
   - idempotent; everything else in the file is preserved byte for byte
   - the first change keeps a one-time copy as bitcoin.conf.nodesignal-backup
   - a file we cannot parse with confidence is left alone (throws)
   - never restarts bitcoind; the caller tells the operator to do it
   - as root, the edit runs as the file's owner (editConf)
   opts.owner = { uid, gid } sets ownership of a file root creates (Linux). */
function setUaComment(confPath, on, opts = {}) {
  const value = opts.value || UA_COMMENT;
  return editConf(confPath, (buf) => uaEdit(confPath, buf, on, value), opts);
}
function uaEdit(confPath, buf, on, value) {
  if (buf === null) {
    if (!on) return { result: { changed: false, created: false, path: confPath, on: false } };
    const eol = IS_WIN ? '\r\n' : '\n';
    return { out: UA_MARKER + eol + 'uacomment=' + value + eol, result: { changed: true, created: true, path: confPath, on: true } };
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
    const mine = top.find(isOurUaLine);
    if (mine && uaValueOf(mine) === value) return { result: { changed: false, path: confPath, on: true, inSection } };
    if (mine) {
      // the same line with a new value (an onion added or changed)
      const nl = mine.raw.endsWith('\r\n') ? '\r\n' : mine.raw.endsWith('\n') ? '\n' : '';
      out = a.lines.map((l) => (l === mine ? 'uacomment=' + value + nl : l.raw)).join('');
    }
    const block = UA_MARKER + a.eol + 'uacomment=' + value + a.eol;
    const raws = a.lines.map((l) => l.raw);
    if (mine) { /* replaced above */ } else if (firstSection < 0) {
      let tail = raws.join('');
      if (tail.length && !tail.endsWith('\n')) tail += a.eol;
      out = tail + block;
    } else {
      raws.splice(firstSection, 0, block + a.eol);
      out = raws.join('');
    }
  } else {
    if (!present) return { result: { changed: false, path: confPath, on: false, inSection } };
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
  // editConf writes it in place (not tmp + rename) so the file keeps its
  // inode, owner, mode, ACLs, and a symlinked bitcoin.conf stays a symlink.
  return { out, result: { changed: true, path: confPath, on, inSection } };
}

/* ------------------------------------------------------------ RPC access
   rpcauth=<user>:<salt>$<hmac> with hmac = HMAC-SHA256(key = salt as text,
   message = password), as Bitcoin Core's share/rpcauth/rpcauth.py writes it.

   rpcwhitelist subtlety: with rpcwhitelistdefault unset, the FIRST
   rpcwhitelist line makes bitcoind give every other RPC user (the cookie
   user bitcoin-cli relies on, Electrs, mempool...) an empty whitelist,
   locking them out. So when bitcoin.conf has no whitelist settings of its
   own we also write rpcwhitelistdefault=0, which keeps every other user
   exactly as before. If the operator already uses whitelists at the top
   level, their rpcwhitelistdefault choice is left alone.
   bitcoind's rule is rpcwhitelistdefault = (is any rpcwhitelist set), over
   bitcoin.conf, its includeconf files and its command line, per chain. So
   when whitelists may be set where this file does not show them (an
   includeconf line, an -rpcwhitelist option of the running bitcoind) or for
   one chain only (a [section], or a "main." prefix), either choice can be
   wrong: rpcwhitelistdefault=0 would give unlisted users every method, and
   leaving it out would lock them out of a chain. Then nothing is written
   and the operator adds the lines by hand. */
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
   confidence is refused (throws), as is a whitelist we would weaken. As
   root, the edit runs as the file's owner (editConf). opts.cmdlineWhitelist:
   the running bitcoind has an -rpcwhitelist* option (refused, see above).
   Returns { changed, created, path, on, backup, lines }. */
function setRpcAccess(confPath, password, opts = {}) {
  return editConf(confPath, (buf) => rpcEdit(confPath, buf, password, opts), opts);
}
function rpcEdit(confPath, buf, password, rpcOpts = {}) {
  const on = password != null;
  const a = buf === null ? { ok: true, text: '', lines: [], eol: IS_WIN ? '\r\n' : '\n' } : analyzeConf(buf);
  if (!a.ok) throw new Error(`refusing to edit ${confPath}: ${a.error}. Add the NodeSignal lines by hand (nodesignal rpc-access show).`);
  const blk = findRpcBlock(a.lines);
  if (blk && blk.end === null) throw new Error(`refusing to edit ${confPath}: it has a "${RPC_BEGIN.slice(0, 30)}..." line with no end marker. Fix it by hand.`);
  const outside = a.lines.filter((l, i) => !blk || i < blk.begin || i > blk.end);

  if (on) {
    const cur = blk ? a.lines.slice(blk.begin + 1, blk.end).map((l) => l.body) : [];
    const auth = cur.find((x) => /^\s*rpcauth\s*=/.test(x));
    if (blk && rpcAuthMatches(auth, RPC_USER, password)) return { result: { changed: false, path: confPath, on: true, lines: cur } };
  } else if (!blk) return { result: { changed: false, path: confPath, on: false } };

  let block = '';
  let inner = [];
  if (on) {
    // Each of their lines: its option name (a "main." style chain prefix
    // and a "no" negation taken off) and whether it applies to one chain only.
    let inSection = false;
    const theirs = [];
    a.lines.forEach((l, i) => {
      if (l.kind === 'section') inSection = true;
      if (l.kind !== 'kv' || (blk && i >= blk.begin && i <= blk.end)) return;
      const key = KV_RE.exec(l.body)[1].toLowerCase();
      const dot = key.lastIndexOf('.');
      theirs.push({ name: key.slice(dot + 1).replace(/^no(?=rpcwhitelist|includeconf)/, ''), oneChain: inSection || dot >= 0 });
    });
    const isWl = (o) => o.name === 'rpcwhitelist' || o.name === 'rpcwhitelistdefault';
    const why = [];
    if (theirs.some((o) => o.name === 'includeconf')) why.push('it reads other files (includeconf), which may set rpcwhitelist');
    if (theirs.some((o) => isWl(o) && o.oneChain)) why.push('it sets rpcwhitelist or rpcwhitelistdefault for one chain only (in a [section])');
    if (rpcOpts.cmdlineWhitelist) why.push('the running bitcoind has an -rpcwhitelist option on its command line');
    if (why.length) {
      throw new Error(`refusing to edit ${confPath}: ${why.join('; ')}. NodeSignal's rpcwhitelist line changes what every other RPC user may call unless rpcwhitelistdefault is set to match, and NodeSignal cannot see or place that setting safely here. Add the NodeSignal lines by hand.`);
    }
    const theirWhitelist = theirs.some(isWl);
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
  if (buf === null) return { out, result: { changed: true, created: true, path: confPath, on, lines: inner } };
  return { out, result: { changed: true, created: false, path: confPath, on, lines: inner } };   // in place: keeps inode, owner, mode
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
  replaceFile(rpcRecordPath(cfgPath), confPath + '\n', 0o644);
}
/* installRpcAccess: the whole job, shared by Linux setup, "nodesignal
   rpc-access add" and the Windows installer. Ensures NodeSignal's login in
   cfg (the caller writes cfg when cfgChanged), writes the matching block into
   confPath and records which file holds it. P maps a real path to a test
   root. cmdlineWhitelist: whether the running bitcoind has an -rpcwhitelist*
   option (detectBitcoinNode's rpcWhitelistOnCmdline); when the caller does
   not say, Linux looks at the running bitcoind itself.
   Returns { cfgChanged, result } (result from setRpcAccess). */
function installRpcAccess({ cfg, cfgPath, confPath, owner = null, P = (x) => x, cmdlineWhitelist = null }) {
  const cfgChanged = ensureRpcLogin(cfg);
  if (cmdlineWhitelist === null) cmdlineWhitelist = process.platform === 'linux' && linuxProcesses().some((p) => p.rpcWhitelistArgs);
  const result = setRpcAccess(P(confPath), cfg['rpc-pass'], { owner, cmdlineWhitelist });
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
  try { const st = fs.lstatSync(file); if (!st.isSymbolicLink()) owner = owner || { uid: st.uid, gid: st.gid }; } catch { }
  replaceFile(file, JSON.stringify(obj, null, 2) + '\n', 0o600, owner);
  return IS_WIN ? lockDownFile(file) : true;
}
/* replaceFile: write a new file under a fresh random name opened with O_EXCL
   (so never an existing file or a link someone left in the folder), set its
   owner and mode on the open descriptor, then rename it over `file`. Root
   uses this for files beside the config, which a from-source install keeps
   in a folder its user owns. */
function replaceFile(file, data, mode, owner = null) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  const fd = fs.openSync(tmp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), mode);
  try {
    fs.writeSync(fd, data);
    if (!IS_WIN) {
      if (owner && typeof process.getuid === 'function' && process.getuid() === 0) { try { fs.fchownSync(fd, owner.uid, owner.gid); } catch { } }
      fs.fchmodSync(fd, mode);
    }
  } catch (e) { fs.closeSync(fd); try { fs.unlinkSync(tmp); } catch { } throw e; }
  fs.closeSync(fd);
  fs.renameSync(tmp, file);
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
function readGroups(root = '') {
  const groups = [];
  try {
    for (const line of fs.readFileSync(path.join(root || '/', 'etc', 'group'), 'utf8').split('\n')) {
      const p = line.split(':');
      if (p.length < 4 || !p[0]) continue;
      groups.push({ name: p[0], gid: Number(p[2]), members: p[3].trim() ? p[3].trim().split(',') : [] });
    }
  } catch { }
  return groups;
}
/* Add user to, or remove it from, a supplementary group (root): usermod and
   gpasswd. With root set (tests), that fake root's etc/group is edited
   instead, so a test never changes the machine it runs on. */
function setGroupMember(user, group, on, { root = '' } = {}) {
  if (root) {
    const f = path.join(root, 'etc', 'group');
    const lines = fs.readFileSync(f, 'utf8').split('\n').map((l) => {
      const p = l.split(':');
      if (p.length < 4 || p[0] !== group) return l;
      const m = p[3].trim() ? p[3].trim().split(',') : [];
      p[3] = (on ? [...new Set([...m, user])] : m.filter((x) => x !== user)).join(',');
      return p.join(':');
    });
    fs.writeFileSync(f, lines.join('\n'));
    return;
  }
  if (on) execFileSync('usermod', ['-a', '-G', group, user], { stdio: 'ignore', timeout: 30000 });
  else execFileSync('gpasswd', ['-d', user, group], { stdio: 'ignore', timeout: 30000 });
}

/* ------------------------------------------------------------ node detection */
const DATADIR_MARKERS = ['blocks', 'chainstate', 'bitcoin.conf', '.cookie', 'settings.json', 'peers.dat', 'debug.log', 'wallets'];
const PROC_NAMES = new Set(['bitcoind', 'bitcoin-qt', 'bitcoin-node', 'bitcoin-gui']);
const WIN_IMAGES = new Set(['bitcoind.exe', 'bitcoin-qt.exe', 'bitcoin-node.exe', 'bitcoin-gui.exe']);
const CHAIN_SUBDIR = { main: '', test: 'testnet3', testnet4: 'testnet4', signet: 'signet', regtest: 'regtest' };
const CHAIN_PORT = { main: 8332, test: 18332, testnet4: 48332, signet: 38332, regtest: 18443 };
const SYSTEM_DATADIRS = ['/var/lib/bitcoind', '/var/lib/bitcoin'];

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
    // Any account can start a program called bitcoind. One installed by root
    // (owned by root, writable by nobody else) is "trusted"; null when this
    // account may not look (another user's process, not running as root).
    let exeTrusted = null;
    try {
      const st = fs.statSync(path.join(procDir, pid, 'exe'));
      exeTrusted = st.isFile() && st.uid === 0 && !(st.mode & 0o022);
    } catch (e) { if (e.code !== 'EACCES' && e.code !== 'EPERM' && e.code !== 'ENOENT') exeTrusted = false; }
    // -rpcwhitelist, -rpcwhitelistdefault and their -no forms: setRpcAccess
    // cannot tell from bitcoin.conf alone what rpcwhitelistdefault will be
    const rpcWhitelistArgs = args.slice(1).some((a) => /^--?(no)?rpcwhitelist/i.test(a));
    out.push({ pid: Number(pid), name: comm, uid, exeTrusted, datadir: argValue(args, 'datadir'), conf: argValue(args, 'conf'), rpcWhitelistArgs });
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

/* Any local account can run a process named bitcoind with -conf= and
   -datadir= of its own, and setup would then edit that file and point
   NodeSignal at that "node". So: when a node runs from a program root
   installed, processes running another program are ignored; and a -conf or
   -datadir that belongs to neither root nor the process's own user is
   ignored. Each is noted in how (lines starting "ignored"). */
function trustedProcesses(processes, R, how) {
  let list = processes;
  if (list.some((p) => p.exeTrusted === true)) {
    list = list.filter((p) => {
      if (p.exeTrusted !== false) return true;
      how.push(`ignored ${p.name} (pid ${p.pid}): its program is not a root-owned file that only root can change, and another node's is`);
      return false;
    });
  }
  return list.map((p) => {
    const q = Object.assign({}, p);
    for (const k of ['conf', 'datadir']) {
      if (!q[k]) continue;
      let st = null;
      try { st = fs.statSync(R(q[k])); } catch { }
      if (st && st.uid !== 0 && st.uid !== q.uid) {
        how.push(`ignored -${k}=${q[k]} of ${q.name} (pid ${q.pid}): it belongs to uid ${st.uid}, neither root nor the node's user`);
        q[k] = '';
      }
    }
    return q;
  });
}

/* detectBitcoinNode: is a Bitcoin node (Core or Knots) installed here, and
   where does it keep its data? Never throws.
   Returns { installed, datadirs, datadir, confPath, cookiePath, chain,
             rpcUrl, rpcconnectIgnored, owner, running, processes, binaries,
             how, rpcWhitelistOnCmdline }. rpcUrl is always on this machine.
   opts.root lets tests point the Linux scan at a fake filesystem. */
async function detectBitcoinNode(opts = {}) {
  const platform = opts.platform || process.platform;
  const root = opts.root || '';
  const R = (p) => (root ? path.join(root, p) : p);
  const env = opts.env || process.env;
  const how = [], ignored = [];

  let processes = [];
  try { processes = platform === 'win32' ? await windowsProcesses() : (platform === 'linux' ? linuxProcesses(root) : []); }
  catch { processes = []; }
  if (platform === 'linux') processes = trustedProcesses(processes, R, ignored);

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
  // Prefer the datadir a running node uses, then one holding a chain. With
  // no node running, a system datadir comes first: only root can make a
  // folder in /var/lib, while any account can make a ~/.bitcoin with blocks/
  // and a .cookie, and setup would then edit that account's bitcoin.conf.
  datadirs.sort((a, b) => score(b) - score(a));
  function score(d) {
    let s = 0;
    if (processes.some((p) => p.datadir && samePath(p.datadir, d, platform))) s += 4;
    else if (!processes.length && isSystemDatadir(d)) s += 8;
    if (isDir(R(path.join(d, 'blocks')))) s += 2;
    if (isFile(R(path.join(d, '.cookie')))) s += 1;
    return s;
  }
  // /var/lib/bitcoind or /var/lib/bitcoin, in a folder only root can change
  // (when we are root and can tell)
  function isSystemDatadir(d) {
    if (platform !== 'linux' || !SYSTEM_DATADIRS.includes(path.posix.resolve(d))) return false;
    return !(canSwitchIds() && unsafeFolder(R(path.dirname(d))));
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
  const confPort = (conf && Number(conf.rpcport)) || CHAIN_PORT[chain];
  let host = '127.0.0.1', port = confPort, rpcconnectIgnored = null;
  // rpcconnect=host or host:port (rpcport wins over its port, as in
  // bitcoin-cli). Only this machine: setup writes the result as rpc-url, and
  // NodeSignal sends its RPC login there. A bitcoin.conf can belong to any
  // account, so a remote host in it would carry that login off the machine.
  if (conf && conf.rpcconnect) {
    const hp = splitHostPort(conf.rpcconnect);
    if (isLoopbackHost(hp.host)) {
      host = hp.host.replace(/^\[|\]$/g, '');
      if (hp.port && !(conf && Number(conf.rpcport))) port = hp.port;
    } else rpcconnectIgnored = conf.rpcconnect;
  }
  const rpcUrl = `http://${host.includes(':') ? '[' + host + ']' : host}:${port}`;
  if (rpcconnectIgnored !== null) {
    ignored.push(`ignored rpcconnect=${String(rpcconnectIgnored).replace(/[^\x20-\x7e]/g, '?')} in ${confPath}: it is not this machine, so NodeSignal uses ${rpcUrl} and never sends its RPC login elsewhere by itself (for a node on another machine, set rpc-url in NodeSignal's config by hand)`);
  }
  // The daemon applies rpcport= from bitcoin.conf by itself, but knows nothing
  // of test chains or rpcconnect=, so only then must installers write rpc-url.
  const rpcUrlNeeded = host !== '127.0.0.1' || port !== confPort || !!(chain !== 'main' && !(conf && conf.rpcport));

  const binaries = platform === 'win32' ? windowsBinaries(env) : (platform === 'linux' ? linuxBinaries(root) : []);
  for (const d of datadirs) how.push(`data directory ${d}`);
  if (confPath) how.push(`config ${confPath}`);
  for (const b of binaries) how.push(`program ${b}`);
  how.push(...ignored);

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
    datadirs, datadir, confPath, cookiePath, chain, rpcUrl, rpcUrlNeeded, rpcconnectIgnored, owner,
    running: processes.length > 0, processes, binaries, how,
    rpcWhitelistOnCmdline: processes.some((p) => p.rpcWhitelistArgs),
  };
}
// "host", "host:port", "[v6]" or "[v6]:port"; a bare IPv6 address has no port
function splitHostPort(s) {
  s = String(s).trim();
  let m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (m) return { host: m[1], port: m[2] ? Number(m[2]) : null };
  m = /^([^:]+):(\d+)$/.exec(s);
  if (m) return { host: m[1], port: Number(m[2]) };
  return { host: s, port: null };
}
// 127.0.0.0/8, ::1 (and IPv4-mapped 127/8) or localhost; never a name DNS answers
function isLoopbackHost(h) {
  h = String(h || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost') return true;
  if (net.isIPv4(h)) return h.split('.')[0] === '127';
  if (!net.isIPv6(h)) return false;
  let n;
  try { n = new URL(`http://[${h}]/`).hostname; } catch { return false; }
  return n === '[::1]' || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(n);
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
/* ------------------------------------------------------------ terminal look
   Colour for the installers' console. On a terminal only: never in a pipe,
   a log or CI. NO_COLOR turns it off, FORCE_COLOR on. Windows 10 and 11
   consoles understand these codes (Node passes them through, or translates
   them on an older console). 24-bit colour where the console reports it
   (Windows Terminal, recent conhost), else the nearest of the 16 basic
   colours. With colour on, every symbol is from WGL4, the set Consolas and
   the other console fonts carry; with it off, the output is plain ASCII. */
const PALETTE = {
  //       24-bit          16 colours
  orange: ['247;147;26', '33'],    // the map's colours: Bitcoin Core
  green: ['34;169;90', '32'],      // Knots
  cyan: ['77;210;255', '96'],      // btcd
  violet: ['180;140;255', '95'],   // libbitcoin
  pink: ['255;122;184', '35'],     // Bcoin
  yellow: ['255;214;10', '93'],
  red: ['255;85;85', '91'],
  gray: ['138;147;166', '90'],
  white: ['236;240;245', '97'],
};
const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;
function termStyle(stream = process.stdout, env = process.env) {
  const on = env.NO_COLOR ? false : (env.FORCE_COLOR && env.FORCE_COLOR !== '0') ? true : !!(stream && stream.isTTY);
  let depth = 4;
  try { if (on && stream && typeof stream.getColorDepth === 'function') depth = stream.getColorDepth(env); } catch { }
  if (on && env.FORCE_COLOR === '3') depth = 24;   // Node's convention: 3 means 24-bit
  const rich = on && depth >= 24;
  const sgr = (code, s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const fgCode = (name) => (rich ? '38;2;' + PALETTE[name][0] : PALETTE[name][1]);
  const t = {
    on, rich,
    // a colour by name, optionally bold
    fg: (name, s, bold) => sgr((bold ? '1;' : '') + fgCode(name), s),
    // dark text on a colour: labels and title bars
    bg: (name, s) => sgr(rich ? `1;48;2;${PALETTE[name][0]};38;2;14;16;22` : `1;${Number(PALETTE[name][1]) + 10};30`, s),
    bold: (s) => sgr('1', s),
    // one colour per character, blended between the stops (24-bit), or
    // stepping through them (16 colours)
    gradient(text, stops) {
      if (!on) return text;
      const chars = [...text], n = Math.max(1, chars.length - 1);
      return chars.map((ch, i) => {
        if (ch === ' ') return ch;
        const f = (i / n) * (stops.length - 1), k = Math.min(stops.length - 2, Math.floor(f));
        if (!rich) return sgr('1;' + PALETTE[stops[Math.round(f)]][1], ch);
        const a = PALETTE[stops[k]][0].split(';').map(Number), b = PALETTE[stops[k + 1]][0].split(';').map(Number);
        const mix = a.map((v, j) => Math.round(v + (b[j] - v) * (f - k)));
        return sgr('1;38;2;' + mix.join(';'), ch);
      }).join('');
    },
    strip: (s) => String(s).replace(ANSI_RE, ''),
    width: (s) => [...String(s).replace(ANSI_RE, '')].length,
    sym: on
      ? { ok: '\u221a', warn: '!', bad: '\u00d7', step: '\u25ba', dot: '\u25cf', ask: '?', rule: '\u2500' }
      : { ok: '-', warn: '-', bad: '-', step: '-', dot: '*', ask: '', rule: '-' },
  };
  // word wrap to a width, keeping words whole (a path longer than the width
  // gets a line of its own)
  t.wrap = (text, width) => {
    const out = [];
    for (const para of String(text).split('\n')) {
      let line = '';
      for (const word of para.split(' ')) {
        if (line && t.width(line) + 1 + t.width(word) > width) { out.push(line); line = word; }
        else line = line ? line + ' ' + word : word;
      }
      out.push(line);
    }
    return out;
  };
  // A framed panel: a title bar in the colour, then the lines; double rules
  // for the ones that must not be missed. Plain ASCII with colour off.
  t.box = (color, title, lines, width = 72, double = false) => {
    const inner = width - 4;
    const body = [];
    for (const l of lines) for (const w of t.wrap(l, inner)) body.push(w);
    if (!on) {
      const rule = '  ' + '-'.repeat(width);
      return [rule, '  ' + title, ...body.map((l) => '  ' + l), rule];
    }
    const edge = (s) => t.fg(color, s, true);
    const pad = (s) => s + ' '.repeat(Math.max(0, inner - t.width(s)));
    const [tl, tr, bl, br, h, v] = double
      ? ['\u2554', '\u2557', '\u255a', '\u255d', '\u2550', '\u2551']
      : ['\u250c', '\u2510', '\u2514', '\u2518', '\u2500', '\u2502'];
    return [
      '  ' + edge(tl + h.repeat(width - 2) + tr),
      '  ' + edge(v) + t.bg(color, ' ' + pad(title) + ' ') + edge(v),
      ...body.map((l) => '  ' + edge(v) + ' ' + pad(l) + ' ' + edge(v)),
      '  ' + edge(bl + h.repeat(width - 2) + br),
    ];
  };
  return t;
}

function createPrompter({ input = process.stdin, output = process.stdout } = {}) {
  const tty = !!input.isTTY;
  const st = termStyle(output);
  // the question bright, the default and choices dimmed, a marker in front
  const q2 = (q, hint) => st.on
    ? `  ${st.fg('cyan', st.sym.ask, true)} ${st.bold(q)} ${st.fg('gray', '[' + hint + ']')}${st.fg('cyan', ' \u25ba ', true)}`
    : `  ${q} [${hint}]: `;
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
  // A secret (a passphrase): never written back. On a terminal it is typed in
  // raw mode with no echo; piped, the line is read and the output gets only
  // the question and a newline.
  async function askSecret(q) {
    if (!tty) {
      if (!queued) await loadPiped();
      output.write(q + '\n');
      return String(queued.length ? queued.shift() : '').trim();
    }
    if (rl) { rl.close(); rl = null; }
    return new Promise((resolve) => {
      output.write(q);
      input.setRawMode(true); input.resume(); input.setEncoding('utf8');
      let buf = '';
      const onData = (d) => {
        for (const ch of d) {
          if (ch === '\r' || ch === '\n') { input.setRawMode(false); input.pause(); input.removeListener('data', onData); output.write('\n'); resolve(buf); return; }
          if (ch === '\x03') { input.setRawMode(false); output.write('\n'); process.exit(130); }
          if (ch === '\x7f' || ch === '\b') buf = buf.slice(0, -1); else buf += ch;
        }
      };
      input.on('data', onData);
    });
  }
  async function askDefault(q, dflt) {
    const a = await ask(q2(q, dflt));
    return a === '' ? dflt : a;
  }
  async function askYesNo(q, dfltYes = false) {
    for (let i = 0; i < 20; i++) {
      const a = (await ask(q2(q, dfltYes ? 'Y/n' : 'y/N'))).toLowerCase();
      if (a === '') return dfltYes;
      if (a === 'y' || a === 'yes') return true;
      if (a === 'n' || a === 'no') return false;
      output.write(st.fg('yellow', '  Please answer y or n.') + '\n');
    }
    return dfltYes;
  }
  async function pause(msg = '  Press Enter to close this window.') {
    if (!tty) return;
    await ask(st.fg('gray', msg));
  }
  function close() { if (rl) { rl.close(); rl = null; } }
  return { ask, askSecret, askDefault, askYesNo, pause, close, tty };
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
  VERSION_FALLBACK: '1.4.0',
  IS_WIN, UA_COMMENT, UA_MARKER, BACKUP_SUFFIX, OPT_IN_TEXT,
  RPC_USER, RPC_METHODS, RPC_BEGIN, RPC_END,
  generateRpcPassword, makeRpcAuth, rpcAuthMatches, rpcAccessState, setRpcAccess, nodeConfPath,
  ensureRpcLogin, rpcRecordPath, readRpcRecord, writeRpcRecord, installRpcAccess, RPC_RESTART_TEXT,
  readFileList, missingFiles,
  parseConf, readConf, analyzeConf, setUaComment, uaCommentState,
  lockDownFile, writeConfig, readConfig, chownIfRoot,
  ownerIdentity, asOwner, unsafeFolder, readPlainFileSync, replaceFileSync, editConf,
  readPasswd, userByUid, readGroups, setGroupMember,
  detectBitcoinNode, daemonDataDirs, samePath, chainOf,
  findRpcAuth, rpcCall, rpcCheck, checkNode, rpcHint,
  portFree, tailscaleAddr, httpGetJson, waitForHealth, webUrl,
  defaultConfigPath, createPrompter, termStyle, uaCommentFor,
  copyStateTree,
  linuxProcesses,
  isLoopbackHost,
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
