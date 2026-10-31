// backup.js: passphrase-encrypted backup of a NodeSignal identity
// ============================================================================
// A daemon's identity is its X25519 key, and every contact pins its
// fingerprint. Lose the key (a dead disk, a reinstall) and every contact sees
// a key change they have to accept by hand. A backup carries the key, and
// whatever else the caller puts in the payload, to a new install.
//
// The format is plain text, so it survives email, a password manager or a
// printout:
//
//   NodeSignal identity backup v1
//   <base64 of {"v":1,"kdf":{"name":"scrypt","N":..,"r":..,"p":..,"salt":..},
//               "nonce":..,"ct":..}, wrapped at 76 columns>
//
//   key = scrypt(passphrase in NFC, salt (16 bytes), 32, N = 2^17, r = 8, p = 1)
//         (the same cost as store.js: about 128 MB and a fraction of a second)
//   ct  = ChaCha20-Poly1305(key, nonce (12 bytes), JSON of the payload),
//         associated data "NodeSignal identity backup v1"
//
// Nothing in a backup is trusted before the passphrase checks out, so the KDF
// parameters are bounded first: N a power of two from 2^14 to 2^20, r from 1
// to 16, p from 1 to 4, and also at most 256 MiB of scrypt memory and four
// times the default work. Those last two matter: N = 2^20 with r = 16 is
// inside the single ranges but would ask for 2 GiB. A crafted file therefore
// cannot make the daemon allocate gigabytes or spin for minutes.
//
// What this does NOT protect, stated plainly: a weak passphrase. Anyone with
// the file can guess offline; scrypt only makes each guess cost memory and
// time. And whoever opens the backup holds the identity key, so they can pose
// as this daemon to every contact.
//
// exportBackup and importBackup block for the scrypt call. The daemon should
// use exportBackupAsync / importBackupAsync, which run it off the event loop.
//
// Node standard library only: scrypt, ChaCha20-Poly1305.
// ============================================================================
'use strict';
const crypto = require('crypto');

const VERSION = 1;
const HEADER = 'NodeSignal identity backup v1';
const AD = Buffer.from(HEADER);
const KDF = Object.freeze({ name: 'scrypt', N: 1 << 17, r: 8, p: 1 });
const MIN_PASSPHRASE = 8, MAX_PASSPHRASE = 1024;
const MAX_SCRYPT_MEM = 256 * 1024 * 1024;              // scrypt needs about 128 * N * r bytes
const MAX_SCRYPT_WORK = 4 * KDF.N * KDF.r * KDF.p;     // N * r * p
const MAX_TEXT = 64 * 1024 * 1024;
const WIDTH = 76;
const SALTLEN = 16, NONCELEN = 12, TAGLEN = 16;

const err = (code, message) => Object.assign(new Error(message), { code });
const notBackup = () => err('NOT_BACKUP', 'not a NodeSignal backup');
const damaged = () => err('DAMAGED', 'the backup is damaged or incomplete');
const wrongPassphrase = () => err('WRONG_PASSPHRASE', 'wrong passphrase, or the backup is damaged');
const unsupported = (v) => err('UNSUPPORTED_VERSION', `unsupported backup version ${v}; this build reads v${VERSION}`);

function checkPassphrase(p) {
  if (typeof p !== 'string' || [...p].length < MIN_PASSPHRASE) throw err('WEAK_PASSPHRASE', `passphrase must be at least ${MIN_PASSPHRASE} characters`);
  if (p.length > MAX_PASSPHRASE) throw err('WEAK_PASSPHRASE', 'passphrase too long');
}
// Strict base64: canonical encoding only, length checked before the regex.
function unb64(s, maxBytes) {
  if (typeof s !== 'string' || s.length === 0 || s.length % 4 || s.length > Math.ceil(maxBytes / 3) * 4) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  return b.toString('base64') === s ? b : null;
}

/** Throws BAD_KDF unless the parameters are within the safe range. -> { N, r, p } */
function checkKdf(kdf) {
  if (!kdf || typeof kdf !== 'object' || kdf.name !== 'scrypt') throw err('BAD_KDF', 'unsupported key derivation in the backup');
  const { N, r, p } = kdf;
  const ok = Number.isSafeInteger(N) && N >= 1 << 14 && N <= 1 << 20 && (N & (N - 1)) === 0
    && Number.isSafeInteger(r) && r >= 1 && r <= 16
    && Number.isSafeInteger(p) && p >= 1 && p <= 4
    && 128 * N * r <= MAX_SCRYPT_MEM && N * r * p <= MAX_SCRYPT_WORK;
  if (!ok) throw err('BAD_KDF', 'the backup asks for key derivation settings outside the safe range');
  return { N, r, p };
}
const scryptArgs = (passphrase, salt, { N, r, p }) =>
  [String(passphrase).normalize('NFC'), salt, 32, { N, r, p, maxmem: 160 * N * r + 1024 * 1024 }];

function serialise(payload) {
  let json;
  try { json = JSON.stringify(payload); } catch (e) { throw new TypeError(`backup payload must be JSON-serialisable (${e.message})`); }
  if (typeof json !== 'string') throw new TypeError('backup payload must be JSON-serialisable');
  return Buffer.from(json, 'utf8');
}

/* ---- export ---- */
function prepareExport(payload, passphrase) {
  const pt = serialise(payload);
  checkPassphrase(passphrase);
  return { pt, salt: crypto.randomBytes(SALTLEN), nonce: crypto.randomBytes(NONCELEN) };
}
function finishExport({ pt, salt, nonce }, key) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAGLEN });
  c.setAAD(AD, { plaintextLength: pt.length });
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  const doc = { v: VERSION, kdf: { ...KDF, salt: salt.toString('base64') }, nonce: nonce.toString('base64'), ct: ct.toString('base64') };
  const body = Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
  const lines = [HEADER];
  for (let i = 0; i < body.length; i += WIDTH) lines.push(body.slice(i, i + WIDTH));
  return lines.join('\n') + '\n';
}

/* ---- import ---- */
/** Everything that can be checked without the passphrase. -> { kdf, salt, nonce, ct } */
function parse(text) {
  if (Buffer.isBuffer(text)) text = text.toString('utf8');
  if (typeof text !== 'string') throw notBackup();
  if (text.length > MAX_TEXT) throw err('DAMAGED', 'the backup is too large');
  const lines = text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').trim().split('\n');
  const head = lines[0].trim();
  if (head !== HEADER) {
    const m = /^NodeSignal identity backup (v\d{1,6})$/.exec(head);
    throw m ? unsupported(m[1]) : notBackup();
  }
  const raw = unb64(lines.slice(1).join('').replace(/\s+/g, ''), MAX_TEXT);
  if (!raw) throw damaged();
  let doc;
  try { doc = JSON.parse(raw.toString('utf8')); } catch { throw damaged(); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw damaged();
  if (doc.v !== VERSION) throw Number.isSafeInteger(doc.v) ? unsupported('v' + doc.v) : damaged();
  const kdf = checkKdf(doc.kdf);
  const salt = unb64(doc.kdf.salt, 64), nonce = unb64(doc.nonce, NONCELEN), ct = unb64(doc.ct, MAX_TEXT);
  if (!salt || salt.length < SALTLEN || !nonce || nonce.length !== NONCELEN || !ct || ct.length < TAGLEN) throw damaged();
  return { kdf, salt, nonce, ct };
}
function finishImport({ nonce, ct }, key) {
  let pt;
  try {
    const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAGLEN });
    d.setAAD(AD, { plaintextLength: ct.length - TAGLEN });
    d.setAuthTag(ct.subarray(ct.length - TAGLEN));
    pt = Buffer.concat([d.update(ct.subarray(0, ct.length - TAGLEN)), d.final()]);   // final() throws on a bad tag
  } catch { throw wrongPassphrase(); }
  try { return JSON.parse(pt.toString('utf8')); } catch { throw damaged(); }
}

/** payload (any JSON-serialisable value) -> backup text. Blocks for the scrypt call. */
function exportBackup(payload, passphrase) {
  const st = prepareExport(payload, passphrase);
  return finishExport(st, crypto.scryptSync(...scryptArgs(passphrase, st.salt, KDF)));
}
/** backup text (string or Buffer) -> payload. Blocks for the scrypt call. */
function importBackup(text, passphrase) {
  const b = parse(text);
  checkPassphrase(passphrase);
  return finishImport(b, crypto.scryptSync(...scryptArgs(passphrase, b.salt, b.kdf)));
}

const scryptAsync = (args) => new Promise((resolve, reject) => crypto.scrypt(...args, (e, k) => (e ? reject(e) : resolve(k))));
/** Same as exportBackup, without blocking the event loop. */
async function exportBackupAsync(payload, passphrase) {
  const st = prepareExport(payload, passphrase);
  return finishExport(st, await scryptAsync(scryptArgs(passphrase, st.salt, KDF)));
}
/** Same as importBackup, without blocking the event loop. */
async function importBackupAsync(text, passphrase) {
  const b = parse(text);
  checkPassphrase(passphrase);
  return finishImport(b, await scryptAsync(scryptArgs(passphrase, b.salt, b.kdf)));
}

/* What an identity backup holds, built the same way by the daemon (console
   button) and by the CLI (nodesignal backup): the keys and who you know.
   Not message history: that stays on the machine (sealed, if a history
   passphrase is set). state is state.json's content, socialJson is
   social.json's (or null). */
function buildPayload(state, socialJson, { nick = '' } = {}) {
  const contacts = Object.values((state && state.contacts) || {})
    .filter((c) => c && !c.inbound && typeof c.host === 'string' && !/^(tor|mbox):/.test(c.host))
    .map((c) => ({ host: c.host, port: c.port, nick: c.nick || '', peerFp: c.peerFp || null, peerPub: c.peerPub || null,
      signPub: c.signPub || null, onion: c.onion || null, mailboxes: c.mailboxes || [], established: !!c.established, hidden: !!c.hidden }));
  const rooms = ((socialJson && socialJson.rooms) || []).filter((r) => r && r.joined && r.def).map((r) => ({ def: r.def, members: r.members || [] }));
  return {
    kind: 'nodesignal-identity', v: 1, at: Date.now(), nick,
    identity: state.identity, signKey: state.signKey || null, onionKey: state.onionKey || null,
    contacts, follows: state.follows || [], unfollows: state.unfollows || [],
    myMailboxes: (state.myMailboxes || []).map((m) => ({ host: m.host, port: m.port, fp: m.fp })),
    settings: state.settings || {}, rooms,
  };
}
/* Merge a backup into a state.json (and social.json): the keys are replaced,
   contacts and follows are added to what is there, history is kept. Returns
   { state, social, added } without writing anything. */
function mergePayload(state, socialJson, p) {
  if (!p || p.kind !== 'nodesignal-identity' || !p.identity || !p.identity.priv || !p.identity.pub) {
    const e = new Error('this backup does not hold a NodeSignal identity'); e.code = 'DAMAGED'; throw e;
  }
  const st = Object.assign({}, state || {});
  st.contacts = Object.assign({}, st.contacts || {});
  st.identity = p.identity;
  if (p.signKey) st.signKey = p.signKey;
  if (p.onionKey) st.onionKey = p.onionKey;
  let added = 0;
  for (const c of p.contacts || []) {
    if (!c || typeof c.host !== 'string' || st.contacts[c.host]) continue;
    st.contacts[c.host] = { host: c.host, port: c.port || 8788, nick: c.nick || '', msgs: [], unread: 0, lastSeen: 0, peerInfo: null,
      peerFp: c.peerFp || undefined, peerPub: c.peerPub || undefined, signPub: c.signPub || undefined, onion: c.onion || undefined,
      mailboxes: c.mailboxes || [], established: !!c.established, hidden: !!c.hidden || undefined, pinnedBy: 'backup' };
    added++;
  }
  st.follows = [...new Set([...(st.follows || []), ...(p.follows || [])])];
  st.unfollows = [...new Set([...(st.unfollows || []), ...(p.unfollows || [])])];
  if (Array.isArray(p.myMailboxes) && p.myMailboxes.length) st.myMailboxes = p.myMailboxes;
  st.settings = Object.assign({}, p.settings || {}, st.settings || {});
  const so = Object.assign({ v: 1, posts: [], rooms: [] }, socialJson || {});
  so.rooms = (so.rooms || []).slice();
  for (const r of p.rooms || []) {
    if (!r || !r.def || so.rooms.some((x) => x.def && x.def.room === r.def.room)) continue;
    so.rooms.push({ def: r.def, joined: true, members: r.members || [], msgs: [] });
  }
  return { state: st, social: so, added };
}

module.exports = {
  buildPayload, mergePayload,
  exportBackup, importBackup, exportBackupAsync, importBackupAsync,
  HEADER, VERSION, KDF, MIN_PASSPHRASE,
};
