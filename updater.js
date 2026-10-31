// updater.js: find, check and download signed NodeSignal releases.
// ============================================================================
// Installed daemons ask GitHub once a day whether a newer release exists. A
// release can be installed from the app only when it carries a manifest
// (nodesignal-release.json) listing each installer's SHA-256 and size, signed
// with an Ed25519 release key whose public key ships inside the app
// (release-keys.json). SHA256SUMS.txt is published next to the files by the
// same hands that publish the files, so it proves a download is intact, not
// that the release is genuine. Without a valid signature the app only says
// that a new version exists and points to GitHub; it never installs.
//
// Formats
//   nodesignal-release.json
//     { "name": "NodeSignal", "version": "1.4.0", "tag": "v1.4.0",
//       "date": "2026-10-31T12:00:00Z",
//       "files": { "<asset name>": { "sha256": "<64 lowercase hex>", "size": <bytes> } } }
//     Asset names: NodeSignal-Setup-windows-x64.exe, nodesignal-linux-amd64.deb,
//     nodesignal-linux-arm64.deb. No other keys, at least one file, sizes from
//     1 byte to under 300 MB.
//   nodesignal-release.json.sig
//     { "v": 1, "keyId": "<16 hex>", "sig": "<base64 Ed25519 signature over the
//       exact bytes of nodesignal-release.json>" }
//   release-keys.json
//     { "keys": [ { "id": "<16 hex>", "publicKey": "<base64 of the raw 32 bytes>",
//                   "added": "YYYY-MM-DD", "note": "..." } ] }
//   keyId = hex of the first 8 bytes of SHA-256(raw 32-byte public key).
//
// API
//   compareVersions(a, b)                        -1, 0 or 1 (leading v ignored,
//                                                a pre-release sorts below its release)
//   verifyManifest({ manifestBytes, sigBytes, trustedKeys })
//                                                { ok, signed, keyId, manifest, error }
//   checkLatest({ repo, currentVersion, trustedKeys, get })
//                                                { available, version, tag, notes, published,
//                                                  page, signed, verified, error, manifest, assets }
//   httpsGet(url, { maxBytes, timeoutMs, redirects, connect })
//                                                { status, headers, body: Buffer }
//   httpsGetStream(url, { same })                { status, headers, stream }
//   downloadVerified({ url, sha256, size, dest, getStream | get })   -> dest
//   loadTrustedKeys(file)                        [ { id, publicKey, added?, note? } ]
//   platformAsset(platform, arch)                this machine's installer name, or null
//
// Network rules: https only; GitHub's API and download hosts only, every
// redirect target checked too; certificate verification always on; every
// body capped. When a connect(host, port) is given (the daemon passes one that
// goes through Tor's SOCKS port), no DNS lookup happens here.
//
// Node.js standard library only. Requiring this file has no side effects.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const http = require('http');
const crypto = require('crypto');
const { Transform } = require('stream');

const DEFAULT_REPO = 'Connor-03/NodeSignal';
const MANIFEST_NAME = 'nodesignal-release.json';
const SIG_NAME = MANIFEST_NAME + '.sig';
const ASSETS = Object.freeze(['NodeSignal-Setup-windows-x64.exe', 'nodesignal-linux-amd64.deb', 'nodesignal-linux-arm64.deb']);
// Release files checkLatest reports in `assets`; anything else is ignored.
const RELEASE_FILES = Object.freeze([...ASSETS, MANIFEST_NAME, SIG_NAME, 'SHA256SUMS.txt']);
const ALLOWED_HOSTS = Object.freeze(['api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
const MAX_ASSET_BYTES = 300 * 1024 * 1024;   // a listed size must be below this
const MAX_META_BYTES = 64 * 1024;            // manifest, signature, release-keys.json
const MAX_API_BYTES = 1024 * 1024;           // GitHub's releases/latest answer
const MAX_NOTES_BYTES = 8 * 1024;            // release notes kept for display
const USER_AGENT = 'NodeSignal-updater';
const DEFAULT_KEYS_FILE = path.join(__dirname, 'release-keys.json');
// The version rule of .github/workflows/release.yml.
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+([.+~-][0-9A-Za-z.+~-]+)?$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const KEYID_RE = /^[0-9a-f]{16}$/;
// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
/* Tests only: lets httpsGet speak plain http to exactly 127.0.0.1. It is a
   Symbol so that no config file, environment variable or command-line flag
   can carry it: JSON has no symbols, and nothing here reads the environment. */
const TEST_ALLOW_HTTP_LOOPBACK = Symbol('updater test only: allow http://127.0.0.1');

const noop = () => {};
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
// For error messages: no control characters, bounded length.
const printable = (s, n = 80) => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, '?').slice(0, n);
const short = (e) => printable(String(e && e.message ? e.message : e).trim(), 200);

/* ---------------------------------------------------------------- versions */
// "1.4.0", "v1.4.0", "1.4.0-rc.1", "1.4.0~rc1", "1.4.0+build.5", "1.3.0.1".
// Pre-release (after - or ~) sorts below the release; build metadata is ignored.
function parseVersion(v) {
  if (typeof v !== 'string' || v.length > 64) return null;
  const m = /^[vV]?(\d{1,9}(?:\.\d{1,9}){0,3})(?:[-~]([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(v);
  if (!m) return null;
  return { nums: m[1].split('.').map(Number), pre: m[2] ? m[2].split('.') : [] };
}
function cmpNumeric(p, q) {
  p = p.replace(/^0+(?=\d)/, ''); q = q.replace(/^0+(?=\d)/, '');
  if (p.length !== q.length) return p.length < q.length ? -1 : 1;
  return p === q ? 0 : (p < q ? -1 : 1);
}
function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  if (!x) throw new TypeError(`not a version: "${printable(a, 64)}"`);
  if (!y) throw new TypeError(`not a version: "${printable(b, 64)}"`);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] || 0) - (y.nums[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  if (!x.pre.length || !y.pre.length) return x.pre.length === y.pre.length ? 0 : (x.pre.length ? -1 : 1);
  for (let i = 0; i < Math.min(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i], q = y.pre[i];
    if (p === q) continue;
    const pn = /^\d+$/.test(p), qn = /^\d+$/.test(q);
    if (pn && qn) { const c = cmpNumeric(p, q); if (c) return c; continue; }
    if (pn !== qn) return pn ? -1 : 1;   // numeric identifiers sort first
    return p < q ? -1 : 1;
  }
  return x.pre.length === y.pre.length ? 0 : (x.pre.length < y.pre.length ? -1 : 1);
}
const isPrerelease = (v) => { const p = parseVersion(v); return !!p && p.pre.length > 0; };

/* ---------------------------------------------------------------- keys */
function strictBase64(s, len) {
  if (typeof s !== 'string' || !s.length || s.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  if (b.toString('base64') !== s) return null;   // canonical encoding only
  return len == null || b.length === len ? b : null;
}
const keyIdOf = (raw) => crypto.createHash('sha256').update(raw).digest().subarray(0, 8).toString('hex');
const publicKeyFromRaw = (raw) => crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
// KeyObject (public or private) -> raw 32-byte Ed25519 public key.
function rawPublicKey(key) {
  const pub = key.type === 'private' ? crypto.createPublicKey(key) : key;
  if (pub.asymmetricKeyType !== 'ed25519') throw new Error(`not an Ed25519 key (${pub.asymmetricKeyType})`);
  const der = pub.export({ format: 'der', type: 'spki' });
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) throw new Error('unexpected Ed25519 public key encoding');
  return Buffer.from(der.subarray(12));
}
// One release-keys.json entry, checked; null when it is unusable. The id must
// be the one derived from the key, so a mislabelled entry trusts nothing.
function checkKeyEntry(e) {
  if (!isObj(e) || typeof e.id !== 'string' || !KEYID_RE.test(e.id)) return null;
  const raw = strictBase64(e.publicKey, 32);
  if (!raw || keyIdOf(raw) !== e.id) return null;
  try { publicKeyFromRaw(raw); } catch { return null; }
  if (has(e, 'added') && (typeof e.added !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(e.added))) return null;
  if (has(e, 'note') && (typeof e.note !== 'string' || e.note.length > 200)) return null;
  const out = { id: e.id, publicKey: e.publicKey };
  if (has(e, 'added')) out.added = e.added;
  if (has(e, 'note')) out.note = printable(e.note, 200);
  return out;
}
function normalizeKeys(list) {
  const out = [], seen = new Set();
  for (const e of Array.isArray(list) ? list : []) {
    const k = checkKeyEntry(e);
    if (k && !seen.has(k.id)) { seen.add(k.id); out.push(k); }
  }
  return out;
}
/* release-keys.json -> the valid entries (bad ones are dropped). A missing
   file means no trusted keys: updates are then announced, never installed.
   A file that is not { "keys": [...] } JSON is an error. */
function loadTrustedKeys(file = DEFAULT_KEYS_FILE) {
  let text;
  try {
    if (fs.statSync(file).size > MAX_META_BYTES) throw new Error(`${file}: larger than ${MAX_META_BYTES} bytes`);
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  let j;
  try { j = JSON.parse(text.replace(/^\ufeff/, '')); } catch (e) { throw new Error(`${file}: not valid JSON (${short(e)})`); }
  if (!isObj(j) || !Array.isArray(j.keys)) throw new Error(`${file}: expected { "keys": [ ... ] }`);
  return normalizeKeys(j.keys);
}

/* ---------------------------------------------------------------- manifest */
function toBuffer(b, what) {
  if (Buffer.isBuffer(b)) return b;
  if (b instanceof Uint8Array) return Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  if (typeof b === 'string') return Buffer.from(b, 'utf8');
  throw new Error(`${what}: no data`);
}
function strictJson(bytes, what) {
  if (bytes.length > MAX_META_BYTES) throw new Error(`${what}: larger than ${MAX_META_BYTES} bytes`);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new Error(`${what}: not UTF-8`); }
  try { return JSON.parse(text); } catch { throw new Error(`${what}: not valid JSON`); }
}
function exactKeys(o, keys, what) {
  for (const k of Object.keys(o)) if (!keys.includes(k)) throw new Error(`${what}: unexpected field "${printable(k, 40)}"`);
  for (const k of keys) if (!has(o, k)) throw new Error(`${what}: missing "${k}"`);
}
// A parsed manifest object -> a clean copy, or throws with the reason.
function checkManifest(m) {
  if (!isObj(m)) throw new Error('manifest: not a JSON object');
  exactKeys(m, ['name', 'version', 'tag', 'date', 'files'], 'manifest');
  if (m.name !== 'NodeSignal') throw new Error('manifest: name is not "NodeSignal"');
  if (typeof m.version !== 'string' || !VERSION_RE.test(m.version) || !parseVersion(m.version)) throw new Error('manifest: version is not a version number');
  if (m.tag !== 'v' + m.version) throw new Error('manifest: tag is not "v" + version');
  if (typeof m.date !== 'string' || !ISO_RE.test(m.date) || Number.isNaN(Date.parse(m.date))) throw new Error('manifest: date is not an ISO-8601 time');
  if (!isObj(m.files)) throw new Error('manifest: files is not an object');
  const names = Object.keys(m.files);
  if (!names.length) throw new Error('manifest: lists no files');
  const files = {};
  for (const n of names) {
    if (!ASSETS.includes(n)) throw new Error(`manifest: unexpected file name "${printable(n, 60)}"`);
    const f = m.files[n];
    if (!isObj(f)) throw new Error(`manifest: entry for ${n} is not an object`);
    exactKeys(f, ['sha256', 'size'], `manifest: ${n}`);
    if (typeof f.sha256 !== 'string' || !HEX64_RE.test(f.sha256)) throw new Error(`manifest: sha256 of ${n} is not 64 lowercase hex characters`);
    if (!Number.isSafeInteger(f.size) || f.size <= 0 || f.size >= MAX_ASSET_BYTES) throw new Error(`manifest: size of ${n} is not a whole number of bytes from 1 to under 300 MB`);
    files[n] = { sha256: f.sha256, size: f.size };
  }
  return { name: m.name, version: m.version, tag: m.tag, date: m.date, files };
}
const parseManifest = (bytes) => checkManifest(strictJson(toBuffer(bytes, 'manifest'), 'manifest'));
function parseSig(bytes) {
  const s = strictJson(toBuffer(bytes, 'signature'), 'signature');
  if (!isObj(s)) throw new Error('signature: not a JSON object');
  exactKeys(s, ['v', 'keyId', 'sig'], 'signature');
  if (s.v !== 1) throw new Error('signature: unknown format version');
  if (typeof s.keyId !== 'string' || !KEYID_RE.test(s.keyId)) throw new Error('signature: keyId is not 16 hex characters');
  const sig = strictBase64(s.sig, 64);
  if (!sig) throw new Error('signature: sig is not a base64 Ed25519 signature');
  return { keyId: s.keyId, sig };
}
/* ok only when the signature file names a trusted key, that key signed these
   exact manifest bytes, and the manifest has the expected shape. `manifest`
   is set only when ok, so nothing unverified can be installed by mistake. */
function verifyManifest({ manifestBytes, sigBytes = null, trustedKeys = [] } = {}) {
  const r = { ok: false, signed: sigBytes != null, keyId: null, manifest: null, error: null };
  let mb;
  try {
    mb = toBuffer(manifestBytes, 'manifest');
    if (mb.length > MAX_META_BYTES) throw new Error(`manifest: larger than ${MAX_META_BYTES} bytes`);
  } catch (e) { r.error = e.message; return r; }
  if (!r.signed) { r.error = `the release has no signature (${SIG_NAME})`; return r; }
  let s;
  try { s = parseSig(sigBytes); } catch (e) { r.error = e.message; return r; }
  r.keyId = s.keyId;
  const key = normalizeKeys(trustedKeys).find((k) => k.id === s.keyId);
  if (!key) { r.error = `signed with key ${s.keyId}, which this installation does not trust`; return r; }
  let good = false;
  try { good = crypto.verify(null, mb, publicKeyFromRaw(Buffer.from(key.publicKey, 'base64')), s.sig); } catch { good = false; }
  if (!good) { r.error = `the signature does not match the manifest (key ${s.keyId})`; return r; }
  try { r.manifest = parseManifest(mb); } catch (e) { r.error = e.message; return r; }
  r.ok = true;
  return r;
}

/* ---------------------------------------------------------------- GitHub */
// Release notes for display: no control or direction-changing characters,
// well-formed UTF-16, at most MAX_NOTES_BYTES of UTF-8.
function cleanNotes(body) {
  if (typeof body !== 'string') return '';
  let s = body.replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]/g, '')
    .replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd');
  const b = Buffer.from(s, 'utf8');
  if (b.length > MAX_NOTES_BYTES) {
    let end = MAX_NOTES_BYTES;
    while (end > 0 && (b[end] & 0xc0) === 0x80) end--;   // never cut inside a character
    s = b.subarray(0, end).toString('utf8');
  }
  return s;
}
async function fetchSmall(get, url, what) {
  const res = await get(url, { maxBytes: MAX_META_BYTES });
  if (!res || res.status !== 200) throw new Error(`${what}: HTTP ${res && res.status}`);
  const body = toBuffer(res.body, what);
  if (body.length > MAX_META_BYTES) throw new Error(`${what}: larger than ${MAX_META_BYTES} bytes`);
  return body;
}
/* Ask GitHub for the latest release. Never throws for network or GitHub
   trouble (that goes in `error`); throws only for a bad currentVersion or
   repo, which are programming mistakes. The manifest and its signature are
   fetched only when the release is newer. `manifest` is set only when
   verified. */
async function checkLatest({ repo = DEFAULT_REPO, currentVersion, trustedKeys = [], get = httpsGet } = {}) {
  if (!parseVersion(currentVersion)) throw new TypeError('checkLatest: currentVersion is not a version');
  if (typeof repo !== 'string' || !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(repo)) throw new TypeError('checkLatest: repo must be "owner/name"');
  const r = { available: false, version: null, tag: null, notes: '', published: null, page: null,
    signed: false, verified: false, error: null, manifest: null, assets: {} };
  let rel;
  try {
    const res = await get(`https://api.github.com/repos/${repo}/releases/latest`, { maxBytes: MAX_API_BYTES, accept: 'application/vnd.github+json' });
    if (!res || res.status === 404) { r.error = 'GitHub lists no published release'; return r; }
    if (res.status !== 200) {
      r.error = `GitHub answered HTTP ${res.status}` + (res.status === 403 || res.status === 429 ? ' (rate limited; the next check will try again)' : '');
      return r;
    }
    const body = toBuffer(res.body, 'GitHub answer');
    if (body.length > MAX_API_BYTES) throw new Error(`answer larger than ${MAX_API_BYTES} bytes`);
    rel = JSON.parse(body.toString('utf8'));
  } catch (e) { r.error = 'could not check GitHub for a new version: ' + short(e); return r; }
  if (!isObj(rel)) { r.error = 'GitHub sent an unexpected answer'; return r; }
  // releases/latest never returns drafts or pre-releases; if it ever does, skip them.
  if (rel.draft === true || rel.prerelease === true) return r;
  const tag = typeof rel.tag_name === 'string' ? rel.tag_name : '';
  const version = tag.slice(1);
  if (tag[0] !== 'v' || !VERSION_RE.test(version) || !parseVersion(version)) {
    r.error = `the latest release's tag is not a version: "${printable(tag, 40)}"`;
    return r;
  }
  if (isPrerelease(version)) return r;   // release.yml marks these as pre-releases
  r.version = version;
  r.tag = tag;
  r.notes = cleanNotes(rel.body);
  r.published = typeof rel.published_at === 'string' && ISO_RE.test(rel.published_at) && !Number.isNaN(Date.parse(rel.published_at)) ? rel.published_at : null;
  r.page = `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`;
  for (const a of Array.isArray(rel.assets) ? rel.assets : []) {
    if (!isObj(a) || !RELEASE_FILES.includes(a.name) || has(r.assets, a.name) || typeof a.browser_download_url !== 'string') continue;
    try { checkUrl(a.browser_download_url); } catch { continue; }
    r.assets[a.name] = a.browser_download_url;
  }
  r.available = compareVersions(version, currentVersion) > 0;
  if (!r.available) return r;
  const byHand = '; install it by hand from GitHub';
  if (!r.assets[MANIFEST_NAME]) { r.error = `the release has no ${MANIFEST_NAME}` + byHand; return r; }
  let mb, sb = null;
  try {
    mb = await fetchSmall(get, r.assets[MANIFEST_NAME], MANIFEST_NAME);
    if (r.assets[SIG_NAME]) sb = await fetchSmall(get, r.assets[SIG_NAME], SIG_NAME);
  } catch (e) { r.error = 'could not download the release manifest: ' + short(e); return r; }
  r.signed = sb != null;
  const v = verifyManifest({ manifestBytes: mb, sigBytes: sb, trustedKeys });
  if (!v.ok) { r.error = v.error + byHand; return r; }
  if (v.manifest.version !== version) {
    r.error = `the signed manifest is for version ${v.manifest.version}, not ${version}` + byHand;
    return r;
  }
  r.verified = true;
  r.manifest = v.manifest;
  // the exact signed bytes, so an installer running as another user (the
  // .deb's root unit) can check the signature again itself
  r.manifestBytes = mb;
  r.sigBytes = sb;
  return r;
}
// The installer for this machine, or null when there is none.
function platformAsset(platform = process.platform, arch = process.arch) {
  if (platform === 'win32' && arch === 'x64') return 'NodeSignal-Setup-windows-x64.exe';
  if (platform === 'linux' && arch === 'x64') return 'nodesignal-linux-amd64.deb';
  if (platform === 'linux' && arch === 'arm64') return 'nodesignal-linux-arm64.deb';
  return null;
}

/* ---------------------------------------------------------------- https */
// Throws unless the URL may be fetched: https to an allowlisted host on the
// default port, no credentials. (Tests may also use http://127.0.0.1.)
function checkUrl(u, opts = {}) {
  let url;
  try { url = new URL(String(u)); } catch { throw new Error('not a valid URL'); }
  if (url.username || url.password) throw new Error('URLs with credentials are not allowed');
  if (url.protocol === 'https:') {
    if (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error(`host not allowed: ${printable(url.hostname, 100)}`);
    if (url.port) throw new Error(`port not allowed: ${url.port}`);
    return url;
  }
  if (url.protocol === 'http:' && opts[TEST_ALLOW_HTTP_LOOPBACK] === true && url.hostname === '127.0.0.1') return url;
  throw new Error(`only https is allowed, not ${printable(url.protocol.replace(/:$/, ''), 20)}`);
}
function netOptions(opts, defaultMax) {
  opts = opts || {};
  const o = {
    maxBytes: opts.maxBytes == null ? defaultMax : opts.maxBytes,
    timeoutMs: opts.timeoutMs == null ? 20000 : opts.timeoutMs,
    redirects: opts.redirects == null ? 5 : opts.redirects,
    connect: typeof opts.connect === 'function' ? opts.connect : null,
    accept: typeof opts.accept === 'string' && /^[\x20-\x7e]{1,200}$/.test(opts.accept) ? opts.accept : '*/*',
    [TEST_ALLOW_HTTP_LOOPBACK]: opts[TEST_ALLOW_HTTP_LOOPBACK] === true,
  };
  if (!Number.isSafeInteger(o.maxBytes) || o.maxBytes <= 0 || o.maxBytes > MAX_ASSET_BYTES) throw new TypeError('maxBytes must be a positive whole number up to 300 MB');
  if (!Number.isFinite(o.timeoutMs) || o.timeoutMs <= 0) throw new TypeError('timeoutMs must be a positive number');
  if (!Number.isInteger(o.redirects) || o.redirects < 0 || o.redirects > 10) throw new TypeError('redirects must be a whole number from 0 to 10');
  return o;
}
// A connected socket for url: TLS with verification (over connect() when
// given), or plain TCP for the test-only http://127.0.0.1.
async function connectTo(url, o, track) {
  const host = url.hostname, port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
  let raw = null;
  if (o.connect) {
    raw = await o.connect(host, port);
    if (!raw || typeof raw.write !== 'function' || typeof raw.on !== 'function') throw new Error('connect() did not give a socket');
    track(raw);
    raw.on('error', noop);   // a late error must not crash the process; the TLS layer sees the close
  }
  return new Promise((resolve, reject) => {
    let s;
    const onError = (e) => reject(new Error(`${url.protocol === 'https:' ? 'TLS' : 'connection'} to ${host} failed: ${short(e)}`));
    if (url.protocol === 'http:') {
      if (raw) return resolve(raw);
      s = track(net.connect({ host, port }));
      s.once('error', onError);
      s.once('connect', () => { s.removeListener('error', onError); s.on('error', noop); resolve(s); });
      return;
    }
    s = track(tls.connect({
      ...(raw ? { socket: raw } : { host, port }),
      servername: host,
      rejectUnauthorized: true,        // always, whatever NODE_TLS_REJECT_UNAUTHORIZED says
      ALPNProtocols: ['http/1.1'],
    }));
    s.once('error', onError);
    s.once('secureConnect', () => {
      s.removeListener('error', onError);
      s.on('error', noop);
      if (!s.authorized) { s.destroy(); return reject(new Error('TLS certificate not trusted: ' + s.authorizationError)); }
      resolve(s);
    });
  });
}
// One request, no redirects: resolves with the response once headers arrive.
function openOnce(url, o, waitMs) {
  return new Promise((resolve, reject) => {
    const sockets = [];
    let req = null, settled = false;
    const track = (s) => { sockets.push(s); if (settled) s.destroy(); return s; };
    const fail = (e) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (req) req.destroy();
      for (const s of sockets) s.destroy();
      reject(e);
    };
    const timer = setTimeout(() => fail(new Error(`no answer from ${url.hostname} within ${o.timeoutMs} ms`)), Math.max(1, waitMs));
    connectTo(url, o, track).then((sock) => {
      if (settled) { sock.destroy(); return; }
      req = http.request({
        method: 'GET',
        path: url.pathname + url.search,
        headers: { Host: url.host, 'User-Agent': USER_AGENT, Accept: o.accept, Connection: 'close' },
        createConnection: () => sock,
      });
      req.on('error', fail);
      req.on('response', (res) => {
        if (settled) { res.destroy(); return; }
        settled = true; clearTimeout(timer);
        resolve({ res, sock });
      });
      req.end();
    }, fail);
  });
}
// Follows redirects, checking every target against the same rules.
async function open(u, o, deadline) {
  let url = checkUrl(u, o);
  for (let hops = 0; ; hops++) {
    const wait = deadline ? Math.min(o.timeoutMs, deadline - Date.now()) : o.timeoutMs;
    if (wait <= 0) throw new Error(`timed out after ${o.timeoutMs} ms`);
    const { res, sock } = await openOnce(url, o, wait);
    if (REDIRECT_CODES.has(res.statusCode) && res.headers.location) {
      res.destroy(); sock.destroy();
      if (hops >= o.redirects) throw new Error(`too many redirects (more than ${o.redirects})`);
      let next;
      try { next = new URL(res.headers.location, url); } catch { throw new Error('bad redirect'); }
      url = checkUrl(next.href, o);
      continue;
    }
    return { res, sock, url };
  }
}
const tooBig = (max) => new Error(`answer larger than ${max} bytes; stopped`);
/* GET into memory. maxBytes (default 1 MiB) caps the body: a larger
   Content-Length is refused before reading, and reading stops past the cap.
   timeoutMs (default 20 s) bounds the whole call, redirects included; give
   more when connect() goes through Tor. Any HTTP status is returned. */
async function httpsGet(url, opts = {}) {
  const o = netOptions(opts, MAX_API_BYTES);
  const deadline = Date.now() + o.timeoutMs;
  const { res, sock } = await open(url, o, deadline);
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0, done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true; clearTimeout(timer);
      res.destroy(); sock.destroy();
      if (err) reject(err); else resolve(value);
    };
    const timer = setTimeout(() => finish(new Error(`timed out after ${o.timeoutMs} ms`)), Math.max(1, deadline - Date.now()));
    if (res.headers['content-length'] !== undefined && Number(res.headers['content-length']) > o.maxBytes) return finish(tooBig(o.maxBytes));
    res.on('data', (c) => {
      n += c.length;
      if (n > o.maxBytes) return finish(tooBig(o.maxBytes));
      chunks.push(c);
    });
    res.on('end', () => finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    res.on('error', (e) => finish(e));
    res.on('close', () => finish(new Error('connection closed before the whole answer arrived')));
  });
}
/* GET as a stream, for installers. Same rules as httpsGet. maxBytes defaults
   to 300 MB; timeoutMs bounds each connection and then each silence while
   the body arrives, not the whole download. */
async function httpsGetStream(url, opts = {}) {
  const o = netOptions(opts, MAX_ASSET_BYTES);
  const { res, sock } = await open(url, o, null);
  if (res.headers['content-length'] !== undefined && Number(res.headers['content-length']) > o.maxBytes) {
    res.destroy(); sock.destroy();
    throw tooBig(o.maxBytes);
  }
  let n = 0;
  const stream = new Transform({
    transform(chunk, enc, cb) {
      n += chunk.length;
      if (n > o.maxBytes) return cb(tooBig(o.maxBytes));
      cb(null, chunk);
    },
  });
  const cut = (e) => { if (!stream.destroyed) stream.destroy(e); };
  sock.setTimeout(o.timeoutMs, () => { cut(new Error(`download stalled: nothing received for ${o.timeoutMs} ms`)); sock.destroy(); });
  res.on('error', cut);
  res.on('close', () => { if (!res.complete) cut(new Error('connection closed before the download finished')); });
  stream.on('close', () => { res.destroy(); sock.destroy(); });
  res.pipe(stream);
  return { status: res.statusCode, headers: res.headers, stream };
}

/* ---------------------------------------------------------------- download */
/* Download url to dest only if it has exactly `size` bytes and SHA-256
   `sha256` (take both from a verified manifest). Writes dest + '.part' first,
   renames it to dest only when both match, and removes the part file on any
   failure. Streams through getStream (default: httpsGetStream with
   timeoutMs / connect), or buffers through get when only get is given. */
async function downloadVerified({ url, sha256, size, dest, get, getStream, timeoutMs, connect } = {}) {
  if (typeof url !== 'string' || !url) throw new TypeError('downloadVerified: url is required');
  if (typeof sha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sha256)) throw new TypeError('downloadVerified: sha256 must be 64 hex characters');
  if (!Number.isSafeInteger(size) || size <= 0 || size >= MAX_ASSET_BYTES) throw new TypeError('downloadVerified: size must be from 1 byte to under 300 MB');
  if (typeof dest !== 'string' || !dest) throw new TypeError('downloadVerified: dest is required');
  const part = dest + '.part';
  await fs.promises.rm(part, { force: true });
  let fh = null;
  try {
    fh = await fs.promises.open(part, 'wx', 0o600);
    const hash = crypto.createHash('sha256');
    let n = 0;
    const take = async (chunk) => {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      n += b.length;
      if (n > size) throw new Error(`download is larger than the signed size (${size} bytes)`);
      hash.update(b);
      for (let off = 0; off < b.length;) off += (await fh.write(b, off, b.length - off)).bytesWritten;
    };
    if (getStream || !get) {
      const gs = getStream || ((u, opt) => httpsGetStream(u, { ...opt, timeoutMs, connect }));
      const r = await gs(url, { maxBytes: size });
      if (!r || r.status !== 200) {
        if (r && r.stream && typeof r.stream.destroy === 'function') r.stream.destroy();
        throw new Error(`download failed: HTTP ${r && r.status}`);
      }
      for await (const chunk of r.stream) await take(chunk);
    } else {
      const r = await get(url, { maxBytes: size });
      if (!r || r.status !== 200) throw new Error(`download failed: HTTP ${r && r.status}`);
      await take(toBuffer(r.body, 'download'));
    }
    if (n !== size) throw new Error(`download is ${n} bytes, the signed manifest says ${size}`);
    if (!crypto.timingSafeEqual(hash.digest(), Buffer.from(sha256, 'hex'))) throw new Error('download does not match the signed SHA-256');
    await fh.sync();
    await fh.close();
    fh = null;
    await fs.promises.rename(part, dest);
    return dest;
  } catch (e) {
    if (fh) await fh.close().catch(noop);
    await fs.promises.rm(part, { force: true }).catch(noop);
    throw e;
  }
}

module.exports = {
  compareVersions, verifyManifest, checkLatest, httpsGet, httpsGetStream, downloadVerified, loadTrustedKeys,
  platformAsset, parseVersion, isPrerelease, parseManifest, checkManifest, checkUrl, keyIdOf, rawPublicKey,
  DEFAULT_REPO, MANIFEST_NAME, SIG_NAME, ASSETS, ALLOWED_HOSTS, MAX_ASSET_BYTES, MAX_META_BYTES, VERSION_RE, DEFAULT_KEYS_FILE,
  _test: { ALLOW_HTTP_LOOPBACK: TEST_ALLOW_HTTP_LOOPBACK, cleanNotes },
};
