// update-apply.test.js: the root side of in-app updates (cli.js update-apply).
//   node tests/update-apply.test.js        (Linux, as root, with dpkg-deb; skips otherwise)
// The daemon cannot be trusted here: it only leaves a package, a release
// manifest and its signature in its state directory. update-apply must check
// all of it again, against the release keys shipped beside cli.js, before
// installing. A copy of the program in a temp folder has its own
// release-keys.json and VERSION; NODESIGNAL_UPDATE_DRY_RUN stops just before
// the package manager. No network, no fixed ports.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), assert = require('assert');
const { spawnSync, execFileSync } = require('child_process');
const updater = require('../updater.js');

const ROOT = path.join(__dirname, '..');
let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n').slice(0, 3).join('\n       ')); }
};
const asset = updater.platformAsset('linux', process.arch === 'arm64' ? 'arm64' : 'x64');
const canRun = process.platform === 'linux' && typeof process.getuid === 'function' && process.getuid() === 0
  && spawnSync('dpkg-deb', ['--version']).status === 0 && asset;
if (!canRun) { console.log('  skip update-apply: needs Linux, root and dpkg-deb'); console.log('\nall passed (0, 1 skipped)'); process.exit(0); }

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-upd-'));
const APP = path.join(TMP, 'app'), UPD = path.join(TMP, 'updates');
fs.mkdirSync(APP); fs.mkdirSync(UPD);
for (const f of ['cli.js', 'setup-core.js', 'updater.js', 'backup.js']) fs.copyFileSync(path.join(ROOT, f), path.join(APP, f));
fs.writeFileSync(path.join(APP, 'VERSION'), '1.4.0\n');

// the release key the "shipped" copy trusts, and another one it does not
const key = crypto.generateKeyPairSync('ed25519'), other = crypto.generateKeyPairSync('ed25519');
const raw = (k) => k.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
fs.writeFileSync(path.join(APP, 'release-keys.json'), JSON.stringify({ keys: [{ id: updater.keyIdOf(raw(key)), publicKey: raw(key).toString('base64') }] }));

function deb(pkg, version) {
  const d = path.join(TMP, `pkg-${pkg}-${version}`);
  fs.mkdirSync(path.join(d, 'DEBIAN'), { recursive: true });
  fs.writeFileSync(path.join(d, 'DEBIAN', 'control'), `Package: ${pkg}\nVersion: ${version}\nArchitecture: all\nMaintainer: test <test@example.org>\nDescription: test\n`);
  const out = path.join(TMP, `${pkg}-${version}.deb`);
  execFileSync('dpkg-deb', ['--root-owner-group', '--build', d, out], { stdio: 'ignore' });
  return fs.readFileSync(out);
}
function stage({ version = '1.5.0', pkgBytes = deb('nodesignal', version), signWith = key, manifestVersion = version, reqVersion = version, fileHash } = {}) {
  for (const f of fs.readdirSync(UPD)) fs.rmSync(path.join(UPD, f), { force: true, recursive: true });
  const manifest = Buffer.from(JSON.stringify({ name: 'NodeSignal', version: manifestVersion, tag: 'v' + manifestVersion, date: new Date().toISOString(),
    files: { [asset]: { sha256: fileHash || crypto.createHash('sha256').update(pkgBytes).digest('hex'), size: pkgBytes.length } } }));
  const sig = JSON.stringify({ v: 1, keyId: updater.keyIdOf(raw(signWith)), sig: crypto.sign(null, manifest, signWith.privateKey).toString('base64') });
  fs.writeFileSync(path.join(UPD, asset), pkgBytes);
  fs.writeFileSync(path.join(UPD, updater.MANIFEST_NAME), manifest);
  fs.writeFileSync(path.join(UPD, updater.SIG_NAME), sig);
  fs.writeFileSync(path.join(UPD, 'request.json'), JSON.stringify({ version: reqVersion, asset }));
}
function apply({ dir = UPD, timeout = 60000 } = {}) {
  const r = spawnSync(process.execPath, [path.join(APP, 'cli.js'), 'update-apply'], { encoding: 'utf8', timeout,
    env: Object.assign({}, process.env, { NODESIGNAL_UPDATE_DIR: dir, NODESIGNAL_UPDATE_DRY_RUN: '1' }) });
  let result = null; try { result = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8')); } catch { }
  return { code: r.status, out: r.stdout + r.stderr, result };
}

t('a signed, newer nodesignal package for this machine is accepted', () => {
  stage();
  const r = apply();
  assert.strictEqual(r.code, 0, r.out);
  assert(/signature, version, size and SHA-256 checked/.test(r.out), r.out);
  assert.deepStrictEqual([r.result.ok, r.result.version], [true, '1.5.0']);
  assert(!fs.existsSync(path.join(UPD, 'request.json')) && !fs.existsSync(path.join(UPD, asset)), 'request and files cleaned up');
});

t('a package that does not match the signed manifest is refused', () => {
  stage({ fileHash: 'f'.repeat(64) });
  const r = apply();
  assert.strictEqual(r.code, 1); assert.match(r.result.error, /does not match the signed manifest/);
});

t('a manifest signed with a key this copy does not ship is refused', () => {
  stage({ signWith: other });
  const r = apply();
  assert.strictEqual(r.code, 1); assert.match(r.out, /refused/);
});

t('an older or equal version is refused, even when signed (no downgrades)', () => {
  stage({ version: '1.4.0' });
  assert.match(apply().result.error, /not newer/);
  stage({ version: '1.3.9' });
  assert.match(apply().result.error, /not newer/);
});

t('the request and the manifest must name the same version', () => {
  stage({ version: '1.5.0', reqVersion: '1.6.0' });
  assert.match(apply().result.error, /is for 1\.5\.0/);
});

t('a signed package that is not nodesignal is refused', () => {
  stage({ pkgBytes: deb('something-else', '1.5.0') });
  assert.match(apply().result.error, /not nodesignal 1\.5\.0/);
});

t('a symlink left in place of the package is never followed', () => {
  stage();
  fs.rmSync(path.join(UPD, asset));
  fs.symlinkSync('/etc/passwd', path.join(UPD, asset));
  const r = apply();
  assert.strictEqual(r.code, 1, r.out);
  assert.strictEqual(r.result.ok, false);
});

/* The updates folder belongs to the daemon's user (nodesignal), who can put
   links or FIFOs in it, or swap the folder itself. Root cause of the
   escalation these guard (Oct 2026 review): update-apply wrote and chowned
   result.json as root with writeFileSync + chownSync, which follow a link the
   daemon planted, so root wrote into any file and handed it to nodesignal. */
const ROOT_ONLY = path.join(TMP, 'rootonly');
fs.mkdirSync(ROOT_ONLY, { mode: 0o700 });
const DAEMON_UID = 4242;   // an unused account standing in for nodesignal
const ownTree = (p, uid) => { fs.chownSync(p, uid, uid); if (fs.lstatSync(p).isDirectory()) for (const e of fs.readdirSync(p)) ownTree(path.join(p, e), uid); };

t('a link planted as result.json: its target is left untouched', () => {
  stage();
  const victim = path.join(ROOT_ONLY, 'nodesignal.prerm');
  fs.writeFileSync(victim, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  fs.symlinkSync(victim, path.join(UPD, 'result.json'));
  const r = apply();
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(fs.readFileSync(victim, 'utf8'), '#!/bin/sh\nexit 0\n', 'not written through the link');
  assert.strictEqual(fs.statSync(victim).uid, 0, 'not handed to anyone');
  assert(!fs.lstatSync(path.join(UPD, 'result.json')).isSymbolicLink(), 'the link was replaced by a plain file');
  assert.strictEqual(r.result.ok, true);
});

t('a FIFO as request.json is refused at once, never waited on', () => {
  stage();
  fs.rmSync(path.join(UPD, 'request.json'));
  execFileSync('mkfifo', [path.join(UPD, 'request.json')]);
  const t0 = Date.now();
  const r = apply({ timeout: 20000 });
  assert.strictEqual(r.code, 1, `exit ${r.code} after ${Date.now() - t0} ms: ${r.out}`);
  assert.match(r.result.error, /request\.json is not a plain file/);
  assert(!fs.existsSync(path.join(UPD, 'request.json')), 'the FIFO is removed');
});

t('a link as request.json is not followed', () => {
  stage();   // a valid, signed update whose request is reached only through a link
  const req = path.join(ROOT_ONLY, 'request.json');
  fs.renameSync(path.join(UPD, 'request.json'), req);
  fs.symlinkSync(req, path.join(UPD, 'request.json'));
  const r = apply();
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.result.error, /request\.json is a symbolic link/);
  assert(fs.existsSync(req), 'its target is left alone');
});

t('an updates folder that is a link is refused, and nothing in it is touched', () => {
  stage();
  const link = path.join(TMP, 'updates-link');
  fs.symlinkSync(UPD, link);
  try {
    const r = apply({ dir: link });
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.out, /not a plain folder/);
    assert(fs.existsSync(path.join(UPD, 'request.json')) && fs.existsSync(path.join(UPD, asset)));
    assert(!fs.existsSync(path.join(UPD, 'result.json')));
  } finally { fs.unlinkSync(link); }
});

t('a root-owned updates folder inside a folder another account controls is refused', () => {
  const outer = path.join(TMP, 'theirs'), inner = path.join(outer, 'updates');
  fs.mkdirSync(inner, { recursive: true });
  fs.chownSync(outer, DAEMON_UID, DAEMON_UID);
  fs.writeFileSync(path.join(inner, 'request.json'), JSON.stringify({ version: '1.5.0', asset }));
  const r = apply({ dir: inner });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /belongs to root, but .*theirs can be changed by an account other than root/);
  assert(fs.existsSync(path.join(inner, 'request.json')));
});

t('an updates folder owned by the daemon\'s user is read and written only as that user', () => {
  fs.chmodSync(TMP, 0o755);   // that user reaches its own folder, as on a real machine
  try {
    stage();
    ownTree(UPD, DAEMON_UID);
    // a file only root could read: as the daemon's user it cannot be read, so the update is refused
    fs.chownSync(path.join(UPD, updater.SIG_NAME), 0, 0); fs.chmodSync(path.join(UPD, updater.SIG_NAME), 0o600);
    let r = apply();
    assert.strictEqual(r.code, 1, r.out);
    assert.match(r.result.error, /EACCES/);
    assert.strictEqual(fs.statSync(path.join(UPD, 'result.json')).uid, DAEMON_UID, 'result.json made by that user, not by root');
    // everything readable by that user: the update goes through
    stage(); ownTree(UPD, DAEMON_UID);
    r = apply();
    assert.strictEqual(r.code, 0, r.out);
    assert.strictEqual(r.result.ok, true);
    assert.strictEqual(fs.statSync(path.join(UPD, 'result.json')).uid, DAEMON_UID);
    assert(!fs.existsSync(path.join(UPD, asset)), 'its files removed as that user');
  } finally { fs.chmodSync(TMP, 0o700); ownTree(UPD, 0); }
});

/* Root cause (Oct 2026 final review): update-apply copied the package (up to
   300 MB) into /var/tmp as root before it checked the manifest's signature,
   so whatever the daemon's account left there cost root disk and time
   before anything was verified. The manifest, its signature, the version and
   the package's entry are checked first now; a FIFO in place of the package
   shows the order (reading it first would fail with "not a plain file"). */
t('the signature, version and manifest entry are checked before the package is read', () => {
  const fifo = () => { fs.rmSync(path.join(UPD, asset)); execFileSync('mkfifo', [path.join(UPD, asset)]); };
  stage({ signWith: other }); fifo();
  let r = apply({ timeout: 20000 });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.result.error, /^refused: /);
  assert.doesNotMatch(r.result.error, /not a plain file/);
  stage({ version: '1.4.0' }); fifo();
  r = apply({ timeout: 20000 });
  assert.match(r.result.error, /not newer/);
  // a signed release: only then is the package read, and no more than its signed size
  stage(); fs.appendFileSync(path.join(UPD, asset), Buffer.alloc(1));
  r = apply();
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.result.error, /does not match the signed manifest \(it is larger than the signed size\)/);
  assert(!fs.existsSync(path.join(UPD, asset)), 'cleaned up');
});

t('no request: nothing happens', () => {
  for (const f of fs.readdirSync(UPD)) fs.rmSync(path.join(UPD, f), { force: true });
  const r = apply();
  assert.strictEqual(r.code, 0); assert.match(r.out, /No update request/);
});

fs.rmSync(TMP, { recursive: true, force: true });
console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
