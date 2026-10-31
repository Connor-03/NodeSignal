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
function apply() {
  const r = spawnSync(process.execPath, [path.join(APP, 'cli.js'), 'update-apply'], { encoding: 'utf8', timeout: 60000,
    env: Object.assign({}, process.env, { NODESIGNAL_UPDATE_DIR: UPD, NODESIGNAL_UPDATE_DRY_RUN: '1' }) });
  let result = null; try { result = JSON.parse(fs.readFileSync(path.join(UPD, 'result.json'), 'utf8')); } catch { }
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

t('no request: nothing happens', () => {
  for (const f of fs.readdirSync(UPD)) fs.rmSync(path.join(UPD, f), { force: true });
  const r = apply();
  assert.strictEqual(r.code, 0); assert.match(r.out, /No update request/);
});

fs.rmSync(TMP, { recursive: true, force: true });
console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
