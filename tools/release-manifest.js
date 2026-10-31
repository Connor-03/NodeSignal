#!/usr/bin/env node
// tools/release-manifest.js: make, sign and check the signed release manifest.
// ============================================================================
//   node tools/release-manifest.js make <version> <dist-dir>
//       Writes <dist-dir>/nodesignal-release.json: the SHA-256 and size of
//       each of the three installers, which must all be in <dist-dir>.
//   node tools/release-manifest.js sign <manifest-file>
//       Signs it with the Ed25519 private key (PEM) held in the environment
//       variable NODESIGNAL_RELEASE_SIGNING_KEY, never one named on the
//       command line, and writes <manifest-file>.sig. With the variable empty
//       it warns and writes nothing, so an unsigned release stays possible:
//       installed copies then announce it but do not install it.
//   node tools/release-manifest.js verify <manifest-file> [release-keys.json]
//       Checks the signature against the trusted keys (default: this
//       repository's release-keys.json) and, for each listed installer that
//       sits beside the manifest, its size and SHA-256. Exit 1 on any failure.
//
// Run by the release workflow, Linux, in the publish job once the installers
// are in dist/ (the source is checked out in src/):
//   node src/tools/release-manifest.js make "$VERSION" dist
//   node src/tools/release-manifest.js sign dist/nodesignal-release.json
//
// Formats: see updater.js. Node.js standard library only.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const U = require('../updater.js');

const ENV_KEY = 'NODESIGNAL_RELEASE_SIGNING_KEY';
const REPO_KEYS = path.join(__dirname, '..', 'release-keys.json');
const IN_ACTIONS = process.env.GITHUB_ACTIONS === 'true';
const say = (s = '') => process.stdout.write(s + '\n');
const note = (s = '') => process.stderr.write(s + '\n');
function die(msg, code = 1) { note((IN_ACTIONS ? '::error::' : 'release-manifest: ') + msg); process.exit(code); }
function warn(msg) { note((IN_ACTIONS ? '::warning::' : 'warning: ') + msg); }

function usage() {
  die([
    'usage:',
    '  node tools/release-manifest.js make <version> <dist-dir>',
    `  node tools/release-manifest.js sign <manifest-file>        (key from ${ENV_KEY})`,
    '  node tools/release-manifest.js verify <manifest-file> [release-keys.json]',
  ].join('\n'), 2);
}

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    let size = 0;
    fs.createReadStream(file)
      .on('data', (c) => { size += c.length; h.update(c); })
      .on('error', reject)
      .on('end', () => resolve({ sha256: h.digest('hex'), size }));
  });
}

async function cmdMake(version, dir) {
  version = String(version).replace(/^v/, '');
  if (!U.VERSION_RE.test(version) || !U.parseVersion(version)) die(`not a version: ${version}`);
  const files = {}, missing = [];
  for (const name of U.ASSETS) {
    const p = path.join(dir, name);
    let st;
    try { st = fs.statSync(p); } catch { missing.push(name); continue; }
    if (!st.isFile()) { missing.push(name); continue; }
    const f = await hashFile(p);
    if (f.size <= 0 || f.size >= U.MAX_ASSET_BYTES) die(`${name} is ${f.size} bytes; the updater accepts 1 byte to under 300 MB`);
    files[name] = f;
  }
  if (missing.length) die(`missing from ${path.resolve(dir)}: ${missing.join(', ')}. The manifest lists all three installers; build them first.`);
  const manifest = { name: 'NodeSignal', version, tag: 'v' + version, date: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), files };
  const text = JSON.stringify(manifest, null, 2) + '\n';
  U.parseManifest(Buffer.from(text));   // what we write, the updater accepts
  const out = path.join(dir, U.MANIFEST_NAME);
  fs.writeFileSync(out, text);
  // a signature left from an earlier run would not match the new manifest
  if (fs.existsSync(out + '.sig')) { fs.rmSync(out + '.sig'); say(`removed the old ${U.SIG_NAME}`); }
  say(`wrote ${out}`);
  for (const [name, f] of Object.entries(files)) say(`  ${f.sha256}  ${String(f.size).padStart(10)}  ${name}`);
}

function cmdSign(file) {
  let pem = process.env[ENV_KEY] || '';
  if (!pem.trim()) {
    warn(`${ENV_KEY} is empty, so ${file} was NOT signed and no .sig was written. Installed copies will announce this release but not install it; people install it by hand.`);
    process.exit(0);
  }
  if (!pem.includes('\n') && pem.includes('\\n')) pem = pem.replace(/\\n/g, '\n');   // pasted with escaped newlines
  let key;
  try { key = crypto.createPrivateKey(pem); } catch { die(`${ENV_KEY} does not hold a PEM private key`); }
  pem = null;
  if (key.asymmetricKeyType !== 'ed25519') die(`${ENV_KEY} holds a ${key.asymmetricKeyType} key, not Ed25519`);
  let bytes;
  try { bytes = fs.readFileSync(file); } catch (e) { die(`cannot read ${file}: ${e.code || e.message}`); }
  try { U.parseManifest(bytes); } catch (e) { die(`${file}: ${e.message}; not signed`); }
  const raw = U.rawPublicKey(key);
  const keyId = U.keyIdOf(raw);
  const sigText = JSON.stringify({ v: 1, keyId, sig: crypto.sign(null, bytes, key).toString('base64') }) + '\n';
  const self = U.verifyManifest({ manifestBytes: bytes, sigBytes: Buffer.from(sigText), trustedKeys: [{ id: keyId, publicKey: raw.toString('base64') }] });
  if (!self.ok) die(`the new signature does not verify (${self.error}); not written`);
  fs.writeFileSync(file + '.sig', sigText);
  say(`signed ${file} with key ${keyId}; wrote ${file}.sig`);
  let listed = false;
  try { listed = U.loadTrustedKeys(REPO_KEYS).some((k) => k.id === keyId); } catch (e) { warn(`release-keys.json: ${e.message}`); }
  if (!listed) warn(`key ${keyId} is not in release-keys.json, so installed copies will not trust this signature. Add its entry (node tools/release-key.js pub <file>, on your own computer).`);
}

async function cmdVerify(file, keysFile) {
  keysFile = keysFile || REPO_KEYS;
  if (!fs.existsSync(keysFile)) die(`no such file: ${keysFile}`);
  let keys, bytes, sig = null;
  try { keys = U.loadTrustedKeys(keysFile); } catch (e) { die(e.message); }
  try { bytes = fs.readFileSync(file); } catch (e) { die(`cannot read ${file}: ${e.code || e.message}`); }
  try { sig = fs.readFileSync(file + '.sig'); } catch (e) { if (e.code !== 'ENOENT') die(`cannot read ${file}.sig: ${e.code || e.message}`); }
  const r = U.verifyManifest({ manifestBytes: bytes, sigBytes: sig, trustedKeys: keys });
  if (!r.ok) { say(`FAILED: ${r.error}`); process.exit(1); }
  const k = keys.find((x) => x.id === r.keyId);
  say(`OK: NodeSignal ${r.manifest.version} (${r.manifest.tag}, ${r.manifest.date}), signed with trusted key ${r.keyId}${k && k.note ? ` (${k.note})` : ''}`);
  let bad = 0;
  for (const [name, want] of Object.entries(r.manifest.files)) {
    const p = path.join(path.dirname(file), name);
    if (!fs.existsSync(p)) { say(`  -    ${name}: not beside the manifest, not checked`); continue; }
    const got = await hashFile(p);
    if (got.size !== want.size) { bad++; say(`  BAD  ${name}: ${got.size} bytes, the manifest says ${want.size}`); }
    else if (got.sha256 !== want.sha256) { bad++; say(`  BAD  ${name}: SHA-256 does not match the manifest`); }
    else say(`  ok   ${name}`);
  }
  if (bad) { say(`FAILED: ${bad} file(s) do not match the signed manifest`); process.exit(1); }
}

async function main(argv) {
  const [cmd, ...a] = argv;
  if (cmd === 'make' && a.length === 2) return cmdMake(a[0], a[1]);
  if (cmd === 'sign' && a.length === 1) return cmdSign(a[0]);
  if (cmd === 'sign') die(`sign takes only the manifest file; the key is read from ${ENV_KEY}, never from the command line`, 2);
  if (cmd === 'verify' && (a.length === 1 || a.length === 2)) return cmdVerify(a[0], a[1]);
  usage();
}

if (require.main === module) main(process.argv.slice(2)).catch((e) => die(e && e.message ? e.message : String(e)));
