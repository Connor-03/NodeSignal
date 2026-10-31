#!/usr/bin/env node
// tools/release-key.js: make or show NodeSignal's release signing key.
// ============================================================================
// The maintainer runs this on his own computer, never in CI. The private key
// never goes into the repository.
//
//   node tools/release-key.js new <private-key-file>   make a new Ed25519 key
//   node tools/release-key.js pub <private-key-file>   print its release-keys.json entry again
//
// "new" writes the private key as a PKCS#8 PEM file that only you can read
// (mode 0600; it never overwrites a file), prints the entry to add to
// release-keys.json, and explains how to store the key as the GitHub Actions
// secret NODESIGNAL_RELEASE_SIGNING_KEY, which tools/release-manifest.js uses
// to sign each release. Formats: see updater.js.
//
// Node.js standard library only.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { rawPublicKey, keyIdOf } = require('../updater.js');

const SECRET = 'NODESIGNAL_RELEASE_SIGNING_KEY';
const IS_WIN = process.platform === 'win32';
const say = (s = '') => process.stdout.write(s + '\n');
const note = (s = '') => process.stderr.write(s + '\n');
function die(msg, code = 1) { note('release-key: ' + msg); process.exit(code); }
const today = () => new Date().toISOString().slice(0, 10);

function usage() {
  die([
    'usage:',
    '  node tools/release-key.js new <private-key-file>   make a new release signing key',
    '  node tools/release-key.js pub <private-key-file>   print its release-keys.json entry again',
  ].join('\n'), 2);
}

function entryFor(privateKey, added) {
  const raw = rawPublicKey(privateKey);
  return { id: keyIdOf(raw), publicKey: raw.toString('base64'), added, note: 'NodeSignal release signing key' };
}

function readPrivateKey(file) {
  let pem;
  try { pem = fs.readFileSync(file, 'utf8'); } catch (e) { die(`cannot read ${file}: ${e.code || e.message}`); }
  let key;
  try { key = crypto.createPrivateKey(pem); } catch { die(`${file} does not hold a PEM private key`); }
  if (key.asymmetricKeyType !== 'ed25519') die(`${file} holds a ${key.asymmetricKeyType} key, not Ed25519`);
  if (!IS_WIN) {
    const mode = fs.statSync(file).mode & 0o777;
    if (mode & 0o077) note(`warning: ${file} can be read by other users (mode ${mode.toString(8)}); run: chmod 600 '${file}'`);
  }
  return key;
}

function cmdNew(file) {
  const abs = path.resolve(file);
  if (fs.existsSync(abs)) die(`${abs} already exists; refusing to overwrite it. Pick a new file name, or use "pub" to show the key it holds.`);
  // a random seed imported, not generateKeyPairSync (can deadlock on Node 18 when exported)
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), crypto.randomBytes(32)]), format: 'der', type: 'pkcs8' });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  let fd;
  try { fd = fs.openSync(abs, 'wx', 0o600); }
  catch (e) { die(e.code === 'EEXIST' ? `${abs} already exists; refusing to overwrite it` : `cannot create ${abs}: ${e.code || e.message}`); }
  try { fs.writeSync(fd, pem); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  if (!IS_WIN) fs.chmodSync(abs, 0o600);
  const entry = entryFor(privateKey, today());
  const lines = [
    `Private key written to ${abs}`,
    IS_WIN
      ? '(keep it in a folder only your Windows account can open).'
      : '(mode 0600: only your user can read it).',
    'Never commit it, paste it into an issue or a chat, or copy it to a node.',
    '',
    '1. Trust it in the app. Add this line to the "keys" list in release-keys.json',
    '   (repository root) and commit it:',
    '',
    '   ' + JSON.stringify(entry),
    '',
    '   An installed copy trusts only the keys in its own release-keys.json.',
    '   Copies running a release that ships this key can update in-app to any',
    '   later release signed with it; older copies only announce new releases,',
    '   and their operators install by hand.',
    '',
    '2. Let the release workflow sign with it: store the whole file as the',
    `   GitHub Actions secret ${SECRET}. With the GitHub`,
    '   CLI, signed in as an account that administers the repository, in your',
    '   clone of it:',
    '',
    '   Linux or macOS terminal (or Git Bash on Windows):',
    `     gh secret set ${SECRET} < '${abs}'`,
    '',
    '   Windows PowerShell:',
    `     Get-Content -Raw '${abs}' | gh secret set ${SECRET}`,
    '',
    '   Or in the browser: the repository\'s Settings > Secrets and variables >',
    `   Actions > New repository secret, named ${SECRET},`,
    '   with the whole file pasted in, BEGIN and END lines included.',
    '',
    '3. Keep an offline copy, for example on a USB stick or on paper, somewhere',
    '   safe away from this computer. If the key is lost, the next release must',
    '   ship a new key and be installed by hand. If it leaks, remove its line',
    '   from release-keys.json, make a new key, replace the GitHub secret, and',
    '   say so in the release notes.',
    '',
    `Show the entry again later: node tools/release-key.js pub '${abs}'`,
  ];
  say(lines.join('\n'));
}

function cmdPub(file) {
  const key = readPrivateKey(path.resolve(file));
  say(JSON.stringify(entryFor(key, today())));
  note('Add this line to the "keys" list in release-keys.json. "added" is today\'s date; keep the original date if the key is already listed.');
}

function main(argv) {
  const [cmd, file, ...rest] = argv;
  if (!file || rest.length) usage();
  if (cmd === 'new') return cmdNew(file);
  if (cmd === 'pub') return cmdPub(file);
  usage();
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { entryFor };
