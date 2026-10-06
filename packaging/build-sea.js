#!/usr/bin/env node
// build-sea.js: build the NodeSignal single executable (Node SEA).
// ============================================================================
//   Windows runner:  node packaging/build-sea.js
//                    -> dist/NodeSignal-Setup-windows-x64.exe
//   Linux (tests):   node packaging/build-sea.js
//                    -> dist/nodesignal-sea-linux-x64 (same sea-main.js; used
//                       to test the SEA mechanics, not shipped)
//
// Options: --out <file>  --version <x.y.z>  --src <repo dir>
//
// The executable is the Node.js binary running this script (CI pins Node 22
// LTS) with packaging/windows/sea-main.js and these assets injected:
// every file in packaging/files.json, manifest.json, and Node's LICENSE.
// A file listed in files.json but missing stops the build.
//
// postject is fetched by npx at BUILD time only, pinned to 1.0.0-alpha.6. It
// is never shipped and never becomes a runtime dependency: the finished
// executable contains Node.js and NodeSignal's own files, nothing else.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const IS_WIN = process.platform === 'win32';
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const POSTJECT = 'postject@1.0.0-alpha.6';

function opt(name, dflt) { const i = process.argv.indexOf('--' + name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt; }
function fail(msg) { console.error('\nbuild-sea: ' + msg + '\n'); process.exit(1); }

const SRC = path.resolve(opt('src', path.join(__dirname, '..')));
const pkg = JSON.parse(fs.readFileSync(path.join(SRC, 'package.json'), 'utf8'));
const VERSION = String(opt('version', pkg.version)).replace(/^v/, '');
const arch = process.arch === 'x64' ? 'x64' : process.arch;
const DEFAULT_OUT = IS_WIN ? `NodeSignal-Setup-windows-${arch}.exe` : `nodesignal-sea-${process.platform}-${arch}`;
const OUT = path.resolve(opt('out', path.join(SRC, 'dist', DEFAULT_OUT)));
const WORK = path.join(path.dirname(OUT), 'sea-build');

const major = Number(process.versions.node.split('.')[0]);
if (major < 22) fail(`Node ${process.versions.node} is too old; build with Node 22 LTS (SEA assets need 21.7+).`);

// 1. the file list, checked
const list = JSON.parse(fs.readFileSync(path.join(SRC, 'packaging', 'files.json'), 'utf8'));
const files = [...list.daemon, ...list.tools];
const missing = files.filter((f) => !fs.existsSync(path.join(SRC, f)));
if (missing.length) fail(`missing file(s) listed in packaging/files.json: ${missing.join(', ')}`);

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });

// 2. assets
const assets = {};
for (const f of files) assets[f] = path.join(SRC, f);
const extra = [];
const nodeLicense = [path.join(path.dirname(process.execPath), 'LICENSE'), path.join(path.dirname(process.execPath), '..', 'LICENSE')]
  .find((p) => fs.existsSync(p));
if (nodeLicense) { assets['node-LICENSE.txt'] = nodeLicense; extra.push('node-LICENSE.txt'); }
else console.warn('build-sea: Node LICENSE not found beside the node binary; not embedding it');
const manifest = { version: VERSION, files, extra, node: process.versions.node, built: new Date().toISOString() };
fs.writeFileSync(path.join(WORK, 'manifest.json'), JSON.stringify(manifest, null, 2));
assets['manifest.json'] = path.join(WORK, 'manifest.json');

// 3. blob
const blob = path.join(WORK, 'sea-prep.blob');
const seaConfig = {
  main: path.join(SRC, 'packaging', 'windows', 'sea-main.js'),
  output: blob,
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
  assets,
};
const seaConfigPath = path.join(WORK, 'sea-config.json');
fs.writeFileSync(seaConfigPath, JSON.stringify(seaConfig, null, 2));
execFileSync(process.execPath, ['--experimental-sea-config', seaConfigPath], { stdio: 'inherit' });

// 4. copy node and strip its signature (optional; postject would invalidate it anyway)
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.rmSync(OUT, { force: true });
fs.copyFileSync(process.execPath, OUT);
fs.chmodSync(OUT, 0o755);
if (IS_WIN) {
  const r = spawnSync('signtool', ['remove', '/s', OUT], { stdio: 'inherit', shell: false });
  if (r.error) console.log('build-sea: signtool not found; leaving the Node signature (it is invalidated by injection anyway)');
}

// 5. inject with postject (build time only, see header)
const npxCli = [
  path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npx-cli.js'),
  path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npx-cli.js'),
].find((p) => fs.existsSync(p));
const pjArgs = ['--yes', POSTJECT, OUT, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', FUSE];
if (process.platform === 'darwin') pjArgs.push('--macho-segment-name', 'NODE_SEA');
let r;
if (npxCli) r = spawnSync(process.execPath, [npxCli, ...pjArgs], { stdio: 'inherit' });
else r = spawnSync(IS_WIN ? 'npx.cmd' : 'npx', pjArgs, { stdio: 'inherit', shell: IS_WIN });
if (r.status !== 0) fail('postject failed' + (r.error ? ': ' + r.error.message : ''));

const sha = crypto.createHash('sha256').update(fs.readFileSync(OUT)).digest('hex');
console.log(`\nbuilt ${OUT}\n  version ${VERSION}, Node ${process.versions.node}, ${(fs.statSync(OUT).size / 1048576).toFixed(1)} MB\n  sha256 ${sha}`);
if (!process.env.KEEP_SEA_BUILD) fs.rmSync(WORK, { recursive: true, force: true });
