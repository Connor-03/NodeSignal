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
//          --node <node.exe>  copy this Node binary instead of the one running
//                             the build; it must be the same Node version. For
//                             checking the Windows resource step from Linux
//                             with the official win-x64 node.exe; releases are
//                             built on a Windows runner without it.
//
// The executable is the Node.js binary running this script (CI pins Node 22
// LTS) with packaging/windows/sea-main.js and these assets injected:
// every file in packaging/files.json, manifest.json, and Node's LICENSE.
// A file listed in files.json but missing stops the build.
//
// Windows builds only (the copied binary is a PE file): before injection, the
// version resource (ProductName NodeSignal, the version, the LICENSE holder)
// and the icon are rewritten by packaging/windows/win-resources.js, the icon
// drawn fresh by packaging/windows/make-icon.js. This has to happen BEFORE
// postject, which adds the SEA blob as a resource; afterwards the finished
// file is checked for the version, icon, Node's manifest and the blob.
//
// postject is fetched by npx at BUILD time only, pinned to 1.0.0-alpha.6, and
// resedit (the resource editor, pure JavaScript, pinned to 3.1.0 with its
// one dependency pe-library 2.0.1) is fetched by npm into the build's scratch
// folder, for Windows builds only. Neither is ever shipped nor becomes a
// runtime dependency: the finished executable contains Node.js and
// NodeSignal's own files, nothing else.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const IS_WIN = process.platform === 'win32';
const HOMEPAGE = 'https://github.com/Connor-03/NodeSignal';
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const POSTJECT = 'postject@1.0.0-alpha.6';

function opt(name, dflt) { const i = process.argv.indexOf('--' + name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt; }
function fail(msg) { console.error('\nbuild-sea: ' + msg + '\n'); process.exit(1); }

const SRC = path.resolve(opt('src', path.join(__dirname, '..')));
const pkg = JSON.parse(fs.readFileSync(path.join(SRC, 'package.json'), 'utf8'));
const VERSION = String(opt('version', pkg.version)).replace(/^v/, '');
const NODE_BIN = path.resolve(opt('node', process.execPath));
if (!fs.existsSync(NODE_BIN)) fail(`no Node binary at ${NODE_BIN}`);

// The CPU of a Windows (PE) executable, or null when the file is not one.
function peArch(file) {
  const fd = fs.openSync(file, 'r');
  try {
    const h = Buffer.alloc(4096);
    fs.readSync(fd, h, 0, h.length, 0);
    if (h.toString('latin1', 0, 2) !== 'MZ') return null;
    const pe = h.readUInt32LE(0x3c);
    if (pe + 6 > h.length || h.toString('latin1', pe, pe + 4) !== 'PE\0\0') return null;
    return { 0x8664: 'x64', 0xaa64: 'arm64', 0x14c: 'ia32' }[h.readUInt16LE(pe + 4)] || 'unknown';
  } finally { fs.closeSync(fd); }
}
const PE_ARCH = peArch(NODE_BIN);   // set: a Windows build, resources get stamped
const arch = process.arch === 'x64' ? 'x64' : process.arch;
const DEFAULT_OUT = PE_ARCH ? `NodeSignal-Setup-windows-${PE_ARCH}.exe` : `nodesignal-sea-${process.platform}-${arch}`;
const OUT = path.resolve(opt('out', path.join(SRC, 'dist', DEFAULT_OUT)));
const WORK = path.join(path.dirname(OUT), 'sea-build');

const major = Number(process.versions.node.split('.')[0]);
if (major < 22) fail(`Node ${process.versions.node} is too old; build with Node 22 LTS (SEA assets need 21.7+).`);
if (!PE_ARCH && NODE_BIN !== process.execPath) fail('--node is only for a Windows node.exe');

async function main() {
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

  // 4. copy node and strip its signature (optional; the resource step drops it
  //    and postject would invalidate it anyway)
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.rmSync(OUT, { force: true });
  fs.copyFileSync(NODE_BIN, OUT);
  fs.chmodSync(OUT, 0o755);
  if (IS_WIN && PE_ARCH) {
    const r = spawnSync('signtool', ['remove', '/s', OUT], { stdio: 'inherit', shell: false });
    if (r.error) console.log('build-sea: signtool not found; the resource step drops the Node signature instead');
  }

  // 4b. Windows only: version resource and icon, BEFORE injection (see header)
  let R = null, stamped = null;
  if (PE_ARCH) {
    const winres = require('./windows/win-resources.js');
    const makeIcon = require('./windows/make-icon.js');
    R = await winres.loadResedit(WORK);
    if (NODE_BIN !== process.execPath) {
      const v = winres.nodeVersionOf(R, NODE_BIN);
      if (v !== process.versions.node) fail(`${NODE_BIN} is Node ${v || '(unknown)'}, but the SEA blob is made by Node ${process.versions.node}; they must match`);
    }
    const ico = makeIcon.makeIco();
    try {
      if (!makeIcon.samePixels(fs.readFileSync(makeIcon.DEFAULT_OUT), ico)) console.warn('build-sea: packaging/windows/nodesignal.ico is out of date; using the icon drawn from source');
    } catch { /* no committed copy: the drawn icon is used either way */ }
    const strings = winres.versionStrings({
      version: VERSION,
      originalFilename: path.basename(OUT),
      nodeVersion: process.versions.node,
      licenseText: fs.readFileSync(path.join(SRC, 'LICENSE'), 'utf8'),
      homepage: HOMEPAGE,
    });
    stamped = winres.stamp(R, OUT, { strings, icoBuffer: ico });
    console.log(`build-sea: version resource ${strings.ProductName} ${strings.ProductVersion}, icon ${stamped.iconSizes.join('/')} px`);
  }

  // 5. inject with postject (build time only, see header)
  const npxCli = [
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npx-cli.js'),
    path.join(path.dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npx-cli.js'),
  ].find((p) => fs.existsSync(p));
  const pjArgs = ['--yes', POSTJECT, OUT, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', FUSE];
  if (process.platform === 'darwin' && !PE_ARCH) pjArgs.push('--macho-segment-name', 'NODE_SEA');
  let r;
  if (npxCli) r = spawnSync(process.execPath, [npxCli, ...pjArgs], { stdio: 'inherit' });
  else r = spawnSync(IS_WIN ? 'npx.cmd' : 'npx', pjArgs, { stdio: 'inherit', shell: IS_WIN });
  if (r.status !== 0) fail('postject failed' + (r.error ? ': ' + r.error.message : ''));

  // 6. Windows only: the resources written in 4b survived injection
  if (PE_ARCH) {
    const problems = require('./windows/win-resources.js').verify(R, OUT, stamped);
    if (problems.length) fail('the finished executable failed its resource check:\n  ' + problems.join('\n  '));
    console.log('build-sea: resource check passed (version, icon, Node manifest, SEA blob)');
  }

  const sha = crypto.createHash('sha256').update(fs.readFileSync(OUT)).digest('hex');
  console.log(`\nbuilt ${OUT}\n  version ${VERSION}, Node ${process.versions.node}, ${(fs.statSync(OUT).size / 1048576).toFixed(1)} MB\n  sha256 ${sha}`);
  if (!process.env.KEEP_SEA_BUILD) fs.rmSync(WORK, { recursive: true, force: true });
}

main().catch((e) => fail(e && e.stack ? e.stack : String(e)));
