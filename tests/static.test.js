// static.test.js: what the web side will and will not hand out. Plain node, any version.
//   node tests/static.test.js       (loopback only)
// 1. nodeps.safeResolve / serveStatic directly: path traversal (../, %2e%2e,
//    backslashes, absolute paths, NUL) and dotfiles are refused, with POSIX
//    and (by loading nodeps.js against path.win32) Windows path rules.
// 2. The daemon's web server: the program folder of a from-source install
//    holds nodesignal-config.json (the RPC password, the web token) and may
//    hold state.json (the private identity key), so nothing but the console
//    page itself is ever served from it. Host is 127.0.0.1:<port>, as
//    locked decision 10 requires.
// Ports 44751 and 44752.
'use strict';
const fs = require('fs'), path = require('path'), net = require('net'), vm = require('vm');
const { Writable } = require('stream');
const assert = require('assert');
const W = require('../nodeps.js');
const H = require('./harness.js');
const { ROOT, up, get } = H;
const S = H.suite('ns-static-');
const { t } = S;

const SECRET = 'SECRET-MUST-NOT-LEAK-7f3a';
const WEB = 44752;

// A response good enough for serveStatic (sendFile pipes a file stream into it).
function serve(root, url) {
  return new Promise((resolve) => {
    const chunks = [];
    const res = new Writable({ write(c, e, cb) { chunks.push(c); cb(); } });
    res.status = 0;
    res.writeHead = (s) => { res.status = s; };
    res.on('finish', () => resolve({ status: res.status, body: Buffer.concat(chunks).toString('utf8') }));
    if (!W.serveStatic(root, url, res)) resolve({ status: 404, body: '' });
  });
}
// nodeps.js evaluated with another platform's path module.
function nodepsWith(pathImpl) {
  const src = fs.readFileSync(path.join(ROOT, 'nodeps.js'), 'utf8');
  const mod = { exports: {} };
  const req = (n) => (n === 'path' ? pathImpl : require(n));
  vm.runInThisContext('(function (module, exports, require) {' + src + '\n})')(mod, mod.exports, req);
  return mod.exports;
}
// Raw HTTP so the request line reaches the server exactly as written.
function raw(p) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: WEB });
    let d = '';
    s.on('connect', () => s.write(`GET ${p} HTTP/1.1\r\nHost: 127.0.0.1:${WEB}\r\nConnection: close\r\n\r\n`));
    s.on('data', (x) => (d += x)); s.on('error', () => { });
    s.on('close', () => resolve({ status: Number((/^HTTP\/1\.1 (\d{3})/.exec(d) || [])[1]) || 0, text: d }));
  });
}

const TRAVERSAL = [
  '/../outside-secret.txt', '/../../outside-secret.txt', '/sub/../../outside-secret.txt',
  '/%2e%2e/outside-secret.txt', '/%2E%2E/outside-secret.txt', '/%2e%2e%2foutside-secret.txt', '/..%2foutside-secret.txt',
  '/.%2e/outside-secret.txt', '/sub/%2e%2e/%2e%2e/outside-secret.txt', '/%252e%252e/outside-secret.txt',
  '/..\\outside-secret.txt', '/..%5coutside-secret.txt', '/sub\\..\\..\\outside-secret.txt', '/%5c..%5c..%5coutside-secret.txt',
  '//etc/passwd', '/etc/passwd', '/%2fetc%2fpasswd', '/C:/Windows/win.ini', '/C:%5cWindows%5cwin.ini', '/\\\\server\\share\\x',
  '/index.html%00.txt', '/%00', '/%E0%A4%A',
];
const DOTFILES = ['/.env', '/.git/config', '/.git/HEAD', '/sub/.hidden', '/%2eenv', '/sub/%2ehidden', '/.nodesignal/state.json'];

(async () => {
  /* ---- 1. nodeps directly ---- */
  const TREE = path.join(S.TMP, 'tree'), ROOTDIR = path.join(TREE, 'root');
  fs.mkdirSync(path.join(ROOTDIR, 'sub'), { recursive: true });
  fs.mkdirSync(path.join(ROOTDIR, '.git')); fs.mkdirSync(path.join(ROOTDIR, '.nodesignal'));
  fs.writeFileSync(path.join(TREE, 'outside-secret.txt'), SECRET);
  fs.writeFileSync(path.join(ROOTDIR, 'index.html'), '<p>index</p>');
  fs.writeFileSync(path.join(ROOTDIR, 'sub', 'deep.txt'), 'deep');
  for (const f of ['.env', '.git/config', '.git/HEAD', 'sub/.hidden', '.nodesignal/state.json']) fs.writeFileSync(path.join(ROOTDIR, f), SECRET);

  await t('nodeps serves files inside the root, with their MIME type', async () => {
    const r = await serve(ROOTDIR, '/index.html');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body, '<p>index</p>');
    assert.strictEqual((await serve(ROOTDIR, '/sub/deep.txt?x=1#y')).body, 'deep');
    assert.strictEqual(W.mimeFor('a.html'), 'text/html; charset=utf-8');
  });

  await t('nodeps: path traversal never leaves the root (POSIX rules)', async () => {
    const rootRes = path.resolve(ROOTDIR);
    for (const u of TRAVERSAL) {
      const f = W.safeResolve(ROOTDIR, u);
      assert(f === null || f === rootRes || f.startsWith(rootRes + path.sep), `${u} resolved to ${f}`);
      const r = await serve(ROOTDIR, u);
      assert.notStrictEqual(r.status, 200, `${u} was served`);
      assert(!r.body.includes(SECRET), `${u} leaked`);
    }
    assert.strictEqual(W.safeResolve(ROOTDIR, '/a%00b'), null, 'NUL');
    assert.strictEqual(W.safeResolve(ROOTDIR, '/%E0%A4%A'), null, 'malformed escape');
  });

  await t('nodeps: path traversal never leaves the root (Windows rules, backslashes as separators)', async () => {
    const win = nodepsWith(path.win32);
    const root = 'C:\\NodeSignal\\app';
    for (const u of [...TRAVERSAL, '/..\\..\\Windows\\win.ini', '/sub\\..\\..\\..\\x', '/%5c%5c?%5cC:%5cx', '/..%5c.env']) {
      const f = win.safeResolve(root, u);
      assert(f === null || f === root || f.toLowerCase().startsWith(root.toLowerCase() + '\\'), `${u} resolved to ${f}`);
    }
    assert.strictEqual(win.safeResolve(root, '/..\\outside.txt'), null);
    assert.strictEqual(win.safeResolve(root, '/sub\\.env'), null, 'dotfile behind a backslash');
  });

  await t('nodeps: dotfiles and dot-directories are refused', async () => {
    for (const u of DOTFILES) {
      assert.strictEqual(W.safeResolve(ROOTDIR, u), null, u);
      const r = await serve(ROOTDIR, u);
      assert.strictEqual(r.status, 403, u); assert(!r.body.includes(SECRET), u);
    }
  });

  /* ---- 2. the daemon, on a from-source install's program folder ---- */
  const APP = path.join(S.TMP, 'app');
  fs.mkdirSync(path.join(APP, '.git'), { recursive: true });
  for (const f of ['nodesignald.js', 'noise.js', 'nodeps.js', 'store.js', 'portmap.js', 'nodesignal.html', 'setup-core.js', 'cli.js'])
    fs.copyFileSync(path.join(ROOT, f), path.join(APP, f));
  // what install.js leaves beside the program (CONFIG_FILE, LAUNCHER, bitcoin-conf)
  fs.writeFileSync(path.join(APP, 'nodesignal-config.json'), JSON.stringify({ 'rpc-user': 'nodesignal', 'rpc-pass': SECRET, 'web-token': '' }));
  fs.writeFileSync(path.join(APP, 'run-nodesignal.sh'), '#!/bin/sh\n# ' + SECRET + '\n');
  fs.writeFileSync(path.join(APP, 'bitcoin-conf'), '/home/operator/.bitcoin/bitcoin.conf # ' + SECRET);
  fs.writeFileSync(path.join(APP, '.env'), SECRET); fs.writeFileSync(path.join(APP, '.git', 'config'), SECRET);
  fs.writeFileSync(path.join(S.TMP, 'outside-secret.txt'), SECRET);
  // worst case: the daemon's own data directory is the program folder
  const D = await up(S.daemon('static', { peer: 44751, web: WEB, data: 'app',
    extra: ['--config', path.join(APP, 'nodesignal-config.json'), '--web-root', APP] }));
  const priv = JSON.parse(fs.readFileSync(path.join(APP, 'state.json'), 'utf8')).identity;
  const leaks = (text) => text.includes(SECRET) || JSON.stringify(priv).slice(20, 60).split('"').some((x) => x.length > 20 && text.includes(x));

  await t('the daemon serves the console and /health, without any secret', async () => {
    const page = await get(WEB, '/');
    assert.strictEqual(page.status, 200); assert(/ns-action-token/.test(page.body));
    const h = await get(WEB, '/health');
    assert.strictEqual(h.status, 200);
    assert(!leaks(page.body) && !leaks(h.body), 'a secret reached the page or /health');
  });

  await t('the daemon never serves the config, state, launcher or any other file from its folder', async () => {
    const paths = ['/nodesignal-config.json', '/nodesignal-config.json?x=1', '/x/../nodesignal-config.json', '/%6eodesignal-config.json',
      '/state.json', '/./state.json', '/state.json.tmp', '/STATE.JSON', '/run-nodesignal.sh', '/bitcoin-conf',
      '/nodesignald.js', '/noise.js', '/store.js', '/cli.js', '/nodesignal.html'];
    for (const p of paths) {
      const r = await raw(p);
      assert(r.status === 404 || r.status === 403 || r.status === 400, `${p}: ${r.status}`);
      assert(!leaks(r.text), `${p} leaked a secret`);
    }
  });

  await t('the daemon refuses traversal and dotfiles on the wire', async () => {
    for (const p of [...TRAVERSAL, ...DOTFILES, '/' + path.join(S.TMP, 'outside-secret.txt'), '/..', '/../app/nodesignal-config.json',
      '../outside-secret.txt', '*']) {
      const r = await raw(p);
      // the URL parser folds some of these to "/", which is the console page
      assert(r.status !== 200 || /ns-action-token/.test(r.text), `${p} was served`);
      assert(!leaks(r.text), `${p} leaked a secret`);
    }
    assert(await H.health(D), 'still up');
  });

  await S.finish();
})().catch(S.abort);
