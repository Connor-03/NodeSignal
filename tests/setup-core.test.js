// setup-core.test.js: installer logic (setup-core.js, cli.js setup). Plain node, no deps.
//   node tests/setup-core.test.js
// Uses a fake filesystem root and tests/mock-node.js; never touches a real node.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const { spawnSync } = require('child_process');
const core = require('../setup-core.js');
const { rpcServer } = require('./mock-node.js');

const ROOT = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-setup-test-'));
let failed = 0;
const tests = [];
const t = (name, fn) => tests.push([name, fn]);
const write = (p, s) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s); };

t('every file in packaging/files.json exists', () => {
  const list = core.readFileList(ROOT);
  assert.deepStrictEqual(core.missingFiles(ROOT, list.all), []);
  assert(list.daemon.includes('nodesignald.js') && list.tools.includes('setup-core.js'));
});

t('parseConf reads top level and [main], skips other chains and comments', () => {
  const c = core.parseConf('rpcuser=a # note\n[test]\nrpcport=1\n[main]\nrpcport=9\nrpcuser=b\n');
  assert.strictEqual(c.rpcuser, 'a');
  assert.strictEqual(c.rpcport, '9');
});

t('advertise on/off round trip without sections, LF', () => {
  const f = path.join(tmp, 'a', 'bitcoin.conf');
  const orig = 'server=1\n# comment kept\nprune=550\n';
  write(f, orig);
  const r1 = core.setUaComment(f, true);
  assert(r1.changed && r1.backup);
  assert(/\nuacomment=nodesignal\n$/.test(fs.readFileSync(f, 'utf8')));
  assert.strictEqual(core.setUaComment(f, true).changed, false, 'idempotent');
  assert(core.uaCommentState(f).on);
  core.setUaComment(f, false);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), orig);
  assert.strictEqual(core.setUaComment(f, false).changed, false);
  assert.strictEqual(fs.readFileSync(f + core.BACKUP_SUFFIX, 'utf8'), orig);
});

t('advertise goes before the first [section], CRLF kept, backup is one-time', () => {
  const f = path.join(tmp, 'b', 'bitcoin.conf');
  const orig = 'server=1\r\n\r\n[main]\r\nrpcport=8332\r\n[test]\r\nuacomment=other\r\n';
  write(f, orig);
  core.setUaComment(f, true);
  const on = fs.readFileSync(f, 'utf8');
  assert(on.indexOf('uacomment=nodesignal\r\n') < on.indexOf('[main]'), 'top level');
  assert(!/[^\r]\n/.test(on), 'CRLF only');
  core.setUaComment(f, false);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), orig);
  write(f, 'changed=1\n');
  core.setUaComment(f, true);
  assert.strictEqual(fs.readFileSync(f + core.BACKUP_SUFFIX, 'utf8'), orig, 'backup not overwritten');
});

t('advertise refuses a file it cannot parse, and changes nothing', () => {
  const f = path.join(tmp, 'c', 'bitcoin.conf');
  write(f, 'server=1\nthis is not an option\n');
  assert.throws(() => core.setUaComment(f, true), /refusing to edit/);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), 'server=1\nthis is not an option\n');
  assert(!fs.existsSync(f + core.BACKUP_SUFFIX));
  write(f, Buffer.from([0x73, 0x3d, 0xff, 0x0a]));
  assert.throws(() => core.setUaComment(f, true), /UTF-8/);
});

t('advertise creates a missing bitcoin.conf only when turning on', () => {
  const f = path.join(tmp, 'd', 'bitcoin.conf');
  assert.strictEqual(core.setUaComment(f, false).changed, false);
  assert(!fs.existsSync(f));
  assert(core.setUaComment(f, true).created);
  assert(core.uaCommentState(f).on);
});

t('a uacomment=nodesignal inside a section is reported, not counted as on', () => {
  const f = path.join(tmp, 'e', 'bitcoin.conf');
  write(f, '[main]\nuacomment=nodesignal\n');
  const s = core.uaCommentState(f);
  assert(!s.on && s.inSection);
});

t('writeConfig is atomic JSON readable by its owner only', () => {
  const f = path.join(tmp, 'cfg', 'config.json');
  core.writeConfig(f, { nick: 'x', 'port-mapping': true });
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(f, 'utf8')), { nick: 'x', 'port-mapping': true });
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
});

// a fake Linux machine: one user whose node runs on testnet or mainnet
function fakeRoot(name, { conf = '', proc = true } = {}) {
  const r = path.join(tmp, name);
  // alice owns her files: as root we chown them to 1000, otherwise she is us
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const uid = asRoot || typeof process.getuid !== 'function' ? 1000 : process.getuid();
  const gid = asRoot || typeof process.getgid !== 'function' ? 1000 : process.getgid();
  write(path.join(r, 'etc/passwd'), `root:x:0:0:root:/root:/bin/sh\nalice:x:${uid}:${gid}:A:/home/alice:/bin/sh\n`);
  write(path.join(r, 'etc/group'), `root:x:0:\nalice:x:${gid}:\n`);
  write(path.join(r, 'etc/hostname'), 'testbox\n');
  fs.mkdirSync(path.join(r, 'home/alice/.bitcoin/blocks'), { recursive: true });
  if (conf) write(path.join(r, 'home/alice/.bitcoin/bitcoin.conf'), conf);
  if (proc) {
    write(path.join(r, 'proc/4242/comm'), 'bitcoind\n');
    write(path.join(r, 'proc/4242/cmdline'), 'bitcoind\0-daemon\0');
    write(path.join(r, 'proc/4242/status'), `Name:\tbitcoind\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\n`);
  }
  if (asRoot) chownTree(path.join(r, 'home/alice'), uid, gid);
  return { r, uid };
}

function chownTree(p, uid, gid) {
  fs.chownSync(p, uid, gid);
  if (fs.statSync(p).isDirectory()) for (const e of fs.readdirSync(p)) chownTree(path.join(p, e), uid, gid);
}

t('detectBitcoinNode: nothing installed', async () => {
  const r = path.join(tmp, 'empty');
  fs.mkdirSync(path.join(r, 'etc'), { recursive: true });
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.strictEqual(d.installed, false);
});

t('detectBitcoinNode: running node, datadir, owner, cookie', async () => {
  const { r, uid } = fakeRoot('main', { conf: 'server=1\n' });
  write(path.join(r, 'home/alice/.bitcoin/.cookie'), '__cookie__:abc');
  if (typeof process.getuid === 'function' && process.getuid() === 0) fs.chownSync(path.join(r, 'home/alice/.bitcoin/.cookie'), uid, uid);
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert(d.installed && d.running);
  assert.strictEqual(d.datadir, '/home/alice/.bitcoin');
  assert.strictEqual(d.cookiePath, '/home/alice/.bitcoin/.cookie');
  assert.strictEqual(d.owner.uid, uid);
  assert.strictEqual(d.owner.username, 'alice');
  assert.strictEqual(d.rpcUrlNeeded, false);
  assert(core.daemonFindsCookie(d.cookiePath, '/home/alice', 'linux'));
  const a = core.findRpcAuth(d, {}, { root: r });
  assert.strictEqual(a.auth, '__cookie__:abc');
});

t('detectBitcoinNode: testnet cookie subfolder and port', async () => {
  const { r } = fakeRoot('testnet', { conf: 'testnet=1\n', proc: false });
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert(d.installed && !d.running);
  assert.strictEqual(d.cookiePath, '/home/alice/.bitcoin/testnet3/.cookie');
  assert.strictEqual(d.rpcUrl, 'http://127.0.0.1:18332');
  assert.strictEqual(d.rpcUrlNeeded, true);
});

t('checkNode: connects with conf credentials, explains failures', async () => {
  const srv = await rpcServer({ port: 0 });
  const port = srv.address().port;
  try {
    const { r } = fakeRoot('rpc', { conf: `rpcport=${port}\nrpcuser=u\nrpcpassword=p\n` });
    const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
    const ok = await core.checkNode(d, {}, { root: r });
    assert(ok.ok, ok.error);
    assert.strictEqual(ok.blocks, 950000);
    const bad = await core.checkNode(d, { 'rpc-user': 'u', 'rpc-pass': 'wrong' }, { root: r });
    assert.strictEqual(bad.code, 'auth');
    const down = await core.checkNode(d, { 'rpc-url': 'http://127.0.0.1:1', 'rpc-user': 'u', 'rpc-pass': 'p' }, { root: r });
    assert.strictEqual(down.code, 'refused');
    assert(/running/.test(down.hint));
  } finally { srv.close(); }
});

t('cli setup (the .deb postinst step) writes config, drop-in and state dir', async () => {
  const { r } = fakeRoot('deb', { conf: 'server=1\n' });
  const run = () => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r], { encoding: 'utf8', timeout: 30000 });
  const out = run();
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  const cfg = JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'));
  assert.deepStrictEqual(cfg, { nick: 'testbox', data: '/home/alice/.nodesignal' });
  const drop = fs.readFileSync(path.join(r, 'etc/systemd/system/nodesignal.service.d/10-user.conf'), 'utf8');
  assert(/^User=alice$/m.test(drop) && /^ReadWritePaths=\/home\/alice\/\.nodesignal$/m.test(drop));
  assert(fs.statSync(path.join(r, 'home/alice/.nodesignal')).isDirectory());
  // a second run keeps the existing config
  fs.writeFileSync(path.join(r, 'etc/nodesignal/config.json'), JSON.stringify({ nick: 'kept', data: '/home/alice/.nodesignal' }));
  assert.strictEqual(run().status, 0);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8')).nick, 'kept');
});

(async () => {
  for (const [name, fn] of tests) {
    try { await fn(); console.log('  ok   ' + name); }
    catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exit(failed ? 1 : 0);
})();
