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
  // the cookie is found (detection reports it) but never used to log in
  const a = core.findRpcAuth(d, {}, { root: r });
  assert.strictEqual(a.auth, null);
  assert(/run setup/.test(a.notes.join(' ')));
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
    const none = await core.checkNode(d, {}, { root: r });
    assert.strictEqual(none.code, 'no-auth', 'bitcoin.conf is not read unless rpc-conf points at it');
    const ok = await core.checkNode(d, { 'rpc-conf': '/home/alice/.bitcoin/bitcoin.conf' }, { root: r });
    assert(ok.ok, ok.error);
    assert.strictEqual(ok.blocks, 950000);
    const bad = await core.checkNode(d, { 'rpc-user': 'u', 'rpc-pass': 'wrong' }, { root: r });
    assert.strictEqual(bad.code, 'auth');
    const down = await core.checkNode(d, { 'rpc-url': 'http://127.0.0.1:1', 'rpc-user': 'u', 'rpc-pass': 'p' }, { root: r });
    assert.strictEqual(down.code, 'refused');
    assert(/running/.test(down.hint));
  } finally { srv.close(); }
});

/* ---------------------------------------------------------- RPC access */
t('rpcauth matches Bitcoin Core (test/functional/rpc_users.py vector)', () => {
  const line = 'rpcauth=rt:93648e835a54c573682c2eb19f882535$7681e9c5b74bdd85e78166031d2058e1069b3ed7ed967c93fc63abba06f31144';
  const pw = 'cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM=';
  assert.strictEqual(core.makeRpcAuth('rt', pw, '93648e835a54c573682c2eb19f882535'), line);
  assert(core.rpcAuthMatches(line, 'rt', pw));
  assert(!core.rpcAuthMatches(line, 'rt', pw + 'x'));
  assert(!core.rpcAuthMatches(line, 'other', pw));
  assert(core.generateRpcPassword().length >= 43, '256-bit password');
});

t('every rpcCall in nodesignald.js is in RPC_METHODS, and nothing else is', () => {
  const src = fs.readFileSync(path.join(ROOT, 'nodesignald.js'), 'utf8');
  const used = [...new Set([...src.matchAll(/rpcCall\(\s*'([a-z]+)'/g)].map((m) => m[1]))].sort();
  assert.deepStrictEqual(used, [...core.RPC_METHODS].sort());
  assert.deepStrictEqual(core.RPC_METHODS, ['getblockchaininfo', 'getnetworkinfo', 'getpeerinfo']);
  // setup-core's own check uses a subset
  const own = [...new Set([...fs.readFileSync(path.join(ROOT, 'setup-core.js'), 'utf8').matchAll(/method: '([a-z]+)'/g)].map((m) => m[1]))];
  for (const m of own) assert(core.RPC_METHODS.includes(m), m);
});

t('setRpcAccess: add, idempotent, refresh, remove restores the file byte for byte', () => {
  const f = path.join(tmp, 'ra', 'bitcoin.conf');
  const orig = 'server=1\n# kept\nprune=550\n\n[test]\nrpcport=18332\n';
  write(f, orig);
  const r1 = core.setRpcAccess(f, 'pw1');
  assert(r1.changed && r1.backup);
  const on = fs.readFileSync(f, 'utf8');
  const top = on.slice(0, on.indexOf('[test]'));
  assert(top.includes(core.RPC_BEGIN) && top.includes(core.RPC_END), 'block at the top level');
  assert(/^rpcwhitelist=nodesignal:getblockchaininfo,getnetworkinfo,getpeerinfo$/m.test(top));
  assert(/^rpcwhitelistdefault=0$/m.test(top), 'other users keep full access');
  const st = core.rpcAccessState(f);
  assert(st.on && core.rpcAuthMatches(st.rpcauth, 'nodesignal', 'pw1'));
  assert(!on.includes('pw1'), 'the password never lands in bitcoin.conf');
  assert.strictEqual(core.setRpcAccess(f, 'pw1').changed, false, 'same password: untouched, no restart needed');
  assert.strictEqual(fs.readFileSync(f, 'utf8'), on);
  assert(core.setRpcAccess(f, 'pw2').changed, 'new password refreshes the block');
  assert(core.rpcAuthMatches(core.rpcAccessState(f).rpcauth, 'nodesignal', 'pw2'));
  assert.strictEqual(fs.readFileSync(f, 'utf8').split(core.RPC_BEGIN).length, 2, 'one block only');
  assert(core.setRpcAccess(f, null).changed);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), orig);
  assert.strictEqual(core.setRpcAccess(f, null).changed, false);
  assert.strictEqual(fs.readFileSync(f + core.BACKUP_SUFFIX, 'utf8'), orig);
});

t('setRpcAccess: CRLF and no sections round trip; a missing file is created 0600', () => {
  const f = path.join(tmp, 'rb', 'bitcoin.conf');
  const orig = 'server=1\r\ntxindex=0';                        // no final newline
  write(f, orig);
  core.setRpcAccess(f, 'pw');
  assert(!/[^\r]\n/.test(fs.readFileSync(f, 'utf8')), 'CRLF only');
  core.setRpcAccess(f, null);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), orig + '\r\n');
  const g = path.join(tmp, 'rc', 'bitcoin.conf');
  assert(core.setRpcAccess(g, 'pw').created);
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(g).mode & 0o777, 0o600);
  assert(core.rpcAccessState(g).on);
});

t('setRpcAccess leaves an operator\'s own rpcwhitelist settings alone', () => {
  for (const extra of ['rpcwhitelist=electrs:getblock\n', 'rpcwhitelistdefault=1\n']) {
    const f = path.join(tmp, 'rd' + extra.length, 'bitcoin.conf');
    write(f, 'server=1\n' + extra);
    core.setRpcAccess(f, 'pw');
    const text = fs.readFileSync(f, 'utf8');
    assert(!/^rpcwhitelistdefault=0$/m.test(text), 'no rpcwhitelistdefault=0 when they configure whitelists');
    assert(text.includes(extra));
  }
});

t('setRpcAccess refuses files it cannot parse or a broken block, and changes nothing', () => {
  const f = path.join(tmp, 're', 'bitcoin.conf');
  write(f, 'server=1\nnot an option\n');
  assert.throws(() => core.setRpcAccess(f, 'pw'), /refusing to edit/);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), 'server=1\nnot an option\n');
  write(f, `server=1\n${core.RPC_BEGIN}\nrpcauth=x:00$${'0'.repeat(64)}\n`);
  assert.throws(() => core.setRpcAccess(f, null), /no end marker/);
});

t('the mock node applies rpcauth and rpcwhitelist like bitcoind, after a restart', async () => {
  const f = path.join(tmp, 'rf', 'bitcoin.conf');
  write(f, 'server=1\n');
  const srv = await rpcServer({ port: 0, conf: f });
  const url = `http://127.0.0.1:${srv.address().port}`;
  const call = (auth, method) => core.rpcCall({ url, auth, method });
  try {
    const pw = core.generateRpcPassword();
    core.setRpcAccess(f, pw);
    assert.strictEqual((await call('nodesignal:' + pw, 'getpeerinfo')).code, 'auth', 'the node reads bitcoin.conf at start only');
    srv.reload();
    for (const m of core.RPC_METHODS) assert((await call('nodesignal:' + pw, m)).ok, m);
    assert.strictEqual((await call('nodesignal:' + pw, 'dumpprivkey')).code, 'forbidden', 'whitelist enforced');
    assert.strictEqual((await call('nodesignal:wrong', 'getpeerinfo')).code, 'auth');
    assert((await call('u:p', 'getpeerinfo')).ok, 'rpcwhitelistdefault=0 keeps other users working');
    // without our rpcwhitelistdefault=0, the first whitelist would lock them out
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('rpcwhitelistdefault=0\n', ''));
    srv.reload();
    assert.strictEqual((await call('u:p', 'getpeerinfo')).code, 'forbidden');
  } finally { srv.close(); }
});

t('cli setup (the .deb postinst step): nodesignal user, rpcauth, never the cookie', async () => {
  const { r } = fakeRoot('deb', { conf: 'server=1\nrpcport=18555\n' });
  const confFile = path.join(r, 'home/alice/.bitcoin/bitcoin.conf');
  const origConf = fs.readFileSync(confFile, 'utf8');
  write(path.join(r, 'home/alice/.bitcoin/.cookie'), '__cookie__:abc');
  // an older 1.3 pre-release: drop-in running as the node owner, state in her home
  write(path.join(r, 'etc/systemd/system/nodesignal.service.d/10-user.conf'), '# Written by nodesignal setup. Re-detect with: sudo nodesignal setup --redetect\n[Service]\nUser=alice\n');
  write(path.join(r, 'home/alice/.nodesignal/state.json'), '{"old":true}');
  write(path.join(r, 'etc/nodesignal/config.json'), JSON.stringify({ nick: 'kept', data: '/home/alice/.nodesignal', 'rpc-cookie': '/home/alice/.bitcoin/.cookie' }));
  const run = (...a) => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r, ...a], { encoding: 'utf8', timeout: 30000 });
  const out = run();
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert(/Service user: nodesignal/.test(out.stdout), out.stdout);
  assert(/restart bitcoind/i.test(out.stdout), 'tells the operator to restart the node');
  const cfg = JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'));
  assert.strictEqual(cfg.nick, 'kept');
  assert.strictEqual(cfg.data, '/var/lib/nodesignal');
  assert.strictEqual(cfg['rpc-user'], 'nodesignal');
  assert(cfg['rpc-pass'] && cfg['rpc-pass'].length >= 43);
  assert.strictEqual(cfg['rpc-url'], 'http://127.0.0.1:18555', 'the daemon cannot read bitcoin.conf, so it is told the port');
  assert(!('rpc-cookie' in cfg) && !('rpc-conf' in cfg), 'no cookie, no bitcoin.conf pointer');
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(path.join(r, 'etc/nodesignal/config.json')).mode & 0o777, 0o600);
  assert(!out.stdout.includes(cfg['rpc-pass']), 'password never printed');
  const conf = fs.readFileSync(confFile, 'utf8');
  assert(!conf.includes(cfg['rpc-pass']));
  assert(core.rpcAuthMatches(core.rpcAccessState(confFile).rpcauth, 'nodesignal', cfg['rpc-pass']));
  assert.strictEqual(fs.readFileSync(path.join(r, 'etc/nodesignal/bitcoin-conf'), 'utf8').trim(), '/home/alice/.bitcoin/bitcoin.conf');
  assert(!fs.existsSync(path.join(r, 'etc/systemd/system/nodesignal.service.d/10-user.conf')), 'old drop-in removed');
  assert.strictEqual(fs.readFileSync(path.join(r, 'var/lib/nodesignal/state.json'), 'utf8'), '{"old":true}', 'state copied');
  assert(fs.existsSync(path.join(r, 'home/alice/.nodesignal/state.json')), 'original kept');
  // a second run (an upgrade) changes nothing in bitcoin.conf: no restart needed
  const again = run();
  assert.strictEqual(again.status, 0, again.stdout);
  assert.strictEqual(fs.readFileSync(confFile, 'utf8'), conf);
  assert(!/restart bitcoind/i.test(again.stdout), again.stdout);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'))['rpc-pass'], cfg['rpc-pass']);
  // purge's job, as postrm does it, restores bitcoin.conf
  const purge = spawnSync('sh', [path.join(ROOT, 'packaging/deb/postrm'), 'purge'], { encoding: 'utf8', env: Object.assign({}, process.env, { NODESIGNAL_TEST_ROOT: r }) });
  assert.strictEqual(purge.status, 0, purge.stdout + purge.stderr);
  assert.strictEqual(fs.readFileSync(confFile, 'utf8'), origConf, 'purge removes exactly our lines');
  assert(!fs.existsSync(path.join(r, 'etc/nodesignal')));
  assert(fs.existsSync(path.join(r, 'var/lib/nodesignal/state.json')), 'purge never deletes identity or history');
});

t('cli setup carries a 1.2 from-source unit over: its history, never its RPC password', async () => {
  // 1.2 kept everything on the ExecStart line and history in ~/.nodesignal of User=
  const { r } = fakeRoot('deb12', { conf: 'server=1\nrpcuser=pool\nrpcpassword=poolsecret\n' });
  const unit = '/etc/systemd/system/nodesignal.service';
  write(path.join(r, unit), '[Service]\nUser=alice\nExecStart=/usr/bin/node /opt/ns/nodesignald.js --nick oldbox --web-port 8789 --rpc-user pool --rpc-pass poolsecret\n');
  write(path.join(r, 'home/alice/.nodesignal/state.json'), '{"v12":true}');
  const out = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r, '--migrate-unit', unit], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert(/Copied your identity and history from \/home\/alice\/\.nodesignal/.test(out.stdout), out.stdout);
  assert.strictEqual(fs.readFileSync(path.join(r, 'var/lib/nodesignal/state.json'), 'utf8'), '{"v12":true}');
  assert(fs.existsSync(path.join(r, 'home/alice/.nodesignal/state.json')), 'original kept');
  const cfg = JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'));
  assert.strictEqual(cfg.nick, 'oldbox');
  assert.strictEqual(cfg['rpc-user'], 'nodesignal', 'its own login, not the old shared one');
  assert(!JSON.stringify(cfg).includes('poolsecret'));
  // --data on the old line wins over the home folder
  const { r: r2 } = fakeRoot('deb12b', { conf: 'server=1\n' });
  write(path.join(r2, unit), '[Service]\nExecStart=/usr/bin/node nodesignald.js --data /srv/ns\n');
  write(path.join(r2, 'srv/ns/state.json'), '{"srv":true}');
  write(path.join(r2, 'root/.nodesignal/state.json'), '{"root":true}');
  const out2 = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r2, '--migrate-unit', unit], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(out2.status, 0, out2.stdout + out2.stderr);
  assert.strictEqual(fs.readFileSync(path.join(r2, 'var/lib/nodesignal/state.json'), 'utf8'), '{"srv":true}');
});

t('cli setup on a fresh machine writes a new config', async () => {
  const { r } = fakeRoot('deb2', { conf: 'server=1\n' });
  const out = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r, '--nick', 'fresh'], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  const cfg = JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'));
  assert.deepStrictEqual(Object.keys(cfg).sort(), ['data', 'nick', 'rpc-pass', 'rpc-url', 'rpc-user', 'web-token']);
  // other accounts on a server reach 127.0.0.1 too, so the console gets a
  // login token; apt logs install output, so it is never printed
  assert(cfg['web-token'].length >= 32);
  assert(!out.stdout.includes(cfg['web-token']), 'token never printed by setup');
  assert(/sudo nodesignal web-token/.test(out.stdout), out.stdout);
  const cli = (...a) => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), ...a, '--config', path.join(r, 'etc/nodesignal/config.json')], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(cli('web-token').stdout.trim(), cfg['web-token'], 'web-token shows it');
  const fresh2 = cli('web-token', 'new');
  const tok2 = JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'))['web-token'];
  assert(tok2 && tok2 !== cfg['web-token'] && fresh2.stdout.includes(tok2), 'new replaces it');
  cli('web-token', 'off');
  const readTok = () => JSON.parse(fs.readFileSync(path.join(r, 'etc/nodesignal/config.json'), 'utf8'))['web-token'];
  assert.strictEqual(readTok(), '', 'off empties it');
  // an upgrade (setup again) keeps the operator's "off"
  const again = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(again.status, 0, again.stdout);
  assert.strictEqual(readTok(), '', 'setup on an upgrade keeps it off');
  assert(/no login token/i.test(cli('web-token').stdout));
  assert.strictEqual(cfg.nick, 'fresh');
  assert.strictEqual(cfg['rpc-url'], 'http://127.0.0.1:8332');
  assert(fs.statSync(path.join(r, 'var/lib/nodesignal')).isDirectory());
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
