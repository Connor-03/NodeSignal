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
// As root, bitcoin.conf is edited as its owner (alice, uid 1000 below), who
// must be able to reach her own files, as on a real machine.
fs.chmodSync(tmp, 0o755);
const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
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

t('writeConfig never writes through a link left beside the config (the old temp name was predictable)', () => {
  if (process.platform === 'win32') return;
  const d = path.join(tmp, 'cfg-links'); fs.mkdirSync(d, { recursive: true });
  const f = path.join(d, 'config.json'), victim = path.join(tmp, 'victim.txt');
  fs.writeFileSync(victim, 'untouched\n');
  // what the old code wrote to, and a link in place of the config itself
  fs.symlinkSync(victim, f + '.tmp-' + process.pid);
  fs.symlinkSync(victim, f);
  core.writeConfig(f, { nick: 'x', 'rpc-pass': 'secret' });
  assert.strictEqual(fs.readFileSync(victim, 'utf8'), 'untouched\n', 'the link target is untouched');
  assert(!fs.lstatSync(f).isSymbolicLink() && JSON.parse(fs.readFileSync(f, 'utf8')).nick === 'x', 'the config is a new plain file');
  assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
  assert.deepStrictEqual(fs.readdirSync(d).filter((x) => /\.tmp-/.test(x) && !fs.lstatSync(path.join(d, x)).isSymbolicLink()), [], 'no temp file left');
  core.writeRpcRecord(f, '/home/alice/.bitcoin/bitcoin.conf');
  assert.strictEqual(fs.readFileSync(path.join(d, 'bitcoin-conf'), 'utf8'), '/home/alice/.bitcoin/bitcoin.conf\n');
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

t('termStyle: colour on a terminal only; NO_COLOR wins; FORCE_COLOR=3 is 24-bit', () => {
  const tty = { isTTY: true, getColorDepth: () => 4 }, pipe = { isTTY: false };
  assert.strictEqual(core.termStyle(pipe, {}).on, false, 'a pipe or log gets no colour');
  assert.strictEqual(core.termStyle(tty, {}).on, true);
  assert.strictEqual(core.termStyle(tty, { NO_COLOR: '1' }).on, false);
  assert.strictEqual(core.termStyle(tty, { NO_COLOR: '1', FORCE_COLOR: '1' }).on, false, 'NO_COLOR wins');
  assert.strictEqual(core.termStyle(pipe, { FORCE_COLOR: '1' }).on, true);
  assert.strictEqual(core.termStyle(tty, {}).rich, false, '16 colours unless the console reports 24-bit');
  assert.strictEqual(core.termStyle({ isTTY: true, getColorDepth: () => 24 }, {}).rich, true);
  assert.strictEqual(core.termStyle(pipe, { FORCE_COLOR: '3' }).rich, true);
  const c16 = core.termStyle(tty, {});
  assert.strictEqual(c16.fg('orange', 'x'), '\x1b[33mx\x1b[0m', 'basic colours on an older console');
});

t('termStyle: plain mode is ASCII with no escapes; colour mode uses only WGL4 symbols', () => {
  const plain = core.termStyle({ isTTY: false }, {});
  const out = [plain.fg('red', 'a', true), plain.bg('yellow', 'b'), plain.gradient('NODE', ['pink', 'cyan']),
    ...plain.box('yellow', 'ACTION NEEDED', ['Close Bitcoin Core or Knots and start it again so it reads the new rpcauth line.'], 50, true),
    ...Object.values(plain.sym)].join('\n');
  assert(/^[\x20-\x7e\n]*$/.test(out), 'plain output: ' + JSON.stringify(out));
  // Consolas and the other console fonts carry WGL4; anything outside it can
  // show as an empty box on a Windows console
  const WGL4 = new Set([0xd7, 0x221a, 0x2500, 0x2502, 0x250c, 0x2510, 0x2514, 0x2518, 0x2550, 0x2551, 0x2554, 0x2557,
    0x255a, 0x255d, 0x2580, 0x2584, 0x2588, 0x25a0, 0x25a1, 0x25b2, 0x25ba, 0x25cf]);
  for (const f of ['setup-core.js', 'packaging/windows/sea-main.js']) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert(/^[\x00-\x7f]*$/.test(src), f + ' stays ASCII: symbols are written as \\u escapes');
    for (const m of src.matchAll(/\\u([0-9a-fA-F]{4})/g)) assert(WGL4.has(parseInt(m[1], 16)), `${f}: \\u${m[1]} is not in WGL4`);
  }
  const col = core.termStyle({ isTTY: true, getColorDepth: () => 24 }, {});
  const rows = col.box('green', 'Done', ['a line long enough that it has to wrap inside the panel, twice over at this width'], 40);
  assert(rows.every((r) => col.width(r) === 42), 'every panel row is the same width: ' + rows.map((r) => col.width(r)));
});

t('cli setup (the .deb postinst step): nodesignal user, rpcauth, never the cookie', async () => {
  const { r, uid } = fakeRoot('deb', { conf: 'server=1\nrpcport=18555\n' });
  const confFile = path.join(r, 'home/alice/.bitcoin/bitcoin.conf');
  const origConf = fs.readFileSync(confFile, 'utf8');
  write(path.join(r, 'home/alice/.bitcoin/.cookie'), '__cookie__:abc');
  // an older 1.3 pre-release: drop-in running as the node owner, state in her
  // home (hers: that daemon ran as her)
  write(path.join(r, 'etc/systemd/system/nodesignal.service.d/10-user.conf'), '# Written by nodesignal setup. Re-detect with: sudo nodesignal setup --redetect\n[Service]\nUser=alice\n');
  write(path.join(r, 'home/alice/.nodesignal/state.json'), '{"old":true}');
  if (asRoot) ownTree(path.join(r, 'home/alice/.nodesignal'), uid);
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
  const { r, uid } = fakeRoot('deb12', { conf: 'server=1\nrpcuser=pool\nrpcpassword=poolsecret\n' });
  const unit = '/etc/systemd/system/nodesignal.service';
  write(path.join(r, unit), '[Service]\nUser=alice\nExecStart=/usr/bin/node /opt/ns/nodesignald.js --nick oldbox --web-port 8789 --rpc-user pool --rpc-pass poolsecret\n');
  write(path.join(r, 'home/alice/.nodesignal/state.json'), '{"v12":true}');
  if (asRoot) ownTree(path.join(r, 'home/alice/.nodesignal'), uid);   // the unit ran as alice
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

t('agent-brief warns about secrets and never contains one; rpc-access rotate makes a new password', async () => {
  const { r } = fakeRoot('agent', { conf: 'server=1\n' });
  const setup = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r, '--nick', 'brief'], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(setup.status, 0, setup.stdout + setup.stderr);
  const cfgFile = path.join(r, 'etc/nodesignal/config.json');
  const confFile = path.join(r, 'home/alice/.bitcoin/bitcoin.conf');
  const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  const cli = (...a) => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), ...a, '--config', cfgFile], { encoding: 'utf8', timeout: 30000 });
  const out = cli('agent-brief');
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert(/will be able to see NodeSignal's secrets/.test(out.stdout), 'the warning comes first');
  assert(/RPC password/.test(out.stdout) && /identity, signing and onion keys/.test(out.stdout) && /sends whatever it reads to its/.test(out.stdout));
  assert(/docs\/AGENT-SETUP\.md/.test(out.stdout) && /do not open or print it/.test(out.stdout));
  for (const secret of [cfg['rpc-pass'], cfg['web-token']]) assert(!out.stdout.includes(secret), 'no secret in the brief');
  const file = path.join(r, 'brief.txt');
  const toFile = cli('agent-brief', '--file', file);
  assert.strictEqual(toFile.status, 0, toFile.stdout + toFile.stderr);
  const brief = fs.readFileSync(file, 'utf8');
  assert(brief.startsWith('Please check NodeSignal'), brief);
  assert(!brief.includes(cfg['rpc-pass']) && !brief.includes(cfg['web-token']));
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
  // rotate: a new password in the config and a matching rpcauth hash, the old one no longer works
  const rot = cli('rpc-access', 'rotate', '--bitcoin-conf', confFile);
  assert.strictEqual(rot.status, 0, rot.stdout + rot.stderr);
  const cfg2 = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  assert(cfg2['rpc-pass'] && cfg2['rpc-pass'] !== cfg['rpc-pass'], 'a new password');
  assert(!rot.stdout.includes(cfg2['rpc-pass']), 'never printed');
  const st = core.rpcAccessState(confFile);
  assert(core.rpcAuthMatches(st.rpcauth, 'nodesignal', cfg2['rpc-pass']));
  assert(!core.rpcAuthMatches(st.rpcauth, 'nodesignal', cfg['rpc-pass']));
  assert(/restart/i.test(rot.stdout), 'tells the operator to restart the node');
  assert.strictEqual(cfg2['web-token'], cfg['web-token'], 'rotate leaves everything else alone');
});

/* ---------------------------------------------------------- root and other accounts' files
   Root edits bitcoin.conf, NodeSignal's state folder and the update folder,
   all of which other accounts control. Root cause of the escalations these
   guard (Oct 2026 review): root followed links those accounts planted (the
   one-time backup, a dangling link, a swapped file) and wrote or chowned
   whatever they pointed at. Root now works there as the owner. */
// cli.js in a child process with the service hooks stubbed (no test ever runs
// systemctl) and a /health that never answers
function cliHooked(args, { input = '', env = {} } = {}) {
  const code = `const core = Object.assign({}, require(${JSON.stringify(path.join(ROOT, 'setup-core.js'))}), { httpGetJson: async () => ({ ok: false, error: 'test' }) });
require(${JSON.stringify(path.join(ROOT, 'cli.js'))}).main(JSON.parse(process.env.NS_ARGS), { core, hooks: { restart: async () => 0, stop: async () => {}, start: async () => {} } }).then((c) => process.exit(c || 0));`;
  return spawnSync(process.execPath, ['-e', code], { input, encoding: 'utf8', timeout: 60000, env: Object.assign({}, process.env, env, { NS_ARGS: JSON.stringify(args) }) });
}
const NODE_UID = 4243, OTHER_UID = 4244;   // unused accounts in the test machine
function ownTree(p, uid) { fs.chownSync(p, uid, uid); if (fs.lstatSync(p).isDirectory()) for (const e of fs.readdirSync(p)) ownTree(path.join(p, e), uid); }

t('as root, bitcoin.conf is edited as its owner: a link planted as the backup is never written through', () => {
  if (!asRoot) return 'skip needs root (CI runs this suite as a normal user)';
  const base = path.join(tmp, 'own'), node = path.join(base, 'node'), safe = path.join(base, 'rootonly');
  fs.mkdirSync(node, { recursive: true }); fs.mkdirSync(safe, { mode: 0o700 });
  const victim = path.join(safe, 'victim.sh'), never = path.join(safe, 'never-created');
  fs.writeFileSync(victim, 'root only\n', { mode: 0o600 });
  const conf = path.join(node, 'bitcoin.conf');
  fs.writeFileSync(conf, 'server=1\n', { mode: 0o600 });
  ownTree(node, NODE_UID);
  // the node's user plants the one-time backup as a link to a root file
  fs.symlinkSync(victim, conf + core.BACKUP_SUFFIX);
  const r = core.setRpcAccess(conf, 'pw');
  assert(r.changed && r.backup === null, 'no backup through the link');
  assert.strictEqual(fs.readFileSync(victim, 'utf8'), 'root only\n', 'the link target is untouched');
  assert.strictEqual(fs.statSync(victim).uid, 0, 'and still root\'s');
  assert(core.rpcAccessState(conf).on);
  assert.strictEqual(fs.statSync(conf).uid, NODE_UID, 'bitcoin.conf keeps its owner');
  // a dangling link as the backup: nothing is created through it
  fs.unlinkSync(conf + core.BACKUP_SUFFIX); fs.symlinkSync(never, conf + core.BACKUP_SUFFIX);
  assert(core.setRpcAccess(conf, null).changed);
  assert(!fs.existsSync(never), 'nothing created at the dangling link\'s target');
  // the backup is made by the owner, not by root
  fs.unlinkSync(conf + core.BACKUP_SUFFIX);
  assert(core.setUaComment(conf, true).backup);
  assert.strictEqual(fs.lstatSync(conf + core.BACKUP_SUFFIX).uid, NODE_UID, 'the backup was created by the owner');
  // root's own rights are never used: a file its owner may not write stays as it is
  fs.chmodSync(conf, 0o400);
  const before = fs.readFileSync(conf, 'utf8');
  assert.throws(() => core.setUaComment(conf, false), /cannot write .*EACCES/);
  assert.strictEqual(fs.readFileSync(conf, 'utf8'), before);
  assert.strictEqual(process.geteuid(), 0, 'back to root afterwards');
});

t('as root, a symlinked bitcoin.conf is followed and edited as the real file\'s owner; a new one as its folder\'s owner', () => {
  if (!asRoot) return 'skip needs root (CI runs this suite as a normal user)';
  const base = path.join(tmp, 'own2'), disk = path.join(base, 'disk'), node = path.join(base, 'node');
  fs.mkdirSync(disk, { recursive: true }); fs.mkdirSync(node);
  const real = path.join(disk, 'bitcoin.conf');
  fs.writeFileSync(real, 'server=1\n', { mode: 0o600 });
  ownTree(disk, OTHER_UID); ownTree(node, NODE_UID);
  const link = path.join(node, 'bitcoin.conf');
  fs.symlinkSync(real, link);
  const r = core.setRpcAccess(link, 'pw');
  assert(r.changed && fs.lstatSync(link).isSymbolicLink(), 'the link stays a link');
  assert(core.rpcAccessState(real).on, 'the real file got the block');
  assert.strictEqual(r.backup, real + core.BACKUP_SUFFIX, 'the backup sits beside the real file');
  assert.strictEqual(fs.statSync(r.backup).uid, OTHER_UID, 'made as the real file\'s owner');
  // a missing bitcoin.conf (and folder) in the node's folder: made by its owner
  const fresh = path.join(node, 'sub', 'bitcoin.conf');
  assert(core.setUaComment(fresh, true).created);
  assert.deepStrictEqual([fs.statSync(fresh).uid, fs.statSync(path.dirname(fresh)).uid], [NODE_UID, NODE_UID]);
  assert.strictEqual(fs.statSync(fresh).mode & 0o777, 0o600);
  // the node's file in a root-owned folder (/etc/bitcoin): edited as its owner,
  // who cannot add a backup beside it, and that is reported, not hidden
  const etc = path.join(base, 'etc-bitcoin'), own = path.join(etc, 'bitcoin.conf');
  fs.mkdirSync(etc); fs.writeFileSync(own, 'server=1\n', { mode: 0o600 }); fs.chownSync(own, NODE_UID, NODE_UID);
  const r2 = core.setUaComment(own, true);
  assert(r2.changed && core.uaCommentState(own).on);
  assert.deepStrictEqual([r2.backup, r2.backupError], [null, 'EACCES']);
});

t('as root, a root-owned bitcoin.conf is refused when another account can change a folder above it', () => {
  if (!asRoot) return 'skip needs root (CI runs this suite as a normal user)';
  const base = path.join(tmp, 'own3');
  const mk = (name, mode, uid) => {
    const d = path.join(base, name); fs.mkdirSync(d, { recursive: true }); fs.chmodSync(d, mode); fs.chownSync(d, uid, uid);
    const f = path.join(d, 'bitcoin.conf'); fs.writeFileSync(f, 'server=1\n'); fs.chownSync(f, 0, 0); return f;
  };
  const theirs = mk('theirs', 0o755, NODE_UID), open = mk('open', 0o777, 0), sticky = mk('sticky', 0o1777, 0);
  assert.throws(() => core.setRpcAccess(theirs, 'pw'), /refusing to edit .* as root: .*theirs can be changed by an account other than root \(it belongs to uid 4243\)\. Add the lines by hand/);
  assert.throws(() => core.setUaComment(open, true), /refusing to edit .* as root: .*open can be changed .*accounts other than root can write to it/);
  for (const f of [theirs, open]) { assert.strictEqual(fs.readFileSync(f, 'utf8'), 'server=1\n'); assert(!fs.existsSync(f + core.BACKUP_SUFFIX)); }
  assert(core.setRpcAccess(sticky, 'pw').changed, 'a sticky folder (like /tmp) is fine');
  // the CLI says so and how to do it by hand
  write(path.join(base, 'config.json'), '{}');
  const out = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'rpc-access', 'add', '--bitcoin-conf', theirs, '--config', path.join(base, 'config.json')], { encoding: 'utf8', timeout: 30000 });
  assert.notStrictEqual(out.status, 0); assert.match(out.stdout, /Add the lines by hand/);
});

// a root-owned program that only root can change, for a "trusted" node
const ROOT_BIN = ['/bin/sh', '/usr/bin/env', '/bin/ls'].find((b) => { try { const s = fs.statSync(b); return s.uid === 0 && !(s.mode & 0o022); } catch { return false; } });
function fakeProc(r, pid, { uid, args, exe }) {
  write(path.join(r, `proc/${pid}/comm`), 'bitcoind\n');
  write(path.join(r, `proc/${pid}/cmdline`), ['bitcoind', ...args].join('\0') + '\0');
  write(path.join(r, `proc/${pid}/status`), `Name:\tbitcoind\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\n`);
  if (exe) fs.symlinkSync(exe, path.join(r, `proc/${pid}/exe`));
}

t('detectBitcoinNode: a bitcoind another account runs from its own program is ignored when a root-installed one runs', async () => {
  if (!ROOT_BIN) return 'skip no root-owned program to stand in for bitcoind';
  const { r, uid } = fakeRoot('trust', { conf: 'server=1\n', proc: false });
  fakeProc(r, 4242, { uid, args: ['-daemon'], exe: ROOT_BIN });
  // another local account: its own "bitcoind", its own conf and datadir
  write(path.join(r, 'home/mal/bitcoind'), '#!/bin/sh\n');
  write(path.join(r, 'home/mal/evil.conf'), 'rpcport=19999\nrpcconnect=203.0.113.9\n');
  fs.mkdirSync(path.join(r, 'home/mal/dd/blocks'), { recursive: true });
  if (asRoot) ownTree(path.join(r, 'home/mal'), OTHER_UID);
  fakeProc(r, 4250, { uid: asRoot ? OTHER_UID : uid, args: ['-conf=/home/mal/evil.conf', '-datadir=/home/mal/dd'], exe: path.join(r, 'home/mal/bitcoind') });
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.deepStrictEqual(d.processes.map((p) => p.pid), [4242]);
  assert.strictEqual(d.datadir, '/home/alice/.bitcoin');
  assert.strictEqual(d.confPath, '/home/alice/.bitcoin/bitcoin.conf');
  assert.strictEqual(d.rpcUrl, 'http://127.0.0.1:8332');
  assert(d.how.some((h) => /^ignored bitcoind \(pid 4250\): its program is not a root-owned file/.test(h)), d.how.join(' | '));
  // with no root-installed node running, nothing is ignored (as before)
  fs.unlinkSync(path.join(r, 'proc/4242/exe'));
  const d2 = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.deepStrictEqual(d2.processes.map((p) => p.pid).sort(), [4242, 4250]);
});

t('detectBitcoinNode: a -conf or -datadir owned by neither root nor the node\'s user is ignored', async () => {
  if (!asRoot) return 'skip needs root to make files of another account';
  if (!ROOT_BIN) return 'skip no root-owned program to stand in for bitcoind';
  const { r, uid } = fakeRoot('trust2', { conf: 'server=1\n', proc: false });
  write(path.join(r, 'home/mal/evil.conf'), 'rpcport=19999\n');
  fs.mkdirSync(path.join(r, 'home/mal/dd/blocks'), { recursive: true });
  ownTree(path.join(r, 'home/mal'), OTHER_UID);
  fakeProc(r, 4242, { uid, args: ['-conf=/home/mal/evil.conf', '-datadir=/home/mal/dd'], exe: ROOT_BIN });
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.strictEqual(d.confPath, '/home/alice/.bitcoin/bitcoin.conf', 'the other account\'s conf is not used');
  assert.strictEqual(d.datadir, '/home/alice/.bitcoin');
  assert(d.how.some((h) => /^ignored -conf=\/home\/mal\/evil\.conf of bitcoind \(pid 4242\): it belongs to uid 4244/.test(h)), d.how.join(' | '));
  assert(d.how.some((h) => /^ignored -datadir=\/home\/mal\/dd/.test(h)));
  // the node's own (or root's) files are used as before
  ownTree(path.join(r, 'home/mal'), uid);
  const d2 = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.strictEqual(d2.confPath, '/home/mal/evil.conf');
});

t('Tor group: setup adds nodesignal unless "onion": "off"; onion off removes it, onion on adds it back', async () => {
  const { r } = fakeRoot('tor', { conf: 'server=1\n' });
  fs.appendFileSync(path.join(r, 'etc/group'), 'debian-tor:x:120:\n');
  const cfgFile = path.join(r, 'etc/nodesignal/config.json');
  const members = () => fs.readFileSync(path.join(r, 'etc/group'), 'utf8').match(/^debian-tor:x:120:(.*)$/m)[1];
  const setup = () => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r], { encoding: 'utf8', timeout: 30000 });
  let out = setup();
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.strictEqual(members(), 'nodesignal');
  assert.match(out.stdout, /Tor: added nodesignal to the debian-tor group/);
  // the service user, as the .deb makes it
  fs.appendFileSync(path.join(r, 'etc/passwd'), 'nodesignal:x:999:999::/var/lib/nodesignal:/usr/sbin/nologin\n');
  out = cliHooked(['onion', 'off', '--config', cfgFile], { env: { NODESIGNAL_TEST_ROOT: r } });
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.strictEqual(members(), '', 'onion off takes the membership away');
  assert.match(out.stdout, /Tor: removed nodesignal from the debian-tor group/);
  // an upgrade (setup again) keeps the operator's "off"
  out = setup();
  assert.strictEqual(members(), '');
  assert.match(out.stdout, /onion is off in the config, so nodesignal stays out of the debian-tor group/);
  out = cliHooked(['onion', 'on', '--config', cfgFile], { env: { NODESIGNAL_TEST_ROOT: r } });
  assert.strictEqual(members(), 'nodesignal');
  assert.match(out.stdout, /Tor: added nodesignal to the debian-tor group/);
  // "off" written into the config by hand: setup takes the membership away too
  const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8')); cfg.onion = 'off'; fs.writeFileSync(cfgFile, JSON.stringify(cfg));
  out = setup();
  assert.strictEqual(members(), '');
  assert.match(out.stdout, /removed nodesignal from the debian-tor group \(onion is off in the config\)/);
});

t('setup hands the state folder to nodesignal without following a link planted in it', () => {
  if (!asRoot) return 'skip needs root (chown)';
  const { r } = fakeRoot('chown', { conf: 'server=1\n' });
  const victim = path.join(tmp, 'chown-victim');
  fs.writeFileSync(victim, 'root only\n', { mode: 0o600 });
  write(path.join(r, 'var/lib/nodesignal/state.json'), '{}');
  write(path.join(r, 'var/lib/nodesignal/deep/x.json'), '{}');
  fs.symlinkSync(victim, path.join(r, 'var/lib/nodesignal/planted'));
  fs.symlinkSync(tmp, path.join(r, 'var/lib/nodesignal/planted-dir'));
  const out = spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r], { encoding: 'utf8', timeout: 30000 });
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  for (const f of ['', 'state.json', 'deep', 'deep/x.json']) assert.strictEqual(fs.lstatSync(path.join(r, 'var/lib/nodesignal', f)).uid, 999, f || 'the folder');
  assert.strictEqual(fs.statSync(victim).uid, 0, 'the link target stays root\'s');
  assert.strictEqual(fs.statSync(tmp).uid, 0, 'so does a linked folder');
});

t('install.js hands paths to PowerShell through the environment, never inside the script text', () => {
  // Root cause it guards: the Desktop shortcut script put the folder paths
  // inside single-quoted PowerShell strings, so a quote in a folder name
  // ended the string and the rest ran as code.
  const src = fs.readFileSync(path.join(ROOT, 'install.js'), 'utf8');
  const scripts = [...src.matchAll(/const ps = ([\s\S]*?);\n/g)].map((m) => m[1]);
  assert(scripts.length >= 1 && /powershell/.test(src));
  for (const s of scripts) {
    assert(!/\$\{/.test(s), 'no value interpolated into the script: ' + s);
    assert(/\$env:NS_/.test(s), 'values come from $env:NS_*');
  }
});

t('purge (postrm) rewrites bitcoin.conf as its owner, and leaves a root-owned one in another account\'s folder alone', () => {
  if (!asRoot) return 'skip needs root (setpriv)';
  const block = `${core.RPC_BEGIN}\nrpcauth=nodesignal:00$${'0'.repeat(64)}\n${core.RPC_END}\n`;
  const purge = (r) => spawnSync('sh', [path.join(ROOT, 'packaging/deb/postrm'), 'purge'], { encoding: 'utf8', env: Object.assign({}, process.env, { NODESIGNAL_TEST_ROOT: r }) });
  // the owner may not write it (0400): root would, the owner cannot, so it stays
  const { r } = fakeRoot('purge-owner', { conf: 'server=1\n' + block });
  const conf = path.join(r, 'home/alice/.bitcoin/bitcoin.conf');
  ownTree(path.join(r, 'home/alice'), NODE_UID);
  fs.chmodSync(conf, 0o400);
  write(path.join(r, 'etc/nodesignal/bitcoin-conf'), '/home/alice/.bitcoin/bitcoin.conf\n');
  let out = purge(r);
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.match(out.stdout, /Could not rewrite .* as its owner/);
  assert(fs.readFileSync(conf, 'utf8').includes(core.RPC_BEGIN), 'not written with root\'s rights');
  // writable by its owner: the block goes, the owner and mode stay
  fs.chmodSync(conf, 0o600);
  write(path.join(r, 'etc/nodesignal/bitcoin-conf'), '/home/alice/.bitcoin/bitcoin.conf\n');
  out = purge(r);
  assert.strictEqual(fs.readFileSync(conf, 'utf8'), 'server=1\n', out.stdout + out.stderr);
  assert.deepStrictEqual([fs.statSync(conf).uid, fs.statSync(conf).mode & 0o777], [NODE_UID, 0o600]);
  // a root-owned bitcoin.conf in a folder another account controls
  const { r: r2 } = fakeRoot('purge-root', { conf: 'server=1\n' + block });
  const conf2 = path.join(r2, 'home/alice/.bitcoin/bitcoin.conf');
  ownTree(path.join(r2, 'home/alice'), NODE_UID); fs.chownSync(conf2, 0, 0);
  write(path.join(r2, 'etc/nodesignal/bitcoin-conf'), '/home/alice/.bitcoin/bitcoin.conf\n');
  out = purge(r2);
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.match(out.stdout, /Left .* alone: an account other than root can change a folder above/);
  assert(fs.readFileSync(conf2, 'utf8').includes(core.RPC_BEGIN));
});

/* ---------------------------------------------------------- the old state folder (setup, as root)
   Root cause (Oct 2026 final review): setup copied an older install's state
   folder with fs.cpSync as root. Its path is the "data" of a config the
   nodesignal account can write, and cpSync followed a link that account had
   left in /var/lib/nodesignal, so root wrote files of its choosing anywhere. */
const runSetup = (r, ...a) => spawnSync(process.execPath, [path.join(ROOT, 'cli.js'), 'setup', '--root', r, ...a], { encoding: 'utf8', timeout: 30000 });

t('setup refuses an old state folder inside /var/lib/nodesignal and never writes through a link there (final review poc2)', () => {
  const { r } = fakeRoot('fr1', { conf: 'server=1\n' });
  const sd = path.join(r, 'var/lib/nodesignal'), target = path.join(tmp, 'fr1-target');
  fs.mkdirSync(target, { mode: 0o700 });
  // the nodesignal account: a folder of its own holding state.json and
  // evil/payload, a link named evil beside it, no state.json of its own, and
  // "data" in the config pointing at that folder
  write(path.join(sd, 'sub/state.json'), '{}');
  write(path.join(sd, 'sub/evil/payload'), 'planted\n');
  fs.symlinkSync(target, path.join(sd, 'evil'));
  if (asRoot) { fs.chownSync(sd, 999, 999); ownTree(path.join(sd, 'sub'), 999); fs.lchownSync(path.join(sd, 'evil'), 999, 999); }
  write(path.join(r, 'etc/nodesignal/config.json'), JSON.stringify({ nick: 'x', data: '/var/lib/nodesignal/sub' }));
  const out = runSetup(r);
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.deepStrictEqual(fs.readdirSync(target), [], 'nothing written through the link');
  assert.match(out.stdout, /Did not copy \/var\/lib\/nodesignal\/sub to \/var\/lib\/nodesignal: .* is inside /);
  assert(!fs.existsSync(path.join(sd, 'state.json')));
});

t('setup copies an old state folder as its owner: links on either side and FIFOs are skipped, never followed', () => {
  const { r, uid } = fakeRoot('fr2', { conf: 'server=1\n' });
  const old = path.join(r, 'home/alice/.nodesignal'), sd = path.join(r, 'var/lib/nodesignal');
  const target = path.join(tmp, 'fr2-target'), secret = path.join(tmp, 'fr2-secret.json');
  fs.mkdirSync(target, { mode: 0o700 });
  fs.writeFileSync(secret, '{"only":"root"}', { mode: 0o600 });
  write(path.join(old, 'state.json'), '{"old":true}');
  write(path.join(old, 'social.json'), '{"posts":[]}');
  write(path.join(old, 'sub/x.json'), '{"x":1}');
  fs.symlinkSync(secret, path.join(old, 'leak.json'));        // the old folder's owner links a file only root may read
  spawnSync('mkfifo', [path.join(old, 'fifo')]);
  if (asRoot) { ownTree(path.join(old, 'sub'), uid); for (const f of ['', 'state.json', 'social.json']) fs.chownSync(path.join(old, f), uid, uid); fs.lchownSync(path.join(old, 'leak.json'), uid, uid); }
  fs.mkdirSync(sd, { recursive: true });
  fs.symlinkSync(target, path.join(sd, 'sub'));               // and the nodesignal account plants a link
  if (asRoot) { fs.chownSync(sd, 999, 999); fs.lchownSync(path.join(sd, 'sub'), 999, 999); }
  write(path.join(r, 'etc/nodesignal/config.json'), JSON.stringify({ nick: 'x', data: '/home/alice/.nodesignal' }));
  const out = runSetup(r);
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.match(out.stdout, /Copied your identity and history from \/home\/alice\/\.nodesignal/);
  assert.match(out.stdout, /Not copied: .*fifo \(not a plain file\)/);
  assert.match(out.stdout, /Not copied: .*leak\.json \(a symbolic link\)/);
  assert.strictEqual(fs.readFileSync(path.join(sd, 'state.json'), 'utf8'), '{"old":true}');
  assert.strictEqual(fs.readFileSync(path.join(sd, 'social.json'), 'utf8'), '{"posts":[]}');
  assert(!fs.existsSync(path.join(sd, 'leak.json')), 'a link is not copied');
  assert.deepStrictEqual(fs.readdirSync(target), [], 'nothing written through the planted link');
  if (asRoot) for (const f of ['state.json', 'social.json']) assert.strictEqual(fs.lstatSync(path.join(sd, f)).uid, 999, f + ' written by the service user');
  assert.strictEqual(fs.readFileSync(path.join(old, 'state.json'), 'utf8'), '{"old":true}', 'the original stays');
});

t('copyStateTree refuses a folder that holds the destination, a link, one over the size cap, and a root-owned one another account can change', () => {
  const base = path.join(tmp, 'cst'), src = path.join(base, 'old'), dst = path.join(base, 'new');
  write(path.join(src, 'big.bin'), Buffer.alloc(2048));
  write(path.join(src, 'state.json'), '{}');
  fs.mkdirSync(dst);
  assert.throws(() => core.copyStateTree(base, dst), /is inside/);
  assert.throws(() => core.copyStateTree(src, dst, { maxBytes: 1024 }), /holds more than 1024 bytes/);
  assert.deepStrictEqual(fs.readdirSync(dst), [], 'a refused source writes nothing');
  fs.symlinkSync(src, path.join(base, 'old-link'));
  assert.throws(() => core.copyStateTree(path.join(base, 'old-link'), dst), /not a plain folder/);
  if (asRoot) {
    const theirs = path.join(base, 'theirs');
    write(path.join(theirs, 'ns/state.json'), '{}');
    fs.chownSync(theirs, NODE_UID, NODE_UID);
    assert.throws(() => core.copyStateTree(path.join(theirs, 'ns'), dst), /belongs to root, but .*theirs can be changed by an account other than root/);
  }
  assert.strictEqual(core.copyStateTree(src, dst).files, 2);
});

/* ---------------------------------------------------------- rpcwhitelistdefault
   Root cause (Oct 2026 final review): setRpcAccess decided whether to add
   rpcwhitelistdefault=0 from the top level of bitcoin.conf alone. bitcoind
   makes the default "is any rpcwhitelist set", counting includeconf files
   and its command line, per chain: a whitelist kept in an included file gave
   every other RPC user (the cookie user too) every method, and one in a
   [section] locked them out of the other chains. */
t('setRpcAccess refuses when whitelists may be set where bitcoin.conf does not show them (final review poc5)', () => {
  const cases = [
    ['includeconf', 'server=1\nincludeconf=rpc-users.conf\n', {}, /includeconf/],
    ['includeconf in a section', 'server=1\n[main]\nincludeconf=rpc-users.conf\n', {}, /includeconf/],
    ['section', 'server=1\n\n[test]\nrpcwhitelist=tester:getblockcount\n', {}, /one chain only/],
    ['chain prefix', 'server=1\nmain.rpcwhitelist=electrs:getblock\n', {}, /one chain only/],
    ['negated default in a section', 'server=1\n[main]\nnorpcwhitelistdefault=1\n', {}, /one chain only/],
    ['command line', 'server=1\n', { cmdlineWhitelist: true }, /command line/],
  ];
  for (const [name, text, opts, re] of cases) {
    const f = path.join(tmp, 'wl-' + name.replace(/ /g, '-'), 'bitcoin.conf');
    write(f, text);
    write(path.join(path.dirname(f), 'rpc-users.conf'), 'rpcwhitelist=electrs:getblock\n');
    assert.throws(() => core.setRpcAccess(f, 'pw', opts), (e) => re.test(e.message) && /Add the NodeSignal lines by hand/.test(e.message), name);
    assert.strictEqual(fs.readFileSync(f, 'utf8'), text, name + ': unchanged');
    assert(!fs.existsSync(f + core.BACKUP_SUFFIX), name + ': no backup');
  }
  // a block already there: the same password stays (upgrades), a new one is
  // refused, removing it always works and restores the file
  const f = path.join(tmp, 'wl-existing', 'bitcoin.conf');
  write(f, 'server=1\n');
  core.setRpcAccess(f, 'pw');
  fs.appendFileSync(f, 'includeconf=more.conf\n');
  assert.strictEqual(core.setRpcAccess(f, 'pw').changed, false);
  assert.throws(() => core.setRpcAccess(f, 'pw2'), /includeconf/);
  assert(core.setRpcAccess(f, null).changed);
  assert.strictEqual(fs.readFileSync(f, 'utf8'), 'server=1\nincludeconf=more.conf\n');
});

t('setup leaves bitcoin.conf alone, and prints the lines, when the running bitcoind has -rpcwhitelist on its command line', async () => {
  const { r, uid } = fakeRoot('wlcmd', { conf: 'server=1\n', proc: false });
  fakeProc(r, 4242, { uid, args: ['-daemon', '-rpcwhitelist=electrs:getblock'] });
  const conf = path.join(r, 'home/alice/.bitcoin/bitcoin.conf');
  const d = await core.detectBitcoinNode({ root: r, platform: 'linux' });
  assert.strictEqual(d.rpcWhitelistOnCmdline, true);
  const out = runSetup(r);
  assert.strictEqual(out.status, 0, out.stdout + out.stderr);
  assert.strictEqual(fs.readFileSync(conf, 'utf8'), 'server=1\n');
  assert.match(out.stdout, /command line\..*Add the NodeSignal lines by hand/);
  assert.match(out.stdout, /^ {2}rpcauth=nodesignal:[0-9a-f]+\$[0-9a-f]{64}$/m, 'the lines to add by hand');
  assert.match(out.stdout, /rpcwhitelistdefault=0 +\(only if nothing else sets rpcwhitelist/);
  // without the option, as before
  write(path.join(r, 'proc/4242/cmdline'), 'bitcoind\0-daemon\0');
  assert.strictEqual(runSetup(r).status, 0);
  assert(core.rpcAccessState(conf).on);
  assert(/^rpcwhitelistdefault=0$/m.test(fs.readFileSync(conf, 'utf8')));
});

(async () => {
  for (const [name, fn] of tests) {
    try {
      const r = await fn();
      console.log(typeof r === 'string' && r.startsWith('skip') ? `  skip ${name}: ${r.slice(5)}` : '  ok   ' + name);
    }
    catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exit(failed ? 1 : 0);
})();
