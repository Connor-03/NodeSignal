// backup-cli.test.js: "nodesignal backup" and "nodesignal restore" (cli.js). Plain node.
//   node tests/backup-cli.test.js
// No daemon and no ports: the service hooks are stubbed and /health never
// answers. A few seconds: every backup made or read runs scrypt at the real
// cost. The root-only part needs root (CI runs the suite as a normal user).
// Root causes it guards (Oct 2026 review):
// - "sudo nodesignal restore" wrote state.json.tmp and chowned state.json as
//   root inside the nodesignal-owned state folder, following links that
//   account planted: root wrote into any file and handed it over.
// - with piped input the passphrase prompt echoed the passphrase back.
// - a restore from a script replaced the identity without any confirmation.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const { spawnSync } = require('child_process');
const noise = require('../noise.js');

const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-backup-cli-'));
const PASS = 'correct horse battery staple';
const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const DAEMON_UID = 4242;   // an unused account standing in for nodesignal
let failed = 0, passed = 0, skipped = 0;
const tests = [];
const t = (name, fn) => tests.push([name, fn]);

// cli.js in a child process with the service hooks stubbed (no systemctl) and
// a /health that never answers, so "the daemon is stopped"
function cli(args, { input = '' } = {}) {
  const code = `const core = Object.assign({}, require(${JSON.stringify(path.join(ROOT, 'setup-core.js'))}), { httpGetJson: async () => ({ ok: false, error: 'test' }) });
require(${JSON.stringify(path.join(ROOT, 'cli.js'))}).main(JSON.parse(process.env.NS_ARGS), { core, hooks: { restart: async () => 0, stop: async () => {}, start: async () => {} } }).then((c) => process.exit(c || 0));`;
  const r = spawnSync(process.execPath, ['-e', code], { input, encoding: 'utf8', timeout: 60000, env: Object.assign({}, process.env, { NS_ARGS: JSON.stringify(args) }) });
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}
// one machine: a state folder with an identity, and a config pointing at it
function machine(name) {
  const base = path.join(TMP, name), dir = path.join(base, 'state'), cfg = path.join(base, 'config.json');
  fs.mkdirSync(base); fs.mkdirSync(dir, { mode: 0o700 });
  const identity = noise.newIdentity();
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ identity, contacts: { 'h': { host: '192.0.2.7', port: 8788, msgs: [{ text: 'kept' }] } } }), { mode: 0o600 });
  fs.writeFileSync(cfg, JSON.stringify({ nick: name, data: dir }));
  return { base, dir, cfg, identity, state: path.join(dir, 'state.json') };
}
const identityIn = (file) => JSON.parse(fs.readFileSync(file, 'utf8')).identity.pub;
const ownTree = (p, uid) => { fs.chownSync(p, uid, uid); if (fs.lstatSync(p).isDirectory()) for (const e of fs.readdirSync(p)) ownTree(path.join(p, e), uid); };

t('backup and restore never print the passphrase (piped input)', () => {
  const a = machine('echo-a'), b = machine('echo-b'), file = path.join(TMP, 'echo.ns');
  let r = cli(['backup', file, '--config', a.cfg], { input: `${PASS}\n${PASS}\n` });
  assert.strictEqual(r.code, 0, r.out);
  assert(fs.existsSync(file));
  assert(!r.out.includes(PASS), 'backup printed the passphrase:\n' + r.out);
  assert.match(r.out, /Passphrase for the backup/);
  r = cli(['restore', file, '--yes', '--config', b.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 0, r.out);
  assert(!r.out.includes(PASS), 'restore printed the passphrase:\n' + r.out);
  assert.strictEqual(identityIn(b.state), a.identity.pub, 'the identity came across');
});

t('restore from a script needs --yes; without it nothing changes', () => {
  const a = machine('yes-a'), b = machine('yes-b'), file = path.join(TMP, 'yes.ns');
  assert.strictEqual(cli(['backup', file, '--config', a.cfg], { input: `${PASS}\n${PASS}\n` }).code, 0);
  const before = fs.readFileSync(b.state);
  let r = cli(['restore', file, '--config', b.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /Nothing changed: not run from a terminal, so confirm with --yes/);
  assert(fs.readFileSync(b.state).equals(before), 'state.json untouched');
  assert.deepStrictEqual(fs.readdirSync(b.dir), ['state.json'], 'nothing else written');
  r = cli(['restore', file, '--yes', '--config', b.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(identityIn(b.state), a.identity.pub);
  const st = JSON.parse(fs.readFileSync(b.state, 'utf8'));
  assert.strictEqual(st.contacts.h.msgs[0].text, 'kept', 'history kept');
  assert(fs.readdirSync(b.dir).some((f) => /^state\.json\.before-restore-\d+$/.test(f)), 'the old state kept');
  assert.match(cli(['restore'], {}).out, /usage: nodesignal restore <file> \[--yes\]/);
});

t('as root, backup and restore work in the state folder as its owner: planted links lead nowhere', () => {
  if (!asRoot) return 'skip needs root (CI runs this suite as a normal user)';
  fs.chmodSync(TMP, 0o755);   // the state folder's owner reaches it, as on a real machine
  const a = machine('own-a'), b = machine('own-b'), file = path.join(TMP, 'own.ns');
  assert.strictEqual(cli(['backup', file, '--config', a.cfg], { input: `${PASS}\n${PASS}\n` }).code, 0);
  const safe = path.join(TMP, 'rootonly');
  fs.mkdirSync(safe, { mode: 0o700 });
  const victim = path.join(safe, 'zz-nodesignal.sh'), secret = path.join(safe, 'secret.json');
  fs.writeFileSync(victim, '#!/bin/sh\n', { mode: 0o600 });
  fs.writeFileSync(secret, JSON.stringify({ identity: { priv: 'root-only', pub: 'root-only' } }), { mode: 0o600 });
  // the daemon's user owns its state folder and plants links in it
  ownTree(b.dir, DAEMON_UID);
  fs.symlinkSync(victim, path.join(b.dir, 'state.json.tmp'));
  fs.symlinkSync(victim, path.join(b.dir, 'social.json.tmp'));
  let r = cli(['restore', file, '--yes', '--config', b.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 0, r.out);
  assert.strictEqual(fs.readFileSync(victim, 'utf8'), '#!/bin/sh\n', 'nothing written through a link');
  assert.strictEqual(fs.statSync(victim).uid, 0, 'nothing handed over');
  for (const f of fs.readdirSync(b.dir)) {
    const st = fs.lstatSync(path.join(b.dir, f));
    if (st.isSymbolicLink()) continue;
    assert.strictEqual(st.uid, DAEMON_UID, `${f} was made by the folder's owner, not by root`);
  }
  assert.strictEqual(identityIn(b.state), a.identity.pub);
  // state.json itself a link to a root-only file: never read through it
  fs.rmSync(b.state); fs.symlinkSync(secret, b.state);
  r = cli(['backup', path.join(TMP, 'leak.ns'), '--config', b.cfg], { input: `${PASS}\n${PASS}\n` });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /state\.json: it is a symbolic link/);
  assert(!fs.existsSync(path.join(TMP, 'leak.ns')));
  r = cli(['restore', file, '--yes', '--config', b.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /state\.json: it is a symbolic link/);
  assert.strictEqual(JSON.parse(fs.readFileSync(secret, 'utf8')).identity.pub, 'root-only');
  // the state folder itself a link: refused
  const c = machine('own-c');
  fs.rmSync(c.dir, { recursive: true }); fs.symlinkSync(safe, c.dir);
  r = cli(['restore', file, '--yes', '--config', c.cfg], { input: PASS + '\n' });
  assert.strictEqual(r.code, 1, r.out);
  assert.match(r.out, /is not a plain folder/);
  assert.deepStrictEqual(fs.readdirSync(safe).sort(), ['secret.json', 'zz-nodesignal.sh']);
});

(async () => {
  for (const [name, fn] of tests) {
    try {
      const r = await fn();
      if (typeof r === 'string' && r.startsWith('skip')) { skipped++; console.log(`  skip ${name}: ${r.slice(5)}`); }
      else { passed++; console.log('  ok   ' + name); }
    } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n').slice(0, 6).join('\n       ')); }
  }
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed}${skipped ? `, ${skipped} skipped` : ''})`);
  process.exit(failed ? 1 : 0);
})();
