#!/usr/bin/env node
// cli.js: the `nodesignal` command.
// ============================================================================
//   nodesignal status                 is the daemon up, is the node connected?
//   nodesignal advertise on|off       uacomment=nodesignal in bitcoin.conf
//   nodesignal port-mapping on|off    UPnP / NAT-PMP for the peer port
//   nodesignal open                   print (and open) the web interface URL
//   nodesignal logs                   where the log is and how to follow it
//   nodesignal uninstall              Windows; on Linux use apt
//   nodesignal version
//   nodesignal rpc-access show|add|remove|rotate   NodeSignal's rpcauth in bitcoin.conf
//   nodesignal agent-brief            a brief for an AI agent the operator asks to check NodeSignal
//   nodesignal setup                  Linux, root: used by the .deb postinst
//
// Options: --config <file>  (default: /etc/nodesignal/config.json on Linux,
// %LOCALAPPDATA%\NodeSignal\config.json on Windows).
//
// Shipped as /usr/bin/nodesignal by the .deb, and embedded in the Windows
// nodesignal.exe, which passes its own helpers in through main()'s deps.
// Node.js standard library only.
// ============================================================================
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawn } = require('child_process');

const IS_WIN = process.platform === 'win32';
const say = (s = '') => process.stdout.write(s + '\n');

function optValue(argv, name) {
  const i = argv.indexOf('--' + name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : null;
}
function positional(argv) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) { if (['--config', '--root', '--wait', '--bitcoin-conf', '--nick', '--migrate-unit', '--file'].includes(argv[i])) i++; continue; }
    out.push(argv[i]);
  }
  return out;
}
const isRoot = () => typeof process.getuid === 'function' && process.getuid() === 0;

function locateConfig(argv, deps, core) {
  const explicit = optValue(argv, 'config') || process.env.NODESIGNAL_CONFIG || deps.configPath;
  if (explicit) return explicit;
  const dflt = core.defaultConfigPath();
  if (fs.existsSync(dflt)) return dflt;
  // a from-source install (install.js) keeps its config beside the program
  const beside = path.join(__dirname, 'nodesignal-config.json');
  if (fs.existsSync(beside)) return beside;
  return dflt;
}
function loadConfig(file) {
  try { return { cfg: JSON.parse(fs.readFileSync(file, 'utf8')), error: null }; }
  catch (e) { return { cfg: {}, error: e.code === 'ENOENT' ? 'not found' : e.code === 'EACCES' ? 'permission denied' : e.message }; }
}
function restartHint() {
  if (IS_WIN) return 'Restart NodeSignal: nodesignal.exe restart (or sign out and back in).';
  return 'Restart NodeSignal: sudo systemctl restart nodesignal';
}
/* Text another account chose goes on the terminal (root's, with sudo): what
   /health says (whoever listens on the web port: NodeSignal, or another
   account's program while NodeSignal is stopped), a path from the config the
   nodesignal account can write, names of files in its folders. Such text is
   printed without control characters (C0, DEL, C1, and the bidirectional and
   line-separator marks), which could otherwise move the cursor, retitle the
   window or hide earlier lines, and at most max characters of it. */
const UNPRINTABLE = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
function printable(v, max = 200) {
  if (v === undefined || v === null) return '';
  return String(v).replace(UNPRINTABLE, '').slice(0, max);
}
// The accounts allowed to answer /health: NodeSignal's config file's owner
// (the nodesignal account for the .deb, the operator for a from-source
// install) and the nodesignal account.
function nodesignalUids(ctx, root = '') {
  const out = [];
  try { out.push(fs.statSync(ctx.cfgPath).uid); } catch { }
  const u = ctx.core.readPasswd(root).find((x) => x.name === 'nodesignal');
  if (u) out.push(u.uid);
  return out;
}

/* ------------------------------------------------------------ status */
async function cmdStatus(ctx) {
  const { core, cfg, cfgPath, cfgError } = ctx;
  if (cfgError === 'permission denied') say(`Config  : ${cfgPath} (readable by root and nodesignal only; run "sudo nodesignal status" for every line)`);
  else if (cfgError) say(`Config  : ${cfgPath} (${cfgError}; using defaults)`);
  else say(`Config  : ${cfgPath}`);
  const port = Number(cfg['web-port']) || 8789;
  const waitSec = Number(optValue(ctx.argv, 'wait')) || 0;
  let r = await core.httpGetJson(`http://127.0.0.1:${port}/health`, 3000);
  if (waitSec > 0) {
    // just (re)started: wait for it to answer, and briefly for RPC
    const h = await core.waitForHealth(port, { timeoutMs: waitSec * 1000, wantRpc: true, rpcGraceMs: 6000 });
    if (h) r = { ok: true, json: h };
  }
  if (!r.ok || !r.json) {
    say(`Daemon  : NOT answering on port ${port} (${r.error || 'HTTP ' + r.status})`);
    if (IS_WIN) say('          Start it: nodesignal.exe start    Log: nodesignal.exe logs');
    else say('          Check: systemctl status nodesignal    Log: journalctl -u nodesignal -n 50');
    return 1;
  }
  const h = r.json, p = (k) => printable(h[k]);
  say(`Daemon  : running ${p('version')} as "${p('nick')}", up ${fmtUptime(h.uptime)}`);
  say(`Web UI  : ${core.webUrl(cfg)}`);
  say(`Bitcoin : ${h.rpcConnected ? `connected, ${p('peerCount')} peers` : 'NOT connected (the daemon retries every 30 seconds)'}${h.rpcSource ? `  [${p('rpcSource')}]` : ''}`);
  say(`Contacts: ${p('contacts')}`);
  say(`Ports   : web ${p('webPort')}, peer ${p('peerPort')}${cfg['port-mapping'] ? ' (router port mapping requested)' : ''}`);
  if (h.fingerprint) say(`Identity: ${p('fingerprint')}`);
  say(`Login   : ${h.authRequired ? 'token required (show it: ' + (IS_WIN ? 'nodesignal.exe' : 'sudo nodesignal') + ' web-token)' : 'open (no token): every account on this machine can use the console'}`);
  try {
    const det = await core.detectBitcoinNode();
    if (det.confPath) {
      const ua = core.uaCommentState(det.confPath);
      if (ua.unreadable) say(`Advertise: unknown (cannot read ${det.confPath}: ${ua.unreadable})`);
      else say(`Advertise: ${ua.on ? 'on' : 'off'} (uacomment in ${det.confPath})`);
    }
  } catch { }
  return 0;
}
function fmtUptime(s) {
  s = Number(s) || 0;
  if (s < 120) return s + 's';
  if (s < 7200) return Math.round(s / 60) + 'm';
  if (s < 172800) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + 'd';
}

/* ------------------------------------------------------------ advertise */
async function cmdAdvertise(ctx, onOff) {
  const { core } = ctx;
  if (onOff !== 'on' && onOff !== 'off') { say('usage: nodesignal advertise on|off'); return 2; }
  const det = await core.detectBitcoinNode();
  const confPath = optValue(ctx.argv, 'bitcoin-conf') || det.confPath || (det.datadir ? path.join(det.datadir, 'bitcoin.conf') : null);
  if (!confPath) {
    say('No Bitcoin node data directory or bitcoin.conf was found on this machine.');
    say('Point at the file: nodesignal advertise ' + onOff + ' --bitcoin-conf /path/to/bitcoin.conf');
    return 1;
  }
  // With an onion address (1.4), the comment carries it, so any operator
  // whose node peers with yours can reach your NodeSignal over Tor. It is
  // taken from /health only when what answers there is NodeSignal's (Linux:
  // the listening socket belongs to its account, checked before and after
  // asking), never from another account's program sitting on the port.
  let value = 'nodesignal';
  if (onOff === 'on') {
    const port = Number(ctx.cfg['web-port']) || 8789;
    const root = optValue(ctx.argv, 'root') || process.env.NODESIGNAL_TEST_ROOT || '';
    const check = () => (process.platform === 'linux' ? core.webListenerCheck(port, nodesignalUids(ctx, root), { root }) : { ok: true });
    const before = check();
    const h = await core.httpGetJson(`http://127.0.0.1:${port}/health`, 3000);
    if (h.ok && h.json && h.json.onion) {
      const after = before.ok ? check() : before;
      if (after.ok) value = core.uaCommentFor(h.json.onion);
      else {
        say(after.other ? `Something other than NodeSignal answers on 127.0.0.1:${port} (${after.why}), so the onion address it gave was not used.`
          : `Could not tell whether NodeSignal is what answers on 127.0.0.1:${port} (${after.why}), so the onion address it gave was not used.`);
      }
    }
  }
  let r;
  try { r = core.setUaComment(confPath, onOff === 'on', { owner: det.owner, value }); }
  catch (e) {
    say(e.message);
    if (e.code === 'EACCES' || /EACCES|permission/i.test(e.message)) say(IS_WIN ? '' : 'Try again with sudo.');
    return 1;
  }
  if (!r.changed) say(`Nothing to change: uacomment=${onOff === 'on' ? value : 'nodesignal'} is already ${onOff} in ${confPath}.`);
  else {
    say(`${onOff === 'on' ? 'Added' : 'Removed'} uacomment=${onOff === 'on' ? value : 'nodesignal'} ${onOff === 'on' ? 'to' : 'from'} ${confPath}${r.created ? ' (new file)' : ''}.`);
    if (r.backup) say(`The original was saved once as ${r.backup}.`);
    if (r.backupError) say(`No copy of the original was kept (${r.backupError}).`);
    say('');
    say('Restart your Bitcoin node for this to take effect. NodeSignal does not do it for you.');
    say(IS_WIN ? 'Close Bitcoin Core or Knots and start it again.' : 'For example: sudo systemctl restart bitcoind');
    if (onOff === 'on') say(`Every peer your node connects to will see "${value}" in its user agent${value !== 'nodesignal' ? ', including your NodeSignal onion address' : ''}.`);
    if (onOff === 'on' && value === 'nodesignal') say('NodeSignal has no onion address yet (is Tor running?). Run this again once it does, to add it.');
  }
  if (r.inSection) say(`Note: a uacomment=nodesignal line inside a [section] of ${confPath} was left as it is.`);
  return 0;
}

/* ------------------------------------------------------------ port mapping */
async function cmdPortMapping(ctx, onOff) {
  const { core, cfgPath, cfgError } = ctx;
  if (onOff !== 'on' && onOff !== 'off') { say('usage: nodesignal port-mapping on|off'); return 2; }
  if (cfgError) {
    say(`Cannot read ${cfgPath}: ${cfgError}.`);
    if (cfgError === 'permission denied') say('Try again with sudo.');
    return 1;
  }
  const cfg = Object.assign({}, ctx.cfg);
  const want = onOff === 'on';
  if (!!cfg['port-mapping'] === want) { say(`Port mapping is already ${onOff}.`); return 0; }
  if (want) cfg['port-mapping'] = true; else delete cfg['port-mapping'];
  try { core.writeConfig(cfgPath, cfg); }
  catch (e) {
    say(`Could not write ${cfgPath}: ${e.code || e.message}`);
    if (e.code === 'EACCES' || e.code === 'EPERM') say('Try again with sudo.');
    return 1;
  }
  say(`Port mapping ${onOff} in ${cfgPath}.`);
  if (want) {
    say('NodeSignal will ask your router (UPnP / NAT-PMP) to forward its peer port.');
    say('Your node\'s public IP becomes visible to the operators you message.');
  }
  return restartDaemon(ctx);
}
/* ------------------------------------------------------------ web token */
async function cmdWebToken(ctx, sub = 'show') {
  const { core, cfgPath, cfgError } = ctx;
  if (!['show', 'new', 'off'].includes(sub)) { say('usage: nodesignal web-token [show|new|off]'); return 2; }
  if (cfgError) {
    say(`Cannot read ${cfgPath}: ${cfgError}.`);
    if (cfgError === 'permission denied') say('Try again with sudo.');
    return 1;
  }
  const cfg = Object.assign({}, ctx.cfg);
  if (sub === 'show') {
    if (!cfg['web-token']) { say('No login token: the console is open to every account on this machine.'); say('Add one with: nodesignal web-token new'); return 0; }
    say(cfg['web-token']);
    return 0;
  }
  if (sub === 'new') cfg['web-token'] = require('crypto').randomBytes(24).toString('base64url');
  else if (!cfg['web-token']) { cfg['web-token'] = ''; try { core.writeConfig(cfgPath, cfg); } catch { } say('There is no login token to remove.'); return 0; }
  else cfg['web-token'] = '';   // empty, not deleted: setup on an upgrade keeps it off
  try { core.writeConfig(cfgPath, cfg); }
  catch (e) {
    say(`Could not write ${cfgPath}: ${e.code || e.message}`);
    if (e.code === 'EACCES' || e.code === 'EPERM') say('Try again with sudo.');
    return 1;
  }
  if (sub === 'new') { say('New console login token (it replaces any old one; open browsers sign in again):'); say('  ' + cfg['web-token']); }
  else say('Login token removed: every account on this machine can now use the console.');
  return restartDaemon(ctx);
}
async function restartDaemon(ctx) {
  if (ctx.deps.hooks && ctx.deps.hooks.restart) return ctx.deps.hooks.restart();
  if (IS_WIN) { say(restartHint()); return 0; }
  if (isRoot() && hasSystemd()) {
    try {
      execFileSync('systemctl', ['restart', 'nodesignal'], { stdio: 'inherit', timeout: 30000 });
      say('Restarted the nodesignal service.');
      return 0;
    } catch { say('Restart failed. Check: systemctl status nodesignal'); return 1; }
  }
  say(restartHint());
  return 0;
}
function hasSystemd() { return fs.existsSync('/run/systemd/system'); }

/* ------------------------------------------------------------ onion (Tor) */
async function cmdOnion(ctx, sub = 'show') {
  const { core, cfgPath, cfgError } = ctx;
  if (!['show', 'on', 'off'].includes(sub)) { say('usage: nodesignal onion [show|on|off]'); return 2; }
  if (sub === 'show') {
    const h = await core.httpGetJson(`http://127.0.0.1:${Number(ctx.cfg['web-port']) || 8789}/health`, 3000);
    const mode = printable(ctx.cfg.onion || 'auto');
    say(`Onion  : ${h.ok && h.json && h.json.onion ? printable(h.json.onion) : 'none yet'}  (mode: ${mode})`);
    if (mode === 'auto' && !(h.ok && h.json && h.json.onion)) {
      say('         NodeSignal asks Tor\'s control port for its own onion address. Is Tor installed and running?');
      say(IS_WIN ? '         On Windows: run the Tor Expert Bundle with ControlPort 9051 and CookieAuthentication 1.'
        : '         Linux, on the node: sudo apt install tor, then sudo nodesignal onion on');
    }
    return 0;
  }
  if (cfgError) { say(`Cannot read ${cfgPath}: ${cfgError}.`); if (cfgError === 'permission denied') say('Try again with sudo.'); return 1; }
  const cfg = Object.assign({}, ctx.cfg);
  if (sub === 'on') delete cfg.onion; else cfg.onion = 'off';
  try { core.writeConfig(cfgPath, cfg); }
  catch (e) { say(`Could not write ${cfgPath}: ${e.code || e.message}`); if (e.code === 'EACCES' || e.code === 'EPERM') say('Try again with sudo.'); return 1; }
  say(sub === 'on' ? 'Onion address: automatic (whenever Tor runs on this machine).' : 'Onion address: off. Peers behind NAT can then only reach you if you forward the peer port.');
  // the debian-tor group follows the choice (Linux, the nodesignal user only)
  const root = optValue(ctx.argv, 'root') || process.env.NODESIGNAL_TEST_ROOT || '';
  if (!IS_WIN && core.readPasswd(root).some((u) => u.name === 'nodesignal')) syncTorGroup(core, sub === 'on', { root });
  return restartDaemon(ctx);
}

/* ------------------------------------------------------------ same onion */
async function cmdSameOnion(ctx) {
  const port = Number(ctx.cfg['peer-port']) || 8788;
  const h = await ctx.core.httpGetJson(`http://127.0.0.1:${Number(ctx.cfg['web-port']) || 8789}/health`, 3000);
  const j = (h.ok && h.json) || {};
  say('Same onion: your Bitcoin node and NodeSignal answer on ONE onion address,');
  say('ports 8333 and ' + port + '. Only whoever holds that onion\'s key can run both, so');
  say('other operators see that you really run that node. Optional and manual;');
  say('it gives your node a new onion address.');
  say('');
  say(j.sameOnion ? 'Status: your node and NodeSignal share an onion address.' : 'Status: not set up' + (j.onion ? ` (NodeSignal's own onion is ${printable(j.onion)}).` : '.'));
  say('');
  say('1. Add a hidden service for both to torrc (Linux, on the node: /etc/tor/torrc):');
  say('     HiddenServiceDir /var/lib/tor/bitcoin-nodesignal/');
  say('     HiddenServicePort 8333 127.0.0.1:8334');
  say(`     HiddenServicePort ${port} 127.0.0.1:${port}`);
  say('   then restart Tor and read the address:');
  say('     sudo systemctl restart tor && sudo cat /var/lib/tor/bitcoin-nodesignal/hostname');
  say('2. Tell bitcoind to use that onion (bitcoin.conf), instead of making its own:');
  say('     listenonion=0');
  say('     bind=127.0.0.1:8334=onion');
  say('     externalip=<the address from step 1>');
  say('   and restart bitcoind.');
  say('3. Tell NodeSignal the same address (its config file), then restart it:');
  say('     "onion": "external", "onion-address": "<the address from step 1>"');
  say(IS_WIN ? '' : '   Linux, on the node: sudo nano /etc/nodesignal/config.json; sudo systemctl restart nodesignal');
  say('');
  say('Run "nodesignal same-onion" again afterwards: the status line checks it against the');
  say('onion address your node reports.');
  return 0;
}

/* ------------------------------------------------------------ update checks */
async function cmdUpdates(ctx, onOff) {
  const { core, cfgPath, cfgError } = ctx;
  if (onOff !== 'on' && onOff !== 'off') { say('usage: nodesignal updates on|off'); return 2; }
  if (cfgError) { say(`Cannot read ${cfgPath}: ${cfgError}.`); if (cfgError === 'permission denied') say('Try again with sudo.'); return 1; }
  const cfg = Object.assign({}, ctx.cfg);
  if (onOff === 'on') delete cfg['update-check']; else cfg['update-check'] = false;
  try { core.writeConfig(cfgPath, cfg); }
  catch (e) { say(`Could not write ${cfgPath}: ${e.code || e.message}`); if (e.code === 'EACCES' || e.code === 'EPERM') say('Try again with sudo.'); return 1; }
  say(onOff === 'on' ? 'Update checks on: once a day NodeSignal asks GitHub Releases (through Tor when it has an onion address) whether a newer version exists.'
    : 'Update checks off. Check by hand with: nodesignal update');
  return restartDaemon(ctx);
}

/* ------------------------------------------------------------ backup / restore */
function stateDir(ctx) {
  if (ctx.cfg.data) return ctx.cfg.data;
  return IS_WIN ? path.join(os.homedir(), '.nodesignal') : (fs.existsSync('/var/lib/nodesignal/state.json') ? '/var/lib/nodesignal' : path.join(os.homedir(), '.nodesignal'));
}
// A passphrase, never echoed (typed on a terminal, or one line of piped
// input). Never taken from the command line.
function askHidden(q) { return ctxPrompter().askSecret(q); }
let promptSingleton = null;
const ctxPrompter = () => promptSingleton || (promptSingleton = require('./setup-core.js').createPrompter());
/* The state folder belongs to the daemon's user (nodesignal on Linux), who
   can put links in it or swap it. So "sudo nodesignal backup / restore" does
   every read and write in it as that user (core.asOwner), never through a
   link; a root-owned state folder is used as root only when no other account
   can change a folder above it. Returns the identity to act as (null: as we
   are). A missing folder: undefined with missingOk, made with create
   (restore onto a new machine), else an error. */
const STATE_MAX = 256 * 1024 * 1024;
function stateFolder(ctx, dir, { create = false, missingOk = false } = {}) {
  const core = ctx.core, root = !IS_WIN && isRoot();
  let st = null;
  try { st = fs.lstatSync(dir); }
  catch (e) {
    if (e.code === 'ENOENT' && missingOk && !create) return undefined;
    if (e.code !== 'ENOENT' || !create) throw new Error(`Cannot open ${dir}: ${e.code || e.message}.`);
  }
  if (!st) {
    if (root) {
      let up = path.dirname(path.resolve(dir));
      while (!fs.existsSync(up) && path.dirname(up) !== up) up = path.dirname(up);
      const bad = core.unsafeFolder(up);
      if (bad) throw new Error(`Refusing to create ${dir} as root: ${bad.dir} can be changed by an account other than root (${bad.why}).`);
    }
    fs.mkdirSync(path.dirname(path.resolve(dir)), { recursive: true });   // parents keep the default mode
    fs.mkdirSync(dir, { mode: 0o700 });
    if (root) { const u = core.readPasswd('').find((x) => x.name === 'nodesignal'); if (u) fs.lchownSync(dir, u.uid, u.gid); }
    st = fs.lstatSync(dir);
  }
  if (!st.isDirectory()) throw new Error(`${dir} is not a plain folder (a symbolic link?); refusing to use it.`);
  if (!root) return null;
  if (st.uid !== 0) return core.ownerIdentity(st.uid, st.gid);
  const bad = core.unsafeFolder(path.dirname(path.resolve(dir)));
  if (bad) throw new Error(`Refusing to work in ${dir} as root: ${bad.dir} can be changed by an account other than root (${bad.why}).`);
  return null;
}
// Why a file the daemon's user controls was not read.
function plainWhy(e) {
  if (e.code === 'ELOOP') return 'it is a symbolic link';
  if (e.code === 'ENOTPLAIN' || e.code === 'ETOOBIG') return e.message.replace(/^\S+ /, 'it ');
  return e.code || e.message;
}
function readStateJson(ctx, id, file) {
  return JSON.parse(ctx.core.asOwner(id, () => ctx.core.readPlainFileSync(file, STATE_MAX)).toString('utf8'));
}
async function cmdBackup(ctx, file) {
  if (!file) { say('usage: nodesignal backup <file>     (writes a passphrase-protected backup of your identity and contacts)'); return 2; }
  const backup = loadSibling('backup.js');
  const dir = stateDir(ctx);
  let id;
  try { id = stateFolder(ctx, dir); } catch (e) { say(e.message); return 1; }
  let st, so = null;
  try { st = readStateJson(ctx, id, path.join(dir, 'state.json')); }
  catch (e) { say(`Cannot read ${path.join(dir, 'state.json')}: ${plainWhy(e)}.${e.code === 'EACCES' ? ' Try again with sudo.' : ''}`); return 1; }
  try { so = readStateJson(ctx, id, path.join(dir, 'social.json')); } catch { }
  if (fs.existsSync(file)) { say(`${file} already exists; pick another name.`); return 1; }
  say('The backup holds your identity keys and contacts, not your message history.');
  const p1 = await askHidden('Passphrase for the backup (at least 8 characters): ');
  const p2 = await askHidden('Again: ');
  if (p1 !== p2) { say('The two passphrases differ. Nothing was written.'); return 1; }
  let text;
  try { text = await backup.exportBackupAsync(backup.buildPayload(st, so, { nick: ctx.cfg.nick || '' }), p1); }
  catch (e) { say(e.message); return 1; }
  fs.writeFileSync(file, text, { mode: 0o600, flag: 'wx' });
  say(`Wrote ${file}. Keep it somewhere safe, away from this machine; anyone with it and the passphrase can be you.`);
  return 0;
}
async function cmdRestore(ctx, file) {
  if (!file) { say('usage: nodesignal restore <file> [--yes]     (--yes: no question, for scripts)'); return 2; }
  const backup = loadSibling('backup.js');
  const core = ctx.core;
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { say(`Cannot read ${file}: ${e.code || e.message}`); return 1; }
  const dir = stateDir(ctx), sf = path.join(dir, 'state.json'), soFile = path.join(dir, 'social.json');
  let id;
  try { id = stateFolder(ctx, dir, { missingOk: true }); } catch (e) { say(e.message); return 1; }
  const pass = await askHidden('Backup passphrase: ');
  let payload;
  try { payload = await backup.importBackupAsync(text, pass); } catch (e) { say(e.message); return 1; }
  let st = {}, so = null;
  if (id !== undefined) {
    try { st = readStateJson(ctx, id, sf); } catch (e) { if (e.code !== 'ENOENT') { say(`Cannot read ${sf}: ${plainWhy(e)}`); return 1; } }
    try { so = readStateJson(ctx, id, soFile); } catch { }
  }
  const merged = backup.mergePayload(st, so, payload);
  say(`This replaces this machine's NodeSignal identity with the one in the backup${payload.nick ? ` ("${payload.nick}")` : ''},`);
  say(`adds ${merged.added} contact(s), and keeps the message history that is here.`);
  // Replacing an identity is never silent: a terminal is asked, a script
  // must say --yes.
  if (!ctx.argv.includes('--yes')) {
    if (!process.stdin.isTTY) { say('Nothing changed: not run from a terminal, so confirm with --yes (nodesignal restore <file> --yes).'); return 1; }
    if (!(await ctxPrompter().askYesNo('Go ahead?', false))) { say('Nothing changed.'); return 0; }
  }
  // the daemon must not be running while its state is replaced
  const hooks = ctx.deps.hooks || {};
  if (hooks.stop) await hooks.stop();
  else if (!IS_WIN && isRoot() && hasSystemd()) { try { execFileSync('systemctl', ['stop', 'nodesignal'], { stdio: 'ignore', timeout: 30000 }); } catch { } }
  const h = await core.httpGetJson(`http://127.0.0.1:${Number(ctx.cfg['web-port']) || 8789}/health`, 1500);
  if (h.ok) { say('NodeSignal is still running. Stop it first, then restore again.'); return 1; }
  if (id === undefined) { try { id = stateFolder(ctx, dir, { create: true }); } catch (e) { say(e.message); return 1; } }
  let keep = null;
  try {
    // as the folder's owner: new files (O_EXCL) renamed into place, never a
    // write through a link the daemon's user left there
    core.asOwner(id, () => {
      let prev = null;
      try { prev = core.readPlainFileSync(sf, STATE_MAX); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (prev) { keep = `${sf}.before-restore-${Date.now()}`; fs.writeFileSync(keep, prev, { mode: 0o600, flag: 'wx' }); }
      for (const [f, obj] of [[sf, merged.state], [soFile, merged.social]]) core.replaceFileSync(f, JSON.stringify(obj));
    });
  } catch (e) { say(`Could not write the restored state in ${dir}: ${plainWhy(e)}.${keep ? ` The previous state.json was kept as ${keep}.` : ''}`); return 1; }
  if (keep) say(`The previous state.json was kept as ${keep}.`);
  say('Restored. Starting NodeSignal.');
  if (hooks.start) await hooks.start();
  else if (!IS_WIN && isRoot() && hasSystemd()) { try { execFileSync('systemctl', ['start', 'nodesignal'], { stdio: 'ignore', timeout: 30000 }); } catch { } }
  else say(restartHint().replace('Restart', 'Start'));
  return 0;
}
// A module that ships beside cli.js (or, inside the Windows .exe, among its assets).
function loadSibling(name) {
  try { return require('./' + name); } catch { return require(path.join(__dirname, name)); }
}

/* ------------------------------------------------------------ update / update-apply
   nodesignal update            check GitHub Releases now and say what it found
   nodesignal update install    (Linux .deb, root) download, check and install
   nodesignal update-apply      (root, run by nodesignal-update.service) install
                                what the console asked for
   Whatever the daemon wrote is untrusted here: the package, the manifest and
   its signature are copied into a directory only root can write, and checked
   there against release-keys.json from /opt/nodesignal (owned by root).
   apt-get gets --no-remove: an update never removes another package. */
// NODESIGNAL_UPDATE_DIR / NODESIGNAL_UPDATE_DRY_RUN: tests only (root's
// systemd unit sets neither); the dry run stops before the package manager.
const UPDATE_DIR = process.env.NODESIGNAL_UPDATE_DIR || '/var/lib/nodesignal/updates';
function installedVersion() { try { return fs.readFileSync(path.join(__dirname, 'VERSION'), 'utf8').trim(); } catch { return readVersion(require('./setup-core.js')); } }
async function cmdUpdate(ctx, sub) {
  const updater = loadSibling('updater.js');
  if (sub && sub !== 'install') { say('usage: nodesignal update [install]'); return 2; }
  const current = ctx.version || installedVersion();
  say(`This version: ${current}. Asking GitHub Releases...`);
  const keys = updater.loadTrustedKeys(path.join(__dirname, 'release-keys.json'));
  const r = await updater.checkLatest({ currentVersion: current, trustedKeys: keys });
  if (!r.available) { say(r.error ? `Could not tell: ${r.error}` : 'Up to date.'); return r.error ? 1 : 0; }
  say(`NodeSignal ${r.version} is available${r.published ? ` (published ${String(r.published).slice(0, 10)})` : ''}.`);
  say(r.verified ? 'Its release manifest is signed with a NodeSignal release key this copy trusts.'
    : 'It is NOT signed with a release key this copy trusts' + (r.error ? ` (${r.error})` : '') + ': install it by hand.');
  if (r.page) say(`Release page: ${r.page}`);
  if (sub !== 'install') {
    if (r.verified) say(IS_WIN ? 'Install it from the console (status panel, Updates).' : 'Install it: sudo nodesignal update install   (or from the console)');
    return 0;
  }
  if (IS_WIN) { say('On Windows, install it from the console (status panel, Updates).'); return 1; }
  if (!isRoot()) { say('Installing needs root: sudo nodesignal update install'); return 1; }
  if (!r.verified) return 1;
  const asset = updater.platformAsset();
  if (!asset || !r.assets[asset] || !r.manifest.files[asset]) { say('This release has no package for this machine.'); return 1; }
  const tmp = fs.mkdtempSync('/var/tmp/nodesignal-update-');
  try {
    const file = path.join(tmp, asset);
    say(`Downloading ${asset}...`);
    await updater.downloadVerified({ url: r.assets[asset], sha256: r.manifest.files[asset].sha256, size: r.manifest.files[asset].size, dest: file });
    fs.writeFileSync(path.join(tmp, updater.MANIFEST_NAME), r.manifestBytes);
    fs.writeFileSync(path.join(tmp, updater.SIG_NAME), r.sigBytes);
    return installVerifiedDeb(ctx, tmp, r.version, asset);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
/* UPDATE_DIR belongs to the daemon's user, who can swap anything in it, the
   folder itself included, while root works. So every read, write and unlink
   there runs as that user (core.asOwner): a link it planted can only lead
   where it could write anyway. Its files are read into memory (no link
   followed, no FIFO waited on, plain files of a capped size) and root writes
   its own copies into a folder only root can write. A root-owned UPDATE_DIR
   (tests) is used as root only when no other account can change a folder
   above it. */
const REQUEST_MAX = 4 * 1024;
async function cmdUpdateApply(ctx) {
  if (IS_WIN || !isRoot()) { say('update-apply runs as root, from nodesignal-update.service'); return 2; }
  const updater = loadSibling('updater.js');
  const core = ctx.core;
  let dst;
  try { dst = fs.lstatSync(UPDATE_DIR); }
  catch (e) { if (e.code === 'ENOENT') { say('No update request.'); return 0; } say(`Cannot open ${UPDATE_DIR}: ${e.code || e.message}`); return 1; }
  if (!dst.isDirectory()) { say(`Refused: ${UPDATE_DIR} is not a plain folder (a symbolic link?).`); return 1; }
  let id = null;
  try {
    if (dst.uid !== 0) id = core.ownerIdentity(dst.uid, dst.gid);
    else {
      const bad = core.unsafeFolder(path.dirname(path.resolve(UPDATE_DIR)));
      if (bad) throw new Error(`Refused: ${UPDATE_DIR} belongs to root, but ${bad.dir} can be changed by an account other than root (${bad.why}).`);
    }
  } catch (e) { say(e.message); return 1; }
  const inDir = (fn) => core.asOwner(id, fn);
  const at = (name) => path.join(UPDATE_DIR, name);
  const unlinkAll = (names) => inDir(() => { for (const f of names) { try { fs.unlinkSync(at(f)); } catch { } } });
  const result = (o) => {
    try { inDir(() => core.replaceFileSync(at('result.json'), JSON.stringify(Object.assign({ at: Date.now() }, o)))); } catch { }
  };
  let req;
  try { req = JSON.parse(inDir(() => core.readPlainFileSync(at('request.json'), REQUEST_MAX)).toString('utf8')); }
  catch (e) {
    if (e.code === 'ENOENT') { say('No update request.'); return 0; }
    unlinkAll(['request.json']);
    const w = e instanceof SyntaxError ? 'it is not JSON' : plainWhy(e);
    const why = `refused the request: request.json ${/^it /.test(w) ? w.slice(3) : `could not be read (${w})`}`;
    result({ ok: false, version: '', error: why }); say(why); return 1;
  }
  unlinkAll(['request.json']);
  if (!req || typeof req !== 'object') req = {};
  const version = typeof req.version === 'string' ? req.version : '', asset = updater.platformAsset();
  if (!asset || req.asset !== asset) { result({ ok: false, version, error: 'the request names a package for another machine' }); return 1; }
  const names = [asset, updater.MANIFEST_NAME, updater.SIG_NAME];
  const tmp = fs.mkdtempSync('/var/tmp/nodesignal-update-');
  try {
    for (const [name, max] of [[asset, updater.MAX_ASSET_BYTES], [updater.MANIFEST_NAME, updater.MAX_META_BYTES], [updater.SIG_NAME, updater.MAX_META_BYTES]]) {
      let buf;
      try { buf = inDir(() => core.readPlainFileSync(at(name), max)); }
      catch (e) { throw new Error(`${name}: ${plainWhy(e)}`); }
      fs.writeFileSync(path.join(tmp, name), buf, { mode: 0o600, flag: 'wx' });
    }
    const code = await installVerifiedDeb(ctx, tmp, version, asset);
    result(code === 0 ? { ok: true, version } : { ok: false, version, error: lastApplyError || 'the install failed; see journalctl -u nodesignal-update' });
    return code;
  } catch (e) {
    result({ ok: false, version, error: e.message }); say(e.message); return 1;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    unlinkAll(names);
  }
}
let lastApplyError = '';
// dir holds the package, the manifest and its signature, all written by root.
async function installVerifiedDeb(ctx, dir, version, asset) {
  const updater = loadSibling('updater.js');
  const fail = (m) => { lastApplyError = m; say(m); return 1; };
  const keys = updater.loadTrustedKeys(path.join(__dirname, 'release-keys.json'));
  const v = updater.verifyManifest({ manifestBytes: fs.readFileSync(path.join(dir, updater.MANIFEST_NAME)),
    sigBytes: fs.readFileSync(path.join(dir, updater.SIG_NAME)), trustedKeys: keys });
  if (!v.ok) return fail('refused: ' + v.error);
  if (v.manifest.version !== version) return fail(`refused: the signed manifest is for ${v.manifest.version}, the request for ${version}`);
  const current = installedVersion();
  if (updater.compareVersions(version, current) <= 0) return fail(`refused: ${version} is not newer than the installed ${current}`);
  const f = v.manifest.files[asset];
  if (!f) return fail(`refused: the signed manifest does not list ${asset}`);
  const deb = path.join(dir, asset), buf = fs.readFileSync(deb);
  const sha = require('crypto').createHash('sha256').update(buf).digest('hex');
  if (buf.length !== f.size || sha !== f.sha256) return fail('refused: the package does not match the signed manifest');
  let fields;
  try { fields = execFileSync('dpkg-deb', ['-f', deb, 'Package', 'Version'], { encoding: 'utf8' }); } catch (e) { return fail('refused: not a readable package: ' + e.message); }
  if (!/^Package: nodesignal$/m.test(fields) || !new RegExp('^Version: ' + version.replace(/[.+~-]/g, '\\$&') + '$', 'm').test(fields)) return fail('refused: the package is not nodesignal ' + version);
  say(`Installing NodeSignal ${version} (signature, version, size and SHA-256 checked)...`);
  if (process.env.NODESIGNAL_UPDATE_DRY_RUN === '1') { say('dry run: not installing'); return 0; }
  const env = Object.assign({}, process.env, { DEBIAN_FRONTEND: 'noninteractive' });
  try {
    if (fs.existsSync('/usr/bin/apt-get')) execFileSync('apt-get', ['install', '-y', '--no-install-recommends', '--no-remove', deb], { stdio: 'inherit', env, timeout: 540000 });
    else execFileSync('dpkg', ['-i', deb], { stdio: 'inherit', env, timeout: 540000 });
  } catch (e) { return fail('the package manager failed: ' + (e.message || e)); }
  say(`NodeSignal ${version} is installed.`);
  return 0;
}

/* ------------------------------------------------------------ agent-brief
   A paste-ready brief for an AI coding agent (Claude Code, Codex, Goose,
   Aider...) that the operator asks to check NodeSignal and finish setting it
   up: this machine's paths and versions, docs/AGENT-SETUP.md for the rest,
   and a plain warning about what the agent will be able to read. It never
   includes a secret. */
function agentBrief(ctx, { installer = null } = {}) {
  const version = ctx.version || installedVersion();
  const kind = installer ? `not yet: the installer is ${installer}; check it, then run it (answers can be piped, see the guide)`
    : IS_WIN ? 'Windows (NodeSignal-Setup-windows-x64.exe)' : (__dirname === '/opt/nodesignal' ? 'Linux .deb package' : 'from source');
  const prog = installer ? '(after install) ' + path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'NodeSignal', 'app')
    : IS_WIN ? path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'NodeSignal', 'app') : __dirname;
  const tag = /^\d+\.\d+\.\d+/.test(version) ? 'v' + version : 'main';
  const cmd = IS_WIN ? '& "$env:LOCALAPPDATA\\NodeSignal\\nodesignal.exe"' : 'sudo nodesignal';
  return [
    'Please check NodeSignal on this machine and finish setting it up, as an independent reviewer.',
    `Follow https://github.com/Connor-03/NodeSignal/blob/${tag}/docs/AGENT-SETUP.md ("For the agent").`,
    '',
    'This machine:',
    `- NodeSignal ${version}, installed: ${kind}`,
    `- program files: ${prog}`,
    `- config file: ${ctx.cfgPath} (holds secrets: do not open or print it)`,
    `- state directory: ${stateDir(ctx)} (identity keys and history: do not open it)`,
    `- operating system: ${os.type()} ${os.release()} (${process.arch})`,
    `- status: run "nodesignal status"; the release to compare with is tag ${tag}`,
    '',
    'Rules: never print or upload NodeSignal\'s config, state.json, backups or bitcoin.conf passwords; ask before restarting',
    'bitcoind, changing a firewall, installing anything besides NodeSignal and Tor, or turning on anything that is off by',
    'default. Report what you checked, what passed, every problem with evidence, and what you could not check.',
  ].join('\n') + '\n';
}
const SECRETS_CMD = IS_WIN ? 'nodesignal.exe' : 'sudo nodesignal';
const AGENT_WARNING = [
  'Before you hand this to an agent: it will be able to see NodeSignal\'s secrets.',
  'It runs commands with your permissions' + (IS_WIN ? '' : ' (and sudo)') + ', so it can read the RPC password NodeSignal',
  'uses with your node, the console login token, your NodeSignal identity, signing and onion keys,',
  'and your message history unless a passphrase locks it. The brief tells it not to, and it does',
  'not need to, but it can. A cloud agent (Claude Code, Codex) sends whatever it reads to its',
  'provider; an open-source agent with a local model keeps it on this machine. With sudo it can',
  'read everything else here too, your node\'s files included. Afterwards, if you like:',
  `  ${SECRETS_CMD} web-token new    and    ${SECRETS_CMD} rpc-access rotate   (then restart bitcoind)`,
];
async function cmdAgentBrief(ctx) {
  const file = optValue(ctx.argv, 'file');
  const text = agentBrief(ctx);
  for (const l of AGENT_WARNING) say(l);
  say('');
  if (file) {
    fs.writeFileSync(file, text, { mode: 0o600 });
    say(`Wrote the brief to ${file}. Give it to your agent, for example:`);
    say(`  claude "Read ${file} and do what it says"`);
    say(`  codex "Read ${file} and do what it says"`);
    return 0;
  }
  say('Paste this into your agent (Claude Code, Codex, Goose, Aider, ...):');
  say('------------------------------------------------------------------------');
  process.stdout.write(text);
  say('------------------------------------------------------------------------');
  return 0;
}

/* ------------------------------------------------------------ open / logs */
async function cmdOpen(ctx) {
  const url = ctx.core.webUrl(ctx.cfg);
  say(url);
  if (ctx.deps.hooks && ctx.deps.hooks.openUrl) { await ctx.deps.hooks.openUrl(url, ctx.argv); return 0; }
  const graphical = process.env.DISPLAY || process.env.WAYLAND_DISPLAY;
  try {
    if (IS_WIN) spawn('explorer.exe', [url], { detached: true, stdio: 'ignore' }).unref();
    else if (process.platform === 'darwin') spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    else if (graphical && !isRoot()) spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).on('error', () => { }).unref();
  } catch { }
  return 0;
}
async function cmdLogs(ctx) {
  if (ctx.deps.logPath) {
    say(ctx.deps.logPath);
    try {
      const lines = fs.readFileSync(ctx.deps.logPath, 'utf8').split(/\r?\n/);
      say('');
      say(lines.slice(-40).join('\n'));
    } catch (e) { say(`(no log yet: ${e.code || e.message})`); }
    return 0;
  }
  if (IS_WIN) { say('From source, NodeSignal logs to the window it runs in.'); return 0; }
  say('NodeSignal logs to the systemd journal. Follow it live with:');
  say('  journalctl -u nodesignal -f');
  say('Last 100 lines:');
  say('  journalctl -u nodesignal -n 100 --no-pager');
  return 0;
}

/* ------------------------------------------------------------ uninstall */
async function cmdUninstall(ctx) {
  if (ctx.deps.hooks && ctx.deps.hooks.uninstall) return ctx.deps.hooks.uninstall(ctx.argv);
  if (IS_WIN) { say('Run uninstall from the installed program: %LOCALAPPDATA%\\NodeSignal\\nodesignal.exe uninstall'); return 1; }
  say('On Linux NodeSignal is removed with the package manager:');
  say('  sudo apt remove nodesignal     keeps /etc/nodesignal, the RPC login and /var/lib/nodesignal');
  say('  sudo apt purge nodesignal      also removes /etc/nodesignal and NodeSignal\'s rpcauth and');
  say('                                 rpcwhitelist lines in bitcoin.conf (never /var/lib/nodesignal,');
  say('                                 which holds your identity key and history)');
  say('If you turned it on, run "sudo nodesignal advertise off" first.');
  return 0;
}

/* ------------------------------------------------------------ setup (Linux)
   Called by the .deb postinst (and install-node.sh) as root. NodeSignal
   never runs as root and never reads the node's cookie:
     1. the dedicated "nodesignal" system user (created if missing)
     2. /etc/nodesignal/config.json, 0600, owned by that user, holding
        NodeSignal's own RPC login (rpc-user nodesignal, a random rpc-pass)
     3. the state directory /var/lib/nodesignal (an older install's state is
        copied in once, never as root; the original stays where it was)
     4. bitcoin.conf gets rpcauth=nodesignal:<salt>$<hash> plus an
        rpcwhitelist of exactly the three methods the daemon calls; the node
        must be restarted to read them, and we say so instead of doing it
   --root <dir> runs it against a fake filesystem for tests. */
const STATE_DIR = '/var/lib/nodesignal';
const OLD_DROP_IN = '/etc/systemd/system/nodesignal.service.d/10-user.conf';
async function cmdSetup(ctx) {
  const { core, argv } = ctx;
  const root = optValue(argv, 'root') || process.env.NODESIGNAL_TEST_ROOT || '';
  const P = (p) => (root ? path.join(root, p) : p);
  if (!root && !isRoot()) { say('nodesignal setup must run as root: sudo nodesignal setup'); return 1; }

  const cfgPath = optValue(argv, 'config') || '/etc/nodesignal/config.json';
  const det = await core.detectBitcoinNode({ root });

  if (det.installed) say(`Bitcoin node found: ${det.how.filter((h) => !/^ignored /.test(h)).slice(0, 3).join('; ')}`);
  else say('No Bitcoin node was found on this machine.');
  for (const h of det.how) if (/^ignored /.test(h)) say(`Note: ${h}`);

  // an older from-source unit (install-node.sh before 1.3) kept its settings
  // on the ExecStart line; carry them over once (but not its User=)
  const migrated = parseOldUnit(optValue(argv, 'migrate-unit') ? P(optValue(argv, 'migrate-unit')) : null);
  if (migrated) say(`Carrying over settings from ${optValue(argv, 'migrate-unit')}`);

  // 1. the dedicated service user, always
  const user = ensureSystemUser(core, root);
  say(`Service user: ${user.name} (a dedicated system account; NodeSignal never runs as root)`);
  if (det.owner && det.owner.uid === 0) say('Note: your Bitcoin node runs as root. NodeSignal does not need to, and does not.');

  // 2. config
  let cfg = {};
  const fresh = !fs.existsSync(P(cfgPath));
  if (!fresh) {
    try { cfg = JSON.parse(fs.readFileSync(P(cfgPath), 'utf8')); }
    catch (e) { say(`Cannot read ${cfgPath}: ${e.message}. Fix or delete it and run setup again.`); return 1; }
  } else cfg = { nick: hostnameOf(root) };
  if (migrated) for (const [k, v] of Object.entries(migrated.config)) if (fresh || !(k in cfg)) cfg[k] = v;
  const nickArg = optValue(argv, 'nick');
  if (nickArg) cfg.nick = nickArg.slice(0, 60);
  // Tor's control socket, for NodeSignal's own onion; "onion": "off" in the
  // config declines it (see syncTorGroup)
  syncTorGroup(core, cfg.onion !== 'off', { root, user: user.name, setup: true });
  // On a server, other accounts (a game server, a web server) can reach
  // 127.0.0.1 too, so the console gets a login token. It is not printed:
  // apt keeps its output in /var/log/apt/term.log. "web-token off" stores
  // an empty token, and an upgrade keeps that choice.
  let newToken = false;
  if (!('web-token' in cfg) && !argv.includes('--no-token')) {
    cfg['web-token'] = require('crypto').randomBytes(24).toString('base64url');
    newToken = true;
  }
  // the daemon cannot read bitcoin.conf any more, so it learns the RPC
  // address (rpcport, rpcconnect, test chains) from its own config
  if (det.installed && (!cfg['rpc-url'] || argv.includes('--redetect'))) cfg['rpc-url'] = det.rpcUrl;

  // 3. state directory, never emptied or replaced
  // a 1.2 from-source unit had no config file: its history sat in --data,
  // or in ~/.nodesignal of the unit's User= (root when it named none)
  const unitData = migrated && (migrated.data || oldUnitHome(core, root, migrated.user));
  const oldData = [cfg.data, unitData].find((d) => typeof d === 'string' && d && path.posix.resolve(d) !== STATE_DIR) || null;
  cfg.data = STATE_DIR;
  if (!fs.existsSync(P(STATE_DIR))) {
    fs.mkdirSync(path.dirname(P(STATE_DIR)), { recursive: true });   // parents keep the default mode
    fs.mkdirSync(P(STATE_DIR), { mode: 0o700 });
  }
  if (oldData && fs.existsSync(P(path.join(oldData, 'state.json')))) {
    let has = true;
    try { fs.lstatSync(P(path.join(STATE_DIR, 'state.json'))); } catch { has = false; }
    if (has) say(`Note: ${printable(oldData, 300)} also holds NodeSignal state; ${STATE_DIR} already has its own, so it was left alone.`);
    else migrateState(core, P, oldData, user);
  }
  chownTree(P(STATE_DIR), user);
  try { fs.chmodSync(P(STATE_DIR), 0o700); } catch { }

  // 4. NodeSignal's own RPC login, in bitcoin.conf and in the config
  const confPath = optValue(argv, 'bitcoin-conf') || core.readRpcRecord(P(cfgPath)) || core.nodeConfPath(det);
  let access = null;
  if (confPath) {
    try {
      access = core.installRpcAccess({ cfg, cfgPath, confPath, owner: det.owner, P, cmdlineWhitelist: !!det.rpcWhitelistOnCmdline });
    } catch (e) {
      core.ensureRpcLogin(cfg);
      say(e.message);
    }
  } else core.ensureRpcLogin(cfg);
  core.writeConfig(P(cfgPath), cfg, { owner: { uid: user.uid, gid: user.gid } });
  try { fs.chownSync(P(cfgPath), user.uid, user.gid); fs.chmodSync(P(cfgPath), 0o600); } catch { }
  try { fs.chmodSync(P(path.dirname(cfgPath)), 0o755); } catch { }
  say(`${fresh ? 'Wrote' : 'Updated'} ${cfgPath} (readable by ${user.name} only)`);
  if (newToken) say('The console now asks for a login token, so other accounts on this machine cannot use it. Show it with: sudo nodesignal web-token');

  // a 1.3 pre-release drop-in ran the daemon as the node's owner; the unit
  // now says User=nodesignal itself
  removeOldDropIn(P);
  if (!root && hasSystemd()) {
    try { execFileSync('systemctl', ['daemon-reload'], { stdio: 'ignore', timeout: 30000 }); } catch { }
  }

  if (access && access.result.changed) {
    say(`Added NodeSignal's RPC login to ${confPath}${access.result.created ? ' (new file)' : ''}:`);
    for (const l of access.result.lines) say('  ' + l.replace(/\$[0-9a-f]{64}$/, '$<hash>'));
    if (access.result.backup) say(`The original was saved once as ${access.result.backup}.`);
    if (access.result.backupError) say(`No copy of the original was kept (${access.result.backupError}).`);
    say('');
    for (const l of core.RPC_RESTART_TEXT.linux) say(l);
    return 0;
  }
  if (access) say(`RPC login: user ${core.RPC_USER} in ${confPath} (unchanged)`);
  else {
    say(confPath ? 'NodeSignal could not add its RPC login to bitcoin.conf. Add these lines by hand,'
      : 'No bitcoin.conf was found, so NodeSignal\'s RPC login was not added. Add these lines to');
    say(confPath ? 'then restart your node:' : 'the node\'s bitcoin.conf, then restart it (or run: sudo nodesignal rpc-access add --bitcoin-conf <file>):');
    printManualLines(core, cfg);
  }

  // 5. RPC check
  if (det.installed) await printRpcCheck(core, det, cfg, { root });
  return 0;
}
function printManualLines(core, cfg) {
  say('  ' + core.makeRpcAuth(core.RPC_USER, cfg['rpc-pass']));
  say(`  rpcwhitelist=${core.RPC_USER}:${core.RPC_METHODS.join(',')}`);
  say('  rpcwhitelistdefault=0      (only if nothing else sets rpcwhitelist or rpcwhitelistdefault:');
  say('                              not bitcoin.conf, its includeconf files, a [section] or bitcoind\'s command line)');
}
/* Hands what root put in the state folder to the service user. The folder
   is that user's, so it can swap entries while this runs: GNU chown -R -P
   walks it with fts relative to each open folder and never follows a link
   (with -R -P it changes a link itself, not its target), and --from=0 only
   touches what root owns. */
function chownTree(dir, user) {
  if (!isRoot()) return;
  try { execFileSync('chown', ['-R', '-P', '--no-dereference', '--from=0', `${user.uid}:${user.gid}`, dir], { stdio: 'ignore', timeout: 120000 }); }
  catch (e) { say(`Note: could not hand ${dir} to ${user.name} (${e.code || 'chown failed'}). Fix it with: sudo chown -R -P --from=0 ${user.name}: ${dir}`); }
}
/* An older install's state folder (the config's "data", or a 1.2 unit's)
   into STATE_DIR. That path comes from a config the nodesignal account can
   write, and both folders belong to other accounts, so root never copies as
   root (core.copyStateTree reads as the old folder's owner and writes as the
   new one's: the service user, to whom a folder root just made is handed
   first). Anything refused is said, and the original is never touched. */
function migrateState(core, P, oldData, user) {
  const shown = printable(oldData, 300);   // from a config another account can write
  if (!path.posix.isAbsolute(oldData)) { say(`Note: ${shown} (an older install's state folder) is not a full path, so it was not copied.`); return; }
  if (isRoot()) {
    try { const st = fs.lstatSync(P(STATE_DIR)); if (st.isDirectory() && st.uid === 0) fs.lchownSync(P(STATE_DIR), user.uid, user.gid); } catch { }
  }
  let r;
  try { r = core.copyStateTree(P(oldData), P(STATE_DIR)); }
  catch (e) {
    say(`Did not copy ${shown} to ${STATE_DIR}: ${printable(e.message, 600)}.`);
    say(`If it holds the identity you want to keep, copy its files into ${STATE_DIR} yourself and give them to ${user.name} (Linux, on the node: sudo chown -R ${user.name}: ${STATE_DIR}).`);
    return;
  }
  say(`Copied your identity and history from ${shown} to ${STATE_DIR}. The original stays where it was.`);
  if (r.skipped.length) say(`Not copied: ${printable(r.skipped.slice(0, 5).join(', '), 600)}${r.skipped.length > 5 ? ` and ${r.skipped.length - 5} more` : ''}.`);
}
function removeOldDropIn(P) {
  try {
    if (/^# Written by nodesignal setup/.test(fs.readFileSync(P(OLD_DROP_IN), 'utf8'))) {
      fs.unlinkSync(P(OLD_DROP_IN));
      try { fs.rmdirSync(path.dirname(P(OLD_DROP_IN))); } catch { }
      say(`Removed the old ${OLD_DROP_IN} (it ran NodeSignal as the node's user).`);
    }
  } catch { }
}

/* ------------------------------------------------------------ rpc-access
   show | add | remove | rotate: NodeSignal's rpcauth + rpcwhitelist block in
   bitcoin.conf. The password is never printed. */
async function cmdRpcAccess(ctx, sub) {
  const { core, cfgPath, cfgError } = ctx;
  if (!['show', 'add', 'remove', 'rotate'].includes(sub)) { say('usage: nodesignal rpc-access show|add|remove|rotate [--bitcoin-conf <file>]'); return 2; }
  let confPath = optValue(ctx.argv, 'bitcoin-conf') || core.readRpcRecord(cfgPath);
  let det = null;
  if (!confPath) { det = await core.detectBitcoinNode(); confPath = core.nodeConfPath(det); }
  if (!confPath) {
    say('No bitcoin.conf was found. Point at it: nodesignal rpc-access ' + sub + ' --bitcoin-conf /path/to/bitcoin.conf');
    return 1;
  }
  const sudo = IS_WIN ? '' : 'Try again with sudo.';
  if (sub === 'show') {
    const st = core.rpcAccessState(confPath);
    if (st.unreadable) { say(`Cannot read ${confPath}: ${st.unreadable}.`); if (/EACCES/.test(st.unreadable)) say(sudo); return 1; }
    say(`bitcoin.conf: ${confPath}`);
    if (!st.on) { say('NodeSignal RPC access: not set up. Add it with: ' + (IS_WIN ? 'nodesignal.exe' : 'sudo nodesignal') + ' rpc-access add'); return 0; }
    say('NodeSignal RPC access: on');
    for (const l of st.lines) say('  ' + l.replace(/\$[0-9a-f]{64}$/, '$<hash>'));
    if (!cfgError && ctx.cfg['rpc-pass']) say(core.rpcAuthMatches(st.rpcauth, core.RPC_USER, ctx.cfg['rpc-pass'])
      ? `It matches the password in ${cfgPath}.` : `It does NOT match the password in ${cfgPath}. Fix it with: rpc-access add`);
    return 0;
  }
  if (sub === 'remove') {
    let r;
    try { r = core.setRpcAccess(confPath, null); }
    catch (e) { say(e.message); if (/EACCES|EPERM/.test(e.message)) say(sudo); return 1; }
    try { fs.unlinkSync(core.rpcRecordPath(cfgPath)); } catch { }
    if (!r.changed) { say(`Nothing to remove: ${confPath} has no NodeSignal RPC block.`); return 0; }
    say(`Removed NodeSignal's rpcauth and rpcwhitelist lines from ${confPath}.`);
    say('NodeSignal cannot reach your node until you add them again (rpc-access add).');
    say('Restart your Bitcoin node for this to take effect. NodeSignal does not do it for you.');
    return 0;
  }
  // add, or rotate: a new random password (and so a new rpcauth hash), for
  // example after someone else (an AI agent, a helper) could read the config
  if (cfgError) { say(`Cannot read ${cfgPath}: ${cfgError}.`); if (cfgError === 'permission denied') say(sudo); return 1; }
  const cfg = Object.assign({}, ctx.cfg);
  if (sub === 'rotate') { delete cfg['rpc-pass']; say('Making a new password for NodeSignal\'s RPC login.'); }
  if (!det) det = await core.detectBitcoinNode();
  let access;
  try {
    access = core.installRpcAccess({ cfg, cfgPath, confPath, owner: det.owner, cmdlineWhitelist: !!det.rpcWhitelistOnCmdline });
    if (access.cfgChanged) core.writeConfig(cfgPath, cfg);
  } catch (e) {
    say(e.message);
    if (/EACCES|EPERM/.test(e.message + (e.code || ''))) say(sudo);
    return 1;
  }
  if (!access.result.changed) say(`Nothing to change: ${confPath} already has NodeSignal's RPC login.`);
  else {
    say(`Added NodeSignal's RPC login to ${confPath}.`);
    if (access.result.backup) say(`The original was saved once as ${access.result.backup}.`);
    if (access.result.backupError) say(`No copy of the original was kept (${access.result.backupError}).`);
    say('');
    for (const l of core.RPC_RESTART_TEXT[IS_WIN ? 'win32' : 'linux']) say(l);
  }
  return access.cfgChanged ? restartDaemon(ctx) : 0;
}
async function printRpcCheck(core, det, cfg, opts = {}) {
  const r = await core.checkNode(det, cfg, opts);
  if (r.ok) {
    say(`Bitcoin RPC: OK at ${r.url} via ${r.source}`);
    say(`  ${r.subversion || 'node'}, ${r.chain} chain, height ${r.blocks}${r.pruned ? ', pruned' : ''}`);
    if (/^rpcuser/.test(r.source || '')) {
      say('  Hardening: NodeSignal only needs three read-only calls. Limit that RPC user in bitcoin.conf:');
      say('    rpcwhitelist=<rpcuser>:getpeerinfo,getnetworkinfo,getblockchaininfo');
    }
  } else {
    say(`Bitcoin RPC: not answering right now (${r.error}).`);
    if (r.hint) say('  ' + r.hint);
    for (const n of r.notes || []) say('  ' + n);
    say('  NodeSignal is installed anyway and reconnects by itself every 30 seconds.');
  }
  return r;
}
/* The pre-1.3 install-node.sh wrote User= and every setting, including a
   web token, onto the unit's ExecStart line. Returns what it can carry over. */
function parseOldUnit(file) {
  if (!file) return null;
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return null; }
  const user = (text.match(/^User=(.+)$/m) || [])[1];
  const exec = (text.match(/^ExecStart=(.+)$/m) || [])[1] || '';
  const words = exec.trim().split(/\s+/);
  const config = {};
  const keys = { nick: 'nick', 'web-port': 'web-port', 'peer-port': 'peer-port', 'web-token': 'web-token', bind: 'bind' };
  for (let i = 0; i < words.length - 1; i++) {
    const k = words[i].replace(/^--/, '');
    if (words[i].startsWith('--') && keys[k]) {
      config[keys[k]] = /port$/.test(k) ? Number(words[i + 1]) : words[i + 1];
      i++;
    }
  }
  const data = (exec.match(/(?:^|\s)--data(?:=|\s+)(\S+)/) || [])[1] || null;
  return { user: user ? user.trim() : null, config, data };
}
function oldUnitHome(core, root, name) {
  const u = core.readPasswd(root).find((x) => x.name === (name || 'root'));
  return u && u.home && u.home !== '/' ? path.posix.join(u.home, '.nodesignal') : null;
}
/* Tor: NodeSignal asks Tor's control socket for its own onion service (no
   port forwarding). On Debian and Ubuntu that socket and its cookie belong
   to the debian-tor group, and membership lets the nodesignal user control
   that Tor. So it is held only while the onion is wanted: setup adds it when
   Tor is installed unless the config says "onion": "off", "onion on" adds
   it, "onion off" removes it, and each says what it did. root: a fake
   filesystem (tests), whose etc/group is changed instead. */
const TOR_GROUP = 'debian-tor';
function syncTorGroup(core, want, { root = '', user = 'nodesignal', setup = false } = {}) {
  if (IS_WIN) return;
  const g = core.readGroups(root).find((x) => x.name === TOR_GROUP);
  if (!g) {
    if (want && !setup) say(`Tor: there is no ${TOR_GROUP} group here (is Tor installed? Linux, on the node: sudo apt install tor), so no group was changed.`);
    return;
  }
  const member = g.members.includes(user);
  if (member === want) {
    say(want ? `Tor: ${user} is in the ${TOR_GROUP} group, so it can create its own onion address (no port forwarding).`
      : (setup ? `Tor: onion is off in the config, so ${user} stays out of the ${TOR_GROUP} group.` : `Tor: ${user} is not in the ${TOR_GROUP} group.`));
    return;
  }
  if (!root && !isRoot()) { say(`Tor: ${user} was not ${want ? 'added to' : 'removed from'} the ${TOR_GROUP} group: that needs sudo.`); return; }
  try {
    core.setGroupMember(user, TOR_GROUP, want, { root });
    say(want ? `Tor: added ${user} to the ${TOR_GROUP} group, so it can create its own onion address (no port forwarding).`
      : `Tor: removed ${user} from the ${TOR_GROUP} group${setup ? ' (onion is off in the config)' : ''}; NodeSignal no longer controls this machine's Tor.`);
  } catch {
    say(want ? `Tor: could not add ${user} to the ${TOR_GROUP} group; it will run without an onion address.`
      : `Tor: could not remove ${user} from the ${TOR_GROUP} group. Linux, on the node: sudo gpasswd -d ${user} ${TOR_GROUP}`);
  }
}
function hostnameOf(root) {
  if (root) { try { return fs.readFileSync(path.join(root, 'etc', 'hostname'), 'utf8').trim() || os.hostname(); } catch { } }
  return os.hostname();
}
function ensureSystemUser(core, root) {
  const existing = core.readPasswd(root).find((u) => u.name === 'nodesignal');
  if (existing) return existing;
  if (!root) {
    try {
      execFileSync('useradd', ['--system', '--user-group', '--home-dir', '/var/lib/nodesignal', '--no-create-home', '--shell', '/usr/sbin/nologin', 'nodesignal'], { stdio: 'ignore' });
    } catch {
      try { execFileSync('adduser', ['--system', '--group', '--home', '/var/lib/nodesignal', '--no-create-home', 'nodesignal'], { stdio: 'ignore' }); } catch { }
    }
    const made = core.readPasswd('').find((u) => u.name === 'nodesignal');
    if (made) return made;
    throw new Error('could not create the nodesignal system user');
  }
  // tests: pretend
  return { name: 'nodesignal', uid: 999, gid: 999, home: '/var/lib/nodesignal' };
}

/* ------------------------------------------------------------ main */
const HELP = `NodeSignal ${'%VERSION%'}

usage: nodesignal <command> [--config <file>]

  status               is the daemon up, is the Bitcoin node connected
  advertise on|off     add/remove uacomment=nodesignal in bitcoin.conf (public)
  port-mapping on|off  ask the router to forward the peer port (exposes your IP)
  rpc-access show|add|remove|rotate
                       NodeSignal's own RPC login (rpcauth + rpcwhitelist) in
                       bitcoin.conf; restart the node after add, remove or rotate
  open [--browser]     open NodeSignal (on Windows: its own window; --browser
                       for a normal browser tab) and print its address
  onion [show|on|off]  NodeSignal's own Tor onion address (automatic when Tor runs here)
  same-onion           how to serve your node and NodeSignal on one onion (proves you run it)
  updates on|off       the daily check for a newer version (on by default)
  update [install]     check for a newer version now; install it (Linux, sudo)
  agent-brief [--file f]  a brief for your own AI agent to check NodeSignal and finish setup
  backup <file>        write a passphrase-protected backup of your identity and contacts
  restore <file> [--yes]
                       put a backup's identity on this machine (keeps the history
                       here); --yes confirms it when not run from a terminal
  web-token [show|new|off]
                       the console's login token (Linux sets one at install,
                       so other accounts on the machine cannot use it)
  logs                 show where the log is and how to follow it
  uninstall            remove NodeSignal (Windows; on Linux use apt)
  version              print the version%EXTRA%`;
const HELP_LINUX = `
  setup [--redetect]   Linux, as root: the nodesignal user, the config and the
                       RPC login (the .deb runs this for you)`;
const HELP_WIN = `
  start | stop | restart
                       control the background daemon`;

async function main(argv = process.argv.slice(2), deps = {}) {
  const core = deps.core || require('./setup-core.js');
  const version = deps.version || readVersion(core);
  const pos = positional(argv);
  const cmd = pos[0] || 'help';
  const cfgPath = locateConfig(argv, deps, core);
  const { cfg, error } = loadConfig(cfgPath);
  const ctx = { core, argv, deps, cfgPath, cfg, cfgError: error, version };
  switch (cmd) {
    case 'status': return cmdStatus(ctx);
    case 'advertise': return cmdAdvertise(ctx, pos[1]);
    case 'port-mapping': return cmdPortMapping(ctx, pos[1]);
    case 'open': return cmdOpen(ctx);
    case 'logs': return cmdLogs(ctx);
    case 'uninstall': return cmdUninstall(ctx);
    case 'setup': return cmdSetup(ctx);
    case 'rpc-access': return cmdRpcAccess(ctx, pos[1]);
    case 'web-token': return cmdWebToken(ctx, pos[1]);
    case 'onion': return cmdOnion(ctx, pos[1]);
    case 'same-onion': return cmdSameOnion(ctx);
    case 'updates': return cmdUpdates(ctx, pos[1]);
    case 'update': return cmdUpdate(ctx, pos[1]);
    case 'update-apply': return cmdUpdateApply(ctx);
    case 'backup': return cmdBackup(ctx, pos[1]);
    case 'agent-brief': return cmdAgentBrief(ctx);
    case 'restore': return cmdRestore(ctx, pos[1]);
    case 'rpc-check': {
      const det = await core.detectBitcoinNode();
      const r = await printRpcCheck(core, det, cfg);
      return r.ok ? 0 : 1;
    }
    case 'version': case '--version': case '-v': say(version); return 0;
    case 'help': case '--help': case '-h': say(help(version, deps)); return 0;
    default: say(`unknown command: ${cmd}\n`); say(help(version, deps)); return 2;
  }
}
function help(version, deps) {
  const extra = deps.hooks && deps.hooks.restart ? HELP_WIN : (IS_WIN ? '' : HELP_LINUX);
  return HELP.replace('%VERSION%', version).replace('%EXTRA%', extra);
}
function readVersion(core) {
  for (const f of [path.join(__dirname, 'VERSION'), path.join(__dirname, 'package.json')]) {
    try {
      const t = fs.readFileSync(f, 'utf8');
      return f.endsWith('.json') ? JSON.parse(t).version : t.trim();
    } catch { }
  }
  return core.VERSION_FALLBACK;
}

module.exports = { main, cmdSetup, agentBrief, AGENT_WARNING };

if (require.main === module) {
  main().then((code) => process.exit(code || 0), (e) => { console.error('nodesignal: ' + (e && e.message ? e.message : e)); process.exit(1); });
}
