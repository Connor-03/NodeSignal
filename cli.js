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
    if (argv[i].startsWith('--')) { if (['--config', '--root', '--wait', '--bitcoin-conf', '--user', '--nick', '--migrate-unit'].includes(argv[i])) i++; continue; }
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

/* ------------------------------------------------------------ status */
async function cmdStatus(ctx) {
  const { core, cfg, cfgPath, cfgError } = ctx;
  if (cfgError) say(`Config  : ${cfgPath} (${cfgError}; using defaults)`);
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
  const h = r.json;
  say(`Daemon  : running ${h.version || ''} as "${h.nick}", up ${fmtUptime(h.uptime)}`);
  say(`Web UI  : ${core.webUrl(cfg)}`);
  say(`Bitcoin : ${h.rpcConnected ? `connected, ${h.peerCount} peers` : 'NOT connected (the daemon retries every 30 seconds)'}${h.rpcSource ? `  [${h.rpcSource}]` : ''}`);
  say(`Contacts: ${h.contacts}`);
  say(`Ports   : web ${h.webPort}, peer ${h.peerPort}${cfg['port-mapping'] ? ' (router port mapping requested)' : ''}`);
  if (h.fingerprint) say(`Identity: ${h.fingerprint}`);
  say(`Login   : ${h.authRequired ? 'token required' : 'open (no token)'}`);
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
  let r;
  try { r = core.setUaComment(confPath, onOff === 'on', { owner: det.owner }); }
  catch (e) {
    say(e.message);
    if (e.code === 'EACCES' || /EACCES|permission/i.test(e.message)) say(IS_WIN ? '' : 'Try again with sudo.');
    return 1;
  }
  if (!r.changed) say(`Nothing to change: uacomment=nodesignal is already ${onOff} in ${confPath}.`);
  else {
    say(`${onOff === 'on' ? 'Added' : 'Removed'} uacomment=nodesignal ${onOff === 'on' ? 'to' : 'from'} ${confPath}${r.created ? ' (new file)' : ''}.`);
    if (r.backup) say(`The original was saved once as ${r.backup}.`);
    say('');
    say('Restart your Bitcoin node for this to take effect. NodeSignal does not do it for you.');
    say(IS_WIN ? 'Close Bitcoin Core or Knots and start it again.' : 'For example: sudo systemctl restart bitcoind');
    if (onOff === 'on') say('Every peer your node connects to will see "nodesignal" in its user agent.');
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

/* ------------------------------------------------------------ open / logs */
async function cmdOpen(ctx) {
  const url = ctx.core.webUrl(ctx.cfg);
  say(url);
  if (ctx.deps.hooks && ctx.deps.hooks.openUrl) { ctx.deps.hooks.openUrl(url); return 0; }
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
  say('  sudo apt remove nodesignal     keeps /etc/nodesignal and your ~/.nodesignal');
  say('  sudo apt purge nodesignal      also removes /etc/nodesignal (never ~/.nodesignal)');
  say('If you turned it on, run "sudo nodesignal advertise off" first.');
  return 0;
}

/* ------------------------------------------------------------ setup (Linux)
   Called by the .deb postinst as root. Picks the service user (the owner of
   the node's data directory or cookie, so the daemon can read the cookie),
   writes /etc/nodesignal/config.json if absent, the systemd drop-in that sets
   User=/Group= and the writable state directory, and checks RPC.
   --root <dir> runs it against a fake filesystem for tests. */
async function cmdSetup(ctx) {
  const { core, argv } = ctx;
  const root = optValue(argv, 'root') || process.env.NODESIGNAL_TEST_ROOT || '';
  const P = (p) => (root ? path.join(root, p) : p);
  const redetect = argv.includes('--redetect');
  if (!root && !isRoot()) { say('nodesignal setup must run as root: sudo nodesignal setup'); return 1; }

  const cfgPath = optValue(argv, 'config') || '/etc/nodesignal/config.json';
  const dropDir = '/etc/systemd/system/nodesignal.service.d';
  const dropIn = path.join(dropDir, '10-user.conf');
  const det = await core.detectBitcoinNode({ root });

  if (det.installed) say(`Bitcoin node found: ${det.how.slice(0, 3).join('; ')}`);
  else say('No Bitcoin node was found on this machine.');

  // an older from-source unit (install-node.sh before 1.3) kept its settings
  // on the ExecStart line; carry them over once
  const migrated = parseOldUnit(optValue(argv, 'migrate-unit') ? P(optValue(argv, 'migrate-unit')) : null);
  if (migrated) say(`Carrying over settings from ${optValue(argv, 'migrate-unit')}`);

  // 1. service user
  let user = null;
  const wantUser = optValue(argv, 'user') || (migrated && migrated.user);
  if (wantUser) {
    user = core.readPasswd(root).find((u) => u.name === wantUser) || null;
    if (!user) { say(`No such user: ${wantUser}`); return 1; }
  }
  const existingDrop = readDropInUser(P(dropIn));
  if (!user && existingDrop && !redetect) user = core.readPasswd(root).find((u) => u.name === existingDrop) || null;
  if (!user && det.owner && det.owner.username) user = core.readPasswd(root).find((u) => u.uid === det.owner.uid) || null;
  let dedicated = false;
  if (!user) {
    user = ensureSystemUser(core, root);
    dedicated = true;
  }
  if (user.uid === 0) say('Warning: the node runs as root, so NodeSignal will too, to read its cookie. Consider running bitcoind as its own user.');
  else say(`Service user: ${user.name}${dedicated ? ' (dedicated account; no node owner was found)' : ' (owns the node\'s data, so it can read the RPC cookie)'}`);

  // 2. config, only if absent
  let cfg;
  const nickArg = optValue(argv, 'nick');
  if (fs.existsSync(P(cfgPath))) {
    cfg = JSON.parse(fs.readFileSync(P(cfgPath), 'utf8'));
    if (nickArg && nickArg !== cfg.nick) { cfg.nick = nickArg.slice(0, 60); core.writeConfig(P(cfgPath), cfg); say(`Display name set to "${cfg.nick}" in ${cfgPath}`); }
    else say(`Keeping existing ${cfgPath}`);
  } else {
    const home = user.home && user.home !== '/' && user.home !== '/nonexistent' && fs.existsSync(P(user.home)) ? user.home : '/var/lib/nodesignal';
    cfg = { nick: hostnameOf(root), data: home === '/var/lib/nodesignal' ? home : path.join(home, '.nodesignal') };
    if (det.cookiePath && !core.daemonFindsCookie(det.cookiePath, user.home || '/', 'linux')) cfg['rpc-cookie'] = det.cookiePath;
    if (det.confPath && !core.daemonFindsConf(det.confPath, user.home || '/', 'linux')) cfg['rpc-conf'] = det.confPath;
    if (det.rpcUrlNeeded) cfg['rpc-url'] = det.rpcUrl;
    if (migrated) Object.assign(cfg, migrated.config);
    if (nickArg) cfg.nick = nickArg.slice(0, 60);
    core.writeConfig(P(cfgPath), cfg, { owner: { uid: user.uid, gid: user.gid } });
    say(`Wrote ${cfgPath}`);
  }
  if (argv.includes('--generate-token') && !cfg['web-token']) {
    cfg['web-token'] = require('crypto').randomBytes(24).toString('base64url');
    core.writeConfig(P(cfgPath), cfg);
    say('Web login token (save it, you need it to sign in):');
    say('  ' + cfg['web-token']);
  }
  // the service user must be able to read its own config
  try { fs.chownSync(P(cfgPath), user.uid, user.gid); fs.chmodSync(P(cfgPath), 0o600); } catch { }
  try { fs.chmodSync(P(path.dirname(cfgPath)), 0o755); } catch { }

  // 3. state directory, never emptied or replaced
  const dataDir = cfg.data || path.join(user.home || '/var/lib/nodesignal', '.nodesignal');
  if (!fs.existsSync(P(dataDir))) {
    fs.mkdirSync(P(dataDir), { recursive: true, mode: 0o700 });
    try { fs.chownSync(P(dataDir), user.uid, user.gid); } catch { }
  }

  // 4. systemd drop-in
  const drop = ['# Written by nodesignal setup. Re-detect with: sudo nodesignal setup --redetect',
    '[Service]', `User=${user.name}`, `Group=${groupName(core, root, user)}`, `ReadWritePaths=${dataDir}`, ''].join('\n');
  fs.mkdirSync(P(dropDir), { recursive: true });
  fs.writeFileSync(P(dropIn), drop, { mode: 0o644 });

  // 5. can that user read the cookie?
  if (det.cookiePath && !cfg['rpc-user']) {
    try {
      const st = fs.statSync(P(det.cookiePath));
      const readable = st.uid === user.uid || (st.mode & 0o004) || ((st.mode & 0o040) && st.gid === user.gid);
      if (!readable) say(`Warning: ${user.name} cannot read ${det.cookiePath}. See "permission denied" in the install guide.`);
    } catch { }
  }

  if (!root && hasSystemd()) {
    try { execFileSync('systemctl', ['daemon-reload'], { stdio: 'ignore', timeout: 30000 }); } catch { }
  }

  // 6. RPC check, as root (it can read any cookie)
  if (det.installed) await printRpcCheck(core, det, cfg, { root });
  return 0;
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
  return { user: user ? user.trim() : null, config };
}
function readDropInUser(file) {
  try { const m = fs.readFileSync(file, 'utf8').match(/^User=(.+)$/m); return m ? m[1].trim() : null; } catch { return null; }
}
function groupName(core, root, user) {
  try {
    for (const line of fs.readFileSync(path.join(root || '/', 'etc', 'group'), 'utf8').split('\n')) {
      const p = line.split(':');
      if (p.length >= 3 && Number(p[2]) === user.gid) return p[0];
    }
  } catch { }
  return user.name;
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
  open                 print the web interface address and open it
  logs                 show where the log is and how to follow it
  uninstall            remove NodeSignal (Windows; on Linux use apt)
  version              print the version%EXTRA%`;
const HELP_LINUX = `
  setup [--redetect]   Linux, as root: pick the service user and write the
                       config if missing (the .deb runs this for you)`;
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

module.exports = { main, cmdSetup };

if (require.main === module) {
  main().then((code) => process.exit(code || 0), (e) => { console.error('nodesignal: ' + (e && e.message ? e.message : e)); process.exit(1); });
}
