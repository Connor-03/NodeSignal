#!/usr/bin/env node
// install.js: interactive NodeSignal setup, from a copy of the source.
// ============================================================================
// Most people should use the one-download installers instead (the Windows
// .exe or the Linux .deb from GitHub Releases); see WindowsInstallGuide.txt
// and LinuxInstallGuide.txt. This script is for running from a git checkout
// with your own Node.js.
//
// NodeSignal runs beside a Bitcoin node (Core or Knots), so setup refuses to
// continue on a machine without one. It asks only what it cannot work out,
// verifies every answer against the real system (does bitcoind answer? is
// that port free?), then writes the configuration and a launcher.
//
// Run it through install-windows.bat, or directly:  node install.js
//
// It never writes secrets to a command line. NodeSignal logs in to the node
// as its own RPC user: setup adds an rpcauth line (a salted hash) and an
// rpcwhitelist of the three methods it calls to bitcoin.conf, and keeps the
// password in nodesignal-config.json, which is locked to the current user on
// Windows via icacls and chmod 600 elsewhere. The node's cookie is never read.
// Setup refuses to run as root or as Windows administrator.
// ============================================================================
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const core = require('./setup-core.js');

const HERE = __dirname;
const IS_WIN = process.platform === 'win32';
const CONFIG_FILE = path.join(HERE, 'nodesignal-config.json');
const LAUNCHER = path.join(HERE, IS_WIN ? 'run-nodesignal.bat' : 'run-nodesignal.sh');

/* ------------------------------------------------------------ pretty output */
const C = process.stdout.isTTY ? {
  r: '\x1b[0m', b: '\x1b[1m', dim: '\x1b[2m',
  grn: '\x1b[32m', yel: '\x1b[33m', red: '\x1b[31m', cyn: '\x1b[36m', org: '\x1b[38;5;208m',
} : { r: '', b: '', dim: '', grn: '', yel: '', red: '', cyn: '', org: '' };
const say = (s = '') => console.log(s);
const ok = (s) => say(`  ${C.grn}✓${C.r} ${s}`);
const warn = (s) => say(`  ${C.yel}!${C.r} ${s}`);
const bad = (s) => say(`  ${C.red}✗${C.r} ${s}`);
const info = (s) => say(`    ${C.dim}${s}${C.r}`);
function header(n, total, title) {
  say('');
  say(`${C.org}${C.b}  Step ${n}/${total}  ${title}${C.r}`);
  say(`  ${C.dim}${'─'.repeat(58)}${C.r}`);
}

/* ------------------------------------------------------------ prompts
   setup-core's prompter reads a terminal or piped input (one answer per
   line), so setup can be scripted:  node install.js < answers.txt */
const P = core.createPrompter();
const ask = (q) => P.ask(q);
const askDefault = (q, d) => P.askDefault(q, d);
const askYesNo = (q, d = true) => P.askYesNo(q, d);
async function askChoice(q, options) {
  say(`  ${q}`);
  options.forEach((o, i) => say(`    ${C.cyn}${i + 1}${C.r}) ${o.label}${o.hint ? `  ${C.dim}${o.hint}${C.r}` : ''}`));
  for (let i = 0; i < 20; i++) {
    const a = await ask(`  Choose 1-${options.length} [1]: `);
    const n = a === '' ? 1 : parseInt(a, 10);
    if (n >= 1 && n <= options.length) return options[n - 1].value;
    warn(`Enter a number between 1 and ${options.length}.`);
  }
  return options[0].value;
}
async function askHidden(q) {
  // Masked entry, but only when a real terminal is attached.
  if (!P.tty) return ask(`  ${q}: `);
  P.close();
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    process.stdout.write(`  ${q}: `);
    let value = '';
    const onData = (ch) => {
      const s = ch.toString('utf8');
      if (s === '\n' || s === '\r' || s === '\u0004') {
        try { stdin.setRawMode(wasRaw); } catch { }
        stdin.removeListener('data', onData);
        stdin.pause();
        process.stdout.write('\n'); resolve(value);
      } else if (s === '\u0003') { process.stdout.write('\n'); process.exit(1); }
      else if (s === '\u0008' || s === '\u007f') {
        if (value.length) { value = value.slice(0, -1); process.stdout.write('\b \b'); }
      } else { value += s; process.stdout.write('*'); }
    };
    stdin.resume();
    try { stdin.setRawMode(true); } catch { }
    stdin.on('data', onData);
  });
}

/* ------------------------------------------------------------ main */
const TOTAL = 7;

// root on Linux/macOS; an elevated (administrator) window on Windows, where
// "net session" only succeeds with admin rights
function runsPrivileged() {
  if (!IS_WIN) return typeof process.getuid === 'function' && process.getuid() === 0;
  try { execFileSync('net', ['session'], { stdio: 'ignore', timeout: 10000, windowsHide: true }); return true; } catch { return false; }
}

async function main() {
  say('');
  say(`${C.org}${C.b}  ◈ NodeSignal setup${C.r}`);
  say(`  ${C.dim}Encrypted operator chat that runs beside your Bitcoin node${C.r}`);
  say(`  ${C.dim}${'═'.repeat(58)}${C.r}`);
  say(`  ${C.dim}Press Enter to accept the value in brackets. Ctrl+C to quit.${C.r}`);

  /* ---- Step 1: prerequisites ---- */
  header(1, TOTAL, 'Checking this machine');
  const major = parseInt(process.versions.node.split('.')[0], 10);
  if (major < 18) {
    bad(`Node.js ${process.versions.node} is too old. Install the LTS build from https://nodejs.org`);
    return 1;
  }
  ok(`Node.js ${process.versions.node}`);
  if (runsPrivileged()) {
    bad(IS_WIN ? 'This window runs as administrator.' : 'This runs as root.');
    info('NodeSignal never runs with admin rights and does not need them.');
    info(IS_WIN ? 'Open a normal Command Prompt or PowerShell window and run setup again.'
      : 'Run it as your normal user, or use the .deb or ./install-node.sh, which run NodeSignal as a dedicated nodesignal user.');
    return 1;
  }

  let list;
  try { list = core.readFileList(HERE); }
  catch (e) { bad(`Cannot read packaging/files.json (${e.message}). Run setup from a full copy of the repository.`); return 1; }
  const missing = core.missingFiles(HERE, list.all);
  if (missing.length) {
    bad(`Missing from this folder: ${missing.join(', ')}`);
    info(`Folder: ${HERE}`);
    info('Use a complete copy of the repository and run setup again.');
    return 1;
  }
  ok('Program files present');

  // A leftover node_modules from an older release is dead weight now.
  const nm = path.join(HERE, 'node_modules');
  if (fs.existsSync(nm)) {
    warn('Found node_modules from an older version. NodeSignal no longer needs it.');
    if (await askYesNo('Delete it?', true)) {
      try {
        fs.rmSync(nm, { recursive: true, force: true });
        fs.rmSync(path.join(HERE, 'package-lock.json'), { force: true });
        ok('Removed');
      } catch (e) { warn('Could not remove: ' + e.message); }
    }
  }

  const cfg = {};
  if (fs.existsSync(CONFIG_FILE)) {
    warn('An existing nodesignal-config.json was found.');
    if (!(await askYesNo('Overwrite it?', false))) { say('\n  Setup cancelled. Nothing changed.\n'); return 0; }
    // keep NodeSignal's RPC password, so bitcoin.conf (and the node) need no change
    try { const old = core.readConfig(CONFIG_FILE); if (old['rpc-user'] === core.RPC_USER && old['rpc-pass']) { cfg['rpc-user'] = old['rpc-user']; cfg['rpc-pass'] = old['rpc-pass']; } } catch { }
  }

  /* ---- Step 2: the Bitcoin node ---- */
  header(2, TOTAL, 'Finding your Bitcoin node');
  let det = await core.detectBitcoinNode();
  if (!det.installed) {
    bad('No Bitcoin node was found on this machine.');
    info('NodeSignal runs beside Bitcoin Core or Bitcoin Knots. It looked for a running');
    info('bitcoind or bitcoin-qt, a Bitcoin data directory and the bitcoind program.');
    info('Install Bitcoin Core (https://bitcoincore.org/en/download/) or');
    info('Bitcoin Knots (https://bitcoinknots.org/), start it once, then run setup again.');
    info('Pruned nodes are fine. Nothing was changed.');
    return 1;
  }
  for (const h of det.how.slice(0, 4)) ok(`Found ${h}`);
  say(`  ${C.dim}NodeSignal only reads: getpeerinfo, getnetworkinfo, getblockchaininfo.${C.r}`);
  say(`  ${C.dim}It never touches your wallet. Pruned nodes are fully supported.${C.r}`);
  say('');

  // NodeSignal's own RPC login: rpcauth + rpcwhitelist in bitcoin.conf
  const nodeConf = core.nodeConfPath(det);
  let access = null;
  if (nodeConf) {
    try { access = core.installRpcAccess({ cfg, cfgPath: CONFIG_FILE, confPath: nodeConf, owner: det.owner }); }
    catch (e) { warn(e.message); }
  }
  core.ensureRpcLogin(cfg);
  cfg['rpc-url'] = det.rpcUrl;                         // the daemon does not read bitcoin.conf
  if (access && access.result.changed) {
    ok(`Added NodeSignal's RPC login (user ${core.RPC_USER}, three read-only methods) to ${nodeConf}`);
    if (access.result.backup) info(`The original was saved as ${access.result.backup}`);
    for (const l of core.RPC_RESTART_TEXT[IS_WIN ? 'win32' : 'linux']) warn(l);
  } else {
    if (access) ok(`NodeSignal's RPC login is already in ${nodeConf}`);
    else {
      warn('NodeSignal could not add its RPC login to bitcoin.conf. Add these lines to it by hand, then restart the node:');
      say(`      ${C.cyn}${core.makeRpcAuth(core.RPC_USER, cfg['rpc-pass'])}${C.r}`);
      say(`      ${C.cyn}rpcwhitelist=${core.RPC_USER}:${core.RPC_METHODS.join(',')}${C.r}`);
      info('Plus rpcwhitelistdefault=0 if bitcoin.conf has no rpcwhitelist lines of its own.');
    }
    for (;;) {
      const rpc = await core.checkNode(det, cfg);
      if (rpc.ok) {
        ok(`Connected as ${core.RPC_USER}`);
        info(`Node: ${rpc.subversion || 'unknown'}`);
        info(`Chain: ${rpc.chain} · height ${Number(rpc.blocks).toLocaleString()}${rpc.pruned ? ' · pruned' : ''}`);
        break;
      }
      warn(`Your node is installed but RPC is not answering right now: ${rpc.error}.`);
      if (rpc.hint) info(rpc.hint);
      info('NodeSignal can be set up anyway: it reconnects by itself every 30 seconds.');
      if (!(await askYesNo('Check again?', true))) break;
    }
  }

  /* ---- Step 3: identity ---- */
  header(3, TOTAL, 'Naming this node');
  cfg.nick = (await askDefault('Display name shown to other operators', os.hostname())).slice(0, 60);

  /* ---- Step 4: networking ---- */
  header(4, TOTAL, 'Networking');
  const ts = core.tailscaleAddr();
  if (ts) ok(`Tailscale detected at ${ts}`);
  const netMode = await askChoice('How will other operators reach this machine?', [
    ...(ts ? [{ value: 'tailscale', label: 'Tailscale only', hint: `(${ts}, private, recommended)` }] : []),
    { value: 'tor', label: 'Tor hidden service', hint: '(most private; needs torrc setup)' },
    { value: 'local', label: 'This machine only', hint: '(localhost, nobody else can reach it)' },
    { value: 'clearnet', label: 'Open internet', hint: '(exposes your IP; read the security notes)' },
  ]);
  if (netMode === 'tailscale') cfg.bind = ts;
  else if (netMode === 'local') cfg.bind = '127.0.0.1';
  else if (netMode === 'tor') {
    cfg.bind = '127.0.0.1';
    // Reaching another operator's .onion needs Tor's SOCKS proxy for outbound
    // connections: DNS cannot resolve .onion, so a direct dial fails.
    const px = await askDefault('Tor SOCKS proxy address', '127.0.0.1:9050');
    cfg['tor-proxy'] = px;
    const [ph, pp] = [px.slice(0, px.lastIndexOf(':')), Number(px.slice(px.lastIndexOf(':') + 1))];
    if (await core.portFree(pp, ph === '0.0.0.0' ? '0.0.0.0' : '127.0.0.1')) {
      warn(`Nothing is listening on ${px}. Start Tor before using NodeSignal.`);
    } else ok(`Tor SOCKS proxy reachable at ${px}`);
    info('Tor reaches the daemon over localhost. Add to your torrc:');
    say(`      ${C.cyn}HiddenServiceDir /var/lib/tor/nodesignal/${C.r}`);
    say(`      ${C.cyn}HiddenServicePort 8788 127.0.0.1:8788${C.r}`);
    say(`      ${C.cyn}HiddenServicePort 8789 127.0.0.1:8789${C.r}`);
    info('Then restart Tor and share the .onion from that directory. No port forwarding.');
  } else {
    warn('Clearnet publishes the link between your identity and your node IP.');
    warn('See SECURITY-CRITIQUE.md before using this on a node holding real value.');
    cfg.bind = '0.0.0.0';
  }

  let webPort = 8789, peerPort = 8788;
  for (;;) {
    webPort = Number(await askDefault('Web interface port', String(webPort)));
    if (await core.portFree(webPort)) { ok(`Port ${webPort} is free`); break; }
    bad(`Port ${webPort} is already in use.`);
    webPort = webPort + 1;
  }
  for (;;) {
    peerPort = Number(await askDefault('Peer messaging port', String(peerPort)));
    if (peerPort === webPort) { bad('Must differ from the web port.'); peerPort = webPort + 1; continue; }
    if (await core.portFree(peerPort)) { ok(`Port ${peerPort} is free`); break; }
    bad(`Port ${peerPort} is already in use.`);
    peerPort = peerPort + 1;
  }
  cfg['web-port'] = webPort;
  cfg['peer-port'] = peerPort;

  /* ---- Step 5: access control ---- */
  header(5, TOTAL, 'Web interface access');
  const openOk = netMode === 'local' || netMode === 'tailscale';
  say(`  ${C.dim}A token requires a login before the interface can be used.${C.r}`);
  if (!openOk) warn('Strongly recommended for Tor or clearnet.');
  if (await askYesNo('Require a login token?', !openOk)) {
    const choice = await askChoice('Token', [
      { value: 'gen', label: 'Generate a strong one for me' },
      { value: 'own', label: 'I will type my own' },
    ]);
    cfg['web-token'] = choice === 'gen'
      ? crypto.randomBytes(24).toString('base64url')
      : await askHidden('Enter token');
    if (choice === 'gen') { ok('Generated'); say(`      ${C.b}${cfg['web-token']}${C.r}`); info('Save this. You will need it to sign in.'); }
  } else {
    info('No login required. Fine on a private tailnet or localhost.');
  }

  /* ---- Step 6: optional extras, both off unless you say yes ---- */
  header(6, TOTAL, 'Optional extras (both off by default)');
  const confPath = det.confPath || (det.datadir ? path.join(det.datadir, 'bitcoin.conf') : null);
  let advertise = false;
  const ua = confPath ? core.uaCommentState(confPath) : { on: false };
  if (ua.on) ok('Your node already advertises NodeSignal (uacomment=nodesignal).');
  else if (confPath && !ua.unreadable) {
    for (const l of core.OPT_IN_TEXT.advertise.slice(1)) info(l);
    advertise = await askYesNo(core.OPT_IN_TEXT.advertise[0], false);
  } else if (!confPath) info('No bitcoin.conf location found, so the user agent offer is skipped.');
  say('');
  for (const l of core.OPT_IN_TEXT.portMapping.slice(1)) info(l);
  if (await askYesNo(core.OPT_IN_TEXT.portMapping[0], false)) cfg['port-mapping'] = true;

  /* ---- Step 7: write everything ---- */
  header(7, TOTAL, 'Writing configuration');
  cfg.data = path.join(os.homedir(), '.nodesignal');

  const locked = core.writeConfig(CONFIG_FILE, cfg);
  ok(`Config written: ${CONFIG_FILE}`);
  if (locked) ok('Permissions restricted to your user account');
  else warn('Could not restrict file permissions. Check them manually.');

  if (advertise) {
    try {
      const r = core.setUaComment(confPath, true);
      ok(`Added uacomment=nodesignal to ${confPath}`);
      if (r.backup) info(`The original was saved as ${r.backup}`);
      info('Restart your node yourself for peers to see it. NodeSignal never restarts it.');
    } catch (e) { warn(`Could not edit bitcoin.conf: ${e.message}`); }
  }

  const nodeExe = process.execPath;
  if (IS_WIN) {
    fs.writeFileSync(LAUNCHER,
      ['@echo off',
        'cd /d "%~dp0"',
        'title NodeSignal',
        `"${nodeExe}" nodesignald.js --config "%~dp0nodesignal-config.json"`,
        'echo.',
        'echo   Daemon stopped. The message above is the reason.',
        'pause', ''].join('\r\n'), 'utf8');
  } else {
    fs.writeFileSync(LAUNCHER,
      ['#!/usr/bin/env bash', 'cd "$(dirname "$0")"',
        `exec "${nodeExe}" nodesignald.js --config ./nodesignal-config.json`, ''].join('\n'));
    fs.chmodSync(LAUNCHER, 0o755);
  }
  ok(`Launcher written: ${path.basename(LAUNCHER)}`);

  // Firewall: only relevant when someone else must reach us.
  if (IS_WIN && netMode !== 'local') {
    say('');
    say(`  ${C.dim}Windows Firewall must allow inbound TCP ${peerPort}, or replies${C.r}`);
    say(`  ${C.dim}from other operators cannot reach you.${C.r}`);
    const cmd = `netsh advfirewall firewall add rule name="NodeSignal ${peerPort}" dir=in action=allow protocol=TCP localport=${peerPort}`;
    if (await askYesNo('Try to add the rule now? (needs admin)', true)) {
      try {
        execFileSync('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=NodeSignal ${peerPort}`,
          'dir=in', 'action=allow', 'protocol=TCP', `localport=${peerPort}`], { stdio: 'ignore' });
        ok('Firewall rule added');
      } catch {
        warn('Could not add it (this window is probably not admin).');
        info('Run this once in an ADMIN PowerShell:');
        say(`      ${C.cyn}${cmd}${C.r}`);
      }
    } else {
      info('Run this later in an ADMIN PowerShell if peers cannot reach you:');
      say(`      ${C.cyn}${cmd}${C.r}`);
    }
  }

  if (IS_WIN && await askYesNo('Create a Desktop shortcut?', true)) {
    try {
      const desktop = path.join(os.homedir(), 'Desktop');
      const ps = `$s=(New-Object -COM WScript.Shell).CreateShortcut('${path.join(desktop, 'NodeSignal.lnk')}');`
        + `$s.TargetPath='${LAUNCHER}';$s.WorkingDirectory='${HERE}';$s.Description='NodeSignal';$s.Save()`;
      execFileSync('powershell', ['-NoProfile', '-Command', ps], { stdio: 'ignore' });
      ok('Desktop shortcut created');
    } catch { warn('Could not create the shortcut.'); }
  }

  /* ---- verify by actually starting it ---- */
  say('');
  say(`  ${C.dim}Starting the daemon to verify the configuration…${C.r}`);
  const child = spawn(nodeExe, ['nodesignald.js', '--config', CONFIG_FILE], { cwd: HERE, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d.toString()));
  child.stderr.on('data', (d) => (out += d.toString()));

  const health = await new Promise((resolve) => {
    const started = Date.now();
    const poll = () => {
      const host = '127.0.0.1';                     // the web console only listens on loopback
      const req = http.get({ host, port: webPort, path: '/health', timeout: 2000 }, (res) => {
        let d = ''; res.on('data', (c) => (d += c));
        res.on('end', () => {
          let j = null; try { j = JSON.parse(d); } catch { }
          // give RPC a few seconds to connect before reporting
          if (j && !j.rpcConnected && Date.now() - started < 9000) return setTimeout(poll, 700);
          resolve(j);
        });
      });
      req.on('error', () => { if (Date.now() - started > 12000) resolve(null); else setTimeout(poll, 500); });
      req.on('timeout', () => { req.destroy(); if (Date.now() - started > 12000) resolve(null); else setTimeout(poll, 500); });
    };
    setTimeout(poll, 1200);
  });
  try { child.kill(); } catch { }
  // Make certain nothing is left holding the terminal open.
  setTimeout(() => { try { child.kill('SIGKILL'); } catch { } }, 1500).unref();

  say('');
  if (health && health.status === 'ok') {
    say(`  ${C.grn}${C.b}  Setup complete.${C.r}`);
    say('');
    ok(`Daemon starts cleanly as "${health.nick}"`);
    ok(`Encryption: ${health.secure ? 'Noise handshake, identity ' + String(health.fingerprint).slice(0, 16) + '…' : 'PIN fallback'}`);
    if (health.rpcConnected) ok(`Bitcoin RPC connected: ${health.peerCount} peers will appear on the map`);
    else warn('Bitcoin RPC is not connected yet. The daemon retries every 30 seconds; see the notes above.');
  } else {
    bad('The daemon did not answer its health check.');
    say(`${C.dim}${out.split('\n').slice(-14).join('\n')}${C.r}`);
  }

  const url = `http://localhost:${webPort}`;   // loopback only; from another machine use an SSH tunnel
  say('');
  say(`  ${C.b}To start NodeSignal:${C.r}  ${C.cyn}${path.basename(LAUNCHER)}${C.r}${IS_WIN ? '  (or the Desktop shortcut)' : ''}`);
  say(`  ${C.b}Then open:${C.r}           ${C.cyn}${url}${C.r}`);
  if (cfg['web-token']) say(`  ${C.b}Sign in with:${C.r}        ${C.dim}the token shown above${C.r}`);
  if (netMode === 'tor') say(`  ${C.b}Tor:${C.r}                 ${C.dim}finish the torrc steps, then share your .onion${C.r}`);
  say('');
  say(`  ${C.dim}Settings live in nodesignal-config.json. Edit and restart to change them,${C.r}`);
  say(`  ${C.dim}or use: node cli.js advertise on|off, node cli.js port-mapping on|off,${C.r}`);
  say(`  ${C.dim}node cli.js rpc-access show|add|remove${C.r}`);
  say('');
  return 0;
}

main().then((code) => {
  P.close();
  // Nothing further to do; exit rather than waiting on any stray handle.
  setTimeout(() => process.exit(code || 0), 50).unref();
}, (e) => { say(''); bad(e && e.message ? e.message : String(e)); P.close(); process.exit(1); });
