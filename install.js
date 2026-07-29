#!/usr/bin/env node
// install.js — interactive NodeSignal setup
// ============================================================================
// Asks only what it cannot work out for itself, verifies every answer against
// the real system (does that cookie file exist? does bitcoind actually answer?
// is that port free?), then writes the configuration and a launcher.
//
// Run it through install-windows.bat, or directly:  node install.js
//
// It never writes secrets to a command line. Credentials go into
// nodesignal-config.json, which is locked to the current user on Windows via
// icacls and chmod 600 elsewhere.
// ============================================================================
'use strict';
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const readline = require('readline');
const { execFileSync } = require('child_process');

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
   Node's readline only yields the first line when stdin is a pipe, so an
   installer built purely on rl.question() cannot be scripted or tested.
   When stdin is not a TTY we read it all up front and serve answers from a
   queue; interactive use is unchanged. That also makes unattended installs
   possible:  node install.js < answers.txt   */
const IS_TTY = !!process.stdin.isTTY;
let rl = null;
let queued = null;

function loadPipedInput() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => (data += d));
    process.stdin.on('end', () => resolve(data.split('\n')));
    process.stdin.on('error', () => resolve([]));
  });
}
function ask(q) {
  if (IS_TTY) return new Promise((res) => rl.question(q, (a) => res(a.trim())));
  process.stdout.write(q);
  const line = queued.length ? queued.shift() : '';
  process.stdout.write(line + '\n');
  return Promise.resolve(String(line).trim());
}
const closeInput = () => { if (rl) rl.close(); };
async function askDefault(q, dflt) {
  const a = await ask(`  ${q} ${C.dim}[${dflt}]${C.r}: `);
  return a === '' ? dflt : a;
}
async function askYesNo(q, dfltYes = true) {
  for (let i = 0; i < 20; i++) {
    const a = (await ask(`  ${q} ${C.dim}[${dfltYes ? 'Y/n' : 'y/N'}]${C.r}: `)).toLowerCase();
    if (a === '') return dfltYes;
    if (['y', 'yes'].includes(a)) return true;
    if (['n', 'no'].includes(a)) return false;
    warn('Please answer y or n.');
  }
  return dfltYes;
}
async function askChoice(q, options) {
  say(`  ${q}`);
  options.forEach((o, i) => say(`    ${C.cyn}${i + 1}${C.r}) ${o.label}${o.hint ? `  ${C.dim}${o.hint}${C.r}` : ''}`));
  for (let i = 0; i < 20; i++) {
    const a = await ask(`  Choose 1-${options.length} ${C.dim}[1]${C.r}: `);
    const n = a === '' ? 1 : parseInt(a, 10);
    if (n >= 1 && n <= options.length) return options[n - 1].value;
    warn(`Enter a number between 1 and ${options.length}.`);
  }
  return options[0].value;
}
async function askHidden(q) {
  // Masked entry, but only when a real terminal is attached.
  if (!IS_TTY) return ask(`  ${q}: `);
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

/* ------------------------------------------------------------ system probes */
function portFree(port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(port, host);
  });
}
function bitcoinDataDirs() {
  const out = [];
  if (IS_WIN) {
    const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    out.push(path.join(appdata, 'Bitcoin'));
    out.push(path.join(os.homedir(), 'AppData', 'Local', 'Bitcoin'));
  } else {
    out.push(path.join(os.homedir(), '.bitcoin'));
    out.push('/var/lib/bitcoind', '/var/lib/bitcoin', '/etc/bitcoin');
  }
  return out.filter((d) => { try { return fs.statSync(d).isDirectory(); } catch { return false; } });
}
function parseConf(file) {
  try {
    const out = {}; let section = '';
    for (let line of fs.readFileSync(file, 'utf8').split('\n')) {
      line = line.trim();
      if (!line || line.startsWith('#')) continue;
      const sec = line.match(/^\[(\w+)\]$/);
      if (sec) { section = sec[1].toLowerCase(); continue; }
      if (section && section !== 'main') continue;
      const i = line.indexOf('=');
      if (i < 0) continue;
      const k = line.slice(0, i).trim().toLowerCase();
      if (!(k in out)) out[k] = line.slice(i + 1).trim();
    }
    return out;
  } catch { return null; }
}
// Actually call the node. This is the difference between collecting text and
// verifying a setup.
function rpcTest(url, auth, method = 'getnetworkinfo', params = []) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, error: 'bad RPC URL' }); }
    const body = JSON.stringify({ jsonrpc: '1.0', id: 'setup', method, params });
    const req = http.request({
      hostname: u.hostname, port: u.port || 8332, path: '/', method: 'POST',
      headers: {
        'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        Authorization: 'Basic ' + Buffer.from(auth).toString('base64'),
      }, timeout: 6000,
    }, (res) => {
      let d = ''; res.on('data', (c) => (d += c));
      res.on('end', () => {
        if (res.statusCode === 401) return resolve({ ok: false, error: 'authentication rejected (wrong user/password or stale cookie)' });
        try {
          const j = JSON.parse(d);
          if (j.error) return resolve({ ok: false, error: j.error.message });
          resolve({ ok: true, result: j.result });
        } catch { resolve({ ok: false, error: `unexpected reply (HTTP ${res.statusCode})` }); }
      });
    });
    req.on('error', (e) => resolve({
      ok: false,
      error: e.code === 'ECONNREFUSED'
        ? 'nothing listening — is bitcoind running with server=1?'
        : (e.code || e.message),
    }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timed out' }); });
    req.end(body);
  });
}
function tailscaleAddr() {
  try {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      for (const a of ifaces[name]) {
        if (a.family !== 'IPv4' || a.internal) continue;
        if (/tailscale|^ts\d/i.test(name)) return a.address;
        const o = a.address.split('.').map(Number);
        if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return a.address;
      }
    }
  } catch { }
  return null;
}
function lockDownFile(file) {
  try {
    if (IS_WIN) {
      const user = process.env.USERNAME || '';
      execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${user}:F`], { stdio: 'ignore' });
    } else fs.chmodSync(file, 0o600);
    return true;
  } catch { return false; }
}

/* ------------------------------------------------------------ main */
const TOTAL = 7;

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
    process.exit(1);
  }
  ok(`Node.js ${process.versions.node}`);

  const needed = ['nodesignald.js', 'noise.js', 'nodeps.js'];
  const missing = needed.filter((f) => !fs.existsSync(path.join(HERE, f)));
  if (missing.length) {
    bad(`Missing from this folder: ${missing.join(', ')}`);
    info(`Folder: ${HERE}`);
    info('Put every NodeSignal file in one folder and run setup again.');
    process.exit(1);
  }
  ok('Program files present');

  const hasConsole = fs.existsSync(path.join(HERE, 'nodesignal.html'));
  const hasDemo = fs.existsSync(path.join(HERE, 'nodesignal-demo.html'));
  if (!hasConsole && !hasDemo) {
    bad('No interface file (nodesignal.html or nodesignal-demo.html) in this folder.');
    process.exit(1);
  }
  // A leftover node_modules from an older release is dead weight now.
  const nm = path.join(HERE, 'node_modules');
  if (fs.existsSync(nm)) {
    warn('Found node_modules from an older version — NodeSignal no longer needs it.');
    if (await askYesNo('Delete it?', true)) {
      try {
        fs.rmSync(nm, { recursive: true, force: true });
        for (const f of ['package-lock.json']) fs.rmSync(path.join(HERE, f), { force: true });
        ok('Removed');
      } catch (e) { warn('Could not remove: ' + e.message); }
    }
  }

  if (fs.existsSync(CONFIG_FILE)) {
    warn('An existing nodesignal-config.json was found.');
    if (!(await askYesNo('Overwrite it?', false))) { say('\n  Setup cancelled. Nothing changed.\n'); closeInput(); return; }
  }

  const cfg = {};

  /* ---- Step 2: role ---- */
  header(2, TOTAL, 'What is this machine?');
  const dataDirs = bitcoinDataDirs();
  if (dataDirs.length) info(`Detected a Bitcoin data directory: ${dataDirs[0]}`);
  const role = await askChoice('Does this machine run a Bitcoin node?', [
    {
      value: 'node',
      label: 'Yes — it runs Bitcoin Core or Knots',
      hint: dataDirs.length ? '(detected)' : '',
    },
    { value: 'peer', label: 'No — set it up as a messaging peer only', hint: '(demo / laptop)' },
  ]);
  cfg['no-rpc'] = role === 'peer';

  /* ---- Step 3: RPC ---- */
  header(3, TOTAL, role === 'node' ? 'Connecting to your Bitcoin node' : 'Peer identity');
  if (role === 'node') {
    say(`  ${C.dim}NodeSignal only reads: getpeerinfo, getnetworkinfo, getblockchaininfo.${C.r}`);
    say(`  ${C.dim}It never touches your wallet. Pruned nodes are fully supported.${C.r}`);
    say('');

    let rpcUrl = 'http://127.0.0.1:8332';
    let auth = null, source = null;

    // Try to find working credentials without asking.
    for (const dir of dataDirs) {
      const conf = parseConf(path.join(dir, 'bitcoin.conf'));
      if (conf && conf.rpcport) rpcUrl = `http://127.0.0.1:${conf.rpcport}`;
      if (conf && conf.rpcuser && conf.rpcpassword) {
        const t = await rpcTest(rpcUrl, `${conf.rpcuser}:${conf.rpcpassword}`);
        if (t.ok) { auth = `${conf.rpcuser}:${conf.rpcpassword}`; source = `bitcoin.conf in ${dir}`;
          cfg['rpc-user'] = conf.rpcuser; cfg['rpc-pass'] = conf.rpcpassword; break; }
      }
      const cookiePath = (conf && conf.rpccookiefile) || path.join((conf && conf.datadir) || dir, '.cookie');
      try {
        const cookie = fs.readFileSync(cookiePath, 'utf8').trim();
        const t = await rpcTest(rpcUrl, cookie);
        if (t.ok) { auth = cookie; source = `cookie file ${cookiePath}`; cfg['rpc-cookie'] = cookiePath; break; }
      } catch { }
      if (conf && conf.rpcauth && !conf.rpcpassword) {
        warn('bitcoin.conf uses rpcauth= (a hash) — the password cannot be read from it.');
      }
    }

    if (auth) {
      ok(`Connected automatically via ${source}`);
    } else {
      warn('Could not connect automatically. Enter credentials manually.');
      info('These are in bitcoin.conf as rpcuser= / rpcpassword=, or use the cookie file.');
      say('');
      for (;;) {
        rpcUrl = await askDefault('RPC address', rpcUrl);
        const how = await askChoice('How should NodeSignal authenticate?', [
          { value: 'userpass', label: 'Username and password' },
          { value: 'cookie', label: 'Cookie file (.cookie)' },
          { value: 'skip', label: 'Skip for now — configure later' },
        ]);
        if (how === 'skip') { warn('Skipped. The peer map stays empty until RPC is configured.'); break; }
        if (how === 'userpass') {
          const u = await ask('  RPC username: ');
          const p = await askHidden('RPC password');
          const t = await rpcTest(rpcUrl, `${u}:${p}`);
          if (t.ok) { ok('Authenticated'); cfg['rpc-user'] = u; cfg['rpc-pass'] = p; auth = `${u}:${p}`; }
          else bad(t.error);
        } else {
          const guess = dataDirs.length ? path.join(dataDirs[0], '.cookie') : '';
          const cp = await askDefault('Path to .cookie', guess);
          try {
            const cookie = fs.readFileSync(cp, 'utf8').trim();
            const t = await rpcTest(rpcUrl, cookie);
            if (t.ok) { ok('Authenticated'); cfg['rpc-cookie'] = cp; auth = cookie; }
            else bad(t.error);
          } catch (e) { bad(`Cannot read ${cp} (${e.code || e.message})`); }
        }
        if (auth) break;
        if (!(await askYesNo('Try again?', true))) { warn('Continuing without RPC.'); break; }
      }
    }
    if (rpcUrl !== 'http://127.0.0.1:8332') cfg['rpc-url'] = rpcUrl;

    if (auth) {
      const ni = await rpcTest(rpcUrl, auth, 'getnetworkinfo');
      const ch = await rpcTest(rpcUrl, auth, 'getblockchaininfo');
      const pi = await rpcTest(rpcUrl, auth, 'getpeerinfo');
      if (ni.ok) info(`Node: ${ni.result.subversion}`);
      if (ch.ok) info(`Chain: ${ch.result.chain} · height ${Number(ch.result.blocks).toLocaleString()}${ch.result.pruned ? ' · pruned' : ''}`);
      if (pi.ok) info(`Peers visible to NodeSignal: ${pi.result.length}`);
      if (pi.ok && pi.result.length === 0) warn('Your node currently has no peers — the map will fill in as it connects.');
    }
  } else {
    say(`  ${C.dim}With no Bitcoin node here, this machine can still message other${C.r}`);
    say(`  ${C.dim}operators. It can also advertise a node identity so it appears on${C.r}`);
    say(`  ${C.dim}their maps — useful for a demo, and flagged to peers as simulated.${C.r}`);
    say('');
    if (await askYesNo('Advertise a simulated node identity?', true)) {
      cfg.impersonate = await askDefault('User agent to advertise',
        '/Satoshi:29.2.0/Knots:20251110+bip110-v0.1/UASF-BIP110:0.1/');
      const h = await askDefault('Block height to advertise', '959370');
      cfg['impersonate-height'] = Number(h) || 0;
      ok('Peers will see this machine as a classified node, marked simulated');
    }
  }

  /* ---- Step 4: identity ---- */
  header(4, TOTAL, 'Naming this node');
  cfg.nick = await askDefault('Display name shown to other operators', os.hostname());

  /* ---- Step 5: networking ---- */
  header(5, TOTAL, 'Networking');
  const ts = tailscaleAddr();
  if (ts) ok(`Tailscale detected at ${ts}`);
  const netMode = await askChoice('How will other operators reach this machine?', [
    ...(ts ? [{ value: 'tailscale', label: `Tailscale only`, hint: `(${ts} — private, recommended)` }] : []),
    { value: 'tor', label: 'Tor hidden service', hint: '(most private; needs torrc setup)' },
    { value: 'local', label: 'This machine only', hint: '(localhost — nobody else can reach it)' },
    { value: 'clearnet', label: 'Open internet', hint: '(exposes your IP — read the security notes)' },
  ]);
  if (netMode === 'tailscale') cfg.bind = ts;
  else if (netMode === 'local') cfg.bind = '127.0.0.1';
  else if (netMode === 'tor') {
    cfg.bind = '127.0.0.1';
    // Reaching another operator's .onion needs Tor's SOCKS proxy for outbound
    // connections — DNS cannot resolve .onion, so a direct dial fails.
    const px = await askDefault('Tor SOCKS proxy address', '127.0.0.1:9050');
    cfg['tor-proxy'] = px;
    const [ph, pp] = [px.slice(0, px.lastIndexOf(':')), Number(px.slice(px.lastIndexOf(':') + 1))];
    if (await portFree(pp, ph === '0.0.0.0' ? '0.0.0.0' : '127.0.0.1')) {
      warn(`Nothing is listening on ${px} — start Tor before using NodeSignal.`);
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
    if (await portFree(webPort)) { ok(`Port ${webPort} is free`); break; }
    bad(`Port ${webPort} is already in use.`);
    webPort = webPort + 1;
  }
  for (;;) {
    peerPort = Number(await askDefault('Peer messaging port', String(peerPort)));
    if (peerPort === webPort) { bad('Must differ from the web port.'); peerPort = webPort + 1; continue; }
    if (await portFree(peerPort)) { ok(`Port ${peerPort} is free`); break; }
    bad(`Port ${peerPort} is already in use.`);
    peerPort = peerPort + 1;
  }
  cfg['web-port'] = webPort;
  cfg['peer-port'] = peerPort;

  /* ---- Step 6: access control ---- */
  header(6, TOTAL, 'Web interface access');
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
    if (choice === 'gen') { ok('Generated'); say(`      ${C.b}${cfg['web-token']}${C.r}`); info('Save this — you will need it to sign in.'); }
  } else {
    info('No login required. Fine on a private tailnet or localhost.');
  }

  /* ---- Step 7: write everything ---- */
  header(7, TOTAL, 'Writing configuration');
  cfg.data = path.join(os.homedir(), '.nodesignal');

  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  ok(`Config written: ${CONFIG_FILE}`);
  if (lockDownFile(CONFIG_FILE)) ok('Permissions restricted to your user account');
  else warn('Could not restrict file permissions — check them manually.');

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
  const { spawn } = require('child_process');
  const child = spawn(nodeExe, ['nodesignald.js', '--config', CONFIG_FILE], { cwd: HERE, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => (out += d.toString()));
  child.stderr.on('data', (d) => (out += d.toString()));

  const health = await new Promise((resolve) => {
    const started = Date.now();
    const poll = () => {
      const host = (cfg.bind && cfg.bind !== '0.0.0.0') ? cfg.bind : '127.0.0.1';
      const req = http.get({ host, port: webPort, path: '/health', timeout: 2000,
        headers: cfg['web-token'] ? { Authorization: 'Bearer ' + cfg['web-token'] } : {} }, (res) => {
        let d = ''; res.on('data', (c) => (d += c));
        res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
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
    if (role === 'node') {
      if (health.rpcConnected) ok(`Bitcoin RPC connected — ${health.peerCount} peers will appear on the map`);
      else warn('Bitcoin RPC is NOT connected — the peer map will be empty. See the notes above.');
    }
  } else {
    bad('The daemon did not answer its health check.');
    say(`${C.dim}${out.split('\n').slice(-14).join('\n')}${C.r}`);
  }

  const url = `http://${(cfg.bind && cfg.bind !== '0.0.0.0') ? cfg.bind : 'localhost'}:${webPort}`;
  say('');
  say(`  ${C.b}To start NodeSignal:${C.r}  ${C.cyn}${path.basename(LAUNCHER)}${C.r}${IS_WIN ? '  (or the Desktop shortcut)' : ''}`);
  say(`  ${C.b}Then open:${C.r}           ${C.cyn}${url}${C.r}`);
  if (cfg['web-token']) say(`  ${C.b}Sign in with:${C.r}        ${C.dim}the token shown above${C.r}`);
  if (netMode === 'tor') say(`  ${C.b}Tor:${C.r}                 ${C.dim}finish the torrc steps, then share your .onion${C.r}`);
  say('');
  say(`  ${C.dim}Settings live in nodesignal-config.json — edit and restart to change them.${C.r}`);
  say('');
  closeInput();
  // Nothing further to do; exit rather than waiting on any stray handle.
  setTimeout(() => process.exit(0), 50).unref();
}

// Bootstrap the input layer before running.
(async () => {
  if (IS_TTY) rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  else queued = await loadPipedInput();
  try { await main(); }
  catch (e) { say(''); bad(e && e.message ? e.message : String(e)); closeInput(); process.exit(1); }
})();
