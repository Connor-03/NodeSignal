// sea-main.js: entry point of the Windows single executable (nodesignal.exe).
// ============================================================================
// Built into NodeSignal-Setup-windows-x64.exe by packaging/build-sea.js, with
// the daemon files, setup-core.js and cli.js embedded as SEA assets.
//
//   (no arguments)      interactive installer: double-click it
//   run                 run the daemon (what the hidden Startup launcher calls)
//   start | stop | restart
//   selftest --rpc-url U --rpc-user X --rpc-pass Y
//                       non-interactive install into a temp folder, run, check
//                       /health, clean up; exit 0 or 1 (for CI, mock node only)
//   uninstall [--purge]
//   anything else       handled by cli.js (status, advertise, port-mapping, ...)
//
// --root <dir> moves the whole install (default %LOCALAPPDATA%\NodeSignal).
//
// Inside a SEA, require() only sees Node's built-in modules, so the embedded
// setup-core.js and cli.js are compiled from their assets, and the daemon is
// loaded from disk with module.createRequire. The same file also runs on
// Linux (paths switch on the platform) so the SEA mechanics can be tested
// there; Windows-only steps are small functions guarded by IS_WIN.
// Console output is plain ASCII so it reads correctly in any code page.
// ============================================================================
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');
const { spawn, spawnSync, execFileSync } = require('child_process');

let sea = null;
try { sea = require('node:sea'); } catch { sea = null; }
const IN_SEA = !!(sea && sea.isSea && sea.isSea());
const IS_WIN = process.platform === 'win32';
const say = (s = '') => process.stdout.write(s + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------ assets
   Outside a SEA (developer runs `node packaging/windows/sea-main.js`), the
   same names are read from the repository instead. */
const REPO = IN_SEA ? null : path.resolve(__dirname, '..', '..');
function assetBuffer(name) {
  if (IN_SEA) return Buffer.from(sea.getAsset(name));
  if (name === 'manifest.json') return Buffer.from(JSON.stringify(devManifest()));
  return fs.readFileSync(path.join(REPO, name));
}
function devManifest() {
  const files = JSON.parse(fs.readFileSync(path.join(REPO, 'packaging', 'files.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8'));
  return { version: pkg.version + '-dev', files: [...files.daemon, ...files.tools] };
}
const MANIFEST = JSON.parse(assetBuffer('manifest.json').toString('utf8'));
const VERSION = MANIFEST.version;

function loadAssetModule(name) {
  if (!IN_SEA) return require(path.join(REPO, name));
  const filename = path.join(path.dirname(process.execPath), name);
  const m = new Module(filename, module);
  m.filename = filename;
  m.paths = [];
  m._compile(assetBuffer(name).toString('utf8'), filename);
  return m.exports;
}
const core = loadAssetModule('setup-core.js');

/* ------------------------------------------------------------ layout */
function defaultRoot() {
  if (IS_WIN) return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'NodeSignal');
  return path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'nodesignal-sea');
}
function layout(root) {
  const r = path.resolve(root || defaultRoot());
  return {
    root: r,
    custom: !!root,
    app: path.join(r, 'app'),
    exe: path.join(r, IS_WIN ? 'nodesignal.exe' : 'nodesignal'),
    config: path.join(r, 'config.json'),
    log: path.join(r, 'nodesignal.log'),
    pid: path.join(r, 'nodesignal.pid'),
  };
}
const VALUE_OPTS = new Set(['--root', '--config', '--rpc-url', '--rpc-user', '--rpc-pass', '--nick', '--bitcoin-conf', '--wait']);
function opt(args, name) { const i = args.indexOf('--' + name); return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : null; }
function positional(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (VALUE_OPTS.has(args[i])) { i++; continue; }
    if (args[i].startsWith('--')) continue;
    out.push(args[i]);
  }
  return out;
}
const runArgs = (L) => ['run', ...(L.custom ? ['--root', L.root] : [])];

/* ------------------------------------------------------------ Windows helpers
   Each one does a single thing, never builds a shell command line from user
   data, and fails soft (returns false) so the installer can explain. */
function winFolders() {
  const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  const out = {
    startup: path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    desktop: path.join(os.homedir(), 'Desktop'),
  };
  try {
    // The real folders, which may be redirected (OneDrive, roaming profiles).
    const ps = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
      + "[Environment]::GetFolderPath('Startup');[Environment]::GetFolderPath('Desktop')";
    const text = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps],
      { encoding: 'utf8', timeout: 20000, windowsHide: true });
    const [s, d] = text.split(/\r?\n/).map((x) => x.trim());
    if (s) out.startup = s;
    if (d) out.desktop = d;
  } catch { }
  return out;
}
const vbsString = (s) => '"' + String(s).replace(/"/g, '""') + '"';
// The hidden launcher: runs "nodesignal.exe run" with window style 0.
// Written as UTF-16LE with a BOM so any path (any user name) survives.
function launcherVbs(L) {
  const local = process.env.LOCALAPPDATA || '';
  let exeExpr;
  if (local && L.exe.toLowerCase().startsWith(local.toLowerCase() + '\\')) {
    exeExpr = 'sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & ' + vbsString(L.exe.slice(local.length));
  } else exeExpr = vbsString(L.exe);
  const extra = L.custom ? ' & " --root " & Chr(34) & ' + vbsString(L.root) + ' & Chr(34)' : '';
  return [
    "' NodeSignal: starts the daemon hidden when you sign in. Written by the installer.",
    "' Remove it with: nodesignal.exe uninstall",
    'Set sh = CreateObject("WScript.Shell")',
    'exe = ' + exeExpr,
    'sh.Run Chr(34) & exe & Chr(34) & " run"' + extra + ', 0, False',
    '',
  ].join('\r\n');
}
function writeLauncher(dir, L) {
  const file = path.join(dir, 'NodeSignal.vbs');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(launcherVbs(L), 'utf16le')]));
  return file;
}
function runLauncher(file) {
  const child = spawn('wscript.exe', ['//B', '//Nologo', file], { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', () => { });
  child.unref();
}
function writeUrlShortcut(dir, url) {
  const file = path.join(dir, 'NodeSignal.url');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, ['[InternetShortcut]', 'URL=' + url, ''].join('\r\n'), 'ascii');
  return file;
}
const UNINSTALL_KEY = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NodeSignal';
// Apps & features entry, per user (no admin). Values go in through
// environment variables so no quoting is involved.
function registerUninstallEntry(L) {
  const ps = [
    `$k='${UNINSTALL_KEY}'`,
    'New-Item -Path $k -Force | Out-Null',
    "Set-ItemProperty -Path $k -Name DisplayName -Value 'NodeSignal'",
    'Set-ItemProperty -Path $k -Name DisplayVersion -Value $env:NS_VERSION',
    "Set-ItemProperty -Path $k -Name Publisher -Value 'NodeSignal'",
    'Set-ItemProperty -Path $k -Name InstallLocation -Value $env:NS_ROOT',
    'Set-ItemProperty -Path $k -Name DisplayIcon -Value $env:NS_EXE',
    "Set-ItemProperty -Path $k -Name UninstallString -Value ([char]34 + $env:NS_EXE + [char]34 + ' uninstall')",
    'Set-ItemProperty -Path $k -Name NoModify -Value 1 -Type DWord',
    'Set-ItemProperty -Path $k -Name NoRepair -Value 1 -Type DWord',
  ].join(';');
  return runPowerShell(ps, { NS_VERSION: VERSION, NS_ROOT: L.root, NS_EXE: L.exe });
}
function removeUninstallEntry() {
  return runPowerShell(`Remove-Item -Path '${UNINSTALL_KEY}' -Recurse -Force -ErrorAction SilentlyContinue`);
}
function runPowerShell(script, env = {}) {
  try {
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script],
      { stdio: 'ignore', timeout: 30000, windowsHide: true, env: Object.assign({}, process.env, env) });
    return true;
  } catch { return false; }
}
const firewallRuleName = (port) => `NodeSignal ${port}`;
const firewallCommand = (port) => `netsh advfirewall firewall add rule name="${firewallRuleName(port)}" dir=in action=allow protocol=TCP localport=${port}`;
function addFirewallRule(port) {
  try {
    const show = spawnSync('netsh', ['advfirewall', 'firewall', 'show', 'rule', `name=${firewallRuleName(port)}`], { stdio: 'ignore', timeout: 20000, windowsHide: true });
    if (show.status === 0) return true;
    execFileSync('netsh', ['advfirewall', 'firewall', 'add', 'rule', `name=${firewallRuleName(port)}`,
      'dir=in', 'action=allow', 'protocol=TCP', `localport=${port}`], { stdio: 'ignore', timeout: 20000, windowsHide: true });
    return true;
  } catch { return false; }
}
function deleteFirewallRule(port) {
  try {
    execFileSync('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${firewallRuleName(port)}`], { stdio: 'ignore', timeout: 20000, windowsHide: true });
    return true;
  } catch { return false; }
}
function openBrowser(url) {
  try {
    if (IS_WIN) spawn('explorer.exe', [url], { detached: true, stdio: 'ignore' }).on('error', () => { }).unref();
  } catch { }
}
// The image name of a running PID, or null. Used so a stale PID file can
// never make us kill an unrelated program that reused the number.
function processImage(pid) {
  if (!pid) return null;
  if (IS_WIN) {
    const r = spawnSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { encoding: 'utf8', timeout: 15000, windowsHide: true });
    const m = String(r.stdout || '').match(/^"([^"]+)","(\d+)"/m);
    return m && Number(m[2]) === pid ? m[1] : null;
  }
  try { return path.basename(fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0')[0]); } catch { return null; }
}
function killPid(pid) {
  if (IS_WIN) {
    try { execFileSync('taskkill', ['/PID', String(pid), '/F'], { stdio: 'ignore', timeout: 15000, windowsHide: true }); return true; } catch { return false; }
  }
  try { process.kill(pid, 'SIGTERM'); return true; } catch { return false; }
}
// Remove our own exe after we exit: a running .exe cannot delete itself.
function scheduleSelfDelete(exe, dir) {
  if (!IS_WIN) { try { fs.unlinkSync(exe); fs.rmdirSync(dir); } catch { } return; }
  const cmdline = `"ping -n 3 127.0.0.1 >nul & del /f /q "${exe}" & rmdir "${dir}" 2>nul"`;
  const child = spawn('cmd.exe', ['/d', '/s', '/c', cmdline], { detached: true, stdio: 'ignore', windowsHide: true, windowsVerbatimArguments: true });
  child.on('error', () => { });
  child.unref();
}

/* ------------------------------------------------------------ process control */
function readPid(L) { try { return Number(fs.readFileSync(L.pid, 'utf8').trim()) || 0; } catch { return 0; } }
function ourImages(L) { return new Set([path.basename(L.exe).toLowerCase(), path.basename(process.execPath).toLowerCase()]); }
async function stopRunning(L, quiet = false) {
  const pid = readPid(L);
  if (!pid || pid === process.pid) return false;
  const img = processImage(pid);
  if (!img || !ourImages(L).has(img.toLowerCase())) { try { fs.unlinkSync(L.pid); } catch { } return false; }
  if (!quiet) say(`  Stopping the running NodeSignal (pid ${pid})...`);
  killPid(pid);
  for (let i = 0; i < 40 && processImage(pid); i++) await sleep(250);
  try { fs.unlinkSync(L.pid); } catch { }
  return true;
}
function startDetached(L, startupFile) {
  if (IN_SEA && IS_WIN && startupFile && fs.existsSync(startupFile)) { runLauncher(startupFile); return; }
  // outside a SEA (developer testing) run this script with the current node
  const [exe, pre] = !IN_SEA ? [process.execPath, [__filename]] : [fs.existsSync(L.exe) ? L.exe : process.execPath, []];
  const child = spawn(exe, [...pre, ...runArgs(L)], { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', () => { });
  child.unref();
}

/* ------------------------------------------------------------ run */
const LOG_MAX = 5 * 1024 * 1024;
function redirectOutput(file) {
  let fd = null, size = 0;
  const open = () => { fd = fs.openSync(file, 'a'); size = fs.fstatSync(fd).size; };
  const rotate = () => {
    try { fs.closeSync(fd); } catch { }
    try { fs.renameSync(file, file + '.1'); open(); }
    catch { fd = fs.openSync(file, 'w'); size = 0; }
  };
  open();
  if (size > LOG_MAX) rotate();
  const tee = !!process.stdout.isTTY;
  const wrap = (orig) => function (chunk, enc, cb) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), typeof enc === 'string' ? enc : 'utf8');
    try { fs.writeSync(fd, buf); size += buf.length; if (size > LOG_MAX) rotate(); } catch { }
    if (tee) return orig(chunk, enc, cb);
    const done = typeof enc === 'function' ? enc : cb;
    if (typeof done === 'function') process.nextTick(done);
    return true;
  };
  process.stdout.write = wrap(process.stdout.write.bind(process.stdout));
  process.stderr.write = wrap(process.stderr.write.bind(process.stderr));
  // A crash is printed by Node straight to the console, not through
  // process.stderr.write, so record it here. The monitor does not change
  // how the process exits.
  process.on('uncaughtExceptionMonitor', (err, origin) => {
    try { fs.writeSync(fd, `${new Date().toISOString()}  fatal (${origin}): ${(err && err.stack) || err}\n`); } catch { }
  });
}
function cmdRun(L) {
  const main = path.join(L.app, 'nodesignald.js');
  if (!fs.existsSync(main)) { say(`NodeSignal is not installed in ${L.root} (missing ${main}). Run the installer.`); return 1; }
  if (!fs.existsSync(L.config)) { say(`Missing ${L.config}. Run the installer again.`); return 1; }
  fs.mkdirSync(L.root, { recursive: true });
  redirectOutput(L.log);
  process.stdout.write(`\n---- NodeSignal ${VERSION} starting, pid ${process.pid}, ${new Date().toISOString()} ----\n`);
  fs.writeFileSync(L.pid, String(process.pid));
  process.on('exit', () => {
    try { if (readPid(L) === process.pid) fs.unlinkSync(L.pid); } catch { }
  });
  process.chdir(L.app);
  process.argv = [process.execPath, main, '--config', L.config, '--web-root', L.app];
  Module.createRequire(main)(main);
  return null; // keep running: the daemon owns the event loop now
}

/* ------------------------------------------------------------ install */
function extractFiles(appDir) {
  const tmp = appDir + '.new';
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  for (const f of MANIFEST.files) fs.writeFileSync(path.join(tmp, f), assetBuffer(f));
  fs.writeFileSync(path.join(tmp, 'VERSION'), VERSION + '\n');
  if (MANIFEST.extra) for (const f of MANIFEST.extra) fs.writeFileSync(path.join(tmp, f), assetBuffer(f));
  const old = appDir + '.old';
  fs.rmSync(old, { recursive: true, force: true });
  try {
    if (fs.existsSync(appDir)) fs.renameSync(appDir, old);
    fs.renameSync(tmp, appDir);
    fs.rmSync(old, { recursive: true, force: true });
  } catch {
    // a folder held open (an Explorer window, an editor): replace file by file
    fs.mkdirSync(appDir, { recursive: true });
    for (const f of fs.readdirSync(tmp)) fs.copyFileSync(path.join(tmp, f), path.join(appDir, f));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  const missing = core.missingFiles(appDir, MANIFEST.files);
  if (missing.length) throw new Error('files missing after extraction: ' + missing.join(', '));
}
async function copySelf(L) {
  if (!IN_SEA || core.samePath(process.execPath, L.exe)) return;
  for (const f of fs.readdirSync(L.root)) if (/^nodesignal\.exe\.old-/.test(f)) { try { fs.unlinkSync(path.join(L.root, f)); } catch { } }
  for (let i = 0; i < 20; i++) {
    try { fs.copyFileSync(process.execPath, L.exe); if (!IS_WIN) fs.chmodSync(L.exe, 0o755); return; }
    catch (e) {
      if (i === 19) {
        // still locked: move it aside (allowed for a running exe) and copy
        const aside = `${L.exe}.old-${Date.now()}`;
        fs.renameSync(L.exe, aside);
        fs.copyFileSync(process.execPath, L.exe);
        return;
      }
      await sleep(250);
    }
  }
}
async function choosePorts(cfg, P, interactive) {
  let web = Number(cfg['web-port']) || 8789;
  const peer = Number(cfg['peer-port']) || 8788;
  const free = async (p) => (await core.portFree(p, '127.0.0.1')) && (await core.portFree(p, '0.0.0.0'));
  if (!(await free(web))) {
    let alt = 0;
    for (let p = web + 1; p < web + 20; p++) if (p !== peer && await free(p)) { alt = p; break; }
    if (alt) { say(`  Port ${web} is in use by another program, so the web interface will use ${alt}.`); web = alt; }
  }
  while (!(await free(peer))) {
    say(`  The peer port ${peer} is in use by another program (an older NodeSignal window?).`);
    say('  NodeSignal cannot start until it is free.');
    if (!interactive || !(await P.askYesNo('Close that program, then check again?', true))) break;
  }
  return { web, peer };
}
/* performInstall: the steps shared by the interactive installer and selftest.
   answers = { nick, portMapping, rpc: {...optional config keys} }
   opts = { userLevel: register Startup/Desktop/Apps entry/firewall,
            startupDir: where the launcher goes, P: prompter, interactive } */
async function performInstall(L, answers, opts) {
  const step = (s) => say(`  - ${s}`);
  fs.mkdirSync(L.root, { recursive: true });
  let existing = {};
  try { existing = core.readConfig(L.config); } catch { }

  await stopRunning(L);
  const ports = await choosePorts(Object.assign({}, existing, answers.config || {}), opts.P, opts.interactive);

  extractFiles(L.app);
  step(`Program files: ${L.app}`);
  await copySelf(L);
  step(`Program: ${L.exe}`);

  const cfg = Object.assign({}, existing);
  cfg.nick = answers.nick;
  cfg['web-port'] = ports.web;
  cfg['peer-port'] = ports.peer;
  if (!cfg.data) cfg.data = path.join(os.homedir(), '.nodesignal');
  if (answers.portMapping) cfg['port-mapping'] = true; else delete cfg['port-mapping'];
  for (const [k, v] of Object.entries(answers.config || {})) if (!(k in existing)) cfg[k] = v;
  if (!core.writeConfig(L.config, cfg)) step('Warning: could not restrict the config file to your account; check its permissions.');
  step(`Settings: ${L.config}`);

  const url = `http://localhost:${ports.web}/`;
  let launcher = null;
  if (IS_WIN) {
    const folders = opts.userLevel ? winFolders() : null;
    const startupDir = opts.startupDir || (folders && folders.startup);
    if (startupDir) {
      try { launcher = writeLauncher(startupDir, L); step('Starts automatically when you sign in (hidden, no admin needed)'); }
      catch (e) { step(`Warning: could not add the sign-in launcher (${e.code || e.message})`); }
    }
    if (opts.userLevel) {
      try { writeUrlShortcut(folders.desktop, url); step('Desktop shortcut: NodeSignal'); }
      catch (e) { step(`Warning: no Desktop shortcut (${e.code || e.message})`); }
      if (registerUninstallEntry(L)) step('Listed in Settings > Apps, for uninstalling');
      if (answers.portMapping) {
        if (addFirewallRule(ports.peer)) step(`Windows Firewall allows inbound TCP ${ports.peer}`);
        else {
          step(`Windows Firewall rule not added (needs admin). Run once in an admin PowerShell:`);
          say(`      ${firewallCommand(ports.peer)}`);
        }
      }
    }
  }

  startDetached(L, launcher);
  step('Starting NodeSignal...');
  let health = await core.waitForHealth(ports.web, { timeoutMs: launcher ? 15000 : 25000, wantRpc: true, rpcGraceMs: 10000 });
  const launcherWorked = !!(launcher && health);
  if (!health && launcher) {
    // wscript.exe can be disabled by policy; then sign-in start will not work either
    step('The hidden launcher did not start NodeSignal (is Windows Script Host disabled?).');
    step('Starting it directly now; it will NOT start by itself at sign-in until that is fixed.');
    startDetached(L, null);
    health = await core.waitForHealth(ports.web, { timeoutMs: 25000, wantRpc: true, rpcGraceMs: 10000 });
  }
  return { cfg, ports, url, health, launcher, launcherWorked };
}

function refuseNoNode() {
  say('');
  say('  NodeSignal needs a Bitcoin node on this computer, and none was found.');
  say('');
  say('  It looked for a running bitcoind or bitcoin-qt, the Bitcoin data folder');
  say('  (%APPDATA%\\Bitcoin, or the custom folder Bitcoin Core remembers), and');
  say('  Bitcoin Core in Program Files.');
  say('');
  say('  Install Bitcoin Core (https://bitcoincore.org/en/download/) or');
  say('  Bitcoin Knots (https://bitcoinknots.org/), let it start once, then run');
  say('  this installer again. Pruned nodes are fine.');
  say('');
  say('  Nothing was installed.');
}
async function cmdInstall(L) {
  const P = core.createPrompter();
  say('');
  say(`  NodeSignal ${VERSION} setup`);
  say('  Encrypted chat between Bitcoin node operators, running beside your node.');
  say('  ------------------------------------------------------------------------');
  say('');
  say('  Looking for your Bitcoin node...');
  let det = await core.detectBitcoinNode();
  if (!det.installed) { refuseNoNode(); await P.pause(); P.close(); return 1; }
  for (const h of det.how.slice(0, 4)) say(`    found: ${h}`);

  let existing = {};
  try { existing = core.readConfig(L.config); say(`    upgrading the existing install in ${L.root}`); } catch { }

  for (;;) {
    const r = await core.checkNode(det, existing);
    if (r.ok) {
      say(`  Connected: ${r.subversion || 'Bitcoin node'}, ${r.chain} chain, height ${r.blocks}${r.pruned ? ', pruned' : ''}`);
      break;
    }
    say('');
    say(`  Your node is installed but is not answering RPC right now: ${r.error}.`);
    if (r.hint) say(`  ${r.hint}`);
    say('  You can fix that now and check again, or carry on: NodeSignal installs');
    say('  anyway and connects by itself (it retries every 30 seconds).');
    if (!(await P.askYesNo('Check again?', true))) break;
    det = await core.detectBitcoinNode();
  }

  say('');
  const nick = (await P.askDefault('Display name other operators will see', existing.nick || os.hostname())).slice(0, 60);

  const confPath = det.confPath || (det.datadir ? path.join(det.datadir, 'bitcoin.conf') : null);
  let advertise = false;
  const ua = confPath ? core.uaCommentState(confPath) : { on: false };
  say('');
  if (ua.on) say('  Your node already advertises NodeSignal (uacomment=nodesignal). Undo: nodesignal.exe advertise off');
  else if (confPath && !ua.unreadable) {
    for (const l of core.OPT_IN_TEXT.advertise.slice(1)) say('  ' + l);
    advertise = await P.askYesNo(core.OPT_IN_TEXT.advertise[0], false);
  }

  say('');
  let portMapping = !!existing['port-mapping'];
  if (portMapping) say('  Router port mapping is on. Undo: nodesignal.exe port-mapping off');
  else {
    for (const l of core.OPT_IN_TEXT.portMapping.slice(1)) say('  ' + l);
    portMapping = await P.askYesNo(core.OPT_IN_TEXT.portMapping[0], false);
  }

  // Only point the daemon at the node when it lives where it would not look.
  const rpcCfg = {};
  if (det.cookiePath && !core.daemonFindsCookie(det.cookiePath, os.homedir())) rpcCfg['rpc-cookie'] = det.cookiePath;
  if (det.confPath && !core.daemonFindsConf(det.confPath, os.homedir())) rpcCfg['rpc-conf'] = det.confPath;
  if (det.rpcUrlNeeded) rpcCfg['rpc-url'] = det.rpcUrl;

  say('');
  say('  Installing...');
  const res = await performInstall(L, { nick, portMapping, config: rpcCfg }, { userLevel: true, P, interactive: true });

  if (advertise) {
    try {
      const r = core.setUaComment(confPath, true);
      say(`  - Added uacomment=nodesignal to ${confPath}${r.backup ? ` (original saved as ${path.basename(r.backup)})` : ''}`);
      say('    Restart Bitcoin Core or Knots yourself for peers to see it.');
    } catch (e) { say(`  - Could not edit bitcoin.conf: ${e.message}`); }
  }

  say('');
  const h = res.health;
  if (h) {
    say(`  NodeSignal is running as "${h.nick}".`);
    say(h.rpcConnected ? `  Bitcoin node connected: ${h.peerCount} peers on the map.`
      : '  Bitcoin node not connected yet. NodeSignal keeps trying every 30 seconds.');
    openBrowser(res.url);
  } else {
    say('  NodeSignal did not answer its health check. The log says why:');
    say(`    ${L.log}`);
  }
  say('');
  say(`  Open it any time:  ${res.url}   (Desktop shortcut: NodeSignal)`);
  say(`  Command line:      "${L.exe}" status`);
  say('  It starts by itself when you sign in. Uninstall from Settings > Apps.');
  say('  If Windows Firewall asks about NodeSignal, allowing private networks is enough');
  say('  unless you turned on port mapping.');
  say('');
  await P.pause();
  P.close();
  return h ? 0 : 1;
}

/* ------------------------------------------------------------ uninstall */
async function cmdUninstall(L, args) {
  const P = core.createPrompter();
  const purge = args.includes('--purge');
  say('');
  say('  Uninstalling NodeSignal');
  let cfg = {};
  try { cfg = core.readConfig(L.config); } catch { }
  await stopRunning(L);

  try {
    const det = await core.detectBitcoinNode();
    const confPath = det.confPath;
    if (confPath && core.uaCommentState(confPath).on) {
      say(`  Your bitcoin.conf still has uacomment=nodesignal (${confPath}).`);
      if (P.tty && await P.askYesNo('Remove it?', true)) {
        core.setUaComment(confPath, false);
        say('  - Removed. Restart your node for peers to stop seeing it.');
      } else say('  - Left in place. Remove the line by hand if you want.');
    }
  } catch (e) { say(`  - Could not check bitcoin.conf: ${e.message}`); }

  if (IS_WIN) {
    const f = winFolders();
    for (const file of [path.join(f.startup, 'NodeSignal.vbs'), path.join(f.desktop, 'NodeSignal.url')]) {
      try { fs.unlinkSync(file); say(`  - Removed ${file}`); } catch { }
    }
    removeUninstallEntry();
    if (cfg['port-mapping']) {
      const port = Number(cfg['peer-port']) || 8788;
      if (!deleteFirewallRule(port)) say(`  - If you added the firewall rule, remove it in an admin PowerShell: netsh advfirewall firewall delete rule name="${firewallRuleName(port)}"`);
    }
  }
  fs.rmSync(L.app, { recursive: true, force: true });
  say(`  - Removed ${L.app}`);

  if (purge) {
    const dataDir = cfg.data || path.join(os.homedir(), '.nodesignal');
    let sure = args.includes('--yes');
    if (!sure && P.tty) {
      say(`  --purge also deletes ${dataDir}: your identity key, contacts and message history.`);
      sure = (await P.ask('  Type DELETE to confirm: ')) === 'DELETE';
    }
    if (sure) {
      for (const f of [L.config, L.log, L.log + '.1', L.pid]) { try { fs.unlinkSync(f); } catch { } }
      fs.rmSync(dataDir, { recursive: true, force: true });
      say(`  - Removed settings and ${dataDir}`);
    } else say('  - Kept settings and history (not confirmed).');
  } else {
    say(`  - Kept your settings (${L.config}) and history (${cfg.data || path.join(os.homedir(), '.nodesignal')}).`);
    say('    Reinstalling picks them up again. Delete everything with: uninstall --purge');
  }

  if (core.samePath(process.execPath, L.exe)) scheduleSelfDelete(L.exe, L.root);
  else { try { fs.unlinkSync(L.exe); } catch { } try { fs.rmdirSync(L.root); } catch { } }
  say('  NodeSignal is uninstalled.');
  say('');
  await P.pause();
  P.close();
  return 0;
}

/* ------------------------------------------------------------ selftest */
async function cmdSelftest(args) {
  const results = [];
  const check = (name, ok, detail = '') => { results.push(ok); say(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  (' + detail + ')' : ''}`); return ok; };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nodesignal-selftest-'));
  const L = layout(tmp);
  say(`NodeSignal ${VERSION} selftest in ${tmp} (${IN_SEA ? 'single executable' : 'source'}, ${process.platform})`);
  const freePort = () => new Promise((r) => { const s = require('net').createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
  let res = null;
  try {
    // bitcoin.conf editing round trip
    const conf = path.join(tmp, 'bitcoin.conf');
    const original = 'server=1\r\n# keep me\r\n[main]\r\nrpcport=8332\r\n';
    fs.writeFileSync(conf, original);
    core.setUaComment(conf, true);
    const second = core.setUaComment(conf, true);
    check('advertise on is idempotent', !second.changed && core.uaCommentState(conf).on);
    core.setUaComment(conf, false);
    check('advertise off restores bitcoin.conf byte for byte', fs.readFileSync(conf, 'utf8') === original);
    check('one-time backup kept', fs.readFileSync(conf + core.BACKUP_SUFFIX, 'utf8') === original);

    const webPort = await freePort();
    let peerPort = await freePort();
    while (peerPort === webPort) peerPort = await freePort();
    const rpc = {};
    for (const k of ['rpc-url', 'rpc-user', 'rpc-pass']) if (opt(args, k)) rpc[k] = opt(args, k);
    const config = Object.assign({ 'web-port': webPort, 'peer-port': peerPort, bind: '127.0.0.1', data: path.join(tmp, 'state') }, rpc);
    fs.writeFileSync(L.config, '{}');
    res = await performInstall(L, { nick: 'selftest', portMapping: false, config },
      { userLevel: false, startupDir: IS_WIN ? path.join(tmp, 'Startup') : null, interactive: false, P: null });
    check('program files extracted', core.missingFiles(L.app, MANIFEST.files).length === 0);
    check('program copied', fs.existsSync(L.exe));
    if (IS_WIN) {
      const vbs = fs.readFileSync(path.join(tmp, 'Startup', 'NodeSignal.vbs'));
      check('hidden launcher written as UTF-16 with BOM', vbs[0] === 0xff && vbs[1] === 0xfe);
      check('hidden launcher (wscript, window style 0) started the daemon', res.launcherWorked);
    }
    check('daemon answers /health', !!res.health, res.health ? `nick ${res.health.nick}` : 'no answer');
    check('daemon connected to the Bitcoin RPC', !!(res.health && res.health.rpcConnected), res.health ? `${res.health.peerCount} peers` : '');
    check('pid file written', readPid(L) > 0 && !!processImage(readPid(L)));
    let logText = '';
    try { logText = fs.readFileSync(L.log, 'utf8'); } catch { }
    check('log file written', /NodeSignal/.test(logText));
    const st = spawnSync(L.exe, ['status', '--root', L.root], { encoding: 'utf8', timeout: 60000, windowsHide: true });
    check('"status" command works', st.status === 0 && /selftest/.test(st.stdout || ''), st.status === 0 ? '' : String(st.stdout || st.error || '').trim().split('\n').pop());
    const v = spawnSync(L.exe, ['version'], { encoding: 'utf8', timeout: 30000, windowsHide: true });
    check('"version" command works', String(v.stdout || '').trim() === VERSION);
    const stopped = await stopRunning(L, true);
    check('stop ends the daemon', stopped && !(await core.httpGetJson(`http://127.0.0.1:${webPort}/health`, 1500)).ok);
  } catch (e) {
    check('selftest ran to completion', false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
    try { say(fs.readFileSync(L.log, 'utf8').split('\n').slice(-30).join('\n')); } catch { }
  } finally {
    await stopRunning(L, true);
    for (let i = 0; i < 10; i++) {
      try { fs.rmSync(tmp, { recursive: true, force: true }); break; } catch { await sleep(500); }
    }
  }
  const failed = results.filter((x) => !x).length;
  say(failed ? `selftest FAILED (${failed} of ${results.length})` : `selftest passed (${results.length} checks)`);
  return failed ? 1 : 0;
}

/* ------------------------------------------------------------ main */
async function main() {
  const args = process.argv.slice(2);
  const L = layout(opt(args, 'root') || process.env.NODESIGNAL_HOME || '');
  const cmd = positional(args)[0] || '';
  switch (cmd) {
    case '': case 'install': return cmdInstall(L);
    case 'run': return cmdRun(L);
    case 'selftest': return cmdSelftest(args);
    case 'start': startDetached(L); return (await core.waitForHealth(portOf(L), { timeoutMs: 20000 })) ? (say('NodeSignal is running.'), 0) : (say(`No answer yet; see ${L.log}`), 1);
    case 'stop': say((await stopRunning(L, true)) ? 'NodeSignal stopped.' : 'NodeSignal was not running.'); return 0;
    case 'restart': return restart(L);
    case 'uninstall': return cmdUninstall(L, args);
    default: {
      const cli = loadAssetModule('cli.js');
      return cli.main(args, {
        core, version: VERSION, configPath: L.config, logPath: L.log,
        hooks: { restart: () => restart(L), openUrl: openBrowser, uninstall: (a) => cmdUninstall(L, a) },
      });
    }
  }
}
function portOf(L) { try { return Number(core.readConfig(L.config)['web-port']) || 8789; } catch { return 8789; } }
async function restart(L) {
  await stopRunning(L, true);
  startDetached(L);
  const h = await core.waitForHealth(portOf(L), { timeoutMs: 20000 });
  say(h ? 'NodeSignal restarted.' : `NodeSignal did not answer after restarting; see ${L.log}`);
  return h ? 0 : 1;
}

main().then((code) => {
  if (code === null) return;            // `run`: the daemon keeps the process alive
  process.exitCode = code || 0;
  // let pending writes flush, then make sure no stray handle keeps us open
  setTimeout(() => process.exit(code || 0), 100).unref();
}, async (e) => {
  say('');
  say('  Something went wrong: ' + (e && e.message ? e.message : String(e)));
  if (process.stdin.isTTY && positional(process.argv.slice(2)).length === 0) {
    try { await core.createPrompter().pause(); } catch { }
  }
  process.exit(1);
});
