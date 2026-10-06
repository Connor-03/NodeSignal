// sea-main.js: entry point of the Windows single executable (nodesignal.exe).
// ============================================================================
// Built into NodeSignal-Setup-windows-x64.exe by packaging/build-sea.js, with
// the daemon files, setup-core.js and cli.js embedded as SEA assets.
//
//   (no arguments)      interactive installer: double-click it
//   run                 the supervisor (what the hidden Startup launcher calls):
//                       starts the daemon as a child process and restarts it
//                       when it stops (see "process control" below)
//   start | stop | restart
//   selftest --rpc-url U --rpc-user X --rpc-pass Y
//                       non-interactive install into a temp folder, run, check
//                       /health, clean up; exit 0 or 1 (for CI, mock node only)
//   uninstall [--purge] --purge also removes the settings and NodeSignal's
//                       RPC login in bitcoin.conf; never the identity or history
//   anything else       handled by cli.js (status, advertise, port-mapping, ...)
//
// Internal, not for people: __daemon (the daemon itself, started by the
// supervisor), __crash (exits 7) and __supervise-test --scale F (the
// supervisor with __crash as its child and timing multiplied by F); the last
// two exist only for the selftest.
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
// tree: Windows also ends the process's children (taskkill /T), which is how
// the supervisor and its daemon go down together. hard: SIGKILL elsewhere.
// On Windows every kill is forced: a hidden console process has no window to
// receive a polite close. The daemon writes state atomically within 100 ms
// of every change, so little can be lost.
function killPid(pid, { tree = false, hard = false } = {}) {
  if (IS_WIN) {
    const a = ['/PID', String(pid), ...(tree ? ['/T'] : []), '/F'];
    try { execFileSync('taskkill', a, { stdio: 'ignore', timeout: 15000, windowsHide: true }); return true; } catch { return false; }
  }
  try { process.kill(pid, hard ? 'SIGKILL' : 'SIGTERM'); return true; } catch { return false; }
}
// Remove our own exe after we exit: a running .exe cannot delete itself.
function scheduleSelfDelete(exe, dir) {
  if (!IS_WIN) { try { fs.unlinkSync(exe); fs.rmdirSync(dir); } catch { } return; }
  const cmdline = `"ping -n 3 127.0.0.1 >nul & del /f /q "${exe}" & rmdir "${dir}" 2>nul"`;
  const child = spawn('cmd.exe', ['/d', '/s', '/c', cmdline], { detached: true, stdio: 'ignore', windowsHide: true, windowsVerbatimArguments: true });
  child.on('error', () => { });
  child.unref();
}

/* ------------------------------------------------------------ process control
   `run` is a supervisor. It writes its own pid to nodesignal.pid, starts the
   daemon as a child (this same executable with `__daemon`), writes the
   child's pid to nodesignal-daemon.pid, and starts it again when it stops:
   1s, 2s, 4s ... capped at 60s, back to 1s once a daemon has stayed up 10
   minutes, and it gives up (logging why, exit 1) at the 5th crash within 10
   minutes. Every line it writes to nodesignal.log starts "supervisor:".

   Stopping: `stop`, `restart`, the installer and `uninstall` all call
   stopRunning(). On Windows that is `taskkill /PID <supervisor> /T /F`,
   which ends the supervisor and the daemon together. Elsewhere it sends
   SIGTERM to the supervisor, which forwards SIGTERM to the daemon, waits for
   it and exits 0. Either way the daemon pid file is checked afterwards and a
   daemon left behind is ended too. The daemon also guards itself: its stdin
   is a pipe from the supervisor, and when that closes (the supervisor died,
   or was ended without /T) it shuts down cleanly instead of running on
   unsupervised. */
const daemonPidPath = (L) => path.join(L.root, 'nodesignal-daemon.pid');
function readPidFile(file) { try { return Number(fs.readFileSync(file, 'utf8').trim()) || 0; } catch { return 0; } }
function readPid(L) { return readPidFile(L.pid); }
function ourImages(L) { return new Set([path.basename(L.exe).toLowerCase(), path.basename(process.execPath).toLowerCase()]); }
// A live process running our executable (never ourselves): a stale pid file
// must not make us kill an unrelated program that reused the number.
function isOurs(L, pid) {
  if (!pid || pid === process.pid) return false;
  const img = processImage(pid);
  return !!img && ourImages(L).has(img.toLowerCase());
}
async function waitGone(pid, ms) {
  for (let t = 0; t < ms && processImage(pid); t += 250) await sleep(250);
  return !processImage(pid);
}
async function stopRunning(L, quiet = false) {
  const sup = readPid(L);
  const kid = readPidFile(daemonPidPath(L));
  let stopped = false;
  // nodesignal.pid holds the supervisor (or, from a version before the
  // supervisor, the daemon itself; ending it works the same way)
  if (isOurs(L, sup)) {
    if (!quiet) say(`  Stopping the running NodeSignal (pid ${sup})...`);
    killPid(sup, { tree: true });
    if (!(await waitGone(sup, 15000)) && !IS_WIN) { killPid(sup, { hard: true }); await waitGone(sup, 3000); }
    stopped = true;
  }
  // The daemon normally goes with its supervisor; this catches one left behind.
  if (isOurs(L, kid)) {
    killPid(kid);
    if (!(await waitGone(kid, 5000))) { killPid(kid, { hard: true }); await waitGone(kid, 5000); }
    stopped = true;
  }
  for (const f of [L.pid, daemonPidPath(L)]) { try { fs.unlinkSync(f); } catch { } }
  return stopped;
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
function redirectOutput(file, { fatalMonitor = true } = {}) {
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
  // how the process exits. Under the supervisor, which already copies the
  // daemon's raw stderr into the log, it is off so a crash is not logged twice.
  if (fatalMonitor) process.on('uncaughtExceptionMonitor', (err, origin) => {
    try { fs.writeSync(fd, `${new Date().toISOString()}  fatal (${origin}): ${(err && err.stack) || err}\n`); } catch { }
  });
}
function installedOk(L) {
  const main = path.join(L.app, 'nodesignald.js');
  if (!fs.existsSync(main)) { say(`NodeSignal is not installed in ${L.root} (missing ${main}). Run the installer.`); return false; }
  if (!fs.existsSync(L.config)) { say(`Missing ${L.config}. Run the installer again.`); return false; }
  return true;
}
// `run`: the supervisor.
function cmdRun(L) {
  if (!installedOk(L)) return 1;
  return supervise(L, { childArgs: ['__daemon'] });
}
// `__daemon`: the daemon itself, in this process. Started by the supervisor.
function cmdDaemon(L) {
  if (!installedOk(L)) return 1;
  const main = path.join(L.app, 'nodesignald.js');
  fs.mkdirSync(L.root, { recursive: true });
  redirectOutput(L.log, { fatalMonitor: !process.env.NODESIGNAL_STDERR_CAPTURED });
  process.stdout.write(`\n---- NodeSignal ${VERSION} daemon starting, pid ${process.pid}, ${new Date().toISOString()} ----\n`);
  if (process.env.NODESIGNAL_SUPERVISOR_PID) {
    // Orphan guard: stdin is a pipe from the supervisor. It closes when the
    // supervisor is gone (or, on Windows, asks us to stop), and then we shut
    // down cleanly through the daemon's own SIGTERM handler.
    let leaving = false;
    const leave = () => {
      if (leaving) return; leaving = true;
      setTimeout(() => process.exit(0), 5000);
      if (process.listenerCount('SIGTERM')) process.emit('SIGTERM', 'SIGTERM'); else process.exit(0);
    };
    for (const ev of ['end', 'close', 'error']) process.stdin.on(ev, leave);
    process.stdin.resume();
  }
  process.chdir(L.app);
  process.argv = [process.execPath, main, '--config', L.config, '--web-root', L.app];
  Module.createRequire(main)(main);
  return null; // keep running: the daemon owns the event loop now
}

/* supervise: run `childArgs` (a subcommand of this executable) as a child and
   restart it on exit. Timing is exactly as documented above unless `scale`
   is given; only the selftest (__supervise-test) passes one, to fit the same
   policy into a few seconds. Never resolves for `run`: it exits the process. */
const SUPERVISOR = { backoffMs: 1000, maxBackoffMs: 60000, crashLimit: 5, windowMs: 10 * 60000, stableMs: 10 * 60000, stopGraceMs: 10000 };
function supervise(L, { childArgs, scale = 1 }) {
  fs.mkdirSync(L.root, { recursive: true });
  const tty = !!process.stdout.isTTY;
  const write = (line) => {
    try { fs.appendFileSync(L.log, line); } catch { }
    if (tty) process.stdout.write(line);
  };
  const log = (s) => write(`${new Date().toISOString()}  supervisor: ${s}\n`);

  const other = readPid(L);
  if (isOurs(L, other)) {
    say(`NodeSignal is already running (pid ${other}).`);
    log(`not starting a second copy: NodeSignal is already running (pid ${other})`);
    return 0;
  }
  fs.writeFileSync(L.pid, String(process.pid));
  const kidFile = daemonPidPath(L);
  const scaled = scale === 1 ? '' : ` (test scale ${scale})`;
  write(`\n---- NodeSignal ${VERSION} starting, ${new Date().toISOString()} ----\n`);
  log(`started, pid ${process.pid}; it restarts the daemon if it stops${scaled}`);

  const C = SUPERVISOR;
  const pre = IN_SEA ? [] : [__filename];
  const rootArgs = L.custom ? ['--root', L.root] : [];
  const crashes = [];       // times of recent crashes, for the give-up rule
  let child = null, startedAt = 0, streak = 0, timer = null, stopping = false;

  const cleanup = () => {
    if (child) { try { child.kill('SIGKILL'); } catch { } }
    try { if (readPid(L) === process.pid) fs.unlinkSync(L.pid); } catch { }
    try { fs.unlinkSync(kidFile); } catch { }
  };
  process.on('exit', cleanup);
  const finishStop = () => { log('stopped'); cleanup(); process.exit(0); };

  function start() {
    timer = null;
    startedAt = Date.now();
    // stdin: the daemon's orphan guard. stderr: captured into the log, so
    // a crash Node prints straight to the console is kept.
    const c = spawn(process.execPath, [...pre, ...childArgs, ...rootArgs], {
      stdio: ['pipe', tty ? 'inherit' : 'ignore', tty ? 'inherit' : 'pipe'],
      windowsHide: true,
      env: Object.assign({}, process.env, { NODESIGNAL_SUPERVISOR_PID: String(process.pid) }, tty ? {} : { NODESIGNAL_STDERR_CAPTURED: '1' }),
    });
    child = c;
    let done = false, rest = '';
    const flush = () => { if (rest) { write(`${new Date().toISOString()}  daemon stderr: ${rest}\n`); rest = ''; } };
    const finish = (code, signal, err) => {
      if (done) return; done = true;
      flush();
      exited(c, code, signal, err);
    };
    c.stdin.on('error', () => { });
    if (c.stderr) {
      c.stderr.setEncoding('utf8');
      c.stderr.on('data', (d) => {
        rest += d;
        let i;
        while ((i = rest.indexOf('\n')) >= 0) { write(`${new Date().toISOString()}  daemon stderr: ${rest.slice(0, i).replace(/\r$/, '')}\n`); rest = rest.slice(i + 1); }
        if (rest.length > 65536) flush();
      });
    }
    // 'close' comes after stderr is drained, so a crash's stack lands above
    // the exit line; 'exit' plus a second covers a stream that never closes.
    c.on('close', (code, signal) => finish(code, signal, null));
    c.on('exit', (code, signal) => setTimeout(() => finish(code, signal, null), 1000));
    c.on('error', (e) => {
      if (c.pid === undefined) finish(null, null, e);   // could not be started at all
      else log(`daemon pid ${c.pid}: ${e.message}`);
    });
    if (c.pid !== undefined) {
      try { fs.writeFileSync(kidFile, String(c.pid)); } catch { }
      log(`started the daemon, pid ${c.pid}`);
    }
  }

  function exited(c, code, signal, err) {
    if (child === c) child = null;
    if (readPidFile(kidFile) === c.pid) { try { fs.unlinkSync(kidFile); } catch { } }
    const up = Date.now() - startedAt;
    const who = c.pid !== undefined ? `the daemon (pid ${c.pid})` : 'the daemon';
    const how = err ? `could not be started (${err.code || err.message})`
      : signal ? `was ended by signal ${signal}` : `exited with code ${code}`;
    log(`${who} ${how} after ${(up / 1000).toFixed(1)}s`);
    if (stopping) return finishStop();
    // Any exit we did not ask for is a crash, exit code 0 included. The daemon
    // is a server that only exits 0 from its own signal handler, so an
    // unrequested 0 means something else stopped it (a stray signal, a
    // console Ctrl+C that reached the daemon first); the operator still
    // expects it to be running, and counting it keeps a loop of clean exits
    // under the same give-up rule instead of spinning forever.
    const now = Date.now();
    if (up >= C.stableMs * scale) streak = 0;      // it ran long enough: back to 1s
    streak++;
    crashes.push(now);
    while (crashes.length && now - crashes[0] >= C.windowMs * scale) crashes.shift();
    const last = err ? `last error ${err.code || err.message}` : signal ? `last exit signal ${signal}` : `last exit code ${code}`;
    if (crashes.length >= C.crashLimit) {
      log(`gave up: ${C.crashLimit} crashes within 10 minutes; ${last}; see the lines above${scaled}`);
      cleanup();
      process.exit(1);
    }
    const delay = Math.min(C.backoffMs * 2 ** (streak - 1), C.maxBackoffMs);
    log(`restarting in ${delay / 1000}s (crash ${crashes.length} within 10 minutes; gives up at ${C.crashLimit})${scaled}`);
    timer = setTimeout(start, delay * scale);
  }

  function requestStop(why) {
    if (stopping) return;
    stopping = true;
    clearTimeout(timer); timer = null;
    if (!child) return finishStop();
    const c = child;
    log(`${why}: stopping the daemon (pid ${c.pid})`);
    // Linux/macOS: forward SIGTERM. Windows has no SIGTERM to send, so close
    // the daemon's stdin, which its orphan guard turns into a clean shutdown.
    if (IS_WIN) { try { c.stdin.end(); } catch { } } else { try { c.kill('SIGTERM'); } catch { } }
    setTimeout(() => {
      if (child !== c) return;
      log(`the daemon did not stop within ${C.stopGraceMs / 1000}s; ending it`);
      try { c.kill('SIGKILL'); } catch { }
    }, C.stopGraceMs).unref();
  }
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP', ...(IS_WIN ? ['SIGBREAK'] : [])]) process.on(sig, () => requestStop(sig));

  start();
  return null; // keep running: the child and the timers own the event loop
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
   answers = { nick, portMapping, config: {...keys for a new install},
               rpc: {...RPC keys that always win} }
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
  // NodeSignal's own RPC login replaces whatever an older install used
  Object.assign(cfg, answers.rpc || {});
  delete cfg['rpc-cookie'];
  delete cfg['rpc-conf'];
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
// An elevated (administrator) process: "net session" only succeeds then.
// Root counts too, for the Linux build of this file.
function runsElevated() {
  if (!IS_WIN) return typeof process.getuid === 'function' && process.getuid() === 0;
  try { execFileSync('net', ['session'], { stdio: 'ignore', timeout: 10000, windowsHide: true }); return true; } catch { return false; }
}
async function cmdInstall(L) {
  const P = core.createPrompter();
  say('');
  say(`  NodeSignal ${VERSION} setup`);
  say('  Encrypted chat between Bitcoin node operators, running beside your node.');
  say('  ------------------------------------------------------------------------');
  say('');
  if (runsElevated()) {
    say('  This installer was started as administrator. NodeSignal never runs with');
    say('  admin rights and does not need them: it installs for your account only.');
    say('  Start it again with a normal double-click (not "Run as administrator").');
    say('');
    say('  Nothing was installed.');
    await P.pause(); P.close();
    return 1;
  }
  say('  Looking for your Bitcoin node...');
  let det = await core.detectBitcoinNode();
  if (!det.installed) { refuseNoNode(); await P.pause(); P.close(); return 1; }
  for (const h of det.how.slice(0, 4)) say(`    found: ${h}`);

  let existing = {};
  try { existing = core.readConfig(L.config); say(`    upgrading the existing install in ${L.root}`); } catch { }

  const confPath = core.nodeConfPath(det);
  // An upgrade whose RPC login already works needs no bitcoin.conf change.
  const loginReady = existing['rpc-user'] === core.RPC_USER && existing['rpc-pass'] && confPath
    && core.rpcAuthMatches(core.rpcAccessState(confPath).rpcauth, core.RPC_USER, existing['rpc-pass']);
  if (loginReady) {
    const r = await core.checkNode(det, existing);
    if (r.ok) say(`  Connected: ${r.subversion || 'Bitcoin node'}, ${r.chain} chain, height ${r.blocks}${r.pruned ? ', pruned' : ''}`);
    else say(`  Your node is not answering RPC right now (${r.error}). NodeSignal connects by itself once it does.`);
  } else {
    say('');
    say('  NodeSignal logs in to your node as its own RPC user, "nodesignal", limited to');
    say('  three read-only methods (getblockchaininfo, getnetworkinfo, getpeerinfo).');
    say(`  Setup adds two or three lines for it to ${confPath || 'bitcoin.conf'}; the password stays`);
    say('  in NodeSignal\'s settings, locked to your account. The cookie file is never used.');
  }

  say('');
  const nick = (await P.askDefault('Display name other operators will see', existing.nick || os.hostname())).slice(0, 60);

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

  // NodeSignal's own RPC login: the password for its config, the hash for bitcoin.conf
  const rpcCfg = { 'rpc-user': existing['rpc-user'], 'rpc-pass': existing['rpc-pass'] };
  let access = null;
  say('');
  say('  Installing...');
  if (confPath) {
    try { access = core.installRpcAccess({ cfg: rpcCfg, cfgPath: L.config, confPath }); }
    catch (e) { say(`  - Could not add NodeSignal's RPC login to bitcoin.conf: ${e.message}`); }
  }
  core.ensureRpcLogin(rpcCfg);
  rpcCfg['rpc-url'] = det.rpcUrl;                    // the daemon does not read bitcoin.conf
  if (access && access.result.changed) {
    say(`  - Added NodeSignal's RPC login to ${confPath}${access.result.backup ? ` (original saved as ${path.basename(access.result.backup)})` : ''}`);
  } else if (!access) {
    say('    Add these lines to bitcoin.conf by hand, then restart your node:');
    say('      ' + core.makeRpcAuth(core.RPC_USER, rpcCfg['rpc-pass']));
    say(`      rpcwhitelist=${core.RPC_USER}:${core.RPC_METHODS.join(',')}`);
    say('      rpcwhitelistdefault=0   (only if bitcoin.conf has no rpcwhitelist lines of its own)');
  }
  const res = await performInstall(L, { nick, portMapping, rpc: rpcCfg }, { userLevel: true, P, interactive: true });

  if (advertise) {
    try {
      const r = core.setUaComment(confPath, true);
      say(`  - Added uacomment=nodesignal to ${confPath}${r.backup ? ` (original saved as ${path.basename(r.backup)})` : ''}`);
      say('    Restart Bitcoin Core or Knots yourself for peers to see it.');
    } catch (e) { say(`  - Could not edit bitcoin.conf: ${e.message}`); }
  }

  say('');
  const h = res.health;
  const needsRestart = !!(access && access.result.changed);
  if (h) {
    say(`  NodeSignal is running as "${h.nick}".`);
    if (h.rpcConnected) say(`  Bitcoin node connected: ${h.peerCount} peers on the map.`);
    else if (needsRestart) for (const l of core.RPC_RESTART_TEXT.win32) say('  ' + l);
    else say('  Bitcoin node not connected yet. NodeSignal keeps trying every 30 seconds.');
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
    // NodeSignal's RPC login: always removed on --purge, offered otherwise
    const rpcConf = core.readRpcRecord(L.config) || confPath;
    if (rpcConf && core.rpcAccessState(rpcConf).on) {
      if (purge || (P.tty && await P.askYesNo(`Remove NodeSignal's RPC login (rpcauth, rpcwhitelist) from ${rpcConf}?`, true))) {
        core.setRpcAccess(rpcConf, null);
        try { fs.unlinkSync(core.rpcRecordPath(L.config)); } catch { }
        say(`  - Removed NodeSignal's RPC login from ${rpcConf}. Restart your node for it to take effect.`);
      } else say(`  - Kept NodeSignal's RPC login in ${rpcConf} (reinstalling reuses it). Remove: uninstall --purge`);
    }
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

  // Purge never deletes the identity key or history, on Windows as on Linux.
  if (purge) {
    const dataDir = cfg.data || path.join(os.homedir(), '.nodesignal');
    for (const f of [L.config, core.rpcRecordPath(L.config), L.log, L.log + '.1', L.pid, daemonPidPath(L)]) { try { fs.unlinkSync(f); } catch { } }
    say('  - Removed settings and logs.');
    say(`  - Kept your identity key and history in ${dataDir}. Delete that folder yourself if you want.`);
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
  let res = null, G = null;
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
    const login = {};
    const acc = core.installRpcAccess({ cfg: login, cfgPath: path.join(tmp, 'rpc-config.json'), confPath: conf });
    const rs = core.rpcAccessState(conf);
    check('RPC login: rpcauth for nodesignal at the top level, password only in the config', acc.result.changed && rs.on
      && core.rpcAuthMatches(rs.rpcauth, 'nodesignal', login['rpc-pass']) && !fs.readFileSync(conf, 'utf8').includes(login['rpc-pass'])
      && fs.readFileSync(conf, 'utf8').indexOf(core.RPC_END) < fs.readFileSync(conf, 'utf8').indexOf('[main]'));
    check('RPC login: whitelist is exactly the three methods', rs.lines.includes('rpcwhitelist=nodesignal:getblockchaininfo,getnetworkinfo,getpeerinfo'));
    check('RPC login: reinstall changes nothing', !core.installRpcAccess({ cfg: login, cfgPath: path.join(tmp, 'rpc-config.json'), confPath: conf }).result.changed);
    core.setRpcAccess(core.readRpcRecord(path.join(tmp, 'rpc-config.json')), null);
    check('RPC login: removal restores bitcoin.conf byte for byte', fs.readFileSync(conf, 'utf8') === original);

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

    // (a) restart: end only the daemon child; the supervisor must start a new one
    const sup = readPid(L);
    const kid1 = readPidFile(daemonPidPath(L));
    check('supervisor and daemon are separate processes', sup > 0 && kid1 > 0 && sup !== kid1 && isOurs(L, kid1), `supervisor ${sup}, daemon ${kid1}`);
    killPid(kid1, { hard: true });
    let kid2 = 0;
    for (let i = 0; i < 80 && !kid2; i++) {
      await sleep(250);
      const p = readPidFile(daemonPidPath(L));
      if (p && p !== kid1 && isOurs(L, p)) kid2 = p;
    }
    const back = kid2 ? await core.waitForHealth(webPort, { timeoutMs: 25000 }) : null;
    check('supervisor restarts a killed daemon', !!kid2 && !!back && readPid(L) === sup && !processImage(kid1),
      kid2 ? `daemon ${kid1} -> ${kid2}${back ? ', /health answers again' : ', no /health'}` : 'no new daemon');
    try { logText = fs.readFileSync(L.log, 'utf8'); } catch { }
    check('log records the restart', new RegExp(`supervisor: the daemon \\(pid ${kid1}\\) (exited|was ended)`).test(logText)
      && /supervisor: restarting in 1s/.test(logText) && new RegExp(`supervisor: started the daemon, pid ${kid2}`).test(logText));
    const st = spawnSync(L.exe, ['status', '--root', L.root], { encoding: 'utf8', timeout: 60000, windowsHide: true });
    check('"status" command works', st.status === 0 && /selftest/.test(st.stdout || ''), st.status === 0 ? '' : String(st.stdout || st.error || '').trim().split('\n').pop());
    const v = spawnSync(L.exe, ['version'], { encoding: 'utf8', timeout: 30000, windowsHide: true });
    check('"version" command works', String(v.stdout || '').trim() === VERSION);
    // (c) stop ends the supervisor and the daemon, leaving no orphan
    const supNow = readPid(L), kidNow = readPidFile(daemonPidPath(L));
    const stopped = await stopRunning(L, true);
    check('stop ends the daemon', stopped && !(await core.httpGetJson(`http://127.0.0.1:${webPort}/health`, 1500)).ok);
    check('stop leaves no supervisor and no daemon running', !!supNow && !!kidNow && !processImage(supNow) && !processImage(kidNow),
      `supervisor ${supNow}, daemon ${kidNow}`);
    check('stop removes both pid files', !fs.existsSync(L.pid) && !fs.existsSync(daemonPidPath(L)));

    // (b) give up: the real supervisor with a child that exits 7 at once,
    // timing scaled down; same policy, so 5 starts, 4 doubling waits, give up.
    const SCALE = 0.1;
    G = layout(path.join(tmp, 'giveup'));
    fs.mkdirSync(G.root, { recursive: true });
    const [gExe, gPre] = IN_SEA ? [L.exe, []] : [process.execPath, [__filename]];
    const gr = spawnSync(gExe, [...gPre, '__supervise-test', '--root', G.root, '--scale', String(SCALE)],
      { encoding: 'utf8', timeout: 120000, windowsHide: true });
    let gLog = '';
    try { gLog = fs.readFileSync(G.log, 'utf8'); } catch { }
    const lines = gLog.split(/\r?\n/);
    const startTimes = lines.filter((l) => /supervisor: started the daemon, pid \d+/.test(l)).map((l) => Date.parse(l.slice(0, 24)));
    const crashes = lines.filter((l) => /supervisor: the daemon \(pid \d+\) exited with code 7/.test(l)).length;
    const delays = lines.map((l) => l.match(/supervisor: restarting in (\d+)s/)).filter(Boolean).map((m) => Number(m[1]));
    check('give-up: supervisor exits non-zero', gr.status !== null && gr.status !== 0, `exit ${gr.status}${gr.error ? ', ' + gr.error.message : ''}`);
    check('give-up: exactly 5 starts and 5 crashes', startTimes.length === 5 && crashes === 5, `${startTimes.length} starts, ${crashes} crashes`);
    check('give-up: backoff doubles 1s, 2s, 4s, 8s', delays.join(',') === '1,2,4,8', delays.map((d) => d + 's').join(', '));
    const gaps = startTimes.slice(1).map((t, i) => t - startTimes[i]);
    check('give-up: each wait really elapsed (scaled)', gaps.length === 4 && gaps.every((g, i) => g + 5 >= 1000 * 2 ** i * SCALE),
      gaps.map((g) => g + 'ms').join(', '));
    check('give-up: reason logged', /supervisor: gave up: 5 crashes within 10 minutes; last exit code 7; see the lines above/.test(gLog));
    check('give-up: pid files removed', !fs.existsSync(G.pid) && !fs.existsSync(daemonPidPath(G)));
    if (!/gave up/.test(gLog)) say(gLog.split('\n').slice(-20).join('\n'));
  } catch (e) {
    check('selftest ran to completion', false, e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : String(e));
    try { say(fs.readFileSync(L.log, 'utf8').split('\n').slice(-30).join('\n')); } catch { }
  } finally {
    await stopRunning(L, true);
    if (G) await stopRunning(G, true);
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
    case '__daemon': return cmdDaemon(L);
    case '__crash': return 7;
    case '__supervise-test': {
      const scale = Number(opt(args, 'scale'));
      if (!(scale >= 0.001 && scale <= 1)) { say('__supervise-test needs --scale between 0.001 and 1'); return 2; }
      return supervise(L, { childArgs: ['__crash'], scale });
    }
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
