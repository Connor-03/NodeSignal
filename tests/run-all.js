// run-all.js: run every tests/*.test.js with plain node, one after another.
//   node tests/run-all.js        (also: npm test)
// New test files are picked up automatically. Exit 1 if any fails.
// Each file gets NS_SUITE_TIMEOUT_MS (default 5 minutes; the slowest takes
// under a minute). A file that runs longer is stopped with everything it
// started, and the suites built on harness.js print the test they were in.
// CI once waited 25 minutes on a suite that never finished.
'use strict';
const fs = require('fs'), path = require('path'), { spawn } = require('child_process');
const LIMIT_MS = Number(process.env.NS_SUITE_TIMEOUT_MS) || 5 * 60 * 1000;
const POSIX = process.platform !== 'win32';
const files = fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js')).sort();
let running = null;

// On POSIX each file runs in its own process group, so the daemons it started
// go with it (by process group id, never by name).
function signalAll(c, sig) {
  try { if (POSIX) process.kill(-c.pid, sig); else c.kill(sig); } catch { }
}
function runOne(f) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [path.join(__dirname, f)], { stdio: 'inherit', detached: POSIX });
    running = c;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      console.log(`\n  TIMEOUT ${f} ran longer than ${Math.round(LIMIT_MS / 1000)} s; stopping it`);
      c.kill('SIGTERM');                                   // harness.js names the test it was in
      setTimeout(() => signalAll(c, 'SIGKILL'), 3000).unref();
    }, LIMIT_MS);
    c.on('exit', (code) => {
      clearTimeout(timer); running = null;
      signalAll(c, 'SIGKILL');                             // anything it left behind
      resolve(code === 0 && !timedOut);
    });
  });
}
process.on('SIGINT', () => { if (running) signalAll(running, 'SIGKILL'); process.exit(130); });

(async () => {
  const failed = [];
  for (const f of files) {
    console.log(`\n== ${f}`);
    if (!(await runOne(f))) failed.push(f);
  }
  console.log(failed.length ? `\nFAILED: ${failed.join(', ')}` : `\nall ${files.length} test files passed`);
  process.exit(failed.length ? 1 : 0);
})();
