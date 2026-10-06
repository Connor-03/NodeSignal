// ports.test.js: no test listens on a fixed port inside an OS ephemeral range.
//   node tests/ports.test.js
// Root cause it guards (CI, Oct 2026): suites used fixed ports such as 44752
// and 47789, inside Linux's ephemeral range (32768-60999). Any process that
// asks the OS for "a free port" (listen on 0), including other suites, can be
// handed one of them, and the daemon then fails with EADDRINUSE. Windows and
// macOS hand out 49152-65535. Fixed test ports therefore stay below 32768.
// Numbers in that range that are data rather than ports are listed below.
'use strict';
const fs = require('fs'), path = require('path'), assert = require('assert');
const DATA = new Set([
  32601,          // mock-node.js: JSON-RPC "method not found" error code
  32760,          // noise.test.js: a payload length
  40000, 49000, 60000,  // portmap.test.js: external ports a mock router reports
  65535,          // a frame or length limit (noise.test.js, websocket.test.js)
]);
const bad = [];
for (const f of fs.readdirSync(__dirname).filter((x) => x.endsWith('.js') && x !== 'ports.test.js')) {
  fs.readFileSync(path.join(__dirname, f), 'utf8').split('\n').forEach((line, i) => {
    for (const m of line.matchAll(/\b(\d{5})\b/g)) {
      const n = Number(m[1]);
      if (n >= 32768 && n <= 65535 && !DATA.has(n)) bad.push(`${f}:${i + 1}: ${n}`);
    }
  });
}
try {
  assert.deepStrictEqual(bad, [], 'fixed ports inside an ephemeral range:\n  ' + bad.join('\n  '));
  console.log('  ok   every fixed test port is below 32768 (outside the OS ephemeral ranges)\n\nall passed (1)');
} catch (e) { console.log('  FAIL ' + e.message); process.exit(1); }
