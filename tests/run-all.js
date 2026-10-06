// run-all.js: run every tests/*.test.js with plain node, one after another.
//   node tests/run-all.js        (also: npm test)
// New test files are picked up automatically. Exit 1 if any fails.
'use strict';
const fs = require('fs'), path = require('path'), { spawnSync } = require('child_process');
const files = fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js')).sort();
const failed = [];
for (const f of files) {
  console.log(`\n== ${f}`);
  const r = spawnSync(process.execPath, [path.join(__dirname, f)], { stdio: 'inherit' });
  if (r.status !== 0) failed.push(f);
}
console.log(failed.length ? `\nFAILED: ${failed.join(', ')}` : `\nall ${files.length} test files passed`);
process.exit(failed.length ? 1 : 0);
