// shoot.js: render nodesignal.html against fixture-ws.js and save a set of
// screenshots. Linux or Windows, from the repo root:
//
//   node tools/screenshots/shoot.js [outDir]        (default: ./screenshots)
//
// Needs Playwright with Chromium (optional, not a project dependency; set
// NODE_PATH if it is installed globally). SEED fixes the radar layout.
'use strict';
const fs = require('fs'), path = require('path'), http = require('http');
let chromium;
try { ({ chromium } = require('playwright')); }
catch { console.error('Playwright is not installed; see the header of this file.'); process.exit(1); }
const ROOT = path.join(__dirname, '..', '..');
const OUT = path.resolve(process.argv[2] || 'screenshots');
const SEED = Number(process.env.SEED || 3);
const FIXTURE = fs.readFileSync(path.join(__dirname, 'fixture-ws.js'), 'utf8');
const SEEDED = `(()=>{let x=${SEED};Math.random=()=>{x=(x*1103515245+12345)%2147483648;return x/2147483648;};})();`;
fs.mkdirSync(OUT, { recursive: true });

const srv = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  fs.createReadStream(path.join(ROOT, 'nodesignal.html')).pipe(res);
});
srv.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${srv.address().port}/`;
  const b = await chromium.launch();
  const open = async (w, h, mode = 'ok', scale = 1.25) => {
    const pg = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: scale });
    await pg.addInitScript(SEEDED); await pg.addInitScript(FIXTURE);
    await pg.goto(base + '?mode=' + mode); await pg.waitForTimeout(1200); return pg;
  };
  const shot = (pg, name) => pg.screenshot({ path: path.join(OUT, name + '.png') }).then(() => console.log('  ' + name));
  const chat = (pg, host) => pg.evaluate((h) => { const p = state.peers.find((x) => x.host === h); p.unread = 0; openChat(p.id); }, host);

  let pg = await open(1440, 900);
  await shot(pg, 'desktop-constellation');
  const g = (await pg.$$('.peer-g'))[3]; if (g) { await g.hover(); await pg.waitForTimeout(300); await shot(pg, 'desktop-constellation-tooltip'); }
  await pg.mouse.move(5, 300);
  await chat(pg, '203.0.113.42'); await pg.waitForTimeout(400); await shot(pg, 'desktop-chat');
  await chat(pg, '198.51.100.77'); await pg.waitForTimeout(300); await shot(pg, 'desktop-chat-failed');
  await pg.evaluate(() => toggleDrawer(true)); await pg.waitForTimeout(400); await shot(pg, 'desktop-status');
  await pg.evaluate(() => { toggleDrawer(false); switchTab('peers'); openAdd(); }); await pg.waitForTimeout(300); await shot(pg, 'desktop-add-contact');
  await pg.close();
  pg = await open(1440, 900, 'norpc'); await shot(pg, 'desktop-waiting-for-rpc'); await pg.close();
  pg = await open(1440, 900, 'slow', 1.25); await shot(pg, 'desktop-connecting'); await pg.close();
  pg = await open(390, 844, 'ok', 3);
  await shot(pg, 'phone-constellation');
  await pg.evaluate(() => switchTab('msgs')); await pg.waitForTimeout(200); await shot(pg, 'phone-conversations');
  await chat(pg, '203.0.113.42'); await pg.waitForTimeout(300); await shot(pg, 'phone-chat');
  await pg.close();
  await b.close(); srv.close();
  console.log('saved to ' + OUT);
});
