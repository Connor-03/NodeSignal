// shoot.js: render nodesignal.html against fixture-ws.js and save a set of
// screenshots. Linux or Windows, from the repo root:
//
//   node tools/screenshots/shoot.js [outDir] [--webp <dir>]
//
// outDir (default ./screenshots) gets every scene as PNG. The website set
// (WEB_SET below, resized and encoded as WebP) goes to --webp <dir>, default
// <outDir>/webp. The published copy lives in docs/website/screenshots:
//
//   node tools/screenshots/shoot.js /tmp/shots --webp docs/website/screenshots
//
// Needs Playwright with Chromium (optional, not a project dependency; set
// NODE_PATH if it is installed globally). The WebP encoding is done by
// Chromium itself (canvas.toDataURL), so nothing else is needed.
// SEED fixes the radar layout; the clock, time zone and locale are pinned too,
// so the same code gives the same images on any machine and any day.
'use strict';
const fs = require('fs'), path = require('path'), http = require('http');
let chromium;
try { ({ chromium } = require('playwright')); }
catch { console.error('Playwright is not installed; see the header of this file.'); process.exit(1); }
const ROOT = path.join(__dirname, '..', '..');
const args = process.argv.slice(2);
const wi = args.indexOf('--webp');
const WEBP_OUT = wi >= 0 ? path.resolve(args[wi + 1] || '') : null;
const positional = args.filter((a, i) => a !== '--webp' && (wi < 0 || i !== wi + 1));
const OUT = path.resolve(positional[0] || 'screenshots');
const WEB_DIR = WEBP_OUT || path.join(OUT, 'webp');
const SEED = Number(process.env.SEED || 3);
// Sample time shown in the images (fixture timestamps are relative to it).
const CLOCK_AT = Date.parse(process.env.CLOCK || '2026-05-12T14:20:00Z');
const FIXTURE = fs.readFileSync(path.join(__dirname, 'fixture-ws.js'), 'utf8');
const SEEDED = `(()=>{let x=${SEED};Math.random=()=>{x=(x*1103515245+12345)%2147483648;return x/2147483648;};})();`;
// A Date that keeps ticking from CLOCK_AT, so animations and timers still run.
const CLOCK = `(()=>{const R=Date,off=${CLOCK_AT}-R.now();class D extends R{constructor(...a){if(a.length)super(...a);else super(R.now()+off);}static now(){return R.now()+off;}}window.Date=D;})();`;

// Website set: [scene, width in px]. Kept small: the whole set should stay
// under about 300 KB. WEBP_Q is the encoder quality (0 to 1).
const WEB_SET = [
  ['desktop-constellation', 1600],
  ['desktop-constellation-tooltip', 1280],
  ['desktop-chat', 1280],
  ['desktop-key-change-review', 1280],
  ['desktop-chat-retrying', 1280],
  ['desktop-history-locked', 1280],
  ['desktop-status', 1280],
  ['phone-chat', 540],
];
const WEBP_Q = Number(process.env.WEBP_Q || 0.75);

fs.mkdirSync(OUT, { recursive: true });

const srv = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  fs.createReadStream(path.join(ROOT, 'nodesignal.html')).pipe(res);
});
srv.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${srv.address().port}/`;
  const b = await chromium.launch();
  const open = async (w, h, mode = 'ok', scale = 1.25, calm = true) => {
    const pg = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: scale, timezoneId: 'UTC', locale: 'en-US' });
    await pg.addInitScript(CLOCK); await pg.addInitScript(SEEDED); await pg.addInitScript(FIXTURE);
    await pg.goto(base + '?mode=' + mode + (calm ? '&calm=1' : '')); await pg.waitForTimeout(1200); return pg;
  };
  const shot = (pg, name) => pg.screenshot({ path: path.join(OUT, name + '.png') }).then(() => console.log('  ' + name));
  const chat = (pg, host) => pg.evaluate((h) => { const p = state.peers.find((x) => x.host === h); p.unread = 0; openChat(p.id); }, host);

  // Scenes that are not about the key change use calm=1 (no red banner).
  let pg = await open(1440, 900);
  await shot(pg, 'desktop-constellation');
  // tooltip on kiwi-relay: its card shows what the :8333 handshake measured
  let g = null;
  for (const x of await pg.$$('.peer-g')) if ((await x.textContent()).includes('kiwi-relay')) { g = x; break; }
  if (g) { await g.hover(); await pg.waitForTimeout(300); await shot(pg, 'desktop-constellation-tooltip'); }
  await pg.mouse.move(5, 300);
  await chat(pg, '203.0.113.42'); await pg.waitForTimeout(400); await shot(pg, 'desktop-chat');
  await chat(pg, '198.51.100.77'); await pg.waitForTimeout(300); await shot(pg, 'desktop-chat-retrying');
  await pg.evaluate(() => openChat(state.peers.find((p) => p.ns).id)); await pg.waitForTimeout(300); await shot(pg, 'desktop-advertised-peer');
  await pg.evaluate(() => toggleDrawer(true)); await pg.waitForTimeout(400); await shot(pg, 'desktop-status');
  await pg.evaluate(() => { toggleDrawer(false); switchTab('peers'); openAdd(); }); await pg.waitForTimeout(300); await shot(pg, 'desktop-add-contact');
  await pg.close();
  pg = await open(1440, 900, 'ok', 1.25, false);
  await chat(pg, '203.0.113.88'); await pg.waitForTimeout(300); await shot(pg, 'desktop-key-change-review'); await pg.close();
  pg = await open(1440, 900, 'locked'); await chat(pg, '203.0.113.42'); await pg.waitForTimeout(300); await shot(pg, 'desktop-history-locked');
  await pg.evaluate(() => openVault('unlock')); await pg.waitForTimeout(200); await shot(pg, 'desktop-unlock'); await pg.close();
  pg = await open(1440, 900, 'norpc'); await shot(pg, 'desktop-waiting-for-rpc'); await pg.close();
  pg = await open(1440, 900, 'slow', 1.25); await shot(pg, 'desktop-connecting'); await pg.close();
  pg = await open(390, 844, 'ok', 3);
  await shot(pg, 'phone-constellation');
  await pg.evaluate(() => switchTab('msgs')); await pg.waitForTimeout(200); await shot(pg, 'phone-conversations');
  await chat(pg, '203.0.113.42'); await pg.waitForTimeout(300); await shot(pg, 'phone-chat');
  await pg.close();
  console.log('saved to ' + OUT);

  // WebP export: Chromium decodes each PNG, scales it on a canvas and
  // re-encodes it, so this needs no image library.
  fs.mkdirSync(WEB_DIR, { recursive: true });
  pg = await b.newPage();
  let total = 0;
  for (const [name, width] of WEB_SET) {
    const png = fs.readFileSync(path.join(OUT, name + '.png')).toString('base64');
    const url = await pg.evaluate(async ({ png, width, q }) => {
      const img = new Image(); img.src = 'data:image/png;base64,' + png; await img.decode();
      const w = Math.min(width, img.naturalWidth), h = Math.round(img.naturalHeight * w / img.naturalWidth);
      const c = document.createElement('canvas'); c.width = w; c.height = h;
      const x = c.getContext('2d'); x.imageSmoothingEnabled = true; x.imageSmoothingQuality = 'high';
      x.drawImage(img, 0, 0, w, h);
      return c.toDataURL('image/webp', q);
    }, { png, width, q: WEBP_Q });
    if (!url.startsWith('data:image/webp;')) throw new Error('this Chromium cannot encode WebP');
    const buf = Buffer.from(url.slice(url.indexOf(',') + 1), 'base64');
    fs.writeFileSync(path.join(WEB_DIR, name + '.webp'), buf);
    total += buf.length;
    console.log(`  ${name}.webp  ${(buf.length / 1024).toFixed(1)} KB`);
  }
  console.log(`website set: ${WEB_SET.length} files, ${(total / 1024).toFixed(1)} KB, in ${WEB_DIR}`);
  await pg.close();
  await b.close(); srv.close();
});
