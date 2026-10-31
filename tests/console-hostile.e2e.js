// console-hostile.e2e.js: nodesignal.html never runs markup that someone
// else chose. Optional, like console.e2e.js: needs Playwright with Chromium,
// skips without it.
//
//   node tests/console-hostile.e2e.js
//
// The fixture daemon (tools/screenshots/fixture-ws.js, ?mode=hostile) ends
// every peer-chosen string (nicks, messages, errors, the mailbox a message is
// held at, user agents, room names and members, introductions, release notes)
// with quotes and an <img onerror> that counts a hit in window.__xss. The
// test opens every view, every conversation, every room and the status
// drawer, and fails on any hit or any injected element.
// Found by it: a message held at a mailbox showed the mailbox operator's nick
// without escaping (1.4 review).
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), assert = require('assert');
let chromium;
try { ({ chromium } = require('playwright')); }
catch { console.log('skip: playwright not installed (optional; see console.e2e.js)'); process.exit(0); }

const ROOT = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'nodesignal.html'), 'utf8').replace(/<head[^>]*>/i,
  (h) => h + '\n<meta name="ns-action-token" content="t">\n<meta name="ns-instance" content="i">\n');
const FIXTURE = fs.readFileSync(path.join(ROOT, 'tools', 'screenshots', 'fixture-ws.js'), 'utf8');
let failed = 0;
const t = async (name, fn) => { try { await fn(); console.log('  ok   ' + name); } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + e.message); } };

(async () => {
  const srv = http.createServer((req, res) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(html); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://localhost:${srv.address().port}/`;
  const browser = await chromium.launch();
  const hits = async (pg) => pg.evaluate(() => ({ ran: window.__xss || 0, imgs: document.querySelectorAll('img[src="x"]').length,
    bold: document.querySelectorAll('b[x]').length }));
  const clean = async (pg, where) => {
    const h = await hits(pg);
    assert.deepStrictEqual(h, { ran: 0, imgs: 0, bold: 0 }, `markup from a peer was rendered (${where}): ${JSON.stringify(h)}`);
  };
  try {
    for (const vp of [{ width: 1280, height: 860 }, { width: 390, height: 844 }]) {
      const pg = await browser.newPage({ viewport: vp });
      const errors = [];
      pg.on('pageerror', (e) => errors.push(e.message));
      await pg.addInitScript(FIXTURE);
      await pg.goto(base + '?mode=hostile');
      await pg.waitForTimeout(800);
      const tag = `${vp.width}px`;

      await t(`${tag}: the page loads the hostile state`, async () => {
        const n = await pg.evaluate(() => state.peers.length);
        assert(n > 20, 'peers: ' + n);
        assert.deepStrictEqual(errors, []);
        await clean(pg, 'map');
      });
      await t(`${tag}: every conversation, including a message held at a mailbox`, async () => {
        const ids = await pg.evaluate(() => state.peers.filter((p) => p.kind === 'contact' || p.msgs && p.msgs.length).map((p) => p.id));
        assert(ids.length >= 4);
        for (const id of ids) { await pg.evaluate((x) => openChat(x), id); await pg.waitForTimeout(60); await clean(pg, 'chat ' + id); }
        await pg.evaluate(() => openChat(state.peers.find((p) => p.host === '198.51.100.77').id)); await pg.waitForTimeout(60);
        const held = await pg.evaluate(() => document.body.innerText.includes('held at mailbox-operator\'"><img'));
        assert(held, 'the held message shows the mailbox, as text');
      });
      await t(`${tag}: peer cards and tooltips for node peers`, async () => {
        const ids = await pg.evaluate(() => state.peers.filter((p) => p.kind !== 'contact').slice(0, 8).map((p) => p.id));
        for (const id of ids) { await pg.evaluate((x) => openChat(x), id); await pg.waitForTimeout(40); }
        await clean(pg, 'node peers');
      });
      await t(`${tag}: messages, feed and rooms tabs, each room`, async () => {
        for (const tab of ['msgs', 'feed', 'rooms', 'peers']) { await pg.evaluate((x) => switchTab(x), tab); await pg.waitForTimeout(80); await clean(pg, 'tab ' + tab); }
        const rooms = await pg.evaluate(() => (state.rooms || []).map((r) => r.room));
        assert(rooms.length >= 1);
        await pg.evaluate(() => switchTab('rooms'));
        for (const r of rooms) { await pg.evaluate((x) => openRoom(x), r); await pg.waitForTimeout(80); await clean(pg, 'room ' + r); }
      });
      await t(`${tag}: status drawer, update notes, share and add dialogs`, async () => {
        await pg.evaluate(() => toggleDrawer(true)); await pg.waitForTimeout(150); await clean(pg, 'drawer');
        await pg.evaluate(() => toggleDrawer(false));
        await pg.evaluate(() => { switchTab('peers'); openAdd(); }); await pg.waitForTimeout(100); await clean(pg, 'add');
        await pg.keyboard.press('Escape');
        await pg.evaluate(() => openShare()); await pg.waitForTimeout(150); await clean(pg, 'share');
        assert.deepStrictEqual(errors, []);
      });
      await pg.close();
    }
  } finally { await browser.close(); srv.close(); }
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
