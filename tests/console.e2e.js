// console.e2e.js: end-to-end check of nodesignal.html against two real
// daemons and a mock Bitcoin node. Linux (needs 127.0.0.2 on loopback).
//
//   node tests/console.e2e.js
//
// Needs Playwright with a Chromium build. It is NOT a project dependency;
// install it globally or point NODE_PATH at it. Without it the test skips.
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), assert = require('assert');
const { spawn } = require('child_process');
let chromium;
try { ({ chromium } = require('playwright')); }
catch { console.log('skip: playwright not installed (optional; see header)'); process.exit(0); }
const { rpcServer, p2pServer } = require('./mock-node.js');
const ROOT = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-'));
const kids = [];
const daemon = (name, args) => {
  const c = spawn(process.execPath, [path.join(ROOT, 'nodesignald.js'), '--nick', name, '--data', path.join(tmp, name), ...args],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  c.log = ''; c.stdout.on('data', (d) => (c.log += d)); c.stderr.on('data', (d) => (c.log += d));
  kids.push(c); return c;
};
const A_ARGS = ['--bind', '127.0.0.1', '--web-port', '18789', '--peer-port', '8788',
  '--rpc-url', 'http://127.0.0.1:18332', '--rpc-user', 'u', '--rpc-pass', 'p'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0;
const t = async (name, fn) => { try { await fn(); console.log('  ok   ' + name); } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + e.message); } };

(async () => {
  const rpc = await rpcServer(), p2p = await p2pServer();
  let A = daemon('alpha', A_ARGS);
  daemon('bravo', ['--bind', '127.0.0.2', '--web-port', '28789', '--peer-port', '8788', '--no-rpc']);
  await sleep(1500);
  const b = await chromium.launch();
  const pg = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; pg.on('pageerror', (e) => errs.push(e.message));
  await pg.goto('http://127.0.0.1:18789/'); await sleep(1200);
  const peerOf = (host) => pg.evaluate((h) => { const p = state.peers.find((x) => x.host === h); return p && { id: p.id, impl: p.impl, msgs: p.msgs.map((m) => [m.text, m.status]) }; }, host);

  await t('node peers from getpeerinfo are drawn', async () => {
    assert.strictEqual(await pg.evaluate(() => state.peers.filter((p) => p.kind === 'peer').length), 22);
  });
  await t('adding a contact identifies it over :8333 automatically', async () => {
    await pg.evaluate(() => send({ type: 'contact.add', host: '127.0.0.2', port: 8788, nick: 'bravo' }));
    await sleep(3000);
    assert.strictEqual((await peerOf('127.0.0.2')).impl, 'Bitcoin Knots');
  });
  await t('a message is delivered daemon to daemon', async () => {
    await pg.evaluate((id) => openChat(id), (await peerOf('127.0.0.2')).id);
    await pg.fill('#composer-in', 'hello bravo'); await pg.press('#composer-in', 'Enter'); await sleep(2500);
    assert.deepStrictEqual((await peerOf('127.0.0.2')).msgs.at(-1), ['hello bravo', 'delivered']);
  });
  await t('while the daemon is down the composer stays enabled and queues', async () => {
    A.kill(); await sleep(1200);
    assert.strictEqual(await pg.evaluate(() => document.getElementById('composer-in').disabled), false);
    await pg.fill('#composer-in', 'queued across a restart'); await pg.press('#composer-in', 'Enter');
    assert.strictEqual(await pg.evaluate(() => state.outbox.length), 1);
    assert(await pg.evaluate(() => !!document.querySelector('.bubble.queued')), 'queued bubble shown');
  });
  await t('the queue is delivered after the daemon comes back', async () => {
    A = daemon('alpha', A_ARGS); await sleep(9000);
    assert.strictEqual(await pg.evaluate(() => state.outbox.length), 0);
    assert.deepStrictEqual((await peerOf('127.0.0.2')).msgs.at(-1), ['queued across a restart', 'delivered']);
  });
  await t('phone width: no sideways scroll and a thread opens', async () => {
    const m = await b.newPage({ viewport: { width: 390, height: 844 } });
    await m.goto('http://127.0.0.1:18789/'); await sleep(1200);
    assert.strictEqual(await m.evaluate(() => document.documentElement.scrollWidth), 390);
    await m.evaluate(() => openChat(state.peers.find((p) => p.host === '127.0.0.2').id)); await sleep(300);
    assert(await m.evaluate(() => getComputedStyle(document.getElementById('thread')).display !== 'none'));
    assert.strictEqual(await m.evaluate(() => document.documentElement.scrollWidth), 390);
    await m.close();
  });
  await t('no page errors', async () => assert.deepStrictEqual(errs, []));

  await b.close(); rpc.close(); p2p.close();
  for (const k of kids) { try { k.kill(); } catch { } }
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); for (const k of kids) { try { k.kill(); } catch { } } process.exit(1); });
