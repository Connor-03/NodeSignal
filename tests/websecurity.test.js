// websecurity.test.js: the web console's front door. Plain node.
//   node tests/websecurity.test.js      (Linux: uses 127.0.0.2 to prove loopback-only)
// Node 22+ for the WebSocket client; the raw-socket checks run everywhere.
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net'), http = require('http');
const assert = require('assert');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-web-'));
const WEB = 47789, PEER = 47788;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0, passed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n')[0]); if (process.env.DEBUG) console.log(d && d.log); }
};

function start(extra = []) {
  // --bind 0.0.0.0 on purpose: it must widen the PEER port only, never the console.
  const c = spawn(process.execPath, [path.join(ROOT, 'nodesignald.js'), '--nick', 'websec', '--no-rpc', '--bind', '0.0.0.0',
    '--web-port', String(WEB), '--peer-port', String(PEER), '--data', path.join(TMP, 'd'), '--checkin-ms', '0', ...extra],
  { stdio: ['ignore', 'pipe', 'pipe'] });
  c.log = ''; c.stdout.on('data', (d) => (c.log += d)); c.stderr.on('data', (d) => (c.log += d));
  return c;
}
const stop = (c) => new Promise((r) => { if (c.exitCode != null) return r(); c.once('exit', r); c.kill('SIGTERM'); });

// Raw HTTP with full control over Host and Origin.
function req({ host = `127.0.0.1:${WEB}`, origin, path: p = '/health', connectTo = '127.0.0.1', method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { Host: host };
    if (origin !== undefined) headers.Origin = origin;
    const r = http.request({ host: connectTo, port: WEB, path: p, method, headers, setHost: false, timeout: 3000 }, (res) => {
      let body = ''; res.on('data', (d) => (body += d)); res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    r.on('error', reject); r.on('timeout', () => r.destroy(new Error('timeout'))); r.end();
  });
}
// A WebSocket upgrade by hand, returning the status line.
function upgrade({ host = `127.0.0.1:${WEB}`, origin } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port: WEB });
    s.on('error', reject);
    s.on('connect', () => s.write(['GET /ws HTTP/1.1', `Host: ${host}`, 'Upgrade: websocket', 'Connection: Upgrade',
      'Sec-WebSocket-Version: 13', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', ...(origin ? [`Origin: ${origin}`] : []), '', ''].join('\r\n')));
    let d = ''; s.on('data', (x) => { d += x; if (d.includes('\r\n')) { resolve(d.split('\r\n')[0]); s.destroy(); } });
    s.on('close', () => resolve(d.split('\r\n')[0] || '(closed)'));
  });
}
const tokenOf = (html) => (/name="ns-action-token" content="([^"]+)"/.exec(html) || [])[1];
function ws(token) {
  return new Promise((resolve, reject) => {
    const w = new WebSocket(`ws://127.0.0.1:${WEB}/ws`); const seen = [];
    w.onmessage = (e) => seen.push(JSON.parse(e.data)); w.onerror = () => reject(new Error('ws error'));
    w.onopen = () => resolve({
      send: (o) => w.send(JSON.stringify(token === undefined ? o : Object.assign({ token }, o))),
      async next(pred, ms = 5000) { const end = Date.now() + ms; while (Date.now() < end) { const i = seen.findIndex(pred); if (i >= 0) return seen.splice(i, 1)[0]; await sleep(30); } throw new Error('timed out'); },
      close: () => w.close(),
    });
  });
}
async function up() { for (let i = 0; i < 60; i++) { try { if ((await req()).status === 200) return; } catch { } await sleep(100); } throw new Error('daemon did not start'); }

let d;
(async () => {
  d = start(); await up();

  await t('the console listens on 127.0.0.1 only, even with --bind 0.0.0.0', async () => {
    await assert.rejects(req({ connectTo: '127.0.0.2', host: `127.0.0.2:${WEB}` }), /ECONNREFUSED/);
    assert.match(d.log, /Web app\s+: http:\/\/127\.0\.0\.1:/);
  });

  await t('Host must be localhost or 127.0.0.1 on the web port (DNS rebinding)', async () => {
    assert.strictEqual((await req({ host: `127.0.0.1:${WEB}` })).status, 200);
    assert.strictEqual((await req({ host: `localhost:${WEB}` })).status, 200);
    assert.strictEqual((await req({ host: `LOCALHOST:${WEB}` })).status, 200);
    for (const h of ['attacker.example', `attacker.example:${WEB}`, `localhost:${WEB + 1}`, `127.0.0.1`, `[::1]:${WEB}`, '', `127.0.0.1:${WEB}.attacker.example`])
      assert.strictEqual((await req({ host: h })).status, 421, 'Host ' + JSON.stringify(h));
    assert.strictEqual((await req({ host: `rebind.attacker.example:${WEB}`, path: '/' })).status, 421);
  });

  await t('cross-origin requests are refused by Origin', async () => {
    assert.strictEqual((await req({ origin: 'http://attacker.example' })).status, 403);
    assert.strictEqual((await req({ origin: 'null' })).status, 403);
    assert.strictEqual((await req({ origin: `http://localhost:${WEB + 1}` })).status, 403);
    assert.strictEqual((await req({ origin: `https://localhost:${WEB}` })).status, 403);
    assert.strictEqual((await req({ origin: `http://localhost:${WEB}` })).status, 200);
    assert.strictEqual((await req({ origin: `http://127.0.0.1:${WEB}` })).status, 200);
  });

  await t('WebSocket upgrades check Host and Origin too', async () => {
    assert.match(await upgrade({ origin: 'http://attacker.example' }), / 403 /);
    assert.match(await upgrade({ host: `attacker.example:${WEB}`, origin: `http://localhost:${WEB}` }), / 421 /);
    assert.match(await upgrade({ origin: `http://localhost:${WEB}` }), / 101 /);
  });

  let token;
  await t('the served page carries a per-launch action token, never cached', async () => {
    const r = await req({ path: '/' });
    token = tokenOf(r.body);
    assert(token && token.length >= 40, 'token present');
    assert.strictEqual(r.headers['cache-control'], 'no-store');
    assert.strictEqual(r.headers['x-frame-options'], 'DENY');
    assert(!d.log.includes(token), 'token never logged');
    assert(!(await req()).body.includes(token), 'token not in /health');
  });

  if (typeof WebSocket === 'undefined') console.log('  skip WebSocket token checks: needs Node 22+');
  else {
    await t('state-changing actions without the token are refused; reads still work', async () => {
      const bare = await ws(undefined);
      bare.send({ type: 'hello' });
      assert((await bare.next((m) => m.type === 'state')).daemon);
      const ops = [
        { type: 'contact.add', host: '198.51.100.9', port: 8788 },
        { type: 'contact.acceptKey', host: '198.51.100.9', fp: 'ab'.repeat(16) },
        { type: 'contact.dismissKey', host: '198.51.100.9' },
        { type: 'contact.remove', host: '198.51.100.9' },
        { type: 'chat.send', host: '198.51.100.9', port: 8788, text: 'x' },
        { type: 'chat.retry', host: '198.51.100.9' }, { type: 'chat.cancel', host: '198.51.100.9', id: 'x' },
        { type: 'chat.read', host: '198.51.100.9' }, { type: 'identify', host: '198.51.100.9' },
        { type: 'vault.set', passphrase: 'correct horse battery' }, { type: 'vault.unlock', passphrase: 'x' },
        { type: 'vault.lock' }, { type: 'vault.change', old: 'a', passphrase: 'b' }, { type: 'peers.refresh' },
      ];
      for (const op of ops) {
        bare.send(op);
        const e = await bare.next((m) => m.type === 'error' && m.op === op.type);
        assert.strictEqual(e.code, 'bad-token', op.type);
      }
      bare.send({ type: 'hello' });
      const st = await bare.next((m) => m.type === 'state');
      assert.strictEqual(st.contacts.length, 0, 'no contact was created');
      assert.deepStrictEqual(st.daemon.vault, { set: false, unlocked: false }, 'no vault was created');
      bare.close();
    });
    await t('a wrong token is refused; the page token works', async () => {
      const wrong = await ws('A'.repeat(43));
      wrong.send({ type: 'contact.add', host: '198.51.100.9', port: 8788 });
      assert.strictEqual((await wrong.next((m) => m.type === 'error')).code, 'bad-token');
      wrong.close();
      const good = await ws(token);
      good.send({ type: 'contact.add', host: '198.51.100.9', port: 8788, nick: 'ok' });
      const c = await good.next((m) => m.type === 'contact');
      assert.strictEqual(c.contact.host, '198.51.100.9');
      good.close();
    });
    await t('a restart issues a new token and the old one stops working', async () => {
      const oldInstance = (/name="ns-instance" content="([^"]+)"/.exec((await req({ path: '/' })).body) || [])[1];
      await stop(d); d = start(); await up();
      const page = (await req({ path: '/' })).body;
      assert.notStrictEqual(tokenOf(page), token);
      assert.notStrictEqual((/name="ns-instance" content="([^"]+)"/.exec(page) || [])[1], oldInstance);
      const stale = await ws(token);
      stale.send({ type: 'contact.remove', host: '198.51.100.9' });
      assert.strictEqual((await stale.next((m) => m.type === 'error')).code, 'bad-token');
      stale.close();
    });
  }

  await stop(d);
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
