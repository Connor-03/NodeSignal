// hardening.test.js: fixes from the v1.3 self-review of nodesignald.js. Plain node.
//   node tests/hardening.test.js
// Each test fails on the code before its fix. Node 22+ for the checks that
// drive the console over WebSocket; Linux for the many-source-address check
// (it dials from 127.0.1.x, which only Linux routes to loopback by default).
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net'), http = require('http'), crypto = require('crypto');
const assert = require('assert');
const { spawn } = require('child_process');
const noise = require('../noise.js');

const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-hard-'));
const WEB = 21789, PEER = 21788, FAKE8333 = 21733;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failed = 0, passed = 0, skipped = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n')[0]); }
};
const skip = (name, why) => { skipped++; console.log(`  skip ${name}: ${why}`); };
const HAS_WS = typeof WebSocket !== 'undefined';

function start(data, extra = []) {
  const c = spawn(process.execPath, [path.join(ROOT, 'nodesignald.js'), '--nick', 'hard', '--no-rpc', '--bind', '127.0.0.1',
    '--web-port', String(WEB), '--peer-port', String(PEER), '--data', data, '--checkin-ms', '0', ...extra],
  { stdio: ['ignore', 'pipe', 'pipe'] });
  c.log = ''; c.stdout.on('data', (d) => (c.log += d)); c.stderr.on('data', (d) => (c.log += d));
  return c;
}
const stop = (c) => new Promise((r) => { if (!c || c.exitCode != null || c.signalCode) return r(); c.once('exit', r); c.kill('SIGTERM'); });
const exited = (c, ms = 8000) => new Promise((r) => { if (c.exitCode != null) return r(c.exitCode); const tm = setTimeout(() => r(null), ms); c.once('exit', (code) => { clearTimeout(tm); r(code); }); });
function health() {
  return new Promise((resolve, reject) => {
    const r = http.get({ host: '127.0.0.1', port: WEB, path: '/health', headers: { Host: `127.0.0.1:${WEB}` }, timeout: 3000 }, (res) => {
      let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    });
    r.on('error', reject); r.on('timeout', () => r.destroy(new Error('timeout')));
  });
}
async function up() { for (let i = 0; i < 80; i++) { try { return await health(); } catch { } await sleep(100); } throw new Error('daemon did not start'); }
function page() {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: WEB, path: '/', headers: { Host: `127.0.0.1:${WEB}`, Accept: 'text/html' } }, (res) => {
      let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve(b));
    }).on('error', reject);
  });
}
async function ui() {
  const token = (/name="ns-action-token" content="([^"]+)"/.exec(await page()) || [])[1];
  return new Promise((resolve, reject) => {
    const w = new WebSocket(`ws://127.0.0.1:${WEB}/ws`); const seen = [];
    w.onmessage = (e) => seen.push(JSON.parse(e.data)); w.onerror = () => reject(new Error('ws error'));
    w.onopen = () => resolve({
      send: (o) => w.send(JSON.stringify(Object.assign({ token }, o))),
      async next(pred, ms = 8000) { const end = Date.now() + ms; while (Date.now() < end) { const i = seen.findIndex(pred); if (i >= 0) return seen.splice(i, 1)[0]; await sleep(25); } throw new Error('timed out waiting for a reply'); },
      close: () => w.close(),
    });
  });
}

// Length-prefixed frames, as on :8788.
const frame = (b) => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length, 0); return Buffer.concat([h, b]); };
function frames(sock, on) {
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4) { const n = buf.readUInt32BE(0); if (buf.length < 4 + n) break; const p = buf.subarray(4, 4 + n); buf = buf.subarray(4 + n); on(p); }
  });
}
/* A peer with a fresh key, dialling from a chosen loopback address. Resolves
   once the daemon answered our hello (state created), or with null if the
   daemon hung up instead. */
function stranger(localAddress, after, id = noise.loadIdentity(noise.newIdentity())) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: PEER, localAddress });
    let st = null, session = null, done = false;
    const finish = (v) => { if (done) return; done = true; resolve(v); };
    s.on('error', () => finish(null));
    s.on('close', () => finish(null));
    s.on('connect', () => { st = noise.v3.initStart(id); s.write(frame(st.msg1)); });
    const send = (o) => s.write(frame(session.encrypt(JSON.stringify(o))));
    frames(s, (p) => {
      if (!session) {
        const r = noise.v3.initFinish(st, p); session = r.session; s.write(frame(r.msg3));
        send({ t: 'hello', proto: 3, nick: 'stranger', peerPort: 8788 });
        return;
      }
      let m; try { m = JSON.parse(session.decrypt(p)); } catch { return; }
      if (m.t === 'hello' && !done) { if (after) after({ send, sock: s }); else { s.destroy(); } finish({ send, sock: s }); }
    });
  });
}
const stateFile = (d) => JSON.parse(fs.readFileSync(path.join(d, 'state.json'), 'utf8'));

(async () => {
  /* 1. Root cause: any error reading state.json, bad JSON included, was
     treated as a fresh install, and the new identity was then saved over
     the old file, losing the identity key, every pin and all history. */
  await t('a corrupt or unreadable state.json stops the daemon and is never overwritten', async () => {
    for (const [name, body] of [['bad-json', '{"contacts": {"203.0.113.5": {"msgs": ['], ['not-object', '[1,2,3]']]) {
      const d = path.join(TMP, name); fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, 'state.json'), body);
      const c = start(d);
      const code = await exited(c);
      assert.strictEqual(code, 1, `${name}: exit code ${code}\n${c.log}`);
      assert.match(c.log, /will not start/);
      assert.strictEqual(fs.readFileSync(path.join(d, 'state.json'), 'utf8'), body, `${name}: file untouched`);
    }
    // a missing file is still a fresh install
    const d = path.join(TMP, 'fresh'); const c = start(d); await up(); await stop(c);
    assert(stateFile(d).identity, 'fresh install created an identity');
  });

  /* 2. Root cause: cookies() called decodeURIComponent on whatever the
     Cookie header held. A malformed escape threw, and on the WebSocket
     upgrade path (a plain event handler) nothing caught it: the daemon
     exited. Reachable by any local process when a web token is set. */
  await t('a malformed Cookie header on the /ws upgrade does not stop the daemon', async () => {
    const d = path.join(TMP, 'cookie'); const c = start(d, ['--web-token', 'hardening-test-token']); await up();
    try {
    await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: WEB }, () => s.write(['GET /ws HTTP/1.1', `Host: 127.0.0.1:${WEB}`, 'Upgrade: websocket', 'Connection: Upgrade',
        'Sec-WebSocket-Version: 13', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', 'Cookie: ns_session=%E0%A4%A; other=%', '', ''].join('\r\n')));
      s.on('data', () => s.destroy()); s.on('close', resolve); s.on('error', resolve);
    });
    await sleep(300);
    assert.strictEqual((await health()).status, 'ok', 'daemon still answers');
    assert.strictEqual(c.exitCode, null, 'daemon still running');
    } finally { await stop(c); }
  });

  if (!HAS_WS) {
    skip('vault.change shares the unlock backoff', 'needs Node 22+ (WebSocket)');
    skip('the :8333 user agent is cleaned and capped', 'needs Node 22+ (WebSocket)');
  } else {
    /* 3. Root cause: vault.change called store.unlock directly, outside the
       exponential backoff that vault.unlock applies, so the change form
       could test passphrases at full speed. */
    await t('vault.change shares the unlock backoff', async () => {
      const d = path.join(TMP, 'vault'); const c = start(d); await up();
      try {
      const u = await ui();
      u.send({ type: 'vault.set', passphrase: 'correct horse battery staple' });
      await u.next((m) => m.type === 'vault' && m.op === 'set');
      u.send({ type: 'vault.change', old: 'wrong guess one', passphrase: 'new passphrase here' });
      const e1 = await u.next((m) => m.type === 'error' && m.op === 'vault.change', 20000);
      assert.doesNotMatch(e1.error, /too many attempts/);
      u.send({ type: 'vault.change', old: 'wrong guess two', passphrase: 'new passphrase here' });
      const e2 = await u.next((m) => m.type === 'error' && m.op === 'vault.change', 20000);
      assert.match(e2.error, /too many attempts/, 'the second fast guess is held back');
      u.send({ type: 'vault.unlock', passphrase: 'correct horse battery staple' });
      const e3 = await u.next((m) => (m.type === 'error' && m.op === 'vault.unlock') || (m.type === 'vault' && m.op === 'unlock'), 20000);
      assert.strictEqual(e3.type, 'error', 'unlock waits out the same backoff');
      await sleep(1100);
      u.send({ type: 'vault.change', old: 'correct horse battery staple', passphrase: 'new passphrase here' });
      assert((await u.next((m) => (m.type === 'vault' && m.op === 'change') || (m.type === 'error' && m.op === 'vault.change'), 20000)).ok, 'right passphrase works after the wait');
      u.close();
      } finally { await stop(c); }
    });

    /* 4. Root cause: the user agent in a :8333 version reply came straight
       from whatever answered, unbounded (up to the 4 MB frame cap) and with
       control characters, into state.json, the log and the console. */
    await t('the :8333 user agent is cleaned and capped', async () => {
      const MAGIC = Buffer.from('f9beb4d9', 'hex');
      const dsha = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
      const p2p = (cmd, p) => { const c = Buffer.alloc(12); c.write(cmd); const l = Buffer.alloc(4); l.writeUInt32LE(p.length); return Buffer.concat([MAGIC, c, l, dsha(p).subarray(0, 4), p]); };
      const ua = Buffer.from('/Evil:1.0/\x1b[31m\nFAKE LOG LINE\r' + 'A'.repeat(5000), 'latin1');
      const vi = Buffer.from([0xfe, 0, 0, 0, 0]); vi.writeUInt32LE(ua.length, 1);
      const payload = Buffer.concat([Buffer.from([0x80, 0x11, 0x01, 0x00]), Buffer.alloc(8), Buffer.alloc(8), Buffer.alloc(26), Buffer.alloc(26), Buffer.alloc(8), vi, ua, Buffer.from([1, 0, 0, 0]), Buffer.from([0])]);
      const fake = net.createServer((s) => { s.on('error', () => { }); s.once('data', () => s.write(p2p('version', payload))); });
      await new Promise((r) => fake.listen(FAKE8333, '127.0.0.1', r));
      const d = path.join(TMP, 'ua'); const c = start(d); await up();
      try {
        const u = await ui();
        u.send({ type: 'identify', host: '127.0.0.1', port: FAKE8333 });
        const r = await u.next((m) => m.type === 'identified', 15000);
        assert(r.info, 'identified: ' + (r.error || ''));
        assert(r.info.ua.length <= 256, 'capped at 256, got ' + r.info.ua.length);
        assert(!/[\u0000-\u001f\u007f]/.test(r.info.ua), 'no control characters');
        assert(r.info.ua.startsWith('/Evil:1.0/'));
        await sleep(200);
        assert(!c.log.includes('\x1b[31m') && !/^FAKE LOG LINE/m.test(c.log), 'nothing injected into the log');
        u.close();
      } finally { await stop(c); fake.close(); }
    });
  }

  if (process.platform !== 'linux') {
    skip('strangers are capped', 'dials from many 127.0.1.x source addresses (Linux only)');
  } else {
    /* 5. Root cause: a contact was created for every authenticated stranger,
       and a key costs nothing, so many source addresses (one IPv6 /64 holds
       plenty, each within the per-/64 rate limit) could grow state.json
       until the disk bitcoind shares filled up. Now inbound-only contacts
       are capped (256, 50 messages each) and one connection is capped
       too. */
    await t('strangers are capped: count, messages kept, and messages per connection', async () => {
      const d = path.join(TMP, 'strangers'); const c = start(d); await up();
      try {
        let ok = 0;
        const firstId = noise.loadIdentity(noise.newIdentity());
        for (let i = 0; i < 256; i++) if (await stranger(`127.0.${1 + Math.floor(i / 250)}.${(i % 250) + 1}`, null, i === 0 ? firstId : undefined)) ok++;
        assert.strictEqual(ok, 256, 'the first 256 strangers are accepted');
        assert.strictEqual(await stranger('127.0.9.1'), null, 'the 257th is refused');
        assert.strictEqual((await health()).contacts, 256);
        assert.match(c.log, /refused a new contact/);
        if (HAS_WS) {   // the operator's own contacts are never refused
          const u = await ui(); u.send({ type: 'contact.add', host: '198.51.100.9', port: 8788 });
          await u.next((m) => m.type === 'contact' && m.contact.host === '198.51.100.9'); u.close();
          assert.strictEqual((await health()).contacts, 257);
        }
        // an existing stranger floods: one connection may carry 200 messages,
        // and 50 are kept
        let acks = 0;
        const closed = await new Promise((resolve) => {
          stranger('127.0.1.1', ({ send, sock }) => {
            sock.on('close', () => resolve(true));
            frames(sock, () => { acks++; });
            for (let i = 0; i < 260; i++) send({ t: 'msg', id: 'm' + i, ts: Date.now(), text: 'flood ' + i });
          }, firstId).then((r) => { if (!r) resolve(false); });
          setTimeout(() => resolve(false), 15000);
        });
        assert(closed, 'the flooding connection was closed');
        await sleep(400);
        const st = stateFile(d);
        const c1 = st.contacts['127.0.1.1'];
        assert(c1 && c1.inbound, 'stored as an inbound-only contact');
        assert(c1.msgs.length <= 50, 'kept ' + c1.msgs.length);
        assert.strictEqual((await health()).status, 'ok');
      } finally { await stop(c); }
    });
  }

  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed}${skipped ? `, ${skipped} skipped` : ''})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
