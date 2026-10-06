// daemon.test.js: real daemons on loopback, driven through their WebSocket API.
//   node tests/daemon.test.js          (Linux: needs 127.0.0.2 and 127.0.0.3 on loopback)
// Node 22+ (uses the built-in WebSocket client); skips on older versions.
'use strict';
if (typeof WebSocket === 'undefined') { console.log('skip: needs Node 22+ (global WebSocket)'); process.exit(0); }
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net'), http = require('http');
const assert = require('assert');
const { spawn } = require('child_process');
const noise = require('../noise.js');
const { rpcServer } = require('./mock-node.js');

const ROOT = path.join(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-daemon-'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const kids = new Set();
let failed = 0, passed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e).toString().split('\n').slice(0, 3).join('\n       ')); }
};

/* ---- daemons ---- */
function daemon(name, { host, peer, web, rpc = false, data = name, extra = [] }) {
  const args = [path.join(ROOT, 'nodesignald.js'), '--nick', name, '--bind', host, '--peer-port', String(peer), '--web-port', String(web),
    '--data', path.join(TMP, data), '--retry-scale', '0.01', '--checkin-ms', '0', '--rl-burst', '1000', ...extra];
  if (rpc) args.push('--rpc-url', 'http://127.0.0.1:18342', '--rpc-user', 'u', '--rpc-pass', 'p'); else args.push('--no-rpc');
  const c = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  c.log = ''; c.stdout.on('data', (d) => (c.log += d)); c.stderr.on('data', (d) => (c.log += d));
  c.web = web; c.host = host; c.peer = peer; c.dataDir = path.join(TMP, data);
  kids.add(c); c.on('exit', () => kids.delete(c));
  return c;
}
const stop = (c) => new Promise((r) => { if (c.exitCode != null) return r(); c.once('exit', r); c.kill('SIGTERM'); });
function health(c) {
  return new Promise((res) => {
    // the web console listens on loopback only, whatever --bind says
    const req = http.get({ host: '127.0.0.1', port: c.web, path: '/health', timeout: 1000 }, (r) => { let d = ''; r.on('data', (x) => (d += x)); r.on('end', () => { try { res(JSON.parse(d)); } catch { res(null); } }); });
    req.on('error', () => res(null)); req.on('timeout', () => { req.destroy(); res(null); });
  });
}
async function up(c) { for (let i = 0; i < 60; i++) { if (await health(c)) return c; await sleep(100); } throw new Error(c.log || 'daemon did not start'); }

/* ---- a tiny UI client ---- */
// The action token is written into the page the daemon serves, exactly as the
// console reads it. send() attaches it; sendBare() does not.
function pageToken(c) {
  return new Promise((res, rej) => http.get({ host: '127.0.0.1', port: c.web, path: '/' }, (r) => {
    let d = ''; r.on('data', (x) => (d += x));
    r.on('end', () => { const m = /name="ns-action-token" content="([^"]+)"/.exec(d); m ? res(m[1]) : rej(new Error('no action token in page')); });
  }).on('error', rej));
}
async function ui(c) {
  const token = await pageToken(c);
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${c.web}/ws`);
    const seen = [], waiters = [];
    ws.onmessage = (e) => {
      // an event goes to the first waiter that wants it, or into the buffer; never both
      const m = JSON.parse(e.data);
      const w = waiters.find((x) => x.pred(m));
      if (w) { waiters.splice(waiters.indexOf(w), 1); w.res(m); } else seen.push(m);
    };
    ws.onerror = () => reject(new Error('ws error'));
    ws.onopen = () => resolve({
      send: (o) => ws.send(JSON.stringify(Object.assign({ token }, o))),
      sendBare: (o) => ws.send(JSON.stringify(o)),
      wait(pred, ms = 8000) {
        const hit = seen.find(pred); if (hit) { seen.splice(seen.indexOf(hit), 1); return Promise.resolve(hit); }
        return new Promise((r, j) => { const w = { pred, res: r }; waiters.push(w); setTimeout(() => { if (waiters.includes(w)) { waiters.splice(waiters.indexOf(w), 1); j(new Error('timed out waiting for a UI event')); } }, ms); });
      },
      async state() { seen.length = 0; this.send({ type: 'hello' }); return this.wait((m) => m.type === 'state'); },
      close: () => ws.close(),
    });
  });
}
const contactOf = (st, host) => st.contacts.find((x) => x.host === host);
// Send from a UI and return the new message id (from the daemon's echo).
async function sent(u, host, port, text) {
  u.send({ type: 'chat.send', host, port, text });
  const r = await u.wait((m) => m.type === 'chat.recv' && m.host === host && m.msg.from === 'me' && m.msg.text === text);
  return r.msg.id;
}
const status = (u, id, st, ms) => u.wait((m) => m.type === 'chat.status' && m.id === id && m.status === st, ms);
async function until(fn, ms = 8000, step = 100) {
  const end = Date.now() + ms; let last;
  while (Date.now() < end) { try { last = await fn(); if (last) return last; } catch (e) { last = e; } await sleep(step); }
  throw new Error('condition not met' + (last instanceof Error ? ': ' + last.message : ''));
}

/* ---- raw peer clients (legacy v2, misbehaving) ---- */
function frames(sock, on) {
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => { buf = Buffer.concat([buf, d]); while (buf.length >= 4) { const n = buf.readUInt32BE(0); if (buf.length < 4 + n) break; const p = buf.subarray(4, 4 + n); buf = buf.subarray(4 + n); on(p); } });
}
const frame = (b) => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };
// Raw clients use their own loopback source address, so they never collide with
// a real daemon's pinned contact (contacts are keyed by source address).
function legacyClient(host, port, id, onJson, localAddress) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port, localAddress }); let st, session;
    s.on('error', reject);
    s.on('connect', () => { st = noise.legacy.initStart(id); s.write(frame(st.msg1)); });
    frames(s, (p) => {
      if (!session) { const r = noise.legacy.initFinish(st, p); s.write(frame(r.msg3)); session = noise.legacy.makeSession(r.tx, r.rx);
        resolve({ send: (o) => s.write(frame(session.encrypt(JSON.stringify(o)))), close: () => s.destroy() }); return; }
      onJson(JSON.parse(session.decrypt(p)));
    });
  });
}

(async () => {
  const rpc = await rpcServer({ port: 18342, npeers: 3, nodesignalPeers: 1 });
  let A = await up(daemon('alpha', { host: '127.0.0.1', peer: 28788, web: 28789, rpc: true }));
  let B = await up(daemon('bravo', { host: '127.0.0.2', peer: 38788, web: 38789 }));
  let ua = await ui(A), ub = await ui(B);

  await t('getpeerinfo peers advertising (nodesignal) are flagged', async () => {
    const st = await ua.state();
    const flagged = st.node.peers.filter((p) => p.nodesignal);
    assert.strictEqual(flagged.length, 1); assert.strictEqual(flagged[0].nodesignal.port, 8788);
    assert.strictEqual(st.daemon.proto, 3);
  });

  await t('v3: A delivers to B over standard Noise and both pin each other', async () => {
    ua.send({ type: 'contact.add', host: '127.0.0.2', port: 38788, nick: 'bravo' });
    const id = await sent(ua, '127.0.0.2', 38788, 'hello over Noise XX\nsecond line');
    await status(ua, id, 'delivered');
    const r = await ub.wait((m) => m.type === 'chat.recv' && m.msg.from === 'them');
    assert.strictEqual(r.msg.text, 'hello over Noise XX\nsecond line');
    const a = contactOf(await ua.state(), '127.0.0.2'), b = contactOf(await ub.state(), '127.0.0.1');
    assert(a.peerFp && b.peerFp); assert.strictEqual(a.proto, 3); assert(a.established);
  });

  await t('reply over an open link: B is unreachable from A, A\'s message rides back on B\'s connection', async () => {
    await sleep(3200);                                                     // let the previous link hang up
    ua.send({ type: 'contact.add', host: '127.0.0.2', port: 9 });          // A can no longer dial B
    const pid = await sent(ua, '127.0.0.2', 9, 'queued for an unreachable peer');
    const p = await status(ua, pid, 'pending');
    assert.match(p.error, /refused|closed|timeout/);
    await sent(ub, '127.0.0.1', 28788, 'B calling A');
    const got = await ub.wait((m) => m.type === 'chat.recv' && m.msg.from === 'them' && m.msg.text === 'queued for an unreachable peer');
    assert(got);
    await ua.wait((m) => m.type === 'chat.status' && m.status === 'delivered' && m.id === p.id);
  });

  await t('retry queue: a message to a stopped peer is delivered when it comes back', async () => {
    await stop(B);
    const pid = await sent(ua, '127.0.0.2', 38788, 'are you back?');
    const p = await status(ua, pid, 'pending');
    B = await up(daemon('bravo', { host: '127.0.0.2', peer: 38788, web: 38789 }));
    ub = await ui(B);
    await ua.wait((m) => m.type === 'chat.status' && m.status === 'delivered' && m.id === p.id, 10000);
    const st = await ub.state();
    assert(contactOf(st, '127.0.0.1').msgs.some((m) => m.text === 'are you back?'));
  });

  await t('duplicates are acknowledged but stored once', async () => {
    const st0 = contactOf(await ub.state(), '127.0.0.1').msgs.length;
    // replay through a legacy client with a fixed id, twice
    const id = noise.loadIdentity(noise.newIdentity());
    const acks = [];
    const cl = await legacyClient('127.0.0.2', 38788, id, (m) => m.t === 'ack' && acks.push(m.id), '127.0.0.11');
    cl.send({ t: 'hello', proto: 2, nick: 'replayer', peerPort: 1 });
    cl.send({ t: 'msg', id: 'dup-1', ts: Date.now(), text: 'once' });
    cl.send({ t: 'msg', id: 'dup-1', ts: Date.now(), text: 'once' });
    await until(() => acks.length === 2);
    cl.close();
    const st = await ub.state();
    const c = st.contacts.find((x) => x.nick === 'replayer');
    assert.strictEqual(c.msgs.filter((m) => m.id === 'dup-1').length, 1);
    assert(contactOf(st, '127.0.0.1').msgs.length >= st0);
  });

  await t('v1.2 peers: a legacy client can still deliver to a v3 daemon', async () => {
    const id = noise.loadIdentity(noise.newIdentity());
    const acks = [];
    const cl = await legacyClient('127.0.0.1', 28788, id, (m) => m.t === 'ack' && acks.push(m.id), '127.0.0.12');
    cl.send({ t: 'hello', proto: 2, nick: 'old-daemon', peerPort: 1 });
    cl.send({ t: 'msg', id: 'legacy-1', ts: Date.now(), text: 'from v1.2' });
    await until(() => acks.includes('legacy-1')); cl.close();
  });

  await t('v1.2 peers: A falls back to the old handshake when a peer hangs up on standard Noise', async () => {
    const id = noise.loadIdentity(noise.newIdentity());
    const got = [];
    const srv = net.createServer((s) => {
      let hs = null, session = null; s.on('error', () => { });
      frames(s, (p) => {
        if (!hs) { try { hs = noise.legacy.respond(id, p); s.write(frame(hs.msg2)); } catch { s.destroy(); } return; }
        if (!session) { const r = hs._finish(p); session = noise.legacy.makeSession(r.tx, r.rx); return; }
        const m = JSON.parse(session.decrypt(p)); got.push(m);
        if (m.t === 'hello') s.write(frame(session.encrypt(JSON.stringify({ t: 'hello', proto: 2, nick: 'old-server', peerPort: 48788 }))));
        if (m.t === 'msg') s.write(frame(session.encrypt(JSON.stringify({ t: 'ack', id: m.id }))));
      });
    });
    await new Promise((r) => srv.listen(48788, '127.0.0.3', r));
    const oid = await sent(ua, '127.0.0.3', 48788, 'hello old friend');
    await status(ua, oid, 'delivered', 10000);
    assert(got.some((m) => m.t === 'msg' && m.text === 'hello old friend'));
    assert.strictEqual(contactOf(await ua.state(), '127.0.0.3').proto, 2);
    srv.close();
  });

  await t('TOFU: a reinstalled peer (new key) is rejected, then accepted deliberately', async () => {
    await stop(B);
    B = await up(daemon('bravo', { host: '127.0.0.2', peer: 38788, web: 38789, data: 'bravo-reinstalled' }));
    ub = await ui(B);
    const rid = await sent(ua, '127.0.0.2', 38788, 'after the reinstall');
    const sec = await ua.wait((m) => m.type === 'security' && m.kind === 'fp-mismatch');
    const c = await until(async () => { const x = contactOf(await ua.state(), '127.0.0.2'); return x.pendingFp && x; });
    assert.strictEqual(c.pendingFp.got, sec.got); assert.notStrictEqual(c.peerFp, sec.got);
    // Without this launch's action token the accept is refused outright...
    ua.sendBare({ type: 'contact.acceptKey', host: '127.0.0.2', fp: sec.got });
    const refused = await ua.wait((m) => m.type === 'error' && m.op === 'contact.acceptKey');
    assert.strictEqual(refused.code, 'bad-token');
    ua.send({ type: 'contact.acceptKey', host: '127.0.0.2', fp: sec.got, token: 'a-guessed-token' });
    assert.strictEqual((await ua.wait((m) => m.type === 'error' && m.op === 'contact.acceptKey')).code, 'bad-token');
    assert(contactOf(await ua.state(), '127.0.0.2').pendingFp, 'still pending after the refused accepts');
    // ...and with the token, a fingerprint that is not the presented one is refused too.
    ua.send({ type: 'contact.acceptKey', host: '127.0.0.2', fp: 'not-the-key' });
    const wrong = await ua.wait((m) => m.type === 'error' && m.op === 'contact.acceptKey');
    assert.notStrictEqual(wrong.code, 'bad-token');
    ua.send({ type: 'contact.acceptKey', host: '127.0.0.2', fp: sec.got });
    await status(ua, rid, 'delivered', 10000);
    const after = contactOf(await ua.state(), '127.0.0.2');
    assert.strictEqual(after.peerFp, sec.got); assert.strictEqual(after.pendingFp, null);
  });

  await t('at rest: with a passphrase set, text never reaches state.json in the clear', async () => {
    ua.send({ type: 'vault.set', passphrase: 'short' });
    await ua.wait((m) => m.type === 'error' && m.op === 'vault.set');
    ua.send({ type: 'vault.set', passphrase: 'correct horse battery' });
    await ua.wait((m) => m.type === 'vault' && m.ok, 15000);
    await status(ub, await sent(ub, '127.0.0.1', 28788, 'SECRET-AFTER-VAULT'), 'delivered');
    await sleep(400);
    const disk = fs.readFileSync(path.join(A.dataDir, 'state.json'), 'utf8');
    assert(!disk.includes('SECRET-AFTER-VAULT'), 'new message in clear');
    assert(!disk.includes('hello over Noise XX'), 'old message not migrated');
    assert(disk.includes('"sealed"'));
  });

  await t('at rest: after a restart A is locked, still receives, and unlocks with the passphrase', async () => {
    await stop(A);
    A = await up(daemon('alpha', { host: '127.0.0.1', peer: 28788, web: 28789, rpc: true }));
    ua = await ui(A);
    let st = await ua.state();
    assert.deepStrictEqual(st.daemon.vault, { set: true, unlocked: false });
    const msgs = contactOf(st, '127.0.0.2').msgs;
    assert(msgs.length && msgs.every((m) => m.text == null && m.lockKind === 'vault'));
    await status(ub, await sent(ub, '127.0.0.1', 28788, 'sent while you were locked'), 'delivered');
    ua.send({ type: 'vault.unlock', passphrase: 'wrong passphrase!' });
    await ua.wait((m) => m.type === 'error' && m.op === 'vault.unlock', 15000);
    await sleep(1100);                                         // back-off after a wrong guess
    ua.send({ type: 'vault.unlock', passphrase: 'correct horse battery' });
    await ua.wait((m) => m.type === 'vault' && m.ok, 15000);
    st = await ua.state();
    const texts = contactOf(st, '127.0.0.2').msgs.map((m) => m.text);
    assert(texts.includes('hello over Noise XX\nsecond line') && texts.includes('sent while you were locked'), JSON.stringify(texts));
  });

  await t('malformed input never takes the daemon down; strangers leave no state', async () => {
    const before = Object.keys(JSON.parse(fs.readFileSync(path.join(A.dataDir, 'state.json'), 'utf8')).contacts).length;
    const junk = [Buffer.from([0, 0, 0, 0]), Buffer.from([0xff, 0xff, 0xff, 0xff, 1]), frame(crypto_random(33)), frame(crypto_random(44)), Buffer.from('GET / HTTP/1.1\r\n\r\n')];
    for (const j of junk) { const s = net.connect({ host: '127.0.0.1', port: 28788, localAddress: '127.0.0.20' }); s.on('error', () => { }); s.write(j); await sleep(50); s.destroy(); }
    // a stranger that completes a v3 handshake and then sends garbage
    const id = noise.loadIdentity(noise.newIdentity());
    await new Promise((res) => {
      const s = net.connect({ host: '127.0.0.1', port: 28788, localAddress: '127.0.0.21' }); let st; s.on('error', res); s.on('close', res);
      s.on('connect', () => { st = noise.v3.initStart(id); s.write(frame(st.msg1)); });
      frames(s, (p) => { const r = noise.v3.initFinish(st, p); s.write(frame(r.msg3)); s.write(frame(crypto_random(40))); setTimeout(() => s.destroy(), 200); });
    });
    await sleep(300);
    assert(await health(A), 'daemon is still up');
    const after = Object.keys(JSON.parse(fs.readFileSync(path.join(A.dataDir, 'state.json'), 'utf8')).contacts).length;
    assert.strictEqual(after, before);
  });

  await t('hostile hello fields are cleaned', async () => {
    const id = noise.loadIdentity(noise.newIdentity());
    const cl = await legacyClient('127.0.0.2', 38788, id, () => { }, '127.0.0.13');
    cl.send({ t: 'hello', proto: 2, nick: '<img src=x>\u0000\u001b[31m' + 'x'.repeat(500), peerPort: 'nope',
      node: { ua: 'u'.repeat(5000), impl: 42, declared: ['BIP-1', { x: 1 }], height: 'tall', __proto__: { polluted: true } } });
    cl.send({ t: 'msg', id: '../../etc', ts: 'yesterday', text: 'x'.repeat(10000) });
    await sleep(500); cl.close();
    const c = (await ub.state()).contacts.find((x) => x.nick && x.nick.startsWith('<img'));
    assert(c, 'contact created');
    assert(c.nick.length <= 60 && !/[\u0000-\u001f]/.test(c.nick));
    assert.strictEqual(c.port, 38788);               // invalid peerPort ignored (default kept)
    assert(c.peerInfo.ua.length <= 256 && c.peerInfo.impl === 'Unknown' && c.peerInfo.height === null);
    assert.deepStrictEqual(c.peerInfo.declared, ['BIP-1']);
    const m = c.msgs.at(-1);
    assert(m.text.length === 4000 && m.id !== '../../etc' && Number.isFinite(m.ts));
  });

  ua.close(); ub.close();
  for (const k of [...kids]) await stop(k);
  rpc.close();
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
  process.exit(failed ? 1 : 0);
})().catch(async (e) => { console.error(e); for (const k of kids) k.kill('SIGKILL'); process.exit(1); });

function crypto_random(n) { return require('crypto').randomBytes(n); }
