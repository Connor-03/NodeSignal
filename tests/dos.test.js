// dos.test.js: the peer port (:8788) under abuse. Plain node, any version.
//   node tests/dos.test.js        (Linux: uses 127.0.0.30 to 127.0.0.99 as client sources)
// A flood of connections that never complete the Noise handshake must persist
// nothing (CLAUDE.md section 5: no persisted state before a completed
// handshake), the daemon must keep answering /health, and the connection cap
// (--max-conns) and per-source rate limit (--rl-burst, --rl-refill-ms) must hold.
// Ports 24711 to 24716.
'use strict';
const net = require('net'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const assert = require('assert');
const noise = require('../noise.js');
const H = require('./harness.js');
const { sleep, until, health, up, frame, frames, v3Client } = H;
const S = H.suite('ns-dos-');
const { t } = S;

// A raw connection that records whether, and when, the daemon dropped it.
function probe(port, localAddress, onConnect) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port, localAddress });
    s.dropped = false; s.got = 0;
    s.on('error', () => { });
    s.on('data', (d) => (s.got += d.length));
    s.on('close', () => { s.dropped = true; s.droppedAt = Date.now(); });
    s.on('connect', () => { s.openedAt = Date.now(); if (onConnect) onConnect(s); resolve(s); });
    setTimeout(() => resolve(s), 2000);
  });
}
const src = (i) => '127.0.0.' + i;
const random = (n) => crypto.randomBytes(n);

// Every way of never finishing a handshake that we could think of.
const ABUSE = {
  idle: () => { },
  garbage: (s) => s.write(random(64)),
  'partial msg1': (s) => { const h = Buffer.alloc(4); h.writeUInt32BE(32); s.write(Buffer.concat([h, random(10)])); },
  'msg1 of the wrong size': (s) => s.write(frame(random(33))),
  'huge length prefix': (s) => s.write(Buffer.from([0xff, 0xff, 0xff, 0xff, 1, 2, 3])),
  'zero length frame': (s) => s.write(Buffer.from([0, 0, 0, 0])),
  'msg1, then silence': (s) => s.write(frame(noise.v3.initStart(noise.loadIdentity(noise.newIdentity())).msg1)),
  'msg1, then a forged msg3': (s) => { s.write(frame(noise.v3.initStart(noise.loadIdentity(noise.newIdentity())).msg1)); setTimeout(() => s.write(frame(random(48))), 50); },
  'legacy msg1, then silence': (s) => s.write(frame(noise.legacy.initStart(noise.loadIdentity(noise.newIdentity())).msg1)),
  'an HTTP request': (s) => s.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'),
  'one byte at a time': (s) => { let n = 0; const iv = setInterval(() => { if (s.destroyed || n++ > 20) return clearInterval(iv); s.write(Buffer.from([0])); }, 20); },
};

(async () => {
  /* ---- 1. the flood ---- */
  const F = await up(S.daemon('flood', { peer: 24711, web: 24712 }));
  await sleep(300);
  const stateFile = path.join(F.dataDir, 'state.json');
  const before = { text: fs.readFileSync(stateFile, 'utf8'), mtime: fs.statSync(stateFile).mtimeMs };

  await t('a flood of handshake-less connections persists zero contacts; /health keeps answering', async () => {
    assert.deepStrictEqual(JSON.parse(before.text).contacts, {});
    const socks = [];
    let healthy = 0, asked = 0;
    const poll = setInterval(async () => { asked++; if (await health(F)) healthy++; }, 50);
    const kinds = Object.values(ABUSE);
    // 50 sources x every kind of abuse, several rounds: well over the 128-connection cap
    for (let round = 0; round < 3; round++) {
      const batch = [];
      for (let i = 30; i < 80; i++) for (const k of kinds) batch.push(probe(24711, src(i), k));
      socks.push(...await Promise.all(batch));
      await sleep(100);
    }
    await sleep(600);
    clearInterval(poll);
    assert(socks.length > 1500, 'flood size ' + socks.length);
    assert(asked > 5 && healthy === asked, `/health answered ${healthy} of ${asked} times during the flood`);
    for (const s of socks) s.destroy();
    await sleep(300);
    const h = await health(F);
    assert(h && h.status === 'ok', 'daemon still healthy');
    assert.strictEqual(h.contacts, 0);
    assert.strictEqual(fs.readFileSync(stateFile, 'utf8'), before.text, 'state.json changed');
    assert.strictEqual(fs.statSync(stateFile).mtimeMs, before.mtime, 'state.json was rewritten');
    assert(!/TypeError|RangeError|uncaught|ERR_/i.test(F.log), 'errors in the log:\n' + F.log);
  });

  await t('a completed handshake with no hello still leaves no state', async () => {
    for (let i = 0; i < 20; i++) {
      const c = await v3Client('127.0.0.1', 24711, () => { }, src(81));
      if (i % 2) c.send({ t: 'ping' });                     // talks, but never says hello
      else c.socket.write(frame(random(40)));                // or sends an undecryptable frame
      await sleep(30); c.close();
    }
    await sleep(400);
    assert.strictEqual((await health(F)).contacts, 0);
    assert.strictEqual(fs.statSync(stateFile).mtimeMs, before.mtime, 'state.json was rewritten');
  });

  await t('after the flood a real peer still gets through (and only then is state written)', async () => {
    const c = await v3Client('127.0.0.1', 24711, () => { }, src(82));
    c.send({ t: 'hello', proto: 3, nick: 'after-the-flood', peerPort: 21700 });
    await until(async () => (await health(F)).contacts === 1, 4000);
    c.close();
    await sleep(300);
    const disk = JSON.parse(fs.readFileSync(stateFile, 'utf8')).contacts;
    assert.deepStrictEqual(Object.keys(disk), [src(82)]);
    assert.strictEqual(disk[src(82)].nick, 'after-the-flood');
  });
  await H.stop(F);

  /* ---- 2. the connection cap ---- */
  const C = await up(S.daemon('cap', { peer: 24713, web: 24714, extra: ['--max-conns', '6'] }));
  await t('--max-conns: the cap holds, and a freed slot is usable again', async () => {
    const held = [];
    for (let i = 0; i < 6; i++) held.push(await probe(24713, src(40 + i)));
    await sleep(400);
    assert(held.every((s) => !s.dropped), 'the first 6 connections are kept');
    const over = await probe(24713, src(50));
    await until(() => over.dropped, 1500, 20);
    assert.strictEqual(over.got, 0, 'a capped connection is sent nothing');
    await assert.rejects(v3Client('127.0.0.1', 24713, () => { }, src(51)), /closed during the handshake|ECONNRESET/);
    assert(await health(C), 'web console unaffected by a full peer port');
    held[0].destroy(); held[1].destroy();
    await sleep(200);
    const c = await v3Client('127.0.0.1', 24713, () => { }, src(52));  // a full handshake now succeeds
    assert(c.peerFp);
    c.close();
    for (const s of held) s.destroy();
  });
  await H.stop(C);

  /* ---- 3. the per-source rate limit ---- */
  const R = await up(S.daemon('rate', { peer: 24715, web: 24716, extra: ['--rl-burst', '3', '--rl-refill-ms', '1500'] }));
  await t('--rl-burst / --rl-refill-ms: one source gets its burst, then waits; others are unaffected', async () => {
    const a = [];
    for (let i = 0; i < 3; i++) a.push(await probe(24715, src(60)));
    const fourth = await probe(24715, src(60));
    await until(() => fourth.dropped, 1000, 20);
    await sleep(150);
    assert(a.every((s) => !s.dropped), 'the burst is allowed');
    // a different /32 has its own bucket
    const other = []; for (let i = 0; i < 3; i++) other.push(await probe(24715, src(61)));
    await sleep(200);
    assert(other.every((s) => !s.dropped), 'another source is not limited');
    // closing connections does not give tokens back: the limit is on new connections
    for (const s of a) s.destroy();
    await sleep(100);
    const again = await probe(24715, src(60));
    await until(() => again.dropped, 1000, 20);
    // after one refill period, exactly one more
    await sleep(1600);
    const refilled = await probe(24715, src(60));
    const extra = await probe(24715, src(60));
    await until(() => extra.dropped, 1000, 20);
    await sleep(150);
    assert(!refilled.dropped, 'one token after a refill period');
    for (const s of [...other, refilled]) s.destroy();
    assert(await health(R));
  });

  await S.finish();
})().catch(S.abort);
