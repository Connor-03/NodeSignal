// established.test.js: what "established" means, and that history outlives the peer.
//   node tests/established.test.js     (Linux: needs 127.0.0.2 and 127.0.0.3 on loopback)
// CLAUDE.md section 4: a solid line means a confirmed two-way NodeSignal
// exchange (their daemon acked our message, or sent us one). An inbound hello
// alone does NOT count. Established persists after they go offline, and
// messages are never tied to the live getpeerinfo list.
// Ports: mock RPC 44720, daemons 44721 to 44724, a raw peer on 127.0.0.3:44725.
'use strict';
const fs = require('fs'), path = require('path');
const assert = require('assert');
const { rpcServer } = require('./mock-node.js');
const H = require('./harness.js');
const { sleep, until, up, ui, contactOf, sent, status, contactsOnDisk, v3Client, v3Server } = H;
const S = H.suite('ns-est-');
const { t } = S;

(async () => {
  const rpc = await rpcServer({ port: 44720, npeers: 4 });
  // B's node is one of A's node peers (getpeerinfo), until it drops off below
  rpc.peers.push({ addr: '127.0.0.2:8333', subver: '/Satoshi:29.1.0/Knots:20250903/', pingtime: 0.03, inbound: false, synced_headers: 950000 });
  const aOpts = { host: '127.0.0.1', peer: 44721, web: 44722, rpc: 44720 };
  const bOpts = { host: '127.0.0.2', peer: 44723, web: 44724 };
  let A = await up(S.daemon('alpha', aOpts));
  let B = await up(S.daemon('bravo', bOpts));
  let ua = await ui(A), ub = await ui(B);
  let raw = null;

  await t('an inbound hello alone does not make a contact established', async () => {
    const hellos = [];
    const c = await v3Client('127.0.0.1', 44721, (m) => m.t === 'hello' && hellos.push(m), '127.0.0.31');
    c.send({ t: 'hello', proto: 3, nick: 'hello-only', peerPort: 44799 });
    const ev = await ua.wait((m) => m.type === 'contact' && m.contact.host === '127.0.0.31');
    await until(() => hellos.length === 1, 3000);            // the daemon said hello back: a live session
    c.send({ t: 'hello', proto: 3, nick: 'hello-only', peerPort: 44799 });
    c.send({ t: 'ping' });
    await sleep(300); c.close();
    assert.strictEqual(ev.contact.established, false);
    const k = contactOf(await ua.state(), '127.0.0.31');
    assert.strictEqual(k.nick, 'hello-only');
    assert.strictEqual(k.established, false, 'established after a hello');
    assert.strictEqual(k.online, false, 'online after a hello');
    await sleep(200);
    assert(!contactsOnDisk(A.dataDir)['127.0.0.31'].established, 'established on disk');
  });

  await t('a hello exchange both ways, with no message, establishes neither side', async () => {
    ua.send({ type: 'contact.add', host: '127.0.0.2', port: 44723, nick: 'bravo' });
    await ua.wait((m) => m.type === 'contact' && m.contact.host === '127.0.0.2');
    ua.send({ type: 'chat.retry', host: '127.0.0.2' });        // dials B: handshake and hellos, nothing else
    const ev = await ub.wait((m) => m.type === 'contact' && m.contact.host === '127.0.0.1');
    assert.strictEqual(ev.contact.established, false);
    const a = await until(async () => { const x = contactOf(await ua.state(), '127.0.0.2'); return x.peerFp && x; });
    assert.strictEqual(a.proto, 3);
    assert.strictEqual(a.established, false, 'A calls B established after hellos only');
    const b = contactOf(await ub.state(), '127.0.0.1');
    assert(b.peerFp, 'B pinned A');
    assert.strictEqual(b.established, false, 'B calls A established after hellos only');
    assert(!b.online && !a.online);
  });

  await t('a message the peer takes but never acknowledges does not establish it', async () => {
    const got = [];
    raw = await v3Server('127.0.0.3', 44725, (m, reply) => {
      got.push(m);
      if (m.t === 'hello') reply({ t: 'hello', proto: 3, nick: 'never-acks', peerPort: 44725 });
    });
    const id = await sent(ua, '127.0.0.3', 44725, 'are you there?');
    await until(() => got.some((m) => m.t === 'msg' && m.id === id), 5000);
    for (const s of raw.conns) s.destroy();                  // hang up without an ack
    const p = await status(ua, id, 'pending');
    assert.match(p.error, /before the peer confirmed delivery/);
    const k = contactOf(await ua.state(), '127.0.0.3');
    assert.strictEqual(k.established, false, 'established without an ack');
    assert.strictEqual(k.nick, 'never-acks');
    assert.strictEqual(k.msgs.find((m) => m.id === id).status, 'pending');
    ua.send({ type: 'chat.cancel', host: '127.0.0.3', id });
    await status(ua, id, 'failed');
    await raw.shut(); raw = null;
  });

  await t('our message acknowledged by their daemon establishes it, on both sides', async () => {
    const id = await sent(ua, '127.0.0.2', 44723, 'first real message');
    await status(ua, id, 'delivered');
    await ub.wait((m) => m.type === 'chat.recv' && m.msg.from === 'them' && m.msg.text === 'first real message');
    const a = contactOf(await ua.state(), '127.0.0.2'), b = contactOf(await ub.state(), '127.0.0.1');
    assert.strictEqual(a.established, true, 'acked: established');
    assert.strictEqual(a.online, true);
    assert.strictEqual(b.established, true, 'received: established');
    await status(ub, await sent(ub, '127.0.0.1', 44721, 'and a reply'), 'delivered');
  });

  await t('a message from them establishes the contact', async () => {
    const acks = [];
    const c = await v3Client('127.0.0.1', 44721, (m) => m.t === 'ack' && acks.push(m.id), '127.0.0.32');
    c.send({ t: 'hello', proto: 3, nick: 'talker', peerPort: 44798 });
    await ua.wait((m) => m.type === 'contact' && m.contact.host === '127.0.0.32' && !m.contact.established);
    c.send({ t: 'msg', id: 'est-1', ts: Date.now(), text: 'hi from a stranger' });
    await until(() => acks.includes('est-1'), 3000);
    c.close();
    const k = contactOf(await ua.state(), '127.0.0.32');
    assert.strictEqual(k.established, true);
    assert.strictEqual(k.online, true);
    assert.deepStrictEqual(k.msgs.map((m) => m.text), ['hi from a stranger']);
  });

  const texts = (k) => k.msgs.map((m) => [m.from, m.text, m.status]);
  let historyBefore;
  await t('history survives the peer dropping off getpeerinfo', async () => {
    let st = await ua.state();
    assert(st.node.peers.some((p) => p.addr === '127.0.0.2:8333'), 'B is a node peer to begin with');
    historyBefore = texts(contactOf(st, '127.0.0.2'));
    assert.deepStrictEqual(historyBefore.slice(-2), [['me', 'first real message', 'delivered'], ['them', 'and a reply', null]]);
    rpc.peers.splice(rpc.peers.findIndex((p) => p.addr === '127.0.0.2:8333'), 1);
    ua.send({ type: 'peers.refresh' });
    st = await ua.wait((m) => m.type === 'state');
    assert(!st.node.peers.some((p) => p.addr === '127.0.0.2:8333'), 'B left getpeerinfo');
    assert.strictEqual(st.node.peers.length, 4);
    const k = contactOf(st, '127.0.0.2');
    assert(k, 'the contact is kept');
    assert.deepStrictEqual(texts(k), historyBefore);
    assert.strictEqual(k.established, true);
  });

  await t('established persists after they go offline; online does not', async () => {
    ub.close(); await H.stop(B);
    const id = await sent(ua, '127.0.0.2', 44723, 'are you still there?');
    await status(ua, id, 'pending');
    const k = await until(async () => { const x = contactOf(await ua.state(), '127.0.0.2'); return !x.online && x; });
    assert.strictEqual(k.established, true, 'established is kept');
    assert.strictEqual(k.online, false, 'a failed dial ends online');
    ua.send({ type: 'chat.cancel', host: '127.0.0.2', id });
    await status(ua, id, 'failed');
  });

  await t('history and established survive a daemon restart', async () => {
    ua.close(); await H.stop(A);
    const disk = contactsOnDisk(A.dataDir);
    assert(disk['127.0.0.2'].established && disk['127.0.0.32'].established && !disk['127.0.0.31'].established);
    A = await up(S.daemon('alpha', aOpts)); ua = await ui(A);
    const st = await ua.state();
    const k = contactOf(st, '127.0.0.2');
    assert.deepStrictEqual(texts(k).slice(0, historyBefore.length), historyBefore);
    assert.deepStrictEqual(texts(k).at(-1), ['me', 'are you still there?', 'failed']);
    assert.strictEqual(k.established, true);
    assert.strictEqual(contactOf(st, '127.0.0.32').established, true);
    assert.deepStrictEqual(contactOf(st, '127.0.0.32').msgs.map((m) => m.text), ['hi from a stranger']);
    assert.strictEqual(contactOf(st, '127.0.0.31').established, false, 'the hello-only contact stays unestablished');
    assert.strictEqual(contactOf(st, '127.0.0.3').established, false);
  });

  ua.close();
  await S.finish(async () => { if (raw) await raw.shut(); rpc.close(); });
})().catch(S.abort);
