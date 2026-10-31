// network.test.js: the 1.4 features between real daemons. Plain node.
//   node tests/network.test.js
// Three daemons on separate loopback addresses (A, B, C), each told its own
// address as public-host, the way an onion would be: contact links that pin
// the key before the first connection, posts and their two-hop spread,
// rooms joined by link, a mailbox holding sealed mail for an unreachable
// operator, introductions, identity backup, and several Tor peers arriving
// from 127.0.0.1. Daemons dial each other from 127.0.0.1, which reads as Tor,
// so a daemon files a peer that calls first under "tor:<its fingerprint>"
// until its operator adds that peer's link. Last, peers from 127.0.0.1 that
// claim an address or an onion in their hello, through a mock SOCKS proxy
// and a mock node. Ports 26000-26099.
'use strict';
const fs = require('fs'), path = require('path'), assert = require('assert'), net = require('net');
const H = require('./harness.js');
const backup = require('../backup.js');
const noise = require('../noise.js');
const { rpcServer, p2pServer } = require('./mock-node.js');
const { until, sleep, ui, contactOf, sent, status } = H;

const S = H.suite('ns-net-');
const t = S.t;
const ADDR = { A: '127.0.0.21', B: '127.0.0.22', C: '127.0.0.23' };
const PORT = { A: 26001, B: 26011, C: 26021 };
const WEB = { A: 26002, B: 26012, C: 26022 };
const start = (n, extra = []) => H.up(S.daemon('d' + n, { host: ADDR[n], peer: PORT[n], web: WEB[n],
  extra: ['--public-host', ADDR[n], '--discoverable', ...extra] }));
const fpOf = async (u) => (await u.state()).daemon.fingerprint;
const shareOf = async (u) => { u.send({ type: 'share.get' }); return u.wait((m) => m.type === 'share'); };

(async () => {
  let A = await start('A'), B = await start('B'), C = await start('C');
  let ua = await ui(A), ub = await ui(B), uc = await ui(C);
  const fp = { A: await fpOf(ua), B: await fpOf(ub), C: await fpOf(uc) };

  await t('share link: address, port, key and nick, and a QR code of it', async () => {
    const s = await shareOf(ua);
    assert.strictEqual(s.link, `nodesignal:${ADDR.A}?port=${PORT.A}&fp=${fp.A}&nick=dA`);
    assert(/^<svg[^>]*viewBox/.test(s.svg) && /<path /.test(s.svg), 'an SVG with a path');
  });

  await t('adding a contact by link pins its key before the first connection', async () => {
    const s = await shareOf(ua);
    ub.send({ type: 'contact.add', link: s.link });
    const c = await until(async () => contactOf(await ub.state(), ADDR.A));
    assert.strictEqual(c.peerFp, fp.A, 'pinned from the link');
    assert.strictEqual(c.pinnedBy, 'link');
    assert.strictEqual(c.nick, 'dA');
    const id = await sent(ub, ADDR.A, PORT.A, 'hello by link');
    await status(ub, id, 'delivered', 8000);
  });

  await t('a peer that called from 127.0.0.1 is filed under its key; adding its link moves the conversation to its address', async () => {
    let st = await ua.state();
    const k = contactOf(st, 'tor:' + fp.B);
    assert(k, 'B called A from 127.0.0.1: kept as tor:<fingerprint>, not as the address it names');
    assert(!contactOf(st, ADDR.B), 'no contact under the public-host B names');
    assert(k.msgs.some((m) => m.text === 'hello by link'));
    ua.send({ type: 'contact.add', link: (await shareOf(ub)).link });
    const c = await until(async () => { st = await ua.state(); return contactOf(st, ADDR.B); });
    assert(!contactOf(st, 'tor:' + fp.B), 'moved, not copied');
    assert.strictEqual(c.peerFp, fp.B);
    assert(c.msgs.some((m) => m.text === 'hello by link'), 'the history came with it');
    await status(ua, await sent(ua, ADDR.B, PORT.B, 'hi B, from A'), 'delivered', 8000);
  });

  await t('a link with the wrong key is not trusted: the real key is held for review', async () => {
    const bad = `nodesignal:${ADDR.C}?port=${PORT.C}&fp=${'0'.repeat(32)}&nick=fake`;
    ua.send({ type: 'contact.add', link: bad });
    await until(async () => contactOf(await ua.state(), ADDR.C));
    ua.send({ type: 'chat.send', host: ADDR.C, port: PORT.C, text: 'are you who the link says?' });
    const c = await until(async () => { const x = contactOf(await ua.state(), ADDR.C); return x.pendingFp && x; }, 10000);
    assert.strictEqual(c.pendingFp.got, fp.C);
    assert.strictEqual(c.peerFp, '0'.repeat(32));
    // the operator removes it and adds the right link
    ua.send({ type: 'contact.remove', host: ADDR.C });
    await ua.wait((m) => m.type === 'contact.removed');
  });

  // B-C established too, so the graph is A - B - C
  await t('B and C become contacts by link', async () => {
    const s = await shareOf(uc);
    ub.send({ type: 'contact.add', link: s.link });
    const id = await sent(ub, ADDR.C, PORT.C, 'hi C');
    await status(ub, id, 'delivered', 8000);
    uc.send({ type: 'contact.add', link: (await shareOf(ub)).link });
    await until(async () => contactOf(await uc.state(), ADDR.B));
    const back = await sent(uc, ADDR.B, PORT.B, 'hi B');
    await status(uc, back, 'delivered', 8000);
  });

  await t('posts: signed, pushed to contacts, and passed on one more hop', async () => {
    ua.send({ type: 'post.create', text: 'first post from A' });
    await ua.wait((m) => m.type === 'posted');
    const p = await until(async () => (await ub.state()).feed.find((x) => x.text === 'first post from A'), 10000);
    assert.strictEqual(p.hops, 1);
    assert.strictEqual(p.contact.host, ADDR.A, 'B knows the signing key is A\'s, from A\'s own hello');
    // C learns it from B on their next link (C never talks to A)
    uc.send({ type: 'sync.now' });
    const q = await until(async () => (await uc.state()).feed.find((x) => x.text === 'first post from A'), 10000);
    assert.strictEqual(q.hops, 2);
    assert.strictEqual(q.contact, null, 'C has never met A: shown by key only');
    assert.strictEqual(q.via, 'dB');
  });

  await t('posts: never more than two hops, and a forged copy is dropped', async () => {
    uc.send({ type: 'post.create', text: 'post from C' });
    await uc.wait((m) => m.type === 'posted');
    await until(async () => (await ub.state()).feed.find((x) => x.text === 'post from C'), 10000);
    ua.send({ type: 'sync.now' });
    const r = await until(async () => (await ua.state()).feed.find((x) => x.text === 'post from C'), 10000);
    assert.strictEqual(r.hops, 2);
    const st = await ua.state();
    assert(!st.feed.some((x) => x.text === 'first post from A' && !x.mine), 'A does not store its own post twice');
  });

  let roomId, roomLink;
  await t('rooms: create, invite by link, join, talk; everyone has the history', async () => {
    ua.send({ type: 'room.create', name: 'relay policy' });
    roomId = (await ua.wait((m) => m.type === 'room.created')).room;
    ua.send({ type: 'room.invite', room: roomId });
    roomLink = (await ua.wait((m) => m.type === 'room.invite')).link;
    assert(roomLink.startsWith('nodesignal-room:' + roomId + '?'));
    ub.send({ type: 'room.join', link: roomLink });
    await until(async () => (await ub.state()).rooms.find((r) => r.room === roomId), 10000);
    await until(async () => (await ua.state()).rooms.find((r) => r.room === roomId).members.length === 2, 10000);
    ub.send({ type: 'room.send', room: roomId, text: 'B says hi to the room' });
    await until(async () => (await ua.state()).rooms.find((r) => r.room === roomId).msgs.some((m) => m.text === 'B says hi to the room'), 10000);
    // C joins later through the same link and gets the history
    uc.send({ type: 'room.join', link: roomLink });
    const rc = await until(async () => { const r = (await uc.state()).rooms.find((x) => x.room === roomId); return r && r.msgs.length && r; }, 10000);
    assert(rc.msgs.some((m) => m.text === 'B says hi to the room'));
    uc.send({ type: 'room.send', room: roomId, text: 'C here' });
    await until(async () => (await ub.state()).rooms.find((r) => r.room === roomId).msgs.some((m) => m.text === 'C here'), 10000);
    await until(async () => (await ua.state()).rooms.find((r) => r.room === roomId).msgs.some((m) => m.text === 'C here'), 10000);
  });

  await t('introductions: discoverable contacts introduce each other, with keys', async () => {
    ua.send({ type: 'sync.now' });
    await ua.wait((m) => m.type === 'synced');
    const intro = await until(async () => (await ua.state()).introductions.find((x) => x.fp === fp.C), 10000);
    assert.strictEqual(intro.host, ADDR.C);
    assert.deepStrictEqual(intro.via, ['dB']);
    ua.send({ type: 'intro.add', fp: fp.C });
    const c = await until(async () => { const x = contactOf(await ua.state(), ADDR.C); return x && !x.hidden && x; }, 5000);
    assert.strictEqual(c.peerFp, fp.C, 'pinned from the introduction');
  });

  await t('mailbox: sealed mail waits at a third operator for someone unreachable', async () => {
    uc.send({ type: 'settings.set', key: 'mailbox', value: true });
    await until(async () => (await uc.state()).daemon.mailbox === true);
    await sent(ub, ADDR.C, PORT.C, 'C, you are my mailbox now');      // B learns C serves one
    await until(async () => contactOf(await ub.state(), ADDR.C).servesMailbox);
    ub.send({ type: 'mailbox.use', fp: fp.C });
    await until(async () => (await ub.state()).daemon.myMailboxes.some((x) => x.ok), 10000);
    await sent(ub, ADDR.A, PORT.A, 'A, my mailbox is at C');           // A learns B's mailbox
    await until(async () => contactOf(await ua.state(), ADDR.B).hasMailbox, 10000);
    // B goes away; it comes back somewhere A cannot dial (behind NAT)
    await H.stop(B); ub.close();
    const id = await sent(ua, ADDR.B, PORT.B, 'sealed for B');
    const held = await status(ua, id, 'held', 20000);
    assert.strictEqual(held.heldAt, 'dC');
    const stC = await uc.state();
    assert(stC.daemon.mailboxStats.items >= 1, 'C holds it');
    assert(!JSON.stringify(stC).includes('sealed for B'), 'C cannot read it');
    B = await H.up(S.daemon('dB', { host: '127.0.0.29', peer: PORT.B, web: WEB.B, extra: ['--public-host', ADDR.B, '--discoverable'] }));
    ub = await ui(B);
    const got = await until(async () => { const c = contactOf(await ub.state(), ADDR.A); return c && c.msgs.find((m) => m.text === 'sealed for B'); }, 20000);
    assert(got, 'B fetched and opened it');
    await status(ua, id, 'delivered', 20000);
    await until(async () => (await uc.state()).daemon.mailboxStats.items === 0, 10000);
  });

  await t('identity backup: passphrase-sealed keys and contacts, no message text', async () => {
    ua.send({ type: 'backup.export', passphrase: 'correct horse battery' });
    const b = await ua.wait((m) => m.type === 'backup' || m.type === 'error', 15000);
    assert.strictEqual(b.type, 'backup', b.error);
    assert(b.text.startsWith('NodeSignal identity backup v1'));
    assert(/^nodesignal-identity-dA-\d{4}-\d\d-\d\d\.nsbackup$/.test(b.filename));
    const payload = backup.importBackup(b.text, 'correct horse battery');
    const disk = JSON.parse(fs.readFileSync(path.join(A.dataDir, 'state.json'), 'utf8'));
    assert.deepStrictEqual(payload.identity, disk.identity);
    assert.deepStrictEqual(payload.signKey, disk.signKey);
    assert(payload.contacts.some((c) => c.peerFp === fp.B));
    assert(!b.text.includes('first post') && !JSON.stringify(payload).includes('hello by link'), 'no history in the backup');
    ua.send({ type: 'backup.export', passphrase: 'short' });
    assert.strictEqual((await ua.wait((m) => m.type === 'error')).type, 'error');
  });

  await t('Tor: several peers arriving from 127.0.0.1 are told apart by key, each keeping the onion it named', async () => {
    // each raw client says hello with its own onion, the way Tor hands peers over locally
    const onion = (ch) => ch.repeat(56) + '.onion';
    const peers = {};
    for (const ch of ['a', 'b']) {
      const got = [];
      const cl = await H.v3Client(ADDR.A, PORT.A, (m) => { got.push(m); if (m.t === 'msg') cl.send({ t: 'ack', id: m.id }); }, '127.0.0.1');
      cl.got = got;
      cl.send({ t: 'hello', proto: 3, nick: 'tor-' + ch, peerPort: 8788, onion: onion(ch), caps: [] });
      cl.send({ t: 'msg', id: 'tor-msg-' + ch, ts: Date.now(), text: 'over tor ' + ch });
      peers[ch] = cl;
    }
    const key = (ch) => 'tor:' + peers[ch].id.fp;
    const st = await until(async () => { const s = await ua.state(); return contactOf(s, key('a')) && contactOf(s, key('b')) && s; }, 8000);
    for (const ch of ['a', 'b']) {
      const k = contactOf(st, key(ch));
      assert(k.msgs.some((m) => m.text === 'over tor ' + ch));
      assert.strictEqual(k.nick, 'tor-' + ch);
      assert.strictEqual(k.onion, onion(ch), 'the onion is kept as a way back through Tor');
      assert(!k.pendingFp, 'no key-change alarm for a different Tor peer');
      assert(!contactOf(st, onion(ch)), 'nothing is filed under the onion a peer names');
    }
    // a reply goes back over that peer's own open link
    const rid = await sent(ua, key('b'), 8788, 'back to you, b');
    await status(ua, rid, 'delivered', 5000);
    assert(peers.b.got.some((m) => m.t === 'msg' && m.text === 'back to you, b'));
    assert(!peers.a.got.some((m) => m.t === 'msg'));
    for (const p of Object.values(peers)) p.close();
  });

  await t('a peer from 127.0.0.1 cannot claim an address: not a contact you wrote to, not one to dial or identify', async () => {
    // The operator writes to a map peer where no NodeSignal answers: it waits, no key pinned.
    const X = '198.51.100.7';
    const xid = await sent(ua, X, 26099, 'meet at 9, the key is under the mat');
    // Something listens where a second claimer says it can be reached.
    const knocks = [];
    const trap = net.createServer((s) => { knocks.push(s.remoteAddress); s.destroy(); });
    await new Promise((r) => trap.listen(26098, '127.0.0.9', r));
    const got = [], got2 = [];
    const M = await H.v3Client(ADDR.A, PORT.A, (m) => { got.push(m); if (m.t === 'msg') M.send({ t: 'ack', id: m.id }); }, '127.0.0.1');
    M.send({ t: 'hello', proto: 3, nick: 'alice', pub: X, peerPort: 26099, caps: [] });
    M.send({ t: 'msg', id: 'claim-1', ts: Date.now(), text: 'it is me, the operator of ' + X });
    const M2 = await H.v3Client(ADDR.A, PORT.A, (m) => { got2.push(m); if (m.t === 'msg') M2.send({ t: 'ack', id: m.id }); }, '127.0.0.1');
    M2.send({ t: 'hello', proto: 3, nick: 'x', pub: '127.0.0.9', peerPort: 26098, caps: [] });
    M2.send({ t: 'msg', id: 'claim-2', ts: Date.now(), text: 'call me back' });
    await sleep(2500);
    assert(!got.some((m) => m.t === 'msg'), 'the waiting message went to the peer that claimed its address');
    let st = await ua.state();
    const x = contactOf(st, X);
    assert.strictEqual(x.peerFp, null, 'the claimer\'s key was pinned on the address it claimed');
    assert.notStrictEqual(x.msgs.find((m) => m.id === xid).status, 'delivered');
    assert(contactOf(st, 'tor:' + M.id.fp).msgs.some((m) => m.text.startsWith('it is me')), 'the claimer is filed under its own key');
    assert(!contactOf(st, '127.0.0.9'), 'nothing is filed (or identified) under a claimed address');
    // A reply to the second goes over its own link; nothing ever calls the address it named.
    await status(ua, await sent(ua, 'tor:' + M2.id.fp, 26098, 'hello x'), 'delivered', 5000);
    assert(got2.some((m) => m.t === 'msg' && m.text === 'hello x'));
    M.close(); M2.close();
    await sleep(1500);
    assert.deepStrictEqual(knocks, [], 'the daemon connected to an address a peer only claimed');
    trap.close();
    st = await ua.state();
    assert.strictEqual(contactOf(st, X).peerFp, null);
  });

  await t('an onion named in a hello is reached only through Tor, where the claimer\'s key must answer: no node proof, no key alarm', async () => {
    // The onion is C's: C's NodeSignal and C's Bitcoin node answer there, through
    // a mock SOCKS proxy. D's node has it as a peer, which the old "same onion"
    // check took as proof once :8333 answered.
    const ONION = 'nodesignalclaimedonion'.padEnd(56, 'c') + '.onion';
    const rpc = await rpcServer({ port: 26061, npeers: 2 });
    rpc.peers.push({ addr: ONION + ':8333', subver: '/Satoshi:29.0.0/', pingtime: 0.2, inbound: false, synced_headers: 950000, network: 'onion' });
    const node = await p2pServer({ port: 26071, host: '127.0.0.24' });
    const routes = { [ONION + ':' + PORT.C]: { host: ADDR.C, port: PORT.C }, [ONION + ':8333']: { host: '127.0.0.24', port: 26071 } };
    const proxy = await socksProxy(26051, routes);
    const D = await H.up(S.daemon('dD', { host: '127.0.0.25', peer: 26041, web: 26042, rpc: 26061, extra: ['--tor-proxy', '127.0.0.1:26051'] }));
    const ud = await ui(D);
    try {
      const M = await H.v3Client('127.0.0.25', 26041, () => { }, '127.0.0.1');
      M.send({ t: 'hello', proto: 3, nick: 'satoshi', onion: ONION, peerPort: PORT.C, caps: [] });
      M.send({ t: 'msg', id: 'onion-claim', ts: Date.now(), text: 'that node is mine' });
      const key = 'tor:' + M.id.fp;
      await until(async () => contactOf(await ud.state(), key), 5000);
      M.close();
      await sleep(3000);                    // where the old code identified the claimed onion and called it proven
      let st = await ud.state();
      assert(!contactOf(st, ONION), 'nothing is filed under the claimed onion');
      assert.strictEqual(contactOf(st, key).nodeProof, null);
      assert(!proxy.requests.includes(ONION + ':8333'), 'the claimed onion was identified');
      // The operator replies. The link is gone, so D calls the onion through Tor, and C answers with its own key.
      const rid = await sent(ud, key, PORT.C, 'did you mean it?');
      await until(() => proxy.requests.includes(ONION + ':' + PORT.C), 15000);
      const k = await until(async () => { const y = contactOf(await ud.state(), key); return !y.onion && y; }, 15000);
      assert.strictEqual(k.pendingFp, null, 'another key at a claimed onion is not a key change to review');
      assert.strictEqual(k.nodeProof, null);
      assert.notStrictEqual(k.msgs.find((m) => m.id === rid).status, 'delivered');
      st = await uc.state();
      assert(!st.contacts.some((c) => c.msgs.some((m) => m.text === 'did you mean it?')), 'the onion\'s real owner got the reply');
      // A peer whose onion is its own: the reply reaches it there, through Tor.
      const ONION2 = 'nodesignalhonestonion'.padEnd(56, 'h') + '.onion';
      const P = noise.loadIdentity(noise.newIdentity()), pgot = [];
      const psrv = await H.v3Server('127.0.0.26', 26081, (m, reply) => {
        pgot.push(m);
        if (m.t === 'hello') reply({ t: 'hello', proto: 3, nick: 'honest', peerPort: 26081, caps: [] });
        if (m.t === 'msg') reply({ t: 'ack', id: m.id });
      }, P);
      routes[ONION2 + ':26081'] = { host: '127.0.0.26', port: 26081 };
      try {
        const P1 = await H.v3Client('127.0.0.25', 26041, () => { }, '127.0.0.1', P);
        P1.send({ t: 'hello', proto: 3, nick: 'honest', onion: ONION2, peerPort: 26081, caps: [] });
        P1.send({ t: 'msg', id: 'honest-1', ts: Date.now(), text: 'reach me at my onion' });
        await until(async () => contactOf(await ud.state(), 'tor:' + P.fp), 5000);
        P1.close();
        await sleep(300);
        await status(ud, await sent(ud, 'tor:' + P.fp, 26081, 'here you are'), 'delivered', 15000);
        assert(proxy.requests.includes(ONION2 + ':26081'), 'not through Tor');
        assert(pgot.some((m) => m.t === 'msg' && m.text === 'here you are'));
        assert.strictEqual(contactOf(await ud.state(), 'tor:' + P.fp).onion, ONION2, 'its own onion is kept');
      } finally { await psrv.shut(); }
    } finally {
      ud.close(); await H.stop(D);
      await new Promise((r) => proxy.close(r)); rpc.close(); node.close();
    }
  });

  ua.close(); ub.close(); uc.close();
  await S.finish();
})().catch(S.abort);

// A SOCKS5 proxy (RFC 1928, no auth, domain names only) that records each
// CONNECT and relays "host:port" to a route, the way Tor reaches an onion.
function socksProxy(port, routes) {
  const requests = [], conns = new Set();
  const srv = net.createServer((c) => {
    conns.add(c); c.on('close', () => conns.delete(c)); c.on('error', () => { });
    let buf = Buffer.alloc(0), stage = 0;
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        buf = buf.subarray(2 + buf[1]); stage = 1; c.write(Buffer.from([5, 0]));
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        if (buf[3] !== 3) { c.destroy(); return; }
        const alen = 1 + buf[4];
        if (buf.length < 4 + alen + 2) return;
        const host = buf.subarray(5, 4 + alen).toString('latin1'), dport = buf.readUInt16BE(4 + alen);
        const rest = buf.subarray(4 + alen + 2);
        requests.push(host + ':' + dport); stage = 2; c.removeListener('data', onData);
        const rt = routes[host + ':' + dport];
        if (!rt) { c.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        const up = net.connect(rt);
        up.on('error', () => c.destroy()); c.on('close', () => up.destroy()); up.on('close', () => c.destroy());
        up.on('connect', () => { c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0])); if (rest.length) up.write(rest); c.pipe(up); up.pipe(c); });
      }
    };
    c.on('data', onData);
  });
  srv.requests = requests;
  const close = srv.close.bind(srv);
  srv.close = (cb) => { for (const c of conns) c.destroy(); close(cb); };
  return new Promise((r) => srv.listen(port, '127.0.0.1', () => r(srv)));
}
