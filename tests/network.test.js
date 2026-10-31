// network.test.js: the 1.4 features between real daemons. Plain node.
//   node tests/network.test.js
// Three daemons on separate loopback addresses (A, B, C), each told its own
// address as public-host, the way an onion would be: contact links that pin
// the key before the first connection, posts and their two-hop spread,
// rooms joined by link, a mailbox holding sealed mail for an unreachable
// operator, introductions, identity backup, and several Tor peers arriving
// from 127.0.0.1. Ports 26000-26099.
'use strict';
const fs = require('fs'), path = require('path'), assert = require('assert');
const H = require('./harness.js');
const backup = require('../backup.js');
const noise = require('../noise.js');
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

  await t('Tor: several peers arriving from 127.0.0.1 are told apart by key and onion', async () => {
    // each raw client says hello with its own onion, the way Tor hands peers over locally
    const onion = (ch) => ch.repeat(56) + '.onion';
    const peers = [];
    for (const ch of ['a', 'b']) {
      const cl = await H.v3Client(ADDR.A, PORT.A, () => { }, '127.0.0.1');
      cl.send({ t: 'hello', proto: 3, nick: 'tor-' + ch, peerPort: 8788, onion: onion(ch), caps: [] });
      cl.send({ t: 'msg', id: 'tor-msg-' + ch, ts: Date.now(), text: 'over tor ' + ch });
      peers.push(cl);
    }
    const st = await until(async () => { const s = await ua.state(); return contactOf(s, onion('a')) && contactOf(s, onion('b')) && s; }, 8000);
    assert(contactOf(st, onion('a')).msgs.some((m) => m.text === 'over tor a'));
    assert(contactOf(st, onion('b')).msgs.some((m) => m.text === 'over tor b'));
    assert(!contactOf(st, onion('b')).pendingFp, 'no key-change alarm for a different Tor peer');
    for (const p of peers) p.close();
  });

  ua.close(); ub.close(); uc.close();
  await S.finish();
})().catch(S.abort);
