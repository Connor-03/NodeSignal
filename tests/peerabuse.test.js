// peerabuse.test.js: what a peer on :8788 can make a daemon do. Plain node, Node 22.
//   node tests/peerabuse.test.js     (Linux: raw peers dial from 127.0.0.x and 127.0.2.x)
// From a review of the 1.4 protocol (Oct 2026); each test fails on the code
// before its fix: a room link naming "__proto__", room member entries that
// pin their key on a contact you wrote to (and how many contacts they may
// make), floods of posts, a peer that asks and never reads, batches too big
// for one Noise frame, strangers treated as contacts after one message,
// introductions nobody asked for, signing keys borrowed from someone else,
// mailbox slots and disk writes, and the rate limiter's eviction.
// Raw peers come from 127.0.0.x, never 127.0.0.1 (that is Tor to a daemon).
// Ports 25100-25199.
'use strict';
const fs = require('fs'), path = require('path'), net = require('net'), vm = require('vm'), crypto = require('crypto');
const assert = require('assert');
const H = require('./harness.js');
const noise = require('../noise.js');
const social = require('../social.js');
const { until, sleep, ui, contactOf, sent } = H;
const S = H.suite('ns-abuse-');
const { t } = S;

const newId = () => noise.loadIdentity(noise.newIdentity());
const newSk = () => social.loadSigningKey(social.newSigningKey());
const blob = (n) => { const b = crypto.randomBytes(n); b[0] = 1; return b.toString('base64'); };
const rss = (pid) => Number(/VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${pid}/status`, 'utf8'))[1]) / 1024;
const rid = () => 'm-' + crypto.randomBytes(6).toString('hex');

// A raw v3 peer. It says hello with a signing key and that key's proof for
// its own Noise key (unless hello overrides them), records every frame and
// acknowledges messages. Resolves once the daemon has said hello back.
async function peer(d, localAddress, { id = newId(), sk = newSk(), hello = {} } = {}) {
  const got = [];
  const p = await H.v3Client(d.host, d.peer, (m) => { got.push(m); if (m.t === 'msg') p.send({ t: 'ack', id: m.id }); }, localAddress, id);
  p.got = got; p.sk = sk;
  p.hello = (extra = {}) => p.send(Object.assign({ t: 'hello', proto: 3, nick: 'peer', peerPort: 25199,
    caps: ['social1', 'rooms1', 'mbox1', 'who1'], sk: sk.pub, skp: social.bindKey(sk, id.fp) }, hello, extra));
  p.next = (pred, ms = 5000) => until(() => got.find(pred), ms, 20);
  p.hello();
  await p.next((m) => m.t === 'hello');
  return p;
}
// One the operator added, by address and key, that has exchanged a message:
// what the daemon calls a trusted contact.
async function trustedPeer(d, u, localAddress, opts = {}) {
  const id = opts.id || newId();
  u.send({ type: 'contact.add', host: localAddress, port: 25199, fp: id.fp, nick: opts.nick || 'friend' });
  await until(async () => contactOf(await u.state(), localAddress));
  const p = await peer(d, localAddress, Object.assign({}, opts, { id }));
  p.send({ t: 'msg', id: rid(), ts: Date.now(), text: 'hi, it is me' });
  await p.next((m) => m.t === 'ack');
  return p;
}
// Count UI events of a type until none comes for a while.
async function countEvents(u, pred, quietMs = 1500) {
  let n = 0;
  try { for (;;) { await u.wait(pred, quietMs); n++; } } catch { }
  return n;
}

(async () => {
  const V = await H.up(S.daemon('victim', { peer: 25101, web: 25102, extra: ['--discoverable', '--mailbox'] }));
  const uv = await ui(V);

  /* ---- prototype keys (review D, A) ---- */
  await t('a room link cannot name "__proto__", "constructor" or "prototype" as its host', async () => {
    const E = newId();
    await sent(uv, '198.51.100.9', 25198, 'MARKER-ONE-TWO-THREE');
    for (const host of ['__proto__', 'constructor', 'prototype']) {
      uv.send({ type: 'room.join', link: `nodesignal-room:${'ab'.repeat(16)}?name=chat&host=${host}&port=25197&fp=${E.fp}` });
      const r = await uv.wait((m) => (m.type === 'error' && m.op === 'room.join') || m.type === 'room.joining');
      assert.strictEqual(r.type, 'error', host + ' was taken as a room host');
    }
    for (const host of ['__proto__', 'constructor', 'prototype', 'a_b']) {
      uv.send({ type: 'chat.send', host, port: 25197, text: 'x' });
      assert.match((await uv.wait((m) => m.type === 'error' && m.op === 'chat.send')).error, /not a valid address/, host);
    }
    // the key from the link gets nothing: no contact took it from Object.prototype
    const p = await peer(V, '127.0.0.40', { id: E });
    await sleep(800);
    assert(!p.got.some((m) => m.t === 'msg'), 'a waiting message went to the key in the room link');
    p.close();
    assert.strictEqual(contactOf(await uv.state(), '198.51.100.9').peerFp, null);
  });

  await t('a state.json with a "__proto__" contact loads without it', async () => {
    const E = newId();
    fs.mkdirSync(path.join(S.TMP, 'protostate'), { recursive: true });
    // written by hand: an object literal would set the prototype instead of a key
    fs.writeFileSync(path.join(S.TMP, 'protostate', 'state.json'), `{"contacts":{"__proto__":{"host":"__proto__","port":25197,"peerFp":"${E.fp}","msgs":[]},`
      + `"198.51.100.10":{"host":"198.51.100.10","port":25197,"nick":"","msgs":[{"id":"q1","from":"me","ts":${Date.now()},"status":"pending","text":"MARKER-FOUR"}],"unread":0,"lastSeen":0,"peerInfo":null}}}`);
    const X = await H.up(S.daemon('protoX', { peer: 25121, web: 25122, data: 'protostate' }));
    const ux = await ui(X);
    try {
      const st = await ux.state();
      assert(!st.contacts.some((c) => c.host === '__proto__'), 'a "__proto__" contact was loaded');
      assert(contactOf(st, '198.51.100.10'), 'the rest of the file is kept');
      const p = await peer(X, '127.0.0.41', { id: E });
      await sleep(800);
      assert(!p.got.some((m) => m.t === 'msg'));
      p.close();
    } finally { ux.close(); await H.stop(X); }
  });

  /* ---- room member entries (review A, 2) ---- */
  await t('a stranger\'s room join cannot pin its key on a contact you wrote to, so its waiting message stays', async () => {
    uv.send({ type: 'room.create', name: 'relay policy' });
    const room = (await uv.wait((m) => m.type === 'room.created')).room;
    const H8 = '198.51.100.8';
    await sent(uv, H8, 25196, 'private: my seed backup plan');
    const MAL = newId();
    const m2 = await peer(V, '127.0.0.43');
    // its own signing key (proven), a member entry naming the contact's address and ANOTHER key
    m2.send({ t: 'room-req', room, since: 0, join: social.makeMember(m2.sk, { room, fp: MAL.fp, nick: 'm', host: H8, port: 25196 }) });
    await m2.next((m) => m.t === 'room-state');
    await sleep(500); m2.close();
    assert.strictEqual(contactOf(await uv.state(), H8).peerFp, null, 'the member entry\'s key was pinned on the contact');
    const m3 = await peer(V, '127.0.0.44', { id: MAL });
    await sleep(800);
    assert(!m3.got.some((m) => m.t === 'msg'), 'the waiting message went to the member entry\'s key');
    m3.close();
  });

  await t('a member entry naming an address no contact has yet cannot catch what you later write there', async () => {
    uv.send({ type: 'room.create', name: 'later' });
    const room = (await uv.wait((m) => m.type === 'room.created')).room;
    const H11 = '198.51.100.11', K = newId();
    const j = await peer(V, '127.0.0.63');
    j.send({ t: 'room-req', room, since: 0, join: social.makeMember(j.sk, { room, fp: K.fp, nick: 'k', host: H11, port: 25194 }) });
    await j.next((m) => m.t === 'room-state');
    j.close();
    // the key it named connects from its own address, and stays
    const k = await peer(V, '127.0.0.64', { id: K });
    // later the operator writes to the map peer at that address
    await sent(uv, H11, 25194, 'for the operator of ' + H11);
    await sleep(1500);
    assert(!k.got.some((m) => m.t === 'msg'), 'a message to the address went to the key a member entry named for it');
    assert.strictEqual(contactOf(await uv.state(), H11).peerFp, null, 'the address was pinned to the named key');
    k.close();
  });

  await t('room members a peer names become at most 256 contacts', async () => {
    const C2 = await H.up(S.daemon('capped', { peer: 25151, web: 25152 }));
    const uc = await ui(C2);
    try {
      const rooms = [];
      for (let i = 0; i < 3; i++) { uc.send({ type: 'room.create', name: 'cap ' + i }); rooms.push((await uc.wait((m) => m.type === 'room.created')).room); }
      let p = null, n = 0;
      const pid = newId();
      for (const room of rooms) for (let i = 0; i < 99; i++, n++) {
        if (n % 60 === 0) { if (p) p.close(); p = await peer(C2, '127.0.0.48', { id: pid }); }   // a fresh link now and then (frame caps)
        const sk = newSk();
        p.hello({ sk: sk.pub, skp: social.bindKey(sk, p.id.fp) });
        const host = `127.0.${2 + (n >> 8)}.${n & 255}`;
        const before = p.got.length;
        p.send({ t: 'room-req', room, since: 0, join: social.makeMember(sk, { room, fp: crypto.randomBytes(16).toString('hex'), nick: 'm' + n, host, port: 25195 }) });
        await until(() => p.got.slice(before).some((m) => m.t === 'room-state' || m.t === 'room-err'), 5000, 5);
      }
      p.close();
      const st = await uc.state();
      // filed under their keys, never under the addresses the entries name
      assert(!st.contacts.some((c) => /^127\.0\.[23]\./.test(c.host)), 'a member entry\'s address became a contact key');
      const made = st.contacts.filter((c) => c.host.startsWith('peer:')).length;
      assert(made > 200, 'the member contacts were made at all: ' + made);
      assert(made <= 256, made + ' contacts made from member entries');
    } finally { uc.close(); await H.stop(C2); }
  });

  await t('with --tor-all, a member\'s address is called through the SOCKS proxy, never directly', async () => {
    const requests = [];
    const proxy = net.createServer((c) => {
      c.on('error', () => { });
      let buf = Buffer.alloc(0), stage = 0;
      c.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        if (stage === 0 && buf.length >= 2 + buf[1]) { buf = buf.subarray(2 + buf[1]); stage = 1; c.write(Buffer.from([5, 0])); }
        if (stage === 1 && buf.length >= 5 && buf.length >= 7 + buf[4]) {
          requests.push(buf.subarray(5, 5 + buf[4]).toString('latin1') + ':' + buf.readUInt16BE(5 + buf[4]));
          stage = 2; c.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0]));      // host unreachable
        }
      });
    });
    await new Promise((r) => proxy.listen(25135, '127.0.0.1', r));
    const knocks = [];
    const trap = net.createServer((s) => { knocks.push(s.remoteAddress); s.destroy(); });
    await new Promise((r) => trap.listen(25137, '127.0.0.45', r));
    const Y = await H.up(S.daemon('torall', { peer: 25131, web: 25132, extra: ['--tor-all', '--tor-proxy', '127.0.0.1:25135'] }));
    const uy = await ui(Y);
    try {
      uy.send({ type: 'room.create', name: 'over tor' });
      const room = (await uy.wait((m) => m.type === 'room.created')).room;
      const p = await peer(Y, '127.0.0.46');
      p.send({ t: 'room-req', room, since: 0, join: social.makeMember(p.sk, { room, fp: newId().fp, nick: 'm', host: '127.0.0.45', port: 25137 }) });
      await until(() => requests.includes('127.0.0.45:25137'), 8000);
      p.close();
      await sleep(500);
      assert.deepStrictEqual(knocks, [], 'the member address was dialled directly');
    } finally { uy.close(); await H.stop(Y); proxy.close(); trap.close(); }
  });

  /* ---- strangers are not contacts (review A, 6) ---- */
  await t('a stranger that sent one message gets no introductions, is not followed, and passes on only its own posts', async () => {
    const bob = await trustedPeer(V, uv, '127.0.0.54', { nick: 'bob', hello: { disc: true } });
    const eve = await peer(V, '127.0.0.55', { hello: { disc: true } });
    eve.send({ t: 'msg', id: rid(), ts: Date.now(), text: 'hi' });
    await eve.next((m) => m.t === 'ack');
    eve.send({ t: 'who-req' });
    assert.deepStrictEqual((await eve.next((m) => m.t === 'who')).items, [], 'a stranger listed our contacts');
    let st = await uv.state();
    assert(st.follows.includes(bob.sk.pub), 'a trusted contact is followed');
    assert(!st.follows.includes(eve.sk.pub), 'a stranger is followed after one message');
    const other = newSk();
    eve.send({ t: 'posts', items: [{ o: social.makePost(eve.sk, { fp: eve.id.fp, nick: 'eve', text: 'eve\'s own' }), h: 0 },
      { o: social.makePost(other, { fp: newId().fp, nick: 'o', text: 'someone else\'s, via eve' }), h: 0 }] });
    await until(async () => (await uv.state()).feed.some((p) => p.text === 'eve\'s own'));
    st = await uv.state();
    assert(!st.feed.some((p) => p.text === 'someone else\'s, via eve'));
    bob.close(); eve.close();
  });

  /* ---- introductions (review A, 7) ---- */
  await t('introductions are taken only as the answer to our own request, and never rewrite another introducer\'s', async () => {
    const p1 = await trustedPeer(V, uv, '127.0.0.56', { nick: 'p1', hello: { disc: true } });
    const p2 = await trustedPeer(V, uv, '127.0.0.57', { nick: 'p2', hello: { disc: true } });
    const X = newId(), Y = newId();
    p1.send({ t: 'who', items: [{ nick: 'carol', host: '203.0.113.66', port: 8788, fp: Y.fp }] });
    await sleep(400);
    assert(!(await uv.state()).introductions.some((i) => i.fp === Y.fp), 'an unasked "who" was stored');
    uv.send({ type: 'sync.now' });                  // the console's refresh asks every trusted contact
    await p1.next((m) => m.t === 'who-req'); await p2.next((m) => m.t === 'who-req');
    p1.send({ t: 'who', items: [{ nick: 'xavier', host: '203.0.113.5', port: 8788, fp: X.fp }] });
    await until(async () => (await uv.state()).introductions.some((i) => i.fp === X.fp));
    p2.send({ t: 'who', items: [{ nick: 'xavier', host: '203.0.113.99', port: 8788, fp: X.fp }] });
    await sleep(400);
    const it = (await uv.state()).introductions.find((i) => i.fp === X.fp);
    assert.strictEqual(it.host, '203.0.113.5', 'a second introducer rewrote the first one\'s entry');
    assert.deepStrictEqual(it.via, ['p1']);
    // the answer is used up: another "who" on the same link is ignored
    p2.send({ t: 'who', items: [{ nick: 'yolanda', host: '203.0.113.7', port: 8788, fp: Y.fp }] });
    await sleep(400);
    assert(!(await uv.state()).introductions.some((i) => i.fp === Y.fp), 'a second, unasked "who" was stored');
    p1.close(); p2.close();
  });

  /* ---- signing keys (review A, 8) ---- */
  await t('a signing key counts only with its holder\'s proof for the link\'s own Noise key', async () => {
    uv.send({ type: 'room.create', name: 'operators' });
    const room = (await uv.wait((m) => m.type === 'room.created')).room;
    uv.send({ type: 'room.send', room, text: 'members-only: we patch on Friday' });
    await sleep(200);
    const eve = await peer(V, '127.0.0.58', { hello: { sk: undefined, skp: undefined } });
    const vh = eve.got.find((m) => m.t === 'hello');
    assert(social.checkBinding(vh.sk, vh.skp, vh.fp), 'the daemon proves its own signing key');
    const forged = newSk();
    for (const claim of [
      { sk: vh.sk },                                         // the room host's own key, no proof
      { sk: vh.sk, skp: vh.skp },                            // with the host's proof, replayed on another Noise key
      { sk: vh.sk, skp: social.bindKey(forged, eve.id.fp) }, // a proof signed by another key
    ]) {
      eve.hello(Object.assign({ skp: undefined }, claim));
      eve.send({ t: 'room-req', room, since: 0 });
      const r = await eve.next((m) => (m.t === 'room-err' || m.t === 'room-state') && !m.seen);
      r.seen = true;
      assert.strictEqual(r.t, 'room-err', 'let in with ' + JSON.stringify(Object.keys(claim)));
    }
    assert(!eve.got.some((m) => m.t === 'room-items'), 'the backlog went out');
    assert.strictEqual(contactOf(await uv.state(), '127.0.0.58').signId, null);
    const own = newSk();
    eve.hello({ sk: own.pub, skp: social.bindKey(own, eve.id.fp) });
    await until(async () => contactOf(await uv.state(), '127.0.0.58').signPub === own.pub);
    eve.close();
  });

  /* ---- frames and buffers (review A, 4 and 5) ---- */
  await t('mailbox: four 16 KiB deposits do not jam it; every item reaches the recipient', async () => {
    const R = await trustedPeer(V, uv, '127.0.0.50');
    R.send({ t: 'mb-reg' });
    await R.next((m) => m.t === 'mb-reg-ok');
    const x = await peer(V, '127.0.0.51');
    for (let i = 0; i < 4; i++) x.send({ t: 'mb-put', to: R.id.fp, id: 'jam' + i, blob: blob(16384) });
    x.send({ t: 'mb-put', to: R.id.fp, id: 'real1', blob: blob(600) });
    await until(() => x.got.filter((m) => m.t === 'mb-put-ok').length === 5);
    x.close();
    let closed = false; R.socket.on('close', () => (closed = true));
    R.send({ t: 'mb-get' });
    const ids = await until(() => { const a = R.got.filter((m) => m.t === 'mb-items').flatMap((m) => m.items.map((i) => i.id)); return a.length >= 5 && a; }, 5000);
    assert.deepStrictEqual(ids.sort(), ['jam0', 'jam1', 'jam2', 'jam3', 'real1']);
    await sleep(300);
    assert(!closed, 'the mailbox dropped the link');
    R.send({ t: 'mb-ack', ids });
    R.close();
  });

  await t('a peer that asks again and again and never reads gets one answer at a time', async () => {
    const R = await trustedPeer(V, uv, '127.0.0.52');
    R.send({ t: 'mb-reg' });
    await R.next((m) => m.t === 'mb-reg-ok');
    const x = await peer(V, '127.0.0.53');
    for (let i = 0; i < 50; i++) x.send({ t: 'mb-put', to: R.id.fp, id: 'm' + i, blob: blob(11400) });
    await until(() => x.got.filter((m) => m.t === 'mb-put-ok').length === 50);
    x.close(); R.close();
    const R2 = await peer(V, '127.0.0.52', { id: R.id });
    const before = rss(V.pid);
    R2.socket.pause();
    for (let i = 0; i < 390; i++) R2.send({ t: 'mb-get' });
    await sleep(4000);
    const grew = rss(V.pid) - before;
    R2.socket.resume();
    await sleep(1500);
    const answers = R2.got.filter((m) => m.t === 'mb-items').length;
    R2.close();
    assert(grew < 100, `daemon RSS grew ${grew.toFixed(0)} MB on one link`);
    assert(answers > 0, 'no answer at all');
    assert(answers < 1000, `${answers} mb-items frames for 390 requests: one answer per request`);
  });

  /* ---- mailbox slots and disk writes (review A, 9) ---- */
  await t('mailbox slots are for contacts the operator added; an unchanged hello and the mailbox write nothing at once', async () => {
    const Q = await H.up(S.daemon('quiet', { peer: 25141, web: 25142, extra: ['--mailbox'] }));
    const uq = await ui(Q);
    try {
      const s = await peer(Q, '127.0.0.59');
      s.send({ t: 'mb-reg' });
      assert.strictEqual((await s.next((m) => m.t === 'mb-reg-ok' || m.t === 'mb-reg-err')).t, 'mb-reg-err', 'a stranger took a mailbox slot');
      await sleep(600);
      const f = path.join(Q.dataDir, 'state.json'), m0 = fs.statSync(f).mtimeMs;
      for (let i = 0; i < 3; i++) s.hello();
      await sleep(600);
      assert.strictEqual(fs.statSync(f).mtimeMs, m0, 'a hello that changed nothing rewrote state.json');
      s.close();
      const R = await trustedPeer(Q, uq, '127.0.0.60');
      R.send({ t: 'mb-reg' });
      await R.next((m) => m.t === 'mb-reg-ok');
      const x = await peer(Q, '127.0.0.61');
      for (let i = 0; i < 5; i++) { x.send({ t: 'mb-put', to: R.id.fp, id: 'w' + i, blob: blob(2000) }); await sleep(400); }
      await sleep(1500);
      const mf = path.join(Q.dataDir, 'mailbox.json');
      assert(!fs.existsSync(mf), 'mailbox.json was rewritten within seconds of each change');
      x.close(); R.close();
    } finally { uq.close(); await H.stop(Q); }
    // and nothing is lost: shutdown writes it
    const saved = JSON.parse(fs.readFileSync(path.join(Q.dataDir, 'mailbox.json'), 'utf8'));
    assert.strictEqual(Object.values(saved.recipients)[0].items.length, 5);
  });

  /* ---- posts (review A, 3) ---- */
  await t('posts: a link gets 200 looked at, and a flood never evicts the posts of someone you follow', async () => {
    const W = await H.up(S.daemon('flooded', { peer: 25111, web: 25112 }));
    const uw = await ui(W);
    try {
      const now = Date.now();
      const friend = await trustedPeer(W, uw, '127.0.0.62', { nick: 'friend' });
      // the friend's own posts are the oldest in the store: the first to go, unless followed ones are kept
      const theirs = Array.from({ length: 20 }, (_, i) => social.makePost(friend.sk, { fp: friend.id.fp, nick: 'friend', text: 'friend post ' + i, ts: now - 29 * 864e5 + i * 60e3 }));
      friend.send({ t: 'posts', items: theirs.map((o) => ({ o, h: 0 })) });
      await until(async () => (await uw.state()).feed.filter((p) => p.text.startsWith('friend post')).length === 20);
      friend.close();
      const authors = Array.from({ length: 24 }, newSk);
      const flood = [];
      authors.forEach((k, a) => { for (let i = 0; i < 100; i++) flood.push(social.makePost(k, { fp: crypto.randomBytes(16).toString('hex'), nick: 'f' + a, text: `flood ${a}/${i}`, ts: now - (i % 25) * 864e5 - a * 1000 - i }));});
      await uw.state();                               // clears the events seen so far
      let link = await peer(W, '127.0.0.62', { id: friend.id, sk: friend.sk });
      for (let f = 0; f < 3; f++) link.send({ t: 'posts', items: flood.slice(f * 100, f * 100 + 100).map((o) => ({ o, h: 0 })) });
      const taken = await countEvents(uw, (m) => m.type === 'post');
      assert.strictEqual(taken, 200, `${taken} posts taken from one link`);
      link.close();
      // the rest, 200 per link, well past the 2000-post store
      for (let off = 300; off < flood.length; off += 200) {
        link = await peer(W, '127.0.0.62', { id: friend.id, sk: friend.sk });
        link.send({ t: 'posts', items: flood.slice(off, off + 100).map((o) => ({ o, h: 0 })) });
        link.send({ t: 'posts', items: flood.slice(off + 100, off + 200).map((o) => ({ o, h: 0 })) });
        await sleep(400);                             // read and handled before the link goes
        link.close();
      }
      await sleep(500);
    } finally { uw.close(); await H.stop(W); }
    const disk = JSON.parse(fs.readFileSync(path.join(W.dataDir, 'social.json'), 'utf8'));
    assert(disk.posts.length <= 2000, disk.posts.length + ' posts kept');
    assert(disk.posts.length > 1500, 'the flood was taken at all: ' + disk.posts.length);
    assert.strictEqual(disk.posts.filter((p) => p.o.text.startsWith('friend post')).length, 20, 'the flood evicted a followed contact\'s posts');
  });

  /* ---- rate limiter (review A, 10) ---- */
  await t('rate limiter: a new source block costs no sort, and the least recently used block is the one dropped', () => {
    const src = fs.readFileSync(path.join(H.ROOT, 'nodesignald.js'), 'utf8');
    const code = src.slice(src.indexOf('const MAX_CONNS'), src.indexOf('/* ---- privacy:'));
    assert(code.includes('function rateOk'), 'the limiter moved: update this test');
    const L = vm.runInNewContext(code + '\n;({ rateOk, rlBuckets, RL_MAX_BLOCKS })', { arg: (n, d) => d, Date, Math, Map, Number });
    const ip = (i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
    for (let i = 0; i < L.RL_MAX_BLOCKS; i++) L.rateOk(ip(i));
    L.rateOk(ip(0));                                 // block 0 is in use again
    L.rateOk(ip(1e6));                               // one more: the least recently used goes, which is block 1
    assert.strictEqual(L.rlBuckets.size, L.RL_MAX_BLOCKS);
    assert(L.rlBuckets.has('v4:' + ip(0)), 'a block in use was dropped');
    assert(!L.rlBuckets.has('v4:' + ip(1)));
    const t0 = Date.now();
    for (let i = 0; i < 5000; i++) L.rateOk(ip(2e6 + i));
    const ms = Date.now() - t0;
    assert(ms < 1000, `5000 new source blocks took ${ms} ms`);
  });
  await t('rate limiter: one IPv6 /64 is one block however Node writes the address (final review)', () => {
    const src = fs.readFileSync(path.join(H.ROOT, 'nodesignald.js'), 'utf8');
    const code = src.slice(src.indexOf('const MAX_CONNS'), src.indexOf('/* ---- privacy:'));
    const L = vm.runInNewContext(code + '\n;({ sourceBlock })', { arg: (n, d) => d, Date, Math, Map, Number });
    const net = require('net');
    // the compressed form Node gives a socket, for 5000 addresses in 2001:db8:0:0::/64
    const keys = new Set();
    for (let i = 1; i <= 5000; i++) keys.add(L.sourceBlock(new net.SocketAddress({ address: `2001:db8:0:0:${i.toString(16)}:1:2:3`, family: 'ipv6' }).address));
    assert.deepStrictEqual([...keys], ['v6:2001:db8:0:0']);
    assert.strictEqual(L.sourceBlock('2001:db8::1'), 'v6:2001:db8:0:0');
    assert.strictEqual(L.sourceBlock('2001:db8:1:2::5%eth0'), 'v6:2001:db8:1:2');
    assert.strictEqual(L.sourceBlock('::1'), 'v6:0:0:0:0');
    assert.strictEqual(L.sourceBlock('::ffff:198.51.100.7'), 'v4:198.51.100.7');
    assert.strictEqual(L.sourceBlock('64:ff9b::198.51.100.7'), 'v6:64:ff9b:0:0');
    assert.notStrictEqual(L.sourceBlock('2001:db8:0:1::1'), L.sourceBlock('2001:db8:0:2::1'), 'different /64s stay apart');
  });

  uv.close();
  await S.finish();
})().catch(S.abort);
