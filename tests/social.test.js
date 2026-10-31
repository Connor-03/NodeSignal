// social.test.js: signed posts, rooms and their store (social.js). Plain node.
//   node tests/social.test.js
'use strict';
const assert = require('assert');
const S = require('../social.js');

let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n')[0]); }
};
const alice = S.loadSigningKey(S.newSigningKey()), bob = S.loadSigningKey(S.newSigningKey());
const FP_A = 'a'.repeat(32), FP_B = 'b'.repeat(32);
const NOW = Date.now();

t('a post signs and verifies; its id is stable and covers the whole body', () => {
  const p = S.makePost(alice, { fp: FP_A, nick: 'alice', text: 'gm\nfrom my node', ts: NOW });
  const v = S.verify(p, NOW);
  assert(v.ok, v.error);
  assert.strictEqual(v.id, S.idOf(JSON.parse(JSON.stringify(p))), 'id survives a round trip through JSON');
  for (const [k, val] of [['text', 'gn'], ['nick', 'mallory'], ['fp', FP_B], ['ts', NOW + 1]]) {
    const bad = Object.assign({}, p, { [k]: val });
    assert.strictEqual(S.verify(bad, NOW).ok, false, 'changing ' + k + ' breaks the signature');
  }
  assert.strictEqual(S.verify(Object.assign({}, p, { a: bob.pub }), NOW).ok, false, 'another author key');
});

t('posts are cleaned and capped; extra fields, old and future items are refused', () => {
  const p = S.makePost(alice, { fp: FP_A, nick: 'al\u0007ice', text: 'x'.repeat(5000) + '\u0000', ts: NOW });
  assert.strictEqual(p.text.length, S.POST_MAX);
  assert.strictEqual(p.nick, 'alice');
  assert.strictEqual(S.verify(Object.assign({}, p, { extra: 1 }), NOW).error, 'unexpected field extra');
  assert.strictEqual(S.verify(S.makePost(alice, { fp: FP_A, nick: 'a', text: 'old', ts: NOW - 40 * 864e5 }), NOW).ok, false);
  assert.strictEqual(S.verify(S.makePost(alice, { fp: FP_A, nick: 'a', text: 'future', ts: NOW + 3600e3 }), NOW).ok, false);
  assert.strictEqual(S.verify({ k: 'post', v: 2 }, NOW).ok, false);
  assert.strictEqual(S.verify(null, NOW).ok, false);
  assert.strictEqual(S.verify([], NOW).ok, false);
});

t('store: duplicates once, per-author and per-day caps, never drops our own', () => {
  const st = S.createStore({ maxPosts: 50, maxPerAuthor: 10, maxPerAuthorDay: 5 });
  const p = S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'one', ts: NOW });
  assert.strictEqual(st.addPost(p, { via: FP_B, hops: 1, now: NOW }).status, 'new');
  assert.strictEqual(st.addPost(JSON.parse(JSON.stringify(p)), { via: FP_A, hops: 2, now: NOW }).status, 'dup');
  for (let i = 0; i < 4; i++) st.addPost(S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'n' + i, ts: NOW - i }), { via: FP_B, now: NOW });
  const r = st.addPost(S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'six', ts: NOW }), { via: FP_B, now: NOW });
  assert.strictEqual(r.status, 'rejected', 'sixth post in a day');
  // older days fill the per-author cap, oldest first out
  for (let d = 2; d < 12; d++) st.addPost(S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'day ' + d, ts: NOW - d * 864e5 }), { via: FP_B, now: NOW });
  assert(st.feed({ filter: (x) => x.o.a === bob.pub, limit: 100 }).length <= 10);
  // our own posts survive the total cap
  const mine = S.makePost(alice, { fp: FP_A, nick: 'alice', text: 'mine', ts: NOW - 20 * 864e5 });
  st.addPost(mine, { via: null, now: NOW, mine: true });
  const st2 = S.createStore({ maxPosts: 3, maxPerAuthor: 100, maxPerAuthorDay: 100 });
  st2.addPost(mine, { via: null, now: NOW, mine: true });
  for (let i = 0; i < 6; i++) st2.addPost(S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'b' + i, ts: NOW - 100 + i }), { via: FP_B, now: NOW });
  assert(st2.feed({ limit: 10 }).some((x) => x.via === null), 'own post kept');
  assert(st2.size <= 3);
});

t('store: feed order, postsSince, prune and a JSON round trip', () => {
  const st = S.createStore();
  const items = [1, 2, 3].map((i) => S.makePost(bob, { fp: FP_B, nick: 'bob', text: 'p' + i, ts: NOW - (10 - i) * 1000 }));
  for (const p of items) st.addPost(p, { via: FP_B, hops: 1, now: NOW });
  assert.deepStrictEqual(st.feed({ limit: 3 }).map((x) => x.o.text), ['p3', 'p2', 'p1']);
  assert.deepStrictEqual(st.postsSince(NOW - 8500, null, 10).map((x) => x.o.text), ['p2', 'p3']);
  const st2 = S.createStore(); st2.load(JSON.parse(JSON.stringify(st.toJSON())));
  assert.strictEqual(st2.size, 3);
  st2.load({ posts: [null, { o: { k: 'post' } }, { o: 'x' }], rooms: [1, { def: {} }] });
  assert.strictEqual(st2.size, 3, 'garbage ignored');
  st2.prune(NOW + 31 * 864e5);
  assert.strictEqual(st2.size, 0, 'old forwarded posts pruned');
});

t('rooms: ids bind creator, name and nonce; members and messages are signed', () => {
  const def = S.makeRoom(alice, { name: 'relay policy', ts: NOW });
  assert(S.verify(def, NOW).ok);
  assert.strictEqual(S.verify(Object.assign({}, def, { name: 'other' }), NOW).ok, false);
  const forged = S.sign(bob, { k: 'roomdef', v: 1, ts: NOW, name: def.name, nonce: def.nonce, room: def.room });
  assert.strictEqual(S.verify(forged, NOW).ok, false, 'bob cannot claim alice\'s room id');
  const st = S.createStore();
  assert.strictEqual(st.addRoom(def, { joined: true, now: NOW }).status, 'new');
  const msg = S.makeRoomMsg(bob, { room: def.room, fp: FP_B, nick: 'bob', text: 'hi room', ts: NOW });
  assert.strictEqual(st.addRoomMsg(msg, { now: NOW }).status, 'rejected', 'not a member yet');
  assert.strictEqual(st.addMember(S.makeMember(bob, { room: def.room, fp: FP_B, nick: 'bob', host: 'x'.repeat(56) + '.onion', port: 8788, ts: NOW }), { now: NOW }).status, 'new');
  assert.strictEqual(st.addRoomMsg(msg, { now: NOW }).status, 'new');
  assert.strictEqual(st.addRoomMsg(msg, { now: NOW }).status, 'dup');
  assert.strictEqual(st.addMember(S.makeMember(bob, { room: def.room, fp: FP_B, nick: 'bob', ts: NOW - 5 }), { now: NOW }).status, 'dup', 'older entry ignored');
  st.addMember(S.makeMember(bob, { room: def.room, fp: FP_B, nick: 'bob', left: true, ts: NOW + 1 }), { now: NOW + 2 });
  assert.strictEqual(st.addRoomMsg(S.makeRoomMsg(bob, { room: def.room, fp: FP_B, nick: 'bob', text: 'after leaving', ts: NOW + 3 }), { now: NOW + 4 }).status, 'rejected');
  const st2 = S.createStore(); st2.load(JSON.parse(JSON.stringify(st.toJSON())));
  assert.strictEqual(st2.roomMsgs(def.room).length, 1);
  assert.strictEqual(st2.room(def.room).joined, true);
});

t('rooms: capped count and message history', () => {
  const st = S.createStore({ maxRooms: 2, maxRoomMsgs: 3 });
  const d1 = S.makeRoom(alice, { name: 'a' }), d2 = S.makeRoom(alice, { name: 'b' }), d3 = S.makeRoom(alice, { name: 'c' });
  st.addRoom(d1, { joined: true }); st.addRoom(d2, { joined: true });
  assert.strictEqual(st.addRoom(d3, { joined: true }).status, 'rejected', 'joined rooms are never dropped for a new one');
  st.addMember(S.makeMember(alice, { room: d1.room, fp: FP_A, nick: 'a' }));
  for (let i = 0; i < 5; i++) st.addRoomMsg(S.makeRoomMsg(alice, { room: d1.room, fp: FP_A, nick: 'a', text: 'm' + i, ts: NOW + i }), { now: NOW + 10 });
  assert.deepStrictEqual(st.roomMsgs(d1.room).map((m) => m.o.text), ['m2', 'm3', 'm4']);
});

t('canonical JSON sorts keys at every level and skips undefined', () => {
  assert.strictEqual(S.canonical({ b: 1, a: { d: [2, { y: 1, x: 2 }], c: undefined } }), '{"a":{"d":[2,{"x":2,"y":1}]},"b":1}');
});

/* Ed25519 on BigInt, just enough to find the points of small order without
   trusting a list: L * (a random point) lands in the 8-torsion. */
const ED = (() => {
  const p = 2n ** 255n - 19n, L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const mod = (a) => ((a % p) + p) % p;
  const pow = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; };
  const inv = (a) => pow(a, p - 2n), d = mod(-121665n * inv(121666n)), I = pow(2n, (p - 1n) / 4n);
  const decode = (buf) => {
    let y = 0n; for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(buf[i] & (i === 31 ? 0x7f : 0xff));
    y = mod(y);
    const u = mod(y * y - 1n), v = mod(d * y * y + 1n);
    let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (p - 5n) / 8n));
    if (mod(v * x * x) !== u) { x = mod(x * I); if (mod(v * x * x) !== u) return null; }
    if (Number(x & 1n) !== buf[31] >> 7) x = mod(-x);
    return [x, y];
  };
  const encode = ([x, y]) => { const b = Buffer.alloc(32); let t = y; for (let i = 0; i < 32; i++) { b[i] = Number(t & 0xffn); t >>= 8n; } if (x & 1n) b[31] |= 0x80; return b; };
  const add = ([x1, y1], [x2, y2]) => { const t = mod(d * x1 * x2 * y1 * y2); return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))]; };
  const mul = (k, P) => { let R = [0n, 1n], Q = P; while (k > 0n) { if (k & 1n) R = add(R, Q); Q = add(Q, Q); k >>= 1n; } return R; };
  const isId = (P) => P[0] === 0n && P[1] === 1n;
  function torsion() {
    for (;;) {
      const P = decode(require('crypto').randomBytes(32));
      if (!P) continue;
      const T = mul(L, P);
      if (!isId(mul(4n, T))) return Array.from({ length: 8 }, (_, k) => encode(mul(BigInt(k), T)));
    }
  }
  return { torsion, p };
})();

t('small-order author keys are refused (a forged signature for any text would verify)', () => {
  const pts = ED.torsion();
  assert.strictEqual(new Set(pts.map((b) => b.toString('hex'))).size, 8, 'eight distinct points of order 1, 2, 4, 8');
  // each with the sign bit flipped too, and the non-canonical encodings y = p, p + 1 (y = 0 and 1 again)
  const extra = [ED.p, ED.p + 1n].map((y) => { const b = Buffer.alloc(32); let t = y; for (let i = 0; i < 32; i++) { b[i] = Number(t & 0xffn); t >>= 8n; } return b; });
  for (const raw of [...pts, ...extra]) for (const sign of [0, 0x80]) {
    const b = Buffer.from(raw); b[31] = (b[31] & 0x7f) | sign;
    assert.strictEqual(S.isPub(b.toString('base64')), false, 'accepted as a key: ' + b.toString('hex'));
  }
  // the forgery itself: identity key, R = identity, S = 0
  const ident = Buffer.alloc(32); ident[0] = 1;
  const body = { k: 'post', v: 1, a: ident.toString('base64'), ts: NOW, fp: FP_A, nick: 'anyone', text: 'forged by anyone' };
  const r = S.verify(Object.assign({}, body, { sig: Buffer.concat([ident, Buffer.alloc(32)]).toString('base64') }), NOW);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, 'bad author key');
  assert(S.isPub(alice.pub) && S.isPub(bob.pub), 'real keys still pass');
});

t('a kind named after an Object.prototype property is refused, not thrown on', () => {
  for (const k of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
    const o = JSON.parse(`{"k":"${k}","v":1}`);
    assert.deepStrictEqual(S.verify(o, NOW), { ok: false, error: 'unknown kind' }, k);
    const st = S.createStore();
    assert.strictEqual(st.addPost(o, { now: NOW }).status, 'rejected', k);
    st.addRoom(Object.assign({}, o)); st.addMember(Object.assign({}, o)); st.addRoomMsg(Object.assign({}, o));
  }
});

t('store under a flood: a held or evicted id costs no signature check, and followed authors go last', () => {
  const st = S.createStore({ maxPosts: 50, maxPerAuthor: 100, maxPerAuthorDay: 100 });
  // the followed author's posts are the oldest in the store
  const mine = Array.from({ length: 10 }, (_, i) => S.makePost(alice, { fp: FP_A, nick: 'alice', text: 'a' + i, ts: NOW - 20 * 864e5 + i }));
  for (const p of mine) assert.strictEqual(st.addPost(p, { via: FP_A, hops: 1, now: NOW }).status, 'new');
  const keep = new Set([alice.pub]);
  const flood = [];
  for (let i = 0; i < 200; i++) {
    const k = i % 2 ? bob : S.loadSigningKey(S.newSigningKey());
    flood.push(S.makePost(k, { fp: FP_B, nick: 'f', text: 'flood ' + i, ts: NOW - 10 * 864e5 + i }));
  }
  for (const p of flood) st.addPost(p, { via: FP_B, hops: 1, now: NOW, keepAuthors: keep });
  assert(st.size <= 50, 'over the cap: ' + st.size);
  assert.strictEqual(st.feed({ filter: (x) => x.o.a === alice.pub, limit: 100 }).length, 10, 'a flood evicted a followed author\'s posts');
  // without keepAuthors the oldest go first: the cap still holds
  const st2 = S.createStore({ maxPosts: 50, maxPerAuthor: 100, maxPerAuthorDay: 100 });
  for (const p of [...mine, ...flood]) st2.addPost(p, { via: FP_B, hops: 1, now: NOW });
  assert(st2.size <= 50);
  // evicted and held ids are duplicates, answered before any signature check:
  // a copy with its signature broken still reads as a duplicate, never as new
  const evictedOne = flood.find((p) => !st.feed({ limit: 1000 }).some((x) => x.id === S.idOf(p)));
  assert(evictedOne, 'something was evicted');
  assert.strictEqual(st.addPost(evictedOne, { via: FP_B, hops: 1, now: NOW, keepAuthors: keep }).status, 'dup', 'a replayed evicted post counted as new');
  const broken = Object.assign({}, mine[0], { sig: Buffer.alloc(64).toString('base64') });
  assert.strictEqual(st.addPost(broken, { via: FP_B, now: NOW }).status, 'dup');
  const size = st.size;
  for (let i = 0; i < 5; i++) st.addPost(evictedOne, { via: FP_B, now: NOW });
  assert.strictEqual(st.size, size);
});

t('a signing key is bound to one Noise fingerprint by its holder', () => {
  const sig = S.bindKey(alice, FP_A);
  assert.strictEqual(S.checkBinding(alice.pub, sig, FP_A), true);
  assert.strictEqual(S.checkBinding(alice.pub, sig, FP_B), false, 'the same proof for another fingerprint');
  assert.strictEqual(S.checkBinding(bob.pub, sig, FP_A), false, 'alice\'s proof for bob\'s key');
  assert.strictEqual(S.checkBinding(bob.pub, S.bindKey(alice, FP_B), FP_B), false, 'signed by someone else');
  assert.strictEqual(S.checkBinding(alice.pub, undefined, FP_A), false);
  assert.strictEqual(S.checkBinding(alice.pub, 'x'.repeat(88), FP_A), false);
  // the proof is no post: it never verifies as one
  const asPost = { k: 'post', v: 1, a: alice.pub, ts: NOW, fp: FP_A, nick: 'a', text: 'x', sig };
  assert.strictEqual(S.verify(asPost, NOW).ok, false);
});

console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
