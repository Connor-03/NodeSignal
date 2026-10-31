// mailbox.test.js: sealed mailbox blobs and the mailbox's store. Plain node.
//   node tests/mailbox.test.js
// No network, no ports: everything runs in this process.
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const noise = require('../noise.js');
const mailbox = require('../mailbox.js');

let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e)); }
};

const ident = () => noise.loadIdentity(noise.newIdentity());
const alice = ident(), bob = ident(), carol = ident();
const GENERIC = /^Error: mailbox: cannot open this message$/;   // assert.throws matches String(err)
const sealAB = (plaintext) => mailbox.seal({ senderPrivRaw: alice.privRaw, senderPubRaw: alice.pubRaw, recipientPubRaw: bob.pubRaw, plaintext });
const openB = (blob) => mailbox.open({ recipientPrivRaw: bob.privRaw, recipientPubRaw: bob.pubRaw, blob });

/* An independent construction of the documented blob format, straight from
   the spec in mailbox.js's header. It proves the wire format is what the
   header says, and lets a test claim a sender key it does not hold. */
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const rawDH = (priv, pub) => crypto.diffieHellman({
  privateKey: crypto.createPrivateKey({ key: Buffer.concat([PKCS8, priv]), format: 'der', type: 'pkcs8' }),
  publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: pub.toString('base64url') }, format: 'jwk' }),
});
function referenceSeal({ macPriv, claimedPub, recipientPub, body }) {
  // from random bytes, not generateKeyPairSync (it can deadlock on Node 18 when exported; see noise.js)
  const ephKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), crypto.randomBytes(32)]), format: 'der', type: 'pkcs8' });
  const jwk = ephKey.export({ format: 'jwk' });
  const eph = { priv: Buffer.from(jwk.d, 'base64url'), pub: Buffer.from(jwk.x, 'base64url') };
  const k1 = Buffer.from(crypto.hkdfSync('sha256', rawDH(eph.priv, recipientPub), Buffer.concat([eph.pub, recipientPub]), 'NodeSignal mailbox v1 outer', 32));
  const macKey = Buffer.from(crypto.hkdfSync('sha256', rawDH(macPriv, recipientPub), eph.pub, 'NodeSignal mailbox v1 sender', 32));
  const mac = crypto.createHmac('sha256', macKey).update(Buffer.concat([eph.pub, recipientPub, body])).digest();
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('chacha20-poly1305', k1, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.concat([Buffer.from([1]), eph.pub, recipientPub]));
  const ct = Buffer.concat([c.update(Buffer.concat([claimedPub, mac, body])), c.final(), c.getAuthTag()]);
  return Buffer.concat([Buffer.from([1]), eph.pub, nonce, ct]);
}

const FP = (n) => crypto.createHash('sha256').update('fp' + n).digest('hex').slice(0, 32);
const fakeBlob = (len = 200, fill = 7) => { const b = Buffer.alloc(len, fill); b[0] = 1; return b; };

/* ---------------------------------------------------------------- seal/open */
t('seal/open round trip with real identities; the sender key is the sender\'s', () => {
  const text = 'gm from behind two NATs ✓ {"t":"msg"}';
  const blob = sealAB(text);
  assert(Buffer.isBuffer(blob));
  assert.strictEqual(blob[0], 1, 'version byte');
  assert.strictEqual(blob.length, mailbox.OVERHEAD + Buffer.byteLength(text), 'version | eph | nonce | senderPub | mac | body | tag');
  const r = openB(blob);
  assert.strictEqual(r.plaintext.toString('utf8'), text);
  assert(r.senderPubRaw.equals(alice.pubRaw), 'opened sender key is alice\'s');
  assert.strictEqual(r.senderFp, alice.fp, 'fingerprint matches noise.fingerprintRaw of the sender');
  // recipientPubRaw is optional; it is derived from the private key
  assert(mailbox.open({ recipientPrivRaw: bob.privRaw, blob }).senderPubRaw.equals(alice.pubRaw));
  // a Buffer body and an empty body work too
  assert(openB(sealAB(Buffer.from([0, 1, 2, 255]))).plaintext.equals(Buffer.from([0, 1, 2, 255])));
  assert.strictEqual(openB(sealAB('')).plaintext.length, 0);
});

t('the blob shows neither the text nor the sender, and two seals share no bytes', () => {
  const text = 'a very recognisable sentence about relay policy';
  const a = sealAB(text), b = sealAB(text);
  for (const blob of [a, b]) {
    assert(!blob.includes(Buffer.from(text)), 'plaintext visible');
    assert(!blob.includes(alice.pubRaw), 'sender key visible');
    assert(!blob.includes(Buffer.from(alice.fp)), 'sender fingerprint visible');
  }
  assert(!a.subarray(1, 33).equals(b.subarray(1, 33)), 'fresh ephemeral key');
  assert(!a.subarray(33, 45).equals(b.subarray(33, 45)), 'fresh nonce');
  assert(!a.subarray(45).equals(b.subarray(45)), 'different ciphertext');
});

t('a blob built independently from the documented format opens (wire format matches the spec)', () => {
  const blob = referenceSeal({ macPriv: alice.privRaw, claimedPub: alice.pubRaw, recipientPub: bob.pubRaw, body: Buffer.from('reference') });
  const r = openB(blob);
  assert.strictEqual(r.plaintext.toString(), 'reference');
  assert(r.senderPubRaw.equals(alice.pubRaw));
});

t('a third party (or the mailbox) cannot open it', () => {
  const blob = sealAB('for bob only');
  assert.throws(() => mailbox.open({ recipientPrivRaw: carol.privRaw, recipientPubRaw: carol.pubRaw, blob }), GENERIC);
  assert.throws(() => mailbox.open({ recipientPrivRaw: alice.privRaw, blob }), GENERIC, 'not even the sender');
});

t('tampering with any single byte fails with the generic error', () => {
  const blob = sealAB('tamper me');
  for (let i = 0; i < blob.length; i++) {
    for (const bit of [0x01, 0x80]) {
      const x = Buffer.from(blob); x[i] ^= bit;
      assert.throws(() => openB(x), GENERIC, `byte ${i} bit ${bit}`);
    }
  }
});

t('truncated, extended, wrong-version, oversized and non-Buffer blobs fail', () => {
  const blob = sealAB('shape');
  assert.throws(() => openB(blob.subarray(0, blob.length - 1)), GENERIC, 'one byte short');
  assert.throws(() => openB(Buffer.concat([blob, Buffer.from([0])])), GENERIC, 'one byte extra');
  assert.throws(() => openB(blob.subarray(0, mailbox.OVERHEAD - 1)), GENERIC, 'under the minimum');
  assert.throws(() => openB(Buffer.alloc(0)), GENERIC);
  const v2 = Buffer.from(blob); v2[0] = 2;
  assert.throws(() => openB(v2), GENERIC, 'version 2');
  assert.throws(() => openB(Buffer.concat([blob, Buffer.alloc(64 * 1024)])), GENERIC, 'over 64 KiB');
  assert.throws(() => openB(blob.toString('base64')), GENERIC, 'a string');
  assert.throws(() => openB(null), GENERIC);
  const zeroEph = Buffer.from(blob); zeroEph.fill(0, 1, 33);
  assert.throws(() => openB(zeroEph), GENERIC, 'low-order ephemeral key');
});

t('the largest plaintext fills exactly 64 KiB; one byte more is refused', () => {
  const big = crypto.randomBytes(mailbox.MAX_PLAINTEXT);
  const blob = sealAB(big);
  assert.strictEqual(blob.length, 64 * 1024);
  assert(openB(blob).plaintext.equals(big));
  assert.throws(() => sealAB(Buffer.alloc(mailbox.MAX_PLAINTEXT + 1)), /plaintext is over/);
});

t('a blob sealed by A but claiming B\'s static key fails the MAC', () => {
  // carol writes to bob, claiming to be alice: she holds the outer key, not alice's
  const forged = referenceSeal({ macPriv: carol.privRaw, claimedPub: alice.pubRaw, recipientPub: bob.pubRaw, body: Buffer.from('trust me, I am alice') });
  assert.throws(() => openB(forged), GENERIC);
  // the same construction with the right key opens, so the MAC is what refused it
  const honest = referenceSeal({ macPriv: carol.privRaw, claimedPub: carol.pubRaw, recipientPub: bob.pubRaw, body: Buffer.from('I am carol') });
  assert(openB(honest).senderPubRaw.equals(carol.pubRaw));
  // and seal() itself will not claim a key it does not hold
  assert.throws(() => mailbox.seal({ senderPrivRaw: carol.privRaw, senderPubRaw: alice.pubRaw, recipientPubRaw: bob.pubRaw, plaintext: 'x' }), /does not match/);
});

t('a blob for bob cannot be re-addressed to carol', () => {
  // the outer key and the AD both bind the recipient's key
  const blob = sealAB('bob only');
  assert.throws(() => mailbox.open({ recipientPrivRaw: carol.privRaw, blob }), GENERIC);
});

t('wrong arguments get clear errors, not the generic one', () => {
  assert.throws(() => mailbox.seal({ senderPrivRaw: alice.privRaw, senderPubRaw: alice.pubRaw, recipientPubRaw: Buffer.alloc(31), plaintext: 'x' }), /recipientPubRaw must be a 32-byte Buffer/);
  assert.throws(() => mailbox.seal({ senderPrivRaw: alice.privRaw, senderPubRaw: alice.pubRaw, recipientPubRaw: bob.pubRaw, plaintext: 42 }), /plaintext must be/);
  assert.throws(() => mailbox.seal({ senderPrivRaw: alice.privRaw, senderPubRaw: alice.pubRaw, recipientPubRaw: Buffer.alloc(32), plaintext: 'x' }), /unusable recipient key/);
  assert.throws(() => mailbox.open({ recipientPrivRaw: bob.privRaw, recipientPubRaw: carol.pubRaw, blob: sealAB('x') }), /does not match/);
  assert.throws(() => mailbox.open({ blob: sealAB('x') }), /recipientPrivRaw must be/);
});

/* -------------------------------------------------------------------- store */
t('createStore: defaults, and bad limits refused', () => {
  const s = mailbox.createStore();
  assert.deepStrictEqual(s.stats(), { recipients: 0, items: 0, bytes: 0, limits: {
    maxPerRecipient: 200, maxBlobBytes: 64 * 1024, maxTotalBytes: 32 * 1024 * 1024, ttlMs: 7 * 864e5, maxRecipients: 256 } });
  for (const bad of [{ maxPerRecipient: 0 }, { ttlMs: -1 }, { maxRecipients: 1.5 }, { maxTotalBytes: '9' }, { maxBlobBytes: 64 * 1024 + 1 }, { maxBlobBytes: 10 }]) {
    assert.throws(() => mailbox.createStore(bad), RangeError, JSON.stringify(bad));
  }
});

t('fingerprints must be 32 lowercase hex characters', () => {
  const s = mailbox.createStore();
  for (const fp of ['', 'abc', FP(1).toUpperCase(), FP(1).slice(1), FP(1) + '0', '__proto__', 'constructor', null, 42, { toString: () => FP(1) }]) {
    assert.strictEqual(s.register(fp, 0), false, String(fp));
    assert.strictEqual(s.isRegistered(fp), false);
    assert.deepStrictEqual(s.deposit(fp, { id: 'a', blob: fakeBlob() }, 0), { ok: false, error: 'bad recipient' });
  }
  assert.strictEqual(s.stats().recipients, 0);
});

t('deposit: unregistered recipient, bad id, bad or oversized blob are each refused', () => {
  const s = mailbox.createStore({ maxBlobBytes: 300 });
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'a', blob: fakeBlob() }, 0), { ok: false, error: 'recipient not registered here' });
  assert(s.register(FP(1), 0));
  for (const id of ['', 'x'.repeat(65), 'a b', 'a/b', 'a.b', 'ü', 42, null, undefined]) {
    assert.deepStrictEqual(s.deposit(FP(1), { id, blob: fakeBlob() }, 0), { ok: false, error: 'bad id' }, String(id));
  }
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'A-z_0'.repeat(12) + 'abcd', blob: fakeBlob() }, 0), { ok: true }, '64 characters is fine');
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'big', blob: fakeBlob(301) }, 0), { ok: false, error: 'blob too big' });
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'max', blob: fakeBlob(300) }, 0), { ok: true });
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'short', blob: fakeBlob(mailbox.OVERHEAD - 1) }, 0), { ok: false, error: 'bad blob' });
  const v2 = fakeBlob(); v2[0] = 2;
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'v2', blob: v2 }, 0), { ok: false, error: 'bad blob' });
  for (const blob of ['AQID', null, [1, 2, 3], undefined]) assert.deepStrictEqual(s.deposit(FP(1), { id: 'x', blob }, 0), { ok: false, error: 'bad blob' });
  assert.deepStrictEqual(s.deposit(FP(1), null, 0), { ok: false, error: 'bad id' }, 'a missing item does not throw');
  // the default cap is 64 KiB
  const d = mailbox.createStore(); d.register(FP(1), 0);
  assert.deepStrictEqual(d.deposit(FP(1), { id: 'x', blob: fakeBlob(64 * 1024 + 1) }, 0), { ok: false, error: 'blob too big' });
  assert.deepStrictEqual(d.deposit(FP(1), { id: 'y', blob: fakeBlob(64 * 1024) }, 0), { ok: true });
});

t('per-recipient cap: the next deposit is refused, other recipients are unaffected', () => {
  const s = mailbox.createStore({ maxPerRecipient: 3 });
  s.register(FP(1), 0); s.register(FP(2), 0);
  for (const id of ['a', 'b', 'c']) assert.deepStrictEqual(s.deposit(FP(1), { id, blob: fakeBlob() }, 0), { ok: true });
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'd', blob: fakeBlob() }, 0), { ok: false, error: 'recipient full' });
  assert.deepStrictEqual(s.deposit(FP(2), { id: 'd', blob: fakeBlob() }, 0), { ok: true });
  assert.strictEqual(s.ack(FP(1), ['a']), 1);
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'd', blob: fakeBlob() }, 0), { ok: true }, 'room again after an ack');
});

t('total byte cap: counted across recipients, freed by ack and unregister', () => {
  const s = mailbox.createStore({ maxTotalBytes: 600 });
  s.register(FP(1), 0); s.register(FP(2), 0);
  assert(s.deposit(FP(1), { id: 'a', blob: fakeBlob(200) }, 0).ok);
  assert(s.deposit(FP(1), { id: 'b', blob: fakeBlob(200) }, 0).ok);
  assert(s.deposit(FP(2), { id: 'c', blob: fakeBlob(200) }, 0).ok);
  assert.strictEqual(s.stats().bytes, 600);
  assert.deepStrictEqual(s.deposit(FP(2), { id: 'd', blob: fakeBlob(mailbox.OVERHEAD) }, 0), { ok: false, error: 'mailbox full' });
  s.ack(FP(2), ['c']);
  assert.strictEqual(s.stats().bytes, 400);
  assert(s.deposit(FP(2), { id: 'd', blob: fakeBlob(200) }, 0).ok);
  assert.strictEqual(s.unregister(FP(1)), true);
  assert.strictEqual(s.unregister(FP(1)), false);
  assert.deepStrictEqual([s.stats().bytes, s.stats().items], [200, 1], 'unregister dropped its mail');
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'e', blob: fakeBlob() }, 0), { ok: false, error: 'recipient not registered here' });
});

t('a duplicate id is accepted and stored once, even when the recipient is full', () => {
  const s = mailbox.createStore({ maxPerRecipient: 1 });
  s.register(FP(1), 0);
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'same', blob: fakeBlob(200, 1) }, 0), { ok: true });
  assert.deepStrictEqual(s.deposit(FP(1), { id: 'same', blob: fakeBlob(300, 2) }, 5), { ok: true, duplicate: true });
  const st = s.stats();
  assert.deepStrictEqual([st.items, st.bytes], [1, 200]);
  const got = s.fetch(FP(1));
  assert.strictEqual(got.length, 1);
  assert(got[0].blob.equals(fakeBlob(200, 1)), 'the first copy is kept');
  assert.strictEqual(got[0].at, 0);
  // the same id for another recipient is a different item
  s.register(FP(2), 0);
  assert.deepStrictEqual(s.deposit(FP(2), { id: 'same', blob: fakeBlob() }, 0), { ok: true });
});

t('fetch is oldest first, limited and non-destructive; ack removes only that recipient\'s ids', () => {
  const s = mailbox.createStore();
  s.register(FP(1), 0); s.register(FP(2), 0);
  for (let i = 0; i < 60; i++) s.deposit(FP(1), { id: 'm' + i, blob: fakeBlob(mailbox.OVERHEAD + i) }, 1000 + i);
  s.deposit(FP(2), { id: 'm0', blob: fakeBlob() }, 0);
  const first = s.fetch(FP(1));
  assert.strictEqual(first.length, 50, 'default limit 50');
  assert.deepStrictEqual(first.slice(0, 3).map((x) => [x.id, x.at, x.blob.length]), [['m0', 1000, 125], ['m1', 1001, 126], ['m2', 1002, 127]]);
  assert.strictEqual(s.fetch(FP(1), 5).length, 5);
  assert.strictEqual(s.fetch(FP(1), 500).length, 60);
  assert.strictEqual(s.fetch(FP(1), -1).length, 50, 'a bad limit falls back to 50');
  assert.strictEqual(s.fetch(FP(1)).length, 50, 'fetch removed nothing');
  first[0].blob.fill(0);
  assert.strictEqual(s.fetch(FP(1), 1)[0].blob[0], 1, 'fetched blobs are copies');
  assert.deepStrictEqual(s.fetch(FP(3)), [], 'unregistered: nothing');
  assert.strictEqual(s.ack(FP(3), ['m0']), 0);
  assert.strictEqual(s.ack(FP(1), ['m0', 'm1', 'm1', 'nope', 7, null]), 2);
  assert.strictEqual(s.ack(FP(1), 'm2'), 1, 'a single id');
  assert.strictEqual(s.ack(FP(1), null), 0);
  assert.strictEqual(s.fetch(FP(1), 1)[0].id, 'm3');
  assert.strictEqual(s.fetch(FP(2)).length, 1, 'bob\'s m0 survived alice\'s ack of m0');
  assert.strictEqual(s.stats().items, 58);
});

t('ttl prune: old mail and stale registrations go; registering again keeps the box but not old mail', () => {
  const TTL = 1000;
  const s = mailbox.createStore({ ttlMs: TTL });
  s.register(FP(1), 0); s.register(FP(2), 0);
  s.deposit(FP(1), { id: 'old', blob: fakeBlob(200) }, 0);
  s.deposit(FP(1), { id: 'new', blob: fakeBlob(200) }, 600);
  s.register(FP(1), 500);                                   // FP(1) checks in, FP(2) never does
  assert.deepStrictEqual(s.prune(TTL - 1), { items: 0, recipients: 0 }, 'nothing is due yet');
  assert.deepStrictEqual(s.prune(TTL), { items: 1, recipients: 1 });
  assert.strictEqual(s.isRegistered(FP(2)), false, 'stale registration dropped');
  assert.strictEqual(s.isRegistered(FP(1)), true, 'refreshed registration kept');
  assert.deepStrictEqual(s.fetch(FP(1)).map((x) => x.id), ['new']);
  assert.strictEqual(s.stats().bytes, 200);
  s.register(FP(1), 1599);
  assert.deepStrictEqual(s.prune(1600), { items: 1, recipients: 0 }, 'refreshing does not extend mail');
  s.deposit(FP(1), { id: 'later', blob: fakeBlob() }, 2000);
  assert.deepStrictEqual(s.prune(2599), { items: 1, recipients: 1 }, 'a stale box takes its mail with it');
  assert.deepStrictEqual(s.stats(), { ...s.stats(), recipients: 0, items: 0, bytes: 0 });
});

t('registration cap: refused when full, re-registering is fine, unregister makes room', () => {
  const s = mailbox.createStore({ maxRecipients: 3 });
  for (let i = 1; i <= 3; i++) assert.strictEqual(s.register(FP(i), 0), true);
  assert.strictEqual(s.register(FP(4), 0), false);
  assert.strictEqual(s.isRegistered(FP(4)), false);
  assert.strictEqual(s.register(FP(2), 10), true, 'refresh while full');
  s.unregister(FP(1));
  assert.strictEqual(s.register(FP(4), 0), true);
  assert.strictEqual(s.stats().recipients, 3);
});

t('toJSON / fromJSON round trip through state.json', () => {
  const s = mailbox.createStore({ ttlMs: 5000 });
  s.register(FP(1), 100); s.register(FP(2), 200);
  const blob = sealAB('kept across a restart');
  s.deposit(FP(1), { id: 'a', blob }, 110);
  s.deposit(FP(1), { id: 'b', blob: fakeBlob(150) }, 120);
  const json = JSON.parse(JSON.stringify(s));
  assert.strictEqual(json.v, 1);
  assert.strictEqual(typeof json.recipients[FP(1)].items[0].blob, 'string', 'blobs as base64');
  const r = mailbox.fromJSON(json, { ttlMs: 5000 });
  const byFp = (j) => Object.keys(j.recipients).sort().map((fp) => [fp, j.recipients[fp]]);
  assert.deepStrictEqual(byFp(r.toJSON()), byFp(s.toJSON()));
  assert.deepStrictEqual(r.stats(), s.stats());
  const got = r.fetch(FP(1));
  assert.deepStrictEqual(got.map((x) => [x.id, x.at]), [['a', 110], ['b', 120]], 'oldest first after loading');
  assert.strictEqual(openB(got[0].blob).plaintext.toString(), 'kept across a restart');
  assert.strictEqual(mailbox.MailboxStore.fromJSON(json).stats().items, 2, 'static fromJSON on the class');
  // registration times survive: FP(1) goes stale first
  assert.deepStrictEqual(r.prune(5100), { items: 2, recipients: 1 });
  assert.strictEqual(r.isRegistered(FP(2)), true);
});

t('fromJSON drops anything malformed and never throws', () => {
  const good = fakeBlob(200).toString('base64');
  const garbage = [undefined, null, 0, 'state', [], [1, 2], {}, { v: 2, recipients: {} }, { v: '1', recipients: {} },
    { v: 1 }, { v: 1, recipients: null }, { v: 1, recipients: [] }, { v: 1, recipients: 'x' },
    { v: 1, recipients: { [FP(1)]: null } }, { v: 1, recipients: { [FP(1)]: 'x' } }, { v: 1, recipients: { [FP(1)]: { seen: 'yesterday' } } },
    { v: 1, recipients: { [FP(1)]: { seen: NaN, items: [] } } },
    JSON.parse('{"v":1,"recipients":{"__proto__":{"seen":1,"items":[]}}}')];
  for (const g of garbage) {
    const s = mailbox.fromJSON(g);
    assert.strictEqual(s.stats().recipients, 0, JSON.stringify(g));
  }
  const mixed = { v: 1, recipients: {
    [FP(1)]: { seen: 10, items: [
      { id: 'ok1', at: 1, blob: good },
      { id: 'ok1', at: 2, blob: fakeBlob(300).toString('base64') },          // duplicate id: first kept
      { id: 'bad id', at: 1, blob: good },
      { id: 'noat', blob: good },
      { id: 'strat', at: '1', blob: good },
      { id: 'notb64', at: 1, blob: '!!!!' },
      { id: 'noncanon', at: 1, blob: good.slice(0, -2) + 'B=' },
      { id: 'nopad', at: 1, blob: good.replace(/=+$/, '') },
      { id: 'short', at: 1, blob: fakeBlob(20).toString('base64') },
      { id: 'v2', at: 1, blob: Buffer.concat([Buffer.from([2]), fakeBlob(200).subarray(1)]).toString('base64') },
      { id: 'huge', at: 1, blob: 'A'.repeat(4 * 1024 * 1024) },
      { id: 'numblob', at: 1, blob: 12 },
      null, 'item', 7,
      { id: 'ok2', at: 3, blob: good },
    ] },
    [FP(2)]: { seen: 20, items: 'not an array' },
    [FP(3)]: { seen: 30 },
    NOTAFP: { seen: 40, items: [] },
  } };
  const s = mailbox.fromJSON(mixed);
  assert.deepStrictEqual(s.fetch(FP(1)).map((x) => [x.id, x.blob.length]), [['ok1', 200], ['ok2', 200]]);
  assert.deepStrictEqual([s.isRegistered(FP(2)), s.isRegistered(FP(3)), s.stats().recipients], [true, true, 3]);
  assert.strictEqual(s.stats().bytes, 400);
  assert.strictEqual(({}).seen, undefined, 'no prototype pollution');
});

t('fromJSON applies the current limits, keeping the most recently registered', () => {
  const s = mailbox.createStore();
  for (let i = 1; i <= 5; i++) { s.register(FP(i), i * 10); for (let j = 0; j < 4; j++) s.deposit(FP(i), { id: 'm' + j, blob: fakeBlob(200) }, j); }
  const r = mailbox.fromJSON(s.toJSON(), { maxRecipients: 2, maxPerRecipient: 3, maxTotalBytes: 1000, maxBlobBytes: 200 });
  assert.deepStrictEqual([1, 2, 3, 4, 5].map((i) => r.isRegistered(FP(i))), [false, false, false, true, true]);
  assert.deepStrictEqual(r.fetch(FP(5)).map((x) => x.id), ['m0', 'm1', 'm2'], 'per-recipient cap');
  assert.deepStrictEqual(r.fetch(FP(4)).map((x) => x.id), ['m0', 'm1'], 'total cap');
  assert.strictEqual(r.stats().bytes, 1000);
  const tiny = mailbox.fromJSON(s.toJSON(), { maxBlobBytes: 199 });
  assert.strictEqual(tiny.stats().items, 0, 'blobs over maxBlobBytes dropped');
});

t('end to end: alice deposits for bob, the mailbox holds only a fingerprint, bob fetches, opens and acks', () => {
  const box = mailbox.createStore();
  assert(box.register(bob.fp, 1));
  const id = mailbox.newDepositId();
  assert.match(id, mailbox.ID_RE);
  assert.notStrictEqual(id, mailbox.newDepositId());
  assert.deepStrictEqual(box.deposit(bob.fp, { id, blob: sealAB('{"t":"msg","id":"x1","text":"gm"}') }, 2), { ok: true });
  const saved = JSON.stringify(box);
  assert(saved.includes(bob.fp) && !saved.includes(alice.fp), 'state names the recipient only');
  assert(!saved.includes(alice.pubRaw.toString('base64')), 'not the sender key either');
  const [m] = box.fetch(bob.fp);
  const opened = openB(m.blob);
  assert.strictEqual(opened.senderFp, alice.fp);
  assert.strictEqual(JSON.parse(opened.plaintext).text, 'gm');
  assert.strictEqual(box.ack(bob.fp, [m.id]), 1);
  assert.strictEqual(box.fetch(bob.fp).length, 0);
});

console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
