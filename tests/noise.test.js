// noise.test.js: Noise_XX_25519_ChaChaPoly_SHA256 (v3) and legacy v2 checks. Plain node, no deps.
//   node tests/noise.test.js
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto'), assert = require('assert');
const noise = require('../noise.js');
const { HandshakeState, CipherState, v3, legacy } = noise;

let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
};
const hex = (s) => Buffer.from(s || '', 'hex');
const eqHex = (buf, want, what) => assert.strictEqual(buf.toString('hex'), want, what);
const kp = (privHex) => { const priv = hex(privHex); return { priv, pub: noise.publicFromPrivate(priv) }; };
const flip = (buf, i) => { const b = Buffer.from(buf); b[i] ^= 0x01; return b; };
const ident = () => noise.loadIdentity(noise.newIdentity());
function v3Pair(A, B) {
  const a = v3.initStart(A);
  const r = v3.respond(B, a.msg1);
  const f = v3.initFinish(a, r.msg2);
  const g = r.finish(f.msg3);
  return { a, r, f, g };
}

/* ---- third-party test vectors ---------------------------------------- */
const vecFile = require('./vectors/noise_xx_25519_chachapoly_sha256.json');
let vectorsChecked = 0;
for (const [idx, v] of vecFile.vectors.entries()) {
  t(`vector ${idx + 1} (${v.source}): ${v.protocol_name}, ${v.messages.length} messages${v.handshake_hash ? ' + handshake_hash' : ''}`, () => {
    assert.strictEqual(v.protocol_name, noise.PROTOCOL_NAME);
    const I = new HandshakeState({ initiator: true, s: kp(v.init_static), e: kp(v.init_ephemeral), prologue: hex(v.init_prologue) });
    const R = new HandshakeState({ initiator: false, s: kp(v.resp_static), e: kp(v.resp_ephemeral), prologue: hex(v.resp_prologue) });
    let iT, rT;
    v.messages.forEach((m, i) => {
      const fromInit = i % 2 === 0;
      if (i < 3) {
        const [w, r] = fromInit ? [I, R] : [R, I];
        const ct = w.writeMessage(hex(m.payload));
        eqHex(ct, m.ciphertext, `handshake message ${i} ciphertext`);
        eqHex(r.readMessage(ct), m.payload, `handshake message ${i} payload`);
        if (i === 2) {
          assert(I.complete && R.complete, 'both sides complete after msg3');
          eqHex(I.rs, kp(v.resp_static).pub.toString('hex'), 'initiator learned responder static');
          eqHex(R.rs, kp(v.init_static).pub.toString('hex'), 'responder learned initiator static');
          assert(I.h.equals(R.h), 'handshake hashes agree');
          if (v.handshake_hash) eqHex(I.h, v.handshake_hash, 'handshake_hash');
          iT = I.split(); rT = R.split();
        }
      } else {
        const [tx, rx] = fromInit ? [iT.tx, rT.rx] : [rT.tx, iT.rx];
        const ct = tx.encryptWithAd(Buffer.alloc(0), hex(m.payload));
        eqHex(ct, m.ciphertext, `transport message ${i} ciphertext`);
        eqHex(rx.decryptWithAd(Buffer.alloc(0), ct), m.payload, `transport message ${i} payload`);
      }
    });
    vectorsChecked++;
  });
}
t('at least one vector carries a handshake_hash and was checked', () => {
  assert(vecFile.vectors.some((v) => v.handshake_hash));
  assert.strictEqual(vectorsChecked, vecFile.vectors.length);
});

/* ---- v3 wrappers ------------------------------------------------------ */
const A = ident(), B = ident(), C = ident();

t('v3 msg1 is exactly 32 bytes, v2 msg1 is 44 (responder can dispatch on length)', () => {
  assert.strictEqual(v3.initStart(A).msg1.length, 32);
  assert.strictEqual(legacy.initStart(A).msg1.length, 44);
});
t('v3 handshake sizes: msg2 96 bytes, msg3 64 bytes', () => {
  const { r, f } = v3Pair(A, B);
  assert.strictEqual(r.msg2.length, 96);
  assert.strictEqual(f.msg3.length, 64);
});
t('v3 round trip: peerFp/peerPub correct on both sides, messages decrypt in order', () => {
  const { f, g } = v3Pair(A, B);
  assert.strictEqual(f.peerFp, B.fp);
  assert.strictEqual(g.peerFp, A.fp);
  assert.strictEqual(f.peerPub, B.pubDer.toString('base64'));
  assert.strictEqual(g.peerPub, A.pubDer.toString('base64'));
  assert(f.handshakeHash.equals(g.handshakeHash), 'handshake hash agrees');
  const msgs = ['hello', '', 'unicode é漢\u{1F680}', JSON.stringify({ type: 'msg', text: 'x'.repeat(5000) })];
  for (const m of msgs) assert.strictEqual(g.session.decrypt(f.session.encrypt(m)), m);
  for (const m of msgs) assert.strictEqual(f.session.decrypt(g.session.encrypt(m)), m);
});
t('v3 sessions are fresh per handshake (same identities, different keys)', () => {
  const p1 = v3Pair(A, B), p2 = v3Pair(A, B);
  assert(!p1.f.session.encrypt('same').equals(p2.f.session.encrypt('same')));
  assert(!p1.f.handshakeHash.equals(p2.f.handshakeHash));
});

/* ---- tamper rejection -------------------------------------------------- */
t('flipping any byte of msg2 makes initFinish throw', () => {
  const a = v3.initStart(A);
  const r = v3.respond(B, a.msg1);
  for (let i = 0; i < r.msg2.length; i++) {
    const fresh = v3.initStart(A);
    const rr = v3.respond(B, fresh.msg1);
    assert.throws(() => v3.initFinish(fresh, flip(rr.msg2, i)), undefined, `msg2 byte ${i}`);
  }
});
t('flipping any byte of msg3 makes finish throw', () => {
  for (let i = 0; i < 64; i++) {
    const a = v3.initStart(A);
    const r = v3.respond(B, a.msg1);
    const f = v3.initFinish(a, r.msg2);
    assert.throws(() => r.finish(flip(f.msg3, i)), undefined, `msg3 byte ${i}`);
  }
});
t('truncated or extended handshake messages are rejected', () => {
  const a = v3.initStart(A), a2 = v3.initStart(A);
  const r = v3.respond(B, a.msg1), r2 = v3.respond(B, a2.msg1);
  assert.throws(() => v3.initFinish(a, r.msg2.subarray(0, 95)), undefined, 'msg2 short by one');
  assert.throws(() => v3.initFinish(a2, Buffer.concat([r2.msg2, Buffer.from([0])])), undefined, 'msg2 long by one');
  const a3 = v3.initStart(A), r3 = v3.respond(B, a3.msg1), f3 = v3.initFinish(a3, r3.msg2);
  assert.throws(() => r3.finish(f3.msg3.subarray(0, 63)), undefined, 'msg3 short by one');
  assert.throws(() => v3.respond(B, a.msg1.subarray(0, 31)));
  assert.throws(() => v3.respond(B, Buffer.concat([a.msg1, Buffer.alloc(12)])));
});
t('a msg1 replayed into a different handshake does not authenticate', () => {
  const a1 = v3.initStart(A), a2 = v3.initStart(A);
  const r = v3.respond(B, a1.msg1);
  assert.throws(() => v3.initFinish(a2, r.msg2));
});
t('flipping any byte of a transport frame throws, and does not consume the nonce', () => {
  const { f, g } = v3Pair(A, B);
  const frame = f.session.encrypt('attack at dawn');
  for (let i = 0; i < frame.length; i++) assert.throws(() => g.session.decrypt(flip(frame, i)), undefined, `frame byte ${i}`);
  assert.strictEqual(g.session.decrypt(frame), 'attack at dawn');
});
t('a different responder static key yields a different peerFp', () => {
  const viaB = v3Pair(A, B).f.peerFp, viaC = v3Pair(A, C).f.peerFp;
  assert.strictEqual(viaB, B.fp);
  assert.strictEqual(viaC, C.fp);
  assert.notStrictEqual(viaB, viaC);
});
t('splicing another responder\'s encrypted static into msg2 is rejected', () => {
  const a = v3.initStart(A);
  const rB = v3.respond(B, a.msg1), rC = v3.respond(C, a.msg1);
  const spliced = Buffer.concat([rB.msg2.subarray(0, 32), rC.msg2.subarray(32)]);
  assert.throws(() => v3.initFinish(a, spliced));
});
t('low-order (all-zero) ephemeral in msg1 aborts the responder', () => {
  assert.throws(() => v3.respond(B, Buffer.alloc(32)));
});
t('handshake steps are single-use and enforce turn order', () => {
  const a = v3.initStart(A);
  const r = v3.respond(B, a.msg1);
  const f = v3.initFinish(a, r.msg2);
  r.finish(f.msg3);
  assert.throws(() => r.finish(f.msg3), undefined, 'finish twice');
  assert.throws(() => v3.initFinish(a, r.msg2), undefined, 'initFinish twice');
  const hs = new HandshakeState({ initiator: true, s: { priv: A.privRaw, pub: A.pubRaw }, prologue: noise.PROLOGUE_V3 });
  assert.throws(() => hs.readMessage(Buffer.alloc(32)), undefined, 'initiator must write first');
  assert.throws(() => hs.split(), undefined, 'split before completion');
});
t('prologue mismatch is detected', () => {
  const I = new HandshakeState({ initiator: true, s: { priv: A.privRaw, pub: A.pubRaw }, prologue: Buffer.from('NodeSignal/3') });
  const R = new HandshakeState({ initiator: false, s: { priv: B.privRaw, pub: B.pubRaw }, prologue: Buffer.from('NodeSignal/4') });
  R.readMessage(I.writeMessage(Buffer.alloc(0)));
  assert.throws(() => I.readMessage(R.writeMessage(Buffer.alloc(0))));
});

/* ---- replay / ordering ------------------------------------------------- */
t('out-of-order and replayed transport frames are rejected', () => {
  const { f, g } = v3Pair(A, B);
  const f1 = f.session.encrypt('one'), f2 = f.session.encrypt('two');
  assert.throws(() => g.session.decrypt(f2), undefined, 'frame 2 before frame 1');
  assert.strictEqual(g.session.decrypt(f1), 'one');
  assert.throws(() => g.session.decrypt(f1), undefined, 'replayed frame 1');
  assert.strictEqual(g.session.decrypt(f2), 'two');
  assert.throws(() => g.session.decrypt(f2), undefined, 'replayed frame 2');
  assert.throws(() => f.session.decrypt(f1), undefined, 'reflected back to sender');
});
t('CipherState refuses the reserved nonce 2^64-1', () => {
  const k = crypto.randomBytes(32);
  const tx = new CipherState(k), rx = new CipherState(k);
  tx.setNonce((1n << 64n) - 2n); rx.setNonce((1n << 64n) - 2n);
  assert.strictEqual(rx.decryptWithAd(Buffer.alloc(0), tx.encryptWithAd(Buffer.alloc(0), Buffer.from('last'))).toString(), 'last');
  assert.throws(() => tx.encryptWithAd(Buffer.alloc(0), Buffer.from('x')));
  assert.throws(() => rx.decryptWithAd(Buffer.alloc(0), Buffer.alloc(16)));
});

/* ---- size limit -------------------------------------------------------- */
t('message size limit (65535 bytes incl. tag) is enforced', () => {
  assert.strictEqual(noise.MAX_MSG, 65535);
  const { f, g } = v3Pair(A, B);
  const max = 'x'.repeat(65535 - 16);
  const frame = f.session.encrypt(max);
  assert.strictEqual(frame.length, 65535);
  assert.strictEqual(g.session.decrypt(frame), max);
  assert.throws(() => f.session.encrypt(max + 'x'), undefined, 'one byte over');
  assert.throws(() => f.session.encrypt('é'.repeat(32760)), undefined, 'limit counts UTF-8 bytes');
  assert.throws(() => g.session.decrypt(Buffer.alloc(65536)), undefined, 'oversize inbound frame');
  assert.throws(() => g.session.decrypt(Buffer.alloc(15)), undefined, 'undersize inbound frame');
  const hs = new HandshakeState({ initiator: true, s: { priv: A.privRaw, pub: A.pubRaw } });
  assert.throws(() => hs.writeMessage(Buffer.alloc(65535 - 32 + 1)), undefined, 'oversize handshake message');
});

/* ---- fingerprints ------------------------------------------------------ */
t('fingerprintRaw(pubRaw) equals fingerprint(pubDer)', () => {
  for (const X of [A, B, C]) {
    assert.strictEqual(noise.fingerprintRaw(X.pubRaw), noise.fingerprint(X.pubDer));
    assert.strictEqual(noise.fingerprintRaw(X.pubRaw), X.fp);
    assert.strictEqual(X.pubRaw.length, 32);
    assert.strictEqual(X.privRaw.length, 32);
    assert(noise.publicFromPrivate(X.privRaw).equals(X.pubRaw), 'privRaw and pubRaw belong together');
  }
});
t('v2 and v3 report the same peerFp for the same identity (state.json pins stay valid)', () => {
  const s = legacy.initStart(A), r = legacy.respond(B, s.msg1), f2 = legacy.initFinish(s, r.msg2), g2 = r._finish(f2.msg3);
  const { f, g } = v3Pair(A, B);
  assert.strictEqual(f.peerFp, f2.peerFp);
  assert.strictEqual(g.peerFp, g2.peerFp);
  assert.strictEqual(f.peerPub, f2.peerPub);
  assert.strictEqual(g.peerPub, g2.peerPub);
});
t('identity format unchanged: newIdentity is base64 PKCS8 / SPKI DER', () => {
  const id = noise.newIdentity();
  assert.strictEqual(Buffer.from(id.pub, 'base64').length, 44);
  crypto.createPrivateKey({ key: Buffer.from(id.priv, 'base64'), format: 'der', type: 'pkcs8' });
  const L = noise.loadIdentity(id);
  assert.strictEqual(L.fp, noise.fingerprint(Buffer.from(id.pub, 'base64')));
});

/* ---- legacy v2 --------------------------------------------------------- */
t('v2 legacy round trip works as the daemon uses it', () => {
  const s = noise.initStart(A);
  const r = noise.respond(B, s.msg1);
  const f = noise.initFinish(s, r.msg2);
  const g = r._finish(f.msg3);
  assert.strictEqual(f.peerFp, B.fp);
  assert.strictEqual(g.peerFp, A.fp);
  const sa = noise.makeSession(f.tx, f.rx), sb = noise.makeSession(g.tx, g.rx);
  for (const m of ['a', 'b', '']) assert.strictEqual(sb.decrypt(sa.encrypt(m)), m);
  for (const m of ['c', 'd']) assert.strictEqual(sa.decrypt(sb.encrypt(m)), m);
});
t('top-level v2 names are aliases of legacy', () => {
  for (const k of ['initStart', 'initFinish', 'respond', 'makeSession']) assert.strictEqual(noise[k], legacy[k], k);
  assert.strictEqual(noise.PUBLEN, 44);
});
t('v2 legacy reproduces the pre-v3 golden vector byte for byte', () => {
  const G = require('./vectors/noise_v2_golden.json');
  const P8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
  const keyFrom = (b) => {
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([P8, Buffer.alloc(32, parseInt(b, 16))]), format: 'der', type: 'pkcs8' });
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
  };
  const idFrom = (b) => {
    const k = keyFrom(b);
    return noise.loadIdentity({
      priv: k.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      pub: k.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    });
  };
  const GA = idFrom(G.static_bytes.initiator), GB = idFrom(G.static_bytes.responder);
  const real = crypto.generateKeyPairSync;
  const queue = [G.ephemeral_bytes.initiator, G.ephemeral_bytes.responder];
  crypto.generateKeyPairSync = (type, ...rest) => (queue.length ? keyFrom(queue.shift()) : real(type, ...rest));
  let s, r, f, g;
  try {
    s = legacy.initStart(GA); r = legacy.respond(GB, s.msg1); f = legacy.initFinish(s, r.msg2); g = r._finish(f.msg3);
  } finally { crypto.generateKeyPairSync = real; }
  eqHex(s.msg1, G.msg1, 'msg1'); eqHex(r.msg2, G.msg2, 'msg2'); eqHex(f.msg3, G.msg3, 'msg3');
  eqHex(f.tx, G.tx, 'tx'); eqHex(f.rx, G.rx, 'rx');
  assert.strictEqual(g.peerFp, G.fpA); assert.strictEqual(f.peerFp, G.fpB);
  eqHex(legacy.makeSession(f.tx, f.rx).encrypt('hello v2'), G.frameAB, 'frame A->B');
  eqHex(legacy.makeSession(g.tx, g.rx).encrypt('hi back'), G.frameBA, 'frame B->A');
});

/* ---- house rules ------------------------------------------------------- */
t('no em dashes in noise.js or this test', () => {
  const dash = String.fromCharCode(0x2014);
  assert(!fs.readFileSync(path.join(__dirname, '..', 'noise.js'), 'utf8').includes(dash));
  assert(!fs.readFileSync(__filename, 'utf8').includes(dash));
});

console.log(`\n${vectorsChecked} third-party vectors checked`);
console.log(failed ? `${failed} failed, ${passed} passed` : `all passed (${passed})`);
process.exit(failed ? 1 : 0);
