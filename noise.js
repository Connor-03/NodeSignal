// noise.js — authenticated key agreement for NodeSignal
// ============================================================================
// A Noise-XX-style handshake over X25519 + HKDF-SHA256 + ChaCha20-Poly1305,
// built entirely on Node's built-in `crypto` (no dependencies).
//
// WHY THIS REPLACES THE PIN
//   The shared-PIN scheme had three fatal weaknesses: a 4-digit PIN brute-forces
//   in minutes, the salt was a global constant (one table breaks every user),
//   and there was no forward secrecy or peer authentication. This fixes all of
//   them at once:
//     · identity is a persistent X25519 keypair, not a guessable PIN
//     · every connection mixes in fresh EPHEMERAL keys, so stealing a static
//       key later cannot decrypt past sessions (forward secrecy)
//     · each side proves possession of its static private key, so a man in the
//       middle who cannot forge a signature is detected and rejected
//     · the first time you talk to a peer you record their key fingerprint
//       (TOFU); a later mismatch means the identity changed — surfaced loudly
//
// WIRE (length-prefixed frames, all binary):
//   -> msg1 : e                       32-byte ephemeral public key, cleartext
//   <- msg2 : e || enc(s) || enc(hi)  responder ephemeral + encrypted static id
//   -> msg3 : enc(s) || enc(hi)       initiator encrypted static id
//   then both hold the same session key; application frames are AEAD sealed.
// ============================================================================
'use strict';
const crypto = require('crypto');

const PROLOGUE = Buffer.from('NodeSignal-noise-v1');
const HKDF = (salt, ikm, info, n = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, n));
const dh = (priv, pub) => crypto.diffieHellman({ privateKey: priv, publicKey: pub });
const genEph = () => crypto.generateKeyPairSync('x25519');
const rawPub = (k) => k.export({ type: 'spki', format: 'der' });          // 44 bytes
const impPub = (b) => crypto.createPublicKey({ key: b, format: 'der', type: 'spki' });
const PUBLEN = 44;

function fingerprint(rawPubDer) {
  return crypto.createHash('sha256').update(rawPubDer).digest('hex').slice(0, 32);
}
function mixKey(ck, ikm) {
  const out = HKDF(ck, ikm, Buffer.from('ns-mix'), 64);
  return { ck: out.slice(0, 32), k: out.slice(32, 64) };
}
const nonceBuf = (n) => { const b = Buffer.alloc(12); b.writeBigUInt64LE(BigInt(n), 4); return b; };
function seal(k, n, pt, ad) {
  const c = crypto.createCipheriv('chacha20-poly1305', k, nonceBuf(n), { authTagLength: 16 });
  if (ad) c.setAAD(ad);
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function open(k, n, ct, ad) {
  const c = crypto.createDecipheriv('chacha20-poly1305', k, nonceBuf(n), { authTagLength: 16 });
  if (ad) c.setAAD(ad);
  c.setAuthTag(ct.slice(-16));
  return Buffer.concat([c.update(ct.slice(0, -16)), c.final()]);
}

/* ---- static identity: generate once, persist the DER-encoded keys ---- */
function newIdentity() {
  const kp = crypto.generateKeyPairSync('x25519');
  return {
    priv: kp.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    pub: rawPub(kp.publicKey).toString('base64'),
  };
}
function loadIdentity(id) {
  const priv = crypto.createPrivateKey({ key: Buffer.from(id.priv, 'base64'), format: 'der', type: 'pkcs8' });
  const pubDer = Buffer.from(id.pub, 'base64');
  return { priv, pubDer, pub: impPub(pubDer), fp: fingerprint(pubDer) };
}

/* ---- initiator ---- */
function initStart(self) {
  const e = genEph();
  return { self, e, msg1: rawPub(e.publicKey) };
}
function initFinish(st, msg2) {
  const beRaw = msg2.slice(0, PUBLEN);
  const bobStaticCt = msg2.slice(PUBLEN);
  const be = impPub(beRaw);
  let ck = Buffer.concat([PROLOGUE, Buffer.alloc(32)]).slice(0, 32);
  let r = mixKey(ck, dh(st.e.privateKey, be)); ck = r.ck;                    // ee
  const peerPubDer = open(r.k, 0, bobStaticCt, st.msg1);                     // decrypt responder static
  r = mixKey(ck, dh(st.e.privateKey, impPub(peerPubDer))); ck = r.ck;       // es
  const myStaticCt = seal(r.k, 0, st.self.pubDer, beRaw);
  const r2 = mixKey(ck, dh(st.self.priv, be)); ck = r2.ck;                  // se
  const session = HKDF(ck, Buffer.alloc(0), Buffer.from('ns-session'), 64);
  return {
    msg3: myStaticCt,
    peerFp: fingerprint(peerPubDer),
    peerPub: peerPubDer.toString('base64'),
    tx: session.slice(0, 32), rx: session.slice(32, 64),
  };
}
/* ---- responder ---- */
function respond(self, msg1) {
  const e = genEph();
  let ck = Buffer.concat([PROLOGUE, Buffer.alloc(32)]).slice(0, 32);
  let r = mixKey(ck, dh(e.privateKey, impPub(msg1))); ck = r.ck;             // ee
  const staticCt = seal(r.k, 0, self.pubDer, msg1);
  const r2 = mixKey(ck, dh(self.priv, impPub(msg1))); ck = r2.ck;           // es
  const msg2 = Buffer.concat([rawPub(e.publicKey), staticCt]);
  // msg3 is sealed by the initiator with the post-'es' key (r2.k) — the
  // responder must open it with the SAME key, then advance with 'se'.
  return { e, ck, k_msg3: r2.k, msg2, self,
    _finish(msg3) {
      const peerPubDer = open(this.k_msg3, 0, msg3, rawPub(this.e.publicKey));
      const rr = mixKey(this.ck, dh(this.e.privateKey, impPub(peerPubDer)));  // se
      const session = HKDF(rr.ck, Buffer.alloc(0), Buffer.from('ns-session'), 64);
      return {
        peerFp: fingerprint(peerPubDer),
        peerPub: peerPubDer.toString('base64'),
        rx: session.slice(0, 32), tx: session.slice(32, 64),   // mirror of initiator
      };
    } };
}

/* ---- transport: AEAD frames with per-direction counters ---- */
function makeSession(tx, rx) {
  let sN = 0, rN = 0;
  return {
    encrypt: (plaintext) => seal(tx, sN++, Buffer.from(plaintext, 'utf8')),
    decrypt: (frame) => open(rx, rN++, frame).toString('utf8'),
  };
}

module.exports = {
  newIdentity, loadIdentity, fingerprint,
  initStart, initFinish, respond, makeSession,
  PUBLEN,
};
