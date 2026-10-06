// noise.js: authenticated key agreement for NodeSignal (Node standard library only)
// ============================================================================
// v3 (current): Noise_XX_25519_ChaChaPoly_SHA256, implemented per the Noise
// Protocol Framework specification, revision 34
// (https://noiseprotocol.org/noise.html). The low-level CipherState /
// SymmetricState / HandshakeState objects follow the spec's section 5
// definitions, and tests/noise.test.js checks them byte for byte against the
// third-party cacophony (and snow) test vectors for this exact protocol name.
//
//   XX:
//     -> e
//     <- e, ee, s, es
//     -> s, se
//
//   prologue  : "NodeSignal/3" (PROLOGUE_V3)
//   msg1      : exactly 32 bytes (initiator ephemeral, empty payload)
//   msg2      : 32 + 48 + 16 = 96 bytes (empty payload)
//   msg3      : 48 + 16 = 64 bytes (empty payload)
//   transport : one ChaChaPoly frame per message, empty AD, 64-bit counter
//               nonces, at most 65535 bytes per frame (MAX_MSG).
//
// Identity is a persistent X25519 keypair stored in state.json as base64
// PKCS8 DER (private) and base64 SPKI DER (public). A peer's fingerprint is
// sha256(SPKI DER) truncated to 32 hex chars, identical for v2 and v3, so
// TOFU pins recorded by older builds stay valid.
//
// v2 (legacy): the earlier custom "XX-style" handshake (crypto.hkdfSync with
// ad-hoc labels, DER-encoded keys on the wire, msg1 = 44 bytes). It is NOT
// Noise-compliant and is kept, byte-for-byte unchanged, only so that peers
// still running the previous release can talk to this one. It will be
// removed in the next release. A responder can tell the two apart by msg1
// length: 32 bytes means v3, 44 bytes means v2.
// ============================================================================
'use strict';
const crypto = require('crypto');

const PROTOCOL_NAME = 'Noise_XX_25519_ChaChaPoly_SHA256';
const PROLOGUE_V3 = Buffer.from('NodeSignal/3');
const MAX_MSG = 65535;
const DHLEN = 32, HASHLEN = 32, TAGLEN = 16;
const EMPTY = Buffer.alloc(0);
const SPKI_X25519_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');   // 12 bytes
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex'); // 16 bytes
const NONCE_MAX = (1n << 64n) - 1n;   // reserved by the spec, never used

/* ---------------------------------------------------------------------------
 * Fingerprints and identity (shared by v2 and v3)
 * ------------------------------------------------------------------------- */
function fingerprint(pubDer) {
  return crypto.createHash('sha256').update(pubDer).digest('hex').slice(0, 32);
}
function fingerprintRaw(pubRaw) {
  if (!Buffer.isBuffer(pubRaw) || pubRaw.length !== DHLEN) throw new Error('fingerprintRaw: need a 32-byte X25519 public key');
  return fingerprint(Buffer.concat([SPKI_X25519_PREFIX, pubRaw]));
}
const rawToDer = (pubRaw) => Buffer.concat([SPKI_X25519_PREFIX, pubRaw]);

function newIdentity() {
  const kp = crypto.generateKeyPairSync('x25519');
  return {
    priv: kp.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    pub: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}
function loadIdentity(id) {
  const priv = crypto.createPrivateKey({ key: Buffer.from(id.priv, 'base64'), format: 'der', type: 'pkcs8' });
  const pubDer = Buffer.from(id.pub, 'base64');
  if (pubDer.length !== 44 || !pubDer.subarray(0, 12).equals(SPKI_X25519_PREFIX)) throw new Error('identity: public key is not X25519 SPKI DER');
  const privRaw = Buffer.from(priv.export({ format: 'jwk' }).d, 'base64url');
  return {
    priv, pubDer, pub: legacyImpPub(pubDer),
    pubRaw: Buffer.from(pubDer.subarray(12)), privRaw,
    fp: fingerprint(pubDer),
  };
}

/* ---------------------------------------------------------------------------
 * Primitives: X25519, SHA-256, HMAC, Noise HKDF, ChaCha20-Poly1305
 * ------------------------------------------------------------------------- */
const b64u = (b) => Buffer.from(b).toString('base64url');
function publicFromPrivate(privRaw) {
  if (!Buffer.isBuffer(privRaw) || privRaw.length !== DHLEN) throw new Error('X25519 private key must be 32 bytes');
  const k = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, privRaw]), format: 'der', type: 'pkcs8' });
  return Buffer.from(k.export({ format: 'jwk' }).x, 'base64url');
}
function privKeyObject(kp) {
  return crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(kp.pub), d: b64u(kp.priv) }, format: 'jwk' });
}
function pubKeyObject(pubRaw) {
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(pubRaw) }, format: 'jwk' });
}
function generateKeypair() {
  const jwk = crypto.generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' });
  return { priv: Buffer.from(jwk.d, 'base64url'), pub: Buffer.from(jwk.x, 'base64url') };
}
// DH(key_pair, public_key). OpenSSL refuses an all-zero result (low-order
// point), which surfaces here as a thrown error and aborts the handshake.
function DH(kp, pubRaw) {
  if (!kp._ko) Object.defineProperty(kp, '_ko', { value: privKeyObject(kp), enumerable: false });
  return crypto.diffieHellman({ privateKey: kp._ko, publicKey: pubKeyObject(pubRaw) });
}
const HASH = (...parts) => { const h = crypto.createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const HMAC = (key, ...parts) => { const h = crypto.createHmac('sha256', key); for (const p of parts) h.update(p); return h.digest(); };
// Noise section 4.3: HKDF(chaining_key, input_key_material, num_outputs)
function HKDF(ck, ikm, n) {
  const temp = HMAC(ck, ikm);
  const o1 = HMAC(temp, Buffer.from([1]));
  const o2 = HMAC(temp, o1, Buffer.from([2]));
  if (n === 2) return [o1, o2];
  return [o1, o2, HMAC(temp, o2, Buffer.from([3]))];
}
// ChaChaPoly nonce: 32 bits of zeros then the 64-bit counter, little-endian.
function chachaNonce(n) { const b = Buffer.alloc(12); b.writeBigUInt64LE(BigInt(n), 4); return b; }
function ENCRYPT(k, n, ad, pt) {
  const c = crypto.createCipheriv('chacha20-poly1305', k, chachaNonce(n), { authTagLength: TAGLEN });
  c.setAAD(ad);
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function DECRYPT(k, n, ad, ct) {
  if (ct.length < TAGLEN) throw new Error('noise: ciphertext too short');
  const d = crypto.createDecipheriv('chacha20-poly1305', k, chachaNonce(n), { authTagLength: TAGLEN });
  d.setAAD(ad);
  d.setAuthTag(ct.subarray(ct.length - TAGLEN));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - TAGLEN)), d.final()]);   // final() throws on bad tag
}

/* ---------------------------------------------------------------------------
 * CipherState (spec 5.1)
 * ------------------------------------------------------------------------- */
class CipherState {
  constructor(k = null) { this.initializeKey(k); }
  initializeKey(k) {
    if (k !== null && (!Buffer.isBuffer(k) || k.length !== 32)) throw new Error('CipherState: key must be 32 bytes');
    this.k = k ? Buffer.from(k) : null;
    this.n = 0n;
  }
  hasKey() { return this.k !== null; }
  setNonce(n) { this.n = BigInt(n); }
  encryptWithAd(ad, pt) {
    if (!this.k) return Buffer.from(pt);
    if (this.n >= NONCE_MAX) throw new Error('noise: nonce exhausted');
    const ct = ENCRYPT(this.k, this.n, ad || EMPTY, pt);
    this.n++;
    return ct;
  }
  decryptWithAd(ad, ct) {
    if (!this.k) return Buffer.from(ct);
    if (this.n >= NONCE_MAX) throw new Error('noise: nonce exhausted');
    const pt = DECRYPT(this.k, this.n, ad || EMPTY, ct);   // n only advances on success
    this.n++;
    return pt;
  }
}

/* ---------------------------------------------------------------------------
 * SymmetricState (spec 5.2)
 * ------------------------------------------------------------------------- */
class SymmetricState {
  constructor(protocolName) {
    const name = Buffer.from(protocolName);
    this.h = name.length <= HASHLEN ? Buffer.concat([name, Buffer.alloc(HASHLEN - name.length)]) : HASH(name);
    this.ck = Buffer.from(this.h);
    this.cs = new CipherState();
  }
  mixKey(ikm) { const [ck, tk] = HKDF(this.ck, ikm, 2); this.ck = ck; this.cs.initializeKey(tk); }
  mixHash(data) { this.h = HASH(this.h, data); }
  encryptAndHash(pt) { const ct = this.cs.encryptWithAd(this.h, pt); this.mixHash(ct); return ct; }
  decryptAndHash(ct) { const pt = this.cs.decryptWithAd(this.h, ct); this.mixHash(ct); return pt; }
  split() { const [k1, k2] = HKDF(this.ck, EMPTY, 2); return [new CipherState(k1), new CipherState(k2)]; }
}

/* ---------------------------------------------------------------------------
 * HandshakeState (spec 5.3), XX pattern only
 * ------------------------------------------------------------------------- */
const XX = [['e'], ['e', 'ee', 's', 'es'], ['s', 'se']];

function checkKeypair(kp, what) {
  if (!kp || !Buffer.isBuffer(kp.priv) || kp.priv.length !== DHLEN) throw new Error(`HandshakeState: ${what}.priv must be a 32-byte Buffer`);
  const pub = kp.pub == null ? publicFromPrivate(kp.priv) : kp.pub;
  if (!Buffer.isBuffer(pub) || pub.length !== DHLEN) throw new Error(`HandshakeState: ${what}.pub must be a 32-byte Buffer`);
  return { priv: Buffer.from(kp.priv), pub: Buffer.from(pub) };
}

class HandshakeState {
  // opts.e is for test-vector injection only; normal use lets it be generated.
  constructor({ initiator, s, e, prologue = EMPTY } = {}) {
    this.initiator = !!initiator;
    this.s = checkKeypair(s, 's');
    this.e = e ? checkKeypair(e, 'e') : null;
    this.re = null;
    this.rs = null;
    this.ss = new SymmetricState(PROTOCOL_NAME);
    this.ss.mixHash(Buffer.from(prologue));
    this.step = 0;            // index into XX
    this.complete = false;
    this.failed = false;
  }
  get h() { return Buffer.from(this.ss.h); }

  _turn(writing) {
    if (this.failed) throw new Error('noise: handshake already failed');
    if (this.complete) throw new Error('noise: handshake already complete');
    const mine = (this.step % 2 === 0) === this.initiator;
    if (mine !== writing) throw new Error('noise: out-of-turn handshake message');
  }
  _dh(token) {
    switch (token) {
      case 'ee': return DH(this.e, this.re);
      case 'es': return this.initiator ? DH(this.e, this.rs) : DH(this.s, this.re);
      case 'se': return this.initiator ? DH(this.s, this.re) : DH(this.e, this.rs);
      default: throw new Error('noise: unknown token ' + token);
    }
  }
  _advance() { this.step++; if (this.step === XX.length) this.complete = true; }

  writeMessage(payload = EMPTY) {
    this._turn(true);
    try {
      const out = [];
      for (const t of XX[this.step]) {
        if (t === 'e') {
          if (!this.e) this.e = generateKeypair();
          out.push(this.e.pub); this.ss.mixHash(this.e.pub);
        } else if (t === 's') {
          out.push(this.ss.encryptAndHash(this.s.pub));
        } else {
          this.ss.mixKey(this._dh(t));
        }
      }
      out.push(this.ss.encryptAndHash(Buffer.from(payload)));
      const msg = Buffer.concat(out);
      if (msg.length > MAX_MSG) throw new Error('noise: handshake message exceeds 65535 bytes');
      this._advance();
      return msg;
    } catch (err) { this.failed = true; throw err; }
  }

  readMessage(message) {
    this._turn(false);
    try {
      if (!Buffer.isBuffer(message)) throw new Error('noise: message must be a Buffer');
      if (message.length > MAX_MSG) throw new Error('noise: handshake message exceeds 65535 bytes');
      let off = 0;
      const take = (len) => {
        if (message.length - off < len) throw new Error('noise: handshake message truncated');
        const b = message.subarray(off, off + len); off += len; return b;
      };
      for (const t of XX[this.step]) {
        if (t === 'e') {
          this.re = Buffer.from(take(DHLEN)); this.ss.mixHash(this.re);
        } else if (t === 's') {
          const ct = take(this.ss.cs.hasKey() ? DHLEN + TAGLEN : DHLEN);
          this.rs = Buffer.from(this.ss.decryptAndHash(ct));
        } else {
          this.ss.mixKey(this._dh(t));
        }
      }
      const rest = message.subarray(off);
      if (this.ss.cs.hasKey() && rest.length < TAGLEN) throw new Error('noise: handshake message truncated');
      const payload = this.ss.decryptAndHash(rest);
      this._advance();
      return payload;
    } catch (err) { this.failed = true; throw err; }
  }

  // initiator: tx = c1, rx = c2; responder: tx = c2, rx = c1
  split() {
    if (!this.complete || this.failed) throw new Error('noise: split before handshake completed');
    const [c1, c2] = this.ss.split();
    return this.initiator ? { tx: c1, rx: c2 } : { tx: c2, rx: c1 };
  }
}

/* ---------------------------------------------------------------------------
 * v3 daemon-facing wrappers
 * ------------------------------------------------------------------------- */
function makeSessionV3({ tx, rx }) {
  return {
    encrypt(plaintext) {
      const pt = Buffer.from(plaintext, 'utf8');
      if (pt.length + TAGLEN > MAX_MSG) throw new Error('noise: message exceeds 65535 bytes');
      return tx.encryptWithAd(EMPTY, pt);
    },
    decrypt(frame) {
      if (!Buffer.isBuffer(frame)) throw new Error('noise: frame must be a Buffer');
      if (frame.length > MAX_MSG) throw new Error('noise: frame exceeds 65535 bytes');
      if (frame.length < TAGLEN) throw new Error('noise: frame too short');
      return rx.decryptWithAd(EMPTY, frame).toString('utf8');
    },
  };
}
const selfKeys = (identity) => ({ priv: identity.privRaw, pub: identity.pubRaw });
function peerInfo(hs) {
  return { peerFp: fingerprintRaw(hs.rs), peerPub: rawToDer(hs.rs).toString('base64') };
}

const v3 = {
  initStart(identity) {
    const hs = new HandshakeState({ initiator: true, s: selfKeys(identity), prologue: PROLOGUE_V3 });
    const msg1 = hs.writeMessage(EMPTY);   // exactly 32 bytes
    return { hs, msg1 };
  },
  initFinish(st, msg2) {
    const hs = st.hs;
    hs.readMessage(msg2);                  // any payload is ignored (reserved)
    const msg3 = hs.writeMessage(EMPTY);
    const info = peerInfo(hs);
    return { msg3, ...info, handshakeHash: hs.h, session: makeSessionV3(hs.split()) };
  },
  respond(identity, msg1) {
    if (!Buffer.isBuffer(msg1) || msg1.length !== DHLEN) throw new Error('noise v3: msg1 must be exactly 32 bytes');
    const hs = new HandshakeState({ initiator: false, s: selfKeys(identity), prologue: PROLOGUE_V3 });
    hs.readMessage(msg1);
    const msg2 = hs.writeMessage(EMPTY);
    return {
      msg2,
      finish(msg3) {
        hs.readMessage(msg3);              // throws on tamper, second call or wrong turn
        const info = peerInfo(hs);
        return { ...info, handshakeHash: hs.h, session: makeSessionV3(hs.split()) };
      },
    };
  },
};

/* ---------------------------------------------------------------------------
 * v2 legacy handshake: kept unchanged for one release of compatibility only.
 * NOT Noise-compliant. Remove once no v2 peers remain.
 * ------------------------------------------------------------------------- */
const PROLOGUE = Buffer.from('NodeSignal-noise-v1');
const legacyHKDF = (salt, ikm, info, n = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, n));
const dh = (priv, pub) => crypto.diffieHellman({ privateKey: priv, publicKey: pub });
const genEph = () => crypto.generateKeyPairSync('x25519');
const rawPub = (k) => k.export({ type: 'spki', format: 'der' });          // 44 bytes
function legacyImpPub(b) { return crypto.createPublicKey({ key: b, format: 'der', type: 'spki' }); }
const impPub = legacyImpPub;
const PUBLEN = 44;

function mixKey(ck, ikm) {
  const out = legacyHKDF(ck, ikm, Buffer.from('ns-mix'), 64);
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

/* ---- v2 initiator ---- */
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
  const session = legacyHKDF(ck, Buffer.alloc(0), Buffer.from('ns-session'), 64);
  return {
    msg3: myStaticCt,
    peerFp: fingerprint(peerPubDer),
    peerPub: peerPubDer.toString('base64'),
    tx: session.slice(0, 32), rx: session.slice(32, 64),
  };
}
/* ---- v2 responder ---- */
function respond(self, msg1) {
  const e = genEph();
  let ck = Buffer.concat([PROLOGUE, Buffer.alloc(32)]).slice(0, 32);
  let r = mixKey(ck, dh(e.privateKey, impPub(msg1))); ck = r.ck;             // ee
  const staticCt = seal(r.k, 0, self.pubDer, msg1);
  const r2 = mixKey(ck, dh(self.priv, impPub(msg1))); ck = r2.ck;           // es
  const msg2 = Buffer.concat([rawPub(e.publicKey), staticCt]);
  // msg3 is sealed by the initiator with the post-'es' key (r2.k); the
  // responder must open it with the SAME key, then advance with 'se'.
  return { e, ck, k_msg3: r2.k, msg2, self,
    _finish(msg3) {
      const peerPubDer = open(this.k_msg3, 0, msg3, rawPub(this.e.publicKey));
      const rr = mixKey(this.ck, dh(this.e.privateKey, impPub(peerPubDer)));  // se
      const session = legacyHKDF(rr.ck, Buffer.alloc(0), Buffer.from('ns-session'), 64);
      return {
        peerFp: fingerprint(peerPubDer),
        peerPub: peerPubDer.toString('base64'),
        rx: session.slice(0, 32), tx: session.slice(32, 64),   // mirror of initiator
      };
    } };
}
/* ---- v2 transport: AEAD frames with per-direction counters ---- */
function makeSession(tx, rx) {
  let sN = 0, rN = 0;
  return {
    encrypt: (plaintext) => seal(tx, sN++, Buffer.from(plaintext, 'utf8')),
    decrypt: (frame) => open(rx, rN++, frame).toString('utf8'),
  };
}
const legacy = { initStart, initFinish, respond, makeSession };

module.exports = {
  newIdentity, loadIdentity, fingerprint, fingerprintRaw,
  PROTOCOL_NAME, PROLOGUE_V3, MAX_MSG,
  HandshakeState, CipherState, publicFromPrivate,
  v3,
  legacy,
  // deprecated top-level aliases of the v2 functions, removed with v2
  initStart, initFinish, respond, makeSession, PUBLEN,
};
