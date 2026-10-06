// store.js: passphrase-locked storage for message history
// ============================================================================
// The daemon has to keep receiving messages after a reboot with nobody at the
// keyboard, but history on disk should be unreadable without the operator's
// passphrase. Those two goals meet in a sealed-box design:
//
//   · a STORAGE keypair (X25519). Its public key sits in state.json in the
//     clear, so the daemon can always encrypt ("seal") a message to it.
//   · the storage PRIVATE key is kept encrypted under a key derived from the
//     passphrase with scrypt. Only an unlocked daemon holds it, in memory.
//
// So a locked daemon still receives and stores; only reading needs the
// passphrase. Each message gets a fresh ephemeral key and random nonce.
//
// What this does NOT protect, stated plainly: metadata (who, when, delivery
// state) stays readable in state.json; the Noise identity key stays readable
// by the daemon's user, because the daemon needs it unattended; and anyone
// who can read the daemon's memory while it is unlocked can read history.
//
// Node standard library only: scrypt, X25519, HKDF-SHA256, ChaCha20-Poly1305.
// ============================================================================
'use strict';
const crypto = require('crypto');

const VERSION = 1;
const KDF = { name: 'scrypt', N: 1 << 17, r: 8, p: 1 };          // ~128 MB, ~0.3 s
const MIN_PASSPHRASE = 8;
const VAULT_AD = Buffer.from('NodeSignal vault v1');
const SEAL_INFO = Buffer.from('NodeSignal sealed message v1');

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(String(s || ''), 'base64');
const b64url = (b) => Buffer.from(b).toString('base64url');

/* ---- raw X25519 helpers ---- */
function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return { priv: Buffer.from(jwk.d, 'base64url'), pub: Buffer.from(jwk.x, 'base64url') };
}
const pubKeyObj = (pub) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64url(pub) }, format: 'jwk' });
function privKeyObj(priv) {
  // the public half is required in the JWK; derive it from the private scalar
  const k = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv]), format: 'der', type: 'pkcs8' });
  return k;
}
const pubOf = (priv) => Buffer.from(crypto.createPublicKey(privKeyObj(priv)).export({ format: 'jwk' }).x, 'base64url');
const dh = (priv, pub) => crypto.diffieHellman({ privateKey: privKeyObj(priv), publicKey: pubKeyObj(pub) });

/* ---- AEAD ---- */
function aeadSeal(key, nonce, pt, ad) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  if (ad) c.setAAD(ad, { plaintextLength: pt.length });
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
}
function aeadOpen(key, nonce, ct, ad) {
  if (ct.length < 16) throw new Error('ciphertext too short');
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  if (ad) d.setAAD(ad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

/* ---- passphrase KDF (async: never block the daemon's event loop) ---- */
function kek(passphrase, kdf) {
  if (!kdf || kdf.name !== 'scrypt') return Promise.reject(new Error('unsupported KDF'));
  const N = Number(kdf.N), r = Number(kdf.r), p = Number(kdf.p);
  // refuse absurd parameters from a tampered file instead of exhausting memory
  if (!(N >= 1 << 14 && N <= 1 << 20 && r >= 1 && r <= 16 && p >= 1 && p <= 4)) return Promise.reject(new Error('bad KDF parameters'));
  return new Promise((resolve, reject) => crypto.scrypt(String(passphrase).normalize('NFC'), unb64(kdf.salt), 32,
    { N, r, p, maxmem: 160 * N * r + 1024 * 1024 }, (e, k) => (e ? reject(e) : resolve(k))));
}
function checkPassphrase(p) {
  if (typeof p !== 'string' || [...p].length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  if (p.length > 1024) throw new Error('passphrase too long');
}
async function wrap(priv, pub, passphrase, kdf) {
  const key = await kek(passphrase, kdf);
  const n = crypto.randomBytes(12);
  return { v: VERSION, kdf, pub: b64(pub), sealedPriv: { n: b64(n), ct: b64(aeadSeal(key, n, priv, Buffer.concat([VAULT_AD, pub]))) } };
}

/** Create a new vault. -> { vault (JSON-safe, goes in state.json), priv (keep in memory only) } */
async function createVault(passphrase) {
  checkPassphrase(passphrase);
  const kp = keypair();
  const kdf = { ...KDF, salt: b64(crypto.randomBytes(16)) };
  return { vault: await wrap(kp.priv, kp.pub, passphrase, kdf), priv: kp.priv };
}
/** Unlock: -> storage private key (Buffer). Throws 'wrong passphrase' on failure. */
async function unlock(vault, passphrase) {
  if (!vault || vault.v !== VERSION || !vault.sealedPriv) throw new Error('no usable vault');
  const key = await kek(passphrase, vault.kdf);
  const pub = unb64(vault.pub);
  let priv;
  try { priv = aeadOpen(key, unb64(vault.sealedPriv.n), unb64(vault.sealedPriv.ct), Buffer.concat([VAULT_AD, pub])); }
  catch { throw new Error('wrong passphrase'); }
  if (priv.length !== 32 || !pubOf(priv).equals(pub)) throw new Error('vault is corrupt');
  return priv;
}
/** Re-wrap the same storage key under a new passphrase (history is not re-encrypted). */
async function changePassphrase(vault, priv, newPassphrase) {
  checkPassphrase(newPassphrase);
  const pub = unb64(vault.pub);
  if (!pubOf(priv).equals(pub)) throw new Error('key does not match vault');
  return wrap(priv, pub, newPassphrase, { ...KDF, salt: b64(crypto.randomBytes(16)) });
}

/** Seal text to the vault's public key. Needs no secret, so a locked daemon can do it. */
function seal(pubB64, text) {
  const pub = unb64(pubB64);
  if (pub.length !== 32) throw new Error('bad storage key');
  const e = keypair();
  const key = Buffer.from(crypto.hkdfSync('sha256', dh(e.priv, pub), Buffer.concat([e.pub, pub]), SEAL_INFO, 32));
  const n = crypto.randomBytes(12);
  return { e: b64(e.pub), n: b64(n), ct: b64(aeadSeal(key, n, Buffer.from(String(text), 'utf8'), e.pub)) };
}
/** Open a sealed record with the unlocked storage private key. Throws if tampered. */
function open(priv, sealed) {
  const e = unb64(sealed && sealed.e), n = unb64(sealed && sealed.n);
  if (e.length !== 32 || n.length !== 12) throw new Error('malformed sealed record');
  const pub = pubOf(priv);
  const key = Buffer.from(crypto.hkdfSync('sha256', dh(priv, e), Buffer.concat([e, pub]), SEAL_INFO, 32));
  return aeadOpen(key, n, unb64(sealed.ct), e).toString('utf8');
}

module.exports = { createVault, unlock, changePassphrase, seal, open, MIN_PASSPHRASE, KDF };
