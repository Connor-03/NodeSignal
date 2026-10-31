// mailbox.js: sealed store-and-forward mail for operators behind NAT
// ============================================================================
// Two daemons that are both behind NAT cannot open a link to each other. A
// third operator who is reachable, and who has opted in, can hold mail for
// them: the sender deposits a sealed blob addressed to the recipient's
// fingerprint, and the recipient later connects, fetches and acknowledges it.
//
// What the mailbox learns, stated plainly: the recipient's fingerprint (it
// files mail under it), the size of each blob, and when blobs arrive and are
// fetched. The blob hides the text and does not name the sender. Two things
// outside this module decide whether that stays true:
//
//   · the deposit link. A deposit made over the sender's normal Noise link
//     shows the mailbox the sender's identity key, which names the sender.
//     Deposit over a link that uses a throwaway identity (and Tor, to hide
//     the address as well).
//   · register, fetch and ack must only be answered for the fingerprint the
//     asking peer proved in its Noise handshake. Otherwise anyone could see
//     how much mail someone has, and delete it (but still not read it).
//
// Blob, version 1 (all keys raw 32-byte X25519):
//
//   0x01 | ephPub (32) | nonce (12) | ChaCha20-Poly1305(k1, nonce, inner, ad)
//
//   k1    = HKDF-SHA256(ikm = DH(eph, recipient), salt = ephPub || recipientPub,
//                       info = "NodeSignal mailbox v1 outer", 32)
//   ad    = 0x01 || ephPub || recipientPub
//   inner = senderPub (32) | mac (32) | body
//   mac   = HMAC-SHA256(key = HKDF-SHA256(ikm = DH(sender, recipient), salt = ephPub,
//                                         info = "NodeSignal mailbox v1 sender", 32),
//                       data = ephPub || recipientPub || body)
//
// The outer layer is a sealed box: only the recipient's private key opens it,
// and a fresh ephemeral key per blob means blobs from one sender share no
// bytes. The mac proves to the recipient that whoever holds senderPub's
// private key wrote this body, to this recipient, in this blob. It proves
// nothing to anyone else: the recipient can compute the same mac, so a blob
// is deniable, as intended.
//
// Limits, in honest terms:
//   · no forward secrecy. A blob opens with the recipient's identity key for
//     as long as that key exists, so someone who keeps copies of blobs and
//     later steals that key reads them. Live Noise links do not share this.
//   · the same theft lets the thief forge blobs to that recipient "from"
//     anyone (the mac key is a static-static DH).
//   · replay. A blob stays valid forever and anyone holding it can deposit it
//     again. The body should carry a message id and time, and the recipient
//     should drop ids it already has.
//   · sizes are not padded.
//
// Node standard library only: X25519, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305.
// ============================================================================
'use strict';
const crypto = require('crypto');
const { fingerprintRaw } = require('./noise.js');

const VERSION = 1;
const KEYLEN = 32, NONCELEN = 12, TAGLEN = 16, MACLEN = 32;
const HEADLEN = 1 + KEYLEN + NONCELEN;                       // version | ephPub | nonce
const OVERHEAD = HEADLEN + KEYLEN + MACLEN + TAGLEN;         // 125: a blob with an empty body
const MAX_BLOB = 64 * 1024;
const MAX_PLAINTEXT = MAX_BLOB - OVERHEAD;
const OUTER_INFO = Buffer.from('NodeSignal mailbox v1 outer');
const SENDER_INFO = Buffer.from('NodeSignal mailbox v1 sender');
const FP_RE = /^[0-9a-f]{32}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const BAD_BLOB = 'mailbox: cannot open this message';
const PKCS8_X25519_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

/* ---- raw X25519 helpers (same approach as store.js) ---- */
const isKey = (b) => Buffer.isBuffer(b) && b.length === KEYLEN;
const privObj = (priv) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519_PREFIX, priv]), format: 'der', type: 'pkcs8' });
const pubObj = (pub) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: pub.toString('base64url') }, format: 'jwk' });
const pubOf = (priv) => Buffer.from(crypto.createPublicKey(privObj(priv)).export({ format: 'jwk' }).x, 'base64url');
// OpenSSL refuses an all-zero result (a low-order public key) by throwing.
const dh = (priv, pub) => crypto.diffieHellman({ privateKey: privObj(priv), publicKey: pubObj(pub) });
const hkdf = (ikm, salt, info) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 32));
// From random bytes, not generateKeyPairSync, which can deadlock on Node 18
// when its key is exported (see freshX25519 in noise.js).
function ephemeral() {
  const priv = crypto.randomBytes(32);
  priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
  return { priv, pub: pubOf(priv) };
}
const senderMac = (macKey, ePub, rPub, body) => crypto.createHmac('sha256', macKey).update(ePub).update(rPub).update(body).digest();

/**
 * Seal plaintext (string or Buffer) to a recipient's identity key, signed for
 * the recipient only by the sender's identity key. -> Buffer blob.
 */
function seal({ senderPrivRaw, senderPubRaw, recipientPubRaw, plaintext } = {}) {
  if (!isKey(senderPrivRaw)) throw new TypeError('mailbox.seal: senderPrivRaw must be a 32-byte Buffer');
  if (!isKey(senderPubRaw)) throw new TypeError('mailbox.seal: senderPubRaw must be a 32-byte Buffer');
  if (!isKey(recipientPubRaw)) throw new TypeError('mailbox.seal: recipientPubRaw must be a 32-byte Buffer');
  if (!pubOf(senderPrivRaw).equals(senderPubRaw)) throw new Error('mailbox.seal: senderPubRaw does not match senderPrivRaw');
  let body;
  if (typeof plaintext === 'string') body = Buffer.from(plaintext, 'utf8');
  else if (plaintext instanceof Uint8Array) body = Buffer.from(plaintext);
  else throw new TypeError('mailbox.seal: plaintext must be a string or a Buffer');
  if (body.length > MAX_PLAINTEXT) throw new Error(`mailbox.seal: plaintext is over ${MAX_PLAINTEXT} bytes`);

  const e = ephemeral();
  let k1, macKey;
  try {
    k1 = hkdf(dh(e.priv, recipientPubRaw), Buffer.concat([e.pub, recipientPubRaw]), OUTER_INFO);
    macKey = hkdf(dh(senderPrivRaw, recipientPubRaw), e.pub, SENDER_INFO);
  } catch { throw new Error('mailbox.seal: unusable recipient key'); }
  const inner = Buffer.concat([senderPubRaw, senderMac(macKey, e.pub, recipientPubRaw, body), body]);
  const version = Buffer.from([VERSION]);
  const nonce = crypto.randomBytes(NONCELEN);
  const c = crypto.createCipheriv('chacha20-poly1305', k1, nonce, { authTagLength: TAGLEN });
  c.setAAD(Buffer.concat([version, e.pub, recipientPubRaw]), { plaintextLength: inner.length });
  return Buffer.concat([version, e.pub, nonce, c.update(inner), c.final(), c.getAuthTag()]);
}

/**
 * Open a blob with the recipient's identity key.
 * -> { senderPubRaw, senderFp, plaintext (Buffer) }. Anything wrong with the
 * blob throws one short generic error; wrong arguments throw a clear one.
 */
function open({ recipientPrivRaw, recipientPubRaw, blob } = {}) {
  if (!isKey(recipientPrivRaw)) throw new TypeError('mailbox.open: recipientPrivRaw must be a 32-byte Buffer');
  const rPub = pubOf(recipientPrivRaw);
  if (recipientPubRaw != null && !(isKey(recipientPubRaw) && recipientPubRaw.equals(rPub))) {
    throw new Error('mailbox.open: recipientPubRaw does not match recipientPrivRaw');
  }
  if (!(blob instanceof Uint8Array) || blob.length < OVERHEAD || blob.length > MAX_BLOB || blob[0] !== VERSION) throw new Error(BAD_BLOB);
  const b = Buffer.from(blob);
  try {
    const ePub = b.subarray(1, 1 + KEYLEN), nonce = b.subarray(1 + KEYLEN, HEADLEN), ct = b.subarray(HEADLEN);
    const k1 = hkdf(dh(recipientPrivRaw, ePub), Buffer.concat([ePub, rPub]), OUTER_INFO);
    const d = crypto.createDecipheriv('chacha20-poly1305', k1, nonce, { authTagLength: TAGLEN });
    d.setAAD(Buffer.concat([b.subarray(0, 1 + KEYLEN), rPub]), { plaintextLength: ct.length - TAGLEN });
    d.setAuthTag(ct.subarray(ct.length - TAGLEN));
    const inner = Buffer.concat([d.update(ct.subarray(0, ct.length - TAGLEN)), d.final()]);   // final() throws on a bad tag
    const sPub = inner.subarray(0, KEYLEN), mac = inner.subarray(KEYLEN, KEYLEN + MACLEN), body = inner.subarray(KEYLEN + MACLEN);
    const want = senderMac(hkdf(dh(recipientPrivRaw, sPub), ePub, SENDER_INFO), ePub, rPub, body);
    if (!crypto.timingSafeEqual(mac, want)) throw new Error('mac');
    const senderPubRaw = Buffer.from(sPub);
    return { senderPubRaw, senderFp: fingerprintRaw(senderPubRaw), plaintext: Buffer.from(body) };
  } catch { throw new Error(BAD_BLOB); }
}

/** A random deposit id (22 characters). Never reuse the inner message id: it would link deposits. */
const newDepositId = () => crypto.randomBytes(16).toString('base64url');

/* ---------------------------------------------------------------------------
 * The mailbox's side: hold blobs per registered recipient, within limits.
 * Call prune(now) on a timer; nothing expires on its own.
 * ------------------------------------------------------------------------- */
const DEFAULTS = Object.freeze({
  maxPerRecipient: 200, maxBlobBytes: MAX_BLOB, maxTotalBytes: 32 * 1024 * 1024, ttlMs: 7 * 864e5, maxRecipients: 256,
});
function limitsFrom(opts) {
  const o = { ...DEFAULTS };
  for (const k of Object.keys(DEFAULTS)) {
    const v = opts ? opts[k] : undefined;
    if (v === undefined) continue;
    if (!Number.isSafeInteger(v) || v < 1) throw new RangeError(`mailbox: ${k} must be a positive integer`);
    o[k] = v;
  }
  if (o.maxBlobBytes > MAX_BLOB) throw new RangeError(`mailbox: maxBlobBytes cannot exceed ${MAX_BLOB}`);
  if (o.maxBlobBytes < OVERHEAD) throw new RangeError(`mailbox: maxBlobBytes cannot be under ${OVERHEAD}`);
  return Object.freeze(o);
}
const validFp = (fp) => typeof fp === 'string' && FP_RE.test(fp);
const validId = (id) => typeof id === 'string' && ID_RE.test(id);
const no = (error) => ({ ok: false, error });
// Strict base64: canonical encoding only, length checked before the regex.
function unb64(s, maxBytes) {
  if (typeof s !== 'string' || s.length === 0 || s.length % 4 || s.length > Math.ceil(maxBytes / 3) * 4) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  return b.toString('base64') === s ? b : null;
}

class MailboxStore {
  #boxes = new Map();     // fp -> { seen, items: Map(id -> { id, blob, at }) }, items oldest first
  #bytes = 0;

  constructor(opts = {}) { this.limits = limitsFrom(opts); }

  /** A recipient asks this mailbox to hold mail for it. false: bad fp, or no room for another recipient. */
  register(fp, now = Date.now()) {
    if (!validFp(fp) || !Number.isFinite(now)) return false;
    const box = this.#boxes.get(fp);
    if (box) { box.seen = Math.max(box.seen, now); return true; }
    if (this.#boxes.size >= this.limits.maxRecipients) return false;
    this.#boxes.set(fp, { seen: now, items: new Map() });
    return true;
  }
  isRegistered(fp) { return validFp(fp) && this.#boxes.has(fp); }
  /** Forget a recipient and drop its mail. -> whether it was registered. */
  unregister(fp) {
    const box = validFp(fp) && this.#boxes.get(fp);
    if (!box) return false;
    for (const it of box.items.values()) this.#bytes -= it.blob.length;
    this.#boxes.delete(fp);
    return true;
  }

  /** -> { ok: true } (plus duplicate: true for an id already held, stored once) or { ok: false, error }. */
  deposit(fp, item, now = Date.now()) {
    const { id, blob } = item && typeof item === 'object' ? item : {};
    if (!validFp(fp)) return no('bad recipient');
    const box = this.#boxes.get(fp);
    if (!box) return no('recipient not registered here');
    if (!validId(id)) return no('bad id');
    if (!(blob instanceof Uint8Array)) return no('bad blob');
    if (blob.length > this.limits.maxBlobBytes) return no('blob too big');
    if (blob.length < OVERHEAD || blob[0] !== VERSION) return no('bad blob');
    if (!Number.isFinite(now)) return no('bad time');
    if (box.items.has(id)) return { ok: true, duplicate: true };
    if (box.items.size >= this.limits.maxPerRecipient) return no('recipient full');
    if (this.#bytes + blob.length > this.limits.maxTotalBytes) return no('mailbox full');
    box.items.set(id, { id, blob: Buffer.from(blob), at: now });
    this.#bytes += blob.length;
    return { ok: true };
  }

  /** Oldest first, without removing anything. -> [{ id, blob, at }] */
  fetch(fp, limit = 50) {
    const box = validFp(fp) && this.#boxes.get(fp);
    if (!box) return [];
    const n = Number.isSafeInteger(limit) && limit > 0 ? limit : 50;
    const out = [];
    for (const it of box.items.values()) {
      if (out.length >= n) break;
      out.push({ id: it.id, blob: Buffer.from(it.blob), at: it.at });
    }
    return out;
  }

  /** The recipient has these ids. -> how many were removed. */
  ack(fp, ids) {
    const box = validFp(fp) && this.#boxes.get(fp);
    const list = typeof ids === 'string' ? [ids] : ids;
    if (!box || !Array.isArray(list)) return 0;
    let n = 0;
    for (const id of list) {
      const it = typeof id === 'string' ? box.items.get(id) : undefined;
      if (!it) continue;
      box.items.delete(id);
      this.#bytes -= it.blob.length;
      n++;
    }
    return n;
  }

  /** Drop mail held ttlMs or longer, and recipients that have not registered again within ttlMs. */
  prune(now = Date.now()) {
    const ttl = this.limits.ttlMs;
    let items = 0, recipients = 0;
    for (const [fp, box] of this.#boxes) {
      if (now - box.seen >= ttl) {
        items += box.items.size; recipients++;
        this.unregister(fp);
        continue;
      }
      for (const [id, it] of box.items) {
        if (now - it.at < ttl) continue;
        box.items.delete(id);
        this.#bytes -= it.blob.length;
        items++;
      }
    }
    return { items, recipients };
  }

  stats() {
    let items = 0;
    for (const box of this.#boxes.values()) items += box.items.size;
    return { recipients: this.#boxes.size, items, bytes: this.#bytes, limits: { ...this.limits } };
  }

  /** For state.json: { v: 1, recipients: { fp: { seen, items: [{ id, at, blob (base64) }] } } } */
  toJSON() {
    const recipients = {};
    for (const [fp, box] of this.#boxes) {
      recipients[fp] = { seen: box.seen, items: [...box.items.values()].map((it) => ({ id: it.id, at: it.at, blob: it.blob.toString('base64') })) };
    }
    return { v: 1, recipients };
  }

  /**
   * Rebuild from toJSON() output. Never throws on bad data: anything malformed
   * is dropped, and the limits in opts apply (most recently registered first).
   */
  static fromJSON(obj, opts) {
    const s = new MailboxStore(opts);
    const rec = obj && typeof obj === 'object' && obj.v === 1 ? obj.recipients : null;
    if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return s;
    const boxes = [];
    for (const fp of Object.keys(rec)) {
      const r = rec[fp];
      if (validFp(fp) && r && typeof r === 'object' && Number.isFinite(r.seen)) boxes.push([fp, r]);
    }
    boxes.sort((a, b) => b[1].seen - a[1].seen);
    for (const [fp, r] of boxes) {
      if (!s.register(fp, r.seen)) break;
      const items = (Array.isArray(r.items) ? r.items : [])
        .filter((it) => it && typeof it === 'object' && validId(it.id) && Number.isFinite(it.at));
      for (const it of items) {                                // saved order is arrival order, oldest first
        const blob = unb64(it.blob, s.limits.maxBlobBytes);
        if (blob) s.deposit(fp, { id: it.id, blob }, it.at);   // deposit re-checks every limit
      }
    }
    return s;
  }
}

const createStore = (opts = {}) => new MailboxStore(opts);
const fromJSON = (obj, opts) => MailboxStore.fromJSON(obj, opts);

module.exports = {
  seal, open, newDepositId,
  createStore, fromJSON, MailboxStore,
  VERSION, OVERHEAD, MAX_BLOB, MAX_PLAINTEXT, FP_RE, ID_RE, DEFAULTS,
};
