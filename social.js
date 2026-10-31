// social.js: signed public posts and topic rooms, and the store that keeps them
// ============================================================================
// NodeSignal's messages are private and travel between two daemons. Posts and
// rooms are the public side: short texts an operator signs and the daemons of
// their contacts store and pass on, so a feed works with no server at all.
//
//   - a SIGNING key (Ed25519), separate from the Noise identity (X25519, which
//     cannot sign). Every post, room message, room and room membership is
//     signed with it, so whoever forwards an item cannot change it.
//   - items are plain JSON with a short `k` (kind). The signature covers a
//     canonical encoding: keys sorted, no whitespace.
//   - an item's id is a hash of its signed body, so the same post arriving
//     twice by two routes is stored once.
//
// Each item names the author's Noise fingerprint (`fp`) and nick, but those
// are the author's own claims: the signature proves only that the holder of
// the signing key wrote them. The daemon learns which signing key belongs to
// which contact from the authenticated hello on a direct link, and shows
// anything else as "signed by key ..., introduced by <whoever passed it on>".
//
// The store keeps bounded amounts of everything (posts per author, per day,
// in total; rooms; messages per room) and drops the oldest first, so a
// flood of valid items cannot fill the disk the node shares.
//
// Node standard library only.
// ============================================================================
'use strict';
const crypto = require('crypto');

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const POST_MAX = 1000;              // characters in a post
const ROOM_MSG_MAX = 2000;          // characters in a room message
const ROOM_NAME_MAX = 60;
const NICK_MAX = 60;
const FUTURE_MS = 10 * 60e3;        // clock skew tolerated
const KEEP_MS = 30 * 864e5;         // items older than this are not accepted or kept
const FP_RE = /^[0-9a-f]{32}$/;
const ID_RE = /^[0-9a-f]{32}$/;
const ONION_RE = /^[a-z2-7]{56}\.onion$/;
const HOST_RE = /^[A-Za-z0-9.:\-[\]]{1,255}$/;

/* ---- keys ---- */
// From a random seed, not generateKeyPairSync, which can deadlock on Node 18
// when its key is exported (see freshX25519 in noise.js).
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
function newSigningKey() {
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, crypto.randomBytes(32)]), format: 'der', type: 'pkcs8' });
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    pub: rawPub(publicKey).toString('base64'),
  };
}
function rawPub(keyObj) { return keyObj.export({ type: 'spki', format: 'der' }).subarray(12); }
function loadSigningKey(k) {
  const priv = crypto.createPrivateKey({ key: Buffer.from(k.priv, 'base64'), format: 'der', type: 'pkcs8' });
  if (priv.asymmetricKeyType !== 'ed25519') throw new Error('signing key: not Ed25519');
  const pubRaw = rawPub(crypto.createPublicKey(priv));
  return { priv, pubRaw, pub: pubRaw.toString('base64'), id: keyId(pubRaw) };
}
const keyId = (pubRaw) => crypto.createHash('sha256').update(pubRaw).digest('hex').slice(0, 16);
/* Ed25519 points of small order, as libsodium lists them. The sign bit is
   ignored, so each line covers two encodings, the non-canonical ones (y >= p)
   included; together they hold all eight points of order 1, 2, 4 and 8. A
   "key" like this verifies a forged signature for any message (with
   R = identity and S = 0, for one), so it is never an author key. */
const SMALL_ORDER = [
  '0000000000000000000000000000000000000000000000000000000000000000',   // order 4
  '0100000000000000000000000000000000000000000000000000000000000000',   // order 1, the identity
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',   // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',   // order 8
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',   // p-1, order 2
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',   // p (= 0), order 4
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',   // p+1 (= 1), order 1
].map((h) => Buffer.from(h, 'hex'));
function smallOrder(raw) {
  const y = Buffer.from(raw); y[31] &= 0x7f;
  return SMALL_ORDER.some((b) => b.equals(y));
}
function pubKeyObj(pubB64) {
  const raw = Buffer.from(String(pubB64 || ''), 'base64');
  if (raw.length !== 32 || smallOrder(raw)) return null;
  try { return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' }); } catch { return null; }
}
const isPub = (s) => typeof s === 'string' && s.length === 44 && Buffer.from(s, 'base64').length === 32
  && Buffer.from(s, 'base64').toString('base64') === s && !smallOrder(Buffer.from(s, 'base64'));

/* A signing key belongs to one Noise identity: its holder signs this label
   with the fingerprint in it, and a hello (sealed mail, an introduction)
   carries the signature. Without it anyone could announce another
   operator's signing key as their own, and be shown as that author or let
   into that member's rooms. The label is not JSON, so it can never be read
   as a post or any other signed item. */
const bindLabel = (fp) => Buffer.from(`NodeSignal signing key of ${fp} v1`);
const bindKey = (key, fp) => crypto.sign(null, bindLabel(fp), key.priv).toString('base64');
function checkBinding(pub, sig, fp) {
  if (!isPub(pub) || typeof fp !== 'string' || !FP_RE.test(fp) || typeof sig !== 'string' || sig.length !== 88) return false;
  const k = pubKeyObj(pub), s = Buffer.from(sig, 'base64');
  if (!k || s.length !== 64) return false;
  try { return crypto.verify(null, bindLabel(fp), k, s); } catch { return false; }
}

/* ---- canonical JSON: sorted keys, no whitespace ---- */
function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
const bodyOf = (o) => { const b = Object.assign({}, o); delete b.sig; return b; };
const idOf = (o) => crypto.createHash('sha256').update(canonical(bodyOf(o))).digest('hex').slice(0, 32);

// Keep newlines and tabs; drop every other control character (the same rule
// as private messages).
const cleanText = (s, max) => (typeof s === 'string'
  ? s.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, max) : '');
const cleanLine = (s, max) => (typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '').trim().slice(0, max) : '');

function sign(key, body) {
  const b = bodyOf(body);
  b.a = key.pub;
  const sig = crypto.sign(null, Buffer.from(canonical(b)), key.priv).toString('base64');
  return Object.assign(b, { sig });
}

/* ---- the kinds ---- */
// What each kind must contain, beyond k, v, a (author key), ts and sig.
const KINDS = {
  // a post on the author's public feed
  post: (o) => FP_RE.test(o.fp) && typeof o.text === 'string' && o.text.length >= 1 && o.text.length <= POST_MAX && cleanText(o.text, POST_MAX) === o.text
    && typeof o.nick === 'string' && o.nick.length <= NICK_MAX,
  // a room: id = hash of creator key, name and nonce, so nobody can claim another room's id
  roomdef: (o) => ID_RE.test(o.room) && typeof o.name === 'string' && o.name.length >= 1 && o.name.length <= ROOM_NAME_MAX
    && cleanLine(o.name, ROOM_NAME_MAX) === o.name && /^[0-9a-f]{32}$/.test(o.nonce) && o.room === roomIdOf(o.a, o.name, o.nonce),
  // "I am in this room, and this is how to reach me"
  member: (o) => ID_RE.test(o.room) && FP_RE.test(o.fp) && typeof o.nick === 'string' && o.nick.length <= NICK_MAX
    && (o.host === undefined || (typeof o.host === 'string' && HOST_RE.test(o.host)))
    && (o.port === undefined || (Number.isInteger(o.port) && o.port > 0 && o.port < 65536))
    && (o.left === undefined || o.left === true),
  // a message in a room
  roommsg: (o) => ID_RE.test(o.room) && FP_RE.test(o.fp) && typeof o.text === 'string' && o.text.length >= 1 && o.text.length <= ROOM_MSG_MAX
    && cleanText(o.text, ROOM_MSG_MAX) === o.text && typeof o.nick === 'string' && o.nick.length <= NICK_MAX,
};
const roomIdOf = (a, name, nonce) => crypto.createHash('sha256').update(`nodesignal room v1\n${a}\n${name}\n${nonce}`).digest('hex').slice(0, 32);

/* Check an item from anywhere: shape, size, time window, signature. Returns
   { ok: true, id } or { ok: false, error }. Unknown fields are refused, so
   nothing unsigned rides along. */
const ALLOWED = {
  post: ['k', 'v', 'a', 'ts', 'sig', 'fp', 'nick', 'text'],
  roomdef: ['k', 'v', 'a', 'ts', 'sig', 'room', 'name', 'nonce'],
  member: ['k', 'v', 'a', 'ts', 'sig', 'room', 'fp', 'nick', 'host', 'port', 'left'],
  roommsg: ['k', 'v', 'a', 'ts', 'sig', 'room', 'fp', 'nick', 'text'],
};
// Own properties only: a kind such as "__proto__", "constructor" or
// "toString" would otherwise find something on Object.prototype.
const has = (obj, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(obj, k);
function verify(o, now = Date.now(), { keepMs = KEEP_MS } = {}) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { ok: false, error: 'not an object' };
  if (!has(ALLOWED, o.k) || !has(KINDS, o.k)) return { ok: false, error: 'unknown kind' };
  const allowed = ALLOWED[o.k];
  for (const key of Object.keys(o)) if (!allowed.includes(key)) return { ok: false, error: 'unexpected field ' + key.slice(0, 20) };
  if (o.v !== 1) return { ok: false, error: 'unsupported version' };
  if (!isPub(o.a)) return { ok: false, error: 'bad author key' };
  if (!Number.isInteger(o.ts) || o.ts > now + FUTURE_MS || (o.k !== 'roomdef' && o.ts < now - keepMs)) return { ok: false, error: 'out of time range' };
  if (typeof o.sig !== 'string' || Buffer.from(o.sig, 'base64').length !== 64) return { ok: false, error: 'bad signature' };
  if (!KINDS[o.k](o)) return { ok: false, error: 'malformed ' + o.k };
  const key = pubKeyObj(o.a);
  let good = false;
  try { good = !!key && crypto.verify(null, Buffer.from(canonical(bodyOf(o))), key, Buffer.from(o.sig, 'base64')); } catch { good = false; }
  if (!good) return { ok: false, error: 'bad signature' };
  return { ok: true, id: idOf(o) };
}

/* ---- builders for this daemon's own items ---- */
const makePost = (key, { fp, nick, text, ts = Date.now() }) =>
  sign(key, { k: 'post', v: 1, ts, fp, nick: cleanLine(nick, NICK_MAX), text: cleanText(text, POST_MAX) });
function makeRoom(key, { name, ts = Date.now() }) {
  const nonce = crypto.randomBytes(16).toString('hex'), n = cleanLine(name, ROOM_NAME_MAX);
  return sign(key, { k: 'roomdef', v: 1, ts, name: n, nonce, room: roomIdOf(key.pub, n, nonce) });
}
const makeMember = (key, { room, fp, nick, host, port, left, ts = Date.now() }) => sign(key, {
  k: 'member', v: 1, ts, room, fp, nick: cleanLine(nick, NICK_MAX),
  host: host || undefined, port: host ? port : undefined, left: left ? true : undefined,
});
const makeRoomMsg = (key, { room, fp, nick, text, ts = Date.now() }) =>
  sign(key, { k: 'roommsg', v: 1, ts, room, fp, nick: cleanLine(nick, NICK_MAX), text: cleanText(text, ROOM_MSG_MAX) });

/* ---- the store ----------------------------------------------------------
   posts:  id -> { o, at (received), via (fp it came from, null if ours), hops }
   rooms:  room id -> { def, joined, members: a -> member item, msgs: id -> { o, at } }
   Everything is bounded; the daemon persists toJSON() in state.json. */
function createStore(opts = {}) {
  const L = Object.assign({
    maxPosts: 2000, maxPerAuthor: 200, maxPerAuthorDay: 30, maxRooms: 20, maxRoomMsgs: 1000,
    maxMembers: 100, keepMs: KEEP_MS,
  }, opts);
  const posts = new Map();
  const byAuthor = new Map();          // author key -> Set of post ids, so nothing scans every post
  // Ids dropped to make room. A replay of one is not new: without this, a
  // peer could send the same evicted posts again and again, each costing a
  // signature check and a trim.
  const evicted = new Set();
  const rooms = new Map();

  function put(id, entry) {
    posts.set(id, entry);
    let s = byAuthor.get(entry.o.a);
    if (!s) byAuthor.set(entry.o.a, (s = new Set()));
    s.add(id);
  }
  function drop(id, remember = true) {
    const p = posts.get(id);
    if (!p) return;
    posts.delete(id);
    const s = byAuthor.get(p.o.a);
    if (s) { s.delete(id); if (!s.size) byAuthor.delete(p.o.a); }
    if (remember) {
      evicted.add(id);
      if (evicted.size > L.maxPosts * 5) evicted.delete(evicted.values().next().value);   // 10,000 ids, about 1 MB
    }
  }
  // keepAuthors: signing keys whose posts go last when the store is full
  // (the daemon passes the people it follows).
  function addPost(o, { via = null, hops = 0, now = Date.now(), mine = false, keepAuthors = null } = {}) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return { status: 'rejected', error: 'not an object' };
    // The cheap checks first: a post we hold, or dropped for room, costs no
    // signature check. The id covers the whole signed body.
    let id;
    try { id = idOf(o); } catch { return { status: 'rejected', error: 'not an object' }; }
    if (posts.has(id) || evicted.has(id)) return { status: 'dup', id };
    const v = verify(o, now, L);
    if (!v.ok) return { status: 'rejected', error: v.error };
    if (o.k !== 'post') return { status: 'rejected', error: 'not a post' };
    const theirs = [...(byAuthor.get(o.a) || [])].map((x) => [x, posts.get(x)]);
    if (!mine && theirs.filter(([, p]) => p.o.ts > o.ts - 864e5 && p.o.ts <= o.ts + 864e5).length >= L.maxPerAuthorDay)
      return { status: 'rejected', error: 'too many posts from this author in a day' };
    put(v.id, { o, at: now, via, hops: Math.max(0, Math.min(9, hops | 0)) });
    // per author: oldest first out
    if (theirs.length + 1 > L.maxPerAuthor) {
      let old = null;
      for (const [x, p] of theirs) if (!old || p.o.ts < old[1].o.ts) old = [x, p];
      if (old) drop(old[0]);
    }
    if (posts.size > L.maxPosts) trimPosts(keepAuthors);
    return { status: 'new', id: v.id };
  }
  /* Over the cap: drop the oldest forwarded posts, never our own. In
     batches, down to 90% of the cap, so one sort serves the next couple of
     hundred posts instead of every one. Posts by keepAuthors go only if the
     others are not enough to get back under the cap. */
  function trimPosts(keepAuthors = null) {
    if (posts.size <= L.maxPosts) return;
    const all = [...posts.entries()].filter(([, p]) => p.via !== null).sort((x, y) => x[1].o.ts - y[1].o.ts);
    const target = Math.floor(L.maxPosts * 0.9);
    for (const [id, p] of all) {
      if (posts.size <= target) return;
      if (keepAuthors && keepAuthors.has(p.o.a)) continue;
      drop(id);
    }
    for (const [id] of all) {
      if (posts.size <= L.maxPosts) return;
      drop(id);
    }
  }
  // newest first; filter is (entry) => bool
  function feed({ filter = null, limit = 100, before = Infinity } = {}) {
    return [...posts.entries()].filter(([, p]) => p.o.ts < before && (!filter || filter(p)))
      .sort((x, y) => y[1].o.ts - x[1].o.ts).slice(0, limit).map(([id, p]) => Object.assign({ id }, p));
  }
  function postsSince(since, filter, limit = 100) {
    return [...posts.entries()].filter(([, p]) => p.o.ts > since && (!filter || filter(p)))
      .sort((x, y) => x[1].o.ts - y[1].o.ts).slice(-limit).map(([id, p]) => Object.assign({ id }, p));
  }
  function removeAuthor(a) { for (const id of [...(byAuthor.get(a) || [])]) if (posts.get(id).via !== null) drop(id, false); }

  /* rooms */
  function addRoom(def, { joined = false, now = Date.now() } = {}) {
    const v = verify(def, now, L);
    if (!v.ok || def.k !== 'roomdef') return { status: 'rejected', error: v.error || 'not a room' };
    const have = rooms.get(def.room);
    if (have) { if (joined) have.joined = true; return { status: 'dup', room: def.room }; }
    if (rooms.size >= L.maxRooms) {
      const drop = [...rooms.entries()].find(([, r]) => !r.joined);
      if (!drop) return { status: 'rejected', error: `already in ${L.maxRooms} rooms` };
      rooms.delete(drop[0]);
    }
    rooms.set(def.room, { def, joined, members: new Map(), msgs: new Map() });
    return { status: 'new', room: def.room };
  }
  function addMember(o, { now = Date.now() } = {}) {
    const v = verify(o, now, L);
    if (!v.ok || o.k !== 'member') return { status: 'rejected', error: v.error || 'not a member entry' };
    const r = rooms.get(o.room);
    if (!r) return { status: 'rejected', error: 'unknown room' };
    const have = r.members.get(o.a);
    if (have && have.ts >= o.ts) return { status: 'dup' };
    if (!have && r.members.size >= L.maxMembers) return { status: 'rejected', error: 'room is full' };
    r.members.set(o.a, o);
    return { status: have ? 'updated' : 'new' };
  }
  function addRoomMsg(o, { now = Date.now(), via = null } = {}) {
    const v = verify(o, now, L);
    if (!v.ok || o.k !== 'roommsg') return { status: 'rejected', error: v.error || 'not a room message' };
    const r = rooms.get(o.room);
    if (!r) return { status: 'rejected', error: 'unknown room' };
    const m = r.members.get(o.a);
    if (!m || m.left) return { status: 'rejected', error: 'not a member of this room' };
    if (r.msgs.has(v.id)) return { status: 'dup', id: v.id };
    r.msgs.set(v.id, { o, at: now, via });
    if (r.msgs.size > L.maxRoomMsgs) {
      const oldest = [...r.msgs.entries()].sort((x, y) => x[1].o.ts - y[1].o.ts)[0];
      r.msgs.delete(oldest[0]);
    }
    return { status: 'new', id: v.id };
  }
  function roomMsgs(room, { since = 0, limit = 200 } = {}) {
    const r = rooms.get(room);
    if (!r) return [];
    return [...r.msgs.entries()].filter(([, m]) => m.o.ts > since).sort((x, y) => x[1].o.ts - y[1].o.ts)
      .slice(-limit).map(([id, m]) => Object.assign({ id }, m));
  }
  const room = (id) => rooms.get(id) || null;
  const roomList = () => [...rooms.values()];
  const leaveRoom = (id) => rooms.delete(id);

  function prune(now = Date.now()) {
    for (const [id, p] of posts) if (p.via !== null && p.o.ts < now - L.keepMs) drop(id, false);
    for (const r of rooms.values()) for (const [id, m] of r.msgs) if (m.o.ts < now - L.keepMs) r.msgs.delete(id);
  }

  function toJSON() {
    return {
      v: 1,
      posts: [...posts.values()].map((p) => ({ o: p.o, at: p.at, via: p.via, hops: p.hops })),
      rooms: [...rooms.values()].map((r) => ({
        def: r.def, joined: r.joined, members: [...r.members.values()],
        msgs: [...r.msgs.values()].map((m) => ({ o: m.o, at: m.at, via: m.via })),
      })),
    };
  }
  // Loading trusts our own file for signatures (it was checked on arrival)
  // but still drops anything that is not shaped right.
  function load(j) {
    if (!j || typeof j !== 'object') return;
    for (const p of Array.isArray(j.posts) ? j.posts : []) {
      if (!p || !p.o || p.o.k !== 'post' || !isPub(p.o.a) || !KINDS.post(p.o)) continue;
      put(idOf(p.o), { o: p.o, at: Number(p.at) || 0, via: typeof p.via === 'string' && FP_RE.test(p.via) ? p.via : (p.via === null ? null : 'unknown'), hops: Number(p.hops) || 0 });
    }
    for (const r of Array.isArray(j.rooms) ? j.rooms : []) {
      if (!r || !r.def || r.def.k !== 'roomdef' || !isPub(r.def.a) || !KINDS.roomdef(r.def)) continue;
      const room = { def: r.def, joined: r.joined === true, members: new Map(), msgs: new Map() };
      for (const m of Array.isArray(r.members) ? r.members : []) if (m && m.k === 'member' && isPub(m.a) && KINDS.member(m) && m.room === r.def.room) room.members.set(m.a, m);
      for (const m of Array.isArray(r.msgs) ? r.msgs : []) if (m && m.o && m.o.k === 'roommsg' && isPub(m.o.a) && KINDS.roommsg(m.o) && m.o.room === r.def.room) room.msgs.set(idOf(m.o), { o: m.o, at: Number(m.at) || 0, via: m.via || null });
      rooms.set(r.def.room, room);
    }
  }

  return {
    addPost, feed, postsSince, removeAuthor, trimPosts,
    addRoom, addMember, addRoomMsg, roomMsgs, room, roomList, leaveRoom,
    prune, toJSON, load, get size() { return posts.size; }, limits: L,
  };
}

module.exports = {
  newSigningKey, loadSigningKey, keyId, canonical, idOf, verify, sign, roomIdOf, isPub, bindKey, checkBinding,
  makePost, makeRoom, makeMember, makeRoomMsg, createStore, cleanText, cleanLine,
  POST_MAX, ROOM_MSG_MAX, ROOM_NAME_MAX, KEEP_MS, ONION_RE, FP_RE, ID_RE,
};
