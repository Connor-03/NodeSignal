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
function newSigningKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
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
function pubKeyObj(pubB64) {
  const raw = Buffer.from(String(pubB64 || ''), 'base64');
  if (raw.length !== 32) return null;
  try { return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' }); } catch { return null; }
}
const isPub = (s) => typeof s === 'string' && s.length === 44 && Buffer.from(s, 'base64').length === 32 && Buffer.from(s, 'base64').toString('base64') === s;

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
function verify(o, now = Date.now(), { keepMs = KEEP_MS } = {}) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return { ok: false, error: 'not an object' };
  const allowed = ALLOWED[o.k];
  if (!allowed) return { ok: false, error: 'unknown kind' };
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
  const rooms = new Map();

  function addPost(o, { via = null, hops = 0, now = Date.now(), mine = false } = {}) {
    const v = verify(o, now, L);
    if (!v.ok) return { status: 'rejected', error: v.error };
    if (o.k !== 'post') return { status: 'rejected', error: 'not a post' };
    if (posts.has(v.id)) return { status: 'dup', id: v.id };
    const byAuthor = [...posts.values()].filter((p) => p.o.a === o.a);
    if (!mine && byAuthor.filter((p) => p.o.ts > o.ts - 864e5 && p.o.ts <= o.ts + 864e5).length >= L.maxPerAuthorDay)
      return { status: 'rejected', error: 'too many posts from this author in a day' };
    posts.set(v.id, { o, at: now, via, hops: Math.max(0, Math.min(9, hops | 0)) });
    // per author: oldest first out
    if (byAuthor.length + 1 > L.maxPerAuthor) {
      const old = byAuthor.sort((x, y) => x.o.ts - y.o.ts)[0];
      if (old) posts.delete(idOf(old.o));
    }
    if (posts.size > L.maxPosts) trimPosts();
    return { status: 'new', id: v.id };
  }
  function trimPosts(keepAuthors = null) {
    const all = [...posts.entries()].sort((x, y) => x[1].o.ts - y[1].o.ts);
    for (const [id, p] of all) {
      if (posts.size <= L.maxPosts) break;
      if (p.via === null) continue;                 // never drop our own
      if (keepAuthors && keepAuthors.has(p.o.a)) continue;
      posts.delete(id);
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
  function removeAuthor(a) { for (const [id, p] of posts) if (p.o.a === a && p.via !== null) posts.delete(id); }

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
    for (const [id, p] of posts) if (p.via !== null && p.o.ts < now - L.keepMs) posts.delete(id);
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
      posts.set(idOf(p.o), { o: p.o, at: Number(p.at) || 0, via: typeof p.via === 'string' && FP_RE.test(p.via) ? p.via : (p.via === null ? null : 'unknown'), hops: Number(p.hops) || 0 });
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
  newSigningKey, loadSigningKey, keyId, canonical, idOf, verify, sign, roomIdOf, isPub,
  makePost, makeRoom, makeMember, makeRoomMsg, createStore, cleanText, cleanLine,
  POST_MAX, ROOM_MSG_MAX, ROOM_NAME_MAX, KEEP_MS, ONION_RE, FP_RE, ID_RE,
};
