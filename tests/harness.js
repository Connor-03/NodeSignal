// harness.js: shared helpers for the test suites. Not a test itself (run-all.js
// only runs *.test.js). Node standard library only.
//   · suite(): the t(name, fn) helper, a temp dir, spawned daemons, clean exit
//   · a raw RFC 6455 client (works on every Node version, no global WebSocket)
//     and the console's WebSocket API on top of it
//   · raw v3 peers (Noise XX initiator and responder) that can misbehave
// Loopback only; any address shown to a daemon as data uses documentation ranges.
'use strict';
const path = require('path'), fs = require('fs'), os = require('os'), net = require('net'), http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const noise = require('../noise.js');

const ROOT = path.join(__dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, ms = 8000, step = 100) {
  const end = Date.now() + ms; let last;
  while (Date.now() < end) { try { last = await fn(); if (last) return last; } catch (e) { last = e; } await sleep(step); }
  throw new Error('condition not met' + (last instanceof Error ? ': ' + last.message : ''));
}

/* ---- the suite: counters, temp dir, child daemons ---- */
function suite(prefix) {
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const kids = new Set();
  let failed = 0, passed = 0;
  const t = async (name, fn) => {
    try { await fn(); passed++; console.log('  ok   ' + name); }
    catch (e) {
      failed++;
      console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e).toString().split('\n').slice(0, 3).join('\n       '));
      if (process.env.DEBUG) for (const k of kids) console.log('--- ' + k.name + '\n' + k.log);
    }
  };
  // Options in `extra` come first, so they win over the defaults below (the
  // daemon reads the first occurrence of a flag).
  function daemon(name, { host = '127.0.0.1', peer, web, rpc = null, data = name, extra = [], nodeArgs = [] }) {
    const args = [...nodeArgs, path.join(ROOT, 'nodesignald.js'), ...extra, '--nick', name, '--bind', host,
      '--peer-port', String(peer), '--web-port', String(web), '--data', path.join(TMP, data),
      '--retry-scale', '0.01', '--checkin-ms', '0', '--rl-burst', '1000'];
    if (rpc) args.push('--rpc-url', 'http://127.0.0.1:' + rpc, '--rpc-user', 'u', '--rpc-pass', 'p'); else args.push('--no-rpc');
    const c = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    c.name = name; c.log = ''; c.stdout.on('data', (d) => (c.log += d)); c.stderr.on('data', (d) => (c.log += d));
    c.web = web; c.host = host; c.peer = peer; c.dataDir = path.join(TMP, data);
    kids.add(c); c.on('exit', () => kids.delete(c));
    return c;
  }
  async function finish(extraCleanup) {
    for (const k of [...kids]) await stop(k);
    if (extraCleanup) await extraCleanup();
    fs.rmSync(TMP, { recursive: true, force: true });
    console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
    process.exit(failed ? 1 : 0);
  }
  function abort(e) {
    console.error(e);
    for (const k of kids) { try { process.kill(k.pid, 'SIGKILL'); } catch { } }
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { }
    process.exit(1);
  }
  return { TMP, kids, t, daemon, finish, abort };
}
// By PID, through the child handle: never pkill -f.
const stop = (c) => new Promise((r) => { if (c.exitCode != null || c.signalCode != null) return r(); c.once('exit', r); c.kill('SIGTERM'); });

/* ---- HTTP: the console only answers as 127.0.0.1:<port> or localhost:<port> ---- */
function get(port, p, { host } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: p, method: 'GET', setHost: false,
      headers: { Host: host || `127.0.0.1:${port}` }, timeout: 3000 }, (res) => {
      const chunks = []; res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject); r.on('timeout', () => r.destroy(new Error('timeout'))); r.end();
  });
}
async function health(c) {
  try { const r = await get(c.web, '/health'); return r.status === 200 ? JSON.parse(r.body) : null; } catch { return null; }
}
// Up means OUR daemon answers: the nick must match, so a stray process on the
// same port (another checkout running its tests) fails loudly instead of
// being tested by mistake.
async function up(c) {
  for (let i = 0; i < 80; i++) {
    if (c.exitCode != null) break;
    const h = await health(c);
    if (h && c.name && h.nick !== c.name) throw new Error(`port ${c.web} is answered by another daemon ("${h.nick}")`);
    if (h) return c;
    await sleep(100);
  }
  throw new Error(c.log || 'daemon did not start');
}
async function pageToken(c) {
  const m = /name="ns-action-token" content="([^"]+)"/.exec((await get(c.web, '/')).body);
  if (!m) throw new Error('no action token in page');
  return m[1];
}

/* ---- WebSocket frames (RFC 6455) ---- */
// A client frame. mask:false makes an (illegal) unmasked one; len lets a test
// claim a length it does not send.
function wsFrame(opcode, payload = Buffer.alloc(0), { fin = true, mask = true, len } = {}) {
  payload = Buffer.from(payload);
  const n = len === undefined ? payload.length : len;
  let h;
  if (n < 126) { h = Buffer.alloc(2); h[1] = n; }
  else if (n < 65536) { h = Buffer.alloc(4); h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  h[0] = (fin ? 0x80 : 0) | opcode;
  if (!mask) return Buffer.concat([h, payload]);
  h[1] |= 0x80;
  const key = crypto.randomBytes(4), out = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ key[i & 3];
  return Buffer.concat([h, key, out]);
}
// Reads server frames off a buffer; returns [frames, rest]. lenCode is the
// 7-bit length field (<126, 126 = 16-bit, 127 = 64-bit).
function wsParse(buf) {
  const out = [];
  for (;;) {
    if (buf.length < 2) break;
    const masked = (buf[1] & 0x80) !== 0, lenCode = buf[1] & 0x7f;
    let len = lenCode, off = 2;
    if (lenCode === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4; }
    else if (lenCode === 127) { if (buf.length < 10) break; len = Number(buf.readBigUInt64BE(2)); off = 10; }
    let key = null;
    if (masked) { if (buf.length < off + 4) break; key = buf.subarray(off, off + 4); off += 4; }
    if (buf.length < off + len) break;
    let payload = Buffer.from(buf.subarray(off, off + len));
    if (key) for (let i = 0; i < payload.length; i++) payload[i] ^= key[i & 3];
    out.push({ fin: (buf[0] & 0x80) !== 0, opcode: buf[0] & 0x0f, masked, lenCode, payload });
    buf = buf.subarray(off + len);
  }
  return [out, buf];
}
// Opens a raw WebSocket. Resolves once the 101 arrives; rejects with the status line otherwise.
function wsConnect(port, { host, path: p = '/ws', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port });
    const key = crypto.randomBytes(16).toString('base64');
    let buf = Buffer.alloc(0), open = false;
    const api = { socket: s, frames: [], onFrame: null, closed: false,
      write: (b) => s.write(b),
      sendText: (str) => s.write(wsFrame(0x1, Buffer.from(str, 'utf8'))),
      close: () => s.destroy(),
      // the next frame matching pred (from the buffer, or as it arrives)
      next(pred = () => true, ms = 5000) {
        const end = Date.now() + ms;
        return (async () => {
          while (Date.now() < end) {
            const i = api.frames.findIndex(pred); if (i >= 0) return api.frames.splice(i, 1)[0];
            if (api.closed) throw new Error('socket closed');
            await sleep(10);
          }
          throw new Error('timed out waiting for a frame');
        })();
      },
      // resolves true once the server ends or destroys the connection
      ended(ms = 3000) { return until(() => api.closed, ms, 10).then(() => true, () => false); },
    };
    s.on('error', (e) => { if (!open) reject(e); });
    s.on('close', () => { api.closed = true; if (!open) reject(new Error('closed before the upgrade')); });
    s.on('end', () => { api.closed = true; });
    s.on('connect', () => s.write([`GET ${p} HTTP/1.1`, `Host: ${host || `127.0.0.1:${port}`}`, 'Upgrade: websocket', 'Connection: Upgrade',
      'Sec-WebSocket-Version: 13', `Sec-WebSocket-Key: ${key}`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), '', ''].join('\r\n')));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (!open) {
        const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
        const head = buf.subarray(0, i).toString('latin1');
        if (!/^HTTP\/1\.1 101/.test(head)) { s.destroy(); return reject(new Error(head.split('\r\n')[0])); }
        const want = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
        if (!head.includes('Sec-WebSocket-Accept: ' + want)) { s.destroy(); return reject(new Error('bad Sec-WebSocket-Accept')); }
        open = true; buf = buf.subarray(i + 4); resolve(api);
      }
      const [fs_, rest] = wsParse(buf); buf = rest;
      for (const f of fs_) { if (api.onFrame) api.onFrame(f); else api.frames.push(f); }
    });
  });
}

/* ---- the console's WebSocket API, as nodesignal.html uses it ---- */
async function ui(c) {
  const token = await pageToken(c);
  const w = await wsConnect(c.web);
  const seen = [], waiters = [];
  w.onFrame = (f) => {
    if (f.opcode !== 0x1) return;
    // an event goes to the first waiter that wants it, or into the buffer; never both
    const m = JSON.parse(f.payload.toString('utf8'));
    const x = waiters.find((y) => y.pred(m));
    if (x) { waiters.splice(waiters.indexOf(x), 1); x.res(m); } else seen.push(m);
  };
  return {
    token,
    send: (o) => w.sendText(JSON.stringify(Object.assign({ token }, o))),
    sendBare: (o) => w.sendText(JSON.stringify(o)),
    wait(pred, ms = 8000) {
      const hit = seen.find(pred); if (hit) { seen.splice(seen.indexOf(hit), 1); return Promise.resolve(hit); }
      return new Promise((r, j) => {
        const x = { pred, res: r }; waiters.push(x);
        setTimeout(() => { if (waiters.includes(x)) { waiters.splice(waiters.indexOf(x), 1); j(new Error('timed out waiting for a UI event')); } }, ms);
      });
    },
    async state() { seen.length = 0; this.send({ type: 'hello' }); return this.wait((m) => m.type === 'state'); },
    close: () => w.close(),
  };
}
const contactOf = (st, host) => st.contacts.find((x) => x.host === host);
// Send from a UI and return the new message id (from the daemon's echo).
async function sent(u, host, port, text) {
  u.send({ type: 'chat.send', host, port, text });
  const r = await u.wait((m) => m.type === 'chat.recv' && m.host === host && m.msg.from === 'me' && m.msg.text === text);
  return r.msg.id;
}
const status = (u, id, st, ms) => u.wait((m) => m.type === 'chat.status' && m.id === id && m.status === st, ms);
const contactsOnDisk = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')).contacts;

/* ---- the peer wire (:8788): length-prefixed frames, Noise XX v3 ---- */
const frame = (b) => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };
function frames(sock, on) {
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4) { const n = buf.readUInt32BE(0); if (buf.length < 4 + n) break; const p = buf.subarray(4, 4 + n); buf = buf.subarray(4 + n); on(p); }
  });
}
// A raw v3 initiator. Resolves once the handshake completes; JSON frames from
// the daemon go to onJson. localAddress keeps it apart from real daemons
// (contacts are keyed by source address).
function v3Client(host, port, onJson, localAddress, id = noise.loadIdentity(noise.newIdentity())) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port, localAddress }); let st, session;
    s.on('error', reject);
    s.on('close', () => { if (!session) reject(new Error('closed during the handshake')); });
    s.on('connect', () => { st = noise.v3.initStart(id); s.write(frame(st.msg1)); });
    frames(s, (p) => {
      if (!session) {
        const r = noise.v3.initFinish(st, p); s.write(frame(r.msg3)); session = r.session;
        resolve({ id, peerFp: r.peerFp, socket: s, send: (o) => s.write(frame(session.encrypt(JSON.stringify(o)))), close: () => s.destroy() });
        return;
      }
      onJson(JSON.parse(session.decrypt(p)));
    });
  });
}
// A raw v3 responder: handler(json, reply) for every frame after the handshake.
function v3Server(host, port, handler, id = noise.loadIdentity(noise.newIdentity())) {
  const conns = new Set();
  const srv = net.createServer((s) => {
    conns.add(s); s.on('close', () => conns.delete(s));
    let hs = null, session = null; s.on('error', () => { });
    frames(s, (p) => {
      if (!hs) { try { hs = noise.v3.respond(id, p); s.write(frame(hs.msg2)); } catch { s.destroy(); } return; }
      if (!session) { session = hs.finish(p).session; return; }
      handler(JSON.parse(session.decrypt(p)), (o) => s.write(frame(session.encrypt(JSON.stringify(o)))));
    });
  });
  srv.id = id; srv.conns = conns;
  srv.shut = () => new Promise((r) => { for (const s of conns) s.destroy(); srv.close(() => r()); });
  return new Promise((r) => srv.listen(port, host, () => r(srv)));
}

module.exports = {
  ROOT, sleep, until, suite, stop, get, health, up, pageToken,
  wsFrame, wsParse, wsConnect, ui, contactOf, sent, status, contactsOnDisk,
  frame, frames, v3Client, v3Server,
};
