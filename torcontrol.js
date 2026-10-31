// torcontrol.js: NodeSignal's own Tor onion service, through Tor's control port
// ============================================================================
// The way bitcoind's -listenonion does it: connect to the control port of the
// Tor already running on this machine, authenticate, and ask Tor (ADD_ONION)
// to publish an onion service that forwards to NodeSignal's peer port. The
// operator needs no port forwarding and no torrc editing.
//
// The service is ephemeral: no Detach flag, so it lives exactly as long as
// this control connection. When NodeSignal stops or the connection drops, Tor
// removes it; startOnionService() reconnects and adds it again with the same
// key, so the .onion address stays the same.
//
// Spoken (Tor control protocol, https://spec.torproject.org/control-spec/):
//   PROTOCOLINFO 1, AUTHCHALLENGE SAFECOOKIE, AUTHENTICATE (NULL, SAFECOOKIE,
//   COOKIE, HASHEDPASSWORD), ADD_ONION with ED25519-V3 keys (v3 onions).
//   Replies: mid lines "250-", data lines "250+KEY=" with a dot-terminated
//   block, end line "250 ". Asynchronous events (650) are skipped.
//
// What it does NOT do, stated plainly:
//   · it does not install, start or configure Tor and never writes torrc.
//     Debian's tor package already opens a control socket at
//     /run/tor/control with cookie authentication, both open to the
//     debian-tor group, so the daemon's user must be in that group.
//   · it only makes NodeSignal reachable. Dialling other operators' onions
//     still goes through Tor's SOCKS port (--tor-proxy).
//   · the onion key it returns is the onion address's identity: whoever reads
//     it can run the same address. The caller stores it; this module never
//     logs it and keeps it out of error messages.
//   · plain COOKIE authentication sends the cookie itself to whatever answers
//     on that port. It is used only when Tor does not offer SAFECOOKIE (Tor
//     before 0.2.3.13). SAFECOOKIE first makes the other side prove it knows
//     the cookie, and is refused outright if it cannot.
//   · NULL authentication means any local program can control this Tor. That
//     is Tor's configuration, not ours; it is accepted and logged.
//   · no v2 onions (RSA1024), no client authorization, no SETEVENTS.
//
// API (Node standard library only, no dependencies)
//   await connectControl({ path, host, port, timeoutMs = 10000 })   (path, or host and port)
//       -> controller { endpoint, closed, command(line), close(), onClose(cb) }
//          timeoutMs bounds the connect and each reply; a reply that times out
//          closes the connection (a late reply would answer the wrong command).
//          command(line) -> { code, lines, data }: lines are the reply lines
//          without their "250-"/"250+"/"250 " prefix, data the dot-terminated
//          blocks (dot-unstuffed, lines joined with "\n"), in order.
//   await authenticate(ctl, { password })            -> method used
//   await addOnion(ctl, { key, virtPort, target })  -> { serviceId, key }
//   startOnionService({ candidates, password, key, virtPort, target, log,
//                       onUp, onDown, retryMs, timeoutMs }) -> { stop() }
//   Small pure helpers are exported for tests.
// ============================================================================
'use strict';

const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const MAX_REPLY = 64 * 1024;          // cap on one buffered reply, events included
const COOKIE_LEN = 32;
const NONCE_LEN = 32;
const SERVER_HASH_KEY = 'Tor safe cookie authentication server-to-controller hash';
const CLIENT_HASH_KEY = 'Tor safe cookie authentication controller-to-server hash';
const KEY_RE = /^ED25519-V3:([A-Za-z0-9+/]{86})(==)?$/;   // 64-byte expanded secret key
const SERVICE_ID_RE = /^[a-z2-7]{56}$/;
const DEFAULT_RETRY_MS = [5000, 30000, 120000, 300000];

/* ---------------------------------------------------------------- helpers */

// Text from the network or a peer, made safe for one log line.
function clean(s, max = 200) {
  s = String(s == null ? '' : s).replace(/[\x00-\x1f\x7f]+/g, ' ').trim();
  return s.length > max ? s.slice(0, max) + '...' : s;
}

// Tor's reply as text for an error message, withheld whole if it repeats a
// secret we sent (checked before truncation, so no partial secret survives).
function replyText(r, secrets = []) {
  const full = r.lines.join(' / ');
  for (const s of secrets) if (s && full.includes(s)) return `${r.code} (Tor's reply text withheld: it repeated a secret)`;
  return clean(`${r.code} ${full}`);
}

function runAs() { try { return os.userInfo().username; } catch { return ''; } }
function groupHint() {
  const u = runAs();
  return `the user NodeSignal runs as${u ? ` (${u})` : ''} must be allowed to read it: on Debian and Ubuntu, add that user to the debian-tor group, then restart NodeSignal`;
}

function describe(ep) {
  if (ep && ep.path != null) return String(ep.path);
  const h = (ep && ep.host) || '127.0.0.1';
  return (h.includes(':') ? `[${h}]` : h) + ':' + (ep && ep.port);
}

function checkEndpoint(ep) {
  if (!ep || typeof ep !== 'object') throw new TypeError('a Tor control endpoint is { path } or { host, port }');
  if (ep.path != null) {
    if (typeof ep.path !== 'string' || !ep.path || /[\0\r\n]/.test(ep.path)) throw new TypeError('invalid Tor control socket path');
    return;
  }
  if (!Number.isInteger(ep.port) || ep.port < 1 || ep.port > 65535) throw new TypeError('a Tor control endpoint needs a path or a port from 1 to 65535');
  if (ep.host != null && (typeof ep.host !== 'string' || !ep.host || /[\s\0]/.test(ep.host))) throw new TypeError('invalid Tor control host');
}

function checkPort(p, what) {
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new TypeError(`${what} must be a port from 1 to 65535`);
}

// ADD_ONION target, as in torrc's HiddenServicePort: a port, addr:port or
// unix:/path. No whitespace, commas, quotes or line breaks get through.
function checkTarget(t) {
  const s = typeof t === 'number' ? String(t) : t;
  if (typeof s !== 'string') throw new TypeError('target must be a port, "host:port" or "unix:/path"');
  if (/^\d{1,5}$/.test(s)) { checkPort(Number(s), 'target'); return s; }
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}|\[([0-9A-Fa-f:.]+)\]|localhost):(\d{1,5})$/.exec(s);
  if (m && (m[1] === 'localhost' || (m[2] ? net.isIPv6(m[2]) : net.isIPv4(m[1])))) { checkPort(Number(m[3]), 'target port'); return s; }
  if (/^unix:\/[^\s",\\]+$/.test(s)) return s;
  throw new TypeError('target must be a port, "host:port" or "unix:/path"');
}

// An ED25519-V3 key as ADD_ONION takes and returns it: canonical base64 of
// exactly 64 bytes. Anything else (other key types, whitespace, CR/LF) fails.
function isOnionKey(k) {
  if (typeof k !== 'string') return false;
  const m = KEY_RE.exec(k);
  if (!m) return false;
  const raw = Buffer.from(m[1] + '==', 'base64');
  return raw.length === 64 && raw.toString('base64') === m[1] + '==';
}
const keySecrets = (k) => { const m = KEY_RE.exec(k || ''); return m ? [m[1].slice(0, 43), m[1].slice(43)] : []; };

// QuotedString as the control spec reads it: backslash escapes \n \t \r \\
// \" \' \xHH and up to three octal digits, the octal and hex ones being raw
// bytes (a path in UTF-8 arrives as \303\251 and so on).
function unquoteAt(s, i) {
  if (s[i] !== '"') throw new Error('expected a quoted string');
  const bytes = [];
  const pushText = (t) => { for (const b of Buffer.from(t, 'utf8')) bytes.push(b); };
  i++;
  while (i < s.length) {
    const c = s[i];
    if (c === '"') return { value: Buffer.from(bytes).toString('utf8'), end: i + 1 };
    if (c !== '\\') {
      const ch = String.fromCodePoint(s.codePointAt(i));
      pushText(ch); i += ch.length; continue;
    }
    const n = s[i + 1];
    if (n === undefined) break;
    if (n >= '0' && n <= '7') {
      let j = i + 1, v = 0;
      while (j < s.length && j < i + 4 && s[j] >= '0' && s[j] <= '7') v = v * 8 + (s.charCodeAt(j++) - 48);
      if (v > 255) throw new Error('bad octal escape in a quoted string');
      bytes.push(v); i = j; continue;
    }
    if (n === 'x' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 2, i + 4))) { bytes.push(parseInt(s.slice(i + 2, i + 4), 16)); i += 4; continue; }
    pushText(n === 'n' ? '\n' : n === 't' ? '\t' : n === 'r' ? '\r' : n);
    i += 2;
  }
  throw new Error('unterminated quoted string');
}

// "KEY=value KEY2=\"quoted\" word" -> { KEY: 'value', KEY2: 'quoted' }.
// Bare words without "=" are skipped. Null prototype: keys come from the wire.
function parseKeyValues(s) {
  const out = Object.create(null);
  let i = 0;
  const n = s.length;
  while (i < n) {
    while (i < n && s[i] === ' ') i++;
    if (i >= n) break;
    const eq = s.indexOf('=', i), sp = s.indexOf(' ', i);
    if (eq === -1 || (sp !== -1 && sp < eq)) { i = sp === -1 ? n : sp; continue; }
    const key = s.slice(i, eq);
    i = eq + 1;
    if (s[i] === '"') {
      const r = unquoteAt(s, i);
      if (r.end < n && s[r.end] !== ' ') throw new Error('text after a quoted string');
      out[key] = r.value; i = r.end;
    } else {
      const e = s.indexOf(' ', i);
      out[key] = s.slice(i, e === -1 ? n : e); i = e === -1 ? n : e;
    }
  }
  return out;
}

// A password as a QuotedString for AUTHENTICATE.
const quoteString = (s) => '"' + String(s).replace(/[\\"]/g, '\\$&') + '"';

/* ------------------------------------------------------------- controller */

function connectControl(opts = {}) {
  try { checkEndpoint(opts); } catch (e) { return Promise.reject(e); }
  const { path: sockPath, host = '127.0.0.1', port, timeoutMs = 10000 } = opts;
  const where = describe(opts);
  return new Promise((resolve, reject) => {
    const sock = sockPath != null ? net.connect({ path: sockPath }) : net.connect({ host, port });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true; sock.destroy();
      reject(new Error(`timed out after ${timeoutMs} ms connecting to the Tor control port at ${where}`));
    }, timeoutMs);
    sock.on('error', (e) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      reject(new Error(connectError(where, e)));
    });
    sock.once('connect', () => {
      if (settled) { sock.destroy(); return; }
      settled = true; clearTimeout(timer);
      resolve(controller(sock, where, timeoutMs));
    });
  });
}

function connectError(where, e) {
  const code = (e && e.code) || '';
  if (code === 'ENOENT') return `no Tor control socket at ${where} (ENOENT)`;
  if (code === 'EACCES' || code === 'EPERM') return `permission denied on the Tor control socket ${where} (${code}): ${groupHint()}`;
  if (code === 'ECONNREFUSED') return `nothing is listening on the Tor control port ${where} (ECONNREFUSED)`;
  return `cannot connect to the Tor control port at ${where}: ${code || clean(e && e.message)}`;
}

function controller(sock, where, timeoutMs) {
  let closed = false, reason = null;
  const queue = [];
  let current = null;
  const closeCbs = [];
  let buf = Buffer.alloc(0), unit = null, unitBytes = 0;

  function fail(err) {
    if (closed) return;
    closed = true; reason = err;
    sock.destroy();
    if (current) { clearTimeout(current.timer); current.reject(err); current = null; }
    for (const q of queue.splice(0)) q.reject(err);
    for (const cb of closeCbs.splice(0)) {
      try { cb(err); } catch (e) { process.emitWarning(`torcontrol onClose callback threw: ${e && e.message}`); }
    }
  }

  function pump() {
    if (closed || current || !queue.length) return;
    current = queue.shift();
    const verb = current.line.split(' ')[0];     // never the arguments: they can be secrets
    current.timer = setTimeout(() => fail(new Error(`no reply to ${verb} from the Tor control port at ${where} within ${timeoutMs} ms`)), timeoutMs);
    sock.write(current.line + '\r\n');
  }

  const tooBig = () => fail(new Error(`the Tor control port at ${where} sent a reply larger than ${MAX_REPLY / 1024} KiB; connection closed`));

  function onData(chunk) {
    if (closed) return;
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    let nl;
    while (!closed && (nl = buf.indexOf(0x0a)) !== -1) {
      const raw = buf.subarray(0, nl + 1);
      buf = buf.subarray(nl + 1);
      unitBytes += raw.length;
      if (unitBytes > MAX_REPLY) return tooBig();
      let line = raw.toString('utf8', 0, raw.length - 1);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      onLine(line);
    }
    if (!closed && unitBytes + buf.length > MAX_REPLY) tooBig();
  }

  function onLine(line) {
    if (unit && unit.block) {                    // inside a "250+KEY=" data block
      if (line === '.') { unit.data.push(unit.block.join('\n')); unit.block = null; }
      else unit.block.push(line.startsWith('.') ? line.slice(1) : line);
      return;
    }
    const m = /^(\d{3})(?:([ +-])(.*))?$/.exec(line);
    if (!m) return fail(new Error(`the Tor control port at ${where} sent a line that is not a control-protocol reply (is this really Tor?)`));
    if (!unit) unit = { async: m[1][0] === '6', lines: [], data: [], block: null };
    unit.lines.push(m[3] || '');
    if (m[2] === '+') { unit.block = []; return; }
    if (m[2] === '-') return;
    const done = unit;                           // end line: the reply is complete
    unit = null; unitBytes = 0;
    if (done.async) return;                      // an event (650), not an answer to us
    if (!current) return fail(new Error(`the Tor control port at ${where} sent a reply nobody asked for`));
    const c = current;
    current = null; clearTimeout(c.timer);
    c.resolve({ code: Number(m[1]), lines: done.lines, data: done.data });
    pump();
  }

  sock.on('data', onData);
  sock.on('error', (e) => fail(new Error(`the Tor control connection to ${where} failed: ${e.code || clean(e.message)}`)));
  sock.on('close', () => fail(new Error(`the Tor control port at ${where} closed the connection`)));

  return {
    endpoint: where,
    get closed() { return closed; },
    command(line) {
      if (typeof line !== 'string' || !line || /[\r\n\0]/.test(line)) return Promise.reject(new TypeError('a Tor control command is one non-empty line with no CR, LF or NUL'));
      if (closed) return Promise.reject(reason);
      return new Promise((resolve, reject) => { queue.push({ line, resolve, reject, timer: null }); pump(); });
    },
    close() { fail(new Error(`the Tor control connection to ${where} was closed by NodeSignal`)); },
    onClose(cb) {
      if (typeof cb !== 'function') throw new TypeError('onClose needs a function');
      if (closed) setImmediate(() => cb(reason)); else closeCbs.push(cb);
    },
  };
}

/* --------------------------------------------------------- authentication */

async function readCookie(file) {
  if (typeof file !== 'string' || !file) throw new Error('Tor offered cookie authentication but named no cookie file');
  const shown = clean(file);
  if (!path.isAbsolute(file)) throw new Error(`Tor named a cookie file that is not an absolute path (${shown})`);
  const failed = (e) => {
    const code = (e && e.code) || 'error';
    if (code === 'EACCES' || code === 'EPERM') return new Error(`Tor's auth cookie file ${shown} could not be read (${code}): ${groupHint()}`);
    if (code === 'ENOENT') return new Error(`Tor's auth cookie file ${shown} could not be read: it does not exist (ENOENT)`);
    return new Error(`Tor's auth cookie file ${shown} could not be read (${code})`);
  };
  let fh;
  // O_NONBLOCK: a FIFO named by an impostor must not hang a thread.
  try { fh = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0)); } catch (e) { throw failed(e); }
  try {
    let st;
    try { st = await fh.stat(); } catch (e) { throw failed(e); }
    if (!st.isFile()) throw new Error(`Tor's auth cookie ${shown} is not a regular file`);
    if (st.size !== COOKIE_LEN) throw new Error(`Tor's auth cookie file ${shown} is ${st.size} bytes, expected exactly ${COOKIE_LEN}`);
    const b = Buffer.alloc(COOKIE_LEN + 1);
    let n;
    try { n = (await fh.read(b, 0, b.length, 0)).bytesRead; } catch (e) { throw failed(e); }
    if (n !== COOKIE_LEN) throw new Error(`Tor's auth cookie file ${shown} changed while it was read`);
    return b.subarray(0, COOKIE_LEN);
  } finally {
    await fh.close().catch(() => { });
  }
}

async function expectOk(ctl, line, method, secrets) {
  const r = await ctl.command(line);
  if (r.code !== 250) throw new Error(`Tor at ${ctl.endpoint} refused ${method} authentication: ${replyText(r, secrets)}`);
}

async function safeCookie(ctl, cookie) {
  const where = ctl.endpoint;
  const clientNonce = crypto.randomBytes(NONCE_LEN);
  const r = await ctl.command('AUTHCHALLENGE SAFECOOKIE ' + clientNonce.toString('hex').toUpperCase());
  if (r.code !== 250) throw new Error(`Tor at ${where} refused AUTHCHALLENGE: ${replyText(r)}`);
  const line = r.lines.find((l) => /^AUTHCHALLENGE( |$)/.test(l));
  let kv = null;
  try { kv = line ? parseKeyValues(line.slice('AUTHCHALLENGE'.length)) : null; } catch { kv = null; }
  const hex64 = /^[0-9A-Fa-f]{64}$/;
  if (!kv || !hex64.test(kv.SERVERHASH || '') || !hex64.test(kv.SERVERNONCE || '')) {
    throw new Error(`Tor at ${where} sent an AUTHCHALLENGE reply without a valid SERVERHASH and SERVERNONCE`);
  }
  const serverNonce = Buffer.from(kv.SERVERNONCE, 'hex');
  const msg = Buffer.concat([cookie, clientNonce, serverNonce]);
  const expected = crypto.createHmac('sha256', SERVER_HASH_KEY).update(msg).digest();
  if (!crypto.timingSafeEqual(expected, Buffer.from(kv.SERVERHASH, 'hex'))) {
    throw new Error(`the control port at ${where} could not prove it knows Tor's auth cookie (SERVERHASH did not match), so NodeSignal refused to authenticate: the cookie file belongs to another Tor, or something other than Tor is listening there`);
  }
  const clientHash = crypto.createHmac('sha256', CLIENT_HASH_KEY).update(msg).digest('hex').toUpperCase();
  await expectOk(ctl, 'AUTHENTICATE ' + clientHash, 'SAFECOOKIE', [clientHash]);
}

// Preference: NULL, SAFECOOKIE, COOKIE, HASHEDPASSWORD. When the cookie cannot
// be read and Tor also takes a password that the operator configured, the
// password is used instead (nothing has been sent yet at that point). A failed
// SAFECOOKIE proof never falls back: an impostor must not get the password.
// On failure the caller closes ctl (Tor closes it after a refused AUTHENTICATE).
async function authenticate(ctl, { password } = {}) {
  const where = ctl.endpoint;
  const info = await ctl.command('PROTOCOLINFO 1');
  if (info.code !== 250) throw new Error(`Tor at ${where} refused PROTOCOLINFO: ${replyText(info)}`);
  const authLine = info.lines.find((l) => /^AUTH( |$)/.test(l));
  if (!authLine) throw new Error(`Tor at ${where} named no authentication methods in its PROTOCOLINFO reply`);
  let kv;
  try { kv = parseKeyValues(authLine.slice(4)); } catch (e) { throw new Error(`Tor at ${where} sent an unreadable AUTH line (${e.message})`); }
  const methods = String(kv.METHODS || '').toUpperCase().split(',').filter(Boolean);
  const havePassword = typeof password === 'string' && password.length > 0;
  const takesPassword = methods.includes('HASHEDPASSWORD');

  if (methods.includes('NULL')) {
    await expectOk(ctl, 'AUTHENTICATE', 'NULL', []);
    return 'NULL';
  }
  const cookieMethod = methods.includes('SAFECOOKIE') ? 'SAFECOOKIE' : methods.includes('COOKIE') ? 'COOKIE' : null;
  if (cookieMethod) {
    let cookie = null;
    try { cookie = await readCookie(kv.COOKIEFILE); } catch (e) { if (!(takesPassword && havePassword)) throw e; }
    if (cookie) {
      if (cookieMethod === 'SAFECOOKIE') await safeCookie(ctl, cookie);
      else {
        const hex = cookie.toString('hex').toUpperCase();
        await expectOk(ctl, 'AUTHENTICATE ' + hex, 'COOKIE', [hex, hex.toLowerCase()]);
      }
      return cookieMethod;
    }
  }
  if (takesPassword) {
    if (!havePassword) throw new Error(`Tor at ${where} asks for its control password (HashedControlPassword) and NodeSignal has none configured`);
    if (/[\r\n\0]/.test(password)) throw new Error('the Tor control password contains a line break or NUL, which the control protocol cannot carry');
    const q = quoteString(password);
    await expectOk(ctl, 'AUTHENTICATE ' + q, 'HASHEDPASSWORD', [password, q]);
    return 'HASHEDPASSWORD';
  }
  throw new Error(`Tor at ${where} offers no authentication method NodeSignal supports (offered: ${clean(methods.join(',')) || 'none'})`);
}

/* -------------------------------------------------------------- ADD_ONION */

async function addOnion(ctl, { key = null, virtPort, target } = {}) {
  if (key != null && !isOnionKey(key)) throw new TypeError('the onion service key must be ED25519-V3:<base64 of 64 bytes>');
  checkPort(virtPort, 'virtPort');
  const tgt = checkTarget(target);
  const secrets = key != null ? keySecrets(key) : [];
  const r = await ctl.command(`ADD_ONION ${key != null ? key : 'NEW:ED25519-V3'} Port=${virtPort},${tgt}`);
  if (r.code !== 250) throw new Error(`Tor at ${ctl.endpoint} refused to add the onion service (ADD_ONION): ${replyText(r, secrets)}`);
  const field = (name) => { const l = r.lines.find((x) => x.startsWith(name + '=')); return l == null ? null : l.slice(name.length + 1); };
  const serviceId = field('ServiceID');
  if (!serviceId || !SERVICE_ID_RE.test(serviceId)) throw new Error(`Tor at ${ctl.endpoint} did not return a valid v3 ServiceID for the onion service`);
  if (key != null) return { serviceId, key };
  const created = field('PrivateKey');
  if (!isOnionKey(created)) throw new Error(`Tor at ${ctl.endpoint} did not return the new onion service's key in the ED25519-V3 form`);
  return { serviceId, key: created };
}

/* ------------------------------------------------------ the running service */

function startOnionService(opts = {}) {
  const {
    candidates, password, virtPort, target, log = () => { }, onUp = () => { }, onDown = () => { },
    retryMs = DEFAULT_RETRY_MS, timeoutMs = 10000,
  } = opts;
  if (!Array.isArray(candidates) || !candidates.length) throw new TypeError('candidates must list at least one Tor control endpoint');
  candidates.forEach(checkEndpoint);
  if (opts.key != null && !isOnionKey(opts.key)) throw new TypeError('the onion service key must be ED25519-V3:<base64 of 64 bytes>');
  checkPort(virtPort, 'virtPort');
  const tgt = checkTarget(target);
  if (!Array.isArray(retryMs) || !retryMs.length || retryMs.some((n) => !Number.isFinite(n) || n < 0)) throw new TypeError('retryMs must be a non-empty list of delays in ms');
  const eps = candidates.map((c) => ({ ...c }));

  let key = opts.key || null;                    // the newest key given or created
  let stopped = false, live = null, trying = null, timer = null, failures = 0;

  // Last line of defence: nothing that contains the key reaches log or onDown.
  const guard = (s) => {
    s = String(s);
    for (const x of keySecrets(key)) if (s.includes(x)) return '(message withheld: it contained the onion service key)';
    return s;
  };
  const say = (s) => { try { log(guard(s)); } catch { } };
  const later = (ms) => (ms >= 1000 ? `${Math.round(ms / 1000)}s` : `${ms}ms`);

  function down(msg) {
    const delay = retryMs[Math.min(failures, retryMs.length - 1)];
    failures++;
    say(`Tor onion service: ${msg}; retrying in ${later(delay)}`);
    try { onDown(guard(msg)); } catch (e) { say(`Tor onion service: the onDown handler failed: ${e && e.message}`); }
    if (stopped) return;
    timer = setTimeout(attempt, delay);
    if (timer.unref) timer.unref();
  }

  async function attempt() {
    timer = null;
    const errors = [];
    for (const ep of eps) {
      if (stopped) return;
      const where = describe(ep);
      let c = null;
      try {
        c = await connectControl({ ...ep, timeoutMs });
        trying = c;
        if (stopped) { c.close(); return; }
        const method = await authenticate(c, { password });
        if (method === 'NULL') say(`Tor control port at ${where} needs no authentication: any local program can control this Tor`);
        const r = await addOnion(c, { key, virtPort, target: tgt });
        trying = null;
        if (stopped) { c.close(); return; }
        key = r.key; failures = 0; live = c;
        const onion = r.serviceId + '.onion';
        c.onClose((err) => {
          if (live !== c) return;
          live = null;
          if (!stopped) down(`lost the control connection, ${onion} is offline until it reconnects (${(err && err.message) || 'closed'})`);
        });
        say(`Tor onion service ${onion} is up through the control port at ${where} (${method} authentication)`);
        try { onUp({ onion, key, endpoint: { ...ep } }); } catch (e) { say(`Tor onion service: the onUp handler failed: ${e && e.message}`); }
        return;
      } catch (e) {
        trying = null;
        if (c) c.close();
        errors.push(`${where}: ${(e && e.message) || e}`);
      }
    }
    if (!stopped) down(`no Tor control port worked (${errors.join('; ')})`);
  }

  timer = setTimeout(attempt, 0);
  return {
    stop() {
      if (stopped) return;
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      for (const c of [live, trying]) if (c) c.close();
      live = trying = null;
    },
  };
}

module.exports = {
  connectControl, authenticate, addOnion, startOnionService,
  // small pure helpers, exported for tests
  parseKeyValues, quoteString, isOnionKey, MAX_REPLY,
};
