// torcontrol.test.js: Tor control port client (torcontrol.js) against a mock Tor. Plain node, no deps.
//   node tests/torcontrol.test.js
// Never touches a real Tor. The mock below speaks the control protocol on
// 127.0.0.1 (ports 23100 to 23149) and on a unix socket in a temp dir:
// PROTOCOLINFO, AUTHCHALLENGE, AUTHENTICATE (NULL, SAFECOOKIE, COOKIE,
// HASHEDPASSWORD, as each test configures) and ADD_ONION (NEW and with a key;
// the ServiceID is derived from the key, so reusing a key can be checked). It
// can put 650 events before every reply and dribble replies in small pieces.
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tc = require('../torcontrol.js');

let failed = 0, skipped = 0;
const tests = [];
const cleanup = [];
const test = (name, fn) => tests.push({ name, fn });
class Skip extends Error { }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, ms = 3000, what = 'condition') => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out waiting for ' + what); await sleep(10); }
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-torctl-'));
const PORT = {
  wrongCookie: 23101, badHash: 23102, cookie: 23103, password: 23104, nul: 23105, onion: 23106,
  parse: 23107, big: 23108, silent: 23109, service: 23110, late: 23111, secrets: 23112, files: 23113,
  notTor: 23114, validate: 23115, locked: 23116, dead: 23149,   // nothing ever listens on 23149
};
const HOST = '127.0.0.1';
const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;

/* ------------------------------------------------------------ mock Tor */

const SERVER_KEY = 'Tor safe cookie authentication server-to-controller hash';
const CLIENT_KEY = 'Tor safe cookie authentication controller-to-server hash';
const hmac = (k, m) => crypto.createHmac('sha256', k).update(m).digest();

// QuotedString the way Tor writes one: \" \\ \n, other bytes outside
// printable ASCII as three octal digits.
function torQuote(s) {
  let out = '"';
  for (const b of Buffer.from(s, 'utf8')) {
    if (b === 0x22) out += '\\"';
    else if (b === 0x5c) out += '\\\\';
    else if (b === 0x0a) out += '\\n';
    else if (b >= 0x20 && b < 0x7f) out += String.fromCharCode(b);
    else out += '\\' + b.toString(8).padStart(3, '0');
  }
  return out + '"';
}
const torUnquote = (q) => q.slice(1, -1).replace(/\\(.)/g, '$1');

function base32(buf) {
  const A = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0, val = 0, out = '';
  for (const b of buf) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += A[(val >>> (bits - 5)) & 31]; bits -= 5; }
    val &= (1 << bits) - 1;
  }
  if (bits) out += A[(val << (5 - bits)) & 31];
  return out;
}
// Deterministic 56-char ServiceID for a key blob (35 bytes = 56 base32 chars).
const serviceIdOf = (blob) => base32(crypto.createHash('sha512').update(blob).digest().subarray(0, 35));
const newKey = () => 'ED25519-V3:' + crypto.randomBytes(64).toString('base64');

// Events a real Tor sends after SETEVENTS: one line, several lines, a data block.
const EVENTS = '650 BW 1024 2048\r\n650-CIRC 7 BUILT\r\n650 OK\r\n650+NS\r\nr fake relay\r\n..dotted\r\n.\r\n650 OK\r\n';

async function mockTor(cfg, where) {
  const m = { cfg, lines: [], auths: [], adds: [], passwords: [], conns: new Set(), onions: new Map(), accepted: 0 };
  const srv = net.createServer((sock) => {
    m.accepted++;
    m.conns.add(sock);
    const st = { authed: false, expect: null, onions: [] };
    sock.on('error', () => { });
    sock.on('close', () => { m.conns.delete(sock); for (const id of st.onions) m.onions.delete(id); });
    const send = async (text) => {
      if (cfg.events) text = EVENTS + text;
      if (!cfg.dribble) { if (!sock.destroyed) sock.write(text); return; }
      for (let k = 0; k < text.length; k += 5) {
        if (sock.destroyed) return;
        sock.write(text.slice(k, k + 5));
        await sleep(1);
      }
    };
    const refuse = (text) => send(text).then(() => sock.end());
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) !== -1) { const line = buf.slice(0, i); buf = buf.slice(i + 2); handle(line); }
    });
    function handle(line) {
      m.lines.push(line);
      const sp = line.indexOf(' ');
      const verb = (sp === -1 ? line : line.slice(0, sp)).toUpperCase();
      const arg = sp === -1 ? '' : line.slice(sp + 1);
      if (cfg.custom) {
        const r = cfg.custom(line, { sock, st, send, m });
        if (r === null) return;                  // handled (or deliberately silent)
        if (typeof r === 'string') return send(r);
      }
      const methods = cfg.methods || ['NULL'];
      switch (verb) {
        case 'PROTOCOLINFO': {
          const cf = methods.some((x) => x.includes('COOKIE')) ? ` COOKIEFILE=${torQuote(cfg.cookieFile)}` : '';
          return send(`250-PROTOCOLINFO 1\r\n250-AUTH METHODS=${methods.join(',')}${cf}\r\n250-VERSION Tor="0.4.8.13"\r\n250 OK\r\n`);
        }
        case 'AUTHCHALLENGE': {
          const [kind, nonce] = arg.split(' ');
          if (kind !== 'SAFECOOKIE' || !/^[0-9A-Fa-f]{64}$/.test(nonce || '')) return refuse('513 Invalid AUTHCHALLENGE argument\r\n');
          const serverNonce = crypto.randomBytes(32);
          const msg = Buffer.concat([cfg.cookie, Buffer.from(nonce, 'hex'), serverNonce]);
          const hash = cfg.badServerHash ? crypto.randomBytes(32) : hmac(SERVER_KEY, msg);
          st.expect = hmac(CLIENT_KEY, msg).toString('hex');
          return send(`250 AUTHCHALLENGE SERVERHASH=${hash.toString('hex').toUpperCase()} SERVERNONCE=${serverNonce.toString('hex').toUpperCase()}\r\n`);
        }
        case 'AUTHENTICATE': {
          let how = null;
          if (!arg) how = methods.includes('NULL') ? 'NULL' : null;
          else if (arg.startsWith('"')) {
            const pw = torUnquote(arg);
            m.passwords.push(pw);
            how = methods.includes('HASHEDPASSWORD') && pw === cfg.password ? 'HASHEDPASSWORD' : null;
          } else if (st.expect && arg.toLowerCase() === st.expect) how = 'SAFECOOKIE';
          else if (methods.includes('COOKIE') && cfg.cookie && arg.toLowerCase() === cfg.cookie.toString('hex')) how = 'COOKIE';
          if (!how) return refuse('515 Authentication failed: Password did not match HashedControlPassword *or* authentication cookie.\r\n');
          st.authed = true; m.auths.push(how);
          return send('250 OK\r\n');
        }
        case 'ADD_ONION': {
          if (!st.authed) return refuse('514 Authentication required.\r\n');
          const a = /^(\S+) Port=(\d+),(\S+)$/.exec(arg);
          if (!a) return send('512 Bad arguments to ADD_ONION\r\n');
          let blob, isNew = false;
          if (a[1] === 'NEW:ED25519-V3') { blob = crypto.randomBytes(64).toString('base64'); isNew = true; }
          else if (a[1].startsWith('ED25519-V3:')) blob = a[1].slice('ED25519-V3:'.length);
          else return send('513 Invalid key type\r\n');
          const id = serviceIdOf(blob);
          if (m.onions.has(id)) return send('550 Onion address collision\r\n');
          m.onions.set(id, { virtPort: Number(a[2]), target: a[3] });
          st.onions.push(id);
          m.adds.push({ id, isNew, line });
          return send(`250-ServiceID=${id}\r\n${isNew ? `250-PrivateKey=ED25519-V3:${blob}\r\n` : ''}250 OK\r\n`);
        }
        case 'QUIT': return refuse('250 closing connection\r\n');
        default: return send(`510 Unrecognized command "${verb}"\r\n`);
      }
    }
  });
  await new Promise((resolve, reject) => {
    srv.once('error', reject);
    if (typeof where === 'string') srv.listen(where, resolve); else srv.listen(where, HOST, resolve);
  });
  m.drop = () => { for (const s of m.conns) s.destroy(); };
  m.close = () => new Promise((r) => { m.drop(); srv.close(() => r()); });
  m.verbs = () => m.lines.map((l) => l.split(' ')[0]);
  cleanup.push(m.close);
  return m;
}

function cookieFile(name, cookie) {
  const f = path.join(TMP, name);
  fs.writeFileSync(f, cookie, { mode: 0o600 });
  return f;
}
const tcp = (port, extra = {}) => tc.connectControl({ host: HOST, port, timeoutMs: 2000, ...extra });
const track = (ctl) => { cleanup.push(() => ctl.close()); return ctl; };

/* ------------------------------------------------------- authentication */

test('SAFECOOKIE over a unix socket (cookie path with a quote, a backslash and UTF-8)', async () => {
  if (process.platform === 'win32') throw new Skip('unix sockets and such file names are POSIX');
  const cookie = crypto.randomBytes(32);
  const file = cookieFile('auth "cookie" \\ \u00e9', cookie);
  const sockPath = path.join(TMP, 'control-safe');
  const tor = await mockTor({ methods: ['COOKIE', 'SAFECOOKIE'], cookie, cookieFile: file }, sockPath);
  const ctl = track(await tc.connectControl({ path: sockPath }));
  assert.strictEqual(ctl.endpoint, sockPath);
  assert.strictEqual(await tc.authenticate(ctl), 'SAFECOOKIE');
  assert.deepStrictEqual(tor.auths, ['SAFECOOKIE']);
  assert.deepStrictEqual(tor.verbs(), ['PROTOCOLINFO', 'AUTHCHALLENGE', 'AUTHENTICATE']);
  assert.strictEqual(tor.lines[0], 'PROTOCOLINFO 1');
  assert(/^AUTHCHALLENGE SAFECOOKIE [0-9A-F]{64}$/.test(tor.lines[1]), tor.lines[1]);
  assert(/^AUTHENTICATE [0-9A-F]{64}$/.test(tor.lines[2]), 'AUTHENTICATE carries the 32-byte client hash');
  const hex = cookie.toString('hex');
  assert(!tor.lines.some((l) => l.toLowerCase().includes(hex)), 'the cookie itself never goes on the wire');
  ctl.close();
});

test('a cookie the server does not accept: Tor\'s refusal is reported clearly, without the cookie', async () => {
  const theirs = crypto.randomBytes(32), ours = crypto.randomBytes(32);
  const file = cookieFile('stale-cookie', ours);
  const tor = await mockTor({ methods: ['COOKIE'], cookie: theirs, cookieFile: file }, PORT.wrongCookie);
  const ctl = track(await tcp(PORT.wrongCookie));
  const err = await tc.authenticate(ctl).then(() => null, (e) => e);
  assert(err, 'authentication must fail');
  assert(/refused COOKIE authentication: 515 Authentication failed/.test(err.message), err.message);
  assert(err.message.includes(`127.0.0.1:${PORT.wrongCookie}`), 'names the endpoint');
  assert(!err.message.toLowerCase().includes(ours.toString('hex')), 'no cookie in the error');
  await until(() => ctl.closed, 2000, 'Tor to close the connection after 515');
  assert.deepStrictEqual(tor.auths, []);
});

test('SAFECOOKIE: a server that cannot prove it knows the cookie is refused before AUTHENTICATE', async () => {
  const cookie = crypto.randomBytes(32);
  const file = cookieFile('cookie-badhash', cookie);
  const tor = await mockTor({ methods: ['SAFECOOKIE', 'HASHEDPASSWORD'], cookie, cookieFile: file, badServerHash: true, password: 'never sent' }, PORT.badHash);
  const ctl = track(await tcp(PORT.badHash));
  await assert.rejects(tc.authenticate(ctl, { password: 'never sent' }), (e) => {
    assert(/could not prove it knows Tor's auth cookie \(SERVERHASH did not match\)/.test(e.message), e.message);
    assert(!e.message.toLowerCase().includes(cookie.toString('hex')));
    return true;
  });
  assert.deepStrictEqual(tor.verbs(), ['PROTOCOLINFO', 'AUTHCHALLENGE'], 'nothing sent after the bad proof, not even the password');
  assert.deepStrictEqual(tor.passwords, []);
  ctl.close();

  // Same outcome when our cookie file is not the one this Tor uses.
  tor.cfg.badServerHash = false;
  tor.cfg.cookieFile = cookieFile('cookie-other-tor', crypto.randomBytes(32));
  tor.lines.length = 0;
  const ctl2 = track(await tcp(PORT.badHash));
  await assert.rejects(tc.authenticate(ctl2), /SERVERHASH did not match/);
  assert.deepStrictEqual(tor.verbs(), ['PROTOCOLINFO', 'AUTHCHALLENGE']);
  ctl2.close();
});

test('COOKIE when Tor does not offer SAFECOOKIE', async () => {
  const cookie = crypto.randomBytes(32);
  const file = cookieFile('cookie-plain', cookie);
  const tor = await mockTor({ methods: ['COOKIE', 'HASHEDPASSWORD'], cookie, cookieFile: file, password: 'unused' }, PORT.cookie);
  const ctl = track(await tcp(PORT.cookie));
  assert.strictEqual(await tc.authenticate(ctl, { password: 'unused' }), 'COOKIE');
  assert.deepStrictEqual(tor.auths, ['COOKIE']);
  assert.deepStrictEqual(tor.lines, ['PROTOCOLINFO 1', 'AUTHENTICATE ' + cookie.toString('hex').toUpperCase()]);
  assert.deepStrictEqual(tor.passwords, []);
  ctl.close();
});

test('HASHEDPASSWORD: quote and backslash escaped; wrong, missing and multi-line passwords', async () => {
  const pw = 'p"ss\\w0rd with space';
  const tor = await mockTor({ methods: ['HASHEDPASSWORD'], password: pw }, PORT.password);
  const ctl = track(await tcp(PORT.password));
  assert.strictEqual(await tc.authenticate(ctl, { password: pw }), 'HASHEDPASSWORD');
  assert.strictEqual(tor.lines[1], 'AUTHENTICATE "p\\"ss\\\\w0rd with space"');
  assert.deepStrictEqual(tor.passwords, [pw], 'Tor decodes exactly the configured password');
  ctl.close();

  const wrong = 'not-the-password-123';
  const c2 = track(await tcp(PORT.password));
  await assert.rejects(tc.authenticate(c2, { password: wrong }), (e) => {
    assert(/refused HASHEDPASSWORD authentication: 515/.test(e.message), e.message);
    assert(!e.message.includes(wrong));
    return true;
  });

  const c3 = track(await tcp(PORT.password));
  await assert.rejects(tc.authenticate(c3, {}), /asks for its control password \(HashedControlPassword\) and NodeSignal has none configured/);
  c3.close();

  const before = tor.lines.length;
  const c4 = track(await tcp(PORT.password));
  await assert.rejects(tc.authenticate(c4, { password: 'line1\r\nSIGNAL HALT' }), (e) => {
    assert(/line break or NUL/.test(e.message));
    assert(!e.message.includes('line1'));
    return true;
  });
  assert.deepStrictEqual(tor.lines.slice(before), ['PROTOCOLINFO 1'], 'the password with CR/LF was never sent');
  c4.close();
});

test('NULL authentication', async () => {
  const tor = await mockTor({ methods: ['NULL'] }, PORT.nul);
  const ctl = track(await tcp(PORT.nul));
  assert.strictEqual(await tc.authenticate(ctl, { password: 'ignored' }), 'NULL');
  assert.deepStrictEqual(tor.lines, ['PROTOCOLINFO 1', 'AUTHENTICATE']);
  assert.deepStrictEqual(tor.auths, ['NULL']);
  ctl.close();
});

test('cookie file problems: missing, wrong size, relative, a directory; password fallback', async () => {
  const cookie = crypto.randomBytes(32);
  const tor = await mockTor({ methods: ['COOKIE', 'SAFECOOKIE'], cookie, cookieFile: path.join(TMP, 'no-such-cookie') }, PORT.files);
  const attempt = async (pw) => { const c = track(await tcp(PORT.files)); try { return await tc.authenticate(c, { password: pw }); } finally { c.close(); } };

  await assert.rejects(attempt(), (e) => {
    assert(e.message.includes(path.join(TMP, 'no-such-cookie')), 'names the file');
    assert(/could not be read: it does not exist \(ENOENT\)/.test(e.message), e.message);
    return true;
  });
  tor.cfg.cookieFile = cookieFile('short-cookie', cookie.subarray(0, 31));
  await assert.rejects(attempt(), /is 31 bytes, expected exactly 32/);
  tor.cfg.cookieFile = 'relative/cookie';
  await assert.rejects(attempt(), /not an absolute path/);
  tor.cfg.cookieFile = TMP;
  await assert.rejects(attempt(), /is not a regular file/);
  assert(!tor.lines.some((l) => l.startsWith('AUTH')), 'nothing but PROTOCOLINFO was sent');

  // Cookie unreadable, but Tor also takes the password the operator configured.
  tor.cfg.methods = ['COOKIE', 'SAFECOOKIE', 'HASHEDPASSWORD'];
  tor.cfg.password = 'fallback-pass';
  tor.cfg.cookieFile = path.join(TMP, 'no-such-cookie');
  assert.strictEqual(await attempt('fallback-pass'), 'HASHEDPASSWORD');
});

test('an unreadable cookie file says the daemon\'s user needs the debian-tor group', async () => {
  if (process.platform === 'win32') throw new Skip('POSIX file modes');
  if (IS_ROOT) throw new Skip('running as root, so a mode 000 file is still readable (CI runs this as a normal user)');
  const cookie = crypto.randomBytes(32);
  const file = cookieFile('locked-cookie', cookie);
  fs.chmodSync(file, 0o000);
  await mockTor({ methods: ['COOKIE', 'SAFECOOKIE'], cookie, cookieFile: file }, PORT.locked);
  const ctl = track(await tcp(PORT.locked));
  await assert.rejects(tc.authenticate(ctl), (e) => {
    assert(/could not be read \(EACCES\)/.test(e.message), e.message);
    assert(/debian-tor group/.test(e.message), 'says how to fix it on Debian');
    return true;
  });
});

/* ------------------------------------------------------------ ADD_ONION */

test('ADD_ONION NEW returns a key and a ServiceID; the same key gives the same ServiceID', async () => {
  const tor = await mockTor({ methods: ['NULL'] }, PORT.onion);
  const ctl = track(await tcp(PORT.onion));
  await tc.authenticate(ctl);
  const first = await tc.addOnion(ctl, { key: null, virtPort: 8788, target: '127.0.0.1:8788' });
  assert.strictEqual(tor.lines[2], 'ADD_ONION NEW:ED25519-V3 Port=8788,127.0.0.1:8788');
  assert(!/Flags=|Detach/.test(tor.lines[2]), 'no Detach: the service ends with the connection');
  assert(/^[a-z2-7]{56}$/.test(first.serviceId), first.serviceId);
  assert(tc.isOnionKey(first.key), 'a new ED25519-V3 key came back');
  assert.deepStrictEqual(tor.onions.get(first.serviceId), { virtPort: 8788, target: '127.0.0.1:8788' });
  ctl.close();
  await until(() => tor.onions.size === 0, 2000, 'Tor to drop the service with the connection');

  const ctl2 = track(await tcp(PORT.onion));
  await tc.authenticate(ctl2);
  const again = await tc.addOnion(ctl2, { key: first.key, virtPort: 8788, target: '127.0.0.1:8788' });
  assert.strictEqual(again.serviceId, first.serviceId);
  assert.strictEqual(again.key, first.key);
  assert.strictEqual(tor.adds[1].line, `ADD_ONION ${first.key} Port=8788,127.0.0.1:8788`);
  assert.strictEqual(tor.adds[1].isNew, false);
  ctl2.close();
});

test('ADD_ONION input is validated before anything is sent; a bad ServiceID is refused', async () => {
  const tor = await mockTor({
    methods: ['NULL'],
    custom: (line) => (line.includes('Port=9999,') ? '250-ServiceID=NOT-A-V3-ID\r\n250 OK\r\n' : undefined),
  }, PORT.validate);
  const ctl = track(await tcp(PORT.validate));
  await tc.authenticate(ctl);
  const good = newKey();
  const badKeys = [
    'ED25519-V3:abc',
    good + '\r\nSIGNAL HALT',
    good + ' Flags=Detach',
    good.slice(0, 30) + ' ' + good.slice(31),
    'RSA1024:' + good.slice('ED25519-V3:'.length),
    good.slice(0, -3) + 'B==',                       // not canonical base64 for 64 bytes
    'NEW:ED25519-V3',
  ];
  for (const key of badKeys) await assert.rejects(tc.addOnion(ctl, { key, virtPort: 8788, target: '127.0.0.1:8788' }), TypeError, JSON.stringify(key));
  for (const virtPort of [0, 70000, '8788', 1.5]) await assert.rejects(tc.addOnion(ctl, { virtPort, target: '127.0.0.1:8788' }), TypeError);
  for (const target of ['127.0.0.1:8788\r\nSIGNAL HALT', '127.0.0.1 8788', '127.0.0.1:8788,9', 'example.com:8788', '999.0.0.1:1', '127.0.0.1:0', undefined]) {
    await assert.rejects(tc.addOnion(ctl, { virtPort: 8788, target }), TypeError, String(target));
  }
  await assert.rejects(ctl.command('GETINFO version\r\nSIGNAL HALT'), TypeError);
  assert.deepStrictEqual(tor.verbs(), ['PROTOCOLINFO', 'AUTHENTICATE'], 'none of that reached Tor');

  for (const target of ['8788', 8788, 'localhost:8788', '[::1]:8788', 'unix:/run/nodesignal/peer.sock']) {
    const r = await tc.addOnion(ctl, { virtPort: 8788, target });
    assert(/^[a-z2-7]{56}$/.test(r.serviceId));
  }
  await assert.rejects(tc.addOnion(ctl, { virtPort: 9999, target: '127.0.0.1:8788' }), /did not return a valid v3 ServiceID/);
  ctl.close();
});

/* ------------------------------------------------------- reply parsing */

test('multi-line and data-block replies parse, with 650 events interleaved and replies dribbled', async () => {
  const tor = await mockTor({
    methods: ['NULL'], events: true, dribble: true,
    custom: (line, { send, sock }) => {
      if (line === 'GETINFO version config-text net/listeners/socks') {
        send('250-version=0.4.8.13\r\n250+config-text=\r\nSocksPort 9050\r\n..dot-stuffed line\r\n\r\n.\r\n250-net/listeners/socks="127.0.0.1:9050"\r\n250 OK\r\n')
          .then(() => sleep(20))
          .then(() => { if (!sock.destroyed) sock.write('650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED\r\n'); });
        return null;
      }
      if (line === 'GETINFO nope') return '552 Unrecognized key "nope"\r\n';
      return undefined;
    },
  }, PORT.parse);
  const ctl = track(await tcp(PORT.parse));
  const r = await ctl.command('GETINFO version config-text net/listeners/socks');
  assert.deepStrictEqual(r, {
    code: 250,
    lines: ['version=0.4.8.13', 'config-text=', 'net/listeners/socks="127.0.0.1:9050"', 'OK'],
    data: ['SocksPort 9050\n.dot-stuffed line\n'],
  });
  await sleep(60);                                // an event arrives while nothing is pending
  const e = await ctl.command('GETINFO nope');
  assert.deepStrictEqual(e, { code: 552, lines: ['Unrecognized key "nope"'], data: [] }, 'an error reply resolves; the caller reads the code');
  // Commands queued together are answered in order.
  const [a, b, c] = await Promise.all([ctl.command('GETINFO nope'), ctl.command('PROTOCOLINFO 1'), ctl.command('GETINFO nope')]);
  assert.deepStrictEqual([a.code, b.code, c.code], [552, 250, 552]);
  assert(b.lines.some((l) => l.startsWith('AUTH METHODS=NULL')));
  assert.strictEqual(await tc.authenticate(ctl), 'NULL');
  assert(!ctl.closed);
  ctl.close();
  assert.deepStrictEqual(tc.parseKeyValues(' METHODS=COOKIE,SAFECOOKIE COOKIEFILE="C:\\\\Tor\\\\cookie \\"x\\"\\303\\251\\x41" word'),
    Object.assign(Object.create(null), { METHODS: 'COOKIE,SAFECOOKIE', COOKIEFILE: 'C:\\Tor\\cookie "x"\u00e9A' }));
  assert.strictEqual(tc.quoteString('a"b\\c'), '"a\\"b\\\\c"');
});

test('an oversize reply (over 64 KiB) destroys the connection and rejects', async () => {
  const line = '250-' + 'x'.repeat(1000) + '\r\n';
  const tor = await mockTor({
    methods: ['NULL'],
    custom: (l, { sock }) => {
      if (l === 'GETINFO huge') { for (let i = 0; i < 70; i++) sock.write(line); return null; }
      if (l === 'GETINFO endless') { sock.write('250 ' + 'y'.repeat(70 * 1024)); return null; }
      return undefined;
    },
  }, PORT.big);
  for (const cmd of ['GETINFO huge', 'GETINFO endless']) {
    const ctl = track(await tcp(PORT.big));
    let closedWith = null;
    ctl.onClose((err) => { closedWith = err; });
    await assert.rejects(ctl.command(cmd), /reply larger than 64 KiB; connection closed/);
    assert(ctl.closed, 'controller closed');
    assert(closedWith && /64 KiB/.test(closedWith.message), 'onClose told why');
    await assert.rejects(ctl.command('GETINFO version'), /64 KiB/);
  }
  await until(() => tor.conns.size === 0, 2000, 'the server to see both connections closed');
});

test('timeouts, connection failures and a server that is not Tor', async () => {
  const tor = await mockTor({ methods: ['NULL'], custom: (l) => (l === 'GETINFO silent' ? null : undefined) }, PORT.silent);
  const ctl = track(await tcp(PORT.silent, { timeoutMs: 300 }));
  const t0 = Date.now();
  await assert.rejects(ctl.command('GETINFO silent'), /no reply to GETINFO from the Tor control port at 127\.0\.0\.1:\d+ within 300 ms/);
  assert(Date.now() - t0 < 2000);
  assert(ctl.closed, 'a late reply would desynchronise the stream, so the connection is dropped');
  await until(() => tor.conns.size === 0, 2000, 'server to see the close');

  await assert.rejects(tc.connectControl({ host: HOST, port: PORT.dead }), /nothing is listening on the Tor control port 127\.0\.0\.1:\d+ \(ECONNREFUSED\)/);
  await assert.rejects(tc.connectControl({ path: path.join(TMP, 'no-such-socket') }), /no Tor control socket at .* \(ENOENT\)/);
  await assert.rejects(tc.connectControl({}), TypeError);
  await assert.rejects(tc.connectControl({ host: HOST, port: 0 }), TypeError);

  const http = net.createServer((s) => { s.on('error', () => { }); s.once('data', () => s.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')); });
  await new Promise((r) => http.listen(PORT.notTor, HOST, r));
  cleanup.push(() => http.close());
  const c2 = track(await tcp(PORT.notTor));
  await assert.rejects(tc.authenticate(c2), /not a control-protocol reply \(is this really Tor\?\)/);
});

/* --------------------------------------------------- startOnionService */

function recorder() {
  const r = { logs: [], ups: [], downs: [] };
  r.opts = { log: (s) => r.logs.push(s), onUp: (u) => r.ups.push(u), onDown: (m) => r.downs.push(m) };
  return r;
}

test('startOnionService: falls through dead candidates, reconnects after a drop with the same key, stops cleanly', async () => {
  const tor = await mockTor({ methods: ['NULL'] }, PORT.service);
  const rec = recorder();
  const svc = tc.startOnionService({
    candidates: [{ path: path.join(TMP, 'no-control-socket') }, { host: HOST, port: PORT.dead }, { host: HOST, port: PORT.service }],
    key: null, virtPort: 8788, target: '127.0.0.1:8788', retryMs: [40, 80], timeoutMs: 1000, ...rec.opts,
  });
  cleanup.push(() => svc.stop());
  await until(() => rec.ups.length === 1, 3000, 'the service to come up');
  const up = rec.ups[0];
  assert(/^[a-z2-7]{56}\.onion$/.test(up.onion), up.onion);
  assert(tc.isOnionKey(up.key), 'the new key is handed over for the caller to store');
  assert.deepStrictEqual(up.endpoint, { host: HOST, port: PORT.service });
  assert.strictEqual(tor.adds.length, 1);
  assert.strictEqual(tor.adds[0].isNew, true);
  assert.strictEqual(rec.downs.length, 0, 'dead candidates before a working one are not a failure');
  assert(rec.logs.some((l) => l.includes(up.onion) && l.includes(`127.0.0.1:${PORT.service}`)), 'logs the onion and the endpoint');

  tor.drop();                                     // Tor restarts, say
  await until(() => rec.downs.length === 1, 3000, 'onDown after the drop');
  assert(/lost the control connection/.test(rec.downs[0]), rec.downs[0]);
  await until(() => rec.ups.length === 2, 3000, 'the service to come back');
  assert.strictEqual(rec.ups[1].onion, up.onion, 'same address after reconnecting');
  assert.strictEqual(rec.ups[1].key, up.key);
  assert.strictEqual(tor.adds.length, 2);
  assert.strictEqual(tor.adds[1].isNew, false);
  assert.strictEqual(tor.adds[1].line, `ADD_ONION ${up.key} Port=8788,127.0.0.1:8788`);

  svc.stop();
  await until(() => tor.conns.size === 0 && tor.onions.size === 0, 2000, 'stop to close the connection (and so the service)');
  const accepted = tor.accepted;
  await sleep(250);
  assert.strictEqual(tor.accepted, accepted, 'no reconnect after stop');
  assert.strictEqual(rec.downs.length, 1, 'stop is not reported as a failure');
  assert.strictEqual(rec.ups.length, 2);
});

test('startOnionService: every candidate failing reports onDown and retries with backoff until Tor appears', async () => {
  const rec = recorder();
  const t0 = Date.now();
  const stamps = [];
  const svc = tc.startOnionService({
    candidates: [{ host: HOST, port: PORT.late }], virtPort: 8788, target: 8788, retryMs: [20, 60], timeoutMs: 1000,
    ...rec.opts, onDown: (m) => { rec.downs.push(m); stamps.push(Date.now() - t0); },
  });
  cleanup.push(() => svc.stop());
  await until(() => rec.downs.length >= 4, 3000, 'several failed rounds');
  assert(/^no Tor control port worked \(127\.0\.0\.1:\d+: nothing is listening/.test(rec.downs[0]), rec.downs[0]);
  const gaps = stamps.slice(1).map((s, i) => s - stamps[i]);
  assert(gaps[0] >= 15, 'first retry after retryMs[0]: ' + gaps);
  assert(gaps[1] >= 50 && gaps[2] >= 50, 'then the last delay repeats: ' + gaps);
  assert(rec.logs.some((l) => /retrying in 60ms/.test(l)));

  const tor = await mockTor({ methods: ['NULL'] }, PORT.late);
  await until(() => rec.ups.length === 1, 3000, 'the service once Tor is up');
  assert.strictEqual(tor.adds[0].line, 'ADD_ONION NEW:ED25519-V3 Port=8788,8788');
  svc.stop();
  await until(() => tor.conns.size === 0, 2000, 'stop to close the connection');
});

test('the onion key and the control password never reach log or onDown', async () => {
  const pw = 'correct horse "battery" staple';
  let failNextReAdd = true;
  const tor = await mockTor({
    methods: ['HASHEDPASSWORD'], password: pw,
    custom: (line) => {
      // A re-add whose error reply echoes the key back (a hostile or buggy server).
      if (line.startsWith('ADD_ONION ED25519-V3:') && failNextReAdd) {
        failNextReAdd = false;
        return `550 Onion address collision for ${line.split(' ')[1]}\r\n`;
      }
      return undefined;
    },
  }, PORT.secrets);
  const rec = recorder();
  const svc = tc.startOnionService({
    candidates: [{ host: HOST, port: PORT.secrets }], password: pw, virtPort: 8788, target: '127.0.0.1:8788',
    retryMs: [30], timeoutMs: 1000, ...rec.opts,
  });
  cleanup.push(() => svc.stop());
  await until(() => rec.ups.length === 1, 3000, 'first up');
  const key = rec.ups[0].key;
  tor.drop();
  await until(() => rec.ups.length === 2, 3000, 'up again after the echoing refusal');
  assert.strictEqual(rec.ups[1].onion, rec.ups[0].onion);
  assert(rec.downs.length >= 2, 'the drop and the refused re-add were both reported');
  assert(rec.downs.some((d) => /refused to add the onion service \(ADD_ONION\): 550 \(Tor's reply text withheld: it repeated a secret\)/.test(d)), rec.downs.join('\n'));
  const blob = key.slice('ED25519-V3:'.length);
  const said = rec.logs.concat(rec.downs).join('\n');
  for (const secret of [blob, blob.replace(/=+$/, ''), blob.slice(0, 43), blob.slice(43), pw]) {
    assert(!said.includes(secret), 'a secret reached log/onDown');
  }
  assert(said.includes(rec.ups[0].onion), 'the onion address itself may be logged');
  svc.stop();

  // Also when the caller passes a malformed key: refused up front, key not echoed.
  const badKey = 'ED25519-V3:' + 'A'.repeat(80) + ' x';
  assert.throws(() => tc.startOnionService({ candidates: [{ port: PORT.secrets }], key: badKey, virtPort: 8788, target: 8788 }),
    (e) => e instanceof TypeError && !e.message.includes('AAAA'));
});

test('no em dashes in torcontrol sources', () => {
  for (const f of ['torcontrol.js', 'tests/torcontrol.test.js']) {
    assert(!fs.readFileSync(path.join(__dirname, '..', f), 'utf8').includes(String.fromCharCode(0x2014)), f);
  }
});

/* ------------------------------------------------------------ runner */

(async () => {
  const t0 = Date.now();
  for (const { name, fn } of tests) {
    try {
      await Promise.race([fn(), sleep(10000).then(() => { throw new Error('test timed out'); })]);
      console.log('  ok   ' + name);
    } catch (e) {
      if (e instanceof Skip) { skipped++; console.log(`  skip ${name}: ${e.message}`); }
      else {
        failed++;
        console.log('  FAIL ' + name + '\n       ' + String(e && e.message).split('\n').join('\n       '));
      }
    }
    for (const c of cleanup.splice(0)) { try { await c(); } catch { } }
  }
  fs.rmSync(TMP, { recursive: true, force: true });
  console.log(failed ? `\n${failed} failed` : `\nall passed (${((Date.now() - t0) / 1000).toFixed(1)}s${skipped ? `, ${skipped} skipped` : ''})`);
  process.exit(failed ? 1 : 0);
})();
