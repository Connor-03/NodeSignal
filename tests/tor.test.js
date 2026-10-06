// tor.test.js: delivery to a .onion contact through a SOCKS5 proxy (--tor-proxy).
//   node tests/tor.test.js     (Linux: uses 127.0.0.2 to 127.0.0.5 on loopback)
// A .onion name cannot be resolved by DNS, so the daemon must hand the name
// itself to the proxy (SOCKS5 CONNECT, address type 3 = domain name) and never
// look it up. The proxy here is a mock written with net: it records each
// request and relays a fake onion to a second real daemon on loopback, the way
// Tor relays to a hidden service. The onion names are fake.
// Ports 24731 to 24736.
'use strict';
const net = require('net'), fs = require('fs'), path = require('path');
const assert = require('assert');
const { p2pServer } = require('./mock-node.js');
const H = require('./harness.js');
const { sleep, until, up, ui, contactOf, sent, status } = H;
const S = H.suite('ns-tor-');
const { t } = S;

const onion = (c) => { const b = 'nodesignalfakeonion'; return b + c.repeat(56 - b.length) + '.onion'; };
const ONION = onion('a'), ONION_SPLIT = onion('b'), ONION_DOWN = onion('c');
const PROXY = 24735;

// A SOCKS5 proxy (RFC 1928, no auth) that parses every byte it is sent.
// routes: "host:port" -> { host, port, split } where to really connect;
// split writes the CONNECT reply in two TCP segments.
function socksProxy(port, routes) {
  const requests = [], greetings = [], conns = new Set();
  const srv = net.createServer((c) => {
    conns.add(c); c.on('close', () => conns.delete(c)); c.on('error', () => { });
    let buf = Buffer.alloc(0), stage = 0;
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]) return;
        greetings.push({ ver: buf[0], methods: [...buf.subarray(2, 2 + buf[1])] });
        buf = buf.subarray(2 + buf[1]); stage = 1;
        c.write(Buffer.from([0x05, 0x00]));
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        const atyp = buf[3];
        const alen = atyp === 3 ? 1 + buf[4] : atyp === 1 ? 4 : atyp === 4 ? 16 : 0;
        if (buf.length < 4 + alen + 2) return;
        const a = buf.subarray(4, 4 + alen);
        const host = atyp === 3 ? a.subarray(1).toString('latin1') : atyp === 1 ? [...a].join('.') : a.toString('hex');
        const dport = buf.readUInt16BE(4 + alen);
        requests.push({ ver: buf[0], cmd: buf[1], atyp, host, port: dport });
        const rest = buf.subarray(4 + alen + 2); stage = 2;
        c.removeListener('data', onData);
        const route = routes[`${host}:${dport}`];
        if (!route) { c.end(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); return; }   // host unreachable
        const up_ = net.connect({ host: route.host, port: route.port, localAddress: '127.0.0.5' });
        up_.on('error', () => c.destroy()); c.on('close', () => up_.destroy()); up_.on('close', () => c.destroy());
        up_.on('connect', async () => {
          const reply = Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 5, 0, 0]);
          if (route.split) { c.write(reply.subarray(0, 3)); await sleep(60); c.write(reply.subarray(3)); }
          else c.write(reply);
          if (rest.length) up_.write(rest);
          c.pipe(up_); up_.pipe(c);
        });
      }
    };
    c.on('data', onData);
  });
  srv.requests = requests; srv.greetings = greetings;
  srv.shut = () => new Promise((r) => { for (const c of conns) c.destroy(); srv.close(() => r()); });
  return new Promise((r) => srv.listen(port, '127.0.0.1', () => r(srv)));
}

(async () => {
  // Every DNS lookup the daemon makes is written to a file by a preload hook.
  const dnsLog = path.join(S.TMP, 'dns.log'), hook = path.join(S.TMP, 'dns-hook.js');
  fs.writeFileSync(dnsLog, '');
  fs.writeFileSync(hook, `'use strict';
const dns = require('dns'), fs = require('fs');
const rec = (h) => { try { fs.appendFileSync(${JSON.stringify(dnsLog)}, String(h) + '\\n'); } catch { } };
for (const api of [dns, dns.promises]) for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname']) {
  const orig = api[k]; if (typeof orig !== 'function') continue;
  api[k] = function (h, ...a) { rec(h); return orig.call(this, h, ...a); };
}
`);
  const p2p = await p2pServer({ port: 24736, host: '127.0.0.3', ua: '/Satoshi:29.2.0/Knots:20251110/' });
  // B is the hidden service. A's peer port listens on 127.0.0.4 only, so B
  // (which sees A arrive from the proxy's 127.0.0.5) cannot dial A back: its
  // reply can only travel over the circuit A opened.
  const B = await up(S.daemon('bravo', { host: '127.0.0.2', peer: 24731, web: 24732 }));
  const routes = {
    [ONION + ':8788']: { host: '127.0.0.2', port: 24731 },
    [ONION + ':8333']: { host: '127.0.0.3', port: 24736 },
    [ONION_SPLIT + ':8788']: { host: '127.0.0.2', port: 24731, split: true },
  };
  let proxy = await socksProxy(PROXY, routes);
  const A = await up(S.daemon('alpha', { host: '127.0.0.4', peer: 24733, web: 24734,
    extra: ['--tor-proxy', '127.0.0.1:' + PROXY], nodeArgs: ['--require', hook] }));
  const ua = await ui(A), ub = await ui(B);

  await t('the DNS hook sees ordinary lookups (so its silence about .onion means something)', async () => {
    ua.send({ type: 'identify', host: 'localhost', port: 9 });
    await ua.wait((m) => m.type === 'identified' && m.host === 'localhost');
    assert(fs.readFileSync(dnsLog, 'utf8').split('\n').includes('localhost'));
  });

  await t('adding a .onion contact identifies it over :8333 through the proxy', async () => {
    ua.send({ type: 'contact.add', host: ONION, port: 8788, nick: 'hidden' });
    const ev = await ua.wait((m) => m.type === 'contact' && m.contact.host === ONION && m.contact.peerInfo, 10000);
    assert.strictEqual(ev.contact.peerInfo.impl, 'Bitcoin Knots');
    assert(proxy.requests.some((r) => r.atyp === 3 && r.host === ONION && r.port === 8333));
  });

  await t('a message to a .onion contact is delivered through SOCKS5 CONNECT with the domain-name address type', async () => {
    const id = await sent(ua, ONION, 8788, 'hello through tor');
    await status(ua, id, 'delivered', 10000);
    const got = await ub.wait((m) => m.type === 'chat.recv' && m.msg.from === 'them' && m.msg.text === 'hello through tor');
    assert.strictEqual(got.host, '127.0.0.5', 'B sees the circuit, not A');
    const r = proxy.requests.find((x) => x.port === 8788);
    assert.deepStrictEqual(r, { ver: 5, cmd: 1, atyp: 3, host: ONION, port: 8788 });
    assert(proxy.greetings.every((g) => g.ver === 5 && g.methods.includes(0)), 'offers no-auth');
    assert(proxy.requests.every((x) => x.atyp === 3), 'never an IP address type');
    const k = contactOf(await ua.state(), ONION);
    assert(k.peerFp && k.established && k.proto === 3);
  });

  await t('their reply rides back over the circuit we opened', async () => {
    const before = proxy.requests.length;
    const id = await sent(ub, '127.0.0.5', 24733, 'reply over the onion circuit');
    const r = await ua.wait((m) => m.type === 'chat.recv' && m.host === ONION && m.msg.from === 'them', 5000);
    assert.strictEqual(r.msg.text, 'reply over the onion circuit');
    await status(ub, id, 'delivered');
    assert.strictEqual(proxy.requests.length, before, 'no new circuit was needed');
    assert(!contactOf(await ua.state(), '127.0.0.5'), 'A never saw the relay address');
  });

  await t('a CONNECT reply split across TCP segments is handled', async () => {
    const id = await sent(ua, ONION_SPLIT, 8788, 'split reply');
    await status(ua, id, 'delivered', 10000);
    await ub.wait((m) => m.type === 'chat.recv' && m.msg.text === 'split reply');
  });

  await t('a hidden service Tor cannot reach fails honestly, with the reason', async () => {
    const id = await sent(ua, ONION_DOWN, 8788, 'nobody home');
    const p = await status(ua, id, 'pending', 10000);
    assert.match(p.error, /Tor could not reach .*\.onion:8788 \(host unreachable\)/);
    ua.send({ type: 'chat.cancel', host: ONION_DOWN, id });
    await status(ua, id, 'failed');
  });

  await t('with no proxy running, the error says so (and still no DNS)', async () => {
    await proxy.shut(); proxy = null;
    await sleep(3000);                                      // let the earlier link hang up
    const id = await sent(ua, ONION, 8788, 'is tor running?');
    const p = await status(ua, id, 'pending', 10000);
    assert.match(p.error, /no SOCKS proxy at 127\.0\.0\.1:24735: is Tor running\?/);
    ua.send({ type: 'chat.cancel', host: ONION, id });
  });

  await t('the daemon never asked DNS for a .onion name', async () => {
    await sleep(200);
    const looked = fs.readFileSync(dnsLog, 'utf8').split('\n').filter(Boolean);
    assert.deepStrictEqual(looked.filter((h) => /\.onion\.?$/i.test(h)), []);
    assert(!/ENOTFOUND/.test(A.log), 'ENOTFOUND in the log');
  });

  ua.close(); ub.close();
  await S.finish(async () => { if (proxy) await proxy.shut(); p2p.close(); });
})().catch(S.abort);
