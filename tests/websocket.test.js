// websocket.test.js: the RFC 6455 server in nodeps.js, driven byte by byte.
//   node tests/websocket.test.js        (plain node, any version, loopback only)
// An echo server built on nodeps.WSServer, in this process, on a free port.
// A misbehaving client must lose its own socket, never the server.
'use strict';
const http = require('http'), net = require('net');
const assert = require('assert');
const W = require('../nodeps.js');
const { sleep, until, wsFrame, wsConnect } = require('./harness.js');

let failed = 0, passed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e).toString().split('\n').slice(0, 3).join('\n       ')); }
};

const events = { messages: [], closes: 0 };
const server = http.createServer((req, res) => res.end('ok'));
const wss = new W.WSServer();
server.on('upgrade', (req, socket, head) => wss.handleUpgrade(req, socket, head, (ws) => {
  ws.on('message', (m) => { events.messages.push(m); ws.send(m); });   // echo: text as text, binary as binary
  ws.on('close', () => events.closes++);
  ws.on('error', () => { });
}));

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const PORT = server.address().port;
  const open = () => wsConnect(PORT, { path: '/' });
  const echo = async (w, opcode = 0x1) => w.next((f) => f.opcode === opcode);
  // after something nasty: the server still takes new clients and echoes
  const stillServing = async () => {
    const w = await open(); w.sendText('still here');
    assert.strictEqual((await echo(w)).payload.toString(), 'still here');
    w.close();
  };

  await t('upgrade: 101 with the right Sec-WebSocket-Accept; a bad request is refused', async () => {
    (await open()).close();                                   // wsConnect checks the accept key
    const status = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: PORT });
      s.on('connect', () => s.write('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'));
      let d = ''; s.on('data', (x) => (d += x)); s.on('close', () => resolve(d.split('\r\n')[0]));
    });
    assert.strictEqual(status, 'HTTP/1.1 400 Bad Request');
  });

  await t('length encodings: 7-bit, 16-bit (5 KB) and 64-bit (200 KB), both directions', async () => {
    const w = await open();
    for (const [n, code] of [[0, 0], [125, 125], [126, 126], [5 * 1024, 126], [65535, 126], [65536, 127], [200 * 1024, 127]]) {
      const text = 'x'.repeat(n);
      w.write(wsFrame(0x1, Buffer.from(text)));
      const f = await echo(w);
      assert.strictEqual(f.lenCode, code, `server header for ${n} bytes`);
      assert.strictEqual(f.masked, false, 'server frames are never masked');
      assert.strictEqual(f.payload.toString(), text, `${n} bytes intact`);
      assert.strictEqual(events.messages.at(-1), text);
    }
    w.close();
  });

  await t('masked frames are unmasked (every mask byte position, binary too)', async () => {
    const w = await open();
    const bin = Buffer.from(Array.from({ length: 1031 }, (_, i) => (i * 37) & 0xff));
    w.write(wsFrame(0x2, bin));
    const f = await echo(w, 0x2);
    assert(f.payload.equals(bin));
    assert(Buffer.isBuffer(events.messages.at(-1)));
    w.close();
  });

  await t('a 200 KB frame arriving in many small TCP writes is reassembled', async () => {
    const w = await open();
    const text = 'ab₿'.repeat(70000);
    const f = wsFrame(0x1, Buffer.from(text));
    for (let i = 0; i < f.length; i += 997) { w.write(f.subarray(i, i + 997)); if (i % 20000 < 997) await sleep(1); }
    assert.strictEqual((await echo(w)).payload.toString(), text);
    w.close();
  });

  await t('multi-byte UTF-8 split across fragments, with a ping between them', async () => {
    const w = await open();
    const text = 'fee ₿ 2.5 sat/vB, 𝄞 héllo, ノード';
    const b = Buffer.from(text, 'utf8');
    const cut1 = b.indexOf(Buffer.from('₿')) + 1, cut2 = b.indexOf(Buffer.from('𝄞')) + 2;   // inside a character, twice
    w.write(wsFrame(0x1, b.subarray(0, cut1), { fin: false }));
    w.write(wsFrame(0x9, Buffer.from('mid')));                    // control frames may interleave
    w.write(wsFrame(0x0, b.subarray(cut1, cut2), { fin: false }));
    await sleep(30);
    w.write(wsFrame(0x0, b.subarray(cut2), { fin: true }));
    const pong = await w.next((f) => f.opcode === 0xA);
    assert.strictEqual(pong.payload.toString(), 'mid');
    assert.strictEqual(events.messages.at(-1), text);
    assert.strictEqual((await echo(w)).payload.toString('utf8'), text);
    w.close();
  });

  await t('a ping gets a pong with the same payload', async () => {
    const w = await open();
    w.write(wsFrame(0x9, Buffer.from('are you alive')));
    const f = await w.next((x) => x.opcode === 0xA);
    assert.strictEqual(f.payload.toString(), 'are you alive');
    w.write(wsFrame(0x9));
    assert.strictEqual((await w.next((x) => x.opcode === 0xA)).payload.length, 0);
    w.close();
  });

  await t('a close frame is answered with a close frame, and close fires once', async () => {
    const before = events.closes;
    const w = await open();
    w.write(wsFrame(0x8, Buffer.from([0x03, 0xe8])));
    const f = await w.next((x) => x.opcode === 0x8, 2000);
    assert(f, 'close frame back');
    assert(await w.ended(), 'socket ended');
    await sleep(100);
    assert.strictEqual(events.closes - before, 1, 'close events');
  });

  await t('an unmasked client frame closes that socket, and nothing after it is read', async () => {
    const msgs = events.messages.length;
    const keep = await open();                               // a well-behaved neighbour
    const w = await open();
    w.write(Buffer.concat([wsFrame(0x1, Buffer.from('unmasked'), { mask: false }), wsFrame(0x1, Buffer.from('after'))]));
    assert(await w.ended(), 'the unmasked client is dropped');
    assert.strictEqual(events.messages.length, msgs, 'no message was accepted from it');
    keep.sendText('neighbour'); assert.strictEqual((await echo(keep)).payload.toString(), 'neighbour');
    keep.close();
    await stillServing();
  });

  await t('an oversize frame closes that socket, never the server', async () => {
    for (const len of [9 * 1024 * 1024, 2 ** 53]) {
      const w = await open();
      w.write(wsFrame(0x1, Buffer.alloc(16), { len }));     // claims far more than it sends
      assert(await w.ended(), `a ${len}-byte frame is refused`);
    }
    await stillServing();
  });

  await t('a message fragmented past the size cap closes that socket', async () => {
    const w = await open();
    const piece = Buffer.alloc(1024 * 1024, 0x61);
    w.write(wsFrame(0x1, piece, { fin: false }));
    for (let i = 0; i < 9 && !w.closed; i++) { w.write(wsFrame(0x0, piece, { fin: false })); await sleep(5); }
    assert(await w.ended(), 'endless continuation frames are refused');
    await stillServing();
  });

  await t('an unknown opcode closes that socket', async () => {
    const w = await open();
    w.write(wsFrame(0x3, Buffer.from('?')));
    assert(await w.ended());
    await stillServing();
  });

  await t('a client that vanishes mid-frame does not crash the server', async () => {
    const w = await open();
    w.write(wsFrame(0x1, Buffer.alloc(5000)).subarray(0, 1200));
    w.socket.destroy();
    await sleep(100);
    await stillServing();
  });

  server.close();
  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
