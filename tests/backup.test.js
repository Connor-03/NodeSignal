// backup.test.js: the passphrase-encrypted identity backup. Plain node.
//   node tests/backup.test.js
// A few seconds: each backup made or read at the real cost runs scrypt with
// N = 2^17. The damage tests use a cheap N = 2^14 backup built here
// independently from the documented format.
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const noise = require('../noise.js');
const backup = require('../backup.js');

let failed = 0, passed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e)); }
};
// assert.throws with a RegExp matches String(err), which starts with "Error: "
const WRONG = /^Error: wrong passphrase, or the backup is damaged$/;
const DAMAGED = /^Error: the backup is damaged or incomplete$/;
const NOT_BACKUP = /^Error: not a NodeSignal backup$/;
const BAD_KDF = /outside the safe range|unsupported key derivation/;
const PASS = 'correct horse battery staple';
const HEADER = 'NodeSignal identity backup v1';

/* The documented format, built without backup.js. */
function wrapText(doc) {
  const body = Buffer.from(JSON.stringify(doc)).toString('base64');
  return [HEADER, ...body.match(/.{1,76}/g)].join('\n') + '\n';
}
function referenceDoc(payload, passphrase, { N = 1 << 14, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16), nonce = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase.normalize('NFC'), salt, 32, { N, r, p, maxmem: 256 * 1024 * 1024 });
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(HEADER));
  const ct = Buffer.concat([c.update(JSON.stringify(payload)), c.final(), c.getAuthTag()]);
  return { v: 1, kdf: { name: 'scrypt', N, r, p, salt: salt.toString('base64') }, nonce: nonce.toString('base64'), ct: ct.toString('base64') };
}
const decodeDoc = (text) => JSON.parse(Buffer.from(text.split('\n').slice(1).join(''), 'base64').toString());
const flip = (b64, i = 0) => { const b = Buffer.from(b64, 'base64'); b[i] ^= 1; return b.toString('base64'); };
const ms = (fn) => { const s = process.hrtime.bigint(); try { fn(); } catch (e) { return [Number(process.hrtime.bigint() - s) / 1e6, e]; } return [Number(process.hrtime.bigint() - s) / 1e6, null]; };

(async () => {
  const identity = noise.newIdentity();
  const payload = { kind: 'nodesignal-identity', identity, nick: 'satoshi ✓', contacts: { 'deadbeef': { pinned: true, n: [1, 2, 3] } }, note: null };
  const text = backup.exportBackup(payload, PASS);

  await t('round trip at the real cost; the text has the documented shape', () => {
    assert.deepStrictEqual(backup.importBackup(text, PASS), payload);
    const lines = text.split('\n');
    assert.strictEqual(lines[0], HEADER, 'first line exactly');
    assert.strictEqual(lines[lines.length - 1], '', 'ends with a newline');
    for (const l of lines.slice(1, -1)) assert.match(l, /^[A-Za-z0-9+/=]{1,76}$/, 'base64 wrapped at 76');
    assert(lines.slice(1, -2).every((l) => l.length === 76), 'every line but the last is full');
    const doc = decodeDoc(text);
    assert.deepStrictEqual(Object.keys(doc).sort(), ['ct', 'kdf', 'nonce', 'v']);
    assert.deepStrictEqual({ ...doc.kdf, salt: undefined }, { name: 'scrypt', N: 1 << 17, r: 8, p: 1, salt: undefined });
    assert.strictEqual(Buffer.from(doc.kdf.salt, 'base64').length, 16);
    assert.strictEqual(Buffer.from(doc.nonce, 'base64').length, 12);
    assert(!text.includes(identity.priv) && !decodeDoc(text).ct.includes(identity.priv), 'no private key in the clear');
  });

  await t('a backup built independently from the documented format imports', () => {
    assert.deepStrictEqual(backup.importBackup(wrapText(referenceDoc(payload, PASS)), PASS), payload);
  });

  await t('two exports of the same payload differ (fresh salt and nonce)', () => {
    const a = decodeDoc(backup.exportBackup(1, 'eight chars')), b = decodeDoc(backup.exportBackup(1, 'eight chars'));
    assert.notStrictEqual(a.kdf.salt, b.kdf.salt);
    assert.notStrictEqual(a.nonce, b.nonce);
    assert.notStrictEqual(a.ct, b.ct);
  });

  const cheapDoc = referenceDoc(payload, PASS);
  const cheap = wrapText(cheapDoc);

  await t('wrong passphrase', () => {
    assert.throws(() => backup.importBackup(cheap, PASS + '!'), WRONG);
    assert.throws(() => backup.importBackup(cheap, 'Correct horse battery staple'), WRONG);
    assert.throws(() => backup.importBackup(cheap, 'short'), /at least 8 characters/);
    assert.throws(() => backup.importBackup(cheap, undefined), /at least 8 characters/);
  });

  await t('tampered ciphertext, nonce or salt is refused', () => {
    for (const i of [0, 10, Buffer.from(cheapDoc.ct, 'base64').length - 1]) {
      assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, ct: flip(cheapDoc.ct, i) }), PASS), WRONG, `ct byte ${i}`);
    }
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, nonce: flip(cheapDoc.nonce) }), PASS), WRONG, 'nonce');
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, kdf: { ...cheapDoc.kdf, salt: flip(cheapDoc.kdf.salt) } }), PASS), WRONG, 'salt');
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, ct: Buffer.from(cheapDoc.ct, 'base64').subarray(0, 15).toString('base64') }), PASS), DAMAGED, 'shorter than a tag');
    // a changed character in the text itself: refused, whatever it hits
    const lines = cheap.split('\n');
    for (let row = 1; row < lines.length - 1; row++) {
      const l = lines[row], col = Math.floor(l.length / 2), ch = l[col] === 'A' ? 'B' : 'A';
      const bad = [...lines.slice(0, row), l.slice(0, col) + ch + l.slice(col + 1), ...lines.slice(row + 1)].join('\n');
      assert.throws(() => backup.importBackup(bad, PASS), undefined, `line ${row}`);
    }
  });

  await t('truncated text is refused as damaged', () => {
    const lines = cheap.trimEnd().split('\n');
    const cuts = [
      lines.slice(0, -1).join('\n'),                       // the last line lost
      lines.slice(0, 2).join('\n'),                        // only the first line of base64
      cheap.trimEnd().slice(0, -1),                        // one character short
      cheap.slice(0, Math.floor(cheap.length / 2)),        // cut in half
      HEADER, HEADER + '\n\n',                             // the header alone
    ];
    for (const c of cuts) assert.throws(() => backup.importBackup(c, PASS), DAMAGED, JSON.stringify(c.slice(-20)));
    const noCt = { ...cheapDoc }; delete noCt.ct;
    assert.throws(() => backup.importBackup(wrapText(noCt), PASS), DAMAGED, 'a field missing');
    assert.throws(() => backup.importBackup(wrapText([1, 2]), PASS), DAMAGED, 'not an object');
  });

  await t('wrong header: not a NodeSignal backup; another version: unsupported', () => {
    const body = cheap.split('\n').slice(1).join('\n');
    for (const head of ['NodeSignal identity backup', 'NodeSignal identity backup v1 extra', 'nodesignal identity backup v1', '-----BEGIN PGP MESSAGE-----', '']) {
      assert.throws(() => backup.importBackup(head + '\n' + body, PASS), NOT_BACKUP, JSON.stringify(head));
    }
    assert.throws(() => backup.importBackup(body, PASS), NOT_BACKUP, 'no header at all');
    for (const v of ['', '   \r\n ', '{"v":1}']) assert.throws(() => backup.importBackup(v, PASS), NOT_BACKUP);
    for (const v of [null, undefined, 42, {}, ['x']]) assert.throws(() => backup.importBackup(v, PASS), NOT_BACKUP);
    assert.throws(() => backup.importBackup('NodeSignal identity backup v2\n' + body, PASS), /^Error: unsupported backup version v2; this build reads v1$/);
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, v: 2 }), PASS), /unsupported backup version v2/, 'v1 header, v2 inside');
    try { backup.importBackup('NodeSignal identity backup v9\n' + body, PASS); } catch (e) { assert.strictEqual(e.code, 'UNSUPPORTED_VERSION'); }
    try { backup.importBackup('hello', PASS); } catch (e) { assert.strictEqual(e.code, 'NOT_BACKUP'); }
  });

  await t('out-of-range KDF parameters are refused before any work (well under a second each)', () => {
    const cases = [
      { N: 1 << 30 }, { N: 1 << 21 }, { N: 1 << 13 }, { N: 3 << 15 }, { N: (1 << 17) + 0.5 }, { N: String(1 << 17) }, { N: -(1 << 17) }, { N: null },
      { r: 0 }, { r: 17 }, { r: 1.5 }, { r: '8' },
      { p: 0 }, { p: 5 }, { p: 1e9 },
      { N: 1 << 20, r: 16 },        // inside each single range, but 2 GiB of memory
      { N: 1 << 20, r: 4 },         // 512 MiB
      { N: 1 << 18, r: 8, p: 4 },   // 256 MiB but 8x the default work
      { name: 'argon2id' }, { name: undefined },
    ];
    for (const k of cases) {
      const doc = { ...cheapDoc, kdf: { ...cheapDoc.kdf, ...k } };
      const [took, e] = ms(() => backup.importBackup(wrapText(doc), PASS));
      assert(e, `accepted ${JSON.stringify(k)}`);
      assert.strictEqual(e.code, 'BAD_KDF', `${JSON.stringify(k)}: ${e.message}`);
      assert.match(e.message, BAD_KDF);
      assert(took < 200, `${JSON.stringify(k)} took ${took.toFixed(0)} ms`);
    }
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, kdf: 'scrypt' }), PASS), BAD_KDF);
    assert.throws(() => backup.importBackup(wrapText({ ...cheapDoc, kdf: undefined }), PASS), BAD_KDF);
    // the edges of the safe range are still accepted
    for (const k of [{ N: 1 << 14, r: 1 }, { N: 1 << 14, r: 16, p: 4 }]) {
      assert.deepStrictEqual(backup.importBackup(wrapText(referenceDoc({ ok: k }, PASS, k)), PASS), { ok: k });
    }
  });

  await t('CRLF line endings, a BOM, surrounding whitespace and other wrapping are tolerated', () => {
    const crlf = '﻿  \r\n\r\n' + text.replace(/\n/g, '\r\n') + '\r\n\r\n   ';
    assert.deepStrictEqual(backup.importBackup(crlf, PASS), payload);
    const body = cheap.split('\n').slice(1).join('');
    const rewrapped = HEADER + '\r\n' + body.match(/.{1,64}/g).map((l) => '  ' + l + ' ').join('\r\n');
    assert.deepStrictEqual(backup.importBackup(rewrapped, PASS), payload);
    assert.deepStrictEqual(backup.importBackup(Buffer.from(cheap.replace(/\n/g, '\r')), PASS), payload, 'old Mac CR, as a Buffer');
  });

  await t('export refuses a short passphrase and a payload that is not JSON', () => {
    for (const p of ['', 'seven77', 'ünïcödé', undefined, 12345678]) assert.throws(() => backup.exportBackup(payload, p), /at least 8 characters/, String(p));
    assert.throws(() => backup.exportBackup(payload, 'x'.repeat(1025)), /too long/);
    const loop = {}; loop.self = loop;
    for (const bad of [undefined, () => 1, Symbol('s'), { n: 1n }, loop]) assert.throws(() => backup.exportBackup(bad, PASS), /JSON-serialisable/);
  });

  await t('the passphrase is compared in NFC (composed and decomposed accents match)', () => {
    const doc = wrapText(referenceDoc({ x: 1 }, 'café au lait'));
    assert.deepStrictEqual(backup.importBackup(doc, 'café au lait'), { x: 1 });
  });

  await t('async variants interoperate with the blocking ones', async () => {
    const a = await backup.exportBackupAsync(payload, PASS);
    assert.deepStrictEqual(backup.importBackup(cheap, PASS), payload);
    assert.deepStrictEqual(await backup.importBackupAsync(a, PASS), payload);
    await assert.rejects(backup.importBackupAsync(cheap, PASS + '?'), WRONG);
    await assert.rejects(backup.importBackupAsync('nope', PASS), NOT_BACKUP);
    await assert.rejects(backup.exportBackupAsync(payload, 'short'), /at least 8/);
  });

  console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
