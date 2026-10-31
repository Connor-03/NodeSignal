// qr.test.js: the QR code encoder and SVG renderer (qr.js). Plain node.
//   node tests/qr.test.js
// The reference symbols in tests/fixtures/qr-vectors.json were made outside
// the repo with python-qrcode and cross-checked against ZXing; its "about"
// lines say how. Neither tool is a dependency: this file needs only node.
//
// Masks. Any of the eight masks gives a valid symbol (a scanner reads the mask
// from the format information), and encoders differ in how they score them.
// So each case is checked twice:
//   1. qr.js forced to the reference's own mask ("mask") must give the
//      reference's matrix exactly. This checks everything except mask choice.
//   2. qr.js left to choose must pick what the four ISO/IEC 18004 penalty
//      rules give on the finished symbol. The test scores all eight masks
//      itself with the independent implementation below, and the answer must
//      also equal ZXing's own choice ("ruleMask", with "ruleSha256" the hash
//      of ZXing's symbol). python-qrcode scores a symbol whose format and
//      version areas and dark module are still light, and only counts
//      1:1:3:1:1 patterns wholly inside the symbol, which is why its "mask"
//      differs in 6 of the 13 cases.
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const assert = require('assert');
const qr = require('../qr.js');

const V = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'qr-vectors.json'), 'utf8'));
let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n')[0]); }
};
const LEVELS = ['L', 'M', 'Q', 'H'];
const sha = (rows) => crypto.createHash('sha256').update(rows.join('\n')).digest('hex');
const fill = (n) => Array.from({ length: n }, (_, i) => V.fill[i % V.fill.length]).join('');

function sameMatrix(got, want, label) {
  assert.strictEqual(got.length, want.length, `${label}: ${got.length} rows, expected ${want.length}`);
  for (let y = 0; y < want.length; y++) {
    if (got[y] === want[y]) continue;
    let x = 0;
    while (got[y][x] === want[y][x]) x++;
    assert.fail(`${label}: first difference at row ${y}, column ${x}`);
  }
}

// The four penalty rules, written apart from qr.js (strings and regular
// expressions rather than typed arrays), scored on the finished symbol:
//   N1 each run of 5 + i same-coloured modules in a row or column: 3 + i
//   N2 each 2x2 block of one colour: 3
//   N3 each 1011101 in a row or column with 0000 right before or right after
//      it, the quiet zone outside the symbol counting as light: 40
//   N4 10 for each whole 5% the dark share is away from 50%
function penaltyOf(rows) {
  const n = rows.length;
  const cols = Array.from({ length: n }, (_, x) => rows.map((r) => r[x]).join(''));
  let score = 0, dark = 0;
  for (const line of rows.concat(cols)) {
    for (const run of line.match(/0{5,}|1{5,}/g) || []) score += 3 + (run.length - 5);
    const q = '0000' + line + '0000';
    for (let i = q.indexOf('1011101'); i >= 0; i = q.indexOf('1011101', i + 1)) {
      if (q.slice(i - 4, i) === '0000' || q.slice(i + 7, i + 11) === '0000') score += 40;
    }
  }
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (rows[y][x] === '1') dark++;
      if (y + 1 < n && x + 1 < n) {
        const c = rows[y][x];
        if (rows[y][x + 1] === c && rows[y + 1][x] === c && rows[y + 1][x + 1] === c) score += 3;
      }
    }
  }
  const total = n * n;
  return score + 10 * Math.floor(Math.abs(2 * dark - total) * 10 / total);
}
function ruleMask(text, ecc) {
  const scores = [];
  for (let m = 0; m < 8; m++) scores.push(penaltyOf(qr.encode(text, { ecc, mask: m }).modules));
  return scores.indexOf(Math.min(...scores)); // lowest score, lowest mask number on a tie
}

console.log('fixture');
t(`the fixture covers what it must (${V.cases.length} cases)`, () => {
  assert(V.cases.length >= 8);
  for (const l of LEVELS) assert(V.cases.some((c) => c.ecc === l), 'a case at level ' + l);
  assert(new Set(V.cases.map((c) => c.mask)).size >= 4, 'several reference masks');
  assert(V.cases.some((c) => c.version >= 7), 'a version with version information');
  assert(V.cases.some((c) => /[^\x00-\x7f]/.test(c.text) && c.bytes > c.text.length), 'a case with multi-byte UTF-8');
  assert(V.cases.some((c) => c.text.startsWith('nodesignal:') && c.bytes >= 110 && c.bytes <= 140), 'a realistic link');
  assert(V.cases.some((c) => c.bytes >= 210), 'a long link');
  for (const c of V.cases) assert.strictEqual(Buffer.byteLength(c.text, 'utf8'), c.bytes, c.name);
  assert.strictEqual(V.sweep.length, 160, 'every version at every level');
});

console.log('reference matrices (the reference mask forced)');
for (const c of V.cases) {
  t(`${c.name}: ${c.bytes} bytes, version ${c.version}-${c.ecc}, mask ${c.mask}`, () => {
    const r = qr.encode(c.text, { ecc: c.ecc, mask: c.mask });
    assert.strictEqual(r.version, c.version, 'version');
    assert.strictEqual(r.ecc, c.ecc);
    assert.strictEqual(r.mask, c.mask);
    assert.strictEqual(r.size, c.version * 4 + 17);
    sameMatrix(r.modules, c.modules, c.name);
  });
}

console.log('automatic mask = the penalty rules = ZXing');
for (const c of V.cases) {
  const note = c.ruleMask === c.mask ? 'same as python-qrcode' : `python-qrcode picks ${c.mask}`;
  t(`${c.name}: mask ${c.ruleMask} (${note})`, () => {
    const r = qr.encode(c.text, { ecc: c.ecc });
    assert.strictEqual(r.version, c.version, 'version');
    assert.strictEqual(ruleMask(c.text, c.ecc), c.ruleMask, 'this file\'s penalty scoring disagrees with ZXing');
    assert.strictEqual(r.mask, c.ruleMask, 'automatic mask');
    assert.strictEqual(sha(r.modules), c.ruleSha256, 'the symbol differs from ZXing\'s');
    if (c.ruleMask === c.mask) sameMatrix(r.modules, c.modules, c.name);
  });
}

console.log('every version at every level, filled to capacity');
for (const l of LEVELS) {
  t(`level ${l}: versions 1 to 40 match the reference, forced and automatic`, () => {
    for (const s of V.sweep.filter((x) => x.ecc === l)) {
      const text = fill(s.bytes), at = `${l} version ${s.version}`;
      const forced = qr.encode(text, { ecc: l, mask: s.mask });
      assert.strictEqual(forced.version, s.version, at + ': version');
      assert.strictEqual(sha(forced.modules), s.sha256, at + ': matrix with the reference mask');
      const auto = qr.encode(text, { ecc: l });
      assert.strictEqual(auto.mask, s.ruleMask, at + ': automatic mask');
      assert.strictEqual(sha(auto.modules), s.ruleSha256 || s.sha256, at + ': automatic matrix');
    }
  });
}

console.log('capacity and version selection');
t('capacity(version, level) matches the reference table, and the ISO corner values', () => {
  for (const l of LEVELS) for (let v = 1; v <= 40; v++) assert.strictEqual(qr.capacity(v, l), V.capacity[l][v - 1], `${l} version ${v}`);
  assert.deepStrictEqual(LEVELS.map((l) => qr.capacity(1, l)), [17, 14, 11, 7]);
  assert.deepStrictEqual(LEVELS.map((l) => qr.capacity(40, l)), [2953, 2331, 1663, 1273]);
  assert.throws(() => qr.capacity(0, 'M'), RangeError);
  assert.throws(() => qr.capacity(41, 'M'), RangeError);
});
t('one byte past a version\'s capacity moves to the next version (all 156 boundaries)', () => {
  for (const l of LEVELS) {
    for (let v = 1; v < 40; v++) {
      const cap = qr.capacity(v, l);
      assert.strictEqual(qr.encode(fill(cap), { ecc: l, mask: 0 }).version, v, `${l}: ${cap} bytes`);
      assert.strictEqual(qr.encode(fill(cap + 1), { ecc: l, mask: 0 }).version, v + 1, `${l}: ${cap + 1} bytes`);
    }
  }
});
t('capacity counts UTF-8 bytes, not characters', () => {
  assert.strictEqual(qr.capacity(1, 'M'), 14);
  assert.strictEqual(qr.encode('é'.repeat(7), { ecc: 'M' }).version, 1); // 14 bytes
  assert.strictEqual(qr.encode('é'.repeat(7) + 'a', { ecc: 'M' }).version, 2); // 15 bytes
  assert.strictEqual(qr.encode('\u{1F680}'.repeat(3) + 'ab', { ecc: 'M' }).version, 1); // 14 bytes
  assert.strictEqual(qr.encode('\u{1F680}'.repeat(4), { ecc: 'M' }).version, 2); // 16 bytes
});
t('the default level is M; lowercase levels are accepted; an empty text fits version 1', () => {
  const text = V.cases.find((c) => c.ecc === 'M').text;
  assert.deepStrictEqual(qr.encode(text), qr.encode(text, { ecc: 'M' }));
  assert.deepStrictEqual(qr.encode(text, { ecc: 'm' }), qr.encode(text, { ecc: 'M' }));
  const e = qr.encode('');
  assert.strictEqual(e.version, 1);
  assert.strictEqual(e.size, 21);
});

console.log('errors');
t('text too long for version 40 throws a clear RangeError', () => {
  assert.strictEqual(qr.encode('a'.repeat(2953), { ecc: 'L', mask: 0 }).version, 40);
  assert.strictEqual(qr.encode('a'.repeat(1273), { ecc: 'H', mask: 0 }).version, 40);
  assert.throws(() => qr.encode('a'.repeat(2954), { ecc: 'L' }), (e) => e instanceof RangeError && /too long/.test(e.message) && /2954 bytes/.test(e.message) && /2953/.test(e.message));
  assert.throws(() => qr.encode('a'.repeat(1274), { ecc: 'H' }), (e) => e instanceof RangeError && /1274 bytes/.test(e.message) && /1273/.test(e.message));
  assert.throws(() => qr.encode('€'.repeat(778)), (e) => e instanceof RangeError && /2334 bytes/.test(e.message) && /2331/.test(e.message));
});
t('bad arguments throw', () => {
  assert.throws(() => qr.encode(42), TypeError);
  assert.throws(() => qr.encode(Buffer.from('x')), TypeError);
  for (const ecc of ['X', '', 'LM', null, 1]) assert.throws(() => qr.encode('x', { ecc }), RangeError, String(ecc));
  for (const mask of [-1, 8, 1.5, '1', null]) assert.throws(() => qr.encode('x', { mask }), RangeError, String(mask));
});

console.log('symbol structure, read back');
// Independent of the fixtures: the format and version information read back
// from the matrix must name the level, mask and version, and both copies agree.
function bch(value, gen, bits) {
  let rem = value << bits;
  const top = 31 - Math.clz32(gen);
  for (let i = 31 - Math.clz32(rem); i >= top; i--) if ((rem >>> i) & 1) rem ^= gen << (i - top);
  return (value << bits) | rem;
}
t('format and version information name the level, mask and version (both copies)', () => {
  const LEVEL_BITS = { L: 1, M: 0, Q: 3, H: 2 };
  for (const c of V.cases) {
    const r = qr.encode(c.text, { ecc: c.ecc }), m = r.modules, n = r.size, bit = (x, y) => Number(m[y][x]);
    const want = bch((LEVEL_BITS[c.ecc] << 3) | r.mask, 0x537, 10) ^ 0x5412;
    let a = 0, b = 0; // bit i of the format word, from the spec's placement
    const first = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
    first.forEach(([x, y], i) => { a |= bit(x, y) << i; });
    for (let i = 0; i < 8; i++) b |= bit(n - 1 - i, 8) << i;
    for (let i = 8; i < 15; i++) b |= bit(8, n - 15 + i) << i;
    assert.strictEqual(a, want, c.name + ': format information, first copy');
    assert.strictEqual(b, want, c.name + ': format information, second copy');
    assert.strictEqual(bit(8, n - 8), 1, c.name + ': dark module');
    if (r.version >= 7) {
      const vw = bch(r.version, 0x1f25, 12);
      let tr = 0, bl = 0;
      for (let i = 0; i < 18; i++) {
        tr |= bit(n - 11 + (i % 3), Math.floor(i / 3)) << i;
        bl |= bit(Math.floor(i / 3), n - 11 + (i % 3)) << i;
      }
      assert.strictEqual(tr, vw, c.name + ': version information, top right');
      assert.strictEqual(bl, vw, c.name + ': version information, bottom left');
    }
    for (const [ox, oy] of [[0, 0], [n - 7, 0], [0, n - 7]]) {
      for (let y = 0; y < 7; y++) {
        for (let x = 0; x < 7; x++) {
          const d = Math.max(Math.abs(x - 3), Math.abs(y - 3));
          assert.strictEqual(bit(ox + x, oy + y), d === 2 ? 0 : 1, `${c.name}: finder at ${ox},${oy}`);
        }
      }
    }
    for (let i = 8; i < n - 8; i++) {
      assert.strictEqual(bit(i, 6), i % 2 ? 0 : 1, c.name + ': horizontal timing');
      assert.strictEqual(bit(6, i), i % 2 ? 0 : 1, c.name + ': vertical timing');
    }
  }
});

console.log('toSvg');
const SAFE = /^[A-Za-z0-9 <>/="#.:-]*$/;
// Loose parse: the whole string is a run of tags with quoted attributes, the
// tags nest properly, and nothing else (no text, entities or comments).
function parseSvg(svg) {
  const tags = [], stack = [];
  const re = /<(\/?)([a-z]+)((?:\s+[a-zA-Z:-]+="[^"<>&]*")*)\s*(\/?)>/gy;
  let m, end = 0;
  while ((m = re.exec(svg))) {
    end = re.lastIndex;
    const [, close, name, attrText, selfClose] = m;
    const attrs = {};
    for (const a of attrText.matchAll(/([a-zA-Z:-]+)="([^"]*)"/g)) {
      assert(!(a[1] in attrs), 'duplicate attribute ' + a[1]);
      attrs[a[1]] = a[2];
    }
    if (close) assert.strictEqual(stack.pop(), name, 'mismatched </' + name + '>');
    else { tags.push({ name, attrs, depth: stack.length }); if (!selfClose) stack.push(name); }
  }
  assert.strictEqual(end, svg.length, 'unparsed text at ' + end + ': ' + svg.slice(end, end + 30));
  assert.strictEqual(stack.length, 0, 'unclosed <' + stack.join('>, <') + '>');
  return tags;
}
// Rebuild the dark modules from the path and check every subpath is one
// maximal horizontal run.
function pathModules(d, size, margin) {
  const rows = Array.from({ length: size }, () => Array(size).fill('0'));
  const re = /M(\d+) (\d+)h(\d+)v1h-(\d+)z/y;
  let m, end = 0;
  while ((m = re.exec(d))) {
    end = re.lastIndex;
    const x = +m[1] - margin, y = +m[2] - margin, w = +m[3];
    assert.strictEqual(+m[4], w, 'subpath closes back to its start');
    assert(y >= 0 && y < size && x >= 0 && x + w <= size && w > 0, 'subpath inside the symbol');
    assert(x === 0 || rows[y][x - 1] === '0', 'runs are merged: subpath touches the previous one');
    for (let i = x; i < x + w; i++) { assert.strictEqual(rows[y][i], '0', 'overlapping subpaths'); rows[y][i] = '1'; }
  }
  assert.strictEqual(end, d.length, 'unparsed path data at ' + end);
  return rows.map((r) => r.join(''));
}
t('the SVG is well formed: svg > rect + path, viewBox in modules, crispEdges', () => {
  for (const c of V.cases) {
    const r = qr.encode(c.text, { ecc: c.ecc });
    for (const margin of [4, 0, 2]) {
      const svg = margin === 4 ? qr.toSvg(r) : qr.toSvg(r, { margin });
      const tags = parseSvg(svg), n = r.size + 2 * margin;
      assert.deepStrictEqual(tags.map((x) => x.name + x.depth), ['svg0', 'rect1', 'path1']);
      assert.strictEqual(tags[0].attrs.xmlns, 'http://www.w3.org/2000/svg');
      assert.strictEqual(tags[0].attrs.viewBox, `0 0 ${n} ${n}`);
      assert.deepStrictEqual(tags[1].attrs, { width: String(n), height: String(n), fill: '#fff' });
      assert.strictEqual(tags[2].attrs.fill, '#000');
      assert.strictEqual(tags[2].attrs['shape-rendering'], 'crispEdges');
      sameMatrix(pathModules(tags[2].attrs.d, r.size, margin), r.modules, c.name + ' path');
      assert(SAFE.test(svg), 'characters outside the safe set');
    }
  }
});
t('colours: hex colours are used as given, anything else throws', () => {
  const r = qr.encode('nodesignal:test', { ecc: 'L' });
  for (const [dark, light] of [['#1a2b3c', '#FFF'], ['#ABC', '#fffe'], ['#1a2b3c80', '#00000000']]) {
    const svg = qr.toSvg(r, { dark, light }), tags = parseSvg(svg);
    assert.strictEqual(tags[1].attrs.fill, light);
    assert.strictEqual(tags[2].attrs.fill, dark);
    assert(SAFE.test(svg));
  }
  const bad = ['red"/><script>alert(1)</script>', 'red', '#12', '#12345', '#1234567', '#ggg', 'url(#x)', '#fff;', '#fff\n', ' #fff',
    '#fff"', "#fff'", '', 123, null, {}, ['#fff']];
  for (const c of bad) {
    assert.throws(() => qr.toSvg(r, { dark: c }), TypeError, 'dark ' + JSON.stringify(c));
    assert.throws(() => qr.toSvg(r, { light: c }), TypeError, 'light ' + JSON.stringify(c));
  }
});
t('margin and the qr argument are validated', () => {
  const r = qr.encode('nodesignal:test');
  for (const margin of [-1, 1.5, '4', 65, NaN, null]) assert.throws(() => qr.toSvg(r, { margin }), RangeError, String(margin));
  assert.strictEqual(parseSvg(qr.toSvg(r, { margin: 64 }))[0].attrs.viewBox, `0 0 ${r.size + 128} ${r.size + 128}`);
  for (const bad of [null, {}, { size: 21 }, { size: 22, modules: r.modules }, { size: r.size, modules: r.modules.slice(1) },
    { size: r.size, modules: r.modules.map((row, i) => (i === 3 ? row.slice(1) : row)) }]) {
    assert.throws(() => qr.toSvg(bad), TypeError);
  }
});
t('rows as Uint8Arrays (dark = 1) render the same as rows as strings', () => {
  const r = qr.encode(V.cases[0].text, { ecc: V.cases[0].ecc });
  const asBytes = { ...r, modules: r.modules.map((row) => Uint8Array.from(row, (ch) => (ch === '1' ? 1 : 0))) };
  assert.strictEqual(qr.toSvg(asBytes), qr.toSvg(r));
});
t('the SVG stays compact (one subpath per run, no per-module rects)', () => {
  const c = V.cases.find((x) => x.bytes >= 210);
  const svg = qr.toSvg(qr.encode(c.text, { ecc: c.ecc }));
  assert.strictEqual((svg.match(/<rect/g) || []).length, 1);
  assert.strictEqual((svg.match(/<path/g) || []).length, 1);
  assert(svg.length < 40 * 1024, svg.length + ' bytes');
});

console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
