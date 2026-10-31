// qr.js: QR code encoder and SVG renderer for NodeSignal contact links
// ============================================================================
// The daemon turns a shareable contact link (nodesignal:<host>?port=..&fp=..
// &nick=..) into a QR code and hands the console a finished SVG string. The
// browser page only shows it: no encoding and no crypto happen in the page.
//
// Standard: ISO/IEC 18004 (QR Code Model 2), versions 1 to 40, ECC levels
// L, M, Q, H. Byte mode only, the text as UTF-8 with no ECI header (the ZXing
// and OpenCV decoders read the UTF-8 test cases correctly without one).
// Node.js standard library only.
//
// What it does, in the spec's order:
//   data      mode 0100, character count (8 bits for versions 1-9, 16 bits
//             for 10-40), the bytes, up to 4 terminator bits, zero bits to a
//             byte boundary, then pad bytes 0xEC 0x11 alternating
//   version   the smallest version that holds the bytes at the asked level
//   ECC       Reed-Solomon over GF(256), polynomial 0x11D, generator roots
//             a^0..a^(n-1); the per-version block split of ISO Table 9 (short
//             blocks first), data then ECC codewords interleaved by block,
//             remainder bits left light
//   layout    finder patterns with separators, timing patterns, alignment
//             patterns, the dark module, format information (BCH 15,5 with
//             generator 0x537, XOR mask 0x5412, both copies) and, from
//             version 7, version information (BCH 18,6 with generator 0x1F25)
//   masking   all eight masks are tried on the finished symbol (format and
//             version information included) and scored with the four penalty
//             rules; the lowest score wins, the lowest mask number on a tie
//
// The penalty rules, as applied here (the spec leaves two readings open; this
// is the reading of ZXing and its ports, and tests/qr.test.js checks it):
//   N1  a run of k >= 5 same-coloured modules in a row or column: 3 + (k - 5)
//   N2  every 2x2 block of one colour (overlapping blocks all count): 3
//   N3  every dark-light-dark-dark-dark-light-dark (1:1:3:1:1) run in a row or
//       column with 4 light modules directly before it or directly after it:
//       40, once per occurrence. Modules past the edge of the symbol count as
//       light, because the quiet zone there is light.
//   N4  10 points for every full 5% the dark share is away from 50%
// Some encoders score the symbol before the format information is drawn, or
// only find N3 patterns that lie wholly inside the symbol; they can pick a
// different mask. Any mask reads the same: scanners take the mask from the
// format information.
//
// API
//   encode(text, { ecc = 'M' })
//       -> { version, ecc, mask, size, modules }
//       text is a string, encoded as UTF-8. ecc is 'L', 'M', 'Q' or 'H'.
//       modules is an array of `size` strings, one per row from the top, each
//       `size` characters of '0' (light) and '1' (dark) from the left, with
//       no quiet zone: modules[y][x] === '1' means dark.
//       Throws a RangeError when the text does not fit in version 40.
//       (A `mask` option, 0 to 7, forces a mask. It exists for the tests;
//       leave it out.)
//   toSvg(qr, { margin = 4, dark = '#000', light = '#fff' })
//       -> a standalone SVG string: viewBox in module units, one rect for the
//       light background and one path for every dark module (one subpath per
//       horizontal run), shape-rendering="crispEdges". margin is the quiet
//       zone in modules (the spec asks for 4). Colours must be hex colours
//       (#rgb, #rgba, #rrggbb, #rrggbbaa); anything else throws, so a caller
//       can never inject markup through them.
//   capacity(version, ecc) -> how many bytes fit in that version at that level
'use strict';

const LEVELS = ['L', 'M', 'Q', 'H'];
const FORMAT_LEVEL_BITS = { L: 1, M: 0, Q: 3, H: 2 };

// ISO/IEC 18004 Table 9, indexed [level][version]; index 0 is unused.
// Error correction codewords in each block:
const ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // H
];
// Number of error correction blocks (short and long blocks together):
const NUM_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81], // H
];

// ---- GF(256) and Reed-Solomon ----------------------------------------------
const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = x; LOG[x] = i;
  x <<= 1; if (x & 0x100) x ^= 0x11d;
}
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const gmul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

const generators = new Map();
// Coefficients of (x - a^0)(x - a^1)...(x - a^(n-1)), highest power first,
// without the leading 1.
function generator(n) {
  let g = generators.get(n);
  if (g) return g;
  let p = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(p.length + 1).fill(0);
    for (let j = 0; j < p.length; j++) {
      next[j] ^= p[j];
      next[j + 1] ^= gmul(p[j], EXP[i]);
    }
    p = next;
  }
  g = Uint8Array.from(p.slice(1));
  generators.set(n, g);
  return g;
}

// The ECC codewords: the remainder of data(x) * x^n divided by the generator.
function rsRemainder(data, gen) {
  const n = gen.length, rem = new Uint8Array(n);
  for (const byte of data) {
    const f = byte ^ rem[0];
    rem.copyWithin(0, 1); rem[n - 1] = 0;
    for (let i = 0; i < n; i++) rem[i] ^= gmul(gen[i], f);
  }
  return rem;
}

// ---- capacity ---------------------------------------------------------------
// Modules left for codewords once every function pattern is placed.
function rawDataModules(v) {
  let n = (16 * v + 128) * v + 64;
  if (v >= 2) {
    const align = Math.floor(v / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (v >= 7) n -= 36;
  }
  return n;
}
const dataCodewords = (v, li) => (rawDataModules(v) >> 3) - ECC_PER_BLOCK[li][v] * NUM_BLOCKS[li][v];
const countBits = (v) => (v < 10 ? 8 : 16);

function levelIndex(ecc) {
  const i = typeof ecc === 'string' ? LEVELS.indexOf(ecc.toUpperCase()) : -1;
  if (i < 0) throw new RangeError(`qr: ECC level must be L, M, Q or H, not ${JSON.stringify(String(ecc)).slice(0, 20)}`);
  return i;
}

function capacity(version, ecc = 'M') {
  if (!Number.isInteger(version) || version < 1 || version > 40) throw new RangeError('qr: version must be 1 to 40');
  return (dataCodewords(version, levelIndex(ecc)) * 8 - 4 - countBits(version)) >> 3;
}

// ---- codewords --------------------------------------------------------------
function buildCodewords(bytes, v, li) {
  const total = dataCodewords(v, li), out = new Uint8Array(total);
  let bit = 0;
  const put = (val, n) => {
    for (let i = n - 1; i >= 0; i--, bit++) if ((val >>> i) & 1) out[bit >> 3] |= 0x80 >> (bit & 7);
  };
  put(0b0100, 4);
  put(bytes.length, countBits(v));
  for (const b of bytes) put(b, 8);
  bit += Math.min(4, total * 8 - bit); // terminator: zero bits, the array is zeroed
  bit = (bit + 7) & ~7;                 // zero bits up to a byte boundary
  for (let i = bit >> 3, pad = 0xec; i < total; i++, pad ^= 0xec ^ 0x11) out[i] = pad;

  // Split into blocks, add ECC, interleave.
  const blocks = NUM_BLOCKS[li][v], eccLen = ECC_PER_BLOCK[li][v];
  const raw = rawDataModules(v) >> 3;
  const shortBlocks = blocks - (raw % blocks), shortData = Math.floor(raw / blocks) - eccLen;
  const gen = generator(eccLen), parts = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const len = shortData + (i < shortBlocks ? 0 : 1);
    const data = out.subarray(k, k + len); k += len;
    parts.push({ data, ecc: rsRemainder(data, gen) });
  }
  const res = new Uint8Array(raw);
  let o = 0;
  for (let i = 0; i <= shortData; i++) for (const p of parts) if (i < p.data.length) res[o++] = p.data[i];
  for (let i = 0; i < eccLen; i++) for (const p of parts) res[o++] = p.ecc[i];
  return res;
}

// ---- symbol layout ----------------------------------------------------------
function alignmentPositions(v) {
  if (v === 1) return [];
  const n = Math.floor(v / 7) + 2;
  const step = Math.floor((v * 8 + n * 3 + 5) / (n * 4 - 4)) * 2;
  const pos = [6];
  for (let p = v * 4 + 10; pos.length < n; p -= step) pos.splice(1, 0, p);
  return pos;
}

function formatBits(li, mask) {
  const data = (FORMAT_LEVEL_BITS[LEVELS[li]] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

// grid holds the module colours (1 = dark), fn marks function modules; both
// are size*size, index y*size + x.
function drawFormat(grid, size, bits) {
  const set = (x, y, i) => { grid[y * size + x] = (bits >>> i) & 1; };
  for (let i = 0; i <= 5; i++) set(8, i, i);
  set(8, 7, 6); set(8, 8, 7); set(7, 8, 8);
  for (let i = 9; i < 15; i++) set(14 - i, 8, i);
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, i);
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, i);
}

function functionPatterns(v, size) {
  const grid = new Uint8Array(size * size), fn = new Uint8Array(size * size);
  const set = (x, y, dark) => { grid[y * size + x] = dark ? 1 : 0; fn[y * size + x] = 1; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || y < 0 || x >= size || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4); // separator ring (d = 4) is light
      }
    }
  }
  const al = alignmentPositions(v), last = al.length - 1;
  for (let i = 0; i <= last; i++) {
    for (let j = 0; j <= last; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue; // finder corners
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  // Reserve both format areas (drawn per mask later) and the dark module.
  for (let i = 0; i < 9; i++) { fn[8 * size + i] = 1; fn[i * size + 8] = 1; }
  for (let i = 0; i < 8; i++) { fn[8 * size + size - 1 - i] = 1; fn[(size - 1 - i) * size + 8] = 1; }
  set(8, size - 8, true);
  if (v >= 7) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (v << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = (bits >>> i) & 1, a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, dark); // top right block
      set(b, a, dark); // bottom left block
    }
  }
  return { grid, fn };
}

// Codeword bits in the two-module-wide zigzag from the bottom right corner,
// skipping the vertical timing pattern. Remainder bits stay light.
function placeData(grid, fn, size, codewords) {
  const total = codewords.length * 8;
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      const y = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const k = y * size + right - j;
        if (fn[k] || i >= total) continue;
        grid[k] = (codewords[i >> 3] >>> (7 - (i & 7))) & 1;
        i++;
      }
    }
  }
}

// Mask conditions with x = column (the spec's j) and y = row (the spec's i).
const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x, y) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(grid, fn, size, mask) {
  const cond = MASKS[mask];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const k = y * size + x;
      if (!fn[k] && cond(x, y)) grid[k] ^= 1;
    }
  }
}

// ---- penalty (see the header for the reading of each rule) ------------------
function lineLight(line, from, to) {
  for (let i = Math.max(from, 0), end = Math.min(to, line.length); i < end; i++) if (line[i]) return false;
  return true;
}

function penalty(grid, size) {
  let score = 0;
  const line = new Uint8Array(size);
  for (let pass = 0; pass < 2; pass++) {
    for (let a = 0; a < size; a++) {
      for (let b = 0; b < size; b++) line[b] = pass ? grid[b * size + a] : grid[a * size + b];
      let run = 1;
      for (let b = 1; b <= size; b++) {
        if (b < size && line[b] === line[b - 1]) { run++; continue; }
        if (run >= 5) score += run - 2; // N1 = 3, plus 1 per module past 5
        run = 1;
      }
      for (let b = 0; b + 7 <= size; b++) {
        if (line[b] && !line[b + 1] && line[b + 2] && line[b + 3] && line[b + 4] && !line[b + 5] && line[b + 6] &&
          (lineLight(line, b - 4, b) || lineLight(line, b + 7, b + 11))) score += 40;
      }
    }
  }
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const k = y * size + x, c = grid[k];
      dark += c;
      if (x + 1 < size && y + 1 < size && c === grid[k + 1] && c === grid[k + size] && c === grid[k + size + 1]) score += 3;
    }
  }
  const total = size * size;
  return score + Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
}

// ---- public -----------------------------------------------------------------
function encode(text, { ecc = 'M', mask } = {}) {
  if (typeof text !== 'string') throw new TypeError('qr: text must be a string');
  const li = levelIndex(ecc), level = LEVELS[li];
  if (mask !== undefined && !(Number.isInteger(mask) && mask >= 0 && mask <= 7)) throw new RangeError('qr: mask must be 0 to 7');
  const bytes = Buffer.from(text, 'utf8');
  let version = 0;
  for (let v = 1; v <= 40 && !version; v++) if (bytes.length <= capacity(v, level)) version = v;
  if (!version) {
    throw new RangeError(`qr: text too long, ${bytes.length} bytes as UTF-8; a QR code at ECC level ${level} holds at most ${capacity(40, level)} bytes`);
  }
  const size = version * 4 + 17;
  const { grid, fn } = functionPatterns(version, size);
  placeData(grid, fn, size, buildCodewords(bytes, version, li));

  let best = null, bestMask = -1, bestScore = Infinity;
  for (let m = 0; m < 8; m++) {
    if (mask !== undefined && m !== mask) continue;
    const g = grid.slice();
    applyMask(g, fn, size, m);
    drawFormat(g, size, formatBits(li, m));
    const score = mask !== undefined ? 0 : penalty(g, size);
    if (score < bestScore) { best = g; bestMask = m; bestScore = score; }
  }
  const modules = [];
  for (let y = 0; y < size; y++) {
    let row = '';
    for (let x = 0; x < size; x++) row += best[y * size + x] ? '1' : '0';
    modules.push(row);
  }
  return { version, ecc: level, mask: bestMask, size, modules };
}

const HEX_COLOUR = /^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;

function toSvg(qr, { margin = 4, dark = '#000', light = '#fff' } = {}) {
  const size = qr && qr.size;
  if (!Number.isInteger(size) || size < 21 || size > 177 || (size - 17) % 4 || !Array.isArray(qr.modules) || qr.modules.length !== size) {
    throw new TypeError('qr: toSvg needs the object encode() returns');
  }
  if (!Number.isInteger(margin) || margin < 0 || margin > 64) throw new RangeError('qr: margin must be a whole number of modules, 0 to 64');
  for (const [name, c] of [['dark', dark], ['light', light]]) {
    if (typeof c !== 'string' || !HEX_COLOUR.test(c)) throw new TypeError(`qr: the ${name} colour must be a hex colour such as #000 or #1a2b3c`);
  }
  const isDark = (m) => m === '1' || m === 1;
  let d = '';
  for (let y = 0; y < size; y++) {
    const row = qr.modules[y];
    if (row == null || row.length !== size) throw new TypeError('qr: toSvg needs the object encode() returns');
    for (let x = 0; x < size;) {
      if (!isDark(row[x])) { x++; continue; }
      let end = x + 1;
      while (end < size && isDark(row[end])) end++;
      d += `M${x + margin} ${y + margin}h${end - x}v1h-${end - x}z`;
      x = end;
    }
  }
  const n = size + 2 * margin;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}">` +
    `<rect width="${n}" height="${n}" fill="${light}"/>` +
    `<path fill="${dark}" shape-rendering="crispEdges" d="${d}"/></svg>`;
}

module.exports = { encode, toSvg, capacity };
