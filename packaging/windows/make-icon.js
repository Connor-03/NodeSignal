#!/usr/bin/env node
// make-icon.js: draw the NodeSignal icon from source and write it as an .ico.
// ============================================================================
//   node packaging/windows/make-icon.js [out.ico]   write the icon (default:
//                                                   packaging/windows/nodesignal.ico)
//   node packaging/windows/make-icon.js --check     exit 1 unless the committed
//                                                   .ico has exactly these pixels
//
// The glyph is a few connected nodes in Bitcoin Core orange (#f7931a) on a
// dark rounded square (the console's --panel colour), drawn at 16, 32, 48 and
// 256 px. Every pixel comes from the geometry below, so the committed .ico is
// not a binary of unknown origin: anyone can regenerate it and compare.
// build-sea.js regenerates it at build time rather than trusting the file.
//
// Standard library only. Each .ico entry is a PNG (Windows Vista and later
// read PNG entries at every size); the PNG is encoded here with zlib and our
// own CRC-32. --check compares decoded pixels, not bytes, because zlib
// versions may compress the same pixels differently.
// ============================================================================
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZES = [16, 32, 48, 256];
const DEFAULT_OUT = path.join(__dirname, 'nodesignal.ico');

const BG = [0x0e, 0x13, 0x1c];      // --panel in nodesignal.html
const EDGE = [0x21, 0x2b, 0x3b];    // --elev-2
const ORANGE = [0xf7, 0x93, 0x1a];  // Bitcoin Core orange (CLAUDE.md decision 1)

// Geometry in a 256 x 256 design space. The fourth node is left out below
// 24 px, where it would only blur the other three together.
const NODES = [
  { x: 62, y: 168, r: 26 },
  { x: 110, y: 62, r: 26 },
  { x: 194, y: 126, r: 35, hub: true },
  { x: 172, y: 206, r: 19, minSize: 24 },
];
const LINKS = [[0, 1], [1, 2], [0, 2], [2, 3]];

/* ---------------------------------------------------------------- drawing */

// distance from (px,py) to the segment a-b
function segDist(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  let t = ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy);
  t = t < 0 ? 0 : t > 1 ? 1 : t;
  const ex = px - (ax + t * dx), ey = py - (ay + t * dy);
  return Math.sqrt(ex * ex + ey * ey);
}

// signed distance to a rounded square [m, 256-m] with corner radius rad
function roundRectDist(px, py, m, rad) {
  const c = 128, h = 128 - m - rad;
  const qx = Math.abs(px - c) - h, qy = Math.abs(py - c) - h;
  const ox = Math.max(qx, 0), oy = Math.max(qy, 0);
  return Math.sqrt(ox * ox + oy * oy) + Math.min(Math.max(qx, qy), 0) - rad;
}

// RGBA pixels (Uint8Array, row-major, straight alpha) for one size.
function render(size) {
  const k = 256 / size;                   // design units per pixel
  const ss = size >= 128 ? 4 : 8;         // supersampling per axis
  const nodes = NODES.filter((n) => !n.minSize || size >= n.minSize);
  const links = LINKS.filter(([a, b]) => a < nodes.length && b < nodes.length);
  // keep strokes readable at small sizes: at least about 1.5 px wide
  const lineHalf = Math.max(7, 0.75 * k);
  const edge = size >= 48 ? 3 : 0;        // a hairline border only where it shows
  const margin = size >= 48 ? 8 : 0;
  const radius = 52;
  const out = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;     // premultiplied sums over samples
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const px = (x + (sx + 0.5) / ss) * k, py = (y + (sy + 0.5) / ss) * k;
          const dBox = roundRectDist(px, py, margin, radius);
          if (dBox > 0) continue;         // outside the square: transparent
          let c = dBox > -edge ? EDGE : BG;
          let lineA = 0;
          for (const [i, j] of links) {
            const d = segDist(px, py, nodes[i].x, nodes[i].y, nodes[j].x, nodes[j].y);
            if (d <= lineHalf) { lineA = 0.8; break; }
          }
          if (lineA) c = [c[0] + (ORANGE[0] - c[0]) * lineA, c[1] + (ORANGE[1] - c[1]) * lineA, c[2] + (ORANGE[2] - c[2]) * lineA];
          for (const n of nodes) {
            const dx = px - n.x, dy = py - n.y, d2 = dx * dx + dy * dy;
            const nr = Math.max(n.r, 1.1 * k);
            if (d2 <= nr * nr) {
              c = ORANGE;
              // the hub has a dark centre, a ring, where there are pixels for it
              const hole = n.hub && size >= 32 ? n.r * 0.42 : 0;
              if (hole && d2 <= hole * hole) c = BG;
            }
          }
          r += c[0]; g += c[1]; b += c[2]; a += 1;
        }
      }
      const o = (y * size + x) * 4, n = ss * ss;
      if (a) {
        out[o] = Math.round(r / a); out[o + 1] = Math.round(g / a); out[o + 2] = Math.round(b / a);
        out[o + 3] = Math.round((255 * a) / n);
      }
    }
  }
  return out;
}

/* -------------------------------------------------------------------- PNG */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;  // 8-bit RGBA, no interlace
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;                                          // filter: none
    Buffer.from(rgba.buffer, rgba.byteOffset + y * size * 4, size * 4).copy(raw, y * (size * 4 + 1) + 1);
  }
  return Buffer.concat([PNG_SIG, chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

// Decode a PNG this script wrote (8-bit RGBA, no interlace, filter none);
// anything else is refused rather than half-read. CRCs are checked.
function decodePng(buf) {
  if (!buf.subarray(0, 8).equals(PNG_SIG)) throw new Error('not a PNG');
  let off = 8, w = 0, h = 0;
  const idat = [];
  while (off < buf.length) {
    const len = buf.readUInt32BE(off), type = buf.toString('ascii', off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    if (crc32(buf.subarray(off + 4, off + 8 + len)) !== buf.readUInt32BE(off + 8 + len)) throw new Error('bad CRC in ' + type);
    if (type === 'IHDR') {
      w = data.readUInt32BE(0); h = data.readUInt32BE(4);
      if (data[8] !== 8 || data[9] !== 6 || data[12] !== 0) throw new Error('unsupported PNG format');
    } else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    off += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  if (raw.length !== h * (w * 4 + 1)) throw new Error('PNG data has the wrong length');
  const px = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    if (raw[y * (w * 4 + 1)] !== 0) throw new Error('unsupported PNG filter');
    px.set(raw.subarray(y * (w * 4 + 1) + 1, (y + 1) * (w * 4 + 1)), y * w * 4);
  }
  return { width: w, height: h, pixels: px };
}

/* -------------------------------------------------------------------- ICO */

function makeIco() {
  const pngs = SIZES.map((s) => encodePng(s, render(s)));
  const head = Buffer.alloc(6 + 16 * pngs.length);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(pngs.length, 4);
  let offset = head.length;
  pngs.forEach((png, i) => {
    const e = 6 + 16 * i, s = SIZES[i];
    head[e] = s >= 256 ? 0 : s; head[e + 1] = s >= 256 ? 0 : s;  // 0 means 256
    head[e + 2] = 0; head[e + 3] = 0;                             // no palette
    head.writeUInt16LE(1, e + 4); head.writeUInt16LE(32, e + 6);  // planes, bits per pixel
    head.writeUInt32LE(png.length, e + 8); head.writeUInt32LE(offset, e + 12);
    offset += png.length;
  });
  return Buffer.concat([head, ...pngs]);
}

// [{ size, pixels }] from an .ico whose entries are PNGs
function readIco(buf) {
  if (buf.readUInt16LE(0) !== 0 || buf.readUInt16LE(2) !== 1) throw new Error('not an .ico');
  const n = buf.readUInt16LE(4), out = [];
  for (let i = 0; i < n; i++) {
    const e = 6 + 16 * i, size = buf[e] || 256;
    const len = buf.readUInt32LE(e + 8), off = buf.readUInt32LE(e + 12);
    const png = decodePng(buf.subarray(off, off + len));
    if (png.width !== size || png.height !== size) throw new Error(`entry ${i} says ${size} px but holds ${png.width}x${png.height}`);
    out.push({ size, pixels: png.pixels });
  }
  return out;
}

// true when two .ico files hold the same sizes with identical pixels
function samePixels(a, b) {
  const x = readIco(a), y = readIco(b);
  return x.length === y.length && x.every((e, i) => e.size === y[i].size && Buffer.from(e.pixels).equals(Buffer.from(y[i].pixels)));
}

module.exports = { SIZES, DEFAULT_OUT, render, encodePng, decodePng, makeIco, readIco, samePixels, crc32 };

if (require.main === module) {
  const ico = makeIco();
  if (process.argv.includes('--check')) {
    let ok = false;
    try { ok = samePixels(fs.readFileSync(DEFAULT_OUT), ico); } catch (e) { console.error('make-icon: ' + e.message); }
    if (!ok) { console.error(`make-icon: ${path.relative(process.cwd(), DEFAULT_OUT)} does not match the source; run node packaging/windows/make-icon.js`); process.exit(1); }
    console.log('make-icon: the committed icon matches the source');
  } else {
    const out = path.resolve(process.argv[2] || DEFAULT_OUT);
    fs.writeFileSync(out, ico);
    console.log(`make-icon: wrote ${out} (${SIZES.join(', ')} px, ${ico.length} bytes)`);
  }
}
