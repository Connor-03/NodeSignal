// winexe.test.js: the Windows executable's icon and version resource, offline.
//   node tests/winexe.test.js
// Plain node, no deps, no network. The resource editor itself (resedit) is
// fetched only by a Windows build; here we check what feeds it: the icon
// drawn by packaging/windows/make-icon.js, the strings and version numbers
// from packaging/windows/win-resources.js, and the build order in build-sea.js.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const icon = require('../packaging/windows/make-icon.js');
const winres = require('../packaging/windows/win-resources.js');

let failed = 0;
function test(name, fn) {
  try { fn(); console.log('  ok   ' + name); } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e && e.message)); }
}

test('crc32 matches the standard check value', () => {
  assert.strictEqual(icon.crc32(Buffer.from('123456789')), 0xcbf43926);
});

test('the .ico has PNG entries at 16, 32, 48 and 256 px with valid CRCs', () => {
  const ico = icon.makeIco();
  assert.strictEqual(ico.readUInt16LE(0), 0);
  assert.strictEqual(ico.readUInt16LE(2), 1);
  const entries = icon.readIco(ico);   // checks every chunk CRC and the sizes
  assert.deepStrictEqual(entries.map((e) => e.size), [16, 32, 48, 256]);
  for (let i = 0; i < entries.length; i++) {
    const e = 6 + 16 * i;
    assert.strictEqual(ico.readUInt16LE(e + 4), 1, 'planes');
    assert.strictEqual(ico.readUInt16LE(e + 6), 32, 'bits per pixel');
    const off = ico.readUInt32LE(e + 12);
    assert.strictEqual(ico.toString('latin1', off + 1, off + 4), 'PNG');
  }
});

test('a damaged PNG is refused', () => {
  const ico = Buffer.from(icon.makeIco());
  const off = ico.readUInt32LE(6 + 12);
  ico[off + 40] ^= 0xff;
  assert.throws(() => icon.readIco(ico), /CRC|incorrect|invalid/i);
});

test('the committed nodesignal.ico has exactly the pixels the source draws', () => {
  const committed = fs.readFileSync(path.join(ROOT, 'packaging', 'windows', 'nodesignal.ico'));
  assert.ok(icon.samePixels(committed, icon.makeIco()), 'run: node packaging/windows/make-icon.js');
});

test('the glyph: transparent corners, dark square, Core orange nodes at every size', () => {
  const near = (p, o, rgb) => Math.abs(p[o] - rgb[0]) < 8 && Math.abs(p[o + 1] - rgb[1]) < 8 && Math.abs(p[o + 2] - rgb[2]) < 8;
  for (const size of icon.SIZES) {
    const px = icon.render(size);
    assert.strictEqual(px[3], 0, `${size}px: top-left corner is transparent`);
    let orange = 0, dark = 0;
    for (let o = 0; o < px.length; o += 4) {
      if (px[o + 3] !== 255) continue;
      if (near(px, o, [0xf7, 0x93, 0x1a])) orange++;
      if (near(px, o, [0x0e, 0x13, 0x1c])) dark++;
    }
    const n = size * size;
    assert.ok(orange > n * 0.05, `${size}px: enough #f7931a (${orange}/${n})`);
    assert.ok(dark > n * 0.35, `${size}px: mostly the dark square (${dark}/${n})`);
  }
});

test('rendering is deterministic', () => {
  assert.ok(Buffer.from(icon.render(48)).equals(Buffer.from(icon.render(48))));
  const a = icon.readIco(icon.makeIco()), b = icon.readIco(icon.makeIco());
  assert.ok(a.every((e, i) => Buffer.from(e.pixels).equals(Buffer.from(b[i].pixels))));
});

test('numeric version fields', () => {
  assert.deepStrictEqual(winres.numericVersion('1.3.0'), [1, 3, 0, 0]);
  assert.deepStrictEqual(winres.numericVersion('1.3.0-rc.1'), [1, 3, 0, 0]);
  assert.deepStrictEqual(winres.numericVersion('2.10.7.4'), [2, 10, 7, 4]);
  assert.throws(() => winres.numericVersion('v1'));
  assert.throws(() => winres.numericVersion('1.70000.0'));
});

test('version strings: from package.json and LICENSE, nothing invented', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const licenseText = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
  const line = licenseText.match(/^Copyright\b.*$/m)[0].trim();
  const s = winres.versionStrings({ version: pkg.version, originalFilename: 'NodeSignal-Setup-windows-x64.exe', nodeVersion: '22.0.0', licenseText, homepage: 'https://github.com/Connor-03/NodeSignal' });
  assert.strictEqual(s.ProductName, 'NodeSignal');
  assert.strictEqual(s.ProductVersion, pkg.version);
  assert.strictEqual(s.FileVersion, pkg.version);
  assert.strictEqual(s.OriginalFilename, 'NodeSignal-Setup-windows-x64.exe');
  assert.strictEqual(s.InternalName, 'nodesignal');
  assert.ok(s.FileDescription.length > 0);
  assert.strictEqual(s.LegalCopyright, `${line}. MIT License.`);
  assert.ok(line.endsWith(s.CompanyName), 'CompanyName is the LICENSE holder');
  assert.ok(/^MIT License/.test(licenseText), 'LICENSE is MIT');
  for (const v of Object.values(s)) assert.ok(!v.includes(String.fromCharCode(0x2014)), 'no em dash');
});

test('LICENSE holder parsing', () => {
  assert.deepStrictEqual(winres.licenseHolder('MIT\n\nCopyright (c) 2026 Some One\n'), { line: 'Copyright (c) 2026 Some One', holder: 'Some One' });
  assert.strictEqual(winres.licenseHolder('Copyright 2025-2026 A B').holder, 'A B');
  assert.throws(() => winres.licenseHolder('no line here'));
});

test('build-time tools: exact pins, never a runtime dependency', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.deepStrictEqual(pkg.dependencies || {}, {});
  assert.ok(!pkg.devDependencies || (!pkg.devDependencies.resedit && !pkg.devDependencies.postject));
  for (const p of [winres.RESEDIT, winres.PE_LIBRARY]) assert.match(p.version, /^\d+\.\d+\.\d+$/, `${p.name} pinned exactly`);
  const files = JSON.parse(fs.readFileSync(path.join(ROOT, 'packaging', 'files.json'), 'utf8'));
  const shipped = [...files.daemon, ...files.tools];
  for (const f of ['packaging/windows/win-resources.js', 'packaging/windows/make-icon.js']) assert.ok(!shipped.includes(f), `${f} is not shipped`);
});

test('build-sea.js stamps resources before postject injects, and checks after', () => {
  const src = fs.readFileSync(path.join(ROOT, 'packaging', 'build-sea.js'), 'utf8');
  const stamp = src.indexOf('winres.stamp(');
  const inject = src.indexOf("'NODE_SEA_BLOB', blob");
  const verify = src.indexOf('.verify(R, OUT, stamped)');
  assert.ok(stamp > 0 && inject > 0 && verify > 0, 'all three steps found');
  assert.ok(stamp < inject, 'resources are written before the SEA blob is injected');
  assert.ok(inject < verify, 'the finished file is checked after injection');
  assert.match(src, /if \(PE_ARCH\) \{\s*const winres/, 'the resource step runs only for a Windows (PE) build');
});

if (failed) { console.log(`\n${failed} test(s) failed`); process.exit(1); }
console.log('\nwinexe: all tests passed');
