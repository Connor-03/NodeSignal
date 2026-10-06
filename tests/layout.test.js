// layout.test.js: the peer constellation at 40 peers. Plain node, any version.
//   node tests/layout.test.js
// The radar is frozen (locked decision 9), so this test never copies or edits
// it: it reads nodesignal.html, cuts the real layout code out of the inline
// script by its own markers (rebuild, contactModel, computeLayout, subLabel,
// ensureLayout and the helpers they call) and runs it in a vm sandbox with a
// seeded Math.random, many times. Each layout must have zero overlaps between
// labels, labels and node circles, or circles, and nothing outside the frame
// the console fits to (fitView: VBW x VBH around CX, CY).
// Text width is the layout's own estimate for its monospace labels (0.62 em
// per character; IBM Plex Mono advances 0.6 em).
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm');
const assert = require('assert');

let failed = 0, passed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + String(e && e.message || e).split('\n').slice(0, 4).join('\n       ')); }
};

const html = fs.readFileSync(path.join(__dirname, '..', 'nodesignal.html'), 'utf8');
const script = [...html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join('\n');
// The source between two markers, both of which must exist exactly once.
function cut(from, to) {
  const a = script.indexOf(from), b = script.indexOf(to, a);
  assert(a >= 0 && script.indexOf(from, a + 1) < 0, 'marker not found once: ' + from);
  assert(b > a, 'end marker not found: ' + to);
  return script.slice(a, b);
}
let SRC;
t('the layout code can be cut out of nodesignal.html by its markers', () => {
  SRC = [
    cut('function hostOf(', 'state.everOpen=false;'),                     // hostOf, implShort
    cut('const wireMsg=', 'const byHost='),
    cut('function rebuild(', '/* ===================== NAV'),             // rebuild ... ensureLayout
  ].join('\n');
  for (const name of ['function rebuild(', 'function contactModel(', 'function computeLayout(', 'function subLabel(', 'function ensureLayout(', 'const CX=470,CY=390'])
    assert(SRC.includes(name), name);
  assert(!/\b(document|window)\.[A-Za-z_]/.test(SRC), 'the cut must not touch the DOM');
});

// A sandbox per run: the page's globals the layout reads, and a seeded PRNG.
function layoutOf(seed, nodePeers, contacts) {
  const ctx = vm.createContext({});
  vm.runInContext(`"use strict";
    let s = ${seed >>> 0} || 1;
    Math.random = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
    const state = { peers: [], active: null };
    let idSeq = 1; const uid = () => 'n' + (idSeq++);
    let layoutDirty = true;
    ${SRC}
    globalThis.run = (np, cs) => { rebuild(np, cs); const L = ensureLayout(); return { L, CX, CY, n: state.peers.length }; };`, ctx);
  return ctx.run(nodePeers, contacts);
}

/* ---- peers, in the shapes the daemon sends ---- */
const IMPLS = [['Bitcoin Core', 'v29'], ['Bitcoin Knots', 'v29.1.knots20250903'], ['btcd', 'v0.24.2'], ['libbitcoin', 'v4'], ['Bcoin', 'v2.2'], ['Unknown', '']];
// documentation-range addresses, every fifth one IPv6, the way getpeerinfo writes them
const addrOf = (i) => (i % 5 === 4 ? `[2001:db8::${(i + 1).toString(16)}]:8333` : `${i % 2 ? '203.0.113' : '198.51.100'}.${10 + i}:8333`);
const nodePeer = (i, latency) => {
  const [impl, version] = IMPLS[i % IMPLS.length];
  return { addr: addrOf(i), ua: '/Satoshi:29.0.0/', impl, version, declared: [], latency, inbound: i % 3 === 0, height: 950000, nodesignal: i % 9 === 0 ? { port: 8788 } : null };
};
const contact = (i, nick, latency) => ({
  host: `192.0.2.${100 + i}`, port: 8788, nick, unread: i % 3, lastSeen: 0, established: i % 2 === 0, online: i % 4 === 0, msgs: [],
  peerInfo: latency == null ? null : { impl: IMPLS[i % 5][0], version: IMPLS[i % 5][1], latency },
});
// a deterministic, roughly log-normal spread around ~90 ms, like a real node's peers
const typical = (i) => Math.round(90 * Math.exp(1.1 * Math.sin(i * 2.399) * Math.cos(i * 0.7)));
const SCENES = {
  '40 node peers, spread latency': () => [Array.from({ length: 40 }, (_, i) => nodePeer(i, 12 + (i % 13) * 50)), []],
  '40 node peers, a typical spread around 90 ms': () => [Array.from({ length: 40 }, (_, i) => nodePeer(i, typical(i))), []],
  '40 node peers, up to 1.2 s': () => [Array.from({ length: 40 }, (_, i) => nodePeer(i, Math.round(8 * Math.pow(150, i / 39)))), []],
  '30 node peers and 10 contacts with long nicks, some unmeasured': () => [
    Array.from({ length: 30 }, (_, i) => nodePeer(i, i % 6 === 5 ? null : 20 + i * 23)),
    Array.from({ length: 10 }, (_, i) => contact(i, ['satoshi-fan', 'knots-operator-eu', 'relay-policy-nerd', 'x', 'node-in-a-closet', 'mempool-watcher', 'op', 'pleb-node-03', 'quiet-node-in-the-alps', 'ab'][i], i % 3 ? 30 + i * 70 : null))],
};
// Degenerate crowds: all 40 in one narrow band. The frozen layout cannot always
// separate these (its radial clamp keeps each node within 1.7 node radii of its
// latency ring), so here only the frame is asserted and overlaps are reported
// as a note for the maintainer, not a failure.
const CROWDS = {
  '40 node peers, all at about 50 ms': () => [Array.from({ length: 40 }, (_, i) => nodePeer(i, 48 + (i % 5))), []],
  '40 contacts on the unmeasured ring': () => [[], Array.from({ length: 40 }, (_, i) => contact(i, 'operator-' + i, null))],
};

/* ---- geometry ---- */
const overlap = (a, b) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;
function check(L, CX, CY) {
  const problems = [];
  const frame = { x0: CX - L.VBW / 2, x1: CX + L.VBW / 2, y0: CY - L.VBH / 2, y1: CY + L.VBH / 2 };
  const shapes = L.nodes.map((nd) => {
    const { x, y } = nd, R = L.nodeR, fs = L.fs, sfs = fs - 1.5;
    const base1 = y + R + fs + 6, base2 = y + R + fs * 2 + 8;            // renderRadar's text baselines
    const w = Math.max(nd.label.length * fs * 0.62, L.showSub ? nd.sub.length * sfs * 0.62 : 0);
    const label = { x0: x - w / 2, x1: x + w / 2, y0: base1 - fs * 0.8, y1: (L.showSub ? base2 + sfs * 0.25 : base1 + fs * 0.25) };
    const circle = { x0: x - R, x1: x + R, y0: y - R, y1: y + R };
    return { nd, label, circle, name: nd.label };
  });
  for (const s of shapes) {
    for (const [what, b] of [['circle', s.circle], ['label', s.label]])
      if (b.x0 < frame.x0 || b.x1 > frame.x1 || b.y0 < frame.y0 || b.y1 > frame.y1) problems.push(`${s.name} ${what} out of frame`);
    if (Math.hypot(s.nd.x - CX, s.nd.y - CY) < L.coreR + L.nodeR) problems.push(`${s.name} on top of YOUR NODE`);
    if (!Number.isFinite(s.nd.x) || !Number.isFinite(s.nd.y)) problems.push(`${s.name} has no position`);
  }
  for (let i = 0; i < shapes.length; i++) for (let j = i + 1; j < shapes.length; j++) {
    const a = shapes[i], b = shapes[j];
    if (overlap(a.label, b.label)) problems.push(`labels ${a.name} / ${b.name}`);
    if (overlap(a.label, b.circle)) problems.push(`label ${a.name} over node ${b.name}`);
    if (overlap(b.label, a.circle)) problems.push(`label ${b.name} over node ${a.name}`);
    if (Math.hypot(a.nd.x - b.nd.x, a.nd.y - b.nd.y) < 2 * L.nodeR) problems.push(`nodes ${a.name} / ${b.name}`);
  }
  return problems;
}

// LAYOUT_SEEDS=200 node tests/layout.test.js tries more layouts
const SEEDS = Array.from({ length: Number(process.env.LAYOUT_SEEDS) || 12 }, (_, i) => 0x9e3779b1 * (i + 1));
for (const [scene, make] of Object.entries(SCENES)) {
  t(`${scene}: zero overlaps, nothing out of frame (${SEEDS.length} seeds)`, () => {
    if (!SRC) throw new Error('layout code not loaded');
    const bad = [];
    for (const seed of SEEDS) {
      const [np, cs] = make();
      const { L, CX, CY, n } = layoutOf(seed, np, cs);
      assert.strictEqual(n, 40, 'peer count');
      assert.strictEqual(L.nodes.length, 40);
      const p = check(L, CX, CY);
      if (p.length) bad.push(`seed ${seed >>> 0}: ${p.slice(0, 3).join('; ')}${p.length > 3 ? ` (+${p.length - 3})` : ''}`);
    }
    assert(!bad.length, bad.join('\n'));
  });
}

for (const [scene, make] of Object.entries(CROWDS)) {
  t(`${scene}: nothing out of frame (${SEEDS.length} seeds; overlaps only noted)`, () => {
    if (!SRC) throw new Error('layout code not loaded');
    const bad = [], noted = [];
    for (const seed of SEEDS) {
      const [np, cs] = make();
      const { L, CX, CY } = layoutOf(seed, np, cs);
      const p = check(L, CX, CY);
      const hard = p.filter((x) => /out of frame|no position/.test(x));
      if (hard.length) bad.push(`seed ${seed >>> 0}: ${hard.slice(0, 3).join('; ')}`);
      if (p.length > hard.length) noted.push(seed);
    }
    assert(!bad.length, bad.join('\n'));
    if (noted.length) console.log(`       note: overlaps in ${noted.length} of ${SEEDS.length} layouts (known limit of the frozen radar)`);
  });
}

t('latency rings keep their even radial spacing and ordering at 40 peers', () => {
  const [np] = SCENES['40 node peers, up to 1.2 s']();
  const { L } = layoutOf(7, np, []);
  assert.deepStrictEqual([...L.rings], [10, 25, 50, 100, 200, 350, 550, 800, 1200]);
  const r = L.rings.map(L.latR), steps = r.slice(1).map((x, i) => x - r[i]);
  assert(steps.every((d) => Math.abs(d - steps[0]) < 1e-9), 'even spacing');
  for (let i = 1; i < np.length; i++) assert(L.latR(np[i].latency) >= L.latR(np[i - 1].latency), 'ordering');
});

console.log(failed ? `\n${failed} failed, ${passed} passed` : `\nall passed (${passed})`);
process.exit(failed ? 1 : 0);
