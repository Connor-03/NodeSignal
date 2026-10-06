// console.test.js: static checks on nodesignal.html. Plain node, no deps.
//   node tests/console.test.js
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, '..', 'nodesignal.html'), 'utf8');
const script = [...html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join('\n');
let failed = 0;
const t = (name, fn) => { try { fn(); console.log('  ok   ' + name); } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + e.message); } };

t('inline script compiles', () => { new vm.Script(script); });
t('no em dashes (CLAUDE.md section 7)', () => assert(!html.includes(String.fromCharCode(0x2014))));
t('implementation colours are the locked palette', () => {
  for (const [impl, hex] of [['Bitcoin Core', '#f7931a'], ['Bitcoin Knots', '#22a95a'], ['btcd', '#4dd2ff'], ['libbitcoin', '#b48cff'], ['Bcoin', '#ff7ab8']])
    assert(script.includes(`'${impl}':'${hex}'`), impl + ' should be ' + hex);
});
t('no mining pool or mined-block UI', () => assert(!/stratum|mined block|⛏/i.test(html)));
t('no PIN entry UI (the daemon uses Noise, not PINs)', () => {
  assert(!/id="f-pin"|set PIN|shared PIN|change PIN|PIN-encrypted'/.test(html));
});
t('no daemon settings fields (URL, token)', () => assert(!/id="f-(url|token|daemon)"|\?daemon=/.test(html)));
t('composer input and send button are never disabled', () => {
  assert(!/composer-in[^>]*disabled|class="send"[^>]*disabled/.test(html));
  // no script ever disables them (other buttons, e.g. a dialog's Save, may be)
  assert(!/(composer-in['"]\)|querySelector\(['"]\.send['"]\))\.disabled\s*=\s*true/.test(script));
  assert(/function queueOrSend/.test(script) && /status:'queued'/.test(script), 'offline sends must queue');
});
t('page connects to same-origin /ws with no configuration', () => assert(/location\.host\+'\/ws'/.test(script)));
t('peer-supplied strings go through esc() in templates', () => {
  // every ${p.nick...}/${p.host}/${m.text}/${m.error} interpolation must be wrapped
  // (sigOf builds the radar's layout cache key, never DOM, so it is skipped;
  // a bare ternary such as ${p.nick?'':'addr'} only emits a constant.)
  const src = script.split('\n').filter((l) => !/^const sigOf=/.test(l)).join('\n');
  const raw = [...src.matchAll(/\$\{(?:p|peer|m)\.(nick|host|text|error|ua|addr)\b[^}]*\}/g)].map((m) => m[0])
    .filter((x) => !/^\$\{\w+\.\w+\?(`|')/.test(x));
  assert.deepStrictEqual(raw, [], 'unescaped: ' + raw.join(', '));
});
t('v1.3 features are wired: history passphrase, key review, retry, advertised peers', () => {
  for (const op of ['vault.set', 'vault.unlock', 'vault.lock', 'vault.change', 'contact.acceptKey', 'contact.dismissKey', 'chat.retry', 'chat.cancel'])
    assert(script.includes(`'${op}'`), op + ' not sent anywhere');
  assert(/pendingFp/.test(script) && /\.ns\b/.test(script) && /status==='pending'/.test(script));
  // accepting a key must echo the exact fingerprint the operator was shown
  assert(/type:'contact\.acceptKey',host:p\.host,fp:p\.pendingFp\.got/.test(script));
});
t('every message to the daemon carries the per-launch action token', () => {
  assert(/meta\[name="\$\{n\}"\]/.test(script) && /metaOf\('ns-action-token'\)/.test(script));
  assert(/state\.ws\.send\(JSON\.stringify\(Object\.assign\(\{token:NS_TOKEN\},o\)\)\)/.test(script), 'send() must attach the token');
  // the only raw socket write is inside send()
  assert.strictEqual((script.match(/state\.ws\.send\(/g) || []).length, 1);
  // a page left open across a daemon restart reloads instead of flushing the outbox with a stale token
  assert(script.indexOf("reloadForNewDaemon();break;}") < script.indexOf('flushOutbox();'));
});
t('mobile: single-pane thread and no legend overlay', () => {
  assert(html.includes('#view-msgs.has-thread .thread{display:flex}'));
  assert(/\.legend\{display:none!important\}/.test(html));
});

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
