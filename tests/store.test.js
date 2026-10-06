// store.test.js: the passphrase vault and sealed message storage. Plain node.
//   node tests/store.test.js
'use strict';
const assert = require('assert');
const store = require('../store.js');
let failed = 0;
const t = async (name, fn) => { try { await fn(); console.log('  ok   ' + name); } catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + e.message); } };

(async () => {
  const { vault, priv } = await store.createVault('correct horse battery');
  await t('vault is JSON-safe and holds no plaintext key', () => {
    const j = JSON.stringify(vault);
    assert(!j.includes(priv.toString('base64')));
    assert.strictEqual(JSON.parse(j).kdf.name, 'scrypt');
  });
  await t('unlock with the right passphrase returns the same key', async () => {
    assert(priv.equals(await store.unlock(vault, 'correct horse battery')));
  });
  await t('wrong passphrase is rejected', async () => {
    await assert.rejects(store.unlock(vault, 'correct horse batterz'), /wrong passphrase/);
  });
  await t('short passphrase refused', async () => { await assert.rejects(store.createVault('short'), /at least 8/); });
  await t('a locked daemon can seal; only the key opens', async () => {
    const s = store.seal(vault.pub, 'gm from the timechain ✓');
    assert.strictEqual(store.open(priv, s), 'gm from the timechain ✓');
    const other = (await store.createVault('another passphrase')).priv;
    assert.throws(() => store.open(other, s));
  });
  await t('every seal uses a fresh ephemeral key and nonce', () => {
    const a = store.seal(vault.pub, 'same'), b = store.seal(vault.pub, 'same');
    assert.notStrictEqual(a.e, b.e); assert.notStrictEqual(a.n, b.n); assert.notStrictEqual(a.ct, b.ct);
  });
  await t('tampering with any field is detected', () => {
    const s = store.seal(vault.pub, 'hello');
    for (const k of ['e', 'n', 'ct']) {
      const buf = Buffer.from(s[k], 'base64'); buf[buf.length - 1] ^= 1;
      assert.throws(() => store.open(priv, { ...s, [k]: buf.toString('base64') }), undefined, k);
    }
  });
  await t('tampered vault (pub swapped) does not unlock', async () => {
    const other = await store.createVault('another passphrase');
    await assert.rejects(store.unlock({ ...vault, pub: other.vault.pub }, 'correct horse battery'));
  });
  await t('absurd KDF parameters are refused before allocating', async () => {
    await assert.rejects(store.unlock({ ...vault, kdf: { ...vault.kdf, N: 2 ** 30 } }, 'correct horse battery'), /bad KDF/);
  });
  await t('changing the passphrase keeps old messages readable', async () => {
    const s = store.seal(vault.pub, 'old message');
    const v2 = await store.changePassphrase(vault, priv, 'a new passphrase here');
    await assert.rejects(store.unlock(v2, 'correct horse battery'), /wrong passphrase/);
    const k2 = await store.unlock(v2, 'a new passphrase here');
    assert.strictEqual(store.open(k2, s), 'old message');
  });
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exit(failed ? 1 : 0);
})();
