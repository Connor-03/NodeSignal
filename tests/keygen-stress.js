// keygen-stress.js: run by noise.test.js in a child process. Makes and
// exports fresh keys on every runtime path, thousands of times. On Node 18,
// keys from crypto.generateKeyPairSync deadlocked here in 9 of 12 runs of
// 4000 rounds (the generation job's destructor, run by the garbage collector
// during an export, waits for the lock the export holds).
'use strict';
const path = require('path'), ROOT = path.join(__dirname, '..');
const N = Number(process.argv[2] || 4000);
const noise = require(path.join(ROOT, 'noise.js')), mailbox = require(path.join(ROOT, 'mailbox.js'));
const social = require(path.join(ROOT, 'social.js')), store = require(path.join(ROOT, 'store.js'));
const A = noise.loadIdentity(noise.newIdentity()), B = noise.loadIdentity(noise.newIdentity());
const raw = (b64) => require('crypto').createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' }).export({ format: 'jwk' }).x;
const idA = noise.newIdentity(), idB = noise.newIdentity();
const aPriv = Buffer.from(require('crypto').createPrivateKey({ key: Buffer.from(idA.priv, 'base64'), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }).d, 'base64url');
const aPub = Buffer.from(raw(idA.pub), 'base64url'), bPub = Buffer.from(raw(idB.pub), 'base64url');
for (let i = 0; i < N; i++) {
  noise.newIdentity();
  const s = noise.v3.initStart(A), r = noise.v3.respond(B, s.msg1);
  r.finish(noise.v3.initFinish(s, r.msg2).msg3);
  social.newSigningKey();
  if (i % 8 === 0) { const l = noise.legacy.initStart(A); noise.legacy.respond(B, l.msg1); }
  if (i % 4 === 0) {
    mailbox.seal({ senderPrivRaw: aPriv, senderPubRaw: aPub, recipientPubRaw: bPub, plaintext: Buffer.from('x') });
    store.seal(bPub.toString('base64'), 'x');
  }
}
console.log('ok ' + N);
