'use strict';

const assert = require('node:assert/strict');
const pq = require('../src/pq');

(async () => {
  if (!pq.supported('65')) {
    console.log('ML-DSA-65 unavailable on this Node runtime: SKIP');
    return;
  }
  const kp = await pq.generateKeypair('65');
  const msg = Buffer.from('authragen-ml-dsa-test');
  const sig = await pq.sign(msg, { alg: kp.alg }, kp.seed);
  assert.equal(await pq.verify(msg, sig, kp.alg, kp.publicKey), true);
  assert.equal(await pq.verify(Buffer.from('tampered'), sig, kp.alg, kp.publicKey), false);
  const env = await pq.seal({ v: 1, subject: 'agent:test', intent_hash: 'abc' }, kp);
  const opened = await pq.open(env, kp.publicKey);
  assert.equal(opened.payload.subject, 'agent:test');
  console.log('ML-DSA-65 credential profile: PASS');
})().catch(err => { console.error(err); process.exit(1); });
