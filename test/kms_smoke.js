'use strict';

const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const { initSigner } = require('../src/kms');

(async () => {
  const type = String(process.env.AUTHRA_KMS || '').toLowerCase();
  if (!['aws', 'gcp', 'azure', 'vault', 'file'].includes(type)) throw new Error('AUTHRA_KMS must be aws|gcp|azure|vault|file');

  const signer = await initSigner(type, path.join(os.tmpdir(), 'authragen-kms-' + Date.now()), {});
  assert.equal(signer.getAlgorithm(), type === 'file' ? 'EdDSA' : 'ES256');

  const message = Buffer.from('authragen-kms-integration-' + Date.now());
  const orgSig = await signer.signOrgRoot(message);
  const cpSig = await signer.signCheckpoint(message);
  assert.equal(await signer.verifyOrgRoot(message, orgSig), true, 'org signature must verify');
  assert.equal(await signer.verifyCheckpoint(message, cpSig), true, 'checkpoint signature must verify');

  const changed = Buffer.from(message);
  changed[0] ^= 1;
  assert.equal(await signer.verifyOrgRoot(changed, orgSig), false, 'changed message must fail org verification');
  assert.equal(await signer.verifyCheckpoint(changed, cpSig), false, 'changed message must fail checkpoint verification');

  console.log(type + ' KMS signer: PASS');
})().catch(err => { console.error(err); process.exit(1); });
