'use strict';

const KMS_BACKENDS = {
  file: () => require('./file').FileSigner,
  aws: () => require('./aws').AwsKmsSigner,
  gcp: () => require('./gcp').GcpKmsSigner,
  vault: () => require('./vault').VaultSigner,
  azure: () => require('./azure').AzureKmsSigner
};

function createSigner(type, dataDir, opts = {}) {
  const normalized = type?.toLowerCase();
  const backend = KMS_BACKENDS[normalized];
  if (!backend) {
    throw new Error(`Unknown KMS backend: ${type}. Available: ${Object.keys(KMS_BACKENDS).join(', ')}`);
  }
  const SignerClass = backend();
  const signer = normalized === 'file'
    ? new SignerClass(dataDir, opts)
    : new SignerClass(opts);
  return signer;
}

async function initSigner(type, dataDir, opts = {}) {
  const signer = createSigner(type, dataDir, opts);
  await signer.init();
  return signer;
}

module.exports = { createSigner, initSigner, KMS_BACKENDS };