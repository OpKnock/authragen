'use strict';

const { Signer } = require('../signer');
const { signCanonical } = require('../crypto');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

class FileSigner extends Signer {
  constructor(dataDir) {
    super();
    this.algorithm = 'EdDSA';
    this.dataDir = dataDir;
    this.orgKeyPath = path.join(dataDir, 'org-root.key');
    this.checkpointKeyPath = path.join(dataDir, 'checkpoint.key');
  }

  async init() {
    fs.mkdirSync(this.dataDir, { recursive: true });
    if (!fs.existsSync(this.orgKeyPath)) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      fs.writeFileSync(this.orgKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      fs.writeFileSync(this.orgKeyPath + '.pub', publicKey.export({ type: 'spki', format: 'pem' }));
      console.warn('WARNING: Generated file-backed org root key. DEVELOPMENT ONLY. Use KMS for production.');
    }
    if (!fs.existsSync(this.checkpointKeyPath)) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      fs.writeFileSync(this.checkpointKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      fs.writeFileSync(this.checkpointKeyPath + '.pub', publicKey.export({ type: 'spki', format: 'pem' }));
    }
    this.orgPrivateKey = crypto.createPrivateKey(fs.readFileSync(this.orgKeyPath));
    this.orgPublicKey = crypto.createPublicKey(fs.readFileSync(this.orgKeyPath + '.pub'));
    this.checkpointPrivateKey = crypto.createPrivateKey(fs.readFileSync(this.checkpointKeyPath));
    this.checkpointPublicKey = crypto.createPublicKey(fs.readFileSync(this.checkpointKeyPath + '.pub'));
  }

  getAlgorithm() { return this.algorithm; }
  getOrgPublicKey() { return this.orgPublicKey.export({ format: 'jwk' }).x; }

  getCheckpointPublicKey() { return this.checkpointPublicKey.export({ format: 'jwk' }).x; }

  async signOrgRoot(data) {
    const sig = crypto.sign(null, Buffer.from(data), this.orgPrivateKey);
    return sig.toString('base64url');
  }

  async signCheckpoint(data) {
    const sig = crypto.sign(null, Buffer.from(data), this.checkpointPrivateKey);
    return sig.toString('base64url');
  }

  async signCanonical(obj) {
    return signCanonical(obj, this.orgPrivateKey);
  }

  async signBytes(buf) {
    const sig = crypto.sign(null, Buffer.from(buf), this.orgPrivateKey);
    return sig.toString('base64url');
  }

  async verifyOrgRoot(data, signature) {
    return crypto.verify(null, Buffer.from(data), this.orgPublicKey, Buffer.from(signature, 'base64url'));
  }

  async verifyCheckpoint(data, signature) {
    return crypto.verify(null, Buffer.from(data), this.checkpointPublicKey, Buffer.from(signature, 'base64url'));
  }
}

module.exports = { FileSigner };