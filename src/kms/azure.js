'use strict';

const { Signer } = require('../signer');
const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
const { DefaultAzureCredential } = require('@azure/identity');
const crypto = require('node:crypto');

class AzureKmsSigner extends Signer {
  constructor(opts = {}) {
    super();
    this.vaultUrl = opts.vaultUrl || process.env.AUTHRA_AZURE_KEYVAULT_URL;
    this.orgKeyName = opts.orgKeyName || process.env.AUTHRA_AZURE_ORG_KEY_NAME || 'authragen-org';
    this.checkpointKeyName = opts.checkpointKeyName || process.env.AUTHRA_AZURE_CHECKPOINT_KEY_NAME || 'authragen-checkpoint';
    this.credential = opts.credential || new DefaultAzureCredential();
    this.keyClient = new KeyClient(this.vaultUrl, this.credential);
    this._orgPubKey = null;
    this._checkpointPubKey = null;
    this._orgCrypto = null;
    this._checkpointCrypto = null;
  }

  async init() {
    if (!this.vaultUrl) throw new Error('AUTHRA_AZURE_KEYVAULT_URL required');
    
    const orgKey = await this.keyClient.getKey(this.orgKeyName);
    const cpKey = await this.keyClient.getKey(this.checkpointKeyName);
    
    this._orgPubKey = crypto.createPublicKey({
      key: Buffer.from(orgKey.key.toString('utf8')),
      format: 'pem',
      type: 'spki'
    });
    
    this._checkpointPubKey = crypto.createPublicKey({
      key: Buffer.from(cpKey.key.toString('utf8')),
      format: 'pem',
      type: 'spki'
    });
    
    this._orgCrypto = new CryptographyClient(orgKey.id, this.credential);
    this._checkpointCrypto = new CryptographyClient(cpKey.id, this.credential);
  }

  getOrgPublicKey() {
    return this._orgPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  getCheckpointPublicKey() {
    return this._checkpointPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  async signOrgRoot(data) {
    const digest = crypto.createHash('sha256').update(data).digest();
    const result = await this._orgCrypto.sign('ES256', digest);
    return Buffer.from(result.result).toString('base64url');
  }

  async signCheckpoint(data) {
    const digest = crypto.createHash('sha256').update(data).digest();
    const result = await this._checkpointCrypto.sign('ES256', digest);
    return Buffer.from(result.result).toString('base64url');
  }

  async verifyOrgRoot(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._orgPubKey, Buffer.from(signature, 'base64url'));
  }

  async verifyCheckpoint(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._checkpointPubKey, Buffer.from(signature, 'base64url'));
  }
}

module.exports = { AzureKmsSigner };