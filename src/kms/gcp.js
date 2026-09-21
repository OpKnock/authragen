'use strict';

const { Signer } = require('../signer');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const crypto = require('node:crypto');

class GcpKmsSigner extends Signer {
  constructor(opts = {}) {
    super();
    this.projectId = opts.projectId || process.env.GCP_PROJECT_ID;
    this.location = opts.location || process.env.AUTHRA_GCP_KMS_LOCATION || 'global';
    this.orgKeyRing = opts.orgKeyRing || process.env.AUTHRA_GCP_KMS_ORG_KEY_RING;
    this.orgKeyName = opts.orgKeyName || process.env.AUTHRA_GCP_KMS_ORG_KEY_NAME;
    this.checkpointKeyRing = opts.checkpointKeyRing || process.env.AUTHRA_GCP_KMS_CHECKPOINT_KEY_RING;
    this.checkpointKeyName = opts.checkpointKeyName || process.env.AUTHRA_GCP_KMS_CHECKPOINT_KEY_NAME;
    this.client = new KeyManagementServiceClient();
    this._orgPubKey = null;
    this._checkpointPubKey = null;
  }

  _keyPath(keyRing, keyName) {
    return this.client.cryptoKeyPath(this.projectId, this.location, keyRing, keyName);
  }

  async init() {
    if (!this.orgKeyRing || !this.orgKeyName || !this.checkpointKeyRing || !this.checkpointKeyName) {
      throw new Error('GCP KMS key paths required');
    }
    await this._loadPublicKeys();
  }

  async _loadPublicKeys() {
    const [orgKey] = await this.client.getPublicKey({ name: this._keyPath(this.orgKeyRing, this.orgKeyName) });
    const [cpKey] = await this.client.getPublicKey({ name: this._keyPath(this.checkpointKeyRing, this.checkpointKeyName) });
    
    this._orgPubKey = crypto.createPublicKey({
      key: Buffer.from(orgKey.pem, 'utf8'),
      format: 'pem',
      type: 'spki'
    });
    
    this._checkpointPubKey = crypto.createPublicKey({
      key: Buffer.from(cpKey.pem, 'utf8'),
      format: 'pem',
      type: 'spki'
    });
  }

  getOrgPublicKey() {
    return this._orgPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  getCheckpointPublicKey() {
    return this._checkpointPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  async signOrgRoot(data) {
    const [resp] = await this.client.asymmetricSign({
      name: this._keyPath(this.orgKeyRing, this.orgKeyName),
      digest: { sha256: crypto.createHash('sha256').update(data).digest() }
    });
    return resp.signature.toString('base64url');
  }

  async signCheckpoint(data) {
    const [resp] = await this.client.asymmetricSign({
      name: this._keyPath(this.checkpointKeyRing, this.checkpointKeyName),
      digest: { sha256: crypto.createHash('sha256').update(data).digest() }
    });
    return resp.signature.toString('base64url');
  }

  async verifyOrgRoot(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._orgPubKey, Buffer.from(signature, 'base64url'));
  }

  async verifyCheckpoint(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._checkpointPubKey, Buffer.from(signature, 'base64url'));
  }
}

module.exports = { GcpKmsSigner };