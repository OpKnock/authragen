'use strict';

const { Signer } = require('../signer');
const { KMSClient, SignCommand, GetPublicKeyCommand } = require('@aws-sdk/client-kms');
const crypto = require('node:crypto');

class AwsKmsSigner extends Signer {
  constructor(opts = {}) {
    super();
    this.algorithm = 'ES256';
    this.region = opts.region || process.env.AWS_REGION || 'us-east-1';
    this.orgKeyId = opts.orgKeyId || process.env.AUTHRA_AWS_KMS_ORG_KEY_ID;
    this.checkpointKeyId = opts.checkpointKeyId || process.env.AUTHRA_AWS_KMS_CHECKPOINT_KEY_ID;
    this.client = new KMSClient({ region: this.region });
    this._orgPubKey = null;
    this._checkpointPubKey = null;
  }

  async init() {
    if (!this.orgKeyId || !this.checkpointKeyId) {
      throw new Error('AWS KMS key IDs required: AUTHRA_AWS_KMS_ORG_KEY_ID, AUTHRA_AWS_KMS_CHECKPOINT_KEY_ID');
    }
    await this._loadPublicKeys();
  }

  async _loadPublicKeys() {
    const orgResp = await this.client.send(new GetPublicKeyCommand({ KeyId: this.orgKeyId }));
    const cpResp = await this.client.send(new GetPublicKeyCommand({ KeyId: this.checkpointKeyId }));
    
    this._orgPubKey = crypto.createPublicKey({
      key: orgResp.PublicKey,
      format: 'der',
      type: 'spki'
    });
    
    this._checkpointPubKey = crypto.createPublicKey({
      key: cpResp.PublicKey,
      format: 'der',
      type: 'spki'
    });
  }

  getAlgorithm() { return this.algorithm; }

  getOrgPublicKey() {
    return this._orgPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  getCheckpointPublicKey() {
    return this._checkpointPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  async signOrgRoot(data) {
    const cmd = new SignCommand({
      KeyId: this.orgKeyId,
      Message: Buffer.from(data),
      MessageType: 'RAW',
      SigningAlgorithm: 'ECDSA_SHA_256'
    });
    const resp = await this.client.send(cmd);
    return resp.Signature.toString('base64url');
  }

  async signCheckpoint(data) {
    const cmd = new SignCommand({
      KeyId: this.checkpointKeyId,
      Message: Buffer.from(data),
      MessageType: 'RAW',
      SigningAlgorithm: 'ECDSA_SHA_256'
    });
    const resp = await this.client.send(cmd);
    return resp.Signature.toString('base64url');
  }

  async signBytes(data) { return this.signOrgRoot(Buffer.from(data)); }
  async signCanonical(obj) { const { canonical } = require('../crypto'); return this.signBytes(Buffer.from(canonical(obj), 'utf8')); }

  async verifyOrgRoot(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._orgPubKey, Buffer.from(signature, 'base64url'));
  }

  async verifyCheckpoint(data, signature) {
    return crypto.verify('sha256', Buffer.from(data), this._checkpointPubKey, Buffer.from(signature, 'base64url'));
  }
}

module.exports = { AwsKmsSigner };