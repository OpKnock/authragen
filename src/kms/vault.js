'use strict';

const { Signer } = require('../signer');
const crypto = require('node:crypto');

class VaultSigner extends Signer {
  constructor(opts = {}) {
    super();
    this.algorithm = 'ES256';
    this.address = opts.address || process.env.VAULT_ADDR || 'http://localhost:8200';
    this.token = opts.token || process.env.VAULT_TOKEN;
    this.orgKeyPath = opts.orgKeyPath || process.env.AUTHRA_VAULT_ORG_KEY || 'transit/keys/authragen-org';
    this.checkpointKeyPath = opts.checkpointKeyPath || process.env.AUTHRA_VAULT_CHECKPOINT_KEY || 'transit/keys/authragen-checkpoint';
    this._orgPubKey = null;
    this._checkpointPubKey = null;
  }

  async _request(method, path, body = null) {
    const url = `${this.address}/v1/${path}`;
    const headers = {
      'X-Vault-Token': this.token,
      'Content-Type': 'application/json'
    };
    const resp = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (!resp.ok) throw new Error(`Vault error: ${resp.status} ${await resp.text()}`);
    return resp.json();
  }

  async init() {
    if (!this.token) throw new Error('VAULT_TOKEN required');
    await this._loadPublicKeys();
  }

  async _loadPublicKeys() {
    const orgResp = await this._request('GET', `${this.orgKeyPath}`);
    const cpResp = await this._request('GET', `${this.checkpointKeyPath}`);
    
    this._orgPubKey = crypto.createPublicKey({
      key: Buffer.from(orgResp.data.keys['1'].public_key, 'utf8'),
      format: 'pem',
      type: 'spki'
    });
    
    this._checkpointPubKey = crypto.createPublicKey({
      key: Buffer.from(cpResp.data.keys['1'].public_key, 'utf8'),
      format: 'pem',
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
    const input = Buffer.from(data).toString('base64');
    const resp = await this._request('POST', `${this.orgKeyPath}/sign`, {
      input,
      algorithm: 'ecdsa-p256-sha256'
    });
    return Buffer.from(resp.data.signature.split(':')[1], 'base64').toString('base64url');
  }

  async signCheckpoint(data) {
    const input = Buffer.from(data).toString('base64');
    const resp = await this._request('POST', `${this.checkpointKeyPath}/sign`, {
      input,
      algorithm: 'ecdsa-p256-sha256'
    });
    return Buffer.from(resp.data.signature.split(':')[1], 'base64').toString('base64url');
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

module.exports = { VaultSigner };