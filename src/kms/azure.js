'use strict';

const { Signer } = require('../signer');
const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
const { DefaultAzureCredential } = require('@azure/identity');
const crypto = require('node:crypto');

function p1363ToDer(signature) {
  const raw = Buffer.from(signature);
  if (raw.length !== 64) return raw;
  const normalize = (part) => {
    let p = Buffer.from(part);
    while (p.length > 1 && p[0] === 0) p = p.subarray(1);
    if (p[0] & 0x80) p = Buffer.concat([Buffer.from([0]), p]);
    return Buffer.concat([Buffer.from([0x02, p.length]), p]);
  };
  const r = normalize(raw.subarray(0, 32));
  const s = normalize(raw.subarray(32, 64));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

class AzureKmsSigner extends Signer {
  constructor(opts = {}) {
    super();
    this.algorithm = 'ES256';
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
    
    const ecJwk = (key) => {
      if (!key?.key || key.key.kty !== 'EC' || key.key.crv !== 'P-256' || !key.key.x || !key.key.y) {
        throw new Error('Azure KMS key must be an EC P-256 key');
      }
      return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: key.key.x, y: key.key.y }, format: 'jwk' });
    };
    this._orgPubKey = ecJwk(orgKey);
    this._checkpointPubKey = ecJwk(cpKey);
    
    this._orgCrypto = new CryptographyClient(orgKey.id, this.credential);
    this._checkpointCrypto = new CryptographyClient(cpKey.id, this.credential);
  }

  getAlgorithm() { return this.algorithm; }

  getOrgPublicKey() {
    return this._orgPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  getCheckpointPublicKey() {
    return this._checkpointPubKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  }

  async signOrgRoot(data) {
    const digest = crypto.createHash('sha256').update(data).digest();
    const result = await this._orgCrypto.sign('ES256', digest);
    return p1363ToDer(result.result).toString('base64url');
  }

  async signCheckpoint(data) {
    const digest = crypto.createHash('sha256').update(data).digest();
    const result = await this._checkpointCrypto.sign('ES256', digest);
    return p1363ToDer(result.result).toString('base64url');
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

module.exports = { AzureKmsSigner };