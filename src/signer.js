'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { generateEd25519, privKeyFromB64u, pubKeyFromB64u, signCanonical, b64uEncode } = require('./crypto');
const { initSigner } = require('./kms');

function dataDir() { return process.env.AUTHRA_DATA || require('./store').DATA_DIR; }
function keysDir() {
  const d = path.join(dataDir(), 'keys');
  try { fs.mkdirSync(d, { recursive: true }); } catch {}
  return d;
}
try { fs.mkdirSync(path.join(dataDir(), 'keys'), { recursive: true }); } catch {}

function restrict(p) {
  try { fs.chmodSync(p, 0o600); } catch { /* Windows ACLs differ; best effort */ }
  if (process.platform === 'win32') {
    console.warn('[authragen] WARNING: file-permission hardening is best-effort on Windows. Production org roots belong in KMS/HSM, not data/keys/.');
  }
}

// Base class for KMS signers
class Signer {
  async init() { throw new Error('Not implemented'); }
  getOrgPublicKey() { throw new Error('Not implemented'); }
  getCheckpointPublicKey() { throw new Error('Not implemented'); }
  async signOrgRoot(data) { throw new Error('Not implemented'); }
  async signCheckpoint(data) { throw new Error('Not implemented'); }
  async verifyOrgRoot(data, signature) { throw new Error('Not implemented'); }
  async verifyCheckpoint(data, signature) { throw new Error('Not implemented'); }
}

let _orgSigners = null;
let _gatewaySigner = null;

async function initSigners(kmsType = 'file') {
  _orgSigners = await initSigner(kmsType, dataDir());
  _gatewaySigner = _orgSigners;
  if (kmsType !== 'file') {
    console.log(`[authragen] KMS backend initialized: ${kmsType}`);
  } else {
    console.warn('[authragen] WARNING: file-backed org roots (dev default). Production MUST set AUTHRA_KMS to a real KMS/HSM (aws|gcp|vault|azure).');
  }
}

function getOrgSigner(org_id) {
  if (!_orgSigners) {
    throw Object.assign(new Error('Signers not initialized. Call initSigners() first.'), { code: 'kms_unconfigured' });
  }
  return _orgSigners;
}

function orgPubkey(org_id) {
  if (!_orgSigners) return null;
  return _orgSigners.getOrgPublicKey ? _orgSigners.getOrgPublicKey() : null;
}

function gatewaySigner() {
  if (!_gatewaySigner) {
    throw Object.assign(new Error('Signers not initialized. Call initSigners() first.'), { code: 'kms_unconfigured' });
  }
  return {
    pubkey: _gatewaySigner.getCheckpointPublicKey ? _gatewaySigner.getCheckpointPublicKey() : null,
    signCanonical: async (obj) => _gatewaySigner.signCheckpoint(JSON.stringify(obj))
  };
}

function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(secret, salt, 32).toString('hex');
  return `scrypt:${salt}:${h}`;
}
function checkSecret(secret, stored) {
  try {
    const [, salt, h] = String(stored).split(':');
    const h2 = crypto.scryptSync(secret, salt, 32).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(h2, 'hex'));
  } catch { return false; }
}
function newSecret(prefix) { return prefix + '_' + crypto.randomBytes(24).toString('hex'); }

module.exports = { Signer, initSigners, getOrgSigner, orgPubkey, gatewaySigner, hashSecret, checkSecret, newSecret };