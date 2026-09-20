'use strict';
// Signer abstraction — the custody boundary.
//
// Rule: the gateway holds ONLY organization roots (and the gateway checkpoint
// key), ideally via KMS/HSM. Agent private keys must NEVER be stored here.
// Self-custody (CSR flow) is the default; server-custodied agent keys exist
// only as an explicit dev fallback (AUTHRA_ALLOW_CUSTODY=1) and are flagged
// in every receipt/passport as custody:"server".
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { generateEd25519, privKeyFromB64u, pubKeyFromB64u, signCanonical, b64uEncode } = require('./crypto');

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

// ---- Org root signer (server-held by design; pluggable for KMS) ----
// DEVELOPMENT ONLY: file backend. Production MUST set AUTHRA_KMS to a real
// HSM/KMS backend (aws|gcp|vault|azure). File keys are a local-dev convenience
// and MUST NOT hold production org roots.
function orgKeyPath(org_id) { return path.join(keysDir(), String(org_id).replace(/[^A-Za-z0-9_-]/g, '_') + '.orgkey.json'); }

function getOrgSigner(org_id) {
  // Future: AUTHRA_KMS=aws|gcp|vault|azure selects a remote signer. File is the default.
  const backend = process.env.AUTHRA_KMS || 'file';
  if (backend !== 'file') throw Object.assign(new Error(`KMS backend '${backend}' not configured`), { code: 'kms_unconfigured' });
  return ensureOrgKey(org_id);
}
// One-time import of pre-v2 org roots that lived inside org records.
function ensureOrgKey(org_id) {
  const p = orgKeyPath(org_id);
  let rec;
  try { rec = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch {
    let imported = null;
    try {
      const { store } = require('./store');
      const org = store.get('orgs', org_id);
      if (org && org._privX && org._privD) {
        imported = { org_id, pubkey: org.pubkey || org._privX, privX: org._privX, privD: org._privD, created_at: org.created_at || Date.now(), imported_legacy: true };
        console.warn(`[authragen] imported legacy org root for ${org_id} into ${p} — rotate to a KMS-backed key for production.`);
      }
    } catch {}
    rec = imported || (() => {
      const k = generateEd25519();
      console.warn(`[authragen] generated org root key for ${org_id} in ${p} — move to KMS/HSM for production.`);
      return { org_id, pubkey: k.pubB64u, privX: k.pubB64u, privD: k.privB64u, created_at: Date.now() };
    })();
    fs.writeFileSync(p, JSON.stringify(rec, null, 2)); restrict(p);
  }
  const priv = privKeyFromB64u(rec.privX, rec.privD);
  return {
    kind: 'org-root', org_id, pubkey: rec.pubkey,
    signBytes: (buf) => b64uEncode(crypto.sign(null, Buffer.from(buf), priv)),
    signCanonical: (obj) => signCanonical(obj, priv),
  };
}
function orgPubkey(org_id) {
  try { return JSON.parse(fs.readFileSync(orgKeyPath(org_id), 'utf8')).pubkey; }
  catch { return null; }
}

// ---- Gateway checkpoint key (signs audit checkpoints) ----
function gatewaySigner() {
  const p = path.join(keysDir(), 'gateway.json');
  let rec;
  try { rec = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch {
    const k = generateEd25519();
    rec = { pubkey: k.pubB64u, privX: k.pubB64u, privD: k.privB64u, created_at: Date.now() };
    fs.writeFileSync(p, JSON.stringify(rec, null, 2)); restrict(p);
  }
  const priv = privKeyFromB64u(rec.privX, rec.privD);
  return { pubkey: rec.pubkey, signCanonical: (obj) => signCanonical(obj, priv) };
}

// ---- API-key hashing (scrypt, per-key salt) ----
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

module.exports = { getOrgSigner, orgPubkey, gatewaySigner, hashSecret, checkSecret, newSecret };
