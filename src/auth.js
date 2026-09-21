'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { getStore } = require('./store');
const { hashSecret, checkSecret, newSecret } = require('./signer');

function dataDir() { return process.env.AUTHRA_DATA || path.join(__dirname, '..', 'data'); }
function BOOT_FILE() { return path.join(dataDir(), 'bootstrap.json'); }

function _store() { return getStore(); }

function bootstrapToken() {
  if (_store().all('orgs').length > 0) return null;
  try {
    const rec = JSON.parse(fs.readFileSync(BOOT_FILE(), 'utf8'));
    return rec.printed ? null : rec;
  } catch {
    const tok = 'ar_boot_' + crypto.randomBytes(24).toString('hex');
    try { fs.mkdirSync(dataDir(), { recursive: true }); } catch {}
    fs.writeFileSync(BOOT_FILE(), JSON.stringify({ hash: hashSecret(tok), created_at: Date.now(), printed: false }));
    fs.writeFileSync(path.join(dataDir(), 'bootstrap.token'), tok + '\n', { mode: 0o600 });
    return { fresh: tok };
  }
}
function markBootstrapPrinted() {
  try {
    const rec = JSON.parse(fs.readFileSync(BOOT_FILE(), 'utf8'));
    rec.printed = true; fs.writeFileSync(BOOT_FILE(), JSON.stringify(rec));
  } catch {}
}
function checkBootstrap(tok) {
  if (_store().all('orgs').length > 0) return false;
  try {
    const rec = JSON.parse(fs.readFileSync(BOOT_FILE(), 'utf8'));
    return tok && checkSecret(tok, rec.hash);
  } catch { return false; }
}
function consumeBootstrap() { try { fs.unlinkSync(BOOT_FILE()); } catch {} try { fs.unlinkSync(path.join(dataDir(), 'bootstrap.token')); } catch {} }

const ROLES = ['admin', 'approver', 'executor', 'reporter'];
const RANK = { reporter: 1, executor: 2, approver: 3, admin: 4 };
const SESSION_TTL_MS = Number(process.env.AUTHRA_SESSION_TTL_MS || 12 * 3600 * 1000);

function mintKey(org_id, role, name, { expires_in_ms = SESSION_TTL_MS } = {}) {
  if (!ROLES.includes(role)) throw Object.assign(new Error('invalid role'), { code: 'bad_request' });
  const secret = newSecret('sk');
  const key_id = 'ak_' + crypto.randomBytes(8).toString('hex');
  const key = { id: key_id, key_id, org_id, role, name, secret_hash: hashSecret(secret), expires_at: expires_in_ms === null ? null : Date.now() + Number(expires_in_ms), last_used: null, revoked: false, created_at: Date.now() };
  _store().put('apikeys', key);
  return { key_id, secret, credential: `${key_id}.${secret}`, role, org_id, expires_at: key.expires_at };
}
function rotateKey(key_id) {
  const old = _store().get('apikeys', key_id);
  if (!old) throw Object.assign(new Error('unknown key'), { code: 'bad_request' });
  const secret = newSecret('sk');
  const newKeyId = 'ak_' + crypto.randomBytes(8).toString('hex');
  const newKey = { ...old, id: newKeyId, key_id: newKeyId, secret_hash: hashSecret(secret), revoked: false, created_at: Date.now() };
  old.revoked = true; _store().put('apikeys', old);
  _store().put('apikeys', newKey);
  return { key_id: newKey.key_id, secret, credential: `${newKey.key_id}.${secret}`, role: newKey.role, org_id: newKey.org_id, expires_at: newKey.expires_at };
}
function lookupKey(token) {
  if (!token) return null;
  const idx = token.indexOf('.');
  if (idx === -1) return null;
  const key_id = token.slice(0, idx);
  const secret = token.slice(idx + 1);
  const store = _store();
  const key = store.get('apikeys', key_id);
  if (!key || key.revoked) return null;
  if (key.expires_at && Date.now() > key.expires_at) return null;
  const valid = checkSecret(secret, key.secret_hash);
  if (!valid) return null;
  key.last_used = Date.now(); store.put('apikeys', key);
  return { id: key.key_id, org_id: key.org_id, role: key.role, name: key.name };
}
function requireRole(key, org_id, minRole) {
  if (!key) throw Object.assign(new Error('missing credentials'), { code: 'unauthorized' });
  if (key.org_id !== org_id) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
  if ((RANK[key.role] || 0) < (RANK[minRole] || 0)) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
}
function allowCustody() { return process.env.AUTHRA_ALLOW_CUSTODY === '1'; }

function bearerOf(req) {
  const auth = req.headers?.authorization || req.headers?.Authorization;
  if (!auth || typeof auth !== 'string') return null;
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1];
}

module.exports = { bootstrapToken, markBootstrapPrinted, checkBootstrap, consumeBootstrap, mintKey, rotateKey, lookupKey, requireRole, allowCustody, bearerOf, ROLES, RANK, SESSION_TTL_MS };