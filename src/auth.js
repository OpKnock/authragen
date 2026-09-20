'use strict';
// Authentication + RBAC for management APIs.
//
// Bootstrap (first-run) token -> org creation -> org admin key -> role keys.
// Roles: admin > approver > executor > reporter. Checked per-org.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { store } = require('./store');
const { hashSecret, checkSecret, newSecret } = require('./signer');

function dataDir() { return process.env.AUTHRA_DATA || require('./store').DATA_DIR; }
function BOOT_FILE() { return path.join(dataDir(), 'bootstrap.json'); }

function bootstrapToken() {
  // Valid only while zero orgs exist. Printed once at boot.
  if (store.all('orgs').length > 0) return null;
  try {
    const rec = JSON.parse(fs.readFileSync(BOOT_FILE(), 'utf8'));
    return rec.printed ? null : rec; // already printed; keep secret server-side only
  } catch {
    const tok = 'ar_boot_' + crypto.randomBytes(24).toString('hex');
    try { fs.mkdirSync(dataDir(), { recursive: true }); } catch {}
    fs.writeFileSync(BOOT_FILE(), JSON.stringify({ hash: hashSecret(tok), created_at: Date.now(), printed: false }));
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
  if (store.all('orgs').length > 0) return false;
  try {
    const rec = JSON.parse(fs.readFileSync(BOOT_FILE(), 'utf8'));
    return tok && checkSecret(tok, rec.hash);
  } catch { return false; }
}
function consumeBootstrap() { try { fs.unlinkSync(BOOT_FILE()); } catch {} try { fs.unlinkSync(path.join(dataDir(), 'bootstrap.token')); } catch {} }

// ---- org API keys (scoped, least-privilege, rotatable, revocable) ----
// Secrets are shown ONCE at mint/rotate time and never returned again
// (GET strips hashes). Supports expiry (expires_at) and rotation.
const ROLES = ['admin', 'approver', 'executor', 'reporter'];
const RANK = { reporter: 1, executor: 2, approver: 3, admin: 4 };
const SESSION_TTL_MS = Number(process.env.AUTHRA_SESSION_TTL_MS || 12 * 3600 * 1000); // 12h default

function mintKey(org_id, role, name, { expires_in_ms = null } = {}) {
  if (!RANK[role]) throw Object.assign(new Error('bad role'), { code: 'bad_request' });
  const org = store.get('orgs', org_id);
  if (!org) throw Object.assign(new Error('unknown org'), { code: 'org_unknown' });
  if (org.locked) throw Object.assign(new Error('org locked'), { code: 'org_locked' });
  const id = 'ak_' + crypto.randomBytes(6).toString('hex');
  const secret = newSecret('sk');
  const now = Date.now();
  const rec = {
    id, org_id, role, name: String(name || role).slice(0, 128),
    hash: hashSecret(id + '.' + secret), created_at: now, revoked: false,
    expires_at: expires_in_ms ? now + expires_in_ms : (now + SESSION_TTL_MS),
    last_used: null, rotated_from: null,
  };
  store.put('apikeys', rec);
  // Secret shown ONCE — never persisted in plaintext, never returned again.
  return { key_id: id, secret: id + '.' + secret, org_id, role, name: rec.name, expires_at: rec.expires_at };
}
function rotateKey(key_id) {
  const rec = store.get('apikeys', key_id);
  if (!rec) throw Object.assign(new Error('unknown key'), { code: 'bad_request' });
  const secret = newSecret('sk');
  const now = Date.now();
  const next = {
    id: 'ak_' + crypto.randomBytes(6).toString('hex'), org_id: rec.org_id, role: rec.role,
    name: rec.name, hash: hashSecret(rec.id + '.' + secret), created_at: now, revoked: false,
    expires_at: now + SESSION_TTL_MS, last_used: null, rotated_from: rec.id,
  };
  // Old key revoked deterministically (grace-free for service keys — rotate callers must swap).
  rec.revoked = true;
  store.put('apikeys', rec);
  try { store.put('revocations', { id: 'apikey:' + rec.id, type: 'apikey', target: rec.id, reason: 'rotated', at: Date.now() }); } catch {}
  store.put('apikeys', next);
  return { key_id: next.id, secret: next.id + '.' + secret, org_id: next.org_id, role: next.role, name: next.name, expires_at: next.expires_at };
}
function lookupKey(bearer) {
  if (!bearer) return null;
  const id = String(bearer).split('.')[0];
  if (!/^ak_[0-9a-f]+$/.test(id)) return null;
  const rec = store.get('apikeys', id);
  if (!rec || rec.revoked) return null;
  if (store.has('revocations', 'apikey:' + id)) return null;
  if (rec.expires_at && Date.now() > rec.expires_at) return null; // session timeout
  if (!checkSecret(bearer, rec.hash)) return null;
  return rec;
}
function touchKey(id) {
  try { const r = store.get('apikeys', id); if (r) { r.last_used = Date.now(); store.put('apikeys', r); } } catch {}
}
// required: minimum role. orgId: the org being acted upon (must match key's org).
// Cross-org access returns generic forbidden WITHOUT revealing whether the target exists.
function requireRole(key, orgId, minRole) {
  if (!key) throw Object.assign(new Error('missing credentials'), { code: 'unauthorized' });
  if (!orgId || key.org_id !== orgId) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
  const org = store.get('orgs', orgId);
  if (org && org.locked) throw Object.assign(new Error('org locked'), { code: 'org_locked' });
  if ((RANK[key.role] || 0) < (RANK[minRole] || 99)) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
  touchKey(key.id);
  return true;
}
function bearerOf(req) {
  // Only Authorization: Bearer <key> is accepted. Bearer material in URLs/query
  // strings is rejected by policy (see server verify POST; GET verify is legacy
  // and rate-limited, never logged).
  const h = req.headers.authorization || req.headers.Authorization || '';
  if (typeof h !== 'string') return null;
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}

module.exports = { bootstrapToken, markBootstrapPrinted, checkBootstrap, consumeBootstrap, mintKey, rotateKey, lookupKey, requireRole, bearerOf, ROLES, SESSION_TTL_MS };
