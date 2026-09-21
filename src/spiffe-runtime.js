'use strict';

const fs = require('node:fs');
const { validateJwtSvid } = require('../adapters/spiffe');

let config = null;
let jwks = null;
let refreshTimer = null;

function loadConfig() {
  if (!process.env.AUTHRA_SPIFFE_AUDIENCE) return null;
  const jwksFile = process.env.AUTHRA_SPIFFE_JWKS_FILE;
  const orgId = process.env.AUTHRA_SPIFFE_ORG_ID;
  if (!jwksFile) throw new Error('AUTHRA_SPIFFE_JWKS_FILE required when SPIFFE bearer authentication is enabled');
  if (!orgId) throw new Error('AUTHRA_SPIFFE_ORG_ID required when SPIFFE bearer authentication is enabled');
  return {
    audience: process.env.AUTHRA_SPIFFE_AUDIENCE,
    orgId,
    role: process.env.AUTHRA_SPIFFE_ROLE || 'executor',
    allowedIds: process.env.AUTHRA_SPIFFE_ALLOWED_IDS ? JSON.parse(process.env.AUTHRA_SPIFFE_ALLOWED_IDS) : null,
    jwksFile
  };
}
function loadJwks() {
  if (!config) return;
  const parsed = JSON.parse(fs.readFileSync(config.jwksFile, 'utf8'));
  if (!parsed || !Array.isArray(parsed.keys)) throw new Error('SPIFFE JWT bundle must be a JWKS document');
  jwks = parsed;
}
async function initFromEnv() {
  config = loadConfig();
  if (!config) return null;
  loadJwks();
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { try { loadJwks(); } catch (e) { console.warn('[authragen] SPIFFE JWKS refresh failed:', e.message); } }, 60 * 1000);
  refreshTimer.unref?.();
  return config;
}
function configured() { return !!config && !!jwks; }
function authenticate(token) {
  if (!configured()) return null;
  const out = validateJwtSvid(token, { jwks, expectedAudience: config.audience });
  if (config.allowedIds && !config.allowedIds.includes(out.spiffe_id)) throw new Error('SPIFFE ID not allowlisted');
  return {
    id: 'spiffe:' + out.spiffe_id,
    org_id: config.orgId || null,
    role: config.role,
    name: out.spiffe_id,
    subject: out.spiffe_id,
    issuer: out.trust_domain,
    source: 'spiffe'
  };
}
module.exports = { initFromEnv, configured, authenticate };
