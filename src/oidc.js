'use strict';

const crypto = require('node:crypto');

function b64uDecode(s) {
  let v = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (v.length % 4) v += '=';
  return Buffer.from(v, 'base64');
}
function jsonPart(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

function assertHttps(url, what) {
  const u = new URL(url);
  if (u.protocol !== 'https:' && process.env.NODE_ENV !== 'test') {
    throw new Error(what + ' must use https');
  }
  return u;
}
async function fetchJson(url, timeoutMs = 5000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctl.signal, headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error('OIDC metadata fetch failed: ' + r.status);
    return await r.json();
  } finally { clearTimeout(timer); }
}
function p1363ToDer(signature) {
  const raw = Buffer.from(signature);
  if (raw.length !== 64) return raw;
  const part = x => {
    let p = Buffer.from(x);
    while (p.length > 1 && p[0] === 0) p = p.subarray(1);
    if (p[0] & 0x80) p = Buffer.concat([Buffer.from([0]), p]);
    return Buffer.concat([Buffer.from([0x02, p.length]), p]);
  };
  const body = Buffer.concat([part(raw.subarray(0,32)), part(raw.subarray(32,64))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function safeKeyFromJwk(jwk) {
  if (!jwk || jwk.d || jwk.key_ops?.includes('sign')) throw new Error('OIDC JWKS contains private signing material');
  if (jwk.use && jwk.use !== 'sig') throw new Error('OIDC JWKS key is not a signing key');
  if (!['RSA','EC','OKP'].includes(jwk.kty)) throw new Error('unsupported OIDC key type');
  if (jwk.kty === 'RSA' && !['RS256','PS256'].includes(jwk.alg || 'RS256')) throw new Error('unsupported OIDC RSA key algorithm');
  if (jwk.kty === 'EC' && jwk.crv !== 'P-256') throw new Error('OIDC EC key must be P-256');
  if (jwk.kty === 'OKP' && jwk.crv !== 'Ed25519') throw new Error('OIDC OKP key must be Ed25519');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
function verifyJwt(token, jwks, { issuer, audience, nonce = null, clockSkewSec = 30 } = {}) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('OIDC token must be a compact JWT');
  const header = jsonPart(parts[0]);
  const payload = jsonPart(parts[1]);
  if (!['RS256','PS256','ES256','EdDSA'].includes(header.alg)) throw new Error('OIDC alg not allowed');
  if (!header.kid) throw new Error('OIDC token missing kid');
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid && (!k.alg || k.alg === header.alg));
  if (!jwk) throw new Error('OIDC signing key not found');
  const key = safeKeyFromJwk(jwk);
  const signing = Buffer.from(parts[0] + '.' + parts[1]);
  let sig = b64uDecode(parts[2]);
  if (header.alg === 'ES256') sig = p1363ToDer(sig);
  let ok = false;
  if (header.alg === 'EdDSA') ok = crypto.verify(null, signing, key, sig);
  else if (header.alg === 'RS256') ok = crypto.verify('sha256', signing, key, sig);
  else if (header.alg === 'PS256') ok = crypto.verify('sha256', signing, { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
  else if (header.alg === 'ES256') ok = crypto.verify('sha256', signing, key, sig);
  if (!ok) throw new Error('OIDC signature invalid');

  const now = Math.floor(Date.now()/1000);
  if (typeof payload.iss !== 'string' || payload.iss !== issuer) throw new Error('OIDC issuer mismatch');
  if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 255) throw new Error('OIDC subject invalid');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(audience)) throw new Error('OIDC audience mismatch');
  if (aud.length > 1 && payload.azp !== audience) throw new Error('OIDC azp mismatch');
  if (!Number.isInteger(payload.exp) || now > payload.exp + clockSkewSec) throw new Error('OIDC token expired');
  if (!Number.isInteger(payload.iat) || payload.iat > now + clockSkewSec) throw new Error('OIDC token iat invalid');
  if (nonce != null && payload.nonce !== nonce) throw new Error('OIDC nonce mismatch');
  return { header, claims: payload };
}

class OidcVerifier {
  constructor({ issuer, clientId, audience = clientId, roleClaim = 'roles', orgClaim = 'org_id', staticOrgId = null, roleMap = {}, defaultRole = 'reporter', clockSkewSec = 30, discovery = null, jwks = null } = {}) {
    if (!issuer || !clientId) throw new Error('OIDC issuer and clientId are required');
    const u = assertHttps(issuer, 'OIDC issuer');
    this.issuer = u.toString().replace(/\/$/, '');
    this.clientId = clientId;
    this.audience = audience || clientId;
    this.roleClaim = roleClaim;
    this.orgClaim = orgClaim;
    this.staticOrgId = staticOrgId;
    this.roleMap = roleMap;
    this.defaultRole = defaultRole;
    this.clockSkewSec = clockSkewSec;
    this.discovery = discovery;
    this.jwks = jwks;
  }
  async init() {
    const discoveryUrl = new URL('.well-known/openid-configuration', this.issuer + '/').toString();
    this.discovery = this.discovery || await fetchJson(discoveryUrl);
    if (this.discovery.issuer !== this.issuer) throw new Error('OIDC discovery issuer mismatch');
    if (!this.discovery.jwks_uri) throw new Error('OIDC discovery missing jwks_uri');
    assertHttps(this.discovery.jwks_uri, 'OIDC jwks_uri');
    this.jwks = await fetchJson(this.discovery.jwks_uri);
    if (!Array.isArray(this.jwks.keys)) throw new Error('OIDC JWKS invalid');
    this.loadedAt = Date.now();
    return this;
  }
  verify(token, opts = {}) {
    if (!this.jwks) throw new Error('OIDC verifier not initialized');
    return verifyJwt(token, this.jwks, { issuer: this.issuer, audience: this.audience, nonce: opts.nonce ?? null, clockSkewSec: this.clockSkewSec });
  }
  principal(token) {
    const { claims } = this.verify(token);
    const rawRole = claims[this.roleClaim];
    const roles = Array.isArray(rawRole) ? rawRole : (typeof rawRole === 'string' ? [rawRole] : []);
    const mapped = Object.entries(this.roleMap).find(([, accepted]) => (Array.isArray(accepted) ? accepted : [accepted]).some(x => roles.includes(x)));
    const role = mapped?.[0] || this.defaultRole;
    if (!['admin','approver','executor','reporter'].includes(role)) throw new Error('OIDC mapped role invalid');
    const orgClaim = claims[this.orgClaim];
    const org_id = this.staticOrgId || (typeof orgClaim === 'string' ? orgClaim : null);
    if (!org_id) throw new Error('OIDC identity does not map to an AuthraGen organization');
    return { id: 'oidc:' + claims.sub, org_id, role, name: claims.name || claims.preferred_username || claims.sub, subject: claims.sub, issuer: this.issuer, source: 'oidc' };
  }
}

let active = null;
let refreshTimer = null;
async function initFromEnv() {
  if (!process.env.AUTHRA_OIDC_ISSUER) return null;
  const roleMap = process.env.AUTHRA_OIDC_ROLE_MAP ? JSON.parse(process.env.AUTHRA_OIDC_ROLE_MAP) : {
    admin: ['admin','owner'],
    approver: ['approver'],
    executor: ['executor'],
    reporter: ['reporter','viewer']
  };
  active = new OidcVerifier({
    issuer: process.env.AUTHRA_OIDC_ISSUER,
    clientId: process.env.AUTHRA_OIDC_CLIENT_ID,
    audience: process.env.AUTHRA_OIDC_AUDIENCE || process.env.AUTHRA_OIDC_CLIENT_ID,
    roleClaim: process.env.AUTHRA_OIDC_ROLE_CLAIM || 'roles',
    orgClaim: process.env.AUTHRA_OIDC_ORG_CLAIM || 'org_id',
    staticOrgId: process.env.AUTHRA_OIDC_ORG_ID || null,
    roleMap,
    defaultRole: process.env.AUTHRA_OIDC_DEFAULT_ROLE || 'reporter',
    clockSkewSec: Number(process.env.AUTHRA_OIDC_CLOCK_SKEW_S || 30)
  });
  await active.init();
  clearInterval(refreshTimer);
  refreshTimer = setInterval(async () => { try { await active.init(); } catch (e) { console.warn('[authragen] OIDC JWKS refresh failed:', e.message); } }, 5 * 60 * 1000);
  refreshTimer.unref?.();
  return active;
}
function configured() { return !!active; }
function authenticate(token) { return active ? active.principal(token) : null; }
module.exports = { OidcVerifier, initFromEnv, configured, authenticate, verifyJwt, fetchJson };