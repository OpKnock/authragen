'use strict';
// Exact-action binding ("intent") + single-use action tokens + approval credentials.
//
// The agent NEVER gets authority from self-reported context. It signs an
// intent describing the EXACT operation; the gateway authorizes that hash;
// the executor re-checks the real operation against the same hash.
// Verification of action tokens / approvals needs ONLY the org public key,
// so edge executors can verify offline (revocation freshness via /v1/revoked).
const crypto = require('node:crypto');
const { canonical, sha256hex, rid, b64uJsonEncode, b64uJsonDecode, b64uDecode, pubKeyFromB64u } = require('./crypto');

const INTENT_TTL_S = Number(process.env.AUTHRA_INTENT_TTL_S || 120);          // max intent lifetime (replay window cap)
const ACTION_TOKEN_TTL_S = Number(process.env.AUTHRA_ACTION_TTL_S || 120);    // action tokens are minutes-lived, single-use
const APPROVAL_TTL_S = Number(process.env.AUTHRA_APPROVAL_TTL_S || 900);      // approval credentials (15m default)
const CLOCK_SKEW_S = Number(process.env.AUTHRA_CLOCK_SKEW_S || 30);           // tolerated clock skew
const PROTOCOL_VERSION = 2;

function normStr(v, name, { max = 512, allowEmpty = true } = {}) {
  if (v == null) {
    if (allowEmpty) return '';
    throw code('bad_intent', `${name} required`);
  }
  if (typeof v !== 'string') throw code('bad_intent', `${name} must be a string (no numeric coercion)`);
  if (v.length > max) throw code('bad_intent', `${name} too long (max ${max})`);
  // Reject ambiguous Unicode: control chars, zero-width, bidi overrides, homoglyph tricks.
  // NFC-normalize to a single canonical representation.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/.test(v)) throw code('bad_intent', `${name} contains disallowed Unicode/control characters`);
  return v.normalize('NFC');
}
function normResource(v) {
  const s = normStr(v, 'resource', { max: 1024, allowEmpty: false });
  // Path/URL normalization: collapse duplicate slashes, strip trailing slash (except root),
  // reject ".." traversal and backslashes to prevent equivalent-but-different representations.
  if (s.includes('\\') || /(^|\/)\.\.(\/|$)/.test(s)) throw code('bad_intent', 'resource contains illegal path traversal');
  return s.replace(/\/{2,}/g, '/').replace(/(.+)\/$/, '$1');
}
function normAmount(v) {
  if (v == null) return 0;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 9007199254740991) throw code('bad_intent', 'amount_cents must be a non-negative safe integer (no strings/floats/NaN/Infinity)');
  return v;
}
function normParams(v) {
  if (v == null) return {};
  if (typeof v !== 'object' || Array.isArray(v)) throw code('bad_intent', 'params must be an object');
  const raw = JSON.stringify(v);
  if (raw.length > 16 * 1024) throw code('bad_intent', 'params too large (max 16KB)');
  // Reject non-finite numbers anywhere in params (JSON.stringify turns them to null — forbid).
  const seen = JSON.stringify(v, (k, val) => {
    if (typeof val === 'number' && !Number.isFinite(val)) throw code('bad_intent', 'params contains non-finite number');
    if (typeof val === 'string' && val.length > 4096) throw code('bad_intent', 'params string value too long');
    return val;
  });
  void seen;
  // Deep NFC-normalize string leaves for deterministic hashing.
  const norm = (x) => {
    if (typeof x === 'string') {
      // eslint-disable-next-line no-control-regex
      if (/[\u0000-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/.test(x)) throw code('bad_intent', 'params contains disallowed Unicode');
      return x.normalize('NFC');
    }
    if (Array.isArray(x)) {
      if (x.length > 256) throw code('bad_intent', 'params array too long');
      return x.map(norm);
    }
    if (x && typeof x === 'object') {
      const keys = Object.keys(x);
      if (keys.length > 64) throw code('bad_intent', 'params object too large');
      const o = {};
      for (const k of keys) {
        if (typeof k !== 'string' || k.length > 128) throw code('bad_intent', 'params key invalid');
        o[k.normalize('NFC')] = norm(x[k]);
      }
      return o;
    }
    return x;
  };
  return norm(v);
}

function canonicalIntent(i) {
  const src = i || {};
  return {
    v: PROTOCOL_VERSION,
    passport_id: normStr(src.passport_id, 'passport_id', { max: 128, allowEmpty: false }),
    org_id: normStr(src.org_id, 'org_id', { max: 128, allowEmpty: false }),
    action: normStr(src.action, 'action', { max: 256, allowEmpty: false }),
    resource: normResource(src.resource),
    params: normParams(src.params),
    amount_cents: normAmount(src.amount_cents),
    destination: normStr(src.destination ?? '', 'destination', { max: 1024 }),
    tool: normStr(src.tool ?? '', 'tool', { max: 256 }),
    nonce: normStr(src.nonce, 'nonce', { max: 256, allowEmpty: false }),
    iat: src.iat, exp: src.exp,
    // Audience binding: exact service/tool/org the credential is FOR.
    // String form "authragen" = legacy default; object/URI form binds to a specific
    // service (e.g. "mcp:payments-svc", "https://api.example.com").
    aud: src.aud == null ? 'authragen' : (typeof src.aud === 'string' ? normStr(src.aud, 'aud', { max: 512, allowEmpty: false }) : (() => { throw code('bad_intent', 'aud must be a string'); })()),
  };
}
function intentHash(intent) { return sha256hex(canonical(intent)); }

function checkIntentShape(raw) {
  let i;
  try { i = canonicalIntent(raw || {}); }
  catch (e) { if (e.code) throw e; throw code('bad_intent', 'malformed intent: ' + e.message); }
  if (typeof i.iat !== 'number' || typeof i.exp !== 'number' || !Number.isFinite(i.iat) || !Number.isFinite(i.exp)) throw code('bad_intent', 'intent needs numeric iat + exp (no coercion)');
  if (!Number.isInteger(i.iat) || !Number.isInteger(i.exp)) throw code('bad_intent', 'iat/exp must be integer ms');
  if (String(i.nonce).length < 16) throw code('bad_intent', 'intent needs a 16+ char nonce');
  if (!/^[A-Za-z0-9:_\-./]+$/.test(String(i.nonce))) throw code('bad_intent', 'nonce charset invalid (alphanumeric plus :_-. /)');
  const now = Date.now();
  if (i.exp <= now) throw code('intent_expired', 'intent expired');
  if (i.exp - i.iat > INTENT_TTL_S * 1000) throw code('bad_intent', `intent lifetime exceeds ${INTENT_TTL_S}s`);
  if (i.iat - now > CLOCK_SKEW_S * 1000) throw code('bad_intent', 'intent iat is in the future (clock skew)');
  if (now - i.iat > INTENT_TTL_S * 1000) throw code('bad_intent', 'intent iat outside window');
  if (!/^agt_[0-9a-f]+$/.test(i.passport_id) && !/^agt_/.test(i.passport_id)) throw code('bad_intent', 'passport_id format invalid');
  if (!/^org_[0-9a-f]+$/.test(i.org_id) && !/^org_/.test(i.org_id)) throw code('bad_intent', 'org_id format invalid');
  return i;
}
// Agent-signed intent: sig over canonical(intent) with the PASSPORT key.
function verifyAgentIntent(intent, sigB64u, passportPubB64u) {
  const msg = Buffer.from(canonical(intent), 'utf8');
  const ok = crypto.verify(null, msg, pubKeyFromB64u(passportPubB64u), b64uDecode(sigB64u));
  if (!ok) throw code('sig_invalid', 'intent signature invalid');
  return true;
}

// ---- org-sealed envelopes (gateway-issued; verify with org pubkey only) ----
function sealWith(privSignFn, payload) {
  const header = { alg: 'EdDSA', typ: 'AR1', v: 1 };
  const h = b64uJsonEncode(header), p = b64uJsonEncode(payload);
  const sig = privSignFn(Buffer.from(h + '.' + p, 'utf8'));
  return `AR1.${h}.${p}.${sig}`;
}
function openWithOrgKey(envelope, orgPubB64u) {
  const parts = String(envelope || '').split('.');
  if (parts.length !== 4 || parts[0] !== 'AR1') throw code('token_malformed', 'not an AR1 envelope');
  const [, h, p, s] = parts;
  let header, payload;
  try { header = b64uJsonDecode(h); payload = b64uJsonDecode(p); }
  catch { throw code('token_malformed', 'envelope encoding invalid'); }
  // Algorithm-confusion defense: only EdDSA/AR1 envelopes are accepted. The `alg`
  // header is NOT trusted for key selection — verification always uses the org
  // Ed25519 root. Any other alg (none/HS256/RS256) is rejected fail-closed.
  if (header.alg !== 'EdDSA' || header.typ !== 'AR1') throw code('token_malformed', 'unsupported envelope alg/typ (algorithm confusion rejected)');
  const ok = crypto.verify(null, Buffer.from(h + '.' + p, 'utf8'), pubKeyFromB64u(orgPubB64u), b64uDecode(s));
  if (!ok) throw code('sig_invalid', 'envelope signature invalid');
  return { header, payload };
}
function checkEnvelopeShape(payload, { kinds = ['action', 'approval'] } = {}) {
  if (!payload || typeof payload !== 'object') throw code('token_malformed', 'envelope payload must be an object');
  if (payload.v !== PROTOCOL_VERSION && payload.v !== 1) throw code('token_malformed', `unsupported protocol version (got ${payload.v}, want ${PROTOCOL_VERSION})`);
  if (!kinds.includes(payload.kind)) throw code('token_malformed', `unexpected credential kind (got ${payload.kind})`);
  for (const f of ['jti', 'org_id', 'iat', 'exp', 'issuer', 'aud']) {
    if (payload.kind === 'approval' && f === 'jti') continue; // approvals use approval_id as jti
    if (payload[f] == null || payload[f] === '') throw code('token_malformed', `credential missing ${f}`);
  }
  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') throw code('token_malformed', 'iat/exp must be numbers');
  return true;
}
function buildActionToken({ orgSigner, org_id, sub, intent_hash, action, resource, amount_cents, requires_approval, token_jti = null, aud = 'authragen', kid = null }) {
  const now = Date.now();
  const payload = {
    v: PROTOCOL_VERSION, kind: 'action', jti: rid('att'), kid: kid || undefined,
    org_id, sub, intent_hash, action, resource,
    amount_cents: amount_cents || 0, requires_approval: !!requires_approval, token_jti,
    aud: aud || 'authragen',
    max_uses: 1, iat: now, exp: now + ACTION_TOKEN_TTL_S * 1000, issuer: 'authragen-gateway',
    sub_kind: 'agent',
  };
  return { jti: payload.jti, envelope: sealWith(orgSigner.signBytes, payload), payload };
}
function buildApproval({ orgSigner, approval_id, org_id, passport_id, intent_hash, action, resource, by, by_role = 'approver', by_key_id = null, action_jti = null, aud = 'authragen' }) {
  const now = Date.now();
  const payload = {
    v: PROTOCOL_VERSION, kind: 'approval', approval_id, jti: approval_id,
    org_id, passport_id, sub: passport_id, intent_hash, action, resource,
    action_jti: action_jti || null,
    decision: 'approved', by, by_role, by_key_id, at: now, exp: now + APPROVAL_TTL_S * 1000,
    aud: aud || 'authragen', issuer: 'authragen-gateway',
  };
  return { envelope: sealWith(orgSigner.signBytes, payload), payload };
}

const SIDE_EFFECT = [/^payments\./, /^admin\./, /^external\.send/, /^code\.exec/, /^data\.write/];
function isSideEffect(action) { return SIDE_EFFECT.some(re => re.test(String(action))); }

function code(c, message) { const e = new Error(message); e.code = c; return e; }

// Pure offline verifier: validates signatures, structure, issuer, audience,
// expiry, key id presence and intent binding WITHOUT contacting the control plane.
// Returns separate fields: signature_valid, credential_valid, expiry_valid,
// revocation_freshness ('unknown' offline unless a feed is supplied).
// Pass { expected_aud } to enforce audience binding; pass { revocationSet, now }
// for callers that HAVE a fresh feed.
function verifyOffline(envelope, orgPubB64u, { expected_aud = null, revocationSet = null, now = Date.now(), expected_intent_hash = null } = {}) {
  const out = { signature_valid: false, credential_valid: false, expiry_valid: false, revocation_freshness: 'unknown', payload: null, error: null };
  try {
    const { payload } = openWithOrgKey(envelope, orgPubB64u);
    out.payload = payload;
    out.signature_valid = true;
    try { checkEnvelopeShape(payload); out.credential_valid = true; }
    catch (e) { out.error = e.code || 'token_malformed'; return out; }
    if (payload.issuer !== 'authragen-gateway') { out.error = 'issuer_mismatch'; out.credential_valid = false; return out; }
    if (expected_aud && payload.aud !== expected_aud && payload.aud !== 'authragen') { out.error = 'audience_mismatch'; out.credential_valid = false; return out; }
    if (expected_intent_hash && payload.intent_hash !== expected_intent_hash) { out.error = 'intent_mismatch'; out.credential_valid = false; return out; }
    out.expiry_valid = now <= payload.exp && now >= (payload.iat - CLOCK_SKEW_S * 1000);
    if (!out.expiry_valid) out.error = 'token_expired';
    if (revocationSet) {
      const revoked = revocationSet.has('action:' + payload.jti) || (payload.token_jti && revocationSet.has('token:' + payload.token_jti));
      out.revocation_freshness = revoked ? 'revoked' : 'fresh';
      if (revoked) { out.error = 'token_revoked'; }
    }
    return out;
  } catch (e) {
    out.error = e.code || 'sig_invalid';
    return out;
  }
}

module.exports = { canonicalIntent, intentHash, checkIntentShape, verifyAgentIntent, sealWith, openWithOrgKey, checkEnvelopeShape, buildActionToken, buildApproval, verifyOffline, isSideEffect, INTENT_TTL_S, ACTION_TOKEN_TTL_S, APPROVAL_TTL_S, CLOCK_SKEW_S, PROTOCOL_VERSION };
