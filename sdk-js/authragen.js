'use strict';
// AuthraGen JS SDK v2 — self-custody by default. Zero deps (node built-ins).
// In-repo it reuses ../src/crypto + ../src/intent (pure modules); a published
// package should bundle those two files alongside this one.
const crypto = require('node:crypto');
const { canonical, sha256hex, rid, b64uEncode, b64uDecode, pubKeyFromB64u, pubKeyFromWire, verifyBytes, privKeyFromB64u } = require('../src/crypto');

function jwkPub(x) { return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' }); }
function jwkPriv(x, d) { return crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x, d }, format: 'jwk' }); }

class AuthraGen {
  constructor({ baseUrl = 'http://localhost:8787', key = null, bootstrap = null } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.key = key; this.bootstrap = bootstrap;
  }
  get headers() {
    const h = new Headers();
    h.set('Content-Type', 'application/json');
    if (this.key) h.set('Authorization', 'Bearer ' + this.key);
    if (this.bootstrap) h.set('X-Bootstrap-Token', this.bootstrap);
    return h;
  }
  async _call(path, method = 'GET', body) {
    const r = await fetch(this.baseUrl + path, { method, headers: this.headers, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok && j.decision === undefined) throw Object.assign(new Error(`AuthraGen ${method} ${path}: ${r.status} ${JSON.stringify(j)}`), { status: r.status, body: j });
    return j;
  }
  // ---- custody: agent keys are generated HERE, never on the server ----
  generateKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const pub = publicKey.export({ format: 'jwk' }); const priv = privateKey.export({ format: 'jwk' });
    return { pub: pub.x, x: pub.x, d: priv.d };
  }
  // ---- orgs & keys (admin) ----
  createOrg(name) { return this._call('/v1/orgs', 'POST', { name }); }
  async mintKey(org_id, role = 'executor', name, opts = {}) {
    const out = await this._call(`/v1/orgs/${org_id}/keys`, 'POST', { role, name, ...opts });
    if (out.key_id && out.secret && !out.credential) out.credential = `${out.key_id}.${out.secret}`;
    return out;
  }
  // ---- passports: CSR flow (self-custody). pubkey = YOUR key. ----
  // Preferred mental flow: createAgent() → createIntent() → signIntent() → authorize() → execute().
  issuePassport(org_id, name, { pubkey, kind = 'agent', parent_id = null, parent_sig = null, exp_days, custodied = false, blueprint_id = null, owner = null, sponsor = null, team = null, environment = null, purpose = null, model = null, provider = null, runtime = null, framework = null } = {}) {
    return this._call('/v1/passports', 'POST', { org_id, name, kind, parent_id, pubkey, parent_sig, exp_days, custodied, blueprint_id, owner, sponsor, team, environment, purpose, model, provider, runtime, framework });
  }
  createAgent(org_id, name, opts = {}) { return this.issuePassport(org_id, name, opts); }
  issueSubAgent(org_id, parent_id, name, opts = {}) { return this.issuePassport(org_id, name, { ...opts, kind: 'subagent', parent_id }); }
  rotatePassport(passport_id, new_pubkey) { return this._call('/v1/passports/rotate', 'POST', { passport_id, new_pubkey }); }
  setAgentStatus(passport_id, status, reason) { const id = passport_id; return this._call(`/v1/passports/${id}/status`, 'POST', { status, reason }); }
  suspendAgent(id, reason) { return this.setAgentStatus(id, 'suspended', reason); }
  quarantineAgent(id, reason) { return this.setAgentStatus(id, 'quarantined', reason); }
  createBlueprint(org_id, blueprint) { return this._call('/v1/blueprints', 'POST', { org_id, ...blueprint }); }
  listAgents(org_id, opts = {}) {
    const q = new URLSearchParams({ org_id, ...Object.fromEntries(Object.entries(opts).map(([k, v]) => [k, String(v)])) }).toString();
    return this._call(`/v1/passports?${q}`);
  }
  // ---- intents: exact-action binding, signed by the AGENT key ----
  intent({ passport_id, org_id, action, resource, params = {}, amount_cents = 0, destination = '', tool = '', aud = 'authragen', ttlMs = 60000 }) {
    const now = Date.now();
    return { v: 2, passport_id, org_id, action, resource, params, amount_cents, destination, tool, nonce: crypto.randomBytes(16).toString('hex'), iat: now, exp: now + ttlMs, aud };
  }
  createIntent(args) { return this.intent(args); }
  intentHash(intent) { return sha256hex(canonical(intent)); }
  signIntent(intent, priv) {
    const k = typeof priv === 'string' ? jwkPriv(intent && priv, priv) : null;
    const key = k || jwkPriv(priv.x, priv.d);
    return b64uEncode(crypto.sign(null, Buffer.from(canonical(intent), 'utf8'), key));
  }
  authorize(intent, intent_sig, { token_id = null, kid = null, context = {}, dry_run = false } = {}) {
    return this._call('/v1/authorize', 'POST', { intent, intent_sig, kid, token_id, context, dry_run });
  }
  dryRun(intent, intent_sig, opts = {}) { return this.authorize(intent, intent_sig, { ...opts, dry_run: true }); }
  simulatePolicy(org_id, action, resource, context = {}) { return this._call('/v1/policies/simulate', 'POST', { org_id, action, resource, context }); }
  // guard: full allow-path in one call (authorize + execute). Throws on deny.
  async guard(intent, priv, opts = {}) {
    const sig = this.signIntent(intent, priv);
    const d = await this.authorize(intent, sig, opts);
    if (d.decision === 'allow') return this.execute(d.action_token, intent);
    if (d.decision === 'step_up') return { step_up: true, ...d };
    throw Object.assign(new Error(`blocked ${intent.action} on ${intent.resource}: ${d.reasons}`), { decision: d });
  }
  execute(action_token, intent, { approval = null } = {}) {
    return this._call('/v1/execute', 'POST', { action_token, intent, approval });
  }
  approve(approval_id, approve = true, by = 'human') { return this._call(`/v1/approvals/${approval_id}`, 'POST', { approve, by }); }
  // ---- delegation: built + signed LOCALLY, registered server-side ----
  async delegate({ org_id, delegator_id, delegatorPriv, scope, resources = ['*'], constraints = {}, parent_jti = null, kid = null, subject_id = null, sub = null }) {
    const payload = { v: 2, jti: 'tkn_' + crypto.randomBytes(6).toString('hex'), org_id, sub: subject_id || sub || delegator_id, parent_jti, scope, resources, constraints, kid: kid || 'k1', iat: Date.now() };
    const key = jwkPriv(delegatorPriv.x, delegatorPriv.d);
    const h = b64uEncode(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'AR1', v: 1 }), 'utf8'));
    const p = b64uEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
    const sig = b64uEncode(crypto.sign(null, Buffer.from(h + '.' + p, 'utf8'), key));
    return this._call('/v1/delegate', 'POST', { org_id, delegator_id, payload, envelope: `AR1.${h}.${p}.${sig}` });
  }
  // ---- reads / lifecycle (role-gated server-side) ----
  revoke(type, id, reason, extra = {}) { return this._call('/v1/revoke', 'POST', { type, id, reason, ...extra }); }
  audit(org_id, limit = 100) { return this._call(`/v1/audit?org_id=${org_id}&limit=${limit}`); }
  auditVerify(org_id) { return this._call(`/v1/audit/verify?org_id=${org_id}`); }
  evidenceBundle(org_id, opts = {}) { return this._call('/v1/audit/evidence', 'POST', { org_id, ...opts }); }
  checkpoint() { return this._call('/v1/audit/checkpoint', 'POST', {}); }
  revoked(org_id, since = 0) { return this._call(`/v1/revoked?org_id=${org_id}&since=${since}`); }
  orgPubkey(org_id) { return this._call(`/v1/orgs/${org_id}/pubkey`); }
  verifyOffline(envelope, org_id) { return this._call('/v1/verify', 'POST', { envelope, org_id }); }
  // ---- offline verify (edge executors): needs ONLY the org pubkey ----
  // Returns { signature_valid, credential_valid, expiry_valid, revocation_freshness, payload, error }.
  static verifyEnvelopeOffline(envelope, orgPubB64u, { expected_aud = null, expected_intent_hash = null } = {}) {
    const out = { signature_valid: false, credential_valid: false, expiry_valid: false, revocation_freshness: 'unknown', payload: null, error: null };
    try {
      const parts = String(envelope).split('.');
      if (parts.length !== 4 || parts[0] !== 'AR1') throw new Error('not an AR1 envelope');
      const [, h, p, s] = parts;
      let header;
      try { header = JSON.parse(Buffer.from(h.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { throw new Error('token_malformed'); }
      if (header.typ !== 'AR1' || header.v !== 1 || !['EdDSA','ES256'].includes(header.alg)) throw new Error('token_malformed');
      const pub = pubKeyFromWire(orgPubB64u, header.alg);
      const ok = verifyBytes(Buffer.from(h + '.' + p, 'utf8'), s, pub, header.alg);
      if (!ok) { out.error = 'sig_invalid'; return out; }
      out.signature_valid = true;
      const payload = JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      out.payload = payload;
      if (!payload.jti || !payload.issuer || !payload.aud || !payload.iat || !payload.exp) { out.error = 'token_malformed'; return out; }
      if (payload.issuer !== 'authragen-gateway') { out.error = 'issuer_mismatch'; return out; }
      if (expected_aud && payload.aud !== expected_aud && payload.aud !== 'authragen') { out.error = 'audience_mismatch'; return out; }
      if (expected_intent_hash && payload.intent_hash !== expected_intent_hash) { out.error = 'intent_mismatch'; return out; }
      out.credential_valid = true;
      out.expiry_valid = Date.now() <= payload.exp;
      if (!out.expiry_valid) out.error = 'token_expired';
      return out;
    } catch (e) { out.error = e.message || 'sig_invalid'; return out; }
  }
  static verifyOffline(envelope, orgPubB64u, opts) { return AuthraGen.verifyEnvelopeOffline(envelope, orgPubB64u, opts); }
}
// Adapter contract: every runtime adapter MUST use exact-intent → authorize →
// single-use execute, never a legacy positional authorize/delegate flow.
// Adapters receive { baseUrl, org_id, passport_id, keypair?, key? } and MUST:
//  1. build the EXACT intent (action+resource+params+amount+destination+tool+aud),
//  2. sign locally when a keypair is present (else trusted-middleware service key),
//  3. call authorize() and branch on allow/step_up/deny,
//  4. call execute() with the SAME intent object (hash-checked, once-only).
// See adapters/*.js for conformant examples and test/conformance.js.
module.exports = { AuthraGen };
