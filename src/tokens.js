'use strict';
// Passports + delegation tokens v2.
//
// Custody boundary: the gateway NEVER holds agent private keys in the primary
// flow. Agents generate keys locally and submit a CSR ({pubkey}); the ORG ROOT
// (server-held, KMS-pluggable) attests the binding. Server-custodied keys
// exist only when AUTHRA_ALLOW_CUSTODY=1 (local dev) and are flagged
// custody:"server" everywhere.
// Delegations are built + signed CLIENT-SIDE by the delegator and REGISTERED
// here after signature + authority + attenuation checks.
const { rid, generateEd25519, pubKeyFromB64u, signCanonical, verifyCanonical, open, didFor: didForShort } = require('./crypto');
const { store } = require('./store');
const { globMatch } = require('./policy');
const { getOrgSigner } = require('./signer');

const MAX_DEPTH = 4;
const DEFAULT_TOKEN_TTL_S = 15 * 60;
const DEFAULT_GRACE_S = 300;

function didFor(pubB64u) { return 'did:authragen:' + String(pubB64u); } // full 43-char fingerprint
function allowCustody() { return process.env.AUTHRA_ALLOW_CUSTODY === '1'; }

const LIFECYCLE = ['draft', 'pending_approval', 'active', 'suspended', 'quarantined', 'rotating', 'expired', 'revoked'];
function isOrgLocked(org_id) {
  const org = store.get('orgs', org_id);
  return !!(org && org.locked);
}
function assertOrgUsable(org_id) {
  const org = store.get('orgs', org_id);
  if (!org) throw code('org_unknown', 'Unknown org');
  if (org.locked) throw code('org_locked', 'Organization is emergency-locked (fail-closed)');
  return org;
}

// ---------- orgs (root key lives in signer, NOT in the org record) ----------
function createOrgRecord(name) {
  if (typeof name !== 'string' || !name.trim() || name.length > 128) throw code('bad_request', 'org name required (max 128)');
  const org = { id: rid('org'), name: String(name).slice(0, 128), created_at: Date.now(), locked: false, quotas: { max_agents: 10000, max_policies: 500 } };
  getOrgSigner(org.id); // generates root (file KMS default) + warns about HSM
  store.put('orgs', org);
  return org;
}
function publicOrg(o) {
  const { ...pub } = o || {};
  return pub;
}

// ---------- blueprints (reusable agent templates) ----------
function createBlueprint({ org_id, name, description = '', policies = {}, permissions = {}, required_approvals = 0, version = 1 }) {
  assertOrgUsable(org_id);
  if (!name || typeof name !== 'string') throw code('bad_request', 'blueprint name required');
  const now = Date.now();
  const bp = {
    id: rid('bp'), org_id, name: String(name).slice(0, 128), description: String(description).slice(0, 1024),
    policies: policies || {}, permissions: permissions || {},
    required_approvals: Number(required_approvals) || 0,
    version, created_at: now, updated_at: now, status: 'active',
  };
  store.put('blueprints', bp);
  return bp;
}
function blueprintInstances(blueprint_id) {
  return store.all('passports').filter(p => p.blueprint_id === blueprint_id).length;
}
function orgPubkey(org_id) {
  const { orgPubkey } = require('./signer');
  return orgPubkey(org_id);
}

// ---------- passports ----------
function upgradeLegacy(pass) {
  if (pass.keys) return pass;
  pass.keys = { current: { kid: 'k1', pubkey: pass.pubkey, since: pass.iat }, history: [] };
  pass.grace_period_s = DEFAULT_GRACE_S;
  pass.custody = (pass._privX && pass._privD) ? 'server-legacy' : 'self';
  pass.v = pass.v || 1;
  return pass;
}
// Resolve a usable pubkey for (passport, kid): current ok; history within grace ok.
function keyFor(pass, kid) {
  pass = upgradeLegacy(pass);
  const now = Date.now();
  const cur = pass.keys.current;
  if (cur.revoked) throw code('key_revoked', `current key ${cur.kid} revoked`);
  if (!kid || kid === cur.kid) return { pubkey: cur.pubkey, kid: cur.kid, grace: false };
  const h = (pass.keys.history || []).find(x => x.kid === kid);
  if (!h) throw code('unknown_kid', `unknown key ${kid}`);
  if (h.revoked) throw code('key_revoked', `key ${kid} revoked`);
  if (now > h.until) throw code('key_expired', `key ${kid} outside grace period`);
  return { pubkey: h.pubkey, kid: h.kid, grace: true };
}
function passportStatus(pass) {
  const p = upgradeLegacy({ ...pass });
  if (p.revoked || isPassportRevoked(p.id)) return 'revoked';
  if (Date.now() > p.exp) return 'expired';
  return p.status || 'active';
}
function assertPassportUsable(pass) {
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  const p = upgradeLegacy(pass);
  assertOrgUsable(p.org_id);
  // Lifecycle: suspended/quarantined are reversible holds (fail-closed); revoked/expired are terminal.
  const st = p.status || 'active';
  if (st === 'suspended') throw code('passport_suspended', 'Passport suspended (reversible hold)');
  if (st === 'quarantined') throw code('passport_quarantined', 'Passport quarantined (reversible hold)');
  if (st === 'revoked' || p.revoked) throw code('passport_revoked', 'Passport revoked');
  if (Date.now() > p.exp) throw code('passport_expired', 'Passport expired');
  if (isPassportRevoked(p.id)) throw code('passport_revoked', 'Passport revoked (or ancestor revoked)');
  // Blueprint revocation cascades: agents from a revoked blueprint fail closed.
  if (p.blueprint_id) {
    const bp = store.get('blueprints', p.blueprint_id);
    if (bp && bp.status === 'revoked') throw code('passport_revoked', 'Agent blueprint revoked');
  }
  // issuer = org root (v2) or legacy parent/org fallback
  // last_seen is mutable telemetry and is EXCLUDED from the signed doc (else every
  // authorize would invalidate the passport signature). All other fields are covered.
  const { _privX, _privD, last_seen, ...doc } = p;
  const org = store.get('orgs', p.org_id);
  if (!org) throw code('org_unknown', 'Unknown org');
  const { pubKeyFromB64u: pub } = require('./crypto');
  if (p.v === 2 || !p.parent_id) {
    const opk = orgPubkey(p.org_id);
    if (!opk || !verifyCanonical(doc, p.signature, pub(opk))) throw code('sig_invalid', 'Passport signature invalid');
  } else {
    const parent = store.get('passports', p.parent_id);
    const issuerPub = parent ? upgradeLegacy(parent).keys.current.pubkey : orgPubkey(p.org_id);
    if (!verifyCanonical(doc, p.signature, pub(issuerPub))) throw code('sig_invalid', 'Passport signature invalid');
  }
  if (p.parent_id && p.v === 2 && p.parent_sig) {
    const parent = upgradeLegacy(store.get('passports', p.parent_id));
    if (parent && !verifyCanonical({ passport: p.id, parent: p.parent_id }, p.parent_sig, pub(parent.keys.current.pubkey)))
      throw code('sig_invalid', 'Parent countersignature invalid');
  }
}
function isPassportRevoked(id) {
  if (store.has('revocations', 'passport:' + id)) return true;
  let cur = store.get('passports', id);
  const seen = new Set();
  while (cur && cur.parent_id && !seen.has(cur.id)) {
    seen.add(cur.id);
    if (store.has('revocations', 'passport:' + cur.parent_id)) return true;
    cur = store.get('passports', cur.parent_id);
  }
  return false;
}
// Primary flow: agent supplies its OWN pubkey (CSR). Server binds, never sees privkey.
// SECURITY: issuance is an ADMIN act. Knowing an org ID is never sufficient —
// the caller must present an org admin key (enforced in server.js). Sub-agents
// additionally clamp expiry to the parent and record parent linkage.
function issuePassport({ org_id, name, kind = 'agent', parent_id = null, pubkey = null, kid = null, parent_sig = null, exp_days = 365, metadata = {}, custodied = false, blueprint_id = null, owner = null, sponsor = null, team = null, environment = 'prod', purpose = '', model = '', provider = '', runtime = '', framework = '', status = 'active' }) {
  const org = store.get('orgs', org_id);
  if (!org) throw code('org_unknown', 'Unknown org');
  assertOrgUsable(org_id);
  // Org quotas (large-fleet guard).
  const count = store.byOrg('passports', org_id).length;
  if (count >= (org.quotas?.max_agents || 10000)) throw code('quota_exceeded', 'Organization agent quota exceeded');
  let parent = null;
  if (parent_id) {
    parent = store.get('passports', parent_id);
    if (!parent || parent.org_id !== org_id) throw code('parent_unknown', 'Unknown parent passport');
    upgradeLegacy(parent);
    assertPassportUsable(parent);
    if (kind !== 'subagent') throw code('parent_mismatch', 'Children of an agent must be kind=subagent');
  }
  if (blueprint_id) {
    const bp = store.get('blueprints', blueprint_id);
    if (!bp || bp.org_id !== org_id) throw code('bad_request', 'unknown blueprint for this org');
    if (bp.status === 'revoked') throw code('passport_revoked', 'Blueprint revoked');
  }
  if (status && !LIFECYCLE.includes(status)) throw code('bad_request', 'invalid lifecycle status');
  let agentPub = pubkey, custody = 'self', privOnce = null;
  if (custodied) {
    if (!allowCustody()) throw code('custody_forbidden', 'Server-custodied keys disabled (set AUTHRA_ALLOW_CUSTODY=1 for local dev only)');
    const k = generateEd25519();
    agentPub = k.pubB64u; custody = 'server';
    privOnce = { x: k.pubB64u, d: k.privB64u }; // returned ONCE; stored only in dev
  }
  if (!agentPub) throw code('bad_request', 'pubkey required (self-custody CSR flow)');
  try { pubKeyFromB64u(agentPub); } catch { throw code('bad_request', 'invalid Ed25519 pubkey'); }
  const now = Date.now();
  let exp = now + (Number(exp_days) || 365) * 86400 * 1000;
  if (parent && exp > parent.exp) exp = parent.exp; // clamp: child never outlives parent
  const pass = {
    v: 2, id: rid('agt'), did: didFor(agentPub), org_id, parent_id, kind, name: String(name || 'agent').slice(0, 128),
    custody, keys: { current: { kid: kid || 'k1', pubkey: agentPub, since: now }, history: [] },
    grace_period_s: DEFAULT_GRACE_S, parent_sig: parent_sig || null,
    iat: now, exp, revoked: false, status: status || 'active',
    blueprint_id: blueprint_id || null,
    owner: owner ? String(owner).slice(0, 128) : null,
    sponsor: sponsor ? String(sponsor).slice(0, 128) : null,
    team: team ? String(team).slice(0, 128) : null,
    environment: String(environment || 'prod').slice(0, 64),
    purpose: String(purpose || '').slice(0, 1024),
    model: String(model || '').slice(0, 128), provider: String(provider || '').slice(0, 128),
    runtime: String(runtime || '').slice(0, 128), framework: String(framework || '').slice(0, 128),
    last_seen: null, created_at: now,
    metadata: metadata && typeof metadata === 'object' ? metadata : {},
  };
  if (custody === 'server' && privOnce) { pass._privX = privOnce.x; pass._privD = privOnce.d; }
  const signer = getOrgSigner(org_id);
  const { _privX, _privD, last_seen, ...doc } = pass;
  pass.signature = signer.signCanonical(doc);
  store.put('passports', pass);
  const pub = publicPassport(pass);
  if (privOnce) pub._privOnce = privOnce;
  return pub;
}
function publicPassport(p) { const { _privX, _privD, ...pub } = upgradeLegacy({ ...p }); return pub; }

function setPassportStatus(passport_id, status, { reversible = true } = {}) {
  const pass = upgradeLegacy(store.get('passports', passport_id));
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  if (!LIFECYCLE.includes(status)) throw code('bad_request', 'invalid lifecycle status');
  if ((pass.status === 'revoked' || pass.revoked) && status !== 'revoked') throw code('bad_request', 'revoked is terminal (issue a new passport)');
  pass.status = status;
  if (status === 'revoked') pass.revoked = true;
  const signer = getOrgSigner(pass.org_id);
  const { _privX, _privD, last_seen, ...doc } = pass;
  pass.signature = signer.signCanonical(doc);
  store.put('passports', pass);
  return publicPassport(pass);
}
function revokeKey(passport_id, kid) {
  const pass = upgradeLegacy(store.get('passports', passport_id));
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  if (pass.keys.current.kid === kid) {
    pass.keys.current.revoked = true;
  } else {
    const h = (pass.keys.history || []).find(x => x.kid === kid);
    if (!h) throw code('unknown_kid', 'unknown key ' + kid);
    h.revoked = true;
  }
  const signer = getOrgSigner(pass.org_id);
  const { _privX, _privD, last_seen, ...doc } = pass;
  pass.signature = signer.signCanonical(doc);
  store.put('passports', pass);
  return publicPassport(pass);
}
function touchLastSeen(passport_id) {
  try {
    const p = store.get('passports', passport_id);
    if (p) { p.last_seen = Date.now(); store.put('passports', p); }
  } catch {}
}
function rotatePassport(passport_id, newPubkey) {
  const pass = upgradeLegacy(store.get('passports', passport_id));
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  assertOrgUsable(pass.org_id);
  if ((pass.status || 'active') === 'revoked' || pass.revoked) throw code('passport_revoked', 'Passport revoked');
  if (['suspended', 'quarantined'].includes(pass.status)) throw code('passport_suspended', 'Passport is held (unsuspend first)');
  let nextPub = newPubkey, privOnce = null;
  if (!nextPub) {
    if (pass.custody !== 'server' || !allowCustody()) throw code('bad_request', 'rotation requires new pubkey (self-custody)');
    const k = generateEd25519();
    nextPub = k.pubB64u; privOnce = { x: k.pubB64u, d: k.privB64u };
    pass._privX = privOnce.x; pass._privD = privOnce.d;
  }
  try { pubKeyFromB64u(nextPub); } catch { throw code('bad_request', 'invalid Ed25519 pubkey'); }
  const now = Date.now();
  const cur = pass.keys.current;
  const nkid = 'k' + (parseInt(String(cur.kid).slice(1), 10) + 1 || pass.keys.history.length + 2);
  pass.keys.history.push({ kid: cur.kid, pubkey: cur.pubkey, since: cur.since, until: now + (pass.grace_period_s || DEFAULT_GRACE_S) * 1000 });
  pass.keys.current = { kid: nkid, pubkey: nextPub, since: now };
  const signer = getOrgSigner(pass.org_id);
  const { _privX, _privD, last_seen, ...doc } = pass;
  pass.signature = signer.signCanonical(doc); // re-attest binding
  store.put('passports', pass);
  const pub = publicPassport(pass);
  if (privOnce) pub._privOnce = privOnce;
  return pub;
}

// ---------- delegation (client-built, server-registered) ----------
function scopeCoveredBy(childScopes, parentScopes) {
  return (childScopes || []).every(cs => (parentScopes || []).some(ps => ps === '*' || ps === cs || globMatch(ps, cs)));
}
function resourcesCoveredBy(childRes, parentRes) {
  if (!parentRes || !parentRes.length) return true;
  if (!childRes || !childRes.length) return true;
  return childRes.every(cr => parentRes.some(pr => pr === '*' || pr === cr || globMatch(pr, cr)));
}
// Verify a token envelope against its issuer passport (kid-aware, grace-aware).
function openTokenEnvelope(tok) {
  const issuer = upgradeLegacy(store.get('passports', tok.issuer));
  if (!issuer) throw code('passport_unknown', 'Unknown token issuer');
  const { pubkey } = keyFor(issuer, tok.kid);
  const { payload } = open(tok.envelope, pubKeyFromB64u(pubkey));
  return payload;
}
function assertTokenUsable(tok) {
  if (!tok) throw code('token_unknown', 'Unknown token');
  const now = Date.now();
  assertOrgUsable(tok.org_id);
  if (now < (tok.constraints?.not_before ?? 0)) throw code('token_not_active', 'Token not yet active');
  if (now > (tok.constraints?.not_after ?? 0)) throw code('token_expired', 'Token expired');
  if (store.has('revocations', 'token:' + tok.id)) throw code('token_revoked', 'Token revoked');
  if (store.has('revocations', 'passport:' + tok.sub)) throw code('passport_revoked', 'Token subject revoked');
  let cur = tok;
  const seen = new Set();
  while (cur && cur.parent_jti && !seen.has(cur.id)) {
    seen.add(cur.id);
    if (store.has('revocations', 'token:' + cur.parent_jti)) throw code('token_revoked', 'Ancestor token revoked');
    cur = store.get('tokens', cur.parent_jti);
    if (cur && cur.org_id !== tok.org_id) throw code('parent_mismatch', 'Cross-org delegation chain');
  }
  if (cur && cur.parent_jti && seen.has(cur.id)) throw code('token_malformed', 'Delegation cycle detected');
  const sub = store.get('passports', tok.sub);
  assertPassportUsable(sub);
  const payload = openTokenEnvelope(tok);
  if (payload.jti !== tok.id) throw code('sig_invalid', 'Token id mismatch');
  if (payload.org_id !== tok.org_id) throw code('sig_invalid', 'Token org mismatch');
}
// Delegation: authority + monotonic attenuation, then register.
// Monotonicity: scope/resources/targets shrink, spend/expiry/depth never grow,
// approval requirements can only be ADDED, never removed.
function registerDelegation({ org_id, delegator_id, payload, envelope, callerIsAdmin = false }) {
  const delegator = upgradeLegacy(store.get('passports', delegator_id));
  if (!delegator || delegator.org_id !== org_id) throw code('passport_unknown', 'Unknown delegator');
  assertOrgUsable(org_id);
  assertPassportUsable(delegator);
  if (!payload || payload.jti == null) throw code('bad_request', 'token payload required');
  if (typeof payload.jti !== 'string' || !/^tkn_[0-9a-f]+$/.test(payload.jti)) throw code('bad_request', 'token jti format invalid');
  if (payload.org_id !== org_id) throw code('parent_mismatch', 'Cross-org delegation forbidden');
  if (store.has('revocations', 'token:' + payload.jti) || store.get('tokens', payload.jti))
    throw code('bad_request', 'token jti invalid or already registered');
  // signature by the DELEGATOR (kid-aware). Wrong-delegator signatures fail here.
  const { pubkey } = keyFor(delegator, payload.kid);
  const { payload: sealed } = open(envelope, pubKeyFromB64u(pubkey));
  const { canonical } = require('./crypto');
  if (canonical(sealed) !== canonical(payload)) throw code('sig_invalid', 'envelope does not match registered payload');
  const { scope = ['*'], resources = ['*'], constraints = {}, parent_jti = null } = payload;
  if (!Array.isArray(scope) || !Array.isArray(resources)) throw code('bad_request', 'scope/resources must be arrays');
  let depth = 0;
  if (parent_jti) {
    const parent = store.get('tokens', parent_jti);
    if (!parent) throw code('token_unknown', 'Unknown parent token');
    assertTokenUsable(parent);
    if (parent.org_id !== org_id) throw code('parent_mismatch', 'Parent token org mismatch (cross-org delegation forbidden)');
    // AUTHORITY: only the agent the parent token was issued to may narrow it.
    if (parent.sub !== delegator_id) throw code('delegation_not_authorized', `parent token issued to ${parent.sub}, not ${delegator_id}`);
    // Forged-parent defense: parent envelope must verify under its issuer key.
    try { openTokenEnvelope(parent); } catch (e) { throw code('sig_invalid', 'parent token signature invalid (forged parent)'); }
    if (!scopeCoveredBy(scope, parent.scope)) throw code('attenuation_violation', `scope not covered by parent`);
    const pSpend = parent.constraints?.max_spend_cents ?? Infinity;
    const cSpend = constraints.max_spend_cents ?? pSpend;
    if (typeof cSpend !== 'number' || cSpend > pSpend) throw code('attenuation_violation', 'spend exceeds parent (budget increase forbidden)');
    const pExp = parent.constraints?.not_after ?? Infinity;
    let cExp = constraints.not_after;
    if (cExp == null) cExp = Math.min(Date.now() + DEFAULT_TOKEN_TTL_S * 1000, pExp);
    if (typeof cExp !== 'number' || cExp > pExp) throw code('attenuation_violation', 'expiry exceeds parent (extension forbidden)');
    if (!resourcesCoveredBy(resources, parent.resources)) throw code('attenuation_violation', 'resources exceed parent');
    const pT = parent.constraints?.allowed_targets || [];
    const cT = constraints.allowed_targets ?? pT;
    if (!Array.isArray(cT)) throw code('bad_request', 'allowed_targets must be an array');
    if (pT.length && !cT.every(t => pT.some(pt => pt === '*' || globMatch(pt, t)))) throw code('attenuation_violation', 'targets exceed parent');
    // Approval requirements cannot be removed: parent requires_approval ⇒ child must too.
    if (parent.constraints?.require_approval && !constraints.require_approval) throw code('attenuation_violation', 'approval requirement cannot be removed');
    depth = parent.depth + 1;
    const maxD = parent.constraints?.max_depth ?? MAX_DEPTH;
    if (constraints.max_depth != null && constraints.max_depth > maxD) throw code('attenuation_violation', 'max_depth exceeds parent (depth increase forbidden)');
    if (depth > maxD) throw code('depth_exceeded', 'Delegation depth exceeded');
    payload.constraints = { ...parent.constraints, ...constraints, not_after: cExp, max_spend_cents: cSpend, allowed_targets: cT };
  } else {
    // Root delegation: you may only delegate YOUR OWN authority (or org admin may issue for anyone).
    if (payload.sub !== delegator_id && !callerIsAdmin) throw code('delegation_not_authorized', 'cannot delegate authority for another agent');
    if (payload.sub !== delegator_id && callerIsAdmin && store.get('passports', payload.sub)?.org_id !== org_id) throw code('parent_mismatch', 'Cross-org delegation forbidden');
    payload.constraints = {
      max_spend_cents: constraints.max_spend_cents ?? 10000,
      not_before: constraints.not_before ?? Date.now(),
      not_after: constraints.not_after ?? (Date.now() + DEFAULT_TOKEN_TTL_S * 1000),
      max_depth: constraints.max_depth ?? MAX_DEPTH,
      allowed_targets: constraints.allowed_targets || [],
      require_approval: !!constraints.require_approval,
    };
  }
  payload.depth = depth;
  const tok = { v: 2, id: payload.jti, ...payload, envelope, issuer: delegator_id, subject: payload.sub, parent_jti: parent_jti || null, spend_used_cents: 0, registered_at: Date.now() };
  store.put('tokens', tok);
  return tok;
}
// P0#4: scope + resources + allowed_targets ALL enforced.
function tokenCovers(tok, action, resource) {
  const scopeOk = (tok.scope || []).some(s => s === '*' || globMatch(s, action));
  if (!scopeOk) return false;
  const res = tok.resources || [];
  if (res.length && !res.some(r => r === '*' || globMatch(r, resource))) return false;
  const targets = tok.constraints?.allowed_targets || [];
  if (targets.length && !targets.some(t => t === '*' || globMatch(t, resource))) return false;
  return true;
}
function checkBudget(tok, amount) {
  if ((tok.spend_used_cents || 0) + (amount || 0) > (tok.constraints?.max_spend_cents ?? 0))
    throw code('budget_exceeded', 'Budget exceeded');
}
function debitBudget(tok, amount) { // call under mutex; sync check-and-set
  checkBudget(tok, amount);
  tok.spend_used_cents = (tok.spend_used_cents || 0) + (amount || 0);
  store.put('tokens', tok);
}
function resolveByDid(did) {
  const all = store.all('passports');
  return all.find(p => p.did === did) || all.find(p => String(p.did).startsWith(String(did))) || null;
}

function code(c, message) { const e = new Error(message); e.code = c; return e; }

module.exports = {
  createOrgRecord, publicOrg, orgPubkey, issuePassport, publicPassport, rotatePassport,
  setPassportStatus, revokeKey, touchLastSeen, passportStatus, LIFECYCLE,
  createBlueprint, blueprintInstances, isOrgLocked, assertOrgUsable,
  assertPassportUsable, isPassportRevoked, keyFor, registerDelegation, assertTokenUsable,
  openTokenEnvelope, tokenCovers, checkBudget, debitBudget, resolveByDid, didFor, MAX_DEPTH, allowCustody,
};
