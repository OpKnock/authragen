'use strict';
const { rid, generateEd25519, pubKeyFromB64u, signCanonical, verifyCanonical, open, didFor: didForShort } = require('./crypto');
const { getStore } = require('./store');
const { globMatch } = require('./policy');
const { getOrgSigner } = require('./signer');

function _store() { return getStore(); }

const MAX_DEPTH = 4;
const DEFAULT_TOKEN_TTL_S = 15 * 60;
const DEFAULT_GRACE_S = 300;

function didFor(pubB64u) { return 'did:authragen:' + String(pubB64u); }
function allowCustody() { return process.env.AUTHRA_ALLOW_CUSTODY === '1'; }

const LIFECYCLE = ['draft', 'pending_approval', 'active', 'suspended', 'quarantined', 'rotating', 'expired', 'revoked'];
function isOrgLocked(org_id) {
  const org = _store().get('orgs', org_id);
  return !!(org && org.locked);
}
function assertOrgUsable(org_id) {
  const org = _store().get('orgs', org_id);
  if (!org) throw code('org_unknown', 'Unknown org');
  if (org.locked) throw code('org_locked', 'Organization is emergency-locked (fail-closed)');
  return org;
}

function createOrgRecord(name) {
  if (typeof name !== 'string' || !name.trim() || name.length > 128) throw code('bad_request', 'org name required (max 128)');
  const org = { id: rid('org'), name: String(name).slice(0, 128), created_at: Date.now(), locked: false, quotas: { max_agents: 10000, max_policies: 500 } };
  getOrgSigner(org.id);
  _store().put('orgs', org);
  return org;
}
function publicOrg(o) {
  const { ...pub } = o || {};
  return pub;
}

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
  _store().put('blueprints', bp);
  return bp;
}
function blueprintInstances(blueprint_id) {
  return _store().all('passports').filter(p => p.blueprint_id === blueprint_id).length;
}
function orgPubkey(org_id) {
  const { orgPubkey } = require('./signer');
  return orgPubkey(org_id);
}

function upgradeLegacy(pass) {
  if (pass.keys) return pass;
  pass.keys = { current: { kid: 'k1', pubkey: pass.pubkey, since: pass.iat }, history: [] };
  pass.grace_period_s = DEFAULT_GRACE_S;
  pass.custody = (pass._privX && pass._privD) ? 'server-legacy' : 'self';
  pass.v = pass.v || 1;
  return pass;
}
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
  if (isOrgLocked(p.org_id)) throw code('org_locked', 'Organization emergency-locked');
  if (p.revoked || isPassportRevoked(p.id)) throw code('passport_revoked', 'Passport revoked');
  if (Date.now() > p.exp) throw code('passport_expired', 'Passport expired');
  if (p.status === 'suspended') throw code('passport_suspended', 'Passport suspended');
  if (p.status === 'quarantined') throw code('passport_quarantined', 'Passport quarantined');
}

function code(name, msg) { const e = new Error(msg); e.code = name; return e; }

function isPassportRevoked(passport_id) {
  return _store().has('revocations', 'passport:' + passport_id);
}

function issuePassport({ org_id, name, kind = 'agent', pubkey, blueprint_id = null, owner = null, sponsor = null, team = null, environment = 'production', purpose = '', model = null, provider = null, runtime = null, framework = null, custody = 'self', custodied = false, parent_id = null, grace_period_s = DEFAULT_GRACE_S }) {
  assertOrgUsable(org_id);
  const isServerCustody = custody === 'server' || custodied === true;
  if (isServerCustody && !allowCustody()) throw code('custody_forbidden', 'server custody disabled (set AUTHRA_ALLOW_CUSTODY=1 to enable)');
  if (!isServerCustody && !pubkey) throw code('bad_request', 'pubkey required');
  if (parent_id) {
    const parent = _store().get('passports', parent_id);
    if (!parent || parent.org_id !== org_id) throw code('bad_request', 'parent passport not in this org');
    if (parent.status === 'revoked' || parent.status === 'suspended' || parent.status === 'quarantined') throw code('bad_request', 'parent passport not usable');
  }
  const kid = 'k1';
  const now = Date.now();
  let finalPubkey = pubkey;
  if (isServerCustody) {
    const kp = generateEd25519();
    finalPubkey = kp.pub;
    // In a real implementation, the private key would be securely stored/returned
    // For now, we just generate it server-side (dev only)
  }
  const pass = {
    v: 2, id: rid('agt'), org_id, kind, name, custody: isServerCustody ? 'server' : 'self',
    parent_id,
    blueprint_id,
    owner, sponsor, team, environment, purpose, model, provider, runtime, framework,
    did: didFor(finalPubkey),
    keys: { current: { kid, pubkey: finalPubkey, since: now }, history: [] },
    grace_period_s, status: 'active', iat: now, exp: 0,
    signature: null
  };
  const signer = getOrgSigner(org_id);
  const doc = { ...pass, signature: undefined };
  pass.signature = signer.signCanonical(doc);
  _store().put('passports', pass);
  if (blueprint_id) {
    const bp = _store().get('blueprints', blueprint_id);
    if (bp) { bp.instance_count = (bp.instance_count || 0) + 1; bp.updated_at = Date.now(); _store().put('blueprints', bp); }
  }
  return pass;
}
function publicPassport(p) { const { ...pub } = upgradeLegacy({ ...p }); delete pub._privX; delete pub._privD; return pub; }
function rotatePassport(passport_id, new_pubkey) {
  const pass = _store().get('passports', passport_id);
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  const cur = pass.keys.current;
  pass.keys.history = pass.keys.history || [];
  pass.keys.history.push({ kid: cur.kid, pubkey: cur.pubkey, since: cur.since, until: Date.now() + pass.grace_period_s, revoked: false });
  pass.keys.current = { kid: 'k' + (pass.keys.history.length + 1), pubkey: new_pubkey, since: Date.now() };
  pass.updated_at = Date.now();
  const signer = getOrgSigner(pass.org_id);
  const doc = { ...pass, signature: undefined };
  pass.signature = signer.signCanonical(doc);
  _store().put('passports', pass);
  return pass;
}
function revokeKey(passport_id, kid) {
  const pass = _store().get('passports', passport_id);
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  const history = pass.keys.history || [];
  const idx = history.findIndex(k => k.kid === kid);
  if (idx >= 0) {
    history[idx] = { ...history[idx], revoked: true, until: Date.now() };
    _store().put('passports', pass);
    return pass;
  }
  if (pass.keys.current?.kid === kid) {
    pass.keys.current = { ...pass.keys.current, revoked: true };
    _store().put('passports', pass);
    return pass;
  }
  throw code('bad_request', 'kid not found');
}
function setPassportStatus(id, status) {
  if (!LIFECYCLE.includes(status)) throw code('bad_request', 'invalid status');
  const pass = _store().get('passports', id);
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  pass.status = status;
  pass.updated_at = Date.now();
  const signer = getOrgSigner(pass.org_id);
  const doc = { ...pass, signature: undefined };
  pass.signature = signer.signCanonical(doc);
  _store().put('passports', pass);
  return pass;
}
function touchLastSeen(id) {
  const pass = _store().get('passports', id);
  if (pass) { pass.last_seen = Date.now(); _store().put('passports', pass); }
}

function registerDelegation({ org_id, delegator_id, payload, envelope, callerIsAdmin = false }) {
  if (!org_id || !delegator_id || !payload || !envelope) throw code('bad_request', 'org_id, delegator_id, payload, envelope required');
  assertOrgUsable(org_id);
  const parentDelegator = _store().get('passports', delegator_id);
  if (!parentDelegator || parentDelegator.org_id !== org_id) throw code('forbidden', 'delegator not in this org');
  assertPassportUsable(parentDelegator);
  const { header } = open(envelope);
  if (!header || header.alg !== 'EdDSA') throw code('bad_request', 'invalid delegation signature');
  const { openWithOrgKey } = require('./intent');
  const { payload: verified } = openWithOrgKey(envelope, orgPubkey(org_id));
  if (!verified.sub || !verified.jti) throw code('bad_request', 'delegation payload missing sub/jti');
  const subject = verified.sub;
  const subjectPassport = _store().get('passports', subject);
  if (!subjectPassport || subjectPassport.org_id !== org_id) throw code('bad_request', 'subject passport not in this org');
  const parentJti = payload.parent_jti || null;
  if (parentJti) {
    const parentToken = _store().get('tokens', parentJti);
    if (!parentToken || parentToken.org_id !== org_id) throw code('forbidden', 'parent delegation not in this org');
    if (parentToken.sub !== delegator_id) throw code('forbidden', 'delegator does not own parent delegation');
    assertTokenUsable(parentToken);
    if (!tokenCovers(parentToken, '*', '*')) throw code('attenuation_violation', 'parent delegation does not cover this action/resource');
  } else {
    if (!callerIsAdmin && subject !== delegator_id) throw code('forbidden', 'service key required to delegate for another agent');
  }
  if (subject === delegator_id) throw code('bad_request', 'self-delegation not allowed (use sub-agents instead)');
  const maxDepth = payload.constraints?.max_depth ?? MAX_DEPTH;
  if (parentJti && maxDepth > 0) {
    const parentToken = _store().get('tokens', parentJti);
    if (parentToken && parentToken.depth >= maxDepth) throw code('depth_exceeded', 'max delegation depth reached');
  }
  const token = {
    v: 2, jti: rid('tkn'), org_id, sub: subject, parent_jti: parentJti,
    scope: payload.scope || ['*'], resources: payload.resources || ['*'],
    constraints: {
      allowed_targets: payload.constraints?.allowed_targets || [],
      max_spend_cents: payload.constraints?.max_spend_cents ?? Number.MAX_SAFE_INTEGER,
      not_after: payload.constraints?.not_after ?? null,
      max_depth: maxDepth,
      require_approval: payload.constraints?.require_approval ?? false,
    },
    kid: verified.kid || parentDelegator.keys.current.kid,
    iat: Date.now(),
    issuer: delegator_id,
    depth: (parentJti ? (_store().get('tokens', parentJti)?.depth || 0) + 1 : 0),
    revoked: false
  };
  _store().put('tokens', token);
  return token;
}

function assertTokenUsable(tok) {
  if (!tok) throw code('token_unknown', 'Unknown token');
  if (tok.revoked) throw code('token_revoked', 'Token revoked');
  if (tok.constraints?.not_after && Date.now() > tok.constraints.not_after) throw code('token_expired', 'Token expired');
  if (_store().has('revocations', 'token:' + tok.jti)) throw code('token_revoked', 'Token revoked');
  if (tok.parent_jti && _store().has('revocations', 'token:' + tok.parent_jti)) throw code('token_revoked', 'Parent token revoked');
}

function tokenCovers(tok, action, resource) {
  if (!tok) return false;
  const scopeOk = globMatch(tok.scope, action);
  const resourceOk = globMatch(tok.resources, resource);
  const targetOk = tok.constraints?.allowed_targets?.length ? globMatch(tok.constraints.allowed_targets, '*') : true;
  return scopeOk && resourceOk && targetOk;
}

function checkBudget(tok, amount_cents) {
  if (!tok) throw code('bad_request', 'no token for budget check');
  if (tok.constraints?.max_spend_cents && amount_cents > tok.constraints.max_spend_cents) throw code('budget_exceeded', 'exceeds token spend cap');
}

function debitBudget(tok, amount_cents) {
  if (tok) {
    _store().put('tokens', { ...tok, spent_cents: (tok.spent_cents || 0) + amount_cents });
  }
}

function addRevocation({ type, target, reason, org_id, kid = null }) {
  const { revSeq } = require('./server');
  revSeq++;
  const rec = { id: `${type}:${target}${kid ? ':' + kid : ''}`, seq: revSeq, type, target, kid: kid || null, org_id, reason: reason || 'manual', at: Date.now() };
  _store().put('revocations', rec);
  return rec;
}

module.exports = { rid: require('./crypto').rid, createOrgRecord, publicOrg, orgPubkey, issuePassport, publicPassport, rotatePassport, setPassportStatus, revokeKey, touchLastSeen, passportStatus, LIFECYCLE, createBlueprint, blueprintInstances, isOrgLocked, assertOrgUsable, assertPassportUsable, keyFor, registerDelegation, assertTokenUsable, tokenCovers, checkBudget, debitBudget, allowCustody, isPassportRevoked, addRevocation };