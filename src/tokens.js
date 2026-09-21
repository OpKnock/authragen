'use strict';
const { rid, generateEd25519, pubKeyFromB64u, verifyBytes, b64uJsonDecode, canonical } = require('./crypto');
const { getStore } = require('./store');
const { globMatch, anyMatch } = require('./policy');
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
function assertPassportUsable(pass, trail = new Set()) {
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  const p = upgradeLegacy({ ...pass });
  if (trail.has(p.id)) throw code('passport_invalid', 'passport hierarchy cycle detected');
  trail.add(p.id);
  if (isOrgLocked(p.org_id)) throw code('org_locked', 'Organization emergency-locked');
  if (p.revoked || p.status === 'revoked' || isPassportRevoked(p.id)) throw code('passport_revoked', 'Passport revoked');
  if (Date.now() > p.exp || p.status === 'expired') throw code('passport_expired', 'Passport expired');
  if (p.status === 'suspended') throw code('passport_suspended', 'Passport suspended');
  if (p.status === 'quarantined') throw code('passport_quarantined', 'Passport quarantined');
  if (p.blueprint_id) {
    const bp = _store().get('blueprints', p.blueprint_id);
    if (!bp || bp.status === 'revoked' || _store().has('revocations', 'blueprint:' + p.blueprint_id)) throw code('blueprint_revoked', 'Passport blueprint is revoked');
  }
  if (p.parent_id) {
    const parent = _store().get('passports', p.parent_id);
    if (!parent || parent.org_id !== p.org_id) throw code('passport_parent_invalid', 'Passport parent is unavailable');
    assertPassportUsable(parent, trail);
  }
}
function code(name, msg) { const e = new Error(msg); e.code = name; return e; }

function isPassportRevoked(passport_id) {
  return _store().has('revocations', 'passport:' + passport_id);
}

const DEFAULT_PASSPORT_TTL_DAYS = Number(process.env.AUTHRA_PASSPORT_TTL_DAYS || 365);
const DAY_MS = 24 * 60 * 60 * 1000;
async function issuePassport({ org_id, name, kind = 'agent', pubkey, blueprint_id = null, owner = null, sponsor = null, team = null, environment = 'production', purpose = '', model = null, provider = null, runtime = null, framework = null, custody = 'self', custodied = false, parent_id = null, grace_period_s = DEFAULT_GRACE_S, exp_days = null }) {
  assertOrgUsable(org_id);
  if (typeof name !== 'string' || !name.trim() || name.length > 256) throw code('bad_request', 'passport name required (max 256)');
  if (!['agent','subagent'].includes(kind)) throw code('bad_request', 'invalid passport kind');
  const serverCustody = custody === 'server' || custodied === true;
  if (serverCustody && !allowCustody()) throw code('custody_forbidden', 'server custody disabled (set AUTHRA_ALLOW_CUSTODY=1 to enable)');
  if (!serverCustody && !pubkey) throw code('bad_request', 'pubkey required');
  if (pubkey) { try { pubKeyFromB64u(pubkey); } catch { throw code('bad_request', 'pubkey must be a valid Ed25519 public key'); } }
  let parent = null;
  if (parent_id) {
    parent = _store().get('passports', parent_id);
    if (!parent || parent.org_id !== org_id) throw code('bad_request', 'parent passport not in this org');
    assertPassportUsable(parent);
  }
  if (kind === 'subagent' && !parent_id) throw code('bad_request', 'subagent requires parent_id');
  if (blueprint_id) {
    const bp = _store().get('blueprints', blueprint_id);
    if (!bp || bp.org_id !== org_id || bp.status === 'revoked') throw code('bad_request', 'blueprint unavailable');
  }
  const now = Date.now();
  let finalPubkey = pubkey;
  const pass = { v:2, id:rid('agt'), org_id, kind, name:String(name).slice(0,256),
    custody: serverCustody ? 'server' : 'self', parent_id, blueprint_id, owner, sponsor, team, environment, purpose, model, provider, runtime, framework,
    did:null, keys:null, grace_period_s:Math.max(0, Number(grace_period_s)||DEFAULT_GRACE_S),
    status:'active', iat:now, exp:0, last_seen:null, signature:null };
  if (serverCustody) {
    const kp=generateEd25519(); finalPubkey=kp.pubB64u; pass._privX=kp.pubB64u; pass._privD=kp.privB64u;
  }
  pass.did=didFor(finalPubkey);
  pass.keys={current:{kid:'k1',pubkey:finalPubkey,since:now},history:[]};
  let exp = exp_days == null ? now + DEFAULT_PASSPORT_TTL_DAYS*DAY_MS : now + Number(exp_days)*DAY_MS;
  if (!Number.isFinite(exp) || exp <= now) throw code('bad_request','exp_days must produce a future expiration');
  if (parent?.exp > 0) exp=Math.min(exp, Number(parent.exp));
  pass.exp=exp;
  const signer=getOrgSigner(org_id);
  pass.signature=await signer.signCanonical({...pass,signature:undefined});
  _store().put('passports',pass);
  if (blueprint_id) { const bp=_store().get('blueprints',blueprint_id); bp.instance_count=(bp.instance_count||0)+1; bp.updated_at=Date.now(); _store().put('blueprints',bp); }
  return pass;
}
function publicPassport(p) { const { ...pub } = upgradeLegacy({ ...p }); delete pub._privX; delete pub._privD; return pub; }
async function rotatePassport(passport_id, new_pubkey) {
  const pass=_store().get('passports',passport_id);
  if(!pass)throw code('passport_unknown','Unknown passport');
  assertPassportUsable(pass);
  let nextPub=new_pubkey, privOnce=null;
  if(!nextPub){
    if(pass.custody!=='server'||!allowCustody())throw code('bad_request','rotation requires new pubkey for self-custody');
    const kp=generateEd25519();
    nextPub=kp.pubB64u; privOnce={x:kp.pubB64u,d:kp.privB64u};
    pass._privX=privOnce.x; pass._privD=privOnce.d;
  }
  try{pubKeyFromB64u(nextPub);}catch{throw code('bad_request','invalid Ed25519 pubkey');}
  const now=Date.now();
  pass.keys=pass.keys||{current:{kid:'k1',pubkey:nextPub,since:now},history:[]};
  const cur=pass.keys.current;
  pass.keys.history=pass.keys.history||[];
  pass.keys.history.push({kid:cur.kid,pubkey:cur.pubkey,since:cur.since,until:now+(Number(pass.grace_period_s)||DEFAULT_GRACE_S)*1000,revoked:false});
  const n=Number(String(cur.kid||'k0').replace(/^k/,''))||0;
  pass.keys.current={kid:'k'+(n+1),pubkey:nextPub,since:now,revoked:false};
  pass.updated_at=now;
  const signer=getOrgSigner(pass.org_id);
  pass.signature=await signer.signCanonical({...pass,signature:undefined});
  _store().put('passports',pass);
  const out=publicPassport(pass);
  if(privOnce)out._privOnce=privOnce;
  return out;
}
async function revokeKey(passport_id, kid) {
  const pass = _store().get('passports', passport_id);
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  const history = pass.keys?.history || [];
  const idx = history.findIndex(k => k.kid === kid);
  if (idx >= 0) {
    history[idx] = { ...history[idx], revoked: true, until: Date.now() };
  } else if (pass.keys?.current?.kid === kid) {
    pass.keys.current = { ...pass.keys.current, revoked: true };
  } else {
    throw code('bad_request', 'kid not found');
  }
  pass.updated_at = Date.now();
  const signer = getOrgSigner(pass.org_id);
  pass.signature = await signer.signCanonical({ ...pass, signature: undefined });
  _store().put('passports', pass);
  return pass;
}
async function setPassportStatus(id, status) {
  if (!LIFECYCLE.includes(status)) throw code('bad_request', 'invalid status');
  const pass = _store().get('passports', id);
  if (!pass) throw code('passport_unknown', 'Unknown passport');
  pass.status = status;
  pass.updated_at = Date.now();
  const signer = getOrgSigner(pass.org_id);
  const doc = { ...pass, signature: undefined };
  pass.signature = await signer.signCanonical(doc);
  _store().put('passports', pass);
  return pass;
}
function touchLastSeen(id) {
  const pass = _store().get('passports', id);
  if (pass) { pass.last_seen = Date.now(); _store().put('passports', pass); }
}

function parseSignedDelegation(envelope) {
  const parts=String(envelope||'').split('.');
  if(parts.length!==4||parts[0]!=='AR1') throw code('token_malformed','not an AR1 delegation envelope');
  let header,payload;
  try{ header=b64uJsonDecode(parts[1]); payload=b64uJsonDecode(parts[2]); }catch{ throw code('token_malformed','delegation envelope encoding invalid'); }
  if(header.v!==1||header.typ!=='AR1'||header.alg!=='EdDSA') throw code('token_malformed','delegation must use EdDSA');
  return { header,payload,sig:parts[3], signingInput:Buffer.from(parts[1]+'.'+parts[2],'utf8') };
}
function globSubset(parentPattern, childPattern) {
  if(parentPattern==='*'||parentPattern==='**'||parentPattern===childPattern) return true;
  const p=String(parentPattern), c=String(childPattern);
  if(!p.includes('*')) return false;
  if(!c.includes('*')) return globMatch(p,c);
  const pi=p.indexOf('*'), ci=c.indexOf('*');
  return c.slice(0,ci).startsWith(p.slice(0,pi)) && (p.slice(pi+1)==='' || c.slice(ci+1).endsWith(p.slice(pi+1)));
}
function patternsSubset(child,parent) {
  const c=Array.isArray(child)?child:[], p=Array.isArray(parent)?parent:[];
  if(!c.length)return true; if(!p.length)return false;
  return c.every(cp=>p.some(pp=>globSubset(pp,cp)));
}
function normalizeNotAfter(v) {
  if(v==null||v==='')return null;
  const n=typeof v==='number'?v:Date.parse(v);
  if(!Number.isFinite(n))throw code('bad_request','constraints.not_after must be a timestamp or ISO date');
  return n;
}
function strictStringArray(value, name, { required = false, max = 256 } = {}) {
  if (value == null) {
    if (required) throw code('bad_request', name + ' must be a non-empty string array');
    return null;
  }
  if (!Array.isArray(value) || value.length > max || value.some(x => typeof x !== 'string' || !x.trim() || x.length > 512)) {
    throw code('bad_request', name + ' must contain only non-empty strings (max 512 chars each)');
  }
  return value.map(x => x.normalize('NFC'));
}
function registerDelegation({ org_id, delegator_id, payload, envelope, callerIsAdmin = false }) {
  if(!org_id||!delegator_id||!payload||!envelope)throw code('bad_request','org_id, delegator_id, payload, envelope required');
  assertOrgUsable(org_id);
  const delegator=_store().get('passports',delegator_id);
  if(!delegator||delegator.org_id!==org_id)throw code('forbidden','delegator not in this org');
  assertPassportUsable(delegator);
  const decoded=parseSignedDelegation(envelope), verified=decoded.payload;
  if(canonical(verified)!==canonical(payload))throw code('token_malformed','delegation payload does not match signed envelope');
  if(verified.v!==2||verified.org_id!==org_id||!verified.sub||!verified.jti)throw code('bad_request','delegation payload missing v/org_id/sub/jti');
  const issuerKey=keyFor(delegator,verified.kid||delegator.keys.current.kid);
  if(!verifyBytes(decoded.signingInput,decoded.sig,pubKeyFromB64u(issuerKey.pubkey),'EdDSA'))throw code('sig_invalid','delegation signature invalid');
  const subject=verified.sub, subjectPassport=_store().get('passports',subject);
  if(!subjectPassport||subjectPassport.org_id!==org_id)throw code('bad_request','subject passport not in this org');
  assertPassportUsable(subjectPassport);
  const parentJti=verified.parent_jti||null; let parentToken=null;
  if(parentJti){
    parentToken=_store().get('tokens',parentJti);
    if(!parentToken||parentToken.org_id!==org_id)throw code('forbidden','parent delegation not in this org');
    if(parentToken.sub!==delegator_id)throw code('delegation_not_authorized','parent delegation is not owned by delegator');
    assertTokenUsable(parentToken);
    const c=verified.constraints||{}, has=k=>Object.prototype.hasOwnProperty.call(c,k);
    const childScope=verified.scope!=null?strictStringArray(verified.scope,'scope',{required:true}):(parentToken.scope||[]);
    const childResources=verified.resources!=null?strictStringArray(verified.resources,'resources',{required:true}):(parentToken.resources||[]);
    if(!patternsSubset(childScope,parentToken.scope||[]))throw code('attenuation_violation','scope widening rejected');
    if(!patternsSubset(childResources,parentToken.resources||[]))throw code('attenuation_violation','resource widening rejected');
    const parentTargets=parentToken.constraints?.allowed_targets||[];
    const childTargets=has('allowed_targets')?strictStringArray(c.allowed_targets,'constraints.allowed_targets'):parentTargets;
    if(parentTargets.length&&(!childTargets.length||!patternsSubset(childTargets,parentTargets)))throw code('attenuation_violation','target widening rejected');
    const parentSpend=parentToken.constraints?.max_spend_cents??Number.MAX_SAFE_INTEGER;
    const childSpend=has('max_spend_cents')?Number(c.max_spend_cents):parentSpend;
    if(!Number.isSafeInteger(childSpend)||childSpend<0||childSpend>parentSpend)throw code('attenuation_violation','budget increase rejected');
    const parentAfter=normalizeNotAfter(parentToken.constraints?.not_after);
    const childAfter=has('not_after')?normalizeNotAfter(c.not_after):parentAfter;
    if(parentAfter!=null&&(childAfter==null||childAfter>parentAfter))throw code('attenuation_violation','expiry extension rejected');
    const parentDepth=parentToken.constraints?.max_depth==null?MAX_DEPTH:Number(parentToken.constraints.max_depth);
    const childDepth=has('max_depth')?Number(c.max_depth):parentDepth;
    if(!Number.isInteger(childDepth)||childDepth<0||childDepth>parentDepth)throw code('attenuation_violation','max_depth widening rejected');
    if(parentToken.depth+1>childDepth)throw code('depth_exceeded','max delegation depth reached');
    const childApproval=has('require_approval')?!!c.require_approval:!!parentToken.constraints?.require_approval;
    if(parentToken.constraints?.require_approval&&!childApproval)throw code('attenuation_violation','approval requirement cannot be removed');
  } else if(!callerIsAdmin&&subject!==delegator_id) {
    throw code('delegation_not_authorized','agent may only create a root delegation for itself');
  }
  if(_store().has('tokens',verified.jti))throw code('bad_request','delegation jti already registered');
  const c=verified.constraints||{}, has=k=>Object.prototype.hasOwnProperty.call(c,k);
  const scope=verified.scope!=null?strictStringArray(verified.scope,'scope',{required:true}):(parentToken?.scope||[]);
  const resources=verified.resources!=null?strictStringArray(verified.resources,'resources',{required:true}):(parentToken?.resources||[]);
  const targets=has('allowed_targets')?strictStringArray(c.allowed_targets,'constraints.allowed_targets'):(parentToken?.constraints?.allowed_targets||[]);
  const maxSpend=has('max_spend_cents')?Number(c.max_spend_cents):(parentToken?.constraints?.max_spend_cents??Number.MAX_SAFE_INTEGER);
  const notAfter=has('not_after')?normalizeNotAfter(c.not_after):(parentToken?.constraints?.not_after??null);
  const maxDepth=has('max_depth')?Number(c.max_depth):(parentToken?.constraints?.max_depth??MAX_DEPTH);
  const requireApproval=has('require_approval')?!!c.require_approval:!!parentToken?.constraints?.require_approval;
  if(!scope.length||!resources.length)throw code('bad_request','delegation scope/resources must not be empty');
  if(!Number.isSafeInteger(maxSpend)||maxSpend<0)throw code('bad_request','max_spend_cents must be a non-negative safe integer');
  if(!Number.isInteger(maxDepth)||maxDepth<0||maxDepth>MAX_DEPTH)throw code('bad_request','max_depth out of range');
  if(notAfter!=null&&notAfter<=Date.now())throw code('bad_request','delegation already expired');
  const token={v:2,id:verified.jti,jti:verified.jti,org_id,sub:subject,parent_jti:parentJti,scope,resources,
    constraints:{allowed_targets:targets,max_spend_cents:maxSpend,not_after:notAfter,max_depth:maxDepth,require_approval:requireApproval},
    kid:verified.kid||delegator.keys.current.kid,iat:Date.now(),issuer:delegator_id,depth:parentToken?(parentToken.depth+1):0,spent_cents:0,revoked:false};
  _store().put('tokens',token); return token;
}
function assertTokenUsable(tok, trail = new Set()) {
  if(!tok)throw code('token_unknown','Unknown token');
  if(trail.has(tok.jti))throw code('token_malformed','delegation cycle detected');
  trail.add(tok.jti);
  if(tok.revoked||_store().has('revocations','token:'+tok.jti))throw code('token_revoked','Token revoked');
  if(tok.org_id==null||tok.sub==null)throw code('token_malformed','Token missing org/subject');
  if(tok.constraints?.not_after&&Date.now()>tok.constraints.not_after)throw code('token_expired','Token expired');
  if(tok.parent_jti){
    const parent=_store().get('tokens',tok.parent_jti);
    if(!parent||parent.org_id!==tok.org_id)throw code('token_revoked','Parent delegation unavailable');
    if(parent.sub!==tok.issuer)throw code('token_revoked','Delegation issuer mismatch');
    assertTokenUsable(parent,trail);
  }
  assertPassportUsable(_store().get('passports',tok.sub));
  return true;
}
function tokenCovers(tok,action,resource,destination='') {
  if(!tok)return false;
  const scopeOk=anyMatch(tok.scope,action);
  const resourceOk=anyMatch(tok.resources,resource);
  const targets=tok.constraints?.allowed_targets||[];
  const targetOk=!targets.length||anyMatch(targets,destination);
  return scopeOk&&resourceOk&&targetOk;
}
function checkBudget(tok,amount_cents) {
  if(!tok)throw code('bad_request','no token for budget check');
  const amount=Number(amount_cents)||0, limit=tok.constraints?.max_spend_cents??Number.MAX_SAFE_INTEGER;
  if(!Number.isSafeInteger(amount)||amount<0||((tok.spent_cents||0)+amount)>limit)throw code('budget_exceeded','exceeds token spend cap');
  return true;
}
function debitBudget(tok,amount_cents) {
  checkBudget(tok,amount_cents);
  tok.spent_cents=(tok.spent_cents||0)+Number(amount_cents||0);
  _store().put('tokens',tok);
  return tok;
}

let revSeq = 0;
let revSeqInitialized = false;
function ensureRevocationSeq() {
  if (revSeqInitialized) return;
  revSeq = _store().all('revocations').reduce((max, r) => {
    const n = Number(r.seq);
    return Number.isSafeInteger(n) && n > max ? n : max;
  }, 0);
  revSeqInitialized = true;
}
function revocationHead() {
  ensureRevocationSeq();
  return revSeq;
}
function addRevocation({ type, target, reason, org_id, kid = null }) {
  ensureRevocationSeq();
  const id = String(type) + ':' + String(target) + (kid ? ':' + kid : '');
  const existing = _store().get('revocations', id);
  if (existing) return existing;
  if (revSeq >= Number.MAX_SAFE_INTEGER) throw code('storage_error', 'revocation sequence exhausted');
  const rec = { id, seq: ++revSeq, type, target, kid: kid || null, org_id, reason: reason || 'manual', at: Date.now() };
  _store().put('revocations', rec);
  return rec;
}

module.exports = { rid: require('./crypto').rid, createOrgRecord, publicOrg, orgPubkey, issuePassport, publicPassport, rotatePassport, setPassportStatus, revokeKey, touchLastSeen, passportStatus, LIFECYCLE, createBlueprint, blueprintInstances, isOrgLocked, assertOrgUsable, assertPassportUsable, keyFor, registerDelegation, assertTokenUsable, tokenCovers, checkBudget, debitBudget, allowCustody, isPassportRevoked, addRevocation, revocationHead };