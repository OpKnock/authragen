'use strict';
const http = require('node:http');
const url = require('node:url');
const crypto = require('node:crypto');
const { initStore, getStore, backend: storeBackend } = require('./store');
const { createOrgRecord, publicOrg, orgPubkey, issuePassport, publicPassport, rotatePassport,
  setPassportStatus, revokeKey, touchLastSeen, passportStatus, LIFECYCLE,
  createBlueprint, blueprintInstances, isOrgLocked, assertOrgUsable,
  assertPassportUsable, keyFor, registerDelegation, assertTokenUsable, tokenCovers,
  checkBudget, debitBudget, allowCustody, addRevocation, revocationHead } = require('./tokens');
const { evaluate, simulate, detectConflicts, newPolicy, seedPolicies, policyHash } = require('./policy');
const { score, listRiskProviders } = require('./risk');
const audit = require('./audit');
const auth = require('./auth');
const { getOrgSigner, gatewaySigner, initSigners } = require('./signer');
const { canonicalIntent, intentHash, checkIntentShape, verifyAgentIntent, openWithOrgKey,
  buildActionToken, buildApproval, verifyOffline, PROTOCOL_VERSION } = require('./intent');
const { hasDuplicateKeys } = require('./crypto');
const { createLogger } = require('./logger');
const { createMetrics } = require('./metrics');
const nonceStore = require('./nonce');

function parseByteSize(value, fallback) {
  if (value == null || value === '') return fallback;
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(1, Math.floor(value));
  const m = String(value).trim().toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|kib|mb|mib|gb|gib)?$/);
  if (!m) return fallback;
  const mult = { b: 1, kb: 1024, kib: 1024, mb: 1024 ** 2, mib: 1024 ** 2, gb: 1024 ** 3, gib: 1024 ** 3 };
  const bytes = Number(m[1]) * (mult[m[2] || 'b'] || 1);
  return Number.isSafeInteger(Math.round(bytes)) ? Math.max(1, Math.round(bytes)) : fallback;
}

const PORT = process.env.PORT || 8787;
const IS_PROD = process.env.NODE_ENV === 'production';
const BODY_LIMIT = parseByteSize(process.env.AUTHRA_BODY_LIMIT, 256 * 1024);
const CORS_ORIGIN = process.env.AUTHRA_CORS || '';
const TRUST_PROXY = process.env.AUTHRA_TRUST_PROXY === '1';
const RISK_CEILING_DEFAULT = Number(process.env.AUTHRA_RISK_CEILING || 85);
const RISK_STEPUP_DEFAULT = Number(process.env.AUTHRA_RISK_STEPUP || 30);
const KMS_TYPE = (process.env.AUTHRA_KMS || 'file').toLowerCase();
const STORE_TYPE = (process.env.AUTHRA_STORE || 'file').toLowerCase();
const ALLOW_INSECURE_PROD_DEFAULTS = process.env.AUTHRA_ALLOW_INSECURE_PROD_DEFAULTS === '1';

const logger = createLogger({ service: 'authragen', env: process.env.NODE_ENV || 'development' });
const metrics = createMetrics();

function newRequestId() { return 'rq_' + crypto.randomBytes(6).toString('hex'); }
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

const buckets = new Map();
function rateLimit(req, route, limitPerMin) {
  const key = clientIp(req) + '|' + route;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.reset) b = { count: 0, reset: now + 60 * 1000 };
  b.count++;
  buckets.set(key, b);
  if (b.count > limitPerMin) {
    const e = new Error(`rate limited for ${route} (retry after ${Math.ceil((b.reset - now) / 1000)}s)`);
    e.code = 'rate_limited'; e.status = 429; e.retryAfter = Math.ceil((b.reset - now) / 1000);
    throw e;
  }
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now > b.reset) buckets.delete(k);
}, 60 * 1000).unref?.();

function securityHeaders(req) {
  const h = {
    'content-type': 'application/json',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'x-request-id': req._rid || '',
  };
  const proto = TRUST_PROXY ? (req.headers['x-forwarded-proto'] || 'http') : 'http';
  if (proto === 'https' || req.headers['x-forwarded-proto'] === 'https') h['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
  const origin = req.headers.origin;
  if (CORS_ORIGIN === '*') h['access-control-allow-origin'] = '*';
  else if (origin && origin === CORS_ORIGIN) { h['access-control-allow-origin'] = origin; h.vary = 'Origin'; }
  return h;
}
function send(req, res, code, obj) {
  const b = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(code, { ...securityHeaders(req), 'content-length': b.length });
  res.end(b);
}
function errorStatus(e) {
  const errCode = e?.code || '';
  const map = {
    unauthorized: 401, forbidden: 403, bad_request: 400, bad_intent: 400,
    sig_invalid: 401, unknown_kid: 401, key_revoked: 401, key_expired: 401,
    passport_unknown: 404, passport_expired: 410, passport_revoked: 410,
    token_unknown: 404, token_expired: 410, token_revoked: 410, token_mismatch: 400, token_malformed: 400,
    scope_insufficient: 403, budget_exceeded: 403, depth_exceeded: 403, attenuation_violation: 403,
    approval_required: 403, approval_expired: 403, approval_resolved: 409, intent_expired: 400, intent_mismatch: 400,
    rate_limited: 429, quota_exceeded: 429, org_locked: 403, replay: 409,
    storage_error: 500,
  };
  let code = e?.status || map[errCode];
  if (!code) {
    if (/unknown|not_found/.test(errCode)) code = 404;
    else if (/expired|revoked|suspended|quarantined|denied|insufficient|exceeded|replay|mismatch|invalid|malformed|unauthorized|forbidden|custody|locked/.test(errCode)) code = 403;
    else code = 400;
  }
  return code;
}

function sendErr(req, res, e) {
  const code = errorStatus(e);
  const body = { error: e.code || 'bad_request', request_id: req._rid };
  if (e.retryAfter) { res.setHeader?.('retry-after', String(e.retryAfter)); body.retry_after = e.retryAfter; }
  body.message = IS_PROD && code === 500 ? 'internal error' : String(e.message || e.code).slice(0, 500);
  return send(req, res, code, body);
}
function bodyRaw(req, { limit = BODY_LIMIT } = {}) {
  return new Promise((resolve, reject) => {
    let len = 0; const chunks = []; let rejected = false;
    req.on('data', c => {
      if (rejected) return;
      len += c.length;
      if (len > limit) {
        rejected = true;
        const e = new Error(`request body too large (max ${limit} bytes)`); e.code = 'bad_request'; e.status = 413;
        reject(e); return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!rejected) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', reject);
  });
}
async function body(req, opts) {
  const raw = await bodyRaw(req, opts);
  if (!raw) return {};
  if (hasDuplicateKeys(raw)) throw Object.assign(new Error('duplicate JSON keys rejected'), { code: 'bad_intent' });
  try { return JSON.parse(raw); }
  catch { throw Object.assign(new Error('bad json'), { code: 'bad_request' }); }
}

let lock = Promise.resolve();
function withLock(fn) { const r = lock.then(fn); lock = r.catch(() => {}); return r; }

const seen = new Map();
function isSeen(pid, resource) { return seen.has(pid) && seen.get(pid).has(resource); }
function markSeen(pid, resource) { if (!seen.has(pid)) seen.set(pid, new Set()); seen.get(pid).add(resource); }

function callerKey(req) { return auth.lookupKey(auth.bearerOf(req)); }
function publicApproval(ap) {
  const out = { ...ap };
  delete out.action_token;
  delete out.approval_credential;
  return out;
}
function orgRisk(org_id) {
  const org = getStore().get('orgs', org_id);
  return {
    ceiling: org?.risk_ceiling ?? RISK_CEILING_DEFAULT,
    stepup: org?.risk_stepup ?? RISK_STEPUP_DEFAULT,
    version: 'risk-v1',
  };
}

async function authorize({ intent, intent_sig, kid, token_id, context = {}, dry_run = false, request_id = null }, svcKey, reqMeta = {}) {
  const rid = request_id || newRequestId();
  const ci = checkIntentShape(intent);
  assertOrgUsable(ci.org_id);
  const pass = getStore().get('passports', ci.passport_id);
  if (!pass || pass.org_id !== ci.org_id) throw Object.assign(new Error('Unknown passport'), { code: 'passport_unknown' });
  let authn = null;
  if (intent_sig) {
    const { pubkey } = keyFor(pass, kid || undefined);
    verifyAgentIntent(ci, intent_sig, pubkey);
    authn = 'agent_sig';
  } else if (svcKey) {
    auth.requireRole(svcKey, ci.org_id, 'executor');
    authn = 'service_key:' + svcKey.id;
  } else throw Object.assign(new Error('intent signature or service key required'), { code: 'unauthorized' });

  const hash = intentHash(ci);
  let tok = null;
  const reasons = [`authn:${authn}`, `intent:${hash.slice(0, 12)}`];
  if (context && (context.spend_cents != null || context.amount_cents != null || context.destination || context.target)) reasons.push('untrusted-context-ignored');
  const base = { org_id: ci.org_id, actor: ci.passport_id, action: ci.action, resource: ci.resource, token_jti: token_id || null, intent_hash: hash, amount_cents: ci.amount_cents, destination: ci.destination || '', tool: ci.tool || '', aud: ci.aud, authn, request_id: rid };
  const deny = (extra, riskScore, policy_id, policy_hash = null, policy_version = null) => {
    const rc = audit.append({ ...base, decision: 'deny', risk: riskScore, policy_id: policy_id || null, policy_hash, policy_version, reasons: [...reasons, ...extra] });
    markSeen(ci.passport_id, ci.resource);
    return { decision: 'deny', risk: riskScore, risk_factors: [], policy_id: policy_id || null, policy_hash, policy_version, reasons: [...reasons, ...extra], receipt: rc, request_id: rid };
  };
  try { assertPassportUsable(pass); }
  catch (e) {
    if (/passport_revoked|passport_expired|passport_suspended|passport_quarantined|key_revoked|key_expired|unknown_kid|org_locked/.test(e.code || '')) return deny([e.code], 100, null);
    throw e;
  }
  try {
    if (token_id) {
      tok = getStore().get('tokens', token_id);
      if (!tok || tok.org_id !== ci.org_id) throw Object.assign(new Error('Unknown token'), { code: 'token_unknown' });
      assertTokenUsable(tok);
      if (tok.sub !== ci.passport_id) throw Object.assign(new Error('Token subject mismatch'), { code: 'token_mismatch' });
      if (!tokenCovers(tok, ci.action, ci.resource, ci.destination)) throw Object.assign(new Error('Token scope/targets insufficient'), { code: 'scope_insufficient' });
      checkBudget(tok, ci.amount_cents);
    }
  } catch (e) { return deny([e.code || 'token_error'], 100, null); }
  const passRec = getStore().get('passports', ci.passport_id);
  const ctx = {
    amount_cents: ci.amount_cents, spend_cents: ci.amount_cents, depth: tok ? tok.depth : 0,
    tool: ci.tool, aud: ci.aud, environment: passRec?.environment, blueprint_id: passRec?.blueprint_id,
    passport_id: ci.passport_id, agent_id: ci.passport_id,
  };
  const policies = getStore().byOrg('policies', ci.org_id);
  const ev = evaluate(policies, { action: ci.action, resource: ci.resource, context: ctx });
  reasons.push(...ev.reasons);
  const riskCfg = orgRisk(ci.org_id);
  const risk = score({ action: ci.action, resource: ci.resource, context: { spend_cents: ci.amount_cents, depth: ctx.depth }, seen: isSeen(ci.passport_id, ci.resource) });
  reasons.push(`risk:${risk.score}(${risk.band})`);
  markSeen(ci.passport_id, ci.resource);
  touchLastSeen(ci.passport_id);

  if (dry_run) {
    const sim = ev.provisional === 'deny' || risk.score >= riskCfg.ceiling ? 'DENY'
      : ev.provisional === 'require_approval' || (risk.score >= riskCfg.stepup && risk.score < 70) ? 'STEP-UP' : ev.provisional === 'allow' ? 'ALLOW' : 'DENY';
    const rc = audit.append({ ...base, decision: 'dry_run', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons: [...reasons, 'dry-run:no-credential'] });
    return { decision: 'dry_run', would: sim, risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  if (ev.provisional === 'deny' || risk.score >= riskCfg.ceiling) {
    reasons.push(ev.provisional === 'deny' ? 'policy-deny' : `risk-ceiling>=${riskCfg.ceiling}`);
    const rc = audit.append({ ...base, decision: 'deny', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons });
    return { decision: 'deny', risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  if (ev.provisional === 'require_approval' || (risk.score >= riskCfg.stepup && risk.score < 70)) {
    const quorum = (() => {
      const pol = policies.find(p => p.id === ev.policy_id);
      return Math.max(1, Number(pol?.condition?.min_approvals) || 1);
    })();
    const ap = { id: 'apr_' + crypto.randomBytes(5).toString('hex'), org_id: ci.org_id, passport_id: ci.passport_id, token_jti: token_id || null, intent: ci, intent_hash: hash, aud: ci.aud, agent_kid: kid || pass.keys?.current?.kid || null, action: ci.action, resource: ci.resource, amount_cents: ci.amount_cents, destination: ci.destination, risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, status: 'pending', quorum, approvals: [], created_at: Date.now(), expires_at: Date.now() + 15 * 60 * 1000, request_id: rid };
    getStore().put('approvals', ap);
    const rc = audit.append({ ...base, decision: 'step_up', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, approval_id: ap.id, request_id: rid });
    return { decision: 'step_up', approval_id: ap.id, quorum, risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  if (ev.provisional === 'allow') {
    const orgSigner = getOrgSigner(ci.org_id);
    const att = await buildActionToken({ orgSigner, org_id: ci.org_id, sub: ci.passport_id, intent_hash: hash, action: ci.action, resource: ci.resource, amount_cents: ci.amount_cents, requires_approval: false, token_jti: token_id || null, aud: ci.aud, kid: kid || pass.keys?.current?.kid || null });
    const rc = audit.append({ ...base, decision: 'allow', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, action_jti: att.jti, request_id: rid });
    return { decision: 'allow', action_token: att.envelope, action_jti: att.jti, risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  const rc = audit.append({ ...base, decision: 'deny', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons: [...reasons, 'fail-closed'], request_id: rid });
  return { decision: 'deny', risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
}

async function execute({ action_token, intent, approval, request_id = null }) {
  return withLock(async () => {
    const rid = request_id || newRequestId();
    const ci = checkIntentShape(intent);
    const hash = intentHash(ci);
    try {
      assertOrgUsable(ci.org_id);
      const orgP = orgPubkey(ci.org_id);
      if (!orgP) throw Object.assign(new Error('Unknown org trust root'), { code: 'org_unknown' });
      const { header, payload: att } = openWithOrgKey(action_token, orgP);
      void header;
      if (att.kind !== 'action') throw Object.assign(new Error('not an action token'), { code: 'token_malformed' });
      if (att.v !== PROTOCOL_VERSION && att.v !== 1) throw Object.assign(new Error('unsupported credential version'), { code: 'token_malformed' });
      if (!att.jti || !att.issuer || !att.sub || !att.aud || !att.iat || !att.exp || !att.intent_hash) throw Object.assign(new Error('action credential missing jti/issuer/sub/aud/iat/exp/intent_hash'), { code: 'token_malformed' });
      if (att.issuer !== 'authragen-gateway') throw Object.assign(new Error('issuer mismatch'), { code: 'token_malformed' });
      if (att.org_id !== ci.org_id || att.sub !== ci.passport_id) throw Object.assign(new Error('action token mismatch'), { code: 'token_mismatch' });
      if ((att.aud || 'authragen') !== (ci.aud || 'authragen')) throw Object.assign(new Error(`audience mismatch (token for ${att.aud}, intent for ${ci.aud})`), { code: 'token_mismatch' });
      if (att.intent_hash !== hash) throw Object.assign(new Error('intent does not match authorized hash — request was altered'), { code: 'intent_mismatch' });
      if (att.action !== ci.action || att.resource !== ci.resource || (att.amount_cents || 0) !== (ci.amount_cents || 0))
        throw Object.assign(new Error('operation differs from authorized intent'), { code: 'intent_mismatch' });
      if (Date.now() > att.exp) throw Object.assign(new Error('action token expired'), { code: 'token_expired' });
      if (Date.now() < att.iat - 30 * 1000) throw Object.assign(new Error('action token not yet valid (clock skew)'), { code: 'token_malformed' });
      if (getStore().has('revocations', 'action:' + att.jti)) throw Object.assign(new Error('action credential revoked'), { code: 'token_revoked' });
      if (att.token_jti && getStore().has('revocations', 'token:' + att.token_jti)) throw Object.assign(new Error('parent delegation revoked'), { code: 'token_revoked' });
      let approvalRec = null;
      if (att.requires_approval) {
        if (!approval) throw Object.assign(new Error('approval credential required'), { code: 'approval_required' });
        const { payload: apc } = openWithOrgKey(approval, orgP);
        if (apc.kind !== 'approval' || apc.decision !== 'approved') throw Object.assign(new Error('not an approval'), { code: 'approval_required' });
        if (!apc.approval_id || !apc.intent_hash || apc.exp == null) throw Object.assign(new Error('approval credential malformed'), { code: 'approval_required' });
        if (apc.intent_hash !== hash) throw Object.assign(new Error('approval is for a different request'), { code: 'intent_mismatch' });
        if ((apc.aud || 'authragen') !== (ci.aud || 'authragen')) throw Object.assign(new Error('approval audience mismatch'), { code: 'token_mismatch' });
        if (apc.action_jti && apc.action_jti !== att.jti) throw Object.assign(new Error('approval is for a different action token'), { code: 'intent_mismatch' });
        if (Date.now() > apc.exp) throw Object.assign(new Error('approval expired'), { code: 'approval_expired' });
        approvalRec = apc;
      }
      const pass = getStore().get('passports', ci.passport_id);
      assertPassportUsable(pass);
      try {
        keyFor(pass, att.kid || undefined);
      } catch (e) {
        throw Object.assign(new Error('action credential key is no longer valid'), { code: e.code || 'key_revoked' });
      }
      let tok = null;
      if (att.token_jti) {
        tok = getStore().get('tokens', att.token_jti);
        if (!tok || tok.org_id !== ci.org_id) throw Object.assign(new Error('Unknown delegation token'), { code: 'token_unknown' });
        assertTokenUsable(tok);
        if (!tokenCovers(tok, ci.action, ci.resource, ci.destination)) throw Object.assign(new Error('Token scope/targets insufficient'), { code: 'scope_insufficient' });
        checkBudget(tok, ci.amount_cents);
      }
      const atomicStore = getStore();
      if (typeof atomicStore.checkAndDebitExecution === 'function') {
        const limit = tok ? (tok.constraints?.max_spend_cents ?? Number.MAX_SAFE_INTEGER) : Number.MAX_SAFE_INTEGER;
        const reservation = await atomicStore.checkAndDebitExecution(
          ci.org_id, ci.nonce, att.jti, tok?.jti || null, ci.amount_cents, limit, 10 * 60 * 1000
        );
        if (!reservation) {
          if (!await nonceStore.consumeOnce(ci.org_id + ':' + ci.nonce, 10 * 60 * 1000)) throw Object.assign(new Error('intent nonce already used (replay)'), { code: 'replay' });
          if (!await nonceStore.consumeActionJTI(att.jti, 10 * 60 * 1000)) throw Object.assign(new Error('action token already used (replay)'), { code: 'replay' });
          if (tok) debitBudget(tok, ci.amount_cents);
        } else if (!reservation.success) {
          const code = reservation.error === 'budget_exceeded' ? 'budget_exceeded' : 'replay';
          throw Object.assign(new Error(reservation.error || 'execution reservation rejected'), { code });
        } else if (tok) {
          tok.spent_cents = reservation.current;
          getStore().put('tokens', tok);
        }
      } else {
        if (!await nonceStore.consumeOnce(ci.org_id + ':' + ci.nonce, 10 * 60 * 1000)) throw Object.assign(new Error('intent nonce already used (replay)'), { code: 'replay' });
        if (!await nonceStore.consumeActionJTI(att.jti, 10 * 60 * 1000)) throw Object.assign(new Error('action token already used (replay)'), { code: 'replay' });
        if (tok) debitBudget(tok, ci.amount_cents);
      }
      touchLastSeen(ci.passport_id);
      const rc = audit.append({ org_id: ci.org_id, actor: ci.passport_id, action: ci.action, resource: ci.resource, token_jti: att.token_jti, intent_hash: hash, amount_cents: ci.amount_cents, destination: ci.destination, aud: ci.aud, decision: 'executed', risk: 0, policy_id: null, reasons: [`action_jti:${att.jti}`, 'intent-match', 'nonce-consumed', `approval:${approvalRec ? approvalRec.by + '/' + (approvalRec.by_key_id || '') : 'n/a'}`, `executor:${approvalRec ? 'approval-bound' : 'direct'}`], action_jti: att.jti, approval_id: approvalRec?.approval_id || null, request_id: rid });
      return { ok: true, receipt: rc, intent_hash: hash, request_id: rid, prepared_vs_executed: 'executed' };
    } catch (e) {
      try {
        audit.append({ org_id: ci.org_id, actor: ci.passport_id, action: ci.action, resource: ci.resource, intent_hash: hash, amount_cents: ci.amount_cents, decision: 'deny', risk: 100, policy_id: null, reasons: ['execute:' + (e.code || 'error')], request_id: rid });
      } catch {}
      throw e;
    }
  });
}

async function main() {
  try {
    if (IS_PROD && !ALLOW_INSECURE_PROD_DEFAULTS) {
      if (KMS_TYPE === 'file') throw new Error('production requires AUTHRA_KMS to be a real KMS/HSM backend (or explicitly set AUTHRA_ALLOW_INSECURE_PROD_DEFAULTS=1 for a non-production demo)');
      if (!['postgres', 'redis'].includes(STORE_TYPE)) throw new Error('production requires AUTHRA_STORE=postgres or redis (or explicitly set AUTHRA_ALLOW_INSECURE_PROD_DEFAULTS=1 for a non-production demo)');
    }
    await initStore();
    await initSigners(KMS_TYPE);
    logger.info({ event: 'store_initialized', backend: storeBackend(), kms: KMS_TYPE });
  } catch (e) {
    logger.error({ event: 'init_failed', error: e.message });
    process.exit(1);
  }

  const server = http.createServer(async (req, res) => {
    req._rid = req.headers['x-request-id'] || newRequestId();
    const u = url.parse(req.url, true);
    const p = u.pathname || '/';
    const t0 = Date.now();
    const startMem = process.memoryUsage().heapUsed;
    
    const logLine = (code) => {
      const safePath = p + (u.query && (u.query.org_id || u.query.since || u.query.limit) ? `?org_id=${u.query.org_id || ''}` : '');
      const duration = Date.now() - t0;
      const memUsed = process.memoryUsage().heapUsed - startMem;
      logger.info({
        event: 'http_request',
        rid: req._rid,
        method: req.method,
        path: safePath,
        status: code,
        duration_ms: duration,
        ip: clientIp(req),
        mem_delta_bytes: memUsed
      });
      metrics.httpRequestDuration.observe({ method: req.method, route: p, status: code }, duration / 1000);
      metrics.httpRequestsTotal.inc({ method: req.method, route: p, status: code });
    };
    const ok = async (code, obj) => {
      try {
        await getStore().flush?.();
      } catch (e) {
        const storageErr = Object.assign(new Error('persistent storage unavailable'), { code: 'storage_error', status: 500 });
        logLine(500);
        return sendErr(req, res, storageErr);
      }
      logLine(code);
      return send(req, res, code, { request_id: req._rid, ...obj });
    };
    const fail = (e) => { const code = errorStatus(e); logLine(code); return sendErr(req, res, e); };
    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, { ...securityHeaders(req), 'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS', 'access-control-allow-headers': 'authorization,content-type,x-bootstrap-token,x-request-id' });
        logLine(204); return res.end();
      }
      if ((p === '/' || p === '/console') && req.method === 'GET') {
        try {
          const html = require('node:fs').readFileSync(require('node:path').join(__dirname, 'dashboard.html'), 'utf8');
          const b = Buffer.from(html, 'utf8');
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': b.length, 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'x-request-id': req._rid });
          logLine(200); return res.end(b);
        } catch { return fail(Object.assign(new Error('no console'), { code: 'not_found' })); }
      }
      if ((p === '/v1/health' || p === '/health') && (req.method === 'GET' || req.method === 'HEAD')) {
        const payload = {
          ok: true, service: 'authragen', v: 2, protocol: PROTOCOL_VERSION, time: Date.now(),
          store: storeBackend(), persistence: getStore().lastWriteError ? 'degraded' : 'ok',
          custody_policy: allowCustody() ? 'dev (server custody ALLOWED)' : 'self-custody enforced'
        };
        if (req.method === 'HEAD') { logLine(200); res.writeHead(200, securityHeaders(req)); return res.end(); }
        return ok(200, payload);
      }

      if (p === '/metrics' && req.method === 'GET') {
        try {
          const metricsOutput = await metrics.register.metrics();
          res.writeHead(200, { 'content-type': metrics.register.contentType, 'x-request-id': req._rid });
          return res.end(metricsOutput);
        } catch (e) {
          return fail(Object.assign(new Error('metrics error'), { code: 'internal' }));
        }
      }

      if (p.startsWith('/v1/orgs/') && p.endsWith('/pubkey') && req.method === 'GET') {
        rateLimit(req, 'pubkey', 120);
        const id = p.split('/')[3];
        const opk = orgPubkey(id) || getStore().get('orgs', id)?.pubkey;
        if (!opk) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
        const signer = getOrgSigner(id);
        return ok(200, { org_id: id, pubkey: opk, alg: signer.getAlgorithm ? signer.getAlgorithm() : 'EdDSA' });
      }
      if (p === '/v1/orgs' && req.method === 'POST') {
        rateLimit(req, 'bootstrap', 5);
        const b = await body(req);
        if (!b.name) return fail(Object.assign(new Error('name required'), { code: 'bad_request' }));
        if (!auth.checkBootstrap(req.headers['x-bootstrap-token'])) return fail(Object.assign(new Error('valid x-bootstrap-token required (printed at first boot)'), { code: 'unauthorized' }));
        const org = createOrgRecord(b.name);
        for (const pol of seedPolicies(org.id)) getStore().put('policies', pol);
        const key = auth.mintKey(org.id, 'admin', 'initial-admin');
        auth.consumeBootstrap();
        audit.append({ org_id: org.id, actor: org.id, action: 'org.create', resource: org.id, decision: 'allow', risk: 0, policy_id: null, reasons: ['bootstrap'], request_id: req._rid });
        const fullSecret = `${key.key_id}.${key.secret}`;
        return ok(201, { ...publicOrg(org), org_pubkey: orgPubkey(org.id), admin_key_id: key.key_id, admin_secret: fullSecret });
      }
      if (p === '/v1/orgs' && req.method === 'GET') {
        const k = callerKey(req);
        if (!k) return fail(Object.assign(new Error('auth required'), { code: 'unauthorized' }));
        return ok(200, { orgs: getStore().byOrg('orgs', k.org_id).concat(getStore().all('orgs').filter(o => o.id === k.org_id)).filter((v, i, a) => a.findIndex(x => x.id === v.id) === i).map(publicOrg) });
      }
      if (/^\/v1\/orgs\/[^/]+$/.test(p) && req.method === 'GET') {
        const orgId = p.split('/')[3];
        const k = callerKey(req);
        try { auth.requireRole(k, orgId, 'reporter'); } catch (e) { return fail(e); }
        const org = getStore().get('orgs', orgId);
        if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
        return ok(200, { ...publicOrg(org), risk_ceiling: org.risk_ceiling ?? RISK_CEILING_DEFAULT, risk_stepup: org.risk_stepup ?? RISK_STEPUP_DEFAULT });
      }
      if (/^\/v1\/orgs\/[^/]+\/(lock|unlock)$/.test(p) && req.method === 'POST') {
        const [_, orgId, op] = p.split('/').filter(Boolean).slice(1);
        const k = callerKey(req);
        try {
          if (!k) throw Object.assign(new Error('missing credentials'), { code: 'unauthorized' });
          if (k.org_id !== orgId) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
          if (k.role !== 'admin') throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
        } catch (e) { return fail(e); }
        const org = getStore().get('orgs', orgId);
        if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
        org.locked = op === 'lock';
        org.locked_at = org.locked ? Date.now() : null;
        org.locked_by = org.locked ? k.id : null;
        getStore().put('orgs', org);
        audit.append({ org_id: orgId, actor: k.id, action: `org.${op}`, resource: orgId, decision: 'allow', risk: 0, policy_id: null, reasons: [`emergency:${op}`], request_id: req._rid });
        return ok(200, { ok: true, locked: org.locked });
      }
      if (/^\/v1\/orgs\/[^/]+\/risk$/.test(p) && req.method === 'PUT') {
        const orgId = p.split('/')[3];
        const k = callerKey(req);
        try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
        const b = await body(req);
        const org = getStore().get('orgs', orgId);
        if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
        if (b.risk_ceiling != null) { const n = Number(b.risk_ceiling); if (!Number.isInteger(n) || n < 0 || n > 100) throw Object.assign(new Error('risk_ceiling must be an integer 0..100'), { code: 'bad_request' }); org.risk_ceiling = n; }
        if (b.risk_stepup != null) { const n = Number(b.risk_stepup); if (!Number.isInteger(n) || n < 0 || n > 100) throw Object.assign(new Error('risk_stepup must be an integer 0..100'), { code: 'bad_request' }); org.risk_stepup = n; }
        if (org.risk_stepup >= org.risk_ceiling) throw Object.assign(new Error('risk_stepup must be below risk_ceiling'), { code: 'bad_request' });
        getStore().put('orgs', org);
        return ok(200, { ok: true, risk_ceiling: org.risk_ceiling, risk_stepup: org.risk_stepup });
      }
      if (/^\/v1\/orgs\/[^/]+\/keys$/.test(p) && req.method === 'POST') {
        rateLimit(req, 'keys', 60);
        const orgId = p.split('/')[3];
        const k = callerKey(req);
        try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
        const b = await body(req);
        return ok(201, auth.mintKey(orgId, b.role || 'executor', b.name));
      }
      if (/^\/v1\/orgs\/[^/]+\/keys$/.test(p) && req.method === 'GET') {
        const orgId = p.split('/')[3];
        const k = callerKey(req);
        try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
        const keys = getStore().byOrg('apikeys', orgId).map(k => ({
          id: k.id, key_id: k.key_id, org_id: k.org_id, role: k.role, name: k.name,
          expires_at: k.expires_at || null, last_used: k.last_used || null,
          revoked: !!k.revoked, created_at: k.created_at || null
        }));
        return ok(200, { keys });
      }
      if (/^\/v1\/orgs\/[^/]+\/keys\/rotate$/.test(p) && req.method === 'POST') {
        const orgId = p.split('/')[3];
        const k = callerKey(req);
        try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
        const b = await body(req);
        try {
          if (!b.key_id) throw Object.assign(new Error('key_id required'), { code: 'bad_request' });
          const target = getStore().get('apikeys', b.key_id);
          if (!target || target.org_id !== orgId) throw Object.assign(new Error('unknown key'), { code: 'bad_request' });
          const out = auth.rotateKey(b.key_id);
          audit.append({ org_id: orgId, actor: k.id, action: 'apikey.rotate', resource: b.key_id, decision: 'allow', risk: 5, policy_id: null, reasons: [`rotated:${out.key_id}`], request_id: req._rid });
          return ok(201, out);
        } catch (e) { return fail(e); }
      }

      if (p === '/v1/blueprints' && req.method === 'POST') {
        const b = await body(req);
        const k = callerKey(req);
        try {
          if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
          auth.requireRole(k, b.org_id, 'admin');
          const bp = createBlueprint({ org_id: b.org_id, name: b.name, description: b.description, policies: b.policies, permissions: b.permissions, required_approvals: b.required_approvals });
          audit.append({ org_id: bp.org_id, actor: k.id, action: 'blueprint.create', resource: bp.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`v:${bp.version}`], request_id: req._rid });
          return ok(201, bp);
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/blueprints' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const items = getStore().byOrg('blueprints', org).map(bp => ({ ...bp, instances: blueprintInstances(bp.id) }));
          return ok(200, { blueprints: items });
        } catch (e) { return fail(e); }
      }
      if (/^\/v1\/blueprints\/[^/]+$/.test(p) && req.method === 'GET') {
        const id = p.split('/')[3];
        const bp = getStore().get('blueprints', id);
        if (!bp) return fail(Object.assign(new Error('unknown blueprint'), { code: 'bad_request' }));
        const k = callerKey(req);
        try { auth.requireRole(k, bp.org_id, 'reporter'); } catch (e) { return fail(e); }
        return ok(200, { ...bp, instances: blueprintInstances(bp.id) });
      }

      if (p === '/v1/passports' && req.method === 'POST') {
        rateLimit(req, 'issuance', 60);
        const b = await body(req);
        const k = callerKey(req);
        try {
          if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
          auth.requireRole(k, b.org_id, 'admin');
          const pass = await issuePassport(b);
          audit.append({ org_id: pass.org_id, actor: k.id, action: 'passport.issue', resource: pass.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`kind:${pass.kind}`, `custody:${pass.custody}`], request_id: req._rid });
          return ok(201, pass);
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/passports' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const { items, total } = getStore().list('passports', { org_id: org, status: u.query.status || null, limit: Math.min(200, Number(u.query.limit) || 50), offset: Number(u.query.offset) || 0, q: u.query.q || null });
          let filtered = items;
          for (const f of ['owner', 'team', 'environment', 'model', 'framework', 'blueprint_id']) {
            if (u.query[f]) filtered = filtered.filter(x => String(x[f] || '') === String(u.query[f]));
          }
          return ok(200, { passports: filtered.map(publicPassport), total, limit: Math.min(200, Number(u.query.limit) || 50), offset: Number(u.query.offset) || 0 });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/passports/rotate' && req.method === 'POST') {
        const b = await body(req);
        try {
          const cur = getStore().get('passports', b.passport_id);
          if (!cur || !cur.org_id) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
          auth.requireRole(callerKey(req), cur.org_id, 'admin');
          const pass = await rotatePassport(b.passport_id, b.new_pubkey);
          const rc = audit.append({ org_id: pass.org_id, actor: b.passport_id, action: 'passport.rotate', resource: pass.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`kid:${pass.keys.current.kid}`], request_id: req._rid });
          return ok(200, { ...pass, receipt: rc });
        } catch (e) { return fail(e); }
      }
      if (/^\/v1\/passports\/[^/]+\/status$/.test(p) && req.method === 'POST') {
        const id = p.split('/')[3];
        const b = await body(req);
        try {
          const cur = getStore().get('passports', id);
          if (!cur) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
          auth.requireRole(callerKey(req), cur.org_id, 'admin');
          if (!LIFECYCLE.includes(b.status)) throw Object.assign(new Error('invalid status'), { code: 'bad_request' });
          const pass = await setPassportStatus(id, b.status);
          let revocation = null;
          if (b.status === 'revoked' && !getStore().has('revocations', 'passport:' + id)) {
            revocation = addRevocation({ type: 'passport', target: id, org_id: pass.org_id, reason: b.reason || 'status:revoked' });
          }
          audit.append({
            org_id: pass.org_id, actor: callerKey(req)?.id || 'admin', action: `passport.${b.status}`, resource: id, decision: 'allow', risk: 5, policy_id: null,
            reasons: [b.reason || b.status, ...(revocation ? [`revocation_seq:${revocation.seq}`] : [])], request_id: req._rid
          });
          return ok(200, { ...pass, revocation_seq: revocation?.seq || null });
        } catch (e) { return fail(e); }
      }
      if (/^\/v1\/passports\/[^/]+\/keys\/revoke$/.test(p) && req.method === 'POST') {
        const id = p.split('/')[3];
        const b = await body(req);
        try {
          const cur = getStore().get('passports', id);
          if (!cur) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
          auth.requireRole(callerKey(req), cur.org_id, 'admin');
          if (!b.kid) throw Object.assign(new Error('kid required'), { code: 'bad_request' });
          const pass = await revokeKey(id, b.kid);
          addRevocation({ type: 'key', target: id, kid: b.kid, org_id: pass.org_id, reason: b.reason });
          return ok(200, pass);
        } catch (e) { return fail(e); }
      }
      if (p.startsWith('/v1/passports/') && req.method === 'GET' && !p.endsWith('/rotate') && !p.endsWith('/status') && !p.endsWith('/revoke')) {
        const id = p.split('/')[3];
        const pass = getStore().get('passports', id);
        if (!pass) return fail(Object.assign(new Error('not found'), { code: 'not_found' }));
        const k = callerKey(req);
        try { auth.requireRole(k, pass.org_id, 'reporter'); } catch (e) { return fail(e); }
        return ok(200, { ...publicPassport(pass), status: passportStatus(pass) });
      }

      if (p === '/v1/delegate' && req.method === 'POST') {
        const b = await body(req);
        try {
          if (!b.org_id || !b.delegator_id || !b.payload || !b.envelope) throw Object.assign(new Error('org_id, delegator_id, payload, envelope required'), { code: 'bad_request' });
          const k = callerKey(req);
          if (k) auth.requireRole(k, b.org_id, 'executor');
          else if (!b.payload.parent_jti && b.payload.sub !== b.delegator_id) throw Object.assign(new Error('service key required to delegate for another agent'), { code: 'unauthorized' });
          const tok = registerDelegation({ org_id: b.org_id, delegator_id: b.delegator_id, payload: b.payload, envelope: b.envelope, callerIsAdmin: !!k && k.role === 'admin' });
          audit.append({ org_id: tok.org_id, actor: tok.issuer, action: 'token.delegate', resource: tok.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`depth:${tok.depth}`, `auth:${k ? 'service_key:' + k.id : 'delegator_sig'}`], request_id: req._rid });
          return ok(201, tok);
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/delegations' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const { items, total } = getStore().list('tokens', { org_id: org, limit: Math.min(200, Number(u.query.limit) || 50), offset: Number(u.query.offset) || 0 });
          return ok(200, { delegations: items, total });
        } catch (e) { return fail(e); }
      }

      if (p === '/v1/policies' && req.method === 'POST') {
        const b = await body(req);
        const k = callerKey(req);
        try {
          if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
          auth.requireRole(k, b.org_id, 'admin');
          const pol = newPolicy(b.org_id, b);
          getStore().put('policies', pol);
          audit.append({ org_id: pol.org_id, actor: k.id, action: 'policy.create', resource: pol.id, decision: 'allow', risk: 0, policy_id: pol.id, policy_hash: pol.hash, reasons: [`v:${pol.version}`], request_id: req._rid });
          return ok(201, pol);
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/policies' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const all = getStore().byOrg('policies', org);
          return ok(200, { policies: all });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/policies/simulate' && req.method === 'POST') {
        const b = await body(req);
        const k = callerKey(req);
        try {
          if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
          auth.requireRole(k, b.org_id, 'reporter');
          const policies = getStore().byOrg('policies', b.org_id);
          const out = simulate(policies, { action: b.action, resource: b.resource, context: b.context || {} });
          return ok(200, { ...out, request_id: req._rid });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/policies/conflicts' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          return ok(200, { conflicts: detectConflicts(getStore().byOrg('policies', org)) });
        } catch (e) { return fail(e); }
      }
      if (/^\/v1\/policies\/[^/]+$/.test(p) && req.method === 'PUT') {
        const id = p.split('/')[3];
        const b = await body(req);
        const k = callerKey(req);
        try {
          const cur = getStore().get('policies', id);
          if (!cur) throw Object.assign(new Error('unknown policy'), { code: 'not_found' });
          auth.requireRole(k, cur.org_id, 'admin');
          const next = { ...cur, ...b, id: cur.id, org_id: cur.org_id, version: (cur.version || 1) + 1, updated_at: Date.now() };
          next.hash = policyHash(next);
          getStore().put('policies', next);
          audit.append({ org_id: next.org_id, actor: k.id, action: 'policy.update', resource: next.id, decision: 'allow', risk: 0, policy_id: next.id, policy_hash: next.hash, reasons: [`v:${next.version}`], request_id: req._rid });
          return ok(200, next);
        } catch (e) { return fail(e); }
      }

      if (p === '/v1/authorize' && req.method === 'POST') {
        rateLimit(req, 'authorize', 180);
        const b = await body(req);
        try {
          const out = await authorize({ ...b, request_id: req._rid }, callerKey(req));
          const code = out.decision === 'allow' ? 200 : out.decision === 'step_up' ? 202 : out.decision === 'dry_run' ? 200 : 403;
          return ok(code, out);
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/execute' && req.method === 'POST') {
        rateLimit(req, 'execute', 180);
        const b = await body(req);
        try {
          const out = await execute({ ...b, request_id: req._rid });
          return ok(200, out);
        } catch (e) { return fail(e); }
      }

      if (p.startsWith('/v1/approvals/') && req.method === 'POST') {
        const id = p.split('/')[3];
        const b = await body(req);
        try {
          const ap = getStore().get('approvals', id);
          if (!ap) throw Object.assign(new Error('unknown approval'), { code: 'not_found' });
          const k = callerKey(req);
          if (!k) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, ap.org_id, 'approver');
          if (ap.status !== 'pending' && ap.status !== 'partial') throw Object.assign(new Error('already resolved'), { code: 'approval_resolved' });
          if (Date.now() > ap.expires_at) { ap.status = 'expired'; getStore().put('approvals', ap); throw Object.assign(new Error('approval expired'), { code: 'approval_expired' }); }
          const who = { id: k.id, role: k.role, note: typeof b.by === 'string' ? String(b.by).slice(0, 128) : null, at: Date.now() };
          ap.approvals = ap.approvals || [];
          if (ap.approvals.some(a => a.id === k.id)) throw Object.assign(new Error('approver already recorded (quorum needs distinct approvers)'), { code: 'approval_resolved' });
          if (b.approve === false || b.decision === 'denied') {
            ap.status = 'denied';
            ap.decided_by = who.id; ap.decided_by_role = who.role; ap.decided_at = who.at;
            getStore().put('approvals', ap);
            const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: 'denied', risk: ap.risk, policy_id: ap.policy_id, policy_hash: ap.policy_hash, reasons: [`approval:${id}:denied`, `by:${who.id}/${who.role}`], intent_hash: ap.intent_hash, request_id: req._rid });
            return ok(200, { ...ap, approval_credential: null, receipt: rc, request_id: req._rid });
          }
          ap.approvals.push(who);
          const need = ap.quorum || 1;
          if (ap.approvals.length < need) {
            ap.status = 'partial';
            getStore().put('approvals', ap);
            const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: 'step_up', risk: ap.risk, policy_id: ap.policy_id, reasons: [`approval:${id}:partial:${ap.approvals.length}/${need}`, `by:${who.id}`], intent_hash: ap.intent_hash, request_id: req._rid });
            return ok(202, { ...ap, receipt: rc, request_id: req._rid, note: `quorum ${ap.approvals.length}/${need} — need ${need - ap.approvals.length} more distinct approver(s)` });
          }
          ap.status = 'approved';
          ap.decided_by = ap.approvals.map(a => a.id).join(',');
          ap.decided_by_role = who.role; ap.decided_at = Date.now();
          getStore().put('approvals', ap);
          let credential = null;
          let actionTokenEnvelope = null;
          if (ap.status === 'approved') {
            const att = await buildActionToken({ orgSigner: getOrgSigner(ap.org_id), org_id: ap.org_id, sub: ap.passport_id, intent_hash: ap.intent_hash, action: ap.action, resource: ap.resource, amount_cents: ap.amount_cents, requires_approval: true, token_jti: ap.token_jti, aud: ap.aud || 'authragen', kid: ap.agent_kid || null });
            ap.action_jti = att.jti; actionTokenEnvelope = att.envelope; getStore().put('approvals', ap);
            credential = await buildApproval({ orgSigner: getOrgSigner(ap.org_id), approval_id: ap.id, org_id: ap.org_id, passport_id: ap.passport_id, intent_hash: ap.intent_hash, action: ap.action, resource: ap.resource, by: ap.decided_by, by_role: who.role, by_key_id: who.id, action_jti: att.jti, aud: ap.aud || 'authragen' });
            ap.approval_jti = credential.payload.jti || ap.id; getStore().put('approvals', ap);
          }
          const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: ap.status, risk: ap.risk, policy_id: ap.policy_id, policy_hash: ap.policy_hash, reasons: [`approval:${id}:${ap.status}`, `by:${ap.decided_by}/${who.role}`, `quorum:${need}`], intent_hash: ap.intent_hash, request_id: req._rid });
          return ok(200, { ...publicApproval(ap), action_token: actionTokenEnvelope, approval_credential: credential?.envelope || null, receipt: rc, request_id: req._rid });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/approvals' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          let all = getStore().byOrg('approvals', org);
          if (u.query.status) all = all.filter(a => a.status === u.query.status);
          return ok(200, { approvals: all.slice(-(Math.min(200, Number(u.query.limit) || 100))).map(publicApproval) });
        } catch (e) { return fail(e); }
      }

      if (p === '/v1/revoke' && req.method === 'POST') {
        const b = await body(req);
        try {
          if (!b.type || !b.id) throw Object.assign(new Error('type + id required'), { code: 'bad_request' });
          const allowed = ['passport', 'token', 'apikey', 'action', 'key', 'blueprint', 'org'];
          if (!allowed.includes(b.type)) throw Object.assign(new Error('unknown revoke type'), { code: 'bad_request' });
          let targetOrg = null;
          if (b.type === 'passport') targetOrg = getStore().get('passports', b.id)?.org_id;
          else if (b.type === 'token') targetOrg = getStore().get('tokens', b.id)?.org_id;
          else if (b.type === 'apikey') targetOrg = getStore().get('apikeys', b.id)?.org_id;
          else if (b.type === 'action') targetOrg = b.org_id || null;
          else if (b.type === 'key') targetOrg = getStore().get('passports', b.id)?.org_id;
          else if (b.type === 'blueprint') targetOrg = getStore().get('blueprints', b.id)?.org_id;
          else if (b.type === 'org') targetOrg = getStore().get('orgs', b.id)?.id;
          if (!targetOrg) throw Object.assign(new Error('unknown target'), { code: 'bad_request' });
          auth.requireRole(callerKey(req), targetOrg, 'admin');
          if (b.type === 'passport') { await setPassportStatus(b.id, 'revoked'); }
          if (b.type === 'apikey') { const ak = getStore().get('apikeys', b.id); if (ak) { ak.revoked = true; getStore().put('apikeys', ak); } }
          if (b.type === 'key') { await revokeKey(b.id, b.kid); }
          if (b.type === 'blueprint') { const bp = getStore().get('blueprints', b.id); if (bp) { bp.status = 'revoked'; getStore().put('blueprints', bp); } }
          if (b.type === 'org') { const o = getStore().get('orgs', b.id); if (o) { o.locked = true; o.locked_at = Date.now(); getStore().put('orgs', o); } }
          const rec = addRevocation({ type: b.type, target: b.id, kid: b.kid || null, org_id: targetOrg, reason: b.reason });
          const rc = audit.append({ org_id: targetOrg, actor: 'admin', action: `${b.type}.revoke`, resource: b.id, decision: 'revoked', risk: 0, policy_id: null, reasons: [b.reason || 'manual', 'cascade:children-fail-closed', `seq:${rec.seq}`], request_id: req._rid });
          return ok(200, { ok: true, revoked: rec.id, seq: rec.seq, cascade: 'children fail closed (passports→sub-agents, tokens→children, blueprints→agents, org→all)', receipt: rc, request_id: req._rid });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/revoked' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const since = Number(u.query.since) || 0;
          const sinceSeq = Number(u.query.since_seq) || 0;
          const all = getStore().all('revocations')
            .filter(r => (!r.org_id || r.org_id === org))
            .filter(r => (r.at || 0) >= since && (r.seq || 0) > sinceSeq)
            .sort((a, b) => (a.seq || 0) - (b.seq || 0));
          return ok(200, { revocations: all, as_of: Date.now(), head_seq: revocationHead(), freshness_note: 'ONLINE live status. Offline verifiers: cache this feed + checkpoints; without a fresh feed you have authenticity-without-freshness.' });
        } catch (e) { return fail(e); }
      }

      async function doVerify({ envelope, org_id, token_id }) {
        if (token_id) {
          const tok = getStore().get('tokens', token_id);
          if (!tok) throw Object.assign(new Error('unknown token'), { code: 'token_unknown' });
          assertTokenUsable(tok);
          return { ok: true, mode: 'registered', jti: tok.id, sub: tok.sub, depth: tok.depth, signature_valid: true, credential_valid: true, expiry_valid: true, revocation_freshness: 'fresh' };
        }
        if (!envelope || !org_id) throw Object.assign(new Error('envelope + org_id required'), { code: 'bad_request' });
        const opk = orgPubkey(org_id);
        if (!opk) throw Object.assign(new Error('unknown org'), { code: 'org_unknown' });
        const v = verifyOffline(envelope, opk, {});
        if (!v.signature_valid) throw Object.assign(new Error('envelope signature invalid'), { code: 'sig_invalid' });
        if (!v.credential_valid) throw Object.assign(new Error(v.error || 'credential invalid'), { code: 'token_malformed' });
        if (v.payload.org_id !== org_id) throw Object.assign(new Error('credential organization mismatch'), { code: 'token_mismatch' });
        const subject = getStore().get('passports', v.payload.sub);
        if (!subject || subject.org_id !== org_id) throw Object.assign(new Error('credential subject unavailable'), { code: 'passport_unknown' });
        assertPassportUsable(subject);
        if (v.payload.kind === 'action' && v.payload.kid) keyFor(subject, v.payload.kid);
        let freshness = 'unknown (offline: poll GET /v1/revoked)';
        try {
          const live = v.payload.kind === 'action' && (getStore().has('revocations', 'action:' + v.payload.jti) || getStore().has('revocations', 'token:' + (v.payload.token_jti || '')));
          freshness = live ? 'revoked' : 'fresh (online check)';
          if (live) throw Object.assign(new Error('credential revoked'), { code: 'token_revoked' });
        } catch (e) { if (e.code === 'token_revoked') throw e; }
        return { ok: true, mode: 'stateless', kind: v.payload.kind, sub: v.payload.sub, intent_hash: v.payload.intent_hash, aud: v.payload.aud, exp: v.payload.exp, signature_valid: true, credential_valid: true, expiry_valid: v.expiry_valid, revocation_freshness: freshness, freshness_note: 'poll GET /v1/revoked for revocation freshness; offline needs a fresh feed/checkpoint' };
      }
      if (p === '/v1/verify' && req.method === 'POST') {
        rateLimit(req, 'verify', 120);
        const b = await body(req);
        try { return ok(200, await doVerify(b)); }
        catch (e) { return fail(e); }
      }
      if (p === '/v1/verify' && req.method === 'GET') {
        rateLimit(req, 'verify', 60);
        try {
          const { envelope, org_id, token_id } = u.query;
          return ok(200, await doVerify({ envelope, org_id, token_id }));
        } catch (e) { return fail(e); }
      }

      if (p === '/v1/audit' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const limit = Math.min(500, Number(u.query.limit) || 100);
          const offset = Number(u.query.offset) || 0;
          const all = audit.byOrg(org, Number.MAX_SAFE_INTEGER);
          return ok(200, { receipts: all.slice(Math.max(0, all.length - offset - limit), all.length - offset || undefined), total: all.length });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/audit/export' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          const format = u.query.format || 'json';
          if (format === 'jsonl') {
            const data = audit.exportJsonl(org);
            const b = Buffer.from(data, 'utf8');
            res.writeHead(200, { ...securityHeaders(req), 'content-type': 'application/x-ndjson', 'content-length': b.length });
            logLine(200); return res.end(b);
          }
          return ok(200, { receipts: audit.byOrg(org, Number.MAX_SAFE_INTEGER) });
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/audit/evidence' && req.method === 'POST') {
        const b = await body(req);
        const k = callerKey(req);
        try {
          if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
          auth.requireRole(k, b.org_id, 'reporter');
          return ok(201, await audit.evidenceBundle({ org_id: b.org_id, intent_hash: b.intent_hash || null, passport_id: b.passport_id || null, signer: gatewaySigner() }));
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/audit/verify' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          const org = u.query.org_id || k?.org_id;
          if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, org, 'reporter');
          return ok(200, audit.verify());
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/audit/checkpoint' && req.method === 'POST') {
        const k = callerKey(req);
        try {
          if (!k) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, k.org_id, 'admin');
          return ok(201, await audit.checkpoint(gatewaySigner()));
        } catch (e) { return fail(e); }
      }
      if (p === '/v1/audit/checkpoints' && req.method === 'GET') {
        const k = callerKey(req);
        try {
          if (!k) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
          auth.requireRole(k, k.org_id, 'reporter');
          return ok(200, { checkpoints: audit.listCheckpoints(), gateway_pubkey: gatewaySigner().pubkey });
        } catch (e) { return fail(e); }
      }

      return fail(Object.assign(new Error('not found: ' + p), { code: 'not_found' }));
    } catch (e) {
      return fail(Object.assign(new Error(IS_PROD ? 'internal error' : String(e.message)), { code: e.code || 'internal' }));
    }
  });

  // custody census
  try {
    const legacy = getStore().all('passports').filter(p => (p._privX && p._privD) || p.custody === 'server-legacy').length;
    if (legacy) logger.warn({ event: 'legacy_custody', count: legacy, message: 'passport(s) have server-held private keys (pre-v2). Rotate to self-custody CSRs.' });
    if (allowCustody()) logger.warn({ event: 'custody_warning', message: 'AUTHRA_ALLOW_CUSTODY=1 — server-custodied agent keys permitted (local dev only).' });
    if ((process.env.AUTHRA_KMS || 'file') === 'file') logger.warn({ event: 'kms_warning', message: 'file-backed org roots (dev default). Production MUST set AUTHRA_KMS to a real KMS/HSM.' });
  } catch {}

  // first-run bootstrap: print one-time token for creating the first org
  const pending = auth.bootstrapToken();
  if (pending && pending.fresh) {
    logger.info({ event: 'bootstrap_token', token: pending.fresh });
    console.log('\n==============================================================');
    console.log('  FIRST RUN — save this one-time bootstrap token:');
    console.log(`    AUTHRA_BOOTSTRAP=${pending.fresh}`);
    console.log('  Create the first org: POST /v1/orgs with x-bootstrap-token header.');
    console.log('==============================================================\n');
    auth.markBootstrapPrinted();
  }

  server.listen(PORT, () => {
    logger.info({ event: 'server_started', port: PORT, store: storeBackend(), kms: KMS_TYPE });
    console.log(`AuthraGen gateway v2 on http://localhost:${PORT}`);
  });
  const shutdown = async (signal) => {
    logger.info({ event: 'shutdown', signal });
    await new Promise(resolve => server.close(resolve));
    try { await getStore().close?.(); } catch {}
  };
  process.once('SIGTERM', () => shutdown('SIGTERM').finally(() => process.exit(0)));
  process.once('SIGINT', () => shutdown('SIGINT').finally(() => process.exit(0)));
  return server;
}

if (require.main === module) {
  main().catch(e => {
    logger.error({ event: 'fatal', error: e.message, stack: e.stack });
    process.exit(1);
  });
}

module.exports = { authorize, execute };