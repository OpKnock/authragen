'use strict';
// AuthraGen gateway v2/vNext — authenticated, intent-bound, replay-safe.
//
// Zero npm dependencies. Run: node src/server.js (PORT default 8787)
//
// Security model:
// - Management APIs require org API keys (admin/approver/executor/reporter),
//   tenant-isolated (every lookup scoped to org; cross-org → generic 403).
// - First org requires a printed bootstrap token (single-use).
// - authorize/execute bind to an AGENT-SIGNED intent (exact action hash) or a
//   service key (trusted-middleware path, recorded in receipts).
// - Spend + action-token consumption are atomic under a mutex (single process).
//   Distributed deployments MUST use Postgres transactions or Redis SET NX EX —
//   same record shapes, see README production notes. Process-local locks are
//   documented as insufficient for multi-instance production.
// - Audit is tamper-EVIDENT (hash-chained + signed checkpoints), not "immutable".
const http = require('node:http');
const url = require('node:url');
const crypto = require('node:crypto');
const { store } = require('./store');
const { createOrgRecord, publicOrg, orgPubkey, issuePassport, publicPassport, rotatePassport,
  setPassportStatus, revokeKey, touchLastSeen, passportStatus, LIFECYCLE,
  createBlueprint, blueprintInstances, isOrgLocked, assertOrgUsable,
  assertPassportUsable, keyFor, registerDelegation, assertTokenUsable, tokenCovers,
  checkBudget, debitBudget, allowCustody } = require('./tokens');
const { evaluate, simulate, detectConflicts, newPolicy, seedPolicies, policyHash } = require('./policy');
const { score, listRiskProviders } = require('./risk');
const audit = require('./audit');
const auth = require('./auth');
const { getOrgSigner, gatewaySigner } = require('./signer');
const { canonicalIntent, intentHash, checkIntentShape, verifyAgentIntent, openWithOrgKey,
  buildActionToken, buildApproval, verifyOffline, PROTOCOL_VERSION } = require('./intent');
const { hasDuplicateKeys } = require('./crypto');
const nonce = require('./nonce');

const PORT = process.env.PORT || 8787;
const IS_PROD = process.env.NODE_ENV === 'production';
const BODY_LIMIT = Number(process.env.AUTHRA_BODY_LIMIT || 256 * 1024);
const CORS_ORIGIN = process.env.AUTHRA_CORS || '*';
const TRUST_PROXY = process.env.AUTHRA_TRUST_PROXY === '1';
const RISK_CEILING_DEFAULT = Number(process.env.AUTHRA_RISK_CEILING || 85);
const RISK_STEPUP_DEFAULT = Number(process.env.AUTHRA_RISK_STEPUP || 30);

function newRequestId() { return 'rq_' + crypto.randomBytes(6).toString('hex'); }
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

// ---- rate limiting (in-memory token bucket per ip+route; distributed needs Redis) ----
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
function sendErr(req, res, e) {
  const map = {
    unauthorized: 401, forbidden: 403, bad_request: 400, bad_intent: 400,
    rate_limited: 429, quota_exceeded: 429, org_locked: 403, token_expired: 403,
    approval_expired: 403, intent_expired: 403, replay: 409, approval_resolved: 409,
    storage_error: 500,
  };
  let code = map[e.code] || e.status;
  if (!code) {
    if (/unknown|not_found/.test(e.code || '')) code = 404;
    else if (/expired|revoked|suspended|quarantined|denied|insufficient|exceeded|replay|mismatch|invalid|malformed|authorized|forbidden|custody|locked/.test(e.code || '')) code = 403;
    else code = 400;
  }
  // 410 Gone for consumed single-use credentials is more precise than 403;
  // keep 403-compatible `replay` code but surface 409 Conflict for clients.
  const body = { error: e.code || 'bad_request', request_id: req._rid };
  if (e.retryAfter) { res.setHeader?.('retry-after', String(e.retryAfter)); body.retry_after = e.retryAfter; }
  // Never leak internals in production; full message only in dev.
  body.message = IS_PROD && code === 500 ? 'internal error' : String(e.message || e.code).slice(0, 500);
  return send(req, res, code, body);
}
function bodyRaw(req, { limit = BODY_LIMIT } = {}) {
  return new Promise((resolve, reject) => {
    let len = 0; const chunks = []; let rejected = false;
    req.on('data', c => {
      if (rejected) return; // drain remaining without buffering (fail-closed 413 follows)
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
// async mutex: execute/authorize critical sections run serialized per process.
// (Multi-process deployments need a DB transaction here — same record shape.
//  A process-local mutex is explicitly NOT sufficient for distributed production.)
let lock = Promise.resolve();
function withLock(fn) { const r = lock.then(fn); lock = r.catch(() => {}); return r; }

const seen = new Map();
function isSeen(pid, resource) { return seen.has(pid) && seen.get(pid).has(resource); }
function markSeen(pid, resource) { if (!seen.has(pid)) seen.set(pid, new Set()); seen.get(pid).add(resource); }

// Resolve caller: {key} for service path, or null (agent-sig path handled per-request).
function callerKey(req) { return auth.lookupKey(auth.bearerOf(req)); }
function orgRisk(org_id) {
  const org = store.get('orgs', org_id);
  return {
    ceiling: org?.risk_ceiling ?? RISK_CEILING_DEFAULT,
    stepup: org?.risk_stepup ?? RISK_STEPUP_DEFAULT,
    version: 'risk-v1',
  };
}

// ---- authorize: decision only (no effects except audit + optional approval record). ----
async function authorize({ intent, intent_sig, kid, token_id, context = {}, dry_run = false, request_id = null }, svcKey, reqMeta = {}) {
  const rid = request_id || newRequestId();
  const ci = checkIntentShape(intent); // throws on malformed/expired/overlong
  assertOrgUsable(ci.org_id);
  const pass = store.get('passports', ci.passport_id);
  // Tenant isolation: never reveal whether a passport exists in another org.
  if (!pass || pass.org_id !== ci.org_id) throw Object.assign(new Error('Unknown passport'), { code: 'passport_unknown' });
  // Authentication: agent proof-of-possession preferred; service key = trusted middleware.
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
  // Liveness: revoked/expired/held identities are deny-DECISIONS with receipts.
  try { assertPassportUsable(pass); }
  catch (e) {
    if (/passport_revoked|passport_expired|passport_suspended|passport_quarantined|key_revoked|key_expired|unknown_kid|org_locked/.test(e.code || '')) return deny([e.code], 100, null);
    throw e;
  }
  // Token stage: failures are deny-DECISIONS with receipts, not silent errors.
  try {
    if (token_id) {
      tok = store.get('tokens', token_id);
      if (!tok || tok.org_id !== ci.org_id) throw Object.assign(new Error('Unknown token'), { code: 'token_unknown' });
      assertTokenUsable(tok);
      if (tok.sub !== ci.passport_id) throw Object.assign(new Error('Token subject mismatch'), { code: 'token_mismatch' });
      if (!tokenCovers(tok, ci.action, ci.resource)) throw Object.assign(new Error('Token scope/targets insufficient'), { code: 'scope_insufficient' });
      checkBudget(tok, ci.amount_cents); // availability only; debit happens at execute
    }
  } catch (e) { return deny([e.code || 'token_error'], 100, null); }
  const passRec = store.get('passports', ci.passport_id);
  const ctx = {
    amount_cents: ci.amount_cents, spend_cents: ci.amount_cents, depth: tok ? tok.depth : 0,
    tool: ci.tool, aud: ci.aud, environment: passRec?.environment, blueprint_id: passRec?.blueprint_id,
    passport_id: ci.passport_id, agent_id: ci.passport_id,
  };
  const policies = store.byOrg('policies', ci.org_id);
  const ev = evaluate(policies, { action: ci.action, resource: ci.resource, context: ctx });
  reasons.push(...ev.reasons);
  const riskCfg = orgRisk(ci.org_id);
  const risk = score({ action: ci.action, resource: ci.resource, context: { spend_cents: ci.amount_cents, depth: ctx.depth }, seen: isSeen(ci.passport_id, ci.resource) });
  reasons.push(`risk:${risk.score}(${risk.band})`);
  markSeen(ci.passport_id, ci.resource);
  touchLastSeen(ci.passport_id);

  // Hard security rules can never be bypassed by a low risk score: policy deny
  // always wins; risk ceiling only ADDS denials, never removes them.
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
    const ap = { id: 'apr_' + crypto.randomBytes(5).toString('hex'), org_id: ci.org_id, passport_id: ci.passport_id, token_jti: token_id || null, intent: ci, intent_hash: hash, aud: ci.aud, action: ci.action, resource: ci.resource, amount_cents: ci.amount_cents, destination: ci.destination, risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, status: 'pending', quorum, approvals: [], created_at: Date.now(), expires_at: Date.now() + 15 * 60 * 1000, request_id: rid };
    store.put('approvals', ap);
    const rc = audit.append({ ...base, decision: 'step_up', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, approval_id: ap.id, request_id: rid });
    return { decision: 'step_up', approval_id: ap.id, quorum, risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  if (ev.provisional === 'allow') {
    const orgSigner = getOrgSigner(ci.org_id);
    const att = buildActionToken({ orgSigner, org_id: ci.org_id, sub: ci.passport_id, intent_hash: hash, action: ci.action, resource: ci.resource, amount_cents: ci.amount_cents, requires_approval: false, token_jti: token_id || null, aud: ci.aud, kid: kid || pass.keys?.current?.kid || null });
    const rc = audit.append({ ...base, decision: 'allow', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, action_jti: att.jti, request_id: rid });
    return { decision: 'allow', action_token: att.envelope, action_jti: att.jti, risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
  }
  const rc = audit.append({ ...base, decision: 'deny', risk: risk.score, risk_version: riskCfg.version, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons: [...reasons, 'fail-closed'], request_id: rid });
  return { decision: 'deny', risk: risk.score, risk_factors: risk.factors, policy_id: ev.policy_id, policy_hash: ev.policy_hash, policy_version: ev.policy_version, reasons, receipt: rc, request_id: rid };
}

// ---- execute: the ONLY place effects are authorized. Atomic + single-use. ----
// Re-validates: passport, signature-of-record (via authorize binding), key version
// (kid in token), issuer, audience, intent hash, action, canonical resource,
// exact params (via hash), amount, destination (via hash), token chain, approval,
// expiration, nonce, revocation state, single-use state. Prepared (authorized) vs
// executed are distinct: authorize=prepared, execute=executed+receipt.
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
    // Audience binding: tokens cannot be replayed against a different service/tool/org.
    if ((att.aud || 'authragen') !== (ci.aud || 'authragen')) throw Object.assign(new Error(`audience mismatch (token for ${att.aud}, intent for ${ci.aud})`), { code: 'token_mismatch' });
    if (att.intent_hash !== hash) throw Object.assign(new Error('intent does not match authorized hash — request was altered'), { code: 'intent_mismatch' });
    if (att.action !== ci.action || att.resource !== ci.resource || (att.amount_cents || 0) !== (ci.amount_cents || 0))
      throw Object.assign(new Error('operation differs from authorized intent'), { code: 'intent_mismatch' });
    if (Date.now() > att.exp) throw Object.assign(new Error('action token expired'), { code: 'token_expired' });
    if (Date.now() < att.iat - 30 * 1000) throw Object.assign(new Error('action token not yet valid (clock skew)'), { code: 'token_malformed' });
    // Revocation: explicit action-credential revocation + parent delegation revocation.
    if (store.has('revocations', 'action:' + att.jti)) throw Object.assign(new Error('action credential revoked'), { code: 'token_revoked' });
    if (att.token_jti && store.has('revocations', 'token:' + att.token_jti)) throw Object.assign(new Error('parent delegation revoked'), { code: 'token_revoked' });
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
    // live checks FIRST (no consumption yet — failed attempts burn nothing) …
    const pass = store.get('passports', ci.passport_id);
    assertPassportUsable(pass);
    let tok = null;
    if (att.token_jti) {
      tok = store.get('tokens', att.token_jti);
      if (!tok || tok.org_id !== ci.org_id) throw Object.assign(new Error('Unknown delegation token'), { code: 'token_unknown' });
      assertTokenUsable(tok);
      if (!tokenCovers(tok, ci.action, ci.resource)) throw Object.assign(new Error('Token scope/targets insufficient'), { code: 'scope_insufficient' });
      checkBudget(tok, ci.amount_cents);
    }
    // … then single-use consumption (replay-safe; persistent store, atomic under mutex;
    // distributed deployments must use Redis/Postgres atomic primitives) …
    if (!nonce.consumeOnce('nonce:' + ci.nonce, 10 * 60 * 1000)) throw Object.assign(new Error('intent nonce already used (replay)'), { code: 'replay' });
    if (!nonce.consumeOnce('att:' + att.jti, 10 * 60 * 1000)) throw Object.assign(new Error('action token already used (replay)'), { code: 'replay' });
    // … then the ATOMIC effect (sync check-and-set; Postgres: UPDATE ... WHERE) …
    if (tok) debitBudget(tok, ci.amount_cents);
    touchLastSeen(ci.passport_id);
    const rc = audit.append({ org_id: ci.org_id, actor: ci.passport_id, action: ci.action, resource: ci.resource, token_jti: att.token_jti, intent_hash: hash, amount_cents: ci.amount_cents, destination: ci.destination, aud: ci.aud, decision: 'executed', risk: 0, policy_id: null, reasons: [`action_jti:${att.jti}`, 'intent-match', 'nonce-consumed', `approval:${approvalRec ? approvalRec.by + '/' + (approvalRec.by_key_id || '') : 'n/a'}`, `executor:${approvalRec ? 'approval-bound' : 'direct'}`], action_jti: att.jti, approval_id: approvalRec?.approval_id || null, request_id: rid });
    return { ok: true, receipt: rc, intent_hash: hash, request_id: rid, prepared_vs_executed: 'executed' };
    } catch (e) {
      // failed executions leave deny receipts too — silent blocks are unauditable blocks
      try {
        audit.append({ org_id: ci.org_id, actor: ci.passport_id, action: ci.action, resource: ci.resource, intent_hash: hash, amount_cents: ci.amount_cents, decision: 'deny', risk: 100, policy_id: null, reasons: ['execute:' + (e.code || 'error')], request_id: rid });
      } catch {}
      throw e;
    }
  });
}

let revSeq = 0;
try {
  for (const r of store.all('revocations')) if (r.seq > revSeq) revSeq = r.seq;
} catch {}
function addRevocation({ type, target, reason, org_id, kid = null }) {
  revSeq++;
  const rec = { id: `${type}:${target}${kid ? ':' + kid : ''}`, seq: revSeq, type, target, kid: kid || null, org_id, reason: reason || 'manual', at: Date.now() };
  store.put('revocations', rec);
  return rec;
}

const server = http.createServer(async (req, res) => {
  req._rid = req.headers['x-request-id'] || newRequestId();
  const u = url.parse(req.url, true);
  const p = u.pathname || '/';
  const t0 = Date.now();
  const logLine = (code) => {
    // Structured access log WITHOUT secrets: method, path (query stripped of
    // envelope material), status, latency, request id, ip. Never log envelopes,
    // intents, keys or approval credentials.
    const safePath = p + (u.query && (u.query.org_id || u.query.since || u.query.limit) ? `?org_id=${u.query.org_id || ''}` : '');
    console.log(JSON.stringify({ ts: new Date().toISOString(), rid: req._rid, m: req.method, p: safePath, s: code, ms: Date.now() - t0, ip: clientIp(req) }));
  };
  const ok = (code, obj) => { logLine(code); return send(req, res, code, { request_id: req._rid, ...obj }); };
  const fail = (e) => { const code = e.status || 400; logLine(code); return sendErr(req, res, e); };
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
    if (p === '/v1/health' && req.method === 'GET') return ok(200, { ok: true, service: 'authragen', v: 2, protocol: PROTOCOL_VERSION, time: Date.now(), store: store.backend(), custody_policy: allowCustody() ? 'dev (server custody ALLOWED)' : 'self-custody enforced' });

    // trust root distribution (open — it's a public key)
    if (p.startsWith('/v1/orgs/') && p.endsWith('/pubkey') && req.method === 'GET') {
      rateLimit(req, 'pubkey', 120);
      const id = p.split('/')[3];
      const opk = orgPubkey(id) || store.get('orgs', id)?.pubkey;
      if (!opk) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
      return ok(200, { org_id: id, pubkey: opk, alg: 'Ed25519' });
    }
    // bootstrap org creation (strictly rate-limited)
    if (p === '/v1/orgs' && req.method === 'POST') {
      rateLimit(req, 'bootstrap', 5);
      const b = await body(req);
      if (!b.name) return fail(Object.assign(new Error('name required'), { code: 'bad_request' }));
      if (!auth.checkBootstrap(req.headers['x-bootstrap-token'])) return fail(Object.assign(new Error('valid x-bootstrap-token required (printed at first boot)'), { code: 'unauthorized' }));
      const org = createOrgRecord(b.name);
      for (const pol of seedPolicies(org.id)) store.put('policies', pol);
      const key = auth.mintKey(org.id, 'admin', 'initial-admin');
      auth.consumeBootstrap();
      audit.append({ org_id: org.id, actor: org.id, action: 'org.create', resource: org.id, decision: 'allow', risk: 0, policy_id: null, reasons: ['bootstrap'], request_id: req._rid });
      return ok(201, { ...publicOrg(org), org_pubkey: orgPubkey(org.id), admin_key_id: key.key_id, admin_secret: key.secret });
    }
    if (p === '/v1/orgs' && req.method === 'GET') {
      const k = callerKey(req);
      if (!k) return fail(Object.assign(new Error('auth required'), { code: 'unauthorized' }));
      return ok(200, { orgs: store.byOrg('orgs', k.org_id).concat(store.all('orgs').filter(o => o.id === k.org_id)).filter((v, i, a) => a.findIndex(x => x.id === v.id) === i).map(publicOrg) });
    }
    // org details + risk thresholds + emergency lock (admin)
    if (/^\/v1\/orgs\/[^/]+$/.test(p) && req.method === 'GET') {
      const orgId = p.split('/')[3];
      const k = callerKey(req);
      try { auth.requireRole(k, orgId, 'reporter'); } catch (e) { return fail(e); }
      const org = store.get('orgs', orgId);
      if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
      return ok(200, { ...publicOrg(org), risk_ceiling: org.risk_ceiling ?? RISK_CEILING_DEFAULT, risk_stepup: org.risk_stepup ?? RISK_STEPUP_DEFAULT });
    }
    if (/^\/v1\/orgs\/[^/]+\/(lock|unlock)$/.test(p) && req.method === 'POST') {
      const [_, orgId, op] = p.split('/').filter(Boolean).slice(1);
      const k = callerKey(req);
      // Emergency lock/unlock must work EVEN when locked (else unlock deadlocks).
      // Check admin role without the org-locked fail-closed gate.
      try {
        if (!k) throw Object.assign(new Error('missing credentials'), { code: 'unauthorized' });
        if (k.org_id !== orgId) throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
        if (k.role !== 'admin') throw Object.assign(new Error('forbidden'), { code: 'forbidden' });
      } catch (e) { return fail(e); }
      const org = store.get('orgs', orgId);
      if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
      org.locked = op === 'lock';
      org.locked_at = org.locked ? Date.now() : null;
      org.locked_by = org.locked ? k.id : null;
      store.put('orgs', org);
      audit.append({ org_id: orgId, actor: k.id, action: `org.${op}`, resource: orgId, decision: 'allow', risk: 0, policy_id: null, reasons: [`emergency:${op}`], request_id: req._rid });
      return ok(200, { ok: true, locked: org.locked });
    }
    if (/^\/v1\/orgs\/[^/]+\/risk$/.test(p) && req.method === 'PUT') {
      const orgId = p.split('/')[3];
      const k = callerKey(req);
      try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
      const b = await body(req);
      const org = store.get('orgs', orgId);
      if (!org) return fail(Object.assign(new Error('unknown org'), { code: 'org_unknown' }));
      if (b.risk_ceiling != null) org.risk_ceiling = Math.max(0, Math.min(100, Number(b.risk_ceiling)));
      if (b.risk_stepup != null) org.risk_stepup = Math.max(0, Math.min(100, Number(b.risk_stepup)));
      store.put('orgs', org);
      return ok(200, { ok: true, risk_ceiling: org.risk_ceiling, risk_stepup: org.risk_stepup });
    }
    // api keys (secret shown ONCE at mint/rotate; GET strips hashes)
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
      return ok(200, { keys: store.byOrg('apikeys', orgId).map(({ hash, ...r }) => r) });
    }
    if (/^\/v1\/orgs\/[^/]+\/keys\/rotate$/.test(p) && req.method === 'POST') {
      const orgId = p.split('/')[3];
      const k = callerKey(req);
      try { auth.requireRole(k, orgId, 'admin'); } catch (e) { return fail(e); }
      const b = await body(req);
      try {
        if (!b.key_id) throw Object.assign(new Error('key_id required'), { code: 'bad_request' });
        const target = store.get('apikeys', b.key_id);
        if (!target || target.org_id !== orgId) throw Object.assign(new Error('unknown key'), { code: 'bad_request' });
        const out = auth.rotateKey(b.key_id);
        audit.append({ org_id: orgId, actor: k.id, action: 'apikey.rotate', resource: b.key_id, decision: 'allow', risk: 5, policy_id: null, reasons: [`rotated:${out.key_id}`], request_id: req._rid });
        return ok(201, out);
      } catch (e) { return fail(e); }
    }

    // ---- blueprints ----
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
        const items = store.byOrg('blueprints', org).map(bp => ({ ...bp, instances: blueprintInstances(bp.id) }));
        return ok(200, { blueprints: items });
      } catch (e) { return fail(e); }
    }
    if (/^\/v1\/blueprints\/[^/]+$/.test(p) && req.method === 'GET') {
      const id = p.split('/')[3];
      const bp = store.get('blueprints', id);
      if (!bp) return fail(Object.assign(new Error('unknown blueprint'), { code: 'bad_request' }));
      const k = callerKey(req);
      try { auth.requireRole(k, bp.org_id, 'reporter'); } catch (e) { return fail(e); }
      return ok(200, { ...bp, instances: blueprintInstances(bp.id) });
    }

    // passports (CSR flow; issuance is an admin act — org ID alone is never enough)
    if (p === '/v1/passports' && req.method === 'POST') {
      rateLimit(req, 'issuance', 60);
      const b = await body(req);
      const k = callerKey(req);
      try {
        if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
        auth.requireRole(k, b.org_id, 'admin');
        const pass = issuePassport(b);
        audit.append({ org_id: pass.org_id, actor: k.id, action: 'passport.issue', resource: pass.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`kind:${pass.kind}`, `custody:${pass.custody}`], request_id: req._rid });
        return ok(201, pass);
      } catch (e) { return fail(e); }
    }
    // fleet listing with search/filter/pagination (large-fleet support)
    if (p === '/v1/passports' && req.method === 'GET') {
      const k = callerKey(req);
      try {
        const org = u.query.org_id || k?.org_id;
        if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
        auth.requireRole(k, org, 'reporter');
        const { items, total } = store.list('passports', { org_id: org, status: u.query.status || null, limit: Math.min(200, Number(u.query.limit) || 50), offset: Number(u.query.offset) || 0, q: u.query.q || null });
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
        const cur = store.get('passports', b.passport_id);
        if (!cur || !cur.org_id) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
        // Tenant isolation: scope the auth check to the passport's org.
        auth.requireRole(callerKey(req), cur.org_id, 'admin');
        const pass = rotatePassport(b.passport_id, b.new_pubkey);
        const rc = audit.append({ org_id: pass.org_id, actor: b.passport_id, action: 'passport.rotate', resource: pass.id, decision: 'allow', risk: 5, policy_id: null, reasons: [`kid:${pass.keys.current.kid}`], request_id: req._rid });
        return ok(200, { ...pass, receipt: rc });
      } catch (e) { return fail(e); }
    }
    // lifecycle: suspend/quarantine/activate/revoke (reversible except revoked)
    if (/^\/v1\/passports\/[^/]+\/status$/.test(p) && req.method === 'POST') {
      const id = p.split('/')[3];
      const b = await body(req);
      try {
        const cur = store.get('passports', id);
        if (!cur) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
        auth.requireRole(callerKey(req), cur.org_id, 'admin');
        if (!LIFECYCLE.includes(b.status)) throw Object.assign(new Error('invalid status'), { code: 'bad_request' });
        const pass = setPassportStatus(id, b.status);
        audit.append({ org_id: pass.org_id, actor: callerKey(req)?.id || 'admin', action: `passport.${b.status}`, resource: id, decision: 'allow', risk: 5, policy_id: null, reasons: [b.reason || b.status], request_id: req._rid });
        return ok(200, pass);
      } catch (e) { return fail(e); }
    }
    // key revocation with explicit kid + validity windows
    if (/^\/v1\/passports\/[^/]+\/keys\/revoke$/.test(p) && req.method === 'POST') {
      const id = p.split('/')[3];
      const b = await body(req);
      try {
        const cur = store.get('passports', id);
        if (!cur) throw Object.assign(new Error('unknown passport'), { code: 'passport_unknown' });
        auth.requireRole(callerKey(req), cur.org_id, 'admin');
        if (!b.kid) throw Object.assign(new Error('kid required'), { code: 'bad_request' });
        const pass = revokeKey(id, b.kid);
        addRevocation({ type: 'key', target: id, kid: b.kid, org_id: pass.org_id, reason: b.reason });
        return ok(200, pass);
      } catch (e) { return fail(e); }
    }
    if (p.startsWith('/v1/passports/') && req.method === 'GET' && !p.endsWith('/rotate') && !p.endsWith('/status') && !p.endsWith('/revoke')) {
      const id = p.split('/')[3];
      const pass = store.get('passports', id);
      // Tenant isolation: unknown IDs and cross-org IDs look identical (404).
      if (!pass) return fail(Object.assign(new Error('not found'), { code: 'not_found' }));
      const k = callerKey(req);
      try { auth.requireRole(k, pass.org_id, 'reporter'); } catch (e) { return fail(e); }
      return ok(200, { ...publicPassport(pass), status: passportStatus(pass) });
    }

    // delegation registration (client-signed; authority enforced)
    if (p === '/v1/delegate' && req.method === 'POST') {
      const b = await body(req);
      try {
        if (!b.org_id || !b.delegator_id || !b.payload || !b.envelope) throw Object.assign(new Error('org_id, delegator_id, payload, envelope required'), { code: 'bad_request' });
        const k = callerKey(req);
        if (k) auth.requireRole(k, b.org_id, 'executor'); // service path; agent path uses delegator sig alone
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
        const { items, total } = store.list('tokens', { org_id: org, limit: Math.min(200, Number(u.query.limit) || 50), offset: Number(u.query.offset) || 0 });
        return ok(200, { delegations: items, total });
      } catch (e) { return fail(e); }
    }

    // ---- policies ----
    if (p === '/v1/policies' && req.method === 'POST') {
      const b = await body(req);
      const k = callerKey(req);
      try {
        if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
        auth.requireRole(k, b.org_id, 'admin');
        const pol = newPolicy(b.org_id, b);
        store.put('policies', pol);
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
        const all = store.byOrg('policies', org);
        return ok(200, { policies: all });
      } catch (e) { return fail(e); }
    }
    if (p === '/v1/policies/simulate' && req.method === 'POST') {
      const b = await body(req);
      const k = callerKey(req);
      try {
        if (!b.org_id) throw Object.assign(new Error('org_id required'), { code: 'bad_request' });
        auth.requireRole(k, b.org_id, 'reporter');
        const policies = store.byOrg('policies', b.org_id);
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
        return ok(200, { conflicts: detectConflicts(store.byOrg('policies', org)) });
      } catch (e) { return fail(e); }
    }
    if (/^\/v1\/policies\/[^/]+$/.test(p) && req.method === 'PUT') {
      const id = p.split('/')[3];
      const b = await body(req);
      const k = callerKey(req);
      try {
        const cur = store.get('policies', id);
        if (!cur) throw Object.assign(new Error('unknown policy'), { code: 'not_found' });
        auth.requireRole(k, cur.org_id, 'admin');
        const next = { ...cur, ...b, id: cur.id, org_id: cur.org_id, version: (cur.version || 1) + 1, updated_at: Date.now() };
        next.hash = policyHash(next);
        store.put('policies', next);
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

    // ---- approvals (authenticated approver identity; CSRF-safe) ----
    // CSRF: approval is a state-changing POST that REQUIRES an Authorization:
    // Bearer approver key (cookies alone are never accepted) + JSON content-type.
    // The `by` field is treated as an optional human note; the RECORDED identity
    // is always the authenticated key (id + role + key id). Approval credentials
    // are bound to the exact intent hash (+ action jti when available) and expire.
    if (p.startsWith('/v1/approvals/') && req.method === 'POST') {
      const id = p.split('/')[3];
      const b = await body(req);
      try {
        const ap = store.get('approvals', id);
        if (!ap) throw Object.assign(new Error('unknown approval'), { code: 'not_found' });
        const k = callerKey(req);
        if (!k) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
        auth.requireRole(k, ap.org_id, 'approver');
        if (ap.status !== 'pending' && ap.status !== 'partial') throw Object.assign(new Error('already resolved'), { code: 'approval_resolved' });
        if (Date.now() > ap.expires_at) { ap.status = 'expired'; store.put('approvals', ap); throw Object.assign(new Error('approval expired'), { code: 'approval_expired' }); }
        // Record authenticated identity — never trust free-form `by` as identity.
        const who = { id: k.id, role: k.role, note: typeof b.by === 'string' ? String(b.by).slice(0, 128) : null, at: Date.now() };
        ap.approvals = ap.approvals || [];
        if (ap.approvals.some(a => a.id === k.id)) throw Object.assign(new Error('approver already recorded (quorum needs distinct approvers)'), { code: 'approval_resolved' });
        if (b.approve === false || b.decision === 'denied') {
          ap.status = 'denied';
          ap.decided_by = who.id; ap.decided_by_role = who.role; ap.decided_at = who.at;
          store.put('approvals', ap);
          const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: 'denied', risk: ap.risk, policy_id: ap.policy_id, policy_hash: ap.policy_hash, reasons: [`approval:${id}:denied`, `by:${who.id}/${who.role}`], intent_hash: ap.intent_hash, request_id: req._rid });
          return ok(200, { ...ap, approval_credential: null, receipt: rc, request_id: req._rid });
        }
        ap.approvals.push(who);
        const need = ap.quorum || 1;
        if (ap.approvals.length < need) {
          ap.status = 'partial';
          store.put('approvals', ap);
          const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: 'step_up', risk: ap.risk, policy_id: ap.policy_id, reasons: [`approval:${id}:partial:${ap.approvals.length}/${need}`, `by:${who.id}`], intent_hash: ap.intent_hash, request_id: req._rid });
          return ok(202, { ...ap, receipt: rc, request_id: req._rid, note: `quorum ${ap.approvals.length}/${need} — need ${need - ap.approvals.length} more distinct approver(s)` });
        }
        ap.status = 'approved';
        ap.decided_by = ap.approvals.map(a => a.id).join(',');
        ap.decided_by_role = who.role; ap.decided_at = Date.now();
        store.put('approvals', ap);
        let credential = null;
        if (ap.status === 'approved') {
          // Mint the deferred action token FIRST so the approval can bind its jti.
          const att = buildActionToken({ orgSigner: getOrgSigner(ap.org_id), org_id: ap.org_id, sub: ap.passport_id, intent_hash: ap.intent_hash, action: ap.action, resource: ap.resource, amount_cents: ap.amount_cents, requires_approval: true, token_jti: ap.token_jti, aud: ap.aud || 'authragen' });
          ap.action_jti = att.jti; store.put('approvals', ap);
          ap.action_token = att.envelope;
          // Signed artifact bound to the EXACT intent hash + action jti — swaps fail at execute.
          credential = buildApproval({ orgSigner: getOrgSigner(ap.org_id), approval_id: ap.id, org_id: ap.org_id, passport_id: ap.passport_id, intent_hash: ap.intent_hash, action: ap.action, resource: ap.resource, by: ap.decided_by, by_role: who.role, by_key_id: who.id, action_jti: att.jti, aud: ap.aud || 'authragen' });
          ap.approval_jti = credential.payload.jti || ap.id; store.put('approvals', ap);
        }
        const rc = audit.append({ org_id: ap.org_id, actor: ap.passport_id, action: ap.action, resource: ap.resource, decision: ap.status, risk: ap.risk, policy_id: ap.policy_id, policy_hash: ap.policy_hash, reasons: [`approval:${id}:${ap.status}`, `by:${ap.decided_by}/${who.role}`, `quorum:${need}`], intent_hash: ap.intent_hash, request_id: req._rid });
        return ok(200, { ...ap, approval_credential: credential?.envelope || null, receipt: rc, request_id: req._rid });
      } catch (e) { return fail(e); }
    }
    if (p === '/v1/approvals' && req.method === 'GET') {
      const k = callerKey(req);
      try {
        const org = u.query.org_id || k?.org_id;
        if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
        auth.requireRole(k, org, 'reporter');
        let all = store.byOrg('approvals', org);
        if (u.query.status) all = all.filter(a => a.status === u.query.status);
        // Exact-request preview is the stored intent (never trust client echo).
        return ok(200, { approvals: all.slice(-(Math.min(200, Number(u.query.limit) || 100))) });
      } catch (e) { return fail(e); }
    }

    // ---- revocation (deterministic cascade; sequence-numbered feed) ----
    if (p === '/v1/revoke' && req.method === 'POST') {
      const b = await body(req);
      try {
        if (!b.type || !b.id) throw Object.assign(new Error('type + id required'), { code: 'bad_request' });
        const allowed = ['passport', 'token', 'apikey', 'action', 'key', 'blueprint', 'org'];
        if (!allowed.includes(b.type)) throw Object.assign(new Error('unknown revoke type'), { code: 'bad_request' });
        let targetOrg = null;
        if (b.type === 'passport') targetOrg = store.get('passports', b.id)?.org_id;
        else if (b.type === 'token') targetOrg = store.get('tokens', b.id)?.org_id;
        else if (b.type === 'apikey') targetOrg = store.get('apikeys', b.id)?.org_id;
        else if (b.type === 'action') targetOrg = b.org_id || null; // action jtis are not stored; caller scopes
        else if (b.type === 'key') targetOrg = store.get('passports', b.id)?.org_id;
        else if (b.type === 'blueprint') targetOrg = store.get('blueprints', b.id)?.org_id;
        else if (b.type === 'org') targetOrg = store.get('orgs', b.id)?.id;
        // Avoid leaking existence across tenants: unknown targets → generic 400
        // without revealing which org they might belong to.
        if (!targetOrg) throw Object.assign(new Error('unknown target'), { code: 'bad_request' });
        auth.requireRole(callerKey(req), targetOrg, 'admin');
        if (b.type === 'passport') { try { setPassportStatus(b.id, 'revoked'); } catch { const ps = store.get('passports', b.id); if (ps) { ps.revoked = true; ps.status = 'revoked'; store.put('passports', ps); } } }
        if (b.type === 'apikey') { const ak = store.get('apikeys', b.id); if (ak) { ak.revoked = true; store.put('apikeys', ak); } }
        if (b.type === 'key') { try { revokeKey(b.id, b.kid); } catch (e) { throw e; } }
        if (b.type === 'blueprint') { const bp = store.get('blueprints', b.id); if (bp) { bp.status = 'revoked'; store.put('blueprints', bp); } }
        if (b.type === 'org') { const o = store.get('orgs', b.id); if (o) { o.locked = true; o.locked_at = Date.now(); store.put('orgs', o); } }
        const rec = addRevocation({ type: b.type, target: b.id, kid: b.kid || null, org_id: targetOrg, reason: b.reason });
        const rc = audit.append({ org_id: targetOrg, actor: 'admin', action: `${b.type}.revoke`, resource: b.id, decision: 'revoked', risk: 0, policy_id: null, reasons: [b.reason || 'manual', 'cascade:children-fail-closed', `seq:${rec.seq}`], request_id: req._rid });
        return ok(200, { ok: true, revoked: rec.id, seq: rec.seq, cascade: 'children fail closed (passports→sub-agents, tokens→children, blueprints→agents, org→all)', receipt: rc, request_id: req._rid });
      } catch (e) { return fail(e); }
    }
    // revocation freshness feed with sequence numbers (for offline/edge verifiers to poll)
    if (p === '/v1/revoked' && req.method === 'GET') {
      const k = callerKey(req);
      try {
        const org = u.query.org_id || k?.org_id;
        if (!org) throw Object.assign(new Error('auth required'), { code: 'unauthorized' });
        auth.requireRole(k, org, 'reporter');
        const since = Number(u.query.since) || 0;
        const sinceSeq = Number(u.query.since_seq) || 0;
        const all = store.all('revocations')
          .filter(r => (!r.org_id || r.org_id === org))
          .filter(r => (r.at || 0) >= since && (r.seq || 0) > sinceSeq)
          .sort((a, b) => (a.seq || 0) - (b.seq || 0));
        return ok(200, { revocations: all, as_of: Date.now(), head_seq: revSeq, freshness_note: 'ONLINE live status. Offline verifiers: cache this feed + checkpoints; without a fresh feed you have authenticity-without-freshness.' });
      } catch (e) { return fail(e); }
    }

    // ---- verify: POST preferred (no bearer material in URLs). GET kept legacy. ----
    async function doVerify({ envelope, org_id, token_id }) {
      if (token_id) { // legacy registered-token path
        const tok = store.get('tokens', token_id);
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
      // Live revocation is checked when online; offline callers get freshness=unknown
      // unless they supply a feed (see SDK verifyOffline with revocationSet).
      let freshness = 'unknown (offline: poll GET /v1/revoked)';
      try {
        const live = v.payload.kind === 'action' && (store.has('revocations', 'action:' + v.payload.jti) || store.has('revocations', 'token:' + (v.payload.token_jti || '')));
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
        // Legacy query form: never log the envelope (bearer-adjacent). Prefer POST.
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
        return ok(201, audit.evidenceBundle({ org_id: b.org_id, intent_hash: b.intent_hash || null, passport_id: b.passport_id || null, signer: gatewaySigner() }));
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
        return ok(201, audit.checkpoint(gatewaySigner()));
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

if (require.main === module) {
  // first-run bootstrap: print one-time token for creating the first org
  const pending = auth.bootstrapToken();
  if (pending && pending.fresh) {
    console.log('\n==============================================================');
    console.log('  FIRST RUN — save this one-time bootstrap token:');
    console.log(`    AUTHRA_BOOTSTRAP=${pending.fresh}`);
    console.log('  Create the first org: POST /v1/orgs with x-bootstrap-token header.');
    console.log('==============================================================\n');
    try {
      const fp = require('node:path').join(process.env.AUTHRA_DATA || require('./store').DATA_DIR, 'bootstrap.token');
      require('node:fs').writeFileSync(fp, pending.fresh + '\n', { mode: 0o600 });
      console.log(`[authragen] (also written to ${fp} for local scripts; deleted after first org)`);
    } catch {}
    auth.markBootstrapPrinted();
  }
  // custody census: flag any server-held agent keys left from pre-v2 data
  try {
    const legacy = store.all('passports').filter(p => (p._privX && p._privD) || p.custody === 'server-legacy').length;
    if (legacy) console.warn(`[authragen] WARNING: ${legacy} passport(s) have server-held private keys (pre-v2). Rotate to self-custody CSRs.`);
    if (allowCustody()) console.warn('[authragen] WARNING: AUTHRA_ALLOW_CUSTODY=1 — server-custodied agent keys permitted (local dev only).');
    if ((process.env.AUTHRA_KMS || 'file') === 'file') console.warn('[authragen] WARNING: file-backed org roots (dev default). Production MUST set AUTHRA_KMS to a real KMS/HSM.');
  } catch {}
  server.listen(PORT, () => console.log(`AuthraGen gateway v2 on http://localhost:${PORT}`));
}
module.exports = { server, authorize, execute };
