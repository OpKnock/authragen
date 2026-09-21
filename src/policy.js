'use strict';
// Fine-grained policy engine. Default-deny. Deny wins. require_approval forces step-up.
//
// SECURITY: empty action/resource arrays mean "matches nothing" (never "matches
// everything"). Only an explicit "*" matches all. This is fail-closed by design.
const { sha256hex, canonical } = require('./crypto');

function globMatch(pattern, value) {
  if (pattern === '*' || pattern === '**') return true;
  const v = String(value), p = String(pattern);
  if (!p.includes('*')) return p === v;
  // Glob → regex: escape everything except '*', then '*' = match any chars.
  // So 'payments.*' covers 'payments.charge', 'catalog:*' covers 'catalog:shoes'.
  const re = '^' + p.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
  try { return new RegExp(re).test(v); } catch { return false; }
}
function anyMatch(patterns, value) {
  // Fail-closed: missing/empty arrays match NOTHING. Use explicit "*" for all.
  if (!patterns || !patterns.length) return false;
  return patterns.some(p => globMatch(p, value) || p === '*');
}
function policyHash(pol) {
  const body = { actions: pol.actions, resources: pol.resources, effect: pol.effect, priority: pol.priority || 0, condition: pol.condition || null };
  return sha256hex(canonical(body));
}
function inWindow(cond, now) {
  if (!cond || !cond.time_window) return true;
  const { start, end } = cond.time_window; // "09:00"-"17:00" UTC HH:MM
  const h = now.getUTCHours() + now.getUTCMinutes() / 60;
  const toH = s => { const [a, b] = s.split(':').map(Number); return a + b / 60; };
  return h >= toH(start) && h <= toH(end);
}

// req: {action, resource, context:{spend_cents, depth, ...}}
// Supported condition keys (all optional, AND-combined):
//   max_spend_cents, max_depth, min_depth, environments[], blueprint_ids[],
//   agent_ids[], audiences[], time_window{start,end UTC HH:MM},
//   require_approval(bool) is expressed via effect=require_approval, not condition.
//   amount_cents is an alias of spend_cents for intent ergonomics.
function conditionMatches(cond, req, now = new Date()) {
  if (!cond) return true;
  if (!inWindow(cond, now)) return false;
  const spend = req.context?.spend_cents ?? req.context?.amount_cents ?? 0;
  if (cond.max_spend_cents != null && spend > cond.max_spend_cents) return false;
  if (cond.min_spend_cents != null && spend < cond.min_spend_cents) return false;
  const depth = req.context?.depth ?? 0;
  if (cond.max_depth != null && depth > cond.max_depth) return false;
  if (cond.min_depth != null && depth < cond.min_depth) return false;
  if (cond.environments && cond.environments.length) {
    if (!cond.environments.includes(req.context?.environment)) return false;
  }
  if (cond.blueprint_ids && cond.blueprint_ids.length) {
    if (!cond.blueprint_ids.includes(req.context?.blueprint_id)) return false;
  }
  if (cond.agent_ids && cond.agent_ids.length) {
    if (!cond.agent_ids.includes(req.context?.passport_id) && !cond.agent_ids.includes(req.context?.agent_id)) return false;
  }
  if (cond.audiences && cond.audiences.length) {
    if (!cond.audiences.includes(req.context?.aud)) return false;
  }
  if (cond.tools && cond.tools.length) {
    if (!cond.tools.some(t => globMatch(t, req.context?.tool || ''))) return false;
  }
  return true;
}

function evaluate(policies, req, now = new Date()) {
  const matched = (policies || []).filter(p =>
    anyMatch(p.actions, req.action) &&
    anyMatch(p.resources, req.resource) &&
    conditionMatches(p.condition, req, now)
  ).sort((a, b) => (b.priority || 0) - (a.priority || 0));

  const reasons = [];
  // Deny overrides allow (explicit). Highest-priority deny wins.
  let deny = matched.find(p => p.effect === 'deny');
  if (deny) return { provisional: 'deny', policy_id: deny.id, policy_hash: deny.hash || policyHash(deny), policy_version: deny.version || 1, matched: matched.map(m => m.id), reasons: [`deny:${deny.id}`] };
  // Explicit step-up semantics: require_approval effect forces human approval.
  // Optional two-person rule: condition.min_approvals>=2 is enforced at approval time.
  let ra = matched.find(p => p.effect === 'require_approval');
  if (ra) {
    reasons.push(`require_approval:${ra.id}`);
    if (ra.condition?.min_approvals > 1) reasons.push(`quorum:${ra.condition.min_approvals}`);
    return { provisional: 'require_approval', policy_id: ra.id, policy_hash: ra.hash || policyHash(ra), policy_version: ra.version || 1, matched: matched.map(m => m.id), reasons };
  }
  let allow = matched.find(p => p.effect === 'allow');
  if (allow) return { provisional: 'allow', policy_id: allow.id, policy_hash: allow.hash || policyHash(allow), policy_version: allow.version || 1, matched: matched.map(m => m.id), reasons: [`allow:${allow.id}`] };
  return { provisional: 'deny', policy_id: null, policy_hash: null, policy_version: null, matched: [], reasons: ['default_deny:no-matching-allow'] };
}

// Detect conflicting policies: same action/resource overlap with different effects
// at equal priority (ambiguous which wins besides deny-override). Returns list of conflicts.
function detectConflicts(policies) {
  const conflicts = [];
  const list = policies || [];
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const a = list[i], b = list[j];
      if (a.effect === b.effect) continue;
      if ((a.priority || 0) !== (b.priority || 0)) continue;
      const actionsOverlap = (a.actions || []).some(x => (b.actions || []).some(y => x === '*' || y === '*' || x === y || globMatch(x, y) || globMatch(y, x)));
      const resOverlap = (a.resources || []).some(x => (b.resources || []).some(y => x === '*' || y === '*' || x === y || globMatch(x, y) || globMatch(y, x)));
      if (actionsOverlap && resOverlap) conflicts.push({ policies: [a.id, b.id], effects: [a.effect, b.effect], priority: a.priority || 0, note: 'same-priority overlap; deny wins at runtime but review recommended' });
    }
  }
  return conflicts;
}

// Dry-run / simulation: evaluate without side effects (no token, no receipt).
function simulate(policies, req, now = new Date()) {
  const ev = evaluate(policies, req, now);
  return { ...ev, dry_run: true, would: ev.provisional === 'allow' ? 'ALLOW' : ev.provisional === 'require_approval' ? 'STEP-UP' : 'DENY' };
}

function validatePolicyBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('policy body must be an object'), { code: 'bad_request' });
  if (!['allow', 'deny', 'require_approval'].includes(body.effect)) throw Object.assign(new Error('bad effect'), { code: 'bad_request' });
  for (const field of ['actions', 'resources']) {
    if (!Array.isArray(body[field]) || body[field].length > 256 || body[field].some(x => typeof x !== 'string' || !x.trim() || x.length > 512)) {
      throw Object.assign(new Error(field + ' must contain only non-empty strings (max 512 chars each)'), { code: 'bad_request' });
    }
  }
  if (body.priority != null && (!Number.isSafeInteger(Number(body.priority)) || Number(body.priority) < -1000000 || Number(body.priority) > 1000000)) {
    throw Object.assign(new Error('priority must be a safe integer between -1000000 and 1000000'), { code: 'bad_request' });
  }
  if (body.condition != null && (typeof body.condition !== 'object' || Array.isArray(body.condition))) {
    throw Object.assign(new Error('condition must be an object'), { code: 'bad_request' });
  }
  if (body.condition?.min_approvals != null && (!Number.isSafeInteger(Number(body.condition.min_approvals)) || Number(body.condition.min_approvals) < 1 || Number(body.condition.min_approvals) > 32)) {
    throw Object.assign(new Error('condition.min_approvals must be an integer between 1 and 32'), { code: 'bad_request' });
  }
  return true;
}

function newPolicy(org_id, body) {
  const now = Date.now();
  const pol = {
    id: 'pol_' + require('node:crypto').randomBytes(5).toString('hex'),
    org_id, effect: body.effect, actions: body.actions, resources: body.resources,
    condition: body.condition || null, priority: body.priority || 0,
    description: body.description || '', version: 1,
    created_at: now, updated_at: now,
  };
  validatePolicyBody({ effect: pol.effect, actions: pol.actions, resources: pol.resources, priority: pol.priority, condition: pol.condition });
  pol.hash = policyHash(pol);
  return pol;
}

// Default seed policies for a new org: read-open, write-approval-free under caps, payments need approval, admin deny.
function seedPolicies(org_id) {
  const t = Date.now();
  const seeds = [
    { id: `pol_seed_read_${org_id.slice(-4)}`, org_id, effect: 'allow', actions: ['data.read', 'search.*', 'browser.read'], resources: ['*'], priority: 10, description: 'Reads are open', created_at: t, updated_at: t, version: 1 },
    { id: `pol_seed_write_${org_id.slice(-4)}`, org_id, effect: 'allow', actions: ['data.write', 'browser.click'], resources: ['*'], condition: { max_spend_cents: 0 }, priority: 10, description: 'Free writes allowed', created_at: t, updated_at: t, version: 1 },
    { id: `pol_seed_pay_${org_id.slice(-4)}`, org_id, effect: 'require_approval', actions: ['payments.*'], resources: ['*'], priority: 50, description: 'Money always steps up', created_at: t, updated_at: t, version: 1 },
    { id: `pol_seed_admin_${org_id.slice(-4)}`, org_id, effect: 'deny', actions: ['admin.*'], resources: ['*'], priority: 100, description: 'Admin blocked by default', created_at: t, updated_at: t, version: 1 },
  ];
  for (const p of seeds) p.hash = policyHash(p);
  return seeds;
}

module.exports = { globMatch, anyMatch, policyHash, conditionMatches, evaluate, detectConflicts, simulate, validatePolicyBody, newPolicy, seedPolicies };
