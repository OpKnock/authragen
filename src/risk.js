'use strict';
// Deterministic, explainable risk HEURISTIC 0-100 — not a safety oracle.
// It triages (auto vs human review); policy denies and exact-action binding
// do the real enforcement. Extend via registerRiskProvider().

const BASE = [
  [/^admin\./, 80],
  [/^payments\./, 60],
  [/^code\.exec/, 50],
  [/^external\.send/, 40],
  [/^data\.write/, 25],
  [/^browser\./, 20],
  [/^data\.read/, 5],
  [/^search\./, 5],
];
function baseFor(action) {
  for (const [re, s] of BASE) if (re.test(String(action))) return s;
  return 15;
}
function score({ action, resource, context = {}, seen = false, now = new Date() }) {
  const factors = [];
  let s = baseFor(action);
  factors.push(`base:${s} for ${action}`);
  const spend = context.spend_cents || 0;
  if (spend > 0) {
    const add = Math.min(30, Math.round(spend / 100));
    s += add; factors.push(`spend:+${add} (${spend}c)`);
  }
  const depth = context.depth || 0;
  if (depth > 0) { s += depth * 5; factors.push(`depth:+${depth * 5} (d=${depth})`); }
  if (!seen && /payments\.|admin\.|external\./.test(String(action))) { s += 10; factors.push('novel-target:+10'); }
  const h = now.getUTCHours();
  if (h < 6) { s += 5; factors.push('off-hours:+5'); }
  if (depth >= 2 && /payments\.|admin\.|code\.exec/.test(String(action))) { s += 15; factors.push('deep-sensitive:+15'); }
  s = Math.max(0, Math.min(100, Math.round(s)));
  // Pluggable providers: org-specific signals (device, behavior, threat intel).
  // Each provider returns {add:number, factor:string}. Base heuristic stays explainable.
  for (const [name, fn] of providers) {
    try {
      const r = fn({ action, resource, context, seen });
      if (r && typeof r.add === 'number' && r.add !== 0) {
        s = Math.max(0, Math.min(100, s + r.add));
        factors.push(`${name}:${r.add >= 0 ? '+' : ''}${r.add}${r.factor ? ` (${r.factor})` : ''}`);
      }
    } catch (e) { factors.push(`${name}:error-ignored`); }
  }
  const band = s < 30 ? 'auto' : s < 70 ? 'step_up' : 'deny_candidate';
  return { score: s, band, factors };
}
const providers = new Map(); // name -> fn (additive risk signals; NOT a safety oracle)
function registerRiskProvider(name, fn) { providers.set(name, fn); return () => providers.delete(name); }
function listRiskProviders() { return [...providers.keys()]; }
module.exports = { score, registerRiskProvider, listRiskProviders };
