'use strict';
// OpenAI-style tool guard v2: exact-intent authorize + single-use execute.
// Adapter contract: exact intent → authorize → single-use execute (no legacy flows).
// Pass EITHER keypair (agent self-custody: intents signed locally) OR key
// (org executor key: trusted-middleware path, recorded in receipts).
// Uses standard Authorization: Bearer headers (never URL/query credentials) and
// binds audience (aud) so tokens cannot replay across services.
const { AuthraGen } = require('../sdk-js/authragen');

function guardedTools({ baseUrl, org_id, passport_id, keypair = null, key = null, tools = {}, aud = 'authragen' }) {
  const ag = new AuthraGen({ baseUrl, key });
  const wrapped = {};
  for (const [name, fn] of Object.entries(tools)) {
    wrapped[name] = async (args = {}, ctx = {}) => {
      const intent = ag.intent({
        passport_id, org_id, action: name,
        resource: ctx.resource || `${name}:${JSON.stringify(args).slice(0, 80)}`,
        params: args, amount_cents: ctx.amount_cents || 0,
        destination: ctx.destination || '', tool: ctx.tool || name,
        aud: ctx.aud || aud,
      });
      const sig = keypair ? ag.signIntent(intent, keypair) : null;
      const d = await ag.authorize(intent, sig, { token_id: ctx.token_id });
      if (d.decision === 'allow') {
        const ex = await ag.execute(d.action_token, intent); // match-checked, once-only, atomic debit
        return { ok: true, result: await fn(args), receipt: ex.receipt.id, request_id: ex.request_id };
      }
      if (d.decision === 'step_up') return { ok: false, step_up: true, approval_id: d.approval_id, reasons: d.reasons, request_id: d.request_id };
      throw Object.assign(new Error(`AuthraGen denied ${name}: ${d.reasons}`), { decision: d });
    };
  }
  return wrapped;
}
module.exports = { guardedTools, adapterContract: 'exact-intent/authorize/single-use-execute v2' };
