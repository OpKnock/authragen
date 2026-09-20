'use strict';
// n8n binding v2: Code-node guard with exact-intent execute.
// Needs either the agent keypair (sign) or an org executor key (middleware path).
//
//   const { n8nGuard } = require('/path/to/AuthraGen/adapters/n8n.js');
//   await n8nGuard({ baseUrl:'http://authragen:8787', org_id:'org_…', passport_id:$env.AG_PASSPORT,
//                   keypair: JSON.parse($env.AG_KEYPAIR), action:'payments.charge',
//                   resource:'stripe:invoice:42', amount_cents: 499 });
const { AuthraGen } = require('../sdk-js/authragen');
async function n8nGuard({ baseUrl, org_id, passport_id, keypair = null, key = null, action, resource, amount_cents = 0, destination = '', params = {}, token_id = null, aud = 'n8n' }) {
  const ag = new AuthraGen({ baseUrl, key });
  const intent = ag.intent({ passport_id, org_id, action, resource, params, amount_cents, destination, tool: 'n8n', aud });
  const sig = keypair ? ag.signIntent(intent, keypair) : null;
  const d = await ag.authorize(intent, sig, { token_id });
  if (d.decision === 'allow') {
    const ex = await ag.execute(d.action_token, intent);
    return { ok: true, receipt: ex.receipt.id, request_id: ex.request_id };
  }
  if (d.decision === 'step_up') return { ok: false, step_up: true, approval_id: d.approval_id, intent, reasons: d.reasons, request_id: d.request_id };
  throw Object.assign(new Error(`n8n node blocked: ${d.reasons}`), { decision: d });
}
module.exports = { n8nGuard, adapterContract: 'exact-intent/authorize/single-use-execute v2' };
