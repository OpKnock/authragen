'use strict';
// A2A binding v2: delegation is client-signed + server-registered; tasks carry
// single-use action tokens bound to the exact intent hash.
// Task delegation carries explicit issuer, subject, audience, task scope and
// exact intent binding (no legacy positional flows).
const { AuthraGen } = require('../sdk-js/authragen');

function a2aClient({ baseUrl, org_id, passport_id, keypair = null, key = null, aud = 'a2a' }) {
  const ag = new AuthraGen({ baseUrl, key });
  return {
    async delegateForTask(scope, resources, constraints, parent_jti = null) {
      if (!keypair) throw new Error('a2a delegation requires the delegator keypair (self-custody)');
      return ag.delegate({ org_id, delegator_id: passport_id, delegatorPriv: keypair, scope, resources, constraints, parent_jti });
    },
    async authorizeTask(action, resource, ctx = {}) {
      const intent = ag.intent({
        passport_id, org_id, action, resource,
        params: ctx.params || {}, amount_cents: ctx.amount_cents || 0,
        destination: ctx.destination || '', tool: 'a2a',
        aud: ctx.aud || aud,
      });
      const sig = keypair ? ag.signIntent(intent, keypair) : null;
      const decision = await ag.authorize(intent, sig, { token_id: ctx.token_id });
      return { intent, decision, issuer: passport_id, subject: ctx.subject || passport_id, audience: intent.aud, scope: ctx.scope || action };
    },
    wrapTask(task, { action_token, intent }) {
      return { ...task, metadata: { ...(task.metadata || {}), authragen: { action_token, intent, issuer: passport_id, audience: intent.aud } } };
    },
  };
}
function a2aServer({ baseUrl, key }) {
  const ag = new AuthraGen({ baseUrl, key });
  return {
    // Verifies match + consumes (replay-safe) BEFORE running the delegated task.
    async executeTask(envelopeTask, approval = null) {
      const m = envelopeTask.metadata?.authragen || {};
      if (!m.action_token || !m.intent) throw new Error('missing authragen action_token + intent');
      return ag.execute(m.action_token, m.intent, { approval });
    },
  };
}
module.exports = { a2aClient, a2aServer };
