'use strict';
// MCP binding v2: intent-bound tool calls; server side re-checks exact hash.
// Client: beforeToolCall -> authorize (gets single-use action_token).
// Server middleware: requires action_token + intent, verifies match via /v1/execute
// semantics (offline: AuthraGen.verifyEnvelopeOffline + intent_hash recompute).
// HTTP semantics: Authorization: Bearer <org-key or action-token> header;
// audience/resource binding per call; never access tokens in URLs.
const { AuthraGen } = require('../sdk-js/authragen');

function mcpGuard({ baseUrl, org_id, passport_id, keypair = null, key = null, aud = null }) {
  const ag = new AuthraGen({ baseUrl, key });
  return {
    async beforeToolCall(toolName, args = {}, ctx = {}) {
      const resource = ctx.resource || `mcp:${toolName}`;
      const intent = ag.intent({ passport_id, org_id, action: `mcp.${toolName}`, resource, params: args, amount_cents: ctx.amount_cents || 0, destination: ctx.destination || '', tool: toolName, aud: ctx.aud || aud || `mcp:${toolName}` });
      const sig = keypair ? ag.signIntent(intent, keypair) : null;
      const d = await ag.authorize(intent, sig, { token_id: ctx.token_id });
      if (d.decision === 'allow') return { proceed: true, action_token: d.action_token, intent, receipt: d.receipt.id, request_id: d.request_id };
      if (d.decision === 'step_up') return { proceed: false, step_up: true, approval_id: d.approval_id, request_id: d.request_id };
      const e = new Error(`MCP tool ${toolName} denied: ${d.reasons}`); e.decision = d; throw e;
    },
    // MCP *server* middleware: verifies the AuthraGen credential BEFORE the tool executes.
    serverMiddleware({ expectedAud = null } = {}) {
      return async (req, res, next) => {
        try {
          // Prefer Authorization header; body _authragen is the legacy in-band path.
          const hdr = req.headers?.authorization || '';
          const { action_token, intent, approval } = req.body?._authragen || {};
          const token = action_token || (hdr.startsWith('Bearer AR1.') ? hdr.slice(7) : null);
          if (!token || !intent) { res.statusCode = 401; return res.end(JSON.stringify({ error: 'authragen_required', message: 'action_token + intent required (Authorization: Bearer or _authragen body)' })); }
          if (expectedAud && intent.aud !== expectedAud) { res.statusCode = 403; return res.end(JSON.stringify({ error: 'token_mismatch', message: `audience mismatch (want ${expectedAud})` })); }
          const ex = await ag.execute(token, intent, { approval });
          req.authragen = ex; next();
        } catch (e) { res.statusCode = 403; res.end(JSON.stringify({ error: e.body?.error || 'authragen_deny', message: e.message })); }
      };
    },
  };
}
module.exports = { mcpGuard, adapterContract: 'exact-intent/authorize/single-use-execute v2' };
