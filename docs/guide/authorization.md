# Authorization Flow

## Overview

```
Agent                                    Gateway
  │                                        │
  │ 1. Create exact intent                 │
  │ 2. Sign with agent private key         │
  ├───────────────────────────────────────►│
  │                                        │ 3. Verify signature
  │                                        │ 4. Check passport (kid, status, exp)
  │                                        │ 5. Evaluate policy + risk
  │                                        │ 6. Check budgets + delegation
  │◄───────────────────────────────────────┤ 7. Return decision + action_token
  │                                        │
  │ 8. Execute with action_token + intent  │
  ├───────────────────────────────────────►│
  │                                        │ 9. Re-verify everything
  │                                        │ 10. Consume nonce + token JTI
  │                                        │ 11. Atomic budget debit
  │                                        │ 12. Append receipt
  │◄───────────────────────────────────────┤ 13. Return receipt
```

## Phase 1: Intent Creation (Agent-Side)

```javascript
const me = new AuthraGen({ baseUrl: 'http://localhost:8787' });

const intent = me.createIntent({
  passport_id: 'agt_abc123',
  org_id: 'org_xyz789',
  action: 'payments.charge',
  resource: 'stripe:invoice:inv_42',
  params: { customer: 'cus_123', currency: 'usd' },
  amount_cents: 499,
  destination: 'acct_merchant_456',
  tool: 'stripe',
  // nonce: auto-generated 16+ chars [A-Za-z0-9:_-./]
  // iat/exp: auto (exp = now + AUTHRA_INTENT_TTL_S, default 120s)
  // aud: 'mcp:payments-svc' (required for MCP, recommended always)
});
```

**Intent validation (strict):**
- NFC normalization
- Control/zero-width/bidi char rejection
- No numeric coercion (amount_cents = safe integer)
- No NaN/Infinity
- Params ≤ 16KB, keys ≤ 64 chars, values ≤ 4KB
- Resource path normalization (no `..`, collapsed slashes)
- Duplicate JSON key rejection
- Clock skew tolerance (`AUTHRA_CLOCK_SKEW_S`, default 30s)

## Phase 2: Signing (Agent-Side)

```javascript
// Agent signs with LOCAL private key (never leaves process)
const signedIntent = me.signIntent(intent, agentKeypair);
// Returns: { intent, signature, kid, alg: 'EdDSA' }
```

## Phase 3: Authorization (Gateway)

```javascript
const decision = await me.authorize(signedIntent);
// or with dry-run:
const preview = await me.authorize(signedIntent, { dry_run: true });
```

**Gateway verification (in order):**
1. Signature valid under passport's current/historical `kid` (grace-aware)
2. Passport exists, `active`, not expired/revoked/suspended/quarantined
3. Org not locked
4. Delegation chain valid (if delegated)
5. Policy evaluation (deny-by-default)
6. Risk scoring (deterministic heuristic)
7. Budget availability
8. Nonce not yet used

**Response:**
```javascript
// Allow
{
  decision: 'allow',
  action_token: 'AR1.eyJ...',  // single-use, aud-bound
  action_jti: 'att_abc123',
  risk: { score: 15, factors: ['low_amount'], band: 'low', version: 2 },
  request_id: 'rq_...',
  policy_id: 'pol_...',
  policy_hash: 'sha256...',
  policy_version: 3
}

// Step-up (requires approval)
{
  decision: 'step_up',
  approval_id: 'apr_...',
  request_id: 'rq_...',
  policy_id: 'pol_...',
  risk: { score: 75, factors: ['high_amount', 'new_destination'], band: 'high', version: 2 }
}

// Deny
{
  decision: 'deny',
  reason: 'policy_deny' | 'scope_insufficient' | 'budget_exceeded' | ...,
  request_id: 'rq_...'
}

// Dry-run
{
  decision: 'dry_run',
  would: 'ALLOW' | 'STEP-UP' | 'DENY',
  risk: { ... },
  policy_id: 'pol_...',
  policy_hash: 'sha256...'
}
```

## Phase 4: Approval (If Step-Up)

```javascript
// Approver (authenticated via Bearer token)
const approver = new AuthraGen({ baseUrl, key: approverKey });
const approval = await approver.approve(approvalId, {
  approve: true,
  reason: 'Authorized by finance lead'
});

// Returns approval credential + deferred action_token
{
  approval_credential: 'AR1.eyJ...',  // bound to intent_hash + action_jti + aud
  action_token: 'AR1.eyJ...',          // ready for execute
  approval_id: 'apr_...'
}
```

**Approval properties:**
- Authenticated approver identity (key id + role), **never** free-form `by`
- Bearer token required (CSRF-safe)
- Bound to `intent_hash` (+ `action_jti` when present) + audience
- Expiring (`AUTHRA_APPROVAL_TTL_S`, default 1hr)
- Quorum: `min_approvals` distinct approvers required
- Non-transferable (cannot move between requests)

## Phase 5: Execution

```javascript
const receipt = await me.execute(actionToken, intent, {
  approval: approvalCredential  // if step_up
});
```

**Execute-time re-verification (all must pass):**
1. ✅ Token authentic (org key, `EdDSA/AR1` only)
2. ✅ `v/jti/kid/issuer/sub/aud/iat/exp/intent_hash` present
3. ✅ Issuer = gateway, kind/exp/org/sub/aud match
4. ✅ Recomputed `intent_hash` == token's
5. ✅ Action/resource/amount/destination/params (via hash) equal
6. ✅ If `requires_approval`: approval credential valid, same hash, same aud
7. ✅ Live passport + delegation chain + budget available + org not locked
8. ✅ **Consume nonce + token JTI** (replay → `replay` deny receipt)
9. ✅ **ATOMIC** budget debit + append `executed` receipt

**Receipt:**
```json
{
  "id": "rcpt_abc123",
  "type": "executed",
  "request_id": "rq_...",
  "intent_hash": "sha256...",
  "action_jti": "att_...",
  "approval_jti": "apr_...",
  "executor": { "authn": "agent_sig", "key_id": "kid_1" },
  "policy_id": "pol_...",
  "policy_hash": "sha256...",
  "policy_version": 3,
  "risk": { "score": 15, "factors": [], "band": "low", "version": 2 },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Service Key Path (Trusted Middleware)

For trusted internal services (not agents):
```javascript
const decision = await me.authorize({
  intent,
  service_key: 'sk_executor_...'  // Bearer auth alternative
});
// Recorded as: authn: "service_key:<key_id>"
```

## Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `unauthorized` | 401 | Missing/invalid auth |
| `forbidden` | 403 | Role/org scope mismatch |
| `bad_intent` | 400 | Intent validation failed |
| `intent_expired` | 400 | Intent past `exp` |
| `sig_invalid` | 401 | Signature verification failed |
| `unknown_kid` | 401 | Key ID not found |
| `key_revoked` | 401 | Key explicitly revoked |
| `key_expired` | 401 | Key past validity window |
| `passport_unknown` | 404 | Passport not found |
| `passport_revoked` | 410 | Passport revoked |
| `passport_suspended` | 403 | Passport suspended |
| `passport_quarantined` | 403 | Passport quarantined |
| `token_unknown` | 404 | Action token not found |
| `token_expired` | 410 | Action token expired |
| `token_revoked` | 410 | Action token revoked |
| `token_mismatch` | 400 | Intent hash mismatch |
| `scope_insufficient` | 403 | Delegation scope insufficient |
| `budget_exceeded` | 403 | Budget exhausted |
| `replay` | 409 | Nonce or token JTI already used |
| `custody_forbidden` | 403 | Server-custodied key not allowed |
| `org_locked` | 403 | Org emergency lock active |

## Next: [Delegation](/guide/delegation)