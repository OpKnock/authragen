# Approvals & Quorum

## Overview

Approvals add human-in-the-loop for high-risk actions. The gateway mints a **signed approval credential** bound to the exact intent hash.

## Flow

```
1. Authorize → step_up + approval_id
2. Approver reviews (dashboard/API)
3. Approver signs approval (Bearer auth)
4. Gateway mints approval_credential + deferred action_token
5. Agent executes with action_token + intent + approval_credential
```

## Approval Request

Created automatically on `step_up` decision:

```json
{
  "id": "apr_abc123",
  "org_id": "org_xyz",
  "intent_hash": "sha256...",
  "action_jti": "att_...",
  "requester": { "authn": "agent_sig", "passport_id": "agt_...", "key_id": "kid_1" },
  "policy_id": "pol_...",
  "policy_version": 3,
  "risk": { "score": 75, "factors": ["high_amount"], "band": "high", "version": 2 },
  "status": "pending",
  "min_approvals": 2,
  "approvals": [],
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-01-01T01:00:00Z"
}
```

## Approving

```javascript
const approver = new AuthraGen({ baseUrl, key: approverKey });

const result = await approver.approve('apr_abc123', {
  approve: true,
  reason: 'Finance lead authorized'
});
```

**Requirements:**
- Authenticated via `Authorization: Bearer` (CSRF-safe)
- Role: `approver` or `admin`
- Recorded identity: `{ key_id, role, timestamp, decision, reason }`
- Free-form `by` field = human note only (not authoritative)

## Quorum (Two-Person Rule)

```javascript
// Policy config
step_up: {
  min_approvals: 2,
  required_roles: ['approver', 'admin']
}
```

**Behavior:**
- Multiple distinct approvals required (different key IDs)
- All approvals recorded on the request
- Gateway mints credential only when `approvals.length >= min_approvals`
- Each approval expires independently (`AUTHRA_APPROVAL_TTL_S`)

## Approval Credential

```json
{
  "v": 2,
  "jti": "apc_abc123",
  "kid": "gateway_kid",
  "issuer": "https://authragen.example.com",
  "subject": "apr_abc123",
  "audience": "mcp:payments-svc",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "intent_hash": "sha256...",
  "action_jti": "att_...",
  "approvals": [
    { "key_id": "ak_1", "role": "approver", "decision": "approve", "timestamp": "..." },
    { "key_id": "ak_2", "role": "admin", "decision": "approve", "timestamp": "..." }
  ],
  "version": 2,
  "signature": "AR1..."
}
```

## Execution with Approval

```javascript
const receipt = await me.execute(actionToken, intent, {
  approval: approvalCredential
});
```

**Execute-time verification:**
- Approval credential valid (signature, issuer, audience, expiry)
- `intent_hash` matches original request
- `action_jti` matches action token (when present)
- Sufficient distinct approvals (`>= min_approvals`)
- All approvers have required roles

## Denying

```javascript
await approver.approve('apr_abc123', {
  approve: false,
  reason: 'Insufficient documentation'
});
// Request status → denied, no credential minted
```

## Listing Approvals

```javascript
// All pending in org
const pending = await me.listApprovals({ org_id, status: 'pending' });

// With filters
const filtered = await me.listApprovals({
  org_id,
  status: 'approved',  // pending | approved | denied | expired
  since: '2024-01-01T00:00:00Z',
  limit: 50,
  offset: 0
});
```

## Expiry

- Approval requests expire at `expires_at` (default `AUTHRA_APPROVAL_TTL_S` = 1hr)
- Approval credentials expire at their `exp`
- Expired requests → `deny` on execute
- No auto-renewal; new authorization required

## Dashboard

- Pending approvals queue with exact intent preview
- "Why step-up?" with risk factors + policy rule
- Approver identity + key ID displayed
- Quorum progress bar
- One-click approve/deny with reason field
- Audit trail of all approvals

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Authenticity | Signed by gateway key (`EdDSA/AR1`) |
| Binding | Bound to `intent_hash` + `action_jti` + `aud` |
| Non-transferable | Cannot move between requests |
| Expiring | TTL on both request and credential |
| Quorum | Distinct key IDs required |
| CSRF-safe | Bearer auth only, no cookies |
| Audit | Full trail in receipts + approval log |

## Next: [Revocation](/guide/revocation)