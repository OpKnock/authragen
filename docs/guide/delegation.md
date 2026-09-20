# Delegation

## Overview

Delegation allows agents to grant narrowed authority to sub-agents or sessions. **Critical properties:**

- **Client-signed**: Delegator signs, server registers (not server-signed)
- **Narrowing-only**: Monotone attenuation — authority can only decrease
- **Chain validation**: Full chain verified on every authorize/execute
- **Registered**: Server stores for revocation/cascade + audit

## Delegation Structure

```javascript
const delegation = {
  v: 2,
  jti: 'tkn_abc123',           // unique token ID
  org_id: 'org_xyz',
  sub: 'agt_child',            // subject (delegatee passport ID)
  parent_jti: 'tkn_parent',    // parent delegation (or null for root)
  scope: ['payments.charge'],  // allowed actions (glob)
  resources: ['stripe:invoice:*'],  // allowed resources (glob)
  constraints: {
    allowed_targets: ['acct_merchant_*'],  // destination glob
    max_spend_cents: 10000,                // spend cap
    not_after: '2024-12-31T23:59:59Z',     // expiry
    max_depth: 2,                          // sub-delegation limit
    require_approval: false                // add approval requirements
  },
  kid: 'kid_1',                // delegator's key ID
  iat: '2024-01-01T00:00:00Z'
};

// Delegator signs envelope
const signed = me.signDelegation(delegation, delegatorKeypair);

// Register with gateway (executor+ auth)
await me.registerDelegation(signed);
```

## Attenuation Rules (Monotone)

| Property | Rule | Enforcement |
|----------|------|-------------|
| `scope` | `child ⊆ parent` (glob) | Authorize + Execute |
| `resources` | `child ⊆ parent` (glob) | Authorize + Execute |
| `allowed_targets` | `child ⊆ parent` (glob) | Authorize + Execute |
| `max_spend_cents` | `child ≤ parent` | Authorize + Execute + Budget |
| `not_after` | `child ≤ parent` | Authorize + Execute |
| `max_depth` | `child ≤ parent`, `depth+1 ≤ max_depth` | Register |
| `require_approval` | Can only add (false → true) | Authorize |

**Glob matching:** `*` matches any segment, `**` matches any path (resource/target)

## Authority Validation

Registration checks (in order):

1. **Signature valid** under delegator's `kid`-aware pubkey
2. **Envelope integrity** (envelope === payload)
3. **Authority**: 
   - With parent: `parent.sub === delegator_id` (delegator owns parent)
   - Without parent: `delegation.sub === delegator_id` OR caller is org admin
4. **Cross-org**: `delegation.org_id === parent.org_id` (reject cross-org)
5. **Attenuation**: All monotone rules pass
6. **Cycle detection**: No loops in delegation graph
7. **Parent live**: Parent not revoked/expired

## Delegation Chain Example

```
Root (org admin)
  │
  ├─► Delegation A (agt_manager)
  │      scope: ['payments.*']
  │      max_spend: 50000
  │      max_depth: 2
  │
  ├─► Delegation B (agt_senior)  [child of A]
  │      scope: ['payments.charge']          ✓ narrowed
  │      max_spend: 10000                    ✓ narrowed
  │      max_depth: 1                        ✓ narrowed
  │
  └─► Delegation C (agt_junior)  [child of B]
         scope: ['payments.charge']          ✓ same
         max_spend: 5000                     ✓ narrowed
         max_depth: 0                        ✓ narrowed
```

## Token Coverage Check

On **every** authorize AND execute:

```javascript
function tokenCovers(token, action, resource) {
  return (
    globMatch(token.scope, action) &&
    globMatch(token.resources, resource) &&
    (token.constraints.allowed_targets.length === 0 ||
     globMatch(token.constraints.allowed_targets, destination))
  );
}
```

## Querying Delegations

```javascript
// List all delegations in org
const delegations = await me.listDelegations({ org_id });

// Get delegation chain for a passport
const chain = await me.getDelegationChain('agt_child');
// Returns: [{ token, delegator, parent, depth, valid }, ...]
```

## Revocation Cascade

Revoking a delegation **cascades to all descendants**:

```javascript
await me.revoke({
  type: 'token',
  id: 'tkn_parent',
  reason: 'Manager left team'
});
// All child delegations + their action credentials → revoked
// Recorded in revocation feed with seq number
```

## Common Patterns

### Session Delegation (Short-Lived)
```javascript
const session = await me.createDelegation({
  parent_jti: agentDelegation.jti,
  sub: sessionAgentId,
  scope: ['payments.charge'],
  resources: ['stripe:invoice:inv_42'],
  constraints: {
    max_spend_cents: 499,
    not_after: '2024-01-01T01:00:00Z',  // 1 hour
    max_depth: 0
  }
});
```

### Team Delegation (Role-Based)
```javascript
const teamLead = await me.createDelegation({
  sub: teamLeadAgentId,
  scope: ['payments.*', 'refunds.*'],
  constraints: {
    max_spend_cents: 100000,
    max_depth: 1,
    require_approval: true  // team lead actions need approval
  }
});
```

### Environment Scoping
```javascript
const stagingOnly = await me.createDelegation({
  sub: stagingAgentId,
  scope: ['*'],
  resources: ['staging:*'],
  constraints: {
    allowed_targets: ['staging-*'],
    not_after: '2024-12-31T23:59:59Z'
  }
});
```

## Dashboard

Control plane shows:
- Full delegation tree per org
- Per-token: scope, constraints, depth, validity
- Delegator identity + key ID
- Revocation status + cascade preview
- "Why allowed/blocked" with exact scope match

## Next: [Policy Engine](/guide/policy)