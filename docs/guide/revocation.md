# Revocation

## Overview

Revocation is **cascading, deterministic, and versioned**. One call revokes an entity and all its dependents.

## Revocation Types

| Type | Target | Cascades To |
|------|--------|-------------|
| `org` | Organization | All blueprints, passports, keys, tokens, approvals, API keys |
| `blueprint` | Blueprint | All member passports + their delegations + tokens |
| `passport` | Agent Passport | All sub-agents + delegations + action credentials |
| `key` | Specific `kid` | Tokens issued with that key |
| `token` | Delegation token | Child delegations + action credentials |
| `action` | Action credential | (Terminal, already single-use) |
| `apikey` | API key | (Terminal) |

## Revoke API

```javascript
await me.revoke({
  type: 'passport',  // 'org' | 'blueprint' | 'passport' | 'key' | 'token' | 'action' | 'apikey'
  id: 'agt_abc123',
  reason: 'Agent decommissioned',
  // For key revocation:
  kid: 'kid_2'  // required when type === 'key'
});
```

**Response:**
```json
{
  "revoked": ["agt_abc123", "agt_child_1", "agt_child_2", "tkn_...", "att_..."],
  "seq": 42,
  "request_id": "rq_..."
}
```

## Cascade Semantics

```
revoke(org)
  → all blueprints
    → all member passports
      → all sub-agents (recursive)
        → all delegations (recursive)
          → all action credentials
  → all API keys
  → org lock (fail-closed)

revoke(blueprint)
  → all member passports (same cascade)

revoke(passport)
  → all sub-agents (recursive)
    → all delegations (recursive)
      → all action credentials

revoke(token)
  → all child delegations (recursive)
    → all action credentials

revoke(key)
  → all tokens issued with that kid
```

## Key Revocation (Explicit `kid`)

```javascript
await me.revoke({
  type: 'key',
  id: 'agt_abc123',  // passport ID
  kid: 'kid_2',      // specific key ID to revoke
  reason: 'Key compromised'
});
```

- Revokes explicit `kid` in `keys.history`
- Sets `revoked: true` + `until: now`
- Tokens/credentials issued with that `kid` → invalid
- Current `kid` can be revoked (forces rotation)

## Suspension vs Revocation

| State | Reversible | Effect | Use Case |
|-------|------------|--------|----------|
| `suspended` | Yes (admin) | Fail-closed, passport exists | Maintenance, investigation |
| `quarantined` | Yes (admin) | Fail-closed, security flag | Suspected compromise |
| `revoked` | **No** | Terminal, cascades | Decommission, confirmed compromise |

```javascript
// Suspend (reversible)
await me.setPassportStatus('agt_abc123', 'suspended');

// Quarantine (reversible, security)
await me.setPassportStatus('agt_abc123', 'quarantined');

// Reactivate
await me.setPassportStatus('agt_abc123', 'active');
```

## Revocation Feed (Polling)

Executors poll for freshness:

```javascript
// Initial sync
let feed = await me.getRevoked({ org_id });
// { revocations: [...], seq: 100, checkpoint: {...} }

// Incremental poll
feed = await me.getRevoked({ org_id, since_seq: 100 });
// Only changes since seq 100
```

**Feed entry:**
```json
{
  "seq": 42,
  "type": "passport",
  "id": "agt_abc123",
  "reason": "Agent decommissioned",
  "timestamp": "2024-01-01T00:00:00Z",
  "cascade": ["agt_child_1", "tkn_..."]
}
```

## Offline Verification Freshness

```javascript
const result = await me.verifyOffline(envelope, orgPubkey);

// result.revocation_freshness:
//   'fresh'     - checked against recent feed (seq within window)
//   'revoked'   - entity in feed
//   'unknown'   - no recent feed/checkpoint available
```

**Freshness requires:** Recent revocation feed (`since_seq`) or signed checkpoint.

## Emergency Org Lock

```javascript
// Lock (fail-closed for entire org)
await me.lockOrg('org_xyz', 'Security incident');

// Unlock
await me.unlockOrg('org_xyz');
```

- Bypasses all authorization (even admin)
- Only `unlockOrg` or direct DB intervention restores
- Audited with request ID + admin identity

## Dashboard

- Revocation center with cascade preview
- "What will this revoke?" tree view
- Revocation feed with real-time updates
- Per-entity: revocation history + cascade graph
- Emergency lock button (with confirmation)

## Best Practices

1. **Rotate before revoke** for keys: `rotateAgentKey()` → wait grace → `revoke({type:'key', kid: old})`
2. **Use suspension** for temporary holds (reversible)
3. **Poll revocation feed** at execute-time for critical paths
4. **Cache with TTL** — never cache revocation status indefinitely
5. **Monitor seq gaps** — detect missed revocations

## Next: [Audit & Accountability](/guide/audit)