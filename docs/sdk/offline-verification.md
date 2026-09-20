# Offline Verification

## Overview

`verifyOffline()` validates credential envelopes **without network access**. Uses only the org public key.

## Use Cases

- Edge/gateway validation without control plane latency
- Air-gapped environments
- Client-side verification before sending to resource
- Audit verification of historical receipts

## JavaScript

```javascript
const { AuthraGen } = require('authragen');

// Static (no instance needed)
const result = AuthraGen.verifyOffline(envelope, orgPubkey);

// Or instance method
const agent = new AuthraGen({ baseUrl });
const result = await agent.verifyOffline(envelope, orgPubkey);
```

## Python

```python
from authragen import AuthraGen

result = AuthraGen.verify_offline_static(envelope, org_pubkey)
```

## Input

- `envelope`: Base64url-encoded credential (action token, approval credential, etc.)
- `orgPubkey`: Base64url-encoded org Ed25519 public key (from `GET /v1/orgs/:id/pubkey`)

## Output

```javascript
{
  signature_valid: true,      // Ed25519 signature verifies under org key
  credential_valid: true,     // Structure valid (v, jti, kid, issuer, sub, aud, iat, exp, intent_hash)
  expiry_valid: true,         // iat <= now <= exp (with clock skew tolerance)
  revocation_freshness: 'fresh' | 'revoked' | 'unknown',
  payload: { ... },           // Decoded credential (if valid)
  error: null                 // Error message if any check failed
}
```

## Revocation Freshness

| Value | Meaning |
|-------|---------|
| `'fresh'` | Verified against recent revocation feed/checkpoint |
| `'revoked'` | Entity found in revocation feed |
| `'unknown'` | No recent feed/checkpoint available (stale or never fetched) |

**Freshness requires:** Recent `GET /v1/revoked` feed or signed checkpoint.

## Credential Types Verified

| Type | Envelope Prefix | Verified Fields |
|------|-----------------|-----------------|
| Action Credential | `AR1.` | All + `intent_hash`, `aud` |
| Approval Credential | `AR1.` | All + `intent_hash`, `action_jti`, `aud`, `approvals[]` |
| Delegation Token | `AR1.` | All + `scope`, `constraints` |
| Passport | `AR1.` | All + `keys`, `status` |
| Blueprint | `AR1.` | All + `policy`, `constraints` |

## Algorithm Enforcement

Only `EdDSA/AR1` (Ed25519) accepted:
- `alg: "none"` → rejected
- `alg: "RS256"` → rejected
- `alg: "HS256"` → rejected
- Any non-EdDSA → rejected

## Audience Binding

- Action credentials: `envelope.aud === intent.aud` (enforced at execute)
- Approval credentials: `envelope.aud === intent.aud`
- Offline verify: Returns `aud` in payload for caller verification

## Example: Edge Gateway Validation

```javascript
// At edge (Cloudflare Worker, Vercel Edge, etc.)
async function validateRequest(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const envelope = authHeader.slice(7);
  const orgPubkey = env.AUTHRA_ORG_PUBKEY;  // Pre-loaded

  const result = AuthraGen.verifyOffline(envelope, orgPubkey);

  if (!result.signature_valid || !result.credential_valid || !result.expiry_valid) {
    return new Response('Invalid credential', { status: 401 });
  }

  if (result.revocation_freshness === 'revoked') {
    return new Response('Credential revoked', { status: 403 });
  }

  if (result.revocation_freshness === 'unknown') {
    // Optionally allow with warning, or require fresh check
    console.warn('Revocation status unknown - stale cache?');
  }

  // Verify audience matches this service
  if (result.payload.audience !== 'mcp:my-service') {
    return new Response('Wrong audience', { status: 403 });
  }

  // Attach verified payload for downstream
  request.headers.set('X-AuthraGen-Payload', JSON.stringify(result.payload));
  return request;
}
```

## Cache Strategy

```javascript
// Fetch and cache revocation feed periodically
async function refreshRevocationCache(orgId, orgPubkey) {
  const response = await fetch(`https://authragen.example.com/v1/revoked?org_id=${orgId}`);
  const feed = await response.json();
  
  // Store in KV/Redis with TTL
  await cache.put(`revocations:${orgId}`, JSON.stringify(feed), { 
    expirationTtl: 300  // 5 min
  });
}

// Verify with cached feed
async function verifyWithCache(envelope, orgId, orgPubkey) {
  const cached = await cache.get(`revocations:${orgId}`);
  const feed = cached ? JSON.parse(cached) : null;
  
  const result = AuthraGen.verifyOffline(envelope, orgPubkey, { 
    revocationFeed: feed 
  });
  
  return result;
}
```

## Limitations

| Limitation | Mitigation |
|------------|------------|
| No real-time revocation | Poll feed frequently (30-60s) |
| No policy evaluation | Use for authn only; authz at gateway |
| No budget/delegation checks | Execute at gateway for full checks |
| Clock skew tolerance | Configure `AUTHRA_CLOCK_SKEW_S` |

## Next: [Adapters Overview](/adapters/overview)