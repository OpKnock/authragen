# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AuthraGen Gateway                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  HTTP    │  │  Auth    │  │  Policy  │  │  Audit   │           │
│  │  Router  │──►│  Middle │──►│  Engine  │──►│  Logger  │           │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
│       │            │            │            │                      │
│       ▼            ▼            ▼            ▼                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     Storage Abstraction                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │  │
│  │  │   Orgs      │  │  Passports  │  │  Policies   │  ...     │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│              ┌────────────┼────────────┐                           │
│              ▼            ▼            ▼                           │
│        ┌──────────┐ ┌──────────┐ ┌──────────┐                     │
│        │  File    │ │ Postgres │ │  Redis   │  (adapters)          │
│        │  (dev)   │ │  (prod)  │ │  (prod)  │                     │
│        └──────────┘ └──────────┘ └──────────┘                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### HTTP Router (`src/server.js`)
- Express-like routing with exact-match paths
- Request ID generation (`X-Request-Id`)
- Body parsing with size limits
- Security headers (CSP, HSTS, etc.)
- CORS configuration
- Rate limiting (per-route + per-IP)

### Auth Middleware (`src/auth.js`)
- API key validation (scrypt-hashed secrets)
- RBAC enforcement per endpoint
- Org-scoped lookups (cross-org returns generic 403)
- Session expiry + rotation
- Bootstrap token (single-use, rate-limited)

### Policy Engine (`src/policy.js`)
- Default-deny with explicit allow/step-up
- Versioned policies with integrity hashes
- Condition evaluation (spend, depth, env, blueprint, agent, audience, tool, time)
- Simulation (`dry_run`) and conflict detection
- Policy versioning for audit trail

### Intent Processing (`src/intent.js`)
- Strict validation + canonicalization
- NFC normalization, duplicate-key rejection
- No numeric coercion, no NaN/Infinity
- Resource path/URL normalization
- Clock skew tolerance
- Audience binding

### Crypto (`src/crypto.js`)
- Ed25519 via noble-ed25519
- Canonical JSON (deterministic, sorted keys)
- SHA-256 hashing
- scrypt for API key hashing
- HKDF for key derivation

### Token Management (`src/tokens.js`)
- Passport lifecycle (issue, rotate, status, revoke)
- Blueprint management (versioned templates)
- Delegation registration + validation
- Key history with `kid` + grace + revocation

### Nonce Store (`src/nonce.js`)
- File-backed persistence (single-instance)
- Redis hook documented for distributed
- Atomic check-and-set for budgets
- TTL-based cleanup

### Audit (`src/audit.js`)
- Hash-chained receipts (O(1) append)
- Signed checkpoints with prev-link
- Per-org streams + JSONL export
- Evidence bundles (signed)
- External anchor hook (`AUTHRA_ANCHOR_URL`)

### Risk (`src/risk.js`)
- Deterministic base heuristic (0-100 + factors)
- Pluggable providers (labeled, not trusted as safety)
- Hard denies never bypassed by low risk
- Ceiling only adds denials

### Signer (`src/signer.js`)
- Abstract key management
- File-backed (dev, warns on boot)
- KMS interface (`AUTHRA_KMS`: aws/gcp/vault/azure)
- Checkpoint signing key separate from org root

## Data Models

### Organization
```json
{
  "id": "org_...",
  "name": "acme",
  "pubkey": "base64url...",
  "root_kid": "kid_...",
  "risk_stepup": 60,
  "risk_ceiling": 80,
  "quotas": { "daily_requests": 10000 },
  "locked": false,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Passport
```json
{
  "v": 2,
  "id": "agt_...",
  "did": "did:authragen:...",
  "org_id": "org_...",
  "parent_id": null,
  "kind": "agent",
  "name": "shopper",
  "custody": "self",
  "blueprint_id": "bp_...",
  "owner": "team-platform",
  "sponsor": "jane@acme.com",
  "team": "platform",
  "environment": "production",
  "purpose": "payment-processing",
  "model": "gpt-4",
  "provider": "openai",
  "runtime": "node",
  "framework": "langchain",
  "created_at": "...",
  "last_seen": "...",
  "keys": {
    "current": { "kid": "kid_1", "pubkey": "...", "since": "..." },
    "history": [{ "kid": "kid_1", "pubkey": "...", "since": "...", "until": "...", "revoked": false }]
  },
  "grace_period_s": 300,
  "status": "active",
  "iat": "...", "exp": "...",
  "signature": "..."
}
```

### Action Credential (envelope)
```json
{
  "v": 2,
  "jti": "att_...",
  "kid": "gateway_kid",
  "issuer": "https://authragen.example.com",
  "subject": "agt_...",
  "audience": "mcp:payments-svc",
  "iat": "...",
  "exp": "...",
  "intent_hash": "sha256...",
  "version": 2,
  "signature": "AR1..."
}
```

## Storage Abstraction

```javascript
// src/store.js
const store = {
  orgs: { get, set, list, delete },
  passports: { get, set, list, delete },
  policies: { get, set, list, delete },
  delegations: { get, set, list, delete },
  approvals: { get, set, list, delete },
  revocations: { get, set, list, delete },
  audit: { append, verify, export, checkpoint },
  nonces: { consume, exists },
  budgets: { debit, check },
  backend: () => 'file' | 'postgres' | 'redis'
}
```

**Production requires:**
- Postgres: transactions for budget/token/approval/revocation/rotation/audit-seq
- Redis: `SET NX EX` for distributed nonce/action-jti atomicity
- Same record shapes, swap adapter

## Scaling Considerations

| Component | Single-Instance | Distributed |
|-----------|-----------------|-------------|
| Auth/Rate Limit | In-memory | Redis-backed |
| Nonce/Action JTI | File + mutex | Redis `SET NX EX` |
| Budgets | File + mutex | Postgres transactions |
| Audit | File + atomic rename | Postgres + async replication |
| Policy/Passport | File | Postgres (read replicas) |
| Revocation Feed | File | Postgres (indexed by seq) |

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                      Trust Boundary                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Agent     │  │  Gateway    │  │   KMS/HSM   │         │
│  │  (untrusted)│  │  (trusted)  │  │  (trusted)  │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│    Private Key      Org Root Key      Org Root Key         │
│    (never leaves)   (or KMS-backed)   (or KMS-backed)      │
└─────────────────────────────────────────────────────────────┘
```

## Next: [Identity & Passports](/guide/identity)