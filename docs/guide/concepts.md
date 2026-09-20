# Core Concepts

## 60-Second Mental Model

```
Human / Organization
  └─ Org Root (KMS-pluggable; file default = dev only) + Role Keys (admin/approver/executor/reporter)
       └─ Agent Blueprint (reusable security posture, versioned)
            └─ Agent Passport (agent-held Ed25519, did:authragen:<full-key>)
                 └─ Delegation (agent-signed, narrowing-only, registered)
                      └─ Signed Intent ──► Policy + Risk ──► allow / step-up / deny
                           └─ allow/step-up-approved ──► Action Credential (single-use, aud-bound)
                                └─ /v1/execute: hash match + approval match + nonce consume + atomic debit
                                     └─ Receipt (hash-chained, checkpointed, request-id + policy-hash bound)
```

## Key Concepts

### Organization
Root of trust. Contains:
- Ed25519 root keypair (KMS-backed in production)
- Role-based API keys (`admin`, `approver`, `executor`, `reporter`)
- Risk thresholds and quotas
- Emergency lock capability

### Agent Blueprint
Reusable security template:
- Default policy, risk thresholds, budgets
- Approval rules (quorum, required approvers)
- Delegation constraints (max depth, spend caps)
- Versioned with instance tracking

### Agent Passport
Agent's identity credential:
- `did:authragen:<base64url(32-byte Ed25519 pubkey)>` — collision-resistant DID
- Self-custody: agent generates keypair, submits CSR
- Key history with `kid` + grace period + revocation
- Lifecycle: `draft` → `pending_approval` → `active` → `suspended`/`quarantined` → `revoked`
- Ownership metadata (technical owner, sponsor, team, environment, purpose, model, runtime)

### Delegation
Client-signed, server-registered narrowing of authority:
- Signed by delegator (not server)
- Monotone attenuation: scope ⊆ parent, resources ⊆ parent, spend ≤ parent, expiry ≤ parent, depth+1 ≤ max_depth
- Authority check: `parent.sub === delegator_id` (or admin for root)
- Cross-org and cycle rejection

### Signed Intent
Exact-action request signed by agent:
```
{
  v: 2,
  passport_id, org_id,
  action: 'payments.charge',
  resource: 'stripe:invoice:42',
  params: { ... },
  amount_cents: 499,
  destination: 'acct_...',
  tool: 'stripe',
  nonce: 'agent-generated-16-chars',
  iat, exp, aud: 'mcp:payments-svc'
}
```
Canonicalized (NFC, no coercion, no traversal, duplicate-key rejection) → SHA-256 → `intent_hash`

### Policy Engine
Deny-by-default evaluation:
- Versioned policies with hashes (`policyHash`)
- Rich conditions: spend, depth, environment, blueprint, agent, audience, tool, time
- `allow` / `step_up` / `deny` decisions
- Simulation endpoint (`dry_run: true`) for preflight
- Conflict detection across policies

### Action Credential
Short-lived, single-use execution token:
- Org-sealed (Ed25519), `EdDSA/AR1` only (alg confusion rejected)
- Carries: `jti, kid, issuer, subject, audience, iat, exp, intent_hash, version`
- Audience-bound (must match `intent.aud`)
- Consumed at execute (nonce + jti replay protection)

### Approval
Human-in-the-loop for high-risk actions:
- Authenticated approver identity (key id + role), CSRF-safe (Bearer only)
- Bound to `intent_hash` (+ `action_jti` when present) and audience
- Quorum support (`min_approvals` distinct approvers)
- Expiring, non-transferable

### Revocation
Cascading, deterministic, versioned:
- Types: `org`, `blueprint`, `passport`, `key`, `token`, `action`, `apikey`
- Sequence-numbered feed (`seq`, `since_seq`) for polling
- Suspension/quarantine = reversible holds; revoke = terminal
- Key revocation names explicit `kid` with validity windows

### Audit Receipts
Hash-chained, tamper-evident:
- O(1) append with atomic rename
- Carries: `request_id`, `policy_id/hash/version`, `risk+version`, `intent_hash`, `action_jti`, approval/executor identities
- Per-org streams, JSONL export, signed evidence bundles
- Checkpoints signed by gateway key + optional `AUTHRA_ANCHOR_URL` anchor

### Offline Verification
Stateless envelope authenticity:
- `verifyOffline(envelope, org_pubkey)` → `{signature_valid, credential_valid, expiry_valid, revocation_freshness, payload}`
- Revocation freshness = `fresh` | `revoked` | `unknown` (needs feed/checkpoint)

## Data Flow Summary

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Agent     │     │  Gateway    │     │  Resource   │
│  (local)    │     │  (server)   │     │  (external) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ 1. generate keypair                   │
       │◄──────────────────────────────────────│
       │                   │                   │
       │ 2. CSR → passport                     │
       ├──────────────────►│                   │
       │◄──────────────────┤                   │
       │                   │                   │
       │ 3. sign intent                        │
       │◄──────────────────────────────────────│
       │                   │                   │
       │ 4. authorize(intent+sig)              │
       ├──────────────────►│                   │
       │◄──── action_token ┤                   │
       │                   │                   │
       │ 5. execute(token+intent)              │
       ├──────────────────►│                   │
       │◄───── receipt ────┤                   │
       │                   │ 6. call resource  │
       │                   ├──────────────────►│
       │                   │◄──────────────────┤
```

## Next: [Architecture](/guide/architecture)