# Security Model

## Core Principles

1. **Self-Custody by Default** — Agent private keys never leave client process
2. **Exact-Intent Authorization** — No ambient authority; every action cryptographically bound
3. **Single-Use Credentials** — Action tokens consumed at execute; replay impossible
4. **Narrowing-Only Delegation** — Authority monotonically decreases down chain
5. **Deny-by-Default Policy** — Empty rules match nothing; explicit allow required
6. **Audit-First** — Every decision hash-chained, checkpointed, exportable
7. **Fail-Closed** — Revoked/suspended/locked entities always denied

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRUSTED                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Gateway   │  │    KMS      │  │  Transparent │             │
│  │  (server)   │  │  (org root) │  │   Log        │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
└─────────│────────────────│────────────────│────────────────────┘
          │                │                │
          ▼                ▼                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      UNTRUSTED                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Agents    │  │  Network    │  │  Callers    │             │
│  │  (clients)  │  │  (transport)│  │  (services) │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Threat Categories Addressed

| Category | Mitigation |
|----------|------------|
| **Forged Intent** | Ed25519 signature verified against passport `kid` |
| **Wrong Key/KID** | `kid`-aware verification; grace period for rotation |
| **Rotated Key Abuse** | History with `until` timestamps; revoked keys fail |
| **Expired Credential** | Short TTLs (configurable); `exp` enforced at execute |
| **Revoked Credential** | Cascade revocation + versioned feed polling |
| **Revoked Parent Delegation** | Chain validation on every authorize/execute |
| **Scope Widening** | Attenuation check: `child ⊆ parent` (glob) |
| **Resource Widening** | Resource glob matching enforced |
| **Target Widening** | `allowed_targets` glob matching |
| **Budget Increase** | `max_spend_cents` monotone decreasing |
| **Expiry Extension** | `not_after` monotone decreasing |
| **Depth Increase** | `max_depth` monotone; cycle detection |
| **Cross-Org Chain** | `org_id` equality enforced |
| **Approval Replay** | Bound to `intent_hash` + `action_jti` + `aud` |
| **Approval Substitution** | Distinct approver key IDs required |
| **Param/Amount/Dest Tampering** | `intent_hash` re-verified at execute |
| **Normalization Attacks** | Canonicalization (NFC, no coercion, no traversal) |
| **Nonce/Action-JTI Replay** | Persistent store + atomic consume |
| **Policy Conflicts** | Conflict detection endpoint |
| **Empty Policy Match** | `[]` matches nothing; `*` required |
| **Malformed Credentials** | Strict schema validation |
| **Algorithm Confusion** | Only `EdDSA/AR1` accepted |
| **Audience Mismatch** | `envelope.aud === intent.aud` enforced |
| **Issuer Mismatch** | Gateway key verified |
| **Clock Skew** | Configurable window (`AUTHRA_CLOCK_SKEW_S`) |
| **Oversized Requests** | Body limit (`AUTHRA_BODY_LIMIT`) |
| **Rate Abuse** | Per-route + per-IP limits |
| **Dashboard XSS** | `textContent` only, CSP, no `localStorage` |
| **Secret Leakage** | Redaction in logs/audit/errors |
| **Audit Tampering** | Hash chain + checkpoints + external anchor |
| **Stale Offline Revocation** | Freshness flags (`fresh`/`revoked`/`unknown`) |

## Threat Categories NOT Addressed (By Design)

| Category | Reason |
|----------|--------|
| **AI Safety** | Risk is triage heuristic, not safety oracle |
| **Full Log Rewrite** | Tamper-evident only; needs external anchor |
| **Compromised KMS** | Bring your own KMS; not managed |
| **Side-Channel Attacks** | Not in scope for application layer |
| **Quantum Resistance** | Ed25519 not quantum-safe; future migration path |
| **Insider Threat (admin)** | Multi-party approval + audit trail only |

## Security Properties Summary

| Property | Guarantee |
|----------|-----------|
| **Authentication** | Ed25519 signatures; API keys scrypt-hashed |
| **Authorization** | Exact-intent + policy + delegation + budget |
| **Integrity** | Canonical JSON + SHA-256 + hash-chained receipts |
| **Non-repudiation** | Signed intents, approvals, receipts |
| **Replay Protection** | Nonce + action JTI single-use |
| **Delegation Safety** | Monotone attenuation + full chain validation |
| **Revocation** | Cascading, versioned, pollable |
| **Audit** | Tamper-evident chain + checkpoints + anchor |
| **Offline Verification** | Envelope authenticity without network |
| **Transport** | HTTPS, security headers, rate limits, body limits |

## Next: [Threat Model](/security/threat-model)