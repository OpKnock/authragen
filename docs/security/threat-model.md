# Threat Model

## Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| Org Root Private Key | CRITICAL | KMS/HSM only (file = dev only) |
| Agent Private Keys | HIGH | Self-custody; never on server |
| API Key Secrets | HIGH | scrypt-hashed; shown once |
| Bootstrap Token | HIGH | Single-use; auto-deleted |
| Action Credentials | MEDIUM | Short TTL; single-use |
| Audit Receipts | MEDIUM | Hash-chained; tamper-evident |
| Revocation Feed | MEDIUM | Versioned; seq-numbered |
| Policy Documents | LOW | Versioned; hash-verified |

## Attack Surface

```
                    ┌─────────────────┐
                    │   Attacker      │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Network      │    │  Application  │    │  Supply Chain │
│  (MITM, DoS)  │    │  (Input,      │    │  (Deps,       │
│               │    │   Logic,      │    │   Build)      │
│               │    │   AuthZ)      │    │               │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                    │                    │
        ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    AUTHROGEN GATEWAY                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ TLS/HTTPS│ │ Rate     │ │ Input    │ │ AuthN/   │       │
│  │ Headers  │ │ Limits   │ │ Validate │ │ AuthZ    │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Policy   │ │ Nonce    │ │ Audit    │ │ Revoke   │       │
│  │ Engine   │ │ Store    │ │ Chain    │ │ Feed     │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## STRIDE Analysis

### Spoofing
| Threat | Mitigation |
|--------|------------|
| Impersonate agent | Ed25519 signatures; `kid`-aware; passport status check |
| Impersonate gateway | Only gateway key signs credentials; `issuer` verified |
| Impersonate approver | Bearer auth required; key ID + role recorded |
| Impersonate org | Org root key in KMS; `org_id` scoped everywhere |

### Tampering
| Threat | Mitigation |
|--------|------------|
| Modify intent in transit | `intent_hash` signed by agent; re-verified at execute |
| Modify action credential | Gateway-signed; `EdDSA/AR1` only; alg confusion rejected |
| Modify audit log | Hash-chained receipts; checkpoints; external anchor |
| Modify policy | Versioned with `policyHash`; receipts carry hash |
| Modify delegation | Client-signed; server validates attenuation |

### Repudiation
| Threat | Mitigation |
|--------|------------|
| Agent denies action | Signed intent + receipt with `authn: agent_sig` |
| Approver denies decision | Signed approval credential with key ID + role |
| Gateway denies receipt | Hash chain + checkpoint + external anchor |
| Admin denies revocation | Signed revocation entry in versioned feed |

### Information Disclosure
| Threat | Mitigation |
|--------|------------|
| API key in logs | Redacted to `key_id` only; secrets never logged |
| Private keys in response | Only public keys; `custody: self` keys never on server |
| Bootstrap token | Single-use; 0600 file; auto-deleted |
| Audit envelopes | Redacted to `jti` + `intent_hash` |
| Cross-org data | Generic `forbidden` (no existence leak) |

### Denial of Service
| Threat | Mitigation |
|--------|------------|
| Rate limit exhaustion | Per-route + per-IP limits; configurable |
| Body bomb | `AUTHRA_BODY_LIMIT` (256KB default) |
| Nonce store exhaustion | TTL cleanup; bounded store |
| Revocation feed spam | Pagination; `since_seq` incremental |
| Policy evaluation DoS | Bounded conditions; no regex; simple glob |

### Elevation of Privilege
| Threat | Mitigation |
|--------|------------|
| Scope widening | Attenuation check: `child ⊆ parent` |
| Delegation forgery | Authority check: `parent.sub === delegator_id` |
| Cross-org escalation | `org_id` equality enforced |
| Policy bypass | Deny-by-default; deny-wins; empty=`[]` matches nothing |
| Approval replay | Bound to `intent_hash` + `action_jti` + `aud` |
| Key rotation abuse | Grace period only; revoked `kid` fails closed |
| Server-custodied key misuse | `AUTHRA_ALLOW_CUSTODY=1` dev-only; flagged everywhere |

## Attack Trees

### Goal: Execute Unauthorized Action

```
Execute Unauthorized Action
├── Forge Valid Intent
│   ├── Steal Agent Private Key
│   │   ├── Compromise Agent Process
│   │   ├── Extract from Memory
│   │   └── Side-Channel Attack
│   ├── Replay Old Intent
│   │   └── Nonce Replay (blocked by nonce store)
│   └── Modify Intent Post-Signature
│       └── Hash Mismatch at Execute (blocked)
├── Bypass Authorization
│   ├── Policy Misconfiguration
│   │   └── Empty Array Match (fixed: [] matches nothing)
│   ├── Delegation Widening
│   │   └── Attenuation Check (blocked)
│   └── Approval Forgery
│       └── Bound to intent_hash + action_jti (blocked)
├── Compromise Gateway
│   ├── Steal Gateway Signing Key
│   │   └── KMS/HSM Protection (production)
│   └── Inject Malicious Policy
│       └── Admin Auth Required + Audit Trail
└── Replay Action Credential
    └── JTI Consume Check (blocked)
```

### Goal: Persistent Access After Revocation

```
Persistent Access After Revocation
├── Use Revoked Credential
│   ├── Revocation Feed Stale
│   │   └── Polling + Freshness Flags (mitigated)
│   └── Offline Verify Without Feed
│       └── Freshness = 'unknown' (caller must handle)
├── Use Child of Revoked Parent
│   └── Cascade Revocation (enforced)
└── Use Rotated Key
    └── Kid Validity Windows + Grace (enforced)
```

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Agent key compromise | Medium | High | Short TTLs; rotation; revocation cascade |
| Gateway key compromise | Low | Critical | KMS/HSM; separate checkpoint key |
| Policy misconfiguration | Medium | High | Simulation; conflict detection; default-deny |
| Replay attack | Low | High | Nonce + JTI single-use; persistent store |
| Audit tampering | Low | Medium | Hash chain + checkpoints + external anchor |
| Supply chain attack | Low | High | Dependabot; CodeQL; SLSA provenance |
| Insider admin abuse | Low | High | Multi-party approval; full audit trail |

## Next: [Cryptography](/security/cryptography)