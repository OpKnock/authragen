# Known Limitations (v2.1)

## Storage

| Limitation | Impact | Workaround |
|------------|--------|------------|
| File storage = single-instance | No horizontal scaling | Use Postgres adapter (documented) |
| No built-in Postgres adapter | Production requires custom impl | Schema + transaction patterns documented |
| No built-in Redis adapter | Distributed nonce/action-JTI not atomic | Redis `SET NX EX` pattern documented |
| Process-local mutex for execute | Concurrent execute race in clustered | Postgres `SELECT FOR UPDATE` or Redis lock |

## KMS & Cryptography

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No built-in KMS | File-backed org root = dev only | `AUTHRA_KMS` interface; bring AWS KMS/GCP KMS/Vault/Azure |
| No HSM integration | FIPS 140-2 not certified | KMS backend can use CloudHSM |
| Ed25519 only | Not quantum-resistant | Algorithm agility via `v` + `alg` header |
| No key ceremony | Single admin can rotate root | Policy: require quorum for root rotation (future) |

## Revocation & Freshness

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Offline revocation = stale | `freshness: unknown` without recent feed | Poll feed at execute; cache with short TTL |
| No push revocation | Polling required | Webhook for critical paths (future) |
| Feed grows unbounded | Storage growth | Compaction + retention (future) |
| No CRL/OCSP | Standard formats not supported | Custom feed format; adapter possible |

## Audit & Accountability

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Tamper-evident ≠ immutable | Full rewrite possible without anchor | `AUTHRA_ANCHOR_URL` to Rekor/timestamp service |
| No built-in transparency log | Anchor hook only | Bring your own Rekor/TLSNotary |
| Checkpoint key = single point | Compromise = fake checkpoints | Separate key; KMS-backed; rotation |
| No log compression | Linear growth | Periodic export + archive (manual) |

## Policy & Risk

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Risk = heuristic | Not ML-based safety | Pluggable providers; ceiling only adds denials |
| No dynamic policy update | Requires version bump | Fast versioning; simulation before deploy |
| No ABAC/XACML | Custom condition language | Conditions cover common cases; extensible |
| Time windows = simple | No complex cron | Multiple windows; extensible |

## Delegation

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No delegation expiry auto-cleanup | Orphaned tokens | TTL + periodic cleanup job |
| No delegation templates | Manual per-delegation | Blueprint constraints as templates |
| No cross-org delegation | Hard `org_id` equality | Federation via OIDC (roadmap) |

## Interoperability

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No OIDC federation | Can't bind to Entra/Okta/Google | Roadmap; wrapper possible |
| No SPIFFE/SPIRE | No workload identity integration | Adapter pattern |
| No standard token format | AR1 proprietary | JWT-compatible structure; converter possible |
| MCP/A2A = custom adapters | Not native protocols | Adapters implement contract |

## Operational

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No built-in UI auth | Dashboard = API key only | Proxy with OIDC (future) |
| No multi-tenancy UI | Single org per dashboard | Run multiple instances |
| No config API | Env vars only | ConfigMap/Secrets + reload (future) |
| No metric for delegation depth | Blind spot | Custom metric (easy to add) |

## Roadmap (Not Committed)

### v2.2 (Planned)
- [ ] Postgres storage adapter
- [ ] Redis storage adapter
- [ ] AWS KMS / GCP KMS / Vault backends
- [ ] OIDC federation (bind `did:authragen` to external IdP)
- [ ] Webhook push for revocation
- [ ] Dashboard OIDC auth
- [ ] Metrics endpoint (`/metrics` Prometheus)

### v2.3 (Planned)
- [ ] SPIFFE/SPIRE integration
- [ ] Standard token format (JWT profile)
- [ ] Native MCP/A2A server implementations
- [ ] Policy visual editor in dashboard
- [ ] Delegation templates
- [ ] Log compression + archival

### v3.0 (Research)
- [ ] Post-quantum signatures (ML-DSA)
- [ ] Zero-knowledge proofs for policy evaluation
- [ ] Verifiable credentials (W3C VC) interop
- [ ] Formal verification of attenuation logic

## Honest Assessment

**AuthraGen is a prototype-grade control plane.** It implements the core cryptographic primitives and authorization logic correctly, but production deployment requires:

1. **Operational maturity**: Postgres/Redis, KMS, monitoring, DR
2. **Organizational process**: Key ceremonies, rotation schedules, incident response
3. **Compliance validation**: SOC 2, ISO 27001, GDPR mapping (implemented; needs audit)
4. **Scale testing**: Load tested to 10k req/s single-instance; distributed needs work

**Use for production pilots with operational investment. Not a drop-in SaaS replacement.**

## Next: [Deployment](/deployment/docker)