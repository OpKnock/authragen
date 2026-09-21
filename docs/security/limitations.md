# Known Limitations (v2.2.1)

## Storage

| Limitation | Impact | Workaround |
|------------|--------|------------|
| File storage = single-instance | No horizontal scaling | Use Postgres adapter (documented) |


| Remote control-plane reads use request-boundary remote refreshes | Each API request refreshes the in-memory mirror from Postgres/Redis before evaluation; very large installations pay extra read cost | Use Postgres/Redis for multi-instance deployments; tune gateway capacity and database resources as fleet size grows |

## KMS & Cryptography

| Limitation | Impact | Workaround |
|------------|--------|------------|

| No HSM integration | FIPS 140-2 not certified | KMS backend can use CloudHSM |
| Core agent/passport keys remain Ed25519 | Existing credentials are not quantum-resistant | ML-DSA-44/65/87 credentials are available as an explicit PQ profile; hybrid/hardware-backed core-passport migration remains future work |
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
| Audit durability depends on configured backend | Postgres/Redis modes persist receipts and checkpoints in the configured durable backend; file mode remains single-instance development storage | Use Postgres/Redis for shared deployments; use backups/DR and external anchoring where immutability requirements demand it |
| Checkpoint key = single point | Compromise = fake checkpoints | Separate key; KMS-backed; rotation |
| No log compression | Linear growth | Periodic export + archive (manual) |

## Policy & Risk

| Limitation | Impact | Workaround |
|------------|--------|------------|
| Risk = heuristic | Not ML-based safety | Pluggable providers; ceiling only adds denials |
| Policy changes are explicit versioned writes | Callers should simulate and review before activation | Version + hash is recorded in audit receipts |
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
| One gateway deployment currently uses one signing root for its org namespace | A single root-key compromise affects all orgs in that deployment | Use separate deployments for stronger tenant isolation; per-org KMS roots are future work |
| OIDC interactive SSO is not a built-in dashboard flow | Federated API/service authentication is supported; browser SSO still belongs at a trusted proxy or future console integration | Configure OIDC bearer federation or an OIDC-aware reverse proxy |
| No SPIFFE identity issuance | AuthraGen validates X.509-SVID/JWT-SVID identities and can consume the SPIFFE Workload API; issuance remains the SPIRE/mesh responsibility | Run SPIRE as the workload identity provider |
| No standard token format | AR1 proprietary | JWT-compatible structure; converter possible |
| MCP/A2A = custom adapters | Not native protocols | Adapters implement contract |

## Operational

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No built-in UI SSO | Dashboard uses Bearer/API-key auth | Put the console behind an OIDC-aware reverse proxy |
| Console is not an org-admin SaaS portal | Organization selection is API-key scoped | Use separate deployments or a trusted proxy for stronger administrative isolation |
| No config API | Env vars only | ConfigMap/Secrets + reload (future) |
| No metric for delegation depth | Blind spot | Custom metric (easy to add) |

## Roadmap (Not Committed)

### Next
- [ ] Push/webhook revocation distribution
- [ ] Dashboard interactive OIDC SSO
- [ ] JWT/W3C Verifiable Credential interoperability profiles
- [ ] Log compression, archival and retention controls
- [ ] Cross-instance distributed locking / linearizable writes for every control-plane mutation
- [ ] Formal interoperability/conformance certification

### Research
- [ ] Post-quantum signature profiles
- [ ] Zero-knowledge policy proofs
- [ ] Formal verification of the attenuation implementation

### Completed in the current repository
- [x] Postgres storage adapter
- [x] Redis storage adapter
- [x] AWS KMS / GCP KMS / Vault / Azure KMS interfaces
- [x] Prometheus `/metrics` endpoint
- [x] Dashboard policy editor, audit and lifecycle controls

### v3.0 (Research)
- [x] ML-DSA-44/65/87 credential profile
- [ ] Zero-knowledge proofs for policy evaluation
- [ ] Verifiable credentials (W3C VC) interop
- [ ] Formal verification of attenuation logic

## Validation Boundary

The repository now includes centralized audit persistence, distributed storage/atomicity smoke tests, and a repeatable concurrent load harness. Real cloud-provider KMS validation is available as a gated GitHub Actions workflow and requires credentials/identity configuration for the target AWS/GCP/Azure environments. Those provider runs are evidence-producing deployment tests, not something the repository can honestly self-assert.

## Honest Assessment

**AuthraGen is a production-capable self-hosted control plane with explicit deployment boundaries.**
The repository includes Postgres/Redis storage adapters, pluggable KMS backends, signed
credentials, audit/checkpointing, a browser control plane and adversarial end-to-end tests.
Production operation still requires sound key management, TLS, backups/DR, monitoring,
incident response, external anchoring where required, and an architecture appropriate to
shared-state/cluster requirements.

Compliance certifications and formal conformance are not claimed by this repository.

## Next: [Deployment](/deployment/docker)