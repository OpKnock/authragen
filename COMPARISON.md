# AuthraGen and Microsoft Entra Agent ID / Agent 365 — factual comparison

Microsoft's agent identity stack (Entra Agent ID, Agent 365, Conditional Access,
Dataverse agent users, Defender/Purview signals) is a strong option **inside Microsoft
tenants**. Microsoft supports third-party agents and open standards including OAuth,
MCP and A2A, and continues to interoperate beyond M365/Azure-first scenarios.

AuthraGen is not a clone and does not claim superiority without evidence. It is a
**complementary, neutral, self-hosted trust layer** for teams that need portable
credentials and exact-action authorization across vendors.

## Where Entra Agent ID is strong today

- Deep Entra/Conditional Access integration, familiar lifecycle and access reviews.
- Dataverse role binding per environment; Defender/Purview threat and compliance signals.
- Partner integrations and enterprise procurement motion.

Entra remains a good choice for HR-driven lifecycle and M365 DLP depth. AuthraGen
interoperates there (federate via OIDC on the roadmap; wrap Copilot Studio/Foundry
agents with `adapters/mcp.js` / `a2a.js`) rather than replacing on day one.

## Where a neutral layer helps

1. **Portability.** `did:authragen` Ed25519 passports verify offline with the org
   pubkey. No tenant required; useful for local models, edge devices and multi-cloud
   fleets. Credentials matter when relying parties choose to accept them.
2. **Adoption cost.** `POST /v1/orgs` → `POST /v1/passports` (CSR) →
   `POST /v1/authorize` — minutes for a pilot. No licensing prerequisite.
3. **Least privilege by attenuation.** Client-signed delegation chains narrow
   scope/spend/expiry/depth/targets monotonically; authority confusion rejected
   (`parent.sub === delegator`). Complements JIT scoped tokens.
4. **Exact-action binding.** The signed intent hash (action + canonical resource +
   exact params + amount + destination + tool + audience + nonce + window) is
   re-checked at execute; post-approval swaps fail.
5. **Accountability.** Hash-chained receipts + signed checkpoints + optional external
   anchoring (`AUTHRA_ANCHOR_URL`). Tamper-evident (not “immutable”); portable across clouds.
6. **Offline story.** Authenticity offline via org pubkey; freshness via polled
   revocation feed/checkpoints for air-gapped and on-prem agents.
7. **Cost/scale.** Self-hosted gateway with explicit runtime dependencies; stateless envelope verification;
   Postgres and Redis adapters are available for durable external state; authoritative reads remain mirror-backed.

## AuthraGen moves (what it actually implements)

| # | Capability | AuthraGen answer |
|---|---|---|
| 1 | Portable identity | `did:authragen` Ed25519 passport, offline-verifiable |
| 2 | Fast pilot | org → CSR passport → signed intents |
| 3 | Least privilege | Attenuation lattice on every delegation |
| 4 | Risk per call | Deterministic 0–100 + factors; auto/step-up/deny (triage, not safety) |
| 5 | Accountability | Hash-chained receipts + checkpoints + anchor hook |
| 6 | Kill-switch | One `POST /v1/revoke` cascades; short TTLs; versioned feed |
| 7 | Interop | MCP + A2A + n8n + raw HTTP; OpenAI/Anthropic/Gemini adapters, one flow |
| 8 | Hosting | Self-host; JSON-file dev adapter, Postgres path documented |

## Migration path (federate, wrap, export, scale out)

1. **Federate, don't rip:** bind `did:authragen` ↔ Entra workload identity via OIDC
   (roadmap). Keep Conditional Access AND get portable passports.
2. **Wrap, don't rewrite:** put `adapters/mcp.js` / `a2a.js` in front of existing agents.
   Policy + receipts appear immediately.
3. **Export the truth:** mirror audit events as AuthraGen receipts for cross-cloud compliance.
4. **Scale out:** move hot-path verify to edge; keep existing directories for joiner/leaver.

## Honest gaps (v2/vNext)

KMS/HSM storage is an interface with a file default (dev-only, not certified);
transparency-log anchoring is a webhook hook (bring Rekor/timestamp service);
OIDC federation and formal interop certs remain roadmap. Short TTLs and polling
are the price of offline freshness. Risk is a heuristic, not an AI safety guarantee.
