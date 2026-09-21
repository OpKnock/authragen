# AuthraGen — Vendor-Neutral Agent Identity, Authorization & Accountability

AuthraGen is a **private, self-hosted, vendor-neutral trust layer** for autonomous agents.
It issues portable, cryptographically verifiable agent credentials and enforces
**exact-action authorization**: an agent can only execute the precise operation that was
authorized, with least-privilege delegation, single-use execution and independently
verifiable receipts.

Credentials are useful **when relying parties choose to verify and accept them**.
AuthraGen is not a global registry, not an official standard and not universally trusted.
It is a control plane you run for your own agents and services.

Works across OpenAI, Anthropic, Gemini, local models, MCP, A2A, n8n and custom runtimes.
No cloud lock-in; no tenant required.

Core invariant: **an agent can only execute the exact authority that was cryptographically
granted to it, and nobody can silently increase that authority.**

## 60-second mental model

```
Human / Organization
  └─ Org root (KMS-pluggable; file default = dev only) + role keys (admin/approver/executor/reporter)
       └─ Agent Blueprint (reusable security posture, versioned)
            └─ Agent Passport (agent-held Ed25519, did:authragen:<full-key>)
                 └─ Delegation (agent-signed, narrowing-only, registered)
                      └─ Signed Intent ──► Policy + Risk ──► allow / step-up / deny
                           └─ allow/step-up-approved ──► Action Credential (single-use, aud-bound)
                                └─ /v1/execute: hash match + approval match + atomic replay/spend reservation + execute
                                     └─ Receipt (hash-chained, checkpointed, request-id + policy-hash bound)
```

## Quickstart

```bash
cd AuthraGen
node src/server.js   # first boot prints a one-time AUTHRA_BOOTSTRAP token
# open http://localhost:8787/ for the control-plane console
```

```bash
BOOT=$(cat data/bootstrap.token)
curl -s -X POST localhost:8787/v1/orgs -H "x-bootstrap-token: $BOOT" \
  -H 'content-type: application/json' -d '{"name":"acme"}'
# → {id, org_pubkey, admin_key_id, admin_secret}  (secret shown ONCE)
```

JS SDK (self-custody — keys never leave your process):

```js
const { AuthraGen } = require('./sdk-js/authragen');
const admin = new AuthraGen({ baseUrl: 'http://localhost:8787', key: process.env.AUTHRA_ADMIN });

// 1. create blueprint or register agent public key (CSR: YOUR pubkey)
const kp = admin.generateKeypair();                                   // agent key, local only
const agent = await admin.createAgent(org.id, 'shopper', { pubkey: kp.pub });

// 2-4. agent signs exact intent locally, sends to authorize
const me = new AuthraGen({ baseUrl: 'http://localhost:8787' });       // no keys at all
const intent = me.createIntent({ passport_id: agent.id, org_id: org.id,
  action: 'payments.charge', resource: 'stripe:invoice:42', amount_cents: 499 });
const d = await me.authorize(intent, me.signIntent(intent, kp));      // agent-signed
// 5-7. allow → single-use credential → execute exact intent → signed receipt
if (d.decision === 'allow') await me.execute(d.action_token, intent);
// step_up → approver.approve(id) returns approval_credential + action_token → execute(token, intent, {approval})
```

Preferred flow: `createAgent() → createIntent() → signIntent() → authorize() → execute() → delegate()/approve()/revoke()/verifyOffline()`.

## What AuthraGen is / is not

**Current capabilities (implemented in this repository):**
self-custody passports, blueprints, narrowing delegation, exact-intent authorize/execute,
single-use aud-bound credentials, RBAC management APIs, policy engine (deny-wins,
empty-means-nothing), deterministic risk triage, quorum approvals, revocation cascade +
versioned feed, hash-chained receipts + signed checkpoints, offline verifier, MCP/A2A/n8n
adapters, JS + Python SDKs, control-plane dashboard.

**Production deployment requirements:**
Use a real KMS/HSM via `AUTHRA_KMS` and a durable Postgres/Redis backend. Control-plane state,
audit receipts, and checkpoints are persisted through the configured durable backend. The gateway
waits for persistent-store writes before returning successful responses. Postgres/Redis-backed gateways refresh the generic state mirror from the persistent source at each API request boundary, so ordinary control-plane reads do not remain permanently instance-local. Replay and token-spend reservations remain backend-atomic; the request sees a remote-refreshed control-plane state for the duration of that request. Use HTTPS behind a trusted
proxy (`AUTHRA_TRUST_PROXY=1`), exact `AUTHRA_CORS` origins, bounded request bodies, tuned
rate limits and fresh revocation-feed polling for offline verifiers.

**Validation & roadmap:**
The repository includes centralized audit persistence, distributed atomicity tests, two-instance
HTTP validation, and a concurrent load harness. The gated KMS integration workflow exercises
real AWS/GCP/Azure credentials when configured and a real Vault deployment in CI. OIDC federation,
richer external transparency-log integrations, formal interoperability certification, and
post-quantum profiles remain post-v1 work.

**Non-goals:**
No fake global registry claiming authority over all AI agents. Identity alone is not the
product — exact authorization + accountability are. No trust in self-reported context.
No server-side agent private keys by default. No process-local locks for distributed
production. No “immutable” logs (tamper-evident + externally anchored). No AI safety
oracle (risk is a triage heuristic).

## Security model (summary)

- Management APIs: authenticated (`Authorization: Bearer ak_…`), tenant-isolated, RBAC
  (`admin > approver > executor > reporter`) on every endpoint. Bootstrap single-use.
- Custody: agent private keys never stored server-side by default (CSR flow). File org roots
  are **development-only**; production uses KMS/HSM. `AUTHRA_ALLOW_CUSTODY=1` is dev-only
  and flagged `custody:"server"` everywhere.
- Source of truth: the **signed intent** (action + canonical resource + exact params +
  amount + destination + tool + audience + nonce + iat/exp + agent + org). Generic caller
  context is untrusted signal.
- Binding: `intent_hash = sha256(canonical(intent))`. Authorization produces a short-lived
  single-use action credential bound to exactly one hash + audience. Execution re-validates
  passport, signature, key version (`kid` + grace), issuer, audience, hash, action, resource,
  params (via hash), amount, destination (via hash), token chain, approval, expiry, nonce,
  revocation and single-use state. Altered requests fail. Prepared (authorized) vs executed
  are distinct; receipts record both.
- Replay: persistent nonce + action-jti store (file-backed single-instance; Redis/Postgres
  for distributed atomicity). Postgres/Redis also atomically reserve token spend at execute-time;
  remote-backed gateways refresh their control-plane mirror from the persistent source at each
  API request boundary, while file mode remains single-instance.
- Credentials carry `jti, kid, issuer, subject, audience, iat, exp, intent_hash, version`.
  Algorithm confusion rejected (only `EdDSA/AR1` with the org Ed25519 root verifies).
- Revocation cascades deterministically (org → blueprints → passports → sub-agents →
  delegation children → action credentials). Suspension/quarantine are reversible holds.
  Offline verifiers get `signature_valid / credential_valid / expiry_valid /
  revocation_freshness` separately; freshness requires a fresh feed/checkpoint.
- Secrets never appear in GET responses, logs, audit entries, errors or dashboard output
  (envelopes redacted to jti + hash; keys stripped to metadata). Bearer material uses
  `Authorization` headers, never URLs (POST `/v1/verify` preferred).
- Approvals: authenticated approver identity (key id + role), never free-form `by`;
  CSRF-safe (Bearer required, no cookie auth); bound to intent hash (+ action jti);
  expiring; optional quorum (`min_approvals`) for two-person rules.
- Transport: rate limits, body limits (default 256KB), request/correlation IDs, security
  headers, configurable CORS, HTTPS/proxy awareness, strict schema validation +
  canonicalization (NFC, no coercion, no NaN/Infinity, no traversal, duplicate-key rejection),
  structured `{error, message, request_id}` errors with correct 400/401/403/404/409/410/429/500.

Threat model (abridged): defends against forged intents, wrong-key/kid use, rotated-key
abuse, expired/revoked credential use, revoked-parent delegation, scope/resource/target/
budget/expiry/depth widening, cross-org chains, approval replay/substitution, intent/amount/
destination tampering, normalization attacks, nonce/action-token replay (incl. concurrent
and distributed when backed correctly), policy conflicts/empty-grants, malformed/alg-confused
credentials, audience/issuer mismatch, clock-skew abuse, oversized/rate abuse, dashboard XSS,
log/secret leakage, audit tampering/deletion/reordering (detected; full rewrites need external
anchors), stale offline revocation. See PROTOCOL.md for the normative details.

## API surface

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /v1/orgs` | bootstrap token | Create org → admin secret (once) |
| `GET /v1/orgs/:id` | reporter+ | Org details, risk thresholds, lock state |
| `POST /v1/orgs/:id/lock` / `unlock` | admin | Emergency fail-closed lock |
| `PUT /v1/orgs/:id/risk` | admin | Org risk thresholds |
| `POST /v1/orgs/:id/keys` | admin | Mint role keys (secret once) |
| `POST /v1/orgs/:id/keys/rotate` | admin | Rotate service key (old revoked) |
| `GET /v1/orgs/:id/pubkey` | open | Trust-root distribution (offline verify) |
| `POST /v1/blueprints` / `GET /v1/blueprints` | admin / reporter+ | Templates with versions + instance counts |
| `POST /v1/passports` | admin | Issue via CSR pubkey (`custodied:true` = dev only) |
| `GET /v1/passports?org_id&…` | reporter+ | Fleet search/filter/pagination |
| `POST /v1/passports/rotate` | admin | Rotate with history + grace (`kid`) |
| `POST /v1/passports/:id/status` | admin | `active/suspended/quarantined/revoked` |
| `POST /v1/passports/:id/keys/revoke` | admin | Revoke explicit `kid` |
| `POST /v1/delegate` | executor+ (+delegator sig) | Register client-signed narrowing delegation |
| `GET /v1/delegations?org_id` | reporter+ | Delegation chains |
| `POST /v1/policies` / `PUT /v1/policies/:id` | admin | Versioned policies with hashes |
| `POST /v1/policies/simulate` | reporter+ | Dry-run evaluation (no credential) |
| `GET /v1/policies/conflicts?org_id` | reporter+ | Conflict detection |
| `POST /v1/authorize` | agent-signed intent or executor | Decision only (+ `dry_run:true` preflight) |
| `POST /v1/execute` | action token + intent (+approval) | ONLY effectful call: match, consume, debit, receipt |
| `GET /v1/approvals?org_id&status` | reporter+ | Pending + exact request preview |
| `POST /v1/approvals/:id` | approver | Approve/deny → signed credential bound to hash (+ quorum) |
| `POST /v1/revoke` | admin | Revoke org/blueprint/passport/key/token/action/apikey (cascade, seq) |
| `GET /v1/revoked?org_id&since&since_seq` | reporter+ | Versioned freshness feed |
| `POST /v1/verify` (`GET` legacy) | open (rate-limited) | Stateless check + separate validity fields |
| `GET /v1/audit?org_id` / `verify` / `export` | reporter+ | Receipts / chain verify / JSONL export |
| `POST /v1/audit/evidence` | reporter+ | Signed evidence bundle |
| `POST /v1/audit/checkpoint` | admin | Signed checkpoint (+ `AUTHRA_ANCHOR_URL` hook) |

## Repo layout

```
AuthraGen/
  README.md / PROTOCOL.md / COMPARISON.md / CHANGELOG.md
  src/ server.js auth.js signer.js tokens.js intent.js nonce.js
       policy.js risk.js audit.js store.js crypto.js dashboard.html
  sdk-js/authragen.js        sdk_python/authragen.py
  adapters/ openai.js anthropic.js gemini.js mcp.js a2a.js n8n.js
  examples/ demo.js python_demo.py
  test/ run.js               # adversarial end-to-end gateway harness, clean temp-dir state
```

## Interoperability

Protocol is implementation-independent (Ed25519 + SHA-256 + JSON + scrypt).
OAuth/OIDC concepts apply where appropriate (Bearer headers, audience binding,
issuer/subject semantics). MCP uses proper HTTP authorization semantics with
audience/resource binding and server-side verification before tool execution.
A2A task delegation carries explicit issuer/subject/audience/scope/intent binding.
n8n, OpenAI-style, Anthropic-style and Gemini-style adapters all use the same
exact-intent → authorize → single-use execute flow (adapter contract in
`sdk-js/authragen.js`; conformance covered in `test/run.js`).

## Entra Agent ID comparison

See COMPARISON.md for a factual comparison. In short: Microsoft Entra Agent ID and
Agent 365 provide strong identity, Conditional Access, Dataverse roles and audit **inside
Microsoft tenants**, and Microsoft supports third-party agents and open standards
including OAuth, MCP and A2A. AuthraGen is a complementary neutral option: portable
credentials, self-custody, exact-intent authorization with attenuation math, portable
signed receipts, offline-capable verification and self-hosting — useful when relying
parties choose to verify them, without requiring any cloud tenant.

**AuthraGen: passports for agents. Exact authority, provably.**
License: Apache-2.0.
