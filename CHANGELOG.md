# CHANGELOG — AuthraGen v2/vNext security hardening

## v2.1.0 (2026-09-16) — production-oriented vNext

Coherent v2/vNext implementation preserving working v2 behavior while fixing
security-correctness issues. Backwards compatible where safe; fail-closed where not.

### Critical fixes

- **Policy empty arrays now match nothing** (was: match everything). Explicit `*`
  is the only match-all. Fail-closed default-deny restored.
- **Intent canonicalization hardened:** NFC normalization, control/zero-width/bidi
  rejection, no numeric coercion, no NaN/Infinity, params size/key limits, resource
  path/URL normalization (no `..`, collapsed slashes), duplicate-JSON-key rejection,
  clock-skew window, configurable TTLs (`AUTHRA_INTENT_TTL_S`, `AUTHRA_ACTION_TTL_S`,
  `AUTHRA_APPROVAL_TTL_S`, `AUTHRA_CLOCK_SKEW_S`).
- **Passport signatures cover lifecycle/ownership fields;** `last_seen` telemetry
  excluded (was: signature breakage on every authorize). Revoke paths re-sign.
- **Envelope algorithm-confusion defense:** only `EdDSA/AR1` with the org Ed25519 root
  verifies; `alg:none`/foreign algs rejected.
- **Audience binding end-to-end:** intents, action credentials and approvals carry
  `aud`; execute and offline verify enforce equality (no cross-service replay).
- **Credential shape enforced:** `v/jti/kid/issuer/sub/aud/iat/exp/intent_hash`
  checked on every verifiable credential (protocol v2).

### Auth, transport & API

- Request/correlation IDs on every response + receipt; structured
  `{error, message, request_id}` errors with 400/401/403/404/409/410/429/500.
- Rate limiting per route/IP (bootstrap 5/min, authorize/execute/verify capped),
  256KB body limits (413, no socket-kill), security headers, configurable CORS
  (`AUTHRA_CORS`), HTTPS/proxy awareness (`AUTHRA_TRUST_PROXY`), tenant-isolated
  lookups with generic cross-org `forbidden`.
- Bearer credentials via `Authorization` headers only; POST `/v1/verify` preferred
  (GET legacy kept rate-limited, never logged). Oversized/duplicate-key bodies rejected.
- Service keys: expiry/session timeout (`AUTHRA_SESSION_TTL_MS`, 12h), rotation
  (`…/keys/rotate`, old revoked), `last_used` tracking; secrets shown once, stripped on GET.
- Approvals: authenticated approver identity (key id + role), Bearer-required
  (CSRF-safe), `by` treated as note only, intent-hash + action-jti binding, expiry,
  quorum/two-person (`min_approvals`, distinct approvers).
- Emergency org lock (`…/lock`/`unlock`, unlock bypasses fail-closed gate), per-org risk
  thresholds, quotas, paginated fleet/delegation/approval/audit listings.

### Identity, delegation, policy, risk

- Blueprints (versioned templates + instance counts); ownership metadata
  (owner/sponsor/team/env/purpose/model/provider/runtime/framework); lifecycle
  (`draft/pending_approval/active/suspended/quarantined/rotating/expired/revoked`)
  with reversible holds; explicit `kid` validity windows + revocation.
- Delegation: full-chain validation, forged-parent/wrong-signer rejection,
  monotone attenuation (scope/resources/targets shrink; spend/expiry/depth never grow;
  approvals only added), cross-org/cycle/revoked-parent rejection.
- Policy: IDs/versions/hashes (`policyHash`), `updated_at`, rich conditions
  (spend/depth/env/blueprint/agent/audience/tool/time), deny-wins, explicit step-up +
  quorum, conflict detection (`GET …/conflicts`), simulation/test
  (`POST …/simulate`, `dry_run:true` preflight with no credential).
- Risk stays deterministic/explainable (score + factors + version in receipts);
  hard denies never bypassed by low risk; ceiling only adds denials.

### Accountability & offline

- Hash-chained receipts (O(1) append, atomic rename) with redaction (no secrets or
  raw envelopes); per-org streams, JSONL export, signed evidence bundles.
- Signed checkpoints + `AUTHRA_ANCHOR_URL` hook (tamper-evident, not “immutable”).
- Revocation feed sequence-numbered (`seq`, `since_seq`, org-scoped) with
  online-vs-offline freshness documentation.
- Offline verifier returns `signature_valid/credential_valid/expiry_valid/
  revocation_freshness` separately (SDK + server + POST verify).

### Storage & scale

- Storage abstraction (`store.list`, atomic file writes, `reload()`); JSON-file kept as
  dev/test adapter; Postgres/Redis paths documented with required transactions,
  indexes and atomic primitives. Nonce store file-persistent (single-instance) with
  Redis hook documented for distributed atomicity. `store.backend()` surfaced on health.

### Dashboard, SDKs, adapters

- Dashboard rebuilt as control-plane UI (Overview/Agents/Blueprints/Policies/
  Delegations/Approvals/Activity/Audit/Keys/Settings + Demo): in-memory keys only
  (no localStorage), `textContent`-only rendering (no `innerHTML` with untrusted data),
  CSP (header + meta), custody warnings, tenant display, confirmations for dangerous
  controls, “Why allowed/blocked?”, exact-intent previews, policy hashes, request IDs.
- SDKs: `createAgent/createIntent/signIntent/authorize/execute/delegate/approve/
  revoke/verifyOffline` (+ `dryRun`, `simulatePolicy`, blueprints, lifecycle helpers);
  offline verify with separate validity fields. Adapters (OpenAI/Anthropic/Gemini/MCP/
  A2A/n8n) audited to the exact-intent → authorize → single-use execute contract with
  audience/resource binding and header auth; no legacy positional flows remain.

### Tests & hygiene

- `test/run.js` now spawns an isolated gateway in a clean temp `AUTHRA_DATA`
  (no repo state required) and asserts **104 checks**: unauthenticated/cross-tenant/
  priv-esc, forged/wrong/unknown/rotated/revoked keys, expired/revoked/suspended/
  quarantined/locked credentials, revoked parents/tokens/blueprints, all widening
  classes, cross-org chains, approval replay/substitution, param/amount/destination
  tampering, normalization attacks, nonce/action-token replay (incl. concurrent spend
  race), policy conflicts/empty grants, malformed/alg-confused credentials,
  audience/issuer mismatch, clock skew, oversized/rate-limit, XSS-safe dashboard,
  log/secret leakage, CORS/headers, audit tampering, checkpoint/evidence, offline
  freshness and adapter conformance.
- Removed `data/*` runtime state, `data.bak.*`, keys, bootstrap secrets, API-key state,
  `__pycache__`, logs and temp files (`.gitkeep` kept). `.gitignore` now covers secrets,
  runtime state, logs, caches, builds and env files.
- README/PROTOCOL rewritten to match implementation (prototype vs production vs roadmap
  vs non-goals separated; no “globally recognized/official/immutable/stateless/
  universally trusted” claims; private trust-system framing; threat model; interop
  guidance; factual Entra comparison acknowledging Microsoft’s third-party and
  OAuth/MCP/A2A support).
