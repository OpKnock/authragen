# AuthraGen Protocol v2/vNext (normative)

Status: v2/vNext reference. Reimplementable with Ed25519 + SHA-256 + JSON + scrypt.
Transports: HTTP/JSON. Bindings: MCP, A2A, n8n, raw HTTP, in-process SDK.

AuthraGen is a **private, vendor-neutral trust system**. Credentials become useful when
relying parties choose to verify/accept them. There is no global registry, no official
status and no universal trust.

## 0. Honest scope

- Risk scores are triage heuristics, not safety judgments.
- The audit chain is tamper-evident; protection against full rewrites comes from
  EXTERNAL checkpoints/anchors, not from the file itself. Never called “immutable”.
- “Offline verify” means envelope authenticity needs only the org pubkey.
  Revocation freshness always needs a fresh feed (`GET /v1/revoked`) or checkpoint.
- Verification is stateless/edge-friendly for authenticity; revocation and policy state
  stay centrally authoritative.
- Process-local mutexes are insufficient for distributed production; use Postgres
  transactions or Redis atomic primitives (same record shapes).

## 1. Authentication & RBAC

- First org creation requires the one-time bootstrap token (server stdout +
  `data/bootstrap.token`, 0600, deleted after first org). Rate-limited (5/min).
- Org API keys `ak_<id>.<secret>` (secret = scrypt hash server-side, shown once at
  mint/rotate, never returned again). Roles: `admin > approver > executor > reporter`,
  org-scoped, expirable (`expires_at`, default 12h session), rotatable, revocable
  (`POST /v1/revoke {type:"apikey"}` + revocation feed).
- Matrix: orgs/keys/passports-issue/rotate/status/blueprints/policies-write/revoke/
  checkpoint/lock = `admin`; approvals-decide = `approver+`; authorize (service path)/
  delegate-register = `executor+`; reads = `reporter+`; `/pubkey`, `/verify` = open
  (rate-limited). Every object lookup is org-scoped; cross-org access returns generic
  `forbidden` without leaking existence. Errors use 400/401/403/404/409/410/429/500
  with `{error, message, request_id}` (no internals in production).
- Transport: `Authorization: Bearer` headers only (never URL/query credentials;
  POST `/v1/verify` preferred over legacy GET). Rate limits, body limits (default
  256KB), request/correlation IDs (`X-Request-Id`), security headers, configurable CORS
  (`AUTHRA_CORS`), HTTPS/proxy awareness (`AUTHRA_TRUST_PROXY`), strict validation.

## 2. Identifiers, DIDs & hierarchy

- Hierarchy: Organization → Agent Blueprint → Agent Instance → Delegated Sub-Agent →
  Session/Action. Runtime replicas do not require permanent identities.
- `org_*`, `agt_*` (passports), `bp_*` (blueprints), `tkn_*` (delegation),
  `att_*` (action), `pol_*`, `apr_*`, `ak_*`, `rcpt_*`, `rq_*` (requests).
  Collision-resistant (`crypto.randomBytes`), semantics documented in code.
- DID: `did:authragen:<base64url(full 32-byte Ed25519 pubkey)>` (43 chars,
  collision-resistant). Resolution: passport lookup by exact DID (legacy 16-char
  prefixes resolve best-effort). DID is a protocol feature with key-history
  (`kid` + grace + revocation) semantics, not a truncated label.
- Agent records carry ownership: technical owner, business sponsor, team, environment,
  purpose, model/provider, runtime/framework, created/last-seen timestamps, status.
- Lifecycle: `draft, pending_approval, active, suspended, quarantined, rotating,
  expired, revoked`. Suspend/quarantine are reversible holds (fail-closed); revoked is
  terminal. Rotation uses explicit `kid`s with validity windows (`since/until` + grace).
- Issuance is an admin act. Knowing an org ID is never sufficient. Organization-issued
  identities and cryptographically authorized agent-to-agent delegation are distinct flows.

## 3. Custody & KMS

- Agents generate keys locally and submit CSRs (`POST /v1/passports {pubkey}`).
  The ORG ROOT attests the binding. The gateway never sees agent privkeys.
- Org roots + checkpoint key live in the `Signer` abstraction (file default =
  **explicitly development-only**, `AUTHRA_KMS` selects `aws|gcp|vault|azure`).
  Production belongs in KMS/HSM; file keys warn on every boot.
- `AUTHRA_ALLOW_CUSTODY=1` permits server-custodied dev keys, flagged
  `custody:"server"` in passports and receipts with prominent warnings.
- Private keys, bootstrap secrets, API secrets and raw envelopes never appear in GET
  responses, logs, audit entries, errors or dashboard output.

## 4. Passports

```
{ v:2, id, did, org_id, parent_id|null, kind, name, custody,
  blueprint_id|null, owner, sponsor, team, environment, purpose,
  model, provider, runtime, framework, created_at, last_seen,
  keys:{ current:{kid, pubkey, since}, history:[{kid, pubkey, since, until, revoked?}] },
  grace_period_s (default 300), parent_sig|null, status, iat, exp, revoked, metadata,
  signature (org-root over doc excluding last_seen) }
```

- Subagent requires existing, live parent in same org; child exp clamped to parent.
- Rotation appends history with `until = now+grace`; verification accepts `kid` =
  current, or history while `now < until` (flagged grace); unknown/revoked/expired kids
  fail closed. Tokens/intents carry `kid` where relevant.
- `last_seen` is telemetry excluded from the signature; all other fields are covered.
- Revocation cascade is deterministic: org lock → all fail closed; blueprint revoke →
  member agents fail closed; passport revoke → sub-agents + descendant tokens fail closed.

## 5. Delegation (client-built, server-registered)

Payload `{v:2, jti, org_id, sub, parent_jti, scope, resources, constraints, kid, iat}`,
sealed (AR1 `EdDSA`) by the DELEGATOR key. Registration checks, in order:

- Signature valid under delegator's (kid-aware) pubkey; envelope == payload.
  Wrong-delegator and forged-parent signatures rejected.
- AUTHORITY: with parent → `parent.sub === delegator_id`, else `delegation_not_authorized`;
  without parent → `payload.sub === delegator_id` or caller is org admin (recorded).
  Cross-org (`payload.org_id !== parent.org_id`) rejected.
- ATTENUATION (monotone, verified over the whole chain): scope ⊆ parent (glob),
  resources ⊆ parent, `allowed_targets` ⊆ parent, spend ≤ parent (increase forbidden),
  `not_after` ≤ parent (extension forbidden; defaults clamp), `max_depth` ≤ parent,
  depth+1 ≤ max, approval requirements can only be added. Cycle detection included.
- Stored with `issuer, subject, parent_jti, depth, parent linkage`.
- `tokenCovers(action, resource)` = scope ✓ AND resources ✓ AND
  (`allowed_targets` empty OR glob-match) — enforced on authorize AND execute.
- Delegation after parent revocation/expiration rejected.

## 6. Intents (exact-action binding)

```
{v:2, passport_id, org_id, action, resource, params, amount_cents,
 destination, tool, nonce (≥16 chars, [A-Za-z0-9:_-./]), iat, exp (≤120s default,
 configurable via AUTHRA_INTENT_TTL_S), aud}
```

- Strict validation + canonicalization: NFC normalization, control/zero-width/bidi
  rejection, no numeric coercion (amount must be safe integer; params typed), no
  NaN/Infinity, params ≤16KB with key/value limits, resource path/URL normalization
  (no `..`, no backslashes, collapsed slashes), duplicate-JSON-key rejection at the
  HTTP layer, clock-skew window (`AUTHRA_CLOCK_SKEW_S`, default 30s).
- `intent_hash = sha256(canonical(intent))`. Agent signs canonical intent;
  gateway verifies with passport (kid-aware) key. Service-key path allowed for
  trusted middleware and recorded as `authn:service_key:<id>`.
- Policy, risk and budget use ONLY intent fields. Bare `context` is untrusted signal;
  unexpected security fields there are ignored + logged (`untrusted-context-ignored`).
- Audience (`aud`) binds the credential to one service/tool/org
  (e.g. `mcp:payments-svc`). `att.aud` must equal `intent.aud`; mismatches fail.
  TTLs configurable (`AUTHRA_INTENT_TTL_S`, `AUTHRA_ACTION_TTL_S`,
  `AUTHRA_APPROVAL_TTL_S`); fail-closed on expiry.

## 7. Authorize (prepared) → Execute (executed)

`authorize` returns `allow + action_token` (org-sealed, single-use, aud-bound,
carrying `token_jti`), `step_up + approval_id` (quorum-aware), `deny`, or `dry_run`
(preflight with `would: ALLOW/STEP-UP/DENY` and no credential) — every branch appends
a receipt with `request_id`, `policy_id/hash/version`, `risk + version`.
`execute{action_token, intent, approval?}` under a mutex (single-process; distributed
needs DB/Redis transactions):

- E1 token authentic (org key, `EdDSA/AR1` only — alg confusion rejected),
  `v/jti/kid/issuer/sub/aud/iat/exp/intent_hash` present, issuer is gateway,
  kind/exp/org/sub/aud match.
- E2 recomputed `intent_hash` == token's; action/resource/amount/destination/params
  (via hash) equal. Post-approval swaps fail.
- E3 if `requires_approval`: approval credential (org-sealed, `approved`,
  same hash, same `action_jti` when present, same aud, live) required.
- E4 live passport + delegation chain + budget availability + org not locked.
- E5 consume nonce + token jti from the persistent store (replay → `replay` + deny receipt).
- E6 ATOMIC sync check-and-set debit; append `executed` receipt with intent hash,
  policy version/hash, action jti, approval identity, executor path, timestamps.
Reads may skip execute; side effects MUST go through it.

## 8. Approvals

`POST /v1/approvals/:id {approve, by?}` (approver+, Bearer-required, CSRF-safe: no
cookie auth). Recorded identity is always the authenticated key (`id + role + key id`
+ timestamp + decision + reason-note + credential `kid`); free-form `by` is only a
human note. On quorum (`condition.min_approvals`, default 1) distinct approvals the
gateway mints a signed approval credential + deferred action token, both bound to the
stored `intent_hash` (+ `action_jti`) and audience, expiring (`AUTHRA_APPROVAL_TTL_S`).
Altered post-approval requests fail E2/E3. Approvals cannot transfer between requests.

## 9. Revocation & freshness

`revoke{org|blueprint|passport|key|token|action|apikey}` cascades (children fail closed),
is sequence-numbered (`seq`) and org-scoped. Suspension/quarantine are reversible;
revoke is terminal. Key revocation names an explicit `kid` with validity windows.
Executors poll `GET /v1/revoked?since&since_seq`; stateless verification is explicitly
authenticity-without-freshness until polled. Online vs offline (cached) status is
documented on every verify response.

## 10. Audit & checkpoints

O(1) append via `audit_state.json {count, head}` with atomic rename; `verify` replays
(detects tampering, deletion, insertion, reordering). Per-org streams
(`GET /v1/audit?org_id`, `export` as JSON/JSONL, `evidence` as signed bundles with
`bundle_hash`). Every receipt carries `request_id`, `policy_id/hash/version`, `risk +
version`, `intent_hash`, `action_jti`, approval/executor identities and timestamps.
Secrets/envelopes are redacted (jti + hash only). `POST /v1/audit/checkpoint` signs
`{count, head, prev}` with the gateway key; `AUTHRA_ANCHOR_URL` receives each checkpoint
(transparency-log/timestamp hook, optional production feature). Verify checkpoints
against the gateway pubkey (`GET /v1/audit/checkpoints`).

## 11. Risk providers

`registerRiskProvider(name, fn)` adds `{add, factor}` signals to the deterministic,
explainable base heuristic (0–100 + factors + band + version). Providers are labelled;
none is trusted as a safety oracle. Hard policy denies can never be bypassed by low
risk; the risk ceiling (`AUTHRA_RISK_CEILING`, per-org overridable) only adds denials.
Organization thresholds (`risk_stepup`, `risk_ceiling`) tune auto/step-up/deny.

## 12. Offline verification

Pure offline library (`verifyOffline` in SDK + `intent.js`): validates signatures,
structure, issuer, audience, expiry, key-id presence and intent binding without the
control plane. Returns `{signature_valid, credential_valid, expiry_valid,
revocation_freshness, payload, error}`. A revocation feed/checkpoint makes freshness
`fresh/revoked`; otherwise `unknown`. Documented as such.

## 13. Errors

`unauthorized | forbidden | bad_request | bad_intent | intent_expired | sig_invalid |
unknown_kid | key_revoked | key_expired | passport_unknown | passport_expired |
passport_revoked | passport_suspended | passport_quarantined | token_unknown |
token_expired | token_revoked | token_mismatch | token_malformed | scope_insufficient |
budget_exceeded | depth_exceeded | attenuation_violation | delegation_not_authorized |
policy_deny | approval_required | approval_expired | approval_resolved | intent_mismatch |
replay | custody_forbidden | kms_unconfigured | org_locked | org_unknown | rate_limited |
quota_exceeded | not_found | storage_error`.
