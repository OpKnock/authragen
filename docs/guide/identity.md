# Identity & Passports

## DID Format

```
did:authragen:<base64url(32-byte Ed25519 pubkey)>
```

- 43 characters, collision-resistant
- Full public key encoded (not truncated)
- Resolution: passport lookup by exact DID
- Legacy 16-char prefixes: best-effort resolution

## Passport Lifecycle

```
draft → pending_approval → active ↔ suspended/quarantined → revoked
                    │              │
                    └──── rotating ┘
```

| State | Description | Fail-Closed? |
|-------|-------------|--------------|
| `draft` | Created, not yet approved | Yes |
| `pending_approval` | Awaiting admin approval | Yes |
| `active` | Fully operational | No |
| `suspended` | Reversible hold (admin) | Yes |
| `quarantined` | Reversible hold (security) | Yes |
| `rotating` | Key rotation in progress | No (grace) |
| `revoked` | Terminal, cascades to children | Yes |
| `expired` | Past `exp` timestamp | Yes |

## Self-Custody (Default)

```javascript
const { AuthraGen } = require('authragen');
const admin = new AuthraGen({ baseUrl, key: adminKey });

// Agent generates keypair LOCALLY
const kp = admin.generateKeypair(); // { pub, priv }

// Submit CSR - server NEVER sees private key
const agent = await admin.createAgent(orgId, 'my-agent', {
  pubkey: kp.pub,
  blueprint_id: 'bp_...',  // optional
  owner: 'team-platform',
  sponsor: 'jane@acme.com',
  team: 'platform',
  environment: 'production',
  purpose: 'payment-processing',
  model: 'gpt-4',
  provider: 'openai',
  runtime: 'node',
  framework: 'langchain'
});
```

**Passport response includes:**
- `custody: "self"` — confirms self-custody
- `keys.current` — current `kid` + pubkey + since
- `keys.history` — rotation history with validity windows
- `grace_period_s` — default 300s for key rotation overlap

## Server-Custodied Keys (Dev Only)

```bash
AUTHRA_ALLOW_CUSTODY=1 node src/server.js
```

```javascript
const agent = await admin.createAgent(orgId, 'my-agent', {
  custodied: true  // server generates + stores private key
});
```

**Response flags:**
- `custody: "server"` — prominent warning
- Private key in response (shown once)
- **Never use in production**

## Key Rotation

```javascript
// Rotate to new keypair (agent generates locally)
const newKp = admin.generateKeypair();
const rotated = await admin.rotateAgentKey(agent.id, {
  new_pubkey: newKp.pub,
  grace_period_s: 300  // overlap window
});
```

**Rotation mechanics:**
- New `kid` appended to `keys.history` with `since=now`, `until=now+grace`
- Old `kid` gets `until=now+grace`, `revoked=false`
- Verification accepts:
  - `kid` = current → valid
  - `kid` in history while `now < until` → valid (flagged `grace: true`)
  - Unknown/revoked/expired `kid` → **fail closed**
- Tokens/intents carry `kid` where relevant
- Revoke specific `kid`: `POST /v1/passports/:id/keys/revoke { kid }`

## Sub-Agents (Delegation Chain)

```javascript
const child = await admin.createAgent(orgId, 'sub-agent', {
  pubkey: childKp.pub,
  parent_id: parentAgent.id  // must be active, same org
});
```

**Constraints:**
- Child `exp` clamped to parent `exp`
- Parent must be `active` (not suspended/quarantined/revoked)
- Child inherits parent's org, blueprint (optional override)
- Revoking parent cascades to all descendants

## Ownership Metadata

Required for governance/audit:
```javascript
{
  owner: 'team-platform',           // technical owner
  sponsor: 'jane@acme.com',         // business sponsor
  team: 'platform',                 // team identifier
  environment: 'production',        // dev/staging/prod
  purpose: 'payment-processing',    // business purpose
  model: 'gpt-4',                   // model identifier
  provider: 'openai',               // model provider
  runtime: 'node',                  // runtime
  framework: 'langchain'            // agent framework
}
```

## Blueprint-Based Issuance

```javascript
// Create blueprint (admin)
const bp = await admin.createBlueprint(orgId, {
  name: 'payment-agent',
  version: '1.0.0',
  policy: { /* policy config */ },
  risk_stepup: 60,
  risk_ceiling: 80,
  budgets: { daily_usd: 10000 },
  approval_rules: { min_approvals: 2 },
  delegation_constraints: { max_depth: 2, max_spend_cents: 50000 }
});

// Issue passport from blueprint
const agent = await admin.createAgent(orgId, 'shopper-1', {
  pubkey: kp.pub,
  blueprint_id: bp.id
});
// Agent inherits blueprint config, instance count tracked
```

## Passport Operations

| Operation | Endpoint | Auth | Description |
|-----------|----------|------|-------------|
| Create | `POST /v1/passports` | admin | Issue via CSR |
| List | `GET /v1/passports` | reporter+ | Filter: org_id, status, blueprint_id, parent_id |
| Get | `GET /v1/passports/:id` | reporter+ | Full details |
| Rotate | `POST /v1/passports/rotate` | admin | New keypair + grace |
| Status | `POST /v1/passports/:id/status` | admin | active/suspended/quarantined/revoked |
| Revoke Key | `POST /v1/passports/:id/keys/revoke` | admin | Explicit `kid` |

## Dashboard

Control plane UI at `/`:
- Fleet view with filters (status, blueprint, environment)
- Per-agent: keys, rotation history, delegation tree, audit trail
- Key rotation with grace period visualization
- Status changes with confirmations
- **Keys in-memory only** (never localStorage)

## Next: [Authorization Flow](/guide/authorization)