# JavaScript SDK

## Installation

```bash
npm install authragen
# or
yarn add authragen
```

## Quick Start

```javascript
const { AuthraGen } = require('authragen');

// Admin client (with API key)
const admin = new AuthraGen({
  baseUrl: 'http://localhost:8787',
  key: process.env.AUTHRA_ADMIN_KEY
});

// Agent client (no keys - for verify/execute only)
const agent = new AuthraGen({
  baseUrl: 'http://localhost:8787'
});
```

## Core Methods

### `generateKeypair()`

Generates Ed25519 keypair locally (keys never leave process).

```javascript
const kp = admin.generateKeypair();
// { pub: 'base64url...', x: 'base64url...', d: 'base64url...' }
```

### `createAgent(orgId, name, options)`

```javascript
const agent = await admin.createAgent('org_abc', 'shopper', {
  pubkey: kp.pub,              // Required: agent's public key (CSR)
  blueprint_id: 'bp_...',      // Optional: blueprint to inherit
  owner: 'team-platform',
  sponsor: 'jane@acme.com',
  team: 'platform',
  environment: 'production',
  purpose: 'payment-processing',
  model: 'gpt-4',
  provider: 'openai',
  runtime: 'node',
  framework: 'langchain',
  custodied: false             // Default: false (self-custody)
});
```

### `createIntent(params)`

```javascript
const intent = agent.createIntent({
  passport_id: 'agt_abc',
  org_id: 'org_xyz',
  action: 'payments.charge',
  resource: 'stripe:invoice:inv_42',
  params: { customer: 'cus_123' },
  amount_cents: 499,
  destination: 'acct_merchant',
  tool: 'stripe',
  aud: 'mcp:payments-svc'      // Recommended
  // nonce: auto-generated
  // iat/exp: auto (exp = now + 120s)
});
```

### `signIntent(intent, keypair)`

```javascript
const signature = agent.signIntent(intent, agentKeypair);
// returns the base64url Ed25519 signature string
```

### `authorize(intent, intentSig, options?)`

```javascript
const decision = await agent.authorize(intent, signature);
// or with dry-run:
const preview = await agent.authorize(signedIntent, { dry_run: true });

// Response:
{
  decision: 'allow' | 'step_up' | 'deny' | 'dry_run',
  action_token: 'AR1.eyJ...',   // if allow
  action_jti: 'att_...',
  approval_id: 'apr_...',        // if step_up
  risk: { score: 15, factors: [], band: 'low', version: 2 },
  request_id: 'rq_...',
  policy_id: 'pol_...',
  policy_hash: 'sha256...',
  policy_version: 3
}
```

### `execute(actionToken, intent, options?)`

```javascript
const receipt = await agent.execute(actionToken, intent, {
  approval: approvalCredential  // if step_up
});

// Response:
{
  id: 'rcpt_...',
  type: 'executed',
  request_id: 'rq_...',
  intent_hash: 'sha256...',
  action_jti: 'att_...',
  approval_jti: 'apr_...',
  executor: { authn: 'agent_sig', key_id: 'kid_1' },
  policy_id: 'pol_...',
  policy_hash: 'sha256...',
  policy_version: 3,
  risk: { score: 15, factors: [], band: 'low', version: 2 },
  timestamp: '2024-01-01T00:00:00.000Z'
}
```

### `delegate(delegation, keypair)`

```javascript
const delegation = {
  v: 2,
  jti: 'tkn_...',
  org_id: 'org_xyz',
  sub: 'agt_child',
  parent_jti: 'tkn_parent',  // or null for root
  scope: ['payments.charge'],
  resources: ['stripe:invoice:*'],
  constraints: {
    max_spend_cents: 10000,
    not_after: '2024-12-31T23:59:59Z',
    max_depth: 1
  },
  kid: 'kid_1',
  iat: new Date().toISOString()
};

const signed = agent.signDelegation(delegation, delegatorKeypair);
await agent.registerDelegation(signed);
```

### `approve(approvalId, decision)`

```javascript
const result = await admin.approve('apr_abc123', true, 'Authorized by finance lead');

// If quorum met:
{
  approval_credential: 'AR1.eyJ...',
  action_token: 'AR1.eyJ...',
  approval_id: 'apr_...'
}
```

### `revoke(params)`

```javascript
await admin.revoke('passport', 'agt_abc', 'Decommissioned');
// key revocation: await admin.revoke('key', 'agt_abc', 'Compromised', { kid: 'kid_2' })
```

### `verifyOffline(envelope, orgPubkey)`

**Static method - no network required:**

```javascript
const result = AuthraGen.verifyOffline(envelope, orgPubkey);
// or instance method:
const result = await agent.verifyOffline(envelope, orgId);

// Response:
{
  signature_valid: true,
  credential_valid: true,
  expiry_valid: true,
  revocation_freshness: 'fresh' | 'revoked' | 'unknown',
  payload: { ... },  // decoded credential
  error: null
}
```

## Additional Methods

### `dryRun(signedIntent)` — Alias for `authorize(..., { dry_run: true })`

### `simulatePolicy(params)` — Policy simulation

```javascript
const preview = await admin.simulatePolicy({
  org_id: 'org_xyz',
  passport_id: 'agt_abc',
  intent: { action: 'payments.charge', amount_cents: 5000 },
  delegation_chain: [...]
});
```

### `listPassports(filters)`

```javascript
const agents = await admin.listPassports({
  org_id: 'org_xyz',
  status: 'active',
  blueprint_id: 'bp_...',
  parent_id: 'agt_...',
  limit: 50,
  offset: 0
});
```

### `listDelegations(filters)`

```javascript
const delegations = await admin.listDelegations({
  org_id: 'org_xyz',
  delegator_id: 'agt_...',
  subject_id: 'agt_...',
  limit: 50
});
```

### `getDelegationChain(passportId)`

```javascript
const chain = await admin.getDelegationChain('agt_child');
// [{ token, delegator, parent, depth, valid }, ...]
```

### `listApprovals(filters)`

```javascript
const approvals = await admin.listApprovals({
  org_id: 'org_xyz',
  status: 'pending',
  since: '2024-01-01T00:00:00Z'
});
```

### `getRevoked(filters)`

```javascript
const feed = await admin.getRevoked({
  org_id: 'org_xyz',
  since_seq: 100
});
```

### `getAudit(filters)`

```javascript
const receipts = await admin.getAudit({
  org_id: 'org_xyz',
  since: '2024-01-01T00:00:00Z',
  type: 'executed',
  passport_id: 'agt_...'
});
```

### `exportAudit(filters)`

```javascript
const stream = await admin.exportAudit({
  org_id: 'org_xyz',
  format: 'jsonl'  // or 'json'
});
// Returns ReadableStream
```

### `createEvidenceBundle(params)`

```javascript
const bundle = await admin.createEvidenceBundle({
  org_id: 'org_xyz',
  receipt_ids: ['rcpt_1', 'rcpt_2'],
  include_checkpoints: true
});
```

### `createCheckpoint()`

```javascript
const cp = await admin.createCheckpoint();
// { count, head, prev, timestamp, signature }
```

## Error Handling

```javascript
try {
  await agent.execute(token, intent);
} catch (err) {
  if (err.code === 'replay') {
    // Nonce or token already used
  } else if (err.code === 'token_mismatch') {
    // Intent hash mismatch
  } else if (err.code === 'passport_revoked') {
    // Passport revoked
  }
  // All errors have: code, message, request_id
}
```

## TypeScript

Full TypeScript definitions included:

```typescript
import { AuthraGen, Intent, Decision, Receipt, Passport } from 'authragen';

const agent: AuthraGen = new AuthraGen({ baseUrl });
const intent: Intent = agent.createIntent({ ... });
const decision: Decision = await agent.authorize(signed);
```

## Next: [Python SDK](/sdk/python)