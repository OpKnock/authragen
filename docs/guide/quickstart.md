# Quickstart

## Prerequisites

- Node.js 18+
- Docker (optional, for containerized deployment)

## 1. Run Locally

```bash
git clone https://github.com/OpKnock/authragen.git
cd authragen
npm ci
node src/server.js
```

First boot prints a one-time bootstrap token:

```
AuthraGen v2.1.0 listening on http://localhost:8787
Bootstrap token: AUTHRA_BOOTSTRAP=bt_abc123...
```

## 2. Create Organization

```bash
BOOT=$(cat data/bootstrap.token)
curl -s -X POST localhost:8787/v1/orgs \
  -H "x-bootstrap-token: $BOOT" \
  -H 'content-type: application/json' \
  -d '{"name":"acme"}'
```

Response (admin secret shown **once**):
```json
{
  "id": "org_abc123",
  "org_pubkey": "base64url...",
  "admin_key_id": "ak_admin_...",
  "admin_secret": "sk_admin_..."  // SAVE THIS - never shown again
}
```

## 3. Open Dashboard

Navigate to http://localhost:8787/ — enter your admin service key to access the control plane.

## 4. Issue Agent Passport (Self-Custody)

```javascript
const { AuthraGen } = require('./sdk-js/authragen');
const admin = new AuthraGen({ baseUrl: 'http://localhost:8787', key: process.env.AUTHRA_ADMIN });

// Agent generates keypair locally (keys never leave this process)
const kp = admin.generateKeypair();

// Register agent with CSR (Certificate Signing Request)
const agent = await admin.createAgent(org.id, 'shopper', { pubkey: kp.pub });
// agent = { id: 'agt_...', did: 'did:authragen:...', custody: 'self', ... }
```

## 5. Authorize & Execute

```javascript
// Agent signs exact intent locally
const me = new AuthraGen({ baseUrl: 'http://localhost:8787' });
const intent = me.createIntent({
  passport_id: agent.id,
  org_id: org.id,
  action: 'payments.charge',
  resource: 'stripe:invoice:42',
  amount_cents: 499
});

const signed = me.signIntent(intent, kp);
const decision = await me.authorize(signed);

if (decision.decision === 'allow') {
  const receipt = await me.execute(decision.action_token, intent);
  console.log('Executed:', receipt);
}
// step_up → approver.approve(id) → execute(token, intent, { approval })
```

## 6. Run Demo

```bash
npm run demo
# or
npm run demo:python
```

## Docker (Production)

```bash
docker-compose up -d
# Service at http://localhost:8787
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8787` | HTTP port |
| `AUTHRA_DATA` | `./data` | Data directory |
| `AUTHRA_CORS` | `*` | CORS origin |
| `AUTHRA_TRUST_PROXY` | `0` | Trust X-Forwarded-* headers |
| `AUTHRA_BODY_LIMIT` | `256kb` | Max request body |
| `AUTHRA_SESSION_TTL_MS` | `43200000` | API key session TTL (12h) |
| `AUTHRA_INTENT_TTL_S` | `120` | Intent TTL (seconds) |
| `AUTHRA_ACTION_TTL_S` | `300` | Action credential TTL |
| `AUTHRA_APPROVAL_TTL_S` | `3600` | Approval credential TTL |
| `AUTHRA_CLOCK_SKEW_S` | `30` | Clock skew tolerance |
| `AUTHRA_RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window |
| `AUTHRA_RATE_LIMIT_MAX` | `100` | Max requests per window |
| `AUTHRA_RISK_CEILING` | `80` | Global risk ceiling |
| `AUTHRA_ALLOW_CUSTODY` | `0` | Allow server-custodied keys (dev only) |
| `AUTHRA_KMS` | - | KMS backend: `aws\|gcp\|vault\|azure` |
| `AUTHRA_ANCHOR_URL` | - | Transparency log anchor webhook |

## Next Steps

- [Core Concepts](/guide/concepts) — Understand the mental model
- [Architecture](/guide/architecture) — System design
- [API Reference](/api/overview) — Complete endpoint docs