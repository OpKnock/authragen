# Authentication

## API Keys

### Format

```
ak_<key_id>.<secret>
```

- `key_id`: 16-char identifier
- `secret`: High-entropy secret (shown once; keep it in your secret manager)
- Server stores: `scrypt(secret, N=16384, r=8, p=1)`

### Creation

```bash
curl -X POST localhost:8787/v1/orgs/org_abc/keys \
  -H "Authorization: Bearer ${AUTHRA_ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"role": "executor", "expires_in": "12h", "description": "Payment service"}'
```

**Response (secret shown ONCE):**
```json
{
  "key_id": "${AUTHRA_KEY_ID}",
  "secret": "${AUTHRA_NEW_SECRET}"
  "role": "executor",
  "expires_at": "2024-01-01T12:00:00Z",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Roles

| Role | Permissions |
|------|-------------|
| `admin` | All endpoints, org management, keys, policies, revocation, checkpoints |
| `approver` | Approvals decide, read access |
| `executor` | Authorize (service path), delegate register, read access |
| `reporter` | Read-only access to all list/get endpoints |

### Usage

```bash
# Header (preferred)
Authorization: Bearer ${AUTHRA_EXECUTOR_KEY}

# Query (legacy, rate-limited, not logged)
GET /v1/verify?envelope=...&org_id=...
```

### Rotation

```bash
curl -X POST localhost:8787/v1/orgs/org_abc/keys/rotate \
  -H "Authorization: Bearer ${AUTHRA_ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"key_id": "ak_exec_abc123"}'
```

- Old key immediately revoked
- New key issued with new secret
- `last_used` timestamp tracked

### Expiry & Sessions

- Default TTL: `AUTHRA_SESSION_TTL_MS` (12h = 43200000ms)
- Configurable per-key at creation
- Expired keys → `unauthorized`
- Sessions tracked for audit

## Bootstrap Token

First org creation only:
- Printed to stdout on first server start
- Saved to `data/bootstrap.token` (0600)
- Single-use, rate-limited (5/min)
- Auto-deleted after first successful org creation

```bash
BOOT=$(cat data/bootstrap.token)
curl -X POST localhost:8787/v1/orgs \
  -H "x-bootstrap-token: $BOOT" \
  -d '{"name": "acme"}'
```

## Agent Signatures

For `/v1/authorize` with agent-signed intent:

```javascript
// No API key needed - auth via intent signature
const signature = me.signIntent(intent, agentKeypair);
await me.authorize(intent, signature);
```

- Validates Ed25519 signature against passport
- `kid`-aware (supports rotation grace period)
- Recorded as `authn: "agent_sig"`

## Service Key Path

For trusted internal middleware:

```bash
curl -X POST localhost:8787/v1/authorize \
  -H "Authorization: Bearer ${AUTHRA_EXECUTOR_KEY}" \
  -H "Content-Type: application/json" \
  -d '{ "intent": ... }'
```

- Uses executor+ API key for auth
- Recorded as `authn: "service_key:<key_id>"`
- Still validates intent signature if provided

## CORS

Configure via `AUTHRA_CORS`:
- Default: `*` (all origins)
- Production: Set to specific origins
- Credentials: Not supported (Bearer only)

## Security Headers

Dashboard responses include the following CSP header; JSON API responses expose the transport/security headers configured by the gateway. 
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
```

## Trust Proxy

Behind load balancer/reverse proxy:
```bash
AUTHRA_TRUST_PROXY=1
```
- Reads forwarded client IP/protocol headers only when explicitly enabled
- Use only behind a trusted proxy; otherwise clients can spoof these headers

## Next: [Organizations](/api/organizations)