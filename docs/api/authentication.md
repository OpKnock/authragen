# Authentication

## API Keys

### Format

```
ak_<key_id>.<secret>
```

- `key_id`: 16-char identifier
- `secret`: High-entropy secret (shown once)
- Server stores: `scrypt(secret, N=16384, r=8, p=1)`

### Creation

```bash
curl -X POST localhost:8787/v1/orgs/org_abc/keys \
  -H "Authorization: Bearer ak_admin_..." \
  -H "Content-Type: application/json" \
  -d '{"role": "executor", "expires_in": "12h", "description": "Payment service"}'
```

**Response (secret shown ONCE):**
```json
{
  "key_id": "ak_exec_abc123",
  "secret": "sk_exec_xyz789...",  # SAVE THIS
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
Authorization: Bearer ak_exec_abc123.sk_exec_xyz789

# Query (legacy, rate-limited, not logged)
GET /v1/verify?envelope=...&org_id=...&key=ak_exec_abc123.sk_exec_xyz789
```

### Rotation

```bash
curl -X POST localhost:8787/v1/orgs/org_abc/keys/rotate \
  -H "Authorization: Bearer ak_admin_..." \
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
const signed = me.signIntent(intent, agentKeypair);
await me.authorize(signed);
```

- Validates Ed25519 signature against passport
- `kid`-aware (supports rotation grace period)
- Recorded as `authn: "agent_sig"`

## Service Key Path

For trusted internal middleware:

```bash
curl -X POST localhost:8787/v1/authorize \
  -H "Authorization: Bearer sk_executor_..." \
  -H "Content-Type: application/json" \
  -d '{ "intent": ..., "service_key": "sk_executor_..." }'
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

All responses include:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

## Trust Proxy

Behind load balancer/reverse proxy:
```bash
AUTHRA_TRUST_PROXY=1
```
- Reads `X-Forwarded-For`, `X-Forwarded-Proto`
- Uses for rate limiting, logging, security decisions

## Next: [Organizations](/api/organizations)