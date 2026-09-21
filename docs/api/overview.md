# API Reference

## Base URL

```
http://localhost:8787/v1
```

## Authentication

All management endpoints require `Authorization: Bearer <api_key>`.

```bash
curl -H "Authorization: Bearer ${AUTHRA_API_KEY}" ...
```

**API Key format:** `ak_<key_id>.<secret>` (secret shown once at creation)

**Roles:** `admin` > `approver` > `executor` > `reporter`

## Request/Response Format

- Content-Type: `application/json`
- Request IDs: `X-Request-Id` header on all responses
- Errors: `{ "error": "code", "message": "human readable", "request_id": "rq_..." }`

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /v1/orgs` (bootstrap) | 5 | 1 min |
| `POST /v1/authorize` | 180 | 1 min |
| `POST /v1/execute` | 180 | 1 min |
| `POST /v1/verify` | 120 | 1 min |
| Other rate-limited routes | Route-specific | 1 min |

## Endpoints

### Organizations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/orgs` | bootstrap | Create organization |
| GET | `/orgs/:id` | reporter+ | Get organization |
| PUT | `/orgs/:id/risk` | admin | Update risk thresholds |
| POST | `/orgs/:id/lock` | admin | Emergency lock |
| POST | `/orgs/:id/unlock` | admin | Unlock |
| GET | `/orgs/:id/pubkey` | public | Org root public key |

### API Keys

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/orgs/:id/keys` | admin | Create API key |
| POST | `/orgs/:id/keys/rotate` | admin | Rotate API key |
| GET | `/orgs/:id/keys` | admin | List API keys |

### Blueprints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/blueprints` | admin | Create blueprint |
| GET | `/blueprints` | reporter+ | List blueprints |
| GET | `/blueprints/:id` | reporter+ | Get blueprint |

### Passports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/passports` | admin | Create passport (CSR) |
| GET | `/passports` | reporter+ | List passports |
| GET | `/passports/:id` | reporter+ | Get passport |
| POST | `/passports/rotate` | admin | Rotate passport key |
| POST | `/passports/:id/status` | admin | Update status |
| POST | `/passports/:id/keys/revoke` | admin | Revoke specific kid |

### Delegations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/delegate` | executor+ | Register delegation |
| GET | `/delegations` | reporter+ | List delegations |

### Policies

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/policies` | admin | Create policy |
| GET | `/policies` | reporter+ | List policies |
| GET | `/policies/:id` | reporter+ | Get policy |
| PUT | `/policies/:id` | admin | Update policy |
| POST | `/policies/simulate` | reporter+ | Dry-run evaluation |
| GET | `/policies/conflicts` | reporter+ | Detect conflicts |

### Authorization & Execution

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/authorize` | agent-sig/executor | Authorize intent |
| POST | `/execute` | action-token | Execute action |
| POST | `/verify` | public | Verify credential |

### Approvals

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/approvals` | reporter+ | List approvals |
| GET | `/approvals/:id` | reporter+ | Get approval |
| POST | `/approvals/:id` | approver+ | Approve/deny |

### Revocation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/revoke` | admin | Revoke entity |
| GET | `/revoked` | reporter+ | Get revocation feed |

### Audit

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit` | reporter+ | Query receipts |
| GET | `/audit/verify` | reporter+ | Verify chain |
| GET | `/audit/export` | reporter+ | Export JSONL |
| POST | `/audit/evidence` | reporter+ | Create evidence bundle |
| POST | `/audit/checkpoint` | admin | Create checkpoint |
| GET | `/audit/checkpoints` | reporter+ | List checkpoints |

## Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `unauthorized` | 401 | Missing/invalid authentication |
| `forbidden` | 403 | Insufficient permissions |
| `bad_request` | 400 | Invalid request body |
| `bad_intent` | 400 | Intent validation failed |
| `intent_expired` | 400 | Intent past expiration |
| `sig_invalid` | 401 | Signature verification failed |
| `unknown_kid` | 401 | Key ID not found |
| `key_revoked` | 401 | Key explicitly revoked |
| `key_expired` | 401 | Key past validity |
| `passport_unknown` | 404 | Passport not found |
| `passport_revoked` | 410 | Passport revoked |
| `passport_suspended` | 403 | Passport suspended |
| `passport_quarantined` | 403 | Passport quarantined |
| `token_unknown` | 404 | Action token not found |
| `token_expired` | 410 | Action token expired |
| `token_revoked` | 410 | Action token revoked |
| `token_mismatch` | 400 | Intent hash mismatch |
| `scope_insufficient` | 403 | Delegation scope insufficient |
| `budget_exceeded` | 403 | Budget exhausted |
| `replay` | 409 | Nonce/JTI replay detected |
| `custody_forbidden` | 403 | Server-custodied key not allowed |
| `org_locked` | 403 | Org emergency lock active |
| `rate_limited` | 429 | Rate limit exceeded |
| `quota_exceeded` | 429 | Org quota exceeded |
| `not_found` | 404 | Resource not found |
| `storage_error` | 500 | Storage backend error |

## Health Check

```
GET /health
```

Response includes `ok`, protocol/version, backend, persistence status, timestamp, custody policy, and the request ID.

## OpenAPI Spec

Generated at `/openapi.json` (when enabled) or via `make openapi`.

## Next: [Authentication](/api/authentication)