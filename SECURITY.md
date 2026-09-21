# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.3.x   | :white_check_mark: |
| 2.2.x   | :white_check_mark: |
| 2.1.x   | :x:                |
| < 2.1   | :x:                |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Report security issues privately via:
- GitHub Security Advisories: https://github.com/OpKnock/authragen/security/advisories/new
- Email: security@authragen.dev (PGP key available on request)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Security Model

AuthraGen implements defense in depth:

### Authentication & Authorization
- Org-scoped API keys with RBAC (admin > approver > executor > reporter)
- Ed25519 agent/passport signatures plus gateway EdDSA/ES256 envelopes and optional ML-DSA credentials
- Audience-bound tokens (prevents cross-service replay)
- Single-use action credentials with nonce replay protection
- Short TTLs (configurable; defaults are enforced by protocol configuration)

### Cryptography
- Ed25519 for agent/passport signatures
- EdDSA/ES256 gateway envelopes
- ML-DSA-44/65/87 post-quantum credential profile (Node 24.7+)
- SHA-256 for hashing
- scrypt for API key hashing (N=16384, r=8, p=1)
- HKDF for key derivation
- Constant-time comparisons

### Transport Security
- HTTPS enforced in production (`AUTHRA_TRUST_PROXY=1`)
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Rate limiting (per-IP and per-key)
- Body size limits (256KB default)
- CORS configurable (`AUTHRA_CORS`)

### Data Protection
- Secrets never in logs, responses, or audit trails
- API key secrets shown once at creation
- Bootstrap token single-use, auto-deleted
- Private keys never leave client (CSR flow)
- File-backed org keys = development only (KMS for production)

### Audit & Accountability
- Hash-chained receipts (tamper-evident)
- Signed checkpoints with external anchor hook
- Versioned revocation feed with sequence numbers
- Per-org audit streams with export/evidence bundles

## Known Limitations

- File storage is single-instance; production uses Postgres/Redis.
- Dashboard interactive OIDC SSO is still proxy-based; OIDC bearer federation is supported.
- ML-DSA credential support is native when running Node 24.7+; hybrid migration of the core Ed25519 passport format remains a separate profile.
- External transparency anchoring remains operator-configured; tamper-evident logs are not magically immutable.
- Offline revocation freshness requires polling or another trusted distribution mechanism.

## Disclosure Timeline

1. Day 0: Report received, acknowledged
2. Day 1-2: Triage, impact assessment
3. Day 3-7: Fix developed, tested
4. Day 7: Advisory published, release cut
5. Day 14: Public disclosure (coordinated)

## Hall of Fame

Thank you to security researchers who responsibly disclose:

*(none yet - be the first!)*