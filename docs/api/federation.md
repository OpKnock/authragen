# Federation & Workload Identity

AuthraGen accepts federated identities without replacing its own authorization model. An external
identity is mapped to an AuthraGen principal, and the normal organization + RBAC checks still run.

## OIDC

Set:

```bash
AUTHRA_OIDC_ISSUER=https://idp.example.com
AUTHRA_OIDC_CLIENT_ID=authragen
AUTHRA_OIDC_AUDIENCE=authragen
AUTHRA_OIDC_ROLE_CLAIM=roles
AUTHRA_OIDC_ORG_CLAIM=org_id
AUTHRA_OIDC_ROLE_MAP='{"admin":["authragen-admin"],"approver":["authragen-approver"],"executor":["authragen-executor"],"reporter":["authragen-reporter"]}'
```

A static organization mapping may be used instead of an `org_id` claim:

```bash
AUTHRA_OIDC_ORG_ID=org_123
```

Bearer JWTs are discovered from the issuer's OpenID Provider configuration and JWKS. AuthraGen
validates issuer, signature, algorithm, audience, multi-audience `azp`, expiration, issued-at
time, and optional nonce. The issuer and JWKS URI must use HTTPS outside tests.

The resulting identity is:

```text
id: oidc:<sub>
source: oidc
org_id: <mapped organization>
role: <mapped AuthraGen role>
```

The OIDC identity is still subject to AuthraGen RBAC and organization-lock checks.

## SPIFFE / SPIRE

AuthraGen provides validators for both standards-defined SVID forms:

- X.509-SVID: exactly one `spiffe://` URI SAN, validity-window checking, and signature checking
  against a configured trust bundle.
- JWT-SVID: JWT signature checking from a SPIFFE JWKS bundle, SPIFFE subject validation,
  audience checking, and time validation.

SPIFFE/SPIRE-issued JWT-SVIDs can also authenticate the gateway as a Bearer credential when:

```bash
AUTHRA_SPIFFE_AUDIENCE=authragen
AUTHRA_SPIFFE_JWKS_FILE=/run/spire/bundle/jwt-bundle.json
AUTHRA_SPIFFE_ORG_ID=org_123
AUTHRA_SPIFFE_ROLE=executor
```

Optional allowlisting:

```bash
AUTHRA_SPIFFE_ALLOWED_IDS='["spiffe://prod.example/workload/payments"]'
```

The SPIFFE Workload API remains the standards-defined source for obtaining SVIDs; deployments can
place this validation layer next to a SPIRE agent, sidecar, proxy, or workload identity gateway.

## Post-quantum ML-DSA

AuthraGen includes a native ML-DSA credential profile:

```text
PQ1.<base64url header>.<base64url payload>.<base64url signature>
```

Supported variants are ML-DSA-44, ML-DSA-65, and ML-DSA-87. The implementation uses Node's native
WebCrypto ML-DSA support and keeps the PQ profile separate from the existing AR1 Ed25519/ES256
gateway envelope so deployments can introduce post-quantum credentials without breaking existing
credentials.

Example:

```javascript
const pq = require('./src/pq');

const keypair = await pq.generateKeypair('65');
const credential = await pq.seal(
  { subject: 'agent:payments', intent_hash: 'abc123' },
  keypair
);

const opened = await pq.open(credential, keypair.publicKey);
```

Node releases with native WebCrypto ML-DSA support are required for this profile.

ML-DSA is standardized by NIST FIPS 204. The PQ profile is an AuthraGen credential envelope, not a
claim that AR1 is a globally standardized token format.

## Assurance boundary

Federation proves the external identity. It does not grant authorization by itself. AuthraGen's
policy engine, passport lifecycle, exact-intent binding, delegation constraints, replay controls,
revocation, and audit receipts remain authoritative for protected operations.
