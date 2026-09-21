# SPIFFE / SPIRE Interoperability

AuthraGen consumes SPIFFE identities issued by SPIRE or another SPIFFE-compatible trust authority. It does not replace the SPIRE control plane.

## Supported identity forms

- X.509-SVID validation against a configured trust bundle.
- JWT-SVID validation with issuer, SPIFFE URI subject, audience, expiry and signing-key checks.
- SPIFFE Workload API access through the local Unix-domain workload endpoint for JWT-SVID and X.509-SVID retrieval.

The JWT-SVID validator follows the SPIFFE requirement that the token carries a SPIFFE URI subject, an audience and an expiration time.

## Runtime bearer authentication

Configure the AuthraGen gateway with a trusted SPIFFE JWT-SVID signing bundle:

```text
AUTHRA_SPIFFE_AUDIENCE=authragen-api
AUTHRA_SPIFFE_JWKS_FILE=/etc/authragen/spiffe-jwks.json
AUTHRA_SPIFFE_ORG_ID=org_...
AUTHRA_SPIFFE_ROLE=executor
AUTHRA_SPIFFE_ALLOWED_IDS=["spiffe://example.org/ns/prod/sa/payments"]
```

Then a workload may authenticate using:

```http
Authorization: Bearer <jwt-svid>
```

The normal AuthraGen organization and RBAC gates still apply.

## Workload API

The adapter can retrieve SVIDs directly from the local SPIFFE Workload API:

```js
const { fetchJwtSvidFromWorkloadApi } = require('./adapters/spiffe');

const [svid] = await fetchJwtSvidFromWorkloadApi({
  socketPath: '/run/spire/sockets/agent.sock',
  audience: 'authragen-api'
});
```

This design keeps workload identity issuance in SPIRE and lets AuthraGen consume the resulting SVIDs at the authorization boundary.

