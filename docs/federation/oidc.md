# OIDC Federation

AuthraGen can use an OpenID Connect provider as a federated administrative/service identity source.

## What is verified

The verifier discovers the provider configuration from:

`<issuer>/.well-known/openid-configuration`

and retrieves its JWKS. Tokens are accepted only when the issuer, signature algorithm, signing key, audience, subject, issued-at time, expiration, and (when supplied by the caller) nonce pass validation. Multiple audiences require `azp` to match the configured audience.

Supported signing algorithms are RS256, PS256, ES256, and EdDSA. The configured issuer and discovered JWKS endpoint must use HTTPS outside test mode.

## Mapping an OIDC principal

Set:

```text
AUTHRA_OIDC_ISSUER=https://id.example.com
AUTHRA_OIDC_CLIENT_ID=authragen
AUTHRA_OIDC_AUDIENCE=authragen
AUTHRA_OIDC_ORG_ID=org_...
AUTHRA_OIDC_ROLE_CLAIM=roles
AUTHRA_OIDC_ROLE_MAP={"admin":["ops-admin"],"approver":["ops-approver"],"executor":["ops-executor"],"reporter":["ops-viewer"]}
```

Use `AUTHRA_OIDC_ORG_ID` for a deployment-scoped mapping, or `AUTHRA_OIDC_ORG_CLAIM` to map the organization from a trusted claim.

After startup, an OIDC bearer JWT can be used in:

```http
Authorization: Bearer <oidc-jwt>
```

AuthraGen converts the verified identity into an internal principal and applies the normal organization and RBAC checks. A failed or missing OIDC verification never falls through to an elevated role.

## Operational guidance

OIDC federation is for API/service authentication in AuthraGen. The dashboard itself remains a bearer-authenticated console; place it behind an OIDC-aware reverse proxy when browser SSO is required.

Rotate provider signing keys normally. AuthraGen refreshes the discovered JWKS periodically. Configure short token lifetimes and a bounded clock-skew window.

