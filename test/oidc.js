'use strict';

process.env.NODE_ENV = 'test';
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { OidcVerifier } = require('../src/oidc');

function b64u(x) { return Buffer.from(x).toString('base64url'); }
function jwt(header, claims, privateKey) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(claims));
  const input = Buffer.from(h + '.' + p);
  const sig = crypto.sign('sha256', input, privateKey).toString('base64url');
  return h + '.' + p + '.' + sig;
}

(async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'oidc-test-1'; jwk.alg = 'RS256'; jwk.use = 'sig';

  const issuer = 'http://127.0.0.1';
  const server = http.createServer((req, res) => {
    if (req.url === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer, jwks_uri: issuer + '/jwks' }));
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    res.statusCode = 404; res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const actualIssuer = 'http://127.0.0.1:' + port;

  const verifier = new OidcVerifier({
    issuer: actualIssuer,
    clientId: 'authragen-client',
    audience: 'authragen-client',
    roleMap: { admin: ['ops-admin'], executor: ['ops-executor'] },
    orgClaim: 'org_id'
  });
  await verifier.init();

  const now = Math.floor(Date.now()/1000);
  const token = jwt(
    { typ: 'JWT', alg: 'RS256', kid: 'oidc-test-1' },
    { iss: actualIssuer, sub: 'user-123', aud: 'authragen-client', iat: now, exp: now + 300, org_id: 'org_test', roles: ['ops-executor'], name: 'OIDC Test' },
    privateKey
  );
  const principal = verifier.principal(token);
  assert.equal(principal.org_id, 'org_test');
  assert.equal(principal.role, 'executor');
  assert.equal(principal.source, 'oidc');
  const nonceToken = jwt(
    { typ: 'JWT', alg: 'RS256', kid: 'oidc-test-1' },
    { iss: actualIssuer, sub: 'user-123', aud: 'authragen-client', iat: now, exp: now + 300, nonce: 'n-123', org_id: 'org_test', roles: ['ops-executor'] },
    privateKey
  );
  assert.equal(verifier.verify(nonceToken, { nonce: 'n-123' }).claims.nonce, 'n-123');
  assert.throws(() => verifier.verify(nonceToken, { nonce: 'wrong' }), /nonce mismatch/);
  const bad = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
  assert.throws(() => verifier.verify(bad), /signature invalid/);
  await new Promise(resolve => server.close(resolve));
  console.log('OIDC discovery + ID-token validation: PASS');
})().catch(err => { console.error(err); process.exit(1); });
