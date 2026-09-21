'use strict';

const { OidcVerifier } = require('../src/oidc');

function createOidcFederation(opts) {
  const verifier = opts instanceof OidcVerifier ? opts : new OidcVerifier(opts);
  return {
    verifier,
    async initialize() { await verifier.init(); return this; },
    verifyIdToken(token, { nonce = null } = {}) { return verifier.verify(token, { nonce }); },
    authenticate(token) { return verifier.principal(token); }
  };
}
module.exports = { createOidcFederation, adapterContract: 'oidc-core-id-token-validation v1' };
