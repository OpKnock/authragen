# Post-Quantum ML-DSA Credentials

AuthraGen includes an explicit post-quantum credential profile using ML-DSA, the signature family standardized by NIST FIPS 204.

## Supported profiles

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

Native Node WebCrypto support is required. Node.js added ML-DSA support in v24.7.0, so PQ operations are available on supported Node 24+ runtimes.

## Usage

```js
const { AuthraGen } = require('./sdk-js/authragen');

const ag = new AuthraGen();
const keypair = await ag.generatePqKeypair('65');

const payload = {
  v: 1,
  subject: 'agent:payments',
  intent_hash: '...',
  issued_at: Date.now()
};

const envelope = await ag.sealPq(payload, keypair);
const opened = await ag.openPq(envelope, keypair.publicKey);
```

The PQ envelope uses the `PQ1` compact format and carries the ML-DSA algorithm identifier in its header. Signatures are verified before payloads are accepted.

## Design boundary

The PQ profile is additive. Existing AuthraGen AR1 action credentials and current Ed25519 agent passports remain interoperable. This avoids silently changing the trust model of deployed credentials.

For environments requiring end-to-end hybrid post-quantum identity, use the ML-DSA profile for the additional credential/signature layer while retaining the existing AR1 authorization path until a formal hybrid passport profile is standardized.
