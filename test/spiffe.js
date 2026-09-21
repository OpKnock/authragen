'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateX509Svid, validateJwtSvid } = require('../adapters/spiffe');

function b64u(x) { return Buffer.from(x).toString('base64url'); }

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authragen-spiffe-'));
  const key = path.join(dir, 'root.key');
  const crt = path.join(dir, 'root.crt');
  const leafKey = path.join(dir, 'leaf.key');
  const csr = path.join(dir, 'leaf.csr');
  const leaf = path.join(dir, 'leaf.crt');
  const ext = path.join(dir, 'leaf.ext');

  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch {
    console.log('openssl unavailable on this host: SKIP');
    return;
  }
  execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',crt,'-subj','/CN=AuthraGen SPIFFE Test Root','-days','2'], { stdio:'ignore' });
  fs.writeFileSync(ext, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=URI:spiffe://example.org/ns/default/sa/authragen\n');
  execFileSync('openssl', ['req','-new','-newkey','rsa:2048','-nodes','-keyout',leafKey,'-out',csr,'-subj','/CN=authragen','-days','2'], { stdio:'ignore' });
  execFileSync('openssl', ['x509','-req','-in',csr,'-CA',crt,'-CAkey',key,'-CAcreateserial','-out',leaf,'-days','1','-extfile',ext], { stdio:'ignore' });

  const x = validateX509Svid({
    certificate: fs.readFileSync(leaf, 'utf8'),
    trustBundle: fs.readFileSync(crt, 'utf8'),
    expectedSpiffeId: 'spiffe://example.org/ns/default/sa/authragen'
  });
  assert.equal(x.valid, true);
  assert.equal(x.trust_domain, 'example.org');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format:'jwk' });
  jwk.kid='spiffe-test'; jwk.use='sig'; jwk.alg='EdDSA';
  const now = Math.floor(Date.now()/1000);
  const h = b64u(JSON.stringify({ typ:'JWT', alg:'EdDSA', kid:'spiffe-test' }));
  const p = b64u(JSON.stringify({ iss:'example.org', sub:'spiffe://example.org/ns/default/sa/authragen', aud:['authragen'], iat:now, exp:now+60 }));
  const s = b64u(crypto.sign(null, Buffer.from(h+'.'+p), privateKey));
  const out = validateJwtSvid(h+'.'+p+'.'+s, { jwks:{keys:[jwk]}, expectedAudience:'authragen' });
  assert.equal(out.valid, true);
  assert.equal(out.spiffe_id, 'spiffe://example.org/ns/default/sa/authragen');

  const http2 = require('node:http2');
  const sock = path.join(dir, 'workload.sock');
  const h2 = http2.createServer();
  const encVarint = n => { const out=[]; let v=BigInt(n); while(v>127n){out.push(Number((v&127n)|128n));v>>=7n;} out.push(Number(v)); return Buffer.from(out); };
  const field = (n, value) => { const b=Buffer.isBuffer(value)?value:Buffer.from(value,'utf8'); return Buffer.concat([encVarint((n<<3)|2),encVarint(b.length),b]); };
  h2.on('stream', (stream, headers) => {
    stream.respond({ ':status': 200, 'content-type':'application/grpc' });
    const inner=Buffer.concat([field(1,'spiffe://example.org/ns/default/sa/authragen'),field(2,'jwt-svid-test')]);
    const payload=field(1,inner); const frame=Buffer.concat([Buffer.from([0]),Buffer.from([0,0,0,payload.length]),payload]);
    stream.end(frame);
  });
  await new Promise(resolve=>h2.listen(sock,resolve));
  const { fetchJwtSvidFromWorkloadApi } = require('../adapters/spiffe');
  const svids = await fetchJwtSvidFromWorkloadApi({ socketPath:sock, audience:'authragen' });
  assert.equal(svids[0].spiffe_id,'spiffe://example.org/ns/default/sa/authragen');
  assert.equal(svids[0].svid,'jwt-svid-test');
  h2.close();
  console.log('SPIFFE X.509-SVID + JWT-SVID validation: PASS');
})().catch(err => { console.error(err); process.exit(1); });
