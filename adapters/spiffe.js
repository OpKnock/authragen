'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

function pemBlocks(text) {
  return [...String(text || '').matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)].map(m => m[0]);
}
function certFrom(value) { return value instanceof crypto.X509Certificate ? value : new crypto.X509Certificate(String(value)); }
function extractSpiffeIds(cert) {
  const san = cert.subjectAltName || '';
  return san.split(/,\s*/).filter(x => x.startsWith('URI:')).map(x => x.slice(4));
}
function validateX509Svid({ certificate, trustBundle, expectedSpiffeId = null, now = Date.now() } = {}) {
  const leaf = certFrom(certificate);
  const ids = extractSpiffeIds(leaf);
  if (ids.length !== 1 || !ids[0].startsWith('spiffe://')) throw new Error('SPIFFE X.509-SVID must contain exactly one SPIFFE URI SAN');
  if (expectedSpiffeId && ids[0] !== expectedSpiffeId) throw new Error('SPIFFE ID mismatch');
  const notBefore = Date.parse(leaf.validFrom);
  const notAfter = Date.parse(leaf.validTo);
  if (!(now >= notBefore && now <= notAfter)) throw new Error('SPIFFE X.509-SVID expired or not yet valid');

  const roots = pemBlocks(trustBundle).map(certFrom);
  if (!roots.length) throw new Error('SPIFFE trust bundle is empty');
  let issuer = null;
  for (const parent of roots) {
    try { if (leaf.verify(parent.publicKey)) { issuer = parent; break; } } catch {}
  }
  if (!issuer) throw new Error('SPIFFE X.509-SVID is not signed by configured trust bundle');

  return { valid: true, spiffe_id: ids[0], trust_domain: new URL(ids[0]).host, certificate: leaf };
}

function b64uDecode(s) {
  let x = String(s).replace(/-/g,'+').replace(/_/g,'/');
  while (x.length % 4) x += '=';
  return Buffer.from(x,'base64');
}
function verifyJwtSignature(token, jwks, now = Math.floor(Date.now()/1000)) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('SPIFFE JWT-SVID must be a compact JWT');
  const header = JSON.parse(b64uDecode(parts[0]).toString('utf8'));
  const claims = JSON.parse(b64uDecode(parts[1]).toString('utf8'));
  if (!header.kid || !['RS256','ES256','EdDSA'].includes(header.alg)) throw new Error('unsupported SPIFFE JWT-SVID algorithm');
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid && (!k.use || k.use === 'sig'));
  if (!jwk || jwk.d) throw new Error('SPIFFE JWT-SVID signing key not found');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const sig = b64uDecode(parts[2]);
  const signing = Buffer.from(parts[0] + '.' + parts[1]);
  let ok;
  if (header.alg === 'RS256') ok = crypto.verify('sha256', signing, key, sig);
  else if (header.alg === 'ES256') {
    const raw = sig; if (raw.length !== 64) throw new Error('invalid ES256 signature');
    const part = x => { let p = Buffer.from(x); while(p.length>1&&p[0]===0)p=p.subarray(1); if(p[0]&0x80)p=Buffer.concat([Buffer.from([0]),p]); return Buffer.concat([Buffer.from([2,p.length]),p]); };
    const body = Buffer.concat([part(raw.subarray(0,32)),part(raw.subarray(32))]);
    ok = crypto.verify('sha256', signing, key, Buffer.concat([Buffer.from([0x30,body.length]),body]));
  } else ok = crypto.verify(null, signing, key, sig);
  if (!ok) throw new Error('SPIFFE JWT-SVID signature invalid');
  if (typeof claims.sub !== 'string' || !claims.sub.startsWith('spiffe://')) throw new Error('SPIFFE JWT-SVID subject is not a SPIFFE ID');
  if (claims.exp != null && now > claims.exp) throw new Error('SPIFFE JWT-SVID expired');
  if (claims.nbf != null && now < claims.nbf) throw new Error('SPIFFE JWT-SVID not yet valid');
  if (!claims.iat || !Number.isInteger(claims.iat)) throw new Error('SPIFFE JWT-SVID missing iat');
  if (typeof claims.aud === 'undefined') throw new Error('SPIFFE JWT-SVID missing audience');
  return { header, claims, spiffe_id: claims.sub, trust_domain: new URL(claims.sub).host };
}
function audienceMatches(aud, expected) {
  const vals = Array.isArray(aud) ? aud : [aud];
  return vals.includes(expected);
}
function validateJwtSvid(token, { jwks, expectedAudience, expectedSpiffeId = null } = {}) {
  const out = verifyJwtSignature(token, jwks);
  if (!audienceMatches(out.claims.aud, expectedAudience)) throw new Error('SPIFFE JWT-SVID audience mismatch');
  if (expectedSpiffeId && out.spiffe_id !== expectedSpiffeId) throw new Error('SPIFFE ID mismatch');
  return { ...out, valid: true };
}
function loadTrustBundle(file) { return fs.readFileSync(file, 'utf8'); }
module.exports = { validateX509Svid, validateJwtSvid, extractSpiffeIds, loadTrustBundle };
