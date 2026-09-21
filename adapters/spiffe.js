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
  const trustDomain = new URL(claims.sub).host;
  if (claims.iss !== trustDomain && claims.iss !== 'spiffe://' + trustDomain) throw new Error('SPIFFE JWT-SVID issuer must match its trust domain');
  if (!Number.isInteger(claims.exp)) throw new Error('SPIFFE JWT-SVID missing exp');
  if (now > claims.exp) throw new Error('SPIFFE JWT-SVID expired');
  if (claims.nbf != null && now < claims.nbf) throw new Error('SPIFFE JWT-SVID not yet valid');
  if (!claims.iat || !Number.isInteger(claims.iat)) throw new Error('SPIFFE JWT-SVID missing iat');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.length || audiences.some(x => typeof x !== 'string' || !x)) throw new Error('SPIFFE JWT-SVID missing audience');
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

function encVarint(n) {
  const out=[]; let v=BigInt(n);
  while(v>127n){out.push(Number((v&127n)|128n));v>>=7n;} out.push(Number(v)); return Buffer.from(out);
}
function encString(field, value) {
  const b=Buffer.from(String(value),'utf8');
  return Buffer.concat([encVarint((field<<3)|2),encVarint(b.length),b]);
}
function grpcFrame(message) {
  const b=Buffer.from(message||Buffer.alloc(0));
  const len=Buffer.alloc(4); len.writeUInt32BE(b.length,0);
  return Buffer.concat([Buffer.from([0]),len,b]);
}
function readVarint(buf, state) {
  let v=0n,shift=0n;
  while(state.i<buf.length){const x=buf[state.i++];v|=BigInt(x&127)<<shift;if(!(x&128))return Number(v);shift+=7n;if(shift>63n)throw new Error('protobuf varint too large');}
  throw new Error('truncated protobuf varint');
}
function decodeFields(buf) {
  const fields=[]; const state={i:0};
  while(state.i<buf.length){
    const tag=readVarint(buf,state); const num=tag>>>3; const wt=tag&7;
    if(wt===2){const len=readVarint(buf,state); if(state.i+len>buf.length)throw new Error('truncated protobuf field'); const value=buf.subarray(state.i,state.i+len);state.i+=len;fields.push({num,wt,value});}
    else if(wt===0){fields.push({num,wt,value:readVarint(buf,state)});}
    else if(wt===1){fields.push({num,wt,value:buf.subarray(state.i,state.i+8)});state.i+=8;}
    else if(wt===5){fields.push({num,wt,value:buf.subarray(state.i,state.i+4)});state.i+=4;}
    else throw new Error('unsupported protobuf wire type');
  }
  return fields;
}
function parseGrpcFrames(buffer) {
  const frames=[]; let i=0;
  while(i+5<=buffer.length){const compressed=buffer[i];const len=buffer.readUInt32BE(i+1);i+=5;if(i+len>buffer.length)throw new Error('truncated gRPC frame');if(compressed!==0)throw new Error('compressed gRPC messages are not supported');frames.push(buffer.subarray(i,i+len));i+=len;}
  if(i!==buffer.length)throw new Error('trailing gRPC bytes');
  return frames;
}
function decodeJwtSvidMessages(frames) {
  return frames.flatMap(frame=>decodeFields(frame).filter(f=>f.num===1&&f.wt===2).map(f=>{
    const fields=decodeFields(f.value); const out={};
    for(const x of fields){if(x.num===1)out.spiffe_id=x.value.toString('utf8');else if(x.num===2)out.svid=x.value.toString('utf8');else if(x.num===3)out.hint=x.value.toString('utf8');}
    return out;
  }));
}
function decodeX509SvidMessages(frames) {
  return frames.flatMap(frame=>decodeFields(frame).filter(f=>f.num===1&&f.wt===2).map(f=>{
    const fields=decodeFields(f.value); const out={};
    for(const x of fields){if(x.num===1)out.spiffe_id=x.value.toString('utf8');else if(x.num===2)out.x509_svid=Buffer.from(x.value);else if(x.num===3)out.x509_svid_key=Buffer.from(x.value);else if(x.num===4)out.bundle=Buffer.from(x.value);else if(x.num===5)out.hint=x.value.toString('utf8');}
    return out;
  }));
}
async function workloadRpc({socketPath='/run/spire/sockets/agent.sock', rpcPath, request=Buffer.alloc(0), timeoutMs=5000}={}) {
  const http2=require('node:http2');
  const net=require('node:net');
  // node:http2.connect ignores a bare socketPath option (it would dial
  // localhost:80 instead), so dial the unix socket explicitly.
  const client=http2.connect('http://localhost',{ createConnection: () => net.connect(socketPath) });
  return new Promise((resolve,reject)=>{
    const chunks=[]; let settled=false;
    const timer=setTimeout(()=>{if(!settled){settled=true;client.destroy();reject(new Error('SPIFFE Workload API timeout'));}},timeoutMs);
    const req=client.request({':method':'POST',':path':rpcPath,'content-type':'application/grpc','te':'trailers'});
    req.on('data',c=>chunks.push(Buffer.from(c)));
    req.on('error',e=>{if(!settled){settled=true;clearTimeout(timer);client.close();reject(e);}});
    req.on('trailers',(headers)=>{const status=Number(headers['grpc-status']||0);if(status!==0&& !settled){settled=true;clearTimeout(timer);client.close();reject(new Error('SPIFFE Workload API grpc-status '+status+' '+String(headers['grpc-message']||'')));}});
    req.on('end',()=>{if(settled)return;settled=true;clearTimeout(timer);client.close();try{resolve(parseGrpcFrames(Buffer.concat(chunks)));}catch(e){reject(e);}});
    req.end(grpcFrame(request));
  });
}
async function fetchJwtSvidFromWorkloadApi({socketPath, audience, spiffeId=null}={}) {
  if(!audience)throw new Error('SPIFFE Workload API audience required');
  const request=Buffer.concat([].concat((Array.isArray(audience)?audience:[audience]).map(x=>encString(1,x)),spiffeId?[encString(2,spiffeId)]:[]));
  const frames=await workloadRpc({socketPath,rpcPath:'/spiffe.workloadapi.v1.SpiffeWorkloadAPI/FetchJWTSVID',request});
  const svids=decodeJwtSvidMessages(frames); if(!svids.length)throw new Error('SPIFFE Workload API returned no JWT-SVID'); return svids;
}
async function fetchX509SvidFromWorkloadApi({socketPath}={}) {
  const frames=await workloadRpc({socketPath,rpcPath:'/spiffe.workloadapi.v1.SpiffeWorkloadAPI/FetchX509SVID'});
  const svids=decodeX509SvidMessages(frames); if(!svids.length)throw new Error('SPIFFE Workload API returned no X.509-SVID'); return svids;
}

function loadTrustBundle(file) { return fs.readFileSync(file, 'utf8'); }
module.exports = { validateX509Svid, validateJwtSvid, extractSpiffeIds, loadTrustBundle, workloadRpc, fetchJwtSvidFromWorkloadApi, fetchX509SvidFromWorkloadApi };
