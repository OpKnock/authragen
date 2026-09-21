'use strict';

const { webcrypto } = require('node:crypto');
const { canonical, b64uEncode, b64uDecode } = require('./crypto');

const LEVELS = new Set(['44','65','87']);
function algorithm(level = '65') {
  const l = String(level);
  if (!LEVELS.has(l)) throw new Error('ML-DSA level must be 44, 65, or 87');
  return 'ML-DSA-' + l;
}
function supported(level = '65') {
  try { return !!webcrypto?.subtle?.supports?.('generateKey', algorithm(level)); }
  catch { return false; }
}
function requireSupport(level) {
  if (!supported(level)) throw new Error('ML-DSA requires a Node.js release with native WebCrypto ML-DSA support (Node 24.7+).');
}
async function generateKeypair(level = '65') {
  requireSupport(level);
  const alg = algorithm(level);
  const pair = await webcrypto.subtle.generateKey({ name: alg }, true, ['sign','verify']);
  const publicKey = Buffer.from(await webcrypto.subtle.exportKey('raw-public', pair.publicKey));
  const seed = Buffer.from(await webcrypto.subtle.exportKey('raw-seed', pair.privateKey));
  return { alg, publicKey: b64uEncode(publicKey), seed: b64uEncode(seed) };
}
async function importPublic(alg, publicKey) {
  requireSupport(String(alg).replace(/^ML-DSA-/,''));
  return webcrypto.subtle.importKey('raw-public', b64uDecode(publicKey), alg, false, ['verify']);
}
async function importPrivate(alg, seed) {
  requireSupport(String(alg).replace(/^ML-DSA-/,''));
  return webcrypto.subtle.importKey('raw-seed', b64uDecode(seed), alg, false, ['sign']);
}
async function sign(data, key, seed = null) {
  const privateKey = seed ? await importPrivate(key.alg || key.algorithm || 'ML-DSA-65', seed) : key;
  const alg = key.alg || key.algorithm || privateKey.algorithm.name;
  const sig = await webcrypto.subtle.sign({ name: alg }, privateKey, Buffer.from(data));
  return b64uEncode(Buffer.from(sig));
}
async function verify(data, signature, alg, publicKey) {
  const key = await importPublic(alg, publicKey);
  return webcrypto.subtle.verify({ name: alg }, key, b64uDecode(signature), Buffer.from(data));
}
async function seal(payload, keypair) {
  const header = { typ: 'PQ1', v: 1, alg: keypair.alg };
  const h = b64uEncode(Buffer.from(canonical(header)));
  const p = b64uEncode(Buffer.from(canonical(payload)));
  const sig = await sign(Buffer.from(h + '.' + p), { alg: keypair.alg }, keypair.seed);
  return 'PQ1.' + h + '.' + p + '.' + sig;
}
async function open(token, publicKey) {
  const parts = String(token || '').split('.');
  if (parts.length !== 4 || parts[0] !== 'PQ1') throw new Error('invalid PQ1 envelope');
  const [, h, p, s] = parts;
  const header = JSON.parse(b64uDecode(h).toString('utf8'));
  if (header.typ !== 'PQ1' || !/^ML-DSA-(44|65|87)$/.test(header.alg)) throw new Error('invalid PQ1 algorithm');
  if (!await verify(Buffer.from(h + '.' + p), s, header.alg, publicKey)) throw new Error('PQ1 signature invalid');
  return { header, payload: JSON.parse(b64uDecode(p).toString('utf8')) };
}
module.exports = { LEVELS: [...LEVELS], algorithm, supported, generateKeypair, sign, verify, seal, open };
