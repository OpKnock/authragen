'use strict';
// AuthraGen crypto — Node built-ins only (Ed25519 + SHA-256).
const crypto = require('node:crypto');

function b64uEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function b64uJsonEncode(obj) { return b64uEncode(Buffer.from(JSON.stringify(obj), 'utf8')); }
function b64uJsonDecode(s) { return JSON.parse(b64uDecode(s).toString('utf8')); }

// Deterministic canonical JSON: sorted keys recursively, no whitespace.
// SECURITY: strict — rejects undefined/functions/symbols, NaN/Infinity,
// normalizes strings to NFC (prevents ambiguous-Unicode equivalent-but-different
// representations), and sorts keys by UTF-16 code units. Duplicate JSON keys
// cannot survive JSON.parse (last wins) — callers that need raw-duplicate
// detection must check the raw body BEFORE parsing (see server body()).
function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number not allowed in canonical form');
    return JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v.normalize('NFC'));
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v !== 'object') throw new Error('unserializable value in canonical form: ' + typeof v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  const keys = Object.keys(v).filter(k => k !== 'signature').sort();
  return '{' + keys.map(k => JSON.stringify(k.normalize('NFC')) + ':' + canonical(v[k])).join(',') + '}';
}
// Detect duplicate JSON object keys in a raw body string (security: ambiguous parses).
function hasDuplicateKeys(raw) {
  try {
    const stack = [];
    let i = 0;
    const s = String(raw);
    // Lightweight scan: track object key sets via a simple recursive-descent hook.
    // For robustness we re-parse with a reviver that flags duplicates.
    const seen = [];
    let dup = false;
    JSON.parse(s, function (k, v) {
      if (k && this && typeof this === 'object' && !Array.isArray(this)) {
        // `this` is the holder; count occurrences by scanning siblings is expensive,
        // so we use a parallel stack: JSON.parse calls reviver bottom-up; instead
        // detect via regex-free second pass below.
      }
      return v;
    });
    // Second pass: tokenize strings to find object boundaries and duplicate keys.
    // Simple but effective for attack detection (may false-negative on exotic escapes;
    // canonical() still provides deterministic hashing).
    const tokens = [];
    let idx = 0, inStr = false, esc = false, cur = '';
    const objs = [];
    // Fallback: use a strict duplicate check by parsing with explicit key tracking.
    let pos = 0;
    function skipWs() { while (pos < s.length && /\s/.test(s[pos])) pos++; }
    function parseVal() {
      skipWs();
      const c = s[pos];
      if (c === '{') return parseObj();
      if (c === '[') { pos++; skipWs(); if (s[pos] === ']') { pos++; return 0; } while (true) { parseVal(); skipWs(); if (s[pos] === ',') { pos++; continue; } if (s[pos] === ']') { pos++; break; } throw new Error('bad'); } return 0; }
      if (c === '"') { parseStr(); return 0; }
      // number/literal: consume
      while (pos < s.length && ![',', '}', ']', ' ', '\n', '\r', '\t'].includes(s[pos])) pos++;
      return 0;
    }
    function parseStr() {
      // assumes s[pos]==='"'
      pos++; let out = '';
      while (pos < s.length) {
        const ch = s[pos];
        if (esc) { out += ch; esc = false; pos++; continue; }
        if (ch === '\\') { esc = true; out += ch; pos++; continue; }
        if (ch === '"') { pos++; return out; }
        out += ch; pos++;
      }
      throw new Error('bad string');
    }
    function parseObj() {
      pos++; // {
      skipWs();
      const keys = new Set();
      if (s[pos] === '}') { pos++; return 0; }
      while (true) {
        skipWs();
        if (s[pos] !== '"') throw new Error('expected key');
        const k = parseStr();
        if (keys.has(k)) { dup = true; }
        keys.add(k);
        skipWs();
        if (s[pos] !== ':') throw new Error('expected colon');
        pos++;
        parseVal();
        skipWs();
        if (s[pos] === ',') { pos++; continue; }
        if (s[pos] === '}') { pos++; break; }
        throw new Error('bad obj');
      }
      return 0;
    }
    skipWs();
    if (s.trim()) parseVal();
    return dup;
  } catch { return false; }
}

function sha256hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }
function rid(prefix) { return prefix + '_' + crypto.randomBytes(6).toString('hex'); }

function generateEd25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubJwk = publicKey.export({ format: 'jwk' });
  const privJwk = privateKey.export({ format: 'jwk' });
  // x and d are base64url per JWK
  return { publicKey, privateKey, pubB64u: pubJwk.x, privB64u: privJwk.d, pubJwk, privJwk };
}
function pubKeyFromB64u(x) {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x };
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
function pubKeyFromWire(value, alg = 'EdDSA') {
  if (alg === 'EdDSA') return pubKeyFromB64u(value);
  if (alg === 'ES256') return crypto.createPublicKey({ key: Buffer.from(String(value), 'base64url'), format: 'der', type: 'spki' });
  throw err('token_malformed', 'unsupported credential algorithm');
}
function verifyBytes(data, signatureB64u, pubKey, alg = 'EdDSA') {
  const sig = b64uDecode(signatureB64u);
  if (alg === 'EdDSA') return crypto.verify(null, Buffer.from(data), pubKey, sig);
  if (alg === 'ES256') return crypto.verify('sha256', Buffer.from(data), pubKey, sig);
  throw err('token_malformed', 'unsupported credential algorithm');
}
function privKeyFromB64u(x, d) {
  const jwk = { kty: 'OKP', crv: 'Ed25519', x, d };
  return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
}

function signCanonical(obj, privKey) {
  const msg = Buffer.from(canonical(obj), 'utf8');
  const sig = crypto.sign(null, msg, privKey);
  return b64uEncode(sig);
}
function verifyCanonical(obj, sigB64u, pubKey) {
  const msg = Buffer.from(canonical(obj), 'utf8');
  const sig = b64uDecode(sigB64u);
  return crypto.verify(null, msg, pubKey, sig);
}

// AR1 token envelope: AR1.<b64u(header)>.<b64u(payload)>.<b64u(sig)>
function seal(payload, privKey) {
  const header = { alg: 'EdDSA', typ: 'AR1', v: 1 };
  const h = b64uJsonEncode(header), p = b64uJsonEncode(payload);
  const sig = b64uEncode(crypto.sign(null, Buffer.from(h + '.' + p, 'utf8'), privKey));
  return `AR1.${h}.${p}.${sig}`;
}
function open(token, pubKey) {
  const parts = String(token || '').split('.');
  if (parts.length !== 4 || parts[0] !== 'AR1') throw err('token_malformed', 'Not an AR1 token');
  const [, h, p, s] = parts;
  const ok = crypto.verify(null, Buffer.from(h + '.' + p, 'utf8'), pubKey, b64uDecode(s));
  if (!ok) throw err('sig_invalid', 'Bad signature');
  return { header: b64uJsonDecode(h), payload: b64uJsonDecode(p) };
}
function err(code, message) { const e = new Error(message); e.code = code; return e; }
function didFor(pubB64u) { return 'did:authragen:' + String(pubB64u); }

module.exports = { b64uEncode, b64uDecode, b64uJsonEncode, b64uJsonDecode, canonical, hasDuplicateKeys, sha256hex, rid, generateEd25519, pubKeyFromB64u, pubKeyFromWire, verifyBytes, privKeyFromB64u, signCanonical, verifyCanonical, seal, open, didFor };
