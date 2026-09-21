'use strict';
// Tamper-evident, append-optimized audit log.
//
// - append() is O(1): reads only a tiny state file (count+head), appends one
//   line, rewrites state. No full-file scan per write (scales past demo size;
//   production path is a real append-only store / DB — same record shape).
// - verify() replays the chain (inherently O(n)).
// - checkpoint() signs {count, head} with the gateway key so an EXTERNAL
//   party can detect whole-file rewrites. Set AUTHRA_ANCHOR_URL to POST each
//   checkpoint to a transparency log / timestamping service (fire-and-forget,
//   result recorded). Without external anchoring the chain is tamper-EVIDENT
//   against partial edits, not tamper-PROOF against full rewrites — see docs.
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { canonical, sha256hex } = require('./crypto');

function dataDir() { return process.env.AUTHRA_DATA || require('./store').DATA_DIR; }
function LOG() { return path.join(dataDir(), 'audit.jsonl'); }
function STATE() { return path.join(dataDir(), 'audit_state.json'); }
function CHECKPOINTS() { return path.join(dataDir(), 'checkpoints.jsonl'); }
// Back-compat constants (first-load values) — internal code uses the functions above.
const LOG_PATH = LOG; const STATE_PATH = STATE; const CHECKPOINTS_PATH = CHECKPOINTS;

function state() {
  try { return JSON.parse(fs.readFileSync(STATE(), 'utf8')); }
  catch {
    // Recover state from a valid log, but never treat a malformed log as a fresh log.
    const all = readAll();
    if (!all.length) return { count: 0, head: 'GENESIS' };
    return { count: all.length, head: all[all.length - 1].hash };
  }
}
function redact(entry) {
  // Never persist secrets: strip any field that looks like a secret or private key.
  const out = { ...entry };
  for (const k of Object.keys(out)) {
    if (/secret|priv|password|token_(?!jti|_jti)|bootstrap|api[_-]?key/i.test(k) && k !== 'token_jti' && k !== 'action_jti' && k !== 'action_token') {
      out[k] = '[redacted]';
    }
  }
  // Action tokens are single-use bearer-adjacent credentials: store only the jti + hash, never the envelope.
  if (typeof out.action_token === 'string' && out.action_token.startsWith('AR1.')) {
    out.action_token = '[envelope-redacted]';
  }
  if (typeof out.approval === 'string' && out.approval.startsWith('AR1.')) out.approval = '[envelope-redacted]';
  return out;
}
function append(entry) {
  // Concurrency-safe + durable: O(1) state read, single appendFileSync (atomic for
  // small writes on POSIX), atomic state rewrite via rename. The server mutex
  // serializes execute(); authorize() appends are independent sequence numbers.
  // Production Postgres: INSERT with SERIAL seq + RETURNING (transactional).
  const st = state();
  const seq = st.count + 1;
  const safe = redact(entry);
  const body = { seq, id: `rcpt_${seq}`, ts: Date.now(), prev_hash: st.head, ...safe };
  // Every receipt carries request ID + policy version/hash when available (callers set them).
  if (!body.request_id) body.request_id = 'rq_' + require('node:crypto').randomBytes(6).toString('hex');
  const hash = sha256hex(st.head + '|' + canonical(body));
  const rec = { ...body, hash };
  const dir = require('node:path').dirname(LOG());
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  fs.appendFileSync(LOG(), JSON.stringify(rec) + '\n');
  const tmp = STATE() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ count: seq, head: hash }));
  fs.renameSync(tmp, STATE());
  return rec;
}
function byOrg(org_id, limit = 100) {
  return readAll().filter(r => r.org_id === org_id).slice(-limit);
}
function exportJsonl(org_id) {
  return byOrg(org_id, Number.MAX_SAFE_INTEGER).map(r => JSON.stringify(r)).join('\n') + '\n';
}
async function evidenceBundle({ org_id, intent_hash = null, passport_id = null, signer = null } = {}) {
  let receipts = byOrg(org_id, Number.MAX_SAFE_INTEGER);
  if (intent_hash) receipts = receipts.filter(r => r.intent_hash === intent_hash);
  if (passport_id) receipts = receipts.filter(r => r.actor === passport_id);
  const body = { v: 1, org_id, exported_at: Date.now(), intent_hash, passport_id, count: receipts.length, receipts };
  const bundle = { ...body, bundle_hash: sha256hex(canonical(body)) };
  if (signer) bundle.signature = await signer.signCanonical({ ...body, bundle_hash: bundle.bundle_hash });
  return bundle;
}
function readAll() {
  try {
    const raw = fs.readFileSync(LOG(), 'utf8').trim();
    if (!raw) return [];
    return raw.split('\n').map(l => JSON.parse(l));
  } catch (e) {
    throw Object.assign(new Error('audit log unreadable or malformed'), { code: 'audit_corrupt', cause: e });
  }
}
function verify() {
  const all = readAll();
  let prev = 'GENESIS';
  for (const r of all) {
    const { hash, ...body } = r;
    if (body.prev_hash !== prev) return { ok: false, broken_at: body.seq, reason: 'prev_hash mismatch' };
    const h = sha256hex(prev + '|' + canonical(body));
    if (h !== hash) return { ok: false, broken_at: body.seq, reason: 'hash mismatch — log tampered' };
    prev = hash;
  }
  return { ok: true, count: all.length, head: prev };
}
async function checkpoint(signer) {
  const st = state();
  const prev = lastCheckpoint();
  const body = {
    v: 1, alg: signer.alg || 'EdDSA', ts: Date.now(), count: st.count, head: st.head,
    prev: prev ? prev.hash : 'GENESIS', gateway_pubkey: signer.pubkey,
  };
  const hash = sha256hex(canonical(body));
  const rec = { ...body, hash, signature: await signer.signCanonical({ ...body, hash }) };
  fs.mkdirSync(path.dirname(CHECKPOINTS()), { recursive: true });
  fs.appendFileSync(CHECKPOINTS(), JSON.stringify(rec) + '\n');
  const anchorUrl = process.env.AUTHRA_ANCHOR_URL;
  if (anchorUrl) anchor(rec, anchorUrl);
  else console.log(`[authragen] checkpoint #${st.count} ${hash.slice(0, 16)}… (no AUTHRA_ANCHOR_URL — printed for external anchoring)`);
  return rec;
}
function lastCheckpoint() {
  try {
    const raw = fs.readFileSync(CHECKPOINTS(), 'utf8').trim();
    if (!raw) return null;
    const lines = raw.split('\n');
    return JSON.parse(lines[lines.length - 1]);
  } catch { return null; }
}
function listCheckpoints() {
  try {
    const raw = fs.readFileSync(CHECKPOINTS(), 'utf8').trim();
    return raw ? raw.split('\n').map(l => JSON.parse(l)) : [];
  } catch { return []; }
}
function anchor(rec, target) {
  try {
    const u = new URL(target);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { 'content-type': 'application/json' }, timeout: 5000 },
      (res) => console.log(`[authragen] anchored checkpoint → ${target}: ${res.statusCode}`));
    req.on('error', (e) => console.warn(`[authragen] anchor failed (${target}): ${e.message}`));
    req.end(JSON.stringify({ type: 'authragen-checkpoint', ...rec }));
  } catch (e) { console.warn(`[authragen] bad AUTHRA_ANCHOR_URL: ${e.message}`); }
}
module.exports = { append, verify, readAll, byOrg, exportJsonl, evidenceBundle, checkpoint, listCheckpoints, lastCheckpoint };
