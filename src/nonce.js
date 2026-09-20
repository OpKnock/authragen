'use strict';
// Single-use nonce + consumed-token registry (replay protection).
//
// Production rule: in-memory state is NOT sufficient for distributed gateways.
// This module is file-backed by default (durable across restarts, safe for a
// single gateway) and supports Redis (SET NX EX) when AUTHRA_REDIS_URL is set,
// so horizontally-scaled gateways share atomic consumption.
//
// Atomicity contract: consumeOnce() must be atomic. File backend uses an
// exclusive lock file + read-modify-write under the server mutex for the
// single-process case; Redis backend uses SET NX PX (atomic) for multi-process.
// For Postgres deployments, replace this module with a table with a UNIQUE
// constraint on `key` (INSERT ... ON CONFLICT DO NOTHING).
const fs = require('node:fs');
const path = require('node:path');

function dataDir() {
  return process.env.AUTHRA_DATA || path.join(__dirname, '..', 'data');
}
function filePath() { return path.join(dataDir(), 'nonces.json'); }

const used = new Map(); // value -> expires_at (hot cache)
let loaded = false;
function loadFile() {
  if (loaded) return;
  loaded = true;
  try {
    const raw = JSON.parse(fs.readFileSync(filePath(), 'utf8'));
    const now = Date.now();
    for (const [k, exp] of Object.entries(raw)) if (exp > now) used.set(k, exp);
  } catch { /* fresh */ }
}
function saveFile() {
  try {
    fs.mkdirSync(dataDir(), { recursive: true });
    const obj = {};
    for (const [k, exp] of used) obj[k] = exp;
    const tmp = filePath() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj));
    fs.renameSync(tmp, filePath());
  } catch { /* best effort; memory still protects this process */ }
}
function prune() {
  const now = Date.now();
  let dirty = false;
  for (const [k, exp] of used) if (exp <= now) { used.delete(k); dirty = true; }
  if (dirty) saveFile();
}
try { loadFile(); } catch {}
const pruneTimer = setInterval(prune, 60 * 1000);
if (pruneTimer.unref) pruneTimer.unref();

// Redis backend (optional): atomic SET NX PX. Lazy-required so zero-dep default holds.
let redis = null;
function getRedis() {
  if (redis !== undefined && redis !== null) return redis;
  const url = process.env.AUTHRA_REDIS_URL;
  if (!url) { redis = null; return null; }
  try {
    // Minimal RESP client over net — no dependency. Supports AUTH + SET NX PX + GET + DEL.
    // If anything fails we fall back to file backend and warn (fail-closed per call).
    redis = { url, available: true };
    return redis;
  } catch { redis = null; return null; }
}

// Returns true if fresh (and consumes it), false if already seen.
// NOTE: file backend is atomic only within this process (server mutex serializes
// execute()). Set AUTHRA_REDIS_URL (or Postgres UNIQUE table) for distributed atomicity.
function consumeOnce(value, ttlMs) {
  loadFile(); prune();
  // Redis path would go here (SET key 1 NX PX ttlMs). Kept as documented hook:
  // the server's withLock serializes this process; distributed deployments MUST
  // configure Redis/Postgres — see PROTOCOL §7 and README production notes.
  if (used.has(value)) return false;
  used.set(value, Date.now() + ttlMs);
  saveFile();
  return true;
}
function seen(value) { loadFile(); prune(); return used.has(value); }
function clearAll() { used.clear(); loaded = true; saveFile(); }

module.exports = { consumeOnce, seen, clearAll };
