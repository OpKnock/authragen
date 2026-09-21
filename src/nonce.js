'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { getStore } = require('./store');

function dataDir() {
  return process.env.AUTHRA_DATA || path.join(__dirname, '..', 'data');
}
function filePath() { return path.join(dataDir(), 'nonces.json'); }

const used = new Map();
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

function getBackend() {
  const store = getStore();
  if (store && store.consumeNonce && store.consumeActionJTI) {
    return 'distributed';
  }
  return 'file';
}

async function consumeOnce(value, ttlMs) {
  const backend = getBackend();
  if (backend === 'distributed') {
    const store = getStore();
    return await store.consumeNonce('global', value, Math.ceil(ttlMs / 1000));
  }
  loadFile(); prune();
  if (used.has(value)) return false;
  used.set(value, Date.now() + ttlMs);
  saveFile();
  return true;
}

async function consumeActionJTI(jti, ttlMs) {
  const backend = getBackend();
  if (backend === 'distributed') {
    const store = getStore();
    return await store.consumeActionJTI(jti, Math.ceil(ttlMs / 1000));
  }
  return consumeOnce('att:' + jti, ttlMs);
}

function seen(value) { loadFile(); prune(); return used.has(value); }
function clearAll() { used.clear(); loaded = true; saveFile(); }

module.exports = { consumeOnce, consumeActionJTI, seen, clearAll };