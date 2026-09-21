'use strict';

const fs = require('node:fs');
const path = require('node:path');

function resolveDataDir() { return process.env.AUTHRA_DATA || path.join(__dirname, '..', '..', 'data'); }
const DATA_DIR = resolveDataDir();
fs.mkdirSync(DATA_DIR, { recursive: true });

const FILES = ['orgs', 'passports', 'tokens', 'policies', 'revocations', 'approvals', 'apikeys', 'blueprints'];
const mem = {};

function loadAll() {
  const dir = resolveDataDir();
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  for (const f of FILES) {
    const p = path.join(dir, f + '.json');
    try { mem[f] = JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch { mem[f] = {}; }
  }
}

function save(f) {
  const dir = resolveDataDir();
  try {
    const tmp = path.join(dir, f + '.json.tmp');
    fs.writeFileSync(tmp, JSON.stringify(mem[f], null, 2));
    fs.renameSync(tmp, path.join(dir, f + '.json'));
  } catch (e) {
    throw Object.assign(new Error('storage write failed for ' + f + ': ' + e.message), { code: 'storage_error' });
  }
}

function reload() { loadAll(); }
loadAll();

const store = {
  get(col, id) { if (!mem[col]) return null; return mem[col][id] || null; },
  all(col) { if (!mem[col]) return []; return Object.values(mem[col]); },
  byOrg(col, org_id) { if (!mem[col]) return []; return Object.values(mem[col]).filter(x => x.org_id === org_id); },
  list(col, { org_id = null, status = null, limit = 100, offset = 0, q = null } = {}) {
    if (!mem[col]) return { items: [], total: 0 };
    let arr = Object.values(mem[col]);
    if (org_id) arr = arr.filter(x => x.org_id === org_id);
    if (status) arr = arr.filter(x => (x.status || x.lifecycle || '') === status);
    if (q) {
      const needle = String(q).toLowerCase();
      arr = arr.filter(x => JSON.stringify([x.name, x.id, x.owner, x.team, x.environment, x.model, x.framework, x.blueprint_id]).toLowerCase().includes(needle));
    }
    arr = arr.slice().sort((a, b) => (b.created_at || b.iat || 0) - (a.created_at || a.iat || 0));
    const total = arr.length;
    return { items: arr.slice(offset, offset + limit), total };
  },
  put(col, obj) { if (!mem[col]) mem[col] = {}; mem[col][obj.id] = obj; save(col); return obj; },
  del(col, id) { if (mem[col]) { delete mem[col][id]; save(col); } },
  has(col, id) { return !!(mem[col] && mem[col][id]); },
  backend() { return 'json-file (dev/test; use Postgres in production)'; },
};

module.exports = { store, DATA_DIR, reload: loadAll };