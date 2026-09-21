'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const audit = require('../src/audit');

class FakeDurableStore {
  constructor(seed = {}) {
    this.data = Object.fromEntries(Object.entries(seed).map(([k, v]) => [k, new Map((v || []).map(x => [x.id, structuredClone(x)]))]));
  }
  backend() { return 'postgres'; }
  all(collection) { return Array.from(this.data[collection]?.values() || []); }
  put(collection, obj) {
    if (!this.data[collection]) this.data[collection] = new Map();
    this.data[collection].set(obj.id, structuredClone(obj));
    return obj;
  }
  async flush() {}
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authragen-audit-'));
  process.env.AUTHRA_DATA = dir;

  const first = new FakeDurableStore();
  audit.configureStore(first);

  const r1 = audit.append({ org_id: 'org_test', actor: 'agent_1', action: 'data.read', resource: 'x:1', decision: 'allow', request_id: 'rq_1' });
  const r2 = audit.append({ org_id: 'org_test', actor: 'agent_1', action: 'data.write', resource: 'x:1', decision: 'executed', request_id: 'rq_2' });

  assert.equal(r1.seq, 1);
  assert.equal(r2.seq, 2);
  assert.equal(r2.prev_hash, r1.hash);
  assert.deepEqual(audit.verify(), { ok: true, count: 2, head: r2.hash });
  await audit.flush();

  const persisted = first.all('audit_receipts');
  assert.equal(persisted.length, 2);
  assert.equal(fs.existsSync(path.join(dir, 'audit.jsonl')), false, 'remote mode must not depend on local audit.jsonl');

  const restarted = new FakeDurableStore({ audit_receipts: persisted });
  audit.configureStore(restarted);
  assert.equal(audit.readAll().length, 2);
  assert.equal(audit.byOrg('org_test').length, 2);
  assert.equal(audit.verify().ok, true);

  const signer = { alg: 'EdDSA', pubkey: 'test-pub', signCanonical: async () => 'test-signature' };
  const cp = await audit.checkpoint(signer);
  await audit.flush();
  assert.equal(restarted.all('audit_checkpoints').length, 1);
  assert.equal(audit.listCheckpoints()[0].hash, cp.hash);
  assert.equal(audit.lastCheckpoint().hash, cp.hash);

  console.log('centralized audit persistence: PASS');
})().catch(err => {
  console.error(err);
  process.exit(1);
});
