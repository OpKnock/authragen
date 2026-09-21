'use strict';

const assert = require('node:assert/strict');
const { PostgresStore } = require('../src/store/postgres');
const { RedisStore } = require('../src/store/redis');

async function testPostgres() {
  const url = process.env.DATABASE_URL;
  if (!url) return false;
  const a = new PostgresStore(url);
  const b = new PostgresStore(url);
  await Promise.all([a.init(), b.init()]);

  const id = 'org_smoke_' + Date.now();
  await a.setRecord('orgs', { id, org_id: id, name: 'smoke', created_at: new Date().toISOString() });
  const rows = await b.dumpCollection('orgs');
  assert(rows.some(r => r.id === id), 'Postgres second instance must observe first instance writes');

  const token = 'token_' + Date.now();
  const attempts = await Promise.all(Array.from({ length: 32 }, (_, i) =>
    a.checkAndDebitExecution('org_smoke', 'nonce_' + i, 'jti_' + i, token, 10, 100)
  ));
  assert.equal(attempts.filter(x => x.success).length, 10, 'Postgres token spend must enforce cap atomically');

  const replayToken = 'replay_' + Date.now();
  const replay = await b.checkAndDebitExecution('org_smoke', 'same_nonce', 'same_jti', replayToken, 1, 100);
  const replay2 = await a.checkAndDebitExecution('org_smoke', 'same_nonce', 'same_jti', replayToken, 1, 100);
  assert.notEqual(replay.success, replay2.success, 'Postgres replay reservation must be single-winner');

  await a.deleteRecord('orgs', id);
  await Promise.all([a.close(), b.close()]);
  console.log('postgres multi-instance + atomicity: PASS');
  return true;
}

async function testRedis() {
  const url = process.env.REDIS_URL;
  if (!url) return false;
  const a = new RedisStore(url);
  const b = new RedisStore(url);
  await Promise.all([a.connect(), b.connect()]);

  const id = 'org_smoke_' + Date.now();
  await a.setRecord('orgs', { id, org_id: id, name: 'smoke', created_at: new Date().toISOString() });
  const rows = await b.dumpCollection('orgs');
  assert(rows.some(r => r.id === id), 'Redis second instance must observe first instance writes');

  const token = 'token_' + Date.now();
  const attempts = await Promise.all(Array.from({ length: 32 }, (_, i) =>
    a.checkAndDebitExecution('org_smoke', 'nonce_' + i, 'jti_' + i, token, 10, 100)
  ));
  assert.equal(attempts.filter(x => x.success).length, 10, 'Redis token spend must enforce cap atomically');

  const replayToken = 'replay_' + Date.now();
  const replay = await b.checkAndDebitExecution('org_smoke', 'same_nonce', 'same_jti', replayToken, 1, 100);
  const replay2 = await a.checkAndDebitExecution('org_smoke', 'same_nonce', 'same_jti', replayToken, 1, 100);
  assert.notEqual(replay.success, replay2.success, 'Redis replay reservation must be single-winner');

  await a.deleteRecord('orgs', id);
  await Promise.all([a.close(), b.close()]);
  console.log('redis multi-instance + atomicity: PASS');
  return true;
}

(async () => {
  const pg = await testPostgres();
  const redis = await testRedis();
  if (!pg && !redis) throw new Error('persistence smoke requires DATABASE_URL and/or REDIS_URL');
})().catch(err => { console.error(err); process.exit(1); });
