'use strict';

// Battle-scale hot-path test: full authorize → execute bursts against a clean
// temporary gateway, then audit-chain + evidence verification.
//
//   AUTHRA_BATTLE_REQUESTS=2000 AUTHRA_BATTLE_CONCURRENCY=50 node test/battle.js
//
// Asserts zero failed executions and a verifiable audit chain. Every iteration
// uses a fresh nonce, so any replay-protection false positive fails loudly.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { AuthraGen } = require('../sdk-js/authragen');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function waitHealth(base, tries = 120) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(base + '/v1/health');
      if (r.ok) return true;
    } catch {}
    await sleep(250);
  }
  throw new Error('gateway never became healthy at ' + base);
}

(async () => {
  // Defaults fit the gateway's enforced 180 req/min authorize+execute budgets
  // (the harness honors 429 + Retry-After like a production client). Raise both
  // for heavier soaks: AUTHRA_BATTLE_REQUESTS=2000 AUTHRA_BATTLE_CONCURRENCY=50.
  const REQUESTS = Number(process.env.AUTHRA_BATTLE_REQUESTS || 240);
  const CONCURRENCY = Number(process.env.AUTHRA_BATTLE_CONCURRENCY || 12);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'authragen-battle-'));
  const port = 18800 + Math.floor(Math.random() * 600);
  const base = `http://127.0.0.1:${port}`;
  const child = cp.spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
    env: { ...process.env, PORT: String(port), AUTHRA_DATA: tmp },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let childOutput = '';
  child.stdout.on('data', d => { childOutput += d.toString(); });
  child.stderr.on('data', d => { childOutput += d.toString(); });

  try {
    await waitHealth(base);

    const boot = fs.readFileSync(path.join(tmp, 'bootstrap.token'), 'utf8').trim();
    const org = await new AuthraGen({ baseUrl: base, bootstrap: boot }).createOrg('battle-' + Date.now().toString(36));
    const admin = new AuthraGen({ baseUrl: base, key: org.admin_secret });
    const orgId = org.id;

    const kp = admin.generateKeypair();
    const agent = await admin.createAgent(orgId, 'battle-agent', { pubkey: kp.pub });
    const me = new AuthraGen({ baseUrl: base });

    // Warmup so JIT/GC settle before measurement.
    for (let i = 0; i < 20; i++) {
      const w = me.intent({ passport_id: agent.id, org_id: orgId, action: 'data.read', resource: 'battle:warm:' + i });
      const dw = await me.authorize(w, me.signIntent(w, kp));
      if (dw.decision !== 'allow') throw new Error('warmup authorize did not allow: ' + JSON.stringify(dw).slice(0, 200));
      await me.execute(dw.action_token, w);
    }

    const latencies = [];
    const serverLat = [];
    async function timed(fn) {
      const s = process.hrtime.bigint();
      try {
        return await fn();
      } finally {
        serverLat.push(Number(process.hrtime.bigint() - s) / 1e6);
      }
    }
    let next = 0;
    let failures = 0;
    let retries = 0;
    let firstError = null;

    // Production-grade client behavior: honor 429 + Retry-After until the
    // server's rolling window drains (bounded by a per-call deadline).
    // Anything else fails fast and loud.
    async function withRetry(fn, deadlineMs = 180000) {
      const start = Date.now();
      let attempt = 0;
      for (;;) {
        try {
          return await fn();
        } catch (e) {
          const body = e && e.body;
          const retryable = e && (e.status === 429 || (body && body.error === 'rate_limited'));
          const waitMs = Math.min(15000, (Number(body && body.retry_after) || 0) * 1000 + 250 * 2 ** attempt + Math.floor(Math.random() * 250));
          if (!retryable || Date.now() + waitMs - start > deadlineMs) throw e;
          retries++;
          await sleep(waitMs);
          attempt++;
        }
      }
    }

    async function worker() {
      while (true) {
        const i = next++;
        if (i >= REQUESTS) return;
        const start = process.hrtime.bigint();
        try {
          // Fresh signed intent per attempt: a 429 backoff can outlast the
          // intent TTL, and the signature covers iat/exp, so re-sign instead
          // of replaying a stale intent.
          const { d, intent } = await withRetry(async () => {
            const attempt = me.intent({ passport_id: agent.id, org_id: orgId, action: 'data.read', resource: 'battle:record:' + i });
            const decision = await timed(() => me.authorize(attempt, me.signIntent(attempt, kp)));
            return { d: decision, intent: attempt };
          });
          if (d.decision !== 'allow') throw new Error('expected allow, got ' + d.decision);
          await withRetry(() => timed(() => me.execute(d.action_token, intent)));
          latencies.push(Number(process.hrtime.bigint() - start) / 1e6);
        } catch (e) {
          failures++;
          if (!firstError) firstError = JSON.stringify((e && e.body) || (e && e.message) || e).slice(0, 300);
        }
      }
    }

    const t0 = Date.now();
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    const wallMs = Date.now() - t0;

    latencies.sort((a, b) => a - b);
    serverLat.sort((a, b) => a - b);
    const pct = (arr, p) => arr.length ? Number(arr[Math.min(arr.length - 1, Math.floor(arr.length * p))].toFixed(2)) : 0;
    const result = {
      requests: REQUESTS,
      concurrency: CONCURRENCY,
      successes: REQUESTS - failures,
      failures,
      retries_429: retries,
      first_error: firstError,
      wall_ms: wallMs,
      throughput_rps: Number((latencies.length / (wallMs / 1000)).toFixed(1)),
      authorize_execute_p50_ms: pct(latencies, 0.5),
      authorize_execute_p95_ms: pct(latencies, 0.95),
      authorize_execute_p99_ms: pct(latencies, 0.99),
      server_only_p50_ms: pct(serverLat, 0.5),
      server_only_p95_ms: pct(serverLat, 0.95),
      server_only_p99_ms: pct(serverLat, 0.99),
    };

    const chain = await admin.auditVerify(orgId);
    result.audit_chain_ok = chain.ok === true;
    result.audit_receipts = chain.count;
    const ev = await admin.evidenceBundle(orgId, {});
    result.evidence_bundle_ok = !!ev.bundle_hash;
    const feed = await admin.revoked(orgId, 0);
    result.revocation_feed_ok = Array.isArray(feed.revocations);

    console.log(JSON.stringify(result));
    if (failures || !result.audit_chain_ok || !result.evidence_bundle_ok) {
      throw new Error('battle test failed: ' + JSON.stringify(result).slice(0, 500));
    }
    console.log(`battle: ${result.successes}/${REQUESTS} authorize+execute pairs, p99 ${result.authorize_execute_p99_ms}ms, chain verified (${result.audit_receipts} receipts)`);
  } finally {
    try { child.kill('SIGTERM'); } catch {}
    await sleep(500);
  }
})().catch(err => { console.error(err); process.exit(1); });
