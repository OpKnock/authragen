'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { AuthraGen } = require('../sdk-js/authragen');

const BASE_URL = process.env.AUTHRA_BENCH_URL || 'http://localhost:8787';
const CONCURRENCY = parseInt(process.env.AUTHRA_BENCH_CONCURRENCY || '10', 10);
const DURATION = parseInt(process.env.AUTHRA_BENCH_DURATION || '30', 10);
const ORG_ID = process.env.AUTHRA_BENCH_ORG_ID;
const ADMIN_KEY = process.env.AUTHRA_BENCH_ADMIN_KEY;
const AGENT_KEYPAIR = process.env.AUTHRA_BENCH_AGENT_KEYPAIR;

if (!ORG_ID || !ADMIN_KEY || !AGENT_KEYPAIR) {
  console.error('Required env: AUTHRA_BENCH_ORG_ID, AUTHRA_BENCH_ADMIN_KEY, AUTHRA_BENCH_AGENT_KEYPAIR');
  process.exit(1);
}

const admin = new AuthraGen({ baseUrl: BASE_URL, key: ADMIN_KEY });
const agent = new AuthraGen({ baseUrl: BASE_URL });
const keypair = JSON.parse(AGENT_KEYPAIR);

let agentId = null;
let actionToken = null;

async function httpRequest(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function setup() {
  console.log('Setting up benchmark...');
  
  // Create agent
  const agentData = await admin.createAgent(ORG_ID, 'bench-agent', { pubkey: keypair.pub });
  agentId = agentData.id;
  console.log('Created agent:', agentId);
  
  // Create intent and get action token
  const intent = agent.createIntent({
    passport_id: agentId,
    org_id: ORG_ID,
    action: 'bench.test',
    resource: 'bench:resource',
    params: { iteration: 0 },
    amount_cents: 1,
    destination: 'bench:dest',
    tool: 'bench',
    aud: 'bench:service'
  });
  
  const signed = agent.signIntent(intent, keypair);
  const decision = await agent.authorize(signed);
  
  if (decision.decision !== 'allow') {
    throw new Error('Setup authorize failed: ' + JSON.stringify(decision));
  }
  
  actionToken = decision.action_token;
  console.log('Got action token, ready to benchmark');
}

function makeIntent(iteration) {
  return agent.createIntent({
    passport_id: agentId,
    org_id: ORG_ID,
    action: 'bench.test',
    resource: 'bench:resource',
    params: { iteration },
    amount_cents: 1,
    destination: 'bench:dest',
    tool: 'bench',
    aud: 'bench:service'
  });
}

async function benchmarkAuthorize() {
  const intent = makeIntent(Date.now());
  const signed = agent.signIntent(intent, keypair);
  
  const start = process.hrtime.bigint();
  const decision = await agent.authorize(signed);
  const end = process.hrtime.bigint();
  
  return { 
    latency: Number(end - start) / 1e6,
    success: decision.decision === 'allow' || decision.decision === 'step_up'
  };
}

async function benchmarkExecute() {
  const intent = makeIntent(Date.now());
  
  const start = process.hrtime.bigint();
  try {
    await agent.execute(actionToken, intent);
    const end = process.hrtime.bigint();
    return { latency: Number(end - start) / 1e6, success: true };
  } catch (e) {
    const end = process.hrtime.bigint();
    return { latency: Number(end - start) / 1e6, success: false, error: e.message };
  }
}

async function runBenchmark(name, fn, concurrency, duration) {
  console.log(`\nRunning ${name} (concurrency=${concurrency}, duration=${duration}s)...`);
  
  const latencies = [];
  const errors = [];
  let completed = 0;
  let running = 0;
  let stopped = false;
  
  const startTime = Date.now();
  const endTime = startTime + duration * 1000;
  
  async function worker() {
    while (!stopped && Date.now() < endTime) {
      running++;
      try {
        const result = await fn();
        latencies.push(result.latency);
        if (!result.success) errors.push(result.error || 'failed');
      } catch (e) {
        errors.push(e.message);
      }
      running--;
      completed++;
    }
  }
  
  const workers = Array(concurrency).fill(null).map(() => worker());
  await Promise.all(workers);
  stopped = true;
  
  const actualDuration = (Date.now() - startTime) / 1000;
  
  latencies.sort((a, b) => a - b);
  
  const p50 = latencies[Math.floor(latencies.length * 0.5)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];
  const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  
  console.log(`  Completed: ${completed} requests in ${actualDuration.toFixed(2)}s`);
  console.log(`  Throughput: ${(completed / actualDuration).toFixed(2)} req/s`);
  console.log(`  Latency (ms): avg=${avg.toFixed(2)}, p50=${p50.toFixed(2)}, p95=${p95.toFixed(2)}, p99=${p99.toFixed(2)}`);
  console.log(`  Errors: ${errors.length}`);
  if (errors.length > 0) console.log(`  Error samples: ${errors.slice(0, 3).join(', ')}`);
  
  return { completed, duration: actualDuration, throughput: completed / actualDuration, latencies, errors };
}

async function main() {
  console.log('AuthraGen Benchmark');
  console.log('===================');
  console.log(`Target: ${BASE_URL}`);
  console.log(`Org: ${ORG_ID}`);
  console.log(`Concurrency: ${CONCURRENCY}`);
  console.log(`Duration: ${DURATION}s`);
  
  await setup();
  
  await runBenchmark('Authorize', benchmarkAuthorize, CONCURRENCY, DURATION);
  
  // Re-authorize for fresh token
  const intent = makeIntent(Date.now());
  const signed = agent.signIntent(intent, keypair);
  const decision = await agent.authorize(signed);
  if (decision.decision === 'allow') actionToken = decision.action_token;
  
  await runBenchmark('Execute', benchmarkExecute, CONCURRENCY, DURATION);
  
  console.log('\nBenchmark complete!');
}

main().catch(e => {
  console.error('Benchmark failed:', e);
  process.exit(1);
});