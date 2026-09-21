'use strict';

const { spawn } = require('node:child_process');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

function get(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, res => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
  });
}

(async () => {
  const port = Number(process.env.AUTHRA_LOAD_PORT || 8899);
  const store = process.env.AUTHRA_LOAD_STORE || 'file';
  const data = process.env.AUTHRA_DATA || path.join(os.tmpdir(), 'authragen-load-' + Date.now());
  const env = {
    ...process.env,
    PORT: String(port),
    AUTHRA_DATA: data,
    AUTHRA_STORE: store,
    AUTHRA_KMS: 'file',
    NODE_ENV: 'development'
  };

  const child = spawn(process.execPath, ['src/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', d => { output += d.toString(); });
  child.stderr.on('data', d => { output += d.toString(); });

  try {
    const deadline = Date.now() + 30000;
    let ready = false;
    while (Date.now() < deadline) {
      try {
        if ((await get('http://127.0.0.1:' + port + '/v1/health')) === 200) { ready = true; break; }
      } catch {}
      await new Promise(r => setTimeout(r, 250));
    }
    if (!ready) throw new Error('server did not become healthy within 30s');

    const total = Number(process.env.AUTHRA_LOAD_REQUESTS || 5000);
    const concurrency = Number(process.env.AUTHRA_LOAD_CONCURRENCY || 100);
    const latencies = [];
    let next = 0;
    let failures = 0;

    async function worker() {
      while (true) {
        const i = next++;
        if (i >= total) return;
        const start = process.hrtime.bigint();
        try {
          const code = await get('http://127.0.0.1:' + port + '/v1/health');
          const ms = Number(process.hrtime.bigint() - start) / 1e6;
          latencies.push(ms);
          if (code !== 200) failures++;
        } catch {
          failures++;
        }
      }
    }

    await Promise.all(Array.from({ length: concurrency }, worker));
    latencies.sort((a, b) => a - b);
    const percentile = p => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))];
    const elapsed = latencies.length ? latencies.reduce((a,b) => a + b, 0) : 0;
    const result = {
      store,
      requests: total,
      concurrency,
      successes: total - failures,
      failures,
      p50_ms: Number(percentile(0.50).toFixed(2)),
      p95_ms: Number(percentile(0.95).toFixed(2)),
      p99_ms: Number(percentile(0.99).toFixed(2)),
      avg_ms: Number((elapsed / Math.max(1, latencies.length)).toFixed(2))
    };
    console.log(JSON.stringify(result));
    if (failures) throw new Error('load test recorded HTTP failures');
  } finally {
    child.kill('SIGTERM');
    await new Promise(resolve => child.once('exit', resolve));
    if (output && /fatal|error/i.test(output)) console.error(output);
  }
})().catch(err => { console.error(err); process.exit(1); });
