'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const http = require('node:http');

function request(port, method, pathName, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ hostname: '127.0.0.1', port, path: pathName, method, headers: {
      'content-type': 'application/json',
      ...(data ? { 'content-length': data.length } : {}),
      ...headers
    }}, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null; try { parsed = text ? JSON.parse(text) : null; } catch {}
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function waitReady(port) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const r = await request(port, 'GET', '/v1/health');
      if (r.status === 200) return;
    } catch {}
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('instance on port ' + port + ' did not become healthy');
}

(async () => {
  const store = String(process.env.AUTHRA_MULTI_STORE || '').toLowerCase();
  if (!['postgres', 'redis'].includes(store)) throw new Error('AUTHRA_MULTI_STORE must be postgres or redis');
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'authragen-multi-'));
  const ports = [8911, 8912];
  const envBase = {
    ...process.env,
    NODE_ENV: 'development',
    AUTHRA_STORE: store,
    AUTHRA_KMS: 'file',
    AUTHRA_DATA: data
  };
  const children = ports.map(port => spawn(process.execPath, ['src/server.js'], {
    env: { ...envBase, PORT: String(port) },
    stdio: 'ignore'
  }));

  try {
    await Promise.all(ports.map(waitReady));
    const bootstrapPath = path.join(data, 'bootstrap.token');
    const bootstrap = fs.readFileSync(bootstrapPath, 'utf8').trim();
    assert(bootstrap, 'bootstrap token must exist');

    const created = await request(ports[0], 'POST', '/v1/orgs', { name: 'multi-instance' }, { 'x-bootstrap-token': bootstrap });
    assert.equal(created.status, 201, 'first instance must create the organization');
    const adminSecret = created.body.admin_secret;
    assert(adminSecret);

    const seen = await request(ports[1], 'GET', '/v1/orgs', null, { authorization: 'Bearer ' + adminSecret });
    assert.equal(seen.status, 200, 'second instance must observe org created by first');
    assert.equal(seen.body.orgs[0].name, 'multi-instance');

    const lock = await request(ports[0], 'POST', '/v1/orgs/' + created.body.id + '/lock', null, { authorization: 'Bearer ' + adminSecret });
    assert.equal(lock.status, 200, 'first instance must lock the organization');

    const locked = await request(ports[1], 'GET', '/v1/orgs/' + created.body.id, null, { authorization: 'Bearer ' + adminSecret });
    assert.equal(locked.status, 200);
    assert.equal(locked.body.locked, true, 'second instance must observe lock mutation after remote refresh');

    console.log(store + ' two-instance HTTP state propagation: PASS');
  } finally {
    for (const child of children) child.kill('SIGTERM');
    await Promise.all(children.map(child => new Promise(resolve => child.once('exit', resolve))));
  }
})().catch(err => { console.error(err); process.exit(1); });
