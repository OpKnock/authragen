'use strict';

const client = require('prom-client');

const register = new client.Registry();
client.collectDefaultMetrics({ register, prefix: 'authragen_' });

const httpRequestsTotal = new client.Counter({
  name: 'authragen_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register]
});

const httpRequestDuration = new client.Histogram({
  name: 'authragen_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register]
});

const authorizeDecisions = new client.Counter({
  name: 'authragen_authorize_decisions_total',
  help: 'Total number of authorization decisions',
  labelNames: ['decision', 'org_id'],
  registers: [register]
});

const activePassports = new client.Gauge({
  name: 'authragen_active_passports',
  help: 'Number of active passports',
  labelNames: ['org_id'],
  registers: [register]
});

const revocationFeedSeq = new client.Gauge({
  name: 'authragen_revocation_feed_seq',
  help: 'Current revocation feed sequence number',
  labelNames: ['org_id'],
  registers: [register]
});

const auditChainHead = new client.Gauge({
  name: 'authragen_audit_chain_head',
  help: 'Audit chain head hash (as number)',
  labelNames: ['org_id'],
  registers: [register]
});

const storageBackend = new client.Gauge({
  name: 'authragen_storage_backend',
  help: 'Storage backend type (1=file, 2=postgres, 3=redis)',
  labelNames: ['backend'],
  registers: [register]
});

function setStorageBackend(backend) {
  storageBackend.set({ backend: 'file' }, 0);
  storageBackend.set({ backend: 'postgres' }, 0);
  storageBackend.set({ backend: 'redis' }, 0);
  storageBackend.set({ backend }, 1);
}

module.exports = {
  register,
  httpRequestsTotal,
  httpRequestDuration,
  authorizeDecisions,
  activePassports,
  revocationFeedSeq,
  auditChainHead,
  storageBackend,
  setStorageBackend,
  createMetrics: () => ({
    register,
    httpRequestsTotal,
    httpRequestDuration,
    authorizeDecisions,
    activePassports,
    revocationFeedSeq,
    auditChainHead,
    storageBackend,
    setStorageBackend,
  })
};