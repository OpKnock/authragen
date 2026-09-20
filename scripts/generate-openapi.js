#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const serverPath = path.join(__dirname, '..', 'src', 'server.js');
const serverCode = fs.readFileSync(serverPath, 'utf8');

const routes = [];
const routeRegex = /app\.(get|post|put|delete|patch)\(['"]([^'"]+)['"](?:,|$)/g;
let match;

while ((match = routeRegex.exec(serverCode)) !== null) {
  const method = match[1].toUpperCase();
  const path_ = match[2];
  routes.push({ method, path: path_ });
}

const openapi = {
  openapi: '3.0.3',
  info: {
    title: 'AuthraGen API',
    version: '2.1.0',
    description: 'Vendor-neutral Agent Passport trust layer — exact-authority identity for agents',
    license: { name: 'Apache-2.0', url: 'https://www.apache.org/licenses/LICENSE-2.0.html' },
    contact: { url: 'https://github.com/OpKnock/authragen' }
  },
  servers: [
    { url: 'http://localhost:8787/v1', description: 'Local development' },
    { url: 'https://api.authragen.dev/v1', description: 'Production' }
  ],
  security: [{ BearerAuth: [] }],
  components: {
    securitySchemes: {
      BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      BootstrapToken: { type: 'apiKey', in: 'header', name: 'x-bootstrap-token' }
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string' },
          message: { type: 'string' },
          request_id: { type: 'string' }
        },
        required: ['error', 'message', 'request_id']
      },
      Organization: {
        type: 'object',
        properties: {
          id: { type: 'string', pattern: '^org_' },
          name: { type: 'string' },
          org_pubkey: { type: 'string' },
          admin_key_id: { type: 'string' },
          admin_secret: { type: 'string' },
          risk_stepup: { type: 'integer' },
          risk_ceiling: { type: 'integer' },
          locked: { type: 'boolean' },
          created_at: { type: 'string', format: 'date-time' }
        }
      },
      Passport: {
        type: 'object',
        properties: {
          v: { type: 'integer', enum: [2] },
          id: { type: 'string', pattern: '^agt_' },
          did: { type: 'string', pattern: '^did:authragen:' },
          org_id: { type: 'string' },
          parent_id: { type: 'string', nullable: true },
          kind: { type: 'string', enum: ['agent', 'subagent'] },
          name: { type: 'string' },
          custody: { type: 'string', enum: ['self', 'server'] },
          blueprint_id: { type: 'string', nullable: true },
          owner: { type: 'string' },
          sponsor: { type: 'string' },
          team: { type: 'string' },
          environment: { type: 'string', enum: ['development', 'staging', 'production'] },
          purpose: { type: 'string' },
          model: { type: 'string' },
          provider: { type: 'string' },
          runtime: { type: 'string' },
          framework: { type: 'string' },
          created_at: { type: 'string', format: 'date-time' },
          last_seen: { type: 'string', format: 'date-time' },
          keys: {
            type: 'object',
            properties: {
              current: { type: 'object' },
              history: { type: 'array', items: { type: 'object' } }
            }
          },
          grace_period_s: { type: 'integer' },
          status: { type: 'string', enum: ['draft', 'pending_approval', 'active', 'suspended', 'quarantined', 'rotating', 'expired', 'revoked'] },
          iat: { type: 'string', format: 'date-time' },
          exp: { type: 'string', format: 'date-time' },
          signature: { type: 'string' }
        }
      },
      Intent: {
        type: 'object',
        required: ['passport_id', 'org_id', 'action', 'resource', 'amount_cents', 'destination', 'tool', 'aud'],
        properties: {
          v: { type: 'integer', enum: [2] },
          passport_id: { type: 'string' },
          org_id: { type: 'string' },
          action: { type: 'string' },
          resource: { type: 'string' },
          params: { type: 'object' },
          amount_cents: { type: 'integer', minimum: 0 },
          destination: { type: 'string' },
          tool: { type: 'string' },
          nonce: { type: 'string', minLength: 16 },
          iat: { type: 'string', format: 'date-time' },
          exp: { type: 'string', format: 'date-time' },
          aud: { type: 'string' }
        }
      },
      Decision: {
        type: 'object',
        properties: {
          decision: { type: 'string', enum: ['allow', 'step_up', 'deny', 'dry_run'] },
          action_token: { type: 'string', nullable: true },
          action_jti: { type: 'string', nullable: true },
          approval_id: { type: 'string', nullable: true },
          would: { type: 'string', enum: ['ALLOW', 'STEP-UP', 'DENY'], nullable: true },
          risk: { type: 'object' },
          request_id: { type: 'string' },
          policy_id: { type: 'string' },
          policy_hash: { type: 'string' },
          policy_version: { type: 'integer' },
          reason: { type: 'string', nullable: true }
        }
      },
      Receipt: {
        type: 'object',
        properties: {
          id: { type: 'string', pattern: '^rcpt_' },
          type: { type: 'string', enum: ['authorized', 'executed', 'denied', 'replay'] },
          request_id: { type: 'string' },
          intent_hash: { type: 'string' },
          action_jti: { type: 'string' },
          approval_jti: { type: 'string' },
          executor: { type: 'object' },
          policy_id: { type: 'string' },
          policy_hash: { type: 'string' },
          policy_version: { type: 'integer' },
          risk: { type: 'object' },
          timestamp: { type: 'string', format: 'date-time' },
          prev_receipt_hash: { type: 'string' }
        }
      },
      RevocationEntry: {
        type: 'object',
        properties: {
          seq: { type: 'integer' },
          type: { type: 'string', enum: ['org', 'blueprint', 'passport', 'key', 'token', 'action', 'apikey'] },
          id: { type: 'string' },
          reason: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
          cascade: { type: 'array', items: { type: 'string' } }
        }
      }
    }
  },
  paths: {}
};

for (const route of routes) {
  const pathKey = route.path.replace(/:([^/]+)/g, '{$1}');
  if (!openapi.paths[pathKey]) openapi.paths[pathKey] = {};
  
  openapi.paths[pathKey][route.method.toLowerCase()] = {
    summary: `${route.method} ${route.path}`,
    responses: {
      '200': { description: 'Success' },
      '400': { description: 'Bad Request', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '403': { description: 'Forbidden', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '404': { description: 'Not Found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '429': { description: 'Rate Limited', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }
    },
    security: route.path === '/orgs' && route.method === 'POST' ? [{ BootstrapToken: [] }] : [{ BearerAuth: [] }]
  };
}

console.log(JSON.stringify(openapi, null, 2));