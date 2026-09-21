#!/usr/bin/env node
'use strict';

const ROUTES = [
  ['GET','/'], ['GET','/console'], ['GET','/v1/health'], ['HEAD','/v1/health'], ['GET','/health'],
  ['GET','/metrics'],
  ['GET','/v1/orgs/:id/pubkey'],
  ['POST','/v1/orgs'], ['GET','/v1/orgs'], ['GET','/v1/orgs/:id'],
  ['POST','/v1/orgs/:id/lock'], ['POST','/v1/orgs/:id/unlock'], ['PUT','/v1/orgs/:id/risk'],
  ['POST','/v1/orgs/:id/keys'], ['GET','/v1/orgs/:id/keys'], ['POST','/v1/orgs/:id/keys/rotate'],
  ['POST','/v1/blueprints'], ['GET','/v1/blueprints'], ['GET','/v1/blueprints/:id'],
  ['POST','/v1/passports'], ['GET','/v1/passports'], ['POST','/v1/passports/rotate'],
  ['POST','/v1/passports/:id/status'], ['POST','/v1/passports/:id/keys/revoke'], ['GET','/v1/passports/:id'],
  ['POST','/v1/delegate'], ['GET','/v1/delegations'],
  ['POST','/v1/policies'], ['GET','/v1/policies'], ['POST','/v1/policies/simulate'], ['GET','/v1/policies/conflicts'], ['PUT','/v1/policies/:id'],
  ['POST','/v1/authorize'], ['POST','/v1/execute'],
  ['POST','/v1/approvals/:id'], ['GET','/v1/approvals/:id'], ['GET','/v1/approvals'],
  ['POST','/v1/revoke'], ['GET','/v1/revoked'],
  ['POST','/v1/verify'], ['GET','/v1/verify'],
  ['GET','/v1/audit'], ['GET','/v1/audit/export'], ['POST','/v1/audit/evidence'],
  ['GET','/v1/audit/verify'], ['POST','/v1/audit/checkpoint'], ['GET','/v1/audit/checkpoints'],
];

const openapi = {
  openapi: '3.0.3',
  info: {
    title: 'AuthraGen API',
    version: '2.2.1',
    description: 'Vendor-neutral agent identity and exact-intent authorization trust layer.',
    license: { name: 'Apache-2.0', url: 'https://www.apache.org/licenses/LICENSE-2.0.html' },
    contact: { url: 'https://github.com/OpKnock/authragen' }
  },
  servers: [{ url: 'http://localhost:8787', description: 'Local development' }],
  security: [{ BearerAuth: [] }],
  components: {
    securitySchemes: {
      BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'AuthraGen API key or credential' },
      BootstrapToken: { type: 'apiKey', in: 'header', name: 'x-bootstrap-token' }
    },
    schemas: {
      Error: {
        type: 'object',
        required: ['error','message','request_id'],
        properties: {
          error: { type: 'string' },
          message: { type: 'string' },
          request_id: { type: 'string' }
        }
      },
      Intent: {
        type: 'object',
        required: ['v','passport_id','org_id','action','resource','amount_cents','nonce','iat','exp','aud'],
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
          iat: { type: 'integer' },
          exp: { type: 'integer' },
          aud: { type: 'string' }
        }
      },
      Decision: {
        type: 'object',
        properties: {
          decision: { type: 'string', enum: ['allow','step_up','deny','dry_run'] },
          action_token: { type: 'string', nullable: true },
          action_jti: { type: 'string', nullable: true },
          approval_id: { type: 'string', nullable: true },
          would: { type: 'string', nullable: true },
          risk: { type: 'object', nullable: true },
          request_id: { type: 'string' },
          policy_id: { type: 'string', nullable: true },
          policy_hash: { type: 'string', nullable: true },
          policy_version: { type: 'integer', nullable: true }
        }
      }
    }
  },
  paths: {}
};

for (const [method, rawPath] of ROUTES) {
  const pathKey = rawPath.replace(/:([^/]+)/g, '{$1}');
  const security = rawPath === '/v1/orgs' && method === 'POST' ? [{ BootstrapToken: [] }] : [{ BearerAuth: [] }];
  openapi.paths[pathKey] ||= {};
  openapi.paths[pathKey][method.toLowerCase()] = {
    summary: method + ' ' + rawPath,
    security,
    responses: {
      '200': { description: 'Success' },
      '201': { description: 'Created' },
      '202': { description: 'Accepted / step-up required' },
      '204': { description: 'No Content' },
      '400': { description: 'Bad Request', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '403': { description: 'Forbidden / policy denied', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '404': { description: 'Not Found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '410': { description: 'Expired or revoked', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '409': { description: 'Conflict / replay', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '429': { description: 'Rate Limited', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      '500': { description: 'Storage/Internal Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } }
    }
  };
}

process.stdout.write(JSON.stringify(openapi, null, 2) + '\n');
