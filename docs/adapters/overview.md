# Adapters Overview

AuthraGen provides adapters for popular agent runtimes. All follow the **exact-intent → authorize → single-use execute** contract.

## Common Contract

Every adapter implements:

```javascript
// 1. Guard function - wraps tool calls
const guardedTool = adapter.guardedTools({
  authorize: async (intent, signature) => { /* call gateway */ },
  execute: async (actionToken, intent, approval) => { /* call gateway */ },
  getPassportId: () => 'agt_...',
  getOrgId: () => 'org_...',
  getAgentKeypair: () => ({ pub, priv })
});

// 2. Use guarded tool instead of raw SDK
const result = await guardedTool.stripe.charge({ amount: 499, ... });
// Internally: createIntent → signIntent → authorize → execute
```

## Available Adapters

| Adapter | Runtime | Install | Auth Style |
|---------|---------|---------|------------|
| OpenAI | OpenAI Assistants/Functions | `require('./adapters/openai')` | Bearer/API Key |
| Anthropic | Claude Tools | `require('./adapters/anthropic')` | Bearer/API Key |
| Gemini | Google AI Tools | `require('./adapters/gemini')` | Bearer/API Key |
| MCP | Model Context Protocol | `require('./adapters/mcp')` | HTTP Authorization |
| A2A | Agent-to-Agent | `require('./adapters/a2a')` | HTTP Authorization |
| n8n | n8n Workflow Nodes | `require('./adapters/n8n')` | Header Auth |

## Adapter Contract (TypeScript)

```typescript
interface AdapterContract {
  // Required: called before each tool invocation
  authorize: (intent: Intent, signature: Signature) => Promise<Decision>;
  
  // Required: called after allow/step_up
  execute: (actionToken: string, intent: Intent, approval?: ApprovalCredential) => Promise<Receipt>;
  
  // Required: agent identity
  getPassportId: () => string;
  getOrgId: () => string;
  getAgentKeypair: () => KeyPair;
  
  // Optional: custom intent builder
  buildIntent?: (toolName: string, args: any) => Intent;
  
  // Optional: custom approval handler
  handleStepUp?: (approvalId: string) => Promise<ApprovalCredential>;
}
```

## OpenAI Adapter

```javascript
const { guardedTools } = require('./adapters/openai');

const tools = guardedTools({
  authorize: async (intent, sig) => agentClient.authorize(sig),
  execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
  getPassportId: () => 'agt_openai_1',
  getOrgId: () => 'org_abc',
  getAgentKeypair: () => openaiAgentKeypair
});

// Use with OpenAI SDK
const openai = new OpenAI({ apiKey: '...' });
const completion = await openai.chat.completions.create({
  model: 'gpt-4',
  tools: tools,  // guarded tools
  messages: [{ role: 'user', content: 'Charge $4.99' }]
});
```

## Anthropic Adapter

```javascript
const { guardedTools } = require('./adapters/anthropic');

const tools = guardedTools({
  authorize: async (intent, sig) => agentClient.authorize(sig),
  execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
  getPassportId: () => 'agt_anthropic_1',
  getOrgId: () => 'org_abc',
  getAgentKeypair: () => anthropicAgentKeypair
});

const anthropic = new Anthropic({ apiKey: '...' });
const message = await anthropic.messages.create({
  model: 'claude-3-opus',
  tools: tools,
  messages: [{ role: 'user', content: 'Charge $4.99' }]
});
```

## Gemini Adapter

```javascript
const { guardedTools } = require('./adapters/gemini');

const tools = guardedTools({
  authorize: async (intent, sig) => agentClient.authorize(sig),
  execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
  getPassportId: () => 'agt_gemini_1',
  getOrgId: () => 'org_abc',
  getAgentKeypair: () => geminiAgentKeypair
});

const genAI = new GoogleGenerativeAI('...');
const model = genAI.getGenerativeModel({ 
  model: 'gemini-1.5-pro',
  tools: tools
});
```

## MCP Adapter

```javascript
const { mcpGuard } = require('./adapters/mcp');

// Wrap MCP server
const server = new McpServer({ name: 'payments', version: '1.0.0' });

server.tool('charge', {
  amount: z.number(),
  currency: z.string()
}, mcpGuard({
  authorize: async (intent, sig) => agentClient.authorize(sig),
  execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
  getPassportId: () => 'agt_mcp_1',
  getOrgId: () => 'org_abc',
  getAgentKeypair: () => mcpAgentKeypair,
  // Audience binding for MCP
  aud: 'mcp:payments-server'
}));

// HTTP Authorization header automatically added
```

## A2A Adapter

```javascript
const { a2aClient, a2aServer } = require('./adapters/a2a');

// Client (delegating agent)
const client = a2aClient({
  authorize: async (intent, sig) => agentClient.authorize(sig),
  execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
  getPassportId: () => 'agt_a2a_client',
  getOrgId: () => 'org_abc',
  getAgentKeypair: () => a2aClientKeypair
});

// Server (receiving agent)
const server = a2aServer({
  onTask: async (task, context) => {
    // Verify incoming task has valid AuthraGen delegation
    const verified = await verifyA2ATask(task, context);
    if (!verified) throw new Error('Invalid delegation');
    return handleTask(task);
  }
});
```

## n8n Adapter

```javascript
const { n8nGuard } = require('./adapters/n8n');

// In n8n custom node
module.exports = {
  name: 'AuthraGen Stripe Charge',
  async execute(this: IExecuteFunctions) {
    return n8nGuard(this, {
      authorize: async (intent, sig) => agentClient.authorize(sig),
      execute: async (token, intent, approval) => agentClient.execute(token, intent, { approval }),
      getPassportId: () => 'agt_n8n_1',
      getOrgId: () => 'org_abc',
      getAgentKeypair: () => n8nAgentKeypair,
      // n8n credentials for gateway
      gatewayCredentials: 'authragenApi'
    });
  }
};
```

## Writing Custom Adapters

```javascript
// my-custom-adapter.js
const { createIntent, signIntent } = require('authragen');

function createGuardedTools(config) {
  const agent = new AuthraGen({ baseUrl: config.baseUrl });
  
  return {
    myTool: async (args) => {
      // 1. Build intent from tool args
      const intent = agent.createIntent({
        passport_id: config.getPassportId(),
        org_id: config.getOrgId(),
        action: 'my.custom.action',
        resource: args.resource,
        params: args,
        amount_cents: args.amount_cents || 0,
        destination: args.destination,
        tool: 'my-custom-tool',
        aud: config.aud || 'custom:my-service'
      });
      
      // 2. Sign with agent key
      const signed = agent.signIntent(intent, config.getAgentKeypair());
      
      // 3. Authorize
      const decision = await config.authorize(intent, signed);
      
      if (decision.decision === 'deny') {
        throw new Error(`Denied: ${decision.reason}`);
      }
      
      if (decision.decision === 'step_up') {
        const approval = await config.handleStepUp(decision.approval_id);
        return config.execute(decision.action_token, intent, { approval });
      }
      
      // 4. Execute
      return config.execute(decision.action_token, intent);
    }
  };
}

module.exports = { createGuardedTools };
```

## Next: [OpenAI Adapter](/adapters/openai)