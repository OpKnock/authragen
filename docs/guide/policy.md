# Policy Engine

## Philosophy

**Default-deny, explicit allow.** Empty arrays match nothing. Only explicit `*` matches all.

## Policy Structure

```javascript
{
  id: 'pol_abc123',
  org_id: 'org_xyz',
  version: 3,
  policyHash: 'sha256...',  // integrity hash of policy document
  updated_at: '2024-01-01T00:00:00Z',
  rules: [
    {
      effect: 'allow',           // 'allow' | 'step_up' | 'deny'
      actions: ['payments.charge'],  // exact or glob
      resources: ['stripe:invoice:*'], // exact or glob
      conditions: {
        max_spend_cents: 10000,
        max_depth: 1,
        environments: ['production'],
        blueprints: ['bp_payment'],
        agents: ['agt_*'],
        audiences: ['mcp:payments-svc'],
        tools: ['stripe'],
        time_windows: [
          { start: '09:00', end: '17:00', tz: 'UTC', days: [1,2,3,4,5] }
        ]
      },
      step_up: {
        min_approvals: 2,        // quorum
        required_roles: ['approver', 'admin']
      }
    }
  ],
  default: 'deny'  // implicit
}
```

## Rule Evaluation Order

1. **Deny rules** — any match → `deny` (deny-wins)
2. **Step-up rules** — any match → `step_up` (unless denied)
3. **Allow rules** — any match → `allow` (unless denied/stepped-up)
4. **Default** → `deny`

**Empty arrays = match nothing.** Use `["*"]` for match-all.

## Conditions

| Condition | Type | Description |
|-----------|------|-------------|
| `max_spend_cents` | integer | Max amount per action |
| `max_depth` | integer | Max delegation depth |
| `environments` | string[] | Allowed `environment` values |
| `blueprints` | string[] | Allowed blueprint IDs (glob) |
| `agents` | string[] | Allowed agent IDs (glob) |
| `audiences` | string[] | Required `aud` values (glob) |
| `tools` | string[] | Allowed `tool` values (glob) |
| `time_windows` | object[] | Cron-like time restrictions |

### Time Windows
```javascript
time_windows: [
  { start: '09:00', end: '17:00', tz: 'America/New_York', days: [1,2,3,4,5] },  // Mon-Fri
  { start: '10:00', end: '14:00', tz: 'UTC', days: [6] }  // Saturday
]
```

## Step-Up with Quorum

```javascript
step_up: {
  min_approvals: 2,              // distinct approvers required
  required_roles: ['approver', 'admin']  // roles that can approve
}
```

- Approvers must have distinct key IDs
- All approvals bound to same `intent_hash` + `action_jti` + `aud`
- Expiring (`AUTHRA_APPROVAL_TTL_S`)

## Simulation (Dry-Run)

```javascript
// Test policy without creating credential
const preview = await me.simulatePolicy({
  org_id: 'org_xyz',
  passport_id: 'agt_abc',
  intent: { action: 'payments.charge', amount_cents: 5000, ... },
  delegation_chain: [...]
});

// Response:
{
  would: 'ALLOW' | 'STEP-UP' | 'DENY',
  matched_rules: ['rule_id_1', ...],
  risk: { score: 45, factors: [...], band: 'medium', version: 2 },
  policy_id: 'pol_...',
  policy_hash: 'sha256...',
  policy_version: 3,
  request_id: 'rq_...'
}
```

## Conflict Detection

```javascript
const conflicts = await me.getPolicyConflicts({ org_id });

// Response:
{
  conflicts: [
    {
      type: 'shadowing',  // 'shadowing' | 'overlap' | 'contradiction'
      rules: ['rule_id_1', 'rule_id_2'],
      description: 'Rule 2 shadows Rule 1 for payments.charge in production'
    }
  ]
}
```

**Conflict types:**
- `shadowing`: Earlier rule never matches because later rule catches all cases
- `overlap`: Multiple rules match same request with different effects
- `contradiction`: Allow + deny for exact same conditions

## Policy Versioning

- Every policy change increments `version` and recomputes `policyHash`
- Receipts carry `policy_id`, `policy_hash`, `policy_version`
- Audit trail shows policy at time of decision
- Rollback: `PUT /v1/policies/:id { version: N }` (creates new version)

## API

| Operation | Endpoint | Auth |
|-----------|----------|------|
| Create | `POST /v1/policies` | admin |
| Update | `PUT /v1/policies/:id` | admin |
| Get | `GET /v1/policies/:id` | reporter+ |
| List | `GET /v1/policies` | reporter+ |
| Simulate | `POST /v1/policies/simulate` | reporter+ |
| Conflicts | `GET /v1/policies/conflicts?org_id` | reporter+ |

## Dashboard

- Visual rule builder with condition editor
- Policy version history with diff
- Simulation panel (test intent against live policy)
- Conflict detection with auto-fix suggestions
- Policy hash displayed for audit verification

## Next: [Approvals & Quorum](/guide/approvals)