# Python SDK

## Installation

```bash
pip install authragen
# or
pip install -e ./sdk_python  # local development
```

## Quick Start

```python
from authragen import AuthraGen

# Admin client
admin = AuthraGen(base_url='http://localhost:8787', key=os.environ['AUTHRA_ADMIN_KEY'])

# Agent client (no keys)
agent = AuthraGen(base_url='http://localhost:8787')
```

## Core Methods

### `generate_keypair()`

```python
kp = admin.generate_keypair()
# {'pub': 'base64url...', 'd': 'base64url...'}
```

### `create_agent(org_id, name, **options)`

```python
agent = admin.create_agent('org_abc', 'shopper',
    pubkey=kp['pub'],
    blueprint_id='bp_...',
    owner='team-platform',
    sponsor='jane@acme.com',
    team='platform',
    environment='production',
    purpose='payment-processing',
    model='gpt-4',
    provider='openai',
    runtime='python',
    framework='langchain',
    custodied=False
)
```

### `create_intent(**params)`

```python
intent = agent.create_intent(
    passport_id='agt_abc',
    org_id='org_xyz',
    action='payments.charge',
    resource='stripe:invoice:inv_42',
    params={'customer': 'cus_123'},
    amount_cents=499,
    destination='acct_merchant',
    tool='stripe',
    aud='mcp:payments-svc'
)
```

### `sign_intent(intent, keypair)`

```python
signature = agent.sign_intent(intent, agent_keypair)
# base64url Ed25519 signature string
```

### `authorize(signed_intent, **options)`

```python
decision = agent.authorize(intent, signature)
# or dry-run:
preview = agent.authorize(signed_intent, dry_run=True)
```

### `execute(action_token, intent, **options)`

```python
receipt = agent.execute(action_token, intent, approval=approval_credential)
```

### `sign_delegation(delegation, keypair)`

```python
delegation = {
    'v': 2,
    'jti': 'tkn_...',
    'org_id': 'org_xyz',
    'sub': 'agt_child',
    'parent_jti': 'tkn_parent',
    'scope': ['payments.charge'],
    'resources': ['stripe:invoice:*'],
    'constraints': {
        'max_spend_cents': 10000,
        'not_after': '2024-12-31T23:59:59Z',
        'max_depth': 1
    },
    'kid': 'kid_1',
    'iat': datetime.utcnow().isoformat() + 'Z'
}

signed = agent.sign_delegation(delegation, delegator_keypair)
admin.register_delegation(signed)
```

### `approve(approval_id, decision)`

```python
result = admin.approve('apr_abc123', approve=True, by_='Authorized')
```

### `revoke(**params)`

```python
admin.revoke(type='passport', id='agt_abc', reason='Decommissioned')
# For keys:
admin.revoke(type='key', id='agt_abc', kid='kid_2', reason='Compromised')
```

### `verify_offline_static(envelope, org_pubkey)`

**Static method - no network:**

```python
from authragen import AuthraGen

result = AuthraGen.verify_offline_static(envelope, org_pubkey)
# {
#     'signature_valid': True,
#     'credential_valid': True,
#     'expiry_valid': True,
#     'revocation_freshness': 'fresh' | 'revoked' | 'unknown',
#     'payload': {...},
#     'error': None
# }
```

## Additional Methods

- `dry_run(signed_intent)` — Dry-run authorization
- `simulate_policy(**params)` — Policy simulation
- `list_passports(**filters)` — List agents
- `list_delegations(**filters)` — List delegations
- `get_delegation_chain(passport_id)` — Get chain
- `list_approvals(**filters)` — List approvals
- `get_revoked(**filters)` — Get revocation feed
- `get_audit(**filters)` — Query receipts
- `export_audit(**filters)` — Export JSONL
- `create_evidence_bundle(**params)` — Create bundle
- `create_checkpoint()` — Create checkpoint
- `set_passport_status(passport_id, status)` — Update status
- `rotate_agent_key(passport_id, new_pubkey, grace_period_s=300)` — Rotate key
- `lock_org(org_id, reason)` / `unlock_org(org_id)` — Emergency lock

## Error Handling

```python
from authragen import AuthraGen, Blocked

try:
    agent.execute(token, intent)
except Blocked as e:
    # e.code, e.message, e.request_id
    if e.code == 'replay':
        ...
except Exception as e:
    # Network/other errors
    ...
```

## Async Support

The current Python SDK is synchronous and does not ship an `AsyncAuthraGen` client.

## Type Hints

```python
from authragen import AuthraGen, Intent, Decision, Receipt, Passport

agent: AuthraGen = AuthraGen(base_url='...')
intent: Intent = agent.create_intent(...)
decision: Decision = agent.authorize(signed)
```

## Next: [Offline Verification](/sdk/offline-verification)