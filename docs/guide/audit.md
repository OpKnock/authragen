# Audit & Accountability

## Receipts

Every authorization decision and execution creates a **hash-chained receipt**.

### Receipt Structure

```json
{
  "id": "rcpt_abc123",
  "type": "authorized" | "executed" | "denied" | "replay",
  "request_id": "rq_xyz789",
  "intent_hash": "sha256...",
  "action_jti": "att_...",
  "approval_jti": "apr_...",
  "executor": {
    "authn": "agent_sig" | "service_key:<id>",
    "key_id": "kid_1",
    "passport_id": "agt_..."
  },
  "policy_id": "pol_...",
  "policy_hash": "sha256...",
  "policy_version": 3,
  "risk": { "score": 15, "factors": [], "band": "low", "version": 2 },
  "timestamp": "2024-01-01T00:00:00.000Z",
  "prev_receipt_hash": "sha256..."
}
```

### Chain Integrity

- `prev_receipt_hash` = SHA-256 of previous receipt
- Genesis receipt has `prev_receipt_hash: null`
- `verifyAuditChain()` replays and validates entire chain
- **Tamper-evident**: Any modification/insertion/deletion/reordering detected
- **Not immutable**: Full rewrite protection requires external anchors

## Checkpoints

Signed snapshots for efficient verification + external anchoring.

```json
{
  "count": 15432,
  "head": "sha256...",      // hash of latest receipt
  "prev": "sha256...",      // previous checkpoint head
  "timestamp": "2024-01-01T00:00:00Z",
  "signature": "AR1..."     // gateway checkpoint key
}
```

**Checkpoint operations:**
```javascript
// Create checkpoint (admin)
await me.createCheckpoint();

// Verify all checkpoints
const checkpoints = await me.verifyCheckpoints();

// Get specific checkpoint
const cp = await me.getCheckpoint(100);
```

**External anchoring** (`AUTHRA_ANCHOR_URL`):
- Each checkpoint POSTed to configured webhook
- Enables transparency log / timestamp service integration
- Rekor, RFC3161, or custom anchor service

## Per-Org Audit Streams

```javascript
// Query receipts for org
const receipts = await me.getAudit({
  org_id: 'org_xyz',
  since: '2024-01-01T00:00:00Z',
  until: '2024-01-02T00:00:00Z',
  type: 'executed',  // authorized | executed | denied | replay
  passport_id: 'agt_...',
  limit: 100,
  offset: 0
});

// Export as JSONL (streaming)
const stream = await me.exportAudit({ org_id, format: 'jsonl' });
```

## Evidence Bundles

Signed, portable audit evidence for compliance.

```javascript
const bundle = await me.createEvidenceBundle({
  org_id: 'org_xyz',
  receipt_ids: ['rcpt_1', 'rcpt_2', 'rcpt_3'],
  include_checkpoints: true
});
```

**Bundle structure:**
```json
{
  "bundle_id": "evd_abc123",
  "org_id": "org_xyz",
  "receipts": [...],
  "checkpoints": [...],
  "bundle_hash": "sha256...",
  "signature": "AR1...",
  "created_at": "2024-01-01T00:00:00Z"
}
```

**Verification:**
```javascript
const valid = await me.verifyEvidenceBundle(bundle, orgPubkey);
// Returns: { valid: true, bundle_hash_match: true, signature_valid: true }
```

## Redaction

**Secrets never in audit:**
- API key secrets (only `key_id` logged)
- Private keys (never)
- Bootstrap tokens (never)
- Full envelopes (only `jti` + `intent_hash` logged)
- Approval reasons (kept, not secret)

## Verification API

```javascript
// Verify audit chain integrity
const result = await me.verifyAuditChain({ org_id });
// { ok: true, count: 15432, head: 'sha256...', checked: 15432 }

// Verify single receipt
const receipt = await me.getReceipt('rcpt_abc123');
const valid = await me.verifyReceipt(receipt, orgPubkey);
```

## Compliance Patterns

### SOC 2 / ISO 27001
- Receipts = immutable-ish log of all authz decisions
- Checkpoints = periodic integrity verification
- Evidence bundles = auditor-ready packages
- Revocation feed = access termination proof

### GDPR
- `exportAudit` = data subject access request
- Redaction = no PII in audit (only IDs)
- Retention = configure via `AUTHRA_AUDIT_RETENTION_DAYS`

### Financial Audit
- `amount_cents` + `destination` in every executed receipt
- Policy version = control framework version
- Approver identity = segregation of duties proof

## Dashboard

- Real-time receipt stream with filters
- Chain verification status (green/red)
- Checkpoint timeline with anchor status
- Evidence bundle builder
- Export (JSONL, CSV) with date ranges
- "Why allowed/blocked" drill-down per receipt

## Retention

Configure via env:
```bash
AUTHRA_AUDIT_RETENTION_DAYS=2555  # 7 years default
```

- Automatic cleanup of receipts older than retention
- Checkpoints never auto-deleted
- Evidence bundles manual only

## Next: [API Reference](/api/overview)