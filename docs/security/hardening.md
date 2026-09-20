# Production Hardening

## Infrastructure

### TLS/HTTPS
- Terminate TLS at load balancer/ingress
- `AUTHRA_TRUST_PROXY=1` to trust `X-Forwarded-*`
- HSTS header enforced
- Certificate transparency monitoring

### Network
- Private subnet for gateway
- Ingress only on 443 (80 redirect)
- Egress restricted (allowlist for KMS, anchor, monitoring)
- WAF rules for OWASP Top 10

### Secrets Management
- **Never** in images, configmaps, or repo
- Use: Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault
- `AUTHRA_KMS` selects backend
- Rotation automated

### Storage
- **Postgres** for primary (transactions, durability)
- **Redis** for nonce/action-JTI/budget atomicity
- Encryption at rest (cloud provider)
- Automated backups + point-in-time recovery

## Gateway Configuration

### Rate Limiting
```bash
AUTHRA_RATE_LIMIT_WINDOW_MS=60000
AUTHRA_RATE_LIMIT_MAX=1000          # Adjust for traffic
AUTHRA_BODY_LIMIT=256kb             # Adjust for payloads
```

### CORS
```bash
AUTHRA_CORS="https://app.yourdomain.com,https://api.yourdomain.com"
# Never * in production
```

### Timeouts
```bash
AUTHRA_INTENT_TTL_S=120
AUTHRA_ACTION_TTL_S=300
AUTHRA_APPROVAL_TTL_S=3600
AUTHRA_CLOCK_SKEW_S=30
```

### Quotas
- Per-org daily/monthly request quotas
- Per-passport budget limits
- Alert on quota exhaustion

## Monitoring & Alerting

### Health Checks
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8787
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health
    port: 8787
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Key Metrics (Prometheus)
| Metric | Alert Threshold |
|--------|-----------------|
| `authragen_requests_total{status=~"5.."}` | > 1% |
| `authragen_authorize_decisions{decision="deny"}` | Spike |
| `authragen_active_passports` | Unexpected drop |
| `authragen_revocation_feed_seq` | Stalled |
| `authragen_audit_chain_head` | Gap |
| `process_memory_bytes` | > 80% limit |
| `process_cpu_seconds_total` | > 80% limit |

### Logging
- Structured JSON to stdout
- Fields: `timestamp, level, request_id, route, method, status, duration_ms, org_id, passport_id, decision, risk_score`
- Ship to: Loki, Elasticsearch, Datadog, CloudWatch
- Retention: 90 days hot, 7 years cold

### Tracing
- OpenTelemetry instrumentation
- OTLP export to collector
- Spans: HTTP request, authorize, execute, storage, KMS
- Sampling: 10% (adjust for volume)

## Incident Response

### Runbooks
| Scenario | Detection | Response |
|----------|-----------|----------|
| High error rate | Metrics alert | Check logs; restart pods; check dependencies |
| Revocation feed stalled | Seq not increasing | Check storage; restart gateway |
| Audit chain gap | Verification fails | Investigate; restore from checkpoint |
| KMS unavailable | Health check fails | Fail closed; alert; manual intervention |
| Org lock triggered | Alert + audit | Investigate; unlock if false positive |

### Forensics
- Audit receipts + checkpoints = complete history
- Evidence bundles for legal/compliance
- Revocation feed for access termination proof
- Request IDs correlate across systems

## Disaster Recovery

### RTO/RPO Targets
| Tier | RTO | RPO |
|------|-----|-----|
| Critical (authz) | 15 min | 0 (sync replica) |
| Audit | 1 hour | 1 hour |
| Config | 4 hours | 24 hours |

### Backup Strategy
- Postgres: Continuous archiving + daily base backups
- Redis: AOF + RDB snapshots
- Audit: Export JSONL weekly to cold storage
- Revocation feed: Export weekly

### Recovery Procedure
1. Restore Postgres from latest backup + WAL
2. Restore Redis from snapshot
3. Verify audit chain integrity
4. Verify revocation feed continuity
5. Start gateway; verify `/health`
6. Run smoke tests

## Security Testing

### CI/CD
- Dependabot weekly
- CodeQL on every PR
- Trivy container scan
- Gitleaks secret scan
- npm audit / pip-audit

### Periodic
- Penetration test (annual)
- Dependency review (quarterly)
- Chaos engineering (monthly)
- DR drill (quarterly)

## Compliance Mapping

| Control | Implementation |
|---------|----------------|
| SOC 2 CC6.1 | AuthN/AuthZ on all endpoints |
| SOC 2 CC6.7 | Revocation + audit trail |
| ISO 27001 A.9 | RBAC + API key management |
| ISO 27001 A.12 | Audit logging + monitoring |
| GDPR Art. 32 | Encryption + access control |
| PCI DSS 8.3 | MFA via approval quorum |

## Next: [Known Limitations](/security/limitations)