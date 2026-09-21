# Deployment

AuthraGen requires Node.js 22.13+ at runtime. The file-backed key store is for development/testing; production should use a real KMS and durable storage. The optional ML-DSA post-quantum profile requires a Node release with native WebCrypto ML-DSA support (24.7+).

## Docker (Recommended)

### Production

```bash
# Build
docker build -t authragen:latest .

# Run
docker run -d \
  --name authragen \
  -p 8787:8787 \
  -v authragen_data:/app/data \
  -e NODE_ENV=production \
  -e AUTHRA_CORS="https://yourdomain.com" \
  -e AUTHRA_TRUST_PROXY=1 \
  -e AUTHRA_KMS=aws \
  -e AUTHRA_STORE=postgres \
  -e DATABASE_URL='postgres://user:password@db.example/authragen' \
  -e AUTHRA_ANCHOR_URL=https://rekor.example.com/api/v1/log/entries \
  authragen:latest

# Production compose requires real KMS + durable store settings:
export AUTHRA_KMS=aws
export AUTHRA_STORE=postgres
export DATABASE_URL='postgres://user:password@db.example/authragen'
docker-compose up -d
```

### Development

```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
# Hot reload on port 8787, inspector on 9229
```

## Kubernetes

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authragen
  labels:
    app: authragen
spec:
  replicas: 1
  selector:
    matchLabels:
      app: authragen
  template:
    metadata:
      labels:
        app: authragen
    spec:
      containers:
      - name: authragen
        image: ghcr.io/opknock/authragen:latest
        ports:
        - containerPort: 8787
        env:
        - name: NODE_ENV
          value: "production"
        - name: AUTHRA_DATA
          value: "/app/data"
        - name: AUTHRA_CORS
          value: "https://api.yourdomain.com"
        - name: AUTHRA_TRUST_PROXY
          value: "1"
        - name: AUTHRA_KMS
          valueFrom:
            secretKeyRef:
              name: authragen-secrets
              key: kms-backend
        - name: AUTHRA_STORE
          value: "postgres"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: authragen-secrets
              key: database-url
        - name: AUTHRA_ANCHOR_URL
          valueFrom:
            secretKeyRef:
              name: authragen-secrets
              key: anchor-url
        volumeMounts:
        - name: data
          mountPath: /app/data
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
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: authragen-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: authragen
spec:
  selector:
    app: authragen
  ports:
  - port: 80
    targetPort: 8787
  type: ClusterIP
```

### Persistent Volume

```yaml
# k8s/pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: authragen-pvc
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
```

### ConfigMap & Secrets

```yaml
# k8s/config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authragen-config
data:
  AUTHRA_CORS: "https://api.yourdomain.com"
  AUTHRA_TRUST_PROXY: "1"
  AUTHRA_RISK_CEILING: "80"
---
apiVersion: v1
kind: Secret
metadata:
  name: authragen-secrets
type: Opaque
stringData:
  kms-backend: "aws"
  database-url: "REPLACE_WITH_DATABASE_URL"
  anchor-url: "https://rekor.example.com/api/v1/log/entries"
```

### Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authragen
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/proxy-body-size: "256k"
spec:
  tls:
  - hosts:
    - authragen.yourdomain.com
    secretName: authragen-tls
  rules:
  - host: authragen.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: authragen
            port:
              number: 80
```

## Production Checklist

> Postgres/Redis deployments refresh the generic control-plane state from the persistent source at each API request boundary. This supports multi-instance gateways without permanently stale in-process control-plane reads; strict linearizability for concurrent administrative mutations is still outside the current scope.

- [ ] **HTTPS/TLS** - Terminate at ingress/load balancer, `AUTHRA_TRUST_PROXY=1`
- [ ] **CORS** - `AUTHRA_CORS` set to exact origins (not `*`)
- [ ] **KMS** - `AUTHRA_KMS=aws|gcp|vault|azure` (not file-backed)
- [ ] **Anchor** - `AUTHRA_ANCHOR_URL` configured for transparency log
- [ ] **Storage** - Postgres/Redis for durable records, replay protection and atomic token-spend reservation; remote-backed control-plane state is refreshed at every API request
- [ ] **Secrets** - No secrets in images/configmaps; use Vault/SealedSecrets
- [ ] **Monitoring** - `/health` + `/metrics` (Prometheus) scraped
- [ ] **Logging** - Structured JSON logs to centralized system
- [ ] **Rate Limits** - Tune the gateway's per-route limits or enforce limits at the trusted ingress
- [ ] **Body Limits** - `AUTHRA_BODY_LIMIT` appropriate for payloads
- [ ] **Quotas** - Per-org quotas configured
- [ ] **Backups** - PVC snapshots + revocation feed exports
- [ ] **Disaster Recovery** - RTO/RPO documented, tested
- [ ] **Capacity** - Load tested, autoscaling configured

## Environment Variables

| Variable | Required | Default | Production |
|----------|----------|---------|------------|
| `PORT` | No | 8787 | 8787 |
| `NODE_ENV` | No | development | production |
| `AUTHRA_DATA` | No | ./data | /app/data |
| `AUTHRA_CORS` | No | disabled | Exact origins |
| `AUTHRA_TRUST_PROXY` | No | 0 | 1 |
| `AUTHRA_BODY_LIMIT` | No | 256kb | 256kb |
| `AUTHRA_SESSION_TTL_MS` | No | 43200000 | 43200000 |
| `AUTHRA_INTENT_TTL_S` | No | 120 | 120 |
| `AUTHRA_ACTION_TTL_S` | No | 120 | 120 |
| `AUTHRA_APPROVAL_TTL_S` | No | 900 | 900 |
| `AUTHRA_CLOCK_SKEW_S` | No | 30 | 30 |
| `AUTHRA_RISK_CEILING` | No | 80 | 80 |
| `AUTHRA_ALLOW_CUSTODY` | No | 0 | 0 |
| `AUTHRA_KMS` | **Yes** | file | aws/gcp/vault/azure |
| `AUTHRA_ANCHOR_URL` | Recommended | - | Set |
| `AUTHRA_AUDIT_RETENTION_DAYS` | No | - | Manage audit retention operationally; compaction policy is not built-in |
| `AUTHRA_OIDC_ISSUER` | No | - | Enables OIDC bearer federation |
| `AUTHRA_OIDC_CLIENT_ID` | No | - | Required with OIDC issuer |
| `AUTHRA_OIDC_AUDIENCE` | No | client ID | OIDC accepted audience |
| `AUTHRA_OIDC_ROLE_CLAIM` | No | roles | Claim used for RBAC mapping |
| `AUTHRA_OIDC_ORG_CLAIM` | No | org_id | Claim used for organization mapping |
| `AUTHRA_OIDC_ORG_ID` | No | - | Static OIDC organization mapping |
| `AUTHRA_OIDC_ROLE_MAP` | No | built-in map | JSON role mapping |
| `AUTHRA_SPIFFE_AUDIENCE` | No | - | Enables SPIFFE JWT-SVID bearer federation |
| `AUTHRA_SPIFFE_JWKS_FILE` | No | - | SPIFFE JWT bundle/JWKS path |
| `AUTHRA_SPIFFE_ORG_ID` | No | - | Static SPIFFE organization mapping |
| `AUTHRA_SPIFFE_ROLE` | No | executor | AuthraGen role for SPIFFE principals |
| `AUTHRA_SPIFFE_ALLOWED_IDS` | No | - | JSON allowlist of SPIFFE IDs |

## Postgres Adapter (Production)

```javascript
// src/store/postgres.js
const pg = require('pg');
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// The gateway refreshes generic control-plane state from Postgres at each API request boundary.
// Replay and token-spend reservation are adapter-backed and atomic; audit/checkpoint files remain local.
```

## Redis Adapter (Production)

```javascript
// src/store/redis.js
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL);

// Nonce: SET nonce:{org}:{nonce} EX 3600 NX
// Action JTI: SET action:{jti} EX 3600 NX
// The gateway refreshes generic control-plane state from Redis at each API request boundary.
// Replay and token-spend reservation use Redis atomic primitives.

## Federation

See [Federation](/api/federation) for OIDC issuer/JWKS configuration and SPIFFE/SPIRE SVID validation.
JWT-SVID bearer federation should use the SPIFFE trust domain's JWKS bundle from a trusted local path.
```

## Monitoring

### Health Endpoint

```
GET /health
```
Response includes `ok`, protocol/version, backend, persistence status, consistency mode, last remote sync timestamp, custody policy, and the request ID.

### Metrics (Prometheus)

```
GET /metrics
```
Key metrics:
- `authragen_requests_total{route,method,status}`
- `authragen_request_duration_seconds{route}`
- `authragen_authorize_decisions{decision}`
- `authragen_active_passports{org}`
- `authragen_revocation_feed_seq{org}`
- `authragen_audit_chain_head{org}`

### Logging

Structured JSON logs:
```json
{
  "level": "info",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "request_id": "rq_abc123",
  "route": "/v1/authorize",
  "method": "POST",
  "status": 200,
  "duration_ms": 15,
  "org_id": "org_xyz",
  "passport_id": "agt_abc",
  "decision": "allow",
  "risk_score": 15
}
```

## Next: [Configuration](/deployment/configuration)