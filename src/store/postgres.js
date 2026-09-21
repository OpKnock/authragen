'use strict';

const pg = require('pg');
const crypto = require('node:crypto');

class PostgresStore {
  constructor(connectionString) {
    this.pool = new pg.Pool({
      connectionString,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      
      await client.query(`
        CREATE TABLE IF NOT EXISTS orgs (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          pubkey TEXT NOT NULL,
          root_kid TEXT NOT NULL,
          risk_stepup INTEGER DEFAULT 60,
          risk_ceiling INTEGER DEFAULT 80,
          quotas JSONB DEFAULT '{}',
          locked BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS blueprints (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          name TEXT NOT NULL,
          version TEXT NOT NULL,
          policy JSONB NOT NULL DEFAULT '{}',
          risk_stepup INTEGER,
          risk_ceiling INTEGER,
          budgets JSONB DEFAULT '{}',
          approval_rules JSONB DEFAULT '{}',
          delegation_constraints JSONB DEFAULT '{}',
          instance_count INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_blueprints_org ON blueprints(org_id);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS passports (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          did TEXT NOT NULL UNIQUE,
          parent_id TEXT REFERENCES passports(id),
          kind TEXT NOT NULL DEFAULT 'agent',
          name TEXT NOT NULL,
          custody TEXT NOT NULL DEFAULT 'self',
          blueprint_id TEXT REFERENCES blueprints(id),
          owner TEXT,
          sponsor TEXT,
          team TEXT,
          environment TEXT,
          purpose TEXT,
          model TEXT,
          provider TEXT,
          runtime TEXT,
          framework TEXT,
          keys_current JSONB NOT NULL,
          keys_history JSONB NOT NULL DEFAULT '[]',
          grace_period_s INTEGER DEFAULT 300,
          status TEXT NOT NULL DEFAULT 'active',
          iat TIMESTAMPTZ NOT NULL,
          exp TIMESTAMPTZ,
          signature TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_passports_org ON passports(org_id);
        CREATE INDEX IF NOT EXISTS idx_passports_parent ON passports(parent_id);
        CREATE INDEX IF NOT EXISTS idx_passports_status ON passports(status);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS policies (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          version INTEGER NOT NULL DEFAULT 1,
          policy_hash TEXT NOT NULL,
          rules JSONB NOT NULL DEFAULT '[]',
          updated_at TIMESTAMPTZ DEFAULT NOW(),
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(org_id);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS delegations (
          jti TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          sub TEXT NOT NULL REFERENCES passports(id),
          parent_jti TEXT REFERENCES delegations(jti),
          scope JSONB NOT NULL DEFAULT '[]',
          resources JSONB NOT NULL DEFAULT '[]',
          constraints JSONB NOT NULL DEFAULT '{}',
          kid TEXT NOT NULL,
          iat TIMESTAMPTZ NOT NULL,
          depth INTEGER DEFAULT 0,
          revoked BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_delegations_org ON delegations(org_id);
        CREATE INDEX IF NOT EXISTS idx_delegations_sub ON delegations(sub);
        CREATE INDEX IF NOT EXISTS idx_delegations_parent ON delegations(parent_jti);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS approvals (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          intent_hash TEXT NOT NULL,
          action_jti TEXT,
          requester JSONB NOT NULL,
          policy_id TEXT,
          policy_version INTEGER,
          risk JSONB,
          status TEXT NOT NULL DEFAULT 'pending',
          min_approvals INTEGER DEFAULT 1,
          approvals JSONB NOT NULL DEFAULT '[]',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          expires_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_approvals_org ON approvals(org_id);
        CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS revocations (
          seq BIGSERIAL PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          type TEXT NOT NULL,
          id TEXT NOT NULL,
          kid TEXT,
          reason TEXT,
          timestamp TIMESTAMPTZ DEFAULT NOW(),
          cascade JSONB DEFAULT '[]'
        );
        CREATE INDEX IF NOT EXISTS idx_revocations_org ON revocations(org_id);
        CREATE INDEX IF NOT EXISTS idx_revocations_seq ON revocations(seq);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_receipts (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          type TEXT NOT NULL,
          request_id TEXT NOT NULL,
          intent_hash TEXT,
          action_jti TEXT,
          approval_jti TEXT,
          executor JSONB,
          policy_id TEXT,
          policy_hash TEXT,
          policy_version INTEGER,
          risk JSONB,
          timestamp TIMESTAMPTZ NOT NULL,
          prev_receipt_hash TEXT,
          data JSONB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_receipts(org_id);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_receipts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_receipts(request_id);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
          id BIGSERIAL PRIMARY KEY,
          count BIGINT NOT NULL,
          head TEXT NOT NULL,
          prev TEXT,
          timestamp TIMESTAMPTZ DEFAULT NOW(),
          signature TEXT NOT NULL
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS nonces (
          org_id TEXT NOT NULL,
          nonce TEXT NOT NULL,
          consumed_at TIMESTAMPTZ DEFAULT NOW(),
          PRIMARY KEY (org_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_nonces_consumed ON nonces(consumed_at);
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS action_jtis (
          jti TEXT PRIMARY KEY,
          consumed_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS budgets (
          org_id TEXT NOT NULL,
          passport_id TEXT NOT NULL,
          period TEXT NOT NULL,
          amount_cents BIGINT NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ DEFAULT NOW(),
          PRIMARY KEY (org_id, passport_id, period)
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS token_spends (
          token_id TEXT PRIMARY KEY,
          spent_cents BIGINT NOT NULL DEFAULT 0,
          updated_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);

      await client.query(`
        CREATE TABLE IF NOT EXISTS api_keys (
          key_id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL REFERENCES orgs(id),
          role TEXT NOT NULL,
          secret_hash TEXT NOT NULL,
          expires_at TIMESTAMPTZ,
          last_used TIMESTAMPTZ,
          revoked BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_apikeys_org ON api_keys(org_id);
      `);

      await client.query('CREATE TABLE IF NOT EXISTS authragen_records (collection TEXT NOT NULL, id TEXT NOT NULL, org_id TEXT, data JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (collection, id)); CREATE INDEX IF NOT EXISTS idx_authragen_records_org ON authragen_records(collection, org_id);');

      await client.query('COMMIT');
      this.initialized = true;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async close() {
    await this.pool.end();
  }

  // ===== Organizations =====
  async getOrg(id) {
    const res = await this.pool.query('SELECT * FROM orgs WHERE id = $1', [id]);
    return res.rows[0] || null;
  }

  async setOrg(org) {
    await this.pool.query(`
      INSERT INTO orgs (id, name, pubkey, root_kid, risk_stepup, risk_ceiling, quotas, locked, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        pubkey = EXCLUDED.pubkey,
        root_kid = EXCLUDED.root_kid,
        risk_stepup = EXCLUDED.risk_stepup,
        risk_ceiling = EXCLUDED.risk_ceiling,
        quotas = EXCLUDED.quotas,
        locked = EXCLUDED.locked
    `, [org.id, org.name, org.pubkey, org.root_kid, org.risk_stepup, org.risk_ceiling,
        JSON.stringify(org.quotas || {}), org.locked, org.created_at]);
  }

  async listOrgs() {
    const res = await this.pool.query('SELECT * FROM orgs ORDER BY created_at');
    return res.rows;
  }

  // ===== Blueprints =====
  async getBlueprint(id) {
    const res = await this.pool.query('SELECT * FROM blueprints WHERE id = $1', [id]);
    return res.rows[0] || null;
  }

  async setBlueprint(bp) {
    await this.pool.query(`
      INSERT INTO blueprints (id, org_id, name, version, policy, risk_stepup, risk_ceiling, budgets, approval_rules, delegation_constraints, instance_count, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (id) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        name = EXCLUDED.name,
        version = EXCLUDED.version,
        policy = EXCLUDED.policy,
        risk_stepup = EXCLUDED.risk_stepup,
        risk_ceiling = EXCLUDED.risk_ceiling,
        budgets = EXCLUDED.budgets,
        approval_rules = EXCLUDED.approval_rules,
        delegation_constraints = EXCLUDED.delegation_constraints,
        instance_count = EXCLUDED.instance_count,
        updated_at = EXCLUDED.updated_at
    `, [bp.id, bp.org_id, bp.name, bp.version, JSON.stringify(bp.policy || {}),
        bp.risk_stepup, bp.risk_ceiling, JSON.stringify(bp.budgets || {}),
        JSON.stringify(bp.approval_rules || {}), JSON.stringify(bp.delegation_constraints || {}),
        bp.instance_count || 0, bp.created_at, bp.updated_at || new Date().toISOString()]);
  }

  async listBlueprints(filters = {}) {
    let sql = 'SELECT * FROM blueprints WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); sql += ` OFFSET $${params.length}`; }
    sql += ' ORDER BY created_at DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  async deleteBlueprint(id) {
    await this.pool.query('DELETE FROM blueprints WHERE id = $1', [id]);
  }

  // ===== Passports =====
  async getPassport(id) {
    const res = await this.pool.query('SELECT * FROM passports WHERE id = $1', [id]);
    return res.rows[0] || null;
  }

  async getPassportByDID(did) {
    const res = await this.pool.query('SELECT * FROM passports WHERE did = $1', [did]);
    return res.rows[0] || null;
  }

  async setPassport(passport) {
    await this.pool.query(`
      INSERT INTO passports (id, org_id, did, parent_id, kind, name, custody, blueprint_id, owner, sponsor, team, environment, purpose, model, provider, runtime, framework, keys_current, keys_history, grace_period_s, status, iat, exp, signature, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
      ON CONFLICT (id) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        did = EXCLUDED.did,
        parent_id = EXCLUDED.parent_id,
        kind = EXCLUDED.kind,
        name = EXCLUDED.name,
        custody = EXCLUDED.custody,
        blueprint_id = EXCLUDED.blueprint_id,
        owner = EXCLUDED.owner,
        sponsor = EXCLUDED.sponsor,
        team = EXCLUDED.team,
        environment = EXCLUDED.environment,
        purpose = EXCLUDED.purpose,
        model = EXCLUDED.model,
        provider = EXCLUDED.provider,
        runtime = EXCLUDED.runtime,
        framework = EXCLUDED.framework,
        keys_current = EXCLUDED.keys_current,
        keys_history = EXCLUDED.keys_history,
        grace_period_s = EXCLUDED.grace_period_s,
        status = EXCLUDED.status,
        iat = EXCLUDED.iat,
        exp = EXCLUDED.exp,
        signature = EXCLUDED.signature,
        updated_at = EXCLUDED.updated_at
    `, [passport.id, passport.org_id, passport.did, passport.parent_id, passport.kind,
        passport.name, passport.custody, passport.blueprint_id, passport.owner, passport.sponsor,
        passport.team, passport.environment, passport.purpose, passport.model, passport.provider,
        passport.runtime, passport.framework, JSON.stringify(passport.keys.current),
        JSON.stringify(passport.keys.history || []), passport.grace_period_s, passport.status,
        passport.iat, passport.exp, passport.signature, passport.created_at, new Date().toISOString()]);
  }

  async listPassports(filters = {}) {
    let sql = 'SELECT * FROM passports WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.status) { params.push(filters.status); sql += ` AND status = $${params.length}`; }
    if (filters.blueprint_id) { params.push(filters.blueprint_id); sql += ` AND blueprint_id = $${params.length}`; }
    if (filters.parent_id) { params.push(filters.parent_id); sql += ` AND parent_id = $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); sql += ` OFFSET $${params.length}`; }
    sql += ' ORDER BY created_at DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  async updatePassportStatus(id, status) {
    await this.pool.query('UPDATE passports SET status = $1, updated_at = NOW() WHERE id = $2', [status, id]);
  }

  async revokePassportKey(id, kid) {
    const passport = await this.getPassport(id);
    if (!passport) return false;
    const history = passport.keys_history || [];
    const idx = history.findIndex(k => k.kid === kid);
    if (idx >= 0) {
      history[idx] = { ...history[idx], revoked: true, until: new Date().toISOString() };
      await this.setPassport({ ...passport, keys_history: history });
      return true;
    }
    if (passport.keys_current?.kid === kid) {
      passport.keys_current = { ...passport.keys_current, revoked: true };
      await this.setPassport(passport);
      return true;
    }
    return false;
  }

  // ===== Policies =====
  async getPolicy(id) {
    const res = await this.pool.query('SELECT * FROM policies WHERE id = $1', [id]);
    return res.rows[0] || null;
  }

  async setPolicy(policy) {
    await this.pool.query(`
      INSERT INTO policies (id, org_id, version, policy_hash, rules, updated_at, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT (id) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        version = EXCLUDED.version,
        policy_hash = EXCLUDED.policy_hash,
        rules = EXCLUDED.rules,
        updated_at = EXCLUDED.updated_at
    `, [policy.id, policy.org_id, policy.version, policy.policyHash,
        JSON.stringify(policy.rules || []), policy.updated_at || new Date().toISOString(),
        policy.created_at || new Date().toISOString()]);
  }

  async listPolicies(filters = {}) {
    let sql = 'SELECT * FROM policies WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    sql += ' ORDER BY updated_at DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  // ===== Delegations =====
  async getDelegation(jti) {
    const res = await this.pool.query('SELECT * FROM delegations WHERE jti = $1', [jti]);
    return res.rows[0] || null;
  }

  async setDelegation(d) {
    await this.pool.query(`
      INSERT INTO delegations (jti, org_id, sub, parent_jti, scope, resources, constraints, kid, iat, depth, revoked, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (jti) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        sub = EXCLUDED.sub,
        parent_jti = EXCLUDED.parent_jti,
        scope = EXCLUDED.scope,
        resources = EXCLUDED.resources,
        constraints = EXCLUDED.constraints,
        kid = EXCLUDED.kid,
        iat = EXCLUDED.iat,
        depth = EXCLUDED.depth,
        revoked = EXCLUDED.revoked
    `, [d.jti, d.org_id, d.sub, d.parent_jti, JSON.stringify(d.scope || []),
        JSON.stringify(d.resources || []), JSON.stringify(d.constraints || {}),
        d.kid, d.iat, d.depth || 0, d.revoked || false, d.created_at || new Date().toISOString()]);
  }

  async listDelegations(filters = {}) {
    let sql = 'SELECT * FROM delegations WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.delegator_id) { params.push(filters.delegator_id); sql += ` AND sub = $${params.length}`; }
    if (filters.subject_id) { params.push(filters.subject_id); sql += ` AND sub = $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); sql += ` OFFSET $${params.length}`; }
    sql += ' ORDER BY created_at DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  async getDelegationChain(passportId) {
    const res = await this.pool.query('SELECT * FROM delegations WHERE sub = $1 ORDER BY depth', [passportId]);
    return res.rows;
  }

  async revokeDelegation(jti) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE delegations SET revoked = TRUE WHERE jti = $1', [jti]);
      await client.query('UPDATE delegations SET revoked = TRUE WHERE parent_jti = $1', [jti]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  // ===== Approvals =====
  async getApproval(id) {
    const res = await this.pool.query('SELECT * FROM approvals WHERE id = $1', [id]);
    return res.rows[0] || null;
  }

  async setApproval(a) {
    await this.pool.query(`
      INSERT INTO approvals (id, org_id, intent_hash, action_jti, requester, policy_id, policy_version, risk, status, min_approvals, approvals, created_at, expires_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (id) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        intent_hash = EXCLUDED.intent_hash,
        action_jti = EXCLUDED.action_jti,
        requester = EXCLUDED.requester,
        policy_id = EXCLUDED.policy_id,
        policy_version = EXCLUDED.policy_version,
        risk = EXCLUDED.risk,
        status = EXCLUDED.status,
        min_approvals = EXCLUDED.min_approvals,
        approvals = EXCLUDED.approvals,
        expires_at = EXCLUDED.expires_at
    `, [a.id, a.org_id, a.intent_hash, a.action_jti, JSON.stringify(a.requester || {}),
        a.policy_id, a.policy_version, JSON.stringify(a.risk || {}),
        a.status, a.min_approvals, JSON.stringify(a.approvals || []),
        a.created_at, a.expires_at]);
  }

  async listApprovals(filters = {}) {
    let sql = 'SELECT * FROM approvals WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.status) { params.push(filters.status); sql += ` AND status = $${params.length}`; }
    if (filters.since) { params.push(filters.since); sql += ` AND created_at >= $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); sql += ` OFFSET $${params.length}`; }
    sql += ' ORDER BY created_at DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  // ===== Revocations =====
  async addRevocation(r) {
    const res = await this.pool.query(`
      INSERT INTO revocations (org_id, type, id, kid, reason, cascade)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING seq
    `, [r.org_id, r.type, r.id, r.kid, r.reason, JSON.stringify(r.cascade || [])]);
    return res.rows[0].seq;
  }

  async getRevocations(filters = {}) {
    let sql = 'SELECT * FROM revocations WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.since_seq) { params.push(filters.since_seq); sql += ` AND seq > $${params.length}`; }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    sql += ' ORDER BY seq ASC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  // ===== Audit =====
  async appendReceipt(receipt) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      
      const prevRes = await client.query(
        'SELECT id FROM audit_receipts WHERE org_id = $1 ORDER BY timestamp DESC LIMIT 1',
        [receipt.org_id]
      );
      const prevHash = prevRes.rows[0] ? crypto.createHash('sha256')
        .update(JSON.stringify(prevRes.rows[0])).digest('hex') : null;

      const receiptWithHash = { ...receipt, prev_receipt_hash: prevHash };
      
      await client.query(`
        INSERT INTO audit_receipts (id, org_id, type, request_id, intent_hash, action_jti, approval_jti, executor, policy_id, policy_hash, policy_version, risk, timestamp, prev_receipt_hash, data)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      `, [receiptWithHash.id, receiptWithHash.org_id, receiptWithHash.type,
          receiptWithHash.request_id, receiptWithHash.intent_hash, receiptWithHash.action_jti,
          receiptWithHash.approval_jti, JSON.stringify(receiptWithHash.executor || {}),
          receiptWithHash.policy_id, receiptWithHash.policy_hash, receiptWithHash.policy_version,
          JSON.stringify(receiptWithHash.risk || {}), receiptWithHash.timestamp,
          receiptWithHash.prev_receipt_hash, JSON.stringify(receiptWithHash)]);

      await client.query('COMMIT');
      return receiptWithHash;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async getAudit(filters = {}) {
    let sql = 'SELECT * FROM audit_receipts WHERE 1=1';
    const params = [];
    if (filters.org_id) { params.push(filters.org_id); sql += ` AND org_id = $${params.length}`; }
    if (filters.since) { params.push(filters.since); sql += ` AND timestamp >= $${params.length}`; }
    if (filters.until) { params.push(filters.until); sql += ` AND timestamp <= $${params.length}`; }
    if (filters.type) { params.push(filters.type); sql += ` AND type = $${params.length}`; }
    if (filters.passport_id) { 
      params.push(filters.passport_id); 
      sql += ` AND (executor->>'passport_id') = $${params.length}`; 
    }
    if (filters.limit) { params.push(filters.limit); sql += ` LIMIT $${params.length}`; }
    if (filters.offset) { params.push(filters.offset); sql += ` OFFSET $${params.length}`; }
    sql += ' ORDER BY timestamp DESC';
    const res = await this.pool.query(sql, params);
    return res.rows;
  }

  async verifyAuditChain(orgId) {
    const res = await this.pool.query(
      'SELECT * FROM audit_receipts WHERE org_id = $1 ORDER BY timestamp ASC',
      [orgId]
    );
    let prevHash = null;
    for (const r of res.rows) {
      if (r.prev_receipt_hash !== prevHash) {
        return { ok: false, count: res.rows.length, head: null, error: `Chain broken at ${r.id}` };
      }
      prevHash = crypto.createHash('sha256').update(JSON.stringify(r)).digest('hex');
    }
    return { ok: true, count: res.rows.length, head: prevHash };
  }

  async exportAudit(filters = {}) {
    const receipts = await this.getAudit(filters);
    return receipts.map(r => JSON.stringify(r)).join('\n');
  }

  async createCheckpoint(checkpoint) {
    const res = await this.pool.query(`
      INSERT INTO audit_checkpoints (count, head, prev, signature)
      VALUES ($1,$2,$3,$4)
      RETURNING id
    `, [checkpoint.count, checkpoint.head, checkpoint.prev, checkpoint.signature]);
    return res.rows[0];
  }

  async listCheckpoints() {
    const res = await this.pool.query('SELECT * FROM audit_checkpoints ORDER BY id');
    return res.rows;
  }

  // ===== Nonces =====
  async consumeNonce(orgId, nonce) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const res = await client.query(
        'INSERT INTO nonces (org_id, nonce) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING 1',
        [orgId, nonce]
      );
      await client.query('COMMIT');
      return res.rowCount === 1;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async nonceExists(orgId, nonce) {
    const res = await this.pool.query('SELECT 1 FROM nonces WHERE org_id = $1 AND nonce = $2', [orgId, nonce]);
    return res.rows.length > 0;
  }

  // ===== Action JTIs =====
  async consumeActionJTI(jti) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const res = await client.query(
        'INSERT INTO action_jtis (jti) VALUES ($1) ON CONFLICT DO NOTHING RETURNING 1',
        [jti]
      );
      await client.query('COMMIT');
      return res.rowCount === 1;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async actionJTIExists(jti) {
    const res = await this.pool.query('SELECT 1 FROM action_jtis WHERE jti = $1', [jti]);
    return res.rows.length > 0;
  }

  // ===== Atomic execute reservation =====
  async checkAndDebitExecution(orgId, nonce, actionJti, tokenId, amountCents, limitCents) {
    const amount = Number(amountCents) || 0;
    const limit = Number(limitCents);
    if (!Number.isSafeInteger(amount) || amount < 0 || !Number.isSafeInteger(limit) || limit < 0) {
      throw Object.assign(new Error('invalid execution budget'), { code: 'bad_request' });
    }
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const nonceRes = await client.query(
        'INSERT INTO nonces (org_id, nonce) VALUES ($1,$2) ON CONFLICT DO NOTHING RETURNING 1',
        [orgId, nonce]
      );
      if (nonceRes.rowCount !== 1) {
        await client.query('ROLLBACK');
        return { success: false, error: 'nonce_replay', current: 0 };
      }
      const jtiRes = await client.query(
        'INSERT INTO action_jtis (jti) VALUES ($1) ON CONFLICT DO NOTHING RETURNING 1',
        [actionJti]
      );
      if (jtiRes.rowCount !== 1) {
        await client.query('ROLLBACK');
        return { success: false, error: 'jti_replay', current: 0 };
      }
      let current = 0;
      if (tokenId) {
        await client.query(
          'INSERT INTO token_spends (token_id, spent_cents) VALUES ($1, 0) ON CONFLICT (token_id) DO NOTHING',
          [tokenId]
        );
        const spendRes = await client.query(
          'SELECT spent_cents FROM token_spends WHERE token_id = $1 FOR UPDATE',
          [tokenId]
        );
        current = Number(spendRes.rows[0]?.spent_cents || 0);
        if (!Number.isSafeInteger(current) || current + amount > limit) {
          await client.query('ROLLBACK');
          return { success: false, error: 'budget_exceeded', current };
        }
        await client.query(
          'INSERT INTO token_spends (token_id, spent_cents, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (token_id) DO UPDATE SET spent_cents = EXCLUDED.spent_cents, updated_at = NOW()',
          [tokenId, current + amount]
        );
        current += amount;
      }
      await client.query('COMMIT');
      return { success: true, current };
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
  }

  // ===== Budgets =====
  async debitBudget(orgId, passportId, period, amountCents) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const res = await client.query(`
        INSERT INTO budgets (org_id, passport_id, period, amount_cents)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (org_id, passport_id, period) DO UPDATE SET
          amount_cents = budgets.amount_cents + EXCLUDED.amount_cents,
          updated_at = NOW()
        RETURNING amount_cents
      `, [orgId, passportId, period, amountCents]);
      await client.query('COMMIT');
      return res.rows[0].amount_cents;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async checkBudget(orgId, passportId, period, limitCents) {
    const res = await this.pool.query(
      'SELECT amount_cents FROM budgets WHERE org_id = $1 AND passport_id = $2 AND period = $3',
      [orgId, passportId, period]
    );
    const current = res.rows[0]?.amount_cents || 0;
    return current < limitCents;
  }

  // ===== API Keys =====
  async getApiKey(keyId) {
    const res = await this.pool.query('SELECT * FROM api_keys WHERE key_id = $1', [keyId]);
    return res.rows[0] || null;
  }

  async setApiKey(key) {
    await this.pool.query(`
      INSERT INTO api_keys (key_id, org_id, role, secret_hash, expires_at, last_used, revoked, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (key_id) DO UPDATE SET
        org_id = EXCLUDED.org_id,
        role = EXCLUDED.role,
        secret_hash = EXCLUDED.secret_hash,
        expires_at = EXCLUDED.expires_at,
        last_used = EXCLUDED.last_used,
        revoked = EXCLUDED.revoked
    `, [key.key_id, key.org_id, key.role, key.secret_hash, key.expires_at, key.last_used, key.revoked, key.created_at]);
  }

  async listApiKeys(orgId) {
    const res = await this.pool.query('SELECT * FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC', [orgId]);
    return res.rows;
  }

  async revokeApiKey(keyId) {
    await this.pool.query('UPDATE api_keys SET revoked = TRUE WHERE key_id = $1', [keyId]);
  }

  async updateApiKeyLastUsed(keyId) {
    await this.pool.query('UPDATE api_keys SET last_used = NOW() WHERE key_id = $1', [keyId]);
  }

  async all(col) {
    const res = await this.pool.query(`SELECT * FROM ${col} ORDER BY created_at DESC`);
    return res.rows;
  }

  async has(col, id) {
    const res = await this.pool.query(`SELECT 1 FROM ${col} WHERE id = $1`, [id]);
    return res.rows.length > 0;
  }

  async del(col, id) {
    await this.pool.query(`DELETE FROM ${col} WHERE id = $1`, [id]);
  }

  async dumpCollection(collection) {
    const res = await this.pool.query('SELECT data FROM authragen_records WHERE collection = $1 ORDER BY created_at DESC', [collection]);
    return res.rows.map(r => r.data);
  }
  async setRecord(collection, obj) {
    await this.pool.query('INSERT INTO authragen_records (collection,id,org_id,data,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (collection,id) DO UPDATE SET org_id=EXCLUDED.org_id,data=EXCLUDED.data,updated_at=EXCLUDED.updated_at', [collection,obj.id,obj.org_id||null,JSON.stringify(obj),obj.created_at?new Date(obj.created_at):new Date(),new Date()]);
  }
  async deleteRecord(collection,id){ await this.pool.query('DELETE FROM authragen_records WHERE collection = $1 AND id = $2',[collection,id]); }
  backend() { return 'postgres'; }
}

module.exports = { PostgresStore };