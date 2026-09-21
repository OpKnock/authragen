'use strict';

const Redis = require('ioredis');
const crypto = require('node:crypto');

class RedisStore {
  constructor(redisUrl, opts = {}) {
    this.redis = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 100, 3000),
      enableReadyCheck: true,
      lazyConnect: true,
      ...opts
    });
    this.connected = false;
    this.connecting = null;
    this.luaScripts = {
      consumeNonce: `
        local key = KEYS[1]
        local ttl = tonumber(ARGV[1])
        if redis.call('SET', key, '1', 'EX', ttl, 'NX') then
          return 1
        else
          return 0
        end
      `,
      consumeActionJTI: `
        local key = KEYS[1]
        local ttl = tonumber(ARGV[1])
        if redis.call('SET', key, '1', 'EX', ttl, 'NX') then
          return 1
        else
          return 0
        end
      `,
      debitBudget: `
        local key = KEYS[1]
        local amount = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
        local current = redis.call('GET', key)
        current = current and tonumber(current) or 0
        if current + amount > limit then
          return {0, current}
        end
        local newVal = redis.call('INCRBY', key, amount)
        if newVal == amount then
          redis.call('EXPIRE', key, ttl)
        end
        return {1, newVal}
      `,
      addRevocation: `
        local recordKey = KEYS[1]
        local seqKey = KEYS[2]
        local existing = redis.call('GET', recordKey)
        if existing then
          return existing
        end
        local seq = redis.call('INCR', seqKey)
        local record = cjson.decode(ARGV[1])
        record['seq'] = seq
        local encoded = cjson.encode(record)
        redis.call('SET', recordKey, encoded)
        return encoded
      `,
      checkAndDebit: `
        local nonceKey = KEYS[1]
        local jtiKey = KEYS[2]
        local budgetKey = KEYS[3]
        local amount = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local ttl = tonumber(ARGV[3])
        local hasBudget = ARGV[4] == '1'
        local current = 0

        if hasBudget then
          local raw = redis.call('GET', budgetKey)
          current = raw and tonumber(raw) or 0
          if current + amount > limit then
            return {0, 'budget_exceeded', current}
          end
        end

        if redis.call('SET', nonceKey, '1', 'EX', ttl, 'NX') == false then
          return {0, 'nonce_replay', current}
        end
        if redis.call('SET', jtiKey, '1', 'EX', ttl, 'NX') == false then
          return {0, 'jti_replay', current}
        end

        if hasBudget then
          current = redis.call('INCRBY', budgetKey, amount)
          if ttl > 0 then redis.call('EXPIRE', budgetKey, ttl) end
        end

        return {1, 'ok', current}
      `
    };
  }

  async connect() {
    if (this.connected) return;
    if (this.connecting) return this.connecting;
    this.connecting = (async () => {
      await this.redis.connect();
      this.consumeNonceSha = await this.redis.script('LOAD', this.luaScripts.consumeNonce);
      this.consumeActionJTISha = await this.redis.script('LOAD', this.luaScripts.consumeActionJTI);
      this.debitBudgetSha = await this.redis.script('LOAD', this.luaScripts.debitBudget);
      this.checkAndDebitSha = await this.redis.script('LOAD', this.luaScripts.checkAndDebit);
      await this.initializeRevocationSequence();
      this.connected = true;
    })();
    try {
      await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  async initializeRevocationSequence() {
    const currentRaw = await this.redis.get('revocation:seq');
    let current = Number(currentRaw || 0);
    if (!Number.isSafeInteger(current) || current < 0) current = 0;
    if (current === 0 && currentRaw == null) {
      const existing = await this.all('revocations');
      const max = existing.reduce((m, r) => {
        const n = Number(r.seq);
        return Number.isSafeInteger(n) && n > m ? n : m;
      }, 0);
      if (max > current) {
        await this.redis.set('revocation:seq', String(max));
      } else {
        await this.redis.set('revocation:seq', '0', 'NX');
      }
    }
  }

  async close() {
    await this.redis.quit();
    this.connected = false;
  }

  // ===== Nonces (distributed atomic) =====
  async consumeNonce(orgId, nonce, ttl = 86400) {
    await this.connect();
    const key = `nonce:${orgId}:${nonce}`;
    const result = await this.redis.evalsha(this.consumeNonceSha, 1, key, ttl);
    return result === 1;
  }

  async nonceExists(orgId, nonce) {
    await this.connect();
    const key = `nonce:${orgId}:${nonce}`;
    return await this.redis.exists(key) === 1;
  }

  // ===== Action JTIs (distributed atomic) =====
  async consumeActionJTI(jti, ttl = 86400) {
    await this.connect();
    const key = `action:jti:${jti}`;
    const result = await this.redis.evalsha(this.consumeActionJTISha, 1, key, ttl);
    return result === 1;
  }

  async actionJTIExists(jti) {
    await this.connect();
    const key = `action:jti:${jti}`;
    return await this.redis.exists(key) === 1;
  }

  // ===== Budgets (distributed atomic) =====
  async debitBudget(orgId, passportId, period, amountCents, limitCents, ttl = 86400) {
    await this.connect();
    const key = `budget:${orgId}:${passportId}:${period}`;
    const result = await this.redis.evalsha(this.debitBudgetSha, 1, key, amountCents, limitCents, ttl);
    return { success: result[0] === 1, current: result[1] };
  }

  async checkBudget(orgId, passportId, period, limitCents) {
    await this.connect();
    const key = `budget:${orgId}:${passportId}:${period}`;
    const current = await this.redis.get(key);
    return (parseInt(current || '0', 10)) < limitCents;
  }

  async getBudget(orgId, passportId, period) {
    await this.connect();
    const key = `budget:${orgId}:${passportId}:${period}`;
    return parseInt(await this.redis.get(key) || '0', 10);
  }

  // ===== Atomic check-and-debit (nonce + jti + budget) =====
  async addRevocation(r) {
    await this.connect();
    const id = r.id || (String(r.type) + ':' + String(r.target));
    const record = { ...r, id, target: r.target ?? r.id, kid: r.kid || null, reason: r.reason || 'manual', at: r.at || Date.now() };
    const result = await this.redis.eval(
      this.luaScripts.addRevocation, 2,
      `revocations:${id}`, 'revocation:seq', JSON.stringify(record)
    );
    return JSON.parse(result);
  }

  async getRevocationHead() {
    await this.connect();
    return Number(await this.redis.get('revocation:seq') || 0);
  }

  async getTokenSpend(tokenId) {
    await this.connect();
    return Number(await this.redis.get(`token-spend:${tokenId}`) || 0);
  }

  async checkAndDebit(orgId, passportId, period, nonce, actionJti, amountCents, limitCents, ttl = 86400) {
    await this.connect();
    const nonceKey = `nonce:${orgId}:${nonce}`;
    const jtiKey = `action:jti:${actionJti}`;
    const budgetKey = `budget:${orgId}:${passportId}:${period}`;
    const result = await this.redis.evalsha(this.checkAndDebitSha, 3, nonceKey, jtiKey, budgetKey, amountCents, limitCents, ttl, '1');
    return { success: result[0] === 1, error: result[1], current: Number(result[2] || 0) };
  }

  async checkAndDebitExecution(orgId, nonce, actionJti, tokenId, amountCents, limitCents, ttl = 86400) {
    await this.connect();
    const nonceKey = `nonce:${orgId}:${nonce}`;
    const jtiKey = `action:jti:${actionJti}`;
    const budgetKey = `token-spend:${tokenId || actionJti}`;
    const result = await this.redis.evalsha(this.checkAndDebitSha, 3, nonceKey, jtiKey, budgetKey, Number(amountCents) || 0, Number(limitCents), ttl, tokenId ? '1' : '0');
    return { success: result[0] === 1, error: result[1], current: Number(result[2] || 0) };
  }

  // ===== Rate Limiting =====
  async checkRateLimit(key, limit, windowMs) {
    await this.connect();
    const redisKey = `ratelimit:${key}`;
    const current = await this.redis.incr(redisKey);
    if (current === 1) {
      await this.redis.pexpire(redisKey, windowMs);
    }
    const ttl = await this.redis.pttl(redisKey);
    return { allowed: current <= limit, current, remaining: Math.max(0, limit - current), resetMs: Date.now() + ttl };
  }

  // ===== Distributed Locks =====
  async acquireLock(key, ttlMs = 10000, owner = null) {
    await this.connect();
    const lockKey = `lock:${key}`;
    const lockValue = owner || crypto.randomUUID();
    const result = await this.redis.set(lockKey, lockValue, 'PX', ttlMs, 'NX');
    return result === 'OK' ? lockValue : null;
  }

  async releaseLock(key, owner) {
    await this.connect();
    const lockKey = `lock:${key}`;
    const script = `
      if redis.call('GET', KEYS[1]) == ARGV[1] then
        return redis.call('DEL', KEYS[1])
      else
        return 0
      end
    `;
    return await this.redis.eval(script, 1, lockKey, owner) === 1;
  }

  async extendLock(key, owner, ttlMs) {
    await this.connect();
    const lockKey = `lock:${key}`;
    const script = `
      if redis.call('GET', KEYS[1]) == ARGV[1] then
        return redis.call('PEXPIRE', KEYS[1], ARGV[2])
      else
        return 0
      end
    `;
    return await this.redis.eval(script, 1, lockKey, owner, ttlMs) === 1;
  }

  // ===== Pub/Sub for Revocation Feed =====
  async publishRevocation(orgId, revocation) {
    await this.connect();
    await this.redis.publish(`revocations:${orgId}`, JSON.stringify(revocation));
  }

  subscribeRevocations(orgId, handler) {
    const sub = this.redis.duplicate();
    sub.subscribe(`revocations:${orgId}`);
    sub.on('message', (channel, message) => {
      try { handler(JSON.parse(message)); } catch {}
    });
    return sub;
  }

  // ===== Session / Cache =====
  async setSession(key, value, ttlMs) {
    await this.connect();
    await this.redis.set(`session:${key}`, JSON.stringify(value), 'PX', ttlMs);
  }

  async getSession(key) {
    await this.connect();
    const val = await this.redis.get(`session:${key}`);
    return val ? JSON.parse(val) : null;
  }

  async deleteSession(key) {
    await this.connect();
    await this.redis.del(`session:${key}`);
  }

  // ===== Metrics Counters =====
  async incrMetric(name, labels = {}, value = 1) {
    await this.connect();
    const labelStr = Object.entries(labels).sort((a,b) => a[0].localeCompare(b[0]))
      .map(([k,v]) => `${k}="${v}"`).join(',');
    const key = `metrics:${name}{${labelStr}}`;
    await this.redis.incrby(key, value);
  }

  async getMetric(name, labels = {}) {
    await this.connect();
    const labelStr = Object.entries(labels).sort((a,b) => a[0].localeCompare(b[0]))
      .map(([k,v]) => `${k}="${v}"`).join(',');
    const key = `metrics:${name}{${labelStr}}`;
    return parseInt(await this.redis.get(key) || '0', 10);
  }

  async all(col) {
    await this.connect();
    const values = [];
    let cursor = '0';
    do {
      const [next, keys] = await this.redis.scan(cursor, 'MATCH', col + ':*', 'COUNT', 500);
      cursor = next;
      if (keys.length) {
        const batch = await this.redis.mget(keys);
        values.push(...batch.filter(v => v).map(v => JSON.parse(v)));
      }
    } while (cursor !== '0');
    return values;
  }
  async dumpCollection(collection){ return this.all(collection); }
  async getRecord(collection,id){ await this.connect(); const v=await this.redis.get(collection+':'+id); return v?JSON.parse(v):null; }
  async setRecord(collection,obj){ await this.connect(); await this.redis.set(collection+':'+obj.id,JSON.stringify(obj)); }
  async deleteRecord(collection,id){ await this.connect(); await this.redis.del(collection+':'+id); }


  async has(col, id) {
    return await this.redis.exists(`${col}:${id}`) === 1;
  }

  async del(col, id) {
    await this.redis.del(`${col}:${id}`);
  }

  backend() { return 'redis'; }
}

module.exports = { RedisStore };