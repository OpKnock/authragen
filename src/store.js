'use strict';

const fs = require('node:fs');
const path = require('node:path');

const BACKENDS = {
  file: require('./store/file'),
  postgres: require('./store/postgres'),
  redis: require('./store/redis')
};

function resolveDataDir() { return process.env.AUTHRA_DATA || path.join(__dirname, '..', 'data'); }
const DATA_DIR = resolveDataDir();

let activeStore = null;
let activeBackend = null;

const COLLECTIONS = ['orgs','passports','tokens','policies','revocations','approvals','apikeys','blueprints'];

class PersistentMirrorStore {
  constructor(remote, backendType){ this.remote=remote; this.backendType=backendType; this.mem=Object.fromEntries(COLLECTIONS.map(c=>[c,Object.create(null)])); this.writeChain=Promise.resolve(); this.refreshing=null; this.lastWriteError=null; this.lastSyncAt=0; }
  async init(){ if(this.remote.init) await this.remote.init(); else if(this.remote.connect) await this.remote.connect(); await this.refresh(); return this; }
  _persist(task){
    this.writeChain=this.writeChain.then(async()=>{
      await task();
    }).catch(err=>{
      this.lastWriteError=err;
      console.error('[store] persistent write failed:',err.message);
    });
  }
  async flush(){
    await this.writeChain;
    if(this.lastWriteError){
      throw Object.assign(new Error('persistent store write failed: '+this.lastWriteError.message), { code:'storage_error' });
    }
  }
  async refresh(){
    if(this.backendType === 'file' || !this.remote.dumpCollection) return;
    if(this.refreshing) return this.refreshing;
    this.refreshing = (async()=>{
      await this.flush();
      const snapshots = await Promise.all(COLLECTIONS.map(async col => [col, await this.remote.dumpCollection(col)]));
      for(const [col, rows] of snapshots){
        const next = Object.create(null);
        for(const row of rows || []) if(row && row.id) next[row.id]=row;
        this.mem[col]=next;
      }
      this.lastSyncAt=Date.now();
    })().finally(()=>{ this.refreshing=null; });
    return this.refreshing;
  }
  consistencyMode(){ return this.backendType === 'file' ? 'single-instance' : 'remote-snapshot-per-request'; }
  get(col,id){ return this.mem[col]?.[id]||null; } all(col){ return this.mem[col]?Object.values(this.mem[col]):[]; } byOrg(col,org_id){ return this.all(col).filter(x=>x.org_id===org_id); }
  list(col,{org_id=null,status=null,limit=100,offset=0,q=null}={}){ let arr=this.all(col); if(org_id)arr=arr.filter(x=>x.org_id===org_id); if(status)arr=arr.filter(x=>(x.status||x.lifecycle||'')===status); if(q){const n=String(q).toLowerCase();arr=arr.filter(x=>JSON.stringify([x.name,x.id,x.owner,x.team,x.environment,x.model,x.framework,x.blueprint_id]).toLowerCase().includes(n));} arr=arr.slice().sort((a,b)=>(b.created_at||b.iat||0)-(a.created_at||a.iat||0)); return {items:arr.slice(offset,offset+limit),total:arr.length}; }
  put(col,obj){ if(!this.mem[col])this.mem[col]=Object.create(null); this.mem[col][obj.id]=obj; if(this.remote.setRecord)this._persist(()=>this.remote.setRecord(col,obj)); return obj; }
  del(col,id){ if(this.mem[col])delete this.mem[col][id]; if(this.remote.deleteRecord)this._persist(()=>this.remote.deleteRecord(col,id)); }
  has(col,id){ return !!this.mem[col]?.[id]; }
  async consumeNonce(...args){ return this.remote.consumeNonce(...args); } async nonceExists(...args){ return this.remote.nonceExists?this.remote.nonceExists(...args):false; }
  async consumeActionJTI(...args){ return this.remote.consumeActionJTI(...args); } async actionJTIExists(...args){ return this.remote.actionJTIExists?this.remote.actionJTIExists(...args):false; }  async checkAndDebitExecution(...args){ if(!this.remote.checkAndDebitExecution) return null; return this.remote.checkAndDebitExecution(...args); }  async getTokenSpend(...args){ if(!this.remote.getTokenSpend) return null; return this.remote.getTokenSpend(...args); }
  async close(){ await this.writeChain; if(this.remote.close)await this.remote.close(); } backend(){ return this.backendType; }
}

async function initStore(){
  const backendType=(process.env.AUTHRA_STORE||'file').toLowerCase();
  if(!['file','postgres','redis'].includes(backendType))throw new Error('unsupported AUTHRA_STORE: '+backendType);
  activeBackend=backendType;
  if(backendType==='postgres'){ const connectionString=process.env.DATABASE_URL||process.env.AUTHRA_POSTGRES_URL; if(!connectionString)throw new Error('DATABASE_URL or AUTHRA_POSTGRES_URL required for Postgres backend'); const {PostgresStore}=require('./store/postgres'); activeStore=await new PersistentMirrorStore(new PostgresStore(connectionString),backendType).init(); console.log('[store] Initialized Postgres-backed generic store'); }
  else if(backendType==='redis'){ const redisUrl=process.env.REDIS_URL||process.env.AUTHRA_REDIS_URL; if(!redisUrl)throw new Error('REDIS_URL or AUTHRA_REDIS_URL required for Redis backend'); const {RedisStore}=require('./store/redis'); activeStore=await new PersistentMirrorStore(new RedisStore(redisUrl),backendType).init(); console.log('[store] Initialized Redis-backed generic store'); }
  else{ const fileModule=require('./store/file'); activeStore=fileModule.store; console.log('[store] Initialized file backend (development only)'); }
  return activeStore;
}

function getStore() {
  if (!activeStore) {
    throw new Error('Store not initialized. Call initStore() first.');
  }
  return activeStore;
}

function backend() { return activeBackend || 'file'; }

module.exports = { initStore, getStore, backend, DATA_DIR, PersistentMirrorStore };