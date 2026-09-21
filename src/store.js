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

async function initStore() {
  const backendType = (process.env.AUTHRA_STORE || 'file').toLowerCase();
  activeBackend = backendType;
  
  if (backendType === 'postgres') {
    const connectionString = process.env.DATABASE_URL || process.env.AUTHRA_POSTGRES_URL;
    if (!connectionString) throw new Error('DATABASE_URL or AUTHRA_POSTGRES_URL required for Postgres backend');
    const { PostgresStore } = require('./store/postgres');
    activeStore = new PostgresStore(connectionString);
    await activeStore.init();
    console.log('[store] Initialized Postgres backend');
  } else if (backendType === 'redis') {
    const redisUrl = process.env.REDIS_URL || process.env.AUTHRA_REDIS_URL;
    if (!redisUrl) throw new Error('REDIS_URL or AUTHRA_REDIS_URL required for Redis backend');
    const { RedisStore } = require('./store/redis');
    activeStore = new RedisStore(redisUrl);
    await activeStore.connect();
    console.log('[store] Initialized Redis backend');
  } else {
    const fileModule = require('./store/file');
    activeStore = fileModule.store;
    console.log('[store] Initialized file backend (development only)');
  }
  
  return activeStore;
}

function getStore() {
  if (!activeStore) {
    throw new Error('Store not initialized. Call initStore() first.');
  }
  return activeStore;
}

function backend() { return activeBackend || 'file'; }

module.exports = { initStore, getStore, backend, DATA_DIR };