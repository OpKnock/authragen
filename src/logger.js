'use strict';

function createLogger({ service = 'authragen', env = 'development' } = {}) {
  const isProd = env === 'production';
  const level = process.env.LOG_LEVEL || (isProd ? 'info' : 'debug');
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  const currentLevel = levels[level] ?? 1;

  function shouldLog(l) {
    return levels[l] >= currentLevel;
  }

  function formatMessage(l, msg, meta = {}) {
    const base = {
      timestamp: new Date().toISOString(),
      level: l,
      service,
      message: msg,
      ...meta
    };
    return JSON.stringify(base);
  }

  return {
    debug: (msg, meta) => { if (shouldLog('debug')) console.log(formatMessage('debug', msg, meta)); },
    info: (msg, meta) => { if (shouldLog('info')) console.log(formatMessage('info', msg, meta)); },
    warn: (msg, meta) => { if (shouldLog('warn')) console.warn(formatMessage('warn', msg, meta)); },
    error: (msg, meta) => { if (shouldLog('error')) console.error(formatMessage('error', msg, meta)); },
  };
}

module.exports = { createLogger };