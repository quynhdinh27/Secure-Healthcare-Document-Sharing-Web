const path = require('node:path');

const backendDir = path.resolve(__dirname, '..');

function loadDotEnv(file = path.join(backendDir, '.env')) {
  try {
    process.loadEnvFile(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function readInteger(env, name, fallback, min, max) {
  const raw = env[name] ?? String(fallback);
  if (!/^[0-9]{1,10}$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return Number(raw);
}

function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const authMode = env.AUTH_MODE || 'dev';
  const storageDriver = env.STORAGE_DRIVER || 'local';
  if (authMode !== 'dev') throw new Error('AUTH_MODE must be one of: dev');
  if (authMode === 'dev' && nodeEnv === 'production') {
    throw new Error('AUTH_MODE=dev is not allowed when NODE_ENV=production');
  }
  if (storageDriver !== 'local') throw new Error('STORAGE_DRIVER must be one of: local');
  if (!env.DB_PASSWORD) throw new Error('DB_PASSWORD is required');
  return Object.freeze({
    nodeEnv,
    port: readInteger(env, 'PORT', 3000, 1, 65535),
    db: Object.freeze({
      host: env.DB_HOST || '127.0.0.1',
      port: readInteger(env, 'DB_PORT', 3306, 1, 65535),
      user: env.DB_USER || 'medshare',
      password: env.DB_PASSWORD,
      database: env.DB_NAME || 'medshare',
    }),
    authMode,
    storage: Object.freeze({
      driver: storageDriver,
      dir: path.resolve(backendDir, env.STORAGE_DIR || 'data/objects'),
    }),
    maxUploadBytes: readInteger(env, 'MAX_UPLOAD_MB', 25, 1, 1024) * 1024 * 1024,
    uploadContextTtlSeconds: readInteger(env, 'UPLOAD_CONTEXT_TTL_SECONDS', 600, 60, 3600),
  });
}

module.exports = { backendDir, loadConfig, loadDotEnv };
