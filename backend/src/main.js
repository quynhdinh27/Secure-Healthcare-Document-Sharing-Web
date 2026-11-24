const mysql = require('mysql2/promise');
const { devHeaderAuth } = require('./auth/dev-header-auth');
const { loadConfig, loadDotEnv } = require('./config');
const { createMysqlKeyDirectory } = require('./keys/mysql-key-directory');
const { createApp } = require('./server');
const { createLocalObjectStorage } = require('./storage/local-object-storage');

function createPool(db) {
  return mysql.createPool({
    ...db,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,
  });
}

function buildApp({ config, pool }) {
  const isDevAuth = config.authMode === 'dev';
  if (!isDevAuth && config.authMode !== 'session') {
    throw new Error(`Unsupported AUTH_MODE: ${config.authMode}`);
  }
  return createApp({
    authenticate: isDevAuth ? devHeaderAuth : undefined,
    mysqlPool: pool,
    keyDirectory: createMysqlKeyDirectory(),
    objectStorage: createLocalObjectStorage({ rootDir: config.storage.dir }),
    maxUploadBytes: config.maxUploadBytes,
    uploadContextTtlSeconds: config.uploadContextTtlSeconds,
    cookieSecure: config.cookieSecure,
    sessionTtlMs: config.sessionTtlMs,
    reauthTtlMs: config.reauthTtlMs,
  });
}

async function main() {
  loadDotEnv();
  const config = loadConfig();
  const pool = createPool(config.db);
  await pool.query('SELECT 1');
  if (config.authMode === 'dev') {
    // Dev header auth trusts any caller, so the dev server only listens on loopback.
    buildApp({ config, pool }).listen(config.port, '127.0.0.1', () => {
      console.log(`Backend running at http://localhost:${config.port}`);
      console.warn('AUTH_MODE=dev: X-Dev-User-Id identifies the caller. Development use only.');
    });
    return;
  }
  buildApp({ config, pool }).listen(config.port, () => {
    console.log(`Backend running at http://localhost:${config.port}`);
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { buildApp, createPool };
