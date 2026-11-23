const mysql = require('mysql2/promise');
const { devHeaderAuth } = require('./auth/dev-header-auth');
const { loadConfig, loadDotEnv } = require('./config');
const { createMysqlKeyDirectory } = require('./keys/mysql-key-directory');
const { createApp } = require('./server');
const { createLocalObjectStorage } = require('./storage/local-object-storage');

function createPool(db) {
  return mysql.createPool({ ...db, timezone: 'Z', waitForConnections: true, connectionLimit: 10 });
}

function selectAuthentication(config) {
  // Only AUTH_MODE=dev exists today; the Auth module adds its session middleware here.
  if (config.authMode === 'dev') return devHeaderAuth;
  throw new Error(`Unsupported AUTH_MODE: ${config.authMode}`);
}

function buildApp({ config, pool }) {
  return createApp({
    authenticate: selectAuthentication(config),
    mysqlPool: pool,
    keyDirectory: createMysqlKeyDirectory(),
    objectStorage: createLocalObjectStorage({ rootDir: config.storage.dir }),
    maxUploadBytes: config.maxUploadBytes,
    uploadContextTtlSeconds: config.uploadContextTtlSeconds,
  });
}

async function main() {
  loadDotEnv();
  const config = loadConfig();
  const pool = createPool(config.db);
  await pool.query('SELECT 1');
  // Dev header auth trusts any caller, so the dev server only listens on loopback.
  buildApp({ config, pool }).listen(config.port, '127.0.0.1', () => {
    console.log(`Backend running at http://localhost:${config.port}`);
    console.warn('AUTH_MODE=dev: X-Dev-User-Id identifies the caller. Development use only.');
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { buildApp, createPool };
