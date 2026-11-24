const mysql = require('mysql2/promise');
const { loadConfig, loadDotEnv } = require('./config');
const { createApp } = require('./server');

function createPool(db) {
  return mysql.createPool({
    ...db,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,
  });
}

function buildApp({ config, pool }) {
  return createApp({
    mysqlPool: pool,
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
