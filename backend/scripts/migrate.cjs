// Applies migrations/*.sql in lexicographic filename order and records each in schema_migrations.
// MySQL DDL auto-commits: if a file fails halfway, fix it by hand or reset the
// dev database (docker compose down -v).
const fs = require('node:fs/promises');
const path = require('node:path');
const { backendDir, loadConfig, loadDotEnv } = require('../src/config');

const DEFAULT_MIGRATIONS_DIR = path.join(backendDir, 'migrations');

async function getMigrationFiles(migrationsDir = DEFAULT_MIGRATIONS_DIR) {
  const entries = await fs.readdir(migrationsDir);
  return entries.filter((file) => /^[0-9]{3}_[a-z0-9_]+\.sql$/.test(file)).sort();
}

async function applyMigrations(connection, migrationsDir = DEFAULT_MIGRATIONS_DIR) {
  await connection.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename VARCHAR(255) NOT NULL PRIMARY KEY,
      applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE = InnoDB
  `);
  const [rows] = await connection.query('SELECT filename FROM schema_migrations');
  const applied = new Set(rows.map((row) => row.filename));
  const files = await getMigrationFiles(migrationsDir);
  const newlyApplied = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
    await connection.query(sql);
    await connection.execute('INSERT INTO schema_migrations (filename) VALUES (?)', [file]);
    newlyApplied.push(file);
  }
  return { applied: newlyApplied, totalFiles: files.length };
}

async function main() {
  loadDotEnv();
  const { db } = loadConfig();
  const mysql = require('mysql2/promise');
  const connection = await mysql.createConnection({ ...db, timezone: 'Z', multipleStatements: true });
  try {
    const result = await applyMigrations(connection);
    if (result.applied.length > 0) {
      console.log(`Applied migrations: ${result.applied.join(', ')}`);
    }
    console.log('Migrations are up to date');
  } finally {
    await connection.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_MIGRATIONS_DIR,
  getMigrationFiles,
  applyMigrations,
};
