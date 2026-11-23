// Applies migrations/*.sql in filename order and records each in schema_migrations.
// MySQL DDL auto-commits: if a file fails halfway, fix it by hand or reset the
// dev database (docker compose down -v).
const fs = require('node:fs/promises');
const path = require('node:path');
const mysql = require('mysql2/promise');
const { backendDir, loadConfig, loadDotEnv } = require('../src/config');

async function main() {
  loadDotEnv();
  const { db } = loadConfig();
  const connection = await mysql.createConnection({ ...db, multipleStatements: true });
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        filename VARCHAR(255) NOT NULL PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE = InnoDB
    `);
    const [rows] = await connection.query('SELECT filename FROM schema_migrations');
    const applied = new Set(rows.map((row) => row.filename));
    const dir = path.join(backendDir, 'migrations');
    const files = (await fs.readdir(dir)).filter((file) => /^[0-9]{3}_[a-z0-9_]+\.sql$/.test(file)).sort();
    for (const file of files) {
      if (applied.has(file)) continue;
      console.log(`Applying ${file}`);
      await connection.query(await fs.readFile(path.join(dir, file), 'utf8'));
      await connection.execute('INSERT INTO schema_migrations (filename) VALUES (?)', [file]);
    }
    console.log('Migrations are up to date');
  } finally {
    await connection.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
