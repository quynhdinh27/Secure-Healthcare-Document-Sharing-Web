const test = require('node:test');
const assert = require('node:assert/strict');
const { DEFAULT_SEED_ACCOUNTS, seedUsers } = require('../scripts/seed-users.cjs');
const { loadConfig } = require('../src/config');

test('seedUsers creates 5 departments and 16 distinct-password accounts idempotently without hardcoded department IDs', async () => {
  const departments = new Map();
  const users = new Map();
  let nextDeptId = 101n;
  let nextUserId = 1001n;

  const connection = {
    async beginTransaction() {},
    async commit() {},
    async rollback() {},
    release() {},
    async execute(sql, params) {
      if (sql.startsWith('SELECT CAST(department_id AS CHAR)')) {
        const existing = departments.get(params[0]);
        return [existing ? [{ departmentId: existing.departmentId }] : []];
      }
      if (sql.startsWith('INSERT INTO Department')) {
        const departmentId = String(nextDeptId++);
        departments.set(params[0], { departmentId, departmentCode: params[0], departmentName: params[1] });
        return [{ insertId: departmentId }];
      }
      if (sql.startsWith('UPDATE Department')) {
        return [{ affectedRows: 1 }];
      }
      if (sql.startsWith('SELECT CAST(user_id AS CHAR)')) {
        const existing = users.get(params[0]);
        return [existing ? [{ userId: existing.userId }] : []];
      }
      if (sql.startsWith('INSERT INTO `User`')) {
        const userId = String(nextUserId++);
        users.set(params[1], {
          userId,
          departmentId: params[0],
          email: params[1],
          passwordHash: params[2],
          fullName: params[3],
          accountType: params[4],
          accountStatus: params[5],
        });
        return [{ insertId: userId }];
      }
      if (sql.startsWith('UPDATE `User`')) {
        return [{ affectedRows: 1 }];
      }
      throw new Error(`Unexpected SQL: ${sql}`);
    },
  };
  const pool = { async getConnection() { return connection; } };

  // Distinct dev passwords per account
  const uniquePasswords = new Set(DEFAULT_SEED_ACCOUNTS.map((a) => a.devPassword));
  assert.equal(uniquePasswords.size, 16);

  const first = await seedUsers(pool, { env: { NODE_ENV: 'development' } });
  assert.equal(first.departments.length, 5);
  assert.equal(first.accounts.length, 16);
  assert.equal(first.accounts.filter((a) => a.accountType === 'ADMIN' && a.accountStatus === 'ACTIVE').length, 2);
  assert.equal(first.accounts.filter((a) => a.accountType === 'STAFF' && a.accountStatus === 'ACTIVE').length, 12);
  assert.equal(first.accounts.filter((a) => a.accountStatus === 'DISABLED').length, 2);
  // Verifies department IDs came from lookup/insert (101..105), not hardcoded 1..5
  assert.ok(first.accounts.some((a) => a.departmentId === '101'));

  // Re-run is idempotent (same 16 users, no duplicates)
  const second = await seedUsers(pool, { env: { NODE_ENV: 'development' } });
  assert.equal(users.size, 16);
  assert.equal(departments.size, 5);
  assert.deepEqual(
    second.accounts.map((a) => a.userId),
    first.accounts.map((a) => a.userId),
  );

  // Refuses default dev passwords in production
  await assert.rejects(
    () => seedUsers(pool, { env: { NODE_ENV: 'production' } }),
    /Refusing to seed default development passwords/,
  );
});

test('loadConfig validates DB_PASSWORD, AUTH_MODE, COOKIE_SECURE, and TTL bounds', () => {
  assert.throws(() => loadConfig({}), /DB_PASSWORD is required/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'pw', AUTH_MODE: 'dev' }), /AUTH_MODE must be: session/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'pw', COOKIE_SECURE: 'yes' }), /COOKIE_SECURE must be/);

  const cfg = loadConfig({ DB_PASSWORD: 'pw', COOKIE_SECURE: 'false', PORT: '4000' });
  assert.equal(cfg.port, 4000);
  assert.equal(cfg.cookieSecure, false);
  assert.equal(cfg.authMode, 'session');
  assert.equal(cfg.sessionTtlMs, 8 * 60 * 60 * 1000);
  assert.equal(cfg.reauthTtlMs, 5 * 60 * 1000);

  const defaultCfg = loadConfig({ DB_PASSWORD: 'pw' });
  assert.equal(defaultCfg.cookieSecure, true);
});
