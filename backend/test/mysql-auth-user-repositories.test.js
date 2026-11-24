const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { createMysqlSessionRepository } = require('../src/auth/mysql-session-repository');
const { createMysqlUserRepository, escapeLikePattern } = require('../src/users/mysql-user-repository');
const { createMysqlAuditRepository } = require('../src/audit/mysql-audit-repository');
const { applyMigrations, getMigrationFiles } = require('../scripts/migrate.cjs');

test('mysql-session-repository uses UTC_TIMESTAMP(3), DATE_FORMAT Z, field truncation, and unrevoked logout guard', async () => {
  const calls = [];
  const pool = {
    async execute(sql, params) {
      calls.push({ sql, params });
      if (sql.includes('UPDATE User_Session') && sql.includes('AND revoked_at IS NULL')) {
        return [{ affectedRows: 0 }];
      }
      if (sql.includes('FROM User_Session AS s')) {
        return [[{
          sessionId: 'sess-1',
          userId: '7',
          csrfTokenHash: 'h',
          reauthenticatedAt: null,
          expiresAt: '2026-11-24T12:00:00.000000Z',
          revokedAt: null,
          revokeReason: null,
          createdAt: '2026-11-24T04:00:00.000000Z',
          lastSeenAt: '2026-11-24T04:00:00.000000Z',
          email: 'a@hospital.local',
          fullName: 'Doc A',
          accountType: 'STAFF',
          accountStatus: 'ACTIVE',
          departmentId: '2',
          departmentName: 'Oncology',
          userCreatedAt: '2026-11-24T00:00:00.000000Z',
          userUpdatedAt: '2026-11-24T00:00:00.000000Z',
        }]];
      }
      return [{ affectedRows: 1 }];
    },
  };

  const repo = createMysqlSessionRepository(pool);
  await repo.createSession({
    sessionId: 'sess-1',
    userId: '7',
    tokenHash: 'a'.repeat(64),
    csrfTokenHash: 'b'.repeat(64),
    ttlMs: 300_000,
    ipAddress: '1'.repeat(60),
    userAgent: 'U'.repeat(300),
  });
  assert.match(calls[0].sql, /TIMESTAMPADD\(MICROSECOND, \?, UTC_TIMESTAMP\(3\)\)/);
  assert.equal(calls[0].params[5].length, 45);
  assert.equal(calls[0].params[6].length, 255);

  const found = await repo.findActiveSessionWithUserByTokenHash('a'.repeat(64));
  assert.match(calls[1].sql, /DATE_FORMAT\(s\.reauthenticated_at, '%Y-%m-%dT%H:%i:%s\.%fZ'\)/);
  assert.match(calls[1].sql, /s\.expires_at > UTC_TIMESTAMP\(3\)/);
  assert.equal(found.user.userId, '7');
  assert.equal(found.user.departmentId, '2');

  const logoutRes = await repo.revokeSessionByTokenHash('a'.repeat(64), 'USER_LOGOUT');
  assert.match(calls[2].sql, /WHERE token_hash = \? AND revoked_at IS NULL/);
  assert.deepEqual(logoutRes, { revoked: false });
});

test('mysql-user-repository uses FOR UPDATE, same-connection session revocation, rollback, and ESCAPE LIKE', async () => {
  assert.equal(escapeLikePattern('100%_!test'), '100!%!_!!test');

  const events = [];
  let shouldFailAfterRevoke = false;
  const connection = {
    async beginTransaction() { events.push('begin'); },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
    async execute(sql, params) {
      events.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
      if (sql.includes('FROM `User`') && sql.includes('WHERE user_id = ?') && sql.includes('FOR UPDATE')) {
        return [[{ userId: '2', fullName: 'Admin 2', accountType: 'ADMIN', accountStatus: 'ACTIVE', departmentId: null }]];
      }
      if (sql.includes("account_type = 'ADMIN' AND account_status = 'ACTIVE'")) {
        return [[{ userId: '1' }, { userId: '2' }]];
      }
      if (sql.includes('UPDATE User_Session') && shouldFailAfterRevoke) {
        throw new Error('simulated DB failure');
      }
      if (sql.includes('FROM `User` AS u') && sql.includes('WHERE u.user_id = ?')) {
        return [[{
          userId: '2', email: 'a2@hospital.local', fullName: 'Admin 2',
          accountType: 'ADMIN', accountStatus: 'DISABLED', departmentId: null,
          departmentName: null, createdBy: '1', updatedBy: '1',
          createdAt: '2026-11-24T00:00:00.000000Z', updatedAt: '2026-11-24T01:00:00.000000Z',
        }]];
      }
      return [{ affectedRows: 1 }];
    },
  };

  const queryCalls = [];
  const pool = {
    async getConnection() { return connection; },
    async execute(sql, params) {
      queryCalls.push({ method: 'execute', sql, params });
      return [[{ total: 1 }]];
    },
    async query(sql, params) {
      queryCalls.push({ method: 'query', sql, params });
      return [[]];
    },
  };

  const repo = createMysqlUserRepository(pool);
  await repo.searchActiveStaff({ query: '100%', limit: 10 });
  assert.equal(queryCalls[0].method, 'query');
  assert.match(queryCalls[0].sql, /LIKE \? ESCAPE '!'/);
  assert.equal(queryCalls[0].params[0], '%100!%%');

  const okStatus = await repo.updateUserStatus({ userId: '2', accountStatus: 'DISABLED', actorId: '1' });
  assert.equal(okStatus.user.accountStatus, 'DISABLED');
  assert.ok(events.some((e) => typeof e === 'object' && e.sql.includes("revoke_reason = 'ACCOUNT_DISABLED'")));
  assert.equal(events.at(-2), 'commit');
  assert.equal(events.at(-1), 'release');

  events.length = 0;
  shouldFailAfterRevoke = true;
  await assert.rejects(() => repo.updateUserStatus({ userId: '2', accountStatus: 'DISABLED', actorId: '1' }), /simulated DB failure/);
  assert.equal(events.at(-2), 'rollback');
  assert.equal(events.at(-1), 'release');
});

test('mysql-audit-repository truncates fields and 018_create_audit_log matches CHAR(36) UUID types', async () => {
  const executed = [];
  const repo = createMysqlAuditRepository({
    async execute(sql, params) {
      executed.push({ sql, params });
      return [{ insertId: 42 }];
    },
  });

  const res = await repo.record({
    actorId: '1',
    actionType: 'AUTH_LOGIN',
    targetType: 'USER_SESSION',
    targetId: 't'.repeat(100),
    result: 'SUCCESS',
    details: { ok: true },
    ipAddress: '9'.repeat(80),
  });
  assert.equal(res.logId, '42');
  assert.equal(executed[0].params[3].length, 64);
  assert.equal(executed[0].params[9].length, 45);
  assert.equal(executed[0].params[8], '{"ok":true}');

  const sql018 = await fs.readFile(path.join(__dirname, '../migrations/018_create_audit_log.sql'), 'utf8');
  assert.match(sql018, /folder_id CHAR\(36\) CHARACTER SET ascii COLLATE ascii_bin NULL/);
  assert.match(sql018, /document_id CHAR\(36\) CHARACTER SET ascii COLLATE ascii_bin NULL/);
  assert.match(sql018, /version_id CHAR\(36\) CHARACTER SET ascii COLLATE ascii_bin NULL/);
  assert.match(sql018, /target_id VARCHAR\(64\) NULL/);
});

test('migrate.cjs lists 000..008 and 015..018 in lexicographic order and applies idempotently', async () => {
  const files = await getMigrationFiles();
  assert.equal(files[0], '000_create_user.sql');
  assert.ok(files.includes('015_create_department.sql'));
  assert.ok(files.includes('016_alter_user_auth.sql'));
  assert.ok(files.includes('017_create_user_session.sql'));
  assert.ok(files.includes('018_create_audit_log.sql'));

  const appliedSet = new Set();
  const mockConn = {
    async query(sql) {
      if (sql.startsWith('SELECT filename FROM schema_migrations')) {
        return [[...appliedSet].map((filename) => ({ filename }))];
      }
      return [[]];
    },
    async execute(sql, [file]) {
      if (sql.startsWith('INSERT INTO schema_migrations')) {
        appliedSet.add(file);
      }
      return [{ affectedRows: 1 }];
    },
  };

  const first = await applyMigrations(mockConn);
  assert.equal(first.applied.length, files.length);
  const second = await applyMigrations(mockConn);
  assert.equal(second.applied.length, 0);
});
