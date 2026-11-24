const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { once } = require('node:events');
const { test } = require('node:test');
const { createApp } = require('../src/server');
const { createMysqlKeyEnrollmentRepository } = require('../src/keys/mysql-key-enrollment-repository');

// Keep the SQL adapter exercised while running the real HTTP and crypto paths without a database.
function createPoolFixture() {
  const rows = new Map();
  async function execute(statement, values) {
    const sql = statement.replace(/\s+/g, ' ').trim();
    const [first, second, third] = values;
    if (sql.startsWith('SELECT user_id FROM')) return [[{ user_id: first }]];
    if (sql.startsWith('SELECT key_id FROM')) {
      return [[...rows.values()].filter(
        (row) => row.userId === first && row.purpose === second && row.status === 'ACTIVE',
      )];
    }
    if (sql.startsWith('DELETE FROM User_Key')) {
      for (const row of rows.values()) {
        if (row.userId === first && row.purpose === second && row.status === 'PENDING_VERIFICATION') rows.delete(row.keyId);
      }
      return [];
    }
    if (sql.startsWith('INSERT INTO User_Key')) {
      rows.set(first, {
        keyId: first, userId: second, purpose: third, publicKeyJwk: values[4], fingerprint: values[5],
        challenge: values[6], responseHash: values[7], status: 'PENDING_VERIFICATION',
      });
      return [];
    }
    if (sql.startsWith('UPDATE User_Key SET encrypted_backup')) {
      rows.get(second).backup = first;
      return [];
    }
    if (sql.startsWith("UPDATE User_Key SET status = 'ACTIVE'")) {
      Object.assign(rows.get(first), { status: 'ACTIVE', challenge: null, responseHash: null });
      return [];
    }
    assert.match(sql, /^SELECT key_id AS keyId, purpose/);
    return [[...rows.values()].filter((row) => row.userId === first && (second === undefined || row.keyId === second))];
  }
  return {
    rows,
    execute,
    async getConnection() {
      return { execute, async beginTransaction() {}, async commit() {}, async rollback() {}, release() {} };
    },
  };
}

test('cookie-authenticated setup enrolls and restores browser SIGN and ENC keys', async (t) => {
  const { beginKeyEnrollment, answerKeyChallenge, finalizeLocalKey, restorePrivateKey } =
    await import('../../crypto/keys/enrollment.js');
  // The test provider isolates transport and backup binding from Argon2's work factor.
  const deriveArgon2id = (password, salt) => createHash('sha256').update(password).update(salt).digest();
  const pool = createPoolFixture();
  const app = createApp({
    cookieSecure: false,
    seedUsers: [{ email: 'keys@medshare.test', password: 'TestPassword!', fullName: 'Test Staff' }],
    keyEnrollmentRepository: createMysqlKeyEnrollmentRepository(pool),
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  const jar = new Map();
  async function call(path, method = 'GET', body, useCsrf = true) {
    const headers = { cookie: [...jar.values()].join('; ') };
    if (useCsrf && jar.has('medshare_csrf')) {
      headers['x-csrf-token'] = decodeURIComponent(jar.get('medshare_csrf').split('=')[1]);
    }
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    for (const cookie of res.headers.getSetCookie()) jar.set(cookie.split('=')[0], cookie.split(';')[0]);
    return { status: res.status, data: await res.json() };
  }
  const path = '/users/me/keys';
  assert.equal((await call(path)).status, 401);
  await call('/auth/csrf');
  const login = await call('/auth/login', 'POST', { email: 'keys@medshare.test', password: 'TestPassword!' });
  assert.equal(login.status, 200, JSON.stringify(login.data));
  const userId = String(login.data.user.userId);
  assert.equal((await call(path, 'POST', {}, false)).data.code, 'CSRF_INVALID');
  assert.equal((await call(path, 'POST', {})).data.code, 'REAUTHENTICATION_REQUIRED');
  assert.equal((await call('/auth/reauthenticate', 'POST', { password: 'TestPassword!' })).status, 200);

  for (const purpose of ['SIGN', 'ENC']) {
    const enrollment = await beginKeyEnrollment({ userId, purpose });
    const registered = await call(path, 'POST', { ...enrollment.registration, userId: 'different-user' });
    assert.equal(registered.status, 201, JSON.stringify(registered.data));
    const { keyId, challenge } = registered.data;
    assert.equal(challenge.userId, userId);
    assert.equal(Object.hasOwn(registered.data, 'responseHash'), false);
    const endpoint = path + '/' + keyId;
    const response = await answerKeyChallenge(enrollment, { keyId, challenge });
    assert.equal((await call(endpoint + '/activate', 'POST', { response })).data.code, 'KEY_BACKUP_REQUIRED');

    const passphrase = 'test recovery passphrase';
    const { backup } = await finalizeLocalKey(enrollment, { keyId, passphrase, deriveArgon2id });
    assert.equal((await call(endpoint + '/backup', 'PUT', {
      backup: { ...backup, userId: 'different-user' },
    })).data.code, 'INVALID_KEY_BACKUP');
    assert.equal((await call(endpoint + '/backup', 'PUT', { backup })).status, 200);
    assert.equal((await call(endpoint + '/activate', 'POST', { response: 'wrong-response' })).data.code, 'INVALID_KEY_PROOF');
    assert.deepEqual(await call(endpoint + '/activate', 'POST', { response }), {
      status: 200, data: { keyId, status: 'ACTIVE' },
    });
    assert.equal(pool.rows.get(keyId).challenge, null);
    assert.equal(pool.rows.get(keyId).responseHash, null);
    assert.equal((await call(endpoint + '/activate', 'POST', { response })).data.code, 'KEY_NOT_PENDING');
    assert.equal((await call(path, 'POST', enrollment.registration)).data.code, 'KEY_ALREADY_ACTIVE');
    const stored = await call(endpoint + '/backup');
    assert.equal(stored.status, 200);
    const privateKey = await restorePrivateKey({ ...stored.data, passphrase, deriveArgon2id });
    assert.equal(privateKey.type, 'private');
    assert.equal(privateKey.extractable, false);
  }
  const keys = await call(path);
  assert.deepEqual(keys.data.map(({ purpose }) => purpose).sort(), ['ENC', 'SIGN']);
  assert.ok(keys.data.every((key) => key.status === 'ACTIVE' && !('backup' in key) && !('challenge' in key)));
});
