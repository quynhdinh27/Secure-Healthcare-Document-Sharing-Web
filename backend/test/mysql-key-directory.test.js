const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlKeyDirectory, fingerprintPublicJwk, toPublicJwk } = require('../src/keys/mysql-key-directory');

test('key directory returns only active keys for the requested purpose', async () => {
  const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
  const connection = {
    async execute(sql, args) {
      if (sql.includes('FROM `User`')) {
        assert.match(sql, /u\.account_status = 'ACTIVE'/);
        assert.match(sql, /k\.purpose = 'ENCRYPTION' AND k\.status = 'ACTIVE'/);
        return [args[0] === '7' ? [{ eligible: 1 }] : []];
      }
      if (sql.includes('k.key_id = ?')) {
        return [[{ keyId: args[0], userId: '7', purpose: 'SIGNING', status: 'RETIRED', publicKeyJwk: JSON.stringify(jwk), fingerprint: 'f' }]];
      }
      assert.match(sql, /k\.user_id = \? AND k\.purpose = \? AND k\.status = 'ACTIVE'/);
      return [args[0] === '7'
        ? [{ keyId: 'key-' + args[1], userId: '7', purpose: args[1], status: 'ACTIVE', publicKeyJwk: jwk, fingerprint: 'f' }]
        : []];
    },
  };
  const keys = createMysqlKeyDirectory();
  assert.deepEqual(await keys.lookupActiveSigningKey(connection, '7'), jwk);
  assert.equal(await keys.lookupActiveSigningKey(connection, '8'), null);
  assert.equal((await keys.getActiveSigningKey(connection, '7')).keyId, 'key-SIGNING');
  assert.equal((await keys.getActiveEncryptionKey(connection, '7')).keyId, 'key-ENCRYPTION');
  assert.equal(await keys.getActiveEncryptionKey(connection, '8'), null);
  assert.equal(await keys.canReceiveFolderKeys(connection, '7'), true);
  assert.equal(await keys.canReceiveFolderKeys(connection, '8'), false);
  const retired = await keys.getSigningKeyById(connection, 'k1');
  assert.deepEqual(retired.publicKeyJwk, jwk);
  assert.equal(retired.status, 'RETIRED');
});

test('public JWKs keep only required members and have a canonical fingerprint', () => {
  const ec = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def', ext: true, key_ops: ['verify'] };
  assert.deepEqual(toPublicJwk(ec, 'SIGNING'), { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' });
  assert.deepEqual(toPublicJwk({ kty: 'RSA', n: 'n', e: 'AQAB', alg: 'RSA-OAEP-256' }, 'ENCRYPTION'), { kty: 'RSA', n: 'n', e: 'AQAB' });
  assert.equal(
    fingerprintPublicJwk({ y: 'def', x: 'abc', crv: 'P-256', kty: 'EC' }),
    fingerprintPublicJwk(toPublicJwk(ec, 'SIGNING')),
  );
  assert.match(fingerprintPublicJwk(toPublicJwk(ec, 'SIGNING')), /^[0-9a-f]{64}$/);
  assert.throws(() => toPublicJwk({ ...ec, d: 'secret' }, 'SIGNING'), /Invalid public JWK/);
  assert.throws(() => toPublicJwk(ec, 'ENCRYPTION'), /Invalid public JWK/);
  assert.throws(() => toPublicJwk({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' }, 'SIGNING'), /Invalid public JWK/);
});
