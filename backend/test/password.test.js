const test = require('node:test');
const assert = require('node:assert/strict');
const {
  DUMMY_PASSWORD_HASH,
  hashPassword,
  verifyPassword,
  validatePasswordPolicy,
} = require('../src/auth/password');

test('hashPassword and verifyPassword roundtrip with salted scrypt$16384$8$1', async () => {
  const password = '  CorrectHorse!99  ';
  const hash = await hashPassword(password);
  assert.match(hash, /^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);

  assert.equal(await verifyPassword(password, hash), true);
  // Must not trim leading/trailing spaces
  assert.equal(await verifyPassword('CorrectHorse!99', hash), false);
  assert.equal(await verifyPassword('WrongPassword!99', hash), false);

  const hash2 = await hashPassword(password);
  assert.notEqual(hash, hash2);
});

test('verifyPassword handles DUMMY_PASSWORD_HASH and malformed/length-mismatched hashes without throwing', async () => {
  assert.equal(await verifyPassword('AnyPassword123!', DUMMY_PASSWORD_HASH), false);

  const malformed = [
    null,
    undefined,
    '',
    'plaintext',
    'scrypt$16384$8$1$short$short',
    'scrypt$16384$8$1$doHBuKKKVUfbcmldGffk1g$abc',
    'scrypt$16384$8$1$doHBuKKKVUfbcmldGffk1g$===invalid===',
    'scrypt$99999999$8$1$doHBuKKKVUfbcmldGffk1g$2IzsU86ACwvVQCV1HMmHMCPD3aPHrBGvq6_gghfq3Adbi4ZaOS8SJY72OOkbiISV3iPoPW_qc2TgBCga-d0XEA',
  ];

  for (const candidate of malformed) {
    assert.equal(await verifyPassword('TestPass123!', candidate), false);
  }

  assert.equal(await verifyPassword('', DUMMY_PASSWORD_HASH), false);
  assert.equal(await verifyPassword(null, DUMMY_PASSWORD_HASH), false);
  assert.equal(await verifyPassword('a'.repeat(1025), DUMMY_PASSWORD_HASH), false);
});

test('validatePasswordPolicy enforces 8..128 character bounds without trimming', () => {
  assert.equal(validatePasswordPolicy('1234567'), false);
  assert.equal(validatePasswordPolicy('12345678'), true);
  assert.equal(validatePasswordPolicy('        '), true);
  assert.equal(validatePasswordPolicy('a'.repeat(128)), true);
  assert.equal(validatePasswordPolicy('a'.repeat(129)), false);
  assert.equal(validatePasswordPolicy(12345678), false);
});
