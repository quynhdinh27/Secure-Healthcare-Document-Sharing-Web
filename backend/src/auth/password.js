const { randomBytes, scrypt, timingSafeEqual } = require('node:crypto');

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const SCRYPT_MAXMEM = 32 * 1024 * 1024;
const SALT_BYTES = 16;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MAX_LOGIN_PASSWORD_LENGTH = 1024;

// Precomputed real scrypt$16384$8$1 hash used when an account does not exist or has NULL password_hash.
const DUMMY_PASSWORD_HASH =
  'scrypt$16384$8$1$doHBuKKKVUfbcmldGffk1g$2IzsU86ACwvVQCV1HMmHMCPD3aPHrBGvq6_gghfq3Adbi4ZaOS8SJY72OOkbiISV3iPoPW_qc2TgBCga-d0XEA';

function scryptAsync(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

function validatePasswordPolicy(password) {
  return (
    typeof password === 'string'
    && password.length >= MIN_PASSWORD_LENGTH
    && password.length <= MAX_PASSWORD_LENGTH
  );
}

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length === 0 || password.length > MAX_LOGIN_PASSWORD_LENGTH) {
    throw new Error('Password must be a non-empty string within allowed length bounds');
  }
  const salt = randomBytes(SALT_BYTES);
  const derived = await scryptAsync(password, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

function parseScryptHash(storedHash) {
  if (typeof storedHash !== 'string' || storedHash.length === 0 || storedHash.length > 512) {
    return null;
  }
  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;

  const [, nStr, rStr, pStr, saltB64, hashB64] = parts;
  if (!/^[1-9][0-9]{0,7}$/.test(nStr) || !/^[1-9][0-9]{0,3}$/.test(rStr) || !/^[1-9][0-9]{0,2}$/.test(pStr)) {
    return null;
  }
  const N = Number(nStr);
  const r = Number(rStr);
  const p = Number(pStr);
  if (N < 1024 || N > 65536 || (N & (N - 1)) !== 0 || r < 1 || r > 32 || p < 1 || p > 8) {
    return null;
  }
  if (128 * N * r * p > SCRYPT_MAXMEM) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(saltB64) || !/^[A-Za-z0-9_-]+$/.test(hashB64)) {
    return null;
  }

  const salt = Buffer.from(saltB64, 'base64url');
  const expected = Buffer.from(hashB64, 'base64url');
  if (salt.toString('base64url') !== saltB64 || expected.toString('base64url') !== hashB64) {
    return null;
  }
  if (salt.length < 8 || salt.length > 64 || expected.length !== SCRYPT_KEYLEN) {
    return null;
  }
  return { N, r, p, salt, expected };
}

async function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || password.length === 0 || password.length > MAX_LOGIN_PASSWORD_LENGTH) {
    return false;
  }
  const parsed = parseScryptHash(storedHash);
  if (!parsed) return false;

  const derived = await scryptAsync(password, parsed.salt, parsed.expected.length, {
    N: parsed.N,
    r: parsed.r,
    p: parsed.p,
    maxmem: SCRYPT_MAXMEM,
  });
  if (derived.length !== parsed.expected.length) {
    return false;
  }
  return timingSafeEqual(derived, parsed.expected);
}

module.exports = {
  DUMMY_PASSWORD_HASH,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_LOGIN_PASSWORD_LENGTH,
  hashPassword,
  verifyPassword,
  validatePasswordPolicy,
};
