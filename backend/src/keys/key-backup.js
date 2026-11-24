const canonicalize = require('canonicalize');
const { decodeBase64url } = require('./key-challenges');

const backupProfile = {
  algorithm: 'Argon2id', memoryKiB: 65536, iterations: 3,
  parallelism: 4, length: 32, version: 19,
};

function validateEncryptedBackup(backup, binding) {
  if (!backup || typeof backup !== 'object' || Array.isArray(backup)) return false;
  const { ciphertext, ...header } = backup;
  const expected = {
    format: 'medshare-private-key-backup/v1',
    ...binding,
    kdf: backupProfile,
    salt: header.salt,
    nonce: header.nonce,
  };
  return decodeBase64url(header.salt, 22)?.length === 16
    && decodeBase64url(header.nonce, 16)?.length === 12
    && decodeBase64url(ciphertext, 8192)?.length > 16
    && canonicalize(header) === canonicalize(expected);
}

module.exports = { validateEncryptedBackup };
