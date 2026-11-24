const { createHash } = require('node:crypto');
const canonicalize = require('canonicalize');

// Read-only public-key lookups over User_Key. Key registration, proof of
// possession and backups belong to the Key Management module.
const publicMembers = {
  ENCRYPTION: { fixed: { kty: 'RSA' }, members: ['kty', 'n', 'e'] },
  SIGNING: { fixed: { kty: 'EC', crv: 'P-256' }, members: ['kty', 'crv', 'x', 'y'] },
};

function toPublicJwk(jwk, purpose) {
  const profile = publicMembers[purpose];
  if (!profile) throw new Error('Unknown key purpose');
  const valid = jwk && typeof jwk === 'object' && jwk.d === undefined
    && Object.entries(profile.fixed).every(([name, value]) => jwk[name] === value)
    && profile.members.every((name) => typeof jwk[name] === 'string' && jwk[name] !== '');
  if (!valid) throw new Error('Invalid public JWK');
  return Object.fromEntries(profile.members.map((name) => [name, jwk[name]]));
}

function fingerprintPublicJwk(publicJwk) {
  return createHash('sha256').update(canonicalize(publicJwk)).digest('hex');
}

const keyColumns = `
  k.key_id AS keyId, CAST(k.user_id AS CHAR) AS userId, k.purpose, k.status,
  k.public_key_jwk AS publicKeyJwk, k.fingerprint
`;

function toKey(row) {
  if (!row) return null;
  const publicKeyJwk = typeof row.publicKeyJwk === 'string' ? JSON.parse(row.publicKeyJwk) : row.publicKeyJwk;
  return { ...row, publicKeyJwk };
}

function createMysqlKeyDirectory() {
  async function findActiveKey(executor, userId, purpose) {
    const [[row]] = await executor.execute(`
      SELECT ${keyColumns} FROM User_Key AS k
      WHERE k.user_id = ? AND k.purpose = ? AND k.status = 'ACTIVE'
    `, [userId, purpose]);
    return toKey(row);
  }
  return {
    async lookupActiveSigningKey(executor, userId) {
      return (await findActiveKey(executor, userId, 'SIGNING'))?.publicKeyJwk ?? null;
    },
    async canReceiveFolderKeys(executor, userId) {
      const [[row]] = await executor.execute(`
        SELECT 1 AS eligible FROM \`User\` AS u
        INNER JOIN User_Key AS k
          ON k.user_id = u.user_id AND k.purpose = 'ENCRYPTION' AND k.status = 'ACTIVE'
        WHERE u.user_id = ? AND u.account_status = 'ACTIVE'
      `, [userId]);
      return Boolean(row);
    },
    getActiveSigningKey(executor, userId) {
      return findActiveKey(executor, userId, 'SIGNING');
    },
    getActiveEncryptionKey(executor, userId) {
      return findActiveKey(executor, userId, 'ENCRYPTION');
    },
    async getSigningKeyById(executor, keyId) {
      const [[row]] = await executor.execute(`
        SELECT ${keyColumns} FROM User_Key AS k WHERE k.key_id = ? AND k.purpose = 'SIGNING'
      `, [keyId]);
      return toKey(row);
    },
  };
}

module.exports = { createMysqlKeyDirectory, fingerprintPublicJwk, toPublicJwk };
