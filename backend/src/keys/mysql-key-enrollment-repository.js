const { createHash, createPublicKey, randomUUID } = require('node:crypto');
const { issueKeyChallenge, verifyKeyChallenge } = require('./key-challenges');
const { validateEncryptedBackup } = require('./key-backup');
const { fingerprintPublicJwk } = require('./mysql-key-directory');

const publicColumns = `
  key_id AS keyId, purpose, public_key_jwk AS publicKeyJwk, status, created_at AS createdAt
`;
const dbPurpose = { ENC: 'ENCRYPTION', SIGN: 'SIGNING' };
const algorithms = { ENC: 'RSA-OAEP-3072-SHA256', SIGN: 'ECDSA-P256-SHA256' };

function parseJson(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function toPublicKey(row) {
  const spki = createPublicKey({ key: parseJson(row.publicKeyJwk), format: 'jwk' }).export({ type: 'spki', format: 'der' });
  return {
    keyId: row.keyId, purpose: row.purpose === 'ENCRYPTION' ? 'ENC' : 'SIGN',
    publicKey: spki.toString('base64url'),
    publicKeyFingerprint: createHash('sha256').update(spki).digest('base64url'),
    status: row.status, createdAt: row.createdAt,
  };
}

function bindingFor(userId, key) {
  return {
    userId, keyId: key.keyId, purpose: key.purpose, publicKeyFingerprint: key.publicKeyFingerprint,
  };
}

function createMysqlKeyEnrollmentRepository(pool) {
  async function transact(userId, operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [[user]] = await connection.execute(
        "SELECT user_id FROM \`User\` WHERE user_id = ? AND account_status = 'ACTIVE' FOR UPDATE", [userId],
      );
      const result = user ? await operation(connection) : { error: 'FORBIDDEN' };
      if (result.error) await connection.rollback();
      else await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async function find(executor, userId, keyId, lock = false) {
    const [[row]] = await executor.execute(`
      SELECT ${publicColumns}, enrollment_challenge AS challenge,
             enrollment_response_hash AS responseHash, encrypted_backup AS backup
      FROM User_Key WHERE user_id = ? AND key_id = ?${lock ? ' FOR UPDATE' : ''}
    `, [userId, keyId]);
    return row;
  }

  return {
    async list(userId) {
      const [rows] = await pool.execute(`
        SELECT ${publicColumns} FROM User_Key WHERE user_id = ? ORDER BY created_at DESC, key_id
      `, [userId]);
      return rows.map(toPublicKey);
    },

    async register(userId, input) {
      let issued;
      const keyId = randomUUID();
      try {
        issued = issueKeyChallenge({ ...input, userId, keyId });
      } catch {
        return { error: 'INVALID_PUBLIC_KEY' };
      }
      const purpose = dbPurpose[input.purpose];
      const jwk = issued.publicKeyJwk;
      try {
        return await transact(userId, async (connection) => {
          const [[active]] = await connection.execute(`
            SELECT key_id FROM User_Key WHERE user_id = ? AND purpose = ? AND status = 'ACTIVE' FOR UPDATE
          `, [userId, purpose]);
          if (active) return { error: 'KEY_ALREADY_ACTIVE' };
          await connection.execute(`
            DELETE FROM User_Key WHERE user_id = ? AND purpose = ? AND status = 'PENDING_VERIFICATION'
          `, [userId, purpose]);
          await connection.execute(`
            INSERT INTO User_Key
              (key_id, user_id, purpose, algorithm, public_key_jwk, fingerprint, enrollment_challenge, enrollment_response_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `, [keyId, userId, purpose, algorithms[input.purpose], JSON.stringify(jwk),
            fingerprintPublicJwk(jwk), JSON.stringify(issued.challenge), issued.responseHash]);
          return { keyId, challenge: issued.challenge };
        });
      } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return { error: 'KEY_ALREADY_REGISTERED' };
        throw error;
      }
    },

    saveBackup(userId, keyId, backup) {
      return transact(userId, async (connection) => {
        const row = await find(connection, userId, keyId, true);
        if (!row) return { error: 'KEY_NOT_FOUND' };
        if (row.status !== 'PENDING_VERIFICATION') return { error: 'KEY_NOT_PENDING' };
        if (!validateEncryptedBackup(backup, bindingFor(userId, toPublicKey(row)))) {
          return { error: 'INVALID_KEY_BACKUP' };
        }
        await connection.execute('UPDATE User_Key SET encrypted_backup = ? WHERE key_id = ?', [JSON.stringify(backup), keyId]);
        return { saved: true };
      });
    },

    async getBackup(userId, keyId) {
      const row = await find(pool, userId, keyId);
      if (row?.status !== 'ACTIVE' || !row.backup) return { error: 'KEY_BACKUP_NOT_FOUND' };
      const key = toPublicKey(row);
      return { backup: parseJson(row.backup), binding: bindingFor(userId, key), publicKey: key.publicKey };
    },

    activate(userId, keyId, response) {
      return transact(userId, async (connection) => {
        const row = await find(connection, userId, keyId, true);
        if (!row) return { error: 'KEY_NOT_FOUND' };
        if (row.status !== 'PENDING_VERIFICATION' || !row.challenge) return { error: 'KEY_NOT_PENDING' };
        if (!row.backup) return { error: 'KEY_BACKUP_REQUIRED' };
        const key = toPublicKey(row);
        const challenge = parseJson(row.challenge);
        if (challenge.userId !== userId || challenge.keyId !== keyId || challenge.purpose !== key.purpose
          || !verifyKeyChallenge({ challenge, publicKey: key.publicKey, response, responseHash: row.responseHash })) {
          return { error: 'INVALID_KEY_PROOF' };
        }
        await connection.execute(`
          UPDATE User_Key SET status = 'ACTIVE', activated_at = UTC_TIMESTAMP(3),
            enrollment_challenge = NULL, enrollment_response_hash = NULL
          WHERE key_id = ?
        `, [keyId]);
        return { keyId, status: 'ACTIVE' };
      });
    },
  };
}

module.exports = { createMysqlKeyEnrollmentRepository };
