const canonicalize = require('canonicalize');
const { sha256Hex, verifyDocumentUpload, verifyManifestSignature } = require('../documents/document-manifest');
const { lockRotationForUser } = require('../folders/mysql-folder-repository');

const PAGE_SIZE = 100;
const parseJson = (value) => typeof value === 'string' ? JSON.parse(value) : value;
const manifestDigest = (manifest) => sha256Hex(canonicalize(manifest));

async function isCurrentJob(connection, folderId, policyVersion) {
  const [[policy]] = await connection.execute(
    'SELECT policy_version AS version FROM Folder_Policy WHERE folder_id = ? ORDER BY policy_version DESC LIMIT 1 FOR SHARE',
    [folderId],
  );
  const [[deletion]] = await connection.execute(
    'SELECT operation_id FROM Folder_Deletion_Operation WHERE folder_id = ? FOR SHARE', [folderId],
  );
  return policy?.version === policyVersion && !deletion;
}

async function canReadRotationSources({ connection, userId, folderId, policyVersion }) {
  if (!await isCurrentJob(connection, folderId, policyVersion)) return false;
  const [sources] = await connection.execute(`
    SELECT r.revision_id AS revisionId, k.key_id AS ownKeyId
    FROM Document AS d
    INNER JOIN Document_Version AS v ON v.document_id = d.document_id
    LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
    LEFT JOIN Folder_Membership AS m ON m.folder_id = d.folder_id AND m.user_id = ? AND m.status = 'ACTIVE'
    LEFT JOIN DEK_Envelope AS e ON e.revision_id = r.revision_id
      AND e.recipient_user_id = m.user_id AND e.recipient_membership_id = m.membership_id
    LEFT JOIN User_Key AS k ON k.key_id = e.recipient_key_id
      AND k.user_id = m.user_id AND k.purpose = 'ENCRYPTION' AND k.status = 'ACTIVE'
    WHERE d.folder_id = ?
    FOR SHARE
  `, [userId, folderId]);
  return sources.length > 0 && sources.every(({ revisionId, ownKeyId }) => revisionId && ownKeyId);
}

async function readRecipients(connection, folderId) {
  // Lock account and key rows while staging or publishing. Key activation uses an exclusive account lock.
  const [rows] = await connection.execute(`
    SELECT CAST(m.user_id AS CHAR) AS userId, CAST(m.membership_id AS CHAR) AS membershipId,
           k.key_id AS keyId, k.public_key_jwk AS publicKeyJwk
    FROM Folder_Membership AS m
    INNER JOIN \`User\` AS u ON u.user_id = m.user_id
    LEFT JOIN User_Key AS k ON k.user_id = u.user_id AND u.account_status = 'ACTIVE'
      AND k.purpose = 'ENCRYPTION' AND k.status = 'ACTIVE'
    WHERE m.folder_id = ? AND m.status = 'ACTIVE'
    ORDER BY m.user_id
    FOR SHARE
  `, [folderId]);
  if (rows.some(({ keyId }) => !keyId)) return null;
  return rows.map((row) => ({ ...row, publicKeyJwk: parseJson(row.publicKeyJwk) }));
}

async function readActiveSigner(connection, userId) {
  const [[row]] = await connection.execute(`
    SELECT k.key_id AS keyId, k.public_key_jwk AS publicKeyJwk
    FROM User_Key AS k
    INNER JOIN \`User\` AS u ON u.user_id = k.user_id AND u.account_status = 'ACTIVE'
    WHERE k.user_id = ? AND k.purpose = 'SIGNING' AND k.status = 'ACTIVE'
    FOR SHARE
  `, [userId]);
  return row && { ...row, publicKeyJwk: parseJson(row.publicKeyJwk) };
}

function createMysqlRotationRepository(pool, keyDirectory) {
  async function withJob({ userId, rotationId, generation }, access, operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const job = await lockRotationForUser(connection, userId, rotationId);
      let result;
      if (!job) result = { code: 'ROTATION_NOT_FOUND' };
      else if (access === 'owner' && job.role !== 'OWNER') result = { code: 'FORBIDDEN' };
      else if (job.generation !== generation) result = { code: 'LEASE_EXPIRED' };
      else if (!await isCurrentJob(connection, job.folderId, job.policyVersion)) result = { code: 'ROTATION_NOT_CURRENT' };
      else if (access === 'owner' && job.status === 'COMPLETED') {
        result = { rotationId, status: 'COMPLETED' };
      } else if (job.status !== 'IN_PROGRESS' || Number(job.leaseActive) !== 1
          || (access === 'executor' && job.executorId !== userId)
          || (access === 'review' && job.role !== 'OWNER' && job.executorId !== userId)) {
        result = { code: 'LEASE_EXPIRED' };
      } else {
        result = await operation(connection, job);
      }
      if (result.code) await connection.rollback();
      else await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async function readItem(connection, folderId, itemId) {
    const [[row]] = await connection.execute(`
      SELECT d.document_id AS documentId, v.version_id AS versionId, v.version_number AS versionNumber,
             v.base_version_id AS baseVersionId, r.revision_id AS revisionId, r.signed_manifest AS signedManifest
      FROM Document AS d
      INNER JOIN Document_Version AS v ON v.document_id = d.document_id
      INNER JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
      WHERE d.folder_id = ? AND v.version_id = ?
      FOR SHARE
    `, [folderId, itemId]);
    return row;
  }

  return {
    async readProgress(input) {
      return withJob(input, 'review', async (connection, job) => {
        const [items] = await connection.query(`
          SELECT v.version_id AS itemId, d.document_name AS title, v.version_number AS versionNumber,
                 CASE WHEN r.revision_id IS NULL THEN 'PENDING' ELSE 'STAGED' END AS status
          FROM Document AS d
          INNER JOIN Document_Version AS v ON v.document_id = d.document_id
          LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id
            AND r.rotation_id = ? AND r.rotation_generation = ? AND r.status = 'STAGED'
          WHERE d.folder_id = ?
          ORDER BY v.version_id LIMIT ?
        `, [input.rotationId, input.generation, job.folderId, PAGE_SIZE]);
        const [[counts]] = await connection.execute(`
          SELECT COUNT(*) AS total, COUNT(r.revision_id) AS done
          FROM Document AS d
          INNER JOIN Document_Version AS v ON v.document_id = d.document_id
          LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id
            AND r.rotation_id = ? AND r.rotation_generation = ? AND r.status = 'STAGED'
          WHERE d.folder_id = ?
          FOR SHARE
        `, [input.rotationId, input.generation, job.folderId]);
        const total = Number(counts.total);
        const done = Number(counts.done);
        return { items, total, done, canCommit: job.role === 'OWNER' && total > 0 && total === done };
      });
    },

    listItems(input) {
      return withJob(input, 'review', async (connection, job) => {
        const recipients = await readRecipients(connection, job.folderId);
        if (!recipients) return { code: 'RECIPIENT_KEY_MISSING' };
        const signer = await readActiveSigner(connection, input.userId);
        if (!signer) return { code: 'SIGNING_KEY_MISSING' };
        const [items] = await connection.query(`
          SELECT v.version_id AS itemId, d.document_id AS documentId, v.version_number AS versionNumber,
                 v.base_version_id AS baseVersionId, r.revision_id AS sourceRevisionId,
                 staged.revision_id AS stagedRevisionId
          FROM Document AS d
          INNER JOIN Document_Version AS v ON v.document_id = d.document_id
          INNER JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
          LEFT JOIN Crypto_Revision AS staged ON staged.version_id = v.version_id
            AND staged.rotation_id = ? AND staged.rotation_generation = ? AND staged.status = 'STAGED'
          WHERE d.folder_id = ? AND v.version_id > ?
          ORDER BY v.version_id LIMIT ?
          FOR SHARE
        `, [input.rotationId, input.generation, job.folderId, input.after, PAGE_SIZE + 1]);
        return {
          rotationId: input.rotationId, generation: input.generation, folderId: job.folderId,
          policyVersion: job.policyVersion, signerKeyId: signer.keyId, recipients, items: items.slice(0, PAGE_SIZE),
          nextCursor: items.length > PAGE_SIZE ? items[PAGE_SIZE - 1].itemId : null,
        };
      });
    },

    readItemEvidence(input, staged) {
      return withJob(input, 'review', async (connection, job) => {
        const revisionFilter = staged
          ? "r.status = 'STAGED' AND r.rotation_id = ? AND r.rotation_generation = ?"
          : "r.status = 'ACTIVE'";
        const values = staged ? [input.rotationId, input.generation] : [];
        const [[row]] = await connection.execute(`
          SELECT d.document_id AS documentId, v.version_id AS versionId, r.revision_id AS revisionId,
                 r.storage_object_key AS objectKey, r.signed_manifest AS signedManifest, r.signer_key_id AS signerKeyId,
                 e.recipient_key_id AS recipientKeyId, e.wrapped_dek AS wrappedDek
          FROM Document AS d
          INNER JOIN Document_Version AS v ON v.document_id = d.document_id
          INNER JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND ${revisionFilter}
          INNER JOIN Folder_Membership AS m ON m.folder_id = d.folder_id AND m.user_id = ? AND m.status = 'ACTIVE'
          INNER JOIN DEK_Envelope AS e ON e.revision_id = r.revision_id
            AND e.recipient_user_id = m.user_id AND e.recipient_membership_id = m.membership_id
          INNER JOIN User_Key AS k ON k.key_id = e.recipient_key_id
            AND k.user_id = m.user_id AND k.purpose = 'ENCRYPTION' AND k.status = 'ACTIVE'
          WHERE d.folder_id = ? AND v.version_id = ?
          FOR SHARE
        `, [...values, input.userId, job.folderId, input.itemId]);
        if (!row) return { code: 'ROTATION_ITEM_NOT_FOUND' };
        const signer = await keyDirectory.getSigningKeyById(connection, row.signerKeyId);
        return {
          folderId: job.folderId, documentId: row.documentId, versionId: row.versionId,
          revisionId: row.revisionId, objectKey: row.objectKey, ...parseJson(row.signedManifest),
          signer: { userId: signer.userId, keyId: signer.keyId, publicKeyJwk: signer.publicKeyJwk },
          envelope: { keyId: row.recipientKeyId, wrappedDek: Buffer.from(row.wrappedDek).toString('base64url') },
        };
      });
    },

    stageItem(input) {
      return withJob(input, 'executor', async (connection, job) => {
        if (!await canReadRotationSources({ connection, userId: input.userId, ...job })) {
          return { code: 'ROTATION_SOURCE_UNAVAILABLE' };
        }
        const item = await readItem(connection, job.folderId, input.itemId);
        if (!item) return { code: 'ROTATION_ITEM_NOT_FOUND' };
        const [[existing]] = await connection.execute(`
          SELECT revision_id FROM Crypto_Revision WHERE rotation_id = ? AND rotation_generation = ? AND version_id = ?
          FOR SHARE
        `, [input.rotationId, input.generation, item.versionId]);
        if (existing) return { code: 'ROTATION_ITEM_ALREADY_STAGED' };
        if (input.manifest.revisionId === item.revisionId) return { code: 'MANIFEST_MISMATCH' };
        const recipients = await readRecipients(connection, job.folderId);
        if (!recipients) return { code: 'RECIPIENT_KEY_MISSING' };
        const signer = await readActiveSigner(connection, input.userId);
        if (!signer) return { code: 'SIGNING_KEY_MISSING' };
        const { manifest: source } = parseJson(item.signedManifest);
        const context = {
          ...item, contextId: input.rotationId, folderId: job.folderId, policyVersion: job.policyVersion,
          revisionId: input.manifest.revisionId, userId: input.userId, signerKeyId: signer.keyId, recipients,
          rotation: {
            generation: input.generation, sourceRevisionId: item.revisionId, sourceManifestSha256: manifestDigest(source),
            authorRecordSha256: source.authorRecordSha256,
          },
        };
        const verified = verifyDocumentUpload({
          context, manifest: input.manifest, signature: input.signature, envelopes: input.envelopes,
          signerPublicJwk: signer.publicKeyJwk, ciphertext: input.ciphertext,
        });
        if (verified.code) return verified;
        if (input.manifest.ciphertextSha256 === source.ciphertextSha256) return { code: 'MANIFEST_MISMATCH' };
        const [[latest]] = await connection.execute(`
          SELECT revision_number AS number FROM Crypto_Revision
          WHERE version_id = ? ORDER BY revision_number DESC LIMIT 1 FOR UPDATE
        `, [item.versionId]);
        try {
          await connection.execute(`
            INSERT INTO Crypto_Revision (revision_id, version_id, revision_number, status, storage_object_key,
              ciphertext_size, ciphertext_sha256, nonce, policy_version, signed_manifest, signer_key_id, created_by,
              rotation_id, rotation_generation)
            VALUES (?, ?, ?, 'STAGED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `, [
            context.revisionId, item.versionId, latest.number + 1, input.objectKey, input.ciphertext.size,
            input.ciphertext.sha256, verified.nonce, job.policyVersion,
            JSON.stringify({ manifest: input.manifest, signature: input.signature }), signer.keyId, input.userId,
            input.rotationId, input.generation,
          ]);
        } catch (error) {
          if (error.code === 'ER_DUP_ENTRY') return { code: 'ROTATION_REVISION_CONFLICT' };
          throw error;
        }
        for (const envelope of verified.envelopes) {
          await connection.execute(`
            INSERT INTO DEK_Envelope (revision_id, recipient_user_id, recipient_membership_id, recipient_key_id, wrapped_dek)
            VALUES (?, ?, ?, ?, ?)
          `, [context.revisionId, envelope.userId, envelope.membershipId, envelope.keyId, envelope.wrappedDek]);
        }
        return { revisionId: context.revisionId };
      });
    },

    commit(input) {
      return withJob(input, 'owner', async (connection, job) => {
        const signer = await readActiveSigner(connection, input.userId);
        const executor = await readActiveSigner(connection, job.executorId);
        if (!signer || !executor) return { code: 'SIGNING_KEY_MISSING' };
        const recipients = await readRecipients(connection, job.folderId);
        if (!recipients) return { code: 'RECIPIENT_KEY_MISSING' };
        const [rows] = await connection.execute(`
          SELECT v.version_id AS itemId, source.revision_id AS sourceRevisionId, source.signed_manifest AS sourceEvidence,
                 staged.revision_id AS revisionId, staged.signed_manifest AS stagedEvidence
          FROM Document AS d
          INNER JOIN Document_Version AS v ON v.document_id = d.document_id
          LEFT JOIN Crypto_Revision AS source ON source.version_id = v.version_id AND source.status = 'ACTIVE'
          LEFT JOIN Crypto_Revision AS staged ON staged.version_id = v.version_id
            AND staged.rotation_id = ? AND staged.rotation_generation = ? AND staged.status = 'STAGED'
          WHERE d.folder_id = ?
          ORDER BY v.version_id
          FOR UPDATE
        `, [input.rotationId, input.generation, job.folderId]);
        if (!rows.length || rows.some(({ sourceRevisionId, revisionId }) => !sourceRevisionId || !revisionId)) {
          return { code: 'ROTATION_INCOMPLETE' };
        }
        const results = [];
        for (const row of rows) {
          const { manifest: source } = parseJson(row.sourceEvidence);
          const { manifest: staged } = parseJson(row.stagedEvidence);
          const matches = staged.sourceRevisionId === row.sourceRevisionId
            && staged.sourceManifestSha256 === manifestDigest(source)
            && staged.signerKeyId === executor.keyId
            && recipients.length === staged.recipients.length
            && recipients.every(({ userId, keyId }, index) => (
              staged.recipients[index].userId === userId && staged.recipients[index].keyId === keyId
            ));
          if (!matches) return { code: 'ROTATION_RESULT_STALE' };
          results.push({ itemId: row.itemId, revisionId: row.revisionId, manifestSha256: manifestDigest(staged) });
        }
        const record = {
          purpose: 'DOCUMENT_ROTATION_COMMIT', rotationId: input.rotationId, generation: input.generation,
          folderId: job.folderId, policyVersion: job.policyVersion, actorUserId: input.userId,
          signerKeyId: signer.keyId, results,
        };
        if (!verifyManifestSignature(signer.publicKeyJwk, record, input.signature)) return { code: 'INVALID_SIGNATURE' };
        const [finished] = await connection.execute(`
          UPDATE Folder_Rotation_Job SET status = 'COMPLETED', finished_at = UTC_TIMESTAMP(3), lease_expires_at = NULL
          WHERE rotation_id = ? AND lease_expires_at > UTC_TIMESTAMP(3)
        `, [input.rotationId]);
        if (finished.affectedRows !== 1) return { code: 'LEASE_EXPIRED' };
        for (const row of rows) {
          await connection.execute("UPDATE Crypto_Revision SET status = 'SUPERSEDED' WHERE revision_id = ?", [row.sourceRevisionId]);
          await connection.execute(`
            UPDATE Crypto_Revision SET status = 'ACTIVE', activated_at = UTC_TIMESTAMP(3) WHERE revision_id = ?
          `, [row.revisionId]);
        }
        return { rotationId: input.rotationId, status: 'COMPLETED' };
      });
    },
  };
}

module.exports = { canReadRotationSources, createMysqlRotationRepository };
