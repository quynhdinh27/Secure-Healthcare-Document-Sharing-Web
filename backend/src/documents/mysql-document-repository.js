const { randomUUID } = require('node:crypto');
const { hasFolderPermission } = require('../folders/folder-router');
const { verifyDocumentUpload } = require('./document-manifest');

const PAGE_SIZE = 50;

const documentColumns = `
  d.document_id AS documentId, d.folder_id AS folderId, d.document_name AS documentName,
  d.category, CAST(d.original_uploader_id AS CHAR) AS originalUploaderId,
  d.current_version_id AS currentVersionId, v.version_number AS currentVersionNumber,
  r.ciphertext_size AS ciphertextSize, d.created_at AS createdAt, d.updated_at AS updatedAt
`;
const currentRevisionJoins = `
  LEFT JOIN Document_Version AS v ON v.version_id = d.current_version_id
  LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
`;
const callerMembershipJoin = `
  INNER JOIN Folder_Membership AS m
    ON m.folder_id = d.folder_id AND m.user_id = ? AND m.status = 'ACTIVE'
`;
// Parameters: [userId, documentId].
const findDocumentQuery = `
  SELECT ${documentColumns}, m.role FROM Document AS d
  ${callerMembershipJoin} ${currentRevisionJoins}
  WHERE d.document_id = ?
`;

function parseJson(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function toNumber(value) {
  return value === null || value === undefined ? null : Number(value);
}

function toDocument(row) {
  return { ...row, currentVersionNumber: toNumber(row.currentVersionNumber), ciphertextSize: toNumber(row.ciphertextSize) };
}

function toMysqlDateTime(date) {
  return date.toISOString().slice(0, -1).replace('T', ' ');
}

// Same rule as the folders module's cryptoState: no rotation job for the current
// policy (null) or a COMPLETED job means ready; a deletion operation never is.
async function readFolderState(executor, folderId) {
  const [[row]] = await executor.execute(`
    SELECT p.policyVersion,
           (SELECT j.status FROM Folder_Rotation_Job AS j
            WHERE j.folder_id = ? AND j.policy_version = p.policyVersion) AS rotationStatus,
           EXISTS (SELECT 1 FROM Folder_Deletion_Operation AS o WHERE o.folder_id = ?) AS deleting
    FROM (SELECT MAX(policy_version) AS policyVersion FROM Folder_Policy WHERE folder_id = ?) AS p
  `, [folderId, folderId, folderId]);
  const policyVersion = Number(row?.policyVersion ?? 0);
  const rotationStatus = row?.rotationStatus ?? null;
  const ready = policyVersion > 0 && Number(row?.deleting ?? 1) === 0
    && (rotationStatus === null || rotationStatus === 'COMPLETED');
  return { policyVersion, ready };
}

// Lock order for every write: Treatment_Folder, then Folder_Membership, then
// Upload_Context / Document. Matches the folders module.
async function lockMembership(connection, folderId, userId) {
  const [[folder]] = await connection.execute(
    'SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId],
  );
  if (!folder) return null;
  const [[membership]] = await connection.execute(`
    SELECT CAST(membership_id AS CHAR) AS membershipId, role, status
    FROM Folder_Membership WHERE folder_id = ? AND user_id = ? AND status = 'ACTIVE' FOR UPDATE
  `, [folderId, userId]);
  return membership ?? null;
}

async function findDocumentFolder(executor, documentId) {
  const [[row]] = await executor.execute(
    'SELECT folder_id AS folderId FROM Document WHERE document_id = ?', [documentId],
  );
  return row?.folderId ?? null;
}

const contextColumns = `
  context_id AS contextId, purpose, folder_id AS folderId, CAST(user_id AS CHAR) AS userId,
  document_id AS documentId, version_id AS versionId, revision_id AS revisionId,
  base_version_id AS baseVersionId, version_number AS versionNumber,
  policy_version AS policyVersion, signer_key_id AS signerKeyId, recipients,
  consumed_at AS consumedAt, expires_at <= UTC_TIMESTAMP(3) AS expired
`;

async function issueUploadContext(connection, { userId, folderId, request, keyDirectory, ttlSeconds }) {
  const membership = await lockMembership(connection, folderId, userId);
  if (!hasFolderPermission(membership, 'upload')) return { code: 'FORBIDDEN' };
  const state = await readFolderState(connection, folderId);
  if (!state.ready) return { code: 'FOLDER_NOT_READY' };
  const signer = await keyDirectory.getActiveSigningKey(connection, userId);
  if (!signer) return { code: 'SIGNING_KEY_MISSING' };
  let documentId = randomUUID();
  let versionNumber = 1;
  let baseVersionId = null;
  if (request.purpose === 'NEW_VERSION') {
    const [[document]] = await connection.execute(`
      SELECT current_version_id AS currentVersionId FROM Document
      WHERE document_id = ? AND folder_id = ? FOR UPDATE
    `, [request.documentId, folderId]);
    if (!document) return { code: 'DOCUMENT_NOT_FOUND' };
    if (document.currentVersionId !== request.baseVersionId) {
      return { code: 'VERSION_CONFLICT', currentVersionId: document.currentVersionId };
    }
    const [[latest]] = await connection.execute(
      'SELECT MAX(version_number) AS versionNumber FROM Document_Version WHERE document_id = ?', [request.documentId],
    );
    documentId = request.documentId;
    versionNumber = Number(latest.versionNumber) + 1;
    baseVersionId = request.baseVersionId;
  }
  const [members] = await connection.execute(`
    SELECT CAST(membership_id AS CHAR) AS membershipId, CAST(user_id AS CHAR) AS userId
    FROM Folder_Membership WHERE folder_id = ? AND status = 'ACTIVE' ORDER BY user_id
  `, [folderId]);
  const recipients = [];
  const missing = [];
  for (const member of members) {
    const key = await keyDirectory.getActiveEncryptionKey(connection, member.userId);
    if (!key) missing.push(member.userId);
    else recipients.push({ userId: member.userId, membershipId: member.membershipId, keyId: key.keyId, fingerprint: key.fingerprint, publicKeyJwk: key.publicKeyJwk });
  }
  if (missing.length) return { code: 'RECIPIENT_KEY_MISSING', userIds: missing };
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const context = {
    contextId: randomUUID(), purpose: request.purpose, folderId, documentId,
    versionId: randomUUID(), revisionId: randomUUID(), versionNumber, baseVersionId,
    policyVersion: state.policyVersion, signerKeyId: signer.keyId, expiresAt: expiresAt.toISOString(),
  };
  const storedRecipients = recipients.map(({ publicKeyJwk, ...recipient }) => recipient);
  await connection.execute(`
    INSERT INTO Upload_Context (context_id, folder_id, user_id, purpose, document_id, version_id,
      revision_id, base_version_id, version_number, policy_version, signer_key_id, recipients, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    context.contextId, folderId, userId, context.purpose, documentId, context.versionId,
    context.revisionId, baseVersionId, versionNumber, context.policyVersion, signer.keyId,
    JSON.stringify(storedRecipients), toMysqlDateTime(expiresAt),
  ]);
  return { ...context, recipients };
}

async function publishVersion(connection, input, keyDirectory) {
  const { userId, purpose } = input;
  const hidden = purpose === 'NEW_VERSION' ? { code: 'DOCUMENT_NOT_FOUND' } : { code: 'FORBIDDEN' };
  const folderId = purpose === 'NEW_VERSION' ? await findDocumentFolder(connection, input.documentId) : input.folderId;
  if (!folderId) return hidden;
  const membership = await lockMembership(connection, folderId, userId);
  if (!membership) return hidden;
  if (!hasFolderPermission(membership, 'upload')) return { code: 'FORBIDDEN' };
  const [[stored]] = await connection.execute(`
    SELECT ${contextColumns} FROM Upload_Context
    WHERE context_id = ? AND folder_id = ? AND user_id = ? FOR UPDATE
  `, [input.contextId, folderId, userId]);
  if (!stored || stored.purpose !== purpose
      || (purpose === 'NEW_VERSION' && stored.documentId !== input.documentId)) {
    return { code: 'CONTEXT_NOT_FOUND' };
  }
  if (stored.consumedAt) return { code: 'CONTEXT_USED' };
  if (Number(stored.expired)) return { code: 'CONTEXT_EXPIRED' };
  const context = { ...stored, recipients: parseJson(stored.recipients) };
  const state = await readFolderState(connection, folderId);
  if (!state.ready) return { code: 'FOLDER_NOT_READY' };
  if (state.policyVersion !== Number(context.policyVersion)) return { code: 'CONTEXT_STALE' };
  const signer = await keyDirectory.getActiveSigningKey(connection, userId);
  if (!signer || signer.keyId !== context.signerKeyId) return { code: 'SIGNING_KEY_MISSING' };
  for (const recipient of context.recipients) {
    const key = await keyDirectory.getActiveEncryptionKey(connection, recipient.userId);
    if (key?.keyId !== recipient.keyId) return { code: 'CONTEXT_STALE' };
  }
  const verified = verifyDocumentUpload({
    context,
    manifest: input.manifest,
    signature: input.signature,
    envelopes: input.envelopes,
    signerPublicJwk: signer.publicKeyJwk,
    ciphertext: { sha256: input.ciphertextSha256, size: input.ciphertextSize },
  });
  if (verified.code) return verified;
  if (purpose === 'NEW_VERSION') {
    const [[document]] = await connection.execute(
      'SELECT current_version_id AS currentVersionId FROM Document WHERE document_id = ? FOR UPDATE', [context.documentId],
    );
    if (!document) return { code: 'DOCUMENT_NOT_FOUND' };
    if (document.currentVersionId !== context.baseVersionId) {
      return { code: 'VERSION_CONFLICT', currentVersionId: document.currentVersionId };
    }
  } else {
    await connection.execute(`
      INSERT INTO Document (document_id, folder_id, document_name, category, original_uploader_id)
      VALUES (?, ?, ?, ?, ?)
    `, [context.documentId, folderId, input.documentName, input.category, userId]);
  }
  const versionNumber = Number(context.versionNumber);
  await connection.execute(`
    INSERT INTO Document_Version (version_id, document_id, version_number, base_version_id,
      created_by, author_key_id, mime_type)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [context.versionId, context.documentId, versionNumber, context.baseVersionId, userId, signer.keyId, input.mimeType]);
  await connection.execute(`
    INSERT INTO Crypto_Revision (revision_id, version_id, revision_number, status, storage_object_key,
      ciphertext_size, ciphertext_sha256, nonce, policy_version, signed_manifest, signer_key_id,
      created_by, activated_at)
    VALUES (?, ?, 1, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(3))
  `, [
    context.revisionId, context.versionId, input.objectKey, input.ciphertextSize, input.ciphertextSha256,
    verified.nonce, Number(context.policyVersion), JSON.stringify({ manifest: input.manifest, signature: input.signature }),
    signer.keyId, userId,
  ]);
  for (const envelope of verified.envelopes) {
    await connection.execute(`
      INSERT INTO DEK_Envelope (revision_id, recipient_user_id, recipient_membership_id, recipient_key_id, wrapped_dek)
      VALUES (?, ?, ?, ?, ?)
    `, [context.revisionId, envelope.userId, envelope.membershipId, envelope.keyId, envelope.wrappedDek]);
  }
  await connection.execute(
    'UPDATE Document SET current_version_id = ?, updated_at = UTC_TIMESTAMP(3) WHERE document_id = ?',
    [context.versionId, context.documentId],
  );
  const [consumed] = await connection.execute(
    'UPDATE Upload_Context SET consumed_at = UTC_TIMESTAMP(3) WHERE context_id = ? AND consumed_at IS NULL',
    [context.contextId],
  );
  if (consumed.affectedRows !== 1) throw new Error('Upload context was consumed concurrently');
  return { documentId: context.documentId, versionId: context.versionId, revisionId: context.revisionId, versionNumber };
}

function createMysqlDocumentRepository(pool, { keyDirectory, uploadContextTtlSeconds = 600 } = {}) {
  if (!keyDirectory) throw new Error('keyDirectory is required');

  async function inTransaction(operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await operation(connection);
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

  async function findReadableRevision(userId, versionId) {
    const [[version]] = await pool.execute(`
      SELECT v.version_id AS versionId, d.document_id AS documentId, d.folder_id AS folderId, m.role, m.status
      FROM Document_Version AS v INNER JOIN Document AS d ON d.document_id = v.document_id
      ${callerMembershipJoin}
      WHERE v.version_id = ?
    `, [userId, versionId]);
    if (!hasFolderPermission(version, 'read')) return { code: 'VERSION_NOT_FOUND' };
    const state = await readFolderState(pool, version.folderId);
    if (!state.ready) return { code: 'FOLDER_NOT_READY' };
    const [[revision]] = await pool.execute(`
      SELECT r.revision_id AS revisionId, r.storage_object_key AS objectKey,
             r.ciphertext_size AS ciphertextSize, r.signer_key_id AS signerKeyId,
             r.signed_manifest AS signedManifest
      FROM Crypto_Revision AS r WHERE r.version_id = ? AND r.status = 'ACTIVE'
    `, [versionId]);
    if (!revision) return { code: 'VERSION_NOT_FOUND' };
    return { version, revision };
  }

  return {
    async listDocumentsForUser(userId, folderId, { query = '', category, page = 1 } = {}) {
      const [[membership]] = await pool.execute(`
        SELECT role, status FROM Folder_Membership
        WHERE folder_id = ? AND user_id = ? AND status = 'ACTIVE'
      `, [folderId, userId]);
      if (!hasFolderPermission(membership, 'read')) return { code: 'FORBIDDEN' };
      const filters = ['d.folder_id = ?'];
      const values = [folderId];
      if (query) {
        filters.push("d.document_name LIKE ? ESCAPE '!'");
        values.push('%' + query.replace(/[!%_]/g, '!$&') + '%');
      }
      if (category) {
        filters.push('d.category = ?');
        values.push(category);
      }
      const [rows] = await pool.query(`
        SELECT ${documentColumns} FROM Document AS d ${currentRevisionJoins}
        WHERE ${filters.join(' AND ')}
        ORDER BY d.updated_at DESC, d.document_id
        LIMIT ? OFFSET ?
      `, [...values, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE]);
      return {
        documents: rows.slice(0, PAGE_SIZE).map(toDocument),
        nextPage: rows.length > PAGE_SIZE ? page + 1 : null,
      };
    },

    async findDocumentForUser(userId, documentId) {
      const [[row]] = await pool.execute(findDocumentQuery, [userId, documentId]);
      return row ? toDocument(row) : null;
    },

    async listVersionsForUser(userId, documentId) {
      const [[document]] = await pool.execute(`
        SELECT d.current_version_id AS currentVersionId FROM Document AS d
        ${callerMembershipJoin}
        WHERE d.document_id = ?
      `, [userId, documentId]);
      if (!document) return null;
      const [rows] = await pool.execute(`
        SELECT v.version_id AS versionId, v.version_number AS versionNumber,
               v.base_version_id AS baseVersionId, CAST(v.created_by AS CHAR) AS createdBy,
               v.mime_type AS mimeType, r.ciphertext_size AS ciphertextSize, v.created_at AS createdAt
        FROM Document_Version AS v
        LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
        WHERE v.document_id = ?
        ORDER BY v.version_number DESC
      `, [documentId]);
      return {
        versions: rows.map((row) => ({
          ...row,
          ciphertextSize: toNumber(row.ciphertextSize),
          isCurrent: row.versionId === document.currentVersionId,
        })),
      };
    },

    async getVersionManifestForUser(userId, versionId) {
      const access = await findReadableRevision(userId, versionId);
      if (access.code) return access;
      const { version, revision } = access;
      const [[envelope]] = await pool.execute(`
        SELECT recipient_key_id AS keyId, wrapped_dek AS wrappedDek
        FROM DEK_Envelope WHERE revision_id = ? AND recipient_user_id = ?
      `, [revision.revisionId, userId]);
      if (!envelope) return { code: 'ENVELOPE_NOT_AVAILABLE' };
      const signer = await keyDirectory.getSigningKeyById(pool, revision.signerKeyId);
      const { manifest, signature } = parseJson(revision.signedManifest);
      return {
        versionId: version.versionId,
        documentId: version.documentId,
        folderId: version.folderId,
        revisionId: revision.revisionId,
        manifest,
        signature,
        signer: { userId: signer.userId, keyId: signer.keyId, publicKeyJwk: signer.publicKeyJwk },
        envelope: { keyId: envelope.keyId, wrappedDek: Buffer.from(envelope.wrappedDek).toString('base64url') },
      };
    },

    async getVersionContentForUser(userId, versionId, revisionId) {
      const access = await findReadableRevision(userId, versionId);
      if (access.code) return access;
      const { revision } = access;
      if (revisionId && revisionId !== revision.revisionId) {
        return { code: 'REVISION_CHANGED', revisionId: revision.revisionId };
      }
      return { revisionId: revision.revisionId, objectKey: revision.objectKey, ciphertextSize: Number(revision.ciphertextSize) };
    },

    createUploadContext(userId, folderId, request) {
      return inTransaction((connection) => issueUploadContext(connection, {
        userId, folderId, request, keyDirectory, ttlSeconds: uploadContextTtlSeconds,
      }));
    },

    publishUpload(input) {
      return inTransaction((connection) => publishVersion(connection, input, keyDirectory));
    },
  };
}

module.exports = { createMysqlDocumentRepository };
