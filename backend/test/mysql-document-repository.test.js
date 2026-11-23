const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlDocumentRepository } = require('../src/documents/mysql-document-repository');
const { createFakeMysql } = require('./helpers/fake-mysql');

const folderId = '11111111-1111-4111-8111-111111111111';
const documentId = '22222222-2222-4222-8222-222222222222';
const versionId = '33333333-3333-4333-8333-333333333333';
const revisionId = '44444444-4444-4444-8444-444444444444';

test('document lists require active membership and escape search filters', async () => {
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      return [args[1] === '7' ? [{ role: 'VIEWER', status: 'ACTIVE' }] : []];
    }
    assert.match(sql, /d\.document_name LIKE \? ESCAPE '!'/);
    assert.match(sql, /d\.category = \?/);
    assert.match(sql, /ORDER BY d\.updated_at DESC, d\.document_id LIMIT \? OFFSET \?$/);
    assert.deepEqual(args, [folderId, '%50!%!_x!!%', 'LABORATORY_RESULT', 51, 50]);
    return [Array.from({ length: 51 }, (_, index) => ({ documentId: String(index), currentVersionNumber: 1, ciphertextSize: '64' }))];
  });
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.listDocumentsForUser('8', folderId, { query: '', page: 1 }), { code: 'FORBIDDEN' });
  const result = await repository.listDocumentsForUser('7', folderId, { query: '50%_x!', category: 'LABORATORY_RESULT', page: 2 });
  assert.equal(result.documents.length, 50);
  assert.equal(result.documents[0].ciphertextSize, 64);
  assert.equal(result.nextPage, 3);
});

test('version history lists retained business versions and marks the current one', async () => {
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.startsWith('SELECT d.current_version_id AS currentVersionId')) {
      return [args[0] === '7' ? [{ currentVersionId: 'v2' }] : []];
    }
    assert.match(sql, /ORDER BY v\.version_number DESC$/);
    assert.deepEqual(args, [documentId]);
    return [[{ versionId: 'v2', versionNumber: 2, ciphertextSize: '80' }, { versionId: 'v1', versionNumber: 1, ciphertextSize: '64' }]];
  });
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.equal(await repository.listVersionsForUser('8', documentId), null);
  assert.deepEqual(await repository.listVersionsForUser('7', documentId), {
    versions: [
      { versionId: 'v2', versionNumber: 2, ciphertextSize: 80, isCurrent: true },
      { versionId: 'v1', versionNumber: 1, ciphertextSize: 64, isCurrent: false },
    ],
  });
});

test('version downloads need a ready folder and return only the caller envelope', async () => {
  const state = { rotationStatus: null, deleting: 0, envelope: true };
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.includes('FROM Document_Version AS v INNER JOIN Document AS d')) {
      return [args[0] === '7' && args[1] === versionId ? [{ versionId, documentId, folderId, role: 'VIEWER', status: 'ACTIVE' }] : []];
    }
    if (sql.includes('FROM Folder_Policy')) {
      return [[{ policyVersion: 3, rotationStatus: state.rotationStatus, deleting: state.deleting }]];
    }
    if (sql.includes("FROM Crypto_Revision AS r WHERE r.version_id = ? AND r.status = 'ACTIVE'")) {
      return [[{
        revisionId, objectKey: `${revisionId}/obj`, ciphertextSize: '3', signerKeyId: 'signer-key',
        signedManifest: { manifest: { versionId }, signature: 'sig' },
      }]];
    }
    assert.match(sql, /FROM DEK_Envelope WHERE revision_id = \? AND recipient_user_id = \?$/);
    assert.deepEqual(args, [revisionId, '7']);
    return [state.envelope ? [{ keyId: 'enc-key', wrappedDek: Buffer.from([1, 2, 3]) }] : []];
  });
  const keyDirectory = {
    async getSigningKeyById(executor, keyId) {
      assert.equal(executor, pool);
      return { userId: '5', keyId, publicKeyJwk: { kty: 'EC' } };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory });
  assert.deepEqual(await repository.getVersionManifestForUser('7', versionId), {
    versionId, documentId, folderId, revisionId,
    manifest: { versionId }, signature: 'sig',
    signer: { userId: '5', keyId: 'signer-key', publicKeyJwk: { kty: 'EC' } },
    envelope: { keyId: 'enc-key', wrappedDek: 'AQID' },
  });
  assert.deepEqual(await repository.getVersionContentForUser('7', versionId, revisionId), {
    revisionId, objectKey: `${revisionId}/obj`, ciphertextSize: 3,
  });
  assert.deepEqual(await repository.getVersionContentForUser('7', versionId, folderId), { code: 'REVISION_CHANGED', revisionId });
  assert.deepEqual(await repository.getVersionManifestForUser('8', versionId), { code: 'VERSION_NOT_FOUND' });
  state.envelope = false;
  assert.deepEqual(await repository.getVersionManifestForUser('7', versionId), { code: 'ENVELOPE_NOT_AVAILABLE' });
  for (const [rotationStatus, deleting] of [['PENDING', 0], ['WAITING_FOR_OWNER', 0], [null, 1]]) {
    Object.assign(state, { rotationStatus, deleting });
    assert.deepEqual(await repository.getVersionContentForUser('7', versionId), { code: 'FOLDER_NOT_READY' });
  }
  Object.assign(state, { rotationStatus: 'COMPLETED', deleting: 0 });
  assert.equal((await repository.getVersionContentForUser('7', versionId)).revisionId, revisionId);
});
