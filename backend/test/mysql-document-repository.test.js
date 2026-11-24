const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlDocumentRepository } = require('../src/documents/mysql-document-repository');
const { createFakeMysql } = require('./helpers/fake-mysql');
const { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex } = require('./helpers/document-fixtures');

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
    assert.match(sql, /m\.user_id = \? AND m\.status = 'ACTIVE'/);
    assert.match(sql, /r\.version_id = v\.version_id AND r\.status = 'ACTIVE'/);
    assert.match(sql, /e\.recipient_user_id = m\.user_id AND e\.recipient_membership_id = m\.membership_id/);
    assert.equal(args[1], versionId);
    if (args[0] !== '7') return [[]];
    return [[{
      versionId, documentId, folderId, role: 'VIEWER', status: 'ACTIVE',
      policyVersion: 3, rotationStatus: state.rotationStatus, deleting: state.deleting,
      revisionId, objectKey: `${revisionId}/obj`, ciphertextSize: '3', signerKeyId: 'signer-key',
      signedManifest: { manifest: { versionId }, signature: 'sig' },
      recipientKeyId: state.envelope ? 'enc-key' : null, wrappedDek: Buffer.from([1, 2, 3]),
    }]];
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
  assert.deepEqual(await repository.getVersionContentForUser('8', versionId), { code: 'VERSION_NOT_FOUND' });
  state.envelope = false;
  assert.deepEqual(await repository.getVersionContentForUser('7', versionId), { code: 'ENVELOPE_NOT_AVAILABLE' });
  assert.deepEqual(await repository.getVersionManifestForUser('7', versionId), { code: 'ENVELOPE_NOT_AVAILABLE' });
  for (const [rotationStatus, deleting] of [['PENDING', 0], ['WAITING_FOR_OWNER', 0], [null, 1]]) {
    Object.assign(state, { rotationStatus, deleting });
    assert.deepEqual(await repository.getVersionContentForUser('7', versionId), { code: 'FOLDER_NOT_READY' });
  }
  Object.assign(state, { rotationStatus: 'COMPLETED', deleting: 0, envelope: true });
  assert.equal((await repository.getVersionContentForUser('7', versionId)).revisionId, revisionId);
});

test('upload contexts lock the folder, check the base version and snapshot recipient keys', async () => {
  const state = { currentVersionId: versionId, missingKeyFor: null };
  const { pool, events } = createFakeMysql((sql, args, events) => {
    if (sql.includes('FROM Treatment_Folder')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock folder');
      return [[{ folder_id: folderId }]];
    }
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      events.push('lock membership');
      return [[{ membershipId: '70', role: args[1] === '7' ? 'EDITOR' : 'VIEWER', status: 'ACTIVE' }]];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: 3, rotationStatus: 'COMPLETED', deleting: 0 }]];
    if (sql.includes('FROM Document WHERE document_id = ? AND folder_id = ?')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock document');
      return [[{ currentVersionId: state.currentVersionId }]];
    }
    if (sql.includes('MAX(version_number)')) return [[{ versionNumber: 4 }]];
    if (sql.includes("FROM Folder_Membership WHERE folder_id = ? AND status = 'ACTIVE' ORDER BY user_id")) {
      return [[{ membershipId: '70', userId: '7' }, { membershipId: '90', userId: '9' }]];
    }
    assert.match(sql, /^INSERT INTO Upload_Context/);
    events.push('insert context');
    const recipients = JSON.parse(args[11]);
    assert.deepEqual(recipients.map(({ userId }) => userId), ['7', '9']);
    assert.equal(recipients.some((recipient) => 'publicKeyJwk' in recipient), false);
    return [{ affectedRows: 1 }];
  });
  const keyDirectory = {
    async getActiveSigningKey(_connection, userId) { return { keyId: 'sign-' + userId }; },
    async getActiveEncryptionKey(_connection, userId) {
      return userId === state.missingKeyFor ? null : { keyId: 'enc-' + userId, fingerprint: 'f' + userId, publicKeyJwk: { kty: 'RSA', n: userId, e: 'AQAB' } };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory, uploadContextTtlSeconds: 600 });
  const request = { purpose: 'NEW_VERSION', documentId, baseVersionId: versionId };
  const context = await repository.createUploadContext('7', folderId, request);
  assert.deepEqual(events, ['begin', 'lock folder', 'lock membership', 'lock document', 'insert context', 'commit', 'release']);
  assert.equal(context.documentId, documentId);
  assert.equal(context.baseVersionId, versionId);
  assert.equal(context.versionNumber, 5);
  assert.equal(context.policyVersion, 3);
  assert.equal(context.signerKeyId, 'sign-7');
  assert.ok(Date.parse(context.expiresAt) > Date.now() + 590_000);
  assert.deepEqual(context.recipients, [
    { userId: '7', membershipId: '70', keyId: 'enc-7', fingerprint: 'f7', publicKeyJwk: { kty: 'RSA', n: '7', e: 'AQAB' } },
    { userId: '9', membershipId: '90', keyId: 'enc-9', fingerprint: 'f9', publicKeyJwk: { kty: 'RSA', n: '9', e: 'AQAB' } },
  ]);
  events.length = 0;
  assert.deepEqual(await repository.createUploadContext('8', folderId, request), { code: 'FORBIDDEN' });
  assert.deepEqual(events.slice(-2), ['rollback', 'release']);
  state.currentVersionId = 'newer';
  assert.deepEqual(await repository.createUploadContext('7', folderId, request), { code: 'VERSION_CONFLICT', currentVersionId: 'newer' });
  state.missingKeyFor = '9';
  assert.deepEqual(await repository.createUploadContext('7', folderId, { purpose: 'NEW_DOCUMENT' }), { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] });
});

test('publishing a new version re-checks the context under lock and rejects stale state', async () => {
  const signer = await createSigner();
  const context = createUploadContextFixture({ purpose: 'NEW_VERSION', folderId, documentId, baseVersionId: versionId, versionNumber: 2 });
  const upload = await createSignedUpload(context, signer);
  const state = { currentVersionId: versionId, policyVersion: context.policyVersion, consumedAt: null };
  const { pool, events } = createFakeMysql((sql, args, events) => {
    if (sql === 'SELECT folder_id AS folderId FROM Document WHERE document_id = ?') return [[{ folderId }]];
    if (sql.includes('FROM Treatment_Folder')) {
      events.push('lock folder');
      return [[{ folder_id: folderId }]];
    }
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      events.push('lock membership');
      return [[{ membershipId: '70', role: 'EDITOR', status: 'ACTIVE' }]];
    }
    if (sql.includes('FROM Upload_Context')) {
      assert.match(sql, /FOR UPDATE$/);
      assert.deepEqual(args, [context.contextId, folderId, '7']);
      events.push('lock context');
      return [[{ ...context, recipients: JSON.stringify(context.recipients), consumedAt: state.consumedAt, expired: 0 }]];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: state.policyVersion, rotationStatus: null, deleting: 0 }]];
    if (sql.startsWith('SELECT current_version_id AS currentVersionId FROM Document')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock document');
      return [[{ currentVersionId: state.currentVersionId }]];
    }
    if (sql.startsWith('INSERT INTO Document_Version')) {
      events.push('insert version');
      assert.deepEqual(args, [context.versionId, documentId, 2, versionId, '7', context.signerKeyId, 'application/pdf']);
    } else if (sql.startsWith('INSERT INTO Crypto_Revision')) {
      events.push('insert revision');
      assert.equal(args[2], `${context.revisionId}/object`);
      assert.equal(args[5].length, 12);
    } else if (sql.startsWith('INSERT INTO DEK_Envelope')) {
      events.push('insert envelope ' + args[1]);
      assert.equal(args[4].length, 384);
    } else if (sql.startsWith('UPDATE Document SET current_version_id')) {
      events.push('set current');
    } else {
      assert.match(sql, /^UPDATE Upload_Context SET consumed_at/);
      events.push('consume');
    }
    return [{ affectedRows: 1 }];
  });
  const keyDirectory = {
    async getActiveSigningKey() { return { keyId: context.signerKeyId, publicKeyJwk: signer.publicKeyJwk }; },
    async getActiveEncryptionKey(_connection, userId) {
      return { keyId: context.recipients.find((recipient) => recipient.userId === userId).keyId };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory });
  const input = {
    userId: '7', purpose: 'NEW_VERSION', documentId, contextId: context.contextId, mimeType: 'application/pdf',
    manifest: upload.manifest, signature: upload.signature, envelopes: upload.envelopes,
    objectKey: `${context.revisionId}/object`, ciphertextSize: upload.ciphertext.length,
    ciphertextSha256: sha256Hex(upload.ciphertext),
  };
  assert.deepEqual(await repository.publishUpload(input), {
    documentId, versionId: context.versionId, revisionId: context.revisionId, versionNumber: 2,
  });
  assert.deepEqual(events, [
    'begin', 'lock folder', 'lock membership', 'lock context', 'lock document', 'insert version',
    'insert revision', 'insert envelope 7', 'insert envelope 9', 'set current', 'consume', 'commit', 'release',
  ]);
  const failures = [
    [{ currentVersionId: 'newer' }, { code: 'VERSION_CONFLICT', currentVersionId: 'newer' }],
    [{ currentVersionId: versionId, policyVersion: context.policyVersion + 1 }, { code: 'CONTEXT_STALE' }],
    [{ policyVersion: context.policyVersion, consumedAt: new Date() }, { code: 'CONTEXT_USED' }],
  ];
  for (const [change, expected] of failures) {
    Object.assign(state, change);
    events.length = 0;
    assert.deepEqual(await repository.publishUpload(input), expected);
    assert.equal(events.some((event) => event.startsWith('insert')), false);
    assert.deepEqual(events.slice(-2), ['rollback', 'release']);
  }
});

function documentAccessHandler(roles, extra) {
  return (sql, args, events) => {
    if (sql === 'SELECT folder_id AS folderId FROM Document WHERE document_id = ?') return [[{ folderId }]];
    if (sql.includes('FROM Treatment_Folder')) return [[{ folder_id: folderId }]];
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      return [roles[args[1]] ? [{ membershipId: '1', role: roles[args[1]], status: 'ACTIVE' }] : []];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: 2, rotationStatus: null, deleting: 0 }]];
    if (sql.startsWith('SELECT document_id FROM Document')) {
      assert.match(sql, /FOR UPDATE$/);
      return [[{ document_id: documentId }]];
    }
    return extra(sql, args, events);
  };
}

test('metadata updates re-check the editor role and change only display fields', async () => {
  const roles = { 5: 'OWNER', 7: 'EDITOR', 8: 'VIEWER' };
  let update;
  const { pool } = createFakeMysql(documentAccessHandler(roles, (sql, args) => {
    if (sql.startsWith('UPDATE Document SET')) {
      update = { sql, args };
      return [{ affectedRows: 1 }];
    }
    assert.match(sql, /m\.role FROM Document AS d/);
    return [[{ documentId, documentName: 'Đơn thuốc', category: 'PRESCRIPTION', role: roles[args[0]], currentVersionNumber: 1, ciphertextSize: '64' }]];
  }));
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.updateDocumentMetadata('8', documentId, { documentName: 'X' }), { code: 'FORBIDDEN' });
  assert.deepEqual(await repository.updateDocumentMetadata('9', documentId, { documentName: 'X' }), { code: 'DOCUMENT_NOT_FOUND' });
  assert.equal(update, undefined);
  const result = await repository.updateDocumentMetadata('7', documentId, { documentName: 'Đơn thuốc', category: 'PRESCRIPTION' });
  assert.equal(update.sql, 'UPDATE Document SET document_name = ?, category = ?, updated_at = UTC_TIMESTAMP(3) WHERE document_id = ?');
  assert.deepEqual(update.args, ['Đơn thuốc', 'PRESCRIPTION', documentId]);
  assert.equal(result.role, 'EDITOR');
  assert.equal(result.ciphertextSize, 64);
});

test('document deletion is owner-only and removes rows children-first', async () => {
  const roles = { 5: 'OWNER', 7: 'EDITOR' };
  const { pool, events } = createFakeMysql(documentAccessHandler(roles, (sql, _args, events) => {
    if (sql.startsWith('SELECT r.storage_object_key')) return [[{ objectKey: 'a/1' }, { objectKey: 'b/2' }]];
    if (sql.startsWith('DELETE FROM Document_Version')) assert.match(sql, /ORDER BY version_number DESC$/);
    events.push(sql.split(' ').slice(0, 3).join(' '));
    return [{ affectedRows: 1 }];
  }));
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.deleteDocument('7', documentId), { code: 'FORBIDDEN' });
  assert.deepEqual(await repository.deleteDocument('9', documentId), { code: 'DOCUMENT_NOT_FOUND' });
  events.length = 0;
  assert.deepEqual(await repository.deleteDocument('5', documentId), { objectKeys: ['a/1', 'b/2'] });
  assert.deepEqual(events, [
    'begin', 'DELETE e FROM', 'DELETE r FROM', 'UPDATE Document SET', 'DELETE FROM Document_Version',
    'DELETE FROM Upload_Context', 'DELETE FROM Document', 'commit', 'release',
  ]);
});
