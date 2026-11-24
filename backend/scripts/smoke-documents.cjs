// End-to-end check of Document Management against the dev MySQL and local storage.
// Requires: docker compose up -d --wait && npm run migrate. Creates its own users.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');
const {
  addFolderMember, createApiClient, createDevUser, createFolderWithMembers, signPayload, startDevServer,
} = require('./lib/dev-accounts.cjs');
const { downloadAndDecrypt, prepareUpload } = require('./lib/dev-document-client.cjs');
const { completeRotation } = require('./lib/dev-rotation-client.cjs');
const { completeFolderRotations } = require('./dev-complete-rotations.cjs');

async function main() {
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('smoke:documents is not allowed in production');
  const pool = createPool(config.db);
  let server;
  try {
    const suffix = randomUUID().slice(0, 8);
    const user = (role) => createDevUser(pool, { email: `smoke-${role}-${suffix}@medshare.test`, fullName: `Smoke ${role}` });
    const [owner, editor, viewer, outsider, late] = [
      await user('owner'), await user('editor'), await user('viewer'), await user('outsider'), await user('late'),
    ];
    server = await startDevServer({ config, pool });
    const call = createApiClient(server.baseUrl);
    const folderId = await createFolderWithMembers({
      call, owner,
      folder: { name: 'Documents smoke test', patientRef: 'SMOKE-PATIENT', treatmentReference: `SMOKE-${suffix}` },
      members: [{ user: editor, role: 'EDITOR' }, { user: viewer, role: 'VIEWER' }],
    });
    const contextsPath = `/folders/${folderId}/upload-contexts`;
    const newDocument = { method: 'POST', body: { purpose: 'NEW_DOCUMENT' } };

    const dashboardBefore = await call('/dashboard/summary', owner.userId, 200);

    // 1. Owner uploads V1 for every current member.
    const context = await call(contextsPath, owner.userId, 201, newDocument);
    assert.deepEqual(context.recipients.map(({ userId }) => userId).sort(), [owner, editor, viewer].map(({ userId }) => userId).sort());
    const v1Plain = Buffer.from('Kết quả xét nghiệm máu - bản 1');
    const v1Upload = await prepareUpload({
      context, author: owner, plaintext: v1Plain,
      documentName: 'Xét nghiệm máu', category: 'LABORATORY_RESULT', mimeType: 'text/plain',
    });
    const v1 = await call(`/folders/${folderId}/documents`, owner.userId, 201, { method: 'POST', form: v1Upload.form });
    const reused = await prepareUpload({
      context, author: owner, plaintext: v1Plain, documentName: 'Lần 2', category: 'OTHER', mimeType: 'text/plain',
    });
    assert.equal((await call(`/folders/${folderId}/documents`, owner.userId, 409, { method: 'POST', form: reused.form })).code, 'CONTEXT_USED');

    // 2. Viewer decrypts V1.
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v1.versionId }), v1Plain);

    // 3. Editor creates V2; an upload based on the old V1 conflicts.
    const versionRequest = { method: 'POST', body: { purpose: 'NEW_VERSION', documentId: v1.documentId, baseVersionId: v1.versionId } };
    const editorContext = await call(contextsPath, editor.userId, 201, versionRequest);
    const staleContext = await call(contextsPath, owner.userId, 201, versionRequest);
    const v2Plain = Buffer.from('Kết quả xét nghiệm máu - bản 2');
    const v2Upload = await prepareUpload({ context: editorContext, author: editor, plaintext: v2Plain, mimeType: 'text/plain' });
    const v2 = await call(`/documents/${v1.documentId}/versions`, editor.userId, 201, { method: 'POST', form: v2Upload.form });
    assert.equal(v2.versionNumber, 2);
    const staleUpload = await prepareUpload({ context: staleContext, author: owner, plaintext: Buffer.from('stale'), mimeType: 'text/plain' });
    assert.equal((await call(`/documents/${v1.documentId}/versions`, owner.userId, 409, { method: 'POST', form: staleUpload.form })).code, 'VERSION_CONFLICT');
    const { versions } = await call(`/documents/${v1.documentId}/versions`, viewer.userId, 200);
    assert.deepEqual(versions.map(({ versionNumber, isCurrent }) => [versionNumber, isCurrent]), [[2, true], [1, false]]);
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v2.versionId }), v2Plain);
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v1.versionId }), v1Plain);

    // 4. Role checks.
    assert.equal((await call(contextsPath, viewer.userId, 403, newDocument)).code, 'FORBIDDEN');
    assert.equal((await call(`/documents/${v1.documentId}`, outsider.userId, 404)).code, 'DOCUMENT_NOT_FOUND');
    assert.equal((await call(`/documents/${v1.documentId}`, editor.userId, 403, { method: 'DELETE' })).code, 'FORBIDDEN');
    const dashboardAfter = await call('/dashboard/summary', owner.userId, 200);
    assert.equal(dashboardAfter.documentCount, dashboardBefore.documentCount + 1);

    // 5. Owner deletes the document and both ciphertext objects.
    const [objects] = await pool.execute(`
      SELECT r.storage_object_key AS objectKey FROM Crypto_Revision AS r
      INNER JOIN Document_Version AS v ON v.version_id = r.version_id WHERE v.document_id = ?
    `, [v1.documentId]);
    assert.equal(objects.length, 2);
    await call(`/documents/${v1.documentId}`, owner.userId, 204, { method: 'DELETE' });
    await call(`/documents/${v1.documentId}`, owner.userId, 404);
    for (const { objectKey } of objects) {
      await assert.rejects(fs.access(path.join(config.storage.dir, ...objectKey.split('/'))), { code: 'ENOENT' });
    }
    const dashboardFinal = await call('/dashboard/summary', owner.userId, 200);
    assert.equal(dashboardFinal.documentCount, dashboardBefore.documentCount);
    // 6. Membership changes to a populated folder require real rotation.
    const rotationContext = await call(contextsPath, owner.userId, 201, newDocument);
    const rotationUpload = await prepareUpload({
      context: rotationContext, author: owner, plaintext: v1Plain,
      documentName: 'Rotation smoke test', category: 'OTHER', mimeType: 'text/plain',
    });
    const rotationDocument = await call(`/folders/${folderId}/documents`, owner.userId, 201, {
      method: 'POST', form: rotationUpload.form,
    });
    const secondContext = await call(contextsPath, editor.userId, 201, {
      method: 'POST', body: { purpose: 'NEW_VERSION', documentId: rotationDocument.documentId, baseVersionId: rotationDocument.versionId },
    });
    const secondUpload = await prepareUpload({ context: secondContext, author: editor, plaintext: v2Plain, mimeType: 'text/plain' });
    const secondVersion = await call(`/documents/${rotationDocument.documentId}/versions`, editor.userId, 201, {
      method: 'POST', form: secondUpload.form,
    });
    const { rotationId } = await addFolderMember({ call, owner, folderId, userId: late.userId, role: 'EDITOR' });
    await assert.rejects(completeFolderRotations(pool, folderId), /folder with documents/);
    assert.equal((await call(`/key-rotations/${rotationId}`, owner.userId, 200)).status, 'PENDING');
    const downloadPath = `/versions/${rotationDocument.versionId}`;
    for (const user of [viewer, late]) {
      for (const type of ['manifest', 'content']) {
        assert.equal((await call(`${downloadPath}/${type}`, user.userId, 409)).code, 'FOLDER_NOT_READY');
      }
    }

    const cannotClaim = await call(`/key-rotations/${rotationId}/claim`, late.userId, 409, { method: 'POST' });
    assert.equal(cannotClaim.code, 'ROTATION_SOURCE_UNAVAILABLE');
    const addedResults = await completeRotation({ call, owner, executor: editor, rotationId, checkGuards: true });
    assert.equal(addedResults.length, 2);
    assert.deepEqual(await downloadAndDecrypt({ call, user: late, versionId: rotationDocument.versionId }), v1Plain);
    assert.deepEqual(await downloadAndDecrypt({ call, user: late, versionId: secondVersion.versionId }), v2Plain);
    const previousManifest = await call(downloadPath + '/manifest', editor.userId, 200);

    const [[{ membershipId }]] = await pool.execute(`
      SELECT CAST(membership_id AS CHAR) AS membershipId
      FROM Folder_Membership WHERE folder_id = ? AND user_id = ? AND status = 'ACTIVE'
    `, [folderId, viewer.userId]);
    const revokeContext = await call(`/folders/${folderId}/policy-contexts`, owner.userId, 201, {
      method: 'POST', body: { action: 'REVOKE_MEMBER', membershipId },
    });
    const ownerSignature = await signPayload(owner.keys.signing.privateJwk, {
      purpose: 'FOLDER_MEMBERSHIP_CHANGE', context: revokeContext,
    });
    const revoked = await call(`/folders/${folderId}/members/${membershipId}`, owner.userId, 202, {
      method: 'DELETE', headers: { 'X-Policy-Context-Id': revokeContext.contextId, 'X-Policy-Signature': ownerSignature },
    });
    assert.equal((await call(`/key-rotations/${rotationId}`, owner.userId, 200)).status, 'COMPLETED');
    assert.equal((await call(`/key-rotations/${revoked.rotationId}`, owner.userId, 200)).status, 'PENDING');
    for (const type of ['manifest', 'content']) {
      assert.equal((await call(`${downloadPath}/${type}`, viewer.userId, 404)).code, 'VERSION_NOT_FOUND');
      assert.equal((await call(`${downloadPath}/${type}`, editor.userId, 409)).code, 'FOLDER_NOT_READY');
    }
    await completeRotation({ call, owner, executor: editor, rotationId: revoked.rotationId });
    assert.deepEqual(await downloadAndDecrypt({ call, user: late, versionId: rotationDocument.versionId }), v1Plain);
    assert.deepEqual(await downloadAndDecrypt({ call, user: editor, versionId: secondVersion.versionId }), v2Plain);
    const current = await call(downloadPath + '/manifest', editor.userId, 200);
    assert.notEqual(current.revisionId, previousManifest.revisionId);
    assert.equal(current.manifest.recipients.some(({ userId }) => userId === viewer.userId), false);
    assert.equal((await call(downloadPath + '/content?revisionId=' + previousManifest.revisionId, editor.userId, 409)).code, 'REVISION_CHANGED');
    assert.equal((await call(downloadPath + '/manifest', viewer.userId, 404)).code, 'VERSION_NOT_FOUND');
    assert.equal((await call(downloadPath + '/content', viewer.userId, 404)).code, 'VERSION_NOT_FOUND');
    console.log('PASS: upload, decryption, deletion, and key rotation after adding and revoking members on MySQL');
  } finally {
    if (server) await server.close();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
