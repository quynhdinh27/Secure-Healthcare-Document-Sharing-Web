// End-to-end check of Document Management against the dev MySQL and local storage.
// Requires: docker compose up -d --wait && npm run migrate. Creates its own users.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');
const {
  addFolderMember, createApiClient, createDevUser, createFolderWithMembers, startDevServer,
} = require('./lib/dev-accounts.cjs');
const { downloadAndDecrypt, prepareUpload } = require('./lib/dev-document-client.cjs');
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

    // Membership changes queue rotation jobs; until they finish the folder is not ready.
    assert.equal((await call(contextsPath, owner.userId, 409, newDocument)).code, 'FOLDER_NOT_READY');
    await completeFolderRotations(pool, folderId);
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

    // 5. A new member waits for rotation and then has no envelope for existing documents.
    await addFolderMember({ call, owner, folderId, userId: late.userId, role: 'VIEWER' });
    assert.equal((await call(`/versions/${v2.versionId}/manifest`, viewer.userId, 409)).code, 'FOLDER_NOT_READY');
    await completeFolderRotations(pool, folderId);
    assert.equal((await call(`/versions/${v2.versionId}/manifest`, late.userId, 409)).code, 'ENVELOPE_NOT_AVAILABLE');

    // 6. Owner deletes the document; rows and ciphertext objects disappear.
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
    console.log('PASS: upload, versions, conflict, download/decrypt, roles, rotation gate and delete on MySQL');
  } finally {
    if (server) await server.close();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
