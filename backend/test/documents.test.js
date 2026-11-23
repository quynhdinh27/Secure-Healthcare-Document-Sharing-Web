const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { once } = require('node:events');
const { test } = require('node:test');
const { createApp } = require('../src/server');

const folderId = randomUUID();
const documentId = randomUUID();
const versionId = randomUUID();
const revisionId = randomUUID();

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function createMemoryStorage() {
  const objects = new Map();
  return {
    objects,
    async put(key, data) { objects.set(key, Buffer.from(data)); },
    async get(key) {
      if (!objects.has(key)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return objects.get(key);
    },
    async delete(key) { objects.delete(key); },
  };
}

async function startApp(t, options) {
  const app = createApp({
    authenticate(request, _response, next) {
      const id = request.get('x-test-user');
      if (id) request.user = { id };
      next();
    },
    ...options,
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  return (path, { user = '7', headers = {}, ...init } = {}) => fetch(base + path, {
    ...init,
    headers: { ...(user ? { 'x-test-user': user } : {}), ...headers },
  });
}

function uploadForm({ ciphertext = Buffer.alloc(32, 1), manifest = {}, metadata = {} } = {}) {
  const form = new FormData();
  form.append('metadata', JSON.stringify({
    contextId: randomUUID(),
    documentName: '  Xét nghiệm máu  ',
    category: 'LABORATORY_RESULT',
    mimeType: 'application/pdf',
    signature: 'sig',
    envelopes: [],
    manifest: { revisionId, ciphertextSha256: sha256Hex(ciphertext), ciphertextSize: ciphertext.length, ...manifest },
    ...metadata,
  }));
  form.append('ciphertext', new Blob([ciphertext]), 'ciphertext.bin');
  return form;
}

test('document routes require an authenticated user and configured services', async (t) => {
  const call = await startApp(t, { documentRepository: {}, objectStorage: createMemoryStorage() });
  const anonymous = await call(`/documents/${documentId}`, { user: null });
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.headers.get('cache-control'), 'no-store');
  assert.equal((await call('/documents/not-a-uuid')).status, 400);
  const unconfigured = await startApp(t, { documentRepository: {} });
  const response = await unconfigured(`/documents/${documentId}`);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { code: 'DOCUMENT_SERVICE_UNAVAILABLE' });
});

test('document lists validate filters and map repository results', async (t) => {
  const calls = [];
  const call = await startApp(t, {
    objectStorage: createMemoryStorage(),
    documentRepository: {
      async listDocumentsForUser(userId, id, filters) {
        calls.push([userId, id, filters]);
        return id === folderId ? { documents: [], nextPage: null } : { code: 'FORBIDDEN' };
      },
    },
  });
  const ok = await call(`/folders/${folderId}/documents?query=%20x%20&category=PRESCRIPTION&page=2`);
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await ok.json(), { documents: [], nextPage: null });
  assert.deepEqual(calls, [['7', folderId, { query: 'x', category: 'PRESCRIPTION', page: 2 }]]);
  assert.equal((await call(`/folders/${folderId}/documents?page=0`)).status, 400);
  assert.equal((await call(`/folders/${folderId}/documents?category=BAD`)).status, 400);
  assert.equal((await call(`/folders/${folderId}/documents?query=${'a'.repeat(101)}`)).status, 400);
  assert.equal((await call('/folders/not-a-uuid/documents')).status, 403);
  assert.equal((await call(`/folders/${randomUUID()}/documents`)).status, 403);
  assert.equal(calls.length, 2);
});

test('upload contexts accept only the documented request shapes', async (t) => {
  const calls = [];
  const call = await startApp(t, {
    objectStorage: createMemoryStorage(),
    documentRepository: {
      async createUploadContext(userId, id, request) {
        calls.push([userId, id, request]);
        return request.purpose === 'NEW_DOCUMENT'
          ? { contextId: 'c1', recipients: [] }
          : { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] };
      },
    },
  });
  const post = (body, headers = { 'content-type': 'application/json' }) => call(`/folders/${folderId}/upload-contexts`, {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const created = await post({ purpose: 'NEW_DOCUMENT' });
  assert.equal(created.status, 201);
  assert.deepEqual(await created.json(), { contextId: 'c1', recipients: [] });
  const missing = await post({ purpose: 'NEW_VERSION', documentId, baseVersionId: versionId });
  assert.equal(missing.status, 409);
  assert.deepEqual(await missing.json(), { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] });
  for (const body of [
    {}, { purpose: 'NEW_DOCUMENT', extra: 1 }, { purpose: 'NEW_VERSION', documentId },
    { purpose: 'NEW_VERSION', documentId: 'x', baseVersionId: versionId }, { purpose: 'OTHER' }, [],
  ]) {
    const response = await post(body);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.deepEqual(await response.json(), { code: 'INVALID_UPLOAD_CONTEXT_INPUT' });
  }
  const badJson = await post('{');
  assert.equal(badJson.status, 400);
  assert.deepEqual(await badJson.json(), { code: 'INVALID_JSON' });
  assert.deepEqual(calls, [
    ['7', folderId, { purpose: 'NEW_DOCUMENT' }],
    ['7', folderId, { purpose: 'NEW_VERSION', documentId, baseVersionId: versionId }],
  ]);
});

test('uploads store ciphertext before publishing and discard it when publishing fails', async (t) => {
  const storage = createMemoryStorage();
  const inputs = [];
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async publishUpload(input) {
        inputs.push(input);
        assert.ok(storage.objects.has(input.objectKey), 'ciphertext is stored before publishing');
        if (input.purpose === 'NEW_VERSION') return { code: 'VERSION_CONFLICT', currentVersionId: 'v9' };
        if (input.mimeType === 'application/x-explode') throw new Error('database down');
        return { documentId, versionId, revisionId: input.manifest.revisionId, versionNumber: 1 };
      },
    },
  });
  const ciphertext = Buffer.alloc(32, 1);
  const created = await call(`/folders/${folderId}/documents`, { method: 'POST', body: uploadForm({ ciphertext }) });
  assert.equal(created.status, 201);
  assert.equal(created.headers.get('location'), `/api/v1/documents/${documentId}`);
  assert.deepEqual(await created.json(), { documentId, versionId, revisionId, versionNumber: 1 });
  const [first] = inputs;
  assert.equal(first.userId, '7');
  assert.equal(first.purpose, 'NEW_DOCUMENT');
  assert.equal(first.folderId, folderId);
  assert.equal(first.documentName, 'Xét nghiệm máu');
  assert.equal(first.ciphertextSize, 32);
  assert.equal(first.ciphertextSha256, sha256Hex(ciphertext));
  assert.match(first.objectKey, new RegExp(`^${revisionId}/[0-9a-f-]{36}$`));
  assert.deepEqual([...storage.objects.keys()], [first.objectKey]);

  const conflict = await call(`/documents/${documentId}/versions`, {
    method: 'POST', body: uploadForm({ metadata: { documentName: undefined, category: undefined } }),
  });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { code: 'VERSION_CONFLICT', currentVersionId: 'v9' });
  assert.equal(inputs[1].documentId, documentId);
  assert.equal(inputs[1].folderId, undefined);

  const failed = await call(`/folders/${folderId}/documents`, {
    method: 'POST', body: uploadForm({ metadata: { mimeType: 'application/x-explode' } }),
  });
  assert.equal(failed.status, 500);
  assert.deepEqual([...storage.objects.keys()], [first.objectKey]);
});

test('uploads reject malformed, mismatched or oversized ciphertext without storing it', async (t) => {
  const storage = createMemoryStorage();
  let published = 0;
  const call = await startApp(t, {
    objectStorage: storage,
    maxUploadBytes: 64,
    documentRepository: { async publishUpload() { published += 1; return { code: 'FORBIDDEN' }; } },
  });
  const upload = (form) => call(`/folders/${folderId}/documents`, { method: 'POST', body: form });
  const expectations = [
    [uploadForm({ manifest: { ciphertextSha256: '0'.repeat(64) } }), 422, 'CIPHERTEXT_HASH_MISMATCH'],
    [uploadForm({ manifest: { ciphertextSize: 31 } }), 422, 'CIPHERTEXT_HASH_MISMATCH'],
    [uploadForm({ manifest: { revisionId: 'bad' } }), 422, 'MANIFEST_MISMATCH'],
    [uploadForm({ ciphertext: Buffer.alloc(100, 1) }), 413, 'PAYLOAD_TOO_LARGE'],
    [uploadForm({ ciphertext: Buffer.alloc(8, 1) }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { category: 'BAD' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { documentName: '   ' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { mimeType: 'pdf' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { contextId: 'x' } }), 400, 'INVALID_DOCUMENT_INPUT'],
  ];
  const onlyFile = new FormData();
  onlyFile.append('ciphertext', new Blob([Buffer.alloc(32)]), 'ciphertext.bin');
  expectations.push([onlyFile, 400, 'INVALID_DOCUMENT_INPUT']);
  const extraField = uploadForm();
  extraField.append('other', 'x');
  expectations.push([extraField, 400, 'INVALID_DOCUMENT_INPUT']);
  for (const [form, status, code] of expectations) {
    const response = await upload(form);
    assert.equal(response.status, status, code);
    assert.deepEqual(await response.json(), { code });
  }
  const json = await call(`/folders/${folderId}/documents`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(json.status, 400);
  assert.equal(storage.objects.size, 0);
  assert.equal(published, 0);
});

test('downloads return the caller manifest and the active ciphertext revision', async (t) => {
  const storage = createMemoryStorage();
  storage.objects.set('k1', Buffer.from([1, 2, 3]));
  const oldRevision = randomUUID();
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async getVersionManifestForUser(userId, id) {
        return userId === '7' && id === versionId ? { versionId, revisionId } : { code: 'VERSION_NOT_FOUND' };
      },
      async getVersionContentForUser(userId, id, requested) {
        if (requested === oldRevision) return { code: 'REVISION_CHANGED', revisionId };
        return { revisionId, objectKey: 'k1', ciphertextSize: 3 };
      },
    },
  });
  const manifest = await call(`/versions/${versionId}/manifest`);
  assert.equal(manifest.status, 200);
  assert.deepEqual(await manifest.json(), { versionId, revisionId });
  assert.equal((await call(`/versions/${versionId}/manifest`, { user: '8' })).status, 404);
  const content = await call(`/versions/${versionId}/content?revisionId=${revisionId}`);
  assert.equal(content.status, 200);
  assert.equal(content.headers.get('content-type'), 'application/octet-stream');
  assert.equal(content.headers.get('x-crypto-revision-id'), revisionId);
  assert.equal(content.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Buffer.from(await content.arrayBuffer()), Buffer.from([1, 2, 3]));
  const stale = await call(`/versions/${versionId}/content?revisionId=${oldRevision}`);
  assert.equal(stale.status, 409);
  assert.deepEqual(await stale.json(), { code: 'REVISION_CHANGED', revisionId });
  assert.equal((await call(`/versions/${versionId}/content?revisionId=bad`)).status, 400);
  assert.equal((await call('/versions/bad/manifest')).status, 400);
});

test('document details, metadata updates and deletion follow repository results', async (t) => {
  const storage = createMemoryStorage();
  storage.objects.set('a/1', Buffer.from('x'));
  storage.objects.set('b/2', Buffer.from('y'));
  const updates = [];
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async findDocumentForUser(userId) { return userId === '7' ? { documentId, role: 'EDITOR' } : null; },
      async listVersionsForUser(userId) { return userId === '7' ? { versions: [] } : null; },
      async updateDocumentMetadata(userId, id, changes) {
        updates.push(changes);
        return userId === '7' ? { documentId: id, ...changes } : { code: 'FORBIDDEN' };
      },
      async deleteDocument(userId) {
        return userId === '5' ? { objectKeys: ['a/1', 'b/2'] } : { code: 'FORBIDDEN' };
      },
    },
  });
  assert.deepEqual(await (await call(`/documents/${documentId}`)).json(), { documentId, role: 'EDITOR' });
  assert.equal((await call(`/documents/${documentId}`, { user: '8' })).status, 404);
  assert.deepEqual(await (await call(`/documents/${documentId}/versions`)).json(), { versions: [] });
  assert.equal((await call(`/documents/${documentId}/versions`, { user: '8' })).status, 404);
  const patch = (body, user = '7') => call(`/documents/${documentId}`, {
    method: 'PATCH', user, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const renamed = await patch({ documentName: '  Đơn thuốc  ' });
  assert.equal(renamed.status, 200);
  assert.deepEqual(await renamed.json(), { documentId, documentName: 'Đơn thuốc' });
  assert.equal((await patch({ category: 'PRESCRIPTION' }, '8')).status, 403);
  for (const body of [{}, { folderId }, { category: 'BAD' }, { documentName: '' }, { documentName: 'x'.repeat(256) }]) {
    assert.equal((await patch(body)).status, 400, JSON.stringify(body));
  }
  assert.deepEqual(updates, [{ documentName: 'Đơn thuốc' }, { category: 'PRESCRIPTION' }]);
  assert.equal((await call(`/documents/${documentId}`, { method: 'DELETE', user: '7' })).status, 403);
  assert.equal(storage.objects.size, 2);
  const deleted = await call(`/documents/${documentId}`, { method: 'DELETE', user: '5' });
  assert.equal(deleted.status, 204);
  assert.equal(storage.objects.size, 0);
});
