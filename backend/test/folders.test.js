const assert = require('node:assert/strict');
const { once } = require('node:events');
const { test } = require('node:test');
const { createApp } = require('../src/server');
const { hasFolderPermission } = require('../src/folders/folder-router');

test('folder roles allow only the appropriate actions for active members', () => {
  const editor = { role: 'EDITOR', status: 'ACTIVE' };
  assert.equal(hasFolderPermission(editor, 'upload'), true);
  assert.equal(hasFolderPermission(editor, 'updateDocument'), true);
  assert.equal(hasFolderPermission(editor, 'deleteDocument'), false);
  assert.equal(hasFolderPermission(editor, 'constructor'), false);
  assert.equal(hasFolderPermission({ role: 'OWNER', status: 'REVOKED' }, 'read'), false);
});

test('folder endpoints use authenticated identity and expose only active memberships', async (t) => {
  const active = { folder: { folderId: 'A' }, membership: { status: 'ACTIVE', role: 'VIEWER' } };
  const revoked = { folder: { folderId: 'B' }, membership: { status: 'REVOKED', role: 'EDITOR' } };
  const app = createApp({
    authenticate(request, _response, next) {
      if (request.get('authorization') === 'Bearer test-token') request.user = { id: 'binh' };
      next();
    },
    folderRepository: {
      async listForUser(userId) {
        assert.equal(userId, 'binh');
        return [active, revoked];
      },
      async findForUser(userId, folderId) {
        assert.equal(userId, 'binh');
        return [active, revoked].find(({ folder }) => folder.folderId === folderId);
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { authorization: 'Bearer test-token' };

  assert.equal((await fetch(base + '/health/live')).status, 200);
  assert.equal((await fetch(base + '/demo')).status, 200);
  assert.equal((await fetch(base + '/api/v1/folders?userId=binh')).status, 401);

  const list = await fetch(base + '/api/v1/folders', { headers });
  assert.equal(list.status, 200);
  assert.deepEqual(await list.json(), { folders: [{ folderId: 'A', role: 'VIEWER' }] });

  const folder = await fetch(base + '/api/v1/folders/A', { headers });
  assert.equal(folder.status, 200);
  assert.deepEqual(await folder.json(), { folderId: 'A', role: 'VIEWER' });
  for (const id of ['B', 'C']) {
    assert.equal((await fetch(base + '/api/v1/folders/' + id, { headers })).status, 403);
  }
});
