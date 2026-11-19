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
      async listMembersForUser(userId, folderId) {
        assert.equal(userId, 'binh');
        return folderId === 'A' ? [{ membershipId: 1, userId, role: 'VIEWER' }] : null;
      },
      async getDashboardSummary(userId) {
        assert.equal(userId, 'binh');
        return { folderCount: 1, documentCount: 2, recentFolders: [{ folderId: 'A', role: 'VIEWER' }] };
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

  const members = await fetch(base + '/api/v1/folders/A/members', { headers });
  assert.equal(members.status, 200);
  assert.deepEqual(await members.json(), { members: [{ membershipId: 1, userId: 'binh', role: 'VIEWER' }] });
  assert.equal((await fetch(base + '/api/v1/folders/B/members', { headers })).status, 403);

  const dashboardUrl = base + '/api/v1/dashboard/summary';
  assert.equal((await fetch(dashboardUrl + '?userId=binh')).status, 401);
  const dashboard = await fetch(dashboardUrl, { headers });
  assert.equal(dashboard.status, 200);
  assert.deepEqual(await dashboard.json(), {
    folderCount: 1, documentCount: 2, recentFolders: [{ folderId: 'A', role: 'VIEWER' }],
  });
});

test('folder rename updates the name only for active owners and editors', async (t) => {
  const folder = { folderId: 'A', name: 'Original' };
  const memberships = {
    owner: { status: 'ACTIVE', role: 'OWNER' },
    editor: { status: 'ACTIVE', role: 'EDITOR' },
    viewer: { status: 'ACTIVE', role: 'VIEWER' },
    revoked: { status: 'REVOKED', role: 'EDITOR' },
    changing: { status: 'ACTIVE', role: 'EDITOR' },
  };
  const app = createApp({
    authenticate(request, _response, next) {
      const token = request.get('authorization');
      if (token) request.user = { id: token.slice('Bearer '.length) };
      next();
    },
    folderRepository: {
      async findForUser(userId, folderId) {
        const membership = memberships[userId];
        if (membership && folderId === folder.folderId) return { folder, membership };
      },
      async renameForUser(userId, folderId, name, allowedRoles) {
        assert.equal(folderId, folder.folderId);
        const membership = memberships[userId];
        if (userId === 'changing') membership.status = 'REVOKED';
        assert.ok(allowedRoles.includes(membership.role));
        if (membership.status !== 'ACTIVE') return null;
        folder.name = name;
        return { folder, membership };
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/api/v1/folders/A`;
  const rename = (userId, body) => fetch(url, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      ...(userId && { authorization: 'Bearer ' + userId }),
    },
    body,
  });

  for (const userId of ['owner', 'editor']) {
    const result = await rename(userId, JSON.stringify({ name: '  ' + userId + '  ' }));
    assert.equal(result.status, 200);
    assert.deepEqual(await result.json(), { folderId: 'A', name: userId, role: memberships[userId].role });
    assert.equal(folder.name, userId);
  }

  for (const userId of ['viewer', 'revoked', 'outsider', 'changing']) {
    assert.equal((await rename(userId, '{"name":"Denied"}')).status, 403);
  }
  assert.equal((await rename(null, '{"name":"Denied"}')).status, 401);
  for (const body of ['{}', '{"name":42}', '{"name":" "}', '{"name":"Valid","role":"OWNER"}', '{']) {
    assert.equal((await rename('editor', body)).status, 400);
  }
  assert.equal(folder.name, 'editor');
});
