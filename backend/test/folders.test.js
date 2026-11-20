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

test('folder details and signed policy history use current folder membership', async (t) => {
  const initial = { payload: { purpose: 'INITIAL_FOLDER_POLICY' }, signature: 'initial-signature' };
  const change = { context: { action: 'ADD_MEMBER' }, ownerSignature: 'member-signature' };
  let rotationStatus = 'PENDING';
  let leaseExpired = 0;
  const app = createApp({
    authenticate(request, _response, next) {
      const id = request.get('authorization');
      if (id) request.user = { id };
      next();
    },
    mysqlPool: {
      async execute(sql, args) {
        if (sql.includes('MAX(p.policy_version)')) {
          assert.match(sql, /m\.status = 'ACTIVE'/);
          assert.match(sql, /j\.folder_id = detail\.folderId AND j\.policy_version = detail\.policyVersion/);
          assert.match(sql, /j\.lease_expires_at <= UTC_TIMESTAMP\(3\)/);
          const [userId, folderId] = args;
          assert.equal(folderId, 'A');
          if (userId !== 'viewer') return [[]];
          return [[{
            folderId, policyVersion: 2, status: 'ACTIVE', role: 'VIEWER', rotationStatus, leaseExpired,
          }]];
        }
        assert.match(sql, /p\.folder_id = m\.folder_id AND p\.policy_version = \?/);
        assert.match(sql, /m\.user_id = \? AND m\.status = 'ACTIVE'/);
        const [version, folderId, userId] = args;
        assert.equal(folderId, 'A');
        if (userId !== 'viewer') return [[]];
        if (version === 1) {
          return [[{ policyVersion: 1, signedPolicy: { ...initial, extra: 'unverified input field' } }]];
        }
        if (version === 2) return [[{ policyVersion: 2, signedPolicy: JSON.stringify(change) }]];
        return [[{ policyVersion: null }]];
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const folderUrl = `http://127.0.0.1:${server.address().port}/api/v1/folders/A`;
  const headers = { authorization: 'viewer' };
  const states = [
    ['PENDING', 1, 'ROTATING'],
    ['IN_PROGRESS', 0, 'ROTATING'],
    ['IN_PROGRESS', 1, 'WAITING_FOR_CLIENT'],
    ['WAITING_FOR_CLIENT', 1, 'WAITING_FOR_CLIENT'],
    ['WAITING_FOR_KEY', 1, 'WAITING_FOR_KEY'],
    ['WAITING_FOR_OWNER', 1, 'WAITING_FOR_OWNER'],
    ['FAILED', 1, 'FAILED'],
    ['COMPLETED', 1, 'READY'],
    ['CANCELLED', 1, null],
    [null, 1, null],
  ];
  for (const [status, expired, cryptoState] of states) {
    rotationStatus = status;
    leaseExpired = expired;
    const details = await fetch(folderUrl, { headers });
    assert.equal(details.status, 200);
    assert.equal(details.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await details.json(), { folderId: 'A', policyVersion: 2, role: 'VIEWER', cryptoState });
  }
  assert.equal((await fetch(folderUrl, { headers: { authorization: 'revoked' } })).status, 403);

  const policiesUrl = folderUrl + '/policies/';
  for (const [version, signedPolicy] of [[1, initial], [2, change]]) {
    const response = await fetch(policiesUrl + version, { headers });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), { folderId: 'A', policyVersion: version, signedPolicy });
  }

  assert.equal((await fetch(policiesUrl + '1')).status, 401);
  for (const authorization of ['revoked', 'outsider']) {
    assert.equal((await fetch(policiesUrl + '1', { headers: { authorization } })).status, 403);
  }
  assert.equal((await fetch(policiesUrl + '3', { headers })).status, 404);
  for (const version of ['0', '1e0', '4294967296']) {
    assert.equal((await fetch(policiesUrl + version, { headers })).status, 400);
  }
});

test('folder deletion requires owner reauthentication and exposes cleanup progress to that owner', async (t) => {
  const folderId = 'abc12345-1234-1234-1234-123456789abc';
  const roles = { owner: 'OWNER', editor: 'EDITOR' };
  let operation;
  let cancelled = false;
  const connection = {
    async beginTransaction() {},
    async commit() {},
    async rollback() {},
    release() {},
    async execute(sql, args) {
      if (sql.includes('FROM Treatment_Folder')) {
        assert.match(sql, /FOR UPDATE/);
        return [[{ folder_id: folderId }]];
      }
      if (sql.includes('FROM Folder_Deletion_Operation')) {
        assert.deepEqual(args.slice(0, 1), [folderId]);
        return [operation && args[1] === 'owner' ? [operation] : []];
      }
      if (sql.includes('FROM Folder_Membership')) {
        assert.match(sql, /role = 'OWNER' AND status = 'ACTIVE'/);
        return [roles[args[1]] === 'OWNER' ? [{ membership_id: 1 }] : []];
      }
      if (sql.includes('INSERT INTO Folder_Deletion_Operation')) {
        assert.deepEqual(args.slice(1), [folderId, 'owner']);
        assert.equal(operation, undefined);
        operation = { operationId: args[0], status: 'PENDING' };
      } else if (sql.includes('UPDATE Folder_Membership')) {
        assert.deepEqual(args, ['owner', folderId]);
        assert.match(sql, /status = 'REVOKED'/);
        delete roles.owner;
        delete roles.editor;
      } else {
        assert.match(sql, /UPDATE Folder_Rotation_Job SET status = 'CANCELLED'/);
        assert.deepEqual(args, [folderId]);
        cancelled = true;
      }
      return [{ affectedRows: 1 }];
    },
  };
  const app = createApp({
    authenticate(request, _response, next) {
      const id = request.get('authorization');
      if (id) request.user = { id };
      next();
    },
    async verifyFolderDeletionReauth(request) {
      return request.get('x-test-reauth') === request.user.id;
    },
    mysqlPool: {
      async getConnection() { return connection; },
      async execute(sql, [id, userId]) {
        if (sql.includes('FROM Folder_Deletion_Operation')) {
          assert.match(sql, /requested_by = \?/);
          return [id === operation?.operationId && userId === 'owner' ? [{ ...operation, folderId }] : []];
        }
        assert.match(sql, /m\.status = 'ACTIVE'/);
        return [roles[id] ? [{ folderId, role: roles[id], status: 'ACTIVE' }] : []];
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  const url = base + '/folders/' + folderId;
  const remove = (id, reauthenticated = true) => fetch(url, {
    method: 'DELETE', headers: { authorization: id, ...(reauthenticated && { 'x-test-reauth': id }) },
  });

  assert.equal((await fetch(url, { method: 'DELETE' })).status, 401);
  const stale = await remove('owner', false);
  assert.equal(stale.status, 403);
  assert.deepEqual(await stale.json(), { code: 'REAUTHENTICATION_REQUIRED' });
  assert.equal((await remove('editor')).status, 403);
  assert.equal(operation, undefined);

  const accepted = await remove('owner');
  const location = '/operations/' + operation.operationId;
  assert.equal(accepted.status, 202);
  assert.deepEqual(await accepted.json(), operation);
  assert.equal(accepted.headers.get('location'), '/api/v1' + location);
  assert.equal(cancelled, true);
  assert.equal((await fetch(url, { headers: { authorization: 'editor' } })).status, 403);
  assert.deepEqual(await (await remove('owner')).json(), operation);
  assert.equal((await fetch(base + location, { headers: { authorization: 'editor' } })).status, 404);
  assert.deepEqual(await (await fetch(base + location, { headers: { authorization: 'owner' } })).json(), {
    ...operation, folderId,
  });
});

test('rotation list is scoped to active owners and editors and paginates jobs', async (t) => {
  const jobs = Array.from({ length: 51 }, (_, index) => ({
    rotationId: String(index), status: index === 0 ? 'PENDING' : 'CANCELLED', canAttemptClaim: index === 0 ? 1 : 0,
  }));
  const app = createApp({
    authenticate(request, _response, next) {
      const id = request.get('authorization');
      if (id) request.user = { id };
      next();
    },
    async canReadRotationSources() {
      assert.fail('Listing should leave source verification to the claim endpoint');
    },
    mysqlPool: {
      async query(sql, [userId, limit, offset]) {
        assert.match(sql, /m\.folder_id = j\.folder_id/);
        assert.match(sql, /m\.status = 'ACTIVE' AND m\.role IN \('OWNER', 'EDITOR'\)/);
        assert.match(sql, /ORDER BY j\.created_at DESC, j\.rotation_id DESC/);
        assert.equal(limit, 51);
        return [['owner', 'editor'].includes(userId) ? jobs.slice(offset, offset + limit) : []];
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/api/v1/key-rotations`;
  assert.equal((await fetch(url)).status, 401);
  const editor = { authorization: 'editor' };
  const first = await fetch(url, { headers: editor });
  assert.equal(first.headers.get('cache-control'), 'no-store');
  const firstPage = await first.json();
  assert.equal(firstPage.rotations.length, 50);
  assert.equal(firstPage.nextPage, 2);
  assert.deepEqual(firstPage.rotations[0], { rotationId: '0', status: 'PENDING', canClaim: null });
  assert.deepEqual(await (await fetch(url + '?page=2', { headers: editor })).json(), {
    rotations: [{ rotationId: '50', status: 'CANCELLED', canClaim: false }], nextPage: null,
  });
  for (const authorization of ['viewer', 'revoked', 'outsider']) {
    assert.deepEqual(await (await fetch(url, { headers: { authorization } })).json(), { rotations: [], nextPage: null });
  }
  assert.equal((await fetch(url + '?page=1&page=2', { headers: editor })).status, 400);
});

test('rotation status is available only to active owners and editors of the folder', async (t) => {
  const rotationId = 'abc12345-1234-1234-1234-123456789abc';
  const rotation = { rotationId, folderId: 'A', policyVersion: 2, status: 'PENDING' };
  const app = createApp({
    authenticate(request, _response, next) {
      const userId = request.get('authorization');
      if (userId) request.user = { id: userId };
      next();
    },
    mysqlPool: {
      async execute(sql, [id, userId]) {
        assert.match(sql, /m\.folder_id = j\.folder_id/);
        assert.match(sql, /m\.status = 'ACTIVE' AND m\.role IN \('OWNER', 'EDITOR'\)/);
        return [id === rotationId && ['owner', 'editor'].includes(userId) ? [rotation] : []];
      },
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/api/v1/key-rotations/${rotationId}`;

  assert.equal((await fetch(url)).status, 401);
  for (const authorization of ['owner', 'editor']) {
    const result = await fetch(url, { headers: { authorization } });
    assert.equal(result.status, 200);
    assert.equal(result.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await result.json(), rotation);
  }
  for (const authorization of ['viewer', 'revoked', 'outsider']) {
    assert.equal((await fetch(url, { headers: { authorization } })).status, 404);
  }
  assert.equal((await fetch(url + 'invalid', { headers: { authorization: 'owner' } })).status, 400);
  const claimUrl = url + '/claim';
  assert.equal((await fetch(claimUrl, { method: 'POST' })).status, 401);
  const claim = await fetch(claimUrl, { method: 'POST', headers: { authorization: 'owner' } });
  assert.equal(claim.status, 503);
  assert.deepEqual(await claim.json(), { code: 'ROTATION_SERVICE_UNAVAILABLE' });
});

test('folder updates allow active owners and editors to change the name and description', async (t) => {
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
      async updateForUser(userId, folderId, change, allowedRoles) {
        assert.equal(folderId, folder.folderId);
        const membership = memberships[userId];
        assert.ok(allowedRoles.includes(membership.role));
        if (change.name !== undefined) folder.name = change.name;
        folder.description = change.description;
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

  assert.equal((await rename('viewer', '{"description":"Denied"}')).status, 403);
  assert.equal((await rename('editor', '{"description":42}')).status, 400);
  assert.equal((await rename('editor', JSON.stringify({ description: 'a'.repeat(1001) }))).status, 400);
  const edited = await rename('editor', '{"description":"  Follow up  "}');
  assert.equal(edited.status, 200);
  assert.deepEqual(await edited.json(), { folderId: 'A', name: 'editor', description: 'Follow up', role: 'EDITOR' });
  const cleared = await rename('owner', '{"name":"New name","description":null}');
  assert.equal(cleared.status, 200);
  assert.deepEqual(await cleared.json(), { folderId: 'A', name: 'New name', description: null, role: 'OWNER' });
});
