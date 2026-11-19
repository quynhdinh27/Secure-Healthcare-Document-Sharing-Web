const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlFolderRepository } = require('../src/folders/mysql-folder-repository');

test('rename checks the current membership under lock before issuing a write', async () => {
  const calls = [];
  const connection = {
    async beginTransaction() { calls.push('begin'); },
    async execute(sql, parameters) {
      assert.match(sql, /m\.status = 'ACTIVE'/);
      assert.match(sql, /FOR UPDATE$/);
      assert.deepEqual(parameters, ['editor', 'folder-a']);
      calls.push('check');
      return [[{ role: 'VIEWER' }]];
    },
    async rollback() { calls.push('rollback'); },
    release() { calls.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });

  assert.equal(await repository.renameForUser('editor', 'folder-a', 'New', ['OWNER', 'EDITOR']), null);
  assert.deepEqual(calls, ['begin', 'check', 'rollback', 'release']);
});

test('rename rolls back and releases the connection if the update fails', async () => {
  const failure = new Error('write failed');
  const calls = [];
  const connection = {
    async beginTransaction() {},
    async execute(sql, parameters) {
      if (sql.endsWith('FOR UPDATE')) return [[{ name: 'Old', role: 'EDITOR' }]];
      assert.match(sql, /^UPDATE Treatment_Folder/);
      assert.deepEqual(parameters, ['New', 'folder-a']);
      throw failure;
    },
    async rollback() { calls.push('rollback'); },
    release() { calls.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });

  await assert.rejects(repository.renameForUser('editor', 'folder-a', 'New', ['OWNER', 'EDITOR']), failure);
  assert.deepEqual(calls, ['rollback', 'release']);
});

test('create folder rejects an unverified policy and saves a verified folder for the authenticated owner', async (t) => {
  const { createApp } = require('../src/server');
  const { once } = require('node:events');
  const folderId = '0dab1340-76c0-4d03-8f77-3b743d187453';
  const payload = { folderId, name: 'First folder', patientRef: 'p1', treatmentReference: 'e1', signedPolicy: { proof: 'fixture' } };
  const events = [];
  let policyValid = false;
  const connection = {
    async beginTransaction() { events.push('begin'); },
    async execute(sql, args) {
      if (sql.includes('INSERT INTO Treatment_Folder')) {
        assert.deepEqual(args, [folderId, 'First folder', 'p1', 'e1']);
        events.push('folder');
      } else if (sql.includes('INSERT INTO Folder_Membership')) {
        assert.match(sql, /'OWNER'/);
        assert.deepEqual(args, [folderId, '7', '7']);
        events.push('owner');
      } else if (sql.includes('INSERT INTO Folder_Policy')) {
        assert.deepEqual(args, [folderId, JSON.stringify(payload.signedPolicy)]);
        events.push('policy');
      } else {
        assert.deepEqual(args, ['7', folderId]);
        return [[{ folderId, name: 'First folder', role: 'OWNER', status: 'ACTIVE' }]];
      }
    },
    async rollback() { events.push('rollback'); },
    async commit() { events.push('commit'); },
    release() { events.push('release'); },
  };
  const app = createApp({
    authenticate(request, _response, next) {
      if (request.get('authorization') === 'Bearer fixture') request.user = { id: '7' };
      next();
    },
    mysqlPool: { async getConnection() { return connection; } },
    async verifyInitialFolderPolicy(input) {
      assert.equal(input.connection, connection);
      assert.equal(input.folder.folderId, folderId);
      assert.equal(input.ownerId, '7');
      assert.equal(input.policyVersion, 1);
      return policyValid;
    },
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/api/v1/folders`;
  const create = () => fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer fixture' },
    body: JSON.stringify(payload),
  });

  assert.equal((await create()).status, 422);
  assert.deepEqual(events, ['begin', 'rollback', 'release']);
  events.length = 0;

  policyValid = true;
  const created = await create();
  assert.equal(created.status, 201);
  assert.equal(created.headers.get('location'), '/api/v1/folders/' + folderId);
  assert.deepEqual(await created.json(), { folderId, name: 'First folder', role: 'OWNER', policyVersion: 1 });
  assert.deepEqual(events, ['begin', 'folder', 'owner', 'policy', 'commit', 'release']);
});
