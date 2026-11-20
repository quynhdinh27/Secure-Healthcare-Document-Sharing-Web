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

test('policy context snapshots a revocation without changing membership', async () => {
  const statements = [];
  const members = [
    { membershipId: '1', userId: '10', role: 'OWNER' },
    { membershipId: '2', userId: '20', role: 'EDITOR' },
  ];
  const connection = {
    async beginTransaction() {},
    async execute(sql, parameters) {
      statements.push(sql.trim());
      if (sql.includes('FROM Treatment_Folder')) return [[{ folder_id: 'A' }]];
      if (sql.includes('FROM Folder_Membership')) return [members];
      if (sql.includes('MAX(policy_version)')) return [[{ version: 1 }]];
      assert.match(sql, /^INSERT INTO Folder_Policy_Context/);
      assert.equal(parameters[2], '1');
      assert.deepEqual(JSON.parse(parameters[3]).proposedPolicy, {
        policyVersion: 2,
        members: [{ userId: '10', role: 'OWNER' }],
      });
    },
    async commit() {},
    async rollback() {},
    release() {},
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });
  const target = { membershipId: '2' };
  assert.deepEqual(await repository.createPolicyContext('20', 'A', 'REVOKE_MEMBER', target), { code: 'FORBIDDEN' });
  assert.equal(statements.length, 2);
  const result = await repository.createPolicyContext('10', 'A', 'REVOKE_MEMBER', target);
  assert.equal(result.expectedPolicyVersion, 1);
  assert.equal(result.action, 'REVOKE_MEMBER');
  assert.match(result.nonce, /^[0-9a-f]{32}$/);
  assert.equal(members.length, 2);
  assert.equal(statements.filter((sql) => sql.startsWith('INSERT')).length, 1);
});

test('member revocation commits policy and rotation together and rolls back if rotation fails', async () => {
  const events = [];
  const context = {
    action: 'REVOKE_MEMBER', target: { membershipId: '2' },
    expectedPolicyVersion: 1, proposedPolicy: { policyVersion: 2 },
  };
  let expired = false;
  const connection = {
    async beginTransaction() { events.push('begin'); },
    async execute(sql, args) {
      if (sql.includes('FROM Treatment_Folder')) return [[{ folder_id: 'A' }]];
      if (sql.includes('FROM Folder_Membership')) return [[{ membershipId: '1' }]];
      if (sql.includes('FROM Folder_Policy_Context')) return [[{ payload: context, expired }]];
      if (sql.includes('MAX(policy_version)')) return [[{ version: 1 }]];
      if (sql.startsWith('UPDATE Folder_Membership')) {
        assert.deepEqual(args, ['7', 'A', '2']);
        events.push('revoke');
      } else if (sql.includes('INSERT INTO Folder_Policy')) events.push('save policy');
      else if (sql.includes('UPDATE Folder_Policy_Context')) events.push('consume context');
      else assert.fail('Unexpected SQL: ' + sql);
      return [{ affectedRows: 1 }];
    },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });
  let failRotation = false;
  const input = {
    ownerId: '7', folderId: 'A', membershipId: '2', action: 'REVOKE_MEMBER',
    policyContextId: 'context', ownerSignature: 'fixture',
    async verifyFolderPolicy({ context: storedContext }) {
      assert.equal(storedContext, context);
      events.push('verify');
      return true;
    },
    async queueFolderRotation({ connection: transaction, policyVersion }) {
      assert.equal(transaction, connection);
      assert.equal(policyVersion, 2);
      events.push('rotation');
      if (failRotation) throw new Error('queue failed');
      return 'rotation-1';
    },
  };

  assert.deepEqual(await repository.applyMemberChange(input), { policyVersion: 2, rotationId: 'rotation-1' });
  assert.deepEqual(events, ['begin', 'verify', 'revoke', 'save policy', 'consume context', 'rotation', 'commit', 'release']);

  events.length = 0;
  failRotation = true;
  await assert.rejects(repository.applyMemberChange(input), /queue failed/);
  assert.deepEqual(events, ['begin', 'verify', 'revoke', 'save policy', 'consume context', 'rotation', 'rollback', 'release']);

  events.length = 0;
  expired = true;
  assert.deepEqual(await repository.applyMemberChange(input), { code: 'POLICY_CONTEXT_INVALID' });
  assert.deepEqual(events, ['begin', 'rollback', 'release']);
});
