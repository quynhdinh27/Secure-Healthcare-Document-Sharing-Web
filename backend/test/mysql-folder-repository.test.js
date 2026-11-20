const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlFolderRepository } = require('../src/folders/mysql-folder-repository');
const { queueMysqlFolderRotation } = require('../src/folders/mysql-folder-rotation-queue');

test('rotation claim and renewal enforce current membership, source access and lease ownership', async () => {
  const leaseExpiresAt = '2026-11-20T08:15:00.000000Z';
  const renewedUntil = '2026-11-20T08:17:00.000000Z';
  const job = { folderId: 'A', policyVersion: 2, status: 'PENDING', generation: 0 };
  const events = [];
  const connection = {
    async beginTransaction() { events.push('begin'); },
    async execute(sql, args) {
      if (sql.includes('SELECT folder_id AS folderId')) return [[{ folderId: 'A' }]];
      if (sql.includes('FROM Treatment_Folder')) {
        assert.match(sql, /FOR UPDATE/);
        events.push('folder lock');
        return [[{ folder_id: 'A' }]];
      }
      if (sql.includes('INNER JOIN Folder_Membership')) {
        assert.match(sql, /m\.status = 'ACTIVE' AND m\.role IN \('OWNER', 'EDITOR'\)/);
        assert.match(sql, /FOR UPDATE/);
        assert.equal(args[0], 'rotation');
        return [args[1] === 'viewer' ? [] : [job]];
      }
      if (sql.includes('UPDATE Folder_Rotation_Job')) {
        assert.match(sql, /INTERVAL 5 MINUTE/);
        if (!sql.includes('generation = generation + 1')) {
          assert.match(sql, /lease_expires_at > UTC_TIMESTAMP\(3\)/);
          assert.deepEqual(args, ['rotation']);
          if (!job.leaseActive) return [{ affectedRows: 0 }];
          events.push('lease renew');
          job.leaseExpiresAt = renewedUntil;
          return [{ affectedRows: 1 }];
        }
        events.push('lease write');
        Object.assign(job, {
          executorId: args[0], status: 'IN_PROGRESS', generation: job.generation + 1,
          leaseActive: 1, leaseExpiresAt,
        });
        return [{ affectedRows: 1 }];
      }
      assert.match(sql, /SELECT generation/);
      return [[{ generation: job.generation, leaseExpiresAt: job.leaseExpiresAt }]];
    },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });
  const claim = (userId, eligible = true) => repository.claimRotationForUser(userId, 'rotation', async (source) => {
    assert.deepEqual(source, { connection, userId, rotationId: 'rotation', folderId: 'A', policyVersion: 2 });
    events.push('source check');
    return eligible;
  });

  assert.deepEqual(await claim('viewer'), { code: 'ROTATION_NOT_FOUND' });
  assert.deepEqual(await claim('editor', false), { code: 'ROTATION_SOURCE_UNAVAILABLE' });
  assert.equal(job.generation, 0);
  events.length = 0;
  const first = await claim('editor');
  assert.deepEqual(first, { rotationId: 'rotation', status: 'IN_PROGRESS', generation: 1, leaseExpiresAt });
  assert.deepEqual(events, ['begin', 'folder lock', 'source check', 'lease write', 'commit', 'release']);
  assert.deepEqual(await claim('editor'), first);
  assert.deepEqual(await claim('owner'), { code: 'ROTATION_ALREADY_CLAIMED' });
  const renew = (userId, generation, verify = async () => true) => (
    repository.renewRotationLeaseForUser(userId, 'rotation', generation, verify)
  );
  assert.deepEqual(await renew('viewer', 1), { code: 'ROTATION_NOT_FOUND' });
  assert.deepEqual(await renew('owner', 1), { code: 'LEASE_EXPIRED' });
  assert.deepEqual(await renew('editor', 2), { code: 'LEASE_EXPIRED' });
  assert.deepEqual(await renew('editor', 1, async () => false), { code: 'ROTATION_SOURCE_UNAVAILABLE' });
  assert.deepEqual(await renew('editor', 1), { ...first, leaseExpiresAt: renewedUntil });
  assert.deepEqual(await renew('editor', 1, async () => {
    job.leaseActive = 0;
    return true;
  }), { code: 'LEASE_EXPIRED' });
  assert.deepEqual(await renew('editor', 1), { code: 'LEASE_EXPIRED' });
  assert.deepEqual(await claim('owner'), { ...first, generation: 2 });
  job.status = 'CANCELLED';
  assert.deepEqual(await renew('owner', 2), { code: 'LEASE_EXPIRED' });
  assert.deepEqual(await claim('owner'), { code: 'ROTATION_NOT_CLAIMABLE' });
});

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

test('folder description updates leave the existing name intact', async () => {
  const row = { folderId: 'folder-a', name: 'Original', description: 'Old', role: 'EDITOR', status: 'ACTIVE' };
  const calls = [];
  const connection = {
    async beginTransaction() { calls.push('begin'); },
    async execute(sql, parameters) {
      if (sql.startsWith('UPDATE')) {
        assert.match(sql, /^UPDATE Treatment_Folder SET description = \?, updated_at = CURRENT_TIMESTAMP WHERE folder_id = \?$/);
        assert.deepEqual(parameters, [null, 'folder-a']);
        calls.push('write');
        row.description = null;
      } else {
        assert.deepEqual(parameters, ['editor', 'folder-a']);
        calls.push(sql.endsWith('FOR UPDATE') ? 'lock' : 'read');
      }
      return [[row]];
    },
    async commit() { calls.push('commit'); },
    release() { calls.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });
  assert.deepEqual(await repository.updateForUser('editor', 'folder-a', { description: null }, ['OWNER', 'EDITOR']), {
    folder: { folderId: 'folder-a', name: 'Original', description: null },
    membership: { role: 'EDITOR', status: 'ACTIVE' },
  });
  assert.deepEqual(calls, ['begin', 'lock', 'write', 'read', 'commit', 'release']);
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
  let failRotation = false;
  let rotationId;
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
      else if (sql.includes('UPDATE Folder_Rotation_Job')) {
        assert.match(sql, /status = 'CANCELLED'/);
        assert.deepEqual(args, ['A']);
        events.push('cancel old jobs');
      } else if (sql.includes('INSERT INTO Folder_Rotation_Job')) {
        [rotationId] = args;
        assert.match(rotationId, /^[0-9a-f-]{36}$/);
        assert.deepEqual(args.slice(1), ['A', 2, '7', 'REVOKE_MEMBER']);
        events.push('queue new job');
        if (failRotation) throw new Error('queue failed');
      }
      else assert.fail('Unexpected SQL: ' + sql);
      return [{ affectedRows: 1 }];
    },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
  };
  const repository = createMysqlFolderRepository({ async getConnection() { return connection; } });
  const input = {
    ownerId: '7', folderId: 'A', membershipId: '2', action: 'REVOKE_MEMBER',
    policyContextId: 'context', ownerSignature: 'fixture',
    async verifyFolderPolicy({ context: storedContext }) {
      assert.equal(storedContext, context);
      events.push('verify');
      return true;
    },
    queueFolderRotation: queueMysqlFolderRotation,
  };

  const writes = ['begin', 'verify', 'revoke', 'save policy', 'consume context', 'cancel old jobs', 'queue new job'];
  const result = await repository.applyMemberChange(input);
  assert.deepEqual(result, { policyVersion: 2, rotationId });
  assert.deepEqual(events, [...writes, 'commit', 'release']);

  events.length = 0;
  failRotation = true;
  await assert.rejects(repository.applyMemberChange(input), /queue failed/);
  assert.deepEqual(events, [...writes, 'rollback', 'release']);

  events.length = 0;
  expired = true;
  assert.deepEqual(await repository.applyMemberChange(input), { code: 'POLICY_CONTEXT_INVALID' });
  assert.deepEqual(events, ['begin', 'rollback', 'release']);
});
