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
