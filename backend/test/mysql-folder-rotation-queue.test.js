const assert = require('node:assert/strict');
const { test } = require('node:test');
const { completeFolderRotations } = require('../scripts/dev-complete-rotations.cjs');
const { queueMysqlFolderRotation } = require('../src/folders/mysql-folder-rotation-queue');
const { createFakeMysql } = require('./helpers/fake-mysql');

test('membership changes settle rotations only when a folder has no documents', async () => {
  for (const [hasDocuments, status] of [[0, 'COMPLETED'], [1, 'PENDING']]) {
    const statements = [];
    const { connection } = createFakeMysql((sql, args) => {
      statements.push(sql.split(' ').slice(0, 2).join(' '));
      if (sql.startsWith('SELECT EXISTS')) {
        assert.deepEqual(args, ['folder']);
        return [[{ hasDocuments }]];
      }
      if (sql.startsWith('INSERT')) {
        assert.match(sql, /IF\(\? = 'COMPLETED', UTC_TIMESTAMP\(3\), NULL\)/);
        assert.deepEqual(args.slice(1), ['folder', 2, '7', 'ADD_MEMBER', status, status]);
      }
      return [{ affectedRows: 1 }];
    });
    await queueMysqlFolderRotation({ connection, folderId: 'folder', policyVersion: 2, ownerId: '7', action: 'ADD_MEMBER' });
    assert.deepEqual(statements, ['UPDATE Folder_Rotation_Job', 'SELECT EXISTS', 'INSERT INTO']);
  }
});

test('dev rotation repair locks the folder and refuses to settle jobs with existing documents', async () => {
  for (const hasDocuments of [0, 1]) {
    const { pool, events } = createFakeMysql((sql, args, calls) => {
      assert.deepEqual(args, ['folder']);
      if (sql.endsWith('FOR UPDATE')) {
        calls.push('lock folder');
        return [[{ folder_id: 'folder' }]];
      }
      if (sql.startsWith('SELECT EXISTS')) {
        calls.push('check documents');
        return [[{ hasDocuments }]];
      }
      calls.push('settle jobs');
      assert.match(sql, /^UPDATE Folder_Rotation_Job/);
      return [{ affectedRows: 1 }];
    });
    if (hasDocuments) {
      await assert.rejects(completeFolderRotations(pool, 'folder'), /folder with documents/);
      assert.deepEqual(events, ['begin', 'lock folder', 'check documents', 'rollback', 'release']);
    } else {
      assert.equal(await completeFolderRotations(pool, 'folder'), 1);
      assert.deepEqual(events, ['begin', 'lock folder', 'check documents', 'settle jobs', 'commit', 'release']);
    }
  }
});
