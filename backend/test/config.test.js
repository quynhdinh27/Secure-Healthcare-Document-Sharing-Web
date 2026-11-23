const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { backendDir, loadConfig } = require('../src/config');

test('config applies local development defaults', () => {
  const config = loadConfig({ DB_PASSWORD: 'secret' });
  assert.equal(config.nodeEnv, 'development');
  assert.equal(config.port, 3000);
  assert.equal(config.authMode, 'dev');
  assert.deepEqual({ ...config.db }, {
    host: '127.0.0.1', port: 3306, user: 'medshare', password: 'secret', database: 'medshare',
  });
  assert.deepEqual({ ...config.storage }, { driver: 'local', dir: path.join(backendDir, 'data', 'objects') });
  assert.equal(config.maxUploadBytes, 25 * 1024 * 1024);
  assert.equal(config.uploadContextTtlSeconds, 600);
  assert.ok(Object.isFrozen(config) && Object.isFrozen(config.db) && Object.isFrozen(config.storage));
});

test('config rejects unsafe or invalid settings', () => {
  assert.throws(() => loadConfig({}), /DB_PASSWORD is required/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', NODE_ENV: 'production' }), /AUTH_MODE=dev is not allowed/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', AUTH_MODE: 'session' }), /AUTH_MODE must be one of: dev/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', STORAGE_DRIVER: 's3' }), /STORAGE_DRIVER must be one of: local/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', MAX_UPLOAD_MB: '0' }), /MAX_UPLOAD_MB must be an integer/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', PORT: 'abc' }), /PORT must be an integer/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', UPLOAD_CONTEXT_TTL_SECONDS: '5' }), /UPLOAD_CONTEXT_TTL_SECONDS/);
});
