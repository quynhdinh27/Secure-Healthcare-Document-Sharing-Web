const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { createLocalObjectStorage } = require('../src/storage/local-object-storage');

async function tempStorage(t) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), 'medshare-objects-'));
  t.after(() => fs.rm(rootDir, { recursive: true, force: true }));
  return { rootDir, storage: createLocalObjectStorage({ rootDir }) };
}

test('local object storage stores, reads and deletes objects under its root', async (t) => {
  const { rootDir, storage } = await tempStorage(t);
  const [prefix, name] = [randomUUID(), randomUUID()];
  const key = `${prefix}/${name}`;
  await storage.put(key, Buffer.from('ciphertext'));
  assert.deepEqual(await storage.get(key), Buffer.from('ciphertext'));
  assert.deepEqual(await fs.readdir(path.join(rootDir, prefix)), [name]);
  await storage.delete(key);
  await assert.rejects(storage.get(key), { code: 'ENOENT' });
  await storage.delete(key);
});

test('local object storage rejects keys outside the object key format', async (t) => {
  const { storage } = await tempStorage(t);
  const id = randomUUID();
  for (const key of ['../x', '/etc/passwd', 'a/b', id, `${id}/../${id}`, `${id.toUpperCase()}/${id}`, `${id}/${id}/x`, 42]) {
    await assert.rejects(storage.put(key, Buffer.from('x')), { code: 'INVALID_OBJECT_KEY' });
    await assert.rejects(storage.get(key), { code: 'INVALID_OBJECT_KEY' });
    await assert.rejects(storage.delete(key), { code: 'INVALID_OBJECT_KEY' });
  }
});
