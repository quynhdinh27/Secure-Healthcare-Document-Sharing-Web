const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const OBJECT_KEY = new RegExp(`^${UUID}/${UUID}$`);

// Development storage driver: one file per ciphertext object under rootDir.
// The same put/get/delete interface will be implemented for S3 later.
function createLocalObjectStorage({ rootDir }) {
  const root = path.resolve(rootDir);

  function resolveKey(key) {
    if (typeof key !== 'string' || !OBJECT_KEY.test(key)) {
      throw Object.assign(new Error('Invalid object key'), { code: 'INVALID_OBJECT_KEY' });
    }
    return path.join(root, ...key.split('/'));
  }

  return {
    async put(key, data) {
      const file = resolveKey(key);
      await fs.mkdir(path.dirname(file), { recursive: true });
      const temporary = `${file}.${randomUUID()}.tmp`;
      try {
        await fs.writeFile(temporary, data, { flag: 'wx' });
        await fs.rename(temporary, file);
      } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
      }
    },
    async get(key) {
      return fs.readFile(resolveKey(key));
    },
    async delete(key) {
      await fs.rm(resolveKey(key), { force: true });
    },
  };
}

module.exports = { createLocalObjectStorage };
