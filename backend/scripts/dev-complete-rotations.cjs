// DEVELOPMENT ONLY. Rotation commit (commitRotation) is not implemented yet, so a
// folder stays FOLDER_NOT_READY after any membership change. This marks the
// folder's unfinished rotation jobs COMPLETED so local testing can continue.
// It does not re-encrypt anything: new members get no envelopes for existing
// documents and DEKs are not rotated. Remove once rotation commit exists.
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function completeFolderRotations(executor, folderId) {
  const [result] = await executor.execute(`
    UPDATE Folder_Rotation_Job SET status = 'COMPLETED', finished_at = UTC_TIMESTAMP(3)
    WHERE folder_id = ?
      AND status IN ('PENDING', 'IN_PROGRESS', 'WAITING_FOR_CLIENT', 'WAITING_FOR_KEY', 'WAITING_FOR_OWNER')
  `, [folderId]);
  const [[documents]] = await executor.execute('SELECT COUNT(*) AS count FROM Document WHERE folder_id = ?', [folderId]);
  return { completed: result.affectedRows, documentCount: Number(documents.count) };
}

async function main() {
  const folderId = process.argv[2];
  if (!UUID.test(folderId ?? '')) {
    throw new Error('Usage: npm run dev:complete-rotations -- <folderId>');
  }
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('dev:complete-rotations is not allowed in production');
  const pool = createPool(config.db);
  try {
    const { completed, documentCount } = await completeFolderRotations(pool, folderId);
    console.log(`Marked ${completed} rotation job(s) COMPLETED for folder ${folderId}`);
    if (documentCount > 0) {
      console.warn(`Warning: the folder has ${documentCount} document(s). Members added since the last upload have no envelope (ENVELOPE_NOT_AVAILABLE) and DEKs were not rotated.`);
    }
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { completeFolderRotations };
