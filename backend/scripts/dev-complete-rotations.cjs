// DEVELOPMENT ONLY. Repairs unfinished jobs created before empty folders settled automatically.
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function completeFolderRotations(pool, folderId) {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [[folder]] = await connection.execute(
      'SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId],
    );
    if (!folder) throw new Error('Folder not found');
    const [[{ hasDocuments }]] = await connection.execute(
      'SELECT EXISTS (SELECT 1 FROM Document WHERE folder_id = ?) AS hasDocuments', [folderId],
    );
    if (Number(hasDocuments) !== 0) throw new Error('Cannot complete rotation for a folder with documents');
    const [result] = await connection.execute(`
      UPDATE Folder_Rotation_Job SET status = 'COMPLETED', finished_at = UTC_TIMESTAMP(3)
      WHERE folder_id = ?
        AND status IN ('PENDING', 'IN_PROGRESS', 'WAITING_FOR_CLIENT', 'WAITING_FOR_KEY', 'WAITING_FOR_OWNER')
    `, [folderId]);
    await connection.commit();
    return result.affectedRows;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
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
    const completed = await completeFolderRotations(pool, folderId);
    console.log(`Marked ${completed} rotation job(s) COMPLETED for folder ${folderId}`);
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
